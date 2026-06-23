import base64
import os
import select
import threading
from contextlib import contextmanager

import psycopg2
import psycopg2.extensions
import psycopg2.extras
import psycopg2.pool

REVOKE_CHANNEL = 'radix_revoke'

# FreeRADIUS runs rlm_python3 multi-threaded, and psycopg2 releases the GIL
# during libpq I/O — so a single shared connection is unsafe. Each request
# borrows its own connection from this pool for the duration of one operation.
_pool = None
_pool_lock = threading.Lock()


def _conn_params():
    return dict(
        host=os.environ['DB_HOST'],
        dbname=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
    )


def _get_pool():
    global _pool
    if _pool is None:
        with _pool_lock:
            if _pool is None:
                _pool = psycopg2.pool.ThreadedConnectionPool(
                    minconn=1,
                    maxconn=int(os.environ.get('DB_POOL_MAX', 16)),
                    **_conn_params(),
                )
    return _pool


def reset_conn():
    """Tear down the pool so the next call rebuilds it (recovery after fatal DB errors)."""
    global _pool
    with _pool_lock:
        if _pool is not None:
            try:
                _pool.closeall()
            except Exception:
                pass
            _pool = None


@contextmanager
def _cursor(commit=False):
    """Borrow a pooled connection for one operation.

    Always ends the transaction (commit or rollback) so a failed statement can
    never leave a borrowed connection in an aborted state for the next caller.
    """
    pool = _get_pool()
    conn = pool.getconn()
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
            yield cur
        conn.commit() if commit else conn.rollback()
    except Exception:
        try:
            conn.rollback()
        except Exception:
            pass
        raise
    finally:
        pool.putconn(conn)


def _row(row):
    return {
        'id':        row['id'],
        'pmk_bytes': base64.b64decode(row['pmk_b64']),
        'psk':       row['psk'],
        'vlan_id':   row['vlan_id'],
    }


def lookup_pmk_by_mac(mac, ssid):
    """Fast DB path: MAC already bound to a PMK on this SSID."""
    sql = """
        SELECT pmk.id, pmk.psk, pmk.pmk_b64, pmk.vlan_id
        FROM pairwise_master_keys pmk
        JOIN mac_bindings mb ON mb.pmk_id = pmk.id
        WHERE mb.mac = %s AND pmk.ssid = %s AND pmk.revoked_at IS NULL
        ORDER BY pmk.id DESC
        LIMIT 1
    """
    with _cursor() as cur:
        cur.execute(sql, (mac, ssid))
        row = cur.fetchone()
    return _row(row) if row else None


def lookup_all_pmks(ssid):
    """Slow path: all PMKs for an SSID — iterated to find MIC match for new MACs."""
    sql = """
        SELECT id, psk, pmk_b64, vlan_id
        FROM pairwise_master_keys
        WHERE ssid = %s AND revoked_at IS NULL
        ORDER BY id DESC
    """
    with _cursor() as cur:
        cur.execute(sql, (ssid,))
        return [_row(r) for r in cur.fetchall()]


def lookup_pmk_by_mac_only(mac):
    """MAC auth path: return first bound PSK for this MAC (SSID unknown)."""
    sql = """
        SELECT pmk.id, pmk.psk, pmk.pmk_b64, pmk.vlan_id
        FROM pairwise_master_keys pmk
        JOIN mac_bindings mb ON mb.pmk_id = pmk.id
        WHERE mb.mac = %s AND pmk.revoked_at IS NULL
        ORDER BY pmk.id DESC
        LIMIT 1
    """
    with _cursor() as cur:
        cur.execute(sql, (mac,))
        row = cur.fetchone()
    return _row(row) if row else None


def bind_mac(pmk_id, mac):
    """Persist discovered MAC → PMK mapping after first successful auth."""
    with _cursor(commit=True) as cur:
        cur.execute("""
            INSERT INTO mac_bindings (pmk_id, mac)
            VALUES (%s, %s)
            ON CONFLICT (mac, pmk_id) DO NOTHING
        """, (pmk_id, mac))


def log_auth(mac, ssid, vendor, result, cache_hit=False):
    """Best-effort audit log; never propagates errors into the auth path."""
    try:
        with _cursor(commit=True) as cur:
            cur.execute("""
                INSERT INTO auth_log (mac, ssid, vendor, result, cache_hit)
                VALUES (%s, %s, %s, %s, %s)
            """, (mac, ssid, vendor, result, cache_hit))
    except Exception:
        pass


def upsert_acct_session(rec):
    """Insert or update one accounting session keyed by Acct-Session-Id.

    Counters use GREATEST so out-of-order interim packets can't roll values
    backward; started_at is set once (on insert) and preserved thereafter."""
    rec = dict(rec)
    rec['is_stop'] = (rec.get('status') == 'stop')
    sql = """
        INSERT INTO acct_sessions
            (session_id, mac, username, ssid, nas_ip, framed_ip,
             in_octets, out_octets, session_time, status, terminate_cause,
             started_at, updated_at, stopped_at)
        VALUES
            (%(session_id)s, %(mac)s, %(username)s, %(ssid)s, %(nas_ip)s, %(framed_ip)s,
             %(in_octets)s, %(out_octets)s, %(session_time)s, %(status)s, %(terminate_cause)s,
             now(), now(), CASE WHEN %(is_stop)s THEN now() ELSE NULL END)
        ON CONFLICT (session_id) DO UPDATE SET
            mac             = COALESCE(EXCLUDED.mac, acct_sessions.mac),
            username        = COALESCE(EXCLUDED.username, acct_sessions.username),
            ssid            = COALESCE(EXCLUDED.ssid, acct_sessions.ssid),
            nas_ip          = COALESCE(EXCLUDED.nas_ip, acct_sessions.nas_ip),
            framed_ip       = COALESCE(EXCLUDED.framed_ip, acct_sessions.framed_ip),
            in_octets       = GREATEST(acct_sessions.in_octets, EXCLUDED.in_octets),
            out_octets      = GREATEST(acct_sessions.out_octets, EXCLUDED.out_octets),
            session_time    = GREATEST(acct_sessions.session_time, EXCLUDED.session_time),
            status          = EXCLUDED.status,
            terminate_cause = COALESCE(EXCLUDED.terminate_cause, acct_sessions.terminate_cause),
            updated_at      = now(),
            stopped_at      = COALESCE(EXCLUDED.stopped_at, acct_sessions.stopped_at)
    """
    with _cursor(commit=True) as cur:
        cur.execute(sql, rec)


def close_nas_sessions(nas_ip):
    """Close all still-open sessions for a NAS — used on Accounting-On/Off, which
    a controller emits on reboot/shutdown (the per-session Stops are lost)."""
    if not nas_ip:
        return
    with _cursor(commit=True) as cur:
        cur.execute("""
            UPDATE acct_sessions
            SET stopped_at = now(), status = 'stop', terminate_cause = 'NAS-Reboot'
            WHERE nas_ip = %s AND stopped_at IS NULL
        """, (nas_ip,))


def listen_revocations(on_revoke, _timeout=60):
    """Block on a dedicated connection, invoking on_revoke(payload) for each
    NOTIFY on REVOKE_CHANNEL. Runs until the connection drops (caller retries)."""
    conn = psycopg2.connect(**_conn_params())
    try:
        conn.set_isolation_level(psycopg2.extensions.ISOLATION_LEVEL_AUTOCOMMIT)
        with conn.cursor() as cur:
            cur.execute(f"LISTEN {REVOKE_CHANNEL}")
        while True:
            if select.select([conn], [], [], _timeout) == ([], [], []):
                continue  # timeout — loop so a dead socket eventually surfaces
            conn.poll()
            while conn.notifies:
                note = conn.notifies.pop(0)
                try:
                    on_revoke(note.payload)
                except Exception:
                    pass
    finally:
        try:
            conn.close()
        except Exception:
            pass
