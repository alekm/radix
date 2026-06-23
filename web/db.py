import base64
import hashlib
import os
from contextlib import contextmanager
import psycopg2
import psycopg2.extras

_conn = None

REVOKE_CHANNEL = 'radix_revoke'


def _conn_params():
    return dict(
        host=os.environ['DB_HOST'],
        dbname=os.environ['DB_NAME'],
        user=os.environ['DB_USER'],
        password=os.environ['DB_PASSWORD'],
    )


def _get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(**_conn_params())
        _conn.autocommit = False
    return _conn


@contextmanager
def _bg_cursor(commit=False):
    """A dedicated short-lived connection for background work (retention,
    analytics sampling/aggregation). Keeps those off the shared single-threaded
    request connection so they're safe to run from a worker thread."""
    conn = psycopg2.connect(**_conn_params())
    try:
        with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
            yield cur
        conn.commit() if commit else conn.rollback()
    finally:
        conn.close()


def purge_old(days):
    """Delete auth_log / acct_sessions rows older than `days`. Uses a dedicated
    connection so it's safe to call from the retention worker thread (the shared
    _conn is single-threaded). Returns (auth_log_deleted, acct_sessions_deleted).
    Active sessions are preserved (updated_at advances on every interim)."""
    conn = psycopg2.connect(**_conn_params())
    try:
        with conn.cursor() as cur:
            cur.execute(
                "DELETE FROM auth_log WHERE created_at < now() - make_interval(days => %s)",
                (days,),
            )
            auth_n = cur.rowcount
            cur.execute(
                "DELETE FROM acct_sessions WHERE updated_at < now() - make_interval(days => %s)",
                (days,),
            )
            acct_n = cur.rowcount
            cur.execute(
                "DELETE FROM metrics_rollup WHERE ts < now() - make_interval(days => %s)",
                (days,),
            )
        conn.commit()
        return auth_n, acct_n
    finally:
        conn.close()


# -- analytics ----------------------------------------------------------------

ANALYTICS_WINDOW_DAYS = int(os.environ.get("ANALYTICS_WINDOW_DAYS", 7))


def sample_metrics():
    """Append one rollup sample: active session count + cumulative bytes."""
    with _bg_cursor(commit=True) as cur:
        cur.execute("""
            INSERT INTO metrics_rollup (active_sessions, total_in, total_out)
            SELECT
                count(*) FILTER (WHERE stopped_at IS NULL),
                COALESCE(SUM(in_octets), 0),
                COALESCE(SUM(out_octets), 0)
            FROM acct_sessions
        """)


def compute_analytics():
    """Run every dashboard aggregation once and return a JSON-able dict.
    Called on a timer from the background loop; the request path serves the
    cached result, so page loads never trigger these scans."""
    win = f"{ANALYTICS_WINDOW_DAYS} days"
    out = {"window_days": ANALYTICS_WINDOW_DAYS}

    with _bg_cursor() as cur:
        # Auth health: hourly accepts/rejects + cache hit-rate.
        cur.execute("""
            SELECT date_trunc('hour', created_at) AS bucket,
                   count(*) FILTER (WHERE result = 'accept') AS accepts,
                   count(*) FILTER (WHERE result = 'reject') AS rejects,
                   count(*)                                  AS total,
                   count(*) FILTER (WHERE cache_hit)         AS hits
            FROM auth_log
            WHERE created_at > now() - %s::interval
            GROUP BY bucket ORDER BY bucket
        """, (win,))
        labels, accepts, rejects, hitrate = [], [], [], []
        for r in cur.fetchall():
            labels.append(r["bucket"].isoformat())
            accepts.append(r["accepts"])
            rejects.append(r["rejects"])
            hitrate.append(round(r["hits"] / r["total"] * 100, 1) if r["total"] else None)
        out["auth"] = {"labels": labels, "accepts": accepts,
                       "rejects": rejects, "cache_hit_rate": hitrate}

        # Vendor + SSID breakdowns.
        cur.execute("""
            SELECT COALESCE(NULLIF(vendor, ''), 'unknown') AS k, count(*) AS n
            FROM auth_log WHERE created_at > now() - %s::interval
            GROUP BY k ORDER BY n DESC
        """, (win,))
        rows = cur.fetchall()
        out["vendor"] = {"labels": [r["k"] for r in rows], "counts": [r["n"] for r in rows]}

        cur.execute("""
            SELECT COALESCE(NULLIF(ssid, ''), 'unknown') AS k, count(*) AS n
            FROM auth_log WHERE created_at > now() - %s::interval
            GROUP BY k ORDER BY n DESC LIMIT 12
        """, (win,))
        rows = cur.fetchall()
        out["ssid"] = {"labels": [r["k"] for r in rows], "counts": [r["n"] for r in rows]}

        # Top talkers by total bytes (username if present, else MAC).
        cur.execute("""
            SELECT COALESCE(NULLIF(username, ''), mac, 'unknown') AS who,
                   SUM(in_octets) AS i, SUM(out_octets) AS o
            FROM acct_sessions WHERE updated_at > now() - %s::interval
            GROUP BY who ORDER BY SUM(in_octets) + SUM(out_octets) DESC LIMIT 10
        """, (win,))
        rows = cur.fetchall()
        out["top_talkers"] = {
            "labels": [r["who"] for r in rows],
            "in":     [int(r["i"] or 0) for r in rows],
            "out":    [int(r["o"] or 0) for r in rows],
        }

        # Session duration histogram.
        cur.execute("""
            SELECT width_bucket(session_time, ARRAY[300, 1800, 7200, 28800]) AS b,
                   count(*) AS n
            FROM acct_sessions WHERE updated_at > now() - %s::interval
            GROUP BY b ORDER BY b
        """, (win,))
        hist = {r["b"]: r["n"] for r in cur.fetchall()}
        dur_labels = ["<5m", "5–30m", "30m–2h", "2–8h", ">8h"]
        out["duration"] = {"labels": dur_labels,
                           "counts": [hist.get(i, 0) for i in range(5)]}

        # Concurrency + throughput from the rollup samples.
        cur.execute("""
            SELECT ts, active_sessions, total_in, total_out
            FROM metrics_rollup
            WHERE ts > now() - %s::interval
            ORDER BY ts
        """, (win,))
        r_labels, active, tin, tout = [], [], [], []
        prev = None
        for r in cur.fetchall():
            r_labels.append(r["ts"].isoformat())
            active.append(r["active_sessions"])
            if prev is None:
                tin.append(0.0); tout.append(0.0)
            else:
                dt = (r["ts"] - prev["ts"]).total_seconds() or 1
                # Clamp: retention purges can drop cumulative totals.
                tin.append(round(max(0, r["total_in"]  - prev["total_in"])  / dt, 1))
                tout.append(round(max(0, r["total_out"] - prev["total_out"]) / dt, 1))
            prev = r
        out["rollup"] = {"labels": r_labels, "active": active,
                         "in_bps": tin, "out_bps": tout}

    return out


def _compute_pmk(psk: str, ssid: str) -> str:
    pmk = hashlib.pbkdf2_hmac('sha1', psk.encode(), ssid.encode(), 4096, 32)
    return base64.b64encode(pmk).decode()


# -- dashboard ----------------------------------------------------------------

def get_stats():
    with _get_conn().cursor() as cur:
        cur.execute("SELECT COUNT(*) FROM accounts")
        accounts = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM pairwise_master_keys")
        psks = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM auth_log WHERE created_at > now() - interval '24h'")
        auths = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM auth_log WHERE result = 'reject' AND created_at > now() - interval '24h'")
        rejects = cur.fetchone()[0]
        cur.execute("SELECT COUNT(*) FROM acct_sessions WHERE stopped_at IS NULL")
        active = cur.fetchone()[0]
    return {'accounts': accounts, 'psks': psks, 'auths_24h': auths,
            'rejects_24h': rejects, 'active_sessions': active}


def get_recent_logs(n=10):
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM auth_log ORDER BY created_at DESC LIMIT %s", (n,))
        return cur.fetchall()


# -- accounts -----------------------------------------------------------------

def get_accounts():
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT a.*,
                   COUNT(DISTINCT pmk.id)  AS psk_count,
                   COUNT(DISTINCT mb.mac)  AS device_count
            FROM accounts a
            LEFT JOIN pairwise_master_keys pmk
                   ON pmk.account_id = a.id AND pmk.revoked_at IS NULL
            LEFT JOIN mac_bindings mb ON mb.pmk_id = pmk.id
            GROUP BY a.id
            ORDER BY a.created_at DESC
        """)
        return cur.fetchall()


def get_account(account_id):
    conn = _get_conn()
    with conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("SELECT * FROM accounts WHERE id = %s", (account_id,))
        account = cur.fetchone()
        if account is None:
            return None, []
        cur.execute("""
            SELECT pmk.*,
                   COALESCE(
                       array_agg(mb.mac ORDER BY mb.created_at)
                       FILTER (WHERE mb.mac IS NOT NULL),
                       '{}'
                   ) AS macs
            FROM pairwise_master_keys pmk
            LEFT JOIN mac_bindings mb ON mb.pmk_id = pmk.id
            WHERE pmk.account_id = %s AND pmk.revoked_at IS NULL
            GROUP BY pmk.id
            ORDER BY pmk.id DESC
        """, (account_id,))
        psks = cur.fetchall()
    return account, psks


def create_account(username, email):
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO accounts (username, email)
            VALUES (%s, %s)
            RETURNING id
        """, (username, email or None))
        row = cur.fetchone()
    conn.commit()
    return row[0]


def delete_account(account_id):
    """Hard-delete the account (cascades to its PSKs and MAC bindings) and tell
    the RADIUS process to flush its cache, since the removed PMK ids are gone."""
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM accounts WHERE id = %s", (account_id,))
        cur.execute("SELECT pg_notify(%s, 'all')", (REVOKE_CHANNEL,))
    conn.commit()


# -- PSKs ---------------------------------------------------------------------

def add_psk(account_id, psk, ssid, vlan_id=None):
    pmk_b64 = _compute_pmk(psk, ssid)
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO pairwise_master_keys (account_id, psk, ssid, pmk_b64, vlan_id)
            VALUES (%s, %s, %s, %s, %s)
            RETURNING id
        """, (account_id, psk, ssid, pmk_b64, int(vlan_id) if vlan_id else None))
        row = cur.fetchone()
    conn.commit()
    return row[0]


def revoke_psk(psk_id):
    """Soft-delete: stamp revoked_at so the PSK stops authenticating but its
    history (auth_log, bound MACs) is preserved for audit. Notifies the RADIUS
    process to evict any cached copy of this PMK immediately."""
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE pairwise_master_keys SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL",
            (psk_id,),
        )
        cur.execute("SELECT pg_notify(%s, %s)", (REVOKE_CHANNEL, str(psk_id)))
    conn.commit()


# -- accounting sessions ------------------------------------------------------

def get_sessions(limit=200, active_only=False):
    where = "WHERE stopped_at IS NULL" if active_only else ""
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"""
            SELECT * FROM acct_sessions
            {where}
            ORDER BY (stopped_at IS NULL) DESC, updated_at DESC
            LIMIT %s
        """, (limit,))
        return cur.fetchall()


def get_account_sessions(account_id, limit=50):
    """Sessions for an account, resolved through its PSKs' learned MAC bindings."""
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT DISTINCT s.*
            FROM acct_sessions s
            JOIN mac_bindings mb           ON mb.mac = s.mac
            JOIN pairwise_master_keys pmk  ON pmk.id = mb.pmk_id
            WHERE pmk.account_id = %s
            ORDER BY (s.stopped_at IS NULL) DESC, s.updated_at DESC
            LIMIT %s
        """, (account_id, limit))
        return cur.fetchall()


# -- logs ---------------------------------------------------------------------

def get_logs(limit=200, offset=0, mac=None, ssid=None, result=None):
    filters, params = [], []
    if mac:
        filters.append("mac ILIKE %s")
        params.append(f"%{mac}%")
    if ssid:
        filters.append("ssid ILIKE %s")
        params.append(f"%{ssid}%")
    if result:
        filters.append("result = %s")
        params.append(result)
    where = ("WHERE " + " AND ".join(filters)) if filters else ""
    params += [limit, offset]
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"""
            SELECT * FROM auth_log
            {where}
            ORDER BY created_at DESC
            LIMIT %s OFFSET %s
        """, params)
        return cur.fetchall()
