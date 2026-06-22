import base64
import os
import psycopg2
import psycopg2.extras

_conn = None


def _get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(
            host=os.environ['DB_HOST'],
            dbname=os.environ['DB_NAME'],
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASSWORD'],
        )
    return _conn


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
        WHERE mb.mac = %s AND pmk.ssid = %s
        ORDER BY pmk.id DESC
        LIMIT 1
    """
    with _get_conn().cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute(sql, (mac, ssid))
        row = cur.fetchone()
    return _row(row) if row else None


def lookup_all_pmks(ssid):
    """Slow path: all PMKs for an SSID — iterated to find MIC match for new MACs."""
    sql = """
        SELECT id, psk, pmk_b64, vlan_id
        FROM pairwise_master_keys
        WHERE ssid = %s
        ORDER BY id DESC
    """
    with _get_conn().cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute(sql, (ssid,))
        return [_row(r) for r in cur.fetchall()]


def bind_mac(pmk_id, mac):
    """Persist discovered MAC → PMK mapping after first successful auth."""
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO mac_bindings (pmk_id, mac)
            VALUES (%s, %s)
            ON CONFLICT (mac, pmk_id) DO NOTHING
        """, (pmk_id, mac))
    conn.commit()


def log_auth(mac, ssid, vendor, result, cache_hit=False):
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("""
                INSERT INTO auth_log (mac, ssid, vendor, result, cache_hit)
                VALUES (%s, %s, %s, %s, %s)
            """, (mac, ssid, vendor, result, cache_hit))
        conn.commit()
    except Exception:
        pass
