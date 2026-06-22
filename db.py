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


def lookup_pmk(mac, ssid):
    """Return {'pmk_bytes', 'psk', 'vlan_id'} or None."""
    sql = """
        SELECT pmk.psk, pmk.pmk_b64, pmk.vlan_id
        FROM pairwise_master_keys pmk
        JOIN accounts a ON a.id = pmk.account_id
        WHERE a.mac = %s AND pmk.ssid = %s
        ORDER BY pmk.id DESC
        LIMIT 1
    """
    with _get_conn().cursor(cursor_factory=psycopg2.extras.DictCursor) as cur:
        cur.execute(sql, (mac, ssid))
        row = cur.fetchone()
    if row is None:
        return None
    return {
        'pmk_bytes': base64.b64decode(row['pmk_b64']),
        'psk':       row['psk'],
        'vlan_id':   row['vlan_id'],
    }


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
        pass  # never let logging break auth
