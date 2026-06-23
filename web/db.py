import base64
import hashlib
import os
import psycopg2
import psycopg2.extras

_conn = None

REVOKE_CHANNEL = 'radix_revoke'


def _get_conn():
    global _conn
    if _conn is None or _conn.closed:
        _conn = psycopg2.connect(
            host=os.environ['DB_HOST'],
            dbname=os.environ['DB_NAME'],
            user=os.environ['DB_USER'],
            password=os.environ['DB_PASSWORD'],
        )
        _conn.autocommit = False
    return _conn


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
    return {'accounts': accounts, 'psks': psks, 'auths_24h': auths, 'rejects_24h': rejects}


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
