import base64
import hashlib
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
            SELECT a.*, COUNT(pmk.id) AS psk_count
            FROM accounts a
            LEFT JOIN pairwise_master_keys pmk ON pmk.account_id = a.id
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
            SELECT * FROM pairwise_master_keys
            WHERE account_id = %s
            ORDER BY id DESC
        """, (account_id,))
        psks = cur.fetchall()
    return account, psks


def create_account(username, email, mac):
    mac = mac.lower().replace('-', ':').strip()
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("""
            INSERT INTO accounts (username, email, mac)
            VALUES (%s, %s, %s)
            RETURNING id
        """, (username, email or None, mac))
        row = cur.fetchone()
    conn.commit()
    return row[0]


def delete_account(account_id):
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM accounts WHERE id = %s", (account_id,))
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
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("DELETE FROM pairwise_master_keys WHERE id = %s", (psk_id,))
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
