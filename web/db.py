import base64
import hashlib
import hmac
import os
import secrets
from contextlib import contextmanager
import psycopg2
import psycopg2.extras

_conn = None

REVOKE_CHANNEL = 'radix_revoke'

# A session is "active" only if it's open AND has sent an interim update within
# this window — so sessions whose Stop was lost (device gone, NAS reboot) age out
# of the active count instead of lingering forever. Set >= 2x the AP's interim
# interval. Set to 0 to disable (active = any open session) when the controller
# doesn't send interim updates.
_STALE_MINUTES = int(os.environ.get("SESSION_STALE_MINUTES", 30))


def _active_expr(alias=""):
    """SQL boolean for an 'active' session, plus its bind params. With the stale
    window disabled (<= 0), 'active' is simply 'open' (no Stop received)."""
    a = (alias + ".") if alias else ""
    if _STALE_MINUTES > 0:
        return (f"({a}stopped_at IS NULL AND {a}updated_at > now() - make_interval(mins => %s))",
                [_STALE_MINUTES])
    return f"({a}stopped_at IS NULL)", []


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
        # Autocommit so a failed statement can't leave the shared connection in
        # an aborted-transaction state that wedges every later request. Each
        # write here is a single statement, so per-statement commit is fine.
        _conn.autocommit = True
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
        expr, p = _active_expr()
        cur.execute(f"""
            INSERT INTO metrics_rollup (active_sessions, total_in, total_out)
            SELECT
                count(*) FILTER (WHERE {expr}),
                COALESCE(SUM(in_octets), 0),
                COALESCE(SUM(out_octets), 0)
            FROM acct_sessions
        """, p)


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
        expr, p = _active_expr()
        cur.execute(f"SELECT COUNT(*) FROM acct_sessions WHERE {expr}", p)
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


def update_psk_vlan(psk_id, vlan_id):
    """Change a PSK's VLAN. Safe — the PMK depends on psk+ssid, not the VLAN.
    NOTIFY evicts any cached entry so the new VLAN applies on the next auth."""
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE pairwise_master_keys SET vlan_id = %s WHERE id = %s AND revoked_at IS NULL",
            (int(vlan_id) if vlan_id else None, psk_id),
        )
        cur.execute("SELECT pg_notify(%s, %s)", (REVOKE_CHANNEL, str(psk_id)))
    conn.commit()


def rekey_psk(psk_id, new_psk):
    """Replace a PSK's key: recompute the PMK, clear its learned MAC bindings
    (the device must reconfigure), and evict the cached PMK. Returns False if
    the PSK doesn't exist / is revoked."""
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute("SELECT ssid FROM pairwise_master_keys WHERE id = %s AND revoked_at IS NULL", (psk_id,))
        row = cur.fetchone()
        if not row:
            return False
        pmk_b64 = _compute_pmk(new_psk, row[0])
        cur.execute(
            "UPDATE pairwise_master_keys SET psk = %s, pmk_b64 = %s WHERE id = %s",
            (new_psk, pmk_b64, psk_id),
        )
        cur.execute("DELETE FROM mac_bindings WHERE pmk_id = %s", (psk_id,))
        cur.execute("SELECT pg_notify(%s, %s)", (REVOKE_CHANNEL, str(psk_id)))
    conn.commit()
    return True


def update_account(account_id, username, email):
    """Rename an account / change its email. Metadata only; no effect on auth."""
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE accounts SET username = %s, email = %s WHERE id = %s",
            (username, email or None, account_id),
        )
    conn.commit()


# -- API clients --------------------------------------------------------------

def _hash_secret(secret):
    return hashlib.sha256(secret.encode()).hexdigest()


def generate_api_credentials():
    """Return (client_key, secret). The secret is shown once; only its hash is stored."""
    return "rdx_" + secrets.token_hex(8), secrets.token_urlsafe(32)


def create_api_client(name, client_key, secret):
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute(
            "INSERT INTO api_clients (name, client_key, secret_hash) VALUES (%s, %s, %s) RETURNING id",
            (name, client_key, _hash_secret(secret)),
        )
        row = cur.fetchone()
    conn.commit()
    return row[0]


def get_api_clients():
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute("""
            SELECT id, name, client_key, created_at, last_used_at, revoked_at
            FROM api_clients ORDER BY created_at DESC
        """)
        return cur.fetchall()


def revoke_api_client(client_id):
    conn = _get_conn()
    with conn.cursor() as cur:
        cur.execute(
            "UPDATE api_clients SET revoked_at = now() WHERE id = %s AND revoked_at IS NULL",
            (client_id,),
        )
    conn.commit()


def verify_api_client(client_key, secret):
    """Return the client id if key+secret match an active client, else None.
    Constant-time comparison; stamps last_used_at on success. (For the future
    JSON API / MCP — not yet enforced on any route.)"""
    if not client_key or not secret:
        return None
    with _get_conn().cursor() as cur:
        cur.execute(
            "SELECT id, secret_hash FROM api_clients WHERE client_key = %s AND revoked_at IS NULL",
            (client_key,),
        )
        row = cur.fetchone()
    if not row or not hmac.compare_digest(row[1], _hash_secret(secret)):
        return None
    try:
        conn = _get_conn()
        with conn.cursor() as cur:
            cur.execute("UPDATE api_clients SET last_used_at = now() WHERE id = %s", (row[0],))
        conn.commit()
    except Exception:
        pass
    return row[0]


# -- accounting sessions ------------------------------------------------------

def get_sessions(limit=200, active_only=False):
    expr, p = _active_expr("s")
    where = "WHERE is_active" if active_only else ""
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"""
            SELECT * FROM (
                SELECT s.*, a.id AS account_id, a.username AS account_username,
                       {expr} AS is_active
                FROM acct_sessions s
                LEFT JOIN LATERAL (
                    SELECT acc.id, acc.username
                    FROM mac_bindings mb
                    JOIN pairwise_master_keys pmk ON pmk.id = mb.pmk_id
                    JOIN accounts acc           ON acc.id = pmk.account_id
                    WHERE mb.mac = s.mac
                    ORDER BY pmk.id DESC
                    LIMIT 1
                ) a ON true
            ) t
            {where}
            ORDER BY is_active DESC, updated_at DESC
            LIMIT %s
        """, p + [limit])
        return cur.fetchall()


def get_account_sessions(account_id, limit=50):
    """Sessions for an account, resolved through its PSKs' learned MAC bindings."""
    expr, p = _active_expr("s")
    with _get_conn().cursor(cursor_factory=psycopg2.extras.RealDictCursor) as cur:
        cur.execute(f"""
            SELECT s.*, {expr} AS is_active
            FROM acct_sessions s
            JOIN mac_bindings mb           ON mb.mac = s.mac
            JOIN pairwise_master_keys pmk  ON pmk.id = mb.pmk_id
            WHERE pmk.account_id = %s
            GROUP BY s.id
            ORDER BY is_active DESC, s.updated_at DESC
            LIMIT %s
        """, p + [account_id, limit])
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
