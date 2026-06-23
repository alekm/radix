-- 003 — RADIUS accounting sessions. Idempotent.

CREATE TABLE IF NOT EXISTS acct_sessions (
    id              SERIAL PRIMARY KEY,
    session_id      TEXT NOT NULL,           -- Acct-Session-Id (unique per NAS)
    mac             TEXT,                    -- Calling-Station-Id (normalized)
    username        TEXT,                    -- User-Name
    ssid            TEXT,                    -- from Called-Station-Id
    nas_ip          TEXT,                    -- NAS-IP-Address
    framed_ip       TEXT,                    -- Framed-IP-Address
    in_octets       BIGINT NOT NULL DEFAULT 0,   -- input octets (incl. gigawords)
    out_octets      BIGINT NOT NULL DEFAULT 0,   -- output octets (incl. gigawords)
    session_time    INTEGER NOT NULL DEFAULT 0,  -- Acct-Session-Time, seconds
    status          TEXT,                    -- start | interim | stop
    terminate_cause TEXT,                    -- Acct-Terminate-Cause
    started_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    stopped_at      TIMESTAMPTZ,
    UNIQUE (session_id)
);

CREATE INDEX IF NOT EXISTS idx_acct_mac        ON acct_sessions (mac);
CREATE INDEX IF NOT EXISTS idx_acct_status     ON acct_sessions (status);
CREATE INDEX IF NOT EXISTS idx_acct_updated_at ON acct_sessions (updated_at DESC);
