CREATE TABLE IF NOT EXISTS accounts (
    id          SERIAL PRIMARY KEY,
    username    TEXT NOT NULL,
    email       TEXT,
    mac         TEXT NOT NULL UNIQUE,   -- client MAC, lowercase colon-separated
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON accounts (mac);

CREATE TABLE IF NOT EXISTS pairwise_master_keys (
    id          SERIAL PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    psk         TEXT NOT NULL,
    ssid        TEXT NOT NULL,
    pmk_b64     TEXT NOT NULL,          -- base64(PBKDF2-HMAC-SHA1(psk, ssid, 4096, 32)), pre-computed by web UI
    wlan_id     TEXT,                   -- vendor WLAN/AP group identifier (optional)
    vlan_id     INTEGER,                -- 802.1Q VLAN tag to assign on accept (optional)
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON pairwise_master_keys (account_id, ssid);

CREATE TABLE IF NOT EXISTS auth_log (
    id          SERIAL PRIMARY KEY,
    mac         TEXT NOT NULL,
    ssid        TEXT,
    vendor      TEXT,                   -- openwifi | tplink | ruckus
    result      TEXT NOT NULL,          -- accept | reject | noop
    cache_hit   BOOLEAN NOT NULL DEFAULT false,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON auth_log (mac);
CREATE INDEX ON auth_log (created_at DESC);
