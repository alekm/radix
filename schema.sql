CREATE TABLE IF NOT EXISTS accounts (
    id          SERIAL PRIMARY KEY,
    username    TEXT NOT NULL,
    email       TEXT,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS pairwise_master_keys (
    id          SERIAL PRIMARY KEY,
    account_id  INTEGER NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    psk         TEXT NOT NULL,
    ssid        TEXT NOT NULL,
    pmk_b64     TEXT NOT NULL,          -- base64(PBKDF2-HMAC-SHA1(psk, ssid, 4096, 32)), pre-computed by web UI
    wlan_id     TEXT,
    vlan_id     INTEGER,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX ON pairwise_master_keys (ssid);
CREATE INDEX ON pairwise_master_keys (account_id);

-- MACs are discovered dynamically on first auth and bound here.
-- One PSK can bind to multiple MACs (e.g. phone + laptop sharing a PSK).
CREATE TABLE IF NOT EXISTS mac_bindings (
    id          SERIAL PRIMARY KEY,
    pmk_id      INTEGER NOT NULL REFERENCES pairwise_master_keys(id) ON DELETE CASCADE,
    mac         TEXT NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (mac, pmk_id)
);

CREATE INDEX ON mac_bindings (mac);

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
