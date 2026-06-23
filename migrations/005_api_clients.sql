-- 005 — API client credentials (key + hashed secret) for programmatic access.
-- Idempotent. The plaintext secret is shown once at creation; only its hash is stored.

CREATE TABLE IF NOT EXISTS api_clients (
    id           SERIAL PRIMARY KEY,
    name         TEXT NOT NULL,
    client_key   TEXT NOT NULL UNIQUE,    -- public identifier (rdx_...)
    secret_hash  TEXT NOT NULL,           -- sha256(secret) hex
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ,
    revoked_at   TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_api_clients_active ON api_clients (client_key) WHERE revoked_at IS NULL;
