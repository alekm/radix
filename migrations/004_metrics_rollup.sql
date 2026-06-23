-- 004 — periodic metrics rollup for the analytics dashboard. Idempotent.
-- One small row sampled every few minutes; charts read this instead of scanning
-- the raw session table, keeping the dashboard light enough for a Raspberry Pi.

CREATE TABLE IF NOT EXISTS metrics_rollup (
    id              SERIAL PRIMARY KEY,
    ts              TIMESTAMPTZ NOT NULL DEFAULT now(),
    active_sessions INTEGER NOT NULL DEFAULT 0,
    total_in        BIGINT NOT NULL DEFAULT 0,   -- cumulative bytes across live+stored sessions
    total_out       BIGINT NOT NULL DEFAULT 0
);

CREATE INDEX IF NOT EXISTS idx_metrics_rollup_ts ON metrics_rollup (ts DESC);
