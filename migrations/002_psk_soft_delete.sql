-- 002 — soft-delete for PSKs + drop the unused wlan_id column. Idempotent.

-- Revoking a PSK now stamps revoked_at instead of deleting the row, preserving
-- the auth_log history and the audit trail of who had access when.
ALTER TABLE pairwise_master_keys ADD COLUMN IF NOT EXISTS revoked_at TIMESTAMPTZ;

-- Auth lookups filter on revoked_at IS NULL; index that hot path.
CREATE INDEX IF NOT EXISTS idx_pmk_active
    ON pairwise_master_keys (ssid)
    WHERE revoked_at IS NULL;

-- wlan_id was never read by any code path.
ALTER TABLE pairwise_master_keys DROP COLUMN IF EXISTS wlan_id;
