-- M5.1 device bootstrap, trust-set CAS, and binding replay barriers.

CREATE TABLE IF NOT EXISTS registration_device_bootstraps (
    bootstrap_digest BYTEA PRIMARY KEY CHECK (octet_length(bootstrap_digest)=32),
    account_id UUID NOT NULL UNIQUE REFERENCES accounts(account_id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS registration_device_bootstraps_expiry
    ON registration_device_bootstraps(expires_at);

CREATE TABLE IF NOT EXISTS consumed_device_binding_challenges (
    challenge_digest BYTEA PRIMARY KEY CHECK (octet_length(challenge_digest)=32),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS consumed_device_binding_challenges_expiry
    ON consumed_device_binding_challenges(expires_at);

-- Registration creates accounts with status=1 (pending device genesis).
-- Atomic genesis consumption flips status to 0. Expired pending accounts may be
-- garbage-collected after a safety delay if they have no DeviceSet.
