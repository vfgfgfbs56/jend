-- One nonce per device/account for proof-of-possession request replay defense.
-- The signed request must be verified before consuming the nonce.
CREATE TABLE IF NOT EXISTS consumed_jreq_nonces (
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    nonce BYTEA NOT NULL CHECK (octet_length(nonce) = 32),
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, device_id, nonce)
);
CREATE INDEX IF NOT EXISTS consumed_jreq_nonces_age
    ON consumed_jreq_nonces(consumed_at);
-- Retain nonce rows longer than the maximum permitted clock skew and TTL.
