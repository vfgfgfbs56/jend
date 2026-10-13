-- M5.0 HTTP authentication safety state. Contains no plaintext password/chat data.
CREATE TABLE IF NOT EXISTS login_ip_buckets (
    bucket_key BYTEA PRIMARY KEY CHECK (octet_length(bucket_key) = 32),
    tokens INTEGER NOT NULL CHECK (tokens BETWEEN 0 AND 30),
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS login_account_buckets (
    bucket_key BYTEA PRIMARY KEY CHECK (octet_length(bucket_key) = 32),
    tokens INTEGER NOT NULL CHECK (tokens BETWEEN 0 AND 10),
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- SHA-256(domain || encrypted login ticket), not the ticket itself.
CREATE TABLE IF NOT EXISTS consumed_login_tickets (
    ticket_digest BYTEA PRIMARY KEY CHECK (octet_length(ticket_digest) = 32),
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX IF NOT EXISTS consumed_login_tickets_expiry
    ON consumed_login_tickets(expires_at);
