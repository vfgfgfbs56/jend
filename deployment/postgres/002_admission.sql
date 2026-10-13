-- M4.8: transactional registration admission backstop.
CREATE TABLE IF NOT EXISTS admission_buckets (
    bucket_key BYTEA PRIMARY KEY CHECK (octet_length(bucket_key) = 32),
    tokens INTEGER NOT NULL CHECK (tokens BETWEEN 0 AND 5),
    window_start TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE TABLE IF NOT EXISTS admission_used_challenges (
    challenge_id BYTEA PRIMARY KEY CHECK (octet_length(challenge_id) = 16),
    expires_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX IF NOT EXISTS admission_used_challenges_expiry
    ON admission_used_challenges(expires_at);
-- Prune expired rows with a scheduled DB job, outside the request path.
