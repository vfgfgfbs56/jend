-- Jend control-plane schema baseline.
-- NO messages, conversation titles, prompts, AI answers, conversation keys,
-- SyncRootKeys, AccountRootKeys, or device private keys belong in this DB.

CREATE TABLE accounts (
    account_id UUID PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    opaque_password_file BYTEA NOT NULL,
    auth_epoch BIGINT NOT NULL DEFAULT 0 CHECK (auth_epoch >= 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    status SMALLINT NOT NULL DEFAULT 0
);

CREATE TABLE device_sets (
    account_id UUID PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    epoch BIGINT NOT NULL CHECK (epoch >= 0),
    signed_device_set BYTEA NOT NULL,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- One-time nonces produced by a trusted-device recovery approval.
-- The unique key is the replay barrier. Expired rows may be garbage-collected
-- after a safety window, but a consumed nonce must not become reusable.
CREATE TABLE consumed_recovery_grants (
    grant_nonce BYTEA PRIMARY KEY CHECK (octet_length(grant_nonce) = 32),
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    request_id BYTEA NOT NULL CHECK (octet_length(request_id) = 32),
    consumed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Application sessions/capabilities will carry auth_epoch. Password reset
-- increments it so previously issued sessions fail closed after refresh/check.
CREATE INDEX consumed_recovery_grants_account_idx
    ON consumed_recovery_grants(account_id, consumed_at DESC);

-- Required transaction for a password reset (conceptual):
-- BEGIN;
--   INSERT INTO consumed_recovery_grants (...) VALUES (...); -- unique or fail
--   UPDATE accounts
--      SET opaque_password_file = $new_file,
--          auth_epoch = auth_epoch + 1
--    WHERE account_id = $account AND username = $username;
-- COMMIT;

-- ---------------------------------------------------------------------------
-- M4 model store control plane.
-- Public model metadata is allowed here. Chat contents / conversation keys are not.
-- The slot CHECK + composite primary key make >3 active entitlements impossible
-- at the database boundary, independent of application bugs.

CREATE TABLE model_catalog (
    model_id UUID PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    display_name TEXT NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE model_releases (
    manifest_digest BYTEA PRIMARY KEY CHECK (octet_length(manifest_digest) = 32),
    model_id UUID NOT NULL REFERENCES model_catalog(model_id) ON DELETE CASCADE,
    release_sequence BIGINT NOT NULL CHECK (release_sequence >= 0),
    signed_manifest BYTEA NOT NULL,
    status SMALLINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (model_id, release_sequence)
);

CREATE TABLE model_entitlements (
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    slot SMALLINT NOT NULL CHECK (slot BETWEEN 0 AND 2),
    model_id UUID NOT NULL REFERENCES model_catalog(model_id),
    entitlement_epoch BIGINT NOT NULL DEFAULT 0 CHECK (entitlement_epoch >= 0),
    pinned_manifest_digest BYTEA NULL CHECK (
        pinned_manifest_digest IS NULL OR octet_length(pinned_manifest_digest) = 32
    ),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, slot),
    UNIQUE (account_id, model_id),
    FOREIGN KEY (pinned_manifest_digest)
        REFERENCES model_releases(manifest_digest)
);

-- Installation state is separate from entitlement state. Selecting a model once
-- may allow it on several trusted devices without consuming more account slots.
CREATE TABLE device_model_installations (
    account_id UUID NOT NULL REFERENCES accounts(account_id) ON DELETE CASCADE,
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    model_id UUID NOT NULL REFERENCES model_catalog(model_id),
    manifest_digest BYTEA NOT NULL REFERENCES model_releases(manifest_digest),
    installation_generation BIGINT NOT NULL DEFAULT 0 CHECK (installation_generation >= 0),
    state SMALLINT NOT NULL CHECK (state BETWEEN 0 AND 4),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, device_id, model_id)
);

CREATE INDEX model_entitlements_account_idx
    ON model_entitlements(account_id, slot);

CREATE INDEX device_model_installations_account_idx
    ON device_model_installations(account_id, device_id);

-- Slot replacement must be compare-and-swap so two clients cannot race the same
-- entitlement silently. Conceptual transaction:
-- BEGIN;
--   UPDATE model_entitlements
--      SET model_id = $new_model,
--          pinned_manifest_digest = $manifest,
--          entitlement_epoch = entitlement_epoch + 1,
--          updated_at = now()
--    WHERE account_id = $account
--      AND slot = $slot
--      AND entitlement_epoch = $expected_epoch;
--   -- require exactly one affected row (or insert slot with epoch 0)
-- COMMIT;
