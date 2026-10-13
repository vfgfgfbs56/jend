-- Jend temporary encrypted relay baseline.
-- `blob_location` points to opaque JESP bytes in object storage. The database
-- never parses message nodes, sync indexes, conversation ids, titles or keys.

CREATE TABLE sync_mailboxes (
    account_id UUID PRIMARY KEY REFERENCES accounts(account_id) ON DELETE CASCADE,
    mailbox_id BYTEA NOT NULL UNIQUE CHECK (octet_length(mailbox_id) = 32),
    latest_index_object_id BYTEA CHECK (
        latest_index_object_id IS NULL OR octet_length(latest_index_object_id) = 32
    ),
    -- Server-side CAS revision only. It is not the encrypted client generation.
    head_revision BIGINT NOT NULL DEFAULT 0 CHECK (head_revision >= 0),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE relay_objects (
    mailbox_id BYTEA NOT NULL REFERENCES sync_mailboxes(mailbox_id) ON DELETE CASCADE,
    object_id BYTEA NOT NULL CHECK (octet_length(object_id) = 32),
    device_set_epoch BIGINT NOT NULL CHECK (device_set_epoch >= 0),
    blob_location TEXT NOT NULL,
    byte_length BIGINT NOT NULL CHECK (byte_length > 0),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (mailbox_id, object_id)
);

CREATE INDEX relay_objects_expiry_idx ON relay_objects(expires_at);

-- Signed ACKs allow an honest relay to delete a temporary object after every
-- currently active device acknowledged it. Early deletion by a malicious relay
-- remains an availability attack, not a confidentiality break.
CREATE TABLE relay_acks (
    mailbox_id BYTEA NOT NULL,
    object_id BYTEA NOT NULL,
    device_id BYTEA NOT NULL CHECK (octet_length(device_id) = 16),
    ack_nonce BYTEA NOT NULL CHECK (octet_length(ack_nonce) = 32),
    signature BYTEA NOT NULL CHECK (octet_length(signature) = 64),
    acked_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (mailbox_id, object_id, device_id),
    FOREIGN KEY (mailbox_id, object_id)
        REFERENCES relay_objects(mailbox_id, object_id) ON DELETE CASCADE
);
