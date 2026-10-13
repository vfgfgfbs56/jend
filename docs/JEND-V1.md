# JEND container v1 — draft 0

This is the first wire/storage-format draft. It is intentionally small enough to audit and replace before production.

## Goals

- opaque local storage for chat/AI messages;
- canonical parsing, no generic object serializer;
- authenticated encryption;
- signed record commitment;
- encrypted ordering/history metadata;
- tamper-evident chaining;
- room for a later transparency/timestamp proof layer.

## Primitive suite 1

| Purpose | Primitive |
|---|---|
| Payload AEAD | XChaCha20-Poly1305 |
| Key derivation | HKDF-SHA-256 |
| Commitments / key IDs | SHA-256 |
| Device signatures | Ed25519 |
| Randomness | OS CSPRNG |

Jend does not implement those primitives itself.

## Record layout

All integers are big-endian.

```text
OUTER HEADER (72 bytes)
+0   4   magic               "JEND"
+4   2   version             0x0001
+6   2   crypto_suite        0x0001
+8   1   record_type         0x01 = message
+9   1   flags               0 for draft 0
+10  2   reserved            MUST be zero
+12 16   packet_id           random
+28 16   signer_key_id       truncated domain-separated SHA-256(public key)
+44 24   XChaCha nonce       random
+68  4   ciphertext_len      includes Poly1305 tag

CIPHERTEXT (variable)

TRAILER (96 bytes)
+0  32   commitment
+32 64   Ed25519 signature over commitment domain
```

The entire outer header is AEAD associated data.

## Inner message

The following structure is fully encrypted:

```text
u16 inner_version = 1
u8  role           (1=user, 2=assistant, 3=system)
u8  reserved = 0
[16] conversation_id
u64 sequence
u32 epoch
i64 local_unix_ms
[32] previous_commitment
u32 plaintext_len
[..] plaintext
[..] random padding
```

The inner plaintext is padded so the complete encrypted plaintext size is a multiple of 256 bytes.

## Commitment

```text
commitment = SHA-256(
    "JEND/COMMITMENT/V1" ||
    outer_header ||
    ciphertext
)
```

The device signs:

```text
"JEND/SIGNATURE/V1" || commitment
```

The verifying key is trusted from the local account/device registry. A public key carried alongside an untrusted record is not sufficient to establish identity.

## History chaining

Message N contains `previous_commitment = commitment(N-1)` inside the encrypted body.

The first record uses 32 zero bytes.

For a trusted head/root, mutation of history is detectable. Future work will periodically anchor roots outside the device using an append-only transparency/timestamp service.

## Ratchet draft

A random 32-byte conversation seed derives `chain_key_0`.

For sequence N, HKDF expands the current chain key into 64 bytes using a domain-separated context containing N:

- first 32 bytes -> `message_key_N`
- second 32 bytes -> `chain_key_(N+1)`

After advancing, the old chain key and consumed message key are zeroized.

This v1 local-storage ratchet is **not** a substitute for Signal Double Ratchet or MLS for multi-party messaging.

## Parsing rules

- reject unknown magic/version/suite/type;
- reject nonzero reserved fields;
- reject records larger than configured limits;
- require the byte stream to contain exactly one canonical record when using `decode_exact`;
- verify commitment before signature/decryption;
- verify device key ID against a separately trusted verifying key;
- verify Ed25519 signature before decryption;
- reject malformed inner lengths and unsupported roles;
- never continue with unauthenticated plaintext.

## Future v1 extensions (not implemented in M0)

- timestamp receipt envelope;
- Merkle inclusion/consistency proofs;
- per-conversation signing identities;
- optional encrypted attachments;
- key-wrap envelope for multi-device recovery;
- streaming container containing multiple framed records.
