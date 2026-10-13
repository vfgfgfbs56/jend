# M3 — Jend Encrypted Sync (JESP) baseline

Status: implementation draft; compile/integration/fuzz testing is intentionally deferred to the dedicated test pass.

## Goal

Synchronize `.jend` conversations between multiple devices while treating the synchronization service as an untrusted blob relay.

A compromised sync server may learn unavoidable transport metadata such as account access times, approximate object sizes and IP-layer information. It must not learn:

- message plaintext;
- conversation titles;
- local message timestamps;
- `.jend` record commitments/signatures;
- conversation IDs or graph structure;
- sync epoch secrets;
- conversation keys;
- AI prompts/responses.

The sync layer adds an outer encryption envelope around already-encrypted `.jend` records specifically to hide `.jend` metadata from the server.

## Object model

The server stores immutable opaque objects under random 256-bit IDs:

```text
SyncObjectId = random(256 bits)

server value =
    JESO magic/version
    random XChaCha nonce
    ciphertext
```

The following fields are encrypted *inside* the ciphertext:

```text
sync epoch
object kind
conversation graph parents
conversation id
Jend record bytes
sync index
DeviceSet snapshot
padding
```

The object ID is authenticated as AEAD associated data, so moving ciphertext from one object ID to another fails decryption.

Object plaintext is padded into coarse buckets before encryption. Exact lengths are therefore not exposed, although the server still learns the bucket size.

## Sync epochs

The sync key is **not** deterministically derived forever from the Account Root Key.

Every DeviceSet epoch owns a fresh random 256-bit `SyncEpochSecret`:

```text
DeviceSet epoch 7  -> random SyncEpochSecret_7
DeviceSet epoch 8  -> random SyncEpochSecret_8
```

When a device is removed, the remaining trusted devices create a new random epoch secret and never deliver it to the removed device.

This provides the critical property:

```text
knowledge of SyncEpochSecret_7
    does NOT derive
SyncEpochSecret_8
```

Existing trusted devices retain older epoch keys so historical encrypted objects remain readable. A newly approved device may receive an authorized historical keyring if the user chooses full-history synchronization.

## Device identity

The sync subsystem uses a separated device identity:

```text
Ed25519 signing key
X25519 key-agreement key
```

Both private keys live in Jend Vault / platform secure storage and have no secret-export API.

The public device identity contains:

```text
device_id
sync Ed25519 public key
X25519 public key
.jend message-signing Ed25519 public key
```

`device_id` is a domain-separated digest of all three public keys. This binds a
trusted sync-device record to the key that signs the inner `.jend` history; sync
trust and message-signature trust cannot silently drift apart.

## DeviceSet

The server is not authoritative for trusted devices.

A `DeviceSet` contains:

```text
account_id
epoch
previous_device_set_hash
sorted active device public identities
```

Genesis is self-signed by the first device. Every later transition:

1. increments the epoch exactly once;
2. commits to the previous DeviceSet hash;
3. is signed by a device that belonged to the previous DeviceSet;
4. rotates the sync epoch secret.

Therefore an API administrator cannot simply insert an attacker public key into the database and make a Jend client trust it.

### Revocation

If device C is removed:

```text
DeviceSet 17: A B C
        |
        | signed transition by trusted A/B
        v
DeviceSet 18: A B
        |
        +-- fresh SyncEpochSecret_18
```

C can still read data it legitimately obtained before revocation. It cannot derive future epoch keys.

## Device-to-device key envelope

A trusted device transfers synchronization state to another approved device through `KeyEnvelope`.

The envelope uses:

- ephemeral X25519 key agreement;
- HKDF-SHA-256 key derivation;
- XChaCha20-Poly1305 encryption;
- Ed25519 sender signature;
- account/epoch/sender/recipient/ephemeral key binding in the transcript.

Encrypted payload:

```text
historical SyncKeyring (authorized history only)
verifiable DeviceSet history
current DeviceSet hash
latest encrypted index object id
index generation
```

The relay only needs to move the envelope bytes. It does not obtain the keyring.

## Local state

`LocalSyncState` is persisted by Vault only after being encrypted by the Account Root Key.

It contains:

```text
account id
current signed DeviceSet
verifiable DeviceSet history
historical sync keyring
latest index object id
highest accepted index generation
```

This gives the local client an anti-rollback anchor. A server can withhold data (availability attack), but cannot silently fabricate a higher valid local generation or decrypt the state.

## Encrypted sync index

The sync index is signed by a trusted sync device and then placed inside an encrypted `SyncObject`.

It contains:

```text
generation
DeviceSet epoch + hash
conversation IDs
conversation DAG heads
Lamport maxima
conversation seeds wrapped by the referenced SyncEpochSecret
```

The relay cannot inspect this index. A newly trusted device receives an authorized
sync keyring, opens the encrypted index, unwraps conversation seeds locally, and
then derives the per-device sender ratchets required to read history.

On an established device, the Vault remembers the highest accepted generation and
object ID. An older generation is rejected as rollback; a different object at the
same generation is rejected as a fork.

For a new device, the trusted-device bootstrap envelope carries the expected generation and latest object ID.

## Concurrent multi-device chat DAG

A linear sequence alone is unsafe when two devices are offline and both append messages.

Jend therefore synchronizes signed DAG nodes:

```text
             desktop B
            /
root -> A --
            \
             phone C
```

Each encrypted node contains:

```text
conversation id
parents[]
author_previous
author device id
trust_epoch
per-device monotonic counter
Lamport clock
already encrypted .jend record
sync-device signature
```

Every device derives an independent sender-ratchet chain from the common
conversation seed plus its cryptographic device ID. Two offline devices can
therefore both create their first new message without reusing a message key.
`trust_epoch` makes old messages remain verifiable after a later device revocation
while preventing a revoked device from presenting future nodes as currently trusted.

`author_previous` creates a strict second chain per device. This detects duplicate/forked per-device counters in the received graph.

A deterministic topological order uses causal dependencies first and the stable tuple

```text
(lamport, author_device_id, device_counter, node_id)
```

for independent ready nodes.

## Why `.jend` is encrypted again for sync

The inner `.jend` record already protects message plaintext. However its outer record format can expose cryptographic metadata such as commitments, signatures and exact record relationships.

JESP therefore uses two layers:

```text
message plaintext
      |
      v
.jend conversation encryption/signature
      |
      v
JESP epoch-encrypted opaque object
      |
      v
untrusted server/object storage
```

This is deliberate metadata protection, not a replacement for `.jend` message encryption.

## Relay / cloud modes

The same encrypted object format supports three storage policies.

### Direct

Devices exchange encrypted objects directly. Server chat storage is zero.

### Relay (planned default)

The server temporarily stores encrypted objects until active devices acknowledge
them. Relay ACKs are device-signed and bound to the object ID and DeviceSet epoch.
The current protocol caps object retention at 30 days; an honest relay may delete
earlier once all active devices have acknowledged the object. A malicious relay
can still perform an availability attack by deleting/withholding ciphertext, but
it cannot forge plaintext or keys.

### Cloud

The user explicitly enables persistent encrypted backup. The cloud still receives only JESP ciphertext. Full data recovery additionally requires user-controlled recovery key material; account-password recovery alone is not enough.

## Important security limitation: malicious client code and covert channels

OS sandboxing removes ordinary network APIs from plaintext/key-owning processes, but it is **not a mathematical proof against intentionally malicious code**. A process that sees plaintext and is allowed to influence any externally observable ciphertext/object can encode information into that output as a covert channel.

Therefore developer-resistance relies on *both*:

1. process isolation / narrow IPC; and
2. production release governance: independent review, reproducible builders, release transparency and threshold signing.

No single developer is allowed to modify, build, authorize and distribute a privacy-sensitive production binary alone.

## Server data model target

A sync relay should need only small control-plane rows plus opaque storage:

```text
accounts
  user_id
  username
  opaque password credential

sync_heads
  user_id
  opaque_latest_object_id
  storage_etag / CAS token

relay_mailboxes
  random_mailbox_id
  opaque_blob_location
  expires_at
```

Message bodies, graph nodes and chat indexes are not parsed into database columns.

## Still required

- complete crash-safe DeviceSet rotation + key-envelope distribution state machine;
- message-node batching/segments to reduce object-store operation cost;
- persistent cloud-backup recovery wrapping;
- direct P2P transport;
- platform secure-keystore adapters;
- compile/unit/property/fuzz/crash/byzantine-relay tests;
- external cryptographic review before production.
