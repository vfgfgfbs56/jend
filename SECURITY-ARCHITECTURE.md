# Jend security architecture

Status: evolving design baseline for M0–M3. These are required invariants, not a claim of completed formal verification or audit.

## Threat model

Jend assumes attackers may eventually obtain one or more of:

- production API root access;
- PostgreSQL database access;
- object-storage / CDN credentials;
- Cloudflare / edge credentials;
- one developer workstation/account;
- public web application source;
- encrypted `.jend` / JESP objects;
- a removed/stolen device containing historical keys.

The design must avoid turning any one of those compromises into unrestricted plaintext-conversation access.

## Mandatory invariants

### JSI-001 — Server zero-access

Production servers must never possess enough material to decrypt conversation contents.

No normal production schema contains plaintext `messages`, `prompts`, AI responses or conversation keys.

### JSI-002 — Separate plaintext/key processes from Internet processes

- **Vault:** raw key access; cryptographic operations; outbound Internet denied.
- **UI:** narrowly scoped plaintext for rendering; outbound Internet denied.
- **Local AI:** plaintext/model access; outbound Internet denied.
- **Network:** Internet access; raw master/conversation/sync keys and arbitrary plaintext denied.

This removes ordinary direct exfiltration paths and limits accidental compromise blast radius.

### JSI-003 — No raw master-key export API

No normal API equivalent to:

```text
export_master_key()
dump_all_conversation_keys()
dump_all_plaintext()
```

Recovery uses reviewed wrapping/authorization protocols instead.

### JSI-004 — One developer cannot ship a privacy-breaking production build

A source commit is not release authority.

Production target:

```text
review
  -> independent reproducible builders
  -> identical artifact digest
  -> append-only release transparency
  -> threshold signing (initial target 2-of-3)
  -> client fail-closed verification
```

No single human identity may modify, build, authorize and distribute a privacy-sensitive production binary alone.

### JSI-005 — Standard cryptographic primitives; Jend owns composition/encoding

Jend does not invent AES/X25519/Ed25519/Argon2-style primitives.

Current baseline uses established primitives such as:

- XChaCha20-Poly1305;
- HKDF-SHA-256;
- SHA-256 domain-separated commitments;
- Ed25519 signatures;
- X25519 key agreement;
- OPAQUE password authentication.

Suites/formats are versioned for cryptographic agility.

### JSI-006 — Domain separation everywhere

Every signature, KDF and commitment purpose uses a fixed Jend-specific domain label.

### JSI-007 — Password is never a conversation key

The password authenticates the account through OPAQUE. Conversation, Vault and synchronization secrets come from independent CSPRNG material / reviewed key-wrapping flows.

### JSI-008 — Forward-only message-key evolution

Each stored message consumes a fresh message key. Used message keys are zeroized. Compromise of a later chain state must not trivially reconstruct already-discarded message keys.

### JSI-009 — Tamper-evident local history

`.jend` records are authenticated, signed and chained through encrypted previous commitments. Reorder/rewrite/insert attacks fail verification once history is anchored.

### JSI-010 — Server metadata minimization

Inside `.jend`, conversation ID, sequence, role, local timestamp and previous commitment are encrypted.

For cloud/device sync, JESP encrypts the complete `.jend` object again, hiding its public commitment/signature and DAG metadata from the relay. Server object IDs are random, and plaintext is padded into coarse size buckets.

Network-layer facts such as IP addresses, connection times and approximate traffic volume are not magically hidden by JESP and require separate anonymity/traffic-shaping mechanisms if that becomes a product requirement.

### JSI-011 — Server is not the device-trust authority

Multi-device chat trust is controlled by a signed client-side `DeviceSet` chain.

Editing a server database row cannot make an attacker device cryptographically trusted.

Every DeviceSet change increments an epoch and requires authorization by a device trusted in the previous set.

### JSI-012 — Device removal rotates sync secrets

Every DeviceSet change creates a fresh random `SyncEpochSecret`. Old epoch secrets cannot derive future epoch secrets.

A removed device may retain data/keys it legitimately received in the past; Jend cannot remotely erase adversary-controlled storage. It must not receive future epoch secrets.

### JSI-013 — Encrypted synchronization objects are opaque

The sync relay stores immutable ciphertext objects under random IDs. Conversation graph structure, object kind, `.jend` record contents/commitments and sync index are encrypted inside the object.

The object ID is AEAD-bound so ciphertext substitution between IDs fails.

### JSI-014 — Account recovery and data recovery are separate

The server does not store a bare SHA recovery verifier. Recovery credentials use a separate OPAQUE domain/setup.

Recovering an account login does not by itself provide conversation keys. Persistent cloud-data recovery, when implemented, requires separately protected user-controlled recovery material.

## Critical limitation: software sandboxing is not a proof against malicious code

A process that sees plaintext and can influence any externally observable output can theoretically create a covert channel (for example, by encoding information into nonce choices, padding, object timing or ciphertext selection).

Therefore `network=false` for Vault/UI/AI is valuable hardening but **cannot alone prove that intentionally malicious client code cannot leak data**.

The developer-threat requirement is enforced through layers:

1. plaintext/key process network isolation;
2. narrow typed IPC and filesystem isolation;
3. no raw key-export APIs;
4. independent code review;
5. reproducible builds;
6. release transparency;
7. threshold production signing;
8. eventually external security audits.

The realistic security claim is: compromising servers or one developer is insufficient; there is no promise that an attacker controlling the user's kernel/hardware or enough release authorities cannot observe plaintext during legitimate use.

## Sync trust chain

```text
DeviceSet 0
  signed by A
  epoch key K0
      |
      v
DeviceSet 1 (A,B)
  signed by A (trusted in set 0)
  fresh random K1
      |
      v
DeviceSet 2 (A)
  signed by A/B trusted in set 1
  fresh random K2

removed B knows K0,K1 but not K2
```

## Release-security target

```text
source change
   |
mandatory review
   |
static/security checks
   |
independent deterministic builders
   |
matching artifact hashes
   |
release transparency inclusion
   |
threshold signatures
   |
client verifies all checks
   v
install
```

The updater fails closed.

### JSI-015 — Model distribution cannot become a code/content substitution path

Model catalog database rows and CDN objects are not trusted as release authority.
A model is accepted only after verification of a canonical signed manifest,
per-chunk hashes and the final whole-model hash against a pinned release key
policy.

The model store never receives chat plaintext, conversation keys, AccountRootKey
or SyncRootKey. Model download authorization and chat decryption remain separate
security domains.

Production model/release authorization inherits JSI-004: one developer-held key
must not be sufficient to publish a privacy-sensitive runtime/model release.

### JSI-016 — Online download authority is not release authority

The gateway may hold an online key used to issue short-lived model-download
grants. That key is not accepted for model release signatures.

A compromised gateway/download-grant key may cause unauthorized distribution of
an already-valid release, but it must not let an attacker create a new
client-accepted model, runtime or updater artifact.

## Internet-capable local models: brokered egress

A local model never receives raw network access. Internet-backed tools are
implemented through `Jend Net Broker`, a separate process that owns narrowly
scoped network plaintext but has no Vault keys, conversation database access or
model weights.

Security properties:

- Local AI has no sockets/DNS/connect privilege.
- HTTPS-only baseline for arbitrary public web fetches.
- no arbitrary model-controlled `fetch(url)` primitive by default;
- search results become broker-issued opaque handles, and `Open(handle)` opens
  the exact broker-stored target;
- typed connectors use fixed endpoint templates and inject credentials outside
  the model context;
- DNS is resolved once, every IP is validated as public, and the transport must
  connect to an exact validated address while preserving host/SNI; redirects
  are fully revalidated;
- localhost/private/link-local/CGNAT/special-use/cloud-metadata ranges are
  denied;
- response, redirect and decompression budgets are enforced outside the model;
- internet content is tainted data and cannot grant capabilities or modify
  trusted device/recovery/model-install state.

`JNET` local IPC may be AEAD-encrypted and sequence-bound, but encryption is not
an authorization boundary. A compromised holder of a session key can emit
valid ciphertext, so broker policy and sandboxing remain mandatory.

The remote destination necessarily sees the request intentionally sent to it.
A future multi-hop/oblivious privacy relay can reduce linkability between user
identity and destination, but cannot make the destination answer a request it
cannot read.

## Registration abuse boundary

OPAQUE protects passwords; it does not prevent automated namespace squatting.
Registration is therefore preceded by a separate admission layer:

- privacy-normalized edge token buckets;
- multiple independent rate dimensions (IP/network/creation pressure);
- adaptive proof of work that is zero for ordinary low-risk clients;
- short-lived Ed25519-signed challenges bound to the canonical username;
- database uniqueness as the final concurrent username reservation barrier;
- third-party bot signals, if used, remain inputs rather than trust anchors.

The in-tree rate limiter is per-process/per-edge. Production still requires an
HTTP edge adapter and, where necessary, a small distributed rate-state backstop.
