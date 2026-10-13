# Jend

> **Для новых чатов и разработчиков:** сначала открыть [JEND-PROJECT-CONTEXT.md](JEND-PROJECT-CONTEXT.md) — текущее состояние, подтверждённые проверки, порядок PR, следующие задачи и критерии завершения архитектуры. Этот файл обновляется вместе с существенными PR; CI проверяет наличие обновления.

Security-first, local-first AI messaging architecture.

Models run on the user's device. Production servers are a control plane / encrypted relay, not a place where user conversations or model inference live. The cryptographic design aims to ensure that a server compromise or a single developer identity is insufficient to obtain conversation plaintext.

> **Pre-audit software.** The current code is an architecture/prototype milestone and must not protect production secrets until it has compiled, passed the dedicated test campaign and received independent cryptographic/security review.

## Implemented milestones

### M0 — `jend-core`

- `.jend v1` authenticated encrypted record format
- XChaCha20-Poly1305 payload encryption
- HKDF-SHA-256 key separation / forward-only message-key chain
- SHA-256 domain-separated commitments
- Ed25519 device signatures
- coarse random padding buckets
- zeroization of sensitive buffers
- `#![forbid(unsafe_code)]`

### M1 — `jend-vault`

- local key-owning process boundary
- no raw Account Root Key export API
- encrypted local conversation index
- crash-safe append-only `.jend` logs
- durability journal
- two-phase ratchet `prepare -> fsync -> commit`
- Linux no-network sandbox baseline
- separate local sync signing / X25519 keys
- AccountRootKey-sealed local sync state

### M2 — `jend-auth`

- conservative canonical username policy
- OPAQUE password flow
- Argon2-backed OPAQUE suite baseline
- stateless AEAD handshake tickets
- dummy unknown-user login path
- 256-bit recovery secret
- recovery moved from a bare SHA verifier to a separate OPAQUE credential flow

### M3 — `jend-sync`

- untrusted-server encrypted synchronization layer (JESP draft)
- random 256-bit object IDs
- outer encryption hiding `.jend` metadata/commitments from the server
- random sync epoch secrets rotated on DeviceSet changes
- signed client-controlled `DeviceSet`
- revoked devices cannot derive future sync epochs
- device-to-device X25519/HKDF/XChaCha key envelopes
- encrypted historical sync keyring transfer
- AccountRootKey-sealed local sync state
- signed encrypted sync index
- multi-device signed message DAG with per-device anti-fork chain
- deterministic causal ordering

See `docs/M3-SYNC.md` and `docs/SYNC-SERVER-PROTOCOL.md`.

### M4 — `jend-model-store`

- canonical signed `JMDL v1` model manifests
- database-enforced slots 0..2 (maximum three selected models per account)
- account entitlements separated from per-device installations
- random opaque object IDs for model chunks
- incremental chunk verification and resumable download state
- final whole-model digest verification before install
- atomic staging installer: verified chunks -> whole digest -> final rename
- short-lived device/slot/entitlement-bound model download grants
- gateway integration requiring current signed DeviceSet membership
- offline release-signing primitive; production threshold governance is M5

See `docs/M4-MODEL-STORE.md`.


### M4.5 — `jend-net-broker` and registration admission

- Local AI remains network-denied; internet access is brokered through a separate process
- HTTPS-only public-target validation and DNS-rebinding-resistant IP pinning core
- private/link-local/localhost/cloud-metadata SSRF targets rejected
- response/redirect budgets and opaque broker handles
- XChaCha20-Poly1305 sequence-bound local JNET IPC frames
- internet content explicitly treated as untrusted/tainted data
- Rust registration admission core with privacy-normalized token buckets
- adaptive, signed, username-bound proof-of-work challenges
- anti-bot signals remain inputs, not cryptographic trust anchors

See `docs/M4.5-NET-SANDBOX.md` and `docs/M2.5-ADMISSION.md`.

## Process architecture

```text
                      Internet
                         ^
                         |
                 +-------+-------+
                 | Jend Network  |
                 | no raw keys   |
                 | no plaintext  |
                 +-------+-------+
                         ^
                         | opaque protocol objects only
                         |
+-----------+       +----+-----+       +------------+
| Jend UI   |<----->| Jend     |<----->| Local AI   |
| no net    |       | Vault    |       | no net     |
| plaintext |       | keys     |       | plaintext  |
+-----------+       | no net   |       | model      |
                    +----------+       +------------+
```

OS sandboxing is only one control. A malicious plaintext-owning component can theoretically use allowed outputs as a covert channel. Therefore production privacy also depends on threshold release authorization, reproducible builds and release transparency: one developer cannot unilaterally ship a changed privacy-sensitive binary.

## Server target

The server may store:

- username and opaque OPAQUE account credentials;
- public/account routing data;
- model entitlements;
- encrypted sync objects under random IDs;
- tiny opaque sync-head pointers / quotas;
- temporary encrypted relay mailboxes.

The server does **not** need normal tables containing messages, prompts, AI responses, conversation titles or conversation encryption keys.

## Next implementation milestone

Turn the gateway core into the production HTTP edge, wire admission to real request metadata and PostgreSQL, and implement the network-broker transport/sandbox profiles. Then M5 hardens release trust with threshold authorization, reproducible builds and transparency.

## Current milestone

M4 adds the model catalog/store while preserving the zero-access chat boundary. See `docs/M4-MODEL-STORE.md` and `deployment/postgres/001_control_plane.sql`.

## M4.6 — real Rust HTTP gateway

`server/jend-gateway` now provides the hardened Axum transport shell (body/time limits, graceful shutdown, health endpoint), an explicit PostgreSQL adapter boundary, and a fail-closed registration-admission route. Business cryptography remains in `jend-gateway-core`; production registration stays disabled until M4.7 wires async DB transactions and shared rate-state.


### M5.0 authentication gateway

Source now includes OPAQUE HTTP registration/login, replay-resistant login tickets, persisted server-secret bootstrap via `jend-keygen`, shared login rate backstops, and five-minute signed account capabilities. See `docs/M5.0-AUTH-GATEWAY.md`. This code has not yet been compiled/tested in the current environment.


### M5.4 headless smoke path

The repository now includes `jend-migrate`, a localhost PostgreSQL compose
configuration, and `jend-cli smoke-register`. The intended smoke path covers
OPAQUE registration/login, first-device activation, device binding, JREQ
proof-of-possession, device capability refresh, and trusted-device session
bootstrap without a repeated password prompt. See `docs/M5.4-HEADLESS-RUNBOOK.md`.

This remains pre-audit source until it is compiled and exercised against
PostgreSQL.


### M5.5 build/test baseline

Run `scripts/check-headless.sh` for format/check/unit tests. With a PostgreSQL
instance and the documented `DATABASE_URL`, set `JEND_RUN_DB_SMOKE=1` to also
run the full registration/device/JREQ security smoke test.

The repository includes a GitHub Actions workflow that performs the same checks
against a PostgreSQL service. See `docs/M5.5-BUILD-TEST-BASELINE.md`.


### M5.7 server-bound device sessions

Passwordless trusted-device session challenges now carry a server HMAC using a
dedicated secret, and the smoke test rejects a forged challenge MAC. Run
`python3 scripts/static-preflight.py` for the no-Rust structural security gate.
See `docs/M5.7-SESSION-CHALLENGE-MAC.md`.


### M5.8 startup safety

`jend-gateway` refuses to start on an incomplete PostgreSQL schema and refuses
non-loopback plain-HTTP binds by default. See `docs/M5.8-STARTUP-READINESS.md`.


### M5.9 first-run helper

On a development machine with Rust, Docker and curl, run
`scripts/doctor-headless.sh`, then `scripts/dev-headless-smoke.sh`. The gateway
now requires the exact bundled SQLx migration version and a critical-column
contract before it opens the listener.


### M6.0 toolchain baseline

The first-run baseline is Rust 1.99.0. Run `scripts/doctor-headless.sh` before
the smoke harness; it verifies the declared toolchain and the offline dependency
policy as well as the repository/static security contracts.


### M6.1 crypto API compatibility

The source has been updated for the `chacha20poly1305 0.11` key/nonce API.
Static preflight rejects the obsolete generic `Key::<XChaCha20Poly1305>` form.
This is a source-level compatibility repair; the project still requires a real
Cargo runner before it can be called compiled.


### First technical registration test

The headless authentication path is now at the first-test boundary. On a
machine with Rust 1.99.0, Docker and curl, run:

```bash
bash scripts/doctor-headless.sh
JEND_DEV_CLEANUP=1 bash scripts/dev-headless-smoke.sh
```

See `docs/M6.2-FIRST-TEST-READY.md`. A green compiler/database run is still
required before calling the service build-verified.


### First real test

Before starting PostgreSQL, run `bash scripts/first-test-ladder.sh`. It performs
a real in-memory OPAQUE registration/login test, JREQ tests, gateway unit tests,
and a workspace compile check. If that is green, run
`JEND_DEV_CLEANUP=1 bash scripts/dev-headless-smoke.sh` for the full database
registration/login smoke path.
