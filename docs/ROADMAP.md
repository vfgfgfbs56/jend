# Jend implementation roadmap

## M0 — cryptographic storage core

- [x] security invariants draft
- [x] canonical `.jend v1` draft
- [x] Account Root Key and wrapped conversation seed
- [x] forward-only message-key chain
- [x] XChaCha20-Poly1305 record encryption
- [x] random size-bucket padding
- [x] SHA-256 domain-separated commitments
- [x] Ed25519 trusted-device signature
- [x] zeroize sensitive buffers
- [x] tamper/chain unit-test drafts
- [ ] compile/test on Rust toolchain
- [ ] independent cryptographic design review before freezing v1

## M1 — Jend Vault

- [x] development SecretStore boundary
- [x] no raw master-key export API
- [x] narrow local IPC baseline
- [x] Linux no-network sandbox baseline
- [x] encrypted local conversation index
- [x] crash-safe append-only `.jend` storage
- [x] two-phase ratchet prepare/fsync/commit
- [x] separate sync signing/key-agreement secrets in Vault
- [x] AccountRootKey-sealed local sync state
- [ ] production IPC peer authentication/capability handles
- [ ] platform secure-keystore adapters
- [ ] filesystem/IPC sandbox profiles for every process
- [ ] compile/integration/fuzz/crash testing

## M2 — account authentication

- [x] canonical username policy
- [x] zeroizing password container
- [x] OPAQUE client/server wrapper
- [x] Argon2-backed OPAQUE baseline
- [x] stateless AEAD registration/login tickets
- [x] dummy unknown-user login path
- [x] 256-bit recovery secret
- [x] remove bare SHA recovery verifier
- [x] recovery-client OPAQUE flow helpers
- [ ] independent persisted OPAQUE server setup for password and recovery
- [ ] benchmark/freeze Argon2 profile
- [x] signed short-lived application capabilities
- [ ] password-change/recovery rotation
- [ ] compile/integration/fuzz testing


## M2.5 — gateway admission / anti-bot

- [x] privacy-normalized per-edge token-bucket core
- [x] adaptive risk -> proof-of-work difficulty mapping
- [x] Ed25519-signed short-lived registration challenge
- [x] challenge bound to canonical username
- [x] gateway composition helper for rate keys + challenge verification
- [ ] production HTTP request metadata normalization
- [ ] distributed/edge rate-state backstop
- [ ] optional Turnstile/provider risk adapter
- [ ] load/abuse simulation

## M3 — encrypted multi-device sync (implementation started)

- [x] random 256-bit opaque sync object IDs
- [x] outer JESP encryption hiding `.jend` metadata
- [x] per-DeviceSet random sync epoch secrets
- [x] historical SyncKeyring
- [x] client-signed DeviceSet chain
- [x] removed-device future-epoch isolation
- [x] X25519/HKDF/XChaCha device key envelopes
- [x] signed encrypted sync index
- [x] AccountRootKey-sealed local sync state
- [x] signed message DAG baseline
- [x] per-device author chain/counter anti-fork checks
- [x] deterministic causal ordering baseline
- [x] minimal opaque sync-relay API draft
- [ ] crash-safe DeviceSet+key rotation state machine
- [ ] new-device approval handshake/QR UX protocol
- [ ] anti-rollback acceptance state machine
- [ ] relay ACK + TTL protocol
- [ ] bundle multiple DAG nodes into encrypted segments to reduce storage operations
- [ ] direct P2P sync transport
- [ ] persistent cloud backup + separate data-recovery wrapping
- [ ] compile/property/fuzz/byzantine-server tests

## M3.5 — account recovery

- [x] self-signed new-device RecoveryRequest
- [x] trusted-device signed RecoveryApproval
- [x] six-digit human comparison code never sent through relay
- [x] approval encrypted candidate-device-to-trusted-device via DH
- [x] DeviceSet epoch/hash binding
- [x] short approval lifetime and request commitment
- [x] OPAQUE password re-registration gated by recovery approval
- [x] random one-time grant nonce
- [x] PostgreSQL atomic consume + password rotation schema
- [x] auth_epoch rotation contract for old-session invalidation
- [ ] encrypted Jend Security system-channel UX
- [ ] guardian threshold recovery
- [ ] optional offline recovery card
- [ ] compile/integration/replay/fuzz testing

## M4 — model store

- [x] canonical `JMDL v1` model manifest
- [x] random opaque model/object identifiers
- [x] database-enforced maximum 3 active account model entitlements
- [x] optimistic entitlement epoch / slot replacement contract
- [x] device installations separated from entitlements
- [x] offline Ed25519 release-signature building block
- [x] manifest digest + pinned release public-key verification
- [x] chunked/resumable download state
- [x] incremental per-chunk SHA-256 verification
- [x] final whole-model SHA-256 verification
- [x] PostgreSQL model catalog/release/installation schema
- [x] short-lived device-bound download capability
- [ ] object-store/CDN adapter
- [x] atomic local installer / cleanup state machine
- [ ] optional encrypted-at-rest model content-key wrapping
- [ ] compile/integration/corruption/resume testing


## M4.5 — internet tools and model sandbox

- [x] Local AI remains raw-network denied by architecture
- [x] HTTPS-only target-validation core
- [x] SSRF/private/link-local/cloud-metadata address rejection
- [x] DNS-resolution pinning contract against rebinding
- [x] redirect and response-size policy budgets
- [x] opaque broker handle primitive
- [x] sequence-bound XChaCha20-Poly1305 local JNET IPC frame
- [x] untrusted-web content trust label
- [ ] concrete HTTP client that connects only to validated pinned IPs
- [ ] broker-issued search-result handle cache
- [ ] typed connector framework / secret injection helper
- [ ] Linux seccomp + Landlock profile
- [ ] Windows AppContainer/WFP profile
- [ ] macOS sandbox profile
- [ ] Android/iOS sandbox integration
- [ ] GPU isolation/broker design
- [ ] prompt-injection/tool-escalation adversarial tests
- [ ] sandbox escape / SSRF / DNS rebinding test suite

## M5.0–M5.2 — gateway authentication and device authorization

- [x] OPAQUE HTTP registration/login source integration
- [x] persistent server auth/capability/admission secrets
- [x] PostgreSQL login-ticket one-time replay barrier
- [x] pending registration account + one-time first-device bootstrap
- [x] signed DeviceSet genesis activation
- [x] DeviceSet current-state HTTP retrieval
- [x] signed DeviceSet transition + PostgreSQL epoch CAS
- [x] device session challenge/proof endpoints
- [x] one-time device-binding challenge replay barrier
- [ ] per-request device proof-of-possession for device-bound capabilities
- [ ] device-capability refresh without repeated password entry
- [ ] authenticated reverse-proxy client-network identity
- [ ] expired pending-account / replay-row garbage collection jobs
- [ ] cargo/PostgreSQL integration, concurrency and abuse tests

## M5 — production release trust

- deterministic/reproducible builds
- independent builders
- append-only release transparency log
- threshold production signing target: 2-of-3 initially
- updater fails closed on missing signatures/transparency
- targeted-update detection

## M6 — optional timestamp anchoring

- local Merkle roots over `.jend`/sync history
- timestamp receipts over commitments, never plaintext hashes
- independent timestamp nodes
- threshold timestamp signing

## M7 — local inference

- model runtime abstraction
- CPU/GPU/NPU backends
- quantization / memory mapping
- local context/memory through Vault
- zero server inference requirement


## Future: grounded-response / hallucination checks

After the local inference and trusted-weight path is stable, evaluate an
optional response-verification layer: provenance/citation tracking for retrieved
facts, deterministic tool-result binding, claim extraction plus evidence checks,
and uncertainty signaling. This is a quality/trust layer, not a substitute for
model-weight integrity and not a claim that hallucinations can be eliminated.

## M8.5.7 bounded assembler
Offline multi-term/multi-xorb reconstruction from already-decoded ranges, with coverage, length and output-budget rejection. Next: schedule authorized physical ranges under bounded concurrency and total fetch budget; bind to signed Jend page requests; live end-to-end verified-page admission. Future quality layer: evidence-backed claims, provenance and uncertainty to reduce (not eliminate) hallucinations.

## M9 — multi-region availability and low-latency gateway fabric

- [ ] signed multi-endpoint gateway discovery / bootstrap rotation
- [ ] client nearest-healthy endpoint selection with automatic failover
- [ ] stateless regional gateways with no plaintext-message or model keys
- [ ] authoritative strongly-consistent security/control-plane writer
- [ ] regional read replicas/caches only for staleness-safe data
- [ ] encrypted sync-object cross-region replication and retention policy
- [ ] independent-provider / region failure drills
- [ ] optional Anycast/global DNS front door without single-provider dependency
- [ ] direct P2P sync path when available, relay fallback otherwise
- [ ] latency SLOs measured by region; do not claim zero-latency across distance

## M8.5.8 bounded Xet fetch scheduling
- [x] preserve each signed XorbMultiRangeFetch as one atomic request
- [x] exact aggregate/per-request physical byte budgets
- [x] deterministic bounded-concurrency waves (hard max 8)
- [x] reject duplicate chunk coverage across fetch entries
- [ ] strict bounded multipart/byteranges HTTP 206 parser
- [ ] live multi-range xorb execution
- [ ] independently signed live WeightPage admission
