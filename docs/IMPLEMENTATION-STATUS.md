# Jend implementation status

This file distinguishes architecture/code-core from production-ready service.

## Implemented in Rust source

- OPAQUE auth core and stateless auth tickets.
- `.jend` crypto/storage core and Vault boundary.
- encrypted multi-device sync core.
- device-bound signed application capability tokens (`JCAP`).
- Rust `jend-gateway-core` for registration/login, device binding, DeviceSet
  transitions and model-store authorization.
- model entitlements / signed manifests / download grants / installer core.
- registration admission core: privacy-normalized token bucket + signed
  adaptive proof-of-work challenge.
- internet target-policy core (`jend-net-broker`): HTTPS-only, SSRF/special-IP
  rejection, DNS pinning contract, redirects/size budgets, JNET encrypted IPC.

## Not yet production-complete

- actual public HTTP server/router around `jend-gateway-core`;
- concrete PostgreSQL repository implementation wired to the gateway;
- distributed rate-limit state / edge deployment adapter;
- Cloudflare/Turnstile optional adapter;
- concrete pinned-IP HTTP client for `jend-net-broker`;
- Linux/Windows/macOS/mobile sandbox profiles beyond the existing baseline;
- connector credential helper and search-result handle cache;
- production release threshold/transparency pipeline;
- compile, unit, integration, fuzz, crash, abuse and sandbox-escape testing.

Until those are complete and independently reviewed, the repository is a
prototype and must not protect real secrets.


## M5.0 update

OPAQUE HTTP registration/login endpoints, persistent secret loading, one-time login-ticket replay barrier, and PostgreSQL login rate backstops are implemented in source. They remain **unverified** until the Rust/PostgreSQL test environment is run. Authenticated reverse-proxy identity and device-binding HTTP endpoints are still pending.


## M5.1 update

Implemented in source: pending-account registration bootstrap, atomic signed DeviceSet
genesis activation, current DeviceSet retrieval, epoch-CAS signed transitions,
device-session challenge/proof HTTP endpoints, and one-time device-binding challenge
consumption. Device-bound JCAP remains a bearer token until M5.2 per-request
proof-of-possession is implemented. Authenticated reverse-proxy client identity and
full compile/PostgreSQL testing are still pending.


## M5.3/M5.4 update

JREQ is enforced in source for DeviceSet reads/mutations and device-capability
refresh. DeviceSet mutation combines replay-nonce consumption and epoch CAS in
one PostgreSQL transaction. A trusted-device session challenge/proof path can
reissue a device capability after expiry without requiring the password, while
checking the latest signed DeviceSet.

A headless SQLx migration runner, localhost PostgreSQL compose file and
development smoke CLI are present. The pre-release migration numbering was
normalized and an incompatible duplicate model-store draft was removed from the
migration path.

**Still unverified here:** no Rust toolchain/PostgreSQL runtime is installed in
this execution environment, so this source has not yet passed `cargo check`,
unit tests, or the end-to-end database smoke run. Do not use it for real secrets.


## M5.5 update

A reproducible compiler/test/DB-smoke harness is now part of the repository.
The CLI can run noninteractively only via the explicit `--password-stdin`
development flag, and the end-to-end smoke includes bearer-only, JREQ replay
and device-session replay rejection checks.

This revision still requires execution on a runner with Rust 1.85.0 and
PostgreSQL before it can be called a passing build.

## M5.7 update

Trusted-device passwordless session challenges are now authenticated by a
separate server HMAC key, so `/session/finish` cannot accept a locally fabricated
challenge and `/session/start` rate limiting cannot be bypassed that way. The
CLI smoke includes a forged-MAC rejection check. A static preflight now runs in
CI before compilation and validates key HTTP/SQL/security invariants.


## M5.8 update

Gateway startup and `/readyz` now share the complete table contract used by the
implemented authentication/device repository. Incomplete migrations fail before
the listener opens. Plain-HTTP non-loopback binds are rejected unless an
explicit development-only override is set. CI asserts this fail-closed behavior.


## M5.9 update

Gateway startup/readiness now verifies exact SQLx migration version 6 and a
critical PostgreSQL column/type contract in addition to table presence. CI
resolves dependencies once and then runs check/test/smoke with `--locked`. A
local doctor and one-command Docker headless smoke helper were added.

This revision is still awaiting an actual Rust/PostgreSQL execution environment
before it may be described as compiled or passing end-to-end.


## M6.0 update

The first-run toolchain was moved from the historical Rust 1.85 baseline to
Rust 1.99.0. CI derives the exact toolchain from `rust-toolchain.toml`, generates
a real lockfile once, and then operates with `--locked`. A repository dependency
policy rejects git/custom-registry/out-of-workspace path dependencies and
requirement drift before Cargo network access.

This source still has not been compiled in the current execution environment.


## M6.1 update

Two concrete RustCrypto compatibility errors were repaired. Across 18
XChaCha20-Poly1305 construction sites, obsolete generic root `Key` syntax was
replaced with `KeyInit::new_from_slice` and deprecated nonce conversions were
modernized. In `jend-auth`, HKDF 0.13 now receives SHA-2 0.11 while the OPAQUE
4.0.1 cipher suite uses a renamed SHA-2 0.10 dependency, avoiding incompatible
digest trait generations. Static preflight locks both source-level contracts.

M6.0's dependency policy is explicitly classified as an allowlist, not a full
dependency freeze until a real Cargo runner produces `Cargo.lock`. The source
still has not been compiled in this execution environment.


## M6.2 update

The project has crossed the intended architecture-to-testing boundary for the
headless registration service. Two additional compile-oriented hazards were
removed: reusable JREQ test requests are Copy, and OPAQUE client/server RNG use
is backed by an explicit `rand 0.8.5` dependency instead of a feature-limited
re-export. The next step is a real Rust/PostgreSQL run.


## M6.3 update

Passwordless device-session finish now authenticates and freshness-checks its
server-issued challenge before database lookups. SQLx is pinned to 0.8.6
pre-lock and uses explicit Tokio + rustls/WebPKI feature flags.

This is a first-run hardening checkpoint, not a claim of a successful Cargo or
PostgreSQL run.

## M6.4 update

A focused first-test ladder now exists. It starts with an in-memory OPAQUE
registration/login integration test (including wrong-password and unknown-user
fake-record cases), then JREQ and gateway unit tests, and only then compiles the
full workspace. PostgreSQL smoke remains the second-stage acceptance gate.

No new product/UI architecture was added in this milestone.


## M6.5 update

First real Rust 1.99.0 compiler feedback from macOS fixed two E0308 errors in
the sender ratchet: array-preserving deref is now used when deriving the next
chain step. The manifest checker also tolerates macOS `.DS_Store` files and
root-level test logs.

Compilation of the whole workspace is not yet claimed green; M6.5 is the first
compiler-driven repair checkpoint.


## M6.6 update

Second real macOS compiler pass fixed four E0308 errors in `jend-sync` envelope
and recovery KDF calls. X25519 shared secrets wrapped in
`Zeroizing<[u8; 32]>` now retain the fixed-array reference type when passed to
KDF helpers. Static preflight locks this invariant.


## M6.7 update

Third real macOS compiler pass fixed an Axum handler-shadowing error in the
registration admission route and removed the deprecated tower-http timeout
constructor. Static preflight now detects route-handler/local-binding name
collisions.


## M6.8 update

Fourth real macOS compiler pass fixed mutable fixed-array coercions in
`jend-vault` for AccountRootKey, DeviceIdentity and SyncDeviceIdentity secret
imports. The unused synchronous gateway repository adapter and the superseded
non-JREQ DeviceSet CAS function were removed, eliminating their dead-code
warnings while preserving the atomic JREQ CAS path.


## M6.9 update

The first full-workspace test-target pass reached `jend-core` tests. A test
that used `unwrap_err()` was rewritten so secret-bearing `ConversationSeed`
does not need a `Debug` implementation. CLI expiry fields are now consumed by
real smoke assertions instead of generating dead-code warnings.

## M7.0 first checkpoint

macOS/Linux Unix socket Vault daemon now refuses to replace an existing socket
and requires a private parent directory. This is an initial fail-closed IPC
boundary, not complete peer authentication or OS-backed key custody.


## M7.1 update

A reusable bounded Unix Vault IPC client and a real process smoke were added.
The smoke proves message/history persistence and stable device signing identity
across a Vault daemon restart, and verifies fail-closed socket-path/private-dir
behavior. Socket reads/writes now have finite deadlines. Same-user peer
authorization remains an explicit next-step boundary.


## M7.2 update

Vault IPC is now capability-authenticated with a fresh per-daemon 256-bit
credential compared in constant time. The daemon uses four fixed workers and a
bounded 32-connection queue; requests are fully read and authenticated before
the Vault mutex is acquired. The process smoke now proves an incorrect
capability is rejected. Same-OS-user malware resistance remains a future
platform-launch/attestation problem rather than an unsafe peer-credential
shortcut.


## M7.2.1 update

Removed the new `subtle` dependency from M7.2 so an existing M7.1 `Cargo.lock`
remains valid under `--locked`. IPC capability comparison now uses a safe
fixed-size XOR accumulator over all 32 bytes.


## M7.2.2 update

Fixed the authenticated Vault IPC append path to pass `SensitiveBytes` by value
into `Vault::append_message`, matching the API and preserving the sensitive
buffer ownership boundary.


## M7.2.3 update

Rust 1.99.0 exposed a never-type inference failure in the new bounded Vault IPC
worker channel. The `sync_channel` element type is now explicitly
`std::os::unix::net::UnixStream`, preserving the existing bounded runtime while
eliminating the `!` inference cascade.


## M7.3 update

Added a bounded local runtime scheduler with UI/Vault/sync/AI/background lanes,
non-blocking `try_submit`, queue-wait budgets, bounded fairness for AI, and
runtime pressure snapshots. No new package or external dependency was added, so
the M7.2.3 lock-file baseline remains valid. A deterministic runtime smoke
proves UI/Vault work overtakes an existing AI backlog and that the AI queue
applies immediate backpressure.


## M7.4 update

Added a local-only device profiler and adaptive performance policy. Coarse CPU
parallelism and RAM capacity select Low/Balanced/High/Ultra tiers; live runtime
pressure can reduce AI concurrency, background work, queue depth and animation
detail before interactive work is affected. Unknown hardware is classified
conservatively. The unused M7.3 `has_work` helper was removed.


## M7.5 update

iOS/Android are now explicit mobile runtime targets. Mobile policy caps
foreground AI/background concurrency and disables background prefetch even when
raw CPU/RAM appears desktop-class. A live `RuntimeController` responds to
scheduler pressure, thermal pressure and low-power mode. Android uses local
`/proc/meminfo`; iOS stays conservative until a native platform bridge feeds
memory/thermal/power/display signals.


## M7.6 update

Adaptive performance policy is now applied to live runtime queue admission via
`RuntimeGovernor`. AI/background queue limits tighten immediately on
power/thermal/load changes while UI/Vault/Sync capacities stay intact. Already
accepted work is never discarded; new expensive work receives backpressure
until queues drain under the new limit. Execution worker/share limits are
exposed for the future AI/background executors.


## M7.7 update

The Model Store now distinguishes `LocalPackage`, `ProviderRemote`, and
`VirtualPaged` delivery. Closed/provider-only models no longer imply downloadable
weights, while huge open/licensed models may install a virtual index/cache
instead of an eager full file. The signed-manifest logical ceiling was expanded
from 256 GiB to 64 TiB. Explicit storage math tests preserve the fact that a
generic 1T model at 4 bits/weight is still roughly 500 GB before overhead.


## M7.8 update

Added immutable model-source/provenance contracts and a two-stage Store safety
gate. Hugging Face sources are pinned to full commit SHAs; publisher origins are
SHA-256 pinned; weight publication requires explicit license approval. Direct
pickle/custom-code packages are rejected. Clean data-only artifacts remain in
quarantine until isolated behavioral suites cover backdoors, prompt injection,
tool abuse, data exfiltration and malformed output behavior.


## M7.9 update

Added zero-install model selection. Account model slots are now conceptually
separate from device weight residency: provider models need no weights,
VirtualPaged models may start from a megabyte-scale bootstrap and bounded lazy
cache, and eager full downloads remain an explicit option. Readiness distinguishes
a genuinely resident working set from online page streaming or insufficient
offline data.


## M7.10 update

Added separate `jend-aid` local AI process boundary with authenticated private
Unix IPC, zeroizing input buffers, bounded queues/workers, dynamic worker limits
and cooperative cancellation. The AI process package has no direct network or
Vault dependency. Real inference is intentionally not claimed yet; the process
smoke uses deterministic SHA-256 work to validate the execution boundary.


## M7.10.1 update

Fixed Rust test-target compilation for the AI executor. Success-path tests no
longer use `Result::unwrap()` on `AiSubmitFailure<T>`, avoiding an unnecessary
`Debug` requirement on the generic failure type. Runtime behavior is unchanged.


## M7.10.2 update

Fixed `jend-aid` Rust 1.99.0 compilation by importing the Unix
`OpenOptionsExt` trait required by `.mode(0o600)`. AI IPC auth-file creation
remains fail-closed with `create_new(true)` and mode `0600`.


## M7.11 update

Added a clean-room provenance boundary for Jend-owned model prototypes.
Provider-backed, open/licensed, and independently developed Jend models are
separate identities. Restricted provider outputs, unknown/leaked checkpoints,
unreviewed rights, and provider impersonation fail closed.


## M7.12 update

Added unified chat execution routing and the provider-adapter/Network-Broker
boundary. Provider-backed Store models route to a provider adapter rather than
`jend-aid`; local and VirtualPaged models route to the isolated local executor.
The Network Broker authorizes only a registered HTTPS provider host with public
DNS pinning and opaque encrypted-byte budgets, and has no API for parsing prompt
or provider credential plaintext.


## M7.13 update

Public Jend Store execution is now Store-only: ProviderRemote entries fail
closed during activation and chat routing, while LocalPackage and VirtualPaged
models use the isolated local AI path. Added `JendNativeBlueprint` for
independently developed dense/sparse models with explicit component paging,
training stages and teacher provenance. Restricted closed-provider teachers are
rejected; Jend-owned or explicitly licensed teachers are allowed.


## M8.0 update

Started WeightVM. Added content-addressed SHA-256 weight pages, verified page
faults, a bounded resident-byte cache, LRU eviction, active-page leases/pinning,
dynamic budget tightening, cache-hit/fault/eviction counters, and digest-based
resident deduplication. WeightVM intentionally has no network dependency.


## M8.0.1 update

Fixed Rust 1.99.0 compilation of `jend-weightvm-smoke`: the model-store
single-parameter `Result<T>` alias no longer shadows the boxed-error result used
by `main`. WeightVM behavior is unchanged.


## M8.1 update

Added a durable content-addressed WeightVM page store. Immutable SHA-256 page
objects are written through private staging files, synced and verified before
atomic publication, survive process restarts, recover stale crash artifacts,
deduplicate identical disk pages and directly implement `WeightPageSource`.
Unix store/files use private permissions; existing public store roots fail
closed. The store remains network-agnostic.


## M8.1.1 update

Fixed Rust 1.99.0 compilation of the durable WeightVM page store by importing
`sha2::Digest` at module scope for `Sha256::new()`. Also removed the intentionally
unused rename-race warning. Runtime/storage behavior is unchanged.


## M8.2 update

Added signed virtual-model address maps. Logical backbone/router/expert regions now
resolve to ordered content-addressed WeightVM page descriptors, expert IDs and roles
are validated, prefetch dependencies are bounded/deduplicated, and the canonical
map is release-signed under a separate signature domain. The smoke proves the path
from coding ExpertId -> durable page store -> bounded WeightVM residency and detects
signed map tampering.


## M8.3 update

Added Jend Source Descriptor Protocol v1. WeightVM-facing source reads are now
URL-free typed range requests bound to expected page identities. Immutable
HF/Xet, structured publisher HTTPS and Jend-object descriptors are canonical,
range-bounded and carried in a release-signed source map with a distinct
signature domain. Multiple source candidates may bind the same WeightPageId,
while the model-store crate remains free of direct HTTP/runtime dependencies.


## M8.4 update

Added a dependency-neutral Hugging Face/Xet source-adapter planner. It converts
JSDP HF sources into immutable no-redirect resolve requests, repo/ref-scoped
Xet token requests and exact-range CAS reconstruction plans. It validates Xet
file IDs, current US/EU CAS/transfer hosts, signed xorb URLs, chunk/range
coverage and transfer budgets while keeping credentials/signed URLs out of
Debug. HTTP/JSON/xorb transport remains isolated for M8.5.

## M8.5.0
Bounded Source Worker response/DNS policy contract (no live transport yet).

## M8.5.1
Added a real hardened pinned HTTPS transport executable target in the already-networked development CLI package without changing dependency manifests. It resolves HF/Xet hosts before request execution, rejects any non-public result, overrides reqwest DNS to the validated addresses, disables redirects/proxies, preserves hostname TLS verification, streams with hard byte caps, and supports an explicit live immutable HF/Xet resolve smoke. Production IPC, sandboxing and Xet reconstruction decoding remain pending.

## M8.5.2.1
Cleaned Xet metadata smoke warnings without project-wide warning suppression; runtime smoke now exercises valid reconstruction metadata and SSRF rejection directly.

## M8.5.2.2
Corrected the offline Xet v2 reconstruction parser to the published schema:
`terms[].range`, `xorbs` map keyed by xorb hash, and nested `chunks`/`bytes`
range descriptors. Added a regression test that explicitly rejects the older
incorrect fixture shape before any live CAS integration is enabled.

## M8.5.3 update

Added an opt-in live Hugging Face/Xet metadata chain: immutable `X-Xet-Hash`
resolve, repo+commit-scoped short-lived read-token acquisition, pinned CAS v2
reconstruction query for `bytes=0-0`, and strict parsing of the live v2 schema.
M8.5.3 explicitly does not execute signed xorb URLs or download model payload.

## M8.5.3.1
Fixed live Xet signed transfer path validation for current `/xorbs/default/` traffic while preserving exact-host/hash binding and the older singular compatibility form.

## M8.5.3.2
Structural signed-Xorb URL validation and safe live rejection diagnostics; no xorb execution.

## M8.5.3.3
Added exact current HF CDN bridge hosts/path validation for live Xet reconstruction metadata; no wildcard and no xorb fetch yet.

## M8.5.3.4
Live compatibility: exact HF CDN direct `/xorbs/default/<hash>` path accepted with signed-range + CDN signature checks; bridge path retained.

## M8.5.3.5
Adjusted strict signed-URL validation to current live HF CDN direct-xorb behavior: CloudFront-signed CDN URLs may omit X-Xet-Signed-Range; reconstruction byte ranges remain authoritative. transfer.xethub URLs still require X-Xet-Signed-Range.


## M8.5.4
Added a fail-closed live signed-Xet single-range payload smoke. A one-byte file reconstruction probe may execute exactly one authorized physical xorb range, capped at 16 MiB, with pinned HTTPS, HTTP 206 and exact response-length enforcement. Multi-range/multipart, xorb decoding, content verification and WeightVM ingestion remain disabled.

## M8.5.5
Added bounded Xet xorb v0 header parsing, None/LZ4/BG4-LZ4 decoding, and one-xorb logical slice reconstruction in the isolated CLI Source Worker. Live data is still not admitted to WeightVM until signed expected-page hashing is wired.

## M8.5.5.1
Fixed negative xorb decoder tests without adding Debug to decoded model-byte containers. Production decoder unchanged.


## M8.5.6 — verified WeightPage publication

Implemented an opaque signed-map-derived `VerifiedSourceReadRequest`, exact
length/SHA-256 pre-staging verification, durable atomic publication, and
WeightVM re-verification. Real HF/Xet live decode remains separate until a
release-signed Jend page map exists for that live fixture.

M8.5.7: bounded multi-term/multi-xorb logical assembler implemented and offline smoke extended. This does NOT yet fetch multiple ranges live or publish an independently signed live WeightPage. Rust compilation pending Mac test.

## M8.5.7.1
Fixed only the M8.5.7 executable smoke expectation: the bounded multi-xorb
assembler already returned the correct slice, but the smoke incorrectly
expected a partial second-term suffix. Production assembler behavior is
unchanged. A multi-region deployment direction is also documented; no
multi-region runtime implementation is claimed in this milestone.

## M8.5.8
Added a bounded transport-independent scheduler for validated Xet fetch entries.
Each signed multi-range entry remains atomic, aggregate/per-request physical
payload budgets are enforced, fetches are assigned deterministic bounded
concurrency waves, and duplicate physical chunk coverage is rejected. The
network transport still rejects comma-separated ranges; multipart/byteranges
execution is intentionally pending.
