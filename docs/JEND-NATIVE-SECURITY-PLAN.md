# Native runtime security plan — 2026-10-14

This is a dependency plan, not a release date or production authorization.
Universal Jend runtime still targets Linux, Windows, macOS, Android and iOS
with trusted Rust control and separate native adapters. No silent remote
fallback, model-provided signing roots, arbitrary code or private-key access.

| Stage | Deliverable / acceptance | Evidence / next gate |
|---|---|---|
| M8.5.15.6c | Signed static worker, sealed FD exec; trusted OS controls before constructor; clean launch; kernel quotas / kill / reap | PR #19 all 8 CI checks PASS; user Mac 2 refusal PASS. Linux-only model-free profile; production trust / separate identity still open |
| M8.5.15.6d | Signed GGUF byte copy sealed against writes/resize/execute mode; final chunk/whole rehash; sole O_RDONLY data FD; no executable mappings | PR #20 baseline 8/8 checks PASS, Linux 9 data + 10 launch PASS; NX stack/personality hardening требует current-head CI; other hosts refuse |
| M8.5.15.6e | Full bounded GGUF structural pre-parser and versioned IPC/FD contract | Validate metadata, tensor types/dimensions/offsets/alignment, overlapping/truncated regions and resource arithmetic; fuzz malformed files/IPC, ASan/UBSan native boundaries; header/hash PASS is insufficient |
| Trust + compartments | Independently enroll distribution/model keys, persisted accepted releases, rotation/revocation/rollback; separate confidential service/OS identity | Audit source/worker permissions, same-UID debugger access, secret/log data flows, process lifetime handles; platform adapters need their own security profiles and device tests |
| M8.5.15.7 | First small licensed third-party CPU model using verified same-byte FD reader and signed backend | Published independent identity/license and distributor chain; real tokens, cancel, wall/CPU/RAM budgets, latency/RSS on ARM64 and x64; no private content until all mandatory trust/isolation gates pass |
| M8.5.16 / M8.6 / M8.7 | Architecture freeze, integrate backend contracts, independent Backend & Security Ready review | Mandatory critical/high risks closed with evidence, real end-to-end contracts, review and release scope; only then main frontend implementation |

Next after 6d: write/test the bounded GGUF structure parser independently of
native loading. Define accepted architecture/tensor/operator scope, reject
unsupported variants before launch, and keep a fuzz corpus of corrupt/truncated
files. In parallel in the dependency plan (not claiming implementation), specify
production root enrollment and per-OS compartment requirements. Never widen a
Linux syscall profile merely to make a native backend run.

Real model inference cannot be enabled by an additional PASS counter. JSEC-001,
002, 003, 004, 005, 010 and 012 remain production gates until their full scoped
requirements are implemented and independently reviewed. Detailed risk ledger:
[JEND-SECURITY-REGISTER.md](../JEND-SECURITY-REGISTER.md).
