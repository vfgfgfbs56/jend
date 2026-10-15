# Native runtime security plan — 2026-10-15

This is a dependency plan, not a release date or production authorization.
Universal Jend runtime still targets Linux, Windows, macOS, Android and iOS
with trusted Rust control and separate native adapters. No silent remote
fallback, model-provided signing roots, arbitrary code or private-key access.

| Stage | Deliverable / acceptance | Evidence / next gate |
|---|---|---|
| M8.5.15.6c | Signed static worker, sealed FD exec; trusted OS controls before constructor; clean launch; kernel quotas / kill / reap | PR #19 all 8 CI checks PASS; user Mac 2 refusal PASS. Linux-only model-free profile; production trust / separate identity still open |
| M8.5.15.6d | Signed GGUF byte copy sealed against writes/resize/execute mode; final chunk/whole rehash; sole O_RDONLY data FD; no executable mappings | PR #20 final source f8dd341: 8/8 checks PASS, Linux 9 data + 11 launch PASS, copy-race/reader tests, NX stack/personality checks; other hosts refuse. Production gate stays CLOSED |
| M8.5.15.6d.1 | Scope Linux-only imports/argv; document child syscall safety and use explicit unsafe blocks; reject unused imports/variables and implicit unsafe for both binaries on all five desktop runners | User Mac 6d: exactly 2 refusal/no-inference PASS on 2026-10-15; PR #21 source dcbe5fe: all 8 checks PASS; both binaries compile without warnings on all five desktop runners. Linux 11 launch + 9 data PASS, other desktop hosts 2 launch + 2 data refusal PASS. User retest after pinned 33b1d24 instructions: exactly 2 Mac refusal/no-inference PASS, 2026-10-15. No new execution capability |
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

The M8.5.15.6e implementation should be split into reviewable steps:

1. Define a narrow supported GGUF version/type profile and bounded streaming
   reader budgets. Validate metadata counts, strings/arrays and lengths with
   checked arithmetic before allocation; reject duplicate or unsupported fields
   according to the written profile.
2. Validate the tensor table, type/block sizes, dimensions, offsets, alignment,
   overlap and file bounds. Bind the validation receipt to the same sealed
   bytes and accepted model identity; no pathname reopen for the backend.
3. Specify the versioned IPC/FD contract and negative corpus, then run parser
   fuzzing and native ASan/UBSan gates. Malformed data, unsupported profiles and
   exhausted budgets must refuse before backend access. A parser PASS alone
   does not enable inference or close production trust/compartment gates.

These are planned acceptance criteria, not implemented parser support.

Real model inference cannot be enabled by an additional PASS counter. JSEC-001,
002, 003, 004, 005, 010 and 012 remain production gates until their full scoped
requirements are implemented and independently reviewed. Detailed risk ledger:
[JEND-SECURITY-REGISTER.md](../JEND-SECURITY-REGISTER.md).
