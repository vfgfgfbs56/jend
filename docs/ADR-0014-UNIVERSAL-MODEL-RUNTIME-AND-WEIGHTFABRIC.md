# ADR-0014 — Universal Model Runtime and WeightFabric

Status: **product direction approved for proposal; technical implementation staged**.
Date: 2026-10-13.

## 1. Product identity and explicit correction

**Jend is a universal user interface for existing familiar AI models, not a
project to train or create a new foundation model.** Jend owns its experience,
security, execution orchestration, delivery protocol and resource scheduler.
Model publishers own model architectures, artifacts and licensing.

This ADR supersedes the **product direction**, but not automatically the code
or security policy, in docs/M7.13-STORE-ONLY-JEND-NATIVE-MODELS.md.
That old document is retained as historical context. Public ProviderRemote is
currently fail-closed; a future opt-in remote-provider lane must be reviewed
before enabling. Existing entitlements, signatures, rights gates, three model
slots and E2EE boundaries stay intact until separately approved migrations.

Jend supports locally runnable models only if lawful, immutable compatible
weights are available. Proprietary hosted models without weights are NOT
downloadable or runnable offline; they may optionally be reached through
user-consented BYOK/provider account APIs as a distinct privacy/billing lane.

## 2. Top-level architecture

    Unified Jend UI / user model choice and switcher
                 |
    Rust Model Orchestrator (control + trust)
      |-- Signed catalog + publisher provenance + license policy
      |-- Device profiler + conservative hardware feasibility gate
      |-- Verified runtime/backend compatibility matrix
      |-- Signed immutable artifact and page authorization
      |-- Resolver: local CAS / publisher / optional Jend seed / opt-in peer
      |        |
      |        +--> isolated network source-worker (all bytes untrusted)
      |                   |
      |            signed digest + length gate
      |                   |
      |            local content-addressed verified store
      |                   |
      +-- verified read-only page leases --> isolated inference engine worker
                                              |
              tokens to local UI <-- CPU/C++/Metal/CUDA/Vulkan/ONNX backend

    Remote provider execution is a separate opt-in lane, never an automatic
    fallback from local execution failure or out-of-memory.

### Rust security plane

The existing ModelReleasePublicKey, signed SourceMap/VirtualModelMap, opaque
VerifiedSourceReadRequest, DurableWeightPageStore and WeightVM are the trust
path. Never self-sign upstream bytes with a freshly generated key and call them
an independently trusted release. Need separately provisioned trusted signing
keys, key rotation and revocation.

Add an update root based on The Update Framework concepts: pinned offline
root, threshold signatures, root/targets/snapshot/timestamp metadata,
expiration/version monotonicity and rollback, freeze and mix-and-match
protection. Metadata trust is separate from file transport security and from
semantic model behavior.

Native inference workers receive only verified read-only pages or capability
handles and bounded session requests. No unrestricted networking, filesystem
discovery, bearer token, full messenger DB or E2EE encryption key in a worker.
OS-specific process sandbox, IPC size limits and crash/time/memory quotas must
be tested before treating native backends as secure.

## 3. Multiple formats require different execution backends

**GGUF** is the first delivery format. Use a version-pinned, security-reviewed
llama.cpp/ggml C API in an isolated C++ worker. Start CPU-only and with a
small explicit architecture/tokenizer/quantization allowlist. Follow with
Metal (Apple), CUDA (NVIDIA), Vulkan and HIP where benchmarks and security
tests justify it. GGUF does not imply every model architecture can execute.

**ONNX** is a second planned lane via pinned ONNX Runtime execution providers
and strict operator, tensor shape, file and resource bounds.

**safetensors** is a safe tensor container, not a complete universal inference
engine. Loading it still requires a separately supported architecture,
tokenizer/config mapping and tensor graph. Never execute upstream Python
trust_remote_code, pickle checkpoints or model-supplied shared libraries.

Apple MLX and additional backends are optional adapters, not a dependency for
all devices. Converted and quantized variants have NEW immutable identities;
a trusted release/variant metadata record must bind their lineage and exact
digest. A plain checksum next to a third-party blob is not a trust anchor.

### Versioned engine worker protocol (planned)

    probe_device -> DeviceCapabilities
    inspect_verified_variant -> Compatible | Rejected(reason)
    estimate_resources -> bounded resident RAM / VRAM / KV / scratch
    load_verified -> session handle (opaque verified page leases only)
    prefill -> token state
    decode -> bounded token stream
    cancel / unload -> release all resources

No dynamic arbitrary plugin download; permit only reviewed, version-pinned
backend modules. Interface must specify ABI version, architecture, format
version, quantization, tokenizer digest, required operators and memory budget.
Future C++/hand-optimized assembly is restricted to profiled GEMM, dequant,
attention and cache kernels with CPU feature detection and differential tests.
Do NOT write assembly for cryptography, untrusted parsers or authorization.

## 4. WeightFabric: many model listings without a terabyte-scale Jend server

Metadata is cheap: the registry stores signed catalog entries, size estimates,
license attribution, architecture/backend matrix, SHA-256 page identities
and known immutable source candidates, NOT all large weight artifacts.

Resolver policy:
1. Verified local CAS, deduplicated by content hash across model variants.
2. Optional user-authorized same-user LAN/device transfer.
3. Direct upstream publisher, whose URL and immutable release were authorized.
4. Very limited Jend seed cache for a deliberately selected model set, only
   when weights may lawfully be redistributed.
5. Optional explicit-consent P2P transfer of PUBLIC WEIGHTS ONLY.

A source supplies bytes, never the expected trust digest. Keep hard byte limits,
response status/content-range, DNS pinning, TLS, anti-SSRF, no redirects,
credentials isolated in source workers, structured retries and quotas. P2P is
OFF by default: IP-address exposure, NAT relays, bandwidth and battery matter.
No user messages, private files or secret model inputs may join a peer swarm.

Do not promise zero costs: all available model artifacts need a retrievable
copy SOMEWHERE; a million first downloads of 1 GB each create ~1 PB traffic,
independent of which provider carries it. If Jend promises first-install
availability for selected models it needs mirrors/seed capacity and budgets.
Local inference avoids per-chat-token API charges, not software distribution.

## 5. Weak device realism and hardware-level performance

For a dense decoder, most weights participate every generated token; a 64 MB
WeightVM cache cannot make a 7 GB dense model run fast in 64 MB of physical RAM.

    RAM_required >= resident_weights + KV_cache(context, batch)
                    + runtime_scratch + graph_buffers + OS_headroom

Disk/SSD cache cannot be counted as free RAM; memory mapping and paging protect
address space, not sustained token throughput. Sparse expert paging is justified
only when the model actually has a verified sparse compute graph. Device
feasibility should select SMALLER EXISTING variants/quantizations for weaker
hardware, lower context and lower batch, or report NotLocallyRunnable.
No hidden fallback to remote API if local execution is impossible.

Use observed working set, peak RSS, first-token latency, tokens/sec, energy,
thermal throttling and page-fault measurements on low-end CPU and Apple Silicon.
Hardware dispatch must check available CPU features before using AVX2,
AVX-512, NEON or AMX. Per-device optimized native kernels need overflow,
alignment, fuzz/sanitizer and known-good numerical comparisons.

## 6. Privacy and user consent

Local models must not transmit decrypted Jend conversations to the registry,
download network or peers. Tool/file/chat access requires user-scoped typed
capabilities; instructions from generated text do not confer privileges.
Diagnostics default to no prompt tokens, secrets or signed transfer URLs.
Remote inference requires distinct opt-in, provider identity, cost disclosure
and separate credentials. Never silently substitute API execution for local.

## 7. Delivery phases and hard proof gates

P0 / M8.5.14: this ADR + pure Rust conservative memory/backend feasibility
policy, tests for overflow, wrong execution backend and disk-versus-RAM.
This does NOT implement neural inference.

P1 / M8.5.15: isolated pinned llama.cpp GGUF CPU backend with permitted
architecture matrix, real stream/cancel, no arbitrary network or native code
load, crash containment, malformed tensor tests, measured RAM and throughput.

P2 / M8.5.16: multi-publisher signed catalog and variant identity, license
filter, source federation, verified cache; at least two providers tested.

P3 / M8.6: actual CPU/Metal/Vulkan/CUDA device measurements, GPU dispatch,
KV-cache budgeting and model-switch/eviction logic; add ONNX safely.

P4: optional peer transfer and optional BYOK remote API with full consent,
new endpoint permissions, cost policy and audits.

Release blockers: rejected metadata MUST not reach worker; a model with
unsupported architecture/backend MUST not launch; local OOM MUST not secretly
call an API; source changes MUST preserve independent signed page identities;
weak devices MUST not claim disk equals RAM; optional peer IP disclosure MUST
be explicit; verified installed models MUST work while completely offline.

## 8. Current evidence versus future scope

Already existing: Jend signed SourceMap/VirtualModelMap and WeightPage
SHA-256+length admission; local CAS; WeightVM residency; offline signed-page
bridge; tested one live HF/Xet signed HTTP 206 single-range fetch + 1 MiB
logical reconstruction on Mac; LocalPackage/VirtualPaged catalog contracts.

NOT yet implemented: universal inference, a pinned llama.cpp engine, a
production GGUF/ONNX adapter, externally provisioned full TUF-style trust
root, real multi-publisher weight catalog, production mirrors, P2P,
remote-BYOK, CPU SIMD native kernels or a production app runtime sandbox.

Reference standards: https://theupdateframework.github.io/specification/v1.0.36/
https://github.com/ggml-org/llama.cpp
https://onnxruntime.ai/docs/execution-providers/index.html
https://huggingface.co/docs/safetensors/index
