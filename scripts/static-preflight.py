#!/usr/bin/env python3
from __future__ import annotations

import re
import sys
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
FAILURES: list[str] = []


def require(condition: bool, message: str) -> None:
    if not condition:
        FAILURES.append(message)


def read(rel: str) -> str:
    return (ROOT / rel).read_text(encoding="utf-8")



# Cargo workspace/path-dependency structure. This does not replace cargo
# metadata; it catches missing local crates before dependency resolution.
workspace = tomllib.loads(read("Cargo.toml"))
members = workspace.get("workspace", {}).get("members", [])
require(bool(members), "Cargo workspace has no members")
for member in members:
    require((ROOT / member / "Cargo.toml").is_file(), f"workspace member missing Cargo.toml: {member}")

workspace_rust = str(workspace.get("workspace", {}).get("package", {}).get("rust-version", ""))
toolchain = tomllib.loads(read("rust-toolchain.toml"))
toolchain_channel = str(toolchain.get("toolchain", {}).get("channel", ""))
require(toolchain_channel.startswith(workspace_rust), "rust-toolchain does not match workspace rust-version")
require((ROOT / "scripts/dependency-policy.py").is_file(), "dependency policy script missing")

for manifest in ROOT.rglob("Cargo.toml"):
    if manifest == ROOT / "Cargo.toml":
        continue
    data = tomllib.loads(manifest.read_text(encoding="utf-8"))
    for section in ["dependencies", "dev-dependencies", "build-dependencies"]:
        for name, spec in data.get(section, {}).items():
            if isinstance(spec, dict) and "path" in spec:
                dep = (manifest.parent / spec["path"]).resolve()
                require((dep / "Cargo.toml").is_file(), f"broken path dependency {name} in {manifest.relative_to(ROOT)}")

# Migration order and table inventory.
migration_dir = ROOT / "deployment/postgres"
migrations = sorted(migration_dir.glob("[0-9][0-9][0-9]_*.sql"))
versions = [int(p.name[:3]) for p in migrations]
require(versions == list(range(1, len(versions) + 1)), f"migration versions not contiguous: {versions}")
require(len(versions) == len(set(versions)), "duplicate migration versions")

created_tables: set[str] = set()
for path in migrations:
    sql = path.read_text(encoding="utf-8")
    for match in re.finditer(
        r"CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?([a-zA-Z_][a-zA-Z0-9_]*)",
        sql,
        re.IGNORECASE,
    ):
        created_tables.add(match.group(1))

required_tables = {
    "accounts",
    "device_sets",
    "admission_buckets",
    "admission_used_challenges",
    "login_ip_buckets",
    "login_account_buckets",
    "consumed_login_tickets",
    "registration_device_bootstraps",
    "consumed_device_binding_challenges",
    "consumed_jreq_nonces",
}
require(required_tables <= created_tables, f"missing required tables: {sorted(required_tables-created_tables)}")
require("messages" not in created_tables, "server database must not contain a messages table")

# HTTP route / CLI smoke contract.
gateway = read("server/jend-gateway/src/main.rs")
cli = read("client/jend-cli/src/main.rs")
routes = set(re.findall(r'\.route\("([^"]+)"', gateway))
cli_paths = set(re.findall(r'(/v1/[A-Za-z0-9_./-]+|/readyz)', cli))
require(cli_paths <= routes | {"/readyz", "/healthz"}, f"CLI paths missing on gateway: {sorted(cli_paths-routes)}")

# JREQ enforcement must stay on the implemented device-sensitive routes.
for function_name in ["current_device_set", "submit_device_set", "refresh_device_capability"]:
    match = re.search(rf"async fn {function_name}\(.*?\n\}}", gateway, re.DOTALL)
    require(match is not None, f"missing handler {function_name}")
    if match:
        require("verify_device_jreq" in match.group(0), f"{function_name} lost JREQ verification")

# Trusted-device login must require a server-authenticated challenge before DB/account lookup.
session_finish = re.search(r"async fn device_session_finish\(.*?\n\}", gateway, re.DOTALL)
require(session_finish is not None, "missing device_session_finish")
if session_finish:
    body = session_finish.group(0)
    freshness_pos = body.find("verify_fresh_device_session_challenge")
    account_pos = body.find("account_by_id")
    require(freshness_pos >= 0, "device session finish does not verify challenge MAC + freshness")
    require(account_pos >= 0, "device session finish does not load account")
    require(
        0 <= freshness_pos < account_pos,
        "device session MAC/freshness must be verified before account lookup",
    )


# Startup/readiness must cover every PostgreSQL table referenced by the current gateway.
query_tables = set(re.findall(
    r"(?:FROM|INTO|UPDATE|JOIN)\s+([a-z_][a-z0-9_]*)",
    read("server/jend-gateway/src/repository.rs"),
    re.IGNORECASE,
))
for table in sorted(query_tables):
    require(
        f"public.{table}" in gateway,
        f"gateway readiness/startup contract omits repository table: {table}",
    )
require("database_schema_ready(&pool).await?" in gateway, "gateway does not fail startup on incomplete schema")
migration_version = re.search(r"const REQUIRED_MIGRATION_VERSION: i64 = (\d+);", gateway)
require(migration_version is not None, "gateway lacks required migration version gate")
if migration_version:
    require(int(migration_version.group(1)) == max(versions), "gateway migration version gate does not match migration directory")
require("_sqlx_migrations" in gateway, "gateway readiness does not verify SQLx migration state")
require("REQUIRED_COLUMNS_QUERY" in gateway, "gateway readiness lacks critical column contract")
require("latest_successful == Some(REQUIRED_MIGRATION_VERSION)" in gateway, "gateway does not require exact migration version")
require("validate_bind_address(addr, allow_insecure_http)?" in gateway, "gateway does not validate plain-HTTP bind address")
require("JEND_ALLOW_INSECURE_HTTP" in gateway, "missing explicit insecure HTTP override gate")

# Key generation/loading contract must match exactly for the new MAC key.
secrets = read("server/jend-gateway/src/secrets.rs")
keygen = read("server/jend-keygen/src/main.rs")
secret_name = "device-session-hmac.key"
require(secret_name in secrets, "gateway does not load device-session HMAC key")
require(secret_name in keygen, "keygen does not generate device-session HMAC key")
require("challenge_mac" in cli, "CLI smoke does not carry device-session challenge MAC")
require("forged device-session challenge MAC" in cli, "CLI smoke lacks forged challenge-MAC negative test")

# JREQ replay invariant: DeviceSet mutation uses atomic nonce+CAS repository operation.
repository = read("server/jend-gateway/src/repository.rs")
require("compare_and_swap_device_set_with_jreq" in repository, "missing atomic JREQ DeviceSet CAS")
atomic = re.search(r"pub async fn compare_and_swap_device_set_with_jreq\(.*?\n\}", repository, re.DOTALL)
if atomic:
    text = atomic.group(0)
    require("pool.begin()" in text, "JREQ DeviceSet CAS is not transactional")
    require("consumed_jreq_nonces" in text, "JREQ nonce is not consumed in DeviceSet transaction")
    require("UPDATE device_sets" in text, "DeviceSet transaction does not update DeviceSet")
else:
    require(False, "cannot inspect atomic JREQ DeviceSet CAS")

# jend-auth intentionally needs two SHA-2 major lines: opaque-ke 4.0.1 is on
# digest 0.10, while hkdf 0.13 is on the newer RustCrypto digest generation.
auth_manifest = tomllib.loads(read("crates/jend-auth/Cargo.toml"))
auth_deps = auth_manifest.get("dependencies", {})
require(auth_deps.get("sha2") == "0.11.0", "jend-auth HKDF must use sha2 0.11.0")
sha2_10 = auth_deps.get("sha2_10", {})
require(
    isinstance(sha2_10, dict)
    and sha2_10.get("package") == "sha2"
    and sha2_10.get("version") == "0.10.9",
    "jend-auth OPAQUE suite must retain renamed sha2 0.10.9",
)
require(
    "use sha2_10::Sha512;" in read("crates/jend-auth/src/suite.rs"),
    "OPAQUE suite is not wired to the digest-0.10 SHA-512 dependency",
)
require(
    "use sha2::Sha256;" in read("crates/jend-auth/src/recovery.rs"),
    "recovery HKDF is not wired to SHA-2 0.11",
)

for crate in ["crates/jend-core", "crates/jend-sync"]:
    manifest = tomllib.loads(read(f"{crate}/Cargo.toml")).get("dependencies", {})
    require(manifest.get("hkdf") == "0.13.0", f"{crate} HKDF requirement drift")
    require(manifest.get("sha2") == "0.11.0", f"{crate} HKDF/SHA-2 generation mismatch")

gateway_deps = tomllib.loads(read("server/jend-gateway/Cargo.toml")).get("dependencies", {})
require(gateway_deps.get("hmac") == "0.12", "gateway HMAC requirement drift")
require(gateway_deps.get("sha2") == "0.10.9", "gateway HMAC/SHA-2 generation mismatch")

# OPAQUE 4.0.1 re-exports rand 0.8 built with default features disabled.
# jend-auth needs an explicit rand dependency so rngs::OsRng is available.
auth_manifest_for_rng = tomllib.loads(read("crates/jend-auth/Cargo.toml"))
auth_rng = auth_manifest_for_rng.get("dependencies", {}).get("rand")
require(auth_rng == "0.8.5", "jend-auth must explicitly enable rand 0.8.5 for OsRng")
require(
    "opaque_ke::rand::rngs::OsRng" not in read("crates/jend-auth/src/client.rs")
    and "opaque_ke::rand::rngs::OsRng" not in read("crates/jend-auth/src/server.rs"),
    "jend-auth must not rely on opaque-ke's feature-limited rand re-export for OsRng",
)
require(
    "use rand::rngs::OsRng;" in read("crates/jend-auth/src/client.rs")
    and "use rand::rngs::OsRng;" in read("crates/jend-auth/src/server.rs"),
    "jend-auth OPAQUE flows are not wired to explicit rand::rngs::OsRng",
)

# JREQ Request is reused by struct-update negative tests. Keep it Copy so the
# second tampering case is not a use-after-move compile error.
jreq_source = read("crates/jend-jreq/src/lib.rs")
require(
    "#[derive(Clone, Copy, Debug)]\npub struct Request<'a>" in jreq_source,
    "JREQ Request must remain Copy for current tampering tests",
)

# RustCrypto chacha20poly1305 0.11 compatibility contract. The crate-level
# `Key` alias is no longer generic; old `Key::<Cipher>::from_slice` syntax is a
# compile error. Hybrid-array `from_slice` also remains only as a deprecated
# compatibility method, so keep nonce construction on the current Array API.
rust_sources = "\n".join(
    path.read_text(encoding="utf-8")
    for path in ROOT.rglob("*.rs")
    if "target" not in path.parts
)
require(
    "Key::<XChaCha20Poly1305>" not in rust_sources,
    "obsolete generic chacha20poly1305::Key syntax reintroduced",
)
require(
    "XNonce::from_slice" not in rust_sources,
    "deprecated XNonce::from_slice syntax reintroduced",
)
require(
    rust_sources.count("XChaCha20Poly1305::new_from_slice") >= 18,
    "expected XChaCha20Poly1305 0.11 key construction sites are missing",
)

# Headless local/CI runtime contract must not drift by PostgreSQL major.
compose = read("deployment/docker-compose.headless.yml")
workflow = read(".github/workflows/headless-ci.yml")
compose_pg = re.search(r"image:\s*postgres:([0-9]+)-alpine", compose)
workflow_pg = re.search(r"image:\s*postgres:([0-9]+)-alpine", workflow)
require(compose_pg is not None, "cannot determine local PostgreSQL major")
require(workflow_pg is not None, "cannot determine CI PostgreSQL major")
if compose_pg and workflow_pg:
    require(compose_pg.group(1) == workflow_pg.group(1), "local/CI PostgreSQL major mismatch")
require("cargo generate-lockfile" in workflow, "CI does not explicitly generate Cargo.lock")
require("cargo metadata --format-version 1 --locked > resolved-metadata.json" in workflow, "CI metadata is not lockfile-bound")
require("cargo check --workspace --all-targets --locked" in workflow, "CI cargo check is not lockfile-bound")
require("cargo test --workspace --all-targets --locked" in workflow, "CI cargo test is not lockfile-bound")
require("Cargo.lock" in workflow, "CI does not preserve generated Cargo.lock")


# Keep SQLx on explicit 0.8 runtime/TLS features until the first real Cargo.lock exists.
for rel in ["server/jend-gateway/Cargo.toml", "server/jend-migrate/Cargo.toml"]:
    manifest_text = read(rel)
    require("runtime-tokio-rustls" not in manifest_text, f"{rel} uses soft-deprecated SQLx combined feature")
    require('version = "=0.8.6"' in manifest_text, f"{rel} must pin SQLx 0.8.6 before lockfile generation")
    require('"runtime-tokio"' in manifest_text, f"{rel} missing SQLx Tokio runtime feature")
    require('"tls-rustls-ring-webpki"' in manifest_text, f"{rel} missing explicit SQLx rustls/WebPKI feature")


# M8.5.6 signed WeightPage publication boundary.
model_store_manifest = tomllib.loads(read("crates/jend-model-store/Cargo.toml")).get("dependencies", {})
require(
    model_store_manifest.get("subtle") == "2.6.1",
    "verified WeightPage digest comparison must retain subtle 2.6.1",
)
source_protocol_m856 = read("crates/jend-model-store/src/source_protocol.rs")
release_m856 = read("crates/jend-model-store/src/release.rs")
weight_store_m856 = read("crates/jend-model-store/src/weight_store.rs")
weightvm_m856 = read("crates/jend-model-store/src/weightvm.rs")
require(
    "pub struct VerifiedSourceReadRequest" in source_protocol_m856
    and "request: SourceReadRequest" in source_protocol_m856,
    "opaque verified source-read token missing",
)
require(
    "pub fn verify_source_read_request(" in release_m856
    and "validate_against_virtual_map" in release_m856,
    "release key no longer gates source request through both signed maps",
)
require(
    "pub fn put_verified_source_page(" in weight_store_m856
    and "verify_page_bytes(descriptor, bytes)?;" in weight_store_m856,
    "durable store lost pre-staging signed WeightPage verification",
)
require(
    "ConstantTimeEq" in weight_store_m856 and "ConstantTimeEq" in weightvm_m856,
    "WeightPage SHA-256 comparisons lost constant-time equality",
)
require(
    (ROOT / "scripts/dev-verified-weight-page-smoke.sh").is_file(),
    "M8.5.6 verified WeightPage smoke script missing",
)
require(
    (ROOT / "scripts/prepare-m8.5.6-lock.sh").is_file(),
    "M8.5.6 lock preparation script missing",
)

if FAILURES:
    for failure in FAILURES:
        print(f"FAIL: {failure}", file=sys.stderr)
    raise SystemExit(1)

# First-test ladder must keep the focused OPAQUE/JREQ/gateway sequence.
ladder = read("scripts/first-test-ladder.sh")
for required in [
    "cargo test -p jend-auth --test opaque_roundtrip --locked",
    "cargo test -p jend-jreq --locked",
    "cargo test -p jend-gateway --bin jend-gateway --locked",
    "cargo check --workspace --all-targets --locked",
]:
    require(required in ladder, f"first-test ladder missing: {required}")
require(
    (ROOT / "crates/jend-auth/tests/opaque_roundtrip.rs").is_file(),
    "missing OPAQUE first-run integration test",
)


# Rust type contract: Zeroizing<[u8; 32]>::as_ref() erases the array length to
# &[u8], but derive_step requires &[u8; 32]. Keep the explicit Deref coercion.
ratchet = read("crates/jend-core/src/ratchet.rs")
require(
    "derive_step(self.chain_key.as_ref(), seq)" not in ratchet,
    "ratchet regressed to &[u8] where derive_step requires &[u8; 32]",
)
require(
    ratchet.count("derive_step(&*self.chain_key, seq)") == 2,
    "ratchet must use explicit array-preserving deref at both derive_step call sites",
)


# Rust type contract for Zeroizing<[u8; 32]>: `.as_ref()` erases the array
# length to `&[u8]`. KDF helpers below deliberately require `&[u8; 32]`.
for rel, expected_count in [
    ("crates/jend-sync/src/envelope.rs", 2),
    ("crates/jend-sync/src/recovery.rs", 2),
]:
    source = read(rel)
    require(
        "shared.as_ref()," not in source,
        f"{rel} regressed to &[u8] where KDF helper requires &[u8; 32]",
    )
    require(
        source.count("&*shared,") >= expected_count,
        f"{rel} missing explicit array-preserving Zeroizing deref",
    )


# Axum router contract: route handler identifiers must not be shadowed by local
# bindings in main(), otherwise post/get receives a value instead of a handler.
route_handlers = set(re.findall(
    r'\.route\("[^"]+",\s*(?:get|post)\(([A-Za-z_][A-Za-z0-9_]*)\)\)',
    gateway,
))
main_pos = gateway.find("async fn main()")
main_body = gateway[main_pos:] if main_pos >= 0 else gateway
main_bindings = set(re.findall(r"\blet\s+(?:mut\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=", main_body))
shadowed_handlers = sorted(route_handlers & main_bindings)
require(not shadowed_handlers, f"Axum route handlers shadowed in main(): {shadowed_handlers}")
require(
    "TimeoutLayer::new(" not in gateway,
    "gateway uses deprecated tower-http TimeoutLayer::new",
)
require(
    "TimeoutLayer::with_status_code(StatusCode::REQUEST_TIMEOUT" in gateway,
    "gateway timeout layer must use explicit request-timeout status code",
)


# Rust type contract for mutable Zeroizing<[u8; 32]> secrets in Vault:
# `.as_mut()` erases the array length to `&mut [u8]`, while import constructors
# intentionally require `&mut [u8; 32]` so the exact key size is type-checked.
vault_source = read("crates/jend-vault/src/vault.rs")
for obsolete in [
    "ark_bytes.as_mut()",
    "device_bytes.as_mut()",
    "sync_signing.as_mut(),",
    "sync_kex.as_mut(),",
]:
    require(obsolete not in vault_source, f"vault regressed to slice-erasing mutable secret coercion: {obsolete}")
for required in [
    "AccountRootKey::from_secret_bytes(&mut *ark_bytes)",
    "DeviceIdentity::from_secret_bytes(&mut *device_bytes)",
    "&mut *sync_signing,",
    "&mut *sync_kex,",
]:
    require(required in vault_source, f"vault missing fixed-array mutable secret coercion: {required}")

# The live HTTP gateway no longer keeps the unused synchronous repository
# adapter or the superseded non-JREQ DeviceSet CAS implementation.
repo_source = read("server/jend-gateway/src/repository.rs")
require("PgGatewayRepository" not in repo_source, "dead PgGatewayRepository adapter reintroduced")
require(
    "compare_and_swap_device_set_async" not in repo_source,
    "superseded non-JREQ DeviceSet CAS path reintroduced",
)


# Secret-bearing ConversationSeed intentionally avoids Debug. Tests must not
# use Result::unwrap_err() where the Ok type would require Debug.
core_keys = read("crates/jend-core/src/keys.rs")
require(
    ".unwrap_conversation_seed(&[2u8; 16], &envelope)\n            .unwrap_err()" not in core_keys,
    "ConversationSeed test regressed to unwrap_err(), which requires Debug on secret material",
)
require(
    "matches!(result, Err(JendError::Aead))" in core_keys,
    "conversation-id binding test must assert the AEAD error without Debug on ConversationSeed",
)

cli_source = read("client/jend-cli/src/main.rs")
require(
    "require_future_expiry" in cli_source,
    "CLI smoke no longer validates server expiry timestamps",
)
for field in [
    "bootstrap_expires_unix_ms",
    "login.expires_unix_ms",
    "bind_started.expires_unix_ms",
    "bound.expires_unix_ms",
    "refreshed.expires_unix_ms",
    "session_started.expires_unix_ms",
    "session_cap.expires_unix_ms",
]:
    require(field in cli_source, f"CLI expiry contract missing: {field}")

vault_daemon = read("crates/jend-vault/src/bin/jend-vaultd.rs")
require(
    "fs::remove_file(&socket_path)" not in vault_daemon,
    "Vault daemon must not unlink an existing socket path on startup",
)
require(
    "metadata.permissions().mode() & 0o077 != 0" in vault_daemon,
    "Vault IPC parent must remain private",
)
require(
    "fs::symlink_metadata(&socket_path).is_ok()" in vault_daemon,
    "Vault daemon must refuse existing socket paths including symlinks",
)


vault_ipc = read("crates/jend-vault/src/ipc.rs")
for required in [
    "const MAX_IPC_BODY: usize = 16 * 1024 * 1024;",
    "pub struct VaultIpcClient",
    "REQ_DEVICE_PUBLIC_IDENTITY",
    "stream.set_read_timeout",
    "stream.set_write_timeout",
]:
    # Socket timeout calls live in the daemon; protocol/client symbols live here.
    if required.startswith("stream."):
        continue
    require(required in vault_ipc, f"Vault IPC M7.1 contract missing: {required}")
require(
    "if body.len() > MAX_IPC_BODY" in vault_ipc,
    "Vault IPC must bound request/response bodies",
)

vault_daemon = read("crates/jend-vault/src/bin/jend-vaultd.rs")
for required in [
    "stream.set_read_timeout",
    "stream.set_write_timeout",
    "Duration::from_secs(5)",
    "fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))",
]:
    require(required in vault_daemon, f"Vault daemon liveness/privacy contract missing: {required}")

vault_smoke = read("scripts/dev-vault-ipc-smoke.sh")
for required in [
    "jend-vault-smoke",
    "second Vault replaced an existing socket",
    "device signing identity changed",
    "Jend Vault IPC process smoke: PASS",
]:
    if required == "device signing identity changed":
        require(
            required in read("crates/jend-vault/src/bin/jend-vault-smoke.rs"),
            "Vault restart smoke must verify durable device identity",
        )
    else:
        require(required in vault_smoke, f"Vault process smoke contract missing: {required}")


vault_ipc_m72 = read("crates/jend-vault/src/ipc.rs")
for required in [
    "const IPC_VERSION: u16 = 2;",
    "pub struct IpcAuthToken",
    "constant_time_eq_32",
    "UnauthorizedIpc",
    "serve_authenticated_unix_stream",
    "read_authenticated_request",
]:
    require(required in vault_ipc_m72, f"Vault M7.2 IPC authorization contract missing: {required}")
require(
    "ConversationId, DevicePublicIdentity, MessageRole" in vault_ipc_m72
    and "InnerMessage" not in vault_ipc_m72,
    "Vault IPC must not regress the M7.1 unused InnerMessage import warning",
)

vault_daemon_m72 = read("crates/jend-vault/src/bin/jend-vaultd.rs")
for required in [
    "const WORKERS: usize = 4;",
    "const QUEUE_DEPTH: usize = 32;",
    "mpsc::sync_channel(QUEUE_DEPTH)",
    "tx.try_send(stream)",
    "vault IPC queue full; connection rejected",
    "IpcAuthToken::generate()",
    "authorization path already exists",
]:
    require(required in vault_daemon_m72, f"Vault M7.2 bounded-runtime contract missing: {required}")

vault_smoke_m72 = read("scripts/dev-vault-ipc-smoke.sh")
require(
    "wrong Vault IPC capability was accepted" in vault_smoke_m72,
    "Vault smoke must reject an incorrect IPC capability",
)
vault_cargo_m721 = read("crates/jend-vault/Cargo.toml")
require(
    'subtle = ' not in vault_cargo_m721,
    "M7.2.1 must not require a Cargo.lock update for IPC capability comparison",
)
require(
    "diff |= left[i] ^ right[i];" in vault_ipc_m72,
    "Vault IPC capability comparison must scan all 32 bytes",
)


vault_ipc_m722 = read("crates/jend-vault/src/ipc.rs")
require(
    ".append_message(id, role, timestamp, plaintext)?" in vault_ipc_m722,
    "Vault IPC append path must pass SensitiveBytes by value",
)
require(
    ".append_message(id, role, timestamp, plaintext.as_bytes())?" not in vault_ipc_m722,
    "Vault IPC append path must not downgrade SensitiveBytes to a byte slice",
)


vault_daemon_m723 = read("crates/jend-vault/src/bin/jend-vaultd.rs")
require(
    "mpsc::sync_channel::<std::os::unix::net::UnixStream>(QUEUE_DEPTH)" in vault_daemon_m723,
    "Vault IPC worker channel must explicitly carry UnixStream on Rust 1.99",
)
require(
    "let (tx, rx) = mpsc::sync_channel(QUEUE_DEPTH);" not in vault_daemon_m723,
    "Vault IPC worker channel must not rely on diverging never-type inference",
)


runtime_m73 = read("crates/jend-vault/src/runtime.rs")
for required in [
    "pub enum RuntimeLane",
    "UiInteractive",
    "VaultCritical",
    "AiForeground",
    "pub fn try_submit",
    "const MAX_URGENT_BURST: usize = 8;",
    "pub struct RuntimeSnapshot",
    "RuntimePressure",
]:
    require(required in runtime_m73, f"M7.3 runtime scheduler contract missing: {required}")
require(
    "try_submit" in runtime_m73 and "queue.len() >= self.limits.capacity(lane)" in runtime_m73,
    "M7.3 latency-sensitive submission must remain bounded/non-blocking",
)
require(
    "std::array::from_fn" in runtime_m73,
    "M7.3 scheduler queues must remain fixed-lane rather than dynamically growing lanes",
)

vault_cargo_m73 = read("crates/jend-vault/Cargo.toml")
require(
    "jend-runtime" not in read("Cargo.toml"),
    "M7.3 must not add a workspace crate and invalidate the existing Cargo.lock",
)
require(
    'subtle = ' not in vault_cargo_m73,
    "M7.3 must preserve the no-new-dependency lock-compatible baseline",
)

runtime_smoke_m73 = read("crates/jend-vault/src/bin/jend-runtime-smoke.rs")
for required in [
    "AI backlog overtook UI work",
    "runtime failed to bound the AI queue",
    "Jend runtime priority/backpressure smoke: PASS",
]:
    require(required in runtime_smoke_m73, f"M7.3 runtime smoke contract missing: {required}")


runtime_m74 = read("crates/jend-vault/src/runtime.rs")
require(
    "fn has_work(&self)" not in runtime_m74,
    "M7.4 must keep the runtime free of the M7.3 dead-code warning",
)

performance_m74 = read("crates/jend-vault/src/performance.rs")
for required in [
    "pub enum DeviceTier",
    "pub struct DeviceProfile",
    "thread::available_parallelism()",
    "pub struct AdaptivePerformancePolicy",
    "RuntimePressure::Saturated",
    "policy.ai_workers = 1;",
    "policy.background_workers = 0;",
    "None => DeviceTier::Balanced",
]:
    require(required in performance_m74, f"M7.4 adaptive-performance contract missing: {required}")

require(
    'Command::new("/usr/sbin/sysctl")' in performance_m74,
    "macOS device profiler must use the local sysctl memory signal",
)
require(
    '"hw.memsize"' in performance_m74,
    "macOS device profiler must read coarse RAM capacity",
)
require(
    "brand_string" not in performance_m74.lower()
    and "cpu model" not in performance_m74.lower(),
    "M7.4 policy must not depend on CPU brand/model identifiers",
)

performance_smoke_m74 = read("crates/jend-vault/src/bin/jend-performance-smoke.rs")
for required in [
    "saturated policy increased AI concurrency",
    "logical_parallelism",
    "Jend adaptive performance smoke: PASS",
]:
    require(required in performance_smoke_m74, f"M7.4 performance smoke missing: {required}")


performance_m75 = read("crates/jend-vault/src/performance.rs")
for required in [
    "pub enum PlatformClass",
    "PlatformClass::Mobile",
    'target_os = "ios"',
    'target_os = "android"',
    "pub enum ThermalPressure",
    "pub enum PowerMode",
    "pub struct RuntimeSignals",
    "policy.ai_workers = policy.ai_workers.min(2);",
    "policy.allow_background_prefetch = false;",
]:
    require(required in performance_m75, f"M7.5 mobile performance contract missing: {required}")

require(
    'target_os = "android"' in performance_m75
    and '"/proc/meminfo"' in performance_m75,
    "Android profiler must use the local proc memory signal",
)
require(
    "iOS intentionally takes the conservative fallback" in performance_m75,
    "iOS must keep a conservative no-shell fallback until a platform bridge exists",
)

controller_m75 = read("crates/jend-vault/src/controller.rs")
for required in [
    "pub struct RuntimeController",
    "update_runtime_pressure",
    "update_thermal_pressure",
    "update_power_mode",
    "pub struct PolicyUpdate",
]:
    require(required in controller_m75, f"M7.5 runtime controller contract missing: {required}")

performance_smoke_m75 = read("crates/jend-vault/src/bin/jend-performance-smoke.rs")
for required in [
    "simulated_mobile",
    "mobile baseline exceeded conservative sustained-performance limits",
    "mobile low-power policy failed to reduce compute load",
    "mobile critical-thermal policy failed to protect the device",
    "Jend mobile adaptive policy: PASS",
]:
    require(required in performance_smoke_m75, f"M7.5 mobile smoke contract missing: {required}")


runtime_m76 = read("crates/jend-vault/src/runtime.rs")
for required in [
    "pub struct RuntimeQueueUpdate",
    "pub fn update_limits",
    "pub fn limits",
    "state.limits = limits;",
    "allowed to drain",
]:
    require(required in runtime_m76, f"M7.6 dynamic queue contract missing: {required}")
require(
    "limits: RuntimeQueueLimits," in runtime_m76,
    "M7.6 scheduler state must own live queue limits",
)

controller_m76 = read("crates/jend-vault/src/controller.rs")
for required in [
    "pub struct RuntimeExecutionLimits",
    "pub struct RuntimeGovernor",
    "pub struct GovernorUpdate",
    "self.scheduler.update_limits",
    "ai_foreground: self.policy.ai_queue_limit",
    "background: if self.policy.background_workers == 0",
]:
    require(required in controller_m76, f"M7.6 governor contract missing: {required}")

governor_smoke_m76 = read("crates/jend-vault/src/bin/jend-governor-smoke.rs")
for required in [
    "adaptive policy reduced an interactive queue",
    "live AI queue did not apply low-power backpressure",
    "accepted pre-policy task was dropped",
    "Jend dynamic runtime policy application: PASS",
]:
    require(required in governor_smoke_m76, f"M7.6 governor smoke missing: {required}")


catalog_m77 = read("crates/jend-model-store/src/catalog.rs")
for required in [
    "pub enum ModelDelivery",
    "LocalPackage",
    "ProviderRemote",
    "VirtualPaged",
    "pub enum WeightRights",
    "pub enum ProviderCredentialMode",
    "pub fn approximate_quantized_weight_bytes",
    "500_000_000_000",
]:
    require(required in catalog_m77, f"M7.7 model-access contract missing: {required}")

require(
    "WeightRights::Unavailable" in catalog_m77
    and "return Err(ModelStoreError::InvalidCatalogModel)" in catalog_m77,
    "M7.7 must fail closed when unavailable weights are packaged locally",
)

manifest_m77 = read("crates/jend-model-store/src/manifest.rs")
require(
    "64 * 1024 * 1024 * 1024 * 1024" in manifest_m77,
    "M7.7 manifest ceiling must support multi-terabyte logical models",
)

model_access_smoke_m77 = read("crates/jend-model-store/src/bin/jend-model-access-smoke.rs")
for required in [
    "closed/provider model incorrectly required local weights",
    "trillion-parameter storage math regression",
    "virtual model did not produce a virtual-index install plan",
    "Jend model access/provider/virtual-paging contract: PASS",
]:
    require(required in model_access_smoke_m77, f"M7.7 model-access smoke missing: {required}")


source_m78 = read("crates/jend-model-store/src/source.rs")
for required in [
    "HuggingFaceSnapshot",
    "commit_sha.len() != 40",
    "PublisherHttps",
    "artifact_sha256",
    "RedistributionDecision",
    "permits_weight_publication",
    "SourceFingerprint",
]:
    require(required in source_m78, f"M7.8 immutable-source contract missing: {required}")
require(
    '"main"' in source_m78 and "assert!(main.validate().is_err())" in source_m78,
    "M7.8 must regression-test rejection of floating Hugging Face main revisions",
)

safety_m78 = read("crates/jend-model-store/src/safety.rs")
for required in [
    "SupplyChainReport",
    "BehavioralEvalReport",
    "ArtifactFormat::Pickle",
    "requires_custom_code",
    "SupplyChainDecision::Quarantine",
    "StoreSafetyStatus::Restricted",
    "backdoor_suite",
    "prompt_injection_suite",
    "tool_abuse_suite",
    "data_exfiltration_suite",
]:
    require(required in safety_m78, f"M7.8 model-safety contract missing: {required}")
require(
    "if self.format == ArtifactFormat::Pickle" in safety_m78
    and "return SupplyChainDecision::Reject;" in safety_m78,
    "M7.8 Store must reject direct pickle loading",
)

ingest_smoke_m78 = read("crates/jend-model-store/src/bin/jend-model-ingest-smoke.rs")
for required in [
    "pickle package escaped the Store rejection gate",
    "Jend immutable-source/license/quarantine contract: PASS",
    "Jend model supply-chain/behavior safety contract: PASS",
]:
    require(required in ingest_smoke_m78, f"M7.8 ingest smoke missing: {required}")


activation_m79 = read("crates/jend-model-store/src/activation.rs")
for required in [
    "pub struct ModelCacheBudget",
    "pub enum ActivationPlan",
    "VirtualOnDemand",
    "pub enum ExecutionReadiness",
    "StreamedOnDemand",
    "NeedsMoreLocalData",
    "pub struct SelectedModel",
    "evict_unselected_cache",
    "installation-footprint target",
]:
    require(required in activation_m79, f"M7.9 zero-install contract missing: {required}")
require(
    "bootstrap_bytes, 32 * 1024 * 1024" in activation_m79
    and "disk_cache_budget_bytes, 64 * 1024 * 1024" in activation_m79,
    "M7.9 must regression-test a megabyte-scale virtual-model selection footprint",
)
require(
    "active_weight_bytes <= disk_cache_budget_bytes" not in activation_m79,
    "M7.9 must not conflate tiny cache size with the true active working set",
)

zero_install_smoke_m79 = read("crates/jend-model-store/src/bin/jend-zero-install-smoke.rs")
for required in [
    "virtual model bootstrap is not megabyte-scale",
    "cache/working-set distinction",
    "model slot replacement contract failed",
    "Jend zero-install model selection/cache contract: PASS",
]:
    require(required in zero_install_smoke_m79, f"M7.9 smoke contract missing: {required}")


ai_executor_m710 = read("crates/jend-model-store/src/ai_executor.rs")
for required in [
    "pub struct AiExecutor",
    "pub struct AiExecutorLimits",
    "pub fn try_submit",
    "pub fn cancellation_requested",
    "pub fn update_limits",
    "QueueFull",
    "ActiveMarked",
]:
    require(required in ai_executor_m710, f"M7.10 AI executor contract missing: {required}")
require(
    "prompt" not in ai_executor_m710.lower(),
    "M7.10 model-store AI scheduler metadata must not contain prompt plaintext fields",
)

aid_m710 = read("crates/jend-model-store/src/bin/jend-aid.rs")
for required in [
    "UnixListener",
    "0o600",
    "0o700",
    "Zeroizing<Vec<u8>>",
    "constant_time_eq",
    "MAX_INPUT",
    "HARD_WORKERS",
    "sync_channel::<UnixStream>",
    "cancellation_requested",
]:
    require(required in aid_m710, f"M7.10 AI process boundary missing: {required}")

model_store_cargo_m710 = read("crates/jend-model-store/Cargo.toml")
for forbidden in ["reqwest", "hyper", "tokio", "url ="]:
    require(
        forbidden not in model_store_cargo_m710,
        f"M7.10 AI process package must not gain direct network dependency: {forbidden}",
    )
require(
    "jend-vault" not in model_store_cargo_m710,
    "M7.10 AI process package must not link the Vault crate",
)

ai_smoke_m710 = read("scripts/dev-ai-executor-smoke.sh")
for required in [
    "wrong-auth",
    "second AI daemon unexpectedly replaced live IPC state",
    "AI prompt plaintext was persisted outside process memory",
    "Jend AI executor process smoke: PASS",
]:
    require(required in ai_smoke_m710, f"M7.10 AI process smoke missing: {required}")


ai_executor_m7101 = read("crates/jend-model-store/src/ai_executor.rs")
require(
    "pub enum AiSubmitFailure<T>" in ai_executor_m7101,
    "M7.10.1 requires the AI submit failure contract",
)
require(
    "#[derive(Debug)]\npub enum AiSubmitFailure<T>" not in ai_executor_m7101,
    "M7.10.1 must not add Debug to generic AI submit failures solely for tests",
)
require(
    ".try_submit(job(1, 7)).unwrap()" not in ai_executor_m7101
    and ".try_submit(job(1, 1)).unwrap()" not in ai_executor_m7101
    and ".try_submit(job(2, 2)).unwrap()" not in ai_executor_m7101
    and ".try_submit(job(3, 11)).unwrap()" not in ai_executor_m7101
    and ".try_submit(job(4, 1)).unwrap()" not in ai_executor_m7101
    and ".try_submit(job(5, 1)).unwrap()" not in ai_executor_m7101,
    "AI executor tests must not require Debug through Result::unwrap",
)

aid_m7102 = read("crates/jend-model-store/src/bin/jend-aid.rs")
require(
    "OpenOptionsExt" in aid_m7102,
    "M7.10.2 jend-aid must import Unix OpenOptionsExt for mode(0o600)",
)
require(
    ".mode(0o600)" in aid_m7102,
    "M7.10.2 jend-aid auth file must preserve create-time 0600 permissions",
)
require(
    "fs::{OpenOptionsExt, PermissionsExt}" in aid_m7102,
    "M7.10.2 Unix filesystem extension traits must remain in scope",
)

prototype_m711 = read("crates/jend-model-store/src/prototype.rs")
for required in [
    "pub enum ModelIdentityKind",
    "ProviderBacked",
    "JendIndependent",
    "RestrictedProviderOutput",
    "UnknownOrLeakedMaterial",
    "no_restricted_provider_distillation",
    "no_unlicensed_weights",
    "no_provider_impersonation",
]:
    require(required in prototype_m711, f"M7.11 clean-room contract missing: {required}")
clean_room_smoke_m711 = read("crates/jend-model-store/src/bin/jend-clean-room-smoke.rs")
for required in [
    "restricted provider output escaped clean-room provenance gate",
    "unknown/leaked checkpoint escaped provenance gate",
    "Jend clean-room independent-model provenance: PASS",
    "Jend provider/prototype identity separation: PASS",
]:
    require(required in clean_room_smoke_m711, f"M7.11 clean-room smoke missing: {required}")

execution_m712 = read("crates/jend-model-store/src/execution.rs")
for required in [
    "pub enum ChatExecutionRoute",
    "LocalAi",
    "ProviderAdapter",
    "provider_model_never_routes_into_local_ai_executor",
    "virtual_model_routes_to_same_local_ai_boundary",
]:
    require(required in execution_m712, f"M7.12 chat routing contract missing: {required}")

provider_broker_m712 = read("crates/jend-net-broker/src/provider.rs")
for required in [
    "pub struct ProviderTunnelPolicy",
    "validate_adapter_request",
    "authorize_tunnel",
    "ProviderTunnelMeter",
    "account_encrypted_upload",
    "account_encrypted_download",
    "opaque TLS bytes",
    "validate_and_pin_https_target",
]:
    require(required in provider_broker_m712, f"M7.12 provider broker contract missing: {required}")

require(
    "Authorization" in provider_broker_m712
    and "prompt" in provider_broker_m712
    and "parse" in provider_broker_m712,
    "M7.12 must document that the Network Broker does not parse provider secrets/plaintext",
)
require(
    'ProviderTunnel' in read("crates/jend-net-broker/src/lib.rs"),
    "M7.12 Network Broker must expose a dedicated ProviderTunnel request kind",
)

provider_smoke_m712 = read("crates/jend-net-broker/src/bin/jend-provider-broker-smoke.rs")
for required in [
    "provider tunnel escaped the registered host",
    "provider tunnel accepted metadata/private address",
    "opaque provider tunnel upload budget did not fail closed",
    "Jend provider broker host/path policy: PASS",
    "Jend provider opaque-TLS/byte-budget boundary: PASS",
]:
    require(required in provider_smoke_m712, f"M7.12 provider smoke missing: {required}")


execution_m713 = read("crates/jend-model-store/src/execution.rs")
for required in [
    "ExternalProviderExecutionDisabled",
    "provider_model_fails_closed_for_public_store_chat",
    "ResidentPackage",
    "VirtualPaged",
]:
    require(required in execution_m713, f"M7.13 Store-only execution contract missing: {required}")
require(
    "ProviderAdapter" not in execution_m713,
    "M7.13 public Store execution route must not expose provider/API adapters",
)

activation_m713 = read("crates/jend-model-store/src/activation.rs")
require(
    "ExternalProviderExecutionDisabled" in activation_m713,
    "M7.13 public Store activation must reject ProviderRemote entries",
)

native_m713 = read("crates/jend-model-store/src/native.rs")
for required in [
    "pub struct JendNativeBlueprint",
    "pub enum NativeArchitecture",
    "SparseMoe",
    "pub enum TeacherKind",
    "JendOwned",
    "ExplicitlyLicensed",
    "RestrictedProvider",
    "pub struct NativeComponent",
    "ExpertGroup",
    "pageable_parameters",
]:
    require(required in native_m713, f"M7.13 native-model blueprint missing: {required}")
require(
    "TeacherKind::RestrictedProvider" in native_m713
    and "return Err(ModelStoreError::InvalidNativeModelBlueprint)" in native_m713,
    "M7.13 restricted closed-provider teachers must fail closed",
)

native_smoke_m713 = read("crates/jend-model-store/src/bin/jend-native-blueprint-smoke.rs")
for required in [
    "restricted closed provider escaped native teacher gate",
    "Jend native sparse-model blueprint: PASS",
    "Jend restricted-provider teacher rejection: PASS",
]:
    require(required in native_smoke_m713, f"M7.13 native smoke missing: {required}")


weightvm_m800 = read("crates/jend-model-store/src/weightvm.rs")
for required in [
    "pub struct WeightPageId",
    "pub struct WeightPageDescriptor",
    "pub trait WeightPageSource",
    "pub struct WeightVmBudget",
    "pub struct WeightVmSnapshot",
    "pub struct WeightPageLease",
    "pub struct WeightVm",
    "pin_page",
    "prefetch_page",
    "update_budget",
    "evict_one_unpinned",
    "WeightPageId::for_bytes",
]:
    require(required in weightvm_m800, f"M8.0 WeightVM contract missing: {required}")

require(
    "reqwest" not in read("crates/jend-model-store/Cargo.toml")
    and "tokio" not in read("crates/jend-model-store/Cargo.toml"),
    "M8.0 WeightVM/model-store must remain free of direct network runtime dependencies",
)
require(
    "WeightPageDigestMismatch" in weightvm_m800
    and "WeightPageLengthMismatch" in weightvm_m800,
    "M8.0 WeightVM must verify every faulted page before residency",
)
require(
    "pins > 0" in weightvm_m800
    and "over_budget_due_to_pins" in weightvm_m800,
    "M8.0 WeightVM must preserve active leases when budgets tighten",
)

weightvm_smoke_m800 = read("crates/jend-model-store/src/bin/jend-weightvm-smoke.rs")
for required in [
    "500_000_000_000",
    "4 * 1024 * 1024",
    "WeightVM exceeded its physical residency budget",
    "logical > physical residency",
    "Jend WeightVM bounded residency/page-fault smoke: PASS",
    "Jend WeightVM content-addressed dedup/pinning: PASS",
]:
    require(required in weightvm_smoke_m800, f"M8.0 WeightVM smoke missing: {required}")


weightvm_smoke_m801 = read("crates/jend-model-store/src/bin/jend-weightvm-smoke.rs")
require(
    "ModelStoreError, Result," not in weightvm_smoke_m801,
    "M8.0.1 WeightVM smoke must not shadow std::result::Result with model-store Result alias",
)
require(
    "-> jend_model_store::Result<Vec<u8>>" in weightvm_smoke_m801,
    "M8.0.1 WeightPageSource impl must use the model-store Result alias explicitly",
)
require(
    "fn main() -> std::result::Result<(), Box<dyn std::error::Error>>" in weightvm_smoke_m801,
    "M8.0.1 smoke main must return a boxed-error std::result::Result",
)

weight_store_m81 = read("crates/jend-model-store/src/weight_store.rs")
for required in [
    "pub struct DurableWeightPageStore",
    "impl WeightPageSource for DurableWeightPageStore",
    "create_new(true)",
    ".mode(0o600)",
    "sync_all",
    "fs::rename",
    "recover_staging",
    "contains_verified",
    "WeightPageId::for_bytes",
    "WeightPageDigestMismatch",
    "public_existing_store_directory_is_rejected",
]:
    require(required in weight_store_m81, f"M8.1 durable WeightVM store missing: {required}")

require(
    "reqwest" not in read("crates/jend-model-store/Cargo.toml")
    and "tokio" not in read("crates/jend-model-store/Cargo.toml"),
    "M8.1 durable WeightVM store must remain network-agnostic",
)
require(
    'fs::{OpenOptionsExt' not in weight_store_m81
    or "OpenOptionsExt" in weight_store_m81,
    "M8.1 Unix OpenOptionsExt must be explicitly in scope for mode(0o600)",
)

weight_store_smoke_m81 = read("crates/jend-model-store/src/bin/jend-weight-store-smoke.rs")
for required in [
    "stale crash staging file survived recovery",
    "verified pages did not survive store restart",
    "WeightVM did not evict while backed by durable page store",
    "Jend WeightVM durable restart/recovery: PASS",
    "Jend WeightVM disk content-addressed dedup: PASS",
]:
    require(required in weight_store_smoke_m81, f"M8.1 durable-store smoke missing: {required}")


weight_store_m811 = read("crates/jend-model-store/src/weight_store.rs")
require(
    "use sha2::Digest;" in weight_store_m811,
    "M8.1.1 durable store must keep sha2::Digest in module scope for Sha256::new()",
)
require(
    "let mut hasher = sha2::Sha256::new();" in weight_store_m811,
    "M8.1.1 regression target missing Sha256::new()",
)
require(
    "Err(_rename_error) if final_path.exists()" in weight_store_m811,
    "M8.1.1 racing-publisher rename warning must stay clean",
)

virtual_map_m82 = read("crates/jend-model-store/src/virtual_map.rs")
for required in [
    "pub struct VirtualModelMap",
    "pub struct SignedVirtualModelMap",
    "pub struct VirtualRegion",
    "pub struct ExpertId",
    "pub enum ExpertRole",
    "pages_for_expert",
    "prefetch_pages_for_expert",
    "canonical_bytes",
    "map_id",
    "duplicate_expert_id_is_rejected",
]:
    require(required in virtual_map_m82, f"M8.2 virtual expert map missing: {required}")
require(
    "WeightPageDescriptor" in virtual_map_m82 and "WeightPageId" in virtual_map_m82,
    "M8.2 address map must bind experts to content-addressed WeightVM pages",
)

release_m82 = read("crates/jend-model-store/src/release.rs")
for required in [
    "VIRTUAL_MAP_SIGNATURE_DOMAIN",
    "sign_virtual_map",
    "verify_virtual_map",
    "virtual_map_signature_message",
]:
    require(required in release_m82, f"M8.2 signed map release binding missing: {required}")

virtual_map_smoke_m82 = read("crates/jend-model-store/src/bin/jend-virtual-map-smoke.rs")
for required in [
    "coding role did not resolve to expert 17",
    "signed expert-map tampering was not detected",
    "expert map did not materialize the expected bounded working set",
    "Jend signed virtual-model/expert address map: PASS",
    "Jend expert-to-WeightVM page resolution: PASS",
]:
    require(required in virtual_map_smoke_m82, f"M8.2 virtual-map smoke missing: {required}")

source_protocol_m83 = read("crates/jend-model-store/src/source_protocol.rs")
for required in [
    "pub enum SourceOrigin",
    "HuggingFaceXet",
    "PublisherHttps",
    "pub struct SourceDescriptor",
    "pub struct PageSourceBinding",
    "pub struct ModelSourceMap",
    "pub struct SignedModelSourceMap",
    "pub struct SourceReadRequest",
    "full immutable commit",
    "source_offset",
    "expected_page",
    "bindings_for_page",
    "validate_against_virtual_map",
]:
    require(required in source_protocol_m83, f"M8.3 source protocol missing: {required}")

require(
    "String" not in source_protocol_m83[source_protocol_m83.index("pub struct SourceReadRequest"):source_protocol_m83.index("impl SourceOrigin")],
    "M8.3 WeightVM-facing SourceReadRequest must remain URL/string-free",
)
require(
    "commit_sha.len() != 40" in source_protocol_m83
    or "value.len() != 40" in source_protocol_m83,
    "M8.3 HF source descriptor must require immutable full commit SHA",
)
require(
    "../secret" in source_protocol_m83 and "path traversal" not in "",
    "M8.3 source protocol must test traversal rejection",
)
require(
    "reqwest" not in read("crates/jend-model-store/Cargo.toml")
    and "tokio" not in read("crates/jend-model-store/Cargo.toml"),
    "M8.3 source protocol/model-store must remain network-runtime agnostic",
)

source_smoke_m83 = read("crates/jend-model-store/src/bin/jend-source-protocol-smoke.rs")
for required in [
    "Jend URL-free immutable source descriptors: PASS",
    "Jend signed multi-origin page/range binding: PASS",
    "Jend WeightVM source independence contract: PASS",
    "signed source-map range tampering was not detected",
]:
    require(required in source_smoke_m83, f"M8.3 source protocol smoke missing: {required}")

release_m83 = read("crates/jend-model-store/src/release.rs")
require(
    "JEND/MODEL/SOURCE-MAP-SIGNATURE/V1" in release_m83
    and "sign_source_map" in release_m83
    and "verify_source_map" in release_m83,
    "M8.3 source maps must use a domain-separated release signature",
)


hf_xet_m84 = read("crates/jend-model-store/src/hf_xet.rs")
for required in [
    "pub struct HfXetRequestPlanner",
    "pub struct HfXetReadGrant",
    "pub struct HfXetReconstructionPlan",
    "redirect_policy: HfRedirectPolicy::Reject",
    "/xet-read-token/",
    "/v2/reconstructions/",
    "/v1/reconstructions/",
    "X-Xet-Hash",
    "cas-server.xethub.hf.co",
    "cas-server.xethub-eu.hf.co",
    "transfer.xethub.hf.co",
    "transfer.xethub-eu.hf.co",
    "X-Xet-Signed-Range=",
    "Zeroizing<String>",
    "HfXetBudgetExceeded",
]:
    require(required in hf_xet_m84, f"M8.4 HF/Xet adapter boundary missing: {required}")

require(
    "reqwest" not in read("crates/jend-model-store/Cargo.toml")
    and "tokio" not in read("crates/jend-model-store/Cargo.toml")
    and "url =" not in read("crates/jend-model-store/Cargo.toml"),
    "M8.4 planner must not turn jend-model-store/WeightVM into a network client",
)

hf_xet_smoke_m84 = read("crates/jend-model-store/src/bin/jend-hf-xet-adapter-smoke.rs")
for required in [
    "Jend HF/Xet immutable discovery/range planner: PASS",
    "Jend HF/Xet signed-transfer allowlist/budget policy: PASS",
    "Jend HF/Xet adapter carries no executable redirect: PASS",
    "169.254.169.254",
]:
    require(required in hf_xet_smoke_m84, f"M8.4 HF/Xet smoke missing: {required}")


source_transport_m851 = read("client/jend-cli/src/source_worker_transport.rs")
for required in [
    ".https_only(true)",
    ".no_proxy()",
    ".redirect(Policy::none())",
    ".resolve_to_addrs(&request.host, &pinned_addresses)",
    "SingleRange206",
    "StatusCode::PARTIAL_CONTENT",
    "Zeroizing<String>",
    "169.254.169.254",
    "transfer.xethub.hf.co",
]:
    require(required in source_transport_m851, f"M8.5.1 hardened transport missing: {required}")
require(
    "reqwest" not in read("crates/jend-model-store/Cargo.toml")
    and "tokio" not in read("crates/jend-model-store/Cargo.toml"),
    "M8.5.1 must not add network runtime dependencies to jend-model-store",
)
require(
    "jend-model-store" not in read("client/jend-cli/Cargo.toml"),
    "M8.5.1 must keep Cargo.toml unchanged for lockfile reuse",
)
live_hf_m851 = read("client/jend-cli/src/bin/jend-hf-source-worker-live-smoke.rs")
for required in [
    "607a30d783dfa663caf39e06633721c8d4cfcd7e",
    "model.safetensors",
    "JEND_ALLOW_LIVE_HF",
    "Jend live HF full-weight download avoided: PASS",
]:
    require(required in live_hf_m851, f"M8.5.1 live HF smoke missing: {required}")


# M8.5.2.2 Xet published schema regression gates.
xet_metadata_m8522 = read("client/jend-cli/src/xet_metadata.rs")
for required in [
    'get("range")',
    'get("xorbs")',
    'and_then(Value::as_object)',
    'get("chunks")',
    'get("bytes")',
    'legacy_wrong_fixture_shape_is_rejected',
]:
    require(required in xet_metadata_m8522, f"M8.5.2.2 Xet published schema missing: {required}")
require(
    'get("xorbs").and_then(Value::as_array)' not in xet_metadata_m8522,
    "M8.5.2.2 Xet published schema regressed to xorbs array",
)


# M8.5.3.4 live HF CDN direct-xorb path regression gates.
xet_metadata_m8534 = read("client/jend-cli/src/xet_metadata.rs")
hf_xet_m8534 = read("crates/jend-model-store/src/hf_xet.rs")
for text, name in [(xet_metadata_m8534, "CLI parser"), (hf_xet_m8534, "model-store validator")]:
    for required in [
        '"us.aws.cdn.hf.co"',
        '"us.gcp.cdn.hf.co"',
        'format!("/xorbs/default/{expected_hash}")',
        'format!("/xorb/default/{expected_hash}")',
        'X-Xet-Signed-Range',
        'xet-bridge-us',
    ]:
        require(required in text, f"M8.5.3.4 {name} missing: {required}")
require(
    '*.hf.co' not in xet_metadata_m8534 and '*.hf.co' not in hf_xet_m8534,
    "M8.5.3.4 must not introduce wildcard HF CDN trust",
)


# M8.5.3.5: CDN range authorization profiles must remain split.
xet_meta_m8535 = read("client/jend-cli/src/xet_metadata.rs")
require("CdnSignatureMissing" in xet_meta_m8535, "M8.5.3.5 CDN signature error missing")
require("transfer.xethub.hf.co" in xet_meta_m8535 and "X-Xet-Signed-Range" in xet_meta_m8535, "M8.5.3.5 transfer signed-range policy missing")
require("HF CDN direct-xorb URLs can omit" in read("crates/jend-model-store/src/hf_xet.rs"), "M8.5.3.5 model-store CDN policy missing")


# M8.5.4 single-range xorb transport proof must remain narrow and fail-closed.
xet_meta_m854 = read("client/jend-cli/src/xet_metadata.rs")
xet_live_m854 = read("client/jend-cli/src/bin/jend-hf-xet-single-range-live-smoke.rs")
transport_m854 = read("client/jend-cli/src/source_worker_transport.rs")
for required in [
    "pub struct SignedSingleRangeRequest",
    "pub fn single_range_request",
    "ParseError::SingleRangeRequired",
    "path_and_query: Zeroizing<String>",
]:
    require(required in xet_meta_m854, f"M8.5.4 single-range plan missing: {required}")
for required in [
    "MAX_LIVE_XORB_FETCH_BYTES: u64 = 16 * 1024 * 1024",
    "ExpectedResponse::SingleRange206",
    "payload kept outside WeightVM",
    "JEND_ALLOW_LIVE_HF_XORB",
]:
    require(required in xet_live_m854, f"M8.5.4 live smoke boundary missing: {required}")
require("request.path_and_query.len() > MAX_PATH_AND_QUERY" in transport_m854, "signed URL transport path cap missing")
require("status == StatusCode::PARTIAL_CONTENT" in transport_m854, "M8.5.4 must require HTTP 206")
require("range.contains(',')" in transport_m854, "multi-range must remain rejected by single-range transport")



# M8.5.5 bounded xorb v0 decoding and logical reconstruction.
xorb_decode_m855 = read("client/jend-cli/src/xorb_decode.rs")
xorb_live_m855 = read("client/jend-cli/src/bin/jend-hf-xet-decode-live-smoke.rs")
cli_manifest_m855 = read("client/jend-cli/Cargo.toml")
for required in [
    "CHUNK_HEADER_BYTES: usize = 8",
    "MAX_RAW_CHUNK_BYTES: usize = 128 * 1024",
    "FrameDecoder",
    "ByteGrouping4Lz4",
    "DecompressedLengthMismatch",
    "DecodeBudgetExceeded",
    "TrailingPayload",
    "reconstruct_slice_from_single_xorb",
]:
    require(required in xorb_decode_m855, f"M8.5.5 xorb decoder missing: {required}")
require('lz4_flex = { version = "=0.13.1"' in cli_manifest_m855, "M8.5.5 must pin audited LZ4 decoder")
require("prepare-m8.5.5-lock.sh" in [p.name for p in (ROOT / "scripts").iterdir()], "M8.5.5 lock preparation script missing")
require(">= parsed_terms" in read("client/jend-cli/src/xet_metadata.rs"), "M8.5.5 offset must remain within first term")
require("lz4_flex" not in read("crates/jend-model-store/Cargo.toml"), "M8.5.5 LZ4 must stay outside WeightVM/model-store")
for required in [
    "MAX_LIVE_DECODED_BYTES: u64 = 16 * 1024 * 1024",
    "decode_xorb_single_range",
    "reconstruct_slice_from_single_xorb",
    "decoded data kept outside WeightVM",
    "JEND_ALLOW_LIVE_HF_XORB_DECODE",
]:
    require(required in xorb_live_m855, f"M8.5.5 live decode boundary missing: {required}")

# M8.5.8 bounded multi-range fetch scheduling. Planning may understand an
# atomic comma-separated Range set, but network execution must remain on the
# old single-range contract until multipart/byteranges parsing is implemented.
xet_schedule_m858 = read("client/jend-cli/src/xet_fetch_schedule.rs")
xet_meta_m858 = read("client/jend-cli/src/xet_metadata.rs")
xet_schedule_smoke_m858 = read("client/jend-cli/src/bin/jend-xet-fetch-schedule-smoke.rs")
for required in [
    "HARD_MAX_TOTAL_XORB_PAYLOAD_BYTES: u64 = 64 * 1024 * 1024",
    "HARD_MAX_REQUEST_XORB_PAYLOAD_BYTES: u64 = 16 * 1024 * 1024",
    "HARD_MAX_FETCH_CONCURRENCY: usize = 8",
    "build_fetch_schedule",
    "TotalPayloadBudgetExceeded",
    "RequestPayloadBudgetExceeded",
    "DuplicateChunkCoverage",
]:
    require(required in xet_schedule_m858, f"M8.5.8 fetch scheduler missing: {required}")
for required in [
    "pub struct SignedRangeBatchRequest",
    "pub fn range_batch_request",
    "authorized_payload_bytes",
    "MAX_EXEC_RANGE_HEADER_BYTES: usize = 8 * 1024",
]:
    require(required in xet_meta_m858, f"M8.5.8 range-batch planner missing: {required}")
for required in [
    "Jend Xet bounded multi-range fetch schedule: PASS",
    "Jend Xet deterministic concurrency waves: PASS",
    "Jend Xet aggregate physical-byte budget: PASS",
    "Jend Xet multipart network execution remains fail-closed: PASS",
]:
    require(required in xet_schedule_smoke_m858, f"M8.5.8 scheduler smoke missing: {required}")
require((ROOT / "scripts/dev-xet-fetch-schedule-smoke.sh").is_file(), "M8.5.8 scheduler smoke script missing")
require("range.contains(',')" in transport_m854, "M8.5.8 multipart execution must remain blocked by single-range transport")
require("MultiRange206" not in transport_m854, "M8.5.8 must not enable multipart network execution early")

# M8.5.10 adds only one atomic signed fetch-entry execution path. It must
# preserve the existing single-range comma rejection and must not admit pages.
multi_transport_m8510 = read("client/jend-cli/src/xet_multi_fetch_transport.rs")
multi_smoke_m8510 = read("client/jend-cli/src/bin/jend-xet-fetch-schedule-smoke.rs")
for required in [
    "execute_signed_xet_multi_range",
    "validate_signed_multipart_body",
    "validate_signed_xorb_url",
    "authorized_payload_bytes",
    "Multipart206",
    "UntrustedXorbPhysicalRange",
    "StatusCode::PARTIAL_CONTENT",
]:
    require(required in multi_transport_m8510 or required in source_transport_m851, f"M8.5.10 signed HTTP 206 gate missing: {required}")
require(
    "ExpectedResponse::Multipart206" in source_transport_m851
    and "validate_response_headers(response.headers(), request.expected)" in source_transport_m851,
    "M8.5.10 bounded multipart transport response headers not enforced",
)
require(
    "Jend Xet atomic signed multi-range response gate: PASS" in multi_smoke_m8510
    and "Jend Xet HTTP 200 fallback rejected: PASS" in multi_smoke_m8510,
    "M8.5.10 offline network authorization smoke missing",
)
require(
    "jend_model_store" not in multi_transport_m8510
    and "WeightVM admission" not in multi_transport_m8510,
    "M8.5.10 unverified physical bytes cannot become WeightVM admission",
)

print(f"static preflight PASS: {len(migrations)} migrations, {len(routes)} routes, {len(created_tables)} tables")
