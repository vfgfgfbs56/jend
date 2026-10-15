// Offline synthetic DATA only. Neither a full GGUF nor an inference engine.
#[allow(dead_code)]
#[path = "../native_worker_launch.rs"]
mod native_worker_launch;
#[allow(dead_code)]
#[path = "../native_model_handoff.rs"]
mod native_model_handoff;

use jend_model_store::{ModelChunk, ModelId, ModelManifest, ModelObjectId,
    ModelReleaseSigningKey, VerifiedGgufSnapshotStore};
use native_model_handoff::prepare_sealed_model;
use native_worker_launch::LaunchError;
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

fn require(ok: bool, message: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    if !ok { return Err(message.into()); }
    Ok(())
}
fn fake_gguf() -> Vec<u8> {
    let mut bytes = b"GGUF".to_vec();
    bytes.extend(3u32.to_le_bytes()); bytes.extend(1u64.to_le_bytes()); bytes.extend(0u64.to_le_bytes());
    bytes.extend(b"JEND-SYNTHETIC-PUBLIC-GGUF");
    bytes
}
fn manifest(bytes: &[u8]) -> ModelManifest {
    let mid = bytes.len() / 2;
    ModelManifest {
        model_id: ModelId([0x6d; 16]), release_sequence: 85156, minimum_runtime: 1,
        format: "gguf".into(), architecture: "llama".into(), quantization: "F16".into(),
        total_plaintext_len: bytes.len() as u64, whole_model_sha256: Sha256::digest(bytes).into(),
        chunks: vec![
            ModelChunk { index: 0, object_id: ModelObjectId([1; 32]), offset: 0,
                plaintext_len: mid as u32, sha256: Sha256::digest(&bytes[..mid]).into() },
            ModelChunk { index: 1, object_id: ModelObjectId([2; 32]), offset: mid as u64,
                plaintext_len: (bytes.len() - mid) as u32, sha256: Sha256::digest(&bytes[mid..]).into() },
        ],
    }
}
struct Temp(PathBuf);
impl Drop for Temp { fn drop(&mut self) {
    #[cfg(windows)]
    for p in walk_files(&self.0) {
        if let Ok(meta) = fs::metadata(&p) { let mut perm = meta.permissions(); perm.set_readonly(false); let _ = fs::set_permissions(&p, perm); }
    }
    let _ = fs::remove_dir_all(&self.0);
} }
#[cfg(windows)]
fn walk_files(path: &std::path::Path) -> Vec<PathBuf> {
    let mut files = Vec::new();
    if let Ok(entries) = fs::read_dir(path) { for e in entries.flatten() {
        if e.path().is_dir() { files.extend(walk_files(&e.path())); } else { files.push(e.path()); }
    }}
    files
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp = Temp(env::temp_dir().join(format!("jend-sealed-gguf-{}-{nonce}", std::process::id())));
    fs::create_dir(&temp.0)?;
    let bytes = fake_gguf();
    let source = temp.0.join("synthetic.gguf");
    fs::write(&source, &bytes)?;
    // Signing keys enrolled only in this synthetic test's local policy.
    let signer = ModelReleaseSigningKey::generate()?;
    let key = signer.public_key();
    let signed = signer.sign_manifest(manifest(&bytes))?;
    let store = VerifiedGgufSnapshotStore::open(temp.0.join("cache"))?;
    let snapshot = store.snapshot(&key, &signed, &source, 4096)?;
    let mut lease = store.open_verified_handle(&key, &signed, 4096)?;
    if !cfg!(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))) {
        require(matches!(prepare_sealed_model(&mut lease, &key, &signed, signed.manifest_id, 4096),
            Err(LaunchError::UnsupportedPlatform)), "unsupported host admitted native model handoff")?;
        println!("Jend sealed GGUF handoff unsupported host refused: PASS");
        println!("Jend sealed GGUF handoff still grants no inference: PASS");
        drop(snapshot);
        return Ok(());
    }
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        use jend_model_store::ManifestId;
        use jend_release::{AcceptedReleaseHead, ApproverSigningKey, ArtifactKind, BuilderSigningKey,
            ReleaseBundle, ReleasePolicy, ReleaseStatement, ReleaseStatementId};
        use native_worker_launch::{fixture_target, prepare_worker, run_sealed_model_fixture};
        use std::{os::{fd::AsRawFd, unix::fs::PermissionsExt}, time::Duration};
        let executable = PathBuf::from(env::args_os().nth(1).ok_or("expected local signed fixture path")?);
        let builder = BuilderSigningKey::generate()?;
        let approver = ApproverSigningKey::generate()?;
        let policy = ReleasePolicy::new([builder.public_key()], 1, [approver.public_key()], 1)?;
        let exe_bytes = fs::read(&executable)?;
        let stmt = ReleaseStatement { artifact_kind: ArtifactKind::LocalAiRuntime, sequence: 0,
            version: "M8.5.15.6d-synthetic-data".into(), target: fixture_target().into(),
            artifact_size: exe_bytes.len() as u64, artifact_sha256: Sha256::digest(&exe_bytes).into(),
            source_tree_sha256: [0x11; 32], build_recipe_sha256: [0x22; 32],
            previous_statement_id: ReleaseStatementId([0; 32]) };
        let bundle = ReleaseBundle { builder_attestations: vec![builder.sign(&stmt)?],
            approvals: vec![approver.sign(&stmt)?], statement: stmt };
        let head = AcceptedReleaseHead::genesis(&bundle, &policy)?;
        let worker = prepare_worker(&executable, &bundle, &policy, head)?;

        let wrong = ModelReleaseSigningKey::generate()?;
        require(matches!(prepare_sealed_model(&mut lease, &wrong.public_key(), &signed, signed.manifest_id, 4096),
            Err(LaunchError::ModelRejected)), "source-chosen model key accepted")?;
        require(matches!(prepare_sealed_model(&mut lease, &key, &signed, ManifestId([0x99; 32]), 4096),
            Err(LaunchError::ModelRejected)), "unaccepted model release admitted")?;
        let mut forged = signed.clone();
        forged.signature[0] ^= 1;
        require(matches!(prepare_sealed_model(&mut lease, &key, &forged, signed.manifest_id, 4096),
            Err(LaunchError::ModelRejected)), "forged model signature admitted")?;
        require(matches!(prepare_sealed_model(&mut lease, &key, &signed, signed.manifest_id, 24),
            Err(LaunchError::ModelRejected)), "too-small data budget accepted")?;
        require(matches!(prepare_sealed_model(&mut lease, &key, &signed, signed.manifest_id, 4 * 1024 * 1024 + 1),
            Err(LaunchError::ModelRejected)), "unbounded data staging accepted")?;
        println!("Jend sealed GGUF wrong root signature accepted identity and budget rejected: PASS");

        let prepared = prepare_sealed_model(&mut lease, &key, &signed, signed.manifest_id, 4096)?;
        require(prepared.inspection() == lease.inspection(), "sealed data receipt changed")?;
        let fd = prepared.file.as_raw_fd();
        require(unsafe { libc::fcntl(fd, libc::F_GETFL) } & libc::O_ACCMODE == libc::O_RDONLY,
            "prepared data handle is writable")?;
        require(unsafe { libc::fchmod(fd, 0o500) } == -1 && unsafe { *libc::__errno_location() } == libc::EPERM,
            "sealed data inode became executable")?;
        println!("Jend sealed GGUF final immutable backing matches signed header chunks and whole digest: PASS");
        println!("Jend sealed GGUF data inode cannot gain execute permission: PASS");

        let private = fs::File::open(&source)?;
        require(unsafe { libc::dup2(private.as_raw_fd(), 127) } == 127, "synthetic inherited FD missing")?;
        let address = 0x100000000usize as *mut libc::c_void;
        let mapped = unsafe { libc::mmap(address, 4096, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE, -1, 0) };
        require(mapped == address, "synthetic parent mapping missing")?;
        require(env::var_os("JEND_TEST_SECRET_CANARY").is_some(), "synthetic parent environment missing")?;
        let proof = b"JEND-SEALED-GGUF-DATA-V1\n";
        require(run_sealed_model_fixture(&worker, &prepared, Duration::from_secs(3))? == proof,
            "native constructor did not verify exactly the approved read-only FD")?;
        println!("Jend sealed GGUF constructor reads only approved FD while parent state is absent: PASS");
        println!("Jend sealed GGUF constructor denies write resize exec and executable mappings: PASS");

        // In-place mutation then path replacement affect neither sealed bytes
        // nor the allowed native handle. A newly prepared mutated lease refuses.
        fs::set_permissions(&snapshot.path, fs::Permissions::from_mode(0o600))?;
        let mut corrupted = bytes.clone(); corrupted[24] ^= 1;
        fs::write(&snapshot.path, &corrupted)?;
        require(matches!(prepare_sealed_model(&mut lease, &key, &signed, signed.manifest_id, 4096),
            Err(LaunchError::ModelRejected)), "same-inode corruption admitted")?;
        require(run_sealed_model_fixture(&worker, &prepared, Duration::from_secs(3))? == proof,
            "source inode mutation changed native data")?;
        let old = snapshot.path.with_extension("old");
        fs::rename(&snapshot.path, &old)?; fs::write(&snapshot.path, b"attacker pathname replacement")?;
        require(run_sealed_model_fixture(&worker, &prepared, Duration::from_secs(3))? == proof,
            "source pathname replacement changed native data")?;
        println!("Jend sealed GGUF source inode and pathname substitution cannot change worker bytes: PASS");

        // Constructor checked the sole data slot 4 and EBADF for every other
        // inherited descriptor; the parent retains its separate canary handle.
        require(unsafe { libc::fcntl(127, libc::F_GETFD) } >= 0, "cleanup changed parent table")?;
        require(unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } == -1
            && unsafe { *libc::__errno_location() } == libc::ECHILD, "native child left unreaped")?;
        println!("Jend sealed GGUF child descriptor cleanup preserves parent and reaps worker: PASS");
        unsafe { libc::munmap(mapped, 4096); libc::close(127); }
        println!("Jend sealed GGUF handoff still grants no inference: PASS");
    }
    Ok(())
}
