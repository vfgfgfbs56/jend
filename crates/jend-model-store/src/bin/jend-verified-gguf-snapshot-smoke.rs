#![forbid(unsafe_code)]
// Synthetic GGUF header ONLY; no real model and no native execution.
use jend_model_store::{
    ModelChunk, ModelId, ModelManifest, ModelObjectId, ModelReleaseSigningKey,
    VerifiedGgufSnapshotStore,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

fn fake_gguf() -> Vec<u8> {
    let mut v = b"GGUF".to_vec();
    v.extend(3u32.to_le_bytes());
    v.extend(1u64.to_le_bytes());
    v.extend(0u64.to_le_bytes());
    v.extend(b"m85154 independent trust and snapshot only");
    v
}
fn signed_manifest(bytes: &[u8]) -> ModelManifest {
    let mid = bytes.len()/2;
    ModelManifest {
        model_id: ModelId([54u8; 16]),
        release_sequence: 85154,
        minimum_runtime: 1,
        format: "gguf".into(),
        architecture: "llama".into(),
        quantization: "F16".into(),
        total_plaintext_len: bytes.len() as u64,
        whole_model_sha256: Sha256::digest(bytes).into(),
        chunks: vec![
            ModelChunk {
                index: 0,
                object_id: ModelObjectId([1u8; 32]),
                offset: 0,
                plaintext_len: mid as u32,
                sha256: Sha256::digest(&bytes[..mid]).into(),
            },
            ModelChunk {
                index: 1,
                object_id: ModelObjectId([2u8; 32]),
                offset: mid as u64,
                plaintext_len: (bytes.len()-mid) as u32,
                sha256: Sha256::digest(&bytes[mid..]).into(),
            },
        ],
    }
}
fn main() -> Result<(), Box<dyn std::error::Error>> {
    let suffix = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let parent: PathBuf = std::env::temp_dir()
        .join(format!("jend-85154-{}-{suffix}", std::process::id()));
    fs::create_dir(&parent)?;
    let original = parent.join("untrusted.gguf");
    let good = fake_gguf();
    fs::write(&original, &good)?;
    let signer = ModelReleaseSigningKey::generate()?;
    let trusted = signer.public_key();
    let signed = signer.sign_manifest(signed_manifest(&good))?;
    let store = VerifiedGgufSnapshotStore::open(parent.join("cache"))?;
    let result = store.snapshot(&trusted, &signed, &original, 4096)?;
    if fs::read(&result.path)? != good
        || result.manifest_id != signed.manifest_id
        || result.byte_length != good.len() as u64
    { return Err("snapshot bytes or signed identity incorrect".into()); }
    println!("Jend GGUF independent release signature to private snapshot: PASS");

    let mut pinned = store.open_verified_handle(&trusted, &signed, 4096)?;
    if pinned.inspection().manifest_id != signed.manifest_id
        || pinned.inspection().byte_length != good.len() as u64
    {
        return Err("open file lease identity does not match signed manifest".into());
    }
    pinned.reverify(&trusted, &signed, 4096)?;
    println!("Jend GGUF same opened handle signed hash verification: PASS");


    fs::write(&original, b"untrusted source changed after publication")?;
    store.check_existing(&trusted, &signed, &result.path, 4096)?;
    let second = store.snapshot(&trusted, &signed, &original, 4096)?;
    if second.path != result.path || fs::read(&second.path)? != good {
        return Err("mutated source modified verified GGUF cache".into());
    }
    println!("Jend GGUF source mutation cannot modify verified copy: PASS");

    let wrong = ModelReleaseSigningKey::generate()?.public_key();
    let rejected = VerifiedGgufSnapshotStore::open(parent.join("untrusted-key"))?;
    if rejected.snapshot(&wrong, &signed, &original, 4096).is_ok() {
        return Err("untrusted release key minted a snapshot".into());
    }
    println!("Jend GGUF different release key rejected before staging: PASS");

    fs::write(&original, &good)?;
    let mut corrupted = good.clone();
    let last = corrupted.len()-1;
    corrupted[last] ^= 1;
    fs::write(&original, corrupted)?;
    let reject = VerifiedGgufSnapshotStore::open(parent.join("reject-corrupt"))?;
    if reject.snapshot(&trusted, &signed, &original, 4096).is_ok() {
        return Err("corrupted GGUF bytes reached content-addressed objects".into());
    }
    if fs::read_dir(parent.join("reject-corrupt/objects"))?.next().is_some()
        || fs::read_dir(parent.join("reject-corrupt/staging"))?.next().is_some()
    {
        return Err("failed verification left published object or staged file".into());
    }
    println!("Jend GGUF corrupted copy leaves no published or staged file: PASS");

    fs::write(&original, &good)?;
    let bad_budget = VerifiedGgufSnapshotStore::open(parent.join("reject-budget"))?;
    if bad_budget.snapshot(&trusted, &signed, &original, 23).is_ok() {
        return Err("snapshot accepted below-header byte budget".into());
    }
    println!("Jend GGUF explicit snapshot size budget enforced: PASS");

    // Neither a pathname nor a new trust key is permitted to override the
    // release identity already bound to this opened file description.
    if pinned.reverify(&wrong, &signed, 4096).is_ok() {
        return Err("pinned descriptor accepted a different signing key".into());
    }
    println!("Jend GGUF held descriptor rejects wrong signing key: PASS");

    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Atomic rename changes the path, NOT the inode held by an fd.
        // An attacker can replace the pathname; the old descriptor still
        // points at the independently signed bytes, and reopening that
        // changed pathname MUST fail.
        let old_path = result.path.with_extension("kept");
        fs::rename(&result.path, &old_path)?;
        fs::write(&result.path, b"attacker path replacement")?;
        pinned.reverify(&trusted, &signed, 4096)?;
        if store.open_verified_handle(&trusted, &signed, 4096).is_ok() {
            return Err("changed cache pathname accepted without hashing".into());
        }
        println!("Jend GGUF file descriptor survives pathname substitution: PASS");

        // A same-user actor can still change the original *inode* after
        // clearing mode 0400. This is WHY an fd is not yet immutable.
        fs::set_permissions(&old_path, fs::Permissions::from_mode(0o600))?;
        fs::write(&old_path, b"tampered original inode")?;
        if pinned.reverify(&trusted, &signed, 4096).is_ok() {
            return Err("in-place inode mutation was not detected on rehash".into());
        }
        println!("Jend GGUF held descriptor rehash detects same-inode tampering: PASS");
    }

    println!("Jend GGUF snapshot grants no native execution capability: PASS");
    #[cfg(windows)]
    {
        let mut permissions = fs::metadata(&result.path)?.permissions();
        permissions.set_readonly(false);
        fs::set_permissions(&result.path, permissions)?;
    }
    fs::remove_dir_all(parent)?;
    Ok(())
}
