#![forbid(unsafe_code)]

// Test-only synthetic GGUF *header*, NOT a runnable third-party model.
// Key generated here is a test fixture, NOT a trusted publisher identity.
use jend_model_store::{
    inspect_independently_signed_gguf, ModelChunk, ModelId, ModelManifest,
    ModelObjectId, ModelReleaseSigningKey,
};
use sha2::{Digest, Sha256};
use std::{fs, path::PathBuf, time::{SystemTime, UNIX_EPOCH}};

fn synthetic_gguf() -> Vec<u8> {
    let mut b = b"GGUF".to_vec();
    b.extend(3u32.to_le_bytes());
    b.extend(1u64.to_le_bytes());
    b.extend(0u64.to_le_bytes());
    b.extend(b"synthetic-hash-validation-bytes-not-a-runnable-model");
    b
}

fn manifest(data: &[u8]) -> ModelManifest {
    let cut = 19usize;
    ModelManifest {
        model_id: ModelId([0x53; 16]),
        release_sequence: 85153,
        minimum_runtime: 1,
        format: "gguf".into(),
        architecture: "llama".into(),
        quantization: "F16".into(),
        total_plaintext_len: data.len() as u64,
        whole_model_sha256: Sha256::digest(data).into(),
        chunks: vec![
            ModelChunk {
                index: 0, object_id: ModelObjectId([1; 32]),
                offset: 0, plaintext_len: cut as u32,
                sha256: Sha256::digest(&data[..cut]).into(),
            },
            ModelChunk {
                index: 1, object_id: ModelObjectId([2; 32]),
                offset: cut as u64, plaintext_len: (data.len()-cut) as u32,
                sha256: Sha256::digest(&data[cut..]).into(),
            },
        ],
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let nonce = SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let root: PathBuf = std::env::temp_dir()
        .join(format!("jend-gguf-intake-smoke-{}-{nonce}", std::process::id()));
    fs::create_dir(&root)?;
    let path = root.join("synthetic.gguf");
    let data = synthetic_gguf();
    fs::write(&path, &data)?;
    let signer = ModelReleaseSigningKey::generate()?;
    let trusted = signer.public_key();
    let signed = signer.sign_manifest(manifest(&data))?;
    let verified = inspect_independently_signed_gguf(&trusted, &signed, &path, 1024)?;
    if verified.byte_length != data.len() as u64
        || verified.gguf_version != 3
        || verified.tensor_count != 1
    {
        return Err("signed GGUF intake returned inconsistent inspection".into());
    }
    println!("Jend independently signed GGUF whole-file inspection: PASS");

    let wrong_key = ModelReleaseSigningKey::generate()?.public_key();
    if inspect_independently_signed_gguf(&wrong_key, &signed, &path, 1024).is_ok() {
        return Err("untrusted release signing key accepted".into());
    }
    let mut altered = signed.clone();
    altered.manifest.release_sequence += 1;
    if inspect_independently_signed_gguf(&trusted, &altered, &path, 1024).is_ok() {
        return Err("modified signed manifest accepted".into());
    }
    println!("Jend GGUF wrong release key and signed manifest refused: PASS");

    let mut bad = data.clone();
    let last = bad.len()-1;
    bad[last] ^= 1;
    fs::write(&path, &bad)?;
    if inspect_independently_signed_gguf(&trusted, &signed, &path, 1024).is_ok() {
        return Err("corrupt GGUF bytes passed signed hashes".into());
    }
    fs::write(&path, &data[..data.len()-1])?;
    if inspect_independently_signed_gguf(&trusted, &signed, &path, 1024).is_ok() {
        return Err("truncated GGUF bytes passed signed length".into());
    }
    println!("Jend GGUF corrupt and truncated file refused: PASS");

    let mut invalid = data.clone();
    invalid[0] = b'X';
    fs::write(&path, &invalid)?;
    let new_signed = signer.sign_manifest(manifest(&invalid))?;
    if inspect_independently_signed_gguf(&trusted, &new_signed, &path, 1024).is_ok() {
        return Err("malformed but signed GGUF header accepted".into());
    }
    println!("Jend GGUF malformed header refused even when signed: PASS");

    fs::write(&path, &data)?;
    if inspect_independently_signed_gguf(&trusted, &signed, &path, 24).is_ok() {
        return Err("GGUF exceeds caller's byte budget but was accepted".into());
    }
    println!("Jend GGUF bounded streaming verification budget: PASS");
    println!("Jend GGUF intake fixture grants no native execution: PASS");
    fs::remove_dir_all(root)?;
    Ok(())
}
