//! M8.5.15.3: streamed inspection of an independently release-signed,
//! complete GGUF file. This is NOT an executable native-worker grant.
//!
//! A verified hash proves the bytes read match the **separately trusted**
//! SignedModelManifest. It DOES NOT create a stable, immutable snapshot:
//! another process can modify the path after this function returns.
//! Production native loading must consume a durable, verified read-only
//! object/handle and run a sandboxed, independently attested engine.
//! No network, no executable model scripts, no WeightVM bypass.

use std::{
    fs::{self, File},
    io::{Read, Seek, SeekFrom},
    path::Path,
};

use crate::{
    ChunkVerifier, ManifestId, ModelId, ModelReleasePublicKey, ModelStoreError,
    Result, SignedModelManifest, WholeModelVerifier,
};

const GGUF_HEADER_BYTES: usize = 24;
const GGUF_VERSION: u32 = 3;
const MAX_GGUF_TENSORS: u64 = 4_000_000;
const MAX_GGUF_METADATA_FIELDS: u64 = 1_000_000;
const MAX_GGUF_INPUT_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const IO_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct VerifiedGgufInspection {
    pub manifest_id: ManifestId,
    pub model_id: ModelId,
    pub release_sequence: u64,
    pub byte_length: u64,
    pub gguf_version: u32,
    pub tensor_count: u64,
    pub metadata_count: u64,
}

/// Verify a local GGUF *inspection*, not its runtime execution permission.
///
/// The public key MUST already have been enrolled as a trustworthy release
/// key independently of the downloaded file or signed manifest. Exactly
/// ordered signed chunk lengths/digests and the signed whole-file digest
/// are checked in a single bounded 64-KiB-buffer pass.
///
/// The returned value deliberately does not contain a usable model path or
/// open/native worker handle; it cannot itself authorize loading the input.
/// Signature and format checks happen before a file is opened. A file
/// symlink is refused; race-free native adoption needs a later immutable CAS.
pub fn inspect_independently_signed_gguf(
    trusted_key: &ModelReleasePublicKey,
    signed: &SignedModelManifest,
    path: &Path,
    max_allowed_file_bytes: u64,
) -> Result<VerifiedGgufInspection> {
    // Existing path-facing inspection remains deliberately inspection-only.
    // Even a symlink swapped after lstat cannot forge release-signed bytes;
    // downstream native code must NEVER reopen this pathname after inspection.
    trusted_key.verify(signed)?;
    if !path.is_absolute() {
        return Err(ModelStoreError::InvalidManifest);
    }
    let initial = fs::symlink_metadata(path)?;
    if !initial.file_type().is_file() || initial.file_type().is_symlink() {
        return Err(ModelStoreError::InvalidManifest);
    }
    let mut file = File::open(path)?;
    let opened = file.metadata()?;
    if !opened.is_file() || opened.len() != initial.len() {
        return Err(ModelStoreError::InvalidManifest);
    }
    inspect_independently_signed_gguf_open_file(
        trusted_key, signed, &mut file, max_allowed_file_bytes,
    )
}

/// Inspect the exact already-open file description (not a reopened pathname).
/// Internal to the Rust model-store: a validated descriptor is not itself
/// immutable against writes to the same inode nor authority to start C++.
/// This reuses the SAME header and per-chunk/whole signed hash checks as the
/// legacy path-based inspector. It seeks to offset zero before verification.
pub(crate) fn inspect_independently_signed_gguf_open_file(
    trusted_key: &ModelReleasePublicKey,
    signed: &SignedModelManifest,
    file: &mut File,
    max_allowed_file_bytes: u64,
) -> Result<VerifiedGgufInspection> {
    trusted_key.verify(signed)?;
    let meta = file.metadata()?;
    if !meta.is_file() || meta.len() != signed.manifest.total_plaintext_len {
        return Err(ModelStoreError::InvalidManifest);
    }
    let inspection = inspect_independently_signed_gguf_reader(
        trusted_key, signed, file, max_allowed_file_bytes,
    )?;
    if file.metadata()?.len() != signed.manifest.total_plaintext_len {
        return Err(ModelStoreError::ChunkLengthMismatch);
    }
    Ok(inspection)
}

/// Inspect exact bytes from a caller-owned reader without a pathname/native FD
/// grant. This also verifies a final OS-sealed backing supplied by trusted Rust.
/// Receipt proves signed header/chunk/whole bytes, NOT full GGUF validity,
/// immutable ownership or authority to execute a model.
pub fn inspect_independently_signed_gguf_reader<R: Read + Seek>(
    trusted_key: &ModelReleasePublicKey,
    signed: &SignedModelManifest,
    file: &mut R,
    max_allowed_file_bytes: u64,
) -> Result<VerifiedGgufInspection> {
    trusted_key.verify(signed)?;
    let m = &signed.manifest;
    if m.format != "gguf"
        || m.minimum_runtime == 0
        || m.architecture.is_empty()
        || m.quantization.is_empty()
        || max_allowed_file_bytes < GGUF_HEADER_BYTES as u64
        || max_allowed_file_bytes > MAX_GGUF_INPUT_BYTES
        || m.total_plaintext_len < GGUF_HEADER_BYTES as u64
        || m.total_plaintext_len > max_allowed_file_bytes
    {
        return Err(ModelStoreError::InvalidManifest);
    }
    file.seek(SeekFrom::Start(0))?;
    // Receipt fields come from the SAME first bytes fed into signed hash
    // verification. A second header read would allow a mutable/deceptive
    // reader to present one header and a different signed byte stream.
    let mut header = [0u8; GGUF_HEADER_BYTES];
    let mut header_count = 0usize;
    let mut total = WholeModelVerifier::new(m);
    let mut buffer = [0u8; IO_BUFFER_BYTES];

    for chunk in &m.chunks {
        let mut remaining = chunk.plaintext_len as u64;
        let mut verify_chunk = ChunkVerifier::new(chunk);
        while remaining > 0 {
            let requested = usize::try_from(remaining.min(IO_BUFFER_BYTES as u64))
                .map_err(|_| ModelStoreError::Overflow)?;
            let count = file.read(&mut buffer[..requested])?;
            if count == 0 {
                return Err(ModelStoreError::ChunkLengthMismatch);
            }
            let prefix = (GGUF_HEADER_BYTES - header_count).min(count);
            header[header_count..header_count + prefix].copy_from_slice(&buffer[..prefix]);
            header_count += prefix;
            verify_chunk.update(&buffer[..count])?;
            total.update(&buffer[..count])?;
            remaining -= count as u64;
        }
        verify_chunk.finish()?;
    }

    // A valid signed length cannot hide appended bytes, including if a file
    // grew after we inspected its metadata.
    let mut extra = [0u8; 1];
    if file.read(&mut extra)? != 0 {
        return Err(ModelStoreError::ChunkLengthMismatch);
    }
    total.finish()?;
    if header_count != GGUF_HEADER_BYTES { return Err(ModelStoreError::InvalidManifest); }
    if &header[0..4] != b"GGUF" {
        return Err(ModelStoreError::InvalidManifest);
    }
    let gguf_version = u32::from_le_bytes(header[4..8].try_into()
        .map_err(|_| ModelStoreError::InvalidManifest)?);
    let tensor_count = u64::from_le_bytes(header[8..16].try_into()
        .map_err(|_| ModelStoreError::InvalidManifest)?);
    let metadata_count = u64::from_le_bytes(header[16..24].try_into()
        .map_err(|_| ModelStoreError::InvalidManifest)?);
    if gguf_version != GGUF_VERSION
        || tensor_count == 0 || tensor_count > MAX_GGUF_TENSORS
        || metadata_count > MAX_GGUF_METADATA_FIELDS
    {
        return Err(ModelStoreError::InvalidManifest);
    }



    Ok(VerifiedGgufInspection {
        manifest_id: signed.manifest_id,
        model_id: m.model_id,
        release_sequence: m.release_sequence,
        byte_length: m.total_plaintext_len,
        gguf_version,
        tensor_count,
        metadata_count,
    })
}


#[cfg(test)]
mod tests {
    use super::*;
    use crate::{ModelChunk, ModelObjectId, ModelReleaseSigningKey, ModelManifest};
    use sha2::{Digest, Sha256};
    use std::{
        fs,
        path::PathBuf,
        time::{SystemTime, UNIX_EPOCH},
    };

    fn gguf() -> Vec<u8> {
        let mut bytes = b"GGUF".to_vec();
        bytes.extend_from_slice(&GGUF_VERSION.to_le_bytes());
        bytes.extend_from_slice(&1u64.to_le_bytes());
        bytes.extend_from_slice(&0u64.to_le_bytes());
        bytes.extend_from_slice(b"synthetic GGUF header-only test data");
        bytes
    }

    fn manifest(bytes: &[u8]) -> ModelManifest {
        let split = 13usize;
        ModelManifest {
            model_id: ModelId([0x51; 16]),
            release_sequence: 85153,
            minimum_runtime: 1,
            format: "gguf".into(),
            architecture: "llama".into(),
            quantization: "F16".into(),
            total_plaintext_len: bytes.len() as u64,
            whole_model_sha256: Sha256::digest(bytes).into(),
            chunks: vec![
                ModelChunk {
                    index: 0,
                    object_id: ModelObjectId([1; 32]),
                    offset: 0,
                    plaintext_len: split as u32,
                    sha256: Sha256::digest(&bytes[..split]).into(),
                },
                ModelChunk {
                    index: 1,
                    object_id: ModelObjectId([2; 32]),
                    offset: split as u64,
                    plaintext_len: (bytes.len() - split) as u32,
                    sha256: Sha256::digest(&bytes[split..]).into(),
                },
            ],
        }
    }

    struct Fixture {
        root: PathBuf,
        file: PathBuf,
    }
    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            let nonce = SystemTime::now().duration_since(UNIX_EPOCH)
                .expect("time").as_nanos();
            let root = std::env::temp_dir()
                .join(format!("jend-m85153-{}-{nonce}", std::process::id()));
            fs::create_dir(&root).expect("create private fixture");
            let file = root.join("synthetic.gguf");
            fs::write(&file, bytes).expect("write fixture");
            Self { root, file }
        }
    }
    impl Drop for Fixture {
        fn drop(&mut self) { let _ = fs::remove_dir_all(&self.root); }
    }

    #[test]
    fn deceptive_reader_cannot_separate_receipt_header_from_signed_hash_stream() {
        use std::io::{Cursor, Seek};
        struct SwitchReader { good: Vec<u8>, signed: Vec<u8>, cursor: Cursor<Vec<u8>>, resets: usize }
        impl Read for SwitchReader {
            fn read(&mut self, b: &mut [u8]) -> std::io::Result<usize> { self.cursor.read(b) }
        }
        impl Seek for SwitchReader {
            fn seek(&mut self, position: SeekFrom) -> std::io::Result<u64> {
                if position == SeekFrom::Start(0) {
                    self.resets += 1;
                    self.cursor = Cursor::new(if self.resets == 1 { self.good.clone() } else { self.signed.clone() });
                }
                self.cursor.seek(position)
            }
        }
        let good = gguf();
        let mut bad = good.clone(); bad[0] ^= 1;
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bad)).unwrap();
        // Former header-read/rewind/hash behavior would accept the valid fake
        // header and later independently signed BAD magic as one receipt.
        let mut reader = SwitchReader { good, signed: bad, cursor: Cursor::new(Vec::new()), resets: 0 };
        assert!(inspect_independently_signed_gguf_reader(&signer.public_key(), &signed, &mut reader, 1024).is_err());
    }

    #[test]
    fn reader_checks_full_length_and_signed_chunks_not_only_whole_digest() {
        use std::io::Cursor;
        let bytes = gguf();
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        let key = signer.public_key();
        assert!(inspect_independently_signed_gguf_reader(&key, &signed,
            &mut Cursor::new(bytes.clone()), 1024).is_ok());
        let mut extra = bytes.clone(); extra.push(1);
        assert!(inspect_independently_signed_gguf_reader(&key, &signed,
            &mut Cursor::new(extra), 1024).is_err());
        assert!(inspect_independently_signed_gguf_reader(&key, &signed,
            &mut Cursor::new(&bytes[..bytes.len() - 1]), 1024).is_err());
        let mut wrong_chunks = manifest(&bytes);
        wrong_chunks.chunks[1].sha256[0] ^= 1;
        let signed_wrong = signer.sign_manifest(wrong_chunks).unwrap();
        assert!(inspect_independently_signed_gguf_reader(&key, &signed_wrong,
            &mut Cursor::new(bytes), 1024).is_err());
    }

    #[test]
    fn independently_signed_complete_gguf_and_chunks_pass() {
        let bytes = gguf();
        let fixture = Fixture::new(&bytes);
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        let receipt = inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 1024,
        ).unwrap();
        assert_eq!(receipt.manifest_id, signed.manifest_id);
        assert_eq!(receipt.byte_length, bytes.len() as u64);
        assert_eq!(receipt.tensor_count, 1);
        assert_eq!(receipt.gguf_version, GGUF_VERSION);
    }

    #[test]
    fn tampered_or_mismatched_release_authorization_refused() {
        let bytes = gguf();
        let fixture = Fixture::new(&bytes);
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let wrong = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        assert!(inspect_independently_signed_gguf(
            &wrong.public_key(), &signed, &fixture.file, 1024).is_err());
        let mut changed = signed.clone();
        changed.manifest.format = "onnx".into();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &changed, &fixture.file, 1024).is_err());
        let mut changed = signed.clone();
        changed.manifest.release_sequence += 1;
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &changed, &fixture.file, 1024).is_err());
    }

    #[test]
    fn flipped_corrupted_and_truncated_file_refused() {
        let bytes = gguf();
        let fixture = Fixture::new(&bytes);
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        let mut corrupted = bytes.clone();
        let last = corrupted.len() - 1;
        corrupted[last] ^= 1;
        fs::write(&fixture.file, corrupted).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 1024).is_err());

        fs::write(&fixture.file, &bytes[..bytes.len()-1]).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 1024).is_err());
        let mut appended = bytes.clone();
        appended.push(1);
        fs::write(&fixture.file, appended).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 1024).is_err());
    }

    #[test]
    fn malformed_but_newly_signed_gguf_header_is_still_rejected() {
        let mut bytes = gguf();
        bytes[0] ^= 1;
        let fixture = Fixture::new(&bytes);
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 1024).is_err());

        let mut bytes = gguf();
        bytes[4..8].copy_from_slice(&2u32.to_le_bytes());
        fs::write(&fixture.file, &bytes).unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 1024).is_err());

        let mut bytes = gguf();
        bytes[8..16].copy_from_slice(&0u64.to_le_bytes());
        fs::write(&fixture.file, &bytes).unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 1024).is_err());
    }

    #[test]
    fn budget_and_path_fail_closed() {
        let bytes = gguf();
        let fixture = Fixture::new(&bytes);
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file, 23).is_err());
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, Path::new("relative.gguf"), 1024).is_err());
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &fixture.file,
            MAX_GGUF_INPUT_BYTES + 1).is_err());
    }

    #[cfg(unix)]
    #[test]
    fn symlinked_gguf_file_is_refused() {
        use std::os::unix::fs::symlink;
        let bytes = gguf();
        let fixture = Fixture::new(&bytes);
        let link = fixture.root.join("link.gguf");
        symlink(&fixture.file, &link).unwrap();
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let signed = signer.sign_manifest(manifest(&bytes)).unwrap();
        assert!(inspect_independently_signed_gguf(
            &signer.public_key(), &signed, &link, 1024).is_err());
    }
}
