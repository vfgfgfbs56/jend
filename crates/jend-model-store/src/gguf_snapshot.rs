//! M8.5.15.4: verify and privately snapshot a signed complete GGUF.
//!
//! This is a content-addressed *local staging proof*, NOT an immutable,
//! kernel-pinned executable capability. Same-user attackers can change
//! filesystem paths after inspection. A production worker must receive an
//! OS-attested, stable read-only handle under an OS-enforced sandbox.
//!
//! The input is untrusted: no native execution or model scripts. The SHA-256
//! and exact length originate ONLY from an independently trusted release
//! signature, never from input bytes or a downloaded adjacent checksum.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use crate::{
    inspect_independently_signed_gguf, ManifestId, ModelReleasePublicKey,
    VerifiedGgufInspection,
    ModelStoreError, Result, SignedModelManifest,
};

const MAX_SNAPSHOT_GGUF_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const BUFFER_SIZE: usize = 64 * 1024;

/// A **read-only opened OS file description**, verified against a separately
/// trusted release signature. Its identity survives pathname replacement.
/// It is NOT immutable against in-place writes by another same-user process
/// and deliberately exposes neither the raw File nor a native worker path.
#[derive(Debug)]
pub struct VerifiedGgufOpenLease {
    file: File,
    inspection: VerifiedGgufInspection,
}

impl VerifiedGgufOpenLease {
    pub fn inspection(&self) -> VerifiedGgufInspection {
        self.inspection
    }

    /// Copy candidate bytes from the SAME held file into trusted staging.
    /// No raw File/FD/path escapes this lease. Reverify first and bound copying;
    /// a concurrent inode writer can still race the copy. Caller MUST seal and
    /// independently verify the final destination before any native handoff.
    /// The destination is NOT admitted by this method alone.
    pub fn copy_candidate_to<W: Write>(
        &mut self, key: &ModelReleasePublicKey, signed: &SignedModelManifest,
        allowed_bytes: u64, output: &mut W,
    ) -> Result<u64> {
        self.reverify(key, signed, allowed_bytes)?;
        self.file.seek(SeekFrom::Start(0))?;
        let expected = self.inspection.byte_length;
        let mut copied = 0u64;
        let mut buffer = [0u8; BUFFER_SIZE];
        loop {
            let request = (expected + 1 - copied).min(BUFFER_SIZE as u64) as usize;
            let count = self.file.read(&mut buffer[..request])?;
            if count == 0 { break; }
            copied += count as u64;
            if copied > expected { return Err(ModelStoreError::ChunkLengthMismatch); }
            output.write_all(&buffer[..count])?;
        }
        if copied != expected { return Err(ModelStoreError::ChunkLengthMismatch); }
        Ok(copied)
    }

    /// Rehash the *same* open descriptor rather than reopening its pathname.
    /// This detects in-place modification, but CANNOT prevent writes that
    /// happen later; production requires OS-enforced content immutability.
    pub fn reverify(
        &mut self,
        key: &ModelReleasePublicKey,
        signed: &SignedModelManifest,
        allowed_bytes: u64,
    ) -> Result<VerifiedGgufInspection> {
        let inspection = crate::signed_gguf::inspect_independently_signed_gguf_open_file(
            key, signed, &mut self.file, allowed_bytes,
        )?;
        if inspection != self.inspection {
            return Err(ModelStoreError::InvalidManifest);
        }
        Ok(inspection)
    }
}

#[derive(Debug)]
pub struct VerifiedGgufSnapshot {
    pub manifest_id: ManifestId,
    pub byte_length: u64,
    pub path: PathBuf,
}

/// The base directory must come from local Jend application policy, NEVER
/// from a model's manifest, downloaded metadata or a remote source. The root
/// may already exist only if it satisfies private-directory preflight.
///
/// On Unix, group/world permissions are refused. Windows private DACL
/// enrollment is NOT established by this prototype; see docs.
pub struct VerifiedGgufSnapshotStore {
    root: PathBuf,
}

struct RemoveStagingFile(PathBuf);
impl Drop for RemoveStagingFile {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

impl VerifiedGgufSnapshotStore {
    pub fn open(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref();
        if !root.is_absolute() {
            return Err(ModelStoreError::InvalidWeightPageStore);
        }
        ensure_private_dir(root)?;
        ensure_private_dir(&root.join("objects"))?;
        ensure_private_dir(&root.join("staging"))?;
        Ok(Self { root: root.to_owned() })
    }

    /// Read the entire source into a NEW, Jend-owned staging file. Only
    /// AFTER the copied bytes pass independently signed whole/chunk SHA-256
    /// and GGUF header checks does the store atomically publish its name
    /// with a no-overwrite hard link. The downloaded source may then change
    /// or disappear without changing the published copy.
    ///
    /// The returned path remains non-authoritative for native code. No model
    /// loader/worker is called here; access to this path is not a signature.
    pub fn snapshot(
        &self,
        trusted_key: &ModelReleasePublicKey,
        signed: &SignedModelManifest,
        source: &Path,
        allowed_bytes: u64,
    ) -> Result<VerifiedGgufSnapshot> {
        trusted_key.verify(signed)?;
        let m = &signed.manifest;
        if m.format != "gguf"
            || m.total_plaintext_len < 24
            || m.total_plaintext_len > MAX_SNAPSHOT_GGUF_BYTES
            || allowed_bytes < 24
            || allowed_bytes > MAX_SNAPSHOT_GGUF_BYTES
            || m.total_plaintext_len > allowed_bytes
            || !source.is_absolute()
        {
            return Err(ModelStoreError::InvalidManifest);
        }
        self.check_layout()?;
        let path = self.object_path(m.whole_model_sha256);
        if path.exists() {
            self.check_existing(trusted_key, signed, &path, allowed_bytes)?;
            return Ok(VerifiedGgufSnapshot {
                manifest_id: signed.manifest_id,
                byte_length: m.total_plaintext_len,
                path,
            });
        }
        let source_metadata = fs::symlink_metadata(source)?;
        if !source_metadata.file_type().is_file()
            || source_metadata.file_type().is_symlink()
            || source_metadata.len() != m.total_plaintext_len
        {
            return Err(ModelStoreError::InvalidManifest);
        }
        let mut input = File::open(source)?;
        if !input.metadata()?.is_file() {
            return Err(ModelStoreError::InvalidManifest);
        }

        // The random stage name never appears in signed metadata and is not
        // guessable. create_new prevents overwriting a pre-existing object.
        let mut stage = None;
        for _ in 0..16 {
            let mut random = [0u8; 16];
            getrandom::fill(&mut random)?;
            let candidate = self.root.join("staging")
                .join(format!("{}.part", hex(&random)));
            match OpenOptions::new().write(true).create_new(true).open(&candidate) {
                Ok(file) => {
                    stage = Some((candidate, file));
                    break;
                }
                Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => continue,
                Err(error) => return Err(ModelStoreError::Io(error)),
            }
        }
        let (stage_path, mut staged) =
            stage.ok_or(ModelStoreError::WeightPageStoreCollision)?;
        let _guard = RemoveStagingFile(stage_path.clone());

        let mut buffer = [0u8; BUFFER_SIZE];
        let mut copied = 0u64;
        loop {
            let count = input.read(&mut buffer)?;
            if count == 0 {
                break;
            }
            copied = copied.checked_add(count as u64)
                .ok_or(ModelStoreError::Overflow)?;
            if copied > m.total_plaintext_len {
                return Err(ModelStoreError::ChunkLengthMismatch);
            }
            staged.write_all(&buffer[..count])?;
        }
        if copied != m.total_plaintext_len {
            return Err(ModelStoreError::ChunkLengthMismatch);
        }
        staged.sync_all()?;
        set_readonly(&staged)?;
        staged.sync_all()?;
        drop(staged);

        // Verify the exact staged copy, not the mutable source file. Signed
        // chunk hashes, whole digest and GGUF header MUST all pass.
        inspect_independently_signed_gguf(
            trusted_key, signed, &stage_path, allowed_bytes,
        )?;

        // Same-filesystem hard_link is atomic and refuses overwrite. This is
        // safer than a check-then-rename which can replace an existing file.
        match fs::hard_link(&stage_path, &path) {
            Ok(()) => {
                sync_dir(&self.root.join("objects"))?;
            }
            Err(error) if error.kind() == std::io::ErrorKind::AlreadyExists => {
                self.check_existing(trusted_key, signed, &path, allowed_bytes)?;
            }
            Err(error) => return Err(ModelStoreError::Io(error)),
        }
        // Unlink the staging alias before applying the Windows read-only bit:
        // permissions are shared by hardlinks on NTFS. The guard still cleans
        // partial failures; on Unix the file was already mode 0400.
        fs::remove_file(&stage_path)?;
        #[cfg(windows)]
        {
            let mut p = fs::metadata(&path)?.permissions();
            p.set_readonly(true);
            fs::set_permissions(&path, p)?;
        }
        Ok(VerifiedGgufSnapshot {
            manifest_id: signed.manifest_id,
            byte_length: m.total_plaintext_len,
            path,
        })
    }

    /// A repeat lookup still verifies the independently signed file again;
    /// an existing hash-named file is NEVER trusted on its filename alone.
    pub fn check_existing(
        &self,
        key: &ModelReleasePublicKey,
        signed: &SignedModelManifest,
        path: &Path,
        allowed_bytes: u64,
    ) -> Result<()> {
        self.check_layout()?;
        if path != self.object_path(signed.manifest.whole_model_sha256) {
            return Err(ModelStoreError::InvalidWeightPageStore);
        }
        inspect_independently_signed_gguf(key, signed, path, allowed_bytes)?;
        Ok(())
    }

    /// Open a content-addressed snapshot **once** and validate that exact
    /// open file description. The returned capability has NO public raw file
    /// descriptor, pathname or method to authorize native code execution.
    /// Do not use this as a production stable-memory snapshot or worker grant.
    pub fn open_verified_handle(
        &self,
        trusted_key: &ModelReleasePublicKey,
        signed: &SignedModelManifest,
        allowed_bytes: u64,
    ) -> Result<VerifiedGgufOpenLease> {
        trusted_key.verify(signed)?;
        self.check_layout()?;
        let path = self.object_path(signed.manifest.whole_model_sha256);
        let initial = fs::symlink_metadata(&path)?;
        if !initial.file_type().is_file() || initial.file_type().is_symlink() {
            return Err(ModelStoreError::InvalidWeightPageStore);
        }
        let mut file = File::open(&path)?;
        let opened = file.metadata()?;
        if !opened.is_file() || opened.len() != initial.len() {
            return Err(ModelStoreError::InvalidWeightPageStore);
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if initial.dev() != opened.dev() || initial.ino() != opened.ino() {
                return Err(ModelStoreError::InvalidWeightPageStore);
            }
        }
        let inspection = crate::signed_gguf::inspect_independently_signed_gguf_open_file(
            trusted_key, signed, &mut file, allowed_bytes,
        )?;
        Ok(VerifiedGgufOpenLease { file, inspection })
    }

    fn check_layout(&self) -> Result<()> {
        for path in [&self.root, &self.root.join("objects"), &self.root.join("staging")] {
            check_private_dir(path)?;
        }
        Ok(())
    }

    fn object_path(&self, digest: [u8; 32]) -> PathBuf {
        self.root.join("objects").join(format!("{}.gguf", hex(&digest)))
    }
}

fn hex(bytes: &[u8]) -> String {
    const DIGITS: &[u8; 16] = b"0123456789abcdef";
    let mut result = String::with_capacity(bytes.len() * 2);
    for &byte in bytes {
        result.push(DIGITS[(byte >> 4) as usize] as char);
        result.push(DIGITS[(byte & 15) as usize] as char);
    }
    result
}

fn ensure_private_dir(path: &Path) -> Result<()> {
    if !path.exists() {
        #[cfg(unix)]
        {
            let mut builder = fs::DirBuilder::new();
            builder.mode(0o700);
            builder.create(path)?;
        }
        #[cfg(not(unix))]
        fs::create_dir(path)?;
    }
    check_private_dir(path)
}

fn check_private_dir(path: &Path) -> Result<()> {
    let meta = fs::symlink_metadata(path)?;
    if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
        return Err(ModelStoreError::InvalidWeightPageStore);
    }
    #[cfg(unix)]
    if meta.permissions().mode() & 0o077 != 0 {
        return Err(ModelStoreError::InvalidWeightPageStore);
    }
    Ok(())
}

fn set_readonly(file: &File) -> Result<()> {
    #[cfg(unix)]
    {
        let permissions = fs::Permissions::from_mode(0o400);
        file.set_permissions(permissions)?;
    }
    #[cfg(not(unix))]
    let _ = file; // Windows read-only bit set after unlinking staging alias.
    Ok(())
}

fn sync_dir(path: &Path) -> Result<()> {
    #[cfg(unix)]
    File::open(path)?.sync_all()?;
    #[cfg(not(unix))]
    let _ = path;
    Ok(())
}

#[cfg(all(test, unix))]
mod copy_race_tests {
    use super::*;
    use crate::{ModelChunk, ModelId, ModelManifest, ModelObjectId, ModelReleaseSigningKey};
    use sha2::{Digest, Sha256};
    use std::{io::Cursor, time::{SystemTime, UNIX_EPOCH}};

    struct RaceWriter { inode: File, bytes: Vec<u8>, changed: bool }
    impl Write for RaceWriter {
        fn write(&mut self, bytes: &[u8]) -> std::io::Result<usize> {
            self.bytes.extend_from_slice(bytes);
            if !self.changed {
                // Deterministically change an unread byte AFTER initial rehash
                // and AFTER first copy buffer, without changing length/inode.
                self.inode.seek(SeekFrom::Start(BUFFER_SIZE as u64))?;
                self.inode.write_all(&[0x99])?;
                self.changed = true;
            }
            Ok(bytes.len())
        }
        fn flush(&mut self) -> std::io::Result<()> { Ok(()) }
    }
    #[test]
    fn same_inode_mutation_during_copy_is_rejected_by_final_destination_verifier() {
        let mut bytes = b"GGUF".to_vec();
        bytes.extend(3u32.to_le_bytes()); bytes.extend(1u64.to_le_bytes()); bytes.extend(0u64.to_le_bytes());
        bytes.resize(BUFFER_SIZE * 2, 0x55);
        let signer = ModelReleaseSigningKey::generate().unwrap();
        let manifest = ModelManifest { model_id: ModelId([0x6d; 16]), release_sequence: 1,
            minimum_runtime: 1, format: "gguf".into(), architecture: "llama".into(), quantization: "F16".into(),
            total_plaintext_len: bytes.len() as u64, whole_model_sha256: Sha256::digest(&bytes).into(),
            chunks: bytes.chunks(BUFFER_SIZE).enumerate().map(|(i, b)| ModelChunk {
                index: i as u32, object_id: ModelObjectId([i as u8 + 1; 32]),
                offset: (i * BUFFER_SIZE) as u64, plaintext_len: b.len() as u32,
                sha256: Sha256::digest(b).into(),
            }).collect() };
        let signed = signer.sign_manifest(manifest).unwrap();
        let key = signer.public_key();
        let nonce = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
        let path = std::env::temp_dir().join(format!("jend-copy-race-{}-{nonce}", std::process::id()));
        fs::write(&path, &bytes).unwrap();
        let mut file = File::open(&path).unwrap();
        let inspection = crate::signed_gguf::inspect_independently_signed_gguf_open_file(
            &key, &signed, &mut file, bytes.len() as u64).unwrap();
        let mut lease = VerifiedGgufOpenLease { file, inspection };
        let mut writer = RaceWriter { inode: OpenOptions::new().write(true).open(&path).unwrap(),
            bytes: Vec::new(), changed: false };
        assert_eq!(lease.copy_candidate_to(&key, &signed, bytes.len() as u64, &mut writer).unwrap(), bytes.len() as u64);
        assert!(crate::inspect_independently_signed_gguf_reader(&key, &signed,
            &mut Cursor::new(writer.bytes), bytes.len() as u64).is_err());
        fs::remove_file(path).unwrap();
    }
}
