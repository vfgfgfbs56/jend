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
    io::{Read, Write},
    path::{Path, PathBuf},
};
#[cfg(unix)]
use std::os::unix::fs::{DirBuilderExt, PermissionsExt};

use crate::{
    inspect_independently_signed_gguf, ManifestId, ModelReleasePublicKey,
    ModelStoreError, Result, SignedModelManifest,
};

const MAX_SNAPSHOT_GGUF_BYTES: u64 = 16 * 1024 * 1024 * 1024;
const BUFFER_SIZE: usize = 64 * 1024;

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
