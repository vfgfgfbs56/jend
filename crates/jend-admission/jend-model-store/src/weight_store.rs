//! Durable content-addressed storage for WeightVM pages.
//!
//! Objects are immutable and addressed by SHA-256. Writes use a private staging
//! file, `sync_all`, and an atomic rename before the object becomes visible.
//! WeightVM reads only final object paths; leftover staging files are discarded
//! during recovery.
//!
//! This store is intentionally local-only. It contains no HTTP/network client.

use std::{
    fs::{self, File, OpenOptions},
    io::{Read, Write},
    path::{Path, PathBuf},
};

use sha2::Digest;
use subtle::ConstantTimeEq;

use crate::{
    ModelStoreError, Result, VerifiedSourceReadRequest, WeightPageDescriptor, WeightPageId,
    WeightPageSource,
};

const MAX_STORE_PAGE_BYTES: u64 = 512 * 1024 * 1024;
const IO_BUFFER: usize = 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct WeightStoreStats {
    pub object_count: u64,
    pub stored_bytes: u64,
}

#[derive(Clone, Debug)]
pub struct DurableWeightPageStore {
    root: PathBuf,
}

impl DurableWeightPageStore {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let store = Self {
            root: root.as_ref().to_path_buf(),
        };
        store.prepare()?;
        store.recover_staging()?;
        Ok(store)
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn prepare(&self) -> Result<()> {
        create_private_dir(&self.root)?;
        create_private_dir(&self.objects_dir())?;
        create_private_dir(&self.staging_dir())?;
        Ok(())
    }

    /// Atomically add a locally trusted page. The object becomes visible only
    /// after its staging file has been fully written, synced, and re-verified.
    pub fn put_page(&self, bytes: &[u8]) -> Result<WeightPageDescriptor> {
        let plaintext_len =
            u64::try_from(bytes.len()).map_err(|_| ModelStoreError::Overflow)?;
        if plaintext_len == 0 || plaintext_len > MAX_STORE_PAGE_BYTES {
            return Err(ModelStoreError::InvalidWeightPage);
        }

        let descriptor = WeightPageDescriptor {
            page_id: WeightPageId::for_bytes(bytes),
            plaintext_len,
        }
        .validate()?;
        self.publish_preverified(descriptor, bytes)
    }

    /// Publish bytes reconstructed by an external source adapter only after
    /// they match the exact page identity carried by a verified signed-map
    /// request. Length and SHA-256 are checked before any staging file exists.
    pub fn put_verified_source_page(
        &self,
        verified: VerifiedSourceReadRequest,
        bytes: &[u8],
    ) -> Result<WeightPageDescriptor> {
        let request = verified.request();
        let descriptor = verified.expected_page().validate()?;
        if request.len != descriptor.plaintext_len {
            return Err(ModelStoreError::InvalidSourceBinding);
        }
        verify_page_bytes(descriptor, bytes)?;
        self.publish_preverified(descriptor, bytes)
    }

    fn publish_preverified(
        &self,
        descriptor: WeightPageDescriptor,
        bytes: &[u8],
    ) -> Result<WeightPageDescriptor> {
        descriptor.validate()?;
        let plaintext_len =
            u64::try_from(bytes.len()).map_err(|_| ModelStoreError::Overflow)?;
        if plaintext_len != descriptor.plaintext_len {
            return Err(ModelStoreError::WeightPageLengthMismatch);
        }

        self.prepare()?;
        let final_path = self.object_path(descriptor.page_id);
        let shard = final_path
            .parent()
            .ok_or(ModelStoreError::InvalidWeightPageStore)?;
        create_private_dir(shard)?;

        if final_path.exists() {
            self.verify_object(descriptor)?;
            return Ok(descriptor);
        }

        let staging_path = self.unique_staging_path(descriptor.page_id)?;
        let result = (|| -> Result<()> {
            let mut file = create_private_new_file(&staging_path)?;
            file.write_all(bytes)?;
            file.sync_all()?;
            drop(file);

            // Re-read the durable staging bytes before publication. This makes
            // corruption visible before the object path becomes authoritative.
            verify_file(&staging_path, descriptor)?;

            match fs::rename(&staging_path, &final_path) {
                Ok(()) => {
                    set_private_file_permissions(&final_path)?;
                    sync_dir(shard)?;
                    Ok(())
                }
                Err(_rename_error) if final_path.exists() => {
                    // A racing writer may already have published the same
                    // content-addressed object. Reuse it only after verification.
                    let _ = fs::remove_file(&staging_path);
                    self.verify_object(descriptor)?;
                    Ok(())
                }
                Err(rename_error) => Err(ModelStoreError::Io(rename_error)),
            }
        })();

        if result.is_err() {
            let _ = fs::remove_file(&staging_path);
        }
        result?;
        Ok(descriptor)
    }

    pub fn contains_verified(&self, descriptor: WeightPageDescriptor) -> Result<bool> {
        descriptor.validate()?;
        let path = self.object_path(descriptor.page_id);
        if !path.exists() {
            return Ok(false);
        }
        self.verify_object(descriptor)?;
        Ok(true)
    }

    pub fn verify_object(&self, descriptor: WeightPageDescriptor) -> Result<()> {
        descriptor.validate()?;
        verify_file(&self.object_path(descriptor.page_id), descriptor)
    }

    /// Delete leftover partial writes. Final objects are never touched.
    pub fn recover_staging(&self) -> Result<u64> {
        self.prepare()?;
        let mut removed = 0u64;

        for entry in fs::read_dir(self.staging_dir())? {
            let entry = entry?;
            let path = entry.path();
            let meta = fs::symlink_metadata(&path)?;

            if meta.file_type().is_file() || meta.file_type().is_symlink() {
                fs::remove_file(path)?;
                removed = removed
                    .checked_add(1)
                    .ok_or(ModelStoreError::Overflow)?;
            } else if meta.file_type().is_dir() {
                // Staging has no legitimate subdirectories.
                return Err(ModelStoreError::InvalidWeightPageStore);
            }
        }

        if removed > 0 {
            sync_dir(&self.staging_dir())?;
        }
        Ok(removed)
    }

    pub fn stats(&self) -> Result<WeightStoreStats> {
        self.prepare()?;
        let mut object_count = 0u64;
        let mut stored_bytes = 0u64;

        for shard in fs::read_dir(self.objects_dir())? {
            let shard = shard?;
            let shard_path = shard.path();
            let shard_meta = fs::symlink_metadata(&shard_path)?;
            if !shard_meta.file_type().is_dir() || shard_meta.file_type().is_symlink() {
                return Err(ModelStoreError::InvalidWeightPageStore);
            }

            for entry in fs::read_dir(shard_path)? {
                let entry = entry?;
                let path = entry.path();
                let meta = fs::symlink_metadata(&path)?;
                if !meta.file_type().is_file() || meta.file_type().is_symlink() {
                    return Err(ModelStoreError::InvalidWeightPageStore);
                }
                let name = path
                    .file_name()
                    .and_then(|name| name.to_str())
                    .ok_or(ModelStoreError::InvalidWeightPageStore)?;
                if !valid_object_filename(name) {
                    return Err(ModelStoreError::InvalidWeightPageStore);
                }
                object_count = object_count
                    .checked_add(1)
                    .ok_or(ModelStoreError::Overflow)?;
                stored_bytes = stored_bytes
                    .checked_add(meta.len())
                    .ok_or(ModelStoreError::Overflow)?;
            }
        }

        Ok(WeightStoreStats {
            object_count,
            stored_bytes,
        })
    }

    fn objects_dir(&self) -> PathBuf {
        self.root.join("objects")
    }

    fn staging_dir(&self) -> PathBuf {
        self.root.join("staging")
    }

    fn object_path(&self, page_id: WeightPageId) -> PathBuf {
        let digest = hex(&page_id.0);
        self.objects_dir()
            .join(&digest[..2])
            .join(format!("{digest}.page"))
    }

    fn unique_staging_path(&self, page_id: WeightPageId) -> Result<PathBuf> {
        let digest = hex(&page_id.0);
        for _ in 0..16 {
            let mut random = [0u8; 8];
            getrandom::fill(&mut random)?;
            let candidate = self
                .staging_dir()
                .join(format!("{digest}.{}.part", hex(&random)));
            if !candidate.exists() {
                return Ok(candidate);
            }
        }
        Err(ModelStoreError::WeightPageStoreCollision)
    }
}

impl WeightPageSource for DurableWeightPageStore {
    fn read_page(&self, page_id: WeightPageId) -> Result<Vec<u8>> {
        let path = self.object_path(page_id);
        let meta = fs::symlink_metadata(&path).map_err(|error| {
            if error.kind() == std::io::ErrorKind::NotFound {
                ModelStoreError::InvalidWeightPage
            } else {
                ModelStoreError::Io(error)
            }
        })?;
        if !meta.file_type().is_file() || meta.file_type().is_symlink() {
            return Err(ModelStoreError::InvalidWeightPageStore);
        }
        if meta.len() == 0 || meta.len() > MAX_STORE_PAGE_BYTES {
            return Err(ModelStoreError::InvalidWeightPage);
        }

        let mut file = File::open(&path)?;
        let mut bytes = Vec::with_capacity(
            usize::try_from(meta.len()).map_err(|_| ModelStoreError::Overflow)?,
        );
        file.read_to_end(&mut bytes)?;

        let actual = WeightPageId::for_bytes(&bytes);
        if actual.0.ct_eq(&page_id.0).unwrap_u8() != 1 {
            return Err(ModelStoreError::WeightPageDigestMismatch);
        }
        Ok(bytes)
    }
}

fn verify_page_bytes(descriptor: WeightPageDescriptor, bytes: &[u8]) -> Result<()> {
    descriptor.validate()?;
    let actual_len = u64::try_from(bytes.len()).map_err(|_| ModelStoreError::Overflow)?;
    if actual_len != descriptor.plaintext_len {
        return Err(ModelStoreError::WeightPageLengthMismatch);
    }
    let mut hasher = sha2::Sha256::new();
    hasher.update(bytes);
    let digest: [u8; 32] = hasher.finalize().into();
    if digest.ct_eq(&descriptor.page_id.0).unwrap_u8() != 1 {
        return Err(ModelStoreError::WeightPageDigestMismatch);
    }
    Ok(())
}

fn verify_file(path: &Path, descriptor: WeightPageDescriptor) -> Result<()> {
    let meta = fs::symlink_metadata(path).map_err(|error| {
        if error.kind() == std::io::ErrorKind::NotFound {
            ModelStoreError::InvalidWeightPage
        } else {
            ModelStoreError::Io(error)
        }
    })?;
    if !meta.file_type().is_file() || meta.file_type().is_symlink() {
        return Err(ModelStoreError::InvalidWeightPageStore);
    }
    if meta.len() != descriptor.plaintext_len {
        return Err(ModelStoreError::WeightPageLengthMismatch);
    }

    let mut file = File::open(path)?;
    let mut hasher = sha2::Sha256::new();
    let mut total = 0u64;
    let mut buffer = vec![0u8; IO_BUFFER];

    loop {
        let n = file.read(&mut buffer)?;
        if n == 0 {
            break;
        }
        hasher.update(&buffer[..n]);
        total = total
            .checked_add(u64::try_from(n).map_err(|_| ModelStoreError::Overflow)?)
            .ok_or(ModelStoreError::Overflow)?;
    }

    if total != descriptor.plaintext_len {
        return Err(ModelStoreError::WeightPageLengthMismatch);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if digest.ct_eq(&descriptor.page_id.0).unwrap_u8() != 1 {
        return Err(ModelStoreError::WeightPageDigestMismatch);
    }
    Ok(())
}

fn valid_object_filename(name: &str) -> bool {
    let Some(hex_part) = name.strip_suffix(".page") else {
        return false;
    };
    hex_part.len() == 64
        && hex_part
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
}

fn hex(bytes: &[u8]) -> String {
    const TABLE: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for byte in bytes {
        out.push(TABLE[(byte >> 4) as usize] as char);
        out.push(TABLE[(byte & 0x0f) as usize] as char);
    }
    out
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        if !meta.file_type().is_dir()
            || meta.file_type().is_symlink()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(ModelStoreError::InvalidWeightPageStore);
        }
        return Ok(());
    }

    fs::create_dir(path)?;
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))?;
    Ok(())
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> Result<()> {
    if path.exists() {
        let meta = fs::symlink_metadata(path)?;
        if !meta.file_type().is_dir() || meta.file_type().is_symlink() {
            return Err(ModelStoreError::InvalidWeightPageStore);
        }
        return Ok(());
    }
    fs::create_dir(path)?;
    Ok(())
}

#[cfg(unix)]
fn create_private_new_file(path: &Path) -> Result<File> {
    use std::os::unix::fs::OpenOptionsExt;

    Ok(OpenOptions::new()
        .create_new(true)
        .write(true)
        .mode(0o600)
        .open(path)?)
}

#[cfg(not(unix))]
fn create_private_new_file(path: &Path) -> Result<File> {
    Ok(OpenOptions::new().create_new(true).write(true).open(path)?)
}

#[cfg(unix)]
fn set_private_file_permissions(path: &Path) -> Result<()> {
    use std::os::unix::fs::PermissionsExt;

    fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
    Ok(())
}

#[cfg(not(unix))]
fn set_private_file_permissions(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(unix)]
fn sync_dir(path: &Path) -> Result<()> {
    File::open(path)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_dir(_path: &Path) -> Result<()> {
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{WeightVm, WeightVmBudget};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn temp_store_root(label: &str) -> PathBuf {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        std::env::temp_dir().join(format!(
            "jend-weight-store-test-{}-{}-{}",
            std::process::id(),
            label,
            now
        ))
    }

    #[test]
    fn page_survives_store_restart_and_feeds_weightvm() {
        let root = temp_store_root("restart");
        let payload = vec![7u8; 64 * 1024];

        let descriptor = {
            let store = DurableWeightPageStore::new(&root).unwrap();
            store.put_page(&payload).unwrap()
        };

        let reopened = DurableWeightPageStore::new(&root).unwrap();
        assert!(reopened.contains_verified(descriptor).unwrap());

        let vm = WeightVm::new(
            reopened,
            WeightVmBudget {
                resident_bytes: 128 * 1024,
            },
        )
        .unwrap();
        let lease = vm.pin_page(descriptor).unwrap();
        assert_eq!(lease.bytes(), payload.as_slice());

        drop(lease);
        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn duplicate_put_is_one_disk_object() {
        let root = temp_store_root("dedup");
        let store = DurableWeightPageStore::new(&root).unwrap();
        let payload = vec![3u8; 4096];

        let a = store.put_page(&payload).unwrap();
        let b = store.put_page(&payload).unwrap();
        assert_eq!(a, b);

        let stats = store.stats().unwrap();
        assert_eq!(stats.object_count, 1);
        assert_eq!(stats.stored_bytes, 4096);

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn corruption_is_detected_on_read() {
        let root = temp_store_root("corrupt");
        let store = DurableWeightPageStore::new(&root).unwrap();
        let payload = vec![8u8; 4096];
        let descriptor = store.put_page(&payload).unwrap();

        let path = store.object_path(descriptor.page_id);
        fs::write(&path, vec![9u8; 4096]).unwrap();

        assert!(matches!(
            store.read_page(descriptor.page_id),
            Err(ModelStoreError::WeightPageDigestMismatch)
        ));

        let _ = fs::remove_dir_all(root);
    }

    #[test]
    fn stale_staging_files_are_removed_on_reopen() {
        let root = temp_store_root("recovery");
        let store = DurableWeightPageStore::new(&root).unwrap();
        let stale = store.staging_dir().join("abandoned.part");
        fs::write(&stale, b"partial").unwrap();
        drop(store);

        let reopened = DurableWeightPageStore::new(&root).unwrap();
        assert!(!stale.exists());
        assert_eq!(reopened.stats().unwrap().object_count, 0);

        let _ = fs::remove_dir_all(root);
    }

    #[cfg(unix)]
    #[test]
    fn public_existing_store_directory_is_rejected() {
        use std::os::unix::fs::PermissionsExt;

        let root = temp_store_root("permissions");
        fs::create_dir(&root).unwrap();
        fs::set_permissions(&root, fs::Permissions::from_mode(0o755)).unwrap();

        assert!(matches!(
            DurableWeightPageStore::new(&root),
            Err(ModelStoreError::InvalidWeightPageStore)
        ));

        let _ = fs::remove_dir_all(root);
    }
}
