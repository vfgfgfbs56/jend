use std::{fs, io::{self, Read, Write}, path::{Path, PathBuf}};
use zeroize::Zeroizing;

use crate::{Result, VaultError};

pub trait SecretStore {
    fn load_or_create_32(&self, name: &str) -> Result<Zeroizing<[u8; 32]>>;
}

/// Development-only secret storage. Secrets are written to local files with
/// restrictive Unix permissions. Production builds should replace this with an
/// OS keystore / TPM / Secure Enclave adapter.
pub struct DevFileSecretStore {
    dir: PathBuf,
}

impl DevFileSecretStore {
    pub fn new(dir: impl AsRef<Path>) -> Result<Self> {
        let dir = dir.as_ref().to_path_buf();
        fs::create_dir_all(&dir)?;
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(&dir, fs::Permissions::from_mode(0o700))?;
        }
        Ok(Self { dir })
    }

    fn path_for(&self, name: &str) -> Result<PathBuf> {
        if name.is_empty() || !name.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_') {
            return Err(VaultError::MalformedMetadata);
        }
        Ok(self.dir.join(name))
    }

    fn read_existing(path: &Path) -> Result<Zeroizing<[u8; 32]>> {
        let mut file = fs::File::open(path)?;
        let mut bytes = Zeroizing::new([0u8; 32]);
        file.read_exact(bytes.as_mut())?;
        let mut extra = [0u8; 1];
        if file.read(&mut extra)? != 0 {
            return Err(VaultError::InvalidSecretSize);
        }
        Ok(bytes)
    }
}

impl SecretStore for DevFileSecretStore {
    fn load_or_create_32(&self, name: &str) -> Result<Zeroizing<[u8; 32]>> {
        let path = self.path_for(name)?;
        match Self::read_existing(&path) {
            Ok(v) => return Ok(v),
            Err(VaultError::Io(err)) if err.kind() == io::ErrorKind::NotFound => {}
            Err(err) => return Err(err),
        }

        let mut candidate = Zeroizing::new([0u8; 32]);
        getrandom::fill(candidate.as_mut())?;

        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }

        match options.open(&path) {
            Ok(mut file) => {
                file.write_all(candidate.as_ref())?;
                file.sync_all()?;
                sync_parent(&path)?;
                Ok(candidate)
            }
            Err(err) if err.kind() == io::ErrorKind::AlreadyExists => Self::read_existing(&path),
            Err(err) => Err(err.into()),
        }
    }
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        let dir = fs::File::open(parent)?;
        dir.sync_all()?;
    }
    Ok(())
}
