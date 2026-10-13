use std::{fs, io, path::{Path, PathBuf}};
use zeroize::Zeroizing;

pub struct LoadedSecrets {
    pub opaque_setup: Zeroizing<Vec<u8>>,
    pub auth_ticket: Zeroizing<[u8; 32]>,
    pub capability: Zeroizing<[u8; 32]>,
    pub admission: Zeroizing<[u8; 32]>,
    pub rate_hmac: Zeroizing<[u8; 32]>,
    pub device_session_hmac: Zeroizing<[u8; 32]>,
}

impl LoadedSecrets {
    pub fn load(dir: &Path) -> io::Result<Self> {
        check_private_dir(dir)?;
        let opaque_setup = Zeroizing::new(read_bounded(dir.join("opaque-server-setup.bin"), 32, 4096)?);
        Ok(Self {
            opaque_setup,
            auth_ticket: Zeroizing::new(read_key(dir.join("auth-ticket.key"))?),
            capability: Zeroizing::new(read_key(dir.join("capability-ed25519.key"))?),
            admission: Zeroizing::new(read_key(dir.join("admission-ed25519.key"))?),
            rate_hmac: Zeroizing::new(read_key(dir.join("rate-hmac.key"))?),
            device_session_hmac: Zeroizing::new(read_key(dir.join("device-session-hmac.key"))?),
        })
    }
}

fn read_key(path: PathBuf) -> io::Result<[u8; 32]> {
    let bytes = read_bounded(path, 32, 32)?;
    bytes.try_into().map_err(|_| io::Error::new(io::ErrorKind::InvalidData, "secret must be 32 bytes"))
}

fn read_bounded(path: PathBuf, min: usize, max: usize) -> io::Result<Vec<u8>> {
    check_private_file(&path)?;
    let bytes = fs::read(&path)?;
    if bytes.len() < min || bytes.len() > max {
        return Err(io::Error::new(io::ErrorKind::InvalidData, format!("invalid secret length: {}", path.display())));
    }
    Ok(bytes)
}

#[cfg(unix)]
fn check_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_dir() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("unsafe secret directory: {}", path.display())));
    }
    Ok(())
}

#[cfg(unix)]
fn check_private_file(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let metadata = fs::symlink_metadata(path)?;
    if metadata.file_type().is_symlink() || !metadata.is_file() || metadata.permissions().mode() & 0o077 != 0 {
        return Err(io::Error::new(io::ErrorKind::PermissionDenied, format!("unsafe secret file: {}", path.display())));
    }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_dir(path: &Path) -> io::Result<()> {
    if !fs::metadata(path)?.is_dir() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "secret path is not a directory")); }
    Ok(())
}

#[cfg(not(unix))]
fn check_private_file(path: &Path) -> io::Result<()> {
    if !fs::metadata(path)?.is_file() { return Err(io::Error::new(io::ErrorKind::InvalidInput, "secret path is not a file")); }
    Ok(())
}
