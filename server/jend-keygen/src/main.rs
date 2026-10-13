#![forbid(unsafe_code)]

use std::{fs, fs::OpenOptions, io::{self, Write}, path::{Path, PathBuf}};
use zeroize::Zeroize;

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let dir = std::env::args_os().nth(1).map(PathBuf::from)
        .ok_or("usage: jend-keygen <new-secret-directory>")?;
    create_private_dir(&dir)?;

    let mut setup = jend_auth::AuthServer::generate_setup_bytes();
    write_secret(&dir.join("opaque-server-setup.bin"), &setup)?;
    setup.zeroize();

    for name in [
        "auth-ticket.key",
        "capability-ed25519.key",
        "admission-ed25519.key",
        "rate-hmac.key",
        "device-session-hmac.key",
    ] {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        write_secret(&dir.join(name), &key)?;
        key.zeroize();
    }
    eprintln!("Jend server secrets created in {} (secret values not printed)", dir.display());
    Ok(())
}

#[cfg(unix)]
fn create_private_dir(path: &Path) -> io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    fs::create_dir(path)?; // refuse existing dir: prevents accidental overwrite/mixing
    fs::set_permissions(path, fs::Permissions::from_mode(0o700))
}

#[cfg(not(unix))]
fn create_private_dir(path: &Path) -> io::Result<()> { fs::create_dir(path) }

#[cfg(unix)]
fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    use std::os::unix::fs::OpenOptionsExt;
    let mut file = OpenOptions::new().write(true).create_new(true).mode(0o600).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}

#[cfg(not(unix))]
fn write_secret(path: &Path, bytes: &[u8]) -> io::Result<()> {
    let mut file = OpenOptions::new().write(true).create_new(true).open(path)?;
    file.write_all(bytes)?;
    file.sync_all()
}
