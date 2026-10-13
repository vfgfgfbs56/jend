//! M8.5.15.6a: non-executing local native worker binary integrity check.
//!
//! Development-only preparatory gate. This module NEVER starts a native
//! executable, authorizes any GGUF file, or grants access to private chat.
//! A SHA-256 computed from the candidate itself is NOT a trust anchor.
//! Expected SHA-256 must come from an independently trusted, signed Jend
//! worker distribution / build identity; CI only uses local synthetic trust.
//! This check is NOT race-free process exec or an operating-system sandbox.

use sha2::{Digest, Sha256};
use std::{
    fs::{self, File},
    io::Read,
    path::{Component, Path},
};

const CHUNK_BYTES: usize = 64 * 1024;
const MAX_WORKER_BYTES: u64 = 128 * 1024 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub enum NativeBinaryError {
    UnsafePath,
    InvalidLimit,
    UntrustedBinary,
    FileChanged,
    Io,
}

impl std::fmt::Display for NativeBinaryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Do not leak candidate executable paths or additional details.
        f.write_str(match self {
            Self::UnsafePath => "native worker path is not safe",
            Self::InvalidLimit => "native worker file size bound rejected",
            Self::UntrustedBinary => "native worker digest not enrolled",
            Self::FileChanged => "native worker file changed during inspection",
            Self::Io => "native worker file inspection failed",
        })
    }
}
impl std::error::Error for NativeBinaryError {}

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
pub struct NativeBinaryInspection {
    pub byte_length: u64,
    pub sha256: [u8; 32],
}

/// Verify candidate binary bytes against an independent expected SHA-256.
/// Returns metadata only: there is deliberately NO public exec() method,
/// path, File or platform handle. A caller must not convert this result into
/// authority to launch a worker until the OS guarantees executable identity,
/// sandboxing, no network access and resource limits.
pub fn inspect_pinned_native_worker(
    executable: &Path,
    independently_pinned_sha256: &[u8; 32],
    maximum_bytes: u64,
) -> Result<NativeBinaryInspection, NativeBinaryError> {
    if maximum_bytes == 0 || maximum_bytes > MAX_WORKER_BYTES {
        return Err(NativeBinaryError::InvalidLimit);
    }
    // Reject ambiguous relative paths and parent traversal, including an
    // absolute /trusted/../untrusted location. This is NOT openat2 nor a
    // complete ancestor-symlink/ACL guarantee.
    if !executable.is_absolute() ||
        executable.components().any(|component| {
            matches!(component, Component::ParentDir | Component::CurDir)
        })
    {
        return Err(NativeBinaryError::UnsafePath);
    }
    let before = fs::symlink_metadata(executable).map_err(|_| NativeBinaryError::Io)?;
    if !before.file_type().is_file() || before.file_type().is_symlink()
        || before.len() == 0 || before.len() > maximum_bytes
    {
        return Err(NativeBinaryError::UnsafePath);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        // Reject a directly modifiable-by-others worker. Owner-writable
        // files remain a TOCTOU risk and CANNOT be used in production.
        if before.permissions().mode() & 0o022 != 0 {
            return Err(NativeBinaryError::UnsafePath);
        }
    }
    let mut file = File::open(executable).map_err(|_| NativeBinaryError::Io)?;
    let opened = file.metadata().map_err(|_| NativeBinaryError::Io)?;
    if !opened.is_file() || opened.len() != before.len() {
        return Err(NativeBinaryError::FileChanged);
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::MetadataExt;
        if before.dev() != opened.dev() || before.ino() != opened.ino() {
            return Err(NativeBinaryError::FileChanged);
        }
    }
    let mut hasher = Sha256::new();
    let mut buffer = [0u8; CHUNK_BYTES];
    let mut count = 0u64;
    loop {
        let n = file.read(&mut buffer).map_err(|_| NativeBinaryError::Io)?;
        if n == 0 { break; }
        count = count.checked_add(n as u64).ok_or(NativeBinaryError::FileChanged)?;
        if count > maximum_bytes || count > before.len() {
            return Err(NativeBinaryError::FileChanged);
        }
        hasher.update(&buffer[..n]);
    }
    let after = file.metadata().map_err(|_| NativeBinaryError::Io)?;
    if count != before.len() || after.len() != opened.len() {
        return Err(NativeBinaryError::FileChanged);
    }
    let digest: [u8; 32] = hasher.finalize().into();
    if &digest != independently_pinned_sha256 {
        return Err(NativeBinaryError::UntrustedBinary);
    }
    Ok(NativeBinaryInspection { byte_length: count, sha256: digest })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        fs,
        time::{SystemTime, UNIX_EPOCH},
    };

    struct Fixture(std::path::PathBuf);
    impl Fixture {
        fn new(bytes: &[u8]) -> Self {
            let t = SystemTime::now().duration_since(UNIX_EPOCH).unwrap().as_nanos();
            let path = std::env::temp_dir()
                .join(format!("jend-native-integrity-{}-{t}.bin",std::process::id()));
            fs::write(&path, bytes).unwrap();
            Self(path)
        }
        fn digest(bytes: &[u8]) -> [u8; 32] { Sha256::digest(bytes).into() }
    }
    impl Drop for Fixture { fn drop(&mut self) { let _ = fs::remove_file(&self.0); } }

    #[test]
    fn correctly_pinned_bytes_are_only_inspected() {
        let fixture = Fixture::new(b"test executable bytes without native execution");
        let pinned = Fixture::digest(&fs::read(&fixture.0).unwrap());
        let outcome=inspect_pinned_native_worker(&fixture.0, &pinned, 128).unwrap();
        assert_eq!(outcome.byte_length, 46);
        assert_eq!(outcome.sha256, pinned);
    }

    #[test]
    fn mismatched_digest_is_rejected() {
        let fixture = Fixture::new(b"trusted fixture bytes");
        let pin = [0xaa; 32];
        assert_eq!(
            inspect_pinned_native_worker(&fixture.0,&pin,128),
            Err(NativeBinaryError::UntrustedBinary)
        );
        fs::write(&fixture.0,b"mutated binary bytes").unwrap();
        assert_eq!(
            inspect_pinned_native_worker(&fixture.0,&Fixture::digest(b"trusted fixture bytes"),128),
            Err(NativeBinaryError::UntrustedBinary)
        );
    }

    #[test]
    fn invalid_size_and_relative_path_fail_closed() {
        let fixture = Fixture::new(b"safe");
        let pin=Fixture::digest(b"safe");
        assert_eq!(
            inspect_pinned_native_worker(&fixture.0,&pin,0),
            Err(NativeBinaryError::InvalidLimit)
        );
        assert_eq!(
            inspect_pinned_native_worker(&fixture.0,&pin,MAX_WORKER_BYTES+1),
            Err(NativeBinaryError::InvalidLimit)
        );
        assert_eq!(
            inspect_pinned_native_worker(&fixture.0,&pin,3),
            Err(NativeBinaryError::UnsafePath)
        );
        assert_eq!(
            inspect_pinned_native_worker(Path::new("relative/worker"),&pin,128),
            Err(NativeBinaryError::UnsafePath)
        );
    }

    #[cfg(unix)]
    #[test]
    fn final_symlink_and_group_writable_worker_refused() {
        use std::os::unix::{fs::{symlink,PermissionsExt}};
        let fixture=Fixture::new(b"worker");
        let link=fixture.0.with_extension("link");
        symlink(&fixture.0,&link).unwrap();
        let pin=Fixture::digest(b"worker");
        assert_eq!(
            inspect_pinned_native_worker(&link,&pin,128),
            Err(NativeBinaryError::UnsafePath)
        );
        fs::remove_file(&link).unwrap();
        fs::set_permissions(&fixture.0,fs::Permissions::from_mode(0o666)).unwrap();
        assert_eq!(
            inspect_pinned_native_worker(&fixture.0,&pin,128),
            Err(NativeBinaryError::UnsafePath)
        );
    }
}
