//! M8.5.15.6d: bounded, signed, OS-sealed GGUF DATA capability.
//! Only offline synthetic fixtures use this module; no inference authorization.
//! Candidate path/FD never reaches native code. Final immutable bytes must pass
//! the existing independently trusted model signature/chunk/whole verifier.

use crate::native_worker_launch::LaunchError;
use jend_model_store::{ManifestId, ModelReleasePublicKey, SignedModelManifest,
    VerifiedGgufInspection, VerifiedGgufOpenLease};

const MAX_SEALED_MODEL: u64 = 4 * 1024 * 1024;

pub struct PreparedModel {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    pub(crate) file: std::fs::File,
    inspection: VerifiedGgufInspection,
}
impl PreparedModel {
    pub fn inspection(&self) -> VerifiedGgufInspection { self.inspection }
}

/// `accepted_manifest` is supplied by trusted enrollment/rollback policy, never
/// accepted automatically from source metadata. This stage does not persist it.
pub fn prepare_sealed_model(
    lease: &mut VerifiedGgufOpenLease,
    key: &ModelReleasePublicKey,
    signed: &SignedModelManifest,
    accepted_manifest: ManifestId,
    allowed_bytes: u64,
) -> Result<PreparedModel, LaunchError> {
    #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        let _ = (lease, key, signed, accepted_manifest, allowed_bytes);
        return Err(LaunchError::UnsupportedPlatform);
    }
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        use std::{fs::{File, OpenOptions}, io::{Seek, SeekFrom},
            os::fd::{AsRawFd, FromRawFd}, os::unix::fs::MetadataExt};
        use jend_model_store::inspect_independently_signed_gguf_reader;
        if allowed_bytes < 24 || allowed_bytes > MAX_SEALED_MODEL
            || signed.manifest_id != accepted_manifest
            || signed.manifest.total_plaintext_len > allowed_bytes
            || key.verify(signed).is_err()
        { return Err(LaunchError::ModelRejected); }
        // MFD_NOEXEC_SEAL: NX inode whose execute bits cannot subsequently be set.
        let raw = unsafe { libc::syscall(libc::SYS_memfd_create, c"jend-gguf-data".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | 0x8u32) };
        if raw < 0 { return Err(LaunchError::SetupRefused); }
        let mut stage = unsafe { File::from_raw_fd(raw as i32) };
        lease.copy_candidate_to(key, signed, allowed_bytes, &mut stage)
            .map_err(|_| LaunchError::ModelRejected)?;
        let seals = libc::F_SEAL_WRITE | libc::F_SEAL_GROW | libc::F_SEAL_SHRINK
            | libc::F_SEAL_SEAL | 0x20; // F_SEAL_EXEC
        if unsafe { libc::fchmod(stage.as_raw_fd(), 0o400) } != 0
            || unsafe { libc::fcntl(stage.as_raw_fd(), libc::F_ADD_SEALS, seals) } != 0
        { return Err(LaunchError::SetupRefused); }
        let actual = unsafe { libc::fcntl(stage.as_raw_fd(), libc::F_GET_SEALS) };
        if actual < 0 || actual & seals != seals { return Err(LaunchError::SetupRefused); }
        // Trusted parent ONLY reopens its own held anonymous inode to downgrade
        // O_RDWR to O_RDONLY. No model-supplied pathname, and no proc access in child.
        let mut readonly = OpenOptions::new().read(true)
            .open(format!("/proc/self/fd/{}", stage.as_raw_fd())).map_err(|_| LaunchError::SetupRefused)?;
        let before = stage.metadata().map_err(|_| LaunchError::Io)?;
        let after = readonly.metadata().map_err(|_| LaunchError::Io)?;
        let actual = unsafe { libc::fcntl(readonly.as_raw_fd(), libc::F_GET_SEALS) };
        if before.dev() != after.dev() || before.ino() != after.ino()
            || after.mode() & 0o111 != 0
            || unsafe { libc::fcntl(readonly.as_raw_fd(), libc::F_GETFL) } & libc::O_ACCMODE != libc::O_RDONLY
            || actual < 0 || actual & seals != seals
        { return Err(LaunchError::SetupRefused); }
        let inspection = inspect_independently_signed_gguf_reader(key, signed, &mut readonly, allowed_bytes)
            .map_err(|_| LaunchError::ModelRejected)?;
        if inspection != lease.inspection() { return Err(LaunchError::ModelRejected); }
        readonly.seek(SeekFrom::Start(0)).map_err(|_| LaunchError::Io)?;
        // Writable staging FD is dropped; only a sealed O_RDONLY capability remains.
        Ok(PreparedModel { file: readonly, inspection })
    }
}
