//! M8.5.15.6c: trusted, model-free Linux launch experiment.
//!
//! Not connected to the product, inference, Store or E2EE. Only the offline
//! smoke binary imports this module. Release roots/head must be supplied by
//! the trusted caller; candidate bytes cannot enroll their own signing key.
//! The static executable is copied, sealed, reverified and executed by FD.
//! Filesystem/exec confinement, syscall policy, clean stdio and quotas are
//! established by TRUSTED Rust before any candidate instruction executes.

use jend_release::{AcceptedReleaseHead, ArtifactKind, ReleaseBundle, ReleasePolicy};
use crate::native_model_handoff::PreparedModel;
use std::{path::Path, time::Duration};

const MAX_EXECUTABLE: u64 = 16 * 1024 * 1024;
const MAX_OUTPUT: usize = 32 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum LaunchError {
    UnsupportedPlatform,
    ReleaseRejected,
    ArtifactRejected,
    ModelRejected,
    UnsupportedExecutable,
    PrivilegedParent,
    SetupRefused,
    InvalidTimeout,
    DeadlineExceeded,
    OutputLimit,
    CpuQuotaExceeded,
    WorkerFailed,
    Io,
}
impl std::fmt::Display for LaunchError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Never include a path, environment, signature, private bytes or errno.
        f.write_str(match self {
            Self::UnsupportedPlatform => "native launch platform unsupported",
            Self::ReleaseRejected => "native release authority rejected",
            Self::ArtifactRejected => "native executable bytes rejected",
            Self::ModelRejected => "native model data authority rejected",
            Self::UnsupportedExecutable => "native executable profile unsupported",
            Self::PrivilegedParent => "native launcher requires an unprivileged parent",
            Self::SetupRefused => "native launch confinement unavailable",
            Self::InvalidTimeout => "native launch deadline rejected",
            Self::DeadlineExceeded => "native launch deadline exceeded",
            Self::OutputLimit => "native launch output limit exceeded",
            Self::CpuQuotaExceeded => "native fixture terminated at CPU quota",
            Self::WorkerFailed => "native fixture failed",
            Self::Io => "native launch IO failed",
        })
    }
}
impl std::error::Error for LaunchError {}

pub fn fixture_target() -> &'static str {
    if cfg!(all(target_os = "linux", target_arch = "x86_64")) {
        "jend-model-free-static-v1:x86_64-linux"
    } else if cfg!(all(target_os = "linux", target_arch = "aarch64")) {
        "jend-model-free-static-v1:aarch64-linux"
    } else {
        "jend-model-free-static-v1:unsupported"
    }
}

/// Opaque, immutable executable capability; no pathname or raw FD is exposed.
pub struct PreparedWorker {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    executable: std::fs::File,
}

/// Fixed model-free commands only. No arbitrary argv, prompt, model or FD grant.
#[derive(Clone, Copy)]
pub enum FixtureCommand {
    ProtocolOnly,
    ConstructorProbe,
    Stall,
    Flood,
    Cpu,
}

/// Accept ONLY the exact already-accepted signed head, kind and host profile.
/// The caller owns enrollment/rollback persistence; this API never enrolls or
/// advances a release head using source-provided keys/metadata.
pub fn prepare_worker(
    path: &Path,
    bundle: &ReleaseBundle,
    policy: &ReleasePolicy,
    accepted: AcceptedReleaseHead,
) -> Result<PreparedWorker, LaunchError> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        linux::prepare(path, bundle, policy, accepted)
    }
    #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        let _ = (path, bundle, policy, accepted);
        Err(LaunchError::UnsupportedPlatform)
    }
}

pub fn run_model_free_fixture(
    worker: &PreparedWorker,
    command: FixtureCommand,
    timeout: Duration,
) -> Result<Vec<u8>, LaunchError> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        linux::run(worker, command, None, timeout)
    }
    #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    {
        let _ = (worker, command, timeout);
        Err(LaunchError::UnsupportedPlatform)
    }
}

/// Offline synthetic DATA handoff only; fixed command and one prepared FD.
/// Never accepts an arbitrary FD, model path, user prompt or inference flag.
pub fn run_sealed_model_fixture(
    worker: &PreparedWorker, model: &PreparedModel, timeout: Duration,
) -> Result<Vec<u8>, LaunchError> {
    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    { linux::run(worker, FixtureCommand::ConstructorProbe, Some(model), timeout) }
    #[cfg(not(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))))]
    { let _ = (worker, model, timeout); Err(LaunchError::UnsupportedPlatform) }
}

#[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
mod linux {
    use super::*;
    use std::{
        fs::{File, OpenOptions},
        io::{Read, Seek, SeekFrom, Write},
        os::{fd::{AsRawFd, FromRawFd, RawFd}, unix::fs::OpenOptionsExt},
        path::Component,
        time::Instant,
    };

    const EXEC_FD: RawFd = 3;
    const RAM_BYTES: u64 = 128 * 1024 * 1024;
    // Linux >= 6.3: request executable memfd explicitly and seal its mode.
    const MFD_EXEC: u32 = 0x10;
    const F_SEAL_EXEC: i32 = 0x20;
    const SEALS: i32 = libc::F_SEAL_WRITE | libc::F_SEAL_GROW
        | libc::F_SEAL_SHRINK | libc::F_SEAL_SEAL | F_SEAL_EXEC;
    const ALLOW: u32 = 0x7fff0000;
    const DENY: u32 = 0x00050000 | libc::EPERM as u32;
    const KILL: u32 = 0x80000000;
    const BPF_LD_W_ABS: u16 = 0x20;
    const BPF_JEQ: u16 = 0x15;
    const BPF_RET: u16 = 0x06;

    pub(super) fn prepare(
        path: &Path, bundle: &ReleaseBundle, policy: &ReleasePolicy,
        accepted: AcceptedReleaseHead,
    ) -> Result<PreparedWorker, LaunchError> {
        if bundle.builder_attestations.len() > 16 || bundle.approvals.len() > 16
            || bundle.statement.artifact_kind != ArtifactKind::LocalAiRuntime
            || bundle.statement.target != fixture_target()
            || bundle.statement.sequence != accepted.sequence
            || bundle.statement.statement_id().map_err(|_| LaunchError::ReleaseRejected)?
                != accepted.statement_id
            || policy.verify_bundle(bundle).is_err()
        { return Err(LaunchError::ReleaseRejected); }
        let size = bundle.statement.artifact_size;
        if size == 0 || size > MAX_EXECUTABLE || !path.is_absolute()
            || path.components().any(|p| matches!(p, Component::ParentDir | Component::CurDir))
        { return Err(LaunchError::ArtifactRejected); }
        // O_NONBLOCK prevents opening an attacker-substituted FIFO from hanging.
        // Ancestor changes do not grant authority: only the sealed signed bytes do.
        let source = OpenOptions::new().read(true)
            .custom_flags(libc::O_NOFOLLOW | libc::O_CLOEXEC | libc::O_NONBLOCK)
            .open(path).map_err(|_| LaunchError::ArtifactRejected)?;
        let meta = source.metadata().map_err(|_| LaunchError::Io)?;
        if !meta.is_file() || meta.len() != size { return Err(LaunchError::ArtifactRejected); }
        let mut bytes = Vec::new();
        source.take(size + 1).read_to_end(&mut bytes).map_err(|_| LaunchError::Io)?;
        bundle.statement.verify_artifact(&bytes).map_err(|_| LaunchError::ArtifactRejected)?;
        static_elf(&bytes)?;
        let mut executable = sealed_copy(&bytes)?;
        executable.seek(SeekFrom::Start(0)).map_err(|_| LaunchError::Io)?;
        bytes.clear();
        (&mut executable).take(size + 1).read_to_end(&mut bytes).map_err(|_| LaunchError::Io)?;
        // Verify the final immutable backing, rather than a prior pathname hash.
        bundle.statement.verify_artifact(&bytes).map_err(|_| LaunchError::ArtifactRejected)?;
        static_elf(&bytes)?;
        Ok(PreparedWorker { executable })
    }

    fn sealed_copy(bytes: &[u8]) -> Result<File, LaunchError> {
        // SAFETY: constant C string, documented syscall. File takes ownership once.
        let raw = unsafe { libc::syscall(libc::SYS_memfd_create, c"jend-worker".as_ptr(),
            libc::MFD_CLOEXEC | libc::MFD_ALLOW_SEALING | MFD_EXEC) };
        if raw < 0 { return Err(LaunchError::SetupRefused); }
        let mut executable = unsafe { File::from_raw_fd(raw as RawFd) };
        executable.write_all(bytes).map_err(|_| LaunchError::Io)?;
        let fd = executable.as_raw_fd();
        // No writable shared mapping exists. Both bytes AND execute bits are sealed.
        if unsafe { libc::fchmod(fd, 0o500) } != 0
            || unsafe { libc::fcntl(fd, libc::F_ADD_SEALS, SEALS) } != 0
        { return Err(LaunchError::SetupRefused); }
        let actual = unsafe { libc::fcntl(fd, libc::F_GET_SEALS) };
        if actual < 0 || actual & SEALS != SEALS { return Err(LaunchError::SetupRefused); }
        Ok(executable)
    }

    fn static_elf(b: &[u8]) -> Result<(), LaunchError> {
        let bad = LaunchError::UnsupportedExecutable;
        if b.len() < 64 || &b[..7] != b"\x7fELF\x02\x01\x01" { return Err(bad); }
        let u16at = |i| u16::from_le_bytes([b[i], b[i + 1]]);
        let u64at = |i| u64::from_le_bytes(b[i..i + 8].try_into().unwrap());
        let machine = if cfg!(target_arch = "x86_64") { 62 } else { 183 };
        if u16at(16) != 2 || u16at(18) != machine || u16at(52) != 64
            || u16at(54) != 56 || u16at(56) == 0 || u16at(56) > 256
        { return Err(bad); }
        let offset = usize::try_from(u64at(32)).map_err(|_| bad)?;
        let end = offset.checked_add(u16at(56) as usize * 56).ok_or(bad)?;
        if offset < 64 || end > b.len() { return Err(bad); }
        let entry = u64at(24);
        let mut executable_entry = false;
        for p in b[offset..end].chunks_exact(56) {
            let kind = u32::from_le_bytes(p[..4].try_into().unwrap());
            let flags = u32::from_le_bytes(p[4..8].try_into().unwrap());
            // PT_INTERP / PT_DYNAMIC are forbidden: no loader path or libraries.
            if kind == 2 || kind == 3 { return Err(bad); }
            if kind == 1 {
                let get = |i| u64::from_le_bytes(p[i..i + 8].try_into().unwrap());
                let (off, addr, file, mem) = (get(8), get(16), get(32), get(40));
                if file > mem || mem > RAM_BYTES || flags & 3 == 3
                    || off.checked_add(file).filter(|n| *n <= b.len() as u64).is_none()
                    || addr.checked_add(mem).is_none()
                { return Err(bad); }
                executable_entry |= flags & 1 != 0 && entry >= addr && entry < addr + mem;
            }
        }
        if !executable_entry { return Err(bad); }
        Ok(())
    }

    fn insn(code: u16, jt: u8, jf: u8, k: u32) -> libc::sock_filter {
        libc::sock_filter { code, jt, jf, k }
    }
    fn eq(p: &mut Vec<libc::sock_filter>, value: u32, yes: u8, no: u8) {
        p.push(insn(BPF_JEQ, yes, no, value));
    }
    // Add an argument-checked syscall block. The false syscall branch skips it;
    // every failed comparison returns DENY, so high-half truncation is impossible.
    fn checked(p: &mut Vec<libc::sock_filter>, nr: libc::c_long, args: &[(u32, u64)]) {
        let mut block = Vec::new();
        for &(arg, value) in args {
            for half in 0..2 {
                block.push(insn(BPF_LD_W_ABS, 0, 0, 16 + arg * 8 + half * 4));
                eq(&mut block, (value >> (half * 32)) as u32, 1, 0);
                block.push(insn(BPF_RET, 0, 0, DENY));
            }
        }
        block.push(insn(BPF_RET, 0, 0, ALLOW));
        eq(p, nr as u32, 0, block.len() as u8);
        p.extend(block);
    }
    fn getters(p: &mut Vec<libc::sock_filter>, nr: libc::c_long, arg: u32, values: &[u32]) {
        let mut block = vec![
            insn(BPF_LD_W_ABS, 0, 0, 20 + arg * 8),
            insn(BPF_JEQ, 1, 0, 0), insn(BPF_RET, 0, 0, DENY),
            insn(BPF_LD_W_ABS, 0, 0, 16 + arg * 8),
        ];
        for (i, &value) in values.iter().enumerate() {
            block.push(insn(BPF_JEQ, (values.len() - i) as u8, 0, value));
        }
        block.push(insn(BPF_RET, 0, 0, DENY));
        block.push(insn(BPF_RET, 0, 0, ALLOW));
        eq(p, nr as u32, 0, block.len() as u8);
        p.extend(block);
    }
    fn no_exec_mapping(p: &mut Vec<libc::sock_filter>, nr: libc::c_long) {
        let block = [
            insn(BPF_LD_W_ABS, 0, 0, 36), // protection argument 2 high half
            insn(BPF_JEQ, 1, 0, 0), insn(BPF_RET, 0, 0, DENY),
            insn(BPF_LD_W_ABS, 0, 0, 32),
            insn(0x45, 0, 1, libc::PROT_EXEC as u32), // BPF_JSET
            insn(BPF_RET, 0, 0, DENY), insn(BPF_RET, 0, 0, ALLOW),
        ];
        eq(p, nr as u32, 0, block.len() as u8);
        p.extend(block);
    }
    fn filter(with_model: bool) -> Vec<libc::sock_filter> {
        let arch = if cfg!(target_arch = "x86_64") { 0xc000003e } else { 0xc00000b7 };
        let mut p = vec![insn(BPF_LD_W_ABS, 0, 0, 4)];
        eq(&mut p, arch, 1, 0);
        p.push(insn(BPF_RET, 0, 0, KILL));
        p.push(insn(BPF_LD_W_ABS, 0, 0, 0));
        // x32 has different numbers (bit 30); the exact allowlist denies it.
        // Only initial sealed FD exec is permitted. Landlock MUST also forbid
        // absolute pathname exec: execveat ignores dirfd for an absolute path!
        checked(&mut p, libc::SYS_execveat, &[(0, EXEC_FD as u64), (4, libc::AT_EMPTY_PATH as u64)]);
        checked(&mut p, libc::SYS_prlimit64, &[(0, 0), (2, 0)]); // self, read-only
        getters(&mut p, libc::SYS_prctl, 0,
            &[libc::PR_GET_SECCOMP as u32, libc::PR_GET_NO_NEW_PRIVS as u32]);
        // Read-only queries; no descriptor creation or flags/ownership updates.
        getters(&mut p, libc::SYS_fcntl, 1,
            &[libc::F_GETFD as u32, libc::F_GETFL as u32, libc::F_GET_SEALS as u32]);
        no_exec_mapping(&mut p, libc::SYS_mmap);
        no_exec_mapping(&mut p, libc::SYS_mprotect);
        if with_model { checked(&mut p, libc::SYS_pread64, &[(0, 4)]); }
        for nr in [libc::SYS_read, libc::SYS_write, libc::SYS_writev, libc::SYS_close,
            libc::SYS_fstat, libc::SYS_lseek, libc::SYS_brk,
            libc::SYS_munmap, libc::SYS_madvise, libc::SYS_mincore,
            libc::SYS_rt_sigaction, libc::SYS_rt_sigprocmask, libc::SYS_rt_sigreturn,
            libc::SYS_sigaltstack, libc::SYS_futex, libc::SYS_set_tid_address,
            libc::SYS_set_robust_list, libc::SYS_rseq, libc::SYS_getrandom,
            libc::SYS_getpid, libc::SYS_getppid, libc::SYS_gettid,
            libc::SYS_clock_gettime, libc::SYS_clock_nanosleep, libc::SYS_nanosleep,
            libc::SYS_sched_yield, libc::SYS_exit, libc::SYS_exit_group,
        ] {
            eq(&mut p, nr as u32, 0, 1);
            p.push(insn(BPF_RET, 0, 0, ALLOW));
        }
        #[cfg(target_arch = "x86_64")]
        for nr in [libc::SYS_arch_prctl, libc::SYS_getrlimit] {
            eq(&mut p, nr as u32, 0, 1);
            p.push(insn(BPF_RET, 0, 0, ALLOW));
        }
        p.push(insn(BPF_RET, 0, 0, DENY));
        p
    }

    #[repr(C)]
    struct LandlockRuleset { handled_access_fs: u64 }
    #[repr(C)]
    struct CapHeader { version: u32, pid: i32 }
    #[repr(C)]
    #[derive(Clone, Copy)]
    struct CapData { effective: u32, permitted: u32, inheritable: u32 }

    fn unprivileged() -> bool {
        let mut header = CapHeader { version: 0x20080522, pid: 0 };
        let mut data = [CapData { effective: 0, permitted: 0, inheritable: 0 }; 2];
        // Do not run as root, set-ID or capability-bearing service.
        unsafe {
            libc::getuid() != 0 && libc::getuid() == libc::geteuid()
                && libc::getgid() == libc::getegid()
                && libc::syscall(libc::SYS_capget, &mut header as *mut CapHeader, data.as_mut_ptr()) == 0
                && data.iter().all(|d| d.effective == 0 && d.permitted == 0 && d.inheritable == 0)
        }
    }

    /// Child path has no allocator, locks, unwinding, Rust IO or dynamic errors.
    /// All objects and BPF instructions were prepared before fork; only raw
    /// Linux syscalls and stack values run before exec replaces parent memory.
    unsafe fn child_setup(
        parent: libc::pid_t, worker: RawFd, input: RawFd, output: RawFd,
        null: RawFd, model: RawFd, program: &libc::sock_fprog, argv: &[*const libc::c_char; 3],
    ) -> ! {
        macro_rules! need { ($condition:expr) => { if !$condition { libc::_exit(125); } }; }
        need!(libc::setsid() >= 0);
        need!(libc::prctl(libc::PR_SET_PDEATHSIG, libc::SIGKILL, 0, 0, 0) == 0);
        need!(libc::getppid() == parent); // close parent-death setup race
        need!(libc::dup2(input, 0) == 0);
        need!(libc::dup2(output, 1) == 1);
        need!(libc::dup2(null, 2) == 2);
        if worker != EXEC_FD {
            need!(libc::dup3(worker, EXEC_FD, libc::O_CLOEXEC) == EXEC_FD);
        } else {
            need!(libc::fcntl(EXEC_FD, libc::F_SETFD, libc::FD_CLOEXEC) == 0);
        }
        if model >= 0 { need!(libc::dup3(model, 4, 0) == 4); }
        // No cwd pointing into the vault; filesystem syscalls will be denied.
        need!(libc::chdir(c"/".as_ptr()) == 0);
        for (resource, value) in [(libc::RLIMIT_AS, RAM_BYTES), (libc::RLIMIT_CPU, 1),
            (libc::RLIMIT_CORE, 0), (libc::RLIMIT_FSIZE, 0),
            (libc::RLIMIT_STACK, 8 * 1024 * 1024), (libc::RLIMIT_MEMLOCK, 0),
            (libc::RLIMIT_NPROC, 0)] {
            let limit = libc::rlimit { rlim_cur: value, rlim_max: value };
            need!(libc::setrlimit(resource, &limit) == 0);
        }
        need!(libc::prctl(libc::PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0);
        need!(libc::prctl(libc::PR_SET_DUMPABLE, 0, 0, 0, 0) == 0);
        // Empty filesystem allowlist, including EXECUTE, REFER and TRUNCATE.
        // Anonymous memfd is outside the path hierarchy; this is the sole exec.
        need!(libc::syscall(libc::SYS_landlock_create_ruleset, 0, 0, 1) >= 3);
        let rules = LandlockRuleset { handled_access_fs: (1 << 15) - 1 };
        let rules_fd = libc::syscall(libc::SYS_landlock_create_ruleset,
            &rules as *const LandlockRuleset, std::mem::size_of::<LandlockRuleset>(), 0);
        need!(rules_fd >= 0);
        need!(libc::syscall(libc::SYS_landlock_restrict_self, rules_fd, 0) == 0);
        need!(libc::close(rules_fd as RawFd) == 0);
        // Unshare and close ALL other FDs, including non-CLOEXEC vault handles.
        let first_closed = if model >= 0 { 5u32 } else { 4u32 };
        need!(libc::syscall(libc::SYS_close_range, first_closed, u32::MAX, 2u32) == 0);
        let fd_limit = libc::rlimit { rlim_cur: first_closed as u64, rlim_max: first_closed as u64 };
        need!(libc::setrlimit(libc::RLIMIT_NOFILE, &fd_limit) == 0);
        need!(libc::prctl(libc::PR_SET_SECCOMP, 2, program as *const libc::sock_fprog, 0, 0) == 0);
        let envp: [*const libc::c_char; 1] = [std::ptr::null()];
        // Kernel drops all former mappings. FD 3 closes during successful exec.
        libc::syscall(libc::SYS_execveat, EXEC_FD, c"".as_ptr(), argv.as_ptr(),
            envp.as_ptr(), libc::AT_EMPTY_PATH);
        libc::_exit(125); // no path-based exec or unsandboxed fallback
    }

    struct ChildGuard { pid: libc::pid_t, reaped: bool }
    impl Drop for ChildGuard {
        fn drop(&mut self) {
            if !self.reaped {
                unsafe {
                    libc::kill(-self.pid, libc::SIGKILL);
                    libc::kill(self.pid, libc::SIGKILL);
                    loop {
                        if libc::waitpid(self.pid, std::ptr::null_mut(), 0) >= 0 { break; }
                        if *libc::__errno_location() != libc::EINTR { break; }
                    }
                }
            }
        }
    }
    fn pipe() -> Result<(File, File), LaunchError> {
        let mut fds = [-1; 2];
        if unsafe { libc::pipe2(fds.as_mut_ptr(), libc::O_CLOEXEC) } != 0 {
            return Err(LaunchError::Io);
        }
        Ok(unsafe { (File::from_raw_fd(fds[0]), File::from_raw_fd(fds[1])) })
    }
    fn duplicate_for_remap(file: &File) -> Result<File, LaunchError> {
        // Reserve sources above target 0/1/2/3/4 before fork, so installing
        // exec FD 3 cannot destroy a model source originally at FD 3 or 4.
        let fd = unsafe { libc::fcntl(file.as_raw_fd(), libc::F_DUPFD_CLOEXEC, 10) };
        if fd < 10 { return Err(LaunchError::Io); }
        Ok(unsafe { File::from_raw_fd(fd) })
    }

    pub(super) fn run(
        worker: &PreparedWorker, command: FixtureCommand, model: Option<&PreparedModel>, timeout: Duration,
    ) -> Result<Vec<u8>, LaunchError> {
        if timeout < Duration::from_millis(50) || timeout > Duration::from_secs(5) {
            return Err(LaunchError::InvalidTimeout);
        }
        if !unprivileged() { return Err(LaunchError::PrivilegedParent); }
        let option = if model.is_some() { c"--model-handle-probe" } else { match command {
            FixtureCommand::ProtocolOnly => c"--protocol-smoke",
            FixtureCommand::ConstructorProbe => c"--constructor-probe",
            FixtureCommand::Stall => c"--stall",
            FixtureCommand::Flood => c"--flood",
            FixtureCommand::Cpu => c"--cpu",
        }};
        let executable_source = duplicate_for_remap(&worker.executable)?;
        let model_source = model.map(|m| duplicate_for_remap(&m.file)).transpose()?;
        let model_fd = model_source.as_ref().map_or(-1, |m| m.as_raw_fd());
        let argv = [c"jend-model-free-worker".as_ptr(), option.as_ptr(), std::ptr::null()];
        let (input, mut writer) = pipe()?;
        // Constant harmless fixture only; bounded write completes before fork.
        let fixture = b"no private user content";
        writer.write_all(&(fixture.len() as u32).to_be_bytes()).map_err(|_| LaunchError::Io)?;
        writer.write_all(fixture).map_err(|_| LaunchError::Io)?;
        drop(writer);
        let (mut reader, output) = pipe()?;
        let null = OpenOptions::new().write(true).open("/dev/null").map_err(|_| LaunchError::Io)?;
        // Closed parent stdio is refused: avoids remapping source FD aliasing.
        if [input.as_raw_fd(), output.as_raw_fd(), null.as_raw_fd(), worker.executable.as_raw_fd()]
            .iter().any(|fd| *fd < 3) { return Err(LaunchError::SetupRefused); }
        if unsafe { libc::fcntl(reader.as_raw_fd(), libc::F_SETFL, libc::O_NONBLOCK) } != 0 {
            return Err(LaunchError::Io);
        }
        let instructions = filter(model.is_some());
        let program = libc::sock_fprog { len: instructions.len() as u16,
            filter: instructions.as_ptr() as *mut libc::sock_filter };
        let parent = unsafe { libc::getpid() };
        let start = Instant::now();
        // SAFETY: child uses only the audited syscall path above, never Rust IO.
        let pid = unsafe { libc::fork() };
        if pid < 0 { return Err(LaunchError::Io); }
        if pid == 0 { unsafe { child_setup(parent, executable_source.as_raw_fd(),
            input.as_raw_fd(), output.as_raw_fd(), null.as_raw_fd(), model_fd, &program, &argv) }; }
        let mut child = ChildGuard { pid, reaped: false };
        drop(input); drop(output); drop(null); drop(executable_source); drop(model_source);
        let mut bytes = Vec::new();
        let mut status = 0;
        let mut eof = false;
        loop {
            // Drain a bounded amount per turn so continuous flood cannot starve
            // the deadline or exit check. No blocking writer/reader thread exists.
            let mut buffer = [0u8; 4096];
            match reader.read(&mut buffer) {
                Ok(0) => eof = true,
                Ok(n) => {
                    if bytes.len() + n > MAX_OUTPUT { return Err(LaunchError::OutputLimit); }
                    bytes.extend_from_slice(&buffer[..n]);
                }
                Err(e) if matches!(e.kind(), std::io::ErrorKind::WouldBlock | std::io::ErrorKind::Interrupted) => {}
                Err(_) => return Err(LaunchError::Io),
            }
            if !child.reaped {
                let waited = unsafe { libc::waitpid(pid, &mut status, libc::WNOHANG) };
                if waited == pid { child.reaped = true; }
                else if waited < 0 && unsafe { *libc::__errno_location() } != libc::EINTR {
                    // If an external SIGCHLD reaper consumed the child, its PID
                    // can be reused. Never signal that numeric PID on this path.
                    if unsafe { *libc::__errno_location() } == libc::ECHILD { child.reaped = true; }
                    return Err(LaunchError::Io);
                }
            }
            if child.reaped && eof {
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 0 { return Ok(bytes); }
                if libc::WIFEXITED(status) && libc::WEXITSTATUS(status) == 125 { return Err(LaunchError::SetupRefused); }
                if matches!(command, FixtureCommand::Cpu) && libc::WIFSIGNALED(status)
                    && libc::WTERMSIG(status) == libc::SIGKILL {
                    return Err(LaunchError::CpuQuotaExceeded);
                }
                return Err(LaunchError::WorkerFailed);
            }
            if start.elapsed() >= timeout { return Err(LaunchError::DeadlineExceeded); }
            std::thread::sleep(Duration::from_millis(2));
        }
    }

    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn malformed_elf_is_rejected_without_execution() {
            for bytes in [b"#!/bin/sh".as_slice(), &[0u8; 64], b"\x7fELF\x02\x01\x01"] {
                assert_eq!(static_elf(bytes), Err(LaunchError::UnsupportedExecutable));
            }
        }
        #[test]
        fn sealed_backing_rejects_write_resize_mapping_and_execute_mode_change() {
            let mut file = sealed_copy(b"synthetic bytes never executed").unwrap();
            let fd = file.as_raw_fd();
            assert_eq!(file.write(b"tamper").unwrap_err().raw_os_error(), Some(libc::EPERM));
            unsafe {
                assert_eq!(libc::ftruncate(fd, 0), -1);
                assert_eq!(*libc::__errno_location(), libc::EPERM);
                assert_eq!(libc::ftruncate(fd, 4096), -1);
                assert_eq!(*libc::__errno_location(), libc::EPERM);
                assert_eq!(libc::mmap(std::ptr::null_mut(), 4096, libc::PROT_READ | libc::PROT_WRITE,
                    libc::MAP_SHARED, fd, 0), libc::MAP_FAILED);
                assert_eq!(*libc::__errno_location(), libc::EPERM);
                assert_eq!(libc::fchmod(fd, 0o400), -1);
                assert_eq!(*libc::__errno_location(), libc::EPERM);
            }
        }
    }
}
