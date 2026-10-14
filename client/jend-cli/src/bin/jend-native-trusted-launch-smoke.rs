// Offline synthetic release-authority fixture, NEVER a production enrollment.
#[allow(dead_code)]
#[path = "../native_worker_launch.rs"]
mod native_worker_launch;
#[allow(dead_code)]
#[path = "../native_gguf_ipc.rs"]
mod native_gguf_ipc;

use jend_release::{
    AcceptedReleaseHead, ApproverSigningKey, ArtifactKind, BuilderSigningKey,
    ReleaseBundle, ReleasePolicy, ReleaseStatement, ReleaseStatementId,
};
use native_worker_launch::{
    fixture_target, prepare_worker, run_model_free_fixture, FixtureCommand, LaunchError,
};
use sha2::{Digest, Sha256};
use std::{env, fs, path::PathBuf, time::Duration};

fn require(condition: bool, error: &'static str) -> Result<(), Box<dyn std::error::Error>> {
    if !condition { return Err(error.into()); }
    Ok(())
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let args: Vec<_> = env::args_os().skip(1).collect();
    let builders = [BuilderSigningKey::generate()?, BuilderSigningKey::generate()?];
    let approvers = [ApproverSigningKey::generate()?, ApproverSigningKey::generate()?];
    let policy = ReleasePolicy::new(builders.iter().map(|b| b.public_key()), 2,
        approvers.iter().map(|a| a.public_key()), 2)?;
    let sign = |statement: ReleaseStatement| -> Result<ReleaseBundle, jend_release::ReleaseError> {
        Ok(ReleaseBundle {
            builder_attestations: builders.iter().map(|b| b.sign(&statement)).collect::<Result<_, _>>()?,
            approvals: approvers.iter().map(|a| a.sign(&statement)).collect::<Result<_, _>>()?,
            statement,
        })
    };
    let statement = |bytes: &[u8]| ReleaseStatement {
        artifact_kind: ArtifactKind::LocalAiRuntime, sequence: 0,
        version: "M8.5.15.6c-offline-fixture".into(), target: fixture_target().into(),
        artifact_size: bytes.len() as u64, artifact_sha256: Sha256::digest(bytes).into(),
        source_tree_sha256: [0x11; 32], build_recipe_sha256: [0x22; 32],
        previous_statement_id: ReleaseStatementId([0; 32]),
    };
    if !cfg!(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64"))) {
        let release = sign(statement(b"model-free unavailable platform"))?;
        let head = AcceptedReleaseHead::genesis(&release, &policy)?;
        require(matches!(prepare_worker(&PathBuf::from("/unavailable-worker"), &release, &policy, head),
            Err(LaunchError::UnsupportedPlatform)), "unsupported platform tried to prepare a worker")?;
        println!("Jend trusted launch unsupported platform refused before worker access: PASS");
        println!("Jend trusted launch grants no production inference capability: PASS");
        return Ok(());
    }

    #[cfg(all(target_os = "linux", any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        use std::os::fd::AsRawFd;
        require(args.len() == 4, "expected fixture, static protocol, dynamic and canary paths")?;
        let fixture = PathBuf::from(&args[0]);
        let protocol = PathBuf::from(&args[1]);
        let dynamic = PathBuf::from(&args[2]);
        let canary = PathBuf::from(&args[3]);
        let bytes = fs::read(&fixture)?;
        let release = sign(statement(&bytes))?;
        let head = AcceptedReleaseHead::genesis(&release, &policy)?;

        let mut forged = release.clone();
        forged.approvals[0].signature[0] ^= 0x40;
        require(matches!(prepare_worker(&fixture, &forged, &policy, head),
            Err(LaunchError::ReleaseRejected)), "forged approval accepted")?;
        let outsider = BuilderSigningKey::generate()?;
        let alien = ReleasePolicy::new([outsider.public_key()], 1,
            approvers.iter().map(|a| a.public_key()), 2)?;
        require(matches!(prepare_worker(&fixture, &release, &alien, head),
            Err(LaunchError::ReleaseRejected)), "source-chosen signing root accepted")?;
        let advanced = AcceptedReleaseHead { sequence: 1, statement_id: head.statement_id };
        require(matches!(prepare_worker(&fixture, &release, &policy, advanced),
            Err(LaunchError::ReleaseRejected)), "old release accepted after newer head")?;
        for (kind, target) in [(ArtifactKind::Model, fixture_target()),
            (ArtifactKind::LocalAiRuntime, "jend-model-free-static-v1:other-host")] {
            let mut incompatible = statement(&bytes);
            incompatible.artifact_kind = kind;
            incompatible.target = target.into();
            let wrong = sign(incompatible)?;
            let wrong_head = AcceptedReleaseHead::genesis(&wrong, &policy)?;
            require(matches!(prepare_worker(&fixture, &wrong, &policy, wrong_head),
                Err(LaunchError::ReleaseRejected)), "signed incompatible profile accepted")?;
        }
        println!("Jend trusted launch signature root head kind and target gate: PASS");

        let dyn_release = sign(statement(&fs::read(&dynamic)?))?;
        let dyn_head = AcceptedReleaseHead::genesis(&dyn_release, &policy)?;
        require(matches!(prepare_worker(&dynamic, &dyn_release, &policy, dyn_head),
            Err(LaunchError::UnsupportedExecutable)), "dynamic ELF accepted")?;
        let mut too_big = statement(&bytes);
        too_big.artifact_size = 16 * 1024 * 1024 + 1;
        let oversized = sign(too_big)?;
        let large_head = AcceptedReleaseHead::genesis(&oversized, &policy)?;
        require(matches!(prepare_worker(&fixture, &oversized, &policy, large_head),
            Err(LaunchError::ArtifactRejected)), "unbounded executable admission")?;
        let link = fixture.with_extension("link");
        std::os::unix::fs::symlink(&fixture, &link)?;
        require(matches!(prepare_worker(&link, &release, &policy, head),
            Err(LaunchError::ArtifactRejected)), "symlink executable accepted")?;
        fs::remove_file(&link)?;
        println!("Jend trusted launch dynamic ELF symlink and oversize refused: PASS");

        let prepared = prepare_worker(&fixture, &release, &policy, head)?;
        // Prepare synthetic parent state deliberately. It MUST disappear before
        // the hostile C++ constructor. Never use user secrets in this fixture.
        let private_fd = fs::File::open(&canary)?;
        require(unsafe { libc::dup2(private_fd.as_raw_fd(), 127) } == 127,
            "synthetic parent descriptor creation failed")?;
        let address = 0x100000000usize as *mut libc::c_void;
        let mapped = unsafe { libc::mmap(address, 4096, libc::PROT_READ | libc::PROT_WRITE,
            libc::MAP_PRIVATE | libc::MAP_ANONYMOUS | libc::MAP_FIXED_NOREPLACE, -1, 0) };
        require(mapped == address, "synthetic parent mapping creation failed")?;
        unsafe { std::ptr::copy_nonoverlapping(b"SYNTHETIC-PARENT-ONLY".as_ptr(), mapped.cast(), 21); }
        require(env::var_os("JEND_TEST_SECRET_CANARY").is_some(), "synthetic parent env missing")?;

        let output = run_model_free_fixture(&prepared, FixtureCommand::ConstructorProbe, Duration::from_secs(3))?;
        require(output == b"JEND-PREEXEC-CONSTRUCTOR-V1\n", "pre-main confinement proof failed")?;
        require(unsafe { libc::fcntl(127, libc::F_GETFD) } >= 0,
            "child cleanup modified the parent descriptor table")?;
        println!("Jend trusted launch constructor sees no parent environment FDs or mapped canary: PASS");
        println!("Jend trusted launch constructor filesystem network memory process and exec attacks denied: PASS");
        println!("Jend trusted launch constructor CPU RAM FD and core quotas enforced: PASS");

        // Mutate the SAME inode after preparation, then replace its path entirely.
        let mut corrupted = bytes.clone();
        corrupted[0] ^= 0x01;
        fs::write(&fixture, &corrupted)?;
        require(matches!(prepare_worker(&fixture, &release, &policy, head),
            Err(LaunchError::ArtifactRejected)), "mutated executable admitted")?;
        require(run_model_free_fixture(&prepared, FixtureCommand::ConstructorProbe, Duration::from_secs(3))?
            == output, "same-inode mutation affected sealed execution")?;
        fs::remove_file(&fixture)?;
        fs::copy(&dynamic, &fixture)?;
        require(run_model_free_fixture(&prepared, FixtureCommand::ConstructorProbe, Duration::from_secs(3))?
            == output, "path substitution affected sealed execution")?;
        println!("Jend trusted launch sealed execution survives inode mutation and path substitution: PASS");

        require(matches!(run_model_free_fixture(&prepared, FixtureCommand::Stall, Duration::from_millis(100)),
            Err(LaunchError::DeadlineExceeded)), "non-reading worker escaped deadline")?;
        require(matches!(run_model_free_fixture(&prepared, FixtureCommand::Flood, Duration::from_secs(3)),
            Err(LaunchError::OutputLimit)), "stdout flood escaped bound")?;
        require(matches!(run_model_free_fixture(&prepared, FixtureCommand::Cpu, Duration::from_secs(3)),
            Err(LaunchError::CpuQuotaExceeded)), "CPU spinner escaped kernel CPU quota")?;
        require(unsafe { libc::waitpid(-1, std::ptr::null_mut(), libc::WNOHANG) } == -1
            && unsafe { *libc::__errno_location() } == libc::ECHILD,
            "native failure left an unreaped child")?;
        println!("Jend trusted launch stalled flood and CPU workers killed and reaped: PASS");

        let protocol_release = sign(statement(&fs::read(&protocol)?))?;
        let protocol_head = AcceptedReleaseHead::genesis(&protocol_release, &policy)?;
        let protocol_worker = prepare_worker(&protocol, &protocol_release, &policy, protocol_head)?;
        let response = run_model_free_fixture(&protocol_worker, FixtureCommand::ProtocolOnly, Duration::from_secs(3))?;
        require(native_gguf_ipc::parse_native_response(&response)? == native_gguf_ipc::NativeResponse::NoModel,
            "static C++ fixture returned model output")?;
        println!("Jend trusted launch static C++ IPC remains NO_MODEL: PASS");
        unsafe { libc::munmap(mapped, 4096); libc::close(127); }
        println!("Jend trusted launch grants no production inference capability: PASS");
    }
    Ok(())
}
