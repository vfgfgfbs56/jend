#![forbid(unsafe_code)]
// Model-free developer fixture. The locally-built binary's digest is computed
// here ONLY to exercise the inspection API; a real product MUST independently
// enroll a signed binary identity and use OS-attested execution + sandbox.
#[allow(dead_code)]
#[path="../native_worker_integrity.rs"]
mod native_worker_integrity;
#[allow(dead_code)]
#[path="../native_gguf_ipc.rs"]
mod native_gguf_ipc;

use native_worker_integrity::{
    inspect_pinned_native_worker, NativeBinaryError,
};
use native_gguf_ipc::{run_protocol_only_worker, NativeResponse};
use sha2::{Digest, Sha256};
use std::{
    env, fs,
    path::Path,
    time::{SystemTime, UNIX_EPOCH, Duration},
};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let exe=env::args_os().nth(1).ok_or("expected local C++ protocol worker path")?;
    let exe=Path::new(&exe);
    // This test computes its expected digest locally. It proves ONLY the
    // mismatch-denial API, not independent production trust provisioning.
    let expected: [u8;32] = Sha256::digest(fs::read(exe)?).into();
    let proof=inspect_pinned_native_worker(exe,&expected,128*1024*1024)?;
    if proof.sha256 != expected || proof.byte_length == 0 {
        return Err("locally compiled worker binary digest mismatch".into());
    }
    println!("Jend native worker exact SHA256 binary inspection: PASS");

    let wrong=[0x55;32];
    if inspect_pinned_native_worker(exe,&wrong,128*1024*1024)
        != Err(NativeBinaryError::UntrustedBinary)
    { return Err("wrong expected binary SHA256 not rejected".into()); }
    println!("Jend native worker wrong independent digest denied: PASS");

    let nanos=SystemTime::now().duration_since(UNIX_EPOCH)?.as_nanos();
    let temp=std::env::temp_dir().join(format!("jend-worker-integrity-{}-{nanos}",std::process::id()));
    fs::copy(exe,&temp)?;
    let mut corrupted=fs::read(&temp)?;
    let last=corrupted.len()-1;
    corrupted[last] ^= 1;
    fs::write(&temp,&corrupted)?;
    if inspect_pinned_native_worker(&temp,&expected,128*1024*1024)
        != Err(NativeBinaryError::UntrustedBinary)
    { return Err("modified binary unexpectedly passed trusted pin".into()); }
    fs::remove_file(&temp)?;
    println!("Jend native worker changed binary bytes rejected: PASS");

    if inspect_pinned_native_worker(exe,&expected,1)
        != Err(NativeBinaryError::UnsafePath)
        || inspect_pinned_native_worker(Path::new("relative/worker"),&expected,128*1024*1024)
            != Err(NativeBinaryError::UnsafePath)
    { return Err("worker size and path checks failed".into()); }
    println!("Jend native worker bounded file and path preflight: PASS");

    if run_protocol_only_worker(exe, "no private user content", Duration::from_secs(3))?
        != NativeResponse::NoModel
    { return Err("expected nonexecuting protocol-only worker".into()); }
    println!("Jend native binary preflight plus model-free IPC smoke: PASS");

    println!("Jend native preflight provides no OS sandbox or production execution: PASS");
    Ok(())
}
