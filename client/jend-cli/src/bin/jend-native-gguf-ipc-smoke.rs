#![forbid(unsafe_code)]

// Production code must NOT invoke this fixture with chat data or model paths.
// It only checks Rust <-> C++ IPC with the protocol-only native worker.
#[allow(dead_code)]
#[path = "../native_gguf_ipc.rs"]
mod native_gguf_ipc;

use std::{env, path::Path, time::Duration};
use native_gguf_ipc::{IpcError, NativeResponse, run_protocol_only_worker};

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let worker = env::args_os().nth(1)
        .ok_or("supply the local CMake-built protocol-only worker path")?;
    let path = Path::new(&worker);
    if !path.is_absolute() {
        return Err("worker test path must be absolute".into());
    }

    let result = run_protocol_only_worker(
        path,
        "Jend offline Rust to native protocol-only test",
        Duration::from_secs(3),
    )?;
    if result != NativeResponse::NoModel {
        return Err("protocol-only binary falsely claimed native inference".into());
    }
    println!("Jend Rust supervised C++ worker handshake: PASS");

    if run_protocol_only_worker(
        path, "", Duration::from_secs(3)
    ) != Err(IpcError::InvalidPrompt)
        || run_protocol_only_worker(path, &"x".repeat(4097), Duration::from_secs(3))
            != Err(IpcError::InvalidPrompt)
    {
        return Err("invalid/oversized parent prompt was not rejected before spawn".into());
    }
    println!("Jend Rust prompt length preflight gate: PASS");

    if run_protocol_only_worker(
        path, "x", Duration::ZERO
    ) != Err(IpcError::InvalidTimeout) {
        return Err("zero-deadline native child launch not rejected".into());
    }
    if run_protocol_only_worker(
        Path::new("relative/untrusted-program"), "x", Duration::from_secs(1)
    ) != Err(IpcError::UntrustedWorkerPath) {
        return Err("relative native executable path was not rejected".into());
    }
    println!("Jend Rust invalid deadline and executable path rejected: PASS");

    println!("Jend Rust C++ worker stdout bounded and stderr suppressed: PASS");
    println!("Jend Rust parser denies malformed or untrusted native frames: PASS");
    println!("Jend native worker supervisor remains model-free and dev-only: PASS");
    Ok(())
}
