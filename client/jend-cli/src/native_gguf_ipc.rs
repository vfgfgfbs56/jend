//! M8.5.15.1: strict, model-free, one-shot native GGUF IPC supervisor.
//! This is a DEVELOPMENT-ONLY protocol test, NOT an OS sandbox, verified
//! worker binary, production inference path, or Jend message integration.
//! NEVER pass E2EE chat plaintext to unverified native code.

use std::{
    fs,
    io::{Read, Write},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

const MAGIC: &[u8; 9] = b"JENDGGUF1";
const MAX_PROMPT: usize = 4096;
const MAX_TOKENS: usize = 16;
const MAX_TOKEN_PIECE: usize = 1024;
const MAX_STDOUT: usize = 32 * 1024;
const MIN_TIMEOUT: Duration = Duration::from_millis(50);
const MAX_TIMEOUT: Duration = Duration::from_secs(5);

#[derive(Debug, Clone, Copy, Eq, PartialEq)]
pub enum IpcError {
    InvalidPrompt,
    UntrustedWorkerPath,
    InvalidTimeout,
    UnsupportedMobileProcessMode,
    SpawnOrPipe,
    DeadlineExceeded,
    WorkerFailed,
    TruncatedOrOverflowingOutput,
    InvalidWorkerProtocol,
}

impl std::fmt::Display for IpcError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // No path, secret, token, prompt or model content in errors.
        f.write_str(match self {
            Self::InvalidPrompt => "native worker prompt rejected",
            Self::UntrustedWorkerPath => "native worker executable path rejected",
            Self::InvalidTimeout => "native worker deadline invalid",
            Self::UnsupportedMobileProcessMode => "mobile native worker subprocess disabled",
            Self::SpawnOrPipe => "native worker spawn or IPC failed",
            Self::DeadlineExceeded => "native worker exceeded deadline",
            Self::WorkerFailed => "native worker returned failure",
            Self::TruncatedOrOverflowingOutput => "native worker output size invalid",
            Self::InvalidWorkerProtocol => "native worker protocol rejected",
        })
    }
}

impl std::error::Error for IpcError {}

#[derive(Debug, Clone, Eq, PartialEq)]
pub enum NativeResponse {
    /// A development engine's bounded byte pieces (not guaranteed UTF-8
    /// individually; assembled output may be validated by the caller).
    Tokens(Vec<Vec<u8>>),
    /// The protocol-only C++ worker cannot load model weights.
    NoModel,
}

/// Pure fail-closed wire parser: exact version, complete frames and one
/// terminal D or N. No trailing frames, mixed N+T, unknown frame kinds,
/// excess pieces or oversized payloads. It neither opens a model nor runs C++.
pub fn parse_native_response(bytes: &[u8]) -> Result<NativeResponse, IpcError> {
    if bytes.len() > MAX_STDOUT {
        return Err(IpcError::TruncatedOrOverflowingOutput);
    }
    if !bytes.starts_with(MAGIC) {
        return Err(IpcError::InvalidWorkerProtocol);
    }
    let mut cursor = MAGIC.len();
    let mut pieces = Vec::new();

    loop {
        let header_end = cursor.checked_add(5)
            .ok_or(IpcError::InvalidWorkerProtocol)?;
        if header_end > bytes.len() {
            return Err(IpcError::InvalidWorkerProtocol);
        }
        let kind = bytes[cursor];
        let size = u32::from_be_bytes(
            bytes[cursor + 1..header_end].try_into()
                .map_err(|_| IpcError::InvalidWorkerProtocol)?
        ) as usize;
        cursor = header_end;
        let end = cursor.checked_add(size)
            .ok_or(IpcError::InvalidWorkerProtocol)?;
        if end > bytes.len() {
            return Err(IpcError::InvalidWorkerProtocol);
        }
        let data = &bytes[cursor..end];
        cursor = end;
        match kind {
            b'T' => {
                if size == 0 || size > MAX_TOKEN_PIECE || pieces.len() >= MAX_TOKENS {
                    return Err(IpcError::InvalidWorkerProtocol);
                }
                pieces.push(data.to_vec());
            }
            b'D' if size == 0 && cursor == bytes.len() => {
                return Ok(NativeResponse::Tokens(pieces));
            }
            b'N' if data == b"NO_MODEL" && pieces.is_empty()
                && cursor == bytes.len() =>
            {
                return Ok(NativeResponse::NoModel);
            }
            _ => return Err(IpcError::InvalidWorkerProtocol),
        }
    }
}

/// RAII ensures children are killed/reaped on every error path. No background
/// orphan process is kept and no native worker is launched after this scope.
struct ReapOnExit(Child);
impl Drop for ReapOnExit {
    fn drop(&mut self) {
        if self.0.try_wait().ok().flatten().is_none() {
            let _ = self.0.kill();
            let _ = self.0.wait();
        }
    }
}

/// Model-FREE dev fixture supervisor. It deliberately runs only
/// '--protocol-smoke'; no --infer-dev, no dynamic model/executable argument
/// from Store metadata. Path is supplied by the local offline smoke script,
/// NOT authenticated or safe for product use. Production must attest and
/// sandbox the worker binary before ever processing chat data.
pub fn run_protocol_only_worker(
    executable: &Path,
    prompt: &str,
    timeout: Duration,
) -> Result<NativeResponse, IpcError> {
    // iOS and Android cannot inherit the desktop worker process trust model.
    // A signed in-app/mobile service adapter must be designed separately.
    // cfg! is compile-time determined; a caller cannot override the denial.
    if cfg!(any(target_os = "ios", target_os = "android")) {
        return Err(IpcError::UnsupportedMobileProcessMode);
    }
    if prompt.is_empty() || prompt.len() > MAX_PROMPT {
        return Err(IpcError::InvalidPrompt);
    }
    if timeout < MIN_TIMEOUT || timeout > MAX_TIMEOUT {
        return Err(IpcError::InvalidTimeout);
    }
    if !executable.is_absolute() {
        return Err(IpcError::UntrustedWorkerPath);
    }
    let metadata = fs::symlink_metadata(executable)
        .map_err(|_| IpcError::UntrustedWorkerPath)?;
    if !metadata.file_type().is_file() || metadata.file_type().is_symlink() {
        return Err(IpcError::UntrustedWorkerPath);
    }

    let child = Command::new(executable)
        .arg("--protocol-smoke")
        .env_clear()
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|_| IpcError::SpawnOrPipe)?;
    let mut child = ReapOnExit(child);
    {
        let mut stdin = child.0.stdin.take().ok_or(IpcError::SpawnOrPipe)?;
        let len = u32::try_from(prompt.len()).map_err(|_| IpcError::InvalidPrompt)?;
        stdin.write_all(&len.to_be_bytes())
            .and_then(|_| stdin.write_all(prompt.as_bytes()))
            .map_err(|_| IpcError::SpawnOrPipe)?;
        // Required for native EOF framing; rejects trailing bytes.
    }

    let stdout = child.0.stdout.take().ok_or(IpcError::SpawnOrPipe)?;
    // Drain on a dedicated reader so malicious output cannot block wait().
    // The fixed cap prevents unbounded allocation even for a hostile child.
    let reader = thread::spawn(move || {
        let mut out = Vec::new();
        let result = stdout.take((MAX_STDOUT + 1) as u64)
            .read_to_end(&mut out);
        result.map(|_| out).map_err(|_| IpcError::SpawnOrPipe)
    });

    let start = Instant::now();
    let exit_status = loop {
        if let Some(status) = child.0.try_wait().map_err(|_| IpcError::SpawnOrPipe)? {
            break status;
        }
        if start.elapsed() >= timeout {
            // The Drop guard always kills and reaps before we return.
            return Err(IpcError::DeadlineExceeded);
        }
        thread::sleep(Duration::from_millis(10));
    };
    // Reader finishes when the worker closes stdout. A production parent
    // additionally needs OS sandbox/process-group controls to stop a worker
    // spawning descendants that keep pipe handles open. This dev script
    // only launches the fixed C++ protocol-only executable.
    let output = reader.join().map_err(|_| IpcError::SpawnOrPipe)??;
    if output.len() > MAX_STDOUT {
        return Err(IpcError::TruncatedOrOverflowingOutput);
    }
    if !exit_status.success() {
        return Err(IpcError::WorkerFailed);
    }
    parse_native_response(&output)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(kind: u8, data: &[u8]) -> Vec<u8> {
        let mut b = vec![kind];
        b.extend_from_slice(&(data.len() as u32).to_be_bytes());
        b.extend_from_slice(data);
        b
    }
    fn fixture(frames: &[&[u8]]) -> Vec<u8> {
        let mut out = MAGIC.to_vec();
        for frame in frames {
            out.extend_from_slice(frame);
        }
        out
    }

    #[test]
    fn protocol_only_terminal_is_exact() {
        assert_eq!(
            parse_native_response(&fixture(&[&frame(b'N', b"NO_MODEL")])),
            Ok(NativeResponse::NoModel)
        );
        let mut extra = fixture(&[&frame(b'N', b"NO_MODEL")]);
        extra.push(1);
        assert_eq!(parse_native_response(&extra), Err(IpcError::InvalidWorkerProtocol));
    }

    #[test]
    fn tokens_are_bounded_and_terminated() {
        let out = fixture(&[&frame(b'T', b"hello"), &frame(b'T', b" world"), &frame(b'D', b"")]);
        assert_eq!(
            parse_native_response(&out),
            Ok(NativeResponse::Tokens(vec![b"hello".to_vec(), b" world".to_vec()]))
        );
        assert_eq!(
            parse_native_response(&fixture(&[&frame(b'T', b"no-end")])),
            Err(IpcError::InvalidWorkerProtocol)
        );
        let many = (0..17).map(|_| frame(b'T', b"x")).collect::<Vec<_>>();
        let mut bad = MAGIC.to_vec();
        for part in many { bad.extend(part); }
        bad.extend(frame(b'D', b""));
        assert_eq!(parse_native_response(&bad), Err(IpcError::InvalidWorkerProtocol));
    }

    #[test]
    fn malformed_corrupt_headers_and_bodies_fail_closed() {
        let mut broken = fixture(&[&frame(b'T', b"x"), &frame(b'D', b"")]);
        broken[0] ^= 1;
        assert_eq!(parse_native_response(&broken), Err(IpcError::InvalidWorkerProtocol));
        let mut truncated = fixture(&[&frame(b'N', b"NO_MODEL")]);
        truncated.pop();
        assert_eq!(parse_native_response(&truncated), Err(IpcError::InvalidWorkerProtocol));
        for kind in [b'X', b'n', b't'] {
            assert_eq!(
                parse_native_response(&fixture(&[&frame(kind, b"a")])),
                Err(IpcError::InvalidWorkerProtocol)
            );
        }
        assert_eq!(
            parse_native_response(&fixture(&[&frame(b'T', &vec![0u8; 1025]), &frame(b'D', b"")])),
            Err(IpcError::InvalidWorkerProtocol)
        );
    }

    #[test]
    fn fail_closed_on_mixed_and_duplicate_terminals() {
        for out in [
            fixture(&[&frame(b'T', b"a"), &frame(b'N', b"NO_MODEL")]),
            fixture(&[&frame(b'D', b""), &frame(b'D', b"")]),
            fixture(&[&frame(b'N', b"NO_MODEL"), &frame(b'D', b"")]),
            fixture(&[&frame(b'D', b"x")]),
            fixture(&[&frame(b'T', b""), &frame(b'D', b"")]),
        ] {
            assert_eq!(parse_native_response(&out), Err(IpcError::InvalidWorkerProtocol));
        }
    }
}
