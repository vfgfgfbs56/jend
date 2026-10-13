#![forbid(unsafe_code)]

#[cfg(not(unix))]
fn main() {
    eprintln!("jend-aid currently requires Unix-domain sockets");
    std::process::exit(2);
}

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    unix::run()
}

#[cfg(unix)]
mod unix {
    use std::{
        fs::{self, OpenOptions},
        io::{Read, Write},
        os::unix::{
            fs::{OpenOptionsExt, PermissionsExt},
            net::{UnixListener, UnixStream},
        },
        path::{Path, PathBuf},
        sync::{mpsc, Arc},
        thread,
        time::Duration,
    };

    use jend_model_store::{AiExecutor, AiExecutorLimits, AiJob, AiJobId, AiCancelResult, AiSubmitFailure, ModelId};
    use sha2::{Digest, Sha256};
    use zeroize::Zeroizing;

    const MAGIC: &[u8; 4] = b"JAIX";
    const VERSION: u16 = 1;
    const AUTH_LEN: usize = 32;
    const MAX_INPUT: usize = 8 * 1024 * 1024;
    const CLIENT_TIMEOUT: Duration = Duration::from_secs(5);
    const HARD_WORKERS: usize = 4;
    const IO_WORKERS: usize = 2;
    const IO_QUEUE: usize = 16;

    const OP_PING: u8 = 1;
    const OP_SUBMIT: u8 = 2;
    const OP_CANCEL: u8 = 3;
    const OP_LIMITS: u8 = 4;

    struct WorkPayload {
        input: Zeroizing<Vec<u8>>,
        response: mpsc::SyncSender<WorkerResponse>,
    }

    enum WorkerResponse {
        Digest([u8; 32]),
        Cancelled,
    }

    pub fn run() -> Result<(), Box<dyn std::error::Error>> {
        let socket = std::env::args().nth(1).ok_or("usage: jend-aid <socket-path>")?;
        let socket_path = PathBuf::from(socket);
        let auth_path = socket_path.with_extension("auth");
        prepare_private_parent(&socket_path)?;
        if fs::symlink_metadata(&socket_path).is_ok() || fs::symlink_metadata(&auth_path).is_ok() {
            return Err("AI IPC socket/auth path already exists".into());
        }

        let auth = Arc::new(generate_auth(&auth_path)?);
        let listener = UnixListener::bind(&socket_path)?;
        fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

        let executor = Arc::new(AiExecutor::new(
            HARD_WORKERS,
            AiExecutorLimits { active_workers: 2, max_queue: 8 },
        )?);

        for index in 0..HARD_WORKERS {
            let executor = Arc::clone(&executor);
            thread::Builder::new()
                .name(format!("jend-ai-worker-{index}"))
                .spawn(move || ai_worker(executor))?;
        }

        let (io_tx, io_rx) = mpsc::sync_channel::<UnixStream>(IO_QUEUE);
        let io_rx = Arc::new(std::sync::Mutex::new(io_rx));
        for index in 0..IO_WORKERS {
            let executor = Arc::clone(&executor);
            let auth = Arc::clone(&auth);
            let io_rx = Arc::clone(&io_rx);
            thread::Builder::new()
                .name(format!("jend-ai-ipc-{index}"))
                .spawn(move || loop {
                    let stream = {
                        let receiver = match io_rx.lock() {
                            Ok(v) => v,
                            Err(_) => return,
                        };
                        match receiver.recv() {
                            Ok(stream) => stream,
                            Err(_) => return,
                        }
                    };
                    let _ = handle_stream(stream, &executor, &auth);
                })?;
        }

        for incoming in listener.incoming() {
            match incoming {
                Ok(stream) => {
                    if io_tx.try_send(stream).is_err() {
                        eprintln!("AI IPC queue full; connection rejected");
                    }
                }
                Err(err) => eprintln!("AI IPC accept failed: {err}"),
            }
        }
        Ok(())
    }

    fn ai_worker(executor: Arc<AiExecutor<WorkPayload>>) {
        while let Some(job) = executor.wait_next() {
            let mut cancelled = executor.cancellation_requested(job.id);
            let mut hasher = Sha256::new();
            if !cancelled {
                for chunk in job.payload.input.chunks(64 * 1024) {
                    if executor.cancellation_requested(job.id) {
                        cancelled = true;
                        break;
                    }
                    hasher.update(chunk);
                }
            }
            let response = if cancelled {
                WorkerResponse::Cancelled
            } else {
                WorkerResponse::Digest(hasher.finalize().into())
            };
            let _ = job.payload.response.send(response);
            let _ = executor.finish(job.id);
        }
    }

    fn handle_stream(
        mut stream: UnixStream,
        executor: &Arc<AiExecutor<WorkPayload>>,
        expected_auth: &[u8; AUTH_LEN],
    ) -> Result<(), Box<dyn std::error::Error>> {
        stream.set_read_timeout(Some(CLIENT_TIMEOUT))?;
        stream.set_write_timeout(Some(CLIENT_TIMEOUT))?;

        let mut header = [0u8; 4 + 2 + AUTH_LEN + 1 + 4];
        stream.read_exact(&mut header)?;
        if &header[..4] != MAGIC || u16::from_be_bytes([header[4], header[5]]) != VERSION {
            write_status(&mut stream, 2, b"protocol")?;
            return Ok(());
        }
        let mut supplied = [0u8; AUTH_LEN];
        supplied.copy_from_slice(&header[6..6 + AUTH_LEN]);
        if !constant_time_eq(&supplied, expected_auth) {
            write_status(&mut stream, 3, b"unauthorized")?;
            return Ok(());
        }
        let op = header[6 + AUTH_LEN];
        let len_pos = 7 + AUTH_LEN;
        let body_len = u32::from_be_bytes(header[len_pos..len_pos + 4].try_into()?) as usize;
        if body_len > MAX_INPUT + 64 {
            write_status(&mut stream, 4, b"too-large")?;
            return Ok(());
        }
        let mut body = Zeroizing::new(vec![0u8; body_len]);
        stream.read_exact(&mut body)?;

        match op {
            OP_PING if body.is_empty() => write_status(&mut stream, 0, b"pong")?,
            OP_SUBMIT => submit(&mut stream, executor, &body)?,
            OP_CANCEL => cancel(&mut stream, executor, &body)?,
            OP_LIMITS => limits(&mut stream, executor, &body)?,
            _ => write_status(&mut stream, 2, b"request")?,
        }
        Ok(())
    }

    fn submit(
        stream: &mut UnixStream,
        executor: &Arc<AiExecutor<WorkPayload>>,
        body: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if body.len() < 16 + 16 + 4 {
            write_status(stream, 2, b"submit")?;
            return Ok(());
        }
        let id = AiJobId(body[0..16].try_into()?);
        let model_id = ModelId(body[16..32].try_into()?);
        let input_len = u32::from_be_bytes(body[32..36].try_into()?) as usize;
        if input_len > MAX_INPUT || body.len() != 36 + input_len {
            write_status(stream, 4, b"input")?;
            return Ok(());
        }
        let input = Zeroizing::new(body[36..].to_vec());
        let (tx, rx) = mpsc::sync_channel(1);
        let job = AiJob {
            id,
            model_id,
            payload: WorkPayload { input, response: tx },
        };
        match executor.try_submit(job) {
            Ok(()) => match rx.recv_timeout(CLIENT_TIMEOUT) {
                Ok(WorkerResponse::Digest(digest)) => write_status(stream, 0, &digest)?,
                Ok(WorkerResponse::Cancelled) => write_status(stream, 6, b"cancelled")?,
                Err(_) => write_status(stream, 7, b"timeout")?,
            },
            Err(AiSubmitFailure::QueueFull(_)) => write_status(stream, 5, b"busy")?,
            Err(AiSubmitFailure::Closed(_)) => write_status(stream, 7, b"closed")?,
        }
        Ok(())
    }

    fn cancel(
        stream: &mut UnixStream,
        executor: &Arc<AiExecutor<WorkPayload>>,
        body: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if body.len() != 16 {
            write_status(stream, 2, b"cancel")?;
            return Ok(());
        }
        let id = AiJobId(body.try_into()?);
        match executor.cancel(id) {
            AiCancelResult::QueuedRemoved(job) => {
                let _ = job.payload.response.send(WorkerResponse::Cancelled);
                write_status(stream, 0, b"queued-cancelled")?;
            }
            AiCancelResult::ActiveMarked => write_status(stream, 0, b"active-marked")?,
            AiCancelResult::NotFound => write_status(stream, 8, b"not-found")?,
        }
        Ok(())
    }

    fn limits(
        stream: &mut UnixStream,
        executor: &Arc<AiExecutor<WorkPayload>>,
        body: &[u8],
    ) -> Result<(), Box<dyn std::error::Error>> {
        if body.len() != 6 {
            write_status(stream, 2, b"limits")?;
            return Ok(());
        }
        let active_workers = u16::from_be_bytes(body[0..2].try_into()?) as usize;
        let max_queue = u32::from_be_bytes(body[2..6].try_into()?) as usize;
        match executor.update_limits(AiExecutorLimits { active_workers, max_queue }) {
            Ok(_) => write_status(stream, 0, b"limits-updated")?,
            Err(_) => write_status(stream, 2, b"invalid-limits")?,
        }
        Ok(())
    }

    fn write_status(stream: &mut UnixStream, status: u8, payload: &[u8]) -> std::io::Result<()> {
        let len = u32::try_from(payload.len()).unwrap_or(u32::MAX);
        stream.write_all(&[status])?;
        stream.write_all(&len.to_be_bytes())?;
        stream.write_all(payload)?;
        stream.flush()
    }

    fn prepare_private_parent(socket: &Path) -> Result<(), Box<dyn std::error::Error>> {
        let parent = socket.parent().ok_or("AI IPC socket has no parent directory")?;
        fs::create_dir_all(parent)?;
        let meta = fs::symlink_metadata(parent)?;
        if !meta.file_type().is_dir() || meta.file_type().is_symlink() || meta.permissions().mode() & 0o077 != 0 {
            return Err("AI IPC directory must be private (0700 or stricter)".into());
        }
        Ok(())
    }

    fn generate_auth(path: &Path) -> Result<[u8; AUTH_LEN], Box<dyn std::error::Error>> {
        let mut auth = [0u8; AUTH_LEN];
        getrandom::fill(&mut auth)?;
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(&auth)?;
        file.sync_all()?;
        fs::set_permissions(path, fs::Permissions::from_mode(0o600))?;
        Ok(auth)
    }

    #[inline(never)]
    fn constant_time_eq(left: &[u8; AUTH_LEN], right: &[u8; AUTH_LEN]) -> bool {
        let mut diff = 0u8;
        for i in 0..AUTH_LEN {
            diff |= left[i] ^ right[i];
        }
        diff == 0
    }
}
