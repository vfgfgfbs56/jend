#![forbid(unsafe_code)]

#[cfg(unix)]
fn main() -> Result<(), Box<dyn std::error::Error>> {
    use std::{
        env,
        fs,
        os::unix::{fs::PermissionsExt, net::UnixListener},
        path::{Path, PathBuf},
        sync::{mpsc, Arc, Mutex},
        thread,
        time::Duration,
    };
    use jend_vault::{
        serve_authenticated_unix_stream, DevFileSecretStore, IpcAuthToken, Vault,
    };

    const WORKERS: usize = 4;
    const QUEUE_DEPTH: usize = 32;
    const CLIENT_IO_TIMEOUT: Duration = Duration::from_secs(5);

    fn auth_path_for(socket_path: &Path) -> PathBuf {
        socket_path.with_extension("auth")
    }

    let state_dir = PathBuf::from(
        env::var_os("JEND_VAULT_STATE_DIR")
            .unwrap_or_else(|| "/var/lib/jend-vault".into()),
    );
    let secret_dir = PathBuf::from(
        env::var_os("JEND_VAULT_SECRET_DIR")
            .unwrap_or_else(|| "/var/lib/jend-vault/secrets".into()),
    );
    let socket_path = PathBuf::from(
        env::var_os("JEND_VAULT_SOCKET")
            .unwrap_or_else(|| "/run/jend/vault.sock".into()),
    );
    let auth_path = auth_path_for(&socket_path);

    // Do not delete pre-existing paths: they might belong to a running Vault
    // or have been planted deliberately. Reuse requires verified cleanup by
    // the launcher/operator.
    if let Some(parent) = socket_path.parent() {
        fs::create_dir_all(parent)?;
        let metadata = fs::symlink_metadata(parent)?;
        if !metadata.file_type().is_dir() || metadata.permissions().mode() & 0o077 != 0 {
            return Err("Vault IPC directory must be a private (0700) directory".into());
        }
    }
    if fs::symlink_metadata(&socket_path).is_ok() {
        return Err("Vault IPC path already exists; refusing to replace it".into());
    }
    if fs::symlink_metadata(&auth_path).is_ok() {
        return Err("Vault IPC authorization path already exists; refusing to replace it".into());
    }

    fs::create_dir_all(&state_dir)?;
    fs::set_permissions(&state_dir, fs::Permissions::from_mode(0o700))?;

    let secrets = DevFileSecretStore::new(secret_dir)?;
    let vault = Arc::new(Mutex::new(Vault::open(state_dir, &secrets)?));

    // Fresh per-daemon capability. Only the capability is shared with the
    // local client; Vault root/device private keys never cross IPC.
    let auth = Arc::new(IpcAuthToken::generate()?);
    auth.write_new_private_file(&auth_path)?;

    let listener = UnixListener::bind(&socket_path)?;
    fs::set_permissions(&socket_path, fs::Permissions::from_mode(0o600))?;

    // Fixed worker count + bounded queue prevents unbounded thread/memory
    // growth under local connection floods. Request bodies are read and
    // authenticated before a worker takes the Vault mutex.
    let (tx, rx) = mpsc::sync_channel::<std::os::unix::net::UnixStream>(QUEUE_DEPTH);
    let rx = Arc::new(Mutex::new(rx));

    for worker_index in 0..WORKERS {
        let vault = Arc::clone(&vault);
        let auth = Arc::clone(&auth);
        let rx = Arc::clone(&rx);
        thread::Builder::new()
            .name(format!("jend-vault-ipc-{worker_index}"))
            .spawn(move || loop {
                let stream = {
                    let receiver = match rx.lock() {
                        Ok(receiver) => receiver,
                        Err(_) => {
                            eprintln!("vault IPC receiver mutex poisoned");
                            return;
                        }
                    };
                    match receiver.recv() {
                        Ok(stream) => stream,
                        Err(_) => return,
                    }
                };

                if let Err(err) = stream.set_read_timeout(Some(CLIENT_IO_TIMEOUT)) {
                    eprintln!("vault socket read-timeout setup failed: {err}");
                    continue;
                }
                if let Err(err) = stream.set_write_timeout(Some(CLIENT_IO_TIMEOUT)) {
                    eprintln!("vault socket write-timeout setup failed: {err}");
                    continue;
                }

                if let Err(err) = serve_authenticated_unix_stream(
                    &vault,
                    stream,
                    auth.as_bytes(),
                ) {
                    eprintln!("vault IPC request rejected: {err}");
                }
            })?;
    }

    for stream in listener.incoming() {
        match stream {
            Ok(stream) => match tx.try_send(stream) {
                Ok(()) => {}
                Err(mpsc::TrySendError::Full(_stream)) => {
                    // Drop immediately. A responsive UI should retry with its
                    // own bounded backoff rather than allow unbounded backlog.
                    eprintln!("vault IPC queue full; connection rejected");
                }
                Err(mpsc::TrySendError::Disconnected(_stream)) => {
                    return Err("all Vault IPC workers stopped".into());
                }
            },
            Err(err) => eprintln!("vault socket accept failed: {err}"),
        }
    }
    Ok(())
}

#[cfg(not(unix))]
fn main() {
    compile_error!("jend-vaultd M7 currently supports Unix-domain sockets only");
}
