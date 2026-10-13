use std::io::{Read, Write};
use zeroize::Zeroizing;

use jend_core::{
    ConversationId, DevicePublicIdentity, MessageRole, RecordCommitment, SensitiveBytes,
};

use crate::{Result, Vault, VaultError};

const IPC_VERSION: u16 = 2;
const IPC_AUTH_LEN: usize = 32;
const REQ_CREATE_CONVERSATION: u8 = 1;
const REQ_APPEND_MESSAGE: u8 = 2;
const REQ_LIST_CONVERSATIONS: u8 = 3;
const REQ_READ_HISTORY: u8 = 4;
const REQ_DEVICE_PUBLIC_IDENTITY: u8 = 5;
const MAX_IPC_BODY: usize = 16 * 1024 * 1024;

#[cfg(unix)]
use std::{
    fs,
    io,
    net::Shutdown,
    os::unix::{fs::PermissionsExt, net::UnixStream},
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};


/// Per-daemon IPC capability. It authenticates possession of the private
/// launch/runtime credential without exposing Vault keys.
///
/// This deliberately does not claim to defeat malware already running as the
/// same OS user. Production launch integration can later replace the file
/// handoff with a stronger platform-specific bootstrap while preserving the
/// on-wire capability check.
#[cfg(unix)]
pub struct IpcAuthToken(Zeroizing<[u8; IPC_AUTH_LEN]>);

#[cfg(unix)]
impl IpcAuthToken {
    pub fn generate() -> Result<Self> {
        let mut bytes = Zeroizing::new([0u8; IPC_AUTH_LEN]);
        getrandom::fill(&mut *bytes)?;
        Ok(Self(bytes))
    }

    pub fn load_private_file(path: impl AsRef<Path>) -> Result<Self> {
        let path = path.as_ref();
        let meta = fs::symlink_metadata(path)?;
        if !meta.file_type().is_file()
            || meta.file_type().is_symlink()
            || meta.permissions().mode() & 0o077 != 0
        {
            return Err(VaultError::InsecureIpcAuthFile);
        }
        let raw = fs::read(path)?;
        if raw.len() != IPC_AUTH_LEN {
            return Err(VaultError::InvalidIpcAuthSize);
        }
        let mut bytes = Zeroizing::new([0u8; IPC_AUTH_LEN]);
        bytes.copy_from_slice(&raw);
        Ok(Self(bytes))
    }

    pub fn write_new_private_file(&self, path: impl AsRef<Path>) -> Result<()> {
        use std::os::unix::fs::OpenOptionsExt;

        let path = path.as_ref();
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true).mode(0o600);
        let mut file = options.open(path)?;
        file.write_all(self.as_bytes())?;
        file.sync_all()?;
        Ok(())
    }

    pub fn as_bytes(&self) -> &[u8; IPC_AUTH_LEN] {
        &*self.0
    }
}

/// A decoded history item returned through the local Vault IPC boundary.
/// Plaintext is held in `SensitiveBytes`, whose debug representation is redacted.
#[cfg(unix)]
pub struct IpcHistoryMessage {
    pub role: MessageRole,
    pub sequence: u64,
    pub local_unix_ms: i64,
    pub plaintext: SensitiveBytes,
}

/// Small synchronous client for the dedicated Vault process.
///
/// The transport is synchronous on purpose. UI code must call it only from a
/// worker/runtime queue, never from the render/input thread. Each request has a
/// finite timeout so a wedged peer cannot block a worker forever.
#[cfg(unix)]
pub struct VaultIpcClient {
    socket_path: PathBuf,
    auth: IpcAuthToken,
    timeout: Duration,
}

#[cfg(unix)]
impl VaultIpcClient {
    pub fn connect(
        socket_path: impl AsRef<Path>,
        auth_path: impl AsRef<Path>,
    ) -> Result<Self> {
        Ok(Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            auth: IpcAuthToken::load_private_file(auth_path)?,
            timeout: Duration::from_secs(5),
        })
    }

    pub fn with_timeout(
        socket_path: impl AsRef<Path>,
        auth_path: impl AsRef<Path>,
        timeout: Duration,
    ) -> Result<Self> {
        if timeout.is_zero() {
            return Err(VaultError::MalformedIpc);
        }
        Ok(Self {
            socket_path: socket_path.as_ref().to_path_buf(),
            auth: IpcAuthToken::load_private_file(auth_path)?,
            timeout,
        })
    }

    fn round_trip(&self, request_type: u8, body: &[u8]) -> Result<Zeroizing<Vec<u8>>> {
        if body.len() > MAX_IPC_BODY {
            return Err(VaultError::MalformedIpc);
        }
        let mut stream = UnixStream::connect(&self.socket_path)?;
        stream.set_read_timeout(Some(self.timeout))?;
        stream.set_write_timeout(Some(self.timeout))?;
        write_request(
            &mut stream,
            self.auth.as_bytes(),
            request_type,
            body,
        )?;
        stream.shutdown(Shutdown::Write)?;
        read_response(&mut stream)
    }

    pub fn create_conversation(&self) -> Result<ConversationId> {
        let response = self.round_trip(REQ_CREATE_CONVERSATION, &[])?;
        if response.len() != 16 {
            return Err(VaultError::MalformedIpc);
        }
        Ok(ConversationId(
            response.as_slice().try_into().map_err(|_| VaultError::MalformedIpc)?,
        ))
    }

    pub fn append_message(
        &self,
        id: ConversationId,
        role: MessageRole,
        local_unix_ms: i64,
        plaintext: &[u8],
    ) -> Result<RecordCommitment> {
        if plaintext.len() > u32::MAX as usize {
            return Err(VaultError::MalformedIpc);
        }
        let fixed = 16usize + 1 + 8 + 4;
        let total = fixed.checked_add(plaintext.len()).ok_or(VaultError::MalformedIpc)?;
        if total > MAX_IPC_BODY {
            return Err(VaultError::MalformedIpc);
        }

        let mut body = Zeroizing::new(Vec::with_capacity(total));
        body.extend_from_slice(&id.0);
        body.push(role as u8);
        body.extend_from_slice(&local_unix_ms.to_be_bytes());
        body.extend_from_slice(&(plaintext.len() as u32).to_be_bytes());
        body.extend_from_slice(plaintext);

        let response = self.round_trip(REQ_APPEND_MESSAGE, body.as_slice())?;
        if response.len() != 32 {
            return Err(VaultError::MalformedIpc);
        }
        Ok(RecordCommitment(
            response.as_slice().try_into().map_err(|_| VaultError::MalformedIpc)?,
        ))
    }

    pub fn list_conversations(&self) -> Result<Vec<ConversationId>> {
        let response = self.round_trip(REQ_LIST_CONVERSATIONS, &[])?;
        if response.len() < 4 {
            return Err(VaultError::MalformedIpc);
        }
        let count = u32::from_be_bytes(
            response[0..4].try_into().map_err(|_| VaultError::MalformedIpc)?,
        ) as usize;
        let expected = 4usize
            .checked_add(count.checked_mul(16).ok_or(VaultError::MalformedIpc)?)
            .ok_or(VaultError::MalformedIpc)?;
        if expected != response.len() {
            return Err(VaultError::MalformedIpc);
        }

        let mut ids = Vec::with_capacity(count);
        let mut pos = 4usize;
        for _ in 0..count {
            ids.push(ConversationId(
                response[pos..pos + 16]
                    .try_into()
                    .map_err(|_| VaultError::MalformedIpc)?,
            ));
            pos += 16;
        }
        Ok(ids)
    }

    pub fn read_history(&self, id: ConversationId) -> Result<Vec<IpcHistoryMessage>> {
        let response = self.round_trip(REQ_READ_HISTORY, &id.0)?;
        if response.len() < 4 {
            return Err(VaultError::MalformedIpc);
        }
        let count = u32::from_be_bytes(
            response[0..4].try_into().map_err(|_| VaultError::MalformedIpc)?,
        ) as usize;
        let mut pos = 4usize;
        let mut messages = Vec::with_capacity(count.min(4096));

        for _ in 0..count {
            if response.len().saturating_sub(pos) < 1 + 8 + 8 + 4 {
                return Err(VaultError::MalformedIpc);
            }
            let role = match response[pos] {
                1 => MessageRole::User,
                2 => MessageRole::Assistant,
                3 => MessageRole::System,
                _ => return Err(VaultError::MalformedIpc),
            };
            pos += 1;
            let sequence = u64::from_be_bytes(
                response[pos..pos + 8]
                    .try_into()
                    .map_err(|_| VaultError::MalformedIpc)?,
            );
            pos += 8;
            let local_unix_ms = i64::from_be_bytes(
                response[pos..pos + 8]
                    .try_into()
                    .map_err(|_| VaultError::MalformedIpc)?,
            );
            pos += 8;
            let len = u32::from_be_bytes(
                response[pos..pos + 4]
                    .try_into()
                    .map_err(|_| VaultError::MalformedIpc)?,
            ) as usize;
            pos += 4;
            let end = pos.checked_add(len).ok_or(VaultError::MalformedIpc)?;
            if end > response.len() {
                return Err(VaultError::MalformedIpc);
            }
            let plaintext = SensitiveBytes::from_slice(&response[pos..end]);
            pos = end;
            messages.push(IpcHistoryMessage {
                role,
                sequence,
                local_unix_ms,
                plaintext,
            });
        }
        if pos != response.len() {
            return Err(VaultError::MalformedIpc);
        }
        Ok(messages)
    }

    pub fn device_public_identity(&self) -> Result<DevicePublicIdentity> {
        let response = self.round_trip(REQ_DEVICE_PUBLIC_IDENTITY, &[])?;
        if response.len() != 32 {
            return Err(VaultError::MalformedIpc);
        }
        let bytes: [u8; 32] = response
            .as_slice()
            .try_into()
            .map_err(|_| VaultError::MalformedIpc)?;
        Ok(DevicePublicIdentity::from_bytes(&bytes)?)
    }
}

#[cfg(unix)]
fn write_request(
    writer: &mut impl Write,
    auth: &[u8; IPC_AUTH_LEN],
    request_type: u8,
    body: &[u8],
) -> Result<()> {
    if body.len() > MAX_IPC_BODY {
        return Err(VaultError::MalformedIpc);
    }
    writer.write_all(&IPC_VERSION.to_be_bytes())?;
    writer.write_all(&[request_type])?;
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(auth)?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}

#[cfg(unix)]
fn read_response(reader: &mut impl Read) -> Result<Zeroizing<Vec<u8>>> {
    let mut header = [0u8; 7];
    reader.read_exact(&mut header)?;
    let version = u16::from_be_bytes([header[0], header[1]]);
    if version != IPC_VERSION || header[2] != 0 {
        return Err(VaultError::MalformedIpc);
    }
    let body_len =
        u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    if body_len > MAX_IPC_BODY {
        return Err(VaultError::MalformedIpc);
    }
    let mut body = Zeroizing::new(vec![0u8; body_len]);
    reader.read_exact(body.as_mut_slice())?;
    Ok(body)
}

#[cfg(unix)]
#[inline(never)]
fn constant_time_eq_32(left: &[u8; IPC_AUTH_LEN], right: &[u8; IPC_AUTH_LEN]) -> bool {
    let mut diff = 0u8;
    for i in 0..IPC_AUTH_LEN {
        diff |= left[i] ^ right[i];
    }
    diff == 0
}

#[cfg(unix)]
struct AuthenticatedRequest {
    request_type: u8,
    body: Zeroizing<Vec<u8>>,
}

#[cfg(unix)]
fn read_authenticated_request(
    reader: &mut impl Read,
    expected_auth: &[u8; IPC_AUTH_LEN],
) -> Result<AuthenticatedRequest> {
    let mut header = [0u8; 7];
    reader.read_exact(&mut header)?;
    let version = u16::from_be_bytes([header[0], header[1]]);
    if version != IPC_VERSION {
        return Err(VaultError::MalformedIpc);
    }
    let request_type = header[2];
    let body_len = u32::from_be_bytes([header[3], header[4], header[5], header[6]]) as usize;
    if body_len > MAX_IPC_BODY {
        return Err(VaultError::MalformedIpc);
    }

    let mut supplied = Zeroizing::new([0u8; IPC_AUTH_LEN]);
    reader.read_exact(&mut *supplied)?;
    if !constant_time_eq_32(&*supplied, expected_auth) {
        return Err(VaultError::UnauthorizedIpc);
    }

    let mut body = Zeroizing::new(vec![0u8; body_len]);
    reader.read_exact(body.as_mut_slice())?;
    Ok(AuthenticatedRequest { request_type, body })
}

#[cfg(unix)]
fn execute_request(
    vault: &mut Vault,
    request: AuthenticatedRequest,
) -> Result<Zeroizing<Vec<u8>>> {
    let body = request.body;
    let payload = match request.request_type {
        REQ_CREATE_CONVERSATION => {
            if !body.is_empty() {
                return Err(VaultError::MalformedIpc);
            }
            Zeroizing::new(vault.create_conversation()?.0.to_vec())
        }
        REQ_APPEND_MESSAGE => {
            let (id, role, timestamp, plaintext) = decode_append(body.as_slice())?;
            Zeroizing::new(
                vault
                    .append_message(id, role, timestamp, plaintext)?
                    .0
                    .to_vec(),
            )
        }
        REQ_LIST_CONVERSATIONS => {
            if !body.is_empty() {
                return Err(VaultError::MalformedIpc);
            }
            let ids = vault.conversation_ids();
            let payload_len = 4usize
                .checked_add(ids.len().checked_mul(16).ok_or(VaultError::MalformedIpc)?)
                .ok_or(VaultError::MalformedIpc)?;
            if payload_len > MAX_IPC_BODY {
                return Err(VaultError::MalformedIpc);
            }
            let mut payload = Zeroizing::new(Vec::with_capacity(payload_len));
            payload.extend_from_slice(&(ids.len() as u32).to_be_bytes());
            for id in ids {
                payload.extend_from_slice(&id.0);
            }
            payload
        }
        REQ_READ_HISTORY => {
            if body.len() != 16 {
                return Err(VaultError::MalformedIpc);
            }
            let id = ConversationId(
                body.as_slice()
                    .try_into()
                    .map_err(|_| VaultError::MalformedIpc)?,
            );
            let messages = vault.read_history(id)?;
            let mut payload = Zeroizing::new(Vec::new());
            payload.extend_from_slice(&(messages.len() as u32).to_be_bytes());
            for message in &messages {
                payload.push(message.role as u8);
                payload.extend_from_slice(&message.sequence.to_be_bytes());
                payload.extend_from_slice(&message.local_unix_ms.to_be_bytes());
                let len = message.plaintext.len();
                if len > u32::MAX as usize {
                    return Err(VaultError::MalformedIpc);
                }
                let next_len = payload
                    .len()
                    .checked_add(1 + 8 + 8 + 4)
                    .and_then(|v| v.checked_add(len))
                    .ok_or(VaultError::MalformedIpc)?;
                if next_len > MAX_IPC_BODY {
                    return Err(VaultError::MalformedIpc);
                }
                payload.extend_from_slice(&(len as u32).to_be_bytes());
                payload.extend_from_slice(message.plaintext.as_bytes());
            }
            payload
        }
        REQ_DEVICE_PUBLIC_IDENTITY => {
            if !body.is_empty() {
                return Err(VaultError::MalformedIpc);
            }
            Zeroizing::new(vault.device_public_identity().as_bytes().to_vec())
        }
        other => return Err(VaultError::UnsupportedIpc(other)),
    };
    Ok(payload)
}

/// Handles one authenticated Unix client.
///
/// The full request (including capability validation) is read before taking the
/// Vault mutex. That keeps slow/partial clients from blocking cryptographic and
/// storage work for other accepted clients.
#[cfg(unix)]
pub fn serve_authenticated_unix_stream(
    vault: &Arc<Mutex<Vault>>,
    mut stream: UnixStream,
    auth: &[u8; IPC_AUTH_LEN],
) -> Result<()> {
    let request = read_authenticated_request(&mut stream, auth)?;
    let response = {
        let mut guard = vault.lock().map_err(|_| {
            io::Error::other("Vault worker mutex poisoned")
        })?;
        execute_request(&mut guard, request)?
    };
    write_response(&mut stream, 0, response.as_slice())
}

/// In-memory/request-stream helper retained for focused tests and future
/// platform adapters. It uses an explicit capability rather than an unauthenticated
/// legacy frame.
#[cfg(unix)]
pub fn serve_one<R: Read, W: Write>(
    vault: &mut Vault,
    mut reader: R,
    mut writer: W,
    auth: &[u8; IPC_AUTH_LEN],
) -> Result<()> {
    let request = read_authenticated_request(&mut reader, auth)?;
    let response = execute_request(vault, request)?;
    write_response(&mut writer, 0, response.as_slice())
}

fn decode_append(body: &[u8]) -> Result<(ConversationId, MessageRole, i64, SensitiveBytes)> {
    if body.len() < 16 + 1 + 8 + 4 {
        return Err(VaultError::MalformedIpc);
    }
    let mut pos = 0usize;
    let id = ConversationId(
        body[pos..pos + 16]
            .try_into()
            .map_err(|_| VaultError::MalformedIpc)?,
    );
    pos += 16;
    let role = match body[pos] {
        1 => MessageRole::User,
        2 => MessageRole::Assistant,
        3 => MessageRole::System,
        _ => return Err(VaultError::MalformedIpc),
    };
    pos += 1;
    let timestamp = i64::from_be_bytes(
        body[pos..pos + 8]
            .try_into()
            .map_err(|_| VaultError::MalformedIpc)?,
    );
    pos += 8;
    let len = u32::from_be_bytes(
        body[pos..pos + 4]
            .try_into()
            .map_err(|_| VaultError::MalformedIpc)?,
    ) as usize;
    pos += 4;
    if pos.checked_add(len).is_none() || pos + len != body.len() {
        return Err(VaultError::MalformedIpc);
    }
    let plaintext = SensitiveBytes::from_slice(&body[pos..]);
    Ok((id, role, timestamp, plaintext))
}

fn write_response(writer: &mut impl Write, status: u8, body: &[u8]) -> Result<()> {
    if body.len() > MAX_IPC_BODY {
        return Err(VaultError::MalformedIpc);
    }
    writer.write_all(&IPC_VERSION.to_be_bytes())?;
    writer.write_all(&[status])?;
    writer.write_all(&(body.len() as u32).to_be_bytes())?;
    writer.write_all(body)?;
    writer.flush()?;
    Ok(())
}
