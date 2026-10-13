use std::{
    collections::HashMap,
    fs,
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use sha2::{Digest, Sha256};
use zeroize::Zeroizing;

use jend_core::{
    AccountRootKey, ConversationId, JendRecord, SealedLocalBlob, WrappedConversationSeed,
};
use jend_sync::{SyncObject, SyncObjectId};

use crate::{Result, VaultError};

const INDEX_MAGIC: &[u8; 4] = b"JVIX";
const INDEX_VERSION: u16 = 1;
const INDEX_CONTEXT: &[u8] = b"JEND-VAULT/CONVERSATION-INDEX/V1";
const INDEX_FILE: &str = "conversations.idx";
const SYNC_STATE_MAGIC: &[u8; 4] = b"JVSS";
const SYNC_STATE_FILE: &str = "sync-state.bin";
const LOG_DIR: &str = "conversations";
const SYNC_OBJECT_DIR: &str = "sync-objects";
const PENDING_MAGIC: &[u8; 4] = b"JVPN";
const PENDING_VERSION: u16 = 1;
const PENDING_DOMAIN: &[u8] = b"JEND-VAULT/PENDING-RECORD/V1";
const PENDING_LEN: usize = 4 + 2 + 8 + 4 + 32;
const MAX_INDEX_CIPHERTEXT: usize = 16 * 1024 * 1024 + 16;
const MAX_FRAME: usize = 17 * 1024 * 1024;

pub struct VaultStorage {
    root: PathBuf,
}

struct PendingRecord {
    pre_len: u64,
    record_len: u32,
    digest: [u8; 32],
}

impl VaultStorage {
    pub fn new(root: impl AsRef<Path>) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join(LOG_DIR))?;
        fs::create_dir_all(root.join(SYNC_OBJECT_DIR))?;
        Ok(Self { root })
    }

    pub fn load_index(&self, ark: &AccountRootKey) -> Result<HashMap<ConversationId, WrappedConversationSeed>> {
        let path = self.root.join(INDEX_FILE);
        let bytes = match fs::read(&path) {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(HashMap::new()),
            Err(err) => return Err(err.into()),
        };
        let blob = decode_sealed_blob(&bytes)?;
        let plaintext = ark.open_local_metadata(INDEX_CONTEXT, &blob)?;
        decode_index(plaintext.as_slice())
    }

    pub fn save_index(
        &self,
        ark: &AccountRootKey,
        index: &HashMap<ConversationId, WrappedConversationSeed>,
    ) -> Result<()> {
        let plaintext = Zeroizing::new(encode_index(index)?);
        let blob = ark.seal_local_metadata(INDEX_CONTEXT, plaintext.as_slice())?;
        let encoded = encode_sealed_blob(&blob)?;
        atomic_replace(&self.root.join(INDEX_FILE), &encoded)
    }

    pub fn load_sync_state_blob(&self) -> Result<Option<SealedLocalBlob>> {
        let path = self.root.join(SYNC_STATE_FILE);
        let bytes = match fs::read(&path) {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Ok(Some(decode_sealed_blob_with_magic(&bytes, SYNC_STATE_MAGIC)?))
    }

    pub fn save_sync_state_blob(&self, blob: &SealedLocalBlob) -> Result<()> {
        let encoded = encode_sealed_blob_with_magic(blob, SYNC_STATE_MAGIC)?;
        atomic_replace(&self.root.join(SYNC_STATE_FILE), &encoded)
    }

    pub fn ensure_log_exists(&self, id: ConversationId) -> Result<()> {
        let path = self.log_path(id);
        if path.exists() {
            return Ok(());
        }
        let mut options = fs::OpenOptions::new();
        options.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        match options.open(&path) {
            Ok(file) => {
                file.sync_all()?;
                sync_parent(&path)?;
                Ok(())
            }
            Err(err) if err.kind() == std::io::ErrorKind::AlreadyExists => Ok(()),
            Err(err) => Err(err.into()),
        }
    }

    /// Crash-safe append protocol:
    /// 1) fsync pending journal with pre-append length + record hash;
    /// 2) append framed record and fsync log;
    /// 3) remove pending journal and fsync directory.
    ///
    /// Recovery truncates an incomplete tail only when that pending journal
    /// proves the process was in the middle of this exact append.
    pub fn append_record(&self, id: ConversationId, encoded_record: &[u8]) -> Result<()> {
        if encoded_record.is_empty() || encoded_record.len() > MAX_FRAME || encoded_record.len() > u32::MAX as usize {
            return Err(VaultError::InvalidFrameLength);
        }
        self.ensure_log_exists(id)?;
        self.recover_pending(id)?;

        let path = self.log_path(id);
        let pre_len = fs::metadata(&path)?.len();
        let pending = PendingRecord {
            pre_len,
            record_len: encoded_record.len() as u32,
            digest: record_digest(encoded_record),
        };
        atomic_replace(&self.pending_path(id), &encode_pending(&pending))?;

        let append_result = (|| -> Result<()> {
            let mut file = fs::OpenOptions::new().append(true).open(&path)?;
            file.write_all(&pending.record_len.to_be_bytes())?;
            file.write_all(encoded_record)?;
            file.sync_data()?;
            Ok(())
        })();

        if append_result.is_ok() {
            remove_file_sync_parent(&self.pending_path(id))?;
        }
        append_result
    }

    pub fn read_records_recover_tail(&self, id: ConversationId) -> Result<Vec<JendRecord>> {
        self.ensure_log_exists(id)?;
        self.recover_pending(id)?;

        let path = self.log_path(id);
        let mut file = fs::OpenOptions::new().read(true).open(&path)?;
        let file_len = file.metadata()?.len();
        let mut records = Vec::new();

        loop {
            let frame_start = file.stream_position()?;
            if frame_start == file_len {
                break;
            }
            if file_len.saturating_sub(frame_start) < 4 {
                return Err(VaultError::IncompleteTail);
            }

            let mut len_bytes = [0u8; 4];
            file.read_exact(&mut len_bytes)?;
            let len = u32::from_be_bytes(len_bytes) as usize;
            if len == 0 || len > MAX_FRAME {
                return Err(VaultError::InvalidFrameLength);
            }

            let payload_start = file.stream_position()?;
            if file_len.saturating_sub(payload_start) < len as u64 {
                return Err(VaultError::IncompleteTail);
            }

            let mut encoded = vec![0u8; len];
            file.read_exact(&mut encoded)?;
            records.push(JendRecord::decode_exact(&encoded)?);
        }
        Ok(records)
    }

    /// Stores the exact encrypted JESP object under its random object id.
    /// Existing objects are immutable: the same id with different bytes is a
    /// local integrity failure rather than an overwrite.
    pub fn save_sync_object(&self, object: &SyncObject) -> Result<()> {
        let encoded = object.encode_wire()?;
        let path = self.sync_object_path(object.object_id);
        match fs::read(&path) {
            Ok(existing) => {
                if existing == encoded {
                    return Ok(());
                }
                return Err(VaultError::SyncObjectConflict);
            }
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => {}
            Err(err) => return Err(err.into()),
        }
        atomic_replace(&path, &encoded)
    }

    pub fn load_sync_object(&self, id: SyncObjectId) -> Result<Option<SyncObject>> {
        let path = self.sync_object_path(id);
        let bytes = match fs::read(&path) {
            Ok(bytes) => bytes,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(None),
            Err(err) => return Err(err.into()),
        };
        Ok(Some(SyncObject::decode_wire(id, &bytes)?))
    }

    pub fn sync_object_path(&self, id: SyncObjectId) -> PathBuf {
        self.root
            .join(SYNC_OBJECT_DIR)
            .join(format!("{}.jeso", hex(&id.0)))
    }

    pub fn log_path(&self, id: ConversationId) -> PathBuf {
        self.root.join(LOG_DIR).join(format!("{}.jendlog", hex16(&id.0)))
    }

    fn pending_path(&self, id: ConversationId) -> PathBuf {
        self.root.join(LOG_DIR).join(format!("{}.pending", hex16(&id.0)))
    }

    fn recover_pending(&self, id: ConversationId) -> Result<()> {
        let pending_path = self.pending_path(id);
        let bytes = match fs::read(&pending_path) {
            Ok(v) => v,
            Err(err) if err.kind() == std::io::ErrorKind::NotFound => return Ok(()),
            Err(err) => return Err(err.into()),
        };
        let pending = decode_pending(&bytes)?;
        let log_path = self.log_path(id);
        let mut file = fs::OpenOptions::new().read(true).write(true).open(&log_path)?;
        let log_len = file.metadata()?.len();
        let expected_end = pending
            .pre_len
            .checked_add(4)
            .and_then(|v| v.checked_add(pending.record_len as u64))
            .ok_or(VaultError::PendingMismatch)?;

        if log_len < pending.pre_len || log_len > expected_end {
            return Err(VaultError::PendingMismatch);
        }

        if log_len == pending.pre_len {
            remove_file_sync_parent(&pending_path)?;
            return Ok(());
        }

        if log_len < expected_end {
            // This is the only automatic truncation path: a valid pending
            // journal proves an interrupted append from exactly pre_len.
            file.set_len(pending.pre_len)?;
            file.sync_all()?;
            remove_file_sync_parent(&pending_path)?;
            return Ok(());
        }

        file.seek(SeekFrom::Start(pending.pre_len))?;
        let mut len_bytes = [0u8; 4];
        file.read_exact(&mut len_bytes)?;
        if u32::from_be_bytes(len_bytes) != pending.record_len {
            return Err(VaultError::PendingMismatch);
        }
        let mut encoded = vec![0u8; pending.record_len as usize];
        file.read_exact(&mut encoded)?;
        if record_digest(&encoded) != pending.digest {
            return Err(VaultError::PendingMismatch);
        }
        JendRecord::decode_exact(&encoded)?;
        remove_file_sync_parent(&pending_path)?;
        Ok(())
    }
}

fn record_digest(record: &[u8]) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(PENDING_DOMAIN);
    h.update((record.len() as u64).to_be_bytes());
    h.update(record);
    h.finalize().into()
}

fn encode_pending(pending: &PendingRecord) -> Vec<u8> {
    let mut out = Vec::with_capacity(PENDING_LEN);
    out.extend_from_slice(PENDING_MAGIC);
    out.extend_from_slice(&PENDING_VERSION.to_be_bytes());
    out.extend_from_slice(&pending.pre_len.to_be_bytes());
    out.extend_from_slice(&pending.record_len.to_be_bytes());
    out.extend_from_slice(&pending.digest);
    out
}

fn decode_pending(bytes: &[u8]) -> Result<PendingRecord> {
    if bytes.len() != PENDING_LEN || &bytes[..4] != PENDING_MAGIC {
        return Err(VaultError::PendingMismatch);
    }
    let mut pos = 4usize;
    if take_u16(bytes, &mut pos)? != PENDING_VERSION {
        return Err(VaultError::PendingMismatch);
    }
    let pre_len = u64::from_be_bytes(take_array::<8>(bytes, &mut pos)?);
    let record_len = take_u32(bytes, &mut pos)?;
    if record_len == 0 || record_len as usize > MAX_FRAME {
        return Err(VaultError::PendingMismatch);
    }
    let digest = take_array::<32>(bytes, &mut pos)?;
    Ok(PendingRecord { pre_len, record_len, digest })
}

fn encode_index(index: &HashMap<ConversationId, WrappedConversationSeed>) -> Result<Vec<u8>> {
    if index.len() > u32::MAX as usize {
        return Err(VaultError::MalformedMetadata);
    }
    let mut entries: Vec<_> = index.iter().collect();
    entries.sort_by_key(|(id, _)| id.0);

    let mut out = Vec::new();
    out.extend_from_slice(&INDEX_VERSION.to_be_bytes());
    out.extend_from_slice(&(entries.len() as u32).to_be_bytes());
    for (id, envelope) in entries {
        if envelope.ciphertext.len() > u16::MAX as usize {
            return Err(VaultError::MalformedMetadata);
        }
        out.extend_from_slice(&id.0);
        out.extend_from_slice(&envelope.nonce);
        out.extend_from_slice(&(envelope.ciphertext.len() as u16).to_be_bytes());
        out.extend_from_slice(&envelope.ciphertext);
    }
    Ok(out)
}

fn decode_index(bytes: &[u8]) -> Result<HashMap<ConversationId, WrappedConversationSeed>> {
    let mut pos = 0usize;
    let version = take_u16(bytes, &mut pos)?;
    if version != INDEX_VERSION {
        return Err(VaultError::MalformedMetadata);
    }
    let count = take_u32(bytes, &mut pos)? as usize;
    let mut out = HashMap::with_capacity(count);
    for _ in 0..count {
        let id = ConversationId(take_array::<16>(bytes, &mut pos)?);
        let nonce = take_array::<24>(bytes, &mut pos)?;
        let ct_len = take_u16(bytes, &mut pos)? as usize;
        if ct_len == 0 || pos.checked_add(ct_len).is_none() || pos + ct_len > bytes.len() {
            return Err(VaultError::MalformedMetadata);
        }
        let ciphertext = bytes[pos..pos + ct_len].to_vec();
        pos += ct_len;
        if out.insert(id, WrappedConversationSeed { nonce, ciphertext }).is_some() {
            return Err(VaultError::MalformedMetadata);
        }
    }
    if pos != bytes.len() {
        return Err(VaultError::MalformedMetadata);
    }
    Ok(out)
}

fn encode_sealed_blob(blob: &SealedLocalBlob) -> Result<Vec<u8>> {
    encode_sealed_blob_with_magic(blob, INDEX_MAGIC)
}

fn decode_sealed_blob(bytes: &[u8]) -> Result<SealedLocalBlob> {
    decode_sealed_blob_with_magic(bytes, INDEX_MAGIC)
}

fn encode_sealed_blob_with_magic(blob: &SealedLocalBlob, magic: &[u8; 4]) -> Result<Vec<u8>> {
    if blob.ciphertext.len() > MAX_INDEX_CIPHERTEXT || blob.ciphertext.len() > u32::MAX as usize {
        return Err(VaultError::MalformedMetadata);
    }
    let mut out = Vec::with_capacity(4 + 2 + 24 + 4 + blob.ciphertext.len());
    out.extend_from_slice(magic);
    out.extend_from_slice(&INDEX_VERSION.to_be_bytes());
    out.extend_from_slice(&blob.nonce);
    out.extend_from_slice(&(blob.ciphertext.len() as u32).to_be_bytes());
    out.extend_from_slice(&blob.ciphertext);
    Ok(out)
}

fn decode_sealed_blob_with_magic(bytes: &[u8], magic: &[u8; 4]) -> Result<SealedLocalBlob> {
    if bytes.len() < 34 || &bytes[..4] != magic {
        return Err(VaultError::MalformedMetadata);
    }
    let mut pos = 4usize;
    if take_u16(bytes, &mut pos)? != INDEX_VERSION {
        return Err(VaultError::MalformedMetadata);
    }
    let nonce = take_array::<24>(bytes, &mut pos)?;
    let len = take_u32(bytes, &mut pos)? as usize;
    if len > MAX_INDEX_CIPHERTEXT || pos.checked_add(len).is_none() || pos + len != bytes.len() {
        return Err(VaultError::MalformedMetadata);
    }
    Ok(SealedLocalBlob { nonce, ciphertext: bytes[pos..].to_vec() })
}

fn atomic_replace(path: &Path, bytes: &[u8]) -> Result<()> {
    let parent = path.parent().ok_or(VaultError::MalformedMetadata)?;
    fs::create_dir_all(parent)?;
    let mut suffix = [0u8; 8];
    getrandom::fill(&mut suffix)?;
    let tmp = parent.join(format!(".tmp-{}", hex(&suffix)));

    let mut options = fs::OpenOptions::new();
    options.write(true).create_new(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600);
    }
    let mut file = options.open(&tmp)?;
    if let Err(err) = (|| -> std::io::Result<()> {
        file.write_all(bytes)?;
        file.sync_all()?;
        fs::rename(&tmp, path)?;
        Ok(())
    })() {
        let _ = fs::remove_file(&tmp);
        return Err(err.into());
    }
    sync_parent(path)
}

fn remove_file_sync_parent(path: &Path) -> Result<()> {
    match fs::remove_file(path) {
        Ok(()) => sync_parent(path),
        Err(err) if err.kind() == std::io::ErrorKind::NotFound => Ok(()),
        Err(err) => Err(err.into()),
    }
}

fn sync_parent(path: &Path) -> Result<()> {
    if let Some(parent) = path.parent() {
        fs::File::open(parent)?.sync_all()?;
    }
    Ok(())
}

fn take_u16(bytes: &[u8], pos: &mut usize) -> Result<u16> {
    Ok(u16::from_be_bytes(take_array::<2>(bytes, pos)?))
}

fn take_u32(bytes: &[u8], pos: &mut usize) -> Result<u32> {
    Ok(u32::from_be_bytes(take_array::<4>(bytes, pos)?))
}

fn take_array<const N: usize>(bytes: &[u8], pos: &mut usize) -> Result<[u8; N]> {
    let end = pos.checked_add(N).ok_or(VaultError::MalformedMetadata)?;
    if end > bytes.len() {
        return Err(VaultError::MalformedMetadata);
    }
    let out = bytes[*pos..end].try_into().map_err(|_| VaultError::MalformedMetadata)?;
    *pos = end;
    Ok(out)
}

fn hex16(bytes: &[u8; 16]) -> String { hex(bytes) }
fn hex(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}
