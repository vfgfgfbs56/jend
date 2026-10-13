use chacha20poly1305::{
    aead::{Aead, KeyInit, Payload},
    XChaCha20Poly1305, XNonce,
};
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{AuthError, Result, Username};

const MAGIC: &[u8; 4] = b"JATK";
const VERSION: u16 = 1;
const AAD_DOMAIN: &[u8] = b"JEND/AUTH-TICKET/V1";
const MAX_TICKET_BODY: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Eq, PartialEq)]
#[repr(u8)]
pub enum TicketKind {
    Registration = 1,
    Login = 2,
    PasswordResetRegistration = 3,
}

#[derive(Zeroize, ZeroizeOnDrop)]
pub struct TicketKey([u8; 32]);

pub struct OpenedTicket {
    pub kind: TicketKind,
    pub username: Username,
    pub expires_unix_ms: i64,
    pub state: Zeroizing<Vec<u8>>,
}

impl TicketKey {
    pub fn generate() -> Result<Self> {
        let mut key = [0u8; 32];
        getrandom::fill(&mut key)?;
        Ok(Self(key))
    }

    pub fn from_secret_bytes(bytes: &mut [u8; 32]) -> Self {
        let key = *bytes;
        bytes.zeroize();
        Self(key)
    }

    pub fn seal(
        &self,
        kind: TicketKind,
        username: &Username,
        expires_unix_ms: i64,
        state: &[u8],
    ) -> Result<Vec<u8>> {
        if state.len() > MAX_TICKET_BODY {
            return Err(AuthError::InvalidTicket);
        }
        let mut body = Zeroizing::new(Vec::with_capacity(1 + username.as_bytes().len() + 8 + 4 + state.len()));
        body.push(username.as_bytes().len() as u8);
        body.extend_from_slice(username.as_bytes());
        body.extend_from_slice(&expires_unix_ms.to_be_bytes());
        body.extend_from_slice(&(state.len() as u32).to_be_bytes());
        body.extend_from_slice(state);

        let mut nonce = [0u8; 24];
        getrandom::fill(&mut nonce)?;
        let header = outer_header(kind, &nonce);
        let aad = ticket_aad(&header);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.0)
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let ciphertext = cipher
            .encrypt(&XNonce::from(nonce), Payload { msg: body.as_slice(), aad: &aad })
            .map_err(|_| AuthError::InvalidTicket)?;

        let mut out = Vec::with_capacity(header.len() + 4 + ciphertext.len());
        out.extend_from_slice(&header);
        out.extend_from_slice(&(ciphertext.len() as u32).to_be_bytes());
        out.extend_from_slice(&ciphertext);
        Ok(out)
    }

    pub fn open(&self, encoded: &[u8], now_unix_ms: i64) -> Result<OpenedTicket> {
        if encoded.len() < 4 + 2 + 1 + 24 + 4 + 16 {
            return Err(AuthError::InvalidTicket);
        }
        if &encoded[..4] != MAGIC {
            return Err(AuthError::InvalidTicket);
        }
        let version = u16::from_be_bytes([encoded[4], encoded[5]]);
        if version != VERSION {
            return Err(AuthError::InvalidTicket);
        }
        let kind = match encoded[6] {
            1 => TicketKind::Registration,
            2 => TicketKind::Login,
            3 => TicketKind::PasswordResetRegistration,
            _ => return Err(AuthError::InvalidTicket),
        };
        let nonce: [u8; 24] = encoded[7..31].try_into().map_err(|_| AuthError::InvalidTicket)?;
        let ct_len = u32::from_be_bytes(encoded[31..35].try_into().map_err(|_| AuthError::InvalidTicket)?) as usize;
        if 35usize.checked_add(ct_len).is_none() || 35 + ct_len != encoded.len() || ct_len > MAX_TICKET_BODY + 512 {
            return Err(AuthError::InvalidTicket);
        }
        let header = outer_header(kind, &nonce);
        let aad = ticket_aad(&header);
        let cipher = XChaCha20Poly1305::new_from_slice(&self.0)
            .expect("XChaCha20Poly1305 key length is fixed at 32 bytes");
        let plaintext = cipher
            .decrypt(&XNonce::from(nonce), Payload { msg: &encoded[35..], aad: &aad })
            .map_err(|_| AuthError::InvalidTicket)?;
        let plaintext = Zeroizing::new(plaintext);
        decode_body(kind, plaintext.as_slice(), now_unix_ms)
    }
}

fn outer_header(kind: TicketKind, nonce: &[u8; 24]) -> [u8; 31] {
    let mut out = [0u8; 31];
    out[..4].copy_from_slice(MAGIC);
    out[4..6].copy_from_slice(&VERSION.to_be_bytes());
    out[6] = kind as u8;
    out[7..31].copy_from_slice(nonce);
    out
}

fn ticket_aad(header: &[u8; 31]) -> Vec<u8> {
    let mut out = Vec::with_capacity(AAD_DOMAIN.len() + header.len());
    out.extend_from_slice(AAD_DOMAIN);
    out.extend_from_slice(header);
    out
}

fn decode_body(kind: TicketKind, bytes: &[u8], now_unix_ms: i64) -> Result<OpenedTicket> {
    if bytes.is_empty() {
        return Err(AuthError::InvalidTicket);
    }
    let username_len = bytes[0] as usize;
    if username_len == 0 || bytes.len() < 1 + username_len + 8 + 4 {
        return Err(AuthError::InvalidTicket);
    }
    let username_text = core::str::from_utf8(&bytes[1..1 + username_len]).map_err(|_| AuthError::InvalidTicket)?;
    let username = Username::parse(username_text).map_err(|_| AuthError::InvalidTicket)?;
    let mut pos = 1 + username_len;
    let expires_unix_ms = i64::from_be_bytes(bytes[pos..pos + 8].try_into().map_err(|_| AuthError::InvalidTicket)?);
    pos += 8;
    if now_unix_ms > expires_unix_ms {
        return Err(AuthError::InvalidTicket);
    }
    let state_len = u32::from_be_bytes(bytes[pos..pos + 4].try_into().map_err(|_| AuthError::InvalidTicket)?) as usize;
    pos += 4;
    if pos.checked_add(state_len).is_none() || pos + state_len != bytes.len() {
        return Err(AuthError::InvalidTicket);
    }
    Ok(OpenedTicket {
        kind,
        username,
        expires_unix_ms,
        state: Zeroizing::new(bytes[pos..].to_vec()),
    })
}
