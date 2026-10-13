use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::{Zeroize, ZeroizeOnDrop, Zeroizing};

use crate::{
    AuthError, AuthServer, ClientLoginFinish, ClientLoginState, ClientRegistrationFinish,
    ClientRegistrationState, LoginStart, RegistrationStart, Result, SensitivePassword,
    ServerLoginFinish, Username,
};

const RECOVERY_DOMAIN: &[u8] = b"JEND/ACCOUNT-RECOVERY-OPAQUE/V2";
const SECRET_BYTES: usize = 32; // 256 bits from OS CSPRNG

/// High-entropy recovery secret shown once to the user.
///
/// M2.1 deliberately removed the old SHA-256 verifier. The server should store
/// a *separate OPAQUE credential record* for this secret, using an independent
/// `AuthServer` setup from the normal password credential.
#[derive(Zeroize, ZeroizeOnDrop)]
pub struct RecoverySecret([u8; SECRET_BYTES]);

/// Type-level separation for the server-side recovery OPAQUE setup.
///
/// Production persistence must keep this instance's setup/ticket keys separate
/// from the normal password `AuthServer`.
pub struct RecoveryAuthServer {
    inner: AuthServer,
}

impl RecoveryAuthServer {
    pub fn generate() -> Result<Self> {
        Ok(Self { inner: AuthServer::generate()? })
    }

    pub fn registration_start(
        &self,
        username: &Username,
        request: &[u8],
        now_unix_ms: i64,
    ) -> Result<RegistrationStart> {
        self.inner.registration_start(username, request, now_unix_ms)
    }

    pub fn registration_finish(
        &self,
        username: &Username,
        ticket: &[u8],
        upload: &[u8],
        now_unix_ms: i64,
    ) -> Result<Vec<u8>> {
        self.inner.registration_finish(username, ticket, upload, now_unix_ms)
    }

    pub fn login_start(
        &self,
        username: &Username,
        recovery_file: Option<&[u8]>,
        request: &[u8],
        now_unix_ms: i64,
    ) -> Result<LoginStart> {
        self.inner.login_start(username, recovery_file, request, now_unix_ms)
    }

    pub fn login_finish(
        &self,
        ticket: &[u8],
        finalization: &[u8],
        now_unix_ms: i64,
    ) -> Result<ServerLoginFinish> {
        self.inner.login_finish(ticket, finalization, now_unix_ms)
    }
}

impl RecoverySecret {
    pub fn generate() -> Result<Self> {
        let mut bytes = [0u8; SECRET_BYTES];
        getrandom::fill(&mut bytes)?;
        Ok(Self(bytes))
    }

    /// User-facing representation shown once. The server never stores this
    /// string or raw secret bytes.
    pub fn display_code(&self) -> String {
        let hex = hex_upper(&self.0);
        let mut out = String::from("JEND");
        for chunk in hex.as_bytes().chunks(4) {
            out.push('-');
            out.push_str(core::str::from_utf8(chunk).expect("hex is ASCII"));
        }
        out
    }

    pub fn parse_display_code(input: &str) -> Result<Self> {
        let compact: String = input
            .chars()
            .filter(|c| *c != '-')
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let hex = compact.strip_prefix("JEND").ok_or(AuthError::AuthenticationFailed)?;
        if hex.len() != SECRET_BYTES * 2 {
            return Err(AuthError::AuthenticationFailed);
        }
        let mut bytes = [0u8; SECRET_BYTES];
        for (i, pair) in hex.as_bytes().chunks_exact(2).enumerate() {
            bytes[i] = (from_hex(pair[0])? << 4) | from_hex(pair[1])?;
        }
        Ok(Self(bytes))
    }

    /// Domain-separates the recovery code from every other use before feeding
    /// it into OPAQUE. This value is local-only and is zeroized on drop.
    fn opaque_secret(&self, username: &Username) -> Result<Zeroizing<[u8; 32]>> {
        let hk = Hkdf::<Sha256>::new(Some(username.as_bytes()), &self.0);
        let mut out = Zeroizing::new([0u8; 32]);
        hk.expand(RECOVERY_DOMAIN, out.as_mut())
            .map_err(|_| AuthError::AuthenticationFailed)?;
        Ok(out)
    }
}

pub fn registration_start(
    username: &Username,
    secret: &RecoverySecret,
) -> Result<(ClientRegistrationState, Vec<u8>)> {
    let derived = secret.opaque_secret(username)?;
    let wrapped = SensitivePassword::from_high_entropy_bytes(derived.as_ref())?;
    crate::client::registration_start_secret(wrapped.as_bytes())
}

pub fn registration_finish(
    username: &Username,
    state: ClientRegistrationState,
    secret: &RecoverySecret,
    response: &[u8],
) -> Result<ClientRegistrationFinish> {
    let derived = secret.opaque_secret(username)?;
    let wrapped = SensitivePassword::from_high_entropy_bytes(derived.as_ref())?;
    crate::client::registration_finish_secret(state, wrapped.as_bytes(), response)
}

pub fn login_start(
    username: &Username,
    secret: &RecoverySecret,
) -> Result<(ClientLoginState, Vec<u8>)> {
    let derived = secret.opaque_secret(username)?;
    let wrapped = SensitivePassword::from_high_entropy_bytes(derived.as_ref())?;
    crate::client::login_start_secret(wrapped.as_bytes())
}

pub fn login_finish(
    username: &Username,
    state: ClientLoginState,
    secret: &RecoverySecret,
    response: &[u8],
) -> Result<ClientLoginFinish> {
    let derived = secret.opaque_secret(username)?;
    let wrapped = SensitivePassword::from_high_entropy_bytes(derived.as_ref())?;
    crate::client::login_finish_secret(state, wrapped.as_bytes(), response)
}

fn from_hex(byte: u8) -> Result<u8> {
    match byte {
        b'0'..=b'9' => Ok(byte - b'0'),
        b'A'..=b'F' => Ok(byte - b'A' + 10),
        _ => Err(AuthError::AuthenticationFailed),
    }
}

fn hex_upper(bytes: &[u8]) -> String {
    const LUT: &[u8; 16] = b"0123456789ABCDEF";
    let mut out = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        out.push(LUT[(b >> 4) as usize] as char);
        out.push(LUT[(b & 0x0f) as usize] as char);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn recovery_code_roundtrip() {
        let secret = RecoverySecret::generate().unwrap();
        let code = secret.display_code();
        let parsed = RecoverySecret::parse_display_code(&code).unwrap();
        assert_eq!(parsed.display_code(), code);
    }

    #[test]
    fn recovery_opaque_secret_is_username_bound() {
        let secret = RecoverySecret::generate().unwrap();
        let a = Username::parse("alice_7").unwrap();
        let b = Username::parse("alice_8").unwrap();
        assert_ne!(secret.opaque_secret(&a).unwrap().as_ref(), secret.opaque_secret(&b).unwrap().as_ref());
    }
}
