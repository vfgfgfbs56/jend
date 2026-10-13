use opaque_ke::{
    CredentialFinalization, CredentialRequest, RegistrationRequest, RegistrationUpload,
    ServerLogin, ServerLoginParameters, ServerRegistration, ServerSetup,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;
use jend_sync::{AccountId, RecoveryApproval, RecoveryRequest, SignedDeviceSet};

use crate::{AuthError, JendOpaqueSuite, Result, TicketKey, TicketKind, Username};

const TICKET_LIFETIME_MS: i64 = 5 * 60 * 1000;

pub struct AuthServer {
    setup: ServerSetup<JendOpaqueSuite>,
    ticket_key: TicketKey,
}

pub struct RegistrationStart {
    pub response: Vec<u8>,
    pub ticket: Vec<u8>,
}

pub struct LoginStart {
    pub response: Vec<u8>,
    pub ticket: Vec<u8>,
}

pub struct LoginFinish {
    pub username: Username,
    pub session_key: Zeroizing<Vec<u8>>,
    pub ticket_expires_unix_ms: i64,
}

/// Result of finishing an OPAQUE password reset registration. The caller must
/// atomically consume `grant_nonce` while replacing the persisted password
/// credential. Reusing the same nonce must fail at the database layer.
pub struct PasswordResetRegistrationFinish {
    pub password_file: Vec<u8>,
    pub grant_nonce: [u8; 32],
    pub request_id: [u8; 32],
    pub account_id: AccountId,
}

impl AuthServer {
    pub fn generate() -> Result<Self> {
        let mut rng = OsRng;
        Ok(Self {
            setup: ServerSetup::<JendOpaqueSuite>::new(&mut rng),
            ticket_key: TicketKey::generate()?,
        })
    }

    /// Restore the long-lived OPAQUE setup and ticket-encryption key from an
    /// external secret store. Production must not regenerate ServerSetup on
    /// process restart because existing password files depend on it.
    pub fn from_serialized_setup(
        setup_bytes: &[u8],
        ticket_secret: &mut [u8; 32],
    ) -> Result<Self> {
        let setup = ServerSetup::<JendOpaqueSuite>::deserialize(setup_bytes)
            .map_err(|_| AuthError::InvalidServerSetup)?;
        if setup.serialize().as_slice() != setup_bytes {
            return Err(AuthError::InvalidServerSetup);
        }
        Ok(Self { setup, ticket_key: TicketKey::from_secret_bytes(ticket_secret) })
    }

    /// Bootstrap helper intended for an offline/admin key generator.
    pub fn generate_setup_bytes() -> Vec<u8> {
        let mut rng = OsRng;
        ServerSetup::<JendOpaqueSuite>::new(&mut rng).serialize().to_vec()
    }

    pub fn registration_start(
        &self,
        username: &Username,
        request: &[u8],
        now_unix_ms: i64,
    ) -> Result<RegistrationStart> {
        let request = RegistrationRequest::<JendOpaqueSuite>::deserialize(request)
            .map_err(|_| AuthError::MalformedMessage)?;
        let result = ServerRegistration::<JendOpaqueSuite>::start(
            &self.setup,
            request,
            username.as_bytes(),
        )
        .map_err(|_| AuthError::RegistrationFailed)?;
        let expires = now_unix_ms.checked_add(TICKET_LIFETIME_MS).ok_or(AuthError::InvalidTicket)?;
        let ticket = self.ticket_key.seal(TicketKind::Registration, username, expires, &[])?;
        Ok(RegistrationStart { response: result.message.serialize().to_vec(), ticket })
    }

    pub fn registration_finish(
        &self,
        username: &Username,
        ticket: &[u8],
        upload: &[u8],
        now_unix_ms: i64,
    ) -> Result<Vec<u8>> {
        let opened = self.ticket_key.open(ticket, now_unix_ms)?;
        if opened.kind != TicketKind::Registration || &opened.username != username || !opened.state.is_empty() {
            return Err(AuthError::InvalidTicket);
        }
        let upload = RegistrationUpload::<JendOpaqueSuite>::deserialize(upload)
            .map_err(|_| AuthError::MalformedMessage)?;
        let password_file = ServerRegistration::<JendOpaqueSuite>::finish(upload);
        Ok(password_file.serialize().to_vec())
    }

    /// Starts a new OPAQUE registration only after a currently trusted device
    /// cryptographically authorizes recovery. The six-digit comparison code
    /// never reaches this server API; it was consumed locally when opening the
    /// code-bound approval envelope.
    pub fn password_reset_registration_start(
        &self,
        username: &Username,
        expected_account_id: AccountId,
        recovery_request: &RecoveryRequest,
        approval: &RecoveryApproval,
        device_set: &SignedDeviceSet,
        registration_request: &[u8],
        now_unix_ms: i64,
    ) -> Result<RegistrationStart> {
        if recovery_request.account_id != expected_account_id
            || device_set.set.account_id != expected_account_id
        {
            return Err(AuthError::RecoveryAuthorizationFailed);
        }
        recovery_request
            .verify(now_unix_ms)
            .map_err(|_| AuthError::RecoveryAuthorizationFailed)?;
        approval
            .verify_for_password_reset(recovery_request, device_set, now_unix_ms)
            .map_err(|_| AuthError::RecoveryAuthorizationFailed)?;

        let request = RegistrationRequest::<JendOpaqueSuite>::deserialize(registration_request)
            .map_err(|_| AuthError::MalformedMessage)?;
        let result = ServerRegistration::<JendOpaqueSuite>::start(
            &self.setup,
            request,
            username.as_bytes(),
        )
        .map_err(|_| AuthError::RegistrationFailed)?;

        let hard_expiry = now_unix_ms
            .checked_add(TICKET_LIFETIME_MS)
            .ok_or(AuthError::InvalidTicket)?;
        let expires = hard_expiry.min(approval.expires_unix_ms);
        let state = encode_password_reset_state(
            expected_account_id,
            recovery_request.request_id,
            approval.grant_nonce,
        );
        let ticket = self.ticket_key.seal(
            TicketKind::PasswordResetRegistration,
            username,
            expires,
            &state,
        )?;
        Ok(RegistrationStart {
            response: result.message.serialize().to_vec(),
            ticket,
        })
    }

    pub fn password_reset_registration_finish(
        &self,
        username: &Username,
        ticket: &[u8],
        upload: &[u8],
        now_unix_ms: i64,
    ) -> Result<PasswordResetRegistrationFinish> {
        let opened = self.ticket_key.open(ticket, now_unix_ms)?;
        if opened.kind != TicketKind::PasswordResetRegistration || &opened.username != username {
            return Err(AuthError::InvalidTicket);
        }
        let (account_id, request_id, grant_nonce) =
            decode_password_reset_state(opened.state.as_slice())?;
        let upload = RegistrationUpload::<JendOpaqueSuite>::deserialize(upload)
            .map_err(|_| AuthError::MalformedMessage)?;
        let password_file = ServerRegistration::<JendOpaqueSuite>::finish(upload)
            .serialize()
            .to_vec();
        Ok(PasswordResetRegistrationFinish {
            password_file,
            grant_nonce,
            request_id,
            account_id,
        })
    }

    pub fn login_start(
        &self,
        username: &Username,
        password_file: Option<&[u8]>,
        request: &[u8],
        now_unix_ms: i64,
    ) -> Result<LoginStart> {
        let request = CredentialRequest::<JendOpaqueSuite>::deserialize(request)
            .map_err(|_| AuthError::MalformedMessage)?;
        let password_file = match password_file {
            Some(bytes) => Some(
                ServerRegistration::<JendOpaqueSuite>::deserialize(bytes)
                    .map_err(|_| AuthError::AuthenticationFailed)?,
            ),
            None => None,
        };
        let mut rng = OsRng;
        let result = ServerLogin::start(
            &mut rng,
            &self.setup,
            password_file,
            request,
            username.as_bytes(),
            ServerLoginParameters::default(),
        )
        .map_err(|_| AuthError::AuthenticationFailed)?;
        let state = result.state.serialize();
        let expires = now_unix_ms.checked_add(TICKET_LIFETIME_MS).ok_or(AuthError::InvalidTicket)?;
        let ticket = self.ticket_key.seal(TicketKind::Login, username, expires, state.as_slice())?;
        Ok(LoginStart { response: result.message.serialize().to_vec(), ticket })
    }

    pub fn login_finish(
        &self,
        ticket: &[u8],
        finalization: &[u8],
        now_unix_ms: i64,
    ) -> Result<LoginFinish> {
        let opened = self.ticket_key.open(ticket, now_unix_ms)?;
        if opened.kind != TicketKind::Login {
            return Err(AuthError::InvalidTicket);
        }
        let state = ServerLogin::<JendOpaqueSuite>::deserialize(opened.state.as_slice())
            .map_err(|_| AuthError::InvalidTicket)?;
        let finalization = CredentialFinalization::<JendOpaqueSuite>::deserialize(finalization)
            .map_err(|_| AuthError::MalformedMessage)?;
        let result = state
            .finish(finalization, ServerLoginParameters::default())
            .map_err(|_| AuthError::AuthenticationFailed)?;
        Ok(LoginFinish {
            username: opened.username,
            session_key: Zeroizing::new(result.session_key.to_vec()),
            ticket_expires_unix_ms: opened.expires_unix_ms,
        })
    }

}

fn encode_password_reset_state(
    account_id: AccountId,
    request_id: [u8; 32],
    grant_nonce: [u8; 32],
) -> [u8; 80] {
    let mut out = [0u8; 80];
    out[..16].copy_from_slice(&account_id.0);
    out[16..48].copy_from_slice(&request_id);
    out[48..80].copy_from_slice(&grant_nonce);
    out
}

fn decode_password_reset_state(bytes: &[u8]) -> Result<(AccountId, [u8; 32], [u8; 32])> {
    if bytes.len() != 80 {
        return Err(AuthError::InvalidTicket);
    }
    let account_id = AccountId(bytes[..16].try_into().map_err(|_| AuthError::InvalidTicket)?);
    let request_id = bytes[16..48].try_into().map_err(|_| AuthError::InvalidTicket)?;
    let grant_nonce = bytes[48..80].try_into().map_err(|_| AuthError::InvalidTicket)?;
    Ok((account_id, request_id, grant_nonce))
}
