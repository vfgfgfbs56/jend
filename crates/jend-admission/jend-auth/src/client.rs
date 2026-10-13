use opaque_ke::{
    ClientLogin, ClientLoginFinishParameters, ClientRegistration,
    ClientRegistrationFinishParameters, CredentialResponse, RegistrationResponse,
};
use rand::rngs::OsRng;
use zeroize::Zeroizing;

use crate::{AuthError, JendOpaqueSuite, Result, SensitivePassword};

pub struct ClientRegistrationState(ClientRegistration<JendOpaqueSuite>);
pub struct ClientLoginState(ClientLogin<JendOpaqueSuite>);

pub struct ClientRegistrationFinish {
    pub upload: Vec<u8>,
    pub export_key: Zeroizing<Vec<u8>>,
}

pub struct ClientLoginFinish {
    pub finalization: Vec<u8>,
    pub session_key: Zeroizing<Vec<u8>>,
    pub export_key: Zeroizing<Vec<u8>>,
}

pub fn registration_start(password: &SensitivePassword) -> Result<(ClientRegistrationState, Vec<u8>)> {
    registration_start_secret(password.as_bytes())
}

pub fn registration_finish(
    state: ClientRegistrationState,
    password: &SensitivePassword,
    response: &[u8],
) -> Result<ClientRegistrationFinish> {
    registration_finish_secret(state, password.as_bytes(), response)
}

pub fn login_start(password: &SensitivePassword) -> Result<(ClientLoginState, Vec<u8>)> {
    login_start_secret(password.as_bytes())
}

pub fn login_finish(
    state: ClientLoginState,
    password: &SensitivePassword,
    response: &[u8],
) -> Result<ClientLoginFinish> {
    login_finish_secret(state, password.as_bytes(), response)
}

pub(crate) fn registration_start_secret(secret: &[u8]) -> Result<(ClientRegistrationState, Vec<u8>)> {
    let mut rng = OsRng;
    let result = ClientRegistration::<JendOpaqueSuite>::start(&mut rng, secret)
        .map_err(|_| AuthError::RegistrationFailed)?;
    Ok((ClientRegistrationState(result.state), result.message.serialize().to_vec()))
}

pub(crate) fn registration_finish_secret(
    state: ClientRegistrationState,
    secret: &[u8],
    response: &[u8],
) -> Result<ClientRegistrationFinish> {
    let response = RegistrationResponse::<JendOpaqueSuite>::deserialize(response)
        .map_err(|_| AuthError::MalformedMessage)?;
    let mut rng = OsRng;
    let result = state.0
        .finish(
            &mut rng,
            secret,
            response,
            ClientRegistrationFinishParameters::default(),
        )
        .map_err(|_| AuthError::RegistrationFailed)?;
    Ok(ClientRegistrationFinish {
        upload: result.message.serialize().to_vec(),
        export_key: Zeroizing::new(result.export_key.to_vec()),
    })
}

pub(crate) fn login_start_secret(secret: &[u8]) -> Result<(ClientLoginState, Vec<u8>)> {
    let mut rng = OsRng;
    let result = ClientLogin::<JendOpaqueSuite>::start(&mut rng, secret)
        .map_err(|_| AuthError::AuthenticationFailed)?;
    Ok((ClientLoginState(result.state), result.message.serialize().to_vec()))
}

pub(crate) fn login_finish_secret(
    state: ClientLoginState,
    secret: &[u8],
    response: &[u8],
) -> Result<ClientLoginFinish> {
    let response = CredentialResponse::<JendOpaqueSuite>::deserialize(response)
        .map_err(|_| AuthError::MalformedMessage)?;
    let mut rng = OsRng;
    let result = state.0
        .finish(
            &mut rng,
            secret,
            response,
            ClientLoginFinishParameters::default(),
        )
        .map_err(|_| AuthError::AuthenticationFailed)?;
    Ok(ClientLoginFinish {
        finalization: result.message.serialize().to_vec(),
        session_key: Zeroizing::new(result.session_key.to_vec()),
        export_key: Zeroizing::new(result.export_key.to_vec()),
    })
}
