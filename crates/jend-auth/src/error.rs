use thiserror::Error;

pub type Result<T> = core::result::Result<T, AuthError>;

#[derive(Debug, Error)]
pub enum AuthError {
    #[error("invalid username")]
    InvalidUsername,

    #[error("password does not satisfy local policy")]
    InvalidPassword,

    #[error("authentication failed")]
    AuthenticationFailed,

    #[error("registration handshake failed")]
    RegistrationFailed,

    #[error("authentication ticket is invalid or expired")]
    InvalidTicket,

    #[error("authentication message is malformed")]
    MalformedMessage,

    #[error("server OPAQUE setup is invalid")]
    InvalidServerSetup,

    #[error("device recovery authorization failed")]
    RecoveryAuthorizationFailed,

    #[error("operating-system CSPRNG failed")]
    Random(#[from] getrandom::Error),
}
