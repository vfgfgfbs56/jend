#![forbid(unsafe_code)]

mod client;
mod error;
mod password;
mod recovery;
mod server;
mod suite;
mod ticket;
mod username;

pub use client::{
    login_finish as client_login_finish, login_start as client_login_start,
    registration_finish as client_registration_finish,
    registration_start as client_registration_start, ClientLoginFinish, ClientLoginState,
    ClientRegistrationFinish, ClientRegistrationState,
};
pub use error::{AuthError, Result};
pub use password::SensitivePassword;
pub use recovery::{
    login_finish as recovery_login_finish, login_start as recovery_login_start,
    registration_finish as recovery_registration_finish,
    registration_start as recovery_registration_start, RecoveryAuthServer, RecoverySecret,
};
pub use server::{
    AuthServer, LoginFinish as ServerLoginFinish, LoginStart, PasswordResetRegistrationFinish,
    RegistrationStart,
};
pub use suite::JendOpaqueSuite;
pub use ticket::{OpenedTicket, TicketKey, TicketKind};
pub use username::Username;
