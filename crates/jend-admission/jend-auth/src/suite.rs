use opaque_ke::{CipherSuite, Ristretto255, TripleDh};
use sha2_10::Sha512;

pub struct JendOpaqueSuite;

impl CipherSuite for JendOpaqueSuite {
    type OprfCs = Ristretto255;
    type KeyExchange = TripleDh<Ristretto255, Sha512>;
    type Ksf = opaque_ke::argon2::Argon2<'static>;
}
