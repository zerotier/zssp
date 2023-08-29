#[cfg(feature = "aes-gcm")]
mod aes_impl;
#[cfg(feature = "aes-gcm")]
pub use aes_impl::*;
#[cfg(feature = "pqc_kyber")]
mod kyber1024;
#[cfg(feature = "pqc_kyber")]
pub use kyber1024::*;
#[cfg(feature = "p384")]
mod p384_impl;
#[cfg(feature = "p384")]
pub use p384_impl::*;
#[cfg(feature = "sha2")]
mod sha512;
#[cfg(feature = "sha2")]
pub use sha512::*;

#[cfg(feature = "aes")]
pub use aes;
#[cfg(feature = "aes-gcm")]
pub use aes_gcm;
#[cfg(feature = "hmac")]
pub use hmac;
#[cfg(feature = "p384")]
pub use p384;
#[cfg(feature = "pqc_kyber")]
pub use pqc_kyber;
#[cfg(feature = "sha2")]
pub use sha2;

/*
TODO: wrangle the feature flags so we can provide the default set of crypto implementations below.
use crate::application::{Settings, CryptoLayer};
#[cfg(feature = "default")]
pub trait CrateCryptoLayer {
    /// These are constants that can be redefined from their defaults to change rekey
    /// and negotiation timeout behavior. If two sides of a ZSSP session have different constants,
    /// the protocol will tend to default to the smaller constants.
    const SETTINGS: Settings = Settings::new_ms();

    /// A user-defined error returned when the `ApplicationLayer` fails to access persistent storage
    /// for a peer's ratchet states.
    type StorageError: std::error::Error;

    /// An arbitrary opaque object for use by the application that is attached to each session.
    type SessionData;
}

use rand_core::OsRng;
#[cfg(feature = "default")]
impl<Crypto: CrateCryptoLayer> CryptoLayer for Crypto {
    type Rng = OsRng;
    type Prp = Aes256Crate;
    type Aead = AesGcmCrate;
    type Hash = Sha512Crate;
    type PublicKey = P384CratePublicKey;
    type KeyPair = P384CrateKeyPair;
    type Kem = RustKyber1024PrivateKey;

    type StorageError = Crypto::StorageError;

    type SessionData = Crypto::SessionData;
}
 */
