#[cfg(feature = "pqc_kyber")]
mod kyber1024;
#[cfg(feature = "pqc_kyber")]
pub use kyber1024::*;
#[cfg(feature = "pqc_kyber")]
pub use pqc_kyber;

#[cfg(feature = "p384")]
mod p384_impl;
#[cfg(feature = "p384")]
pub use p384;
#[cfg(feature = "p384")]
pub use p384_impl::*;

#[cfg(feature = "sha2")]
mod sha512;
#[cfg(feature = "sha2")]
pub use hmac;
#[cfg(feature = "sha2")]
pub use sha2;
#[cfg(feature = "sha2")]
pub use sha512::*;

#[cfg(feature = "openssl-sys")]
mod openssl;
#[cfg(feature = "openssl-sys")]
pub use openssl::*;
#[cfg(feature = "openssl-sys")]
pub use openssl_sys;

#[cfg(feature = "default-crypto")]
pub trait DefaultCrypto {
    type SessionData;
    type IncomingPacketBuffer: AsMut<[u8]> + AsRef<[u8]>;
}
#[cfg(feature = "default-crypto")]
impl<C: DefaultCrypto> crate::application::CryptoLayer for C {
    type Rng = rand_core::OsRng;
    type PrpEnc = Aes256OpenSSLEnc;
    type PrpDec = Aes256OpenSSLDec;
    type Aead = AesGcmOpenSSL;
    type AeadPool = AesGcmOpenSSLPool;
    type Hash = Sha512Crate;
    type Hmac = HmacSha512Crate;
    type PublicKey = P384CratePublicKey;
    type KeyPair = P384CrateKeyPair;
    type Kem = Kyber1024CratePrivateKey;

    type SessionData = C::SessionData;
    type IncomingPacketBuffer = C::IncomingPacketBuffer;
}
