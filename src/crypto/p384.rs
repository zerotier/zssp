// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

use super::rand_core::{RngCore, CryptoRng};

pub const P384_PUBLIC_KEY_SIZE: usize = 49;
pub const P384_ECDH_SHARED_SECRET_SIZE: usize = 48;

/// A NIST P-384 ECDH/ECDSA public key.
pub trait P384PublicKey: Sized + Send + Sync {
    /// Create a p384 public key from raw bytes.
    fn from_bytes(raw_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> Option<Self>;

    /// Get the raw bytes that uniquely define the public key.
    fn as_bytes(&self) -> &[u8; P384_PUBLIC_KEY_SIZE];
}

/// A NIST P-384 ECDH/ECDSA public/private key pair.
pub trait P384KeyPair<PubKey: P384PublicKey, Rng: RngCore + CryptoRng>: Send + Sync {
    /// Randomly generate a new p384 keypair.
    /// This function may use the provided RNG or it's own, so long as the produced keys are
    /// cryptographically random.
    fn generate(rng: &mut Rng) -> Self;

    /// Get the raw bytes that uniquely define the public key.
    fn public_key_bytes(&self) -> &[u8; P384_PUBLIC_KEY_SIZE];

    /// Perform ECDH key agreement, returning the raw (un-hashed!) ECDH secret.
    fn agree(&self, other_public: &PubKey, output: &mut [u8; P384_ECDH_SHARED_SECRET_SIZE]) -> bool;
}
