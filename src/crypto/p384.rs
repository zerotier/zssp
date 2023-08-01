// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.
use rand_core::{CryptoRng, RngCore};

pub const P384_PUBLIC_KEY_SIZE: usize = 49;
pub const P384_ECDH_SHARED_SECRET_SIZE: usize = 48;

/// A NIST P-384 ECDH/ECDSA public key.
pub trait PublicKeyP384: Sized + Send + Sync {
    /// Create a p384 public key from raw bytes.
    ///
    /// **CRITICAL**: This function must return `None` if the input `raw_key` is not on the P384 curve,
    /// or if it breaks the P384 standard in any other way.
    fn from_bytes(raw_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> Option<Self>;

    /// Get the raw bytes that uniquely define the public key.
    ///
    /// This must output the standard 49 byte NIST encoding of P384 public keys.
    fn to_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE];
}

/// A NIST P-384 ECDH/ECDSA public/private key pair.
///
/// Instances must securely delete the private key when dropped.
pub trait KeyPairP384<Rng: RngCore + CryptoRng>: Send + Sync {
    type PublicKey: PublicKeyP384;
    /// Randomly generate a new p384 keypair.
    /// This function may use the provided RNG or it's own,
    /// so long as the produced keys are cryptographically random.
    fn generate(rng: &mut Rng) -> Self;

    /// Get the raw bytes that uniquely define the public key.
    ///
    /// This must output the standard 49 byte NIST encoding of P384 public keys.
    fn public_key_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE];

    /// Perform ECDH key agreement, writing the raw (un-hashed!) ECDH secret to `output`.
    ///
    /// **CRITICAL**: This function must return `Nonce` if key agreement between this private key and
    /// the input `public_key` key would result in an invalid, non-standard or predictable ECDH secret.
    /// Please refer to the NIST spec for P384 ECDH key agreement, or better yet use a peer reviewed
    /// library that has already implemented this correctly.
    fn agree(&self, public_key: &Self::PublicKey) -> Option<[u8; P384_ECDH_SHARED_SECRET_SIZE]>;
}
