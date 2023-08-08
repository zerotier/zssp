use rand_core::{CryptoRng, RngCore};

/// The size in bytes of a P-384 public key when in compressed SEC1-encoded format.
pub const P384_PUBLIC_KEY_SIZE: usize = 49;
/// The size in bytes of the raw output of ECDH between a P-384 public and private key.
pub const P384_ECDH_SHARED_SECRET_SIZE: usize = 48;

/// A NIST P-384 ECDH/ECDSA public key.
pub trait P384PublicKey: Sized + Send + Sync {
    /// Create a P-384 public key from raw bytes.
    ///
    /// **CRITICAL**: This function must return `None` if the input `raw_key` is not on the P-384
    /// curve, or if it breaks the P-384 spec in any other way.
    fn from_bytes(raw_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> Option<Self>;

    /// Get the raw bytes that uniquely define the public key.
    ///
    /// This must output the compressed SEC1 NIST encoding of P-384 public keys.
    fn to_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE];
}

/// A NIST P-384 ECDH/ECDSA public/private key pair.
///
/// Instances must securely delete the private key when dropped.
pub trait P384KeyPair<Rng: RngCore + CryptoRng> {
    /// The `PublicKeyP384` implementation which matches this `KeyPairP384` implementation.
    type PublicKey: P384PublicKey;
    /// Randomly generate a new P-384 keypair.
    ///
    /// This function may use the provided RNG or its own, so long as the output is cryptographically random.
    fn generate(rng: &mut Rng) -> Self;

    /// Get the raw bytes that uniquely define the public key.
    ///
    /// This must output the compressed SEC1 NIST encoding of P-384 public keys.
    fn public_key_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE];

    /// Perform ECDH key agreement, writing the raw (un-hashed!) ECDH secret to `output`.
    ///
    /// **CRITICAL**: This function must return `None` if key agreement between this private key and
    /// the input `public_key` key would result in an invalid, non-standard or predictable ECDH secret.
    /// Please refer to the NIST spec for P-384 ECDH key agreement, or better yet use a peer reviewed
    /// library that has already implemented this correctly.
    fn agree(&self, public_key: &Self::PublicKey) -> Option<[u8; P384_ECDH_SHARED_SECRET_SIZE]>;
}
