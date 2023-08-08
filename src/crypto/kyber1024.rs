use rand_core::{CryptoRng, RngCore};

/// The size of a Kyber1024 public key, which is 1568 bytes.
pub const KYBER_PUBLIC_KEY_SIZE: usize = 1568;
/// The size of a Kyber1024 KEM ciphertext, which is 1568 bytes.
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568;
/// The size of a Kyber1024 KEM plaintext, which is 32 bytes.
pub const KYBER_PLAINTEXT_SIZE: usize = 32;

/// Instances must securely delete the private key when dropped.
pub trait Kyber1024PrivateKey<Rng: RngCore + CryptoRng>: Sized + Send + Sync {
    /// Generate a Kyber1024 private key and public key pair, and return the raw bytes of the public
    /// key.
    /// The private key will be temporarily held in memory but the public key will be immediately
    /// sent to the remote peer.
    ///
    /// This function may use the provided RNG or its own, so long as the output is cryptographically random.
    fn generate(rng: &mut Rng) -> (Self, [u8; KYBER_PUBLIC_KEY_SIZE]);
    /// Generate a Kyber1024 key encapsulation based on the given `public_key`, and return the
    /// raw bytes of the generated ciphertext and plaintext. The ciphertext is immediately sent to
    /// the remote peer and the plaintext is immediately hashed, both are quickly deleted.
    ///
    /// This function may use the provided RNG or its own, so long as the output is cryptographically random.
    ///
    /// **CRITICAL**: This must return `None` if the given `public_key` is invalid in any way
    /// according to the Kyber1024 spec.
    #[must_use]
    fn encapsulate(
        rng: &mut Rng,
        public_key: &[u8; KYBER_PUBLIC_KEY_SIZE],
        plaintext_out: &mut [u8; KYBER_PLAINTEXT_SIZE],
    ) -> Option<[u8; KYBER_CIPHERTEXT_SIZE]>;
    /// Decapsulate a Kyber1024 `ciphertext` received from the remote peer, retreiving
    /// the raw bytes of the original plaintext. This plaintext is immediately hashed and deleted.
    ///
    /// **CRITICAL**: This must return `None` if the given `ciphertext` is invalid in any way
    /// according to the Kyber1024 spec.
    #[must_use]
    fn decapsulate(
        &self,
        ciphertext: &[u8; KYBER_CIPHERTEXT_SIZE],
        plaintext_out: &mut [u8; KYBER_PLAINTEXT_SIZE],
    ) -> bool;
}
