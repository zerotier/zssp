use rand_core::{CryptoRng, RngCore};

pub const KYBER_PUBLIC_KEY_SIZE: usize = 1568;
pub const KYBER_CIPHERTEXT_SIZE: usize = 1568;
pub const KYBER_PLAINTEXT_SIZE: usize = 32;

/// Instances must securely delete the private key when dropped.
pub trait PrivateKeyKyber1024<Rng: RngCore + CryptoRng>: Sized + Send + Sync {
    fn generate(rng: &mut Rng) -> (Self, [u8; KYBER_PUBLIC_KEY_SIZE]);

    fn encapsulate(rng: &mut Rng, public_key: &[u8; KYBER_PUBLIC_KEY_SIZE]) -> Option<([u8; KYBER_CIPHERTEXT_SIZE], [u8; KYBER_PLAINTEXT_SIZE])>;

    fn decapsulate(&self, ciphertext: &[u8; KYBER_CIPHERTEXT_SIZE]) -> Option<[u8; KYBER_PLAINTEXT_SIZE]>;
}
