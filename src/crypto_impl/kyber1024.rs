use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::*;

/// A wrapper for a buffer the size of a pqc_kyber secret key.
/// The crate `pqc_kyber` is low level and operates directly on buffers of bytes.
pub type PqcKyberSecretKey = Zeroizing<[u8; pqc_kyber::KYBER_SECRETKEYBYTES]>;

impl<Rng: RngCore + CryptoRng> Kyber1024PrivateKey<Rng> for PqcKyberSecretKey {
    fn generate(rng: &mut Rng) -> (Self, [u8; KYBER_PUBLIC_KEY_SIZE]) {
        let keypair = pqc_kyber::keypair(rng);
        (Zeroizing::new(keypair.secret), keypair.public)
    }

    fn encapsulate(
        rng: &mut Rng,
        public_key: &[u8; KYBER_PUBLIC_KEY_SIZE],
    ) -> Option<([u8; KYBER_CIPHERTEXT_SIZE], [u8; KYBER_PLAINTEXT_SIZE])> {
        pqc_kyber::encapsulate(public_key, rng).ok()
    }

    fn decapsulate(&self, ciphertext: &[u8; KYBER_CIPHERTEXT_SIZE]) -> Option<[u8; KYBER_PLAINTEXT_SIZE]> {
        pqc_kyber::decapsulate(ciphertext, self.as_ref()).ok()
    }
}
