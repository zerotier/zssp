use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::*;

pub type PqcKyberSecretKey = Zeroizing<[u8; pqc_kyber::KYBER_SECRETKEYBYTES]>;

impl<Rng: RngCore + CryptoRng> PrivateKeyKyber1024<Rng> for PqcKyberSecretKey {
    fn generate(rng: &mut Rng) -> (Self, [u8; KYBER_PUBLIC_KEY_SIZE]) {
        let keypair = pqc_kyber::keypair(rng);
        (Zeroizing::new(keypair.secret), keypair.public)
    }

    fn encapsulate(rng: &mut Rng, public_key: &[u8; KYBER_PUBLIC_KEY_SIZE]) -> Option<([u8; KYBER_CIPHERTEXT_SIZE], [u8; KYBER_PLAINTEXT_SIZE])> {
        pqc_kyber::encapsulate(public_key, rng).ok()
    }

    fn decapsulate(&self, ciphertext: &[u8; KYBER_CIPHERTEXT_SIZE]) -> Option<[u8; KYBER_PLAINTEXT_SIZE]> {
        pqc_kyber::decapsulate(ciphertext, self.as_ref()).ok()
    }
}
