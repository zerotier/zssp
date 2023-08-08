use rand_core::{CryptoRng, RngCore};
use zeroize::Zeroizing;

use crate::crypto::*;

/// A wrapper for a buffer the size of a pqc_kyber secret key.
/// The crate `pqc_kyber` is low level and operates directly on buffers of bytes.
pub type RustKyber1024PrivateKey = Zeroizing<[u8; pqc_kyber::KYBER_SECRETKEYBYTES]>;
impl<Rng: RngCore + CryptoRng> Kyber1024PrivateKey<Rng> for RustKyber1024PrivateKey {
    fn generate(rng: &mut Rng) -> (Self, [u8; KYBER_PUBLIC_KEY_SIZE]) {
        let keypair = pqc_kyber::keypair(rng);
        (Zeroizing::new(keypair.secret), keypair.public)
    }

    fn encapsulate(
        rng: &mut Rng,
        public_key: &[u8; KYBER_PUBLIC_KEY_SIZE],
        plaintext_out: &mut [u8; KYBER_PLAINTEXT_SIZE],
    ) -> Option<[u8; KYBER_CIPHERTEXT_SIZE]> {
        let ret;
        (ret, *plaintext_out) = pqc_kyber::encapsulate(public_key, rng).ok()?;
        Some(ret)
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8; KYBER_CIPHERTEXT_SIZE],
        plaintext_out: &mut [u8; KYBER_PLAINTEXT_SIZE],
    ) -> bool {
        if let Ok(result) = pqc_kyber::decapsulate(ciphertext, self.as_ref()) {
            *plaintext_out = result;
            true
        } else {
            false
        }
    }
}
