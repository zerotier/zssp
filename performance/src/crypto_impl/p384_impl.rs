use p384::{ecdh::EphemeralSecret, CompressedPoint, PublicKey};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::*;

/// An alias for the P384PublicKey type from the p384 crate.
pub type CrateP384PublicKey = PublicKey;
impl P384PublicKey for CrateP384PublicKey {
    fn from_bytes(raw_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> Option<Self> {
        PublicKey::from_sec1_bytes(raw_key).ok()
    }

    fn to_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE] {
        let k = CompressedPoint::from(self);
        k.as_slice().try_into().unwrap()
    }
}

/// An alias for the P384KeyPair type from the p384 crate.
pub type CrateP384KeyPair = EphemeralSecret;
impl<Rng: RngCore + CryptoRng> P384KeyPair<Rng> for CrateP384KeyPair {
    type PublicKey = PublicKey;

    fn generate(rng: &mut Rng) -> Self {
        EphemeralSecret::random(rng)
    }

    fn public_key_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE] {
        CompressedPoint::from(self.public_key()).as_slice().try_into().unwrap()
    }

    fn agree(&self, public_key: &Self::PublicKey, output: &mut [u8; P384_ECDH_SHARED_SECRET_SIZE]) {
        *output = self
            .diffie_hellman(public_key)
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();
    }
}
