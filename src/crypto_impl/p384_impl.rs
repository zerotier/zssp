use p384::{ecdh::EphemeralSecret, CompressedPoint, PublicKey};
use rand_core::{CryptoRng, RngCore};

use crate::crypto::*;

pub type P384CratePublicKey = PublicKey;
impl P384PublicKey for P384CratePublicKey {
    fn from_bytes(raw_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> Option<Self> {
        PublicKey::from_sec1_bytes(raw_key).ok()
    }

    fn to_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE] {
        let k = CompressedPoint::from(self);
        k.as_slice().try_into().unwrap()
    }
}

pub type P384CrateKeyPair = EphemeralSecret;
impl<Rng: RngCore + CryptoRng> P384KeyPair<Rng> for P384CrateKeyPair {
    type PublicKey = PublicKey;

    fn generate(rng: &mut Rng) -> Self {
        EphemeralSecret::random(rng)
    }

    fn public_key_bytes(&self) -> [u8; P384_PUBLIC_KEY_SIZE] {
        CompressedPoint::from(self.public_key()).as_slice().try_into().unwrap()
    }

    fn agree(&self, public_key: &Self::PublicKey, output: &mut [u8; P384_ECDH_SHARED_SECRET_SIZE]) -> bool {
        *output = self
            .diffie_hellman(public_key)
            .raw_secret_bytes()
            .as_slice()
            .try_into()
            .unwrap();
        true
    }
}
