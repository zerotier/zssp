use p384::{NistP384, EncodedPoint};
use p384::elliptic_curve::{PublicKey, SecretKey};
use p384::ecdh::EphemeralSecret;
use rand_core::OsRng;

use crate::crypto::p384::{P384PublicKey, P384_PUBLIC_KEY_SIZE, P384KeyPair, P384_ECDH_SHARED_SECRET_SIZE};



impl P384PublicKey for p384::PublicKey {
    fn from_bytes(raw_key: &[u8; P384_PUBLIC_KEY_SIZE]) -> Option<Self> {
        ///
        Some(p384::PublicKey::from_sec1_bytes(raw_key).unwrap())
    }

    fn to_bytes(&self, output: &mut [u8; P384_PUBLIC_KEY_SIZE]) {
        output.copy_from_slice(&self.to_sec1_bytes())
    }
}


impl P384KeyPair for EphemeralSecret {
    type PublicKey = p384::PublicKey;
    type Rng = OsRng;

    fn generate(rng: &mut Self::Rng) -> Self {
        EphemeralSecret::random(rng)
    }

    fn public_key_bytes(&self, output: &mut [u8; P384_PUBLIC_KEY_SIZE]) {
        output.copy_from_slice(&self.public_key().to_sec1_bytes())
    }

    fn agree(&self, other_public: &Self::PublicKey, output: &mut [u8; P384_ECDH_SHARED_SECRET_SIZE]) -> bool {
        output.copy_from_slice(self.diffie_hellman(other_public).raw_secret_bytes());
        true
    }
}
