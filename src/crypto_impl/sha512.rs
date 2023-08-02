use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

use crate::crypto::*;

impl HashSha512 for Sha512 {
    fn new() -> Self {
        Digest::new()
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data)
    }

    fn finish(self) -> [u8; SHA512_HASH_SIZE] {
        self.finalize().into()
    }

    fn hmac(key: &[u8], data: &[u8]) -> [u8; SHA512_HASH_SIZE] {
        let mut hm = Hmac::<Sha512>::new_from_slice(key).unwrap();
        hm.update(data);
        hm.finalize().into_bytes().into()
    }
}
