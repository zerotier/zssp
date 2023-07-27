use sha2::{Sha512, Digest};
use hmac::{Hmac, Mac};

use crate::crypto::sha512::{self, SHA512_HASH_SIZE};




impl sha512::Sha512 for Sha512 {
    fn new() -> Self {
        Digest::new()
    }

    fn update(&mut self, input: &[u8]) {
        Digest::update(self, input)
    }

    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]) {
        output.copy_from_slice(&self.finalize())
    }
}

pub type HmacSha512 = Hmac<Sha512>;
impl sha512::HmacSha512 for HmacSha512 {
    fn new(key: &[u8]) -> Self {
        HmacSha512::new_from_slice(key).unwrap()
    }

    fn update(&mut self, input: &[u8]) {
        Mac::update(self, input)
    }

    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]) {
        output.copy_from_slice(&self.finalize().into_bytes())
    }
}
