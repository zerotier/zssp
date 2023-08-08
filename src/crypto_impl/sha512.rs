use hmac::{Hmac, Mac};
use sha2::{Digest, Sha512};

use crate::crypto::*;

pub type RustSha512 = Sha512;
impl Sha512Hash for RustSha512 {
    fn new() -> Self {
        Digest::new()
    }

    fn update(&mut self, data: &[u8]) {
        Digest::update(self, data)
    }

    fn finish_and_reset(&mut self, output: &mut [u8; SHA512_HASH_SIZE]) {
        let mut hasher = Digest::new();
        std::mem::swap(self, &mut hasher);
        *output = hasher.finalize().into();
    }
}

pub struct RustHmac;
impl Sha512Hmac for RustHmac {
    fn new() -> Self {
        RustHmac
    }

    fn hash(&mut self, key: &[u8], full_input: &[u8], output: &mut [u8; SHA512_HASH_SIZE]) {
        let mut hm = Hmac::<Sha512>::new_from_slice(key).unwrap();
        hm.update(full_input);
        *output = hm.finalize().into_bytes().into()
    }
}
