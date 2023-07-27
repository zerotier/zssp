use aes::Aes256Enc;
use aes::cipher::{BlockEncrypt, KeyInit};

use crate::crypto::aes::{AesEnc, AES_256_KEY_SIZE, AES_256_BLOCK_SIZE};




impl AesEnc for Aes256Enc {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        Aes256Enc::new_from_slice(key).unwrap()
    }

    fn encrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]) {
        self.encrypt_block(block.into())
    }
}
