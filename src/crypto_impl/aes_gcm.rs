use aes_gcm::{
    aead::{Aead, AeadCore, KeyInit, OsRng},
    Aes256Gcm, Nonce, Key, KeySizeUser, TagSize // Or `Aes128Gcm`
};

use crate::crypto::aes_gcm::{AesGcmEnc, AES_GCM_KEY_SIZE, AES_GCM_IV_SIZE, AES_GCM_TAG_SIZE};



impl AesGcmEnc for Aes256Gcm {
    fn new(key: &[u8; AES_GCM_KEY_SIZE]) -> Self {
        let key = Key::<Aes256Gcm>::from_slice(key);
        <Aes256Gcm as KeyInit>::new(key)
    }

    fn set_iv(&mut self, iv: &[u8; AES_GCM_IV_SIZE]) {
        todo!()
    }

    fn set_aad(&mut self, aad: &[u8]) {
        todo!()
    }

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        todo!()
    }

    fn encrypt_in_place(&mut self, data: &mut [u8]) {
        todo!()
    }

    fn finish_encrypt(&mut self, output: &mut [u8; AES_GCM_TAG_SIZE]) {
        todo!()
    }
}
