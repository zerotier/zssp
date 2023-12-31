use aes::cipher::{generic_array::GenericArray, BlockDecrypt, BlockEncrypt, KeyInit};
use aes::Aes256;
use aes_gcm::aead::AeadMutInPlace;
use aes_gcm::{Aes256Gcm, Key, Nonce, Tag};

use crate::crypto::*;

/// The version and type of the aes crate that the `Aes256Prp` trait is implemented for.
pub type Aes256Crate = Aes256;
impl Aes256Prp for Aes256Crate {
    fn encrypt_in_place(key: &[u8; AES_256_KEY_SIZE], block: &mut [u8; AES_256_BLOCK_SIZE]) {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        cipher.encrypt_block(GenericArray::from_mut_slice(block));
    }

    fn decrypt_in_place(key: &[u8; AES_256_KEY_SIZE], block: &mut [u8; AES_256_BLOCK_SIZE]) {
        let cipher = Aes256::new(GenericArray::from_slice(key));
        cipher.decrypt_block(GenericArray::from_mut_slice(block));
    }
}

/// The version and type of the aes-gcm crate that the `Aes256Gcm` trait is implemented for.
pub type AesGcmCrate = Aes256Gcm;
impl AesGcmAead for AesGcmCrate {
    fn encrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        iv: &[u8; AES_GCM_NONCE_SIZE],
        aad: Option<&[u8]>,
        buffer: &mut [u8],
    ) -> [u8; AES_GCM_TAG_SIZE] {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let mut cipher = Aes256Gcm::new(key);
        cipher
            .encrypt_in_place_detached(Nonce::from_slice(iv), aad.unwrap_or(&[]), buffer)
            .unwrap()
            .try_into()
            .unwrap()
    }

    fn decrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        iv: &[u8; AES_GCM_NONCE_SIZE],
        aad: Option<&[u8]>,
        buffer: &mut [u8],
        tag: &[u8; AES_GCM_TAG_SIZE],
    ) -> bool {
        let key = Key::<Aes256Gcm>::from_slice(key);
        let mut cipher = Aes256Gcm::new(key);
        cipher
            .decrypt_in_place_detached(Nonce::from_slice(iv), aad.unwrap_or(&[]), buffer, Tag::from_slice(tag))
            .is_ok()
    }
}
