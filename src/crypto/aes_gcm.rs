// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const AES_GCM_TAG_SIZE: usize = 16;
pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_KEY_SIZE: usize = super::aes::AES_256_KEY_SIZE;

/// Implementations of this trait does not have to be Send + Sync,
/// but if it is wrapped in a `Mutex` it must satisfy the requirements of Send + Sync.
pub trait AesGcmEnc {
    fn new(key: &[u8; AES_GCM_KEY_SIZE]) -> Self;

    fn set_iv(&mut self, iv: &[u8; AES_GCM_IV_SIZE]);

    fn set_aad(&mut self, aad: &[u8]);

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]);

    fn encrypt_in_place(&mut self, data: &mut [u8]);

    fn finish_encrypt(&mut self, output: &mut [u8; AES_GCM_TAG_SIZE]);
}

/// Implementations of this trait does not have to be Send + Sync,
/// but if it is wrapped in a `Mutex` it must satisfy the requirements of Send + Sync.
pub trait AesGcmDec {
    fn new(key: &[u8; AES_GCM_KEY_SIZE]) -> Self;

    fn set_iv(&mut self, iv: &[u8; AES_GCM_IV_SIZE]);

    fn set_aad(&mut self, aad: &[u8]);

    fn decrypt(&mut self, input: &[u8], output: &mut [u8]);

    fn decrypt_in_place(&mut self, data: &mut [u8]);

    fn finish_decrypt(&mut self, expected_tag: &[u8; AES_GCM_TAG_SIZE]) -> bool;
}
