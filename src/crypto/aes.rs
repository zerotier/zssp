// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const AES_256_BLOCK_SIZE: usize = 16;
pub const AES_256_KEY_SIZE: usize = 32;

pub trait AesEnc: Send + Sync {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self;

    fn reset(&self, key: &[u8; AES_256_KEY_SIZE]);

    fn encrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]);
}

pub trait AesDec: Send + Sync {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self;

    fn reset(&self, key: &[u8; AES_256_KEY_SIZE]);

    fn decrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]);
}
