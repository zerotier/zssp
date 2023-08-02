pub const AES_256_BLOCK_SIZE: usize = 16;
pub const AES_256_KEY_SIZE: usize = 32;
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const AES_GCM_IV_SIZE: usize = 12;

/// A trait for encrypting individual blocks of plaintext using AES-256.
/// It is used for header authentication, for which we have a standard model proof that our
/// algorithm is secure.
pub trait PrpAes256 {
    /// Decrypt the given `block` of plaintext directly using the AES block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The ciphertext should be written directly back out to `block`.
    fn encrypt_in_place(key: &[u8; AES_256_KEY_SIZE], block: &mut [u8; AES_256_BLOCK_SIZE]);
    /// Decrypt the given `block` of ciphertext directly using the AES 256 block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The plaintext should be written directly back out to `block`.
    fn decrypt_in_place(key: &[u8; AES_256_KEY_SIZE], block: &mut [u8; AES_256_BLOCK_SIZE]);
}

pub trait AeadAesGcm {
    fn encrypt_in_place(key: &[u8; AES_256_KEY_SIZE], iv: [u8; AES_GCM_IV_SIZE], aad: Option<&[u8]>, buffer: &mut [u8]) -> [u8; AES_GCM_TAG_SIZE];
    fn decrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        iv: [u8; AES_GCM_IV_SIZE],
        aad: Option<&[u8]>,
        buffer: &mut [u8],
        tag: [u8; AES_GCM_TAG_SIZE],
    ) -> bool;
}
