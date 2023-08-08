/// The size of an AES block, which is 16 bytes, or 128 bits.
pub const AES_256_BLOCK_SIZE: usize = 16;
/// The size of an AES-256 key, which is 32 bytes, or 256 bits.
pub const AES_256_KEY_SIZE: usize = 32;
/// The size of an AES-GCM authentication tag, which is 16 bytes, or 128 bits.
/// Some implementations of AES-GCM allow use of smaller tags, but ZSSP will only accept 16 byte tags.
pub const AES_GCM_TAG_SIZE: usize = 16;
/// The size of an AES-GCM IV, or nonce, which is 12 bytes, or 96 bits.
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// A trait for encrypting individual blocks of plaintext using AES-256.
/// It is used for header authentication, for which we have a standard model proof that our
/// algorithm is secure.
pub trait Aes256Prp {
    /// Encrypt the given `block` of plaintext directly using the AES block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The ciphertext should be written directly back to `block`.
    fn encrypt_in_place(key: &[u8; AES_256_KEY_SIZE], block: &mut [u8; AES_256_BLOCK_SIZE]);
    /// Decrypt the given `block` of ciphertext directly using the AES 256 block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The plaintext should be written directly back to `block`.
    fn decrypt_in_place(key: &[u8; AES_256_KEY_SIZE], block: &mut [u8; AES_256_BLOCK_SIZE]);
}

/// A trait accessing AES-GCM-256 encryption and decryption as a set of pure-functions.
/// These should be trivial to implement for most implementations of AES-GCM.
pub trait AesGcmAead {
    /// Encrypt the given `buffer` of plaintext using AES-GCM-256, with the given `key`, `iv` and `aad`.
    /// The ciphertext should be written directly back to `buffer`, and the GCM tag should be returned.
    fn encrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: Option<&[u8]>,
        buffer: &mut [u8],
    ) -> [u8; AES_GCM_TAG_SIZE];
    /// Decrypt the given `buffer` of ciphertext using AES-GCM-256, with the given `key`, `iv` and `aad`.
    /// The ciphertext should be written directly back to `buffer`, and the GCM tag should be returned.
    fn decrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: Option<&[u8]>,
        buffer: &mut [u8],
        tag: &[u8; AES_GCM_TAG_SIZE],
    ) -> bool;
}
