// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const AES_256_KEY_SIZE: usize = 32;
pub const AES_256_BLOCK_SIZE: usize = 16;
pub const AES_GCM_TAG_SIZE: usize = 16;
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// A trait for encrypting individual blocks of plaintext using AES-256.
/// It is used for header authentication, for which we have a standard model proof that our
/// algorithm is secure.
///
/// Instances must securely delete their keys when dropped or reset.
pub trait Aes256Enc: Send + Sync {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self;

    /// Change the encryption key to `key` so that all future encryption is performed with it.
    /// This function is very rarely called so it does not have to be particularly efficient.
    fn reset(&mut self, key: &[u8; AES_256_KEY_SIZE]);

    /// Decrypt the given `block` of plaintext directly using the AES block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The ciphertext should be written directly back out to `block`.
    fn encrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]);
}

/// A trait for decrypting individual blocks of plaintext using AES-256.
///
/// Instances must securely delete their keys when dropped or reset.
pub trait Aes256Dec: Send + Sync {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self;

    /// Change the decryption key to `key` so that all future decryption is performed with it.
    /// This function is very rarely called so it does not have to be particularly efficient.
    fn reset(&mut self, key: &[u8; AES_256_KEY_SIZE]);

    /// Decrypt the given `block` of ciphertext directly using the AES 256 block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The plaintext should be written directly back out to `block`.
    fn decrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]);
}

pub trait AesGcmEncContext {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]);

    fn finish(&mut self) -> [u8; AES_GCM_TAG_SIZE];
}

pub trait AesGcmDecContext {
    fn decrypt_in_place(&mut self, data: &mut [u8]);

    #[must_use]
    fn finish(&mut self, tag: &[u8; AES_GCM_TAG_SIZE]) -> bool;
}

pub trait HighThroughputAesGcmPool: Send + Sync {
    type EncContext<'a>: AesGcmEncContext
    where
        Self: 'a;
    type DecContext<'a>: AesGcmDecContext
    where
        Self: 'a;

    fn new(encrypt_key: &[u8; AES_256_KEY_SIZE], decrypt_key: &[u8; AES_256_KEY_SIZE]) -> Self;

    fn start_enc<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> Self::EncContext<'a>;
    fn start_dec<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> Self::DecContext<'a>;
}

pub trait LowThroughputAesGcm {
    fn encrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; AES_GCM_TAG_SIZE];
    #[must_use]
    fn decrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; AES_GCM_TAG_SIZE],
    ) -> bool;
}
