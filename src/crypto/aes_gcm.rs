// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const AES_GCM_TAG_SIZE: usize = 16;
pub const AES_GCM_IV_SIZE: usize = 12;
pub const AES_GCM_KEY_SIZE: usize = super::aes::AES_256_KEY_SIZE;

/// The order of calls to this trait is always
/// `set_iv` -> `set_aad` -> `encrypt` -> `finish_encrypt`.
/// `set_aad` and `encrypt` may not always be called. `encrypt_in_place` may be called instead of
/// `encrypt`. `encrypt` may be called multiple times, it should start encryption of the input at the point in
/// the keystream where encryption previously ended.
/// An instance of this trait may be reused multiple times, each reuse should use the same key.
/// If it is reused, `set_iv` will always be the very next call after `finish_encrypt`.
///
/// Implementations of this trait do not have to be Send + Sync,
/// but if instances are wrapped in a `Mutex` they must satisfy the requirements of Send + Sync.
///
/// Instances must securely delete their keys when dropped.
pub trait AesGcmEnc {
    fn new(key: &[u8; AES_GCM_KEY_SIZE]) -> Self;

    fn set_iv(&mut self, iv: &[u8; AES_GCM_IV_SIZE]);

    fn set_aad(&mut self, aad: &[u8]);

    fn encrypt(&mut self, input: &[u8], output: &mut [u8]);

    fn encrypt_in_place(&mut self, data: &mut [u8]);

    fn finish_encrypt(&mut self, output: &mut [u8; AES_GCM_TAG_SIZE]);
}

/// The order of calls to this trait is always
/// `set_iv` -> `set_aad` -> `decrypt` -> `finish_decrypt`.
/// `set_aad` and `decrypt` may not always be called. `decrypt_in_place` may be called instead of
/// `decrypt`. `decrypt` may be called multiple times, it should start decryption of the input at the point in
/// the keystream where decryption previously ended.
/// An instance of this trait may be reused multiple times, each reuse should use the same key.
/// If it is reused, `set_iv` will always be the very next call after `finish_decrypt`.
///
/// Implementations of this trait do not have to be Send + Sync,
/// but if instances are wrapped in a `Mutex` they must satisfy the requirements of Send + Sync.
///
/// Instances must securely delete their keys when dropped.
pub trait AesGcmDec {
    fn new(key: &[u8; AES_GCM_KEY_SIZE]) -> Self;

    fn set_iv(&mut self, iv: &[u8; AES_GCM_IV_SIZE]);

    fn set_aad(&mut self, aad: &[u8]);

    fn decrypt(&mut self, input: &[u8], output: &mut [u8]);

    fn decrypt_in_place(&mut self, data: &mut [u8]);

    fn finish_decrypt(&mut self, expected_tag: &[u8; AES_GCM_TAG_SIZE]) -> bool;
}
