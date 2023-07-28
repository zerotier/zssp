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
pub trait AesGcmAead {
    fn encrypt_in_place(key: &[u8; AES_GCM_KEY_SIZE], iv: [u8; AES_GCM_IV_SIZE], aad: Option<&[u8]>, buffer: &mut [u8]) -> [u8; AES_GCM_TAG_SIZE];
    fn decrypt_in_place(
        key: &[u8; AES_GCM_KEY_SIZE],
        iv: [u8; AES_GCM_IV_SIZE],
        aad: Option<&[u8]>,
        buffer: &mut [u8],
        tag: [u8; AES_GCM_TAG_SIZE],
    ) -> bool;
}
