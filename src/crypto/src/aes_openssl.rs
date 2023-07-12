// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

use std::{mem::MaybeUninit, ptr, sync::Mutex};

use crate::{cipher_ctx::CipherCtx, constant::*};

/// An OpenSSL AES_GCM context. Automatically frees itself on drop.
/// The current interface is custom made for ZeroTier, but could easily be adapted for other uses.
/// Whether `ENCRYPT` is true or false decides respectively whether this context encrypts or decrypts.
/// Even though OpenSSL lets you set this dynamically almost no operations work when you do this
/// without resetting the context.
///
/// This object cannot be mutated by multiple threads at the same time so wrap it in a Mutex if
/// you need to do this. As far as I have read a Mutex<AesGcm> can safely implement Send and Sync.
pub struct AesGcm<const ENCRYPT: bool>(CipherCtx);

impl<const ENCRYPT: bool> AesGcm<ENCRYPT> {
    /// Create an AesGcm context with the given key.
    /// OpenSSL internally processes and caches this key, so it is recommended to reuse this context whenever encrypting under the same key. Call `reset_init_gcm` to change the IV for each reuse.
    pub fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let ctx = CipherCtx::new().unwrap();
        unsafe {
            let t = ffi::EVP_aes_256_gcm();
            ctx.cipher_init::<ENCRYPT>(t, key.as_ptr(), ptr::null()).unwrap();
            ffi::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }

        AesGcm(ctx)
    }

    /// Set the IV of this AesGcm context. This call resets the IV but leaves the key and encryption algorithm alone.
    /// This method must be called before any other method on AesGcm.
    /// `iv` must be exactly 12 bytes in length, because that is what Aes supports.
    pub fn reset_init_gcm(&mut self, iv: &[u8]) {
        debug_assert_eq!(iv.len(), AES_GCM_NONCE_SIZE, "Aes IV must be 12 bytes long");
        unsafe {
            self.0.cipher_init::<ENCRYPT>(ptr::null(), ptr::null(), iv.as_ptr()).unwrap();
        }
    }

    /// Add additional authentication data to AesGcm (same operation with CTR mode).
    #[inline(always)]
    pub fn aad(&mut self, aad: &[u8]) {
        unsafe { self.0.update::<ENCRYPT>(aad, ptr::null_mut()).unwrap() };
    }

    /// Encrypt or decrypt (same operation with CTR mode)
    #[inline(always)]
    pub fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        debug_assert!(output.len() >= input.len(), "output buffer must fit the size of the input buffer");
        unsafe { self.0.update::<ENCRYPT>(input, output.as_mut_ptr()).unwrap() };
    }

    /// Encrypt or decrypt in place (same operation with CTR mode).
    #[inline(always)]
    pub fn crypt_in_place(&mut self, data: &mut [u8]) {
        let ptr = data.as_mut_ptr();
        unsafe { self.0.update::<ENCRYPT>(data, ptr).unwrap() }
    }
}
impl AesGcm<true> {
    /// Produce the gcm authentication tag.
    #[inline(always)]
    pub fn finish_encrypt(&mut self) -> [u8; AES_GCM_TAG_SIZE] {
        unsafe {
            let mut tag = MaybeUninit::<[u8; AES_GCM_TAG_SIZE]>::uninit();
            self.0.finalize::<true>(tag.as_mut_ptr().cast()).unwrap();
            self.0.tag(&mut *tag.as_mut_ptr()).unwrap();
            tag.assume_init()
        }
    }
}
impl AesGcm<false> {
    /// Check the gcm authentication tag. Outputs true if it matches the just decrypted message, outputs false otherwise.
    #[inline(always)]
    pub fn finish_decrypt(&mut self, expected_tag: &[u8]) -> bool {
        debug_assert_eq!(expected_tag.len(), AES_GCM_TAG_SIZE);
        if self.0.set_tag(expected_tag).is_ok() {
            unsafe { self.0.finalize::<false>(ptr::null_mut()).is_ok() }
        } else {
            false
        }
    }
}

/// An OpenSSL AES_ECB context. Automatically frees itself on drop.
/// AES_ECB is very insecure if used incorrectly so its public interface supports only exactly what
/// ZeroTier uses it for.
pub struct Aes<const ENCRYPT: bool>(Mutex<CipherCtx>);
unsafe impl<const ENCRYPT: bool> Send for Aes<ENCRYPT> {}
unsafe impl<const ENCRYPT: bool> Sync for Aes<ENCRYPT> {}

impl<const ENCRYPT: bool> Aes<ENCRYPT> {
    /// Create an AesEcb context with the given key.
    /// OpenSSL internally processes and caches this key, so it is recommended to reuse this context
    /// whenever encrypting under the same key.
    pub fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let ctx = CipherCtx::new().unwrap();
        unsafe {
            let t = ffi::EVP_aes_256_ecb();
            ctx.cipher_init::<ENCRYPT>(t, key.as_ptr(), ptr::null()).unwrap();
            ffi::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }

        Aes(Mutex::new(ctx))
    }
    pub fn reset(&self, key: &[u8; AES_256_KEY_SIZE]) {
        let ctx = self.0.lock().unwrap();
        unsafe {
            ctx.cipher_init::<ENCRYPT>(ptr::null(), key.as_ptr(), ptr::null()).unwrap();
        }
    }

    /// Do not ever encrypt the same plaintext twice. Make sure data is always different between calls.
    #[inline(always)]
    pub fn crypt_block_in_place(&self, data: &mut [u8]) {
        debug_assert_eq!(data.len(), AES_BLOCK_SIZE, "Incorrect Aes block size");
        let ptr = data.as_mut_ptr();
        let ctx = self.0.lock().unwrap();
        unsafe { ctx.update::<ENCRYPT>(data, ptr).unwrap() }
    }
}
