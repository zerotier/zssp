use std::{
    ptr::{self, NonNull},
    sync::Mutex,
};

use arrayvec::ArrayVec;
use openssl_sys::*;
use zeroize::Zeroizing;

use crate::crypto::*;

/// A wrapper for a `EVP_CIPHER_CTX` that will free itself on drop.
/// Users are encouraged to not use one of these directly.
pub struct OpenSSLCtx(NonNull<openssl_sys::EVP_CIPHER_CTX>);
impl Drop for OpenSSLCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_CTX_free(self.0.as_ptr());
        }
    }
}
impl OpenSSLCtx {
    /// Creates a new context.
    pub fn new() -> Option<Self> {
        unsafe { Some(OpenSSLCtx(NonNull::new(EVP_CIPHER_CTX_new())?)) }
    }

    /// Initialize a cipher context for encryption or decryption using the specified `key` and `iv`.
    /// If `key` is null then the previous key assigned to this context will be used.
    pub unsafe fn cipher_init<const ENCRYPT: bool>(
        &self,
        t: *const openssl_sys::EVP_CIPHER,
        key: *const u8,
        iv: *const u8,
    ) -> bool {
        let evp_f = if ENCRYPT {
            EVP_EncryptInit_ex
        } else {
            EVP_DecryptInit_ex
        };

        // OpenSSL will usually leak a static amount of memory per cipher given here.
        evp_f(self.0.as_ptr(), t, ptr::null_mut(), key, iv) > 0
    }
    /// Stream a portion of text to be encrypted or decrypted.
    /// `input` will be the input to the cipher stream, and the resulting plaintext or ciphertext
    /// will be written to output. Both buffers must be of size `len`.
    ///
    /// If `output == input`, then the operation will be performed "in-place".
    /// `output` and `input` must not overlap otherwise.
    ///
    /// If `output` is null, then `input` will be treated as AAD rather than plaintext or ciphertext.
    /// `input` must not be null.
    pub unsafe fn update<const ENCRYPT: bool>(&self, input: &[u8], output: *mut u8) -> bool {
        let evp_f = if ENCRYPT {
            EVP_EncryptUpdate
        } else {
            EVP_DecryptUpdate
        };

        let mut outlen = 0;

        evp_f(
            self.0.as_ptr(),
            output,
            &mut outlen,
            input.as_ptr(),
            input.len() as c_int,
        ) > 0
    }


    /// Finish encryption or decryption.
    /// If performing decryption this will return whether the set tag is correct.
    pub unsafe fn finalize<const ENCRYPT: bool>(&self) -> bool {
        let evp_f = if ENCRYPT {
            EVP_EncryptFinal_ex
        } else {
            EVP_DecryptFinal_ex
        };
        let mut outl = 0;

        evp_f(self.0.as_ptr(), ptr::null_mut(), &mut outl) > 0
    }

    /// Retreive the authentication tag from this context.
    /// This must be called after `finalize` is called.
    pub unsafe fn get_tag(&self, tag: &mut [u8]) -> bool {
        EVP_CIPHER_CTX_ctrl(
            self.0.as_ptr(),
            openssl_sys::EVP_CTRL_GCM_GET_TAG,
            tag.len() as c_int,
            tag.as_mut_ptr() as *mut _,
        ) > 0
    }

    /// Set the authentication tag that was assigned to the input ciphertext.
    /// Once set, OpenSLL will check whether it matches the expected authentication tag
    /// produced by decryption.
    #[allow(unused)]
    pub unsafe fn set_tag(&self, tag: &[u8]) -> bool {
        EVP_CIPHER_CTX_ctrl(
            self.0.as_ptr(),
            openssl_sys::EVP_CTRL_GCM_SET_TAG,
            tag.len() as c_int,
            tag.as_ptr() as *mut _,
        ) > 0
    }
    /// Returns the raw pointer to the `EVP_CIPHER_CTX`
    /// object used internally with OpenSSL.
    ///
    /// This function is guaranteed to return a non-null pointer.
    pub fn as_ptr(&self) -> *mut openssl_sys::EVP_CIPHER_CTX {
        self.0.as_ptr()
    }
}

/// An `OpenSSLCtx` wrapped in a mutex for thread-safety.
/// This `OpenSSLCtx` struct only supports AES256 block operations, and implements `OpenSSLAes256Enc`.
pub struct OpenSSLAes256Enc(Mutex<OpenSSLCtx>);
unsafe impl Send for OpenSSLAes256Enc {}
unsafe impl Sync for OpenSSLAes256Enc {}

impl Aes256Enc for OpenSSLAes256Enc {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let ctx = OpenSSLCtx::new().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_ecb();
            assert!(ctx.cipher_init::<true>(t, key.as_ptr(), ptr::null()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }
        Self(Mutex::new(ctx))
    }

    fn reset(&mut self, key: &[u8; AES_256_KEY_SIZE]) {
        let ctx = self.0.lock().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_ecb();
            assert!(ctx.cipher_init::<true>(t, key.as_ptr(), ptr::null()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }
    }

    fn encrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]) {
        let ptr = block.as_mut_ptr();
        let ctx = self.0.lock().unwrap();
        unsafe { assert!(ctx.update::<true>(block, ptr)) }
    }
}
/// An `OpenSSLCtx` wrapped in a mutex for thread-safety.
/// This `OpenSSLCtx` struct only supports AES256 block operations, and implements `OpenSSLAes256Dec`.
pub struct OpenSSLAes256Dec(Mutex<OpenSSLCtx>);
unsafe impl Send for OpenSSLAes256Dec {}
unsafe impl Sync for OpenSSLAes256Dec {}

impl Aes256Dec for OpenSSLAes256Dec {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let ctx = OpenSSLCtx::new().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_ecb();
            assert!(ctx.cipher_init::<false>(t, key.as_ptr(), ptr::null()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }
        Self(Mutex::new(ctx))
    }

    fn reset(&mut self, key: &[u8; AES_256_KEY_SIZE]) {
        let ctx = self.0.lock().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_ecb();
            assert!(ctx.cipher_init::<false>(t, key.as_ptr(), ptr::null()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }
    }

    fn decrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]) {
        let ptr = block.as_mut_ptr();
        let ctx = self.0.lock().unwrap();
        unsafe { assert!(ctx.update::<false>(block, ptr)) }
    }
}

/// A pool of OpenSSL AES-GCM ciphers.
pub struct OpenSSLAesGcmPool {
    enc: Mutex<ArrayVec<OpenSSLCtx, 8>>,
    dec: Mutex<ArrayVec<OpenSSLCtx, 8>>,
    enc_key: Zeroizing<[u8; AES_256_KEY_SIZE]>,
    dec_key: Zeroizing<[u8; AES_256_KEY_SIZE]>,
}
unsafe impl Send for OpenSSLAesGcmPool {}
unsafe impl Sync for OpenSSLAesGcmPool {}

impl HighThroughputAesGcmPool for OpenSSLAesGcmPool {
    type EncContext<'a> = OpenSSLCtx;

    type DecContext<'a> = OpenSSLCtx;

    fn new(encrypt_key: &[u8; AES_256_KEY_SIZE], decrypt_key: &[u8; AES_256_KEY_SIZE]) -> Self {
        Self {
            enc: Default::default(),
            dec: Default::default(),
            enc_key: Zeroizing::new(*encrypt_key),
            dec_key: Zeroizing::new(*decrypt_key),
        }
    }

    fn start_enc(&self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> OpenSSLCtx {
        let ctx = self.enc.lock().unwrap().pop();
        unsafe {
            if let Some(ctx) = ctx {
                assert!(ctx.cipher_init::<true>(ptr::null(), ptr::null(), nonce.as_ptr()));
                ctx
            } else {
                let ctx = OpenSSLCtx::new().unwrap();
                let t = openssl_sys::EVP_aes_256_gcm();
                assert!(ctx.cipher_init::<true>(t, self.enc_key.as_ptr(), nonce.as_ptr()));
                openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
                ctx
            }
        }
    }
    fn start_dec(&self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> OpenSSLCtx {
        let ctx = self.dec.lock().unwrap().pop();
        unsafe {
            if let Some(ctx) = ctx {
                assert!(ctx.cipher_init::<false>(ptr::null(), ptr::null(), nonce.as_ptr()));
                ctx
            } else {
                let ctx = OpenSSLCtx::new().unwrap();
                let t = openssl_sys::EVP_aes_256_gcm();
                assert!(ctx.cipher_init::<false>(t, self.dec_key.as_ptr(), nonce.as_ptr()));
                openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
                ctx
            }
        }
    }

    fn encrypt(&self, ctx: &mut OpenSSLCtx, input: &[u8], output: &mut [u8]) {
        unsafe { assert!(ctx.update::<true>(input, output.as_mut_ptr())) };
    }
    fn decrypt_in_place(&self, ctx: &mut OpenSSLCtx, data: &mut [u8]) {
        let p = data.as_mut_ptr();
        unsafe { assert!(ctx.update::<false>(data, p)) };
    }

    fn finish_enc(&self, ctx: OpenSSLCtx) -> [u8; AES_GCM_TAG_SIZE] {
        let mut output = [0u8; AES_GCM_TAG_SIZE];
        unsafe {
            assert!(ctx.finalize::<true>());
            assert!(ctx.get_tag(&mut output));
        }
        let _ = self.enc.lock().unwrap().try_push(ctx);
        output
    }
    fn finish_dec(&self, ctx: OpenSSLCtx, tag: &[u8; AES_GCM_TAG_SIZE]) -> bool {
        let output = unsafe { ctx.set_tag(tag) && ctx.finalize::<false>() };
        let _ = self.dec.lock().unwrap().try_push(ctx);
        output
    }
}
/// An empty struct which implements `LowThroughputAesGcm` using OpenSSL.
///
/// It is just a namespace and wrapper for OpenSSL.
pub struct OpenSSLAesGcm;
impl LowThroughputAesGcm for OpenSSLAesGcm {
    fn encrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; AES_GCM_TAG_SIZE] {
        let mut output = [0u8; AES_GCM_TAG_SIZE];
        let ctx = OpenSSLCtx::new().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_gcm();
            assert!(ctx.cipher_init::<true>(t, key.as_ptr(), nonce.as_ptr()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);

            assert!(ctx.update::<true>(aad, ptr::null_mut()));
            let p = data.as_mut_ptr();
            assert!(ctx.update::<true>(data, p));

            assert!(ctx.finalize::<true>());
            assert!(ctx.get_tag(&mut output));
        }
        output
    }

    fn decrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; AES_GCM_TAG_SIZE],
    ) -> bool {
        let ctx = OpenSSLCtx::new().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_gcm();
            assert!(ctx.cipher_init::<false>(t, key.as_ptr(), nonce.as_ptr()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);

            assert!(ctx.update::<false>(aad, ptr::null_mut()));
            let p = data.as_mut_ptr();
            assert!(ctx.update::<false>(data, p));

            ctx.set_tag(tag) && ctx.finalize::<false>()
        }
    }
}

#[cfg(test)]
mod test {
    use super::*;
    #[test]
    fn aes_128_ecb() {
        let key = [1u8; 16];
        let ctx = OpenSSLCtx::new().unwrap();
        unsafe {
            assert!(ctx.cipher_init::<true>(openssl_sys::EVP_aes_128_ecb(), key.as_ptr(), ptr::null()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
            assert_eq!(openssl_sys::EVP_CIPHER_CTX_get_block_size(ctx.as_ptr()) as usize, 16);

            let origin = [2u8; 16];
            let mut val = origin;
            let p = val.as_mut_ptr();

            assert!(ctx.update::<true>(&val, p));
            assert!(ctx.cipher_init::<false>(ptr::null(), key.as_ptr(), ptr::null()));
            assert!(ctx.update::<false>(&val, p));

            assert_eq!(val, origin);
        }
    }
}
