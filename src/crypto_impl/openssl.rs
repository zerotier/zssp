use std::{
    ptr::{self, NonNull},
    sync::Mutex,
};

use openssl_sys::*;
use zeroize::Zeroizing;

use crate::crypto::*;

struct CipherCtx(NonNull<openssl_sys::EVP_CIPHER_CTX>);
impl Drop for CipherCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_CTX_free(self.0.as_ptr());
        }
    }
}
impl CipherCtx {
    /// Creates a new context.
    pub fn new() -> Option<Self> {
        unsafe { Some(CipherCtx(NonNull::new(EVP_CIPHER_CTX_new())?)) }
    }

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

    pub unsafe fn finalize<const ENCRYPT: bool>(&self) -> bool {
        let evp_f = if ENCRYPT {
            EVP_EncryptFinal_ex
        } else {
            EVP_DecryptFinal_ex
        };
        let mut outl = 0;

        evp_f(self.0.as_ptr(), ptr::null_mut(), &mut outl) > 0
    }

    pub unsafe fn get_tag(&self, tag: &mut [u8]) -> bool {
        EVP_CIPHER_CTX_ctrl(
            self.0.as_ptr(),
            openssl_sys::EVP_CTRL_GCM_GET_TAG,
            tag.len() as c_int,
            tag.as_mut_ptr() as *mut _,
        ) > 0
    }
    #[allow(unused)]
    pub unsafe fn set_tag(&self, tag: &[u8]) -> bool {
        EVP_CIPHER_CTX_ctrl(
            self.0.as_ptr(),
            openssl_sys::EVP_CTRL_GCM_SET_TAG,
            tag.len() as c_int,
            tag.as_ptr() as *mut _,
        ) > 0
    }
    pub fn as_ptr(&self) -> *mut openssl_sys::EVP_CIPHER_CTX {
        self.0.as_ptr()
    }
}

pub struct Aes256OpenSSLEnc(Mutex<CipherCtx>);
unsafe impl Send for Aes256OpenSSLEnc {}
unsafe impl Sync for Aes256OpenSSLEnc {}

impl Aes256Enc for Aes256OpenSSLEnc {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let ctx = CipherCtx::new().unwrap();
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
pub struct Aes256OpenSSLDec(Mutex<CipherCtx>);
unsafe impl Send for Aes256OpenSSLDec {}
unsafe impl Sync for Aes256OpenSSLDec {}

impl Aes256Dec for Aes256OpenSSLDec {
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        let ctx = CipherCtx::new().unwrap();
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

pub struct AesGcmOpenSSLEnc(CipherCtx);
impl AesGcmEncContext for AesGcmOpenSSLEnc {
    fn encrypt(&mut self, input: &[u8], output: &mut [u8]) {
        unsafe { assert!(self.0.update::<true>(input, output.as_mut_ptr())) };
    }

    fn finish(self) -> [u8; AES_GCM_TAG_SIZE] {
        let mut output = [0u8; AES_GCM_TAG_SIZE];
        unsafe {
            assert!(self.0.finalize::<true>());
            assert!(self.0.get_tag(&mut output));
        }
        output
    }
}

pub struct AesGcmOpenSSLDec(CipherCtx);
impl AesGcmDecContext for AesGcmOpenSSLDec {
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        let p = data.as_mut_ptr();
        unsafe { assert!(self.0.update::<false>(data, p)) };
    }

    fn finish(self, tag: &[u8; AES_GCM_TAG_SIZE]) -> bool {
        unsafe { self.0.set_tag(tag) && self.0.finalize::<false>() }
    }
}

pub struct AesGcmOpenSSLPool {
    enc_key: Zeroizing<[u8; AES_256_KEY_SIZE]>,
    dec_key: Zeroizing<[u8; AES_256_KEY_SIZE]>,
}
impl HighThroughputAesGcmPool for AesGcmOpenSSLPool {
    type EncContext<'a> = AesGcmOpenSSLEnc;

    type DecContext<'a> = AesGcmOpenSSLDec;

    fn new(encrypt_key: &[u8; AES_256_KEY_SIZE], decrypt_key: &[u8; AES_256_KEY_SIZE]) -> Self {
        AesGcmOpenSSLPool {
            enc_key: Zeroizing::new(*encrypt_key),
            dec_key: Zeroizing::new(*decrypt_key),
        }
    }

    fn start_enc<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> AesGcmOpenSSLEnc {
        let ctx = CipherCtx::new().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_gcm();
            assert!(ctx.cipher_init::<true>(t, self.enc_key.as_ptr(), nonce.as_ptr()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }
        AesGcmOpenSSLEnc(ctx)
    }

    fn start_dec<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> AesGcmOpenSSLDec {
        let ctx = CipherCtx::new().unwrap();
        unsafe {
            let t = openssl_sys::EVP_aes_256_gcm();
            assert!(ctx.cipher_init::<false>(t, self.dec_key.as_ptr(), nonce.as_ptr()));
            openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
        }
        AesGcmOpenSSLDec(ctx)
    }
}

pub struct AesGcmOpenSSL;
impl LowThroughputAesGcm for AesGcmOpenSSL {
    fn encrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; AES_GCM_TAG_SIZE] {
        let mut output = [0u8; AES_GCM_TAG_SIZE];
        let ctx = CipherCtx::new().unwrap();
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
        let ctx = CipherCtx::new().unwrap();
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
        let ctx = CipherCtx::new().unwrap();
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
