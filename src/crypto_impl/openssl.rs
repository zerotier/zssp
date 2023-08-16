use std::{
    ptr::{self, NonNull},
    sync::{Mutex, MutexGuard},
};

use openssl_sys::*;

use crate::crypto::*;

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

pub struct OpenSSLAesGcmEnc<'a>(MutexGuard<'a, OpenSSLCtx>);
impl<'a> AesGcmEncContext for OpenSSLAesGcmEnc<'a> {
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

pub struct OpenSSLAesGcmDec<'a>(MutexGuard<'a, OpenSSLCtx>);
impl<'a> AesGcmDecContext for OpenSSLAesGcmDec<'a> {
    fn decrypt_in_place(&mut self, data: &mut [u8]) {
        let p = data.as_mut_ptr();
        unsafe { assert!(self.0.update::<false>(data, p)) };
    }

    fn finish(self, tag: &[u8; AES_GCM_TAG_SIZE]) -> bool {
        unsafe { self.0.set_tag(tag) && self.0.finalize::<false>() }
    }
}

pub struct OpenSSLAesGcmPool {
    enc: [Mutex<OpenSSLCtx>; 8],
    dec: [Mutex<OpenSSLCtx>; 8],
}
unsafe impl Send for OpenSSLAesGcmPool {}
unsafe impl Sync for OpenSSLAesGcmPool {}

impl HighThroughputAesGcmPool for OpenSSLAesGcmPool {
    type EncContext<'a> = OpenSSLAesGcmEnc<'a>;

    type DecContext<'a> = OpenSSLAesGcmDec<'a>;

    fn new(encrypt_key: &[u8; AES_256_KEY_SIZE], decrypt_key: &[u8; AES_256_KEY_SIZE]) -> Self {
        unsafe {
            OpenSSLAesGcmPool {
                enc: std::array::from_fn(|_| {
                    let ctx = OpenSSLCtx::new().unwrap();
                    let t = openssl_sys::EVP_aes_256_gcm();
                    assert!(ctx.cipher_init::<true>(t, encrypt_key.as_ptr(), ptr::null()));
                    openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
                    Mutex::new(ctx)
                }),
                dec: std::array::from_fn(|_| {
                    let ctx = OpenSSLCtx::new().unwrap();
                    let t = openssl_sys::EVP_aes_256_gcm();
                    assert!(ctx.cipher_init::<false>(t, decrypt_key.as_ptr(), ptr::null()));
                    openssl_sys::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
                    Mutex::new(ctx)
                }),
            }
        }
    }

    fn start_enc<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> OpenSSLAesGcmEnc {
        let i = u64::from_be_bytes(nonce[4..].try_into().unwrap());
        let g = self.enc[(i as usize) % self.enc.len()].lock().unwrap();
        unsafe {
            assert!(g.cipher_init::<true>(ptr::null(), ptr::null(), nonce.as_ptr()));
        }
        OpenSSLAesGcmEnc(g)
    }

    fn start_dec<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> OpenSSLAesGcmDec {
        let i = u64::from_be_bytes(nonce[4..].try_into().unwrap());
        let g = self.dec[(i as usize) % self.enc.len()].lock().unwrap();
        unsafe {
            assert!(g.cipher_init::<false>(ptr::null(), ptr::null(), nonce.as_ptr()));
        }
        OpenSSLAesGcmDec(g)
    }
}

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
