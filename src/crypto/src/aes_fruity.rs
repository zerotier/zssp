// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

// MacOS implementation of AES primitives since CommonCrypto seems to be faster than OpenSSL, especially on ARM64.
use std::os::raw::{c_int, c_void};
use std::ptr::{null, null_mut};
use std::sync::Mutex;

use crate::constant::*;
use crate::secure_eq;

#[allow(non_upper_case_globals, unused)]
const kCCModeECB: i32 = 1;
#[allow(non_upper_case_globals, unused)]
const kCCModeCTR: i32 = 4;
#[allow(non_upper_case_globals, unused)]
const kCCModeGCM: i32 = 11;
#[allow(non_upper_case_globals, unused)]
const kCCEncrypt: i32 = 0;
#[allow(non_upper_case_globals, unused)]
const kCCDecrypt: i32 = 1;
#[allow(non_upper_case_globals, unused)]
const kCCAlgorithmAES: i32 = 0;
#[allow(non_upper_case_globals, unused)]
const kCCOptionECBMode: i32 = 2;

extern "C" {
    fn CCCryptorCreateWithMode(
        op: i32,
        mode: i32,
        alg: i32,
        padding: i32,
        iv: *const c_void,
        key: *const c_void,
        key_len: usize,
        tweak: *const c_void,
        tweak_len: usize,
        num_rounds: c_int,
        options: i32,
        cryyptor_ref: *mut *mut c_void,
    ) -> i32;
    fn CCCryptorUpdate(
        cryptor_ref: *mut c_void,
        data_in: *const c_void,
        data_in_len: usize,
        data_out: *mut c_void,
        data_out_len: usize,
        data_out_written: *mut usize,
    ) -> i32;
    //fn CCCryptorReset(cryptor_ref: *mut c_void, iv: *const c_void) -> i32;
    fn CCCryptorRelease(cryptor_ref: *mut c_void) -> i32;
    fn CCCryptorGCMSetIV(cryptor_ref: *mut c_void, iv: *const c_void, iv_len: usize) -> i32;
    fn CCCryptorGCMAddAAD(cryptor_ref: *mut c_void, aad: *const c_void, len: usize) -> i32;
    fn CCCryptorGCMEncrypt(cryptor_ref: *mut c_void, data_in: *const c_void, data_in_len: usize, data_out: *mut c_void) -> i32;
    fn CCCryptorGCMDecrypt(cryptor_ref: *mut c_void, data_in: *const c_void, data_in_len: usize, data_out: *mut c_void) -> i32;
    fn CCCryptorGCMFinal(cryptor_ref: *mut c_void, tag: *mut c_void, tag_len: *mut usize) -> i32;
    fn CCCryptorGCMReset(cryptor_ref: *mut c_void) -> i32;
}

pub struct AesGcm<const ENCRYPT: bool>(*mut c_void);

impl<const ENCRYPT: bool> Drop for AesGcm<ENCRYPT> {
    #[inline(always)]
    fn drop(&mut self) {
        unsafe { CCCryptorRelease(self.0) };
    }
}

impl<const ENCRYPT: bool> AesGcm<ENCRYPT> {
    pub fn new(k: &[u8; AES_256_KEY_SIZE]) -> Self {
        unsafe {
            let mut ptr: *mut c_void = null_mut();
            assert_eq!(
                CCCryptorCreateWithMode(
                    if ENCRYPT {
                        kCCEncrypt
                    } else {
                        kCCDecrypt
                    },
                    kCCModeGCM,
                    kCCAlgorithmAES,
                    0,
                    null(),
                    k.as_ptr().cast(),
                    AES_256_KEY_SIZE,
                    null(),
                    0,
                    0,
                    0,
                    &mut ptr,
                ),
                0
            );
            AesGcm(ptr)
        }
    }

    #[inline(always)]
    pub fn reset_init_gcm(&mut self, iv: &[u8]) {
        assert_eq!(iv.len(), AES_GCM_NONCE_SIZE);
        unsafe {
            assert_eq!(CCCryptorGCMReset(self.0), 0);
            assert_eq!(CCCryptorGCMSetIV(self.0, iv.as_ptr().cast(), AES_GCM_NONCE_SIZE), 0);
        }
    }

    #[inline(always)]
    pub fn aad(&mut self, aad: &[u8]) {
        unsafe {
            assert_eq!(CCCryptorGCMAddAAD(self.0, aad.as_ptr().cast(), aad.len()), 0);
        }
    }

    #[inline(always)]
    pub fn crypt(&mut self, input: &[u8], output: &mut [u8]) {
        unsafe {
            assert_eq!(input.len(), output.len());
            if ENCRYPT {
                assert_eq!(
                    CCCryptorGCMEncrypt(self.0, input.as_ptr().cast(), input.len(), output.as_mut_ptr().cast()),
                    0
                );
            } else {
                assert_eq!(
                    CCCryptorGCMDecrypt(self.0, input.as_ptr().cast(), input.len(), output.as_mut_ptr().cast()),
                    0
                );
            }
        }
    }

    #[inline(always)]
    pub fn crypt_in_place(&mut self, data: &mut [u8]) {
        unsafe {
            if ENCRYPT {
                assert_eq!(CCCryptorGCMEncrypt(self.0, data.as_ptr().cast(), data.len(), data.as_mut_ptr().cast()), 0);
            } else {
                assert_eq!(CCCryptorGCMDecrypt(self.0, data.as_ptr().cast(), data.len(), data.as_mut_ptr().cast()), 0);
            }
        }
    }

    #[inline(always)]
    fn finish(&mut self) -> [u8; AES_GCM_TAG_SIZE] {
        let mut tag = 0_u128.to_ne_bytes();
        unsafe {
            let mut tag_len = AES_GCM_TAG_SIZE;
            if CCCryptorGCMFinal(self.0, tag.as_mut_ptr().cast(), &mut tag_len) != 0 {
                debug_assert!(false);
                tag.fill(0);
            }
        }
        tag
    }
}

impl AesGcm<true> {
    /// Produce the gcm authentication tag.
    #[inline(always)]
    pub fn finish_encrypt(&mut self) -> [u8; AES_GCM_TAG_SIZE] {
        self.finish()
    }
}
impl AesGcm<false> {
    /// Check the gcm authentication tag. Outputs true if it matches the just decrypted message, outputs false otherwise.
    #[inline(always)]
    pub fn finish_decrypt(&mut self, expected_tag: &[u8]) -> bool {
        secure_eq(&self.finish(), expected_tag)
    }
}

pub struct Aes<const ENCRYPT: bool>(Mutex<*mut c_void>);
unsafe impl<const ENCRYPT: bool> Send for Aes<ENCRYPT> {}
unsafe impl<const ENCRYPT: bool> Sync for Aes<ENCRYPT> {}

impl<const ENCRYPT: bool> Drop for Aes<ENCRYPT> {
    #[inline(always)]
    fn drop(&mut self) {
        let p = self.0.lock().unwrap();
        unsafe {
            CCCryptorRelease(*p);
        }
    }
}

impl<const ENCRYPT: bool> Aes<ENCRYPT> {
    pub fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self {
        unsafe {
            let mut p = null_mut();
            assert_eq!(
                CCCryptorCreateWithMode(
                    if ENCRYPT {
                        kCCEncrypt
                    } else {
                        kCCDecrypt
                    },
                    kCCModeECB,
                    kCCAlgorithmAES,
                    0,
                    null(),
                    key.as_ptr().cast(),
                    AES_256_KEY_SIZE,
                    null(),
                    0,
                    0,
                    kCCOptionECBMode,
                    &mut p,
                ),
                0
            );
            Self(Mutex::new(p))
        }
    }
    pub fn reset(&self, key: &[u8; AES_256_KEY_SIZE]) {
        let mut p = self.0.lock().unwrap();
        unsafe {
            CCCryptorRelease(*p);
            assert_eq!(
                CCCryptorCreateWithMode(
                    if ENCRYPT {
                        kCCEncrypt
                    } else {
                        kCCDecrypt
                    },
                    kCCModeECB,
                    kCCAlgorithmAES,
                    0,
                    null(),
                    key.as_ptr().cast(),
                    AES_256_KEY_SIZE,
                    null(),
                    0,
                    0,
                    kCCOptionECBMode,
                    &mut *p,
                ),
                0
            );
        }
    }

    #[inline(always)]
    pub fn crypt_block_in_place(&self, data: &mut [u8]) {
        assert_eq!(data.len(), AES_BLOCK_SIZE);
        unsafe {
            let mut data_out_written = 0;
            let p = self.0.lock().unwrap();
            CCCryptorUpdate(
                *p,
                data.as_ptr().cast(),
                AES_BLOCK_SIZE,
                data.as_mut_ptr().cast(),
                AES_BLOCK_SIZE,
                &mut data_out_written,
            );
        }
    }
}
