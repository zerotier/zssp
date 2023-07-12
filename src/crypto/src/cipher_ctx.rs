use std::ptr::{self, NonNull};

use crate::error::{cvt, cvt_p, ErrorStack};
use libc::{c_int, c_void};

extern "C" {
    fn EVP_CIPHER_CTX_free(ctx: *mut ffi::EVP_CIPHER_CTX);
    fn EVP_CIPHER_CTX_new() -> *mut ffi::EVP_CIPHER_CTX;

    fn EVP_EncryptInit_ex(ctx: *mut ffi::EVP_CIPHER_CTX, cipher: *const ffi::EVP_CIPHER, engine: *mut c_void, key: *const u8, iv: *const u8)
        -> c_int;
    fn EVP_DecryptInit_ex(ctx: *mut ffi::EVP_CIPHER_CTX, cipher: *const ffi::EVP_CIPHER, engine: *mut c_void, key: *const u8, iv: *const u8)
        -> c_int;
    fn EVP_EncryptUpdate(ctx: *mut ffi::EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, in_: *const u8, inl: c_int) -> c_int;
    fn EVP_DecryptUpdate(ctx: *mut ffi::EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int, in_: *const u8, inl: c_int) -> c_int;
    fn EVP_EncryptFinal_ex(ctx: *mut ffi::EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int;
    fn EVP_DecryptFinal_ex(ctx: *mut ffi::EVP_CIPHER_CTX, out: *mut u8, outl: *mut c_int) -> c_int;
    fn EVP_CIPHER_CTX_ctrl(ctx: *mut ffi::EVP_CIPHER_CTX, type_: c_int, arg: c_int, ptr: *mut c_void) -> c_int;

}

pub struct CipherCtx(NonNull<ffi::EVP_CIPHER_CTX>);
impl Drop for CipherCtx {
    fn drop(&mut self) {
        unsafe {
            EVP_CIPHER_CTX_free(self.0.as_ptr());
        }
    }
}

impl CipherCtx {
    /// Creates a new context.
    pub fn new() -> Result<Self, ErrorStack> {
        unsafe {
            let ptr = cvt_p(EVP_CIPHER_CTX_new())?;
            Ok(CipherCtx(NonNull::new_unchecked(ptr)))
        }
    }
}
impl CipherCtx {
    /// Initializes the context for encryption or decryption.
    /// All pointer fields can be null, in which case the corresponding field in the context is not updated.
    pub unsafe fn cipher_init<const ENCRYPT: bool>(&self, t: *const ffi::EVP_CIPHER, key: *const u8, iv: *const u8) -> Result<(), ErrorStack> {
        let evp_f = if ENCRYPT {
            EVP_EncryptInit_ex
        } else {
            EVP_DecryptInit_ex
        };

        // OpenSSL will usually leak a static amount of memory per cipher given here.
        cvt(evp_f(self.0.as_ptr(), t, ptr::null_mut(), key, iv))?;
        Ok(())
    }

    /// Writes data into the context.
    ///
    /// Providing no output buffer will cause the input to be considered additional authenticated data (AAD).
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// This function is the same as [`Self::cipher_update`] but with the
    /// output size check removed. It can be used when the exact
    /// buffer size control is maintained by the caller.
    ///
    /// SAFETY: The caller is expected to provide `output` buffer
    /// large enough to contain correct number of bytes. For streaming
    /// ciphers the output buffer size should be at least as big as
    /// the input buffer. For block ciphers the size of the output
    /// buffer depends on the state of partially updated blocks.
    pub unsafe fn update<const ENCRYPT: bool>(&self, input: &[u8], output: *mut u8) -> Result<(), ErrorStack> {
        let evp_f = if ENCRYPT {
            EVP_EncryptUpdate
        } else {
            EVP_DecryptUpdate
        };

        let mut outlen = 0;

        cvt(evp_f(self.0.as_ptr(), output, &mut outlen, input.as_ptr(), input.len() as c_int))?;

        Ok(())
    }

    /// Finalizes the encryption or decryption process.
    ///
    /// Any remaining data will be written to the output buffer.
    ///
    /// Returns the number of bytes written to `output`.
    ///
    /// This function is the same as [`Self::cipher_final`] but with
    /// the output buffer size check removed.
    ///
    /// SAFETY: The caller is expected to provide `output` buffer
    /// large enough to contain correct number of bytes. For streaming
    /// ciphers the output buffer can be empty, for block ciphers the
    /// output buffer should be at least as big as the block.
    pub unsafe fn finalize<const ENCRYPT: bool>(&self, output: *mut u8) -> Result<(), ErrorStack> {
        let evp_f = if ENCRYPT {
            EVP_EncryptFinal_ex
        } else {
            EVP_DecryptFinal_ex
        };
        let mut outl = 0;

        cvt(evp_f(self.0.as_ptr(), output, &mut outl))?;

        Ok(())
    }

    /// Retrieves the calculated authentication tag from the context.
    ///
    /// This should be called after [`Self::cipher_final`], and is only supported by authenticated ciphers.
    ///
    /// The size of the buffer indicates the size of the tag. While some ciphers support a range of tag sizes, it is
    /// recommended to pick the maximum size.
    pub fn tag(&self, tag: &mut [u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(EVP_CIPHER_CTX_ctrl(
                self.0.as_ptr(),
                ffi::EVP_CTRL_GCM_GET_TAG,
                tag.len() as c_int,
                tag.as_mut_ptr() as *mut _,
            ))?;
        }

        Ok(())
    }

    /// Sets the authentication tag for verification during decryption.
    #[allow(unused)]
    pub fn set_tag(&self, tag: &[u8]) -> Result<(), ErrorStack> {
        unsafe {
            cvt(EVP_CIPHER_CTX_ctrl(
                self.0.as_ptr(),
                ffi::EVP_CTRL_GCM_SET_TAG,
                tag.len() as c_int,
                tag.as_ptr() as *mut _,
            ))?;
        }

        Ok(())
    }
    pub fn as_ptr(&self) -> *mut ffi::EVP_CIPHER_CTX {
        self.0.as_ptr()
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
            ctx.cipher_init::<true>(ffi::EVP_aes_128_ecb(), key.as_ptr(), ptr::null()).unwrap();
            ffi::EVP_CIPHER_CTX_set_padding(ctx.as_ptr(), 0);
            assert_eq!(ffi::EVP_CIPHER_CTX_get_block_size(ctx.as_ptr()) as usize, 16);

            let origin = [2u8; 16];
            let mut val = origin;
            let p = val.as_mut_ptr();

            ctx.update::<true>(&val, p).unwrap();
            ctx.cipher_init::<false>(ptr::null(), key.as_ptr(), ptr::null()).unwrap();
            ctx.update::<false>(&val, p).unwrap();

            assert_eq!(val, origin);
        }
    }
}
