use std::sync::Mutex;

use libc::c_int;

use crate::error::{cvt, ErrorStack};

/// Fill buffer with cryptographically strong pseudo-random bytes.
fn rand_bytes(buf: &mut [u8]) -> Result<(), ErrorStack> {
    unsafe {
        assert!(buf.len() <= c_int::max_value() as usize);
        cvt(ffi::RAND_bytes(buf.as_mut_ptr(), buf.len() as c_int)).map(|_| ())
    }
}

pub fn next_u32_secure() -> u32 {
    unsafe {
        let mut tmp = [0u32; 1];
        rand_bytes(&mut *(tmp.as_mut_ptr().cast::<[u8; 4]>())).unwrap();
        tmp[0]
    }
}

pub fn next_u64_secure() -> u64 {
    unsafe {
        let mut tmp = [0u64; 1];
        rand_bytes(&mut *(tmp.as_mut_ptr().cast::<[u8; 8]>())).unwrap();
        tmp[0]
    }
}

pub fn next_u128_secure() -> u128 {
    unsafe {
        let mut tmp = [0u128; 1];
        rand_bytes(&mut *(tmp.as_mut_ptr().cast::<[u8; 16]>())).unwrap();
        tmp[0]
    }
}

#[inline(always)]
pub fn fill_bytes_secure(dest: &mut [u8]) {
    rand_bytes(dest).unwrap();
}

#[inline(always)]
pub fn get_bytes_secure<const COUNT: usize>() -> [u8; COUNT] {
    let mut tmp = [0u8; COUNT];
    rand_bytes(&mut tmp).unwrap();
    tmp
}

pub struct SecureRandom;

impl Default for SecureRandom {
    #[inline(always)]
    fn default() -> Self {
        Self
    }
}

impl SecureRandom {
    #[inline(always)]
    pub fn get() -> Self {
        Self
    }
}

impl rand_core::RngCore for SecureRandom {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        next_u32_secure()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        next_u64_secure()
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_bytes_secure(dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        fill_bytes_secure(dest);
        Ok(())
    }
}

/// ed25519-dalek still uses rand_core 0.5.1, and that version is incompatible with 0.6.4, so we need to import and implement both.
impl rand_core_051::RngCore for SecureRandom {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        next_u32_secure()
    }

    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        next_u64_secure()
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        fill_bytes_secure(dest);
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core_051::Error> {
        fill_bytes_secure(dest);
        Ok(())
    }
}

impl rand_core::CryptoRng for SecureRandom {}
impl rand_core_051::CryptoRng for SecureRandom {}

unsafe impl Sync for SecureRandom {}
unsafe impl Send for SecureRandom {}

/// xorshift* by Marsaglia.
/// Simple and deterministic which makes it good for testing.
pub struct Xorshift64Star(pub u64);
impl Xorshift64Star {
    #[inline(always)]
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }
}
impl rand_core::RngCore for Xorshift64Star {
    #[inline(always)]
    fn next_u32(&mut self) -> u32 {
        self.next_u64() as u32
    }
    #[inline(always)]
    fn next_u64(&mut self) -> u64 {
        self.0 ^= self.0.wrapping_shr(12);
        self.0 ^= self.0.wrapping_shl(25);
        self.0 ^= self.0.wrapping_shr(27);
        self.0.wrapping_mul(0x2545F4914F6CDD1Du64)
    }

    #[inline(always)]
    fn fill_bytes(&mut self, dest: &mut [u8]) {
        // This could be faster with manual unrolling
        let mut r = self.next_u64().to_ne_bytes();
        let mut n = 0;
        for byte in dest {
            *byte = r[n];
            n += 1;
            if n >= 8 {
                r = self.next_u64().to_ne_bytes();
                n = 0
            }
        }
    }

    #[inline(always)]
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        self.fill_bytes(dest);
        Ok(())
    }
}

/// Get a non-cryptographic random number.
pub fn xorshift64_random() -> u64 {
    static XORSHIFT64_STATE: Mutex<u64> = Mutex::new(0);
    let mut x = XORSHIFT64_STATE.lock().unwrap();
    while *x == 0 {
        *x = next_u64_secure();
    }
    *x ^= x.wrapping_shr(12);
    *x ^= x.wrapping_shl(25);
    *x ^= x.wrapping_shr(27);
    let r = *x;
    drop(x);
    r.wrapping_mul(0x2545F4914F6CDD1Du64)
}
