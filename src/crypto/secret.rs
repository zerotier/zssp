// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.
use std::convert::TryInto;

/// Constant time byte slice equality.
#[inline]
pub fn secure_eq<A: AsRef<[u8]> + ?Sized, B: AsRef<[u8]> + ?Sized>(a: &A, b: &B) -> bool {
    let (a, b) = (a.as_ref(), b.as_ref());
    if a.len() == b.len() {
        let mut x = 0u8;
        for (aa, bb) in a.iter().zip(b.iter()) {
            x |= *aa ^ *bb;
        }
        x == 0
    } else {
        false
    }
}

/// Container for secrets that clears them on drop.
///
/// We can't be totally sure that things like libraries are doing this and it's
/// hard to get every use of a secret anywhere, but using this in our code at
/// least reduces the number of secrets that are left lying around in memory.
///
/// This is generally a low-risk thing since it's process memory that's protected,
/// but it's still not a bad idea due to things like swap or obscure side channel
/// attacks that allow memory to be read.
#[derive(Clone)]
#[repr(transparent)]
pub struct Secret<const L: usize>(pub [u8; L]);

impl<const L: usize> Secret<L> {
    /// Create a new all-zero secret.
    #[inline(always)]
    pub fn new() -> Self {
        Self([0_u8; L])
    }
    /// Copy bytes into secret, then delete the previous value, will panic if the slice does not match the size of this secret.
    pub fn from_bytes_then_delete(b: &mut [u8]) -> Self {
        let ret = Self(b.try_into().unwrap());
        b.fill(0);
        ret
    }
    /// Moves bytes into secret, will panic if the slice does not match the size of this secret.
    /// This is unsafe because it will not destroy the contents of its input.
    /// # Safety
    /// Make sure the contents of the input are securely deleted.
    #[inline(always)]
    pub unsafe fn from_bytes(b: &[u8]) -> Self {
        Self(b.try_into().unwrap())
    }

    #[inline(always)]
    pub fn as_ptr(&self) -> *const u8 {
        self.0.as_ptr()
    }

    #[inline(always)]
    pub fn as_bytes(&self) -> &[u8; L] {
        &self.0
    }

    /// Get the first N bytes of this secret as a fixed length array.
    #[inline(always)]
    pub fn first_n<const N: usize>(&self) -> &[u8; N] {
        assert!(N <= L);
        unsafe { &*self.0.as_ptr().cast() }
    }

    /// Clone the first N bytes of this secret as another secret.
    #[inline(always)]
    pub fn first_n_clone<const N: usize>(&self) -> Secret<N> {
        Secret::<N>(*self.first_n())
    }

    pub fn overwrite(&mut self, src: &Self) {
        self.0.copy_from_slice(&src.0);
    }
    pub fn overwrite_first_n<const N: usize>(&mut self, src: &Secret<N>) {
        let amount = N.min(L);
        self.0[..amount].copy_from_slice(&src.0[..amount]);
    }

    pub fn eq_bytes(&self, other: &[u8]) -> bool {
        secure_eq(&self.0, other)
    }
}

impl<const L: usize> Drop for Secret<L> {
    fn drop(&mut self) {
        self.0.fill(0);
    }
}

impl<const L: usize> Default for Secret<L> {
    #[inline(always)]
    fn default() -> Self {
        Self([0_u8; L])
    }
}

impl<const L: usize> AsRef<[u8]> for Secret<L> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

impl<const L: usize> AsRef<[u8; L]> for Secret<L> {
    #[inline(always)]
    fn as_ref(&self) -> &[u8; L] {
        &self.0
    }
}

impl<const L: usize> AsMut<[u8]> for Secret<L> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8] {
        &mut self.0
    }
}

impl<const L: usize> AsMut<[u8; L]> for Secret<L> {
    #[inline(always)]
    fn as_mut(&mut self) -> &mut [u8; L] {
        &mut self.0
    }
}

impl<const L: usize> PartialEq for Secret<L> {
    fn eq(&self, other: &Self) -> bool {
        secure_eq(&self.0, &other.0)
    }
}
impl<const L: usize> Eq for Secret<L> {}
