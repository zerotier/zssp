// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const SHA512_HASH_SIZE: usize = 64;

/// Opaque SHA-512 implementation.
/// Does not need to be threadsafe.
pub trait Sha512 {
    /// Allocate memory on the stack or heap for Sha512.
    /// An instance of Sha512 will only ever be held on the stack.
    fn new() -> Self;

    /// Reinitialize the internal state of the hash function for a fresh input.
    fn reset(&mut self);

    fn update(&mut self, input: &[u8]);
    /// Finish hashing the input and write the final hash to output.
    ///
    /// After this function is called, this instance of Sha512 will either be dropped
    /// or `reset` will be called.
    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}

/// Opaque HMAC-SHA-512 implementation.
/// Does not need to be threadsafe.
pub trait HmacSha512 {
    /// Allocate memory on the stack or heap for HmacSha512.
    /// An instance of HmacSha512 will only ever be held on the stack.
    ///
    /// `reset` will always be called before `update` on a new instance of HmacSha512,
    /// to make sure there is always a set key.
    fn new() -> Self;
    /// Reinitialize the internal state of the hash function for a fresh input.
    /// The provided key should replace the previous Hmac key.
    fn reset(&mut self, key: &[u8]);

    fn update(&mut self, input: &[u8]);
    /// Finish hashing the input and write the final hash to output.
    ///
    /// After this function is called, this instance of HmacSha512 will either be dropped
    /// or `reset` will be called.
    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}
