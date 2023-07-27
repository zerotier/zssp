// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const SHA512_HASH_SIZE: usize = 64;

/// Opaque SHA-512 implementation.
/// Does not need to be threadsafe.
pub trait Sha512 {
    /// Allocate memory on the stack or heap for Sha512.
    /// An instance of Sha512 will only ever be held on the stack.
    fn new() -> Self;

    fn update(&mut self, input: &[u8]);
    /// Finish hashing the input and write the final hash to output.
    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}

/// Opaque HMAC-SHA-512 implementation.
/// Does not need to be threadsafe.
pub trait HmacSha512 {
    /// Allocate memory on the stack or heap for HmacSha512.
    /// An instance of HmacSha512 will only ever be held on the stack.
    fn new(key: &[u8]) -> Self;

    fn update(&mut self, input: &[u8]);
    /// Finish hashing the input and write the final hash to output.
    fn finish(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}
