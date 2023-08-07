// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub const SHA512_HASH_SIZE: usize = 64;

/// A SHA-512 implementation.
pub trait HashSha512 {
    /// Create a new instance of SHA-512 for streaming data to.
    fn new() -> Self;
    /// Update the instance of SHA-512 with input `data`.
    /// This must update the state of SHA-512 as if `data` was appended to the previous input.
    fn update(&mut self, data: &[u8]);
    /// Finish streaming input and output the final hash.
    fn finish_and_reset(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}


/// Opaque HMAC-SHA-512 implementation.
/// Does not need to be threadsafe.
pub trait HmacSha512 {
    /// Allocate space on the stack or heap for repeated Hmac invocations.
    fn new() -> Self;
    /// Pure function for computing a single HMAC Hash. Repeat invocations of this function should
    /// have no effect on each other.
    fn hash(&mut self, key: &[u8], full_input: &[u8], output: &mut [u8; SHA512_HASH_SIZE]);
}
