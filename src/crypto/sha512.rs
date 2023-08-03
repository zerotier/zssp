/// The size of a SHA-512 hash, which of course is 64 bytes, or 512 bits.
pub const SHA512_HASH_SIZE: usize = 64;

/// A SHA-512 and HMAC-SHA-512 implementation.
pub trait HashSha512 {
    /// Create a new instance of SHA-512 for streaming data to.
    fn new() -> Self;
    /// Update the instance of SHA-512 with input `data`.
    /// This must update the state of SHA-512 as if `data` was appended to the previous input.
    fn update(&mut self, data: &[u8]);
    /// Finish streaming input and output the final hash.
    fn finish(self) -> [u8; SHA512_HASH_SIZE];

    /// Produce a HMAC-SHA-512 hash based on the given `key` and `data`.
    /// This is a pure function and does not need to support streaming.
    fn hmac(key: &[u8], data: &[u8]) -> [u8; SHA512_HASH_SIZE];
}
