pub const SHA512_HASH_SIZE: usize = 64;

/// Opaque SHA-512 implementation.
/// Does not need to be threadsafe.
pub trait HashSha512 {
    /// Allocate memory on the stack or heap for Sha512.
    /// An instance of Sha512 will only ever be held on the stack.
    fn new() -> Self;

    fn update(&mut self, data: &[u8]);
    /// Finish hashing the input and write the final hash to output.
    fn finish(self) -> [u8; SHA512_HASH_SIZE];

    fn hmac(key: &[u8], data: &[u8]) -> [u8; SHA512_HASH_SIZE];
}
