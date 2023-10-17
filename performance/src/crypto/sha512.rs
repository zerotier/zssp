
/// The size of a SHA512 hash, which is always 64 bytes
pub const SHA512_HASH_SIZE: usize = 64;

/// A SHA-512 implementation.
/// Its interface was designed to make this ZSSP implementation reasonably efficient.
/// Does not need to be threadsafe.
pub trait Sha512Hash {
    /// Create a new instance of SHA-512 for streaming data to.
    fn new() -> Self;
    /// Update the instance of SHA-512 with input `data`.
    /// This must update the state of SHA-512 as if `data` was appended to the previous input.
    fn update(&mut self, data: &[u8]);
    /// Finish streaming input and output the final hash.
    /// The hash must be written to `output`.
    ///
    /// This instance should be reset so that a new, independent hash can be generated.
    fn finish_and_reset(&mut self, output: &mut [u8; SHA512_HASH_SIZE]);
}

/// A HMAC-SHA-512 implementation.
/// Its interface was designed to make this ZSSP implementation reasonably efficient.
/// Does not need to be threadsafe.
pub trait Sha512Hmac {
    /// Allocate space on the stack or heap for repeated Hmac invocations.
    ///
    /// Many FIPS compliant libraries, namely OpenSSL, require initializing an Hmac context on the
    /// heap before operating on it.
    /// If you are using a more sane library feel free to make this return an empty type.
    fn new() -> Self;
    /// Pure function for computing a single HMAC Hash. Repeat invocations of this function should
    /// have no effect on each other.
    fn hash(&mut self, key: &[u8], full_input: &[u8], output: &mut [u8; SHA512_HASH_SIZE]);
}
