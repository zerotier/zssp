/// The specified size of an AES-256 key.
pub const AES_256_KEY_SIZE: usize = 32;
/// The specified size of an AES block.
pub const AES_256_BLOCK_SIZE: usize = 16;
/// The specified size of an AES-GCM authentication tag.
pub const AES_GCM_TAG_SIZE: usize = 16;
/// The specified size of an AES-GCM nonce.
pub const AES_GCM_NONCE_SIZE: usize = 12;

/// A trait for encrypting individual blocks of plaintext using AES-256.
/// It is used for header authentication, for which we have a standard model proof that our
/// algorithm is secure.
///
/// Instances must securely delete their keys when dropped or reset.
pub trait Aes256Enc: Sized + Send + Sync {
    /// Create a new instance of this trait that uses the given key for encryption.
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self;

    /// Change the encryption key to `key` so that all future encryption is performed with it.
    /// This function is very rarely called so it does not have to be particularly efficient.
    fn reset(&mut self, key: &[u8; AES_256_KEY_SIZE]) {
        *self = Self::new(key);
    }

    /// Encrypt the given `block` of plaintext directly using the AES block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The ciphertext should be written directly back to `block`.
    fn encrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]);
}

/// A trait for decrypting individual blocks of plaintext using AES-256.
///
/// Instances must securely delete their keys when dropped or reset.
pub trait Aes256Dec: Sized + Send + Sync {
    /// Create a new instance of this trait that uses the given key for decryption.
    fn new(key: &[u8; AES_256_KEY_SIZE]) -> Self;

    /// Change the decryption key to `key` so that all future decryption is performed with it.
    /// This function is very rarely called so it does not have to be particularly efficient.
    fn reset(&mut self, key: &[u8; AES_256_KEY_SIZE]) {
        *self = Self::new(key);
    }

    /// Decrypt the given `block` of ciphertext directly using the AES 256 block cipher
    /// (i.e. AES-256 in zero-padding ECB mode).
    /// The plaintext should be written directly back out to `block`.
    fn decrypt_in_place(&self, block: &mut [u8; AES_256_BLOCK_SIZE]);
}


/// A trait for implementing AES-GCM-256 in a way that allows for extremely high throughput.
/// One instance of this trait is created whenever a new pair of noise keys are created,
/// and it handles all data encryption and decryption that passes through that session.
///
/// It is highly recommended to implement this trait such that encryption and decryption
/// are hardware accelerated and parallelized.
/// ZSSP's throughput is near 90% determined by this trait.
///
/// Instances must securely delete their keys when dropped.
pub trait HighThroughputAesGcmPool: Send + Sync {
    /// This type represents the state needed to stream a single plaintext for
    /// AES-GCM Authenticated Encryption.
    /// It should be set to whatever object, struct, handle or pointer your chosen library
    /// uses for its stream encryption API.
    type EncContext<'a> where Self: 'a;
    /// This type represents the state needed to stream a single ciphertext for
    /// AES-GCM Authenticated Decryption.
    /// It should be set to whatever object, struct, handle or pointer your chosen library
    /// uses for its stream decryption API.
    type DecContext<'a> where Self: 'a;

    /// Create a new instance of this trait.
    /// `encrypt_key` must be used as the encryption key.
    /// `decrypt_key` must be used as the decryption key.
    fn new(encrypt_key: &[u8; AES_256_KEY_SIZE], decrypt_key: &[u8; AES_256_KEY_SIZE]) -> Self;

    /// Borrow an encryption context to be used to stream encrypt a message.
    /// `nonce` must be set as the AEAD nonce.
    /// There is no additional associated data to be used.
    fn start_enc<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> Self::EncContext<'a>;
    /// Borrow a decryption context to be used to stream decrypt a message.
    /// `nonce` must be set as the AEAD nonce.
    /// There is no additional associated data to be used.
    fn start_dec<'a>(&'a self, nonce: &[u8; AES_GCM_NONCE_SIZE]) -> Self::DecContext<'a>;

    /// Stream-encrypt `input` using the specified encryption context `enc`, and write the
    /// resulting ciphertext to `output`.
    ///
    /// `input` and `output` are guaranteed to have the same length.
    ///
    /// Be sure to update the internal state of `enc` so the authentication tag can be correctly
    /// computed.
    fn encrypt<'a>(&'a self, enc: &mut Self::EncContext<'a> , input: &[u8], output: &mut [u8]);

    /// Stream-decrypt `data` using the specified encryption context `dec`.
    /// The resulting plaintext should be written back into `data`.
    ///
    /// Be sure to update the internal state of `dec` so the authentication tag can be correctly
    /// computed.
    fn decrypt_in_place<'a>(&'a self, dec: &mut Self::DecContext<'a>, data: &mut [u8]);

    /// Finish streaming to `enc` and output the resulting authentication tag.
    ///
    /// Perform any pooling or cleanup required on `enc`.
    /// For many libraries it is much faster to return `enc` to some pool to be reused
    /// by `start_enc`, rather than dropping it.
    /// Be sure to perform your own benchmark.
    fn finish_enc<'a>(&'a self, enc: Self::EncContext<'a>) -> [u8; AES_GCM_TAG_SIZE];
    /// Finish streaming to `dec` and check that the expected authentication tag matches `tag`.
    /// Make sure that comparing `tag` to the expected authentication tag is performed
    /// in constant-time. Many libraries provide functions which will do this for you.
    /// Output `true` only if `tag` is correct.
    ///
    /// Afterwards, perform any pooling or cleanup required on `dec`.
    /// For many libraries it is much faster to return `dec` to some pool to be reused
    /// by `start_dec`, rather than dropping it.
    /// Be sure to perform your own benchmark.
    #[must_use]
    fn finish_dec<'a>(&'a self, dec: Self::DecContext<'a>, tag: &[u8; AES_GCM_TAG_SIZE]) -> bool;
}

/// A trait for implementing AES-GCM-256 to handle the more varied, but much lower throughput
/// requirements of a Noise handshake.
pub trait LowThroughputAesGcm {
    /// A pure function (no side effects) that implements AESGCM AEAD enryption.
    ///
    /// Encryption must be performed on `data` in-place.
    /// The initial plaintext of `data` must be overwriten with its ciphertext.
    ///
    /// The resulting GCM authentication tag must be returned.
    fn encrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
    ) -> [u8; AES_GCM_TAG_SIZE];
    /// A pure function (no side effects) that implements AESGCM AEAD decryption.
    ///
    /// Encryption must be performed on `data` in-place.
    /// The initial ciphertext of `data` must be overwriten with its plaintext.
    ///
    /// This function must check that the expected authentication tag matches `tag`,
    /// and only return `true` if they match. This must be done in constant-time.
    #[must_use]
    fn decrypt_in_place(
        key: &[u8; AES_256_KEY_SIZE],
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        aad: &[u8],
        data: &mut [u8],
        tag: &[u8; AES_GCM_TAG_SIZE],
    ) -> bool;
}
