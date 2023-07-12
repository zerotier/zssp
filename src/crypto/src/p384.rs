// Version using OpenSSL's ECC
use std::os::raw::{c_int, c_ulong, c_void};
use std::sync::Mutex;
use std::{mem, ptr};

use lazy_static::lazy_static;

use crate::error::{cvt, cvt_n, cvt_p, ErrorStack};
use crate::hash::SHA384;
use crate::secret::Secret;
use crate::secure_eq;

pub const P384_PUBLIC_KEY_SIZE: usize = 49;
pub const P384_SECRET_KEY_SIZE: usize = 48;
pub const P384_ECDSA_SIGNATURE_SIZE: usize = 96;
pub const P384_ECDH_SHARED_SECRET_SIZE: usize = 48;

extern "C" {
    fn ECDH_compute_key(out: *mut u8, outlen: c_ulong, pub_key: *const ffi::EC_POINT, ecdh: *mut ffi::EC_KEY, kdf: *const c_void) -> c_int;
}
/// A NIST P-384 ECDH/ECDSA public key.
pub struct P384PublicKey {
    /// OpenSSL does not guarantee threadsafety for this object (even though it could) so we have
    /// to wrap this in a mutex.
    key: Mutex<OSSLKey>,
    bytes: [u8; P384_PUBLIC_KEY_SIZE],
}

unsafe impl Send for P384PublicKey {}
unsafe impl Sync for P384PublicKey {}

impl P384PublicKey {
    /// Create a p384 public key from raw bytes.
    /// `buffer` must have length `P384_PUBLIC_KEY_SIZE`.
    pub fn from_bytes(buffer: &[u8]) -> Option<P384PublicKey> {
        if buffer.len() == P384_PUBLIC_KEY_SIZE {
            unsafe {
                // Write the buffer into OpenSSL.
                let key = OSSLKey::pub_from_slice(buffer).ok()?;
                // Get OpenSSL to double check if this final key makes sense.
                // It will be read-only after this point.
                if ffi::EC_KEY_check_key(key.0) == 1 {
                    let mut bytes = [0u8; P384_PUBLIC_KEY_SIZE];
                    bytes.clone_from_slice(buffer);
                    return Some(Self { key: Mutex::new(key), bytes });
                }
            }
        }
        None
    }

    /// Verify the ECDSA/SHA384 signature.
    pub fn verify(&self, msg: &[u8], signature: &[u8]) -> bool {
        if signature.len() == P384_ECDSA_SIGNATURE_SIZE {
            const CAP: usize = P384_ECDSA_SIGNATURE_SIZE / 2;
            unsafe {
                // Write the raw bytes into OpenSSL.
                let r = OSSLBN::from_slice(&signature[0..CAP]);
                let s = OSSLBN::from_slice(&signature[CAP..]);
                if let (Ok(r), Ok(s)) = (r, s) {
                    // Create the OpenSSL object that actually supports verification.
                    if let Ok(sig) = cvt_p(ffi::ECDSA_SIG_new()) {
                        let is_valid = if ffi::ECDSA_SIG_set0(sig, r.0, s.0) == 1 {
                            // For some reason this one random function, `ECDSA_SIG_set0`, takes
                            // ownership of its parameters. I've double checked and it is the only one
                            // we call that does that. We `forget` the memory so we don't double free.
                            mem::forget(r);
                            mem::forget(s);
                            // Digest the message.
                            let data = &SHA384::hash(msg);

                            let key = self.key.lock().unwrap();
                            // Actually perform the verification.
                            ffi::ECDSA_do_verify(data.as_ptr(), data.len() as c_int, sig, key.0) == 1
                        } else {
                            false
                        };
                        // Guarantee signature free.
                        ffi::ECDSA_SIG_free(sig);
                        return is_valid;
                    }
                }
            }
        }
        false
    }

    pub fn as_bytes(&self) -> &[u8; P384_PUBLIC_KEY_SIZE] {
        &self.bytes
    }
}
impl Clone for P384PublicKey {
    fn clone(&self) -> Self {
        Self {
            key: Mutex::new(self.key.lock().unwrap().clone_public().unwrap()),
            bytes: self.bytes,
        }
    }
}
impl PartialEq for P384PublicKey {
    fn eq(&self, other: &Self) -> bool {
        secure_eq(&self.bytes, &other.bytes)
    }
}

/// A NIST P-384 ECDH/ECDSA public/private key pair.
pub struct P384KeyPair {
    /// OpenSSL does not guarantee threadsafety for this object (even though it could) so we have
    /// to wrap this in a mutex.
    pair: Mutex<OSSLKey>,
    pub_bytes: [u8; P384_PUBLIC_KEY_SIZE],
}

unsafe impl Send for P384KeyPair {}
unsafe impl Sync for P384KeyPair {}

impl P384KeyPair {
    /// Randomly generate a new p384 keypair.
    pub fn generate() -> P384KeyPair {
        unsafe {
            let pair = OSSLKey::new().unwrap();
            // Ask OpenSSL to securely generate the keypair.
            cvt(ffi::EC_KEY_generate_key(pair.0)).unwrap();
            // Read out the raw public key into a buffer.
            let public_key = ffi::EC_KEY_get0_public_key(pair.0);
            let mut buffer = [0_u8; P384_PUBLIC_KEY_SIZE];
            let bnc = OSSLBNC::new().unwrap();
            let len = ffi::EC_POINT_point2oct(
                GROUP_P384.0,
                public_key,
                ffi::point_conversion_form_t::POINT_CONVERSION_COMPRESSED,
                buffer.as_mut_ptr(),
                P384_PUBLIC_KEY_SIZE,
                bnc.0,
            );
            if len <= 0 {
                Err::<(), _>(ErrorStack::get()).unwrap();
            }
            Self { pair: Mutex::new(pair), pub_bytes: buffer }
        }
    }

    /// Create a p384 keypair from raw bytes.
    /// `public_bytes` should have length `P384_PUBLIC_KEY_SIZE` and `secret_bytes` should have length
    /// `P384_SECRET_KEY_SIZE`.
    pub fn from_bytes(public_bytes: &[u8], secret_bytes: &[u8]) -> Option<P384KeyPair> {
        if public_bytes.len() == P384_PUBLIC_KEY_SIZE && secret_bytes.len() == P384_SECRET_KEY_SIZE {
            unsafe {
                // Write the raw bytes into OpenSSL.
                let pair = OSSLKey::pub_from_slice(public_bytes).ok()?;
                let private = OSSLBN::from_slice(secret_bytes).ok()?;
                // Tell OpenSSL to assign the private key to the public key.
                // This makes the public key into a proper keypair.
                if cvt(ffi::EC_KEY_set_private_key(pair.0, private.0)).is_ok() {
                    // Get OpenSSL to double check if this final key makes sense.
                    // It will be read-only after this point.
                    if ffi::EC_KEY_check_key(pair.0) == 1 {
                        let mut pub_bytes = [0u8; P384_PUBLIC_KEY_SIZE];
                        pub_bytes.clone_from_slice(public_bytes);
                        return Some(Self { pair: Mutex::new(pair), pub_bytes });
                    }
                }
            }
        }
        None
    }
    /// Create a new `P384PublicKey` object that only contains the public key from
    /// this keypair. This object can be safely sent to a different thread.
    pub fn to_public_key(&self) -> P384PublicKey {
        let key = self.pair.lock().unwrap().clone_public().unwrap();
        P384PublicKey { key: Mutex::new(key), bytes: self.pub_bytes }
    }
    /// Get the raw bytes that uniquely define the public key.
    pub fn public_key_bytes(&self) -> &[u8; P384_PUBLIC_KEY_SIZE] {
        &self.pub_bytes
    }

    /// Clone the raw bytes that uniquely define the secret key.
    /// They are wrapped in a container which will erase them on drop.
    ///
    /// **Only write these to 100% trusted storage mediums. Avoid calling this function in general.**
    pub fn secret_key_bytes(&self) -> Secret<P384_SECRET_KEY_SIZE> {
        unsafe {
            let mut tmp: Secret<P384_SECRET_KEY_SIZE> = Secret::default();
            let keypair = self.pair.lock().unwrap();
            // Get a temporary handle to the private key.
            let ptr = ffi::EC_KEY_get0_private_key(keypair.0);
            // Read the key's raw bytes out of OpenSSL.
            let size = cvt_n(ffi::BN_bn2bin(ptr, tmp.as_bytes_mut().as_mut_ptr())).unwrap() as usize;
            drop(keypair);

            // Double check big-endian-ness.
            tmp.0.copy_within(..size, P384_SECRET_KEY_SIZE - size);
            tmp
        }
    }

    /// Sign a message with ECDSA/SHA384.
    pub fn sign(&self, msg: &[u8]) -> [u8; P384_ECDSA_SIGNATURE_SIZE] {
        // Digest the message.
        let data = &SHA384::hash(msg);
        unsafe {
            let keypair = self.pair.lock().unwrap();
            // Actually create the signature with ECDSA.
            let sig = cvt_p(ffi::ECDSA_do_sign(data.as_ptr(), data.len() as c_int, keypair.0));
            drop(keypair);
            let sig = sig.unwrap();

            // Get handles to the OpenSSL objects that actually support reading out into bytes.
            let mut r = ptr::null();
            let mut s = ptr::null();
            ffi::ECDSA_SIG_get0(sig, &mut r, &mut s);
            if r.is_null() || s.is_null() {
                ffi::ECDSA_SIG_free(sig);
                Err::<(), _>(ErrorStack::get()).unwrap();
            }
            // Determine the size of the buffers to guarantee sanity and big-endian-ness.
            let r_len = ((ffi::BN_num_bits(r) + 7) / 8) as usize;
            let s_len = ((ffi::BN_num_bits(s) + 7) / 8) as usize;
            const CAP: usize = P384_ECDSA_SIGNATURE_SIZE / 2;
            if !(r_len > 0 && s_len > 0 && r_len <= CAP && s_len <= CAP) {
                ffi::ECDSA_SIG_free(sig);
                Err::<(), _>(ErrorStack::get()).unwrap();
            }

            let mut b = [0_u8; P384_ECDSA_SIGNATURE_SIZE];
            // Read the signature's raw bytes out of OpenSSL.
            ffi::BN_bn2bin(r, b[(CAP - r_len)..CAP].as_mut_ptr());
            ffi::BN_bn2bin(s, b[(P384_ECDSA_SIGNATURE_SIZE - s_len)..P384_ECDSA_SIGNATURE_SIZE].as_mut_ptr());
            ffi::ECDSA_SIG_free(sig);
            b
        }
    }

    /// Perform ECDH key agreement, returning the raw (un-hashed!) ECDH secret.
    ///
    /// This secret should not be used directly. It should be hashed and perhaps used in a KDF.
    pub fn agree(&self, other_public: &P384PublicKey) -> Option<Secret<P384_ECDH_SHARED_SECRET_SIZE>> {
        let keypair = self.pair.lock().unwrap();
        let other_key = other_public.key.lock().unwrap();
        unsafe {
            let mut s: Secret<P384_ECDH_SHARED_SECRET_SIZE> = Secret::default();
            // Ask OpenSSL to perform DH between the keypair and the other key's public key object.
            if ECDH_compute_key(
                s.as_bytes_mut().as_mut_ptr(),
                P384_ECDH_SHARED_SECRET_SIZE as c_ulong,
                ffi::EC_KEY_get0_public_key(other_key.0),
                keypair.0,
                ptr::null(),
            ) == P384_ECDH_SHARED_SECRET_SIZE as c_int
            {
                Some(s)
            } else {
                None
            }
        }
    }
}

/// OpenSSL wrapper for a BN_CTX handle that guarantees free will be called.
struct OSSLBNC(*mut ffi::BN_CTX);
impl OSSLBNC {
    unsafe fn new() -> Result<Self, ErrorStack> {
        cvt_p(ffi::BN_CTX_new()).map(Self)
    }
}
impl Drop for OSSLBNC {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_CTX_free(self.0);
        }
    }
}
/// OpenSSL wrapper for a BIGNUM handle that guarantees free will be called.
struct OSSLBN(*mut ffi::BIGNUM);
impl OSSLBN {
    /// We would use OpenSSL's newer API for p384 if it actually supported raw byte encodings of keys.
    /// Until then we are stuck with the old API.
    unsafe fn from_slice(n: &[u8]) -> Result<Self, ErrorStack> {
        cvt_p(ffi::BN_bin2bn(n.as_ptr(), n.len() as c_int, ptr::null_mut())).map(Self)
    }
}
impl Drop for OSSLBN {
    fn drop(&mut self) {
        unsafe {
            ffi::BN_free(self.0);
        }
    }
}
/// OpenSSL wrapper for a EC_KEY handle that guarantees free will be called.
struct OSSLKey(*mut ffi::EC_KEY);
impl OSSLKey {
    /// Create an empty key, guaranteeing to the caller it has the correct group and will be freed.
    unsafe fn new() -> Result<Self, ErrorStack> {
        let key = cvt_p(ffi::EC_KEY_new())?;
        cvt(ffi::EC_KEY_set_group(key, GROUP_P384.0))?;
        Ok(Self(key))
    }
    /// Create a key, guaranteeing to the caller it has the correct group, has a public key and will be freed.
    ///
    /// We would use OpenSSL's newer API for p384 if it actually supported raw byte encodings of keys.
    /// Until then we are stuck with the old API.
    unsafe fn pub_from_slice(buffer: &[u8]) -> Result<OSSLKey, Option<ErrorStack>> {
        /// The public key is an ec_point, we need to be sure we free its memory
        struct Point(*mut ffi::EC_POINT);
        impl Point {
            unsafe fn new() -> Result<Self, ErrorStack> {
                cvt_p(ffi::EC_POINT_new(GROUP_P384.0)).map(Self)
            }
        }
        impl Drop for Point {
            fn drop(&mut self) {
                unsafe {
                    ffi::EC_POINT_free(self.0);
                }
            }
        }
        let bnc = OSSLBNC::new()?;
        let point = Point::new()?;
        // Ask OpenSSL to read the raw bytes into the OpenSSL object.
        cvt(ffi::EC_POINT_oct2point(GROUP_P384.0, point.0, buffer.as_ptr(), buffer.len(), bnc.0))?;
        // Check if the object is valid.
        if cvt_n(ffi::EC_POINT_is_on_curve(GROUP_P384.0, point.0, bnc.0))? == 1 {
            // Create an OpenSSL key and guarantee to the caller that the key was initialized with a
            // public key.
            let ec_key = OSSLKey::new()?;
            cvt(ffi::EC_KEY_set_public_key(ec_key.0, point.0))?;
            Ok(ec_key)
        } else {
            Err(None)
        }
    }
    /// Create a `Send`-able clone of the public key. We don't reference count for this reason.
    fn clone_public(&self) -> Result<Self, ErrorStack> {
        unsafe {
            let point = ffi::EC_KEY_get0_public_key(self.0);
            // Create an OpenSSL key and guarantee to the caller that the key was initialized with a
            // public key.
            let key = OSSLKey::new()?;
            cvt(ffi::EC_KEY_set_public_key(key.0, point))?;
            Ok(key)
        }
    }
}
impl Drop for OSSLKey {
    fn drop(&mut self) {
        unsafe {
            ffi::EC_KEY_free(self.0);
        }
    }
}
/// OpenSSL wrapper for a EC_GROUP that is used to tell rust that an OpenSSL EC_GROUP is threadsafe.
/// We only ever instantiate one of these with lazy_static. It is never freed.
struct OSSLGroup(*mut ffi::EC_GROUP);
impl OSSLGroup {
    unsafe fn p384() -> Self {
        Self(cvt_p(ffi::EC_GROUP_new_by_curve_name(ffi::NID_secp384r1)).unwrap())
    }
}
unsafe impl Send for OSSLGroup {}
unsafe impl Sync for OSSLGroup {}
lazy_static! {
    static ref GROUP_P384: OSSLGroup = unsafe { OSSLGroup::p384() };
}

#[cfg(test)]
mod tests {
    use crate::{p384::P384KeyPair, secure_eq};

    #[test]
    fn generate_sign_verify_agree() {
        let kp = P384KeyPair::generate();
        let kp2 = P384KeyPair::generate();
        let kp_pub = kp.to_public_key();
        let kp2_pub = kp2.to_public_key();

        let sig = kp.sign(&[0_u8; 16]);
        if !kp_pub.verify(&[0_u8; 16], &sig) {
            panic!("ECDSA verify failed");
        }
        if kp_pub.verify(&[1_u8; 16], &sig) {
            panic!("ECDSA verify succeeded for incorrect message");
        }

        let sec0 = kp.agree(&kp2_pub).unwrap();
        let sec1 = kp2.agree(&kp_pub).unwrap();
        if !secure_eq(&sec0, &sec1) {
            panic!("ECDH secrets do not match");
        }

        let pkb = kp.public_key_bytes();
        let skb = kp.secret_key_bytes();
        let kp3 = P384KeyPair::from_bytes(pkb, skb.as_ref()).unwrap();

        let pkb3 = kp3.public_key_bytes();
        let skb3 = kp3.secret_key_bytes();

        assert_eq!(pkb, pkb3);
        assert_eq!(skb.as_bytes(), skb3.as_bytes());

        let sig = kp3.sign(&[3_u8; 16]);
        if !kp_pub.verify(&[3_u8; 16], &sig) {
            panic!("ECDSA verify failed (from key reconstructed from bytes)");
        }
    }
}
