/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
#[cfg(feature = "pqc_kyber")]
mod kyber1024;
#[cfg(feature = "pqc_kyber")]
pub use kyber1024::*;
#[cfg(feature = "pqc_kyber")]
pub use pqc_kyber;

#[cfg(feature = "p384")]
mod p384_impl;
#[cfg(feature = "p384")]
pub use p384;
#[cfg(feature = "p384")]
pub use p384_impl::*;

#[cfg(feature = "sha2")]
mod sha512;
#[cfg(feature = "sha2")]
pub use hmac;
#[cfg(feature = "sha2")]
pub use sha2;
#[cfg(feature = "sha2")]
pub use sha512::*;

#[cfg(feature = "openssl-sys")]
mod openssl;
#[cfg(feature = "openssl-sys")]
pub use openssl::*;
#[cfg(feature = "openssl-sys")]
pub use openssl_sys;

/// Any type which implements this trait will also auto-implement the `CryptoLayer` trait,
/// using the default set of cryptography implementations.
///
/// If you want to use this library, and don't care which specific implementations it uses,
/// then implement this trait instead of the `CryptoLayer` trait.
#[cfg(feature = "default-crypto")]
pub trait DefaultCrypto {
    /// Type for arbitrary opaque object for use by the application that is attached to
    /// each session.
    type SessionData;
    /// Data type for incoming packet buffers.
    ///
    /// This can be something like `Vec<u8>` or `Box<[u8]>` or it can be something like a pooled
    /// reusable buffer that automatically returns to its pool when ZSSP is done with it. ZSSP may
    /// hold these for a short period of time when assembling fragmented packets on the receive
    /// path.
    type IncomingPacketBuffer: AsMut<[u8]> + AsRef<[u8]>;
}
#[cfg(feature = "default-crypto")]
impl<C: DefaultCrypto> crate::application::CryptoLayer for C {
    type Rng = rand_core::OsRng;
    type PrpEnc = OpenSSLAes256Enc;
    type PrpDec = OpenSSLAes256Dec;
    type Aead = OpenSSLAesGcm;
    type AeadPool = OpenSSLAesGcmPool;
    type Hash = CrateSha512;
    type Hmac = CrateHmacSha512;
    type PublicKey = CrateP384PublicKey;
    type KeyPair = CrateP384KeyPair;
    type Kem = CrateKyber1024PrivateKey;
    type FingerprintData = ();

    type SessionData = C::SessionData;
    type IncomingPacketBuffer = C::IncomingPacketBuffer;
}
