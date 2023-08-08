// (c) 2020-2022 ZeroTier, Inc. -- currently proprietary pending actual release and licensing. See LICENSE.md.

pub mod aes;
pub mod kyber1024;
pub mod p384;
pub mod sha512;

// We re-export our dependencies so it is less of a headache for the implementor to use the same
// exact version of them.
pub use pqc_kyber;
pub use rand_core;

/// Constant time byte slice equality.
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
