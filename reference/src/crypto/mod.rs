/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
mod aes;
pub use self::aes::*;

mod p384;
pub use self::p384::*;

mod sha512;
pub use sha512::*;

mod kyber1024;
pub use kyber1024::*;

// We re-export our dependencies so it is less of a headache for the implementor to use the same
// exact version of them.
pub use rand_core;
pub use zeroize;

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
