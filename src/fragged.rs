/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use arrayvec::ArrayVec;
use std::mem::{needs_drop, zeroed, MaybeUninit};

use crate::crypto::AES_GCM_IV_SIZE;
use crate::proto::{MAX_FRAGMENTS, NONCE_SIZE_DIFF};

pub type Assembled<Fragment> = ArrayVec<Fragment, MAX_FRAGMENTS>;

/// Fast packet defragmenter
pub struct Fragged<Fragment, const MAX_FRAGMENTS: usize> {
    nonce: [u8; 10],
    count: u8,
    have: u64,
    size: usize,
    frags: [MaybeUninit<Fragment>; MAX_FRAGMENTS],
}

impl<Fragment, const MAX_FRAGMENTS: usize> Fragged<Fragment, MAX_FRAGMENTS> {
    pub fn new() -> Self {
        debug_assert!(MAX_FRAGMENTS <= 64);
        unsafe { zeroed() }
    }

    /// Add a fragment and return an assembled packet container if all fragments have been received.
    ///
    /// When a fully assembled packet is returned the internal state is reset and this object can
    /// be reused to assemble another packet.
    ///
    /// Will check that aad is the same for all fragments.
    pub(crate) fn assemble(
        &mut self,
        nonce: &[u8; AES_GCM_IV_SIZE],
        fragment: Fragment,
        fragment_no: usize,
        fragment_count: usize,
        ret_assembled: &mut Assembled<Fragment>,
    ) {
        if fragment_no < fragment_count && fragment_count <= MAX_FRAGMENTS {
            let nonce = nonce[NONCE_SIZE_DIFF..].try_into().unwrap();
            // If the counter has changed, reset the structure to receive a new packet.
            if nonce != self.nonce {
                self.drop_in_place();
                self.count = fragment_count as u8;
                self.nonce = nonce;
                self.size = 0;
            }

            let got = 1u64.wrapping_shl(fragment_no as u32);
            if got & self.have == 0 && self.count == fragment_count as u8 {
                self.have |= got;
                unsafe {
                    self.frags.get_unchecked_mut(fragment_no as usize).write(fragment);
                }
                if self.have == 1u64.wrapping_shl(self.count as u32) - 1 {
                    self.have = 0;
                    self.count = 0;
                    self.nonce = [0; 10];
                    self.size = 0;
                    // Setting 'have' to 0 resets the state of this object, and the fragments
                    // are effectively moved into the Assembled<> container and returned. That
                    // container will drop them when it is dropped.
                    unsafe {
                        for i in 0..fragment_count {
                            ret_assembled.push(self.frags[i].assume_init_read());
                        }
                    }
                }
            }
        }
    }

    /// Drops any remaining fragments and resets this object.
    pub fn drop_in_place(&mut self) {
        if needs_drop::<Fragment>() {
            let mut have = self.have;
            let mut i = 0;
            while have != 0 {
                if (have & 1) != 0 {
                    debug_assert!(i < MAX_FRAGMENTS);
                    unsafe { self.frags.get_unchecked_mut(i).assume_init_drop() };
                }
                have = have.wrapping_shr(1);
                i += 1;
            }
        }
        self.have = 0;
        self.count = 0;
        self.nonce = [0; 10];
        self.size = 0;
    }
}

impl<Fragment, const MAX_FRAGMENTS: usize> Drop for Fragged<Fragment, MAX_FRAGMENTS> {
    fn drop(&mut self) {
        self.drop_in_place();
    }
}
