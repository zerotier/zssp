/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::mem::{needs_drop, zeroed, MaybeUninit};
use std::ptr::slice_from_raw_parts;

use crate::proto::MAX_FRAGMENTS;

pub(crate) struct Assembled<Fragment>(pub(crate) [MaybeUninit<Fragment>; MAX_FRAGMENTS], pub(crate) usize);

impl<Fragment> Assembled<Fragment> {
    pub(crate) fn new() -> Self {
        Self(unsafe { MaybeUninit::<[MaybeUninit<_>; MAX_FRAGMENTS]>::uninit().assume_init() }, 0)
    }
    pub(crate) fn is_empty(&self) -> bool {
        self.1 == 0
    }
    pub(crate) fn empty(&mut self) {
        for i in 0..self.1 {
            unsafe {
                self.0.get_unchecked_mut(i).assume_init_drop();
            }
        }
        self.1 = 0;
    }
}
impl<Fragment> AsRef<[Fragment]> for Assembled<Fragment> {
    #[inline(always)]
    fn as_ref(&self) -> &[Fragment] {
        unsafe { &*slice_from_raw_parts(self.0.as_ptr().cast::<Fragment>(), self.1) }
    }
}
impl<Fragment> Drop for Assembled<Fragment> {
    #[inline(always)]
    fn drop(&mut self) {
        self.empty()
    }
}

/// Fast packet defragmenter
pub struct Fragged<Fragment, const MAX_FRAGMENTS: usize> {
    count: u32,
    have: u64,
    nonce: [u8; 10],
    size: usize,
    frags: [MaybeUninit<Fragment>; MAX_FRAGMENTS],
}

impl<Fragment, const MAX_FRAGMENTS: usize> Fragged<Fragment, MAX_FRAGMENTS> {
    #[inline(always)]
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
    #[inline]
    pub(crate) fn assemble(
        &mut self,
        nonce: [u8; 10],
        fragment: Fragment,
        fragment_no: u8,
        fragment_count: u8,
        ret_assembled: &mut Assembled<Fragment>,
    ) {
        if fragment_no < fragment_count && (fragment_count as usize) <= MAX_FRAGMENTS {
            // If the counter has changed, reset the structure to receive a new packet.
            if nonce != self.nonce {
                self.drop_in_place();
                self.count = fragment_count as u32;
                self.nonce = nonce;
                self.size = 0;
            }

            let got = 1u64.wrapping_shl(fragment_no as u32);
            if got & self.have == 0 && self.count as u8 == fragment_count {
                self.have |= got;
                unsafe {
                    self.frags.get_unchecked_mut(fragment_no as usize).write(fragment);
                }
                if self.have == 1u64.wrapping_shl(self.count) - 1 {
                    self.have = 0;
                    self.count = 0;
                    self.nonce = [0; 10];
                    self.size = 0;
                    // Setting 'have' to 0 resets the state of this object, and the fragments
                    // are effectively moved into the Assembled<> container and returned. That
                    // container will drop them when it is dropped.
                    ret_assembled.empty();
                    ret_assembled.1 = fragment_count as usize;
                    unsafe {
                        std::ptr::copy_nonoverlapping(&self.frags[0], &mut ret_assembled.0[0], ret_assembled.1);
                    }
                }
            }
        }
    }

    /// Drops any remaining fragments and resets this object.
    #[inline(always)]
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
    #[inline(always)]
    fn drop(&mut self) {
        self.drop_in_place();
    }
}
