use arrayvec::ArrayVec;
use std::mem::{needs_drop, MaybeUninit};

use crate::proto::MAX_FRAGMENTS;

pub type Assembled<Fragment> = ArrayVec<Fragment, MAX_FRAGMENTS>;

/// Fast packet defragmenter.
pub struct Fragged<Fragment, const MAX_FRAGMENTS: usize> {
    nonce: u64,
    count: u32,
    have: u64,
    frags: [MaybeUninit<Fragment>; MAX_FRAGMENTS],
}

impl<Fragment, const MAX_FRAGMENTS: usize> Fragged<Fragment, MAX_FRAGMENTS> {
    pub fn new() -> Self {
        debug_assert!(MAX_FRAGMENTS <= 64);
        Self {
            nonce: u64::MAX,
            count: 0,
            have: 0,
            frags: core::array::from_fn(|_| MaybeUninit::zeroed()),
        }
    }

    /// Add a fragment and return an assembled packet container if all fragments have been received.
    ///
    /// When a fully assembled packet is returned the internal state is reset and this object can
    /// be reused to assemble another packet.
    ///
    /// Will check that aad is the same for all fragments.
    ///
    /// This function only takes the 8 byte counter rather than the full 10 byte packet nonce,
    /// because it is used in places where that is the only value we expect to always change in ZSSP.
    pub(crate) fn assemble(
        &mut self,
        nonce: u64,
        fragment: Fragment,
        fragment_no: usize,
        fragment_count: usize,
        ret_assembled: &mut Assembled<Fragment>,
    ) {
        if fragment_no < fragment_count && fragment_count <= MAX_FRAGMENTS {
            // If the counter has changed, reset the structure to receive a new packet.
            if nonce != self.nonce {
                self.drop_in_place();
                self.count = fragment_count as u32;
                self.nonce = nonce;
            }

            let got = 1u64.wrapping_shl(fragment_no as u32);
            if got & self.have == 0 && self.count == fragment_count as u32 {
                self.have |= got;
                unsafe {
                    self.frags.get_unchecked_mut(fragment_no as usize).write(fragment);
                    if self.have == 1u64.wrapping_shl(self.count as u32) - 1 {
                        self.have = 0;
                        self.count = 0;
                        self.nonce = u64::MAX;
                        // Setting 'have' to 0 resets the state of this object, and the fragments
                        // are effectively moved into the Assembled<> container and returned. That
                        // container will drop them when it is dropped.
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
        self.nonce = u64::MAX;
    }
}

impl<Fragment, const MAX_FRAGMENTS: usize> Drop for Fragged<Fragment, MAX_FRAGMENTS> {
    fn drop(&mut self) {
        self.drop_in_place();
    }
}
