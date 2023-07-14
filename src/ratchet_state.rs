/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::num::NonZeroU64;

use crate::crypto::secret::Secret;
use crate::RATCHET_SIZE;

#[derive(Clone, PartialEq, Eq)]
pub enum RatchetState {
    Null,
    Empty,
    NonEmpty(NonEmptyRatchetState),
}
use RatchetState::*;
impl RatchetState {
    #[inline]
    pub fn new_nonempty(key: Secret<RATCHET_SIZE>, fingerprint: Secret<RATCHET_SIZE>, chain_len: NonZeroU64) -> Self {
        NonEmpty(NonEmptyRatchetState { key, fingerprint, chain_len })
    }
    #[inline]
    pub fn new_initial_states() -> [RatchetState; 2] {
        [RatchetState::Empty, RatchetState::Null]
    }
    #[inline]
    pub fn is_null(&self) -> bool {
        match self {
            Null => true,
            _ => false,
        }
    }
    #[inline]
    pub fn is_empty(&self) -> bool {
        match self {
            Empty => true,
            _ => false,
        }
    }
    #[inline]
    pub fn nonempty(&self) -> Option<&NonEmptyRatchetState> {
        match self {
            NonEmpty(rs) => Some(&rs),
            _ => None,
        }
    }
    #[inline]
    pub fn chain_len(&self) -> u64 {
        self.nonempty().map_or(0, |rs| rs.chain_len.get())
    }
    #[inline]
    pub fn fingerprint(&self) -> Option<&[u8; RATCHET_SIZE]> {
        self.nonempty().map_or(None, |rs| Some(&rs.fingerprint.as_ref()))
    }
    #[inline]
    pub fn key(&self) -> Option<&[u8; RATCHET_SIZE]> {
        const ZERO_KEY: [u8; RATCHET_SIZE] = [0u8; RATCHET_SIZE];
        match self {
            Null => None,
            Empty => Some(&ZERO_KEY),
            NonEmpty(rs) => Some(rs.key.as_ref()),
        }
    }
}
/// A ratchet key and fingerprint,
/// along with the length of the ratchet chain the keys were derived from.
#[derive(Clone, PartialEq, Eq)]
pub struct NonEmptyRatchetState {
    pub key: Secret<RATCHET_SIZE>,
    pub fingerprint: Secret<RATCHET_SIZE>,
    pub chain_len: NonZeroU64,
}
