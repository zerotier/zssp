/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https://mozilla.org/MPL/2.0/.
*
* (c) ZeroTier, Inc.
* https://www.zerotier.com/
*/
use std::ops::Deref;
use crate::crypto::{HashSha512, secure_eq};
use crate::proto::*;

#[derive(Clone, PartialEq, Eq)]
pub enum RatchetState {
    Null,
    Empty,
    NonEmpty(NonEmptyRatchetState),
}
use RatchetState::*;
use zeroize::Zeroizing;
impl RatchetState {
    pub fn new_nonempty(key: Zeroizing<[u8; RATCHET_SIZE]>, fingerprint: Zeroizing<[u8; RATCHET_SIZE]>, chain_len: u64) -> Self {
        NonEmpty(NonEmptyRatchetState { key, fingerprint, chain_len })
    }
    pub fn new_initial_states() -> [RatchetState; 2] {
        [RatchetState::Empty, RatchetState::Null]
    }
    pub fn new_from_otp<Hmac: HashSha512>(otp: &[u8]) -> [RatchetState; 2] {
        let mut buffer = Vec::new();
        buffer.push(1);
        buffer.extend(LABEL_OTP_TO_RATCHET);
        buffer.push(0);
        buffer.extend((2u16 * 512u16).to_be_bytes());
        let r1 = Hmac::hmac(otp, &buffer);
        buffer[0] = 2;
        let r2 = Hmac::hmac(otp, &buffer);
        [
            Self::new_nonempty(Zeroizing::new(r1[..RATCHET_SIZE].try_into().unwrap()), Zeroizing::new(r2[..RATCHET_SIZE].try_into().unwrap()), 1),
            RatchetState::Null,
        ]
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Null)
    }
    pub fn is_empty(&self) -> bool {
        matches!(self, Empty)
    }
    pub fn nonempty(&self) -> Option<&NonEmptyRatchetState> {
        match self {
            NonEmpty(rs) => Some(rs),
            _ => None,
        }
    }
    pub fn chain_len(&self) -> u64 {
        self.nonempty().map_or(0, |rs| rs.chain_len)
    }
    pub fn fingerprint(&self) -> Option<&[u8; RATCHET_SIZE]> {
        self.nonempty().map(|rs| rs.fingerprint.deref())
    }
    pub fn key(&self) -> Option<&[u8; RATCHET_SIZE]> {
        const ZERO_KEY: [u8; RATCHET_SIZE] = [0u8; RATCHET_SIZE];
        match self {
            Null => None,
            Empty => Some(&ZERO_KEY),
            NonEmpty(rs) => Some(&rs.key),
        }
    }
}
/// A ratchet key and fingerprint,
/// along with the length of the ratchet chain the keys were derived from.
#[derive(Clone, Eq)]
pub struct NonEmptyRatchetState {
    pub key: Zeroizing<[u8; RATCHET_SIZE]>,
    pub fingerprint: Zeroizing<[u8; RATCHET_SIZE]>,
    pub chain_len: u64,
}
impl PartialEq for NonEmptyRatchetState {
    fn eq(&self, other: &Self) -> bool {
        secure_eq(&self.key, &other.key) && secure_eq(&self.fingerprint, &other.fingerprint) && self.chain_len == other.chain_len
    }
}
