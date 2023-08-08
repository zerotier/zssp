use zeroize::Zeroizing;

use crate::crypto::*;
use crate::proto::*;
/// A ratchet key and fingerprint,
/// along with the length of the ratchet chain the keys were derived from.
///
/// Implements constant time equality.
/// The hash implementation only uses the ratchet fingerprint.
/// Any operation involving the ratchet key must take constant time.
///
/// Corresponds to the Ratchet Key and Ratchet Fingerprint described in Section 3.
#[derive(Clone, Eq)]
pub struct RatchetState {
    pub key: Zeroizing<[u8; RATCHET_SIZE]>,
    pub fingerprint: Option<Zeroizing<[u8; RATCHET_SIZE]>>,
    pub chain_len: u64,
}
impl PartialEq for RatchetState {
    fn eq(&self, other: &Self) -> bool {
        let ret = match (self.fingerprint.as_ref(), other.fingerprint.as_ref()) {
            (Some(rf1), Some(rf2)) => secure_eq(rf1, rf2),
            (None, None) => true,
            _ => false,
        };
        ret & secure_eq(&self.key, &other.key) & (self.chain_len == other.chain_len)
    }
}
impl std::hash::Hash for RatchetState {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        if let Some(rf) = &self.fingerprint {
            state.write_u64(u64::from_ne_bytes(rf[..8].try_into().unwrap()))
        }
    }
}
impl RatchetState {
    pub fn new(key: Zeroizing<[u8; RATCHET_SIZE]>, fingerprint: Zeroizing<[u8; RATCHET_SIZE]>, chain_len: u64) -> Self {
        RatchetState { key, fingerprint: Some(fingerprint), chain_len }
    }
    pub fn new_raw(key: [u8; RATCHET_SIZE], fingerprint: [u8; RATCHET_SIZE], chain_len: u64) -> Self {
        RatchetState {
            key: Zeroizing::new(key),
            fingerprint: Some(Zeroizing::new(fingerprint)),
            chain_len,
        }
    }
    pub fn empty() -> Self {
        RatchetState {
            key: Zeroizing::new([0u8; RATCHET_SIZE]),
            fingerprint: None,
            chain_len: 0,
        }
    }
    pub fn new_from_otp<Hmac: Sha512Hash>(otp: &[u8]) -> RatchetState {
        let mut buffer = Vec::new();
        buffer.push(1);
        buffer.extend(LABEL_OTP_TO_RATCHET);
        buffer.push(0x00);
        buffer.extend((1024u16).to_be_bytes());
        let r1 = Hmac::hmac(otp, &buffer);
        buffer[0] = 2;
        let r2 = Hmac::hmac(otp, &buffer);
        Self::new(
            Zeroizing::new(r1[..RATCHET_SIZE].try_into().unwrap()),
            Zeroizing::new(r2[..RATCHET_SIZE].try_into().unwrap()),
            1,
        )
    }
    pub fn is_empty(&self) -> bool {
        self.fingerprint.is_none()
    }
    pub fn fingerprint_eq(&self, rf: &[u8; RATCHET_SIZE]) -> bool {
        self.fingerprint.as_ref().map_or(false, |rf0| secure_eq(rf0, rf))
    }
    pub fn fingerprint(&self) -> Option<&[u8; RATCHET_SIZE]> {
        self.fingerprint.as_deref()
    }
}
impl Default for RatchetState {
    fn default() -> Self {
        Self::empty()
    }
}

/// A pair of ratchet states.
/// It is expected that an instance of this object will be saved to a storage device per-peer,
/// and be restore-able via the `ApplicationLayer` trait.
///
/// This corresponds to the possible values of abstract variables `rf` and `rk` found in Section 4.3.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RatchetStates {
    pub state1: RatchetState,
    pub state2: Option<RatchetState>,
}
impl RatchetStates {
    pub fn new(state1: RatchetState, state2: Option<RatchetState>) -> Self {
        Self { state1, state2 }
    }
    pub fn new_initial_states() -> Self {
        Self { state1: RatchetState::empty(), state2: None }
    }
    pub fn new_otp_states<Hmac: Sha512Hash>(otp: &[u8]) -> Self {
        Self {
            state1: RatchetState::new_from_otp::<Hmac>(otp),
            state2: None,
        }
    }
}
impl Default for RatchetStates {
    fn default() -> Self {
        Self::new_initial_states()
    }
}

/// A set of references to ratchet states specifying how a remote peer's persistent
/// storage should be updated.
///
/// There should be only up to two ratchet states saved to storage at a time per peer.
/// Every time a new ratchet state is generated, a previous ratchet state will be deleted.
///
/// These are sensitive values should they ought to be securely stored.
#[derive(Clone)]
pub struct RatchetUpdate<'a> {
    /// The ratchet key and fingerprint to store in the first slot.
    pub state1: &'a RatchetState,
    /// The ratchet key and fingerprint to store in the second slot.
    pub state2: Option<&'a RatchetState>,
    /// Whether `state1` is a brand new ratchet state, or if it was previously saved.
    pub state1_was_just_added: bool,
    /// A previous ratchet key and fingerprint that now must be deleted from storage.
    /// This will have been a previously given value of `state1` or `state2`.
    pub deleted_state1: Option<&'a RatchetState>,
    /// A previous ratchet key and fingerprint that now must be deleted from storage.
    /// It is extremely rare that this field is occupied.
    pub deleted_state2: Option<&'a RatchetState>,
}
impl<'a> RatchetUpdate<'a> {
    pub fn to_states(&self) -> RatchetStates {
        RatchetStates::new(self.state1.clone(), self.state2.cloned())
    }
    pub fn added_fingerprint(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if self.state1_was_just_added {
            self.state1.fingerprint()
        } else {
            None
        }
    }
    pub fn deleted_fingerprint1(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if let Some(rs) = &self.deleted_state1 {
            rs.fingerprint()
        } else {
            None
        }
    }
    pub fn deleted_fingerprint2(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if let Some(rs) = &self.deleted_state2 {
            rs.fingerprint()
        } else {
            None
        }
    }
}
