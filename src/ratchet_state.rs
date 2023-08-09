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
    key: Zeroizing<[u8; RATCHET_SIZE]>,
    fingerprint: Option<Zeroizing<[u8; RATCHET_SIZE]>>,
    chain_len: u64,
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
    /// Creates a new ratchet state from the given ratchet key, ratchet fingerprint and chain length.
    pub fn new(key: Zeroizing<[u8; RATCHET_SIZE]>, fingerprint: Zeroizing<[u8; RATCHET_SIZE]>, chain_len: u64) -> Self {
        RatchetState { key, fingerprint: Some(fingerprint), chain_len }
    }
    /// Creates a new ratchet state from the given ratchet key, ratchet fingerprint and chain length.
    ///
    /// The caller should make sure any copies of these values are deleted from memory once they are
    /// no longer needed.
    pub fn new_raw(key: [u8; RATCHET_SIZE], fingerprint: [u8; RATCHET_SIZE], chain_len: u64) -> Self {
        RatchetState {
            key: Zeroizing::new(key),
            fingerprint: Some(Zeroizing::new(fingerprint)),
            chain_len,
        }
    }
    /// The ratchet key for this ratchet state. This is directly mixed into the master secret of a
    /// session and so is very sensitive. All operations upon a ratchet key must be implemented
    /// in constant time. The user should prefer to do nothing with the ratchet key besides copying
    /// it to or from a storage device.
    ///
    /// If `fingerprint` returns `None` then this is the "empty" ratchet state and the key will be
    /// all zeros.
    pub fn key(&self) -> &[u8; RATCHET_SIZE] {
        &self.key
    }
    /// Ratchet keys and fingerprints are "chained together", where each set is derived from the
    /// previous set.
    ///
    /// This function outputs the total length of that chain, as in the total number of previous
    /// ratchet states that this ratchet state was derived from.
    pub fn chain_len(&self) -> u64 {
        self.chain_len
    }
    /// Creates a new "empty" ratchet state, where the ratchet fingerprint is the
    /// empty string, the ratchet key is all zeros, and the chain length is 0.
    ///
    /// This value is the default value of `RatchetState`.
    pub fn empty() -> Self {
        RatchetState {
            key: Zeroizing::new([0u8; RATCHET_SIZE]),
            fingerprint: None,
            chain_len: 0,
        }
    }
    /// Creates a new ratchet state derived from a one-time-password. If both sides of a session use
    /// the same one-time-password then they can use this ratchet state to connect with each other
    /// for the first time.
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
    /// Returns true if this is the "empty" ratchet state, where the ratchet fingerprint is the
    /// empty string, the ratchet key is all zeros, and the chain length is 0.
    pub fn is_empty(&self) -> bool {
        self.fingerprint.is_none()
    }
    /// Checks if the fingerprint of this ratchet state equals the fingerprint contained in argument
    /// `rf`. Uses constant time equality.
    pub fn fingerprint_eq(&self, rf: &[u8; RATCHET_SIZE]) -> bool {
        self.fingerprint.as_ref().map_or(false, |rf0| secure_eq(rf0, rf))
    }
    /// The ratchet fingerprint for this ratchet state.
    ///
    /// If this returns `None` then the ratchet fingerprint is the empty string.
    /// This is the "empty" ratchet state and the key will be all zeros.
    ///
    /// The ratchet fingerprint value is sensitive and should be hidden,
    /// but the security of ZSSP can survive having this value leaked.
    /// Operations on a ratchet fingerprint should be implemented in constant time,
    /// but it is ok if they are not.
    pub fn fingerprint(&self) -> Option<&[u8; RATCHET_SIZE]> {
        self.fingerprint.as_deref()
    }
}
impl Default for RatchetState {
    fn default() -> Self {
        Self::empty()
    }
}

/// An ordered pair of two ratchet states.
/// It is expected that an instance of this object will be saved to a storage device per-peer,
/// and be restore-able via the `ApplicationLayer` trait.
///
/// This corresponds to the possible values of abstract variables `rf` and `rk` found in Section 4.3.
#[derive(Clone, PartialEq, Eq, Hash)]
pub struct RatchetStates {
    /// The first ratchet state from the pair.
    pub state1: RatchetState,
    /// The second ratchet state from the pair. It can, and usually will be `None`.
    pub state2: Option<RatchetState>,
}
impl RatchetStates {
    /// Creates a new pair of ratchet states. The order of the arguments matters, and it should be
    /// the same order that was originally given by an instance of the `RatchetUpdate` struct.
    pub fn new(state1: RatchetState, state2: Option<RatchetState>) -> Self {
        Self { state1, state2 }
    }
    /// Creates a new initial pair of ratchet states, where the first ratchet state is the empty
    /// ratchet state and the second is `None`.
    ///
    /// This value is the default value of `RatchetStates`.
    pub fn new_initial_states() -> Self {
        Self { state1: RatchetState::empty(), state2: None }
    }
    /// Creates a new initial pair of ratchet states from a one-time password.
    /// The first ratchet state will be derived from this password, while the second will be `None`.
    ///
    /// If both sides of a session use the same one-time-password then they can use this pair to
    /// connect with each other for the first time. This pair can be generated with this function,
    /// saved to persistent storage, and eventually restored by the `ApplicationLayer` when we
    /// attempt to form a session with the correct peer.
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
    /// Clones the `state1` and `state2` pair of ratchet states out of this struct and into a
    /// `RatchetStates` instance.
    pub fn to_states(&self) -> RatchetStates {
        RatchetStates::new(self.state1.clone(), self.state2.cloned())
    }
    /// Returns the new ratchet fingerprint that was added during this update, if any.
    pub fn added_fingerprint(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if self.state1_was_just_added {
            self.state1.fingerprint()
        } else {
            None
        }
    }
    /// Returns the first ratchet fingerprint that was deleted during this update, if any.
    pub fn deleted_fingerprint1(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if let Some(rs) = &self.deleted_state1 {
            rs.fingerprint()
        } else {
            None
        }
    }
    /// Returns the second fingerprint that was deleted during this update, if there was more than
    /// one ratchet state deleted during this update.
    ///
    /// It is extremely rare that this function ever returns `Some`, but it is possible.
    /// Users should explicitly test that their implementation is able to correctly delete more than
    /// 1 ratchet state at a time, because it is unlikely to occur under normal conditions.
    pub fn deleted_fingerprint2(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if let Some(rs) = &self.deleted_state2 {
            rs.fingerprint()
        } else {
            None
        }
    }
}
