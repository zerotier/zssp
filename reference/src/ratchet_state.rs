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
    pub(crate) key: Zeroizing<[u8; RATCHET_SIZE]>,
    pub(crate) fingerprint: Zeroizing<[u8; RATCHET_SIZE]>,
    pub(crate) chain_len: u64,
}
impl PartialEq for RatchetState {
    fn eq(&self, other: &Self) -> bool {
        self.fingerprint.eq(&other.fingerprint) & (self.chain_len == other.chain_len)
    }
}
impl std::hash::Hash for RatchetState {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        state.write(self.fingerprint.as_ref())
    }
}
impl RatchetState {
    /// Creates a new ratchet state from the given ratchet key, ratchet fingerprint and chain length.
    pub fn new(key: Zeroizing<[u8; RATCHET_SIZE]>, fingerprint: Zeroizing<[u8; RATCHET_SIZE]>, chain_len: u64) -> Self {
        RatchetState { key, fingerprint, chain_len }
    }
    /// Creates a new ratchet state from the given ratchet key, ratchet fingerprint and chain length.
    ///
    /// The caller should make sure any copies of these values are deleted from memory once they are
    /// no longer needed.
    pub fn new_raw(key: [u8; RATCHET_SIZE], fingerprint: [u8; RATCHET_SIZE], chain_len: u64) -> Self {
        RatchetState {
            key: Zeroizing::new(key),
            fingerprint: Zeroizing::new(fingerprint),
            chain_len,
        }
    }
    /// Creates a new "zero" ratchet state, where the ratchet fingerprint is all zeros,
    /// the ratchet key is all zeros, and the chain length is 0.
    ///
    /// This value is the default value of `RatchetState`.
    pub fn zero() -> Self {
        RatchetState {
            key: Zeroizing::new([0u8; RATCHET_SIZE]),
            fingerprint: Zeroizing::new([0u8; RATCHET_SIZE]),
            chain_len: 0,
        }
    }
    /// Creates a new ratchet state derived from a one-time-password. If both sides of a session use
    /// the same one-time-password then they can use this ratchet state to connect with each other
    /// for the first time.
    pub fn new_from_otp<Hmac: Sha512Hash>(otp: &[u8]) -> RatchetState {
        let mut buffer = Vec::new();
        buffer.push(1);
        buffer.extend(*LABEL_OTP_TO_RATCHET);
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
    /// The ratchet fingerprint for this ratchet state.
    /// It could be all zeros if this is the "zero" ratchet state.
    ///
    /// The ratchet fingerprint value is sensitive and should be hidden,
    /// but the security of ZSSP can survive having this value leaked.
    /// Operations on a ratchet fingerprint should be implemented in constant time,
    /// but it is ok if they are not.
    pub fn fingerprint(&self) -> &[u8; RATCHET_SIZE] {
        &self.fingerprint
    }
    /// Ratchet keys and fingerprints are "chained together", where each set is derived from the
    /// previous set.
    ///
    /// This function outputs the total length of that chain, as in the total number of previous
    /// ratchet states that this ratchet state was derived from.
    pub fn chain_len(&self) -> u64 {
        self.chain_len
    }
    /// Returns true if this is the "zero" ratchet state, where the ratchet fingerprint is all zeros,
    /// the ratchet key is all zeros, and the chain length is 0.
    pub fn is_zero(&self) -> bool {
        secure_eq(self.fingerprint(), &[0u8; RATCHET_SIZE])
    }
    /// Checks if the fingerprint of this ratchet state equals the
    /// fingerprint contained in argument `rf`.
    ///
    /// Uses constant time equality.
    pub fn fingerprint_eq(&self, rf: &[u8; RATCHET_SIZE]) -> bool {
        secure_eq(self.fingerprint(), rf)
    }
    /// Returns true if the fingerprint of argument `this` equals the fingerprint represented by
    /// argument `rf`.
    /// If `this` is `None`, `this` is considered to be "null", as in a ratchet state that does not
    /// exist or has been deleted.
    /// If `rf` is `None`, `rf` is considered to be "null" as well.
    /// If `rf` is `Some(None)`, `rf` is considered to be the empty ratchet fingerprint.
    ///
    /// Uses constant time equality.
    pub fn fingerprint_eq_nullable(this: Option<&Self>, rf: Option<&[u8; RATCHET_SIZE]>) -> bool {
        match (this, rf) {
            (Some(this), Some(rf)) => this.fingerprint_eq(rf),
            (None, None) => true,
            _ => false,
        }
    }
}
impl Default for RatchetState {
    fn default() -> Self {
        Self::zero()
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
    /// The second ratchet state from the pair.
    /// It can, and usually will be `None`, which means that this ratchet state is "null".
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
        Self { state1: RatchetState::zero(), state2: None }
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
/// A set of references to ratchet states specifying how a remote peer's persistent storage should
/// be updated. This struct is designed to provide any and all potentially needed data for
/// maintaining a store of these ratchet states. It should be straightforward to commit these updates
/// to anything from an in-memory hashtable to a disk-based database.
///
/// There will only be up to two ratchet states saved to storage at a time per peer.
/// Every time a third ratchet state is generated, a previous ratchet state will be deleted.
///
/// As the name implies, these updates should be applied as one atomic compare-and-swap operation.
/// If the two ratchet states currently in storage equal `cur_state1` and `cur_state2`,
/// then `new_state1` and `new_state2` should overwrite them.
/// If not, then storage must not be modified.
///
/// Ratchet keys must never be checked for equality. Instead, if two ratchet states have equal
/// ratchet fingerprints, it should be assumed that they also have equal ratchet keys.
/// This policy exists to reduce the security impact of timing and other side-channel attacks.
///
/// These are sensitive values and ought to be securely stored, with restricted read-write
/// permissions if stored on disk.
#[derive(Clone)]
pub struct CompareAndSwap<'a> {
    /// The ratchet state to store in the first slot.
    pub new_state1: &'a RatchetState,
    /// The ratchet state to store in the second slot.
    /// A value of `None` implies that the second slot should be set to null.
    pub new_state2: Option<&'a RatchetState>,
    /// This field is `true` if and only if `new_state1 != cur_state1` and `new_state1 != cur_state2`.
    ///
    /// This implies whether `state1` is a brand new ratchet state, or if it was previously saved.
    pub new_state1_was_just_added: bool,
    /// The ratchet state that we expect to see in the first slot.
    /// If this value is not currently stored in the first slot, the entire update must be aborted.
    pub cur_state1: &'a RatchetState,
    /// The ratchet state that we expect to see in the second slot.
    /// A value of `None` implies we expect the second slot to be set to "null".
    ///
    /// If this value is not currently stored in the second slot, the entire update must be aborted.
    pub cur_state2: Option<&'a RatchetState>,
    /// This field is `true` if and only if `cur_state1 != new_state1` and `cur_state1 != new_state2`.
    pub cur_state1_was_just_deleted: bool,
    /// This field is `true` if and only if `cur_state2 != new_state1` and `cur_state2 != new_state2`.
    pub cur_state2_was_just_deleted: bool,
}
impl<'a> CompareAndSwap<'a> {
    pub(crate) fn new(
        new_state1: &'a RatchetState,
        new_state2: Option<&'a RatchetState>,
        new_state1_was_just_added: bool,
        cur_state1: &'a RatchetState,
        cur_state2: Option<&'a RatchetState>,
        cur_state1_was_just_deleted: bool,
        cur_state2_was_just_deleted: bool,
    ) -> Self {
        Self {
            new_state1,
            new_state2,
            new_state1_was_just_added,
            cur_state1,
            cur_state2,
            cur_state1_was_just_deleted,
            cur_state2_was_just_deleted,
        }
    }
    /// Returns the final `RatchetStates` that must be swapped into storage if this update is
    /// fully committed.
    /// Future calls to `ApplicationLayer::restore_by_identity` should return this struct.
    pub fn to_new_states(&self) -> RatchetStates {
        RatchetStates::new(self.new_state1.clone(), self.new_state2.cloned())
    }
    /// Returns the `RatchetStates` that is expected to currently be in storage for this peer.
    /// This value must be compared with the current value in storage, and if they are equal,
    /// the return value of `CompareAndSwap::to_new_states` must overwrite it.
    pub fn to_cur_states(&self) -> RatchetStates {
        RatchetStates::new(self.cur_state1.clone(), self.cur_state2.cloned())
    }
    /// If this update specifies adding a brand new ratchet fingerprint, this function will return it.
    /// The returned ratchet fingerprint will always be the ratchet fingerprint of field `state1`.
    ///
    /// If a fingerprint is returned then it is guaranteed that `state1_was_just_added` will be `true`.
    pub fn added_fingerprint(&self) -> Option<&[u8; RATCHET_SIZE]> {
        self.new_state1_was_just_added.then_some(self.new_state1.fingerprint())
    }
    /// If this updated specifies to delete `cur_state1`, and `cur_state1` has a non-zero ratchet
    /// fingerprint, this function will return the ratchet fingerprint.
    ///
    /// If `cur_state1` is not being deleted (i.e. `cur_state1 == new_state1` or
    /// `cur_state1 == new_state2`), then this will return `None`.
    ///
    /// There may be a second ratchet fingerprint to be deleted, which function
    /// `deleted_fingerprint2` will return.
    pub fn deleted_fingerprint1(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if self.cur_state1_was_just_deleted && !self.cur_state1.is_zero() {
            return Some(self.cur_state1.fingerprint());
        }
        None
    }
    /// If this updated specifies to delete `cur_state2`, and `cur_state2` has a non-zero ratchet
    /// fingerprint, this function will return the ratchet fingerprint.
    ///
    /// If `cur_state2` is not being deleted (i.e. `cur_state2 == new_state1` or
    /// `cur_state2 == new_state2`), then this will return `None`.
    ///
    /// There may be a second ratchet fingerprint to be deleted, which function
    /// `deleted_fingerprint1` will return.
    pub fn deleted_fingerprint2(&self) -> Option<&[u8; RATCHET_SIZE]> {
        if self.cur_state2_was_just_deleted {
            if let Some(rf) = self.cur_state2 {
                if !rf.is_zero() {
                    return Some(rf.fingerprint());
                }
            }
        }
        None
    }
    /// Returns true if the currently stored ratchet states are expected to be the initial ratchet
    /// states. This is the default value for a peer's ratchet states in the event they could not
    /// be found in storage.
    ///
    /// If a peer could not be found in storage, and this function returns true,
    /// then the peer should be added to storage with the new ratchet states specified by this
    /// `CompareAndSwap` struct.
    pub fn cur_is_initial_states(&self) -> bool {
        self.cur_state1.is_zero() && self.cur_state2.is_none()
    }
    /// Compares the ratchet fingerprints of `cur_state1` and `cur_state2` with `rf1` and `rf2`.
    /// If they are equal this function will return `true`.
    ///
    /// If this function returns `true`, then the implementation may proceed to swap out the ratchet
    /// states these fingerprints come from with `new_state1` and `new_state2`.
    pub fn compare_fingerprints(&self, rf1: &[u8; RATCHET_SIZE], rf2: Option<&[u8; RATCHET_SIZE]>) -> bool {
        self.cur_state1.fingerprint_eq(rf1) & RatchetState::fingerprint_eq_nullable(self.cur_state2, rf2)
    }
    /// Compares `cur_state1` and `cur_state2` with `other.state1` and `other.state2`.
    /// If they are equal this function will return `true`.
    ///
    /// If this function returns `true`, then the implementation may proceed to swap `other.state1`
    /// and `other.state2` with `new_state1` and `new_state2`.
    pub fn compare(&self, other: &RatchetStates) -> bool {
        self.cur_state1.eq(&other.state1) & self.cur_state2.eq(&other.state2.as_ref())
    }
}
