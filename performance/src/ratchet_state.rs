use arrayvec::ArrayVec;
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
    pub chain_len: u64,
    pub key: Zeroizing<[u8; RATCHET_SIZE]>,
    pub fingerprint: Option<Zeroizing<[u8; RATCHET_SIZE]>>,
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
    pub fn new_from_otp<Hmac: Sha512Hmac>(otp: &[u8]) -> RatchetState {
        let mut buffer = ArrayVec::<u8, 23>::new();
        buffer.push(1);
        buffer.extend(*LABEL_OTP_TO_RATCHET);
        buffer.push(0x00);
        buffer.extend((1024u16).to_be_bytes());

        let mut hmac = Hmac::new();
        let mut output = Zeroizing::new([0u8; HASHLEN]);
        hmac.hash(otp, &buffer, &mut output);
        let rk = Zeroizing::new(output[..RATCHET_SIZE].try_into().unwrap());
        buffer[0] = 2;
        hmac.hash(otp, &buffer, &mut output);
        let rf = Zeroizing::new(output[..RATCHET_SIZE].try_into().unwrap());

        Self::new(rk, rf, 1)
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
    pub fn new_otp_states<Hmac: Sha512Hmac>(otp: &[u8]) -> Self {
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

#[cfg(feature = "serde")]
impl serde::Serialize for RatchetState {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        if let Some(rf) = &self.fingerprint {
            let mut seq = serializer.serialize_seq(Some(4))?;
            seq.serialize_element(&0u8)?;
            seq.serialize_element(&self.chain_len)?;
            seq.serialize_element(self.key.as_ref())?;
            seq.serialize_element(rf.as_ref())?;
            seq.end()
        } else {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(&0u8)?;
            seq.serialize_element(&self.chain_len)?;
            seq.serialize_element(self.key.as_ref())?;
            seq.end()
        }
    }
}
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RatchetState {
    fn deserialize<D>(deserializer: D) -> Result<RatchetState, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RatchetState;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a ratchet state sequence")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error;
                if Some(0u8) == seq.next_element()? {
                    if let Some(chain_len) = seq.next_element()? {
                        if let Some(rk) = seq.next_element::<&[u8]>()? {
                            if rk.len() == RATCHET_SIZE {
                                let mut key: Zeroizing<[u8; RATCHET_SIZE]> = Zeroizing::default();
                                key.copy_from_slice(rk);
                                let fingerprint = if let Some(rf) = seq.next_element::<&[u8]>()? {
                                    if rf.len() == RATCHET_SIZE {
                                        let mut fingerprint: Zeroizing<[u8; RATCHET_SIZE]> = Zeroizing::default();
                                        fingerprint.copy_from_slice(rf);
                                        Some(fingerprint)
                                    } else {
                                        return Err(A::Error::invalid_length(
                                            rf.len(),
                                            &"a ratchet fingerprint of length 32",
                                        ));
                                    }
                                } else {
                                    None
                                };

                                Ok(RatchetState { chain_len, key, fingerprint })
                            } else {
                                Err(A::Error::invalid_length(
                                    rk.len(),
                                    &"a ratchet key of length 32",
                                ))
                            }
                        } else {
                            Err(A::Error::custom("expected a ratchet key"))
                        }
                    } else {
                        Err(A::Error::custom("expected an unsigned integer"))
                    }
                } else {
                    Err(A::Error::custom("invalid version byte"))
                }
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}

#[cfg(feature = "serde")]
impl serde::Serialize for RatchetStates {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        use serde::ser::SerializeSeq;
        if let Some(state2) = &self.state2 {
            let mut seq = serializer.serialize_seq(Some(3))?;
            seq.serialize_element(&0u8)?;
            seq.serialize_element(&self.state1)?;
            seq.serialize_element(state2)?;
            seq.end()
        } else {
            let mut seq = serializer.serialize_seq(Some(2))?;
            seq.serialize_element(&0u8)?;
            seq.serialize_element(&self.state1)?;
            seq.end()
        }
    }
}
#[cfg(feature = "serde")]
impl<'de> serde::Deserialize<'de> for RatchetStates {
    fn deserialize<D>(deserializer: D) -> Result<RatchetStates, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        struct Visitor;

        impl<'de> serde::de::Visitor<'de> for Visitor {
            type Value = RatchetStates;

            fn expecting(&self, formatter: &mut std::fmt::Formatter) -> std::fmt::Result {
                formatter.write_str("a pair of ratchet states")
            }

            fn visit_seq<A>(self, mut seq: A) -> Result<Self::Value, A::Error>
            where
                A: serde::de::SeqAccess<'de>,
            {
                use serde::de::Error;
                if Some(0u8) == seq.next_element()? {
                    if let Some(state1) = seq.next_element()? {
                        Ok(RatchetStates { state1, state2: seq.next_element()? })
                    } else {
                        Err(A::Error::custom("expected a ratchet state"))
                    }
                } else {
                    Err(A::Error::custom("invalid version byte"))
                }
            }
        }
        deserializer.deserialize_seq(Visitor)
    }
}
