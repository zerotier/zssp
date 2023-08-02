use zeroize::Zeroizing;

use crate::crypto::{secure_eq, HashSha512};
use crate::proto::*;
/// A ratchet key and fingerprint,
/// along with the length of the ratchet chain the keys were derived from.
#[derive(Clone, Eq)]
pub struct RatchetState {
    pub key: Zeroizing<[u8; RATCHET_SIZE]>,
    pub fingerprint: Option<Zeroizing<[u8; RATCHET_SIZE]>>,
    pub chain_len: u64,
}
impl PartialEq for RatchetState {
    fn eq(&self, other: &Self) -> bool {
        secure_eq(&self.key, &other.key) & (self.chain_len == other.chain_len) &
        match (self.fingerprint.as_ref(), other.fingerprint.as_ref()) {
            (Some(rf1), Some(rf2)) => secure_eq(rf1, rf2),
            (None, None) => true,
            _ => false,
        }
    }
}
impl RatchetState {
    pub fn new(key: Zeroizing<[u8; RATCHET_SIZE]>, fingerprint: Zeroizing<[u8; RATCHET_SIZE]>, chain_len: u64) -> Self {
        RatchetState { key, fingerprint: Some(fingerprint), chain_len }
    }
    pub fn empty() -> Self {
        RatchetState { key: Zeroizing::new([0u8; RATCHET_SIZE]), fingerprint: None, chain_len: 0 }
    }

    pub fn new_from_otp<Hmac: HashSha512>(otp: &[u8]) -> RatchetState {
        let mut buffer = Vec::new();
        buffer.push(1);
        buffer.extend(LABEL_OTP_TO_RATCHET);
        buffer.push(0);
        buffer.extend((2u16 * 512u16).to_be_bytes());
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
}
