use std::hash::Hasher;
use std::sync::atomic::{AtomicU64, Ordering};

use rand_core::{CryptoRng, RngCore};

use crate::antireplay::Window;
use crate::crypto::*;
use crate::proto::*;

pub struct ChallengeContext {
    counter: AtomicU64,
    antireplay_window: Window<CHALLENGE_COUNTER_WINDOW_MAX_OOO, { u64::MAX }>,
    salt: [u8; SALT_SIZE],
}

/// Corresponds to Algorithm 11 found in Section 5.
pub fn gen_null_response<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> [u8; CHALLENGE_SIZE] {
    let mut response = [0u8; CHALLENGE_SIZE];
    response[POW_START..].copy_from_slice(&rng.next_u64().to_be_bytes());
    response
}
/// Corresponds to Algorithm 13 found in Section 5.
pub fn respond_to_challenge_in_place<Rng: RngCore + CryptoRng, Hash: HashSha512>(
    rng: &mut Rng,
    challenge: &[u8; CHALLENGE_SIZE],
    pre_response: &mut [u8; CHALLENGE_SIZE],
) {
    if &challenge[POW_START..] == &pre_response[POW_START..] {
        pre_response.copy_from_slice(challenge);
        let mut pow = rng.next_u64();
        let mut work_buf = [0u8; SHA512_HASH_SIZE];
        loop {
            pre_response[POW_START..].copy_from_slice(&pow.to_be_bytes());
            if verify_pow::<Hash>(pre_response, &mut work_buf) {
                return;
            }
            pow = pow.wrapping_add(1);
        }
    }
}

impl ChallengeContext {
    pub fn new<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> Self {
        let mut salt = [0u8; SALT_SIZE];
        rng.fill_bytes(&mut salt);
        Self {
            counter: AtomicU64::new(0),
            antireplay_window: Window::new(),
            salt,
        }
    }
    /// Corresponds to Algorithm 12 found in Section 5.
    pub fn process_hello<Hash: HashSha512>(
        &self,
        addr: &impl std::hash::Hash,
        response: &[u8; CHALLENGE_SIZE],
    ) -> Result<(), [u8; CHALLENGE_SIZE]> {
        let c = u64::from_be_bytes(response[..COUNTER_SIZE].try_into().unwrap());
        let mut work_buf = [0u8; SHA512_HASH_SIZE];
        if self.antireplay_window.check(c)
            && secure_eq(&response[COUNTER_SIZE..POW_START], &self.create_mac::<Hash>(c, addr))
            && verify_pow::<Hash>(response, &mut work_buf)
        {
            self.antireplay_window.update(c);
            Ok(())
        } else {
            let mut challenge = [0u8; CHALLENGE_SIZE];
            let d = self.counter.fetch_add(1, Ordering::Relaxed);
            challenge[..COUNTER_SIZE].copy_from_slice(&d.to_be_bytes());
            challenge[COUNTER_SIZE..POW_START].copy_from_slice(&self.create_mac::<Hash>(d, addr));
            challenge[POW_START..].copy_from_slice(&response[POW_START..]);
            Err(challenge)
        }
    }
    fn create_mac<Hash: HashSha512>(&self, c: u64, addr: &impl std::hash::Hash) -> [u8; MAC_SIZE] {
        let mut h = Hash::new();
        let mut hasher = ShaHasher(&mut h);
        hasher.write(&c.to_be_bytes());
        addr.hash(&mut hasher);
        hasher.write(&self.salt);
        drop(hasher);

        let mut mac = [0u8; SHA512_HASH_SIZE];
        h.finish_and_reset(&mut mac);
        mac[..MAC_SIZE].try_into().unwrap()
    }
}

/// Trick rust into letting us use a hasher that returns more than 64 bits.
struct ShaHasher<'a, ShaImpl: HashSha512>(&'a mut ShaImpl);
impl<'a, ShaImpl: HashSha512> Hasher for ShaHasher<'a, ShaImpl> {
    fn finish(&self) -> u64 {
        unimplemented!()
    }
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }
}

/// Check if the proof of work attached to the first message contains the correct number of leading
/// zeros.
fn verify_pow<Hash: HashSha512>(response: &[u8], work_buf: &mut [u8; SHA512_HASH_SIZE]) -> bool {
    let mut hasher = Hash::new();
    hasher.update(response);
    hasher.finish_and_reset(work_buf);
    let n = u32::from_be_bytes(work_buf[..4].try_into().unwrap());
    n.leading_zeros() >= DIFFICULTY
}
