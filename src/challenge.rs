use std::hash::Hasher;

use rand_core::{CryptoRng, RngCore};

use crate::crypto::{
    secret::secure_eq,
    sha512::{Sha512, SHA512_HASH_SIZE},
};

const COUNTER_SIZE: usize = 8;
const MAC_SIZE: usize = 16;
const POW_SIZE: usize = 8;
const POW_START: usize = COUNTER_SIZE + MAC_SIZE;
pub const CHALLENGE_SIZE: usize = COUNTER_SIZE + MAC_SIZE + POW_SIZE;
const COUNTER_WINDOW_MAX_OOO: usize = 64;
const SALT_SIZE: usize = 32;
const DIFFICULTY: u32 = 13;

pub struct ChallengeContext {
    counter: u64,
    antireplay_window: [u64; COUNTER_WINDOW_MAX_OOO],
    salt: [u8; SALT_SIZE],
}

pub fn append_null_response<Rng: RngCore + CryptoRng>(rng: &mut Rng) -> [u8; CHALLENGE_SIZE] {
    let mut response = [0u8; CHALLENGE_SIZE];
    response[POW_START..].copy_from_slice(&rng.next_u64().to_be_bytes());
    response
}

pub fn respond_to_challenge_in_place<Rng: RngCore + CryptoRng, Hash: Sha512>(
    rng: &mut Rng,
    challenge: &mut [u8; CHALLENGE_SIZE],
    pre_response: &mut [u8; CHALLENGE_SIZE],
) {
    if &challenge[POW_START..] == &pre_response[POW_START..] {
        pre_response.copy_from_slice(challenge);
        let mut pow = rng.next_u64();
        loop {
            pre_response[POW_START..].copy_from_slice(&pow.to_ne_bytes());
            if verify_pow::<Hash>(pre_response) {
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
            counter: 0,
            antireplay_window: std::array::from_fn(|_| 0),
            salt,
        }
    }
    pub fn process_hello<Hash: Sha512>(&mut self, addr: &impl std::hash::Hash, response: &[u8; CHALLENGE_SIZE]) -> Option<Vec<u8>> {
        let c = u64::from_be_bytes(response[..COUNTER_SIZE].try_into().unwrap());
        if self.check_window(c)
            && secure_eq(&response[COUNTER_SIZE..POW_START], &self.create_mac::<Hash>(c, addr))
            && verify_pow::<Hash>(response)
        {
            self.update_window(c);
            None
        } else {
            let mut challenge = Vec::new();
            let d = self.counter;
            self.counter += 1;
            challenge.extend(&d.to_be_bytes());
            challenge.extend(&self.create_mac::<Hash>(d, addr));
            challenge.extend(&response[POW_START..]);
            Some(challenge)
        }
    }
    fn create_mac<Hash: Sha512>(&self, c: u64, addr: &impl std::hash::Hash) -> [u8; SHA512_HASH_SIZE] {
        let mut h = Hash::new();
        let mut hasher = ShaHasher(&mut h);
        hasher.write(&c.to_be_bytes());
        addr.hash(&mut hasher);
        hasher.write(&self.salt);
        let mut mac = [0u8; SHA512_HASH_SIZE];
        hasher.0.finish(&mut mac);
        mac
    }
    /// Check the challenge window, returning true if the challenge is still valid.
    fn check_window(&self, counter: u64) -> bool {
        let slot = &self.antireplay_window[(counter as usize) % self.antireplay_window.len()];
        let counter = counter.wrapping_add(1);
        let prev_counter = *slot;
        prev_counter < counter
    }
    /// Update the challenge window, returning true if the challenge is still valid.
    fn update_window(&mut self, counter: u64) {
        let slot = &mut self.antireplay_window[(counter as usize) % self.antireplay_window.len()];
        *slot = counter.wrapping_add(1);
    }
}

/// Trick rust into letting us use a hasher that returns more than 64 bits.
struct ShaHasher<'a, ShaImpl: Sha512>(&'a mut ShaImpl);
impl<'a, ShaImpl: Sha512> Hasher for ShaHasher<'a, ShaImpl> {
    fn finish(&self) -> u64 {
        unimplemented!()
    }
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }
}

/// Check if the proof of work attached to the first message contains the correct number of leading
/// zeros.
fn verify_pow<Hash: Sha512>(response: &[u8]) -> bool {
    if DIFFICULTY == 0 {
        return true;
    }
    let mut hasher = Hash::new();
    hasher.update(response);
    let mut output = [0u8; SHA512_HASH_SIZE];
    hasher.finish(&mut output);
    let n = u32::from_be_bytes(output[..4].try_into().unwrap());
    n.leading_zeros() >= DIFFICULTY
}
