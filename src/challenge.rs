use rand_core::{RngCore, CryptoRng};

use crate::crypto::sha512::Sha512;




const COUNTER_WINDOW_MAX_OOO: usize = 64;
const SALT_SIZE: usize = 32;
const COUNTER_SIZE: usize = 8;
const MAC_SIZE: usize = 16;
const POW_SIZE: usize = 8;
const TOTAL_SIZE: usize = COUNTER_SIZE + MAC_SIZE + POW_SIZE;

pub struct ChallengeContext {
    counter: u64,
    antireplay_window: [u64; COUNTER_WINDOW_MAX_OOO],
    salt: [u8; SALT_SIZE],
}

pub fn append_null_response<Rng: RngCore + CryptoRng>(rng: &mut Rng, packet: &mut Vec<u8>) {
    packet.extend(&[0; COUNTER_SIZE + MAC_SIZE]);
    packet.extend(&rng.next_u64().to_be_bytes());
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
    pub fn process_hello<Hash: Sha512>(&mut self, addr: impl std::hash::Hash, packet: &[u8; TOTAL_SIZE]) -> Option<Vec<u8>> {
        let mac_start = COUNTER_SIZE;
        let pow_start = mac_start + MAC_SIZE;
        let c = u64::from_be_bytes(packet[..mac_start].try_into().unwrap());
        if self.check_window(c) {
            let mut hash = Hash::new();
            hash.update(&packet[..mac_start]);
        } && secure_eq(&packet[mac_start..pow_start], )
    }
    /// Check the challenge window, returning true if the challenge is still valid.
    fn check_window(&self, counter: u64) -> bool {
        let slot = &self.antireplay_window[(counter as usize) % self.antireplay_window.len()];
        let counter = counter.wrapping_add(1);
        let prev_counter = *slot;
        prev_counter < counter
    }
    /// Update the challenge window, returning true if the challenge is still valid.
    fn update_window(&self, counter: u64) -> bool {
        let slot = &self.antireplay_window[(counter as usize) % self.antireplay_window.len()];
        let counter = counter.wrapping_add(1);
        let prev_counter = *slot;
        prev_counter < counter
    }
}
