use std::collections::hash_map::RandomState;
use std::hash::{BuildHasher, Hash, Hasher};
use std::mem::MaybeUninit;

use crate::application::CryptoLayer;
use crate::crypto::AES_GCM_NONCE_SIZE;
use crate::fragged::Assembled;
use crate::proto::{MAX_FRAGMENTS, MAX_UNASSOCIATED_FRAGMENTS, MAX_UNASSOCIATED_PACKETS, MAX_UNASSOCIATED_PACKET_SIZE};

struct PacketMetadata {
    key: u64,
    frags_idx: u32,
    fragment_have: u64,
    fragment_count: u8,
    packet_size: u32,
    creation_time: i64,
}

pub(crate) struct UnassociatedFragCache<C: CryptoLayer> {
    dos_salt: RandomState,
    frags_first_unused: usize,
    frags_unused_size: usize,
    map: [PacketMetadata; MAX_UNASSOCIATED_PACKETS],
    frags: [MaybeUninit<C::IncomingPacketBuffer>; MAX_UNASSOCIATED_FRAGMENTS],
    map_idx: [u32; MAX_UNASSOCIATED_FRAGMENTS],
}
/// A combination of a hash table cache and a ring buffer for unassociated fragments.
/// Designed specifically to be extremely DDOS resistant.
/// This datastructure takes raw unauthenticated fragments straight from the network.
impl<C: CryptoLayer> UnassociatedFragCache<C> {
    pub(crate) fn new() -> Self {
        Self {
            dos_salt: RandomState::new(),
            frags_first_unused: 0,
            frags_unused_size: MAX_UNASSOCIATED_FRAGMENTS,
            map: std::array::from_fn(|_| PacketMetadata {
                key: 0,
                frags_idx: 0,
                fragment_have: 0,
                fragment_count: 0,
                packet_size: 0,
                creation_time: 0,
            }),
            frags: std::array::from_fn(|_| MaybeUninit::zeroed()),
            map_idx: std::array::from_fn(|_| u32::MAX),
        }
    }
    /// Add a fragment and return an assembled packet container if all fragments have been received.
    /// Will check that aad is the same for all fragments.
    /// Returns true if the fragment is a part of a new fragment.
    pub(crate) fn assemble(
        &mut self,
        nonce: &[u8; AES_GCM_NONCE_SIZE],
        remote_address: impl Hash,
        fragment_size: usize,
        fragment: C::IncomingPacketBuffer,
        fragment_no: usize,
        fragment_count: usize,
        current_time: i64,
        ret_assembled: &mut Assembled<C::IncomingPacketBuffer>,
    ) -> Option<i64> {
        debug_assert!(MAX_FRAGMENTS < MAX_UNASSOCIATED_FRAGMENTS);
        if fragment_no >= fragment_count
            || fragment_count > MAX_FRAGMENTS
            || fragment_size > MAX_UNASSOCIATED_PACKET_SIZE
        {
            return None;
        }

        let mut hasher = self.dos_salt.build_hasher();
        remote_address.hash(&mut hasher);
        hasher.write(nonce);
        let mut key = hasher.finish();
        if key == 0 {
            key = 1;
        }

        let map_len = self.map.len();
        let idx0 = (key as usize) % map_len;
        let mut idx1 = (key as usize) / map_len % (map_len - 1);
        if idx0 == idx1 {
            idx1 = map_len - 1;
        }

        // Open hash lookup of just 2 slots.
        // To DOS, an adversary would either need to volumetrically spam the defrag table to keep most slots full
        // or replay Alice's packet header from a spoofed physical path before Alice's packet is fully processed.
        // Volumetric spam is quite difficult since without the `dos_salt` value an adversary cannot
        // control which slots their fragments index to. And since Alice's packet header has a randomly
        // generated counter value replaying it in time requires extreme amounts of network control.
        let idx = if self.map[idx0].key == key {
            idx0
        } else if self.map[idx1].key == key {
            idx1
        } else if self.map[idx0].key == 0 || self.map[idx1].key == 0 {
            if fragment_count > self.frags_unused_size {
                // There are not enough free fragment slots so attempt to expire a bunch of entries.
                let _ = self.check_for_expiry_inner(C::SETTINGS.resend_time as i64, current_time);
            }
            if self.map[idx0].key == 0 {
                idx0
            } else {
                idx1
            }
        } else {
            // No room for a new entry so attempt to expire a bunch of entries.
            let _ = self.check_for_expiry_inner(C::SETTINGS.resend_time as i64, current_time);
            if self.map[idx0].key == 0 {
                idx0
            } else if self.map[idx1].key == 0 {
                idx1
            } else {
                // Give up and drop the fragment.
                return None;
            }
        };
        let mut new_expiry = None;
        if self.map[idx].key == 0 {
            // This is a new entry so initialize it.
            if fragment_count <= self.frags_unused_size {
                new_expiry = Some(current_time + C::SETTINGS.fragment_assembly_timeout as i64);
                let entry = &mut self.map[idx];
                entry.key = key;
                entry.frags_idx = self.frags_first_unused as u32;
                entry.fragment_have = 0;
                entry.fragment_count = fragment_count as u8;
                entry.packet_size = 0;
                entry.creation_time = current_time;

                for _ in 0..(entry.fragment_count as usize) {
                    self.map_idx[self.frags_first_unused] = idx as u32;
                    self.frags_first_unused = (self.frags_first_unused + 1) % self.frags.len();
                    self.frags_unused_size -= 1;
                }
            } else {
                // If there are not enough free fragment slots by this point we just drop the fragment.
                return None;
            }
        }
        let entry = &mut self.map[idx];

        let new_size = entry.packet_size + fragment_size as u32;
        let got = 1u64.wrapping_shl(fragment_no as u32);
        if got & entry.fragment_have == 0
            && fragment_count == entry.fragment_count as usize
            && new_size <= MAX_UNASSOCIATED_PACKET_SIZE as u32
        {
            entry.packet_size = new_size;
            entry.fragment_have |= got;

            let frag_idx = (entry.frags_idx as usize + fragment_no) % self.frags.len();
            self.frags[frag_idx].write(fragment);

            if entry.fragment_have == 1u64.wrapping_shl(fragment_count as u32) - 1 {
                debug_assert!(ret_assembled.is_empty());
                let start_idx = entry.frags_idx as usize;
                unsafe {
                    for i in start_idx..start_idx + fragment_count {
                        ret_assembled.push(self.frags[i % self.frags.len()].assume_init_read())
                    }
                }
                self.invalidate::<false>(idx);
            }
        }
        new_expiry
    }
    /// Returns the timestamp at which this function should be called again.
    pub(crate) fn check_for_expiry(&mut self, current_time: i64) -> i64 {
        self.check_for_expiry_inner(C::SETTINGS.fragment_assembly_timeout as i64, current_time)
    }
    fn check_for_expiry_inner(&mut self, timeout: i64, current_time: i64) -> i64 {
        while self.frags_unused_size < self.frags.len() {
            // Check if we can drop the entry at the start of the ring buffer.
            let frag_idx = (self.frags_first_unused + self.frags_unused_size) % self.frags.len();
            let map_idx = self.map_idx[frag_idx] as usize;
            debug_assert!(map_idx < self.map.len());

            let entry = &mut self.map[map_idx];
            let expiry = entry.creation_time + timeout;
            if expiry <= current_time {
                self.invalidate::<true>(map_idx);
            } else {
                return expiry;
            }
        }
        i64::MAX
    }

    fn invalidate<const DROP: bool>(&mut self, idx: usize) {
        let entry = &mut self.map[idx];
        let start_idx = entry.frags_idx as usize;
        for fragment_no in 0..(entry.fragment_count as usize) {
            let frag_idx = (start_idx + fragment_no) % self.frags.len();
            self.map_idx[frag_idx] = u32::MAX;
            // DROP is only false when we have moved the fragments out of this entry, and so we can't free them
            // Otherwise we need to manually drop all of the fragments that this entry owns.
            if DROP && entry.fragment_have & 1u64.wrapping_shl(fragment_no as u32) > 0 {
                unsafe { self.frags[frag_idx].assume_init_drop() };
            }
        }
        entry.key = 0;
        entry.frags_idx = 0;
        entry.fragment_have = 0;
        entry.fragment_count = 0;
        entry.packet_size = 0;
        entry.creation_time = 0;
        let mut frags_first_used = (self.frags_first_unused + self.frags_unused_size) % self.frags.len();
        if frags_first_used == start_idx {
            // `frags_unused_size` is pointing to the slot we just emptied.
            // Move `frags_unused_size` to point at the first non-empty slot.
            while self.frags_unused_size < self.frags.len() {
                if self.map_idx[frags_first_used] == u32::MAX {
                    self.frags_unused_size += 1;
                    frags_first_used = (self.frags_first_unused + self.frags_unused_size) % self.frags.len();
                } else {
                    break;
                }
            }
        }
    }
}
impl<C: CryptoLayer> Drop for UnassociatedFragCache<C> {
    fn drop(&mut self) {
        for i in 0..self.map.len() {
            if self.map[i].key != 0 {
                self.invalidate::<true>(i);
            }
        }
    }
}

#[test]
fn test_cache() {
    use std::sync::Mutex;
    fn xorshift64_random() -> u64 {
        static XORSHIFT64_STATE: Mutex<u64> = Mutex::new(12);
        let mut x = XORSHIFT64_STATE.lock().unwrap();
        *x ^= x.wrapping_shr(12);
        *x ^= x.wrapping_shl(25);
        *x ^= x.wrapping_shr(27);
        let r = *x;
        drop(x);
        r.wrapping_mul(0x2545F4914F6CDD1Du64)
    }
    use crate::crypto_impl::*;
    struct C {}
    impl CryptoLayer for C {
        type Rng = rand_core::OsRng;
        type PrpEnc = OpenSSLAes256Enc;
        type PrpDec = OpenSSLAes256Dec;
        type Aead = OpenSSLAesGcm;
        type AeadPool = OpenSSLAesGcmPool;
        type Hash = CrateSha512;
        type Hmac = CrateHmacSha512;
        type PublicKey = CrateP384PublicKey;
        type KeyPair = CrateP384KeyPair;
        type Kem = CrateKyber1024PrivateKey;

        type SessionData = ();
        type FingerprintData = ();
        type IncomingPacketBuffer = Vec<u8>;
    }

    let mut cache = UnassociatedFragCache::<C>::new();
    let mut assembled = Assembled::new();

    let mut time = 0;
    let mut in_progress = Vec::new();
    let mut in_progress_fragments = 0;
    // A basic fuzzer for testing the cache.
    for i in 0..5000u32 {
        let fragment_count = (xorshift64_random() as usize % MAX_FRAGMENTS) + 1;
        let r = xorshift64_random() as u8;
        if r & 1 == 0 {
            let mut packet = Vec::new();
            for j in 0..fragment_count {
                packet.push((j as u8, vec![0, 1, 2, 3, 4, 5, 6, r]));
                in_progress_fragments += 1;
            }
            in_progress.push((i, fragment_count as u8, packet));
        } else {
            assembled.clear();
            let drop = xorshift64_random() as usize % (2 * fragment_count);
            for j in 0..fragment_count {
                if drop != j {
                    let fragment = vec![0, 1, 2, 3, 4, 5, 6, r];
                    // If the timeout is 1 we should be guaranteed to get our packet cached.
                    let mut nonce = [0; 12];
                    nonce[..4].copy_from_slice(&i.to_be_bytes());
                    cache.assemble(
                        &nonce,
                        0,
                        fragment.len(),
                        fragment,
                        j,
                        fragment_count,
                        time,
                        &mut assembled,
                    );
                    time += 200;
                }
            }
            if drop >= fragment_count {
                assert!(
                    !assembled.is_empty(),
                    "Packet was dropped from the cache when it shouldn't have"
                );
                assert_eq!(
                    assembled.as_ref().len(),
                    fragment_count,
                    "Cache returned the wrong packet"
                );
                for j in 0..fragment_count {
                    assert_eq!(assembled.as_ref()[j][7], r, "Cache returned a corrupted packet");
                }
            } else {
                assert!(assembled.is_empty(), "Cache returned an incomplete packet");
            }
        }
        if r > 200 {
            if in_progress.len() > 0 {
                let to_remain = (xorshift64_random() as usize % in_progress_fragments) + 16;
                while in_progress_fragments > to_remain {
                    let (id, fragment_count, mut packet) =
                        in_progress.swap_remove(xorshift64_random() as usize % in_progress.len());
                    for _ in 0..((xorshift64_random() as usize % packet.len()) + 1) {
                        let (no, fragment) = packet.swap_remove(xorshift64_random() as usize % packet.len());

                        assembled.clear();
                        let mut nonce = [0; 12];
                        nonce[..4].copy_from_slice(&id.to_be_bytes());
                        cache.assemble(
                            &nonce,
                            0,
                            fragment.len(),
                            fragment,
                            no as usize,
                            fragment_count as usize,
                            time,
                            &mut assembled,
                        );
                        time += 200;
                        in_progress_fragments -= 1;

                        if packet.len() > 0 {
                            assert!(assembled.is_empty(), "Cache returned an incomplete packet");
                        }
                    }
                    if packet.len() > 0 {
                        in_progress.push((id, fragment_count, packet));
                    }
                }
            }
        }
    }
}
