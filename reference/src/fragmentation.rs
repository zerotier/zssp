use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;

use zeroize::Zeroizing;

use crate::application::{ApplicationLayer, CryptoLayer};
use crate::crypto::{Aes256Prp, AES_256_KEY_SIZE};
use crate::proto::*;
use crate::result::{byzantine_fault, ReceiveError};

/// Corresponds to Figure 13 found in Section 6.
fn create_fragment_header(
    kid_send: u32,
    fragment_count: usize,
    fragment_no: usize,
    n: &[u8; PACKET_NONCE_SIZE],
) -> [u8; HEADER_SIZE] {
    debug_assert!(fragment_count > 0);
    debug_assert!(fragment_count <= MAX_FRAGMENTS);
    debug_assert!(fragment_no < MAX_FRAGMENTS);
    let mut header = [0u8; HEADER_SIZE];
    header[..KID_SIZE].copy_from_slice(&kid_send.to_be_bytes());
    header[FRAGMENT_NO_IDX] = fragment_no as u8;
    header[FRAGMENT_COUNT_IDX] = fragment_count as u8;
    header[PACKET_NONCE_START..].copy_from_slice(n);
    header
}

/// Corresponds to the fragmentation algorithm described in Section 6.
pub fn send_with_fragmentation<Crypto: CryptoLayer>(
    mut send: impl FnMut(Vec<u8>) -> bool,
    mtu: usize,
    identifier: u32,
    packet_nonce: &[u8; PACKET_NONCE_SIZE],
    packet: &[u8],
    hk_send: Option<&[u8; AES_256_KEY_SIZE]>,
) -> bool {
    let payload_mtu = mtu - HEADER_SIZE;
    debug_assert!(payload_mtu >= 4);
    let fragment_count = packet.len().saturating_add(payload_mtu - 1) / payload_mtu; // Ceiling div.
    let fragment_base_size = packet.len() / fragment_count;
    let fragment_size_remainder = packet.len() % fragment_count;

    let mut i = 0;
    for fragment_no in 0..fragment_count {
        let j = i + fragment_base_size + (fragment_no < fragment_size_remainder) as usize;

        let header = create_fragment_header(identifier, fragment_count, fragment_no, packet_nonce);
        let mut fragment = Vec::new();
        fragment.extend(&header);
        fragment.extend(&packet[i..j]);

        if let Some(hk_send) = hk_send {
            Crypto::Prp::encrypt_in_place(
                hk_send,
                (&mut fragment[HEADER_AUTH_START..HEADER_AUTH_END]).try_into().unwrap(),
            );
        }
        if !send(fragment) {
            return false;
        }
        i = j;
    }
    true
}

pub struct DefragBuffer {
    fragment_map: RefCell<HashMap<[u8; PACKET_NONCE_SIZE], Buffer>>,
    hk_recv: Option<Zeroizing<[u8; AES_256_KEY_SIZE]>>,
}

struct Buffer {
    fragments: Vec<Option<Vec<u8>>>,
    fragment_max_size: usize,
    total: usize,
    expiration_time: i64,
}

impl DefragBuffer {
    pub fn new(hk_recv: Option<Zeroizing<[u8; AES_256_KEY_SIZE]>>) -> Self {
        Self { fragment_map: RefCell::new(HashMap::new()), hk_recv }
    }

    /// Corresponds to the authentication and defragmentation algorithm described in Section 6.1.
    pub fn received_fragment<App: ApplicationLayer>(
        &self,
        mut raw_fragment: Vec<u8>,
        current_time: i64,
        vrfy: impl FnOnce(&[u8; PACKET_NONCE_SIZE], usize, usize) -> Result<(), ReceiveError>,
    ) -> Result<Option<([u8; PACKET_NONCE_SIZE], Vec<u8>)>, ReceiveError> {
        use crate::result::FaultType::*;
        if raw_fragment.len() < MIN_PACKET_SIZE {
            return Err(byzantine_fault!(InvalidPacket, true));
        }

        if let Some(hk_recv) = self.hk_recv.as_ref() {
            <App::Crypto as CryptoLayer>::Prp::decrypt_in_place(
                hk_recv,
                (&mut raw_fragment[HEADER_AUTH_START..HEADER_AUTH_END])
                    .try_into()
                    .unwrap(),
            )
        }

        let fragment_no = raw_fragment[FRAGMENT_NO_IDX] as usize;
        let fragment_count = raw_fragment[FRAGMENT_COUNT_IDX] as usize;
        if fragment_no >= fragment_count || fragment_count > MAX_FRAGMENTS {
            return Err(byzantine_fault!(InvalidPacket, true));
        }

        let n = raw_fragment[PACKET_NONCE_START..HEADER_SIZE].try_into().unwrap();
        let result = vrfy(&n, fragment_no, fragment_count);
        if let Err(e) = result {
            return Err(e);
        }

        let expiration_time = current_time + App::Crypto::SETTINGS.fragment_assembly_timeout as i64;
        let mut map = self.fragment_map.borrow_mut();
        match map.entry(n) {
            Entry::Occupied(mut entry) => {
                let buffer = entry.get_mut();
                if fragment_count != buffer.fragments.len()
                    || buffer.fragments[fragment_no].is_some()
                    || raw_fragment.len() > buffer.fragment_max_size
                {
                    // Some parts of the protocol can cause duplicate fragments to be sent.
                    return Err(byzantine_fault!(InvalidPacket, false));
                }
                buffer.fragments[fragment_no] = Some(raw_fragment);
                buffer.total += 1;
                buffer.expiration_time = expiration_time;
                if buffer.total < buffer.fragments.len() {
                    return Ok(None);
                }
                let mut packet = Vec::new();
                for raw_fragment in &buffer.fragments {
                    let raw_fragment = raw_fragment.as_ref().unwrap();
                    packet.extend(&raw_fragment[HEADER_SIZE..]);
                }
                Ok(Some((n, packet)))
            }
            Entry::Vacant(entry) => {
                let fragment_max_size = raw_fragment.len() + 1;
                if fragment_count == 1 {
                    raw_fragment.copy_within(HEADER_SIZE.., 0);
                    raw_fragment.truncate(raw_fragment.len() - HEADER_SIZE);
                    return Ok(Some((n, raw_fragment)));
                }

                let mut fragments = Vec::new();
                fragments.resize(fragment_count, None);
                fragments[fragment_no] = Some(raw_fragment);
                entry.insert(Buffer { fragments, fragment_max_size, total: 1, expiration_time });
                Ok(None)
            }
        }
    }

    pub fn service(&self, current_time: i64) {
        let mut map = self.fragment_map.borrow_mut();
        map.retain(|_, buffer| buffer.expiration_time < current_time);
    }
}
