/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::hash::Hasher;
use std::mem::size_of;

use crate::crypto::aes_gcm::AES_GCM_TAG_SIZE;
use crate::crypto::p384::P384_PUBLIC_KEY_SIZE;
use crate::crypto::pqc_kyber::{KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES};
use crate::crypto::sha512::{Sha512, SHA512_HASH_SIZE};
use hex_literal::hex;

/// Minimum size of a valid physical ZSSP packet of any type. Anything smaller is discarded.
pub const MIN_PACKET_SIZE: usize = HEADER_SIZE + AES_GCM_TAG_SIZE;

/// Minimum physical MTU for ZSSP to function.
pub const MIN_TRANSPORT_MTU: usize = 128;

pub const RATCHET_SIZE: usize = 32;

/// The application has the ability to attach a data payload to Alice's handshake.
/// It will be the first payload Bob receives from Alice.
/// The application also must attach a static public identity to their handshake.
/// The combined size of both in bytes must be at most this value.
///
/// If not ZSSP will return `OpenError::DataTooLarge` and refuse to create a session object.
pub const MAX_IDENTITY_BLOB_SIZE: usize = NoiseXKPattern3::MAX_SIZE - NoiseXKPattern3::MIN_SIZE;

/// Initial value of 'h'.
/// echo -n 'Noise_XKhfs+psk2_P384+Kyber1024_AESGCM_SHA512' | shasum -a 512
pub(crate) const INITIAL_H: [u8; SHA512_HASH_SIZE] =
    hex!("cd1f422196a5a614e24392cf34dcbf340ee61ad6ee6834274ff35fd42a7a5c44d04a045101555548a291778dd036b93ae21005a26c003213f57a5df9fb17f745");
/// Initial value of 'ck' for rekeying.
/// echo -n 'Noise_KKpsk0_P384_AESGCM_SHA512' | shasum -a 512
pub(crate) const INITIAL_H_REKEY: [u8; SHA512_HASH_SIZE] =
    hex!("daeedd651ac9c5173f2eaaff996beebac6f3f1bfe9a70bb1cc54fa1fb2bf46260d71a3c4fb4d4ee36f654c31773a8a15e5d5be974a0668dc7db70f4e13ed172e");

pub(crate) const SESSION_ID_SIZE: usize = 4;

pub(crate) const PACKET_TYPE_NOISE_XK_PATTERN_1: u8 = 0;
pub(crate) const PACKET_TYPE_NOISE_XK_PATTERN_2: u8 = 1;
pub(crate) const PACKET_TYPE_NOISE_XK_PATTERN_3: u8 = 2;
pub(crate) const PACKET_TYPE_KEY_CONFIRM: u8 = 3;
pub(crate) const PACKET_TYPE_ACK: u8 = 4;
pub(crate) const PACKET_TYPE_NOISE_KK_PATTERN_1: u8 = 5;
pub(crate) const PACKET_TYPE_NOISE_KK_PATTERN_2: u8 = 6;
pub(crate) const PACKET_TYPE_SESSION_REJECTED: u8 = 7;
pub(crate) const PACKET_TYPE_DATA: u8 = 8;
pub(crate) const PACKET_TYPE_BOB_DOS_CHALLENGE: u8 = 9;
pub(crate) const PACKET_TYPE_RANGE_TRANSPORT: std::ops::Range<u8> = 3..9;

/// Noise asks that the counter be initialized to 0 but for out of order reasons we have
/// to start it at 1.
/// Since with unreliable transport the first counter could always end up dropped this is
/// functionally equivalent to initializing to 0.
pub(crate) const INIT_COUNTER: u64 = 0;
pub(crate) const LABEL_RATCHET_STATE: u8 = b'R';
pub(crate) const LABEL_HEADER_KEY: u8 = b'H';
pub(crate) const LABEL_KEX_KEY: u8 = b'K';

/// Size of keys used during derivation, mixing, etc.
pub(crate) const NOISE_HASHLEN: usize = SHA512_HASH_SIZE;

pub(crate) const HEADER_SIZE: usize = 16;
pub(crate) const HEADER_PROTECT_ENC_START: usize = 4;
pub(crate) const HEADER_PROTECT_ENC_END: usize = 20;
pub(crate) const CHALLENGE_COUNTER_SIZE: usize = 8;
pub(crate) const CHALLENGE_MAC_SIZE: usize = 16;
pub(crate) const CHALLENGE_POW_SIZE: usize = 8;
pub(crate) const CHALLENGE_SALT_SIZE: usize = 32;

pub(crate) const MAX_NOISE_HANDSHAKE_SIZE: usize = MAX_FRAGMENTS * MIN_TRANSPORT_MTU;
pub(crate) const CONTROL_PACKET_MAX_SIZE: usize = HEADER_SIZE + NoiseKKPattern1or2::SIZE + AES_GCM_TAG_SIZE;
pub(crate) const CONTROL_PACKET_MIN_SIZE: usize = HEADER_SIZE + AES_GCM_TAG_SIZE;

/// Determines the number of counters a session will remember. If a counter arrives over
/// this amount out of order relative to other received counters, it is likely to be
/// rejected on the basis that the session can't remember if this counter was replayed.
/// Increasing this value makes a session consume more memory.
pub(crate) const COUNTER_WINDOW_MAX_OOO: usize = 64;
/// Maximum number of counter steps that the counter is allowed to skip ahead.
/// This cannot be changed away from 2^24 without changing the header nonce handling code.
pub(crate) const COUNTER_WINDOW_MAX_SKIP_AHEAD: u64 = 16777216;
/// Similar to `COUNTER_WINDOW_MAX_OOO`, except this governs the receive context challenge
/// counter rather than the session counter.
/// When Bob issues a challenge to Alice to mitigate DDOS, Bob will only accept Alice's
/// response once, and then its attached counter is added to the window.
pub(crate) const CHALLENGE_COUNTER_WINDOW_MAX_OOO: usize = 32;
/// We hard-expire the Noise counter long before we reach u64::MAX because of the ABA problem.
/// Over (1<<16) threads would have to attempt to increment the counter at the same time
/// to overflow it.
/// Having (1<<16) threads active at the same time would crash basically any system.
pub(crate) const THREAD_SAFE_COUNTER_HARD_EXPIRE: u64 = u64::MAX - (1 << 16);

/// Maximum number of fragments a single packet may be split into. If a packet cannot fit
/// into this number of fragments it will be dropped.
pub(crate) const MAX_FRAGMENTS: usize = 48; // hard protocol max: 63
/// Maximum window over which session packets may be reordered to be defragmented and
/// reassembled. Out of order fragments may be dropped in favor of newer fragments.
/// Increasing this value makes a session consume more significantly more memory.
pub(crate) const SESSION_MAX_FRAGMENTS_OOO: usize = 32;

/// The maximum number of unassociated packets that a receive context will cache.
/// Additional packets will either be dropped or cause a different packet to be dropped
/// from the cache.
/// Larger values consume more memory but provide better reliability and DDOS resistance.
pub(crate) const MAX_UNASSOCIATED_PACKETS: usize = 32;
/// The maximum number of fragments of unassociated packets that a receive context will
/// cache.
/// All unassociated fragments share the same buffer, when it fills up additional
/// fragments will be dropped or cause other fragments to be dropped from the cache.
/// Larger values consume more memory but provide better reliability and DDOS resistance.
pub(crate) const MAX_UNASSOCIATED_FRAGMENTS: usize = 32 * 32;
/// The maximum number of `NoiseXKBobHandshakeState` that a receive context will cache.
/// These are extremely large and since Alice has not been authenticated we put a hard
/// limit to how many we cache.
/// Larger values consume more memory but provide better reliability and DDOS resistance.
pub(crate) const MAX_UNASSOCIATED_HANDSHAKE_STATES: usize = 32;

/// The maximum size a packet that is not associated to a session may be.
/// Excludes the size of headers for fragmentation.
pub(crate) const MAX_UNASSOCIATED_PACKET_SIZE: usize = NoiseXKPattern1::MAX_SIZE - HEADER_SIZE;

/*
XKhfs+psk2:
    <- s
    ...
    -> e, es, e1
    <- e, ee, ekem1, psk
    -> s, se
*/
/*
KKpsk0:
    -> s
    <- s
    ...
    -> psk, e, es, ss
    <- e, ee, se
*/
/*
Header:
    [0..4]   recipient key id
-- start AES(ck_es * h_e_e1_p) encrypted block --
    [4]      fragment count (1..255)
    [5]      fragment number (0..254)
    [6]      reserved zero
-- start AES-GCM Nonce --
    [7]      packet type
    [8..16]  64-bit counter or packet id
*/
/// The first packet in Noise_XK exchange containing Alice's ephemeral keys, key id,
/// and a random symmetric key to protect header fragmentation fields for this session.
#[repr(C, packed)]
pub(crate) struct NoiseXKPattern1 {
    pub header: [u8; HEADER_SIZE],
    /// -- start prologue --
    pub alice_key_id: [u8; SESSION_ID_SIZE],
    /// -- end prologue --
    pub noise_e: [u8; P384_PUBLIC_KEY_SIZE],
    /// -- start AES-GCM(k_es) encrypted section
    pub noise_e1: [u8; KYBER_PUBLICKEYBYTES],
    /// -- end encrypted section
    pub e1_gcm_tag: [u8; AES_GCM_TAG_SIZE],
    pub payload: [u8; RATCHET_SIZE + RATCHET_SIZE + AES_GCM_TAG_SIZE + ChallengeResponse::SIZE],
}

#[repr(C, packed)]
pub(crate) struct ChallengeResponse {
    pub challenge_counter: [u8; CHALLENGE_COUNTER_SIZE],
    pub challenge_mac: [u8; CHALLENGE_MAC_SIZE],
    pub challenge_pow: [u8; CHALLENGE_POW_SIZE],
}

impl NoiseXKPattern1 {
    pub const PROLOGUE_START: usize = HEADER_SIZE;
    pub const PROLOGUE_END: usize = Self::PROLOGUE_START + SESSION_ID_SIZE;
    pub const E1_ENC_START: usize = Self::PROLOGUE_END + P384_PUBLIC_KEY_SIZE;
    pub const E1_AUTH_START: usize = Self::E1_ENC_START + KYBER_PUBLICKEYBYTES;
    pub const P_ENC_START: usize = Self::E1_AUTH_START + AES_GCM_TAG_SIZE;

    pub const MIN_SIZE: usize = Self::P_ENC_START + AES_GCM_TAG_SIZE + ChallengeResponse::SIZE;
    pub const MAX_SIZE: usize = Self::MIN_SIZE + RATCHET_SIZE + RATCHET_SIZE;
}
impl ChallengeResponse {
    pub const SIZE: usize = CHALLENGE_COUNTER_SIZE + CHALLENGE_MAC_SIZE + CHALLENGE_POW_SIZE;
}

#[repr(C, packed)]
pub(crate) struct BobDOSChallenge {
    pub header: [u8; HEADER_SIZE],
    pub alice_key_id: [u8; SESSION_ID_SIZE],
    pub challenge_counter: [u8; CHALLENGE_COUNTER_SIZE],
    pub challenge_mac: [u8; CHALLENGE_MAC_SIZE],
    pub prior_challenge_pow: [u8; CHALLENGE_POW_SIZE],
}

impl BobDOSChallenge {
    pub const SIZE: usize = HEADER_SIZE + SESSION_ID_SIZE + CHALLENGE_COUNTER_SIZE + CHALLENGE_MAC_SIZE + CHALLENGE_POW_SIZE;
}

/// The response to NoiseXKPattern1 containing Bob's ephemeral keys.
#[repr(C, packed)]
pub(crate) struct NoiseXKPattern2 {
    pub header: [u8; HEADER_SIZE],
    pub noise_e: [u8; P384_PUBLIC_KEY_SIZE],
    /// -- start AES-GCM(k_es_ee) encrypted section
    pub noise_ekem1: [u8; KYBER_CIPHERTEXTBYTES],
    /// -- end encrypted section
    pub ekem1_gcm_tag: [u8; AES_GCM_TAG_SIZE],
    /// -- start AES-GCM(k_es_ee_ekem1_psk) encrypted section
    pub bob_key_id: [u8; SESSION_ID_SIZE],
    /// -- end encrypted section
    pub p_gcm_tag: [u8; AES_GCM_TAG_SIZE],
}

impl NoiseXKPattern2 {
    pub const EKEM1_ENC_START: usize = HEADER_SIZE + P384_PUBLIC_KEY_SIZE;
    pub const EKEM1_AUTH_START: usize = Self::EKEM1_ENC_START + KYBER_CIPHERTEXTBYTES;
    pub const P_ENC_START: usize = Self::EKEM1_AUTH_START + AES_GCM_TAG_SIZE;
    pub const P_AUTH_START: usize = Self::P_ENC_START + SESSION_ID_SIZE;
    pub const P_AUTH_END: usize = Self::P_AUTH_START + AES_GCM_TAG_SIZE;
    pub const SIZE: usize = Self::P_AUTH_END;
}

/// Alice's final response containing her identity (she already knows Bob's) and meta-data.
/// While Alice's response does match what is described in this struct,
/// this struct is unused because it would contain variable length fields.
/// It is present here for documentation purposes.
#[repr(C, packed)]
pub(crate) struct NoiseXKPattern3 {
    pub header: [u8; HEADER_SIZE],
    /// -- start AES-GCM(k_es_ee_ekem1_psk) encrypted section
    pub noise_s: [u8; P384_PUBLIC_KEY_SIZE],
    /// -- end encrypted section
    pub s_gcm_tag: [u8; AES_GCM_TAG_SIZE],
    /// -- start AES-GCM(k_es_ee_ekem1_psk_se) encrypted section
    pub alice_blob: [u8; 0],
    /// -- end encrypted section
    pub p_gcm_tag: [u8; AES_GCM_TAG_SIZE],
}
impl NoiseXKPattern3 {
    pub const MIN_SIZE: usize = HEADER_SIZE + P384_PUBLIC_KEY_SIZE + AES_GCM_TAG_SIZE + AES_GCM_TAG_SIZE;
    pub const MAX_SIZE: usize = MAX_NOISE_HANDSHAKE_SIZE;
}

#[repr(C, packed)]
pub(crate) struct NoiseKKPattern1or2 {
    pub header: [u8; HEADER_SIZE],
    pub noise_e: [u8; P384_PUBLIC_KEY_SIZE],
    pub key_id: [u8; SESSION_ID_SIZE],
    pub gcm_tag: [u8; AES_GCM_TAG_SIZE],
    pub kek_tag: [u8; AES_GCM_TAG_SIZE],
}
impl NoiseKKPattern1or2 {
    pub const ENC_START: usize = HEADER_SIZE + P384_PUBLIC_KEY_SIZE;
    pub const AUTH_START: usize = Self::ENC_START + SESSION_ID_SIZE;
    pub const AUTH_END: usize = Self::AUTH_START + AES_GCM_TAG_SIZE;
    pub const SIZE: usize = Self::AUTH_END + AES_GCM_TAG_SIZE;
}

// Annotate only these structs as being compatible with byte_array_as_proto_buffer(). These structs
// are packed flat buffers containing only byte or byte array fields, making them safe to treat
// this way even on architectures that require type size aligned access.
pub(crate) trait ProtocolFlatBuffer {}
impl ProtocolFlatBuffer for NoiseXKPattern1 {}
impl ProtocolFlatBuffer for NoiseXKPattern2 {}
impl ProtocolFlatBuffer for NoiseKKPattern1or2 {}
impl ProtocolFlatBuffer for BobDOSChallenge {}
impl ProtocolFlatBuffer for ChallengeResponse {}

#[inline(always)]
pub(crate) fn byte_array_as_proto_buffer<B: ProtocolFlatBuffer>(b: &[u8]) -> &B {
    assert!(b.len() >= size_of::<B>());
    unsafe { &*b.as_ptr().cast() }
}

#[inline(always)]
pub(crate) fn byte_array_as_proto_buffer_mut<B: ProtocolFlatBuffer>(b: &mut [u8]) -> &mut B {
    assert!(b.len() >= size_of::<B>());
    unsafe { &mut *b.as_mut_ptr().cast() }
}
/// Trick rust into letting us use a hasher that returns more than 64 bits.
pub(crate) struct ShaHasher<'a, ShaImpl: Sha512>(pub &'a mut ShaImpl);
impl<'a, ShaImpl: Sha512> Hasher for ShaHasher<'a, ShaImpl> {
    fn finish(&self) -> u64 {
        panic!()
    }
    fn write(&mut self, bytes: &[u8]) {
        self.0.update(bytes)
    }
}
