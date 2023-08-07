
/* Common constants */

use crate::crypto::{sha512::SHA512_HASH_SIZE, p384::P384_PUBLIC_KEY_SIZE, kyber1024::{KYBER_PUBLIC_KEY_SIZE, KYBER_CIPHERTEXT_SIZE}, aes::AES_GCM_TAG_SIZE};

/// Minimum physical MTU for ZSSP to function.
/// If an MTU is passed to ZSSP that is lower than this, it will be ignored and instead this value
/// will be used.
pub const MIN_TRANSPORT_MTU: usize = 128;

pub(crate) const KID_SIZE: usize = 4;

/* Challenge protocol constants */

pub(crate) const SALT_SIZE: usize = 32;

pub(crate) const COUNTER_SIZE: usize = 8;
pub(crate) const MAC_SIZE: usize = 16;
pub(crate) const POW_SIZE: usize = 8;
pub(crate) const POW_START: usize = COUNTER_SIZE + MAC_SIZE;

pub(crate) const CHALLENGE_SIZE: usize = COUNTER_SIZE + MAC_SIZE + POW_SIZE;
pub(crate) const DIFFICULTY: u32 = 13;

/* Fragmentation constants */
/*
Header:
    [0..4]   recipient key id
-- start AES(ck_es * h_e_e1_p) encrypted block --
    [5]      fragment number (0..254)
    [4]      fragment count (1..255)
-- start packet nonce --
    [6]      reserved zero
    [7]      packet type
    [8..16]  64-bit counter
*/
pub(crate) const HEADER_SIZE: usize = 16;
pub(crate) const PACKET_NONCE_SIZE: usize = 10;

pub(crate) const HEADER_AUTH_START: usize = 4;
pub(crate) const HEADER_AUTH_END: usize = 20;
pub(crate) const PACKET_NONCE_START: usize = HEADER_SIZE - PACKET_NONCE_SIZE;

pub(crate) const FRAGMENT_NO_IDX: usize = 4;
pub(crate) const FRAGMENT_COUNT_IDX: usize = 5;

pub(crate) const MAX_FRAGMENTS: usize = 48;

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
pub(crate) const MAX_UNASSOCIATED_PACKET_SIZE: usize = HANDSHAKE_HELLO_MAX_SIZE - HEADER_SIZE;


/* Key exchange constants */
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
pub(crate) const HASHLEN: usize = SHA512_HASH_SIZE;
/// The size in bytes of both a ratchet key and a ratchet fingerprint.
pub const RATCHET_SIZE: usize = 32;

pub(crate) const PROTOCOL_NAME_NOISE_XK: [u8; HASHLEN] = *b"Noise_XKhfs+psk2_P384+Kyber1024_AESGCM_SHA512\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";
pub(crate) const PROTOCOL_NAME_NOISE_KK: [u8; HASHLEN] =
    *b"Noise_KKpsk0_P384_AESGCM_SHA512\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

pub(crate) const LABEL_OTP_TO_RATCHET: &[u8; 19] = b"ZSSP_OTP_TO_RATCHET";
pub(crate) const LABEL_KBKDF_CHAIN: &[u8; 4] = b"ZSSP";
pub(crate) const LABEL_RATCHET_STATE: &[u8; 4] = b"ASKR";
pub(crate) const LABEL_HEADER_KEY: &[u8; 4] = b"ASKH";
pub(crate) const LABEL_KEX_KEY: &[u8; 4] = b"ASKK";

pub(crate) const INIT_COUNTER: u64 = 0;
pub(crate) const EXPIRE_AFTER_USES: u64 = 4294967295;
pub(crate) const COUNTER_WINDOW_MAX_OOO: usize = 64;
pub(crate) const COUNTER_WINDOW_MAX_SKIP_AHEAD: u64 = 1 << 24;

/* Packet constants */

pub(crate) const PACKET_TYPE_HANDSHAKE_HELLO: u8 = 0;
pub(crate) const PACKET_TYPE_HANDSHAKE_RESPONSE: u8 = 1;
pub(crate) const PACKET_TYPE_HANDSHAKE_COMPLETION: u8 = 2;
pub(crate) const PACKET_TYPE_KEY_CONFIRM: u8 = 3;
pub(crate) const PACKET_TYPE_ACK: u8 = 4;
pub(crate) const PACKET_TYPE_REKEY_INIT: u8 = 5;
pub(crate) const PACKET_TYPE_REKEY_COMPLETE: u8 = 6;
pub(crate) const PACKET_TYPE_SESSION_REJECTED: u8 = 7;
pub(crate) const PACKET_TYPE_DATA: u8 = 8;
pub(crate) const PACKET_TYPE_CHALLENGE: u8 = 9;
pub(crate) const PACKET_TYPE_USES_COUNTER_RANGE: std::ops::Range<u8> = 3..9;

pub(crate) const MAX_HANDSHAKE_SIZE: usize = MAX_FRAGMENTS * MIN_TRANSPORT_MTU;

pub(crate) const HANDSHAKE_HELLO_MIN_SIZE: usize = KID_SIZE + P384_PUBLIC_KEY_SIZE + KYBER_PUBLIC_KEY_SIZE + AES_GCM_TAG_SIZE + AES_GCM_TAG_SIZE;
pub(crate) const HANDSHAKE_HELLO_MAX_SIZE: usize = HANDSHAKE_HELLO_MIN_SIZE + RATCHET_SIZE;

pub(crate) const HANDSHAKE_RESPONSE_SIZE: usize = P384_PUBLIC_KEY_SIZE + KYBER_CIPHERTEXT_SIZE + AES_GCM_TAG_SIZE + KID_SIZE + AES_GCM_TAG_SIZE;

pub(crate) const HANDSHAKE_COMPLETION_MIN_SIZE: usize = P384_PUBLIC_KEY_SIZE + AES_GCM_TAG_SIZE + 0 + AES_GCM_TAG_SIZE;
pub(crate) const HANDSHAKE_COMPLETION_MAX_SIZE: usize = MAX_HANDSHAKE_SIZE;

pub(crate) const KEY_CONFIRMATION_SIZE: usize = AES_GCM_TAG_SIZE;
pub(crate) const ACKNOWLEDGEMENT_SIZE: usize = AES_GCM_TAG_SIZE;
pub(crate) const SESSION_REJECTED_SIZE: usize = AES_GCM_TAG_SIZE;

pub(crate) const REKEY_SIZE: usize = P384_PUBLIC_KEY_SIZE + KID_SIZE + AES_GCM_TAG_SIZE + AES_GCM_TAG_SIZE;

pub(crate) const MAX_IDENTITY_SIZE: usize = MAX_HANDSHAKE_SIZE - HANDSHAKE_COMPLETION_MIN_SIZE;
