
use crate::crypto::aes_gcm::AES_GCM_TAG_SIZE;
use crate::crypto::pqc_kyber::{KYBER_CIPHERTEXTBYTES, KYBER_PUBLICKEYBYTES};
use crate::crypto::p384::P384_PUBLIC_KEY_SIZE;
use crate::crypto::sha512::{Sha512, SHA512_HASH_SIZE};

pub struct HandshakeHello {
    key_id: [u8; 4],
    e: [u8; 49],
    e1: [u8; KYBER_PUBLICKEYBYTES],
    e1_tag: [u8; AES_GCM_TAG_SIZE],
}
