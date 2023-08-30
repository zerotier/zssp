/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https://mozilla.org/MPL/2.0/.
*
* (c) ZeroTier, Inc.
* https://www.zerotier.com/
*/
//! ZeroTier Secure Sessions Protocol
//! ======
//!
//! ## Introduction
//!
//! An in-depth guide to the full protocol specification can be found in the [protocol whitepaper](whitepaper/zssp.pdf) provided in this repo. This implementation references it heavily.
//!
//! ZeroTier Secure Socket Protocol (ZSSP) is a [Noise](http://noiseprotocol.org) protocol implementation using NIST/FIPS/CfSC compliant cryptographic primitives plus post-quantum forward secrecy via [Kyber1024](https://pq-crystals.org/kyber/). It also includes built-in support for fragmentation and defragmentation of large messages with strong resistance against denial of service attacks targeted against the fragmentation protocol.
//!
//! Specifically ZSSP implements the [Noise XK](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) interactive handshake pattern which provides strong forward secrecy not only for data but for the identities of the two participants in the session. The XK pattern was chosen instead of the more popular IK pattern used in popular Noise implementations like Wireguard due to ZeroTier identities being long lived and potentially tied to the real world identity of the user. As a result a Noise pattern providing identity forward secrecy was considered preferable as it offers some level of deniability for recorded traffic even after secret key compromise.
//!
//! Hybrid post-quantum forward secrecy using Kyber1024 is performed alongside Noise with the result being mixed in alongside an optional pre-shared key at the end of session negotiation.
//!
//! ZSSP is designed for use in ZeroTier but is payload-agnostic and could easily be adapted for use in other projects.
//!
//! Further information can be found in the ZSSP whitepaper [protocol whitepaper](whitepaper/zssp.pdf).
//!
//! ## Cryptographic Primitives Used
//!
//!  - **NIST P-384 ECDH**: Elliptic curve key exchange during initial handshake and for periodic re-keying during the session
//!  - **Kyber1024**: Quantum attack resistant lattice-based key exchange during initial handshake
//!  - **SHA-512**: Used to construct KBKDF, also used in a proof of work and IP ownership DOS mitigation scheme
//!  - **KBKDF**: Key mixing, sub-key derivation
//!  - **AES-256**: 128-bit PRP for AES-256-GCM and for authenticated encryption of header to harden fragmentation against DOS (see section on header protection)
//!  - **AES-256-GCM**: Authenticated encryption
#![warn(missing_docs, rust_2018_idioms)]

mod challenge;
mod context;
mod fragmentation;
#[cfg(feature = "logging")]
mod log_event;
mod proto;
mod ratchet_state;
mod symmetric_state;
mod zeta;

/// An abstraction over OS and use-case specific resources and queries.
/// This allows this library to be platform independent, but a user of this library must implement
/// the `ApplicationLayer` trait.
pub mod application;
/// A collection of implementation-independent traits for the various specific cryptographic
/// algorithms ZSSP depends on.
///
/// Each trait is hyper-specific about the semantics of the algorithms and the lengths of their
/// inputs and outputs.
/// This is to enforced a basic sanity-check upon anyone trying to use their own implementations.
///
/// The `crypto_impl` module contains implementations of these traits in terms of popular Rust
/// implementations of these algorithms.
pub mod crypto;
/// A module containing optional implementations of the ZSSP `crypto` traits in terms of popular
/// Rust crates. Some of these crates are not thoroughly audited, so use at your own risk.
///
/// Note that none of these crates are FIPS certified, meaning a build of ZSSP using them will not
/// be FIPS compliant. However lack of FIPS compliance by no means implies lack of security or lack
/// of confidence.
///
/// This module contains the trait implementations as well as re-exports of those crates.
pub mod crypto_impl;
/// The collection of major return types of this library.
pub mod result;

pub use context::Context;
#[cfg(feature = "logging")]
pub use log_event::LogEvent;
pub use proto::MIN_TRANSPORT_MTU;
pub use zeta::Session;
