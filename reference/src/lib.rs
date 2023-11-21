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
//! *NOTICE: ZSSP has not yet completed peer review or code audit, so use at your own risk for now. This will be updated as the project matures.*
//!
//! ## Introduction
//!
//! ZeroTier Secure Sessions Protocol (ZSSP) is a [Noise](http://noiseprotocol.org) protocol implementation using NIST/FIPS/CfSC compliant cryptographic primitives plus post-quantum forward secrecy via [Kyber1024](https://pq-crystals.org/kyber/). It also includes built-in support for fragmentation and defragmentation of large messages with the fragmentation protocol being hardened against the usual denial of service attacks that plague most packet fragmentation and re-assembly protocols.
//!
//! ZSSP implements the [Noise XK](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) interactive handshake pattern which provides strong forward secrecy not only for data but for the identities of the two participants in the session. The XK pattern was chosen instead of the IK pattern used in most Noise implementations (e.g. Wireguard) due to ZeroTier identities being long lived and potentially tied to the real world identity of the user. As a result a Noise pattern providing identity forward secrecy was considered preferable as it offers some level of deniability for recorded traffic even after secret key compromise. Post-quantum forward secrecy is negotiated alongside Noise XK using a [hybrid forward secrecy model suggested by the Noise protocol authors](https://github.com/noiseprotocol/noise_wiki/wiki/Hybrid-Forward-Secrecy).
//!
//! Periodic session re-keying uses the [Noise KK](http://noiseprotocol.org/noise.html#interactive-handshake-patterns-fundamental) pattern with key ratcheting based in part on the methods used by the [Signal protocol](https://signal.org/docs/specifications/doubleratchet/). Unlike Signal ratcheting is performed only on re-key events and not on every message as this would be prohibitively costly for a protocol designed for high throughput applications.
//!
//! Re-keying does not employ a hybrid exchange. Post-quantum forward secrecy is negotiated only on session startup since the threat model underpinning its use is to protect against very long term data storage and future decryption with quantum computers. Ratcheting causes the result of the initial ephemeral PQ exchange to be mixed into all subsequent session keys, protecting the entire session against a future attacker able to break elliptic curve cryptography.
//!
//! An in-depth guide to the full protocol specification can be found in the [protocol whitepaper](whitepaper/zssp.pdf) provided in this repository.
//!
//! ZSSP was designed for use in [ZeroTier](https://www.zerotier.com/) but is payload agnostic and open source and can easily be used by other projects. The implementations here are based around generic cryptographic traits that a user can implement in terms of any cryptographic library of API they wish to use. Default implementations in terms of popular Rust cryptography crates are included but can be disabled via feature selection if alternatives are to be used.
//!
//! This repository includes both a simpler [reference](reference/) implementation that follows the whitepaper very explicitly and a more complex [high performance](performance/) implementation designed for high throughput or use in systems that will manage very large numbers of ZSSP sessions.
//!
//! See the [ZSSP whitepaper](whitepaper/zssp.pdf) for extensive documentation of the protocol.
//!
//! ## Cryptographic Primitives Used in ZSSP
//!
//!  - **NIST P-384 ECDH**: Elliptic curve used in initial Noise XK and subsequent Noise KK key exchanges
//!  - **Kyber1024**: Quantum attack resistant lattice-based key exchange during initial handshake
//!  - **SHA-512**: Used to construct KBKDF, also used in a proof of work and IP ownership DOS mitigation scheme
//!  - **KBKDF**: Key mixing, sub-key derivation
//!  - **AES-256**: Single block encryption of header to harden packet fragmentation protocol
//!  - **AES-256-GCM**: Authenticated encryption
#![warn(missing_docs, rust_2018_idioms)]
#![allow(clippy::too_many_arguments, clippy::type_complexity, clippy::assertions_on_constants)]

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
