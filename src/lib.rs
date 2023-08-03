/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https://mozilla.org/MPL/2.0/.
*
* (c) ZeroTier, Inc.
* https://www.zerotier.com/
*/
#![warn(missing_docs, rust_2018_idioms)]
//! TODO: docs

mod applicationlayer;
mod challenge;
mod context;
mod fragmentation;
#[cfg(feature = "logging")]
mod log_event;
mod proto;
mod symmetric_state;
mod zeta;
mod ratchet_state;

pub mod result;
/// A collection of implementation-independent traits for the various specific cryptographic
/// algorithms ZSSP depends on.
/// Each trait is hyper-specific about the semantics of the algorithms and the lengths of its inputs
/// and outputs as a forced sanity-check for anyone trying to use their own implementations.
///
/// The `crypto_impl` module contains implementations of these traits in terms of popular Rust
/// implementations of these algorithms.
pub mod crypto;
/// A module containing implementations of the ZSSP `crypto` traits in terms of popular Rust crates.
/// Some of these crates are not thoroughly audited, so use at your own risk.
///
/// Note that none of these crates are FIPS certified, meaning a build of ZSSP using them will not
/// be FIPS compliant. However lack of FIPS compliance by no means implies lack of security or lack
/// of confidence.
///
/// This module contains the trait implementations as well as re-exports of those crates.
pub mod crypto_impl;

pub use ratchet_state::RatchetState;
pub use applicationlayer::{ApplicationLayer, Settings};
pub use context::Context;
#[cfg(feature = "logging")]
pub use log_event::LogEvent;
pub use proto::{MIN_TRANSPORT_MTU, RATCHET_SIZE};
pub use zeta::Session;
