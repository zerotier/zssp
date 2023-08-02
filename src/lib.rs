/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https://mozilla.org/MPL/2.0/.
*
* (c) ZeroTier, Inc.
* https://www.zerotier.com/
*/
//#![warn(missing_docs, rust_2018_idioms)]
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

#[macro_use]
pub mod result;
pub mod crypto;
pub mod crypto_impl;
pub mod ratchet_state;

pub use applicationlayer::{ApplicationLayer, Settings};
pub use context::Context;
#[cfg(feature = "logging")]
pub use log_event::LogEvent;
pub use proto::{MIN_TRANSPORT_MTU, RATCHET_SIZE};
pub use zeta::Session;
