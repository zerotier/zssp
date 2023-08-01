/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use rand_core::{CryptoRng, RngCore};

use crate::crypto::{AeadAesGcm, HashSha512, KeyPairP384, PrivateKeyKyber1024, PrpAes256, PublicKeyP384};
use crate::proto::RATCHET_SIZE;
use crate::ratchet_state::RatchetState;

#[cfg(feature = "logging")]
use crate::LogEvent;

pub struct Settings {
    pub initial_offer_timeout: u64,
    pub rekey_timeout: u64,
    pub rekey_after_time: u64,
    pub rekey_time_max_jitter: u64,
    pub rekey_after_key_uses: u64,
    pub resend_time: u64,
    pub fragment_assembly_timeout: u64,
}
impl Default for Settings {
    fn default() -> Self {
        Self::new_ms()
    }
}
impl Settings {
    pub const INITIAL_OFFER_TIMEOUT_MS: u64 = 10 * 1000;
    pub const REKEY_TIMEOUT_MS: u64 = 60 * 1000;
    pub const REKEY_AFTER_TIME_MS: u64 = 60 * 60 * 1000;
    pub const REKEY_AFTER_TIME_MAX_JITTER_MS: u64 = 10 * 60 * 1000;
    pub const REKEY_AFTER_KEY_USES: u64 = 1 << 30;
    pub const RESEND_TIME: u64 = 1000;
    pub const FRAGMENT_ASSEMBLY_TIMEOUT_MS: u64 = 5 * 1000;
    pub const fn new_ms() -> Self {
        Self {
            initial_offer_timeout: Self::INITIAL_OFFER_TIMEOUT_MS,
            rekey_timeout: Self::REKEY_TIMEOUT_MS,
            rekey_after_time: Self::REKEY_AFTER_TIME_MS,
            rekey_time_max_jitter: Self::REKEY_AFTER_TIME_MAX_JITTER_MS,
            rekey_after_key_uses: Self::REKEY_AFTER_KEY_USES,
            resend_time: Self::RESEND_TIME,
            fragment_assembly_timeout: Self::FRAGMENT_ASSEMBLY_TIMEOUT_MS,
        }
    }
}

/// Trait to implement to integrate the session into an application.
///
/// Templating the session on this trait lets the code here be almost entirely transport, OS,
/// and use case independent.
///
/// The constants exposed in this trait can be redefined from their defaults to change rekey
/// and negotiation timeout behavior. Both sides of a ZSSP session **must** have these constants
/// set to the same values. Changing these constants is generally discouraged unless you know
/// what you are doing.
pub trait ApplicationLayer: Sized {
    const SETTINGS: Settings = Settings::new_ms();

    type Rng: CryptoRng + RngCore;

    type Prp: PrpAes256;

    type Aead: AeadAesGcm;

    type Hash: HashSha512;

    type PublicKey: PublicKeyP384;
    type KeyPair: KeyPairP384<Self::Rng, PublicKey = Self::PublicKey>;
    type Kem: PrivateKeyKyber1024<Self::Rng>;

    type DiskError: std::fmt::Debug;

    /// Type for arbitrary opaque object for use by the application that is attached to
    /// each session.
    type Data;

    /// This function will be called whenever Alice's initial Hello packet contains the empty ratchet
    /// fingerprint. Brand new peers will always connect to Bob with the empty ratchet, but from
    /// then on they should be using non-empty ratchet states.
    ///
    /// If this returns false, we will attempt to connect to Alice with the empty ratchet state.
    /// If this returns true, Alice's connection will be silently dropped.
    /// If this function is configured to always return true, it means peers will not be able to
    /// connect to us unless they had a prior-established ratchet key with us. This is the best way
    /// for the paranoid to enforce a manual allow-list.
    fn hello_requires_recognized_ratchet(&self) -> bool;
    /// This function is called if we, as Alice, attempted to open a session with Bob using a
    /// non-empty ratchet key, but Bob does not have this ratchet key and wants to downgrade
    /// to the zero ratchet key.
    ///
    /// If it returns true Alice will downgrade their ratchet state to emtpy, potentially ending
    /// their current ratchet chain.
    /// If it returns false then we will consider Bob as having failed authentication, and this
    /// packet will be dropped. The session will continue attempting to connect to Bob.
    ///
    /// This function must deterministically return either true or false for a given session.
    ///
    /// It is a bad sign that Bob has somehow forgotten Alice's ratchet key, it either means at
    /// least one party is misconfigured and got their ratchet keys corrupted or lost, or Bob has
    /// been compromised and is being impersonated. An attacker must at least have Bob's private
    /// static key to be able to ask Alice to downgrade.
    fn initiator_disallows_downgrade(&self) -> bool;
    /// Lookup a specific ratchet state based on its ratchet fingerprint.
    /// This function will be called whenever Alice attempts to connect to us with a non-empty
    /// ratchet fingerprint.
    ///
    /// If the ratchet key was found, the function should return `RestoreAction::RestoreRatchet`. This will
    /// cause us to connect to Alice using the returned ratchet number and ratchet key.
    ///
    /// If the ratchet key could not be found, the application may choose between returning
    /// `RatchetAction::DowngradeRatchet` or `RatchetAction::FailAuthentication`.
    /// If `RatchetAction::DowngradeRatchet` is returned we will attempt to convince Alice to downgrade
    /// to the empty ratchet key, restarting the ratchet chain.
    /// If `RatchetAction::FailAuthentication` is returned Alice's connection will be silently dropped.
    fn restore_by_fingerprint(&self, ratchet_fingerprint: &[u8; RATCHET_SIZE]) -> Result<RatchetState, Self::DiskError>;

    /// Lookup a specific ratchet state based on the identity of the peer being communicated with.
    /// This function will be called whenever Alice attempts to open a session, or Bob attempts
    /// to verify Alice's identity.
    fn restore_by_identity(&self, remote_static_key: &Self::PublicKey, application_data: &Self::Data) -> Result<[RatchetState; 2], Self::DiskError>;
    /// Atomically save the given `new_ratchet_states` to persistent storage.
    /// `pre_ratchet_states` contains what should be the previous contents of persistent storage.
    ///
    /// If this returns `Err(IoError)`, the packet which triggered this function to be called will be
    /// dropped, and no session state will be mutated, preserving synchronization. The remote peer
    /// will eventually resend that packet and so this function will be called again.
    ///
    /// If persistent storage is supported, this function should not return until the ratchet state
    /// is saved, otherwise it is possible, albeit unlikely, for a sudden restart of the local
    /// machine to put our ratchet state out of sync with the remote peer. If this happens the only
    /// fix is to reset both ratchet keys to empty.
    ///
    /// This function may also save state to volatile storage, in which case all peers which connect
    /// to us will have to allow downgrade, i.e. `initiator_disallows_downgrade` returns false
    /// and/or `check_accept_session` returns `(Some(true, _), _)`.
    /// Otherwise, when we restart, we will not be allowed to reconnect.
    fn save_ratchet_state(
        &self,
        remote_static_key: &Self::PublicKey,
        application_data: &Self::Data,
        pre_ratchet_states: [&RatchetState; 2],
        new_ratchet_states: [&RatchetState; 2],
    ) -> Result<(), Self::DiskError>;

    #[cfg(feature = "logging")]
    fn event_log(&self, event: LogEvent<Self>);

    fn time(&self) -> i64;
    fn check_accept_session(&self, remote_static_key: &Self::PublicKey, identity: &[u8]) -> (Option<(bool, Self::Data)>, bool);
}
