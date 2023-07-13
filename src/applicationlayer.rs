/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

use std::sync::Arc;

use crate::crypto::aes::{AesDec, AesEnc};
use crate::crypto::aes_gcm::{AesGcmDec, AesGcmEnc};
use crate::crypto::p384::{P384KeyPair, P384PublicKey};
use crate::crypto::rand_core::{CryptoRng, RngCore};
use crate::crypto::secret::Secret;
use crate::crypto::sha512::{HmacSha512, Sha512};
use crate::{log_event::LogEvent, Session, RATCHET_SIZE};

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
    /// Retry interval for outgoing connection initiation or rekey attempts.
    ///
    /// Retry attempts will be no more often than this, but the delay may end up being
    /// slightly more in some cases depending on where in the cycle the initial attempt
    /// falls.
    ///
    /// Default value is 1 second.
    const RETRY_INTERVAL_MS: i64 = 1000;
    /// Timeout for how long Alice should wait for Bob to confirm that the Noise_XK handshake
    /// was completed successfully. The handshake attempt will be assumed as failed and
    /// restarted if Bob does not respond by this cut-off.
    ///
    /// Default is 10 seconds.
    const INITIAL_OFFER_TIMEOUT_MS: i64 = 10 * 1000;
    /// Timeout for how long ZSSP should wait before expiring and closing a session when it has
    /// lingered in certain states for too long, primarily the rekeying states.
    /// If a remote peer does not send the correct information to rekey a session before this
    /// timeout then the session will close.
    ///
    /// Default is 1 minute.
    const EXPIRATION_TIMEOUT_MS: i64 = 60 * 1000;
    /// Start attempting to rekey after a key has been in use for this many milliseconds.
    ///
    /// Default is 1 hour.
    const REKEY_AFTER_TIME_MS: i64 = 1000 * 60 * 60;
    /// Maximum random jitter to subtract from the rekey after time timer.
    /// Must be greater than 0 and less than u32::MAX.
    /// This prevents rekeying from occurring predictably on the hour, so traffic analysis is harder.
    ///
    /// Default is 10 minutes.
    const REKEY_AFTER_TIME_MAX_JITTER_MS: i64 = 1000 * 60 * 10;
    /// Rekey after this many key uses.
    ///
    /// The default is 1/4 the recommended NIST limit for AES-GCM. Unless you are transferring
    /// a massive amount of data REKEY_AFTER_TIME_MS is probably going to kick in first.
    const REKEY_AFTER_USES: u64 = 1073741824;

    /// Hard expiration of a key after this many uses.
    ///
    /// Attempting to encrypt more than this many messages with a key will cause a hard error
    /// and prevent all encryption.
    /// This should basically never occur in practice because of rekeying.
    ///
    /// Default value is 2^32 - 1, one less than NIST's recommended limit.
    /// https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38d.pdf
    const EXPIRE_AFTER_USES: u64 = 4294967295;

    /// Determines how computationally difficult the proof of work is when Bob challenges Alice.
    /// It is extremely computationally expensive on Bob to process Alice's initiation packet. So
    /// Bob has the option to challenge Alice to prove ownership of address and to prove work before
    /// they attempt process Alice's initiation packet.
    /// The amount of computational work Alice has to prove increases exponentially with this value.
    ///
    /// This value must be between 0 and 32 (inclusive).
    ///
    /// Default is 13, which, on a modern processor, ensures Alice will have to do about as much
    /// computational work as Bob will when they process Alice's initiation packet.
    const PROOF_OF_WORK_BIT_DIFFICULTY: u32 = 13;

    type Rng: CryptoRng + RngCore;

    type PrpEnc: AesEnc;
    type PrpDec: AesDec;

    type AeadEnc: AesGcmEnc;
    type AeadDec: AesGcmDec;

    type Hash: Sha512;
    type HmacHash: HmacSha512;

    type PublicKey: P384PublicKey;
    type KeyPair: P384KeyPair<PublicKey = Self::PublicKey, Rng = Self::Rng>;

    /// Type for arbitrary opaque object for use by the application that is attached to
    /// each session.
    type Data;

    /// Data type for incoming packet buffers.
    ///
    /// This can be something like `Vec<u8>` or `Box<[u8]>` or it can be something like a pooled
    /// reusable buffer that automatically returns to its pool when ZSSP is done with it. ZSSP may
    /// hold these for a short period of time when assembling fragmented packets on the receive
    /// path.
    type IncomingPacketBuffer: AsRef<[u8]> + AsMut<[u8]>;
    /// Data type for giving ZSSP temporary ownership of a buffer containing the local party's
    /// identity.
    /// It will be dropped as soon as the session is established.
    type LocalIdentityBlob: AsRef<[u8]>;

    /// This function will be called whenever Alice's initial Hello packet contains the zero ratchet
    /// fingerprint. Brand new peers will always connect to Bob with the zero ratchet key, but from
    /// then on they should be using non-zero ratchet keys.
    ///
    /// If this returns false, we will attempt to connect to Alice with the zero ratchet key.
    /// If this returns true, Alice's connection will be silently dropped.
    /// If this function is configured to always return true, it means peers will not be able to
    /// connect to us unless they had a prior-established ratchet key with us. This is the best way
    /// for the paranoid to enforce a manual allow-list.
    #[allow(unused)]
    fn hello_requires_recognized_ratchet(&self, current_time: i64) -> bool {
        false
    }
    /// This function is called if we, as Alice, attempted to open a session with Bob using a
    /// non-zero ratchet key, but Bob does not have this ratchet key and wants to downgrade
    /// to the zero ratchet key.
    ///
    /// If it returns true Alice will downgrade their ratchet number to 0, potentially ending their
    /// current ratchet chain.
    /// If it returns false then we will consider Bob as having failed authentication, and this
    /// packet will be dropped. The session will continue attempting to connect to Bob.
    ///
    /// This function must deterministically return either true or false for a given session.
    ///
    /// It is a bad sign that Bob has somehow forgotten Alice's ratchet key, it either means at
    /// least one party is misconfigured and got their ratchet keys corrupted or lost, or Bob has
    /// been compromised and is being impersonated. An attacker must at least have Bob's private
    /// static key to be able to ask Alice to downgrade.
    ///
    /// If Alice does decide to reconnect without a ratchet key, be sure to generate some warning
    /// that something has gone wrong and Bob could not be fully authenticated.
    #[allow(unused)]
    fn initiator_disallows_downgrade(&self, session: &Arc<Session<Self>>, current_time: i64) -> bool {
        false
    }
    /// Lookup a specific ratchet key based on its ratchet fingerprint.
    /// This function will be called whenever Alice attempts to connect to us with a non-zero
    /// ratchet fingerprint.
    ///
    /// If the ratchet key was found, the function should return `RestoreAction::RestoreRatchet`. This will
    /// cause us to connect to Alice using the returned ratchet number and ratchet key.
    ///
    /// If the ratchet key could not be found, the application may choose between returning
    /// `RatchetAction::DowngradeRatchet` or `RatchetAction::FailAuthentication`.
    /// If `RatchetAction::DowngradeRatchet` is returned we will attempt to convince Alice to downgrade
    /// to the zero ratchet key, restarting the ratchet chain.
    /// If `RatchetAction::FailAuthentication` is returned Alice's connection will be silently dropped.
    #[allow(unused)]
    fn restore_ratchet(&self, ratchet_fingerprint: &[u8; RATCHET_SIZE], current_time: i64) -> Result<Option<RatchetState>, ()> {
        Ok(None)
    }
    /// Atomically save the given ratchet key, fingerprint and number to persistent storage.
    ///
    /// See the documentation of `SaveAction` for more details on how to save them to storage,
    /// and how to handle any pre-existing ratchet keys, fingerprints and numbers.
    ///
    /// If this returns `Err(())`, the packet which triggered this function to be called will be
    /// dropped, and no session state will be mutated, preserving synchronization. The remote peer
    /// will eventually resend that packet and so this function will be called again.
    ///
    /// If persistent storage is supported, this function should not return until the ratchet state
    /// is saved, otherwise it is possible, albeit unlikely, for a sudden restart of the local
    /// machine to put our ratchet state out of sync with the remote peer. If this happens the only
    /// fix is to reset both ratchet keys to zero.
    ///
    /// This function may also save state to volatile storage, in which case all peers which connect
    /// to us will have to allow downgrade
    /// (`initiator_disallows_downgrade` returns false and/or`restore_ratchet` returns `DowngradeRatchet`).
    /// Otherwise, when we restart, we will not be allowed to reconnect.
    #[allow(unused)]
    fn save_ratchet_state<'a>(
        &self,
        remote_static_key: &Self::PublicKey,
        application_data: &Self::Data,
        save_action: SaveAction<'a>,
        current_time: i64,
    ) -> Result<(), ()> {
        Ok(())
    }
    #[allow(unused)]
    #[inline]
    fn event_log<'a>(&self, event: LogEvent<'a, Self>, current_time: i64) {}
}

#[derive(Default, Clone, PartialEq, Eq)]
pub struct RatchetState {
    pub key: Secret<RATCHET_SIZE>,
    pub fingerprint: Secret<RATCHET_SIZE>,
    pub chain_len: u64,
}
/// Ratchet keys and fingerprints should be saved *per remote peer*. It is up to the application to
/// enforce separate storage for each remote peer based on `remote_static_key` and `application_data`.
///
/// Only up to 2 ratchet keys and fingerprints will be saved at one time.
pub enum SaveAction<'a> {
    AddRatchet(&'a RatchetState),
    DeleteRatchet(&'a RatchetState),
    DeleteThenAddRatchet(&'a RatchetState, &'a RatchetState),
    VerifyThenOverwriteRatchet(Option<&'a RatchetState>, &'a RatchetState),
}
