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
use crate::crypto::sha512::{HmacSha512, Sha512};
use crate::crypto::rand_core::{CryptoRng, RngCore};
use crate::{log_event::LogEvent, Session, RATCHET_FINGERPRINT_SIZE, RATCHET_KEY_SIZE};

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

    type BlockCipherEnc: AesEnc;
    type BlockCipherDec: AesDec;

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

    /// Save the given ratchet state to persistent storage.
    /// A ratchet state consists of a ratchet number, a ratchet fingerprint, and a ratchet key.
    ///
    /// Ratchet states are identified by their ratchet number, the latest ratchet state with a
    /// specific ratchet number should overwrite any previous ratchet state with the same number.
    /// Only the `ratchet_number` and `ratchet_number - 1` ratchet states should be saved to persistent
    /// storage, when a new one is saved the `ratchet_number - 2` ratchet state should be deleted.
    ///
    /// The `last_confirmed_ratchet_number` specifies which of the two saved ratchet states should
    /// be used if this local peer needs to re-open this session (i.e. after a system restart).
    /// This number should also be saved to persistent storage.
    ///
    /// A ratchet fingerprint is a 32 byte string unique for each ratchet key, it should be
    /// possible to quickly look up the `ratchet_key` from just its `ratchet_fingerprint`.
    ///
    /// If this returns `Err(())`, the packet which triggered this function to be called will be
    /// dropped, and no session state will be mutated, preserving synchronization. The remote peer
    /// will eventually resend that packet and so this function will be called again.
    ///
    /// If persistent storage is supported, this function should not return until the ratchet state
    /// is saved, otherwise it is possible, albeit unlikely, for a sudden restart of the local
    /// machine to put our ratchet state out of sync with the remote peer. If this happens the only
    /// fix is to restart the entire ratchet chain from zero.
    ///
    /// This function may also save state to volatile storage, or potentially not even save it at
    /// all, in which case all peers which connect to us will always have to allow us to downgrade
    /// the ratchet chain to zero. Otherwise they might not consider us to be "authentic".
    #[allow(unused)]
    fn save_ratchet_state(
        &self,
        alice_s_public: &Self::PublicKey,
        application_data: &Self::Data,
        ratchet_action: SaveRatchetAction,
        latest_ratchet_number: u64,
        latest_ratchet_fingerprint: &[u8; RATCHET_FINGERPRINT_SIZE],
        latest_ratchet_key: &[u8; RATCHET_KEY_SIZE],
        current_time: i64,
    ) -> Result<(), ()> {
        Ok(())
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
    fn allow_downgrade(&self, session: &Arc<Session<Self>>, current_time: i64) -> bool {
        true
    }
    /// Lookup a specific ratchet key based on its ratchet fingerprint.
    /// This function will be called whenever Alice attempts to connect to us with a non-zero
    /// ratchet key.
    ///
    /// If the ratchet key was found, the function should return `RatchetAction::Found`. This will
    /// cause us to connect to Alice using the returned ratchet number and ratchet key.
    /// We don't know Alice's static identity at this point in the handshake, so a
    /// `RemotePeerIdentifier` must be returned, so when Alice does send their identity we
    /// can verify it matches what we expect.
    ///
    /// If the ratchet key could not be found, the application may choose between returning
    /// `RatchetAction::Downgrade` or `RatchetAction::Ignore`.
    /// If `RatchetAction::Downgrade` is returned we will attempt to convince Alice to downgrade
    /// to the zero ratchet key, restarting the ratchet chain.
    /// If `RatchetAction::Ignore` is returned Alice's connection will be silently dropped.
    #[allow(unused)]
    fn lookup_ratchet(&self, ratchet_fingerprint: &[u8; RATCHET_FINGERPRINT_SIZE], current_time: i64) -> Result<GetRatchetAction, ()> {
        Ok(GetRatchetAction::Downgrade)
    }
    /// This function will be called whenever Alice's initial Hello packet contains the zero ratchet
    /// key. Brand new peers will always connect to Bob with the zero ratchet key, but from then on
    /// they should be using non-zero ratchet keys.
    ///
    /// If this returns true, we will attempt to connect to Alice with the zero ratchet key.
    /// If this returns false, Alice's connection will be silently dropped.
    /// If this function is configured to always return false, it means peers will not be able to
    /// connect to us unless they had a prior-established ratchet key with us. This is the best way
    /// for the paranoid to enforce a manual allow-list.
    #[allow(unused)]
    fn allow_zero_ratchet(&self, current_time: i64) -> bool {
        true
    }
    #[allow(unused)]
    #[inline]
    fn event_log<'a>(&self, event: LogEvent<'a, Self>, current_time: i64) {}
}
pub enum GetRatchetAction {
    Found(u64, [u8; RATCHET_KEY_SIZE]),
    Downgrade,
    Ignore,
}
/// Only 2 ratchet states may be saved at one time.
/// If a 3rd ratchet state needs to be saved the 1st should be deleted, if it was not already deleted.
/// The "previous ratchet state" may be the zero ratchet state.
pub enum SaveRatchetAction {
    /// Save the given new ratchet state and set the previous saved ratchet state as
    /// the confirmed ratchet state, if it was not already.
    /// If there are currently two saved states delete the oldest state and replace it with this one.
    SaveAsUnconfirmed,
    /// Save the given new ratchet state and set it as the confirmed ratchet state. Keep the previous
    /// ratchet state saved and searchable until it is explicitly deleted.
    /// If there are currently two saved states delete the oldest state and replace it with this one.
    SaveAsConfirmed,
    /// The given ratchet state will be identical to that saved during a previous call to
    /// `SaveAsUnconfirmedAndConfirmPrevious`. Set the given ratchet state as the
    /// confirmed ratchet state and permanently delete the previous ratchet state.
    ConfirmLatestAndDeletePrevious,
    /// The given ratchet state will be identical to that saved during a previous call to
    /// `SaveAsConfirmed`. Permanently delete the previous ratchet state, as in delete the ratchet
    /// state with ratchet number one less than the given ratchet state.
    DeletePrevious,
}
use SaveRatchetAction::*;
impl SaveRatchetAction {
    /// If this is true then this is the first time the latest ratchet state has ever been seen,
    /// so it ought to be immediately saved.
    pub fn save_latest(&self) -> bool {
        match self {
            SaveAsUnconfirmed => true,
            SaveAsConfirmed => true,
            _ => false,
        }
    }
    /// If this is true then only the latest ratchet state should be saved.
    /// Any previous ratchet states should be deleted now.
    pub fn delete_previous(&self) -> bool {
        match self {
            ConfirmLatestAndDeletePrevious => true,
            DeletePrevious => true,
            _ => false,
        }
    }
    pub fn confirm_latest(&self) -> bool {
        match self {
            ConfirmLatestAndDeletePrevious => true,
            SaveAsConfirmed => true,
            _ => false,
        }
    }
}
