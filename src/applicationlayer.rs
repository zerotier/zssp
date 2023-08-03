use rand_core::{CryptoRng, RngCore};
use std::sync::Arc;

use crate::crypto::{AeadAesGcm, HashSha512, KeyPairP384, PrivateKeyKyber1024, PrpAes256, PublicKeyP384};
use crate::proto::RATCHET_SIZE;
use crate::ratchet_state::RatchetState;
#[cfg(feature = "logging")]
use crate::LogEvent;
use crate::Session;

/// A container for a vast majority of the dynamic settings within ZSSP, including all time-based settings.
/// If the user wishes to measure time in units other than milliseconds for some reason, then they can
/// create an adjusted version of this struct with those units, and use it instead of the default.
pub struct Settings {
    /// Timeout for how long Alice should wait for Bob to confirm that the Noise_XK handshake
    /// was completed successfully. The handshake attempt will be assumed as failed and
    /// restarted if Bob does not respond by this cut-off.
    pub initial_offer_timeout: u64,
    /// Timeout for how long ZSSP should wait before expiring and closing a session when it has
    /// lingered in certain states for too long, primarily the rekeying states.
    /// If a remote peer does not send the correct information to rekey a session before this
    /// timeout then the session will close.
    pub rekey_timeout: u64,
    /// How long until rekeying should occur for each new session key.
    pub rekey_after_time: u64,
    /// Maximum random jitter to subtract from the rekey after time timer.
    /// Must be greater than 0.
    /// This prevents rekeying from occurring predictably on the hour, so traffic analysis is harder.
    pub rekey_time_max_jitter: u64,
    /// How many key uses may occur before the session starts attempting to rekey.
    /// The session will forceably close at 2^32 key uses so it is recommended this value be smaller.
    pub rekey_after_key_uses: u64,
    /// Retry interval for outgoing connection initiation or rekey attempts.
    ///
    /// Retry attempts will be no more often than this, but the delay may end up being
    /// slightly more in some cases based on the rate of calls to `service`.
    pub resend_time: u64,
    /// How long fragments are allowed to linger in the defragmentation buffer before they are dropped.
    /// This implementation of a defrag buffer only bounds memory consumption based on this value.
    pub fragment_assembly_timeout: u64,
}
impl Settings {
    /// Default value for the `initial_offer_timeout`.
    /// The default value is 10 seconds in ms.
    pub const INITIAL_OFFER_TIMEOUT_MS: u64 = 10 * 1000;
    /// Default value for the `rekey_timeout`.
    /// The default value is 1 minute in ms.
    pub const REKEY_TIMEOUT_MS: u64 = 60 * 1000;
    /// Default value for the `rekey_after_time`.
    /// The default value is 1 hour in ms.
    pub const REKEY_AFTER_TIME_MS: u64 = 60 * 60 * 1000;
    /// Default value for the `rekey_time_max_jitter`.
    /// The default is 10 minutes in ms.
    pub const REKEY_AFTER_TIME_MAX_JITTER_MS: u64 = 10 * 60 * 1000;
    /// Default value for the `rekey_after_key_uses`.
    /// The default is 2^30.
    pub const REKEY_AFTER_KEY_USES: u64 = 1 << 30;
    /// Default value for the `resend_time`.
    /// The default is 1 second in ms.
    pub const RESEND_TIME: u64 = 1000;
    /// Default value for the `fragment_assembly_timeout`.
    /// The default is 5 seconds in ms.
    pub const FRAGMENT_ASSEMBLY_TIMEOUT_MS: u64 = 5 * 1000;
    /// Create an instance of Settings with all default values.
    /// These defaults are in units of milliseconds, so if these defaults are used, `App::time`
    /// must return timestamps in unts of milliseconds as well.
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
impl Default for Settings {
    fn default() -> Self {
        Self::new_ms()
    }
}

/// Trait to implement to integrate the session into an application.
///
/// Templating the session on this trait lets the code here be almost entirely transport, OS,
/// and use case independent.
pub trait ApplicationLayer: Sized {
    /// These are constants that can be redefined from their defaults to change rekey
    /// and negotiation timeout behavior. If two sides of a ZSSP session have different constants,
    /// the protocol will tend to default to the smaller constants.
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

    /// Should return the current time in milliseconds. Does not have to be monotonic, nor synced
    /// with remote peers (although both of these properties would help reliability slightly).
    /// Used to determine if any current handshakes should be resent or timed-out, or if a session
    /// should rekey.
    fn time(&self) -> i64;

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
    fn initiator_disallows_downgrade(&self, session: &Arc<Session<Self>>) -> bool;
    /// Function to accept sessions after final negotiation.
    /// The second argument is the identity that the remote peer sent us. The application
    /// must verify this identity is associated with the remote peer's static key.
    /// To prevent desync, if this function returns (Some(_), _), no other open session with the
    /// same remote peer must exist. Drop or call expire on any pre-existing sessions before returning.
    fn check_accept_session(&self, remote_static_key: &Self::PublicKey, identity: &[u8]) -> (Option<(bool, Self::Data)>, bool);

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
    fn restore_by_fingerprint(&self, ratchet_fingerprint: &[u8; RATCHET_SIZE]) -> Result<Option<RatchetState>, Self::DiskError>;
    /// Lookup the specific ratchet states based on the identity of the peer being communicated with.
    /// This function will be called whenever Alice attempts to open a session, or Bob attempts
    /// to verify Alice's identity.
    ///
    /// If the peer's ratchet states could not be could, this function should return
    /// `RatchetState::new_initial_states()`.
    ///
    /// If a one-time-password has been pre-shared with this peer, `RatchetState::new_otp_states(...)`
    /// should be pre-saved to the storage backend as if it is a normal ratchet state.
    /// This is to ensure it can both be restored and eventually deleted when it is used.
    ///
    /// This function is not responsible for deciding whether or not to connect to this remote peer.
    /// Filtering peers should be done by the caller to `Context::open` as well as by the
    /// function `ApplicationLayer::check_accept_session`.
    fn restore_by_identity(&self, remote_static_key: &Self::PublicKey, application_data: &Self::Data) -> Result<(RatchetState, Option<RatchetState>), Self::DiskError>;
    /// Atomically save `current_state1` and `current_state2` so that them and only them can be
    /// restored with `restore_by_identity` and `restore_by_fingerprint` through a system restart.
    /// Theses should overwrite the previous ratchet states 1 and 2 saved to storage.
    ///
    /// `state_added` will be equal to the brand new ratchet state that was added in this update,
    /// or `None` if there is not a new ratchet state this update. `state_deleted1` and
    /// `state_deleted2` will be equal to any ratchet states that are to be deleted and overwritten
    /// as a result of this update, or `None` if there is not one to be deleted.
    /// `state_added` will always have a non-empty (`Some()`) ratchet fingerprint, and it will
    /// always be equal to `current_state1`.
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
        current_state1: &RatchetState,
        current_state2: Option<&RatchetState>,
        state_added: Option<&RatchetState>,
        state_deleted1: Option<&RatchetState>,
        state_deleted2: Option<&RatchetState>,
    ) -> Result<(), Self::DiskError>;

    /// Receives a stream of events that occur during an execution of ZSSP.
    /// These are provided for debugging, logging or metrics purposes, and must be used for
    /// nothing else. Do not base protocol-level decisions upon the events passed to this function.
    #[cfg(feature = "logging")]
    fn event_log(&self, event: LogEvent<Self>);
}
