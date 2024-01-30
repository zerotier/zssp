use rand_core::{CryptoRng, RngCore};
use std::sync::Arc;

use crate::crypto::{Aes256Prp, AesGcmAead, Kyber1024PrivateKey, P384KeyPair, P384PublicKey, Sha512Hash};
#[cfg(feature = "logging")]
use crate::LogEvent;
use crate::Session;

pub use crate::proto::RATCHET_SIZE;
pub use crate::ratchet_state::*;

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

/// Trait to implement to integrate ZSSP into an application.
///
/// This is a container trait for all of the cryptographic algorithms ZSSP will use, and all of the
/// generic types that ZSSP will attach to sessions.
pub trait CryptoLayer: Sized {
    /// These are constants that can be redefined from their defaults to change rekey
    /// and negotiation timeout behavior. If two sides of a ZSSP session have different constants,
    /// the protocol will tend to default to the smaller constants.
    const SETTINGS: Settings = Settings::new_ms();

    /// The random number generator that ZSSP should use.
    /// It is used infrequently, but should still be cryptographically secure.
    ///
    /// FIPS compliance requires use of a FIPS certified implementation.
    type Rng: CryptoRng + RngCore;
    /// The implementation of AES-256 that ZSSP should use.
    /// We provide an optional implementation for this trait using the `aes` crate.
    ///
    /// FIPS compliance requires use of a FIPS certified implementation.
    type Prp: Aes256Prp;
    /// The implementation of AES-GCM-256 that ZSSP should use.
    /// The efficiency and security of ZSSP is very closely tied to the efficiency and security of
    /// this implementation.
    /// We provide an optional implementation for this trait using the `aes-gcm` crate.
    ///
    /// FIPS compliance requires a FIPS certified implementation.
    type Aead: AesGcmAead;
    /// The implementation of SHA-512 and HMAC-SHA-512 that ZSSP should use.
    /// We provide an optional implementation for this trait using the `sha2` crate.
    ///
    /// FIPS compliance requires use of a FIPS certified implementation.
    type Hash: Sha512Hash;
    /// The implementation of P-384 public keys that ZSSP should use.
    /// We provide an optional implementation for this trait using the `p384` crate.
    ///
    /// FIPS compliance requires a FIPS certified implementation.
    type PublicKey: P384PublicKey;
    /// The implementation of P-384 private keys that ZSSP should use.
    /// We provide an optional implementation for this trait using the `p384` crate.
    ///
    /// FIPS compliance requires use of a FIPS certified implementation.
    type KeyPair: P384KeyPair<Self::Rng, PublicKey = Self::PublicKey>;
    /// The implementation of Kyber1024 that ZSSP should use.
    /// We provide an optional implementation for this trait using the `pqc_kyber` crate.
    ///
    /// No implementation of Kyber1024 can be FIPS certified, but this is not required
    /// for ZSSP to achieve FIPS compliance.
    type Kem: Kyber1024PrivateKey<Self::Rng>;

    /// An arbitrary opaque object for use by the application that is attached to each session.
    type SessionData;
}
/// Trait to implement to integrate ZSSP into an application.
///
/// Templating ZSSP on this trait lets the code here be almost entirely transport, OS,
/// and use case independent.
pub trait ApplicationLayer<C: CryptoLayer>: Sized {
    /// Should return the current time in milliseconds. Does not have to be monotonic, nor synced
    /// with remote peers (although both of these properties would help reliability slightly).
    /// Used to determine if any current handshakes should be resent or timed-out, or if a session
    /// should rekey.
    fn time(&mut self) -> i64;

    /// This function will be called whenever Alice's initial Hello packet contains the empty ratchet
    /// fingerprint. Brand new peers will always connect to Bob with the empty ratchet, but from
    /// then on they should be using non-empty ratchet states.
    ///
    /// If this returns false, we will attempt to connect to Alice with the empty ratchet state.
    /// If this returns true, Alice's connection will be silently dropped.
    /// If this function is configured to always return true, it means peers will not be able to
    /// connect to us unless they had a prior-established ratchet key with us. This is the best way
    /// for the paranoid to enforce a manual allow-list.
    ///
    /// Corresponds to the "Hello Requires Recognized Ratchet, π_1" security flag of Transition
    /// Algorithm 2 within the ZSSP whitepaper.
    fn hello_requires_recognized_ratchet(&mut self) -> bool;
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
    ///
    /// Corresponds to the "Initiator Disallows Downgrade, π_2" security flag of Transition
    /// Algorithm 3 within the ZSSP whitepaper.
    fn initiator_disallows_downgrade(&mut self, session: &Arc<Session<C>>) -> bool;
    /// Function to accept sessions after final negotiation.
    ///
    /// The implementor must verify that `remote_static_key` and `identity` all belong to the same
    /// remote peer, using whatever definition
    /// of "same remote peer" that the upper protocol chooses.
    /// `fingerprint_data` is an opaque type that is only `Some` if Alice sent us a ratchet
    /// fingerprint that was successfully restored by `restore_by_fingerprint`.
    ///
    /// To prevent desync, if this function specifies that we should connect, no other open session
    /// with the same remote peer must exist. Drop or call expire on any pre-existing sessions
    /// before returning.
    ///
    /// Corresponds to the **Accept** call of Transition Algorithm 4 within the ZSSP whitepaper.
    fn check_accept_session(
        &mut self,
        remote_static_key: &<C as CryptoLayer>::PublicKey,
        identity: &[u8],
    ) -> AcceptAction<C>;

    /// Lookup a specific ratchet state based on its ratchet fingerprint.
    /// This function will be called whenever Alice attempts to connect to us with a non-empty
    /// ratchet fingerprint.
    ///
    /// If a ratchet state with a matching fingerprint could not be found, this function should
    /// return `Ok(None)`.
    ///
    /// This function can also return an opaque `FingerprintData` object. If Alice continues to connect
    /// with us, then this object will be passed to `check_accept_session` and `restore_by_identity`.
    /// This is useful if the ratchet fingerprint was derived from a one-time password, in which
    /// case `FingerprintData` can contain metadata regarding the one-time password. This can be
    /// used by `check_accept_session` and `restore_by_identity` to perform additional
    /// authentication checks, such as validating the one-time password as an invitation code.
    ///
    /// `FingerprintData` can also be used with extreme caution to cache database resources that can
    /// speed up the expected future calls to `check_accept_session` and `restore_by_identity`.
    /// If this is done, the implementor is required in `check_accept_session` to verify that the
    /// cached resources in `FingerprintData` indeed belong to the specified remote peer.
    ///
    /// Corresponds to the **Restore** call of Transition Algorithm 2 within the ZSSP whitepaper.
    fn restore_by_fingerprint(
        &mut self,
        ratchet_fingerprint: &[u8; RATCHET_SIZE],
    ) -> Result<Option<RatchetState>, std::io::Error>;
    /// Lookup the specific ratchet states based on the identity of the peer being communicated with.
    /// This function will be called whenever Alice attempts to open a session, or Bob attempts
    /// to verify Alice's identity.
    ///
    /// If the peer's ratchet states could not be found, this function should return `None`.
    /// A return value of `None` is equivalent to a return value of
    /// `Some(RatchetState::new_initial_states())`.
    ///
    /// If a one-time-password has been pre-shared with this peer, `RatchetState::new_otp_states(...)`
    /// should be pre-saved to the storage backend as if it is a normal ratchet state.
    /// This is to ensure it can both be restored and eventually deleted when it is used.
    ///
    /// This function is not responsible for deciding whether or not to connect to this remote peer.
    /// Filtering peers should be done by the caller to `Context::open` as well as by the
    /// function `ApplicationLayer::check_accept_session`.
    ///
    /// Corresponds to the **Restore** call of Transition Algorithm 1 and 4 within the ZSSP whitepaper.
    fn restore_by_identity(
        &mut self,
        remote_static_key: &<C as CryptoLayer>::PublicKey,
        session_data: &<C as CryptoLayer>::SessionData,
    ) -> Result<Option<RatchetStates>, std::io::Error>;
    /// Atomically compare-and-swap (a.k.a. compare-exchange) `update` to storage.
    ///
    /// If `update.cur_state1` and `update.cur_state2` are currently in storage, they must
    /// be swapped with `update.new_state1` and `update.new_state2`.
    /// Otherwise, storage must remain unchanged.
    ///
    /// `Ok(true)` must be returned if the compare-and-swap was successful.
    /// `Ok(false)` must be returned if comparison failed and the swap was cancelled.
    ///
    /// If this returns `Err`, the packet which triggered this function to be called will be
    /// dropped, and no session state will be mutated, preserving synchronization. The remote peer
    /// will eventually resend that packet and so this function will be called again.
    ///
    /// If persistent storage is supported, this function should not return until the ratchet state
    /// is saved, otherwise it is possible, albeit unlikely, for a sudden restart of the local
    /// machine to put our ratchet state out of sync with the remote peer. If this happens the only
    /// fix is to reset both ratchet keys to empty.
    ///
    /// This function may also save state to volatile storage, in which case all peers which connect
    /// to us will have to allow downgrade across the board.
    /// Otherwise, when we restart, we will not be allowed to reconnect.
    ///
    /// # Security
    /// Implementations must not perform comparison operations (equals, less than, etc.) directly
    /// on two ratchet keys. Instead, comparison operations must be performed indirectly
    /// upon their ratchet fingerprints. If two ratchet states have the same ratchet fingerprint,
    /// it should be assumed that they also have the same ratchet key.
    ///
    /// The implementations of `PartialEq` for `RatchetState` and `RatchetStates` do this by default.
    ///
    /// # Example
    /// The following code is an example of how to implement this database operation with the
    /// library `rustqlite`, an interface for SQLite in rust.
    /// This code will not work out-of-the-box, it must be adapted based on how your application
    /// structures its SQLite database.
    /// Notably, this code lacks a means of securely indexing ratchet fingerprints.
    /// The function `get_peer_primary_key` is a placeholder for however your application defines
    /// the SQL primary key for a peer. The function `get_sql_conn` is a placeholder getter method
    /// on `self` for retrieving the database connection object.
    /// ```rs
    /// fn to_err<E: std::error::Error + Send + Sync + 'static>(e: E) -> Error {
    ///    Error::new(std::io::ErrorKind::Other, e)
    /// }
    ///
    /// fn save_ratchet_state(
    ///     &mut self,
    ///     remote_static_key: &P384PublicKey,
    ///     session_data: &Peer<T>,
    ///     update_data: CompareAndSwap<'_>,
    /// ) -> Result<bool, Error> {
    ///     let peer = get_peer_primary_key(remote_static_key, session_data);
    ///     let mut conn = get_sql_conn(self);
    ///     // rustqlite will rollback this transaction if this struct is dropped.
    ///     let trans = conn
    ///         .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)
    ///         .map_err(to_err)?;
    ///     {
    ///         // Compare
    ///         let mut stmt = trans
    ///             .prepare_cached("SELECT ratchet_fp1, ratchet_fp2 FROM peers WHERE peer = ?1")
    ///             .map_err(to_err)?;
    ///         let mut rows = stmt.query([peer]).map_err(to_err)?;
    ///         if let Some(row) = rows.next().map_err(to_err)? {
    ///             let peer_fp1 = row.get_ref(0).map_err(to_err)?.as_bytes_or_null().map_err(to_err)?;
    ///             let peer_fp2 = row.get_ref(1).map_err(to_err)?.as_bytes_or_null().map_err(to_err)?;
    ///             let peer_fp1 = if let Some(fp1) = peer_fp1 {
    ///                 fp1.try_into().map_err(to_err)?
    ///             } else {
    ///                 &[0u8; RATCHET_SIZE]
    ///             };
    ///             let peer_fp2 = if let Some(fp2) = peer_fp2 {
    ///                 Some(fp2.try_into().map_err(to_err)?)
    ///             } else {
    ///                 None
    ///             };
    ///             if !update_data.compare_fingerprints(peer_fp1, peer_fp2) {
    ///                 return Ok(false);
    ///             }
    ///         } else {
    ///             return Ok(false);
    ///         }
    ///     }
    ///     {
    ///         // Swap
    ///         let ns1 = update_data.new_state1;
    ///         let ns2 = update_data.new_state2;
    ///         let mut stmt = trans.prepare_cached("UPDATE peers SET ratchet_fp1 = ?1, ratchet_key1 = ?2, chain_len1 = ?3, ratchet_fp2 = ?4, ratchet_key2 = ?5, chain_len2 = ?6 WHERE salted_addr = ?7").map_err(to_err)?;
    ///         stmt.execute((
    ///             ns1.fingerprint(),
    ///             ns1.key(),
    ///             ns1.chain_len(),
    ///             ns2.map(RatchetState::fingerprint),
    ///             ns2.map(RatchetState::key),
    ///             ns2.map(RatchetState::chain_len),
    ///             salted_addr,
    ///         ))
    ///         .map_err(to_err)?;
    ///     }
    ///     // SQLite does its best to make sure committed transactions are actually written
    ///     // to disk: https://www.sqlite.org/howtocorrupt.html.
    ///     trans.commit().map_err(to_err)?;
    ///     Ok(true)
    /// }
    /// ```
    fn save_ratchet_state(
        &mut self,
        remote_static_key: &<C as CryptoLayer>::PublicKey,
        session_data: &<C as CryptoLayer>::SessionData,
        update_data: CompareAndSwap<'_>,
    ) -> Result<bool, std::io::Error>;

    /// Receives a stream of events that occur during an execution of ZSSP.
    /// These are provided for debugging, logging or metrics purposes, and must be used for
    /// nothing else. Do not base protocol-level decisions upon the events passed to this function.
    #[cfg(feature = "logging")]
    #[allow(unused)]
    fn event_log(&mut self, event: LogEvent<'_, C>) {}
}

/// A collection of fields specifying how to complete the key exchange with a specific remote peer,
/// used by Bob, the responder, at the very last stage of the key exchange.
///
/// Corresponds to the *Accept* callback of Transition Algorithm 4.
pub struct AcceptAction<Crypto: CryptoLayer> {
    /// The data object to be attached to the session if we successfully connect.
    /// If this field is None then we will not connect to this remote peer.
    pub session_data: Option<Crypto::SessionData>,
    /// Whether or not we will accept a connection with the remote peer when they do not have a
    /// ratchet key that we think they should have.
    pub responder_disallows_downgrade: bool,
    /// Whether or not to send an explicit rejection packet to the remote peer if we do not create
    /// a session with them.
    ///
    /// This field will not be used if `session_data` is `Some` and the remote peer passes all other
    /// authentication checks.
    pub responder_silently_rejects: bool,
}
