/* This Source Code Form is subject to the terms of the Mozilla Public
* License, v. 2.0. If a copy of the MPL was not distributed with this
* file, You can obtain one at https://mozilla.org/MPL/2.0/.
*
* (c) ZeroTier, Inc.
* https://www.zerotier.com/
*/
// ZSSP: ZeroTier Secure Session Protocol
// FIPS compliant Noise_XK with Jedi powers (Kyber1024) and built-in attack-resistant large payload (fragmentation) support.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::{NonZeroU32, NonZeroU64};
use std::ops::DerefMut;
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, Weak};

use arrayvec::ArrayVec;
use zeroize::Zeroizing;

use crate::zeta::*;
use crate::challenge::ChallengeContext;
use crate::crypto::aes::{AesDec, AesEnc, AES_256_KEY_SIZE, AES_GCM_TAG_SIZE, AES_GCM_IV_SIZE};
use crate::crypto::p384::{P384KeyPair, P384PublicKey, P384_ECDH_SHARED_SECRET_SIZE, P384_PUBLIC_KEY_SIZE};
use crate::crypto::pqc_kyber::KYBER_SECRETKEYBYTES;
use crate::crypto::rand_core::RngCore;
use crate::crypto::sha512::{HmacSha512, HashSha512};

use crate::result::{FaultType, OpenError, ReceiveError, SendError, ReceiveOk, byzantine_fault, SessionEvent};
use crate::frag_cache::UnassociatedFragCache;
use crate::fragged::{Assembled, Fragged};
use crate::handshake_cache::UnassociatedHandshakeCache;
use crate::indexed_heap::{BinaryHeapIndex, IndexedBinaryHeap};
use crate::log_event::LogEvent;
use crate::proto::*;
use crate::symmetric_state::SymmetricState;
use crate::{applicationlayer::*, RatchetState};

/// Macro to turn off logging at compile time.
macro_rules! log {
    ($app:expr, $event:expr) => {
        #[cfg(feature = "logging")]
        $app.event_log($event);
    };
}
pub(crate) use log;

/// Session context for local application.
///
/// Each application using ZSSP must create an instance of this to own sessions and
/// defragment incoming packets that are not yet associated with a session.
///
/// Internally this is just a clonable Arc, so it can be safely shared with multiple threads.
pub struct Context<Application: ApplicationLayer>(pub Arc<ContextInner<Application>>);
impl<Application: ApplicationLayer> Clone for Context<Application> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(crate) type SessionMap<App> = RwLock<HashMap<NonZeroU32, Weak<Session<App>>>>;
pub(crate) struct ContextInner<App: ApplicationLayer> {
    pub rng: Mutex<App::Rng>,
    pub(crate) s_secret: App::KeyPair,
    pub(crate) session_queue: Mutex<IndexedBinaryHeap<Weak<Session<App>>, Reverse<i64>>>,
    pub(crate) session_map: SessionMap<App>,
    pub(crate) unassociated_defrag_cache: Mutex<UnassociatedFragCache<App::IncomingPacketBuffer>>,
    pub(crate) unassociated_handshake_states: UnassociatedHandshakeCache<App>,
    //pub(crate) b2_map: Mutex<HashMap<NonZeroU32, StateB2<App>>>,

    //hello_defrag: Mutex<DefragBuffer>,
    pub(crate) challenge: ChallengeContext,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IncomingSessionAction {
    Allow,
    Challenge,
    Drop,
}

fn parse_fragment_header<App: ApplicationLayer>(incoming_fragment: &[u8]) -> Result<(usize, usize, [u8; AES_GCM_IV_SIZE]), ReceiveError<App::StorageError>> {
    let fragment_no = incoming_fragment[FRAGMENT_NO_IDX] as usize;
    let fragment_count = incoming_fragment[FRAGMENT_COUNT_IDX] as usize;
    if fragment_no >= fragment_count || fragment_count > MAX_FRAGMENTS {
        return Err(byzantine_fault!(FaultType::InvalidPacket, true));
    }
    let mut nonce = [0u8; AES_GCM_IV_SIZE];
    nonce[2..].copy_from_slice(&incoming_fragment[PACKET_NONCE_START..HEADER_SIZE]);
    Ok((fragment_no, fragment_count, nonce))
}


impl<App: ApplicationLayer> Context<App> {
    /// Create a new session context.
    pub fn new(static_secret_key: App::KeyPair, mut rng: App::Rng) -> Self {
        let challenge = ChallengeContext::new(&mut rng);
        Self(Arc::new(ContextInner {
            rng: Mutex::new(rng),
            s_secret: static_secret_key,
            session_map: RwLock::new(HashMap::new()),
            challenge,
            session_queue: Mutex::new(IndexedBinaryHeap::new()),
            unassociated_defrag_cache: Mutex::new(UnassociatedFragCache::new()),
            unassociated_handshake_states: UnassociatedHandshakeCache::new(),
        }))
    }

    /// Create a new session and send initial packet(s) to other side.
    ///
    /// This will return SendError::DataTooLarge if the combined size of the metadata and the local
    /// static public blob (as retrieved from the application layer) exceed MAX_INIT_PAYLOAD_SIZE.
    ///
    /// * `app` - Application layer instance
    /// * `send` - Function to be called to send one or more initial packets to the remote being
    ///   contacted
    /// * `mtu` - MTU for initial packets
    /// * `remote_static_key` - Remote side's static public NIST P-384 key
    /// * `application_data` - Arbitrary data meaningful to the application to include with session
    ///   object
    /// * `ratchet_state` - The last saved and confirmed ratchet state associated with this remote
    ///   peer, or None if we do not have one.
    /// * `local_identity_blob` - Payload to be sent to Bob that contains the information necessary
    ///   for the upper protocol to authenticate and approve of Alice's identity.
    pub fn open(
        &self,
        app: App,
        mut send: impl FnMut(&mut [u8]) -> bool,
        mut mtu: usize,
        static_remote_key: App::PublicKey,
        session_data: App::SessionData,
        identity: &[u8],
    ) -> Result<Arc<Session<App>>, OpenError<App::StorageError>> {
        mtu = mtu.max(MIN_TRANSPORT_MTU);
        if identity.len() > IDENTITY_MAX_SIZE {
            return Err(OpenError::IdentityTooLarge);
        }
        // Process zeta layer.
        trans_to_a1(
            app,
            &self.0,
            static_remote_key,
            session_data,
            identity,
        )
    }

    /// Receive, authenticate, decrypt, and process a physical wire packet.
    ///
    /// The check_allow_incoming_session function is called when an initial Noise_XK init message is
    /// received. This is before anything is known about the caller. A return value of true proceeds
    /// with negotiation. False drops the packet and ignores the inbound attempt.
    ///
    /// The check_accept_session function is called at the end of negotiation for an incoming
    /// session with the caller's static public blob. It must return the P-384 static public key
    /// extracted from the supplied blob and application data. A return of Some() accepts the
    /// session and will always result in a new session ReceiveOk being returned.
    ///
    /// * `app` - Interface to application using ZSSP
    /// * `check_allow_incoming_session` - Function to call to check whether an unidentified new
    ///   session should be accepted
    /// * `check_accept_session` - Function to accept sessions after final negotiation.
    ///   The second argument is the identity blob that the remote peer sent us. The application
    ///   must verify this identity is associated with the remote peer's static key.
    ///   The third argument is the ratchet chain length, or ratchet count.
    ///   To prevent desync, if this function returns (Some(_), _), no other open session with the
    ///   same remote peer must exist.
    /// * `send_unassociated_reply` - Function to send reply packets directly when no session exists
    /// * `send_unassociated_mtu` - MTU for unassociated replies
    /// * `send_to` - Function to get senders for existing sessions, permitting MTU and path lookup
    /// * `remote_address` - Whatever the remote address is, as long as you can Hash it
    /// * `data_buf` - Buffer to receive decrypted and authenticated object data (an error is
    ///   returned if too small)
    /// * `incoming_physical_packet_buf` - Buffer containing incoming wire packet
    ///   (receive() takes ownership)
    /// * `current_time` - Current time in milliseconds. Does not have to be monotonic, nor synced
    ///   with the remote peer. Used to check the state of local offers we may currently have or want
    ///   to put in-flight.
    pub fn receive<'a, SendFn: FnMut(&mut [u8]) -> bool>(
        &self,
        app: &App,
        check_allow_incoming_session: impl FnOnce() -> IncomingSessionAction,
        check_accept_session: impl FnOnce(&App::PublicKey, &[u8], u64) -> (Option<(bool, App::SessionData)>, bool),
        mut send_unassociated_reply: impl FnMut(&mut [u8]) -> bool,
        mut send_unassociated_mtu: usize,
        mut send_to: impl FnMut(&Arc<Session<App>>) -> Option<(SendFn, usize)>,
        remote_address: &impl Hash,
        data_buf: &'a mut [u8],
        mut incoming_fragment_buf: App::IncomingPacketBuffer,
        current_time: i64,
    ) -> Result<ReceiveOk<App>, ReceiveError<App::StorageError>> {
        use crate::result::FaultType::*;
        let ctx = &self.0;
        send_unassociated_mtu = send_unassociated_mtu.max(MIN_TRANSPORT_MTU);
        let incoming_fragment: &mut [u8] = incoming_fragment_buf.as_mut();
        if incoming_fragment.len() < MIN_PACKET_SIZE {
            return Err(byzantine_fault!(FaultType::InvalidPacket, false));
        }

        // The first section parses the header and looks up relevant state information. If it's a DATA
        // or NOP packet it gets handled right here, otherwise we pull out a set of variables and
        // continue to the logic that handles KEX and session control packets.

        let mut assembled_packet = Assembled::new(); // needs to outlive the block below
        let mut incoming = None;
        let (session, packet_type, fragments) = {
            let kid_recv = incoming_fragment[0..KID_SIZE].try_into().unwrap();
            // `from_ne_bytes` because this id was generated locally.
            if let Some(kid_recv) = NonZeroU32::new(u32::from_ne_bytes(kid_recv)) {
                let session_map = self.0.session_map.read().unwrap();
                let session = ctx.session_map.read().unwrap().get(&kid_recv).map(|r| r.upgrade());
                if let Some(Some(session)) = session {
                    drop(session_map);
                    session.hk_recv.decrypt_in_place(
                        (&mut incoming_fragment[HEADER_AUTH_START..HEADER_AUTH_END])
                            .try_into()
                            .unwrap(),
                    );

                    let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
                    let (packet_type, incoming_counter) = from_nonce(&nonce);

                    {//vrfy
                        if packet_type != PACKET_TYPE_DATA {
                            log!(app, ReceivedRawFragment(p, c, fragment_no, fragment_count));
                        }
                        if packet_type == PACKET_TYPE_HANDSHAKE_RESPONSE {
                            if !matches!(&session.state.read().unwrap().beta, ZetaAutomata::A1(_)) {
                                // A resent handshake response from Bob may have arrived out of order,
                                // after we already received one.
                                return Err(byzantine_fault!(OutOfSequence, false));
                            }
                            if incoming_counter >= COUNTER_WINDOW_MAX_SKIP_AHEAD {
                                return Err(byzantine_fault!(ExpiredCounter, true));
                            }
                        } else if PACKET_TYPE_USES_COUNTER_RANGE.contains(&packet_type) {
                            // For DOS resistant reply-protection we need to check that the given counter is
                            // in the window of valid counters immediately.
                            // But for packets larger than 1 fragment we can't actually record the
                            // counter as received until we've authenticated the packet.
                            // So we check the counter window twice, and only update it the second time
                            // after the packet has been authenticated.
                            if !session.window.check(incoming_counter) {
                                // This can occur naturally if packets arrive way out of order, or
                                // if they are duplicates.
                                // This can also be naturally triggered if Bob has just successfully
                                // received the first session key and is reject all of Alice's resends.
                                // This can also occur if a session was manually expired, but not
                                // dropped, and the remote party is still sending us data.
                                return Err(byzantine_fault!(ExpiredCounter, false));
                            }
                        } else if packet_type == PACKET_TYPE_HANDSHAKE_COMPLETION {
                            // This can be triggered if Bob successfully received a session key and
                            // needs to reject all of Alice's resends of PACKET_TYPE_NOISE_XK_PATTERN_3.
                            return Err(byzantine_fault!(InvalidPacket, false));
                        } else {
                            return Err(byzantine_fault!(InvalidPacket, true));
                        }
                    }

                    // Handle defragmentation.
                    let fragments = if fragment_count > 1 {
                        let idx = incoming_counter as usize % session.defrag.len();
                        session.defrag[idx].lock().unwrap().assemble(
                            &nonce,
                            incoming_fragment_buf,
                            fragment_no,
                            fragment_count,
                            &mut assembled_packet,
                        );
                        if assembled_packet.is_empty() {
                            // We have not yet authenticated the sender so we do not report
                            // receiving a packet from them.
                            return Ok(ReceiveOk::Unassociated);
                        } else {
                            assembled_packet.as_ref()
                        }
                    } else {
                        std::slice::from_ref(&incoming_fragment_buf)
                    };

                    match packet_type {
                        PACKET_TYPE_DATA => {
                            let state = session.state.read().unwrap();
                            // The error here can occur because the other party is using a brand new
                            // session key that we have not received yet.
                            let key = state.cipher_states[key_index]
                                .as_ref()
                                .ok_or(byzantine_fault!(FaultType::OutOfSequence, true))?;
                            let mut c = key.get_receive_cipher(incoming_counter);
                            c.set_iv(&create_message_nonce(packet_type, incoming_counter));

                            let mut data_len = 0;

                            // Decrypt fragments 0..N-1 where N is the number of fragments.
                            for f in fragments[..(fragments.len() - 1)].iter() {
                                let f: &[u8] = f.as_ref();
                                debug_assert!(f.len() >= HEADER_SIZE);
                                let current_frag_data_start = data_len;
                                data_len += f.len() - HEADER_SIZE;
                                if data_len > data_buf.len() {
                                    return Err(ReceiveError::DataBufferTooSmall);
                                }
                                c.decrypt(&f[HEADER_SIZE..], &mut data_buf[current_frag_data_start..data_len]);
                            }

                            // Decrypt final fragment (or only fragment if not fragmented)
                            let current_frag_data_start = data_len;
                            let last_fragment = fragments.last().unwrap().as_ref();
                            if last_fragment.len() < (HEADER_SIZE + AES_GCM_TAG_SIZE) {
                                return Err(byzantine_fault!(FaultType::InvalidPacket, false));
                            }
                            data_len += last_fragment.len() - (HEADER_SIZE + AES_GCM_TAG_SIZE);
                            if data_len > data_buf.len() {
                                return Err(ReceiveError::DataBufferTooSmall);
                            }
                            let payload_end = last_fragment.len() - AES_GCM_TAG_SIZE;
                            c.decrypt(&last_fragment[HEADER_SIZE..payload_end], &mut data_buf[current_frag_data_start..data_len]);

                            let aead_authentication_ok = c.finish_decrypt(&last_fragment[payload_end..].try_into().unwrap());
                            drop(c);
                            drop(state);

                            if !aead_authentication_ok {
                                return Err(byzantine_fault!(FaultType::FailedAuthentication, false));
                            }
                            if !session.update_receive_window(incoming_counter) {
                                // This can be naturally triggered because Bob has just
                                // successfully received a session key and needs to reject
                                // all of Alice's resends.
                                // This can also occur naturally if some part of the outer
                                // system is duplicating the packets being sent to us.
                                // We are safely deduplicating them here.
                                return Err(byzantine_fault!(FaultType::ExpiredCounter, true));
                            }
                            // Packet fully authenticated
                            return Ok(ReceiveOk::Session(session, SessionEvent::Data(&mut data_buf[..data_len])));
                        }
                        PACKET_TYPE_HANDSHAKE_RESPONSE => {
                            (Some(session), packet_type, fragments)
                        }
                    }
                } else {
                    drop(session_map);
                    // Check for and handle PACKET_TYPE_ALICE_NOISE_XK_PATTERN_3
                    incoming = self.0.unassociated_handshake_states.get(kid_recv);
                    if let Some(incoming) = incoming.as_ref() {
                        App::PrpDec::new(&incoming.hk_recv).decrypt_in_place(
                            (&mut incoming_fragment[HEADER_AUTH_START..HEADER_AUTH_END])
                                .try_into()
                                .unwrap(),
                        );

                        let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
                        let (packet_type, incoming_counter) = from_nonce(&nonce);

                        {//vrfy
                            log!(app, ReceivedRawFragment(packet_type, incoming_counter, frag_no, frag_count));
                            if packet_type != PACKET_TYPE_HANDSHAKE_COMPLETION || incoming_counter != 0 {
                               return Err(byzantine_fault!(InvalidPacket, true))
                            }
                        }

                        let fragments = if fragment_count > 1 {
                            incoming.defrag.lock().unwrap().assemble(
                                &nonce,
                                incoming_fragment_buf,
                                fragment_no,
                                fragment_count,
                                &mut assembled_packet,
                            );
                            if !assembled_packet.is_empty() {
                                assembled_packet.as_ref()
                            } else {
                                return Ok(ReceiveOk::Unassociated);
                            }
                        } else {
                            std::slice::from_ref(&incoming_fragment_buf)
                        };
                        // We must guarantee that this incoming handshake is processed once and only
                        // once. This prevents catastrophic nonce reuse caused by multithreading.
                        if self.0.unassociated_handshake_states.remove(kid_recv) {
                            (None, PACKET_TYPE_HANDSHAKE_COMPLETION, fragments)
                        } else {
                            return Ok(ReceiveOk::Unassociated);
                        }
                    } else {
                        // This can occur naturally because either Bob's incoming_sessions cache got
                        // full so Alice's incoming session was dropped, or the session this packet
                        // was for was dropped by the application.
                        return Err(byzantine_fault!(UnknownLocalKeyId, true));
                    }
                }
            } else {
                let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
                let (packet_type, incoming_counter) = from_nonce(&nonce);

                {//vrfy
                    log!(app, ReceivedRawFragment(packet_type, incoming_counter, frag_no, frag_count));
                    if packet_type != PACKET_TYPE_HANDSHAKE_HELLO && packet_type != PACKET_TYPE_CHALLENGE {
                        return Err(byzantine_fault!(InvalidPacket, true))
                    }
                }

                let fragments = if fragment_count > 1 {
                    self.0.unassociated_defrag_cache.lock().unwrap().assemble(
                        &nonce,
                        remote_address,
                        incoming_fragment.len() - HEADER_SIZE,
                        incoming_fragment_buf,
                        fragment_no,
                        fragment_count,
                        App::SETTINGS.resend_time as i64,
                        current_time,
                        &mut assembled_packet,
                    );
                    if !assembled_packet.is_empty() {
                        assembled_packet.as_ref()
                    } else {
                        return Ok(ReceiveOk::Unassociated);
                    }
                } else {
                    std::array::from_ref(&incoming_fragment_buf)
                };
                (None, packet_type, fragments)
            }
        };
    }
    /// Send data over the session.
    ///
    /// * `session` - The session to send to
    /// * `send` - Function to call to send physical packet(s); the buffer passed to `send` is a
    ///   slice of `data`
    /// * `mtu_sized_buffer` - A writable work buffer whose size equals the MTU
    /// * `data` - Data to send
    /// * `current_time` - Current time in milliseconds
    pub fn send(
        &self,
        session: &Arc<Session<App>>,
        mut send: impl FnMut(&mut [u8]) -> bool,
        mtu_sized_buffer: &mut [u8],
        mut data: &[u8],
        current_time: i64,
    ) -> Result<(), SendError> {
        if mtu_sized_buffer.len() < MIN_TRANSPORT_MTU {
            return Err(SendError::InvalidParameter);
        }
        let state = session.state.read().unwrap();
        let key = state.cipher_states[state.current_key].as_ref().ok_or(SendError::SessionNotEstablished)?;
        let counter = session.get_next_outgoing_counter()?;

        let mut c = key.get_send_cipher(counter)?;
        c.set_iv(&create_message_nonce(PACKET_TYPE_DATA, counter));

        let fragment_max_chunk_size = mtu_sized_buffer.len() - HEADER_SIZE;
        let fragment_count = (data.len() + AES_GCM_TAG_SIZE + (fragment_max_chunk_size - 1)) / fragment_max_chunk_size;
        if fragment_count > MAX_FRAGMENTS {
            return Err(SendError::DataTooLarge);
        }
        let last_fragment_no = fragment_count - 1;

        for fragment_no in 0..fragment_count {
            let chunk_size = fragment_max_chunk_size.min(data.len());
            let mut fragment_size = chunk_size + HEADER_SIZE;

            set_packet_header(
                mtu_sized_buffer,
                fragment_count as u8,
                fragment_no as u8,
                PACKET_TYPE_DATA,
                key.remote_key_id.get(),
                counter,
            );

            c.encrypt(&data[..chunk_size], &mut mtu_sized_buffer[HEADER_SIZE..fragment_size]);
            data = &data[chunk_size..];

            if fragment_no == last_fragment_no {
                debug_assert!(data.is_empty());
                let tagged_fragment_size = fragment_size + AES_GCM_TAG_SIZE;
                c.finish_encrypt((&mut mtu_sized_buffer[fragment_size..tagged_fragment_size]).try_into().unwrap());
                fragment_size = tagged_fragment_size;
            }

            session.header_send_cipher.encrypt_in_place(
                (&mut mtu_sized_buffer[HEADER_PROTECT_ENC_START..HEADER_PROTECT_ENC_END])
                    .try_into()
                    .unwrap(),
            );
            if !send(&mut mtu_sized_buffer[..fragment_size]) {
                break;
            }
        }
        drop(c);
        if counter >= key.rekey_at_counter {
            if let OfferStateMachine::Normal { .. } = &state.outgoing_offer {
                drop(state);
                if let Ok(timer) = initiate_rekey(&self.0, session, send, current_time) {
                    self.0.session_queue.lock().unwrap().change_priority(session.queue_idx, Reverse(timer));
                }
            }
        }
        Ok(())
    }

    /// Perform periodic background service and cleanup tasks.
    ///
    /// This returns the number of milliseconds until it should be called again. The caller should
    /// try to satisfy this but small variations in timing of up to +/- a second or two are not
    /// a problem.
    ///
    /// * `send_to` - Function to get a sender and an MTU to send something over an active session
    /// * `current_time` - Current time in milliseconds. Does not have to be monotonic, nor synced
    ///   with remote peers (although both of these properties would help reliability slightly).
    ///   Used to determine if any current handshakes should be resent or timed-out, or if a session
    ///   should rekey.
    pub fn service<SendFn: FnMut(&mut [u8]) -> bool>(
        &self,
        app: &App,
        mut send_to: impl FnMut(&Arc<Session<App>>) -> Option<(SendFn, usize)>,
        current_time: i64,
    ) -> i64 {
        let retry_next = current_time.saturating_add(App::RETRY_INTERVAL_MS);
        let mut next_service_time = 2 * App::RETRY_INTERVAL_MS;

        let mut session_queue = self.0.session_queue.lock().unwrap();
        // This update system takes heavy advantage of the fact that sessions only need to be updated
        // either roughly every second or roughly every hour. That big gap allows for minor optimizations.
        // If the gap changes (unlikely) this code may need to be rewritten.
        while let Some((session, timer, queue_idx)) = session_queue.peek() {
            if timer.0 >= current_time {
                next_service_time = next_service_time.min(timer.0 - current_time);
                break;
            }
            let session = match session.upgrade() {
                Some(s) => s,
                _ => {
                    session_queue.remove(queue_idx);
                    continue;
                }
            };
            let state = session.state.read().unwrap();
            let next_timer = match &state.outgoing_offer {
                Normal { timeout, .. } => {
                    if *timeout <= current_time {
                        drop(state);
                        if let Some((send, _)) = send_to(&session) {
                            let result = initiate_rekey(&self.0, &session, send, current_time);
                            if result.is_ok() {
                                app.event_log(LogEvent::ServiceKKStart(&session), current_time);
                            }
                            result.unwrap_or(retry_next)
                        } else {
                            retry_next
                        }
                    } else {
                        *timeout
                    }
                }
                // If there's an outstanding attempt to open a session, retransmit this
                // periodically in case the initial packet doesn't make it.
                NoiseXKPattern1or3(handshake_state) => {
                    if let Some(ts) = process_timer(&handshake_state.next_retry_time, App::RETRY_INTERVAL_MS, current_time) {
                        ts
                    } else {
                        // We have to eventually time out NoiseXKPattern3 because of unreliable network conditions.
                        if handshake_state.timeout <= current_time {
                            drop(state);
                            let _kex_lock = session.state_machine_lock.lock().unwrap();
                            let mut state = session.state.write().unwrap();
                            let ratchet_state = state.ratchet_states.clone();
                            // Since we dropped the lock we must re-check if we are in the correct state.
                            if let NoiseXKPattern1or3(handshake_state) = &mut state.outgoing_offer {
                                if handshake_state.timeout <= current_time {
                                    app.event_log(LogEvent::ServiceXKTimeout(&session), current_time);
                                    handshake_state.reinitialize(
                                        &session,
                                        &ratchet_state,
                                        &mut self.0.session_map.write().unwrap(),
                                        &mut self.0.rng.lock().unwrap(),
                                        current_time,
                                    );
                                }
                            }
                        } else if let Some((mut send, mut mtu)) = send_to(&session) {
                            mtu = mtu.max(MIN_TRANSPORT_MTU);
                            match &handshake_state.offer {
                                NoiseXKAliceHandshakeState::NoiseXKPattern1 { noise_message, noise_message_len, message_id, .. } => {
                                    app.event_log(LogEvent::ServiceXK1Resend(&session), current_time);
                                    // We are in state NoiseXKPattern1 so resend noise_pattern1.
                                    send_with_fragmentation(
                                        &mut send,
                                        mtu,
                                        &mut noise_message.clone()[..*noise_message_len],
                                        PACKET_TYPE_NOISE_XK_PATTERN_1,
                                        None,
                                        *message_id,
                                        None::<&App::PrpEnc>,
                                    );
                                }
                                NoiseXKAliceHandshakeState::NoiseXKPattern3 { noise_message, noise_message_len, .. } => {
                                    app.event_log(LogEvent::ServiceXK3Resend(&session), current_time);
                                    send_with_fragmentation(
                                        &mut send,
                                        mtu,
                                        &mut noise_message.clone()[..*noise_message_len],
                                        PACKET_TYPE_NOISE_XK_PATTERN_3,
                                        state.cipher_states[0].as_ref().map(|k| k.remote_key_id),
                                        0,
                                        Some(&session.header_send_cipher),
                                    );
                                }
                            }
                        }
                        retry_next
                    }
                }
                NoiseKKPattern1 { next_retry_time, timeout, noise_message, .. } | NoiseKKPattern2 { next_retry_time, timeout, noise_message, .. } => {
                    if let Some(ts) = process_timer(next_retry_time, App::RETRY_INTERVAL_MS, current_time) {
                        ts
                    } else {
                        if *timeout <= current_time {
                            app.event_log(LogEvent::ServiceKKTimeout(&session), current_time);
                            next_retry_time.store(i64::MAX, Ordering::Relaxed);
                            drop(state);
                            session.expire_inner(&self.0, &mut session_queue);
                        } else {
                            let packet_type = if let NoiseKKPattern1 { .. } = &state.outgoing_offer {
                                app.event_log(LogEvent::ServiceKK1Resend(&session), current_time);
                                PACKET_TYPE_NOISE_KK_PATTERN_1
                            } else {
                                app.event_log(LogEvent::ServiceKK2Resend(&session), current_time);
                                PACKET_TYPE_NOISE_KK_PATTERN_2
                            };
                            if let Some((send, _)) = send_to(&session) {
                                let _ = session.send_control(&state, send, packet_type, noise_message);
                            }
                        }
                        retry_next
                    }
                }
                KeyConfirm { next_retry_time, timeout, .. } => {
                    if let Some(ts) = process_timer(next_retry_time, App::RETRY_INTERVAL_MS, current_time) {
                        ts
                    } else {
                        if *timeout <= current_time {
                            app.event_log(LogEvent::ServiceKeyConfirmTimeout(&session), current_time);
                            next_retry_time.store(i64::MAX, Ordering::Relaxed);
                            drop(state);
                            session.expire_inner(&self.0, &mut session_queue);
                        } else {
                            app.event_log(LogEvent::ServiceKeyConfirmResend(&session), current_time);
                            if let Some((send, _)) = send_to(&session) {
                                let _ = session.send_control(&state, send, PACKET_TYPE_KEY_CONFIRM, &[]);
                            }
                        }
                        retry_next
                    }
                }
                Null => retry_next,
            };
            session_queue.change_priority(queue_idx, Reverse(next_timer));
        }
        drop(session_queue);

        self.0
            .unassociated_defrag_cache
            .lock()
            .unwrap()
            .check_for_expiry(App::INITIAL_OFFER_TIMEOUT_MS, current_time);
        self.0.unassociated_handshake_states.service(current_time);

        next_service_time
    }
}

impl<Application: ApplicationLayer> Session<Application> {
    ///
    ///// The current ratchet state of this session.
    ///// The returned values are sensitive and should be securely erased before being dropped.
    //pub fn ratchet_states(&self) -> [RatchetState; 2] {
    //    let state = self.state.read().unwrap();
    //    state.ratchet_states.clone()
    //}
    /// The current ratchet count of this session.
    //pub fn ratchet_count(&self) -> u64 {
    //    self.state.read().unwrap().
    //}
    /// Mark a session as expired. This will make it impossible for this session to successfully
    /// receive or send data or control packets. It is recommended to simply `drop` the session
    /// instead, but this can provide some reassurance in complex shared ownership situations.
    //pub fn expire(&self) {
    //    if let Some(context) = self.context.upgrade() {
    //        self.expire_inner(&context, &mut context.session_queue.lock().unwrap());
    //    }
    //}
    //fn expire_inner(
    //    &self,
    //    context: &Arc<ContextInner<Application>>,
    //    session_queue: &mut IndexedBinaryHeap<Weak<Session<Application>>, Reverse<i64>>,
    //) {
    //    // Prevent this session from being updated.
    //    session_queue.remove(self.queue_idx);
    //    self.session_has_expired.store(true, Ordering::Relaxed);
    //    let _kex_lock = self.state_machine_lock.lock().unwrap();
    //    let mut state = self.state.write().unwrap();
    //    let mut session_map = context.session_map.write().unwrap();
    //    for key in &state.cipher_states {
    //        if let Some(pre_id) = key.as_ref().map(|k| k.local_key_id) {
    //            session_map.remove(&pre_id);
    //        }
    //    }
    //    use OfferStateMachine::*;
    //    match &state.outgoing_offer {
    //        NoiseXKPattern1or3(handshake_state) => session_map.remove(&handshake_state.local_key_id),
    //        NoiseKKPattern1 { new_key_id, .. } => session_map.remove(new_key_id),
    //        _ => None,
    //    };
    //    state.outgoing_offer = OfferStateMachine::Null;
    //}
    /// Check whether this session is established.
    pub fn established(&self) -> bool {
        let state = self.state.read().unwrap();
        !matches!(&state.beta, ZetaAutomata::A1(_) | ZetaAutomata::A3 {..} | ZetaAutomata::Null)
    }
    /// The static public key of the remote peer.
    pub fn remote_static_key(&self) -> &Application::PublicKey {
        &self.s_remote
    }
}
