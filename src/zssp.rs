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
use std::io::Write;
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
pub(crate) type SessionQueue<App> = IndexedBinaryHeap<Weak<Session<App>>, Reverse<i64>>;
pub struct ContextInner<App: ApplicationLayer> {
    pub rng: Mutex<App::Rng>,
    pub(crate) s_secret: App::KeyPair,
    /// `session_queue -> state_machine_lock -> state -> session_map`
    pub(crate) session_queue: Mutex<SessionQueue<App>>,
    /// `session_queue -> state_machine_lock -> state -> session_map`
    pub(crate) session_map: SessionMap<App>,
    pub(crate) unassociated_defrag_cache: Mutex<UnassociatedFragCache<App::IncomingPacketBuffer>>,
    pub(crate) unassociated_handshake_states: UnassociatedHandshakeCache<App>,

    pub(crate) challenge: ChallengeContext,
}

#[derive(Debug, PartialEq, Eq)]
pub enum IncomingSessionAction {
    Allow,
    Challenge,
    Drop,
}

fn parse_fragment_header<StorageError>(incoming_fragment: &[u8]) -> Result<(usize, usize, [u8; AES_GCM_IV_SIZE]), ReceiveError<StorageError>> {
    let fragment_no = incoming_fragment[FRAGMENT_NO_IDX] as usize;
    let fragment_count = incoming_fragment[FRAGMENT_COUNT_IDX] as usize;
    if fragment_no >= fragment_count || fragment_count > MAX_FRAGMENTS {
        return Err(byzantine_fault!(FaultType::InvalidPacket, true));
    }
    let mut nonce = [0u8; AES_GCM_IV_SIZE];
    nonce[2..].copy_from_slice(&incoming_fragment[PACKET_NONCE_START..HEADER_SIZE]);
    Ok((fragment_no, fragment_count, nonce))
}


/// Fragments and sends the packet, destroying it in the process.
///
/// Corresponds to the fragmentation algorithm described in Section 6.
fn send_with_fragmentation<PrpEnc: AesEnc>(
    mut send: impl FnMut(&mut [u8]) -> bool,
    mtu: usize,
    headered_packet: &mut [u8],
    hk_send: Option<&PrpEnc>,
) -> bool {
    let payload_len = headered_packet.len() - HEADER_SIZE;
    let payload_mtu = mtu - HEADER_SIZE;
    debug_assert!(payload_mtu >= 4);
    let fragment_count = payload_len.saturating_add(payload_mtu - 1) / payload_mtu; // Ceiling div.
    let fragment_base_size = payload_len / fragment_count;
    let fragment_size_remainder = payload_len % fragment_count;

    let mut i = HEADER_SIZE;
    for fragment_no in 0..fragment_count {
        let j = i + fragment_base_size + (fragment_no < fragment_size_remainder) as usize;
        let fragment = &mut headered_packet[i - HEADER_SIZE..j];

        fragment[FRAGMENT_NO_IDX] = fragment_no as u8;
        fragment[FRAGMENT_COUNT_IDX] = fragment_count as u8;

        if let Some(hk_send) = hk_send {
            hk_send.encrypt_in_place(
                (&mut fragment[HEADER_AUTH_START..HEADER_AUTH_END]).try_into().unwrap(),
            );
        }
        if !send(fragment) {
            return false;
        }
        i = j;
    }
    true
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
            |packet, hk_send| {
                send_with_fragmentation(send, mtu, packet, hk_send);
            }
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
        mut incoming_fragment_buf: App::IncomingPacketBuffer,
        output_buffer: impl Write,
    ) -> Result<ReceiveOk<App>, ReceiveError<App::StorageError>> {
        use crate::result::FaultType::*;
        let ctx = &self.0;
        send_unassociated_mtu = send_unassociated_mtu.max(MIN_TRANSPORT_MTU);
        let incoming_fragment: &mut [u8] = incoming_fragment_buf.as_mut();
        if incoming_fragment.len() < MIN_PACKET_SIZE {
            return Err(byzantine_fault!(FaultType::InvalidPacket, false));
        }

        let mut fragment_buffer = Assembled::new();

        let kid_recv = incoming_fragment[0..KID_SIZE].try_into().unwrap();
        if let Some(kid_recv) = NonZeroU32::new(u32::from_be_bytes(kid_recv)) {
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
                let ret = if packet_type == PACKET_TYPE_DATA {
                    let fragments = if fragment_count > 1 {
                        let idx = incoming_counter as usize % session.defrag.len();
                        session.defrag[idx].lock().unwrap().assemble(
                            &nonce,
                            incoming_fragment_buf,
                            fragment_no,
                            fragment_count,
                            &mut fragment_buffer,
                        );
                        if fragment_buffer.is_empty() {
                            return Ok(ReceiveOk::Unassociated);
                        } else {
                            // We have not yet authenticated the sender so we do not report
                            // receiving a packet from them.
                            fragment_buffer.as_mut()
                        }
                    } else {
                        std::slice::from_mut(&mut incoming_fragment_buf)
                    };
                    receive_payload_in_place(app, ctx, &session, kid_recv, &nonce, fragments, output_buffer)?;
                    SessionEvent::Data
                } else {
                    let mut buffer = ArrayVec::<u8, HANDSHAKE_RESPONSE_SIZE>::new();
                    let assembled_packet = if fragment_count > 1 {
                        let idx = incoming_counter as usize % session.defrag.len();
                        session.defrag[idx].lock().unwrap().assemble(
                            &nonce,
                            incoming_fragment_buf,
                            fragment_no,
                            fragment_count,
                            &mut fragment_buffer,
                        );
                        if fragment_buffer.is_empty() {
                            return Ok(ReceiveOk::Unassociated);
                        } else {
                            for fragment in fragment_buffer.as_ref() {
                                buffer.try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..]).map_err(|_| byzantine_fault!(InvalidPacket, true))?;
                            }
                            // We have not yet authenticated the sender so we do not report
                            // receiving a packet from them.
                            buffer.as_mut()
                        }
                    } else {
                        &mut incoming_fragment_buf.as_mut()[HEADER_SIZE..]
                    };

                    let send_associated = |packet: &mut [u8], hk_send: Option<&App::PrpEnc>| {
                        if let Some((send_fragment, mut mtu)) = send_to(&session) {
                            mtu = mtu.max(MIN_TRANSPORT_MTU);
                            send_with_fragmentation(send_fragment, mtu, packet, hk_send);
                        }
                    };
                    match packet_type {
                        PACKET_TYPE_HANDSHAKE_RESPONSE => {
                            log!(app, ReceivedRawX2);
                            received_x2_trans(
                                app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, X2IsAuthSentX3(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_KEY_CONFIRM => {
                            log!(app, ReceivedRawKeyConfirm);
                            let result =
                                received_c1_trans(app, ctx, &session, kid_recv, &nonce, assembled_packet,send_associated)?;
                            log!(app, KeyConfirmIsAuthSentAck(&session));
                            if result {
                                SessionEvent::Established
                            } else {
                                SessionEvent::Control
                            }
                        }
                        PACKET_TYPE_ACK => {
                            log!(app, ReceivedRawAck);
                            received_c2_trans(app, ctx, &session, kid_recv, &nonce, assembled_packet)?;
                            log!(app, AckIsAuth(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_REKEY_INIT => {
                            log!(app, ReceivedRawK1);
                            received_k1_trans(app, ctx, &session, kid_recv, &nonce, assembled_packet, send_associated)?;
                            log!(app, K1IsAuthSentK2(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_REKEY_COMPLETE => {
                            log!(app, ReceivedRawK2);
                            received_k2_trans(app, ctx, &session, kid_recv, &nonce, assembled_packet, send_associated)?;
                            log!(app, K2IsAuthSentKeyConfirm(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_SESSION_REJECTED => {
                            log!(app, ReceivedRawD);
                            received_d_trans(app, ctx, &session, kid_recv, &nonce, assembled_packet)?;
                            log!(app, DIsAuthClosedSession(&session));
                            SessionEvent::Rejected
                        }
                        _ => return Err(byzantine_fault!(InvalidPacket, true)), // This is unreachable.
                    }
                };
                Ok(ReceiveOk::Session(session, ret))
            } else {
                drop(session_map);
                // Check for and handle PACKET_TYPE_ALICE_NOISE_XK_PATTERN_3
                let zeta = self.0.unassociated_handshake_states.get(kid_recv);
                if let Some(zeta) = zeta {
                    App::PrpDec::new(&zeta.hk_recv).decrypt_in_place(
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

                    let mut buffer = ArrayVec::<u8, HANDSHAKE_COMPLETION_MAX_SIZE>::new();
                    let assembled_packet = if fragment_count > 1 {
                        zeta.defrag.lock().unwrap().assemble(
                            &nonce,
                            incoming_fragment_buf,
                            fragment_no,
                            fragment_count,
                            &mut fragment_buffer
                        );
                        if fragment_buffer.is_empty() {
                            return Ok(ReceiveOk::Unassociated);
                        } else {
                            for fragment in fragment_buffer.as_ref() {
                                buffer.try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..]).map_err(|_| byzantine_fault!(InvalidPacket, true))?;
                            }
                            buffer.as_mut()
                        }
                    } else {
                        &mut incoming_fragment_buf.as_mut()[HEADER_SIZE..]
                    };
                    // We must guarantee that this incoming handshake is processed once and only
                    // once. This prevents catastrophic nonce reuse caused by multithreading.
                    if !self.0.unassociated_handshake_states.remove(kid_recv) {
                        return Ok(ReceiveOk::Unassociated);
                    }

                    log!(app, ReceivedRawX3);
                    let session = received_x3_trans(app, ctx, zeta, kid_recv, assembled_packet, |packet, hk_send| {
                        send_with_fragmentation(
                            send_unassociated_reply,
                            send_unassociated_mtu,
                            packet,
                            hk_send,
                        );
                    })?;
                    log!(app, X3IsAuthSentKeyConfirm(&session));
                    Ok(ReceiveOk::Session(session, SessionEvent::NewSession))
                } else {
                    // This can occur naturally because either Bob's incoming_sessions cache got
                    // full so Alice's incoming session was dropped, or the session this packet
                    // was for was dropped by the application.
                    return Err(byzantine_fault!(UnknownLocalKeyId, true));
                }
            }
        } else {
            let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
            let (packet_type, _c) = from_nonce(&nonce);

            {//vrfy
                log!(app, ReceivedRawFragment(packet_type, _c, frag_no, frag_count));
                if packet_type != PACKET_TYPE_HANDSHAKE_HELLO && packet_type != PACKET_TYPE_CHALLENGE {
                    return Err(byzantine_fault!(InvalidPacket, true))
                }
            }

            let mut buffer = ArrayVec::<u8, HANDSHAKE_HELLO_MAX_SIZE>::new();
            let assembled_packet = if fragment_count > 1 {
                self.0.unassociated_defrag_cache.lock().unwrap().assemble(
                    &nonce,
                    remote_address,
                    incoming_fragment.len() - HEADER_SIZE,
                    incoming_fragment_buf,
                    fragment_no,
                    fragment_count,
                    App::SETTINGS.resend_time as i64,
                    app.time(),
                    &mut fragment_buffer
                );
                if fragment_buffer.is_empty() {
                    return Ok(ReceiveOk::Unassociated);
                } else {
                    for fragment in fragment_buffer.as_ref() {
                        buffer.try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..]).map_err(|_| byzantine_fault!(InvalidPacket, true))?;
                    }
                    buffer.as_mut()
                }
            } else {
                &mut incoming_fragment_buf.as_mut()[HEADER_SIZE..]
            };

            if packet_type == PACKET_TYPE_HANDSHAKE_HELLO {
                log!(app, ReceivedRawX1);

                if !(HANDSHAKE_HELLO_CHALLENGE_MIN_SIZE..=HANDSHAKE_HELLO_CHALLENGE_MAX_SIZE).contains(&assembled_packet.len()) {
                    return Err(byzantine_fault!(InvalidPacket, true));
                }
                // Process recv challenge layer.
                let challenge_start = assembled_packet.len() - CHALLENGE_SIZE;
                let result = ctx.challenge.process_hello::<App::Hash>(remote_address, (&assembled_packet[challenge_start..]).try_into().unwrap());
                if let Err(challenge) = result {
                    log!(app, X1FailedChallengeSentNewChallenge);
                    let mut challenge_packet = ArrayVec::<u8, HEADERED_CHALLENGE_SIZE>::new();
                    challenge_packet.extend([0u8; HEADER_SIZE]);
                    challenge_packet.try_extend_from_slice(&assembled_packet[..KID_SIZE]).unwrap();
                    challenge_packet.extend(challenge);
                    let nonce = to_nonce(PACKET_TYPE_CHALLENGE, ctx.rng.lock().unwrap().next_u64());
                    challenge_packet[FRAGMENT_COUNT_IDX] = 1;
                    challenge_packet[PACKET_NONCE_START..HEADER_SIZE].copy_from_slice(&nonce);

                    send_unassociated_reply(&mut challenge_packet);
                    // If we issue a challenge the first hello packet will always fail.
                    return Err(byzantine_fault!(FailedAuth, false));
                } else {
                    log!(app, X1SucceededChallenge);
                }

                // Process recv zeta layer.
                received_x1_trans(app, ctx, &nonce, assembled_packet, |packet, hk_send| {
                    send_with_fragmentation(
                        send_unassociated_reply,
                        send_unassociated_mtu,
                        packet,
                        hk_send,
                    );
                })?;
                log!(app, X1IsAuthSentX2);

                Ok(ReceiveOk::Unassociated)
            } else if packet_type == PACKET_TYPE_CHALLENGE {
                log!(app, ReceivedRawChallenge);
                // Process recv challenge layer.
                if assembled_packet.len() != KID_SIZE + CHALLENGE_SIZE {
                    return Err(byzantine_fault!(InvalidPacket, true));
                }
                if let Some(kid_recv) = NonZeroU32::new(u32::from_be_bytes(assembled_packet[..KID_SIZE].try_into().unwrap())) {
                    if let Some(Some(session)) = ctx.session_map.read().unwrap().get(&kid_recv).map(|r| r.upgrade()) {
                        respond_to_challenge(ctx, &session, &assembled_packet[KID_SIZE..].try_into().unwrap());
                        log!(app, ChallengeIsAuth(&session));
                        return Ok(ReceiveOk::Unassociated);
                    }
                }
                Err(byzantine_fault!(UnknownLocalKeyId, true))
            } else {
                Err(byzantine_fault!(InvalidPacket, true))
            }
        }
    }
    /*
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
    } */
}
