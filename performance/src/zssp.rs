use std::cmp::Reverse;
use std::collections::HashMap;
use std::hash::Hash;
use std::io::Write;
use std::num::NonZeroU32;
use std::sync::atomic::{AtomicI64, Ordering};
use std::sync::{Arc, Mutex, RwLock, Weak};

use arrayvec::ArrayVec;
use rand_core::RngCore;

use crate::application::*;
use crate::challenge::ChallengeContext;
use crate::crypto::*;
use crate::frag_cache::UnassociatedFragCache;
use crate::fragged::Assembled;
use crate::handshake_cache::UnassociatedHandshakeCache;
use crate::indexed_heap::IndexedBinaryHeap;
use crate::proto::*;
use crate::result::{fault, ExpiredError, FaultType, OpenError, ReceiveError, ReceiveOk, SendError, SessionEvent};
use crate::zeta::*;
#[cfg(feature = "logging")]
use crate::LogEvent::*;

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
pub struct Context<Crypto: CryptoLayer>(pub Arc<ContextInner<Crypto>>);
impl<Crypto: CryptoLayer> Clone for Context<Crypto> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(crate) type SessionMap<Crypto> = RwLock<HashMap<NonZeroU32, Weak<Session<Crypto>>>>;

pub(crate) type SessionQueue<Crypto> = IndexedBinaryHeap<Weak<Session<Crypto>>, Reverse<i64>>;

/// The internal memory of the ZSSP context.
/// One of these is allocated as an `Arc` to initialize this implementation of ZSSP.
/// See `Context::new`.
pub struct ContextInner<Crypto: CryptoLayer> {
    /// The `CryptoRng` instance that was passed to ZSSP when this context was created.
    pub rng: Mutex<Crypto::Rng>,
    pub(crate) next_service_time: AtomicI64,
    pub(crate) s_secret: Crypto::KeyPair,
    /// `session_queue -> state_machine_lock -> state -> session_map`
    pub(crate) session_queue: Mutex<SessionQueue<Crypto>>,
    /// `session_queue -> state_machine_lock -> state -> session_map`
    pub(crate) session_map: SessionMap<Crypto>,
    pub(crate) unassociated_defrag_cache: Mutex<UnassociatedFragCache<Crypto>>,
    pub(crate) unassociated_handshake_states: UnassociatedHandshakeCache<Crypto>,

    pub(crate) challenge: ChallengeContext,
}
impl<Crypto: CryptoLayer> ContextInner<Crypto> {
    pub(crate) fn reduce_next_service_time(&self, time: i64) -> Option<i64> {
        (self.next_service_time.fetch_min(time, Ordering::Relaxed) > time).then_some(time)
    }
}

fn parse_fragment_header<Crypto: CryptoLayer>(
    incoming_fragment: &[u8],
) -> Result<(usize, usize, [u8; AES_GCM_NONCE_SIZE]), ReceiveError<Crypto>> {
    let fragment_no = incoming_fragment[FRAGMENT_NO_IDX] as usize;
    let fragment_count = incoming_fragment[FRAGMENT_COUNT_IDX] as usize;
    if fragment_no >= fragment_count || fragment_count > MAX_FRAGMENTS {
        return Err(fault!(FaultType::InvalidPacket, true));
    }
    let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
    nonce[2..].copy_from_slice(&incoming_fragment[PACKET_NONCE_START..HEADER_SIZE]);
    Ok((fragment_no, fragment_count, nonce))
}

/// Fragments and sends the packet, destroying it in the process.
///
/// Corresponds to the fragmentation algorithm described in Section 6.
fn send_with_fragmentation<PrpEnc: Aes256Enc>(
    mut send: impl Sender,
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

    let mut header: [u8; HEADER_SIZE] = headered_packet[..HEADER_SIZE].try_into().unwrap();
    header[FRAGMENT_COUNT_IDX] = fragment_count as u8;

    let mut i = HEADER_SIZE;
    for fragment_no in 0..fragment_count {
        let j = i + fragment_base_size + (fragment_no < fragment_size_remainder) as usize;
        let fragment = &mut headered_packet[i - HEADER_SIZE..j];

        fragment[..HEADER_SIZE].copy_from_slice(&header);
        fragment[FRAGMENT_NO_IDX] = fragment_no as u8;

        if let Some(hk_send) = hk_send {
            hk_send.encrypt_in_place((&mut fragment[HEADER_AUTH_START..HEADER_AUTH_END]).try_into().unwrap());
        }
        if !send.send_frag(fragment) {
            return false;
        }
        i = j;
    }
    true
}

impl<Crypto: CryptoLayer> Context<Crypto> {
    /// Create a new session context.
    pub fn new(static_secret_key: Crypto::KeyPair, mut rng: Crypto::Rng) -> Self {
        let challenge = ChallengeContext::new(&mut rng);
        Self(Arc::new(ContextInner {
            rng: Mutex::new(rng),
            s_secret: static_secret_key,
            next_service_time: AtomicI64::new(i64::MAX),
            session_map: RwLock::new(HashMap::new()),
            challenge,
            session_queue: Mutex::new(IndexedBinaryHeap::new()),
            unassociated_defrag_cache: Mutex::new(UnassociatedFragCache::new()),
            unassociated_handshake_states: UnassociatedHandshakeCache::new(),
        }))
    }

    /// Create a new session and send initialization packets to Bob, our remote peer.
    ///
    /// The session will not be "established" right away, and so will not be able to send data to
    /// the remote peer until they respond and finish the handshake. A `SessionEvent` variant of
    /// `Established` will be returned by `Context::receive` when this session is able to send data.
    ///
    /// This function returns an `Option<i64>`, which can safely be ignored if not using
    /// `Context::service_scheduled`. `Context::service_scheduled` contains documentation on how to
    /// handle the return value.
    ///
    /// To prevent desync, when this function is called, no other open session with the same remote
    /// peer must exist. Drop or call expire on any pre-existing sessions before calling.
    ///
    /// * `app` - Application layer instance
    /// * `send` - Function to be called to send one or more initial packets to the remote being
    ///   contacted
    /// * `mtu` - MTU for initial packets
    /// * `static_remote_key` - Remote side's static public NIST P-384 key
    /// * `session_data` - Arbitrary data meaningful to the application to include with session
    ///   object
    /// * `identity` - Payload to be sent to Bob that contains the information necessary
    ///   for the upper protocol to authenticate and approve of Alice's identity.
    pub fn open<App: ApplicationLayer<Crypto>>(
        &self,
        app: App,
        send: impl Sender,
        mut mtu: usize,
        static_remote_key: Crypto::PublicKey,
        session_data: Crypto::SessionData,
        identity: &[u8],
    ) -> Result<(Arc<Session<Crypto>>, Option<i64>), OpenError> {
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
            },
        )
    }

    /// Receive, authenticate, decrypt, and process a physical wire packet.
    ///
    /// This function returns an `Option<i64>`, which can safely be ignored if not using
    /// `Context::service_scheduled`. `Context::service_scheduled` contains documentation on how to
    /// handle the return value.
    ///
    /// * `app` - Interface to application using ZSSP
    /// * `send_unassociated_reply` - Function to send reply packets directly when no session exists
    /// * `send_unassociated_mtu` - MTU for unassociated replies
    /// * `send_to` - Function to get senders for existing sessions, permitting MTU and path lookup
    /// * `remote_address` - Whatever the remote address is, as long as you can Hash it
    /// * `incoming_fragment_buf` - Buffer containing incoming wire packet (the context takes ownership)
    /// * `output_buffer` - Buffer to receive decrypted and authenticated object data
    pub fn receive<'a, App: ApplicationLayer<Crypto>>(
        &self,
        mut app: App,
        mut send_unassociated_reply: impl Sender,
        mut send_unassociated_mtu: usize,
        mut send_to: impl SendTo<Crypto>,
        remote_address: &impl Hash,
        mut incoming_fragment_buf: Crypto::IncomingPacketBuffer,
        output_buffer: impl Write,
    ) -> Result<(ReceiveOk<Crypto>, Option<i64>), ReceiveError<Crypto>> {
        use crate::result::FaultType::*;
        let ctx = &self.0;
        send_unassociated_mtu = send_unassociated_mtu.max(MIN_TRANSPORT_MTU);
        let incoming_fragment: &mut [u8] = incoming_fragment_buf.as_mut();
        if incoming_fragment.len() < MIN_PACKET_SIZE {
            return Err(fault!(FaultType::InvalidPacket, false));
        }

        let mut fragment_buffer = Assembled::new();

        let kid_recv = incoming_fragment[0..KID_SIZE].try_into().unwrap();
        if let Some(kid_recv) = NonZeroU32::new(u32::from_ne_bytes(kid_recv)) {
            let session = ctx.session_map.read().unwrap().get(&kid_recv).map(|r| r.upgrade());
            if let Some(Some(session)) = session {
                let state = session.state.read().unwrap();
                let header_auth = &mut incoming_fragment[HEADER_AUTH_START..HEADER_AUTH_END];
                state.hk_recv.decrypt_in_place(header_auth.try_into().unwrap());

                let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
                let (packet_type, incoming_counter) = from_nonce(&nonce);
                if packet_type != PACKET_TYPE_DATA {
                    log!(
                        app,
                        ReceivedRawFragment(packet_type, incoming_counter, fragment_no, fragment_count)
                    );
                }

                //vrfy
                if packet_type == PACKET_TYPE_HANDSHAKE_RESPONSE {
                    if !matches!(&state.beta, ZetaAutomata::A1(_)) {
                        // A resent handshake response from Bob may have arrived out of order,
                        // after we already received one.
                        return Err(fault!(OutOfSequence, false, session));
                    }
                    if incoming_counter >= COUNTER_WINDOW_MAX_SKIP_AHEAD {
                        return Err(fault!(ExpiredCounter, true, session));
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
                        return Err(fault!(ExpiredCounter, false, session));
                    }
                } else if packet_type == PACKET_TYPE_HANDSHAKE_COMPLETION {
                    // This can be triggered if Bob successfully received a session key and
                    // needs to reject all of Alice's resends of PACKET_TYPE_NOISE_XK_PATTERN_3.
                    return Err(fault!(InvalidPacket, false, session));
                } else {
                    return Err(fault!(InvalidPacket, true, session));
                }

                // Handle defragmentation.
                let ret = if packet_type == PACKET_TYPE_DATA {
                    let fragments = if fragment_count > 1 {
                        let idx = incoming_counter as usize % session.defrag.len();
                        session.defrag[idx].lock().unwrap().assemble(
                            incoming_counter,
                            incoming_fragment_buf,
                            fragment_no,
                            fragment_count,
                            &mut fragment_buffer,
                        );
                        if fragment_buffer.is_empty() {
                            drop(state);
                            return Ok((ReceiveOk::Fragment(session), None));
                        } else {
                            // We have not yet authenticated the sender so we do not report
                            // receiving a packet from them.
                            fragment_buffer.as_mut()
                        }
                    } else {
                        std::slice::from_mut(&mut incoming_fragment_buf)
                    };

                    receive_payload_in_place(&session, state, kid_recv, &nonce, fragments, output_buffer)?;

                    (SessionEvent::Data, None)
                } else {
                    drop(state);
                    let mut buffer = ArrayVec::<u8, HANDSHAKE_RESPONSE_SIZE>::new();
                    let assembled_packet = if fragment_count > 1 {
                        let idx = incoming_counter as usize % session.defrag.len();
                        session.defrag[idx].lock().unwrap().assemble(
                            incoming_counter,
                            incoming_fragment_buf,
                            fragment_no,
                            fragment_count,
                            &mut fragment_buffer,
                        );
                        if fragment_buffer.is_empty() {
                            return Ok((ReceiveOk::Fragment(session), None));
                        } else {
                            for fragment in fragment_buffer.as_ref() {
                                buffer
                                    .try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..])
                                    .map_err(|_| fault!(InvalidPacket, true, session))?;
                            }
                            // We have not yet authenticated the sender so we do not report
                            // receiving a packet from them.
                            buffer.as_mut()
                        }
                    } else {
                        &mut incoming_fragment_buf.as_mut()[HEADER_SIZE..]
                    };

                    let send_associated = |packet: &mut [u8], hk_send: Option<&Crypto::PrpEnc>| {
                        if let Some((sender, mut mtu)) = send_to.init_send(&session) {
                            mtu = mtu.max(MIN_TRANSPORT_MTU);
                            send_with_fragmentation(sender, mtu, packet, hk_send);
                        }
                    };
                    match packet_type {
                        PACKET_TYPE_HANDSHAKE_RESPONSE => {
                            log!(app, ReceivedRawX2);
                            let (should_warn_missing_ratchet, reduced) = received_x2_trans(
                                &mut app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, X2IsAuthSentX3(&session));
                            if should_warn_missing_ratchet {
                                (SessionEvent::DowngradedRatchetKey, reduced)
                            } else {
                                (SessionEvent::Control, reduced)
                            }
                        }
                        PACKET_TYPE_KEY_CONFIRM => {
                            log!(app, ReceivedRawKeyConfirm);
                            let (just_established, reduced) = received_c1_trans(
                                &mut app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, KeyConfirmIsAuthSentAck(&session));
                            if just_established {
                                (SessionEvent::Established, reduced)
                            } else {
                                (SessionEvent::Control, reduced)
                            }
                        }
                        PACKET_TYPE_ACK => {
                            log!(app, ReceivedRawAck);
                            let reduced =
                                received_c2_trans(&mut app, ctx, &session, kid_recv, &nonce, assembled_packet)?;
                            log!(app, AckIsAuth(&session));
                            (SessionEvent::Control, reduced)
                        }
                        PACKET_TYPE_REKEY_INIT => {
                            log!(app, ReceivedRawK1);
                            let reduced = received_k1_trans(
                                &mut app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, K1IsAuthSentK2(&session));
                            (SessionEvent::Control, reduced)
                        }
                        PACKET_TYPE_REKEY_COMPLETE => {
                            log!(app, ReceivedRawK2);
                            let reduced = received_k2_trans(
                                &mut app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, K2IsAuthSentKeyConfirm(&session));
                            (SessionEvent::Control, reduced)
                        }
                        PACKET_TYPE_SESSION_REJECTED => {
                            log!(app, ReceivedRawD);
                            received_d_trans(&session, kid_recv, &nonce, assembled_packet)?;
                            log!(app, DIsAuthClosedSession(&session));
                            (SessionEvent::Rejected, None)
                        }
                        _ => return Err(fault!(InvalidPacket, true, session)), // This is unreachable.
                    }
                };
                Ok((ReceiveOk::Associated(session, ret.0), ret.1))
            } else {
                // Check for and handle PACKET_TYPE_ALICE_NOISE_XK_PATTERN_3
                let zeta = self.0.unassociated_handshake_states.get(kid_recv);
                if let Some(zeta) = zeta {
                    Crypto::PrpDec::new(&zeta.hk_recv).decrypt_in_place(
                        (&mut incoming_fragment[HEADER_AUTH_START..HEADER_AUTH_END])
                            .try_into()
                            .unwrap(),
                    );

                    let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
                    let (packet_type, incoming_counter) = from_nonce(&nonce);
                    log!(
                        app,
                        ReceivedRawFragment(packet_type, incoming_counter, fragment_no, fragment_count)
                    );

                    //vrfy
                    if packet_type != PACKET_TYPE_HANDSHAKE_COMPLETION || incoming_counter != 0 {
                        return Err(fault!(InvalidPacket, true));
                    }

                    let mut buffer = ArrayVec::<u8, HANDSHAKE_COMPLETION_MAX_SIZE>::new();
                    let assembled_packet = if fragment_count > 1 {
                        zeta.defrag.lock().unwrap().assemble(
                            incoming_counter,
                            incoming_fragment_buf,
                            fragment_no,
                            fragment_count,
                            &mut fragment_buffer,
                        );
                        if fragment_buffer.is_empty() {
                            return Ok((ReceiveOk::Unassociated, None));
                        } else {
                            for fragment in fragment_buffer.as_ref() {
                                buffer
                                    .try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..])
                                    .map_err(|_| fault!(InvalidPacket, true))?;
                            }
                            buffer.as_mut()
                        }
                    } else {
                        &mut incoming_fragment_buf.as_mut()[HEADER_SIZE..]
                    };
                    // We must guarantee that this incoming handshake is processed once and only
                    // once. This prevents catastrophic nonce reuse caused by multithreading.
                    if !self.0.unassociated_handshake_states.remove(kid_recv) {
                        return Ok((ReceiveOk::Unassociated, None));
                    }

                    log!(app, ReceivedRawX3);
                    let (session, should_warn_missing_ratchet, reduced) =
                        received_x3_trans(&mut app, ctx, zeta, kid_recv, assembled_packet, |packet, hk_send| {
                            send_with_fragmentation(send_unassociated_reply, send_unassociated_mtu, packet, hk_send);
                        })?;
                    log!(app, X3IsAuthSentKeyConfirm(&session));
                    Ok((
                        ReceiveOk::Associated(
                            session,
                            if should_warn_missing_ratchet {
                                SessionEvent::NewDowngradedSession
                            } else {
                                SessionEvent::NewSession
                            },
                        ),
                        reduced,
                    ))
                } else {
                    // This can occur naturally because either Bob's incoming_sessions cache got
                    // full so Alice's incoming session was dropped, or the session this packet
                    // was for was dropped by the application.
                    return Err(fault!(UnknownLocalKeyId, false));
                }
            }
        } else {
            let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
            let (packet_type, _c) = from_nonce(&nonce);
            log!(app, ReceivedRawFragment(packet_type, _c, fragment_no, fragment_count));

            //vrfy
            if packet_type != PACKET_TYPE_HANDSHAKE_HELLO && packet_type != PACKET_TYPE_CHALLENGE {
                return Err(fault!(InvalidPacket, true));
            }

            let mut buffer = ArrayVec::<u8, HANDSHAKE_HELLO_CHALLENGE_MAX_SIZE>::new();
            let assembled_packet = if fragment_count > 1 {
                let mut next_service_time = self.0.unassociated_defrag_cache.lock().unwrap().assemble(
                    &nonce,
                    remote_address,
                    incoming_fragment.len() - HEADER_SIZE,
                    incoming_fragment_buf,
                    fragment_no,
                    fragment_count,
                    app.time(),
                    &mut fragment_buffer,
                );
                if let Some(t) = next_service_time {
                    next_service_time = ctx.reduce_next_service_time(t);
                }
                if fragment_buffer.is_empty() {
                    return Ok((ReceiveOk::Unassociated, next_service_time));
                } else {
                    for fragment in fragment_buffer.as_ref() {
                        buffer
                            .try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..])
                            .map_err(|_| fault!(InvalidPacket, true))?;
                    }
                    buffer.as_mut()
                }
            } else {
                &mut incoming_fragment_buf.as_mut()[HEADER_SIZE..]
            };

            if packet_type == PACKET_TYPE_HANDSHAKE_HELLO {
                log!(app, ReceivedRawX1);

                if !(HANDSHAKE_HELLO_CHALLENGE_MIN_SIZE..=HANDSHAKE_HELLO_CHALLENGE_MAX_SIZE)
                    .contains(&assembled_packet.len())
                {
                    return Err(fault!(InvalidPacket, true));
                }
                // Process recv challenge layer.
                let challenge_start = assembled_packet.len() - CHALLENGE_SIZE;
                let hash = &mut Crypto::Hash::new();
                match app.incoming_session() {
                    IncomingSessionAction::Allow => {}
                    IncomingSessionAction::Challenge => {
                        let result = ctx.challenge.process_hello(
                            hash,
                            remote_address,
                            (&assembled_packet[challenge_start..]).try_into().unwrap(),
                        );
                        if let Err(challenge) = result {
                            log!(app, X1FailedChallengeSentNewChallenge);
                            let mut challenge_packet = ArrayVec::<u8, HEADERED_CHALLENGE_SIZE>::new();
                            challenge_packet.extend([0u8; HEADER_SIZE]);
                            challenge_packet
                                .try_extend_from_slice(&assembled_packet[..KID_SIZE])
                                .unwrap();
                            challenge_packet.extend(challenge);
                            let nonce = to_nonce(PACKET_TYPE_CHALLENGE, ctx.rng.lock().unwrap().next_u64());
                            challenge_packet[FRAGMENT_COUNT_IDX] = 1;
                            challenge_packet[PACKET_NONCE_START..HEADER_SIZE]
                                .copy_from_slice(&nonce[..PACKET_NONCE_SIZE]);
                            set_header(&mut challenge_packet, 0, &nonce);

                            send_unassociated_reply.send_frag(&mut challenge_packet);
                            // If we issue a challenge the first hello packet will always fail.
                            return Err(fault!(FailedAuth, false));
                        } else {
                            log!(app, X1SucceededChallenge);
                        }
                    }
                    IncomingSessionAction::Drop => return Err(ReceiveError::Rejected),
                }

                // Process recv zeta layer.
                let reduced = received_x1_trans(
                    &mut app,
                    ctx,
                    hash,
                    &nonce,
                    &mut assembled_packet[..challenge_start],
                    |packet, hk_send| {
                        send_with_fragmentation(send_unassociated_reply, send_unassociated_mtu, packet, hk_send);
                    },
                )?;
                log!(app, X1IsAuthSentX2);

                Ok((ReceiveOk::Unassociated, reduced))
            } else if packet_type == PACKET_TYPE_CHALLENGE {
                log!(app, ReceivedRawChallenge);
                // Process recv challenge layer.
                if assembled_packet.len() != KID_SIZE + CHALLENGE_SIZE {
                    return Err(fault!(InvalidPacket, true));
                }
                if let Some(kid_recv) =
                    NonZeroU32::new(u32::from_ne_bytes(assembled_packet[..KID_SIZE].try_into().unwrap()))
                {
                    if let Some(Some(session)) = ctx.session_map.read().unwrap().get(&kid_recv).map(|r| r.upgrade()) {
                        respond_to_challenge(ctx, &session, &assembled_packet[KID_SIZE..].try_into().unwrap());
                        log!(app, ChallengeIsAuth(&session));
                        return Ok((ReceiveOk::Unassociated, None));
                    }
                }
                Err(fault!(UnknownLocalKeyId, true))
            } else {
                Err(fault!(InvalidPacket, true))
            }
        }
    }
    /// Encrypt and send data over the session.
    ///
    /// If this function returns `Ok(true)`, if you are using the function `Context::service_scheduled`,
    /// then it should be called as soon as possible. If you are using `Context::service` instead,
    /// then this returned boolean can safely be ignored.
    ///
    /// * `session` - The session to send to
    /// * `send` - Function to call to send physical packet(s); the buffer passed to `send` is a
    ///   slice of `data`
    /// * `mtu_sized_buffer` - A writable work buffer whose size equals the MTU
    /// * `data` - Data to send
    pub fn send(
        &self,
        session: &Session<Crypto>,
        send: impl Sender,
        mtu_sized_buffer: &mut [u8],
        data: &[u8],
    ) -> Result<bool, SendError> {
        send_payload(&self.0, session, data, send, mtu_sized_buffer)
    }
    /// Perform periodic background service and cleanup tasks.
    ///
    /// This returns the number of milliseconds until it should be called again. The caller should
    /// try to satisfy this but small variations in timing of up to +/- a second or two are not
    /// a problem.
    ///
    /// * `app` - Interface to application using ZSSP
    /// * `send_to` - Function to get a sender and an MTU to send something over an active session
    pub fn service<App: ApplicationLayer<Crypto>>(&self, mut app: App, mut send_to: impl SendTo<Crypto>) -> i64 {
        let current_time = app.time();
        let next_service_time = loop {
            match self.service_inner(&mut app, send_to, current_time) {
                Ok(ts) => break ts,
                Err((_, s)) => send_to = s,
            }
        };
        let max_interval = Crypto::SETTINGS
            .fragment_assembly_timeout
            .min(Crypto::SETTINGS.rekey_timeout)
            .min(Crypto::SETTINGS.initial_offer_timeout);

        (next_service_time - current_time).min(max_interval as i64)
    }
    /// Perform periodic background service and cleanup tasks.
    ///
    /// This returns exact timestamp at which this function should be called again, or `i64::MAX` if
    /// there is currently no reason to call this again. However, future calls to `Context::open`
    /// and `Context::receive` can and will change this timestamp. Both of these functions return
    /// an `Option<i64>`. This option can contain an updated, reduced timestamp at which this
    /// function ought to be called again.
    ///
    /// If this returns an error then it means that a session has timed-out and has been expired.
    /// An expired session is no longer "owned" by the ZSSP context.
    /// Therefore it is no longer capable of sending, receiving or being serviced,
    /// so it should be dropped.
    ///
    /// A return type of `Err` effectively means that this function should be called again immediately.
    /// This function should be called repeatedly in a loop until `Ok` is returned.
    ///
    /// This function should only be used if the caller has direct access to a scheduler that allows
    /// them to dynamically modify the interval at which this function is repeatedly called.
    ///
    /// * `app` - Interface to application using ZSSP
    /// * `send_to` - Function to get a sender and an MTU to send something over an active session
    pub fn service_scheduled<App: ApplicationLayer<Crypto>>(
        &self,
        mut app: App,
        send_to: impl SendTo<Crypto>,
    ) -> Result<i64, ExpiredError<Crypto>> {
        let current_time = app.time();
        self.service_inner(&mut app, send_to, current_time).map_err(|e| e.0)
    }
    fn service_inner<App: ApplicationLayer<Crypto>, F: SendTo<Crypto>>(
        &self,
        app: &mut App,
        mut send_to: F,
        current_time: i64,
    ) -> Result<i64, (ExpiredError<Crypto>, F)> {
        let ctx = &self.0;
        let mut session_queue = ctx.session_queue.lock().unwrap();
        let mut queue_service_time = i64::MAX;
        // This update system takes advantage of the fact that sessions only need to be updated
        // either roughly every second or roughly every hour. That big gap allows for minor optimizations.
        // If the gap changes (unlikely) this code may need to be rewritten.
        while let Some((session, Reverse(timer), queue_idx)) = session_queue.peek() {
            if *timer > current_time {
                queue_service_time = queue_service_time.min(*timer);
                break;
            }
            let session = match session.upgrade() {
                Some(s) => s,
                None => {
                    session_queue.remove(queue_idx);
                    continue;
                }
            };
            let result = process_timers(app, ctx, &session, current_time, |packet, hk_send| {
                if let Some((sender, mut mtu)) = send_to.init_send(&session) {
                    mtu = mtu.max(MIN_TRANSPORT_MTU);
                    send_with_fragmentation(sender, mtu, packet, hk_send);
                }
            });
            if let Ok(next_timer) = result {
                queue_service_time = queue_service_time.min(next_timer);
                session_queue.change_priority(queue_idx, Reverse(next_timer));
            } else {
                session.expire_inner(Some(ctx), Some(&mut session_queue));
                return Err((ExpiredError(session), send_to));
            }
        }
        // This is the only place where `ctx.next_service_time` can be increased. This only works
        // correctly because we are holding the `session_queue` lock and we are guaranteed to run
        // the service code for the other two systems which are not currently locked.
        // The code above should not update `ctx.next_service_time`.
        ctx.next_service_time.store(queue_service_time, Ordering::Relaxed);
        drop(session_queue);

        let defrag_service_time = self
            .0
            .unassociated_defrag_cache
            .lock()
            .unwrap()
            .check_for_expiry(current_time);
        let handshake_service_time = self.0.unassociated_handshake_states.service(current_time);

        let t2 = defrag_service_time.min(handshake_service_time);
        let t1 = ctx.next_service_time.fetch_min(t2, Ordering::Relaxed);

        Ok(t1.min(t2))
    }
    /// Returns the exact timestamp at which either `Context::service` or
    /// `Context::service_scheduled` should be called again.
    ///
    /// This can return `i64::MAX` if there is *currently* nothing to service,
    /// or `i64::MIN` if `Context::send` returns `Ok(true)` and ZSSP needs to be serviced right away.
    pub fn next_service_time(&self) -> i64 {
        self.0.next_service_time.load(Ordering::Relaxed)
    }
}
