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
use std::io::Write;
use std::num::NonZeroU32;
use std::sync::{Arc, Mutex, RwLock, Weak};

use arrayvec::ArrayVec;
use rand_core::RngCore;

use crate::challenge::ChallengeContext;
use crate::crypto::*;
use crate::zeta::*;

use crate::application::*;
use crate::frag_cache::UnassociatedFragCache;
use crate::fragged::Assembled;
use crate::handshake_cache::UnassociatedHandshakeCache;
use crate::indexed_heap::IndexedBinaryHeap;
use crate::proto::*;
use crate::result::{byzantine_fault, FaultType, OpenError, ReceiveError, ReceiveOk, SendError, SessionEvent};
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

fn parse_fragment_header<StorageError>(
    incoming_fragment: &[u8],
) -> Result<(usize, usize, [u8; AES_GCM_NONCE_SIZE]), ReceiveError<StorageError>> {
    let fragment_no = incoming_fragment[FRAGMENT_NO_IDX] as usize;
    let fragment_count = incoming_fragment[FRAGMENT_COUNT_IDX] as usize;
    if fragment_no >= fragment_count || fragment_count > MAX_FRAGMENTS {
        return Err(byzantine_fault!(FaultType::InvalidPacket, true));
    }
    let mut nonce = [0u8; AES_GCM_NONCE_SIZE];
    nonce[2..].copy_from_slice(&incoming_fragment[PACKET_NONCE_START..HEADER_SIZE]);
    Ok((fragment_no, fragment_count, nonce))
}

/// Fragments and sends the packet, destroying it in the process.
///
/// Corresponds to the fragmentation algorithm described in Section 6.
fn send_with_fragmentation<PrpEnc: Aes256Enc>(
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
        send: impl FnMut(&mut [u8]) -> bool,
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
            },
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
        app: App,
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
                let state = session.state.read().unwrap();
                state.hk_recv.decrypt_in_place(
                    (&mut incoming_fragment[HEADER_AUTH_START..HEADER_AUTH_END])
                        .try_into()
                        .unwrap(),
                );

                let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
                let (packet_type, incoming_counter) = from_nonce(&nonce);
                if packet_type != PACKET_TYPE_DATA {
                    log!(
                        app,
                        ReceivedRawFragment(packet_type, incoming_counter, fragment_no, fragment_count)
                    );
                }

                {
                    //vrfy
                    if packet_type == PACKET_TYPE_HANDSHAKE_RESPONSE {
                        if !matches!(&state.beta, ZetaAutomata::A1(_)) {
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

                    receive_payload_in_place(&session, state, kid_recv, &nonce, fragments, output_buffer)?;

                    SessionEvent::Data
                } else {
                    drop(state);
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
                                buffer
                                    .try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..])
                                    .map_err(|_| byzantine_fault!(InvalidPacket, true))?;
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
                                &app,
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
                            let result = received_c1_trans(
                                &app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, KeyConfirmIsAuthSentAck(&session));
                            if result {
                                SessionEvent::Established
                            } else {
                                SessionEvent::Control
                            }
                        }
                        PACKET_TYPE_ACK => {
                            log!(app, ReceivedRawAck);
                            received_c2_trans(&app, ctx, &session, kid_recv, &nonce, assembled_packet)?;
                            log!(app, AckIsAuth(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_REKEY_INIT => {
                            log!(app, ReceivedRawK1);
                            received_k1_trans(
                                &app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, K1IsAuthSentK2(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_REKEY_COMPLETE => {
                            log!(app, ReceivedRawK2);
                            received_k2_trans(
                                &app,
                                ctx,
                                &session,
                                kid_recv,
                                &nonce,
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, K2IsAuthSentKeyConfirm(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_SESSION_REJECTED => {
                            log!(app, ReceivedRawD);
                            received_d_trans(&session, kid_recv, &nonce, assembled_packet)?;
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
                    log!(
                        app,
                        ReceivedRawFragment(packet_type, incoming_counter, fragment_no, fragment_count)
                    );

                    {
                        //vrfy
                        if packet_type != PACKET_TYPE_HANDSHAKE_COMPLETION || incoming_counter != 0 {
                            return Err(byzantine_fault!(InvalidPacket, true));
                        }
                    }

                    let mut buffer = ArrayVec::<u8, HANDSHAKE_COMPLETION_MAX_SIZE>::new();
                    let assembled_packet = if fragment_count > 1 {
                        zeta.defrag.lock().unwrap().assemble(
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
                                buffer
                                    .try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..])
                                    .map_err(|_| byzantine_fault!(InvalidPacket, true))?;
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
                    let session = received_x3_trans(&app, ctx, zeta, kid_recv, assembled_packet, |packet, hk_send| {
                        send_with_fragmentation(send_unassociated_reply, send_unassociated_mtu, packet, hk_send);
                    })?;
                    log!(app, X3IsAuthSentKeyConfirm(&session));
                    Ok(ReceiveOk::Session(session, SessionEvent::NewSession))
                } else {
                    // This can occur naturally because either Bob's incoming_sessions cache got
                    // full so Alice's incoming session was dropped, or the session this packet
                    // was for was dropped by the application.
                    return Err(byzantine_fault!(UnknownLocalKeyId, false));
                }
            }
        } else {
            let (fragment_no, fragment_count, nonce) = parse_fragment_header(incoming_fragment)?;
            let (packet_type, _c) = from_nonce(&nonce);
            log!(app, ReceivedRawFragment(packet_type, _c, fragment_no, fragment_count));

            {
                //vrfy
                if packet_type != PACKET_TYPE_HANDSHAKE_HELLO && packet_type != PACKET_TYPE_CHALLENGE {
                    return Err(byzantine_fault!(InvalidPacket, true));
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
                    &mut fragment_buffer,
                );
                if fragment_buffer.is_empty() {
                    return Ok(ReceiveOk::Unassociated);
                } else {
                    for fragment in fragment_buffer.as_ref() {
                        buffer
                            .try_extend_from_slice(&fragment.as_ref()[HEADER_SIZE..])
                            .map_err(|_| byzantine_fault!(InvalidPacket, true))?;
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
                    return Err(byzantine_fault!(InvalidPacket, true));
                }
                // Process recv challenge layer.
                let challenge_start = assembled_packet.len() - CHALLENGE_SIZE;
                let hash = &mut App::Hash::new();
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
                            challenge_packet[PACKET_NONCE_START..HEADER_SIZE].copy_from_slice(&nonce);

                            send_unassociated_reply(&mut challenge_packet);
                            // If we issue a challenge the first hello packet will always fail.
                            return Err(byzantine_fault!(FailedAuth, false));
                        } else {
                            log!(app, X1SucceededChallenge);
                        }
                    }
                    IncomingSessionAction::Drop => return Err(ReceiveError::Rejected),
                }

                // Process recv zeta layer.
                received_x1_trans(
                    &app,
                    ctx,
                    hash,
                    &nonce,
                    &mut assembled_packet[..challenge_start],
                    |packet, hk_send| {
                        send_with_fragmentation(send_unassociated_reply, send_unassociated_mtu, packet, hk_send);
                    },
                )?;
                log!(app, X1IsAuthSentX2);

                Ok(ReceiveOk::Unassociated)
            } else if packet_type == PACKET_TYPE_CHALLENGE {
                log!(app, ReceivedRawChallenge);
                // Process recv challenge layer.
                if assembled_packet.len() != KID_SIZE + CHALLENGE_SIZE {
                    return Err(byzantine_fault!(InvalidPacket, true));
                }
                if let Some(kid_recv) =
                    NonZeroU32::new(u32::from_be_bytes(assembled_packet[..KID_SIZE].try_into().unwrap()))
                {
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
        send: impl FnMut(&[u8]) -> bool,
        mtu_sized_buffer: &mut [u8],
        data: &[u8],
    ) -> Result<(), SendError> {
        send_payload(&self.0, session, data, send, mtu_sized_buffer)
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
        app: App,
        mut send_to: impl FnMut(&Arc<Session<App>>) -> Option<(SendFn, usize)>,
    ) -> i64 {
        let ctx = &self.0;
        let mut session_queue = ctx.session_queue.lock().unwrap();
        let current_time = app.time();
        let mut next_service_time = current_time + App::SETTINGS.fragment_assembly_timeout as i64;
        // This update system takes heavy advantage of the fact that sessions only need to be updated
        // either roughly every second or roughly every hour. That big gap allows for minor optimizations.
        // If the gap changes (unlikely) this code may need to be rewritten.
        while let Some((session, Reverse(timer), queue_idx)) = session_queue.peek() {
            if *timer >= current_time {
                next_service_time = next_service_time.min(*timer);
                break;
            }
            let session = match session.upgrade() {
                Some(s) => s,
                _ => {
                    session_queue.remove(queue_idx);
                    continue;
                }
            };
            let result = process_timers(&app, ctx, &session, current_time, |packet, hk_send| {
                if let Some((send_fragment, mut mtu)) = send_to(&session) {
                    mtu = mtu.max(MIN_TRANSPORT_MTU);
                    send_with_fragmentation(send_fragment, mtu, packet, hk_send);
                }
            });
            if let Some(next_timer) = result {
                next_service_time = next_service_time.min(next_timer);
                session_queue.change_priority(queue_idx, Reverse(next_timer));
            } else {
                session.expire_inner(Some(ctx), Some(&mut session_queue));
            }
        }
        drop(session_queue);

        self.0
            .unassociated_defrag_cache
            .lock()
            .unwrap()
            .check_for_expiry(App::SETTINGS.fragment_assembly_timeout as i64, current_time);
        self.0.unassociated_handshake_states.service(current_time);

        next_service_time - current_time
    }
}
