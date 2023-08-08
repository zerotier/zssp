use rand_core::RngCore;
use std::cell::RefCell;
use std::collections::hash_map::Entry;
use std::collections::HashMap;
use std::hash::Hash;
use std::num::NonZeroU32;
use std::sync::{Arc, Weak};

use crate::application::ApplicationLayer;
use crate::challenge::ChallengeContext;
use crate::crypto::{AES_256_KEY_SIZE, AES_GCM_NONCE_SIZE};
use crate::fragmentation::{send_with_fragmentation, DefragBuffer};
use crate::proto::*;
use crate::result::{byzantine_fault, OpenError, ReceiveError, ReceiveOk, SendError, SessionEvent};
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
pub struct Context<App: ApplicationLayer>(Arc<ContextInner<App>>);
impl<App: ApplicationLayer> Clone for Context<App> {
    fn clone(&self) -> Self {
        Self(self.0.clone())
    }
}

pub(crate) type SessionMap<App> = RefCell<HashMap<NonZeroU32, Weak<Session<App>>>>;

pub(crate) struct ContextInner<App: ApplicationLayer> {
    pub(crate) rng: RefCell<App::Rng>,
    pub(crate) s_secret: App::KeyPair,
    pub(crate) session_map: SessionMap<App>,
    pub(crate) sessions: RefCell<HashMap<*const Session<App>, Weak<Session<App>>>>,
    pub(crate) b2_map: RefCell<HashMap<NonZeroU32, StateB2<App>>>,

    hello_defrag: RefCell<DefragBuffer>,
    challenge: RefCell<ChallengeContext>,
}

/// Corresponds to Figure 10 found in Section 4.3.
fn to_aes_nonce(pn: &[u8; PACKET_NONCE_SIZE]) -> [u8; AES_GCM_NONCE_SIZE] {
    let mut an = [0u8; AES_GCM_NONCE_SIZE];
    an[2..].copy_from_slice(pn);
    an
}
/// Corresponds to Figure 14 found near Section 6.
fn to_packet_nonce(n: &[u8; AES_GCM_NONCE_SIZE]) -> &[u8; PACKET_NONCE_SIZE] {
    (&n[n.len() - PACKET_NONCE_SIZE..]).try_into().unwrap()
}

impl<App: ApplicationLayer> Context<App> {
    /// Create a new session context.
    pub fn new(static_secret_key: App::KeyPair, mut rng: App::Rng) -> Self {
        let challenge = ChallengeContext::new(&mut rng);
        Self(Arc::new(ContextInner {
            rng: RefCell::new(rng),
            s_secret: static_secret_key,
            session_map: RefCell::new(HashMap::new()),
            b2_map: RefCell::new(HashMap::new()),
            hello_defrag: RefCell::new(DefragBuffer::new(None)),
            challenge: RefCell::new(challenge),
            sessions: RefCell::new(HashMap::new()),
        }))
    }
    /// Enable the ZeroTier Challenge Protocol, to protect this machine from CPU exhaustion DDOS
    /// attacks.
    pub fn enable_challenge(&mut self, enabled: bool) {
        self.0.challenge.borrow_mut().enabled = enabled;
    }

    /// Create a new session and send initial packet(s) to other side.
    ///
    /// * `app` - Application layer instance
    /// * `send` - Function to be called to send one or more initial packets to the remote being
    ///   contacted
    /// * `mtu` - MTU for initial packets
    /// * `static_remote_key` - Remote side's static public NIST P-384 key
    /// * `session_data` - Arbitrary data meaningful to the application to include with session
    ///   object
    /// * `identity` - Payload to be sent to Bob that contains the information necessary
    ///   for the upper protocol to authenticate and approve of Alice's identity
    pub fn open(
        &mut self,
        app: App,
        send: impl FnMut(Vec<u8>) -> bool,
        mut mtu: usize,
        static_remote_key: App::PublicKey,
        session_data: App::SessionData,
        identity: Vec<u8>,
    ) -> Result<Arc<Session<App>>, OpenError<App::StorageError>> {
        mtu = mtu.max(MIN_TRANSPORT_MTU);
        if identity.len() > IDENTITY_MAX_SIZE {
            return Err(OpenError::IdentityTooLarge);
        }
        let ctx = &self.0;

        // Process zeta layer.
        trans_to_a1(
            app,
            &ctx,
            static_remote_key,
            session_data,
            identity,
            |Packet(kid, nonce, payload): &Packet| {
                // Process fragmentation layer.
                send_with_fragmentation::<App>(send, mtu, *kid, to_packet_nonce(&nonce), payload, None);
            },
        )
    }

    /// Receive, authenticate, decrypt, and process a physical wire packet.
    ///
    /// * `app` - Interface to application using ZSSP
    /// * `send_unassociated_reply` - Function to send reply packets directly when no session exists
    /// * `send_unassociated_mtu` - MTU for unassociated replies
    /// * `send_to` - Function to get senders for existing sessions, permitting MTU and path lookup
    /// * `remote_address` - Whatever the remote address is, as long as you can Hash it
    /// * `raw_fragment` - Buffer containing incoming wire packet
    pub fn receive<'a, SendFn: FnMut(Vec<u8>) -> bool>(
        &mut self,
        app: App,
        send_unassociated_reply: impl FnMut(Vec<u8>) -> bool,
        mut send_unassociated_mtu: usize,
        send_to: impl FnOnce(&Arc<Session<App>>) -> Option<(SendFn, usize)>,
        remote_address: &impl Hash,
        raw_fragment: Vec<u8>,
    ) -> Result<ReceiveOk<App>, ReceiveError<App::StorageError>> {
        use crate::result::FaultType::*;
        send_unassociated_mtu = send_unassociated_mtu.max(MIN_TRANSPORT_MTU);
        let ctx = &self.0;

        // Multiplex session.
        let kid_recv = u32::from_be_bytes(raw_fragment[..KID_SIZE].try_into().unwrap());
        if let Some(kid_recv) = NonZeroU32::new(kid_recv) {
            let session = ctx.session_map.borrow_mut().get(&kid_recv).map(|r| r.upgrade());
            if let Some(Some(session)) = session {
                // Process recv fragmentation layer.
                let mut zeta = session.0.borrow_mut();
                let result =
                    zeta.defrag
                        .received_fragment::<App>(raw_fragment, app.time(), |n, frag_no, frag_count| {
                            let (p, c) = from_nonce(n);
                            if p != PACKET_TYPE_DATA {
                                log!(app, ReceivedRawFragment(p, c, frag_no, frag_count));
                            }
                            if p == PACKET_TYPE_HANDSHAKE_RESPONSE {
                                if !matches!(&zeta.beta, ZetaAutomata::A1(_)) {
                                    // A resent handshake response from Bob may have arrived out of order,
                                    // after we already received one.
                                    return Err(byzantine_fault!(OutOfSequence, false));
                                }
                                if c >= COUNTER_WINDOW_MAX_SKIP_AHEAD {
                                    return Err(byzantine_fault!(ExpiredCounter, true));
                                }
                                Ok(())
                            } else if PACKET_TYPE_USES_COUNTER_RANGE.contains(&p) {
                                if !zeta.check_counter_window(c) {
                                    // The counter window has finite memory and so will occasionally give
                                    // false positives on very out-of-order packets.
                                    return Err(byzantine_fault!(ExpiredCounter, false));
                                }
                                Ok(())
                            } else if p == PACKET_TYPE_HANDSHAKE_COMPLETION {
                                // The handshake completion packet could have been resent.
                                return Err(byzantine_fault!(InvalidPacket, false));
                            } else {
                                return Err(byzantine_fault!(InvalidPacket, true));
                            }
                        })?;
                if let Some((pn, mut assembled_packet)) = result {
                    // Process recv zeta layer.
                    let send_associated =
                        |Packet(kid, nonce, payload): &Packet, hk: Option<&[u8; AES_256_KEY_SIZE]>| {
                            if let Some((send_fragment, mut mtu)) = send_to(&session) {
                                mtu = mtu.max(MIN_TRANSPORT_MTU);
                                send_with_fragmentation::<App>(
                                    send_fragment,
                                    mtu,
                                    *kid,
                                    to_packet_nonce(&nonce),
                                    payload,
                                    hk,
                                );
                            }
                        };

                    let (p, _) = from_nonce(&pn);
                    let ret = match p {
                        PACKET_TYPE_DATA => {
                            received_payload_in_place(&mut zeta, kid_recv, to_aes_nonce(&pn), &mut assembled_packet)?;
                            SessionEvent::Data(assembled_packet)
                        }
                        PACKET_TYPE_HANDSHAKE_RESPONSE => {
                            log!(app, ReceivedRawX2);
                            let should_warn_missing_ratchet = received_x2_trans(
                                &mut zeta,
                                &session,
                                &app,
                                &ctx,
                                kid_recv,
                                to_aes_nonce(&pn),
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, X2IsAuthSentX3(&session));
                            if should_warn_missing_ratchet {
                                SessionEvent::DowngradedRatchetKey
                            } else {
                                SessionEvent::Control
                            }
                        }
                        PACKET_TYPE_KEY_CONFIRM => {
                            log!(app, ReceivedRawKeyConfirm);
                            let result = received_c1_trans(
                                &mut zeta,
                                &app,
                                &ctx.rng,
                                kid_recv,
                                to_aes_nonce(&pn),
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
                            received_c2_trans(
                                &mut zeta,
                                &app,
                                &ctx.rng,
                                kid_recv,
                                to_aes_nonce(&pn),
                                assembled_packet,
                            )?;
                            log!(app, AckIsAuth(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_REKEY_INIT => {
                            log!(app, ReceivedRawK1);
                            received_k1_trans(
                                &mut zeta,
                                &session,
                                &app,
                                &ctx.rng,
                                &ctx.session_map,
                                &ctx.s_secret,
                                kid_recv,
                                to_aes_nonce(&pn),
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, K1IsAuthSentK2(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_REKEY_COMPLETE => {
                            log!(app, ReceivedRawK2);
                            received_k2_trans(
                                &mut zeta,
                                &app,
                                kid_recv,
                                to_aes_nonce(&pn),
                                assembled_packet,
                                send_associated,
                            )?;
                            log!(app, K2IsAuthSentKeyConfirm(&session));
                            SessionEvent::Control
                        }
                        PACKET_TYPE_SESSION_REJECTED => {
                            log!(app, ReceivedRawD);
                            received_d_trans(&mut zeta, kid_recv, to_aes_nonce(&pn), assembled_packet)?;
                            log!(app, DIsAuthClosedSession(&session));
                            SessionEvent::Rejected
                        }
                        _ => return Err(byzantine_fault!(InvalidPacket, true)), // This is unreachable.
                    };
                    drop(zeta);
                    Ok(ReceiveOk::Session(session, ret))
                } else {
                    Ok(ReceiveOk::Unassociated)
                }
            } else {
                let mut b2_map = ctx.b2_map.borrow_mut();
                if let Entry::Occupied(mut entry) = b2_map.entry(kid_recv) {
                    let zeta = entry.get_mut();
                    // Process recv fragmentation layer.
                    let result =
                        zeta.defrag
                            .received_fragment::<App>(raw_fragment, app.time(), |n, frag_no, frag_count| {
                                let (p, c) = from_nonce(n);
                                log!(app, ReceivedRawFragment(p, c, frag_no, frag_count));
                                if p == PACKET_TYPE_HANDSHAKE_COMPLETION && c == 0 {
                                    Ok(())
                                } else {
                                    Err(byzantine_fault!(InvalidPacket, true))
                                }
                            })?;
                    if let Some((_, assembled_packet)) = result {
                        log!(app, ReceivedRawX3);
                        let zeta = entry.remove();
                        let (session, should_warn_missing_ratchet) = received_x3_trans(
                            zeta,
                            &app,
                            ctx,
                            kid_recv,
                            assembled_packet,
                            |Packet(kid, nonce, payload), hk| {
                                send_with_fragmentation::<App>(
                                    send_unassociated_reply,
                                    send_unassociated_mtu,
                                    *kid,
                                    to_packet_nonce(&nonce),
                                    payload,
                                    hk,
                                );
                            },
                        )?;
                        log!(app, X3IsAuthSentKeyConfirm(&session));
                        Ok(ReceiveOk::Session(session, if should_warn_missing_ratchet {
                            SessionEvent::NewDowngradedSession
                        } else {
                            SessionEvent::NewSession
                        }))
                    } else {
                        Ok(ReceiveOk::Unassociated)
                    }
                } else {
                    // When sessions are added or dropped or packets arrive extremely delayed it is
                    // possible to receive no longer recognized key ids.
                    Err(byzantine_fault!(UnknownLocalKeyId, false))
                }
            }
        } else {
            // Process recv fragmentation layer.
            let result = ctx.hello_defrag.borrow_mut().received_fragment::<App>(
                raw_fragment,
                app.time(),
                |n, frag_no, frag_count| {
                    let (p, c) = from_nonce(n);
                    log!(app, ReceivedRawFragment(p, c, frag_no, frag_count));
                    if p == PACKET_TYPE_HANDSHAKE_HELLO || p == PACKET_TYPE_CHALLENGE {
                        Ok(())
                    } else {
                        Err(byzantine_fault!(InvalidPacket, true))
                    }
                },
            )?;
            if let Some((n, mut assembled_packet)) = result {
                let (p, _) = from_nonce(&n);
                if p == PACKET_TYPE_HANDSHAKE_HELLO {
                    log!(app, ReceivedRawX1);
                    // Process recv challenge layer.
                    let challenge_start = assembled_packet.len() - CHALLENGE_SIZE;
                    let result = ctx.challenge.borrow_mut().process_hello::<App::Hash>(
                        remote_address,
                        (&assembled_packet[challenge_start..]).try_into().unwrap(),
                    );
                    if let Err(challenge) = result {
                        log!(app, X1FailedChallengeSentNewChallenge);
                        let mut challenge_packet = Vec::new();
                        challenge_packet.extend(&assembled_packet[..KID_SIZE]);
                        challenge_packet.extend(&challenge);
                        let nonce = to_nonce(PACKET_TYPE_CHALLENGE, ctx.rng.borrow_mut().next_u64());
                        send_with_fragmentation::<App>(
                            send_unassociated_reply,
                            send_unassociated_mtu,
                            0,
                            to_packet_nonce(&nonce),
                            &challenge_packet,
                            None,
                        );
                        // If we issue a challenge the first hello packet will always fail.
                        return Err(byzantine_fault!(FailedAuth, false));
                    } else if let Ok(true) = result {
                        log!(app, X1SucceededChallenge);
                    }
                    assembled_packet.truncate(challenge_start);

                    // Process recv zeta layer.
                    received_x1_trans(
                        &app,
                        &ctx,
                        to_aes_nonce(&n),
                        assembled_packet,
                        |Packet(kid, nonce, payload), hk| {
                            send_with_fragmentation::<App>(
                                send_unassociated_reply,
                                send_unassociated_mtu,
                                *kid,
                                to_packet_nonce(&nonce),
                                payload,
                                Some(hk),
                            );
                        },
                    )?;
                    log!(app, X1IsAuthSentX2);
                    Ok(ReceiveOk::Unassociated)
                } else if p == PACKET_TYPE_CHALLENGE {
                    log!(app, ReceivedRawChallenge);
                    // Process recv challenge layer.
                    if assembled_packet.len() != KID_SIZE + CHALLENGE_SIZE {
                        return Err(byzantine_fault!(InvalidPacket, true));
                    }
                    if let Some(kid_recv) =
                        NonZeroU32::new(u32::from_be_bytes(assembled_packet[..KID_SIZE].try_into().unwrap()))
                    {
                        if let Some(Some(session)) = ctx.session_map.borrow_mut().get(&kid_recv).map(|r| r.upgrade()) {
                            let mut zeta = session.0.borrow_mut();
                            respond_to_challenge(
                                &mut zeta,
                                &ctx.rng,
                                &assembled_packet[KID_SIZE..].try_into().unwrap(),
                            );
                            log!(app, ChallengeIsAuth(&session));
                            return Ok(ReceiveOk::Unassociated);
                        }
                    }
                    Err(byzantine_fault!(UnknownLocalKeyId, true))
                } else {
                    Err(byzantine_fault!(InvalidPacket, true))
                }
            } else {
                Ok(ReceiveOk::Unassociated)
            }
        }
    }

    /// Send data over the session.
    ///
    /// * `session` - The session to send to
    /// * `send` - Function to call to send physical packet(s); the buffer passed to `send` is a
    ///   slice of `data`
    /// * `mtu` - The MTU of the link, all packets passed to `send` will be at most `mtu` in length
    /// * `payload` - Data to send
    pub fn send(
        &mut self,
        session: &Arc<Session<App>>,
        send: impl FnMut(Vec<u8>) -> bool,
        mut mtu: usize,
        payload: Vec<u8>,
    ) -> Result<(), SendError> {
        mtu = mtu.max(MIN_TRANSPORT_MTU);
        let mut zeta = session.0.borrow_mut();
        send_payload(&mut zeta, payload, |Packet(kid, nonce, payload), hk| {
            send_with_fragmentation::<App>(send, mtu, *kid, to_packet_nonce(nonce), &payload, hk);
        })
    }

    /// Perform periodic background service and cleanup tasks.
    ///
    /// This returns the number of milliseconds until it should be called again. The caller should
    /// try to satisfy this but small variations in timing of up to a few seconds are not
    /// a problem.
    ///
    /// * `send_to` - Function to get a sender and an MTU to send something over an active session
    pub fn service<SendFn: FnMut(Vec<u8>) -> bool>(
        &mut self,
        app: App,
        mut send_to: impl FnMut(&Arc<Session<App>>) -> Option<(SendFn, usize)>,
    ) -> i64 {
        let ctx = &self.0;
        let sessions = ctx.sessions.borrow_mut();
        let current_time = app.time();
        let mut next_timer = i64::MAX;
        for (_, session) in sessions.iter() {
            if let Some(session) = session.upgrade() {
                let mut zeta = session.0.borrow_mut();
                service(
                    &mut zeta,
                    &session,
                    ctx,
                    &app,
                    current_time,
                    |Packet(kid, nonce, payload): &Packet, hk| {
                        if let Some((send_fragment, mut mtu)) = send_to(&session) {
                            mtu = mtu.max(MIN_TRANSPORT_MTU);
                            send_with_fragmentation::<App>(
                                send_fragment,
                                mtu,
                                *kid,
                                to_packet_nonce(&nonce),
                                payload,
                                hk,
                            );
                        }
                    },
                );
                next_timer = next_timer.min(zeta.next_timer());
                zeta.defrag.service::<App>(current_time);
            }
        }
        ctx.hello_defrag.borrow_mut().service::<App>(current_time);
        (App::SETTINGS.resend_time as i64).min(next_timer - current_time)
    }
}
