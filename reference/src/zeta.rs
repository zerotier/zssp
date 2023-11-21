use std::cell::RefCell;
use std::collections::HashMap;
use std::num::NonZeroU32;
use std::ops::{Deref, DerefMut};
use std::sync::{Arc, Weak};

use rand_core::RngCore;
use zeroize::Zeroizing;

use crate::application::{ApplicationLayer, CryptoLayer, RatchetState, RatchetStates, RatchetUpdate};
use crate::challenge::{gen_null_response, respond_to_challenge_in_place};
use crate::context::{log, ContextInner, SessionMap};
use crate::crypto::*;
use crate::fragmentation::DefragBuffer;
use crate::proto::*;
use crate::result::{byzantine_fault, FaultType, OpenError, ReceiveError, SendError};
use crate::symmetric_state::SymmetricState;
#[cfg(feature = "logging")]
use crate::LogEvent::*;

/// Corresponds to the Zeta State Machine found in Section 4.1.
pub(crate) struct Zeta<C: CryptoLayer> {
    pub ctx: Weak<ContextInner<C>>,
    /// An arbitrary application defined object associated with each session.
    pub session_data: C::SessionData,
    /// Is true if the local peer acted as Bob, the responder in the initial key exchange.
    pub was_bob: bool,

    s_remote: C::PublicKey,
    send_counter: u64,
    key_creation_counter: u64,

    key_index: bool,
    keys: [DuplexKey; 2],
    ratchet_state1: RatchetState,
    ratchet_state2: Option<RatchetState>,
    pub hk_send: Zeroizing<[u8; AES_256_KEY_SIZE]>,

    resend_timer: i64,
    timeout_timer: i64,
    pub beta: ZetaAutomata<C>,

    pub counter_antireplay_window: [u64; COUNTER_WINDOW_MAX_OOO],
    pub defrag: DefragBuffer,
}
/// ZeroTier Secure Session Protocol (ZSSP) Session.
///
/// A FIPS/NIST compliant variant of Noise_XK with hybrid Kyber1024 PQ data forward secrecy.
pub struct Session<C: CryptoLayer>(pub(crate) RefCell<Zeta<C>>);

/// Corresponds to State B_2 of the Zeta State Machine found in Section 4.1 - Definition 3.
pub(crate) struct StateB2<C: CryptoLayer> {
    ratchet_state: RatchetState,
    kid_send: NonZeroU32,
    pub kid_recv: NonZeroU32,
    pub hk_send: Zeroizing<[u8; AES_256_KEY_SIZE]>,
    e_secret: C::KeyPair,
    noise: SymmetricState<C>,
    pub defrag: DefragBuffer,
}

#[derive(Default)]
pub(crate) struct DuplexKey {
    send: Keys,
    recv: Keys,
}

#[derive(Default)]
pub(crate) struct Keys {
    kek: Option<Zeroizing<[u8; AES_256_KEY_SIZE]>>,
    nk: Option<Zeroizing<[u8; AES_256_KEY_SIZE]>>,
    kid: Option<NonZeroU32>,
}

/// Corresponds to the tuple of values the Transition Algorithms send to the remote peer in Section 4.3.
#[derive(Clone)]
pub(crate) struct Packet(pub u32, pub [u8; AES_GCM_NONCE_SIZE], pub Vec<u8>);

/// Corresponds to State A_1 of the Zeta State Machine found in Section 4.1.
#[derive(Clone)]
pub(crate) struct StateA1<C: CryptoLayer> {
    noise: SymmetricState<C>,
    e_secret: C::KeyPair,
    e1_secret: C::Kem,
    identity: Vec<u8>,
    packet: Packet,
}

/// Corresponds to the ZKE Automata found in Section 4.1 - Definition 2.
pub(crate) enum ZetaAutomata<C: CryptoLayer> {
    Null,
    A1(StateA1<C>),
    A3 {
        identity: Vec<u8>,
        packet: Packet,
    },
    S1,
    S2,
    R1 {
        noise: SymmetricState<C>,
        e_secret: C::KeyPair,
        k1: Vec<u8>,
    },
    R2 {
        k2: Vec<u8>,
    },
}

impl<C: CryptoLayer> SymmetricState<C> {
    fn write_e(&mut self, rng: &RefCell<C::Rng>, packet: &mut Vec<u8>) -> C::KeyPair {
        let e_secret = C::KeyPair::generate(rng.borrow_mut().deref_mut());
        let pub_key = e_secret.public_key_bytes();
        packet.extend(&pub_key);
        self.mix_hash(&pub_key);
        self.mix_key(&pub_key);
        e_secret
    }
    fn read_e(&mut self, i: &mut usize, packet: &Vec<u8>) -> Option<C::PublicKey> {
        let j = *i + P384_PUBLIC_KEY_SIZE;
        let pub_key = &packet[*i..j];
        self.mix_hash(pub_key);
        self.mix_key(pub_key);
        *i = j;
        C::PublicKey::from_bytes((pub_key).try_into().unwrap())
    }
    fn mix_dh(&mut self, secret: &C::KeyPair, remote: &C::PublicKey) {
        let ecdh = Zeroizing::new(secret.agree(&remote));
        self.mix_key(ecdh.as_ref());
    }
}

/// Create a 96-bit AES-GCM nonce.
///
/// The primary information that we want to be contained here is the counter and the
/// packet type. The former makes this unique and the latter's inclusion authenticates
/// it as effectively AAD. Other elements of the header are either not authenticated,
/// like fragmentation info, or their authentication is implied via key exchange like
/// the key id.
///
/// Corresponds to Figure 10 found in Section 4.3.
pub(crate) fn to_nonce(packet_type: u8, counter: u64) -> [u8; AES_GCM_NONCE_SIZE] {
    let mut ret = [0u8; AES_GCM_NONCE_SIZE];
    ret[3] = packet_type;
    // Noise requires a big endian counter at the end of the Nonce
    ret[4..].copy_from_slice(&counter.to_be_bytes());
    ret
}
/// Corresponds to Figure 10 and Figure 14 found in Section 4.3.
pub(crate) fn from_nonce(n: &[u8]) -> (u8, u64) {
    assert!(n.len() >= PACKET_NONCE_SIZE);
    let c_start = n.len() - 8;
    (n[c_start - 1], u64::from_be_bytes(n[c_start..].try_into().unwrap()))
}
/// Generate a random local key id that is currently unused.
fn gen_kid<T>(session_map: &HashMap<NonZeroU32, T>, rng: &mut impl RngCore) -> NonZeroU32 {
    loop {
        if let Some(kid) = NonZeroU32::new(rng.next_u32()) {
            if !session_map.contains_key(&kid) {
                return kid;
            }
        }
    }
}
fn remap<C: CryptoLayer>(
    session: &Arc<Session<C>>,
    zeta: &Zeta<C>,
    rng: &RefCell<C::Rng>,
    session_map: &SessionMap<C>,
) -> NonZeroU32 {
    let mut session_map = session_map.borrow_mut();
    let weak = if let Some(Some(weak)) = zeta.key_ref(true).recv.kid.as_ref().map(|kid| session_map.remove(kid)) {
        weak
    } else {
        Arc::downgrade(&session)
    };
    let new_kid_recv = gen_kid(session_map.deref(), rng.borrow_mut().deref_mut());
    session_map.insert(new_kid_recv, weak);
    new_kid_recv
}

impl<C: CryptoLayer> Zeta<C> {
    pub(crate) fn check_counter_window(&self, c: u64) -> bool {
        let slot = &self.counter_antireplay_window[c as usize % self.counter_antireplay_window.len()];
        let adj_counter = c.saturating_add(1);
        *slot < adj_counter && adj_counter <= *slot + COUNTER_WINDOW_MAX_SKIP_AHEAD
    }
    /// Updating the counter window should be the last authentication step to ensure
    /// an attacker cannot intentionally waste a peer's counters on fake packets.
    pub(crate) fn update_counter_window(&mut self, c: u64) -> bool {
        let slot = &mut self.counter_antireplay_window[c as usize % self.counter_antireplay_window.len()];
        let adj_counter = c.saturating_add(1);
        if *slot < adj_counter && adj_counter <= *slot + COUNTER_WINDOW_MAX_SKIP_AHEAD {
            *slot = adj_counter;
            true
        } else {
            false
        }
    }
    fn key_ref(&self, is_next: bool) -> &DuplexKey {
        &self.keys[(self.key_index ^ is_next) as usize]
    }
    fn key_mut(&mut self, is_next: bool) -> &mut DuplexKey {
        &mut self.keys[(self.key_index ^ is_next) as usize]
    }
    fn expire(&mut self) {
        self.resend_timer = i64::MAX;
        self.timeout_timer = i64::MAX;
        self.beta = ZetaAutomata::Null;
        if let Some(ctx) = self.ctx.upgrade() {
            let mut session_map = ctx.session_map.borrow_mut();
            let mut sessions = ctx.sessions.borrow_mut();
            for key in &self.keys {
                if let Some(kid_recv) = key.recv.kid {
                    if let Some(weak) = session_map.remove(&kid_recv) {
                        sessions.remove(&weak.as_ptr());
                    }
                }
            }
        }
    }
    pub(crate) fn next_timer(&self) -> i64 {
        self.timeout_timer.min(self.resend_timer)
    }
    fn get_counter(&mut self) -> Option<(u64, bool)> {
        let c = self.send_counter;
        if c >= HARD_EXPIRATION {
            return None;
        }
        self.send_counter += 1;
        Some((
            c,
            c >= self
                .key_creation_counter
                .saturating_add(C::SETTINGS.rekey_after_key_uses),
        ))
    }
}

fn create_a1_state<C: CryptoLayer, App: ApplicationLayer<C>>(
    rng: &RefCell<C::Rng>,
    s_remote: &C::PublicKey,
    kid_recv: NonZeroU32,
    ratchet_state1: &RatchetState,
    ratchet_state2: Option<&RatchetState>,
    identity: Vec<u8>,
) -> StateA1<C> {
    //    <- s
    //    ...
    //    -> e, es, e1
    let mut noise = SymmetricState::<C>::initialize(PROTOCOL_NAME_NOISE_XK);
    let mut x1 = Vec::new();
    // Noise process prologue.
    let kid = kid_recv.get().to_be_bytes();
    x1.extend(&kid);
    noise.mix_hash(&kid);
    noise.mix_hash(&s_remote.to_bytes());
    // Process message pattern 1 e token.
    let e_secret = noise.write_e(rng, &mut x1);
    // Process message pattern 1 es token.
    noise.mix_dh(&e_secret, s_remote);
    // Process message pattern 1 e1 token.
    let i = x1.len();
    let (e1_secret, e1_public) = C::Kem::generate(rng.borrow_mut().deref_mut());
    x1.extend(&e1_public);
    noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 0), i, &mut x1);
    // Process message pattern 1 payload.
    let i = x1.len();
    if let Some(rf) = ratchet_state1.fingerprint() {
        x1.extend(rf.as_ref());
    }
    if let Some(Some(rf)) = ratchet_state2.map(|rs| rs.fingerprint()) {
        x1.extend(rf.as_ref());
    }
    noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 1), i, &mut x1);

    let c = u64::from_be_bytes(x1[x1.len() - 8..].try_into().unwrap());

    x1.extend(&gen_null_response(rng.borrow_mut().deref_mut()));
    StateA1 {
        noise,
        e_secret,
        e1_secret,
        identity,
        packet: Packet(0, to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, c), x1),
    }
}
/// Corresponds to Transition Algorithm 1 found in Section 4.3.
pub(crate) fn trans_to_a1<C: CryptoLayer, App: ApplicationLayer<C>>(
    mut app: App,
    ctx: &Arc<ContextInner<C>>,
    s_remote: C::PublicKey,
    session_data: C::SessionData,
    identity: Vec<u8>,
    send: impl FnOnce(&Packet),
) -> Result<Arc<Session<C>>, OpenError> {
    let ratchet_states = app
        .restore_by_identity(&s_remote, &session_data)
        .map_err(OpenError::StorageError)?;
    let RatchetStates { state1, state2 } = ratchet_states.unwrap_or_default();

    let mut session_map = ctx.session_map.borrow_mut();
    let kid_recv = gen_kid(session_map.deref(), ctx.rng.borrow_mut().deref_mut());

    let a1 = create_a1_state::<C, App>(&ctx.rng, &s_remote, kid_recv, &state1, state2.as_ref(), identity);
    let packet = a1.packet.clone();

    let (hk_recv, hk_send) = a1.noise.get_ask(LABEL_HEADER_KEY);

    let current_time = app.time();
    let mut zeta = Zeta {
        ctx: Arc::downgrade(ctx),
        session_data,
        was_bob: false,
        s_remote,
        send_counter: 0,
        key_creation_counter: 0,
        counter_antireplay_window: std::array::from_fn(|_| 0),
        defrag: DefragBuffer::new(Some(hk_recv)),
        key_index: true,
        keys: [DuplexKey::default(), DuplexKey::default()],
        ratchet_state1: state1,
        ratchet_state2: state2,
        hk_send,
        resend_timer: current_time + C::SETTINGS.resend_time as i64,
        timeout_timer: current_time + C::SETTINGS.initial_offer_timeout as i64,
        beta: ZetaAutomata::A1(a1),
    };
    zeta.key_mut(true).recv.kid = Some(kid_recv);

    let session = Arc::new(Session(RefCell::new(zeta)));
    session_map.insert(kid_recv, Arc::downgrade(&session));
    ctx.sessions
        .borrow_mut()
        .insert(Arc::as_ptr(&session), Arc::downgrade(&session));

    send(&packet);

    Ok(session)
}
/// Corresponds to Algorithm 13 found in Section 5.
pub(crate) fn respond_to_challenge<C: CryptoLayer>(
    zeta: &mut Zeta<C>,
    rng: &RefCell<C::Rng>,
    challenge: &[u8; CHALLENGE_SIZE],
) {
    if let ZetaAutomata::A1(StateA1 { packet: Packet(_, _, x1), .. }) = &mut zeta.beta {
        let response_start = x1.len() - CHALLENGE_SIZE;
        respond_to_challenge_in_place::<C::Rng, C::Hash>(
            rng.borrow_mut().deref_mut(),
            challenge,
            (&mut x1[response_start..]).try_into().unwrap(),
        );
    }
}
/// Corresponds to Transition Algorithm 2 found in Section 4.3.
pub(crate) fn received_x1_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    app: &mut App,
    ctx: &ContextInner<C>,
    n: [u8; AES_GCM_NONCE_SIZE],
    mut x1: Vec<u8>,
    send: impl FnOnce(&Packet, &[u8; AES_256_KEY_SIZE]),
) -> Result<(), ReceiveError> {
    use FaultType::*;
    //    <- s
    //    ...
    //    -> e, es, e1
    //    <- e, ee, ekem1, psk
    if !(HANDSHAKE_HELLO_MIN_SIZE..=HANDSHAKE_HELLO_MAX_SIZE).contains(&x1.len()) {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if n[AES_GCM_NONCE_SIZE - 8..] != x1[x1.len() - 8..] {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let mut noise = SymmetricState::<C>::initialize(PROTOCOL_NAME_NOISE_XK);
    let mut i = 0;
    // Noise process prologue.
    let j = i + KID_SIZE;
    noise.mix_hash(&x1[i..j]);
    let kid_send = NonZeroU32::new(u32::from_be_bytes(x1[i..j].try_into().unwrap()))
        .ok_or(byzantine_fault!(InvalidPacket, true))?;
    noise.mix_hash(&ctx.s_secret.public_key_bytes());
    i = j;
    // Process message pattern 1 e token.
    let e_remote = noise.read_e(&mut i, &x1).ok_or(byzantine_fault!(FailedAuth, true))?;
    // Process message pattern 1 es token.
    noise.mix_dh(&ctx.s_secret, &e_remote);
    // Process message pattern 1 e1 token.
    let j = i + KYBER_PUBLIC_KEY_SIZE;
    let k = j + AES_GCM_TAG_SIZE;
    let tag = x1[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 0), &mut x1[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let e1_start = i;
    let e1_end = j;
    i = k;
    // Process message pattern 1 payload.
    let k = x1.len();
    let j = k - AES_GCM_TAG_SIZE;
    let tag = x1[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 1), &mut x1[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }

    let mut ratchet_state = None;
    while i + RATCHET_SIZE <= j {
        let rf = (&x1[i..i + RATCHET_SIZE]).try_into().unwrap();
        match app.restore_by_fingerprint(rf) {
            Ok(None) => {}
            Ok(Some(rs)) => {
                ratchet_state = Some(rs);
                break;
            }
            Err(e) => return Err(ReceiveError::StorageError(e)),
        }
        i += RATCHET_SIZE;
    }
    let ratchet_state = if let Some(rs) = ratchet_state {
        rs
    } else {
        if app.hello_requires_recognized_ratchet() {
            return Err(byzantine_fault!(FailedAuth, true));
        }
        RatchetState::empty()
    };
    let (hk_send, hk_recv) = noise.get_ask(LABEL_HEADER_KEY);

    let mut x2 = Vec::new();
    // Process message pattern 2 e token.
    let e_secret = noise.write_e(&ctx.rng, &mut x2);
    // Process message pattern 2 ee token.
    noise.mix_dh(&e_secret, &e_remote);
    // Process message pattern 2 ekem1 token.
    let i = x2.len();
    let (ekem1, ekem1_secret) = C::Kem::encapsulate(
        ctx.rng.borrow_mut().deref_mut(),
        (&x1[e1_start..e1_end]).try_into().unwrap(),
    )
    .map(|(ct, secret)| (ct, Zeroizing::new(secret)))
    .ok_or(byzantine_fault!(FailedAuth, true))?;
    x2.extend(ekem1);
    noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), i, &mut x2);
    noise.mix_key(ekem1_secret.as_ref());
    drop(ekem1_secret);
    // Process message pattern 2 psk2 token.
    noise.mix_key_and_hash(ratchet_state.key());
    // Process message pattern 2 payload.
    let session_map = ctx.session_map.borrow_mut();
    let kid_recv = gen_kid(session_map.deref(), ctx.rng.borrow_mut().deref_mut());

    let i = x2.len();
    x2.extend(kid_recv.get().to_be_bytes());
    noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), i, &mut x2);

    let i = x2.len();
    let mut c = [0u8; 8];
    c[5] = x2[i - 3];
    c[6] = x2[i - 2];
    c[7] = x2[i - 1];
    let c = u64::from_be_bytes(c);

    ctx.b2_map.borrow_mut().insert(
        kid_recv,
        StateB2 {
            ratchet_state,
            kid_send,
            kid_recv,
            hk_send: hk_send.clone(),
            e_secret,
            noise,
            defrag: DefragBuffer::new(Some(hk_recv)),
        },
    );

    send(
        &Packet(kid_send.get(), to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, c), x2),
        &hk_send,
    );
    Ok(())
}
/// Corresponds to Transition Algorithm 3 found in Section 4.3.
pub(crate) fn received_x2_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: &mut Zeta<C>,
    session: &Arc<Session<C>>,
    app: &mut App,
    ctx: &Arc<ContextInner<C>>,
    kid: NonZeroU32,
    n: [u8; AES_GCM_NONCE_SIZE],
    mut x2: Vec<u8>,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) -> Result<bool, ReceiveError> {
    use FaultType::*;
    //    <- e, ee, ekem1, psk
    //    -> s, se
    if HANDSHAKE_RESPONSE_SIZE != x2.len() {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if Some(kid) != zeta.key_ref(true).recv.kid {
        return Err(byzantine_fault!(UnknownLocalKeyId, true));
    }
    let (_, c) = from_nonce(&n);
    if c >= COUNTER_WINDOW_MAX_SKIP_AHEAD || n[AES_GCM_NONCE_SIZE - 3..] != x2[x2.len() - 3..] {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let mut should_warn_missing_ratchet = false;
    let result = (|| {
        if let ZetaAutomata::A1(StateA1 { noise, e_secret, e1_secret, identity, .. }) = &zeta.beta {
            let mut noise = noise.clone();
            let mut i = 0;
            // Process message pattern 2 e token.
            let e_remote = noise.read_e(&mut i, &x2).ok_or(byzantine_fault!(FailedAuth, true))?;
            // Process message pattern 2 ee token.
            noise.mix_dh(e_secret, &e_remote);
            // Process message pattern 2 ekem1 token.
            let j = i + KYBER_CIPHERTEXT_SIZE;
            let k = j + AES_GCM_TAG_SIZE;
            let tag = x2[j..k].try_into().unwrap();
            if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), &mut x2[i..j], tag) {
                return Err(byzantine_fault!(FailedAuth, true));
            }
            let ekem1_secret = e1_secret
                .decapsulate((&x2[i..j]).try_into().unwrap())
                .map(Zeroizing::new)
                .ok_or(byzantine_fault!(FailedAuth, true))?;
            noise.mix_key(ekem1_secret.as_ref());
            drop(ekem1_secret);
            i = k;
            // We attempt to decrypt the payload at most three times. First two times with
            // the ratchet key Alice remembers, and final time with a ratchet
            // key of zero if Alice allows ratchet downgrades.
            // The following code is not constant time, meaning we leak to an
            // attacker whether or not we downgraded.
            // We don't currently consider this sensitive enough information to hide.
            let j = i + KID_SIZE;
            let k = j + AES_GCM_TAG_SIZE;
            let payload: [u8; KID_SIZE] = x2[i..j].try_into().unwrap();
            let tag = x2[j..k].try_into().unwrap();
            // Check for which ratchet key Bob wants to use.
            let test_ratchet_key = |ratchet_key| -> Option<(NonZeroU32, SymmetricState<C>)> {
                let mut noise = noise.clone();
                let mut payload = payload;
                // Process message pattern 2 psk token.
                noise.mix_key_and_hash(ratchet_key);
                // Process message pattern 2 payload.
                if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), &mut payload, tag) {
                    return None;
                }
                NonZeroU32::new(u32::from_be_bytes(payload)).map(|kid2| (kid2, noise))
            };
            // Check first key.
            let mut ratchet_i = 1;
            let mut chain_len = zeta.ratchet_state1.chain_len();
            let mut result = test_ratchet_key(zeta.ratchet_state1.key());
            // Check second key.
            if result.is_none() {
                ratchet_i = 2;
                if let Some(rs) = zeta.ratchet_state2.as_ref() {
                    chain_len = rs.chain_len();
                    result = test_ratchet_key(rs.key());
                }
            }
            // Check zero key.
            if result.is_none() && !app.initiator_disallows_downgrade(session) {
                chain_len = 0;
                result = test_ratchet_key(&[0u8; RATCHET_SIZE]);
                if result.is_some() {
                    should_warn_missing_ratchet = true;
                }
            }

            let (kid_send, mut noise) = result.ok_or(byzantine_fault!(FailedAuth, true))?;
            let mut x3 = Vec::new();

            // Process message pattern 3 s token.
            let i = x3.len();
            x3.extend(&ctx.s_secret.public_key_bytes());
            noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 1), i, &mut x3);
            // Process message pattern 3 se token.
            noise.mix_dh(&ctx.s_secret, &e_remote);
            // Process message pattern 3 payload.
            let i = x3.len();
            x3.extend(identity);
            noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 0), i, &mut x3);

            let (rk, rf) = noise.get_ask(LABEL_RATCHET_STATE);
            let new_ratchet_state = RatchetState::new(rk, rf, chain_len + 1);

            let (ratchet_to_preserve, ratchet_to_delete) = if ratchet_i == 1 {
                (Some(&zeta.ratchet_state1), zeta.ratchet_state2.as_ref())
            } else {
                (zeta.ratchet_state2.as_ref(), Some(&zeta.ratchet_state1))
            };
            let result = app.save_ratchet_state(
                &zeta.s_remote,
                &zeta.session_data,
                RatchetUpdate {
                    state1: &new_ratchet_state,
                    state2: ratchet_to_preserve,
                    state1_was_just_added: true,
                    deleted_state1: ratchet_to_delete,
                    deleted_state2: None,
                },
            );
            if let Err(e) = result {
                return Err(ReceiveError::StorageError(e));
            }

            let (kek_recv, kek_send) = noise.get_ask(LABEL_KEX_KEY);
            let (nk_recv, nk_send) = noise.split();
            let n = to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 0);
            let identity = identity.clone();

            zeta.key_mut(true).send.kid = Some(kid_send);
            zeta.key_mut(true).send.kek = Some(kek_send);
            zeta.key_mut(true).send.nk = Some(nk_send);
            zeta.key_mut(true).recv.kek = Some(kek_recv);
            zeta.key_mut(true).recv.nk = Some(nk_recv);
            zeta.ratchet_state2 = Some(zeta.ratchet_state1.clone());
            zeta.ratchet_state1 = new_ratchet_state;
            let current_time = app.time();
            zeta.key_creation_counter = zeta.send_counter;
            zeta.resend_timer = current_time + C::SETTINGS.resend_time as i64;
            zeta.timeout_timer = current_time + C::SETTINGS.initial_offer_timeout as i64;
            let packet = Packet(kid_send.get(), n, x3);
            zeta.beta = ZetaAutomata::A3 { identity, packet: packet.clone() };

            Ok(packet)
        } else {
            Err(byzantine_fault!(FailedAuth, true))
        }
    })();
    match &result {
        Err(ReceiveError::ByzantineFault { .. }) => {
            let current_time = app.time();
            timeout_trans(zeta, session, app, ctx, current_time, send);
        }
        Ok(packet) => send(packet, Some(&zeta.hk_send)),
        _ => {}
    }
    result.map(|_| should_warn_missing_ratchet)
}
fn send_control<C: CryptoLayer>(
    zeta: &mut Zeta<C>,
    packet_type: u8,
    mut payload: Vec<u8>,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) -> bool {
    if let Some((c, _)) = zeta.get_counter() {
        if let (Some(kek), Some(kid)) = (zeta.key_ref(false).send.kek.as_ref(), zeta.key_ref(false).send.kid) {
            let nonce = to_nonce(packet_type, c);
            let tag = C::Aead::encrypt_in_place(kek, &nonce, None, &mut payload);
            payload.extend(tag);

            send(&Packet(kid.get(), nonce, payload), Some(&zeta.hk_send));
            true
        } else {
            false
        }
    } else {
        false
    }
}
/// Corresponds to Transition Algorithm 4 found in Section 4.3.
pub(crate) fn received_x3_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: StateB2<C>,
    app: &mut App,
    ctx: &Arc<ContextInner<C>>,
    kid: NonZeroU32,
    mut x3: Vec<u8>,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) -> Result<(Arc<Session<C>>, bool), ReceiveError> {
    use FaultType::*;
    //    -> s, se
    if !(HANDSHAKE_COMPLETION_MIN_SIZE..=HANDSHAKE_COMPLETION_MAX_SIZE).contains(&x3.len()) {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if kid != zeta.kid_recv {
        return Err(byzantine_fault!(UnknownLocalKeyId, true));
    }

    let mut noise = zeta.noise.clone();
    let mut i = 0;
    // Process message pattern 3 s token.
    let j = i + P384_PUBLIC_KEY_SIZE;
    let k = j + AES_GCM_TAG_SIZE;
    let tag = x3[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 1), &mut x3[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let s_remote =
        C::PublicKey::from_bytes((&x3[i..j]).try_into().unwrap()).ok_or(byzantine_fault!(FailedAuth, true))?;
    i = k;
    // Process message pattern 3 se token.
    noise.mix_dh(&zeta.e_secret, &s_remote);
    // Process message pattern 3 payload.
    let k = x3.len();
    let j = k - AES_GCM_TAG_SIZE;
    let tag = x3[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 0), &mut x3[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let identity_start = i;
    let identity_end = j;

    let (kek_send, kek_recv) = noise.get_ask(LABEL_KEX_KEY);
    let c = 0;

    let action = app.check_accept_session(&s_remote, &x3[identity_start..identity_end]);
    let responder_disallows_downgrade = action.responder_disallows_downgrade;
    let responder_silently_rejects = action.responder_silently_rejects;
    let session_data = action.session_data;
    let create_reject = || {
        let mut d = Vec::<u8>::new();
        let n = to_nonce(PACKET_TYPE_SESSION_REJECTED, c);
        let tag = C::Aead::encrypt_in_place(&kek_send, &n, None, &mut []);
        d.extend(&tag);
        // We just used a counter with this key, but we are not storing
        // the fact we used it in memory. This is currently ok because the
        // handshake is being dropped, so nonce reuse can't happen.
        Packet(zeta.kid_send.get(), n, d)
    };
    if let Some(session_data) = session_data {
        let result = app.restore_by_identity(&s_remote, &session_data);
        match result {
            Ok(rss) => {
                let RatchetStates { state1, state2 } = rss.unwrap_or_default();
                let mut should_warn_missing_ratchet = false;

                if (zeta.ratchet_state != state1) & (Some(&zeta.ratchet_state) != state2.as_ref()) {
                    if !responder_disallows_downgrade && zeta.ratchet_state.fingerprint().is_none() {
                        should_warn_missing_ratchet = true;
                    } else {
                        if !responder_silently_rejects {
                            send(&create_reject(), Some(&zeta.hk_send))
                        }
                        return Err(byzantine_fault!(FailedAuth, true));
                    }
                }

                let (rk, rf) = noise.get_ask(LABEL_RATCHET_STATE);
                // We must make sure the ratchet key is saved before we transition.
                let new_ratchet_state = RatchetState::new(rk, rf, zeta.ratchet_state.chain_len() + 1);
                let result = app.save_ratchet_state(
                    &s_remote,
                    &session_data,
                    RatchetUpdate {
                        state1: &new_ratchet_state,
                        state2: None,
                        state1_was_just_added: true,
                        deleted_state1: Some(&state1),
                        deleted_state2: state2.as_ref(),
                    },
                );
                if let Err(e) = result {
                    return Err(ReceiveError::StorageError(e));
                }

                let mut c1 = Vec::new();
                let n = to_nonce(PACKET_TYPE_KEY_CONFIRM, c);
                let tag = C::Aead::encrypt_in_place(&kek_send, &n, None, &mut []);
                c1.extend(&tag);

                let (nk1, nk2) = noise.split();
                let keys = DuplexKey {
                    send: Keys { kek: Some(kek_send), nk: Some(nk1), kid: Some(zeta.kid_send) },
                    recv: Keys { kek: Some(kek_recv), nk: Some(nk2), kid: Some(zeta.kid_recv) },
                };
                let current_time = app.time();

                let mut session_map = ctx.session_map.borrow_mut();
                use std::collections::hash_map::Entry::*;
                let entry = match session_map.entry(zeta.kid_recv) {
                    // We could have issued the kid that we initially offered Alice to someone else
                    // before Alice was able to respond. It is unlikely but possible.
                    Occupied(_) => return Err(byzantine_fault!(OutOfSequence, false)),
                    Vacant(entry) => entry,
                };
                let session = Arc::new(Session(RefCell::new(Zeta {
                    ctx: Arc::downgrade(ctx),
                    session_data,
                    was_bob: true,
                    s_remote,
                    send_counter: 1,
                    key_creation_counter: 1,
                    key_index: false,
                    keys: [keys, DuplexKey::default()],
                    ratchet_state1: new_ratchet_state,
                    ratchet_state2: None,
                    hk_send: zeta.hk_send.clone(),
                    resend_timer: current_time + C::SETTINGS.resend_time as i64,
                    timeout_timer: current_time + C::SETTINGS.rekey_timeout as i64,
                    beta: ZetaAutomata::S1,
                    counter_antireplay_window: std::array::from_fn(|_| 0),
                    defrag: zeta.defrag,
                })));
                entry.insert(Arc::downgrade(&session));
                ctx.sessions
                    .borrow_mut()
                    .insert(Arc::as_ptr(&session), Arc::downgrade(&session));

                send(&Packet(zeta.kid_send.get(), n, c1), Some(&zeta.hk_send));
                Ok((session, should_warn_missing_ratchet))
            }
            Err(e) => Err(ReceiveError::StorageError(e)),
        }
    } else {
        if !responder_silently_rejects {
            send(&create_reject(), Some(&zeta.hk_send))
        }
        Err(byzantine_fault!(FailedAuth, true))
    }
}
/// Corresponds to Transition Algorithm 5 found in Section 4.3.
pub(crate) fn received_c1_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: &mut Zeta<C>,
    app: &mut App,
    rng: &RefCell<C::Rng>,
    kid: NonZeroU32,
    n: [u8; AES_GCM_NONCE_SIZE],
    c1: Vec<u8>,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) -> Result<bool, ReceiveError> {
    use FaultType::*;

    if c1.len() != KEY_CONFIRMATION_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    let is_other = if Some(kid) == zeta.key_ref(true).recv.kid {
        true
    } else if Some(kid) == zeta.key_ref(false).recv.kid {
        false
    } else {
        // Some key confirmation may have arrived extremely delayed.
        // It is unlikely but possible.
        return Err(byzantine_fault!(OutOfSequence, false));
    };

    let specified_key = zeta
        .key_ref(is_other)
        .recv
        .kek
        .as_ref()
        .ok_or(byzantine_fault!(OutOfSequence, true))?;
    let tag = c1[..].try_into().unwrap();
    if !C::Aead::decrypt_in_place(specified_key, &n, None, &mut [], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(&n);
    if !zeta.update_counter_window(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }

    let just_establised = is_other && matches!(&zeta.beta, ZetaAutomata::A3 { .. });
    if is_other {
        if let ZetaAutomata::A3 { .. } | ZetaAutomata::R2 { .. } = &zeta.beta {
            if zeta.ratchet_state2.is_some() {
                let result = app.save_ratchet_state(
                    &zeta.s_remote,
                    &zeta.session_data,
                    RatchetUpdate {
                        state1: &zeta.ratchet_state1,
                        state2: None,
                        state1_was_just_added: false,
                        deleted_state1: zeta.ratchet_state2.as_ref(),
                        deleted_state2: None,
                    },
                );
                if let Err(e) = result {
                    return Err(ReceiveError::StorageError(e));
                }
            }

            zeta.ratchet_state2 = None;
            zeta.key_index ^= true;
            let r = rng.borrow_mut().next_u64() % C::SETTINGS.rekey_time_max_jitter;
            zeta.timeout_timer = app.time() + C::SETTINGS.rekey_after_time.saturating_sub(r) as i64;
            zeta.resend_timer = i64::MAX;
            zeta.beta = ZetaAutomata::S2;
        }
    }
    let c2 = Vec::new();
    if !send_control::<C>(zeta, PACKET_TYPE_ACK, c2, send) {
        return Err(byzantine_fault!(OutOfSequence, true));
    }

    Ok(just_establised)
}
/// Corresponds to the trivial Transition Algorithm described for processing C_2 packets found in
/// Section 4.3.
pub(crate) fn received_c2_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: &mut Zeta<C>,
    app: &mut App,
    rng: &RefCell<C::Rng>,
    kid: NonZeroU32,
    n: [u8; AES_GCM_NONCE_SIZE],
    c2: Vec<u8>,
) -> Result<(), ReceiveError> {
    use FaultType::*;

    if c2.len() != ACKNOWLEDGEMENT_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if Some(kid) != zeta.key_ref(false).recv.kid {
        // Some acknowledgement may have arrived extremely delayed.
        return Err(byzantine_fault!(UnknownLocalKeyId, false));
    }
    if !matches!(&zeta.beta, ZetaAutomata::S1) {
        // Some acknowledgement may have arrived extremely delayed.
        return Err(byzantine_fault!(OutOfSequence, false));
    }

    let tag = c2[..].try_into().unwrap();
    if !C::Aead::decrypt_in_place(zeta.key_ref(false).recv.kek.as_ref().unwrap(), &n, None, &mut [], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(&n);
    if !zeta.update_counter_window(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }

    let r = rng.borrow_mut().next_u64() % C::SETTINGS.rekey_time_max_jitter;
    zeta.timeout_timer = app.time() + C::SETTINGS.rekey_after_time.saturating_sub(r) as i64;
    zeta.resend_timer = i64::MAX;
    zeta.beta = ZetaAutomata::S2;
    Ok(())
}
/// Corresponds to the trivial Transition Algorithm described for processing D packets found in
/// Section 4.3.
pub(crate) fn received_d_trans<C: CryptoLayer>(
    zeta: &mut Zeta<C>,
    kid: NonZeroU32,
    n: [u8; AES_GCM_NONCE_SIZE],
    d: Vec<u8>,
) -> Result<(), ReceiveError> {
    use FaultType::*;

    if d.len() != SESSION_REJECTED_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if Some(kid) != zeta.key_ref(true).recv.kid || !matches!(&zeta.beta, ZetaAutomata::A3 { .. }) {
        return Err(byzantine_fault!(OutOfSequence, true));
    }

    let tag = d[..].try_into().unwrap();
    if !C::Aead::decrypt_in_place(zeta.key_ref(true).recv.kek.as_ref().unwrap(), &n, None, &mut [], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(&n);
    if !zeta.update_counter_window(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }

    zeta.expire();
    Ok(())
}
/// Corresponds to the timer rules of the Zeta State Machine found in Section 4.1 - Definition 3.
pub(crate) fn service<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: &mut Zeta<C>,
    session: &Arc<Session<C>>,
    ctx: &Arc<ContextInner<C>>,
    app: &mut App,
    current_time: i64,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) {
    if zeta.timeout_timer <= current_time {
        timeout_trans(zeta, session, app, ctx, current_time, send);
    } else if zeta.resend_timer <= current_time {
        // Corresponds to the resend timer rules found in Section 4.1 - Definition 3.
        zeta.resend_timer = current_time + C::SETTINGS.resend_time as i64;

        let (p, control_payload) = match &zeta.beta {
            ZetaAutomata::Null => return,
            ZetaAutomata::A1(StateA1 { packet, .. }) => {
                log!(app, ResentX1(session));
                return send(packet, None);
            }
            ZetaAutomata::A3 { packet, .. } => {
                log!(app, ResentX3(session));
                return send(packet, Some(&zeta.hk_send));
            }
            ZetaAutomata::S1 => {
                log!(app, ResentKeyConfirm(session));
                (PACKET_TYPE_KEY_CONFIRM, Vec::new())
            }
            ZetaAutomata::S2 => return,
            ZetaAutomata::R1 { k1, .. } => {
                log!(app, ResentK1(session));
                (PACKET_TYPE_REKEY_INIT, k1.clone())
            }
            ZetaAutomata::R2 { k2, .. } => {
                log!(app, ResentK2(session));
                (PACKET_TYPE_REKEY_COMPLETE, k2.clone())
            }
        };

        send_control::<C>(zeta, p, control_payload, send);
    }
}
/// Corresponds to the timeout timer Transition Algorithm described in Section 4.1 - Definition 3.
fn timeout_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: &mut Zeta<C>,
    session: &Arc<Session<C>>,
    app: &mut App,
    ctx: &Arc<ContextInner<C>>,
    current_time: i64,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) {
    match &zeta.beta {
        ZetaAutomata::Null => {}
        ZetaAutomata::A1(StateA1 { identity, .. }) | ZetaAutomata::A3 { identity, .. } => {
            if matches!(&zeta.beta, ZetaAutomata::A1(_)) {
                log!(app, TimeoutX1(session));
            } else {
                log!(app, TimeoutX3(session));
            }
            let new_kid_recv = remap(session, zeta, &ctx.rng, &ctx.session_map);

            let a1 = create_a1_state::<C, App>(
                &ctx.rng,
                &zeta.s_remote,
                new_kid_recv,
                &zeta.ratchet_state1,
                zeta.ratchet_state2.as_ref(),
                identity.clone(),
            );
            let (hk_recv, hk_send) = a1.noise.get_ask(LABEL_HEADER_KEY);
            let packet = a1.packet.clone();

            zeta.hk_send = hk_send;
            *zeta.key_mut(true) = DuplexKey::default();
            zeta.key_mut(true).recv.kid = Some(new_kid_recv);
            zeta.resend_timer = current_time + C::SETTINGS.resend_time as i64;
            zeta.timeout_timer = current_time + C::SETTINGS.initial_offer_timeout as i64;
            zeta.beta = ZetaAutomata::A1(a1);
            zeta.defrag = DefragBuffer::new(Some(hk_recv));

            send(&packet, None);
        }
        ZetaAutomata::S2 => {
            // Corresponds to Transition Algorithm 6 found in Section 4.3.
            log!(app, StartedRekeyingSentK1(session));
            let new_kid_recv = remap(session, zeta, &ctx.rng, &ctx.session_map);
            //    -> s
            //    <- s
            //    ...
            //    -> psk, e, es, ss
            let mut k1 = Vec::new();
            let mut noise = SymmetricState::initialize(PROTOCOL_NAME_NOISE_KK);
            // Noise process prologue.
            noise.mix_hash(&ctx.s_secret.public_key_bytes());
            noise.mix_hash(&zeta.s_remote.to_bytes());
            // Process message pattern 1 psk0 token.
            noise.mix_key_and_hash(zeta.ratchet_state1.key());
            // Process message pattern 1 e token.
            let e_secret = noise.write_e(&ctx.rng, &mut k1);
            // Process message pattern 1 es token.
            noise.mix_dh(&e_secret, &zeta.s_remote);
            // Process message pattern 1 ss token.
            noise.mix_dh(&ctx.s_secret, &zeta.s_remote);
            // Process message pattern 1 payload.
            let i = k1.len();
            k1.extend(&new_kid_recv.get().to_be_bytes());
            noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_REKEY_INIT, 0), i, &mut k1);

            zeta.key_mut(true).recv.kid = Some(new_kid_recv);
            zeta.timeout_timer = current_time + C::SETTINGS.rekey_timeout as i64;
            zeta.resend_timer = current_time + C::SETTINGS.resend_time as i64;
            zeta.beta = ZetaAutomata::R1 { noise, e_secret, k1: k1.clone() };

            send_control::<C>(zeta, PACKET_TYPE_REKEY_INIT, k1, send);
        }
        ZetaAutomata::S1 { .. } => {
            log!(app, TimeoutKeyConfirm(session));
            zeta.expire();
        }
        ZetaAutomata::R1 { .. } => {
            log!(app, TimeoutK1(session));
            zeta.expire();
        }
        ZetaAutomata::R2 { .. } => {
            log!(app, TimeoutK2(session));
            zeta.expire();
        }
    }
}
/// Corresponds to Transition Algorithm 7 found in Section 4.3.
pub(crate) fn received_k1_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: &mut Zeta<C>,
    session: &Arc<Session<C>>,
    app: &mut App,
    rng: &RefCell<C::Rng>,
    session_map: &SessionMap<C>,
    s_secret: &C::KeyPair,
    kid: NonZeroU32,
    n: [u8; AES_GCM_NONCE_SIZE],
    mut k1: Vec<u8>,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) -> Result<(), ReceiveError> {
    use FaultType::*;
    //    -> s
    //    <- s
    //    ...
    //    -> psk, e, es, ss
    //    <- e, ee, se
    if k1.len() != REKEY_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if Some(kid) != zeta.key_ref(false).recv.kid {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(UnknownLocalKeyId, false));
    }
    let should_rekey_as_bob = match &zeta.beta {
        ZetaAutomata::S2 { .. } => true,
        ZetaAutomata::R1 { .. } => zeta.was_bob,
        _ => false,
    };
    if !should_rekey_as_bob {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(OutOfSequence, false));
    }

    let i = k1.len() - AES_GCM_TAG_SIZE;
    let tag = k1[i..].try_into().unwrap();
    if !C::Aead::decrypt_in_place(
        zeta.key_ref(false).recv.kek.as_ref().unwrap(),
        &n,
        None,
        &mut k1[..i],
        &tag,
    ) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(&n);
    if !zeta.update_counter_window(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }
    k1.truncate(i);

    let result = (|| {
        let mut i = 0;
        let mut noise = SymmetricState::<C>::initialize(PROTOCOL_NAME_NOISE_KK);
        // Noise process prologue.
        noise.mix_hash(&zeta.s_remote.to_bytes());
        noise.mix_hash(&s_secret.public_key_bytes());
        // Process message pattern 1 psk0 token.
        noise.mix_key_and_hash(zeta.ratchet_state1.key());
        // Process message pattern 1 e token.
        let e_remote = noise.read_e(&mut i, &k1).ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 1 es token.
        noise.mix_dh(s_secret, &e_remote);
        // Process message pattern 1 ss token.
        noise.mix_dh(s_secret, &zeta.s_remote);
        // Process message pattern 1 payload.
        let j = i + KID_SIZE;
        let k = j + AES_GCM_TAG_SIZE;
        let tag = k1[j..k].try_into().unwrap();
        if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_REKEY_INIT, 0), &mut k1[i..j], tag) {
            return Err(byzantine_fault!(FailedAuth, true));
        }
        let kid_send = NonZeroU32::new(u32::from_be_bytes(k1[i..j].try_into().unwrap()))
            .ok_or(byzantine_fault!(FailedAuth, true))?;

        let mut k2 = Vec::new();
        // Process message pattern 2 e token.
        let e_secret = noise.write_e(rng, &mut k2);
        // Process message pattern 2 ee token.
        noise.mix_dh(&e_secret, &e_remote);
        // Process message pattern 2 se token.
        noise.mix_dh(s_secret, &e_remote);
        // Process message pattern 2 payload.
        let i = k2.len();
        let new_kid_recv = remap(session, zeta, rng, session_map);
        k2.extend(&new_kid_recv.get().to_be_bytes());
        noise.encrypt_and_hash_in_place(to_nonce(PACKET_TYPE_REKEY_COMPLETE, 0), i, &mut k2);

        let (rk, rf) = noise.get_ask(LABEL_RATCHET_STATE);
        let new_ratchet_state = RatchetState::new(rk, rf, zeta.ratchet_state1.chain_len() + 1);
        let result = app.save_ratchet_state(
            &zeta.s_remote,
            &zeta.session_data,
            RatchetUpdate {
                state1: &new_ratchet_state,
                state2: Some(&zeta.ratchet_state1),
                state1_was_just_added: true,
                deleted_state1: zeta.ratchet_state2.as_ref(),
                deleted_state2: None,
            },
        );
        if let Err(e) = result {
            return Err(ReceiveError::StorageError(e));
        }
        let (kek_send, kek_recv) = noise.get_ask(LABEL_KEX_KEY);
        let (nk_send, nk_recv) = noise.split();

        zeta.key_mut(true).send.kid = Some(kid_send);
        zeta.key_mut(true).send.kek = Some(kek_send);
        zeta.key_mut(true).send.nk = Some(nk_send);
        zeta.key_mut(true).recv.kid = Some(new_kid_recv);
        zeta.key_mut(true).recv.kek = Some(kek_recv);
        zeta.key_mut(true).recv.nk = Some(nk_recv);
        zeta.ratchet_state2 = Some(zeta.ratchet_state1.clone());
        zeta.ratchet_state1 = new_ratchet_state;
        let current_time = app.time();
        zeta.key_creation_counter = zeta.send_counter;
        zeta.timeout_timer = current_time + C::SETTINGS.rekey_timeout as i64;
        zeta.resend_timer = current_time + C::SETTINGS.resend_time as i64;
        zeta.beta = ZetaAutomata::R2 { k2: k2.clone() };

        send_control::<C>(zeta, PACKET_TYPE_REKEY_COMPLETE, k2, send);
        Ok(())
    })();
    if matches!(result, Err(ReceiveError::ByzantineFault { .. })) {
        zeta.expire();
    }
    result
}
/// Corresponds to Transition Algorithm 8 found in Section 4.3.
pub(crate) fn received_k2_trans<C: CryptoLayer, App: ApplicationLayer<C>>(
    zeta: &mut Zeta<C>,
    app: &mut App,
    kid: NonZeroU32,
    n: [u8; AES_GCM_NONCE_SIZE],
    mut k2: Vec<u8>,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>),
) -> Result<(), ReceiveError> {
    use FaultType::*;
    //    <- e, ee, se
    if k2.len() != REKEY_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if Some(kid) != zeta.key_ref(false).recv.kid {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(UnknownLocalKeyId, false));
    }
    if !matches!(&zeta.beta, ZetaAutomata::R1 { .. }) {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(OutOfSequence, false));
    }

    let i = k2.len() - AES_GCM_TAG_SIZE;
    let tag = k2[i..].try_into().unwrap();
    if !C::Aead::decrypt_in_place(
        zeta.key_ref(false).recv.kek.as_ref().unwrap(),
        &n,
        None,
        &mut k2[..i],
        &tag,
    ) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(&n);
    if !zeta.update_counter_window(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }
    k2.truncate(i);
    let result = (|| {
        if let ZetaAutomata::R1 { noise, e_secret, .. } = &zeta.beta {
            let mut noise = noise.clone();
            let mut i = 0;
            // Process message pattern 2 e token.
            let e_remote = noise.read_e(&mut i, &k2).ok_or(byzantine_fault!(FailedAuth, true))?;
            // Process message pattern 2 ee token.
            noise.mix_dh(e_secret, &e_remote);
            // Process message pattern 2 se token.
            noise.mix_dh(e_secret, &zeta.s_remote);
            // Process message pattern 2 payload.
            let j = i + KID_SIZE;
            let k = j + AES_GCM_TAG_SIZE;
            let tag = k2[j..k].try_into().unwrap();
            if !noise.decrypt_and_hash_in_place(to_nonce(PACKET_TYPE_REKEY_COMPLETE, 0), &mut k2[i..j], tag) {
                return Err(byzantine_fault!(FailedAuth, true));
            }
            let kid_send = NonZeroU32::new(u32::from_be_bytes(k2[i..j].try_into().unwrap()))
                .ok_or(byzantine_fault!(InvalidPacket, true))?;

            let (rk, rf) = noise.get_ask(LABEL_RATCHET_STATE);
            let new_ratchet_state = RatchetState::new(rk, rf, zeta.ratchet_state1.chain_len() + 1);
            let result = app.save_ratchet_state(
                &zeta.s_remote,
                &zeta.session_data,
                RatchetUpdate {
                    state1: &new_ratchet_state,
                    state2: None,
                    state1_was_just_added: true,
                    deleted_state1: Some(&zeta.ratchet_state1),
                    deleted_state2: zeta.ratchet_state2.as_ref(),
                },
            );
            if let Err(e) = result {
                return Err(ReceiveError::StorageError(e));
            }
            let (kek_recv, kek_send) = noise.get_ask(LABEL_KEX_KEY);
            let (nk_recv, nk_send) = noise.split();

            zeta.key_mut(true).send.kid = Some(kid_send);
            zeta.key_mut(true).send.kek = Some(kek_send);
            zeta.key_mut(true).send.nk = Some(nk_send);
            zeta.key_mut(true).recv.kek = Some(kek_recv);
            zeta.key_mut(true).recv.nk = Some(nk_recv);
            zeta.ratchet_state1 = new_ratchet_state;
            zeta.key_index ^= true;
            let current_time = app.time();
            zeta.key_creation_counter = zeta.send_counter;
            zeta.timeout_timer = current_time + C::SETTINGS.rekey_timeout as i64;
            zeta.resend_timer = current_time + C::SETTINGS.resend_time as i64;
            zeta.beta = ZetaAutomata::S1;

            let c1 = Vec::new();
            send_control::<C>(zeta, PACKET_TYPE_KEY_CONFIRM, c1, send);
            Ok(())
        } else {
            unreachable!()
        }
    })();
    if matches!(result, Err(ReceiveError::ByzantineFault { .. })) {
        zeta.expire();
    }
    result
}
/// Corresponds to Algorithm 9 found in Section 4.3.
pub(crate) fn send_payload<C: CryptoLayer>(
    zeta: &mut Zeta<C>,
    mut payload: Vec<u8>,
    send: impl FnOnce(&Packet, Option<&[u8; AES_256_KEY_SIZE]>) -> Result<(), SendError>,
) -> Result<(), SendError> {
    use SendError::*;

    if matches!(&zeta.beta, ZetaAutomata::Null) {
        return Err(SessionExpired);
    }
    if !matches!(
        &zeta.beta,
        ZetaAutomata::S1 | ZetaAutomata::S2 | ZetaAutomata::R1 { .. } | ZetaAutomata::R2 { .. }
    ) {
        return Err(SessionNotEstablished);
    }
    if let Some((c, should_rekey)) = zeta.get_counter() {
        if should_rekey && matches!(&zeta.beta, ZetaAutomata::S1) {
            // Cause timeout to occur next service interval.
            zeta.timeout_timer = i64::MIN;
        }

        let n = to_nonce(PACKET_TYPE_DATA, c);
        let tag = C::Aead::encrypt_in_place(zeta.key_ref(false).send.nk.as_ref().unwrap(), &n, None, &mut payload);
        payload.extend(&tag);

        send(
            &Packet(zeta.key_ref(false).send.kid.unwrap().get(), n, payload),
            Some(&zeta.hk_send),
        )
    } else {
        zeta.expire();
        Err(SessionExpired)
    }
}
/// Corresponds to Algorithm 10 found in Section 4.3.
pub(crate) fn received_payload_in_place<C: CryptoLayer>(
    zeta: &mut Zeta<C>,
    kid: NonZeroU32,
    n: [u8; AES_GCM_NONCE_SIZE],
    payload: &mut Vec<u8>,
) -> Result<(), ReceiveError> {
    use FaultType::*;

    if payload.len() < AES_GCM_TAG_SIZE {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let is_other = if Some(kid) == zeta.key_ref(true).recv.kid {
        true
    } else if Some(kid) == zeta.key_ref(false).recv.kid {
        false
    } else {
        // A packet would have to be delayed by around an hour for this error to occur, but it can
        // occur naturally due to just out-of-order transport.
        return Err(byzantine_fault!(OutOfSequence, false));
    };

    let i = payload.len() - AES_GCM_TAG_SIZE;
    let specified_key = zeta.key_ref(is_other).recv.nk.as_ref();
    let specified_key = specified_key.ok_or(byzantine_fault!(OutOfSequence, true))?;
    let tag = payload[i..].try_into().unwrap();
    if !C::Aead::decrypt_in_place(specified_key, &n, None, &mut payload[..i], &tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(&n);
    if !zeta.update_counter_window(c) {
        // This error is marked as not happening naturally, but it could occur if something about
        // the transport protocol is duplicating packets.
        return Err(byzantine_fault!(ExpiredCounter, true));
    }
    payload.truncate(i);

    Ok(())
}

impl<C: CryptoLayer> Session<C> {
    /// Mark a session as expired. This will make it impossible for this session to successfully
    /// receive or send data or control packets. It is recommended to simply `drop` the session
    /// instead, but this can provide some reassurance in complex shared ownership situations.
    pub fn expire(&mut self) {
        self.0.borrow_mut().expire();
    }
}

impl<C: CryptoLayer> Drop for Session<C> {
    fn drop(&mut self) {
        self.expire();
    }
}
