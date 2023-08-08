use arrayvec::ArrayVec;
use rand_core::RngCore;
use std::cmp::Reverse;
use std::collections::HashMap;
use std::io::Write;
use std::num::NonZeroU32;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicBool, AtomicI64, AtomicU64, Ordering};
use std::sync::{Arc, Mutex, MutexGuard, RwLock, RwLockReadGuard, Weak};
use zeroize::Zeroizing;

use crate::antireplay::Window;
use crate::application::*;
use crate::challenge::{gen_null_response, respond_to_challenge_in_place};
use crate::crypto::*;
use crate::fragged::Fragged;
use crate::indexed_heap::BinaryHeapIndex;
use crate::proto::*;
use crate::ratchet_state::{RatchetState, RatchetStates};
use crate::result::{byzantine_fault, FaultType, OpenError, ReceiveError, SendError};
use crate::symmetric_state::SymmetricState;
use crate::zssp::{log, ContextInner, SessionQueue};
#[cfg(feature = "logging")]
use crate::LogEvent::*;

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
fn create_ratchet_state<App: ApplicationLayer>(
    hmac: &mut App::Hmac,
    noise: &SymmetricState<App>,
    pre_chain_len: u64,
) -> RatchetState {
    let mut rk = Zeroizing::new([0u8; HASHLEN]);
    let mut rf = Zeroizing::new([0u8; HASHLEN]);
    noise.get_ask(hmac, LABEL_RATCHET_STATE, &mut rk, &mut rf);
    RatchetState::new(
        Zeroizing::new(rk[..RATCHET_SIZE].try_into().unwrap()),
        Zeroizing::new(rf[..RATCHET_SIZE].try_into().unwrap()),
        pre_chain_len + 1,
    )
}
fn get_counter<App: ApplicationLayer>(session: &Session<App>, state: &MutableState<App>) -> Option<(u64, bool)> {
    if session.session_has_expired.load(Ordering::Relaxed) {
        None
    } else {
        let c = session.send_counter.fetch_add(1, Ordering::Relaxed);
        if c > state.key_creation_counter + EXPIRE_AFTER_USES {
            session.session_has_expired.store(true, Ordering::SeqCst);
            return None;
        }
        if c > THREAD_SAFE_COUNTER_HARD_EXPIRE {
            session.session_has_expired.store(true, Ordering::SeqCst);
        }
        Some((c, c > state.key_creation_counter + App::SETTINGS.rekey_after_key_uses))
    }
}

/// Corresponds to the Zeta State Machine found in Section 4.1.
pub struct Session<App: ApplicationLayer> {
    ctx: Weak<ContextInner<App>>,
    /// An arbitrary application defined object associated with each session.
    pub session_data: App::SessionData,
    /// Is true if the local peer acted as Bob, the responder in the initial key exchange.
    pub was_bob: bool,
    queue_idx: BinaryHeapIndex,

    pub(crate) s_remote: App::PublicKey,
    send_counter: AtomicU64,
    session_has_expired: AtomicBool,

    pub window: Window<COUNTER_WINDOW_MAX_OOO, COUNTER_WINDOW_MAX_SKIP_AHEAD>,
    pub(crate) defrag: [Mutex<Fragged<App::IncomingPacketBuffer, MAX_FRAGMENTS>>; SESSION_MAX_FRAGMENTS_OOO],

    /// `session_queue -> state_machine_lock -> state -> session_map`
    state_machine_lock: Mutex<()>,
    /// `session_queue -> state_machine_lock -> state -> session_map`
    pub(crate) state: RwLock<MutableState<App>>,

    /// Pre-computed rekeying value.
    noise_kk_ss: Zeroizing<[u8; P384_ECDH_SHARED_SECRET_SIZE]>,
}
pub(crate) struct MutableState<App: ApplicationLayer> {
    ratchet_state1: RatchetState,
    ratchet_state2: Option<RatchetState>,

    pub(crate) hk_send: App::PrpEnc,
    pub(crate) hk_recv: App::PrpDec,
    key_creation_counter: u64,
    key_index: bool,
    keys: [DuplexKey<App>; 2],

    resend_timer: AtomicI64,
    timeout_timer: i64,
    pub(crate) beta: ZetaAutomata<App>,
}

/// Corresponds to State B_2 of the Zeta State Machine found in Section 4.1 - Definition 3.
pub(crate) struct StateB2<App: ApplicationLayer> {
    ratchet_state: RatchetState,
    kid_send: NonZeroU32,
    pub kid_recv: NonZeroU32,
    pub hk_send: Zeroizing<[u8; AES_256_KEY_SIZE]>,
    pub hk_recv: Zeroizing<[u8; AES_256_KEY_SIZE]>,
    e_secret: App::KeyPair,
    noise: SymmetricState<App>,
    pub defrag: Mutex<Fragged<App::IncomingPacketBuffer, MAX_FRAGMENTS>>,
}

pub(crate) struct DuplexKey<App: ApplicationLayer> {
    send: Keys,
    recv: Keys,
    nk: Option<App::AeadPool>,
}
impl<App: ApplicationLayer> Default for DuplexKey<App> {
    fn default() -> Self {
        Self { send: Default::default(), recv: Default::default(), nk: None }
    }
}
impl<App: ApplicationLayer> DuplexKey<App> {
    fn replace_nk(&mut self, nk_send: &[u8; HASHLEN], nk_recv: &[u8; HASHLEN]) {
        self.nk = Some(App::AeadPool::new(
            (&nk_send[..AES_256_KEY_SIZE]).try_into().unwrap(),
            (&nk_recv[..AES_256_KEY_SIZE]).try_into().unwrap(),
        ))
    }
}

#[derive(Default)]
pub(crate) struct Keys {
    kek: Option<Zeroizing<[u8; AES_256_KEY_SIZE]>>,
    kid: Option<NonZeroU32>,
}
impl Keys {
    fn replace_kek(&mut self, kek: &[u8; HASHLEN]) {
        // We want to give rust the best chance of implementing this in a way that does
        // not leak the key on the stack.
        self.kek
            .get_or_insert(Zeroizing::new([0u8; AES_256_KEY_SIZE]))
            .copy_from_slice(&kek[..AES_256_KEY_SIZE]);
    }
}

/// Corresponds to State A_1 of the Zeta State Machine found in Section 4.1.
#[derive(Clone)]
pub(crate) struct StateA1<App: ApplicationLayer> {
    noise: SymmetricState<App>,
    e_secret: App::KeyPair,
    e1_secret: App::Kem,
    identity: ArrayVec<u8, IDENTITY_MAX_SIZE>,
    x1: ArrayVec<u8, HEADERED_HANDSHAKE_HELLO_CHALLENGE_MAX_SIZE>,
}

pub(crate) struct StateA3 {
    identity: ArrayVec<u8, IDENTITY_MAX_SIZE>,
    x3: ArrayVec<u8, HEADERED_HANDSHAKE_COMPLETION_MAX_SIZE>,
}

/// Corresponds to the ZKE Automata found in Section 4.1 - Definition 2.
pub(crate) enum ZetaAutomata<App: ApplicationLayer> {
    Null,
    A1(Box<StateA1<App>>),
    A3(Box<StateA3>),
    S1,
    S2,
    R1 {
        noise: SymmetricState<App>,
        e_secret: App::KeyPair,
        k1: ArrayVec<u8, REKEY_SIZE>,
    },
    R2 {
        k2: ArrayVec<u8, REKEY_SIZE>,
    },
}

impl<App: ApplicationLayer> SymmetricState<App> {
    fn write_e<const CAP: usize>(
        &mut self,
        hash: &mut App::Hash,
        hmac: &mut App::Hmac,
        rng: &Mutex<App::Rng>,
        packet: &mut ArrayVec<u8, CAP>,
    ) -> App::KeyPair {
        let e_secret = App::KeyPair::generate(rng.lock().unwrap().deref_mut());
        let pub_key = e_secret.public_key_bytes();
        packet.extend(pub_key);
        self.mix_hash(hash, &pub_key);
        self.mix_key(hmac, &pub_key);
        e_secret
    }
    fn read_e(
        &mut self,
        hash: &mut App::Hash,
        hmac: &mut App::Hmac,
        i: &mut usize,
        packet: &[u8],
    ) -> Option<App::PublicKey> {
        let j = *i + P384_PUBLIC_KEY_SIZE;
        let pub_key = &packet[*i..j];
        self.mix_hash(hash, pub_key);
        self.mix_key(hmac, pub_key);
        *i = j;
        App::PublicKey::from_bytes((pub_key).try_into().unwrap())
    }
    fn write_e_no_init<const CAP: usize>(
        &mut self,
        hash: &mut App::Hash,
        hmac: &mut App::Hmac,
        rng: &Mutex<App::Rng>,
        packet: &mut ArrayVec<u8, CAP>,
    ) -> App::KeyPair {
        let e_secret = App::KeyPair::generate(rng.lock().unwrap().deref_mut());
        let pub_key = e_secret.public_key_bytes();
        packet.extend(pub_key);
        self.mix_hash(hash, &pub_key);
        self.mix_key_no_init(hmac, &pub_key);
        e_secret
    }
    fn read_e_no_init(
        &mut self,
        hash: &mut App::Hash,
        hmac: &mut App::Hmac,
        i: &mut usize,
        packet: &[u8],
    ) -> Option<App::PublicKey> {
        let j = *i + P384_PUBLIC_KEY_SIZE;
        let pub_key = &packet[*i..j];
        self.mix_hash(hash, pub_key);
        self.mix_key_no_init(hmac, pub_key);
        *i = j;
        App::PublicKey::from_bytes((pub_key).try_into().unwrap())
    }
    fn mix_dh(&mut self, hmac: &mut App::Hmac, secret: &App::KeyPair, remote: &App::PublicKey) -> Option<()> {
        let mut ecdh_secret = Zeroizing::new([0u8; P384_ECDH_SHARED_SECRET_SIZE]);
        if secret.agree(&remote, &mut ecdh_secret) {
            self.mix_key(hmac, ecdh_secret.as_ref());
            Some(())
        } else {
            None
        }
    }
    fn mix_dh_no_init(
        &mut self,
        hmac: &mut App::Hmac,
        secret: &App::KeyPair,
        remote: &App::PublicKey,
    ) -> Option<()> {
        let mut ecdh_secret = Zeroizing::new([0u8; P384_ECDH_SHARED_SECRET_SIZE]);
        if secret.agree(&remote, &mut ecdh_secret) {
            self.mix_key_no_init(hmac, ecdh_secret.as_ref());
            Some(())
        } else {
            None
        }
    }
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

impl<App: ApplicationLayer> MutableState<App> {
    fn key_ref(&self, is_next: bool) -> &DuplexKey<App> {
        &self.keys[(self.key_index ^ is_next) as usize]
    }
    fn key_mut(&mut self, is_next: bool) -> &mut DuplexKey<App> {
        &mut self.keys[(self.key_index ^ is_next) as usize]
    }
}

fn set_header(packet: &mut [u8], kid_send: u32, nonce: &[u8; AES_GCM_NONCE_SIZE]) {
    packet[..KID_SIZE].copy_from_slice(&kid_send.to_be_bytes());
    packet[PACKET_NONCE_START..HEADER_SIZE].copy_from_slice(&nonce[NONCE_SIZE_DIFF..]);
}

fn create_a1_state<App: ApplicationLayer>(
    hash: &mut App::Hash,
    hmac: &mut App::Hmac,
    rng: &Mutex<App::Rng>,
    s_remote: &App::PublicKey,
    kid_recv: NonZeroU32,
    ratchet_state1: &RatchetState,
    ratchet_state2: Option<&RatchetState>,
    identity: &[u8],
) -> Option<Box<StateA1<App>>> {
    //    <- s
    //    ...
    //    -> e, es, e1
    let mut noise = SymmetricState::<App>::initialize(PROTOCOL_NAME_NOISE_XK);
    let mut x1 = ArrayVec::<u8, HEADERED_HANDSHAKE_HELLO_CHALLENGE_MAX_SIZE>::new();
    x1.extend([0u8; HEADER_SIZE]);
    // Noise process prologue.
    let kid = kid_recv.get().to_be_bytes();
    x1.extend(kid);
    noise.mix_hash(hash, &kid);
    noise.mix_hash(hash, &s_remote.to_bytes());
    // Process message pattern 1 e token.
    let e_secret = noise.write_e(hash, hmac, rng, &mut x1);
    // Process message pattern 1 es token.
    noise.mix_dh(hmac, &e_secret, s_remote)?;
    // Process message pattern 1 e1 token.
    let i = x1.len();
    let (e1_secret, e1_public) = App::Kem::generate(rng.lock().unwrap().deref_mut());
    x1.extend(e1_public);
    x1.extend([0u8; AES_GCM_NONCE_SIZE]);
    let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 0), &mut x1[i..]);
    x1.extend(tag);
    // Process message pattern 1 payload.
    let i = x1.len();
    if let Some(rf) = ratchet_state1.fingerprint() {
        x1.try_extend_from_slice(rf).unwrap();
    }
    if let Some(Some(rf)) = ratchet_state2.map(|rs| rs.fingerprint()) {
        x1.try_extend_from_slice(rf).unwrap();
    }
    let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 1), &mut x1[i..]);
    x1.extend(tag);

    let c = u64::from_be_bytes(x1[x1.len() - 8..].try_into().unwrap());

    // Process challenge
    x1.extend(gen_null_response(rng.lock().unwrap().deref_mut()));

    set_header(&mut x1, 0, &to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, c));

    Some(Box::new(StateA1 {
        noise,
        e_secret,
        e1_secret,
        identity: identity.try_into().unwrap(),
        x1,
    }))
}
/// Corresponds to Transition Algorithm 1 found in Section 4.3.
pub(crate) fn trans_to_a1<App: ApplicationLayer>(
    app: App,
    ctx: &Arc<ContextInner<App>>,
    s_remote: App::PublicKey,
    session_data: App::SessionData,
    identity: &[u8],
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Result<Arc<Session<App>>, OpenError<App::StorageError>> {
    let RatchetStates { state1, state2 } = app
        .restore_by_identity(&s_remote, &session_data)
        .map_err(|e| OpenError::RatchetIoError(e))?
        .unwrap_or_default();

    let mut session_queue = ctx.session_queue.lock().unwrap();
    let mut session_map = ctx.session_map.write().unwrap();
    let kid_recv = gen_kid(session_map.deref(), ctx.rng.lock().unwrap().deref_mut());

    let hash = &mut App::Hash::new();
    let hmac = &mut App::Hmac::new();
    let a1 = create_a1_state(
        hash,
        hmac,
        &ctx.rng,
        &s_remote,
        kid_recv,
        &state1,
        state2.as_ref(),
        identity,
    )
    .ok_or(OpenError::InvalidPublicKey)?;

    let mut noise_kk_ss = Zeroizing::new([0u8; P384_ECDH_SHARED_SECRET_SIZE]);
    if !ctx.s_secret.agree(&s_remote, &mut noise_kk_ss) {
        return Err(OpenError::InvalidPublicKey);
    }

    let mut hk_recv = Zeroizing::new([0u8; HASHLEN]);
    let mut hk_send = Zeroizing::new([0u8; HASHLEN]);
    a1.noise.get_ask(hmac, LABEL_HEADER_KEY, &mut hk_recv, &mut hk_send);

    let mut x1 = a1.x1.clone();

    let current_time = app.time();
    let queue_idx = session_queue.reserve_index();
    let resend_timer = current_time + App::SETTINGS.resend_time as i64;
    let session = Arc::new(Session {
        ctx: Arc::downgrade(ctx),
        session_data,
        was_bob: false,
        queue_idx,
        s_remote,
        send_counter: AtomicU64::new(0),
        session_has_expired: AtomicBool::new(false),
        window: Window::new(),
        state_machine_lock: Mutex::new(()),
        state: RwLock::new(MutableState {
            ratchet_state1: state1.clone(),
            ratchet_state2: state2.clone(),
            hk_send: App::PrpEnc::new((&hk_send[..AES_256_KEY_SIZE]).try_into().unwrap()),
            hk_recv: App::PrpDec::new((&hk_recv[..AES_256_KEY_SIZE]).try_into().unwrap()),
            key_creation_counter: 0,
            key_index: true,
            keys: [DuplexKey::default(), DuplexKey::default()],
            resend_timer: AtomicI64::new(resend_timer),
            timeout_timer: current_time + App::SETTINGS.initial_offer_timeout as i64,
            beta: ZetaAutomata::A1(a1),
        }),
        noise_kk_ss: noise_kk_ss.clone(),
        defrag: std::array::from_fn(|_| Mutex::new(Fragged::new())),
    });
    {
        let mut state = session.state.write().unwrap();
        state.key_mut(true).recv.kid = Some(kid_recv);
    }

    session_map.insert(kid_recv, Arc::downgrade(&session));
    session_queue.push_reserved(queue_idx, Arc::downgrade(&session), Reverse(resend_timer));

    send(&mut x1, None);

    Ok(session)
}
/// Corresponds to Algorithm 13 found in Section 5.
pub(crate) fn respond_to_challenge<App: ApplicationLayer>(
    ctx: &Arc<ContextInner<App>>,
    session: &Session<App>,
    challenge: &[u8; CHALLENGE_SIZE],
) {
    let mut state = session.state.write().unwrap();
    if let ZetaAutomata::A1(a1) = &mut state.beta {
        let response_start = a1.x1.len() - CHALLENGE_SIZE;
        respond_to_challenge_in_place(
            ctx.rng.lock().unwrap().deref_mut(),
            &mut App::Hash::new(),
            challenge,
            (&mut a1.x1[response_start..]).try_into().unwrap(),
        );
    }
}
/// Corresponds to Transition Algorithm 2 found in Section 4.3.
pub(crate) fn received_x1_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &ContextInner<App>,
    hash: &mut App::Hash,
    n: &[u8; AES_GCM_NONCE_SIZE],
    x1: &mut [u8],
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Result<(), ReceiveError<App::StorageError>> {
    use FaultType::*;
    //    <- s
    //    ...
    //    -> e, es, e1
    //    <- e, ee, ekem1, psk
    if !(HANDSHAKE_HELLO_CHALLENGE_MIN_SIZE..=HANDSHAKE_HELLO_CHALLENGE_MAX_SIZE).contains(&x1.len()) {
        return Err(byzantine_fault!(InvalidPacket, true));
    }

    if &n[AES_GCM_NONCE_SIZE - 8..] != &x1[x1.len() - 8..] {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let hmac = &mut App::Hmac::new();
    let mut noise = SymmetricState::<App>::initialize(PROTOCOL_NAME_NOISE_XK);
    let mut i = 0;
    // Noise process prologue.
    let j = i + KID_SIZE;
    noise.mix_hash(hash, &x1[i..j]);
    let kid_send = NonZeroU32::new(u32::from_be_bytes(x1[i..j].try_into().unwrap()))
        .ok_or(byzantine_fault!(InvalidPacket, true))?;
    noise.mix_hash(hash, &ctx.s_secret.public_key_bytes());
    i = j;
    // Process message pattern 1 e token.
    let e_remote = noise
        .read_e(hash, hmac, &mut i, &x1)
        .ok_or(byzantine_fault!(FailedAuth, true))?;
    // Process message pattern 1 es token.
    noise
        .mix_dh(hmac, &ctx.s_secret, &e_remote)
        .ok_or(byzantine_fault!(FailedAuth, true))?;
    // Process message pattern 1 e1 token.
    let j = i + KYBER_PUBLIC_KEY_SIZE;
    let k = i + AES_GCM_TAG_SIZE;
    let tag = x1[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 0), &mut x1[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let e1_start = i;
    let e1_end = j;
    i = j;
    // Process message pattern 1 payload.
    let k = x1.len();
    let j = k - AES_GCM_TAG_SIZE;
    let tag = x1[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_HELLO, 1), &mut x1[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }

    let mut ratchet_state = None;
    while i + RATCHET_SIZE <= j {
        match app.restore_by_fingerprint((&x1[i..i + RATCHET_SIZE]).try_into().unwrap()) {
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
    let mut hk_recv = Zeroizing::new([0u8; HASHLEN]);
    let mut hk_send = Zeroizing::new([0u8; HASHLEN]);
    noise.get_ask(hmac, LABEL_HEADER_KEY, &mut hk_recv, &mut hk_send);

    let mut x2 = ArrayVec::<u8, HEADERED_HANDSHAKE_RESPONSE_SIZE>::new();
    x2.extend([0u8; HEADER_SIZE]);
    // Process message pattern 2 e token.
    let e_secret = noise.write_e(hash, hmac, &ctx.rng, &mut x2);
    // Process message pattern 2 ee token.
    noise
        .mix_dh(hmac, &e_secret, &e_remote)
        .ok_or(byzantine_fault!(FailedAuth, true))?;
    // Process message pattern 2 ekem1 token.
    {
        let i = x2.len();
        let mut ekem1_secret = Zeroizing::new([0u8; KYBER_PLAINTEXT_SIZE]);
        let ekem1 = App::Kem::encapsulate(
            ctx.rng.lock().unwrap().deref_mut(),
            (&x1[e1_start..e1_end]).try_into().unwrap(),
            &mut ekem1_secret,
        )
        .ok_or(byzantine_fault!(FailedAuth, true))?;
        x2.extend(ekem1);
        let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), &mut x2[i..]);
        x2.extend(tag);
        noise.mix_key(hmac, ekem1_secret.as_ref());
    }
    // Process message pattern 2 psk2 token.
    noise.mix_key_and_hash(hash, hmac, ratchet_state.key.as_ref());
    // Process message pattern 2 payload.
    let kid_recv = gen_kid(
        ctx.session_map.read().unwrap().deref(),
        ctx.rng.lock().unwrap().deref_mut(),
    );

    let i = x2.len();
    x2.extend(kid_recv.get().to_be_bytes());
    let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), &mut x2[i..]);
    x2.extend(tag);

    let i = x2.len();
    let mut c = 0u64.to_be_bytes();
    c[5] = x2[i - 3];
    c[6] = x2[i - 2];
    c[7] = x2[i - 1];
    let c = u64::from_be_bytes(c);

    set_header(&mut x2, kid_send.get(), &to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, c));

    ctx.unassociated_handshake_states.insert(
        kid_recv,
        Arc::new(StateB2 {
            ratchet_state,
            kid_send,
            kid_recv,
            hk_send: Zeroizing::new(hk_send[..AES_256_KEY_SIZE].try_into().unwrap()),
            hk_recv: Zeroizing::new(hk_recv[..AES_256_KEY_SIZE].try_into().unwrap()),
            e_secret,
            noise,
            defrag: Mutex::new(Fragged::new()),
        }),
        app.time(),
    );

    send(
        &mut x2,
        Some(&App::PrpEnc::new(&hk_send[..AES_256_KEY_SIZE].try_into().unwrap())),
    );
    Ok(())
}
/// Corresponds to Transition Algorithm 3 found in Section 4.3.
pub(crate) fn received_x2_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    kid: NonZeroU32,
    n: &[u8; AES_GCM_NONCE_SIZE],
    x2: &mut [u8],
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Result<(), ReceiveError<App::StorageError>> {
    use FaultType::*;
    //    <- e, ee, ekem1, psk
    //    -> s, se
    if HANDSHAKE_RESPONSE_SIZE != x2.len() {
        return Err(byzantine_fault!(InvalidPacket, true));
    }

    let kex_lock = session.state_machine_lock.lock().unwrap();
    let state = session.state.read().unwrap();
    let hash = &mut App::Hash::new();
    let hmac = &mut App::Hmac::new();

    if Some(kid) != state.key_ref(true).recv.kid {
        return Err(byzantine_fault!(UnknownLocalKeyId, true));
    }
    let (_, c) = from_nonce(n);
    if c >= COUNTER_WINDOW_MAX_SKIP_AHEAD || &n[AES_GCM_NONCE_SIZE - 3..] != &x2[x2.len() - 3..] {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let mut result = (|| {
        let a1 = if let ZetaAutomata::A1(a1) = &state.beta {
            a1
        } else {
            return Err(byzantine_fault!(FailedAuth, true));
        };
        let mut noise = a1.noise.clone();
        let mut i = 0;
        // Process message pattern 2 e token.
        let e_remote = noise
            .read_e(hash, hmac, &mut i, &x2)
            .ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 2 ee token.
        noise
            .mix_dh(hmac, &a1.e_secret, &e_remote)
            .ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 2 ekem1 token.
        let j = i + KYBER_CIPHERTEXT_SIZE;
        let k = j + AES_GCM_TAG_SIZE;
        let tag = x2[j..k].try_into().unwrap();
        if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), &mut x2[i..j], tag) {
            return Err(byzantine_fault!(FailedAuth, true));
        }
        let mut ekem1_secret = Zeroizing::new([0u8; KYBER_PLAINTEXT_SIZE]);
        if !a1
            .e1_secret
            .decapsulate((&x2[i..j]).try_into().unwrap(), &mut ekem1_secret)
        {
            return Err(byzantine_fault!(FailedAuth, true));
        }
        noise.mix_key(hmac, ekem1_secret.as_ref());
        drop(ekem1_secret);
        i = j;
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
        let mut test_ratchet_key = |ratchet_key| -> Option<(NonZeroU32, SymmetricState<App>)> {
            let mut noise = noise.clone();
            let mut payload = payload.clone();
            // Process message pattern 2 psk token.
            noise.mix_key_and_hash(hash, hmac, ratchet_key);
            // Process message pattern 2 payload.
            if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_RESPONSE, 0), &mut payload, tag) {
                return None;
            }
            NonZeroU32::new(u32::from_be_bytes(payload)).map(|kid2| (kid2, noise))
        };
        // Check first key.
        let mut ratchet_i = 1;
        let mut chain_len = state.ratchet_state1.chain_len;
        let mut result = test_ratchet_key(state.ratchet_state1.key.as_ref());
        // Check second key.
        if result.is_none() {
            ratchet_i = 2;
            if let Some(rs) = state.ratchet_state2.as_ref() {
                chain_len = rs.chain_len;
                result = test_ratchet_key(rs.key.as_ref());
            }
        }
        // Check zero key.
        if result.is_none() && !app.initiator_disallows_downgrade(session) {
            chain_len = 0;
            result = test_ratchet_key(&[0u8; RATCHET_SIZE]);
            if result.is_some() {
                // TODO: add some kind of warning callback or signal.
            }
        }

        let (kid_send, mut noise) = result.ok_or(byzantine_fault!(FailedAuth, true))?;

        let mut x3 = ArrayVec::<u8, HEADERED_HANDSHAKE_COMPLETION_MAX_SIZE>::new();
        x3.extend([0u8; HEADER_SIZE]);
        // Process message pattern 3 s token.
        let i = x3.len();
        x3.extend(ctx.s_secret.public_key_bytes());
        let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 1), &mut x3[i..]);
        x3.extend(tag);
        // Process message pattern 3 se token.
        noise
            .mix_dh(hmac, &ctx.s_secret, &e_remote)
            .ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 3 payload.
        let i = x3.len();
        x3.try_extend_from_slice(&a1.identity).unwrap();
        let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 0), &mut x3[i..]);
        x3.extend(tag);

        let new_ratchet_state = create_ratchet_state(hmac, &mut noise, chain_len);

        let (ratchet_to_preserve, ratchet_to_delete) = if ratchet_i == 1 {
            (Some(&state.ratchet_state1), state.ratchet_state2.as_ref())
        } else {
            (state.ratchet_state2.as_ref(), Some(&state.ratchet_state1))
        };
        let result = app.save_ratchet_state(
            &session.s_remote,
            &session.session_data,
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

        let mut kek_recv = Zeroizing::new([0u8; HASHLEN]);
        let mut kek_send = Zeroizing::new([0u8; HASHLEN]);
        let mut nk_recv = Zeroizing::new([0u8; HASHLEN]);
        let mut nk_send = Zeroizing::new([0u8; HASHLEN]);
        noise.get_ask(hmac, LABEL_KEX_KEY, &mut kek_recv, &mut kek_send);
        noise.split(hmac, &mut nk_recv, &mut nk_send);

        let nonce = to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 0);
        set_header(&mut x3, kid_send.get(), &nonce);

        drop(state);
        let resend_timer = {
            let mut state = session.state.write().unwrap();
            state.key_mut(true).send.kid = Some(kid_send);
            state.key_mut(true).send.replace_kek(&kek_send);
            state.key_mut(true).recv.replace_kek(&kek_recv);
            state.key_mut(true).replace_nk(&nk_send, &nk_recv);
            state.ratchet_state2 = Some(state.ratchet_state1.clone());
            state.ratchet_state1 = new_ratchet_state.clone();
            let current_time = app.time();
            state.key_creation_counter = session.send_counter.load(Ordering::Relaxed);
            let resend_timer = current_time + App::SETTINGS.resend_time as i64;
            state.resend_timer = AtomicI64::new(resend_timer);
            state.timeout_timer = current_time + App::SETTINGS.initial_offer_timeout as i64;
            let a1 = if let ZetaAutomata::A1(a1) = &state.beta {
                a1
            } else {
                // This return is unreachable.
                return Err(byzantine_fault!(FailedAuth, true));
            };
            state.beta = ZetaAutomata::A3(Box::new(StateA3 { identity: a1.identity.clone(), x3: x3.clone() }));
            resend_timer
        };
        drop(kex_lock);
        ctx.session_queue
            .lock()
            .unwrap()
            .change_priority(session.queue_idx, Reverse(resend_timer));

        Ok(x3)
    })();

    match result {
        Err(ReceiveError::ByzantineFault { .. }) => {
            let kex_lock = session.state_machine_lock.lock().unwrap();
            let state = session.state.read().unwrap();
            timeout_trans(app, ctx, session, kex_lock, state, app.time(), send);
        }
        Ok(ref mut packet) => send(packet, Some(&session.state.read().unwrap().hk_send)),
        _ => {}
    }
    result.map(|_| ())
}
fn send_control<App: ApplicationLayer, const CAP: usize>(
    session: &Arc<Session<App>>,
    state: &MutableState<App>,
    packet_type: u8,
    mut payload: ArrayVec<u8, CAP>,
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> bool {
    if let Some((c, _)) = get_counter(session, &state) {
        if let (Some(kek), Some(kid)) = (state.key_ref(false).send.kek.as_ref(), state.key_ref(false).send.kid) {
            let nonce = to_nonce(packet_type, c);
            let tag = App::Aead::encrypt_in_place(kek, &nonce, &[], &mut payload[HEADER_SIZE..]);
            payload.extend(tag);
            set_header(&mut payload, kid.get(), &nonce);
            send(&mut payload, Some(&state.hk_send));
            true
        } else {
            false
        }
    } else {
        false
    }
}
/// Corresponds to Transition Algorithm 4 found in Section 4.3.
pub(crate) fn received_x3_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    zeta: Arc<StateB2<App>>,
    kid: NonZeroU32,
    x3: &mut [u8],
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Result<Arc<Session<App>>, ReceiveError<App::StorageError>> {
    use FaultType::*;
    //    -> s, se
    if x3.len() < HANDSHAKE_COMPLETION_MIN_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }
    if kid != zeta.kid_recv {
        return Err(byzantine_fault!(UnknownLocalKeyId, true));
    }
    let hash = &mut App::Hash::new();
    let hmac = &mut App::Hmac::new();

    let mut noise = zeta.noise.clone();
    let mut i = 0;
    // Process message pattern 3 s token.
    let j = i + P384_PUBLIC_KEY_SIZE;
    let k = j + AES_GCM_TAG_SIZE;
    let tag = x3[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 1), &mut x3[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let s_remote =
        App::PublicKey::from_bytes((&x3[i..j]).try_into().unwrap()).ok_or(byzantine_fault!(FailedAuth, true))?;
    i = k;
    // Process message pattern 3 se token.
    noise
        .mix_dh(hmac, &zeta.e_secret, &s_remote)
        .ok_or(byzantine_fault!(FailedAuth, true))?;
    // Process message pattern 3 payload.
    let k = x3.len();
    let j = k - AES_GCM_TAG_SIZE;
    let tag = x3[j..k].try_into().unwrap();
    if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_HANDSHAKE_COMPLETION, 0), &mut x3[i..j], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let identity_start = i;
    let identity_end = j;

    let mut kek_recv = Zeroizing::new([0u8; HASHLEN]);
    let mut kek_send = Zeroizing::new([0u8; HASHLEN]);
    noise.get_ask(hmac, LABEL_KEX_KEY, &mut kek_send, &mut kek_recv);
    let c = 0;

    let action = app.check_accept_session(&s_remote, &x3[identity_start..identity_end]);
    let responder_disallows_downgrade = action.responder_disallows_downgrade;
    let responder_silently_rejects = action.responder_silently_rejects;
    let session_data = action.session_data;
    let create_reject = || {
        // We just used a counter with this key, but we are not storing
        // the fact we used it in memory. This is currently ok because the
        // handshake is being dropped, so nonce reuse can't happen.
        let mut d = ArrayVec::<u8, HEADERED_SESSION_REJECTED_SIZE>::new();
        d.extend([0u8; HEADER_SIZE]);
        let nonce = to_nonce(PACKET_TYPE_SESSION_REJECTED, c);
        d.extend(App::Aead::encrypt_in_place(
            (&kek_send[..AES_256_KEY_SIZE]).try_into().unwrap(),
            &nonce,
            &[],
            &mut [],
        ));
        set_header(&mut d, zeta.kid_send.get(), &nonce);
        d
    };
    if let Some(session_data) = session_data {
        let result = app.restore_by_identity(&s_remote, &session_data);
        match result {
            Ok(rss) => {
                let RatchetStates { state1, state2 } = rss.unwrap_or_default();
                if (&zeta.ratchet_state != &state1) & (Some(&zeta.ratchet_state) != state2.as_ref()) {
                    if !responder_disallows_downgrade && zeta.ratchet_state.fingerprint().is_none() {
                        // TODO: add some kind of warning callback or signal.
                    } else {
                        if !responder_silently_rejects {
                            send(&mut create_reject(), Some(&App::PrpEnc::new(&zeta.hk_send)))
                        }
                        return Err(byzantine_fault!(FailedAuth, true));
                    }
                }

                let mut noise_kk_ss = Zeroizing::new([0u8; P384_ECDH_SHARED_SECRET_SIZE]);
                if !ctx.s_secret.agree(&s_remote, &mut noise_kk_ss) {
                    return Err(byzantine_fault!(FailedAuth, true));
                }

                let new_ratchet_state = create_ratchet_state(hmac, &mut noise, zeta.ratchet_state.chain_len);
                let mut nk_recv = Zeroizing::new([0u8; HASHLEN]);
                let mut nk_send = Zeroizing::new([0u8; HASHLEN]);
                noise.split(hmac, &mut nk_send, &mut nk_recv);

                // We must make sure the ratchet key is saved before we transition.
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

                let session = {
                    let mut session_map = ctx.session_map.write().unwrap();
                    use std::collections::hash_map::Entry::*;
                    let entry = match session_map.entry(zeta.kid_recv) {
                        // We could have issued the kid that we initially offered Alice to someone else
                        // before Alice was able to respond. It is unlikely but possible.
                        Occupied(_) => return Err(byzantine_fault!(OutOfSequence, false)),
                        Vacant(entry) => entry,
                    };
                    let mut session_queue = ctx.session_queue.lock().unwrap();
                    let queue_idx = session_queue.reserve_index();
                    let current_time = app.time();
                    let resend_timer = current_time + App::SETTINGS.resend_time as i64;
                    let session = Arc::new(Session {
                        ctx: Arc::downgrade(ctx),
                        session_data,
                        was_bob: true,
                        s_remote,
                        send_counter: AtomicU64::new(c + 1),
                        session_has_expired: AtomicBool::new(false),
                        state_machine_lock: Mutex::new(()),
                        state: RwLock::new(MutableState {
                            ratchet_state1: new_ratchet_state.clone(),
                            ratchet_state2: None,
                            hk_send: App::PrpEnc::new(&zeta.hk_send),
                            hk_recv: App::PrpDec::new(&zeta.hk_recv),
                            key_creation_counter: c + 1,
                            key_index: false,
                            keys: [DuplexKey::default(), DuplexKey::default()],
                            resend_timer: AtomicI64::new(resend_timer),
                            timeout_timer: current_time + App::SETTINGS.rekey_timeout as i64,
                            beta: ZetaAutomata::S1,
                        }),
                        window: Window::new(),
                        queue_idx,
                        noise_kk_ss: noise_kk_ss.clone(),
                        defrag: std::array::from_fn(|_| Mutex::new(Fragged::new())),
                    });
                    {
                        let mut state = session.state.write().unwrap();
                        state.key_mut(false).replace_nk(&nk_send, &nk_recv);
                        state.key_mut(false).recv.kid = Some(zeta.kid_recv);
                        state.key_mut(false).recv.replace_kek(&kek_recv);
                        state.key_mut(false).send.kid = Some(zeta.kid_send);
                        state.key_mut(false).send.replace_kek(&kek_send);
                    }

                    session_queue.push_reserved(queue_idx, Arc::downgrade(&session), Reverse(resend_timer));
                    entry.insert(Arc::downgrade(&session));

                    session
                };
                let state = session.state.read().unwrap();
                let mut c1 = ArrayVec::<u8, HEADERED_KEY_CONFIRMATION_SIZE>::new();
                c1.extend([0u8; HEADER_SIZE]);
                send_control(&session, &state, PACKET_TYPE_KEY_CONFIRM, c1, send);
                drop(state);

                Ok(session)
            }
            Err(e) => Err(ReceiveError::StorageError(e)),
        }
    } else {
        if !responder_silently_rejects {
            send(&mut create_reject(), Some(&App::PrpEnc::new(&zeta.hk_send)))
        }
        Err(ReceiveError::Rejected)
    }
}
/// Corresponds to Transition Algorithm 5 found in Section 4.3.
pub(crate) fn received_c1_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    kid: NonZeroU32,
    n: &[u8; AES_GCM_NONCE_SIZE],
    c1: &[u8],
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Result<bool, ReceiveError<App::StorageError>> {
    use FaultType::*;

    if c1.len() != KEY_CONFIRMATION_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }

    let kex_lock = session.state_machine_lock.lock().unwrap();
    let mut state = session.state.read().unwrap();

    let is_other = if Some(kid) == state.key_ref(true).recv.kid {
        true
    } else if Some(kid) == state.key_ref(false).recv.kid {
        false
    } else {
        // Some key confirmation may have arrived extremely delayed.
        // It is unlikely but possible.
        return Err(byzantine_fault!(OutOfSequence, false));
    };

    let specified_key = state.key_ref(is_other).recv.kek.as_ref();
    let specified_key = specified_key.ok_or(byzantine_fault!(OutOfSequence, true))?;
    let tag = c1[..].try_into().unwrap();
    if !App::Aead::decrypt_in_place(specified_key, n, &[], &mut [], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(n);
    if !session.window.update(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }

    let just_establised = is_other && matches!(&state.beta, ZetaAutomata::A3 { .. });
    if is_other {
        if let ZetaAutomata::A3 { .. } | ZetaAutomata::R2 { .. } = &state.beta {
            if state.ratchet_state2.is_some() {
                let result = app.save_ratchet_state(
                    &session.s_remote,
                    &session.session_data,
                    RatchetUpdate {
                        state1: &state.ratchet_state1,
                        state2: None,
                        state1_was_just_added: false,
                        deleted_state1: state.ratchet_state2.as_ref(),
                        deleted_state2: None,
                    },
                );
                if let Err(e) = result {
                    return Err(ReceiveError::StorageError(e));
                }
            }
            drop(state);
            let timeout_timer = {
                let mut state = session.state.write().unwrap();
                state.ratchet_state2 = None;
                state.key_index ^= true;
                state.timeout_timer = app.time()
                    + App::SETTINGS
                        .rekey_after_time
                        .saturating_sub(ctx.rng.lock().unwrap().next_u64() % App::SETTINGS.rekey_time_max_jitter)
                        as i64;
                state.resend_timer = AtomicI64::new(i64::MAX);
                state.beta = ZetaAutomata::S2;
                state.timeout_timer
            };
            drop(kex_lock);
            ctx.session_queue
                .lock()
                .unwrap()
                .change_priority(session.queue_idx, Reverse(timeout_timer));
            state = session.state.read().unwrap();
        }
    }

    let mut c2 = ArrayVec::<u8, HEADERED_ACKNOWLEDGEMENT_SIZE>::new();
    c2.extend([0u8; HEADER_SIZE]);
    if !send_control(session, &state, PACKET_TYPE_ACK, c2, send) {
        return Err(byzantine_fault!(OutOfSequence, true));
    }

    Ok(just_establised)
}
/// Corresponds to the trivial Transition Algorithm described for processing C_2 packets found in
/// Section 4.3.
pub(crate) fn received_c2_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    kid: NonZeroU32,
    n: &[u8; AES_GCM_NONCE_SIZE],
    c2: &[u8],
) -> Result<(), ReceiveError<App::StorageError>> {
    use FaultType::*;

    if c2.len() != ACKNOWLEDGEMENT_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }

    let kex_lock = session.state_machine_lock.lock().unwrap();
    let state = session.state.read().unwrap();

    if Some(kid) != state.key_ref(false).recv.kid {
        // Some acknowledgement may have arrived extremely delayed.
        return Err(byzantine_fault!(UnknownLocalKeyId, false));
    }
    if !matches!(&state.beta, ZetaAutomata::S1) {
        // Some acknowledgement may have arrived extremely delayed.
        return Err(byzantine_fault!(OutOfSequence, false));
    }

    let tag = c2[..].try_into().unwrap();
    if !App::Aead::decrypt_in_place(state.key_ref(false).recv.kek.as_ref().unwrap(), n, &[], &mut [], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(n);
    if !session.window.update(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }
    drop(state);
    let timeout_timer = {
        let mut state = session.state.write().unwrap();
        state.timeout_timer = app.time()
            + App::SETTINGS
                .rekey_after_time
                .saturating_sub(ctx.rng.lock().unwrap().next_u64() % App::SETTINGS.rekey_time_max_jitter)
                as i64;
        state.resend_timer = AtomicI64::new(i64::MAX);
        state.beta = ZetaAutomata::S2;
        state.timeout_timer
    };
    drop(kex_lock);
    ctx.session_queue
        .lock()
        .unwrap()
        .change_priority(session.queue_idx, Reverse(timeout_timer));
    Ok(())
}
/// Corresponds to the trivial Transition Algorithm described for processing D packets found in
/// Section 4.3.
pub(crate) fn received_d_trans<App: ApplicationLayer>(
    session: &Arc<Session<App>>,
    kid: NonZeroU32,
    n: &[u8; AES_GCM_NONCE_SIZE],
    d: &[u8],
) -> Result<(), ReceiveError<App::StorageError>> {
    use FaultType::*;

    if d.len() != SESSION_REJECTED_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }

    let kex_lock = session.state_machine_lock.lock().unwrap();
    let state = session.state.read().unwrap();

    if Some(kid) != state.key_ref(true).recv.kid || !matches!(&state.beta, ZetaAutomata::A3 { .. }) {
        return Err(byzantine_fault!(OutOfSequence, true));
    }

    let tag = d[..].try_into().unwrap();
    if !App::Aead::decrypt_in_place(state.key_ref(true).recv.kek.as_ref().unwrap(), n, &[], &mut [], tag) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(n);
    if !session.window.update(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }

    drop(state);
    drop(kex_lock);
    session.expire();
    Ok(())
}
// Corresponds to the timeout timer Transition Algorithm described in Section 4.1 - Definition 3.
fn timeout_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    kex_lock: MutexGuard<'_, ()>,
    state: RwLockReadGuard<'_, MutableState<App>>,
    current_time: i64,
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Option<i64> {
    match &state.beta {
        ZetaAutomata::Null => None,
        ZetaAutomata::A1(_) | ZetaAutomata::A3 { .. } => {
            let identity = match &state.beta {
                ZetaAutomata::A1(a1) => &a1.identity,
                ZetaAutomata::A3(a3) => &a3.identity,
                _ => unreachable!(),
            };
            if matches!(&state.beta, ZetaAutomata::A1(_)) {
                log!(app, TimeoutX1(session));
            } else {
                log!(app, TimeoutX3(session));
            }
            let new_kid_recv = remap(ctx, session, &state);

            let hash = &mut App::Hash::new();
            let hmac = &mut App::Hmac::new();
            if let Some(a1) = create_a1_state(
                hash,
                hmac,
                &ctx.rng,
                &session.s_remote,
                new_kid_recv,
                &state.ratchet_state1,
                state.ratchet_state2.as_ref(),
                identity,
            ) {
                let mut hk_recv = Zeroizing::new([0u8; HASHLEN]);
                let mut hk_send = Zeroizing::new([0u8; HASHLEN]);
                a1.noise.get_ask(hmac, LABEL_HEADER_KEY, &mut hk_recv, &mut hk_send);
                let mut x1 = a1.x1.clone();

                drop(state);
                let resend_timer = {
                    let mut state = session.state.write().unwrap();
                    state.hk_recv.reset((&hk_recv[..AES_256_KEY_SIZE]).try_into().unwrap());
                    state.hk_send.reset((&hk_send[..AES_256_KEY_SIZE]).try_into().unwrap());
                    *state.key_mut(true) = DuplexKey::default();
                    state.key_mut(true).recv.kid = Some(new_kid_recv);
                    let resend_timer = current_time + App::SETTINGS.resend_time as i64;
                    state.resend_timer = AtomicI64::new(resend_timer);
                    state.timeout_timer = current_time + App::SETTINGS.initial_offer_timeout as i64;
                    state.beta = ZetaAutomata::A1(a1);
                    resend_timer
                };
                drop(kex_lock);

                send(&mut x1, None);
                Some(resend_timer)
            } else {
                None
            }
        }
        ZetaAutomata::S2 => {
            // Corresponds to Transition Algorithm 6 found in Section 4.3.
            log!(app, StartedRekeyingSentK1(session));
            let new_kid_recv = remap(ctx, session, &state);
            //    -> s
            //    <- s
            //    ...
            //    -> psk, e, es, ss
            let mut noise = SymmetricState::initialize(PROTOCOL_NAME_NOISE_KK);
            let hash = &mut App::Hash::new();
            let hmac = &mut App::Hmac::new();
            let mut k1 = ArrayVec::<u8, HEADERED_REKEY_SIZE>::new();
            k1.extend([0u8; HEADER_SIZE]);
            // Noise process prologue.
            noise.mix_hash(hash, &ctx.s_secret.public_key_bytes());
            noise.mix_hash(hash, &session.s_remote.to_bytes());
            // Process message pattern 1 psk0 token.
            noise.mix_key_and_hash(hash, hmac, state.ratchet_state1.key.as_ref());
            // Process message pattern 1 e token.
            let e_secret = noise.write_e(hash, hmac, &ctx.rng, &mut k1);
            // Process message pattern 1 es token.
            if noise.mix_dh(hmac, &e_secret, &session.s_remote).is_none() {
                return None;
            }
            // Process message pattern 1 ss token.
            noise.mix_key(hmac, session.noise_kk_ss.as_ref());
            // Process message pattern 1 payload.
            let i = k1.len();
            k1.extend(new_kid_recv.get().to_be_bytes());
            let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_REKEY_INIT, 0), &mut k1[i..]);
            k1.extend(tag);

            drop(state);
            let resend_timer = {
                let mut state = session.state.write().unwrap();
                state.key_mut(true).recv.kid = Some(new_kid_recv);
                state.timeout_timer = current_time + App::SETTINGS.rekey_timeout as i64;
                let resend_timer = current_time + App::SETTINGS.resend_time as i64;
                state.resend_timer = AtomicI64::new(resend_timer);
                state.beta = ZetaAutomata::R1 { noise, e_secret, k1: k1.clone() };
                resend_timer
            };
            drop(kex_lock);
            let state = session.state.read().unwrap();

            send_control(session, &state, PACKET_TYPE_REKEY_INIT, k1, send);
            Some(resend_timer)
        }
        ZetaAutomata::S1 { .. } => {
            log!(app, TimeoutKeyConfirm(session));
            None
        }
        ZetaAutomata::R1 { .. } => {
            log!(app, TimeoutK1(session));
            None
        }
        ZetaAutomata::R2 { .. } => {
            log!(app, TimeoutK2(session));
            None
        }
    }
}
/// Corresponds to the timer rules of the Zeta State Machine found in Section 4.1 - Definition 3.
pub(crate) fn process_timers<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    current_time: i64,
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Option<i64> {
    let kex_lock = session.state_machine_lock.lock().unwrap();
    let state = session.state.read().unwrap();
    if state.timeout_timer <= current_time {
        // Corresponds to the timeout timer Transition Algorithm described in Section 4.1 - Definition 3.
        timeout_trans(app, ctx, session, kex_lock, state, current_time, send)
    } else {
        let ts = state.resend_timer.load(Ordering::Relaxed);
        let resend_next = current_time + App::SETTINGS.resend_time as i64;
        if ts <= current_time && state.resend_timer.fetch_max(resend_next, Ordering::Relaxed) == ts {
            // Corresponds to the resend timer rules found in Section 4.1 - Definition 3.

            let (packet_type, control_payload) = match &state.beta {
                ZetaAutomata::Null => return None,
                ZetaAutomata::A1(a1) => {
                    log!(app, ResentX1(session));
                    send(&mut a1.x1.clone(), None);
                    return Some(resend_next);
                }
                ZetaAutomata::A3(a3) => {
                    log!(app, ResentX3(session));
                    send(&mut a3.x3.clone(), Some(&state.hk_send));
                    return Some(resend_next);
                }
                ZetaAutomata::S1 => {
                    log!(app, ResentKeyConfirm(session));
                    let mut c1 = ArrayVec::new();
                    c1.extend([0u8; HEADER_SIZE]);
                    (PACKET_TYPE_KEY_CONFIRM, c1)
                }
                ZetaAutomata::S2 => return Some(state.timeout_timer),
                ZetaAutomata::R1 { k1, .. } => {
                    log!(app, ResentK1(session));
                    (PACKET_TYPE_REKEY_INIT, k1.clone())
                }
                ZetaAutomata::R2 { k2, .. } => {
                    log!(app, ResentK2(session));
                    (PACKET_TYPE_REKEY_COMPLETE, k2.clone())
                }
            };

            send_control(session, &state, packet_type, control_payload, send);
            Some(resend_next)
        } else {
            Some(ts)
        }
    }
}
fn remap<App: ApplicationLayer>(
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    state: &MutableState<App>,
) -> NonZeroU32 {
    let mut session_map = ctx.session_map.write().unwrap();
    let weak = if let Some(Some(weak)) = state.key_ref(true).recv.kid.as_ref().map(|kid| session_map.remove(kid)) {
        weak
    } else {
        Arc::downgrade(&session)
    };
    let new_kid_recv = gen_kid(session_map.deref(), ctx.rng.lock().unwrap().deref_mut());
    session_map.insert(new_kid_recv, weak);
    new_kid_recv
}
/// Corresponds to Transition Algorithm 7 found in Section 4.3.
pub(crate) fn received_k1_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    kid: NonZeroU32,
    n: &[u8; AES_GCM_NONCE_SIZE],
    k1: &mut [u8],
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Result<(), ReceiveError<App::StorageError>> {
    use FaultType::*;
    //    -> s
    //    <- s
    //    ...
    //    -> psk, e, es, ss
    //    <- e, ee, se
    if k1.len() != REKEY_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }

    let kex_lock = session.state_machine_lock.lock().unwrap();
    let state = session.state.read().unwrap();

    if Some(kid) != state.key_ref(false).recv.kid {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(UnknownLocalKeyId, false));
    }
    let should_rekey_as_bob = match &state.beta {
        ZetaAutomata::S2 { .. } => true,
        ZetaAutomata::R1 { .. } => session.was_bob,
        _ => false,
    };
    if !should_rekey_as_bob {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(OutOfSequence, false));
    }

    let i = k1.len() - AES_GCM_TAG_SIZE;
    let tag = k1[i..].try_into().unwrap();
    if !App::Aead::decrypt_in_place(
        state.key_ref(false).recv.kek.as_ref().unwrap(),
        n,
        &[],
        &mut k1[..i],
        &tag,
    ) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(n);
    if !session.window.update(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }

    let result = (|| {
        let mut i = 0;
        let mut noise = SymmetricState::<App>::initialize(PROTOCOL_NAME_NOISE_KK);
        let hash = &mut App::Hash::new();
        let hmac = &mut App::Hmac::new();
        // Noise process prologue.
        noise.mix_hash(hash, &session.s_remote.to_bytes());
        noise.mix_hash(hash, &ctx.s_secret.public_key_bytes());
        // Process message pattern 1 psk0 token.
        noise.mix_key_and_hash(hash, hmac, state.ratchet_state1.key.as_ref());
        // Process message pattern 1 e token.
        let e_remote = noise
            .read_e(hash, hmac, &mut i, &k1)
            .ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 1 es token.
        noise
            .mix_dh(hmac, &ctx.s_secret, &e_remote)
            .ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 1 ss token.
        noise.mix_key(hmac, session.noise_kk_ss.as_ref());
        // Process message pattern 1 payload.
        let j = i + KID_SIZE;
        let k = j + AES_GCM_TAG_SIZE;
        let tag = k1[j..k].try_into().unwrap();
        if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_REKEY_INIT, 0), &mut k1[i..j], tag) {
            return Err(byzantine_fault!(FailedAuth, true));
        }
        let kid_send = NonZeroU32::new(u32::from_be_bytes(k1[i..j].try_into().unwrap()))
            .ok_or(byzantine_fault!(FailedAuth, true))?;

        let mut k2 = ArrayVec::<u8, HEADERED_REKEY_SIZE>::new();
        k2.extend([0u8; HEADER_SIZE]);
        // Process message pattern 2 e token.
        let e_secret = noise.write_e(hash, hmac, &ctx.rng, &mut k2);
        // Process message pattern 2 ee token.
        noise
            .mix_dh(hmac, &e_secret, &e_remote)
            .ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 2 se token.
        noise
            .mix_dh(hmac, &ctx.s_secret, &e_remote)
            .ok_or(byzantine_fault!(FailedAuth, true))?;
        // Process message pattern 2 payload.
        let i = k2.len();
        let new_kid_recv = remap(ctx, session, &state);
        k2.extend(new_kid_recv.get().to_be_bytes());
        let tag = noise.encrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_REKEY_COMPLETE, 0), &mut k2[i..]);
        k2.extend(tag);

        let new_ratchet_state = create_ratchet_state(hmac, &noise, state.ratchet_state1.chain_len);
        let result = app.save_ratchet_state(
            &session.s_remote,
            &session.session_data,
            RatchetUpdate {
                state1: &new_ratchet_state,
                state2: Some(&state.ratchet_state1),
                state1_was_just_added: true,
                deleted_state1: state.ratchet_state2.as_ref(),
                deleted_state2: None,
            },
        );
        if let Err(e) = result {
            return Err(ReceiveError::StorageError(e));
        }

        let mut kek_recv = Zeroizing::new([0u8; HASHLEN]);
        let mut kek_send = Zeroizing::new([0u8; HASHLEN]);
        let mut nk_recv = Zeroizing::new([0u8; HASHLEN]);
        let mut nk_send = Zeroizing::new([0u8; HASHLEN]);
        noise.get_ask(hmac, LABEL_KEX_KEY, &mut kek_send, &mut kek_recv);
        noise.split(hmac, &mut nk_send, &mut nk_recv);

        drop(state);
        let resend_timer = {
            let mut state = session.state.write().unwrap();
            state.key_mut(true).replace_nk(&nk_send, &nk_recv);
            state.key_mut(true).send.kid = Some(kid_send);
            state.key_mut(true).send.replace_kek(&kek_send);
            state.key_mut(true).recv.kid = Some(new_kid_recv);
            state.key_mut(true).recv.replace_kek(&kek_recv);
            state.ratchet_state2 = Some(state.ratchet_state1.clone());
            state.ratchet_state1 = new_ratchet_state.clone();
            let current_time = app.time();
            state.key_creation_counter = session.send_counter.load(Ordering::Relaxed);
            let resend_timer = current_time + App::SETTINGS.resend_time as i64;
            state.timeout_timer = current_time + App::SETTINGS.rekey_timeout as i64;
            state.resend_timer = AtomicI64::new(resend_timer);
            state.beta = ZetaAutomata::R2 { k2: k2.clone() };
            resend_timer
        };
        drop(kex_lock);
        ctx.session_queue
            .lock()
            .unwrap()
            .change_priority(session.queue_idx, Reverse(resend_timer));
        let state = session.state.read().unwrap();

        if !send_control(session, &state, PACKET_TYPE_REKEY_COMPLETE, k2, send) {
            return Err(byzantine_fault!(OutOfSequence, true));
        }

        Ok(())
    })();

    if matches!(result, Err(ReceiveError::ByzantineFault { .. })) {
        session.expire();
    }
    result
}
/// Corresponds to Transition Algorithm 8 found in Section 4.3.
pub(crate) fn received_k2_trans<App: ApplicationLayer>(
    app: &App,
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    kid: NonZeroU32,
    n: &[u8; AES_GCM_NONCE_SIZE],
    k2: &mut [u8],
    send: impl FnOnce(&mut [u8], Option<&App::PrpEnc>),
) -> Result<(), ReceiveError<App::StorageError>> {
    use FaultType::*;
    //    <- e, ee, se
    if k2.len() != REKEY_SIZE {
        return Err(byzantine_fault!(InvalidPacket, true));
    }

    let kex_lock = session.state_machine_lock.lock().unwrap();
    let state = session.state.read().unwrap();

    if Some(kid) != state.key_ref(false).recv.kid {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(UnknownLocalKeyId, false));
    }
    if !matches!(&state.beta, ZetaAutomata::R1 { .. }) {
        // Some rekey packet may have arrived extremely delayed.
        return Err(byzantine_fault!(OutOfSequence, false));
    }

    let i = k2.len() - AES_GCM_TAG_SIZE;
    let tag = k2[i..].try_into().unwrap();
    if !App::Aead::decrypt_in_place(
        state.key_ref(false).recv.kek.as_ref().unwrap(),
        n,
        &[],
        &mut k2[..i],
        &tag,
    ) {
        return Err(byzantine_fault!(FailedAuth, true));
    }
    let (_, c) = from_nonce(n);
    if !session.window.update(c) {
        return Err(byzantine_fault!(ExpiredCounter, true));
    }
    let result = (|| {
        if let ZetaAutomata::R1 { noise, e_secret, .. } = &state.beta {
            let mut noise = noise.clone();
            let mut i = 0;
            let hash = &mut App::Hash::new();
            let hmac = &mut App::Hmac::new();
            // Process message pattern 2 e token.
            let e_remote = noise
                .read_e(hash, hmac, &mut i, &k2)
                .ok_or(byzantine_fault!(FailedAuth, true))?;
            // Process message pattern 2 ee token.
            noise
                .mix_dh(hmac, e_secret, &e_remote)
                .ok_or(byzantine_fault!(FailedAuth, true))?;
            // Process message pattern 2 se token.
            noise
                .mix_dh(hmac, e_secret, &session.s_remote)
                .ok_or(byzantine_fault!(FailedAuth, true))?;
            // Process message pattern 2 payload.
            let j = i + KID_SIZE;
            let k = j + AES_GCM_TAG_SIZE;
            let tag = k2[j..k].try_into().unwrap();
            if !noise.decrypt_and_hash_in_place(hash, to_nonce(PACKET_TYPE_REKEY_COMPLETE, 0), &mut k2[i..j], tag) {
                return Err(byzantine_fault!(FailedAuth, true));
            }
            let kid_send = NonZeroU32::new(u32::from_be_bytes(k2[i..j].try_into().unwrap()))
                .ok_or(byzantine_fault!(InvalidPacket, true))?;

            let new_ratchet_state = create_ratchet_state(hmac, &noise, state.ratchet_state1.chain_len);
            let result = app.save_ratchet_state(
                &session.s_remote,
                &session.session_data,
                RatchetUpdate {
                    state1: &new_ratchet_state,
                    state2: None,
                    state1_was_just_added: true,
                    deleted_state1: Some(&state.ratchet_state1),
                    deleted_state2: state.ratchet_state2.as_ref(),
                },
            );
            if let Err(e) = result {
                return Err(ReceiveError::StorageError(e));
            }
            let mut kek_recv = Zeroizing::new([0u8; HASHLEN]);
            let mut kek_send = Zeroizing::new([0u8; HASHLEN]);
            let mut nk_recv = Zeroizing::new([0u8; HASHLEN]);
            let mut nk_send = Zeroizing::new([0u8; HASHLEN]);
            noise.get_ask(hmac, LABEL_KEX_KEY, &mut kek_recv, &mut kek_send);
            noise.split(hmac, &mut nk_recv, &mut nk_send);

            drop(state);
            let resend_timer = {
                let mut state = session.state.write().unwrap();
                state.key_mut(true).replace_nk(&nk_send, &nk_recv);
                state.key_mut(true).send.kid = Some(kid_send);
                state.key_mut(true).send.replace_kek(&kek_send);
                state.key_mut(true).recv.replace_kek(&kek_recv);
                state.ratchet_state1 = new_ratchet_state.clone();
                state.key_index ^= true;
                let current_time = app.time();
                state.key_creation_counter = session.send_counter.load(Ordering::Relaxed);
                let resend_timer = current_time + App::SETTINGS.resend_time as i64;
                state.timeout_timer = current_time + App::SETTINGS.rekey_timeout as i64;
                state.resend_timer = AtomicI64::new(resend_timer);
                state.beta = ZetaAutomata::S1;
                resend_timer
            };
            drop(kex_lock);
            ctx.session_queue
                .lock()
                .unwrap()
                .change_priority(session.queue_idx, Reverse(resend_timer));
            let state = session.state.read().unwrap();

            let mut c1 = ArrayVec::<u8, HEADERED_KEY_CONFIRMATION_SIZE>::new();
            c1.extend([0u8; HEADER_SIZE]);
            if !send_control(&session, &state, PACKET_TYPE_KEY_CONFIRM, c1, send) {
                return Err(byzantine_fault!(OutOfSequence, true));
            }

            Ok(())
        } else {
            unreachable!()
        }
    })();

    if matches!(result, Err(ReceiveError::ByzantineFault { .. })) {
        session.expire();
    }
    result
}
/// Corresponds to Algorithm 9 found in Section 4.3.
pub(crate) fn send_payload<App: ApplicationLayer>(
    ctx: &Arc<ContextInner<App>>,
    session: &Arc<Session<App>>,
    payload: &[u8],
    mut send: impl FnMut(&[u8]) -> bool,
    mtu_sized_buffer: &mut [u8],
) -> Result<(), SendError> {
    use SendError::*;
    let mtu = mtu_sized_buffer.len();
    if mtu < MIN_TRANSPORT_MTU {
        return Err(InvalidParameter);
    }

    let state = session.state.read().unwrap();
    if matches!(&state.beta, ZetaAutomata::Null) {
        return Err(SessionExpired);
    }
    if !matches!(
        &state.beta,
        ZetaAutomata::S1 | ZetaAutomata::S2 | ZetaAutomata::R1 { .. } | ZetaAutomata::R2 { .. }
    ) {
        return Err(SessionNotEstablished);
    }
    let (c, should_rekey) = get_counter(session, &state).ok_or(SessionExpired)?;
    let nonce = to_nonce(PACKET_TYPE_DATA, c);

    let key = state.key_ref(false);
    let mut cipher = key.nk.as_ref().unwrap().start_enc(&nonce);

    let payload_mtu = mtu - HEADER_SIZE;
    debug_assert!(payload_mtu >= 4);
    let fragment_count = payload.len().saturating_add(payload_mtu - 1) / payload_mtu; // Ceiling div.
    let fragment_base_size = payload.len() / fragment_count;
    let fragment_size_remainder = payload.len() % fragment_count;

    mtu_sized_buffer[..KID_SIZE].copy_from_slice(&key.send.kid.unwrap().get().to_be_bytes());
    mtu_sized_buffer[FRAGMENT_COUNT_IDX] = fragment_count as u8;
    mtu_sized_buffer[PACKET_NONCE_START..].copy_from_slice(&nonce[NONCE_SIZE_DIFF..]);

    let mut i = 0;
    for fragment_no in 0..fragment_count {
        let fragment_len = fragment_base_size + (fragment_no < fragment_size_remainder) as usize;
        let j = i + fragment_len;

        mtu_sized_buffer[FRAGMENT_NO_IDX] = fragment_no as u8;
        cipher.encrypt(
            &payload[i..j],
            &mut mtu_sized_buffer[HEADER_SIZE..HEADER_SIZE + fragment_len],
        );

        state.hk_send.encrypt_in_place(
            (&mut mtu_sized_buffer[HEADER_AUTH_START..HEADER_AUTH_END])
                .try_into()
                .unwrap(),
        );

        if !send(&mtu_sized_buffer[..HEADER_SIZE + fragment_len]) {
            return Ok(());
        }
        i = j;
    }
    drop(cipher);
    drop(state);

    if should_rekey {
        let mut state = session.state.write().unwrap();
        state.timeout_timer = i64::MIN;
        drop(state);
        ctx.session_queue
            .lock()
            .unwrap()
            .change_priority(session.queue_idx, Reverse(i64::MIN));
    }
    Ok(())
}
/// Corresponds to Algorithm 10 found in Section 4.3.
pub(crate) fn receive_payload_in_place<App: ApplicationLayer>(
    session: &Arc<Session<App>>,
    state: RwLockReadGuard<'_, MutableState<App>>,
    kid: NonZeroU32,
    n: &[u8; AES_GCM_NONCE_SIZE],
    fragments: &mut [App::IncomingPacketBuffer],
    mut output_buffer: impl Write,
) -> Result<(), ReceiveError<App::StorageError>> {
    use FaultType::*;

    let is_other = if Some(kid) == state.key_ref(true).recv.kid {
        true
    } else if Some(kid) == state.key_ref(false).recv.kid {
        false
    } else {
        return Err(byzantine_fault!(OutOfSequence, true));
    };

    let mut cipher = state
        .key_ref(is_other)
        .nk
        .as_ref()
        .ok_or(byzantine_fault!(OutOfSequence, true))?
        .start_dec(n);

    // NOTE: This only works because we check the size of every received fragment in the receive
    // function, otherwise this could panic.
    let mut i = 0;
    while i + 1 < fragments.len() {
        let fragment = &mut fragments[i].as_mut()[HEADER_SIZE..];
        cipher.decrypt_in_place(fragment);
        i += 1;
    }
    let fragment = &mut fragments[i].as_mut()[HEADER_SIZE..];
    let tag_idx = fragment.len() - AES_GCM_NONCE_SIZE;
    cipher.decrypt_in_place(&mut fragment[..tag_idx]);
    if cipher.finish((&fragment[tag_idx..]).try_into().unwrap()) {
        return Err(byzantine_fault!(FailedAuth, true));
    }

    let (_, c) = from_nonce(n);
    if !session.window.update(c) {
        // This error is marked as not happening naturally, but it could occur if something about
        // the transport protocol is duplicating packets.
        return Err(byzantine_fault!(ExpiredCounter, true));
    }

    drop(cipher);
    for fragment in fragments {
        let result = output_buffer.write(&fragment.as_ref()[HEADER_SIZE..]);
        if let Err(e) = result {
            return Err(ReceiveError::IoError(e));
        }
    }

    Ok(())
}

impl<App: ApplicationLayer> Drop for Session<App> {
    fn drop(&mut self) {
        self.expire();
    }
}
impl<App: ApplicationLayer> Session<App> {
    /// Mark a session as expired. This will make it impossible for this session to successfully
    /// receive or send data or control packets. It is recommended to simply `drop` the session
    /// instead, but this can provide some reassurance in complex shared ownership situations.
    pub fn expire(&self) {
        if let Some(ctx) = self.ctx.upgrade() {
            self.expire_inner(Some(&ctx), Some(&mut ctx.session_queue.lock().unwrap()));
        } else {
            self.expire_inner(None, None);
        }
    }
    /// Allows us to expire sessions with the correct locking order, preventing deadlock.
    pub(crate) fn expire_inner(
        &self,
        ctx: Option<&Arc<ContextInner<App>>>,
        session_queue: Option<&mut SessionQueue<App>>,
    ) {
        let _kex_lock = self.state_machine_lock.lock().unwrap();
        let mut state = self.state.write().unwrap();
        let mut kids_to_remove = None;
        if !matches!(&state.beta, ZetaAutomata::Null) {
            self.session_has_expired.store(true, Ordering::Relaxed);
            kids_to_remove = Some([state.keys[0].recv.kid, state.keys[1].recv.kid]);
            state.keys = [DuplexKey::default(), DuplexKey::default()];
            state.resend_timer = AtomicI64::new(i64::MAX);
            state.timeout_timer = i64::MAX;
            state.beta = ZetaAutomata::Null;
        }
        if let Some(session_queue) = session_queue {
            session_queue.remove(self.queue_idx);
        }
        if let (Some(ctx), Some(kids_to_remove)) = (ctx, kids_to_remove) {
            let mut session_map = ctx.session_map.write().unwrap();
            for kid_recv in kids_to_remove.iter().flatten() {
                session_map.remove(kid_recv);
            }
        }
    }
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
        !matches!(
            &state.beta,
            ZetaAutomata::A1(_) | ZetaAutomata::A3 { .. } | ZetaAutomata::Null
        )
    }
    /// The static public key of the remote peer.
    pub fn remote_static_key(&self) -> &App::PublicKey {
        &self.s_remote
    }
}
