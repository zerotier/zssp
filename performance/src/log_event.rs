use std::sync::Arc;

use crate::application::CryptoLayer;
use crate::zeta::Session;

/// ZSSP events that might be interesting to log or aggregate into metrics.
#[allow(missing_docs)]
pub enum LogEvent<'a, Crypto: CryptoLayer> {
    ResentX1(&'a Arc<Session<Crypto>>),
    TimeoutX1(&'a Arc<Session<Crypto>>),
    TimeoutX2,
    ResentX3(&'a Arc<Session<Crypto>>),
    TimeoutX3(&'a Arc<Session<Crypto>>),
    ResentKeyConfirm(&'a Arc<Session<Crypto>>),
    TimeoutKeyConfirm(&'a Arc<Session<Crypto>>),
    StartedRekeyingSentK1(&'a Arc<Session<Crypto>>),
    ResentK1(&'a Arc<Session<Crypto>>),
    TimeoutK1(&'a Arc<Session<Crypto>>),
    ResentK2(&'a Arc<Session<Crypto>>),
    TimeoutK2(&'a Arc<Session<Crypto>>),
    /// `(packet_type, packet_counter, fragment_no, fragment_count)`
    ReceivedRawFragment(u8, u64, usize, usize),
    ReceivedRawX1,
    X1FailedChallengeSentNewChallenge,
    X1SucceededChallenge,
    X1IsAuthSentX2,
    ReceivedRawChallenge,
    ChallengeIsAuth(&'a Arc<Session<Crypto>>),
    ReceivedRawX2,
    X2IsAuthSentX3(&'a Arc<Session<Crypto>>),
    ReceivedRawX3,
    X3IsAuthSentKeyConfirm(&'a Arc<Session<Crypto>>),
    ReceivedRawKeyConfirm,
    KeyConfirmIsAuthSentAck(&'a Arc<Session<Crypto>>),
    ReceivedRawAck,
    AckIsAuth(&'a Arc<Session<Crypto>>),
    ReceivedRawK1,
    K1IsAuthSentK2(&'a Arc<Session<Crypto>>),
    ReceivedRawK2,
    K2IsAuthSentKeyConfirm(&'a Arc<Session<Crypto>>),
    ReceivedRawD,
    DIsAuthClosedSession(&'a Arc<Session<Crypto>>),
}

impl<'a, Crypto: CryptoLayer> std::fmt::Debug for LogEvent<'a, Crypto> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::ResentX1(_) => f.debug_tuple("ResentX1").finish(),
            Self::TimeoutX1(_) => f.debug_tuple("TimeoutX1").finish(),
            Self::TimeoutX2 => write!(f, "TimeoutX2"),
            Self::ResentX3(_) => f.debug_tuple("ResentX3").finish(),
            Self::TimeoutX3(_) => f.debug_tuple("TimeoutX3").finish(),
            Self::ResentKeyConfirm(_) => f.debug_tuple("ResentKeyConfirm").finish(),
            Self::TimeoutKeyConfirm(_) => f.debug_tuple("TimeoutKeyConfirm").finish(),
            Self::StartedRekeyingSentK1(_) => f.debug_tuple("StartedRekeyingSentK1").finish(),
            Self::ResentK1(_) => f.debug_tuple("ResentK1").finish(),
            Self::TimeoutK1(_) => f.debug_tuple("TimeoutK1").finish(),
            Self::ResentK2(_) => f.debug_tuple("ResentK2").finish(),
            Self::TimeoutK2(_) => f.debug_tuple("TimeoutK2").finish(),
            Self::ReceivedRawFragment(arg0, arg1, arg2, arg3) => f
                .debug_tuple("ReceivedRawFragment")
                .field(arg0)
                .field(arg1)
                .field(arg2)
                .field(arg3)
                .finish(),
            Self::ReceivedRawX1 => write!(f, "ReceivedRawX1"),
            Self::X1FailedChallengeSentNewChallenge => write!(f, "X1FailedChallengeSentNewChallenge"),
            Self::X1SucceededChallenge => write!(f, "X1SucceededChallenge"),
            Self::X1IsAuthSentX2 => write!(f, "X1IsAuthSentX2"),
            Self::ReceivedRawChallenge => write!(f, "ReceivedRawChallenge"),
            Self::ChallengeIsAuth(_) => f.debug_tuple("ChallengeIsAuth").finish(),
            Self::ReceivedRawX2 => write!(f, "ReceivedRawX2"),
            Self::X2IsAuthSentX3(_) => f.debug_tuple("X2IsAuthSentX3").finish(),
            Self::ReceivedRawX3 => write!(f, "ReceivedRawX3"),
            Self::X3IsAuthSentKeyConfirm(_) => f.debug_tuple("X3IsAuthSentKeyConfirm").finish(),
            Self::ReceivedRawKeyConfirm => write!(f, "ReceivedRawKeyConfirm"),
            Self::KeyConfirmIsAuthSentAck(_) => f.debug_tuple("KeyConfirmIsAuthSentAck").finish(),
            Self::ReceivedRawAck => write!(f, "ReceivedRawAck"),
            Self::AckIsAuth(_) => f.debug_tuple("AckIsAuth").finish(),
            Self::ReceivedRawK1 => write!(f, "ReceivedRawK1"),
            Self::K1IsAuthSentK2(_) => f.debug_tuple("K1IsAuthSentK2").finish(),
            Self::ReceivedRawK2 => write!(f, "ReceivedRawK2"),
            Self::K2IsAuthSentKeyConfirm(_) => f.debug_tuple("K2IsAuthSentKeyConfirm").finish(),
            Self::ReceivedRawD => write!(f, "ReceivedRawD"),
            Self::DIsAuthClosedSession(_) => f.debug_tuple("DIsAuthClosedSession").finish(),
        }
    }
}
