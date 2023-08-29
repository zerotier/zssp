use std::sync::Arc;

use crate::application::CryptoLayer;
use crate::zeta::Session;

/// An error that can occur when attempting to open a session.
/// Depending on the error type trying again may not work.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum OpenError {
    /// An invalid parameter was supplied to the function.
    InvalidPublicKey,

    IdentityTooLarge,

    RatchetStorageError,
}

/// An error that can occur when attempting to send data over a session.
/// Depending on the error type trying again may not work.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum SendError {
    /// An invalid mtu was supplied to the function. The MTU can be no smaller than 128 bytes.
    MtuTooSmall,

    /// The session has been marked as expired and refuses to send data.
    /// Several components of ZSSP can cause this to occur, but the most likely situation to be seen
    /// in practice is where rekeying repeatedly fails due to exceedingly bad network conditions.
    ///
    /// The user can also explicitly cause this to occur by manually calling `expire` on a session.
    ///
    /// The associated session will no longer send or receive data and must be immediately dropped.
    SessionExpired,

    /// Attempt to send using a session without a shared symmetric key.
    /// The caller should wait until the handshake has completed.
    SessionNotEstablished,

    /// Data object is too large to send, even with fragmentation.
    DataTooLarge,
}

/// A type of fault occurred because we received a bad packet.
///
/// An unauthenticated attacker can intentionally trigger any of these, so it is best to
/// treat these as raw user input that needs to be sanitize.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum FaultType {
    /// The received packet was addressed to an unrecognized local session.
    UnknownLocalKeyId,

    /// The received packet from the remote peer was not well formed.
    InvalidPacket,

    /// Packet failed one or more authentication (MAC) checks.
    FailedAuth,

    /// Packet counter was repeated or outside window of allowed counter values.
    ExpiredCounter,

    /// Packet contained protocol control parameters that are disallowed at this point in
    /// time by ZSSP.
    OutOfSequence,
}

/// An error that occurred during the receipt of a given packet.
#[derive(Debug)]
pub enum ReceiveError {
    /// A type of fault that can occur because a remote peer sent us a bad packet.
    /// Such packets will be ignored by ZSSP but a user of ZSSP might want to log
    /// them for debugging or tracing.
    ///
    /// Because an unauthenticated remote peer can force these to occur with specific
    /// contained information, it is recommended in production to either drop these
    /// immediately, or log them safely to a local output stream and then drop them.
    ByzantineFault {
        /// The type of fault that has occurred. Be cautious if you choose to read this
        /// value, as an attacker has control over it.
        error: FaultType,
        /// Some byzantine faults within ZSSP are naturally occurring, i.e. they can occur
        /// between two well behaved and trusted parties executing the protocol.
        /// This boolean is false if this is one of these faults. If you go to the file and
        /// line number specified by this error you will find a comment describing
        /// how and why exactly this fault can occur naturally.
        ///
        /// Faults that can occur because the underlying communication medium is lossy and
        /// sequentially inconsistent (as in UDP) are considered naturally occurring.
        /// However ZSSP considers faults that occur because data integrity has not been
        /// persevered (i.e. bits have been flipped) to be unnatural.
        /// ZSSP also considers collisions of what are supposed to be uniform random
        /// numbers to be unnatural.
        unnatural: bool,
        /// The file of this implementation of ZSSP from which this error was generated.
        #[cfg(feature = "debug")]
        file: &'static str,
        /// The line number of this implementation of ZSSP from which this error was
        /// generated. As such this number uniquely identifies each possible fault that
        /// can occur during ZSSP. Advanced user can use this information to debug more
        /// complicated usages of ZSSP.
        #[cfg(feature = "debug")]
        line: u32,
    },

    /// Rekeying failed and session secret has reached its hard usage count limit.
    /// The associated session will no longer function and has to be dropped.
    MaxKeyLifetimeExceeded,

    Rejected,
    /// One of the ratchet saving or lookup functions returned an error, so the packet had to be
    /// dropped.
    RatchetStorageError,

    IoError(std::io::Error),
}

macro_rules! fault {
    ($name:expr, $unnatural:ident) => {
        ReceiveError::ByzantineFault {
            #[cfg(feature = "debug")]
            file: file!(),
            #[cfg(feature = "debug")]
            line: line!(),
            error: $name,
            unnatural: $unnatural,
        }
    };
}
pub(crate) use fault;

/// Result generated by the context packet receive function, with possible payloads.
#[derive(Clone)]
pub enum ReceiveOk<Crypto: CryptoLayer> {
    /// Packet superficially appeared valid but is not associated with a session yet.
    /// This can occur because the packet was only a fragment of a larger packet,
    /// or if it was a control packet that does not go through full Noise authentication.
    Unassociated,
    /// Packet was authentic and belongs to this specific session.
    Session(Arc<Session<Crypto>>, SessionEvent),
}
/// Something that can occur to an associated session when a packet is received successfully,
/// including receiving a payload of decrypted, authenticated data.
#[derive(Debug, PartialEq, Eq, Clone, Hash)]
pub enum SessionEvent {
    /// The received packet was valid, and it contained the necessary keys to fully establish a new
    /// session with Alice, the handshake initiator.
    ///
    /// If the session Arc returned is dropped, the session with this peer will be immediately
    /// terminated. Save the session Arc to some long lived datastructure to keep it alive.
    NewSession,
    NewDowngradedSession,
    /// When Alice calls `Context::open`, a session will be created, but Bob will not yet have
    /// received this session. They will have to successfully complete a handshake first.
    ///
    /// Alice will receive this return value when the received packet confirms both parties
    /// have completed the initial handshake and now have a shared session with each other.
    /// If according to the upper protocol, Bob is the first party to send data, it is possible for
    /// Alice to start receiving data from Bob before this value is returned.
    ///
    /// This return value can only occur once per session, only for session objects that were
    /// created with `Context::open`.
    Established,
    /// Bob explicitly refused to establish a session with Alice, and sent us an error code.
    /// The application should immediately drop this session as Bob will not allow us to connect.
    ///
    /// This return value cannot occur after a session is fully established.
    Rejected,
    /// The received packet was valid and a data payload was decoded and authenticated.
    Data,
    /// The received packet was some authentic protocol control packet. No action needs to be taken.
    Control,
    DowngradedRatchetKey,
}
