/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */

#[derive(Debug, PartialEq, Eq)]
pub enum OpenError<IoError> {
    /// An invalid parameter was supplied to the function.
    InvalidPublicKey,

    /// Local identity blob is too large to send, even with fragmentation.
    DataTooLarge,

    RatchetIoError(IoError),
}

#[derive(Debug, PartialEq, Eq)]
pub enum SendError {
    /// An invalid parameter was supplied to the function.
    InvalidParameter,

    /// The session has been marked as expired and refuses to send data.
    /// Several components of ZSSP can cause this to occur, but the most likely situation to be seen
    /// in practice is where rekeying repeatedly fails due to exceedingly bad network conditions.
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
#[derive(Debug, PartialEq, Eq)]
pub enum FaultType {
    /// The received packet was addressed to an unrecognized local session.
    UnknownLocalKeyId,

    /// The received packet from the remote peer was not well formed.
    InvalidPacket,

    /// Packet failed one or more authentication (MAC) checks.
    FailedAuthentication,

    /// Packet counter was repeated or outside window of allowed counter values.
    ExpiredCounter,

    /// Packet contained protocol control parameters that are disallowed at this point in
    /// time by ZSSP.
    OutOfSequence,
}

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveError<IoError> {
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
        /// This boolean is true if this is one of these faults. If you go to the file and
        /// line number specified by this error you will find a comment describing
        /// how and why exactly this fault can occur naturally.
        ///
        /// Faults that can occur because the underlying communication medium is lossy and
        /// sequentially inconsistent (as in UDP) are considered naturally occurring.
        /// However ZSSP considers faults that occur because data integrity has not been
        /// persevered (i.e. bits have been flipped) to be unnatural.
        /// ZSSP also considers collisions of what are supposed to be uniform random
        /// numbers to be unnatural.
        is_naturally_occurring: bool,
        /// The file of this implementation of ZSSP from which this error was generated.
        file: &'static str,
        /// The line number of this implementation of ZSSP from which this error was
        /// generated. As such this number uniquely identifies each possible fault that
        /// can occur during ZSSP. Advanced user can use this information to debug more
        /// complicated usages of ZSSP.
        line: u32,
    },

    /// The caller supplied data buffer is too small to receive data from the remote peer.
    /// An attacker can cause this to occur, so users should place a hard upper limit on
    /// how large their supplied data buffers can be.
    DataBufferTooSmall,

    /// Rekeying failed and session secret has reached its hard usage count limit.
    /// The associated session will no longer function and has to be dropped.
    MaxKeyLifetimeExceeded,

    /// One of the ratchet saving or lookup functions returned an error, so the packet had to be
    /// dropped.
    RatchetIoError(IoError),
}
