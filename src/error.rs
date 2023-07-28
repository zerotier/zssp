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

#[derive(Debug, PartialEq, Eq)]
pub enum ReceiveError<IoError> {
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
