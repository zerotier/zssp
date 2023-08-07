/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use std::sync::Arc;

use crate::{ApplicationLayer, zssp::Session};

/// ZSSP events that might be interesting to log or aggregate into metrics.
pub enum LogEvent<'a, Application: ApplicationLayer> {
    ServiceXK1Resend(&'a Arc<Session<Application>>),
    ServiceXK3Resend(&'a Arc<Session<Application>>),
    ServiceXKTimeout(&'a Arc<Session<Application>>),
    ServiceKKStart(&'a Arc<Session<Application>>),
    ServiceKK1Resend(&'a Arc<Session<Application>>),
    ServiceKK2Resend(&'a Arc<Session<Application>>),
    ServiceKKTimeout(&'a Arc<Session<Application>>),
    ServiceKeyConfirmResend(&'a Arc<Session<Application>>),
    ServiceKeyConfirmTimeout(&'a Arc<Session<Application>>),
    /// `(fragment_count, fragment_no, packet_type)`
    ReceiveUnassociatedFragment(u8, u8, u8),
    ReceiveUncheckedXK1,
    ReceiveCheckXK1Challenge(bool),
    ReceiveValidXK1,
    ReceiveUncheckedDOSChallenge,
    ReceiveValidDOSChallenge(&'a Arc<Session<Application>>),
    ReceiveUncheckedXK2,
    ReceiveValidXK2(&'a Arc<Session<Application>>),
    ReceiveUncheckedXK3,
    ReceiveValidXK3(&'a Application::SessionData),
    ReceiveUncheckedKK1,
    ReceiveValidKK1(&'a Arc<Session<Application>>),
    ReceiveUncheckedKK2,
    ReceiveValidKK2(&'a Arc<Session<Application>>),
    ReceiveValidKeyConfirm(&'a Arc<Session<Application>>),
    ReceiveValidAck(&'a Arc<Session<Application>>),
}
impl<'a, Application: ApplicationLayer> std::fmt::Debug for LogEvent<'a, Application> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        use LogEvent::*;
        match self {
            ServiceXK1Resend(_) => write!(f, "ServiceXK1Resend"),
            ServiceXK3Resend(_) => write!(f, "ServiceXK3Resend"),
            ServiceXKTimeout(_) => write!(f, "ServiceXKTimeout"),
            ServiceKKStart(_) => write!(f, "ServiceKKStart"),
            ServiceKK1Resend(_) => write!(f, "ServiceKK1Resend"),
            ServiceKK2Resend(_) => write!(f, "ServiceKK2Resend"),
            ServiceKKTimeout(_) => write!(f, "ServiceKKTimeout"),
            ServiceKeyConfirmResend(_) => write!(f, "ServiceKeyConfirmResend"),
            ServiceKeyConfirmTimeout(_) => write!(f, "ServiceKeyConfirmTimeout"),
            ReceiveUnassociatedFragment(arg0, arg1, arg2) => {
                f.debug_tuple("ReceiveUnassociatedFragment").field(arg0).field(arg1).field(arg2).finish()
            }
            ReceiveUncheckedXK1 => write!(f, "ReceiveUncheckedXK1"),
            ReceiveCheckXK1Challenge(arg0) => f.debug_tuple("ReceiveCheckXK1Challenge").field(arg0).finish(),
            ReceiveValidXK1 => write!(f, "ReceiveValidXK1"),
            ReceiveUncheckedDOSChallenge => write!(f, "ReceiveUncheckedDOSChallenge"),
            ReceiveValidDOSChallenge(_) => write!(f, "ReceiveValidDOSChallenge"),
            ReceiveUncheckedXK2 => write!(f, "ReceiveUncheckedXK2"),
            ReceiveValidXK2(_) => write!(f, "ReceiveValidXK2"),
            ReceiveUncheckedXK3 => write!(f, "ReceiveUncheckedXK3"),
            ReceiveValidXK3(_) => write!(f, "ReceiveValidXK3"),
            ReceiveUncheckedKK1 => write!(f, "ReceiveUncheckedKK1"),
            ReceiveValidKK1(_) => write!(f, "ReceiveValidKK1"),
            ReceiveUncheckedKK2 => write!(f, "ReceiveUncheckedKK2"),
            ReceiveValidKK2(_) => write!(f, "ReceiveValidKK2"),
            ReceiveValidKeyConfirm(_) => write!(f, "ReceiveValidKeyConfirm"),
            ReceiveValidAck(_) => write!(f, "ReceiveValidAck"),
        }
    }
}
