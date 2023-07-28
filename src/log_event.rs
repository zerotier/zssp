/* This Source Code Form is subject to the terms of the Mozilla Public
 * License, v. 2.0. If a copy of the MPL was not distributed with this
 * file, You can obtain one at https://mozilla.org/MPL/2.0/.
 *
 * (c) ZeroTier, Inc.
 * https://www.zerotier.com/
 */
use std::sync::Arc;

use crate::{ApplicationLayer, Zeta};

/// ZSSP events that might be interesting to log or aggregate into metrics.
pub enum LogEvent<'a, Application: ApplicationLayer> {
    ServiceXK1Resend(&'a Arc<Zeta<Application>>),
    ServiceXK3Resend(&'a Arc<Zeta<Application>>),
    ServiceXKTimeout(&'a Arc<Zeta<Application>>),
    ServiceKKStart(&'a Arc<Zeta<Application>>),
    ServiceKK1Resend(&'a Arc<Zeta<Application>>),
    ServiceKK2Resend(&'a Arc<Zeta<Application>>),
    ServiceKKTimeout(&'a Arc<Zeta<Application>>),
    ServiceKeyConfirmResend(&'a Arc<Zeta<Application>>),
    ServiceKeyConfirmTimeout(&'a Arc<Zeta<Application>>),
    /// `(fragment_count, fragment_no, packet_type)`
    ReceiveUnassociatedFragment(u8, u8, u8),
    ReceiveUncheckedXK1,
    ReceiveCheckXK1Challenge(bool),
    ReceiveValidXK1,
    ReceiveUncheckedDOSChallenge,
    ReceiveValidDOSChallenge(&'a Arc<Zeta<Application>>),
    ReceiveUncheckedXK2,
    ReceiveValidXK2(&'a Arc<Zeta<Application>>),
    ReceiveUncheckedXK3,
    ReceiveValidXK3(&'a Application::Data),
    ReceiveUncheckedKK1,
    ReceiveValidKK1(&'a Arc<Zeta<Application>>),
    ReceiveUncheckedKK2,
    ReceiveValidKK2(&'a Arc<Zeta<Application>>),
    ReceiveValidKeyConfirm(&'a Arc<Zeta<Application>>),
    ReceiveValidAck(&'a Arc<Zeta<Application>>),
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
