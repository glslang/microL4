//! `test=badge`: the clients, their badges and calls, and the verdicts on
//! what the server received and what each client's calls returned.
//!
//! Four clients call one endpoint: A1 and A2 through copies of the badged
//! original B1, B through a copy of B2, U through an unbadged copy. Each
//! makes [`PHASES`] calls, the label naming the client and the phase, and
//! the server answers each with the badge it saw. In the last phase B1 is
//! revoked before `CNode_CancelBadgedSends`, so A1's and A2's restarted
//! calls find their slots empty and return `InvalidCapability`.

use core::fmt;

use libsys::{MessageInfo, Received};

use super::Mismatch;

/// The clients, by index.
pub const CLIENTS: usize = 4;
pub const NAMES: [&str; CLIENTS] = ["A1", "A2", "B", "U"];
pub const A1: usize = 0;
pub const A2: usize = 1;
pub const B: usize = 2;
pub const U: usize = 3;

/// The badges of B1 and B2.
pub const BADGE_1: u64 = 0xB1;
pub const BADGE_2: u64 = 0xB2;
/// Each client's badge.
pub const BADGES: [u64; CLIENTS] = [BADGE_1, BADGE_1, BADGE_2, 0];
/// The badge of the clients' fault endpoint, a capability to the same
/// endpoint: a fault reaches the server as a message with this badge.
pub const FAULT_BADGE: u64 = 0xFA;

/// Calls each client makes.
pub const PHASES: usize = 5;
/// Phases 0 to 2 run freely; the server saves the round-2 callers.
pub const FREE: usize = 3;
/// The phase of the cancel without revoke, and of the revoke and cancel.
pub const CANCEL: usize = 3;
pub const REVOKE: usize = 4;

/// The error code of `InvalidCapability` (`docs/abi.md`, "Errors").
pub const INVALID_CAPABILITY: u64 = 2;

const LABEL_BASE: u64 = 0xBA00;

/// The label of client `id`'s call in `phase`.
pub const fn label(id: usize, phase: usize) -> u64 {
    LABEL_BASE | (id as u64) << 4 | phase as u64
}

/// Why the server's view of a message is wrong.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SenderFailure {
    /// The message came through the clients' fault endpoint.
    Fault { label: u64 },
    /// Its label names no client and phase, or it has the wrong length.
    NotACall { label: u64, length: u64 },
    /// Client `id`'s message carried another badge.
    Badge(usize, Mismatch),
}

impl fmt::Display for SenderFailure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            SenderFailure::Fault { label } => {
                write!(
                    f,
                    "a client faulted: fault type {label} on the fault endpoint"
                )
            }
            SenderFailure::NotACall { label, length } => write!(
                f,
                "a message with label {label:#x} and length {length} is no client's call"
            ),
            SenderFailure::Badge(id, m) => write!(f, "client {}'s call: {m}", NAMES[id]),
        }
    }
}

/// The client and phase of a call the server received, once its badge is
/// checked against the sender's.
pub fn sender(r: &Received) -> Result<(usize, usize), SenderFailure> {
    let info = r.msg.info;
    if r.badge == FAULT_BADGE {
        return Err(SenderFailure::Fault {
            label: info.label(),
        });
    }
    let l = info.label();
    let (id, phase) = (((l >> 4) & 0xF) as usize, (l & 0xF) as usize);
    if l & !0xFF != LABEL_BASE || id >= CLIENTS || phase >= PHASES || info.length() != 1 {
        return Err(SenderFailure::NotACall {
            label: l,
            length: info.length(),
        });
    }
    if r.badge != BADGES[id] {
        return Err(SenderFailure::Badge(
            id,
            Mismatch {
                what: "the badge",
                got: r.badge,
                want: BADGES[id],
            },
        ));
    }
    Ok((id, phase))
}

/// What the server received, in order, is not what it should be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OrderMismatch<'a> {
    pub got: &'a [usize],
    pub want: &'a [usize],
}

impl fmt::Display for OrderMismatch<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("received from ")?;
        names(self.got, f)?;
        f.write_str(", not ")?;
        names(self.want, f)
    }
}

/// Client names, `"U, B, A1"`.
pub struct Names<'a>(pub &'a [usize]);

impl fmt::Display for Names<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        names(self.0, f)
    }
}

fn names(ids: &[usize], f: &mut fmt::Formatter<'_>) -> fmt::Result {
    for (i, &id) in ids.iter().enumerate() {
        if i > 0 {
            f.write_str(", ")?;
        }
        f.write_str(NAMES.get(id).copied().unwrap_or("?"))?;
    }
    Ok(())
}

/// Checks the order the server received a phase's calls in.
pub fn order<'a>(got: &'a [usize], want: &'a [usize]) -> Result<(), OrderMismatch<'a>> {
    if got == want {
        Ok(())
    } else {
        Err(OrderMismatch { got, want })
    }
}

/// Checks the free rounds: each client's calls arrived in phase order,
/// [`FREE`] of them. `phases[id]` lists the phases received from `id`, in
/// order.
pub fn free_rounds(phases: &[[Option<usize>; FREE]; CLIENTS]) -> Result<(), (usize, Mismatch)> {
    for (id, p) in phases.iter().enumerate() {
        for (k, &got) in p.iter().enumerate() {
            if got != Some(k) {
                return Err((
                    id,
                    Mismatch {
                        what: "the phase of the client's next call",
                        got: got.map_or(u64::MAX, |g| g as u64),
                        want: k as u64,
                    },
                ));
            }
        }
    }
    Ok(())
}

/// What one of a client's calls returned: the reply's `MessageInfo` and
/// MR0. `None` until it returned.
pub type Outcome = Option<(MessageInfo, u64)>;

/// What client `id`'s call in `phase` must return: the server's answer,
/// label 0 and the client's badge in MR0, or, for A1 and A2 once B1 is
/// revoked, `InvalidCapability` for the empty slot (MR0 0, the invoked
/// capability).
pub fn expected(id: usize, phase: usize) -> (MessageInfo, u64) {
    if phase == REVOKE && BADGES[id] == BADGE_1 {
        (MessageInfo::new(INVALID_CAPABILITY, 0, 0, 1), 0)
    } else {
        (MessageInfo::new(0, 0, 0, 1), BADGES[id])
    }
}

/// A client's call returned the wrong thing, or nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OutcomeMismatch {
    pub id: usize,
    pub phase: usize,
    pub got: Outcome,
    pub want: (MessageInfo, u64),
}

impl fmt::Display for OutcomeMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "client {}'s call in phase {} ",
            NAMES[self.id], self.phase
        )?;
        match self.got {
            None => f.write_str("never returned")?,
            Some((info, mr0)) => write!(
                f,
                "returned label {}, length {}, MR0 {mr0:#x}",
                info.label(),
                info.length()
            )?,
        }
        let (info, mr0) = self.want;
        write!(
            f,
            "; want label {}, length {}, MR0 {mr0:#x}",
            info.label(),
            info.length()
        )
    }
}

/// Checks every call of every client against [`expected`].
pub fn outcomes(got: &[[Outcome; PHASES]; CLIENTS]) -> Result<(), OutcomeMismatch> {
    for (id, calls) in got.iter().enumerate() {
        for (phase, &o) in calls.iter().enumerate() {
            let want = expected(id, phase);
            if o != Some(want) {
                return Err(OutcomeMismatch {
                    id,
                    phase,
                    got: o,
                    want,
                });
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsys::Message;
    use std::string::ToString;

    fn call(id: usize, phase: usize, badge: u64) -> Received {
        Received {
            badge,
            msg: Message::new(
                MessageInfo::new(label(id, phase), 0, 0, 1),
                [phase as u64, 0, 0, 0],
            ),
        }
    }

    #[test]
    fn senders_are_told_by_label_and_checked_by_badge() {
        for (id, &badge) in BADGES.iter().enumerate() {
            for phase in 0..PHASES {
                assert_eq!(sender(&call(id, phase, badge)), Ok((id, phase)));
            }
        }
        // A2's call with B's badge, U's with A1's.
        assert_eq!(
            sender(&call(A2, 1, BADGE_2)),
            Err(SenderFailure::Badge(
                A2,
                Mismatch {
                    what: "the badge",
                    got: BADGE_2,
                    want: BADGE_1
                }
            ))
        );
        assert!(matches!(
            sender(&call(U, 0, BADGE_1)),
            Err(SenderFailure::Badge(U, _))
        ));
        // A fault message, and messages that are no client's call.
        let fault = Received {
            badge: FAULT_BADGE,
            msg: Message::new(MessageInfo::new(5, 0, 0, 4), [0; 4]),
        };
        assert_eq!(sender(&fault), Err(SenderFailure::Fault { label: 5 }));
        for (l, length) in [
            (label(4, 0), 1),
            (label(0, 5), 1),
            (0x1234, 1),
            (label(0, 0), 2),
        ] {
            let r = Received {
                badge: 0,
                msg: Message::new(MessageInfo::new(l, 0, 0, length), [0; 4]),
            };
            assert_eq!(
                sender(&r),
                Err(SenderFailure::NotACall { label: l, length })
            );
        }
        assert_eq!(
            sender(&fault).unwrap_err().to_string(),
            "a client faulted: fault type 5 on the fault endpoint"
        );
    }

    #[test]
    fn the_receive_order() {
        assert_eq!(order(&[U, B, A1, A2], &[U, B, A1, A2]), Ok(()));
        let e = order(&[B, U, A1, A2], &[U, B, A1, A2]).unwrap_err();
        assert_eq!(
            e.to_string(),
            "received from B, U, A1, A2, not U, B, A1, A2"
        );
        assert!(order(&[U, B], &[U, B, A1]).is_err());
        assert_eq!(Names(&[A1, 9]).to_string(), "A1, ?");
    }

    #[test]
    fn free_rounds_come_in_phase_order() {
        let all = [[Some(0), Some(1), Some(2)]; CLIENTS];
        assert_eq!(free_rounds(&all), Ok(()));
        let mut short = all;
        short[B][2] = None;
        assert_eq!(
            free_rounds(&short).map_err(|(id, m)| (id, m.got)),
            Err((B, u64::MAX))
        );
        let mut swapped = all;
        swapped[U] = [Some(1), Some(0), Some(2)];
        assert_eq!(
            free_rounds(&swapped).map_err(|(id, m)| (id, m.got)),
            Err((U, 1))
        );
    }

    #[test]
    fn outcomes_follow_the_design() {
        let mut got = [[None; PHASES]; CLIENTS];
        for (id, calls) in got.iter_mut().enumerate() {
            for (phase, o) in calls.iter_mut().enumerate() {
                *o = Some(expected(id, phase));
            }
        }
        assert_eq!(outcomes(&got), Ok(()));
        // The revoked clients got InvalidCapability; the others answers.
        assert_eq!(expected(A1, REVOKE).0.label(), INVALID_CAPABILITY);
        assert_eq!(expected(A2, REVOKE).1, 0);
        assert_eq!(expected(B, REVOKE), (MessageInfo::new(0, 0, 0, 1), BADGE_2));
        assert_eq!(expected(U, CANCEL), (MessageInfo::new(0, 0, 0, 1), 0));
        // A2 still queued when the test ended; B answered with a stale
        // badge.
        let mut hung = got;
        hung[A2][REVOKE] = None;
        let e = outcomes(&hung).unwrap_err();
        assert_eq!((e.id, e.phase, e.got), (A2, REVOKE, None));
        assert_eq!(
            e.to_string(),
            "client A2's call in phase 4 never returned; want label 2, length 1, MR0 0x0"
        );
        let mut stale = got;
        stale[B][1] = Some((MessageInfo::new(0, 0, 0, 1), BADGE_1));
        assert_eq!(outcomes(&stale).map_err(|e| (e.id, e.phase)), Err((B, 1)));
    }
}
