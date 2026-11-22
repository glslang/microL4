//! `test=ipcntfn`: "IPC plus notification on one server" (PLAN.md, M6's
//! done-when). The badges, what the server records of each receive, the
//! sequence the scripted part must produce and the verdict on the free
//! part.
//!
//! The server S is bound to notification N and receives on endpoint E.
//! Endpoint capabilities carry badges below bit 32 and notification
//! capabilities badges from bit 32 up, so S tells a signal from a message
//! by the bits in `rdi` ([`libsys::Event::classify`]).

use core::fmt;

use libsys::{Event, Received};

use super::Mismatch;

/// The bits only notification badges use.
pub const SIGNAL_BITS: u64 = 0xFFFF_FFFF_0000_0000;

/// Endpoint badges: the two clients' and the root task's.
pub const CLIENT_BADGES: [u64; 2] = [0x1, 0x2];
pub const ROOT_BADGE: u64 = 0x3;

/// Notification badges: the two signallers', the root task's three, and
/// S's own.
pub const SIGNALLER_BADGES: [u64; 2] = [1 << 32, 1 << 33];
pub const ROOT_SIGNALS: [u64; 3] = [1 << 40, 1 << 41, 1 << 42];
pub const SERVER_SIGNAL: u64 = 1 << 43;

/// The labels of the messages S handles.
pub mod label {
    /// A client's call: S answers MR0 plus one and the badge it saw.
    pub const CALL: u64 = 0xCA11;
    /// The root task's `Send`: no answer.
    pub const PING: u64 = 0x9196;
    /// The root task's call: S answers MR0 plus one.
    pub const ECHO: u64 = 0xEC40;
    /// As `ECHO`, but S signals N itself before its `ReplyRecv`.
    pub const ECHO_SIGNAL: u64 = 0xEC51;
    /// S answers, then waits on N directly once.
    pub const WAIT: u64 = 0xAA17;
    /// S answers; any signal still pending reached S first.
    pub const FLUSH: u64 = 0xF1;
}

/// What S recorded of one receive.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Seen {
    /// An endpoint receive returned a signal: the notification word.
    Signal(u64),
    /// A message: its badge and label.
    Message { badge: u64, label: u64 },
    /// A wait on N itself returned this word.
    Waited(u64),
}

impl Seen {
    /// What an endpoint receive returned.
    pub fn of(r: Received) -> Seen {
        match Event::classify(r, SIGNAL_BITS) {
            Event::Signal(word) => Seen::Signal(word),
            Event::Message(m) => Seen::Message {
                badge: m.badge,
                label: m.msg.info.label(),
            },
        }
    }

    /// Two words, for a log of atomics.
    pub fn encode(self) -> [u64; 2] {
        match self {
            Seen::Signal(w) => [1, w],
            Seen::Message { badge, label } => [2 | label << 8, badge],
            Seen::Waited(w) => [3, w],
        }
    }

    pub fn decode(w: [u64; 2]) -> Option<Seen> {
        match w[0] & 0xFF {
            1 if w[0] == 1 => Some(Seen::Signal(w[1])),
            2 => Some(Seen::Message {
                badge: w[1],
                label: w[0] >> 8,
            }),
            3 if w[0] == 3 => Some(Seen::Waited(w[1])),
            _ => None,
        }
    }
}

impl fmt::Display for Seen {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Seen::Signal(w) => write!(f, "signal {w:#x}"),
            Seen::Message { badge, label } => write!(f, "message {label:#x} badge {badge:#x}"),
            Seen::Waited(w) => write!(f, "wait on N returned {w:#x}"),
        }
    }
}

const fn msg(label: u64) -> Seen {
    Seen::Message {
        badge: ROOT_BADGE,
        label,
    }
}

/// What S must record in the scripted part, in order (the root task's
/// script is in `user/root/src/ipcntfn.rs`):
///
/// 0. a signal woke S out of its endpoint receive;
/// 1. two signals that arrived while S was not receiving, merged, ahead of
/// 2. the message queued on E meanwhile;
/// 3. another signal that woke S, then
/// 4. the root task's call that was queued behind it;
/// 5. a call S handled, signalling N itself before its `ReplyRecv`, whose
///    receive phase then
/// 6. returned that signal at once;
/// 7. a call after which S waits on N directly, and
/// 8. the signal that ended the wait.
pub const SCRIPT: [Seen; 9] = [
    Seen::Signal(ROOT_SIGNALS[0]),
    Seen::Signal(ROOT_SIGNALS[1] | ROOT_SIGNALS[2]),
    msg(label::PING),
    Seen::Signal(ROOT_SIGNALS[2]),
    msg(label::ECHO),
    msg(label::ECHO_SIGNAL),
    Seen::Signal(SERVER_SIGNAL),
    msg(label::WAIT),
    Seen::Waited(ROOT_SIGNALS[1]),
];

/// S's record differs from the script at `at`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScriptMismatch {
    pub at: usize,
    pub got: Option<Seen>,
    pub want: Option<Seen>,
}

impl fmt::Display for ScriptMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "receive {} of the server: ", self.at)?;
        match self.got {
            Some(s) => write!(f, "{s}")?,
            None => f.write_str("none")?,
        }
        f.write_str(", want ")?;
        match self.want {
            Some(s) => write!(f, "{s}"),
            None => f.write_str("none"),
        }
    }
}

/// Checks the first `want.len()` entries S recorded, and that there are
/// no more.
pub fn script(got: &[Seen], want: &[Seen]) -> Result<(), ScriptMismatch> {
    for at in 0..got.len().max(want.len()) {
        let (g, w) = (got.get(at).copied(), want.get(at).copied());
        if g != w {
            return Err(ScriptMismatch {
                at,
                got: g,
                want: w,
            });
        }
    }
    Ok(())
}

/// What the free part counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Tally {
    /// Calls and signals each client and signaller made.
    pub per_thread: u64,
    /// Signals S received from an endpoint receive.
    pub deliveries: u64,
    /// Of those, the ones that carried both signallers' bits.
    pub merged: u64,
    /// The OR of every signal word S received.
    pub signal_or: u64,
    /// Signal words S received that were 0 or had bits no signaller uses.
    pub foreign: u64,
    /// Calls S received from each client.
    pub calls: [u64; 2],
    /// Replies each client received and found right.
    pub answered: [u64; 2],
    /// Each signaller's last `sequence` value before its last signal, and
    /// S's after the last delivery that carried that signaller's bit (0
    /// if none did).
    pub last_sent: [u64; 2],
    pub last_seen: [u64; 2],
}

/// Checks the free part: every call answered, every signaller's bit
/// received, after its last signal, and nothing else.
pub fn free(t: &Tally) -> Result<(), Mismatch> {
    let want = |what, got, want| {
        if got == want {
            Ok(())
        } else {
            Err(Mismatch { what, got, want })
        }
    };
    const CALLS: [&str; 2] = ["calls S received from C1", "calls S received from C2"];
    const ANSWERED: [&str; 2] = ["right answers C1 received", "right answers C2 received"];
    for c in 0..2 {
        want(CALLS[c], t.calls[c], t.per_thread)?;
        want(ANSWERED[c], t.answered[c], t.per_thread)?;
    }
    want(
        "the OR of the signal words S received",
        t.signal_or,
        SIGNALLER_BADGES[0] | SIGNALLER_BADGES[1],
    )?;
    want("signal words with foreign bits", t.foreign, 0)?;
    if t.deliveries == 0 || t.deliveries > 2 * t.per_thread {
        return Err(Mismatch {
            what: "signal deliveries (at least 1, at most one per signal)",
            got: t.deliveries,
            want: 2 * t.per_thread,
        });
    }
    const LAST: [&str; 2] = [
        "the sequence of S's last receipt of G1's bit (after G1's last signal)",
        "the sequence of S's last receipt of G2's bit (after G2's last signal)",
    ];
    for (g, what) in LAST.into_iter().enumerate() {
        if t.last_seen[g] <= t.last_sent[g] {
            return Err(Mismatch {
                what,
                got: t.last_seen[g],
                want: t.last_sent[g] + 1,
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsys::{Message, MessageInfo};
    use std::string::ToString;

    #[test]
    fn badges_keep_to_their_halves() {
        for b in CLIENT_BADGES.into_iter().chain([ROOT_BADGE]) {
            assert!(b != 0 && b & SIGNAL_BITS == 0);
        }
        let signals = SIGNALLER_BADGES
            .into_iter()
            .chain(ROOT_SIGNALS)
            .chain([SERVER_SIGNAL]);
        let mut all = 0;
        for b in signals {
            assert!(b & !SIGNAL_BITS == 0 && b.count_ones() == 1);
            assert_eq!(all & b, 0, "{b:#x} twice");
            all |= b;
        }
    }

    #[test]
    fn what_s_records() {
        let sig = Received {
            badge: SIGNALLER_BADGES[0] | SIGNALLER_BADGES[1],
            msg: Message::EMPTY,
        };
        assert_eq!(Seen::of(sig), Seen::Signal(3 << 32));
        let call = Received {
            badge: CLIENT_BADGES[1],
            msg: Message::new(MessageInfo::new(label::CALL, 0, 0, 1), [9, 0, 0, 0]),
        };
        assert_eq!(
            Seen::of(call),
            Seen::Message {
                badge: 2,
                label: label::CALL
            }
        );
        for s in SCRIPT {
            assert_eq!(Seen::decode(s.encode()), Some(s));
        }
        assert_eq!(Seen::decode([0, 0]), None);
        assert_eq!(Seen::decode([0x101, 0]), None);
        assert_eq!(SCRIPT[1].to_string(), "signal 0x60000000000");
        assert_eq!(SCRIPT[2].to_string(), "message 0x9196 badge 0x3");
    }

    #[test]
    fn the_script_must_match_exactly() {
        assert_eq!(script(&SCRIPT, &SCRIPT), Ok(()));
        // The merged signals delivered one at a time.
        let mut split = SCRIPT;
        split[1] = Seen::Signal(ROOT_SIGNALS[1]);
        let e = script(&split, &SCRIPT).unwrap_err();
        assert_eq!(e.at, 1);
        assert_eq!(
            e.to_string(),
            "receive 1 of the server: signal 0x20000000000, want signal 0x60000000000"
        );
        // The message before the pending signal.
        let mut swapped = SCRIPT;
        swapped.swap(1, 2);
        assert_eq!(script(&swapped, &SCRIPT).map_err(|e| e.at), Err(1));
        // One receive missing, one too many.
        assert_eq!(script(&SCRIPT[..8], &SCRIPT).map_err(|e| e.at), Err(8));
        let mut more = [Seen::Waited(0); 10];
        more[..9].copy_from_slice(&SCRIPT);
        assert_eq!(
            script(&more, &SCRIPT).map_err(|e| (e.at, e.want)),
            Err((9, None))
        );
    }

    fn good() -> Tally {
        Tally {
            per_thread: 100,
            deliveries: 150,
            merged: 20,
            signal_or: 3 << 32,
            foreign: 0,
            calls: [100, 100],
            answered: [100, 100],
            last_sent: [700, 702],
            last_seen: [701, 705],
        }
    }

    #[test]
    fn the_free_part() {
        assert_eq!(free(&good()), Ok(()));
        let what = |f: &dyn Fn(&mut Tally)| {
            let mut t = good();
            f(&mut t);
            free(&t).map_err(|m| m.what)
        };
        assert_eq!(what(&|t| t.calls[1] = 99), Err("calls S received from C2"));
        assert_eq!(
            what(&|t| t.answered[0] = 0),
            Err("right answers C1 received")
        );
        assert_eq!(
            what(&|t| t.signal_or = 1 << 32),
            Err("the OR of the signal words S received")
        );
        assert_eq!(
            what(&|t| t.foreign = 1),
            Err("signal words with foreign bits")
        );
        assert_eq!(
            what(&|t| t.deliveries = 201),
            Err("signal deliveries (at least 1, at most one per signal)")
        );
        assert_eq!(
            what(&|t| t.deliveries = 0),
            Err("signal deliveries (at least 1, at most one per signal)")
        );
        assert_eq!(
            what(&|t| t.last_seen[1] = 702),
            Err("the sequence of S's last receipt of G2's bit (after G2's last signal)")
        );
    }
}
