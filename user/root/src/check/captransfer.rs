//! `test=captransfer`: the steps both sides follow, the server's report and
//! the verdict on each step (`docs/abi.md`, "Capability transfer").
//!
//! The root task, the client C, makes one `Call` per step on endpoint E;
//! the server S receives it in a CSpace of its own, which holds only what
//! the root task put there and what S received. [`STEPS`] says, for each
//! step, what C sends and through which capability, where S receives it
//! and what S does with what arrived, and what the step must show. S
//! answers every step with a [`Report`] of what it saw.

use libsys::MessageInfo;

use super::Mismatch;

/// S's CSpace: one CNode of `2^S_RADIX` slots, whose CSpace-root
/// capability has a guard of the `S_GUARD_BITS` bits above, so S's `CPtr`
/// `n` names slot `n`.
pub const S_RADIX: u64 = 6;
pub const S_GUARD_BITS: u64 = 64 - S_RADIX;

/// The slots of S's CNode, which are also S's `CPtr`s.
pub mod s_slot {
    /// E with Read and Grant: a reply to a call received through it may
    /// carry capabilities.
    pub const EP: u64 = 1;
    /// E with Read only: a reply to a call received through it carries
    /// none.
    pub const EP_NO_GRANT: u64 = 2;
    /// S's own CNode, unguarded: the receive slots and the probes name
    /// slots from it with depth [`super::S_RADIX`].
    pub const CNODE: u64 = 3;
    /// The root task's VSpace, which S shares, to map a received frame.
    pub const VSPACE: u64 = 4;
    /// Receive slots.
    pub const FOR_EP: u64 = 8;
    pub const FOR_FRAME: u64 = 9;
    pub const SPARE_A: u64 = 10;
    pub const SPARE_B: u64 = 11;
}

/// The receive slots S probes after each step: bit `i` of a report's
/// `full` is slot `PROBED[i]`.
pub const PROBED: [u64; 4] = [
    s_slot::FOR_EP,
    s_slot::FOR_FRAME,
    s_slot::SPARE_A,
    s_slot::SPARE_B,
];

/// What S writes in `caps_or_badges` before each receive: an entry the
/// kernel does not unwrap into must still hold it afterwards.
pub const SENTINELS: [u64; 3] = [0x5E47_0000, 0x5E47_0001, 0x5E47_0002];

/// The badge of C's capability to E that the kernel unwraps.
pub const UNWRAP_BADGE: u64 = 0x5E55;
/// The badge of C's capability to its own endpoint E2, which it sends S.
pub const E2_BADGE: u64 = 0xE2;
/// What C writes in the frame it sends.
pub const MAGIC: u64 = 0x00C0_FFEE_CAB5_F00D;
/// The label of S's call back on the endpoint capability it received, and
/// the word it carries; C answers with the word plus one.
pub const PING: u64 = 0x9196;
pub const PING_WORD: u64 = 0x1234_5678;

/// Which of C's capabilities to E a step calls through.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Via {
    /// E's original: every right, Grant included.
    Grant,
    /// A copy with Write and GrantReply: `Call` works, nothing moves.
    NoGrant,
}

/// A capability C sends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Sent {
    /// C's capability to E2, badge [`E2_BADGE`], Write and GrantReply: a
    /// badged original, so S's copy is its child.
    E2,
    /// A copy of frame F, which C maps and writes: S's copy is its
    /// sibling and F's child.
    FrameCopy,
    /// Frame F2, an original, unmapped.
    Frame2,
    /// C's capability to E itself with badge [`UNWRAP_BADGE`] and no rights.
    EpBadged,
    /// C's unbadged copy of E with Write and GrantReply.
    EpUnbadged,
}

/// What S does with a step's message before it reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Nothing,
    /// Maps the frame in [`s_slot::FOR_FRAME`] read-only at the server
    /// page and reads its first word.
    MapAndRead,
    /// Reads the server page's first word again, through the mapping
    /// `MapAndRead` made.
    ReadAgain,
    /// After its reply, calls [`s_slot::FOR_EP`] with [`PING`]; C receives
    /// it on E2 and answers.
    CallBack,
}

/// What C does before a step's call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Before {
    Nothing,
    /// Revokes and deletes the frame copy it sent: S's copy, a sibling,
    /// survives both.
    DropSentCopy,
    /// Revokes F and its E2 capability: S's copies, their children, go.
    RevokeOriginals,
}

/// What a step must show.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Expect {
    /// The `extra_caps` S received.
    pub extra_caps: u64,
    /// The `caps_unwrapped` S received.
    pub unwrapped: u64,
    /// S's `caps_or_badges` after the receive: the badge where unwrapped,
    /// [`SENTINELS`] elsewhere.
    pub badges: [Option<u64>; 3],
    /// S's probed slots that hold a capability after the step, bit `i`
    /// for `PROBED[i]`.
    pub full: u64,
    /// The word S read from the server page, if it read one.
    pub value: Option<u64>,
    /// The `extra_caps` of the reply C received.
    pub reply_caps: u64,
}

/// One step.
#[derive(Clone, Copy, Debug)]
pub struct Step {
    pub name: &'static str,
    pub before: Before,
    pub via: Via,
    pub caps: &'static [Sent],
    /// S receives this step's message on this capability (one of
    /// [`s_slot`]), with this receive slot.
    pub recv_on: u64,
    pub slot: Option<u64>,
    pub action: Action,
    /// The capabilities S sends back in its reply (S's `CPtr`s).
    pub reply_caps: &'static [u64],
    /// Whether C names a receive slot for the reply.
    pub reply_slot: bool,
    pub expect: Expect,
}

const NONE: [Option<u64>; 3] = [None; 3];
const fn expect(extra_caps: u64, unwrapped: u64, badges: [Option<u64>; 3], full: u64) -> Expect {
    Expect {
        extra_caps,
        unwrapped,
        badges,
        full,
        value: None,
        reply_caps: 0,
    }
}
const fn step(name: &'static str, via: Via, caps: &'static [Sent], slot: Option<u64>) -> Step {
    Step {
        name,
        before: Before::Nothing,
        via,
        caps,
        recv_on: s_slot::EP,
        slot,
        action: Action::Nothing,
        reply_caps: &[],
        reply_slot: false,
        expect: expect(0, 0, NONE, 0),
    }
}

/// The steps, in order.
pub const STEPS: [Step; 10] = [
    Step {
        action: Action::CallBack,
        expect: expect(1, 0, NONE, 0b0001),
        ..step(
            "an endpoint capability: S calls C back through its copy",
            Via::Grant,
            &[Sent::E2],
            Some(s_slot::FOR_EP),
        )
    },
    Step {
        action: Action::MapAndRead,
        expect: Expect {
            value: Some(MAGIC),
            ..expect(1, 0, NONE, 0b0011)
        },
        ..step(
            "a frame capability: S maps its copy and reads what C wrote",
            Via::Grant,
            &[Sent::FrameCopy],
            Some(s_slot::FOR_FRAME),
        )
    },
    Step {
        expect: expect(0, 0, NONE, 0b0011),
        ..step(
            "without Grant nothing moves, not even a capability to E",
            Via::NoGrant,
            &[Sent::EpBadged, Sent::Frame2],
            Some(s_slot::SPARE_A),
        )
    },
    Step {
        expect: expect(3, 0b011, [Some(UNWRAP_BADGE), Some(0), None], 0b0111),
        ..step(
            "capabilities to E arrive unwrapped as their badges, whatever their rights, and leave the slot to F2",
            Via::Grant,
            &[Sent::EpBadged, Sent::EpUnbadged, Sent::Frame2],
            Some(s_slot::SPARE_A),
        )
    },
    Step {
        action: Action::ReadAgain,
        expect: Expect {
            value: Some(MAGIC),
            ..expect(1, 0b001, [Some(UNWRAP_BADGE), None, None], 0b0111)
        },
        ..step(
            "an occupied receive slot ends the transfer at F2, after the unwrapped capability",
            Via::Grant,
            &[Sent::EpBadged, Sent::Frame2],
            Some(s_slot::FOR_FRAME),
        )
    },
    Step {
        expect: expect(1, 0, NONE, 0b1111),
        ..step(
            "one copy per message: the second capability finds the slot used",
            Via::Grant,
            &[Sent::Frame2, Sent::FrameCopy],
            Some(s_slot::SPARE_B),
        )
    },
    Step {
        reply_caps: &[s_slot::EP],
        reply_slot: true,
        expect: Expect {
            reply_caps: 1,
            ..expect(0, 0, NONE, 0b1111)
        },
        ..step(
            "a reply through a reply capability with Grant carries S's capability to E, copied, not unwrapped",
            Via::Grant,
            &[],
            None,
        )
    },
    Step {
        recv_on: s_slot::EP_NO_GRANT,
        reply_caps: &[s_slot::EP],
        reply_slot: true,
        expect: expect(0, 0, NONE, 0b1111),
        ..step(
            "a reply to a call S received without Grant carries nothing",
            Via::Grant,
            &[],
            None,
        )
    },
    Step {
        before: Before::DropSentCopy,
        action: Action::ReadAgain,
        expect: Expect {
            value: Some(MAGIC),
            ..expect(0, 0, NONE, 0b1111)
        },
        ..step(
            "C revoked and deleted the frame copy it sent: S's copy, its sibling, still maps the frame",
            Via::Grant,
            &[],
            None,
        )
    },
    Step {
        before: Before::RevokeOriginals,
        expect: expect(0, 0, NONE, 0b1100),
        ..step(
            "C revoked F and its E2 capability: S's copies, their children, are gone",
            Via::Grant,
            &[],
            None,
        )
    },
];

/// What S saw in a step, which its reply carries in MR0 to MR6.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    /// The `MessageInfo` and badge S received.
    pub info: MessageInfo,
    pub badge: u64,
    /// The probed slots that hold a capability, bit `i` for `PROBED[i]`.
    pub full: u64,
    /// The word S read from the server page, or 0.
    pub value: u64,
    /// S's `caps_or_badges` after the receive.
    pub caps_or_badges: [u64; 3],
}

/// Words in a report.
pub const REPORT_WORDS: usize = 7;

impl Report {
    pub fn encode(&self) -> [u64; REPORT_WORDS] {
        let [b0, b1, b2] = self.caps_or_badges;
        [
            self.info.word(),
            self.badge,
            self.full,
            self.value,
            b0,
            b1,
            b2,
        ]
    }

    pub fn decode(w: [u64; REPORT_WORDS]) -> Report {
        Report {
            info: MessageInfo::from_word(w[0]),
            badge: w[1],
            full: w[2],
            value: w[3],
            caps_or_badges: [w[4], w[5], w[6]],
        }
    }
}

fn want(what: &'static str, got: u64, want: u64) -> Result<(), Mismatch> {
    if got == want {
        Ok(())
    } else {
        Err(Mismatch { what, got, want })
    }
}

/// Checks step `i`: S's report `r`, and `reply`, the `MessageInfo` of the
/// reply C received. C calls with label `i` and one word, through an
/// unbadged capability, so S must have received exactly that.
pub fn check(i: usize, step: &Step, r: &Report, reply: MessageInfo) -> Result<(), Mismatch> {
    let e = &step.expect;
    want("the reply's label (S's step)", reply.label(), i as u64)?;
    want("the reply's length", reply.length(), REPORT_WORDS as u64)?;
    want("the label S received", r.info.label(), i as u64)?;
    want("the length S received", r.info.length(), 1)?;
    want("the badge S received", r.badge, 0)?;
    want(
        "the extra_caps S received",
        r.info.extra_caps(),
        e.extra_caps,
    )?;
    want(
        "the caps_unwrapped S received",
        r.info.caps_unwrapped(),
        e.unwrapped,
    )?;
    const WHAT: [&str; 3] = [
        "S's caps_or_badges[0]",
        "S's caps_or_badges[1]",
        "S's caps_or_badges[2]",
    ];
    for (j, b) in e.badges.iter().enumerate() {
        want(WHAT[j], r.caps_or_badges[j], b.unwrap_or(SENTINELS[j]))?;
    }
    want("S's full receive slots", r.full, e.full)?;
    if let Some(v) = e.value {
        want("the word S read from the frame", r.value, v)?;
    }
    want("the reply's extra_caps", reply.extra_caps(), e.reply_caps)?;
    want("the reply's caps_unwrapped", reply.caps_unwrapped(), 0)?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The report a kernel that follows `docs/abi.md` makes S send for
    /// step `i`.
    fn good(i: usize) -> (Report, MessageInfo) {
        let e = STEPS[i].expect;
        let r = Report {
            info: MessageInfo::new(i as u64, e.unwrapped, e.extra_caps, 1),
            badge: 0,
            full: e.full,
            value: e.value.unwrap_or(0),
            caps_or_badges: core::array::from_fn(|j| e.badges[j].unwrap_or(SENTINELS[j])),
        };
        let reply = MessageInfo::new(i as u64, 0, e.reply_caps, REPORT_WORDS as u64);
        (r, reply)
    }

    #[test]
    fn reports_round_trip() {
        let (r, _) = good(3);
        assert_eq!(Report::decode(r.encode()), r);
    }

    #[test]
    fn the_steps_are_consistent() {
        for (i, s) in STEPS.iter().enumerate() {
            let e = s.expect;
            // Something moves only with Grant, and never more than was sent.
            assert!(e.extra_caps as usize <= s.caps.len(), "step {i}");
            if s.via == Via::NoGrant {
                assert_eq!((e.extra_caps, e.unwrapped), (0, 0), "step {i}");
            }
            // Unwrapped bits name processed capabilities to E, with badges.
            for j in 0..3 {
                let unwrapped = e.unwrapped & (1 << j) != 0;
                assert_eq!(unwrapped, e.badges[j].is_some(), "step {i} cap {j}");
                if unwrapped {
                    assert!(j < e.extra_caps as usize, "step {i} cap {j}");
                    assert!(
                        matches!(s.caps[j], Sent::EpBadged | Sent::EpUnbadged),
                        "step {i} cap {j}"
                    );
                }
            }
            // At most one processed capability is copied.
            let copied = e.extra_caps - u64::from(e.unwrapped.count_ones());
            assert!(copied <= 1, "step {i}");
            // A reply carries capabilities only when C offers a slot.
            assert!(e.reply_caps <= s.reply_caps.len() as u64, "step {i}");
            if !s.reply_slot {
                assert!(s.reply_caps.is_empty(), "step {i}");
            }
            // Reading the page needs it mapped: once by step 1, until 9.
            if s.action != Action::Nothing && s.action != Action::CallBack {
                assert!((1..9).contains(&i), "step {i}");
            }
            assert_eq!(good(i).0.info.label(), i as u64);
        }
        // The slots fill as the steps say and only revokes empty them.
        for w in STEPS.windows(2) {
            if w[1].before != Before::RevokeOriginals {
                assert_eq!(w[0].expect.full & !w[1].expect.full, 0);
            }
        }
    }

    #[test]
    fn every_good_report_passes() {
        for (i, step) in STEPS.iter().enumerate() {
            let (r, reply) = good(i);
            assert_eq!(check(i, step, &r, reply), Ok(()), "step {i}");
        }
    }

    #[test]
    fn what_a_kernel_without_transfer_reports_fails() {
        // M5's kernel moves nothing: S gets extra_caps 0.
        let (mut r, reply) = good(0);
        r.info = MessageInfo::new(0, 0, 0, 1);
        r.full = 0;
        assert_eq!(
            check(0, &STEPS[0], &r, reply).map_err(|m| m.what),
            Err("the extra_caps S received")
        );
    }

    #[test]
    fn each_wrong_word_fails() {
        let what = |i: usize, f: &dyn Fn(&mut Report, &mut MessageInfo)| {
            let (mut r, mut reply) = good(i);
            f(&mut r, &mut reply);
            check(i, &STEPS[i], &r, reply).map_err(|m| m.what)
        };
        assert_eq!(
            what(3, &|_, reply| *reply = MessageInfo::new(4, 0, 0, 7)),
            Err("the reply's label (S's step)")
        );
        assert_eq!(
            what(3, &|_, reply| *reply = MessageInfo::new(3, 0, 0, 4)),
            Err("the reply's length")
        );
        assert_eq!(
            what(3, &|r, _| r.badge = UNWRAP_BADGE),
            Err("the badge S received")
        );
        assert_eq!(
            what(3, &|r, _| r.info = MessageInfo::new(3, 0b111, 3, 1)),
            Err("the caps_unwrapped S received")
        );
        assert_eq!(
            what(3, &|r, _| r.caps_or_badges[1] = SENTINELS[1]),
            Err("S's caps_or_badges[1]")
        );
        assert_eq!(
            what(2, &|r, _| r.caps_or_badges[0] = UNWRAP_BADGE),
            Err("S's caps_or_badges[0]")
        );
        assert_eq!(
            what(4, &|r, _| r.full = 0b0011),
            Err("S's full receive slots")
        );
        assert_eq!(
            what(1, &|r, _| r.value = 0),
            Err("the word S read from the frame")
        );
        assert_eq!(
            what(6, &|_, reply| *reply = MessageInfo::new(6, 0, 0, 7)),
            Err("the reply's extra_caps")
        );
        assert_eq!(
            what(7, &|_, reply| *reply = MessageInfo::new(7, 0, 1, 7)),
            Err("the reply's extra_caps")
        );
        assert_eq!(
            what(6, &|_, reply| *reply = MessageInfo::new(6, 1, 1, 7)),
            Err("the reply's caps_unwrapped")
        );
        // A step that reads nothing ignores the value.
        assert_eq!(what(0, &|r, _| r.value = 99), Ok(()));
    }
}
