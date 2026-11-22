//! `test=pingpong`: the messages of each round trip, the server's answer,
//! the check of each reply, and the timing arithmetic.
//!
//! The root task's request `i` carries the round trip's [`Shape`] and `i`
//! in its label, `i` in MR0 when it has words, and `!i` in MR119 when it is
//! full-length. The server answers with the same shape, `i + 1` in the
//! label's counter and MR0, and MR119 plus one, so every reply proves the
//! server saw that request.

use libsys::{Message, MessageInfo};

use super::Mismatch;

/// How long a round trip's messages are.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    /// No message registers: the label only.
    Zero,
    /// One, MR0, in a register.
    One,
    /// All 120: MR4 to MR119 travel through both IPC buffers.
    Full,
}

impl Shape {
    /// The runs, in order: the done-when's first.
    pub const ALL: [Shape; 3] = [Shape::One, Shape::Zero, Shape::Full];

    /// Message registers each message carries.
    pub const fn words(self) -> u64 {
        match self {
            Shape::Zero => 0,
            Shape::One => 1,
            Shape::Full => 120,
        }
    }

    const fn tag(self) -> u64 {
        match self {
            Shape::Zero => 1,
            Shape::One => 2,
            Shape::Full => 3,
        }
    }

    fn from_tag(tag: u64) -> Option<Shape> {
        Shape::ALL.into_iter().find(|s| s.tag() == tag)
    }
}

/// The last message register, which only a full-length message carries.
pub const LAST: usize = 119;

const COUNTER_BITS: u32 = 32;
const COUNTER_MASK: u64 = (1 << COUNTER_BITS) - 1;

/// The label of a message of `shape` with counter `i` (its low 32 bits).
pub const fn label(shape: Shape, i: u64) -> u64 {
    shape.tag() << COUNTER_BITS | (i & COUNTER_MASK)
}

/// What MR119 holds in request `i`.
pub const fn last_word(i: u64) -> u64 {
    !i
}

/// Request `i` of `shape`, as it travels in registers; for a full-length
/// one the sender also puts [`last_word`]`(i)` in MR119, and MR4 to MR118
/// hold whatever its buffer holds.
pub fn request(shape: Shape, i: u64) -> Message {
    let info = MessageInfo::new(label(shape, i), 0, 0, shape.words());
    let mr0 = if shape.words() > 0 { i } else { 0 };
    Message::new(info, [mr0, 0, 0, 0])
}

/// The server's answer to `msg`, whose MR119 was `last` if it is
/// full-length: the reply, and what its MR119 must be. Fails if `msg` is no
/// request.
pub fn answer(msg: &Message, last: u64) -> Result<(Message, u64), Mismatch> {
    let tag = msg.info.label() >> COUNTER_BITS;
    let shape = Shape::from_tag(tag).ok_or(Mismatch {
        what: "the request label's shape",
        got: tag,
        want: Shape::One.tag(),
    })?;
    expect("the request's length", msg.info.length(), shape.words())?;
    expect("the request's extra_caps", msg.info.extra_caps(), 0)?;
    let next = (msg.info.label() & COUNTER_MASK) + 1;
    let info = MessageInfo::new(label(shape, next), 0, 0, shape.words());
    let mr0 = if shape.words() > 0 { msg.mr[0] + 1 } else { 0 };
    Ok((Message::new(info, [mr0, 0, 0, 0]), last.wrapping_add(1)))
}

/// Checks the reply to request `i` of `shape`; `last` is its MR119, read
/// only for a full-length one.
pub fn check_reply(shape: Shape, i: u64, reply: &Message, last: u64) -> Result<(), Mismatch> {
    expect("the reply's label", reply.info.label(), label(shape, i + 1))?;
    expect("the reply's length", reply.info.length(), shape.words())?;
    expect("the reply's extra_caps", reply.info.extra_caps(), 0)?;
    if shape.words() > 0 {
        expect("the reply's MR0", reply.mr[0], i + 1)?;
    }
    if shape == Shape::Full {
        expect("the reply's MR119", last, last_word(i).wrapping_add(1))?;
    }
    Ok(())
}

/// What a fixed word of the full-length runs' MR4 to MR118 holds; the
/// server echoes them, so after the run they must be unchanged.
pub const fn pattern(i: usize) -> u64 {
    (i as u64).wrapping_mul(0x0101_0101_0101_0101) ^ 0x5A5A_0000_0000_5A5A
}

fn expect(what: &'static str, got: u64, want: u64) -> Result<(), Mismatch> {
    if got == want {
        Ok(())
    } else {
        Err(Mismatch { what, got, want })
    }
}

/// A run's time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Timing {
    /// Round trips timed.
    pub trips: u64,
    /// TSC cycles from before the first round trip to after the last.
    pub total: u64,
    /// `total` over the round trips, rounded down.
    pub mean: u64,
    /// The fastest round trip, and the median one (the lower of the two
    /// middle ones for an even count). Under TCG the TSC follows host
    /// time, so a busy host inflates the mean; these two show the trend.
    pub fastest: u64,
    pub median: u64,
}

impl Timing {
    /// The timing of round trips that took `samples` TSC cycles each,
    /// back to back; sorts `samples`.
    pub fn of(samples: &mut [u64]) -> Timing {
        samples.sort_unstable();
        let trips = samples.len() as u64;
        let total = samples.iter().fold(0u64, |t, &s| t.saturating_add(s));
        let middle = samples.len().saturating_sub(1) / 2;
        Timing {
            trips,
            total,
            mean: total.checked_div(trips).unwrap_or(0),
            fastest: samples.first().copied().unwrap_or(0),
            median: samples.get(middle).copied().unwrap_or(0),
        }
    }
}

/// `cycles` TSC cycles in nanoseconds at `tsc_hz` (BootInfo's), rounded to
/// the nearest; `None` without a rate.
pub fn ns(cycles: u64, tsc_hz: u64) -> Option<u64> {
    (tsc_hz > 0).then(|| {
        let num = u128::from(cycles) * 1_000_000_000;
        let den = u128::from(tsc_hz);
        u64::try_from((num + den / 2) / den).unwrap_or(u64::MAX)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_reply_checks_out() {
        for shape in Shape::ALL {
            for i in [0, 1, 999, u32::MAX as u64 - 1] {
                let req = request(shape, i);
                assert_eq!(req.info.length(), shape.words());
                let (reply, last) = answer(&req, last_word(i)).unwrap();
                assert_eq!(check_reply(shape, i, &reply, last), Ok(()), "{shape:?} {i}");
            }
        }
    }

    #[test]
    fn a_wrong_reply_fails() {
        let (good, last) = answer(&request(Shape::Full, 7), last_word(7)).unwrap();
        assert_eq!(check_reply(Shape::Full, 7, &good, last), Ok(()));
        // An answer to another request, another shape, a stale MR0 or MR119.
        let (other, _) = answer(&request(Shape::Full, 8), last_word(8)).unwrap();
        let what = |r: &Message, last| check_reply(Shape::Full, 7, r, last).map_err(|m| m.what);
        assert_eq!(what(&other, last), Err("the reply's label"));
        let short = Message::new(MessageInfo::new(label(Shape::Full, 8), 0, 0, 4), good.mr);
        assert_eq!(what(&short, last), Err("the reply's length"));
        let stale = Message::new(good.info, [7, 0, 0, 0]);
        assert_eq!(what(&stale, last), Err("the reply's MR0"));
        assert_eq!(what(&good, last_word(7)), Err("the reply's MR119"));
        let one = answer(&request(Shape::One, 7), 0).unwrap().0;
        assert_eq!(what(&one, last), Err("the reply's label"));
        // MR0 and MR119 mean nothing in a zero-length reply.
        let zero = answer(&request(Shape::Zero, 3), 0).unwrap().0;
        assert_eq!(zero.mr, [0; 4]);
        assert_eq!(check_reply(Shape::Zero, 3, &zero, 12345), Ok(()));
    }

    #[test]
    fn the_server_refuses_what_is_no_request() {
        let bad = Message::new(MessageInfo::new(0x9 << 32, 0, 0, 1), [0; 4]);
        assert_eq!(
            answer(&bad, 0).map_err(|m| m.what),
            Err("the request label's shape")
        );
        let long = Message::new(MessageInfo::new(label(Shape::One, 0), 0, 0, 2), [0; 4]);
        assert_eq!(
            answer(&long, 0).map_err(|m| m.what),
            Err("the request's length")
        );
        let caps = Message::new(MessageInfo::new(label(Shape::One, 0), 0, 1, 1), [0; 4]);
        assert_eq!(
            answer(&caps, 0).map_err(|m| m.what),
            Err("the request's extra_caps")
        );
    }

    #[test]
    fn timing_arithmetic() {
        let mut samples = [30, 10, 20, 1000, 25];
        let t = Timing::of(&mut samples);
        assert_eq!(
            (t.trips, t.total, t.mean, t.fastest, t.median),
            (5, 1085, 217, 10, 25)
        );
        assert_eq!(samples, [10, 20, 25, 30, 1000], "sorted");
        // An even count takes the lower middle one.
        let t = Timing::of(&mut [4, 1, 3, 2]);
        assert_eq!((t.mean, t.fastest, t.median), (2, 1, 2));
        let t = Timing::of(&mut []);
        assert_eq!(
            (t.trips, t.total, t.mean, t.fastest, t.median),
            (0, 0, 0, 0, 0)
        );
        assert_eq!(Timing::of(&mut [u64::MAX, 2]).total, u64::MAX);
        // 2.112 GHz, as on the owner's Hyper-V host: 2,112 cycles is 1 us,
        // to the nearest nanosecond.
        assert_eq!(ns(2112, 2_112_000_000), Some(1000));
        assert_eq!(ns(1999, 1_000_000_000), Some(1999));
        assert_eq!(ns(3, 2_000_000_000), Some(2));
        // No rate: cycles only. No overflow at the extremes.
        assert_eq!(ns(5, 0), None);
        assert_eq!(ns(u64::MAX, 1), Some(u64::MAX));
        assert_eq!(ns(u64::MAX, u64::MAX), Some(1_000_000_000));
    }

    #[test]
    fn the_pattern_differs_word_to_word() {
        assert_ne!(pattern(4), pattern(5));
        assert_ne!(pattern(4), 0);
    }
}
