//! `test=pingpong`: the messages of each round trip, the server's answer,
//! the check of each reply, and the timing arithmetic.
//!
//! The root task's request `i` carries the round trip's [`Shape`] and `i`
//! in its label, and `i` in MR0 when it has words. The server answers with
//! the same shape and `i + 1` in the label's counter and MR0. A
//! full-length request also carries [`word`]`(k, 2i)` in each of MR4 to
//! MR119, which travel through both IPC buffers: the server checks every
//! one and answers each plus one, [`word`]`(k, 2i + 1)`, and the root task
//! checks every word of the reply and adds one again, which makes its next
//! request. So every reply proves the server saw that request, and every
//! buffer word that crossed, both ways.

use core::fmt;

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

/// The first message register in the IPC buffer.
pub const FIRST_BUFFER_MR: usize = 4;
/// The last message register, which only a full-length message carries.
pub const LAST: usize = 119;

const COUNTER_BITS: u32 = 32;
const COUNTER_MASK: u64 = (1 << COUNTER_BITS) - 1;

/// The label of a message of `shape` with counter `i` (its low 32 bits).
pub const fn label(shape: Shape, i: u64) -> u64 {
    shape.tag() << COUNTER_BITS | (i & COUNTER_MASK)
}

/// Request `i` of `shape`, as it travels in registers; for a full-length
/// one MR4 to MR119 hold whatever the sender's buffer holds, which must be
/// [`word`]`(k, 2i)`.
pub fn request(shape: Shape, i: u64) -> Message {
    let info = MessageInfo::new(label(shape, i), 0, 0, shape.words());
    let mr0 = if shape.words() > 0 { i } else { 0 };
    Message::new(info, [mr0, 0, 0, 0])
}

/// The shape and counter of request `msg`. Fails if `msg` is no request.
pub fn parse_request(msg: &Message) -> Result<(Shape, u64), Mismatch> {
    let tag = msg.info.label() >> COUNTER_BITS;
    let shape = Shape::from_tag(tag).ok_or(Mismatch {
        what: "the request label's shape",
        got: tag,
        want: Shape::One.tag(),
    })?;
    expect("the request's length", msg.info.length(), shape.words())?;
    expect("the request's extra_caps", msg.info.extra_caps(), 0)?;
    Ok((shape, msg.info.label() & COUNTER_MASK))
}

/// The server's answer to `msg`, as it travels in registers; for a
/// full-length one the server has made MR4 to MR119 the reply's with
/// [`advance`]. Fails if `msg` is no request.
pub fn answer(msg: &Message) -> Result<Message, Mismatch> {
    let (shape, i) = parse_request(msg)?;
    let info = MessageInfo::new(label(shape, i + 1), 0, 0, shape.words());
    let mr0 = if shape.words() > 0 { msg.mr[0] + 1 } else { 0 };
    Ok(Message::new(info, [mr0, 0, 0, 0]))
}

/// Checks the registers of the reply to request `i` of `shape`; for a
/// full-length one the root task then checks MR4 to MR119 with
/// [`advance`].
pub fn check_reply(shape: Shape, i: u64, reply: &Message) -> Result<(), Mismatch> {
    expect("the reply's label", reply.info.label(), label(shape, i + 1))?;
    expect("the reply's length", reply.info.length(), shape.words())?;
    expect("the reply's extra_caps", reply.info.extra_caps(), 0)?;
    if shape.words() > 0 {
        expect("the reply's MR0", reply.mr[0], i + 1)?;
    }
    Ok(())
}

/// A base value for MR`k`, different for each `k` from 4 to 119.
pub const fn pattern(k: usize) -> u64 {
    (k as u64).wrapping_mul(0x0101_0101_0101_0101) ^ 0x5A5A_0000_0000_5A5A
}

/// What MR`k`, 4 to 119, holds in message `n` of a full-length run:
/// request `i` is message `2i`, its reply message `2i + 1`.
pub const fn word(k: usize, n: u64) -> u64 {
    pattern(k).wrapping_add(n)
}

/// The message number of request `i` of a full-length run.
pub const fn request_number(i: u64) -> u64 {
    2 * i
}

/// The message number of the reply to request `i`.
pub const fn reply_number(i: u64) -> u64 {
    2 * i + 1
}

/// A buffer word that is not what it should be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WordMismatch {
    pub mr: usize,
    pub got: u64,
    pub want: u64,
}

impl fmt::Display for WordMismatch {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "MR{} is {:#x}, not {:#x}", self.mr, self.got, self.want)
    }
}

/// Checks that MR4 to MR119, which `mr` reads, hold message `n`'s words,
/// and makes each message `n + 1`'s, plus one, with `set_mr`: the server
/// does this to a request, the root task to a reply, which makes its next
/// request. Stops at the first wrong word.
pub fn advance(
    n: u64,
    mr: impl Fn(usize) -> u64,
    mut set_mr: impl FnMut(usize, u64),
) -> Result<(), WordMismatch> {
    for k in FIRST_BUFFER_MR..=LAST {
        let (got, want) = (mr(k), word(k, n));
        if got != want {
            return Err(WordMismatch { mr: k, got, want });
        }
        set_mr(k, got.wrapping_add(1));
    }
    Ok(())
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
                assert_eq!(parse_request(&req), Ok((shape, i)));
                let reply = answer(&req).unwrap();
                assert_eq!(check_reply(shape, i, &reply), Ok(()), "{shape:?} {i}");
            }
        }
    }

    #[test]
    fn a_wrong_reply_fails() {
        let good = answer(&request(Shape::Full, 7)).unwrap();
        assert_eq!(check_reply(Shape::Full, 7, &good), Ok(()));
        // An answer to another request, another shape, a stale MR0.
        let other = answer(&request(Shape::Full, 8)).unwrap();
        let what = |r: &Message| check_reply(Shape::Full, 7, r).map_err(|m| m.what);
        assert_eq!(what(&other), Err("the reply's label"));
        let short = Message::new(MessageInfo::new(label(Shape::Full, 8), 0, 0, 4), good.mr);
        assert_eq!(what(&short), Err("the reply's length"));
        let stale = Message::new(good.info, [7, 0, 0, 0]);
        assert_eq!(what(&stale), Err("the reply's MR0"));
        let one = answer(&request(Shape::One, 7)).unwrap();
        assert_eq!(what(&one), Err("the reply's label"));
        // MR0 means nothing in a zero-length reply.
        let zero = answer(&request(Shape::Zero, 3)).unwrap();
        assert_eq!(zero.mr, [0; 4]);
        assert_eq!(check_reply(Shape::Zero, 3, &zero), Ok(()));
    }

    #[test]
    fn the_server_refuses_what_is_no_request() {
        let bad = Message::new(MessageInfo::new(0x9 << 32, 0, 0, 1), [0; 4]);
        assert_eq!(
            answer(&bad).map_err(|m| m.what),
            Err("the request label's shape")
        );
        let long = Message::new(MessageInfo::new(label(Shape::One, 0), 0, 0, 2), [0; 4]);
        assert_eq!(
            answer(&long).map_err(|m| m.what),
            Err("the request's length")
        );
        let caps = Message::new(MessageInfo::new(label(Shape::One, 0), 0, 1, 1), [0; 4]);
        assert_eq!(
            answer(&caps).map_err(|m| m.what),
            Err("the request's extra_caps")
        );
    }

    /// MR0 to MR119 as plain words, standing for an IPC buffer.
    fn buffer(n: u64) -> [u64; LAST + 1] {
        let mut b = [0; LAST + 1];
        for (k, w) in b.iter_mut().enumerate().skip(FIRST_BUFFER_MR) {
            *w = word(k, n);
        }
        b
    }

    fn advance_buffer(n: u64, b: &mut [u64; LAST + 1]) -> Result<(), WordMismatch> {
        let copy = *b;
        advance(n, |k| copy[k], |k, v| b[k] = v)
    }

    #[test]
    fn the_buffer_words_go_round_each_plus_one() {
        // Request 5 is message 10; the server's answer is message 11, and
        // the root task's next request message 12, request 6's.
        let mut b = buffer(request_number(5));
        assert_eq!(advance_buffer(10, &mut b), Ok(()));
        assert_eq!(b, buffer(reply_number(5)));
        assert_eq!(advance_buffer(11, &mut b), Ok(()));
        assert_eq!(b, buffer(request_number(6)));
        assert_eq!(
            b[..FIRST_BUFFER_MR],
            [0; FIRST_BUFFER_MR],
            "MR0 to MR3 untouched"
        );
    }

    #[test]
    fn a_word_that_did_not_cross_fails() {
        // A kernel that copied only MR119 leaves the receiver's own words.
        let mut reply = buffer(request_number(0));
        reply[LAST] = word(LAST, reply_number(0));
        assert_eq!(
            advance_buffer(reply_number(0), &mut reply),
            Err(WordMismatch {
                mr: 4,
                got: word(4, 0),
                want: word(4, 1),
            })
        );
        // Nor does the server's own last answer pass for the next request.
        let mut stale = buffer(reply_number(3));
        assert_eq!(
            advance_buffer(request_number(4), &mut stale).map_err(|m| m.mr),
            Err(4)
        );
        // Any one word.
        for k in [4, 60, 118, LAST] {
            let mut b = buffer(9);
            b[k] ^= 1 << 40;
            assert_eq!(advance_buffer(9, &mut b).map_err(|m| m.mr), Err(k));
        }
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
        for k in FIRST_BUFFER_MR..LAST {
            assert_ne!(pattern(k), pattern(k + 1));
            assert_ne!(pattern(k), 0);
        }
        assert_ne!(word(4, 0), word(4, 1));
    }
}
