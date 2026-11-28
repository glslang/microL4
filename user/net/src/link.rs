//! net's side of the frame queues (`docs/design.md`, "The frame queues"
//! and "`net::run`"): its start ([`start`]) and one signal's work
//! ([`pump`]) over `libsys::frames::Net`, its lines, and its one request,
//! root's `Stats`, answered with a [`Report`].
//!
//! The queues' own rules (owners, bad entries, the 128 in flight) are
//! `libsys::frames`'s. Here a frame arrives as a copy in net's memory and
//! leaves as a copy into a transmit buffer net owns, so the stack never
//! holds a reference into the shared frame, and nothing a driver writes
//! there changes a frame while the stack parses it.

use core::fmt;

use libsys::frames::{Counters, LinkError, Net};
use libsys::mem::Memory;
use libsys::proto::Refusal;

use crate::config::Config;
use crate::ethernet::Mac;
use crate::stack::Stack;
use crate::stats::Stats;
use crate::udp::Service;
use crate::{MAX_FRAME, NET_STATS, Tx};

/// Frames one signal takes at most from `RX_FILLED`: a full queue. More
/// wait for the next signal, which the driver has already sent.
pub const BATCH: usize = 128;

/// The stack's [`Tx`] over the transmit queue: it builds each frame in
/// net's memory and copies it into a transmit buffer.
pub struct Sender<'a, M: Memory>(pub &'a mut Net<M>);

impl<M: Memory> Tx for Sender<'_, M> {
    fn send(&mut self, build: impl FnOnce(&mut [u8; MAX_FRAME]) -> usize) -> bool {
        if self.0.free_buffers() == 0 && self.0.reclaim() == 0 {
            return false;
        }
        let mut frame = [0u8; MAX_FRAME];
        let len = build(&mut frame).min(MAX_FRAME);
        self.0.send(&frame[..len]).is_ok()
    }
}

/// net's start, at its driver's first `FRAMES` signal: reads the link
/// block and hands the driver every receive buffer ([`Net::attach`]), then
/// starts the stack at `config`'s address with the driver's MAC. The
/// caller then prints [`Up`] and [`crate::echo::LISTENING`], and signals
/// the driver if [`Net::end_batch`] says so. A link block not ready, or
/// with a MAC that is not unicast, is refused: net panics with it.
pub fn start<M: Memory>(config: Config, queues: &mut Net<M>) -> Result<Stack, LinkError> {
    let link = queues.attach()?;
    let mut stack = Stack::new(config, link.mac);
    stack.start(&mut Sender(queues));
    Ok(stack)
}

/// One signal's work: takes back the transmit buffers, then gives the
/// stack each frame on `RX_FILLED`, at most [`BATCH`]. Returns whether
/// net must signal its driver.
pub fn pump<S: Service, M: Memory>(stack: &mut Stack<S>, queues: &mut Net<M>) -> bool {
    queues.reclaim();
    let mut frame = [0u8; MAX_FRAME];
    for _ in 0..BATCH {
        let Some(len) = queues.take_rx(&mut frame) else {
            break;
        };
        stack.input(&frame[..len.min(MAX_FRAME)], &mut Sender(queues));
    }
    queues.end_batch()
}

/// `net: up: 10.0.2.15/24 via 10.0.2.2, MAC 52:54:00:12:34:56`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Up(pub Config, pub Mac);

impl fmt::Display for Up {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "net: up: {}, MAC {}", self.0, self.1)
    }
}

/// Checks a request on endpoint NE: only [`NET_STATS`] with no words,
/// from any badge, answered with [`Report::to_words`].
pub fn request(label: u64, length: usize) -> Result<(), Refusal> {
    match (label, length) {
        (NET_STATS, 0) => Ok(()),
        (NET_STATS, _) => Err(Refusal::BadLength),
        _ => Err(Refusal::BadLabel),
    }
}

/// net's answer to `Stats`: the stack's counters, MR0 to MR34, then its
/// side of the queues', MR35 to MR40.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Report {
    pub stack: Stats,
    pub queues: Counters,
}

impl Report {
    /// The reply's words.
    pub const WORDS: usize = Stats::WORDS + 6;

    pub fn to_words(&self) -> [u64; Self::WORDS] {
        let mut w = [0; Self::WORDS];
        w[..Stats::WORDS].copy_from_slice(&self.stack.to_words());
        let q = &self.queues;
        w[Stats::WORDS..].copy_from_slice(&[
            q.sent,
            q.received,
            q.reclaimed,
            q.dropped,
            q.bad,
            q.signals,
        ]);
        w
    }

    pub fn from_words(w: [u64; Self::WORDS]) -> Report {
        let mut s = [0; Stats::WORDS];
        s.copy_from_slice(&w[..Stats::WORDS]);
        let q = &w[Stats::WORDS..];
        Report {
            stack: Stats::from_words(s),
            queues: Counters {
                sent: q[0],
                received: q[1],
                reclaimed: q[2],
                dropped: q[3],
                bad: q[4],
                signals: q[5],
            },
        }
    }
}

/// The stack's text, then `; queues: <n> frames sent, ...`: root's
/// `net: stats:` line.
impl fmt::Display for Report {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let q = &self.queues;
        write!(
            f,
            "{}; queues: {} frames sent, {} received, {} buffers reclaimed, {} frames dropped, {} bad entries, {} signals",
            self.stack, q.sent, q.received, q.reclaimed, q.dropped, q.bad, q.signals
        )
    }
}
