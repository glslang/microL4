//! net's side of the frame queues (`docs/design.md`, "The frame queues"
//! and "`net::run`"): the link block's check, what net needs of the
//! queues ([`Queues`]: `libsys::frames` on the target, a model in the
//! tests), its start ([`start`]) and one signal's work ([`pump`]), its
//! lines, and its one request, root's `Stats`.
//!
//! The queues' own rules (owners, bad entries, the 128 in flight) are
//! `libsys::frames`'s; here a frame arrives as a copy in net's memory and
//! leaves as a copy into a transmit buffer net owns, so the stack never
//! holds a reference into the shared frame.

use core::fmt;

use libsys::proto::Refusal;

use crate::config::Config;
use crate::ethernet::Mac;
use crate::stack::Stack;
use crate::udp::Service;
use crate::{MAX_FRAME, NET_STATS, Tx};

/// Frames one signal takes at most from `RX_FILLED`: a full queue. More
/// wait for the next signal, which the driver has already sent.
pub const BATCH: usize = 128;

/// The queues' link block, as the driver wrote it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Link {
    pub mac: Mac,
    pub mtu: u16,
    /// The link is up.
    pub up: bool,
}

/// Why net cannot start: a panic with this text.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum LinkError {
    /// The driver signalled before it wrote ready.
    NotReady,
    /// A MAC that is 0, multicast or broadcast.
    Mac(Mac),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::NotReady => f.write_str("net: the link block is not ready"),
            LinkError::Mac(m) => write!(f, "net: the driver's MAC {m} is not unicast"),
        }
    }
}

/// net's view of the frame queues.
pub trait Queues {
    /// The link block, once the driver has written it and ready (with
    /// acquire order); `None` before.
    fn link(&mut self) -> Option<Link>;
    /// Pushes every receive buffer on `RX_FREE`: once, at the start.
    fn give_receive_buffers(&mut self);
    /// Takes back the transmit buffers the driver returned on `TX_FREE`.
    fn reclaim(&mut self);
    /// Takes the next frame on `RX_FILLED`: copies it to `frame`, returns
    /// its buffer on `RX_FREE` and gives its length, 14 to 1,514; `None`
    /// when `RX_FILLED` is empty.
    fn receive(&mut self, frame: &mut [u8; MAX_FRAME]) -> Option<usize>;
    /// Whether net owns a free transmit buffer.
    fn can_transmit(&self) -> bool;
    /// Copies `frame` into a transmit buffer net owns and pushes it on
    /// `TX_FILLED`; `false` if net owns none.
    fn transmit(&mut self, frame: &[u8]) -> bool;
    /// Whether net pushed anything since the last call: then it signals
    /// the driver, once for the batch.
    fn take_pushed(&mut self) -> bool;
}

/// The stack's [`Tx`] over the transmit queue: it builds each frame in
/// net's memory and copies it into the buffer.
pub struct Sender<'a, Q>(pub &'a mut Q);

impl<Q: Queues> Tx for Sender<'_, Q> {
    fn send(&mut self, build: impl FnOnce(&mut [u8; MAX_FRAME]) -> usize) -> bool {
        if !self.0.can_transmit() {
            return false;
        }
        let mut frame = [0u8; MAX_FRAME];
        let len = build(&mut frame).min(MAX_FRAME);
        self.0.transmit(&frame[..len])
    }
}

/// net's start, at its first `FRAMES` signal: checks the link block,
/// pushes the receive buffers, and starts the stack at `config`'s address
/// with the driver's MAC. The caller then prints [`Up`] and
/// [`crate::echo::LISTENING`], and signals the driver if
/// [`Queues::take_pushed`] says so.
pub fn start<Q: Queues>(config: Config, queues: &mut Q) -> Result<Stack, LinkError> {
    let link = queues.link().ok_or(LinkError::NotReady)?;
    if !link.mac.is_unicast() {
        return Err(LinkError::Mac(link.mac));
    }
    queues.give_receive_buffers();
    let mut stack = Stack::new(config, link.mac);
    stack.start(&mut Sender(queues));
    Ok(stack)
}

/// One signal's work: takes back the transmit buffers, then gives the
/// stack each frame on `RX_FILLED`, at most [`BATCH`]. Returns whether
/// net must signal its driver.
pub fn pump<S: Service, Q: Queues>(stack: &mut Stack<S>, queues: &mut Q) -> bool {
    queues.reclaim();
    let mut frame = [0u8; MAX_FRAME];
    for _ in 0..BATCH {
        let Some(len) = queues.receive(&mut frame) else {
            break;
        };
        stack.input(&frame[..len.min(MAX_FRAME)], &mut Sender(queues));
    }
    queues.take_pushed()
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
/// from any badge, answered with [`crate::Stats::to_words`].
pub fn request(label: u64, length: usize) -> Result<(), Refusal> {
    match (label, length) {
        (NET_STATS, 0) => Ok(()),
        (NET_STATS, _) => Err(Refusal::BadLength),
        _ => Err(Refusal::BadLabel),
    }
}
