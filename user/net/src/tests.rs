//! net's host tests (`docs/design.md`, "`net`", "Tests"): the golden
//! frames, the proptests of random and mutated frames, of echoes against
//! an oracle and of single-byte changes to an IPv4 header, the checksum
//! against a naive sum and RFC 1071's examples, the ARP cache against a
//! model, the configuration and its words, and the pump over a model of
//! the frame queues; and [`e2e`], the stack against the end-to-end tests'
//! scripted peer ([`peer`]), straight and over the frame queues with a
//! model driver preempting `net` ([`preempt`], [`owners`]).

mod e2e;
mod golden;
// Shared with `virtio-net`'s and `netvsc`'s end-to-end tests, which
// include these files by path.
pub mod owners;
pub mod peer;
pub mod preempt;
mod props;
mod unit;
pub mod wire;

use std::vec::Vec;

use crate::{MAX_FRAME, MIN_FRAME, Tx};

/// The byte a test's transmit buffer is filled with before the stack
/// builds a frame in it, so a byte the stack leaves unwritten shows.
pub const POISON: u8 = 0xA5;

/// A [`Tx`] that keeps every frame: `free` buffers, or any number.
#[derive(Default)]
pub struct Wire {
    pub frames: Vec<Vec<u8>>,
    /// Transmit buffers left; `None` for no limit.
    pub free: Option<usize>,
}

impl Wire {
    pub fn new() -> Wire {
        Wire::default()
    }

    /// The frames sent since the last call.
    pub fn take(&mut self) -> Vec<Vec<u8>> {
        core::mem::take(&mut self.frames)
    }
}

impl Tx for Wire {
    fn send(&mut self, build: impl FnOnce(&mut [u8; MAX_FRAME]) -> usize) -> bool {
        match &mut self.free {
            Some(0) => return false,
            Some(n) => *n -= 1,
            None => {}
        }
        let mut buf = [POISON; MAX_FRAME];
        let len = build(&mut buf);
        assert!(
            (MIN_FRAME..=MAX_FRAME).contains(&len),
            "the stack built a {len}-byte frame"
        );
        self.frames.push(buf[..len].to_vec());
        true
    }
}
