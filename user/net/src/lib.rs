//! `net`: the network stack and the UDP echo service (`docs/design.md`,
//! "Networking", "`net`").
//!
//! [`Stack`] is the stack: Ethernet ([`ethernet`]), ARP with its cache
//! ([`arp`]), IPv4 ([`ipv4`]), ICMP echo ([`icmp`]) and UDP ([`udp`]), with
//! the echo service on port 7 ([`echo`]) and RFC 1071's checksum
//! ([`checksum`]). It is configured statically ([`Config`]): QEMU's
//! `10.0.2.15/24` via `10.0.2.2` unless the command line says otherwise,
//! and on Hyper-V from the command line alone. [`Stack::input`] takes one
//! received frame and sends what it answers through a [`Tx`], which lends
//! it a transmit buffer per frame; every frame it takes is counted once,
//! as handled or as one drop reason ([`Stats`]), one input sends at most
//! three frames, and nothing it does loops on what the network sends.
//! The stack is pure, uses nothing but `core` and the frame queues' `Mac`
//! ([`ethernet::Mac`] is `libsys::frames::Mac`), and is host-tested
//! against golden frames (`user/net/golden/`) and proptests.
//!
//! [`link`] is net's side of the frame queues it shares with its driver,
//! `libsys::frames::Net`: [`link::start`] and [`link::pump`], one
//! signal's work, host-tested against the driver's side of the same
//! queues, and [`link::Report`], its answer to root. [`run`], the loop,
//! exists only on the user target, where the root task starts it in a
//! VSpace and CSpace of its own with the capabilities [`slot`] lists,
//! bound to notification NN, which its driver signals with `FRAMES`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod arp;
pub mod checksum;
pub mod config;
pub mod echo;
pub mod ethernet;
mod held;
pub mod icmp;
pub mod ipv4;
pub mod link;
#[cfg(target_os = "none")]
mod run;
mod stack;
pub mod stats;
#[cfg(test)]
mod tests;
pub mod udp;

pub use config::{Config, ConfigError};
pub use echo::Echo;
pub use ethernet::Mac;
pub use ipv4::Ip;
#[cfg(target_os = "none")]
pub use run::run;
pub use stack::{Event, Stack};
pub use stats::{Outcome, Stats};
pub use udp::{Endpoint, Reply, Service};

/// The largest frame: a 1,500-byte packet and the Ethernet header, with no
/// FCS and no VLAN tag.
pub const MAX_FRAME: usize = ethernet::HEADER + ipv4::MAX_PACKET;
/// The smallest frame the stack takes: an Ethernet header alone.
pub const MIN_FRAME: usize = ethernet::HEADER;

const _: () = assert!(MAX_FRAME == 1514);

/// Where the stack's frames go: a driver's transmit queue, or a test's
/// list.
pub trait Tx {
    /// Lends the stack a transmit buffer: `build` writes one frame at its
    /// start and returns the frame's length, 14 to [`MAX_FRAME`] bytes.
    /// Returns `false`, without calling `build`, when no buffer is free;
    /// the stack then drops the frame and counts it.
    fn send(&mut self, build: impl FnOnce(&mut [u8; MAX_FRAME]) -> usize) -> bool;
}

/// The bit `net`'s driver signals NN with, and the one `net` signals its
/// driver's notification with (`docs/design.md`, "Where the network
/// servers run").
pub use libsys::proto::FRAMES;
/// The label of root's `Stats` request on endpoint NE, answered with
/// [`Stats::to_words`].
pub use libsys::proto::label::NET_STATS;

/// net's CSpace: a 16-slot CNode with guard 0 of size 60, so `CPtr` `n`
/// is slot `n` (`docs/design.md`, "Capabilities" under "Networking").
pub mod slot {
    /// Slots in net's CNode, and its radix and guard.
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, with the same guard.
    pub const CNODE: u64 = 1;
    /// Endpoint NE, root's `Stats`, with Read.
    pub const ENDPOINT: u64 = 2;
    /// Its driver's notification, NV or NH, with Write and badge `FRAMES`.
    pub const DRIVER: u64 = 3;
    /// Endpoint F, its fault endpoint, badge `NET` (7).
    pub const FAULT: u64 = 4;
    /// Endpoint C, with Write, GrantReply and badge 8: its log lines.
    pub const CONSOLE: u64 = 5;
}
