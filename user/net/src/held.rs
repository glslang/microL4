//! The packets that wait for an address (`docs/design.md`, "`net`",
//! "Resolving"): at most one per pending ARP entry and [`HELD`] in all,
//! each a whole frame whose destination MAC is written when the address
//! resolves.

use crate::MAX_FRAME;
use crate::ethernet::Mac;
use crate::ipv4::Ip;

/// Packets that may wait at once.
pub const HELD: usize = 4;

/// What a waiting packet is, for the counters once it goes out.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Kind {
    /// An ICMP echo reply.
    Icmp,
    /// A datagram from a service.
    Udp,
}

#[derive(Clone)]
struct Slot {
    /// The next hop it waits for; `None` when the slot is free.
    hop: Option<Ip>,
    kind: Kind,
    len: usize,
    frame: [u8; MAX_FRAME],
}

/// The waiting packets.
#[derive(Clone)]
pub struct Held {
    slots: [Slot; HELD],
}

impl Default for Held {
    fn default() -> Held {
        Held::new()
    }
}

impl Held {
    pub const fn new() -> Held {
        const FREE: Slot = Slot {
            hop: None,
            kind: Kind::Udp,
            len: 0,
            frame: [0; MAX_FRAME],
        };
        Held {
            slots: [FREE; HELD],
        }
    }

    /// The slot of the packet waiting for `hop`.
    pub fn find(&self, hop: Ip) -> Option<usize> {
        self.slots.iter().position(|s| s.hop == Some(hop))
    }

    /// A free slot.
    pub fn free(&self) -> Option<usize> {
        self.slots.iter().position(|s| s.hop.is_none())
    }

    /// Puts the frame `build` writes in slot `i`, waiting for `hop`.
    pub fn store(
        &mut self,
        i: usize,
        hop: Ip,
        kind: Kind,
        build: impl FnOnce(&mut [u8; MAX_FRAME]) -> usize,
    ) {
        let s = &mut self.slots[i];
        s.len = build(&mut s.frame).min(MAX_FRAME);
        s.hop = Some(hop);
        s.kind = kind;
    }

    /// Slot `i`'s kind.
    pub fn kind(&self, i: usize) -> Kind {
        self.slots[i].kind
    }

    /// Copies slot `i`'s frame to `out`, addressed to `mac`, and returns
    /// its length.
    pub fn copy(&self, i: usize, mac: Mac, out: &mut [u8; MAX_FRAME]) -> usize {
        let s = &self.slots[i];
        out[..s.len].copy_from_slice(&s.frame[..s.len]);
        out[0..6].copy_from_slice(&mac.0);
        s.len
    }

    /// Frees slot `i`.
    pub fn clear(&mut self, i: usize) {
        self.slots[i].hop = None;
    }

    /// The number of packets waiting.
    pub fn len(&self) -> usize {
        self.slots.iter().filter(|s| s.hop.is_some()).count()
    }

    /// The next hops packets wait for.
    pub fn hops(&self) -> impl Iterator<Item = Ip> + '_ {
        self.slots.iter().filter_map(|s| s.hop)
    }
}
