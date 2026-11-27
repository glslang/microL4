//! ARP (RFC 826) for IPv4 over Ethernet: the packet, and the cache of
//! eight entries (`docs/design.md`, "`net`").
//!
//! The stack takes only Ethernet and IPv4 with lengths 6 and 4, as a
//! request or a reply. Learning is RFC 826's merge: a sender already in
//! the cache is updated by any ARP packet; one whose target is the
//! stack's address is added. Nothing is learnt from IP packets. An entry
//! is resolved or pending; with no timer nothing expires, and the least
//! recently used entry is replaced first.

use crate::ethernet::{Mac, mac_at};
use crate::ipv4::Ip;

/// The body for Ethernet and IPv4: 8 bytes of header, two MACs and two
/// addresses.
pub const BODY: usize = 28;
/// Operation request.
pub const REQUEST: u16 = 1;
/// Operation reply.
pub const REPLY: u16 = 2;
/// Hardware type Ethernet.
const ETHERNET: u16 = 1;
/// Entries in the cache.
pub const CACHE: usize = 8;

/// A packet that parsed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Packet {
    /// [`REQUEST`] or [`REPLY`].
    pub op: u16,
    /// The sender's MAC and address.
    pub sha: Mac,
    pub spa: Ip,
    /// The target's MAC (0 in a request) and address.
    pub tha: Mac,
    pub tpa: Ip,
}

impl Packet {
    /// Checks `body`, an Ethernet payload, padding included: hardware
    /// Ethernet, protocol IPv4, lengths 6 and 4, a request or a reply.
    pub fn parse(body: &[u8]) -> Option<Packet> {
        if body.len() < BODY {
            return None;
        }
        let word = |i: usize| u16::from_be_bytes([body[i], body[i + 1]]);
        let op = word(6);
        let ok = word(0) == ETHERNET
            && word(2) == crate::ethernet::IPV4
            && body[4] == 6
            && body[5] == 4
            && (op == REQUEST || op == REPLY);
        ok.then(|| Packet {
            op,
            sha: mac_at(&body[8..14]),
            spa: Ip::read(&body[14..18]),
            tha: mac_at(&body[18..24]),
            tpa: Ip::read(&body[24..28]),
        })
    }

    /// Writes the body at the start of `buf`.
    pub fn write(&self, buf: &mut [u8]) {
        let b = &mut buf[..BODY];
        b[0..2].copy_from_slice(&ETHERNET.to_be_bytes());
        b[2..4].copy_from_slice(&crate::ethernet::IPV4.to_be_bytes());
        b[4] = 6;
        b[5] = 4;
        b[6..8].copy_from_slice(&self.op.to_be_bytes());
        b[8..14].copy_from_slice(&self.sha.0);
        b[14..18].copy_from_slice(&self.spa.0);
        b[18..24].copy_from_slice(&self.tha.0);
        b[24..28].copy_from_slice(&self.tpa.0);
    }
}

/// What the cache knows of an address.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    /// A request went out and no packet has answered it.
    Pending,
    Resolved(Mac),
}

#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Entry {
    ip: Ip,
    state: State,
    /// The clock at its last use: added, updated, or looked up to send.
    used: u64,
}

/// The cache: eight entries, the least recently used replaced first.
#[derive(Clone, Debug)]
pub struct Cache {
    entries: [Option<Entry>; CACHE],
    clock: u64,
}

impl Default for Cache {
    fn default() -> Cache {
        Cache::new()
    }
}

impl Cache {
    pub const fn new() -> Cache {
        Cache {
            entries: [None; CACHE],
            clock: 0,
        }
    }

    fn find(&self, ip: Ip) -> Option<usize> {
        self.entries
            .iter()
            .position(|e| e.is_some_and(|e| e.ip == ip))
    }

    fn touch(&mut self, i: usize) -> &mut Entry {
        self.clock += 1;
        let e = self.entries[i].as_mut().expect("a found entry");
        e.used = self.clock;
        e
    }

    /// What the cache knows of `ip`, without counting a use.
    pub fn peek(&self, ip: Ip) -> Option<State> {
        self.find(ip).and_then(|i| self.entries[i]).map(|e| e.state)
    }

    /// What the cache knows of `ip`, looked up to send to it: a use.
    pub fn lookup(&mut self, ip: Ip) -> Option<State> {
        let i = self.find(ip)?;
        Some(self.touch(i).state)
    }

    /// RFC 826's merge: if `ip` is in the cache, it is now at `mac` (a
    /// use). Returns whether it was there.
    pub fn merge(&mut self, ip: Ip, mac: Mac) -> bool {
        match self.find(ip) {
            Some(i) => {
                self.touch(i).state = State::Resolved(mac);
                true
            }
            None => false,
        }
    }

    /// Adds `ip`, which is not in the cache, in `state` (a use), in an
    /// empty entry or else in place of the least recently used one, whose
    /// address it returns.
    pub fn insert(&mut self, ip: Ip, state: State) -> Option<Ip> {
        debug_assert!(self.find(ip).is_none(), "{ip} is in the cache already");
        let i = self
            .entries
            .iter()
            .position(Option::is_none)
            .unwrap_or_else(|| {
                (0..CACHE)
                    .min_by_key(|&i| self.entries[i].map_or(0, |e| e.used))
                    .expect("eight entries")
            });
        let evicted = self.entries[i].map(|e| e.ip);
        self.entries[i] = Some(Entry { ip, state, used: 0 });
        self.touch(i);
        evicted
    }

    /// The entries, least recently used first.
    pub fn entries(&self) -> impl Iterator<Item = (Ip, State)> + '_ {
        let mut order = [0usize; CACHE];
        let mut n = 0;
        for (i, e) in self.entries.iter().enumerate() {
            if e.is_some() {
                order[n] = i;
                n += 1;
            }
        }
        order[..n].sort_unstable_by_key(|&i| self.entries[i].map_or(0, |e| e.used));
        (0..n).map(move |k| {
            let e = self.entries[order[k]].expect("a full entry");
            (e.ip, e.state)
        })
    }

    /// The number of entries in use.
    pub fn len(&self) -> usize {
        self.entries.iter().filter(|e| e.is_some()).count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}
