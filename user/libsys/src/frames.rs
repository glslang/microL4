//! The frame queues (`docs/design.md`, "The frame queues"): how a network
//! driver and `net` exchange Ethernet frames through one 2 MiB RAM frame
//! mapped at [`WINDOW`] in both VSpaces, signalling each other with the
//! `FRAMES` badge.
//!
//! The frame holds a link block, four queues and two pools of 128 buffers
//! of 2,048 bytes ([`layout`]). Receive buffers circulate on `RX_FREE`
//! (`net` to the driver) and `RX_FILLED` (the driver to `net`), transmit
//! buffers on `TX_FREE` (the driver to `net`) and `TX_FILLED` (`net` to
//! the driver). Each queue has one producer, which writes its entries and
//! `head`, and one consumer, which writes its `tail`; an [`Entry`] is a
//! buffer index and a length.
//!
//! [`Driver`] and [`Net`] are the two sides, each generic over the
//! [`Memory`] the frame is reached through. Neither trusts what it reads
//! there: each keeps its own copy of the indices it writes and a map of
//! the buffers it owns, and takes an entry only if its index is below 128,
//! the buffer is not one it owns, and its length fits its queue (14 to
//! 1,514 bytes filled, 0 free); any other entry is counted as bad and
//! skipped, and a queue that claims more than 128 entries is taken as
//! empty (consumer) or full (producer) and counted. So neither side reads
//! outside a buffer, holds a buffer twice, or loops, whatever the other
//! writes.
//!
//! Each side signals the other once after a batch in which it pushed
//! anything ([`Driver::end_batch`], [`Net::end_batch`]), and on a signal
//! drains every queue it consumes.

use core::fmt;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};

use crate::mem::{Memory, Part};

/// Where the frame is mapped, in the driver's VSpace and `net`'s.
pub const WINDOW: u64 = 0x1000_0000;
/// The frame: one 2 MiB RAM frame.
pub const SIZE: usize = 1 << 21;
/// Buffers in each pool, and entries in each queue.
pub const BUFFERS: usize = 128;
/// Bytes in each buffer.
pub const BUFFER_SIZE: usize = 2048;
/// The shortest frame a filled entry may carry: an Ethernet header.
pub const MIN_FRAME: usize = 14;
/// The longest: a 1,500-byte packet and its header, with no FCS, VLAN tag
/// or offload.
pub const MAX_FRAME: usize = 1514;
/// The MTU the link block gives.
pub const MTU: u16 = 1500;

/// Offsets in the frame (`docs/design.md`, "The frame queues").
pub mod layout {
    /// The link block, which the driver writes once, before its first
    /// signal.
    pub const LINK: usize = 0x0000;
    /// In the link block: the MAC (6 bytes).
    pub const LINK_MAC: usize = 0;
    /// The MTU (u16).
    pub const LINK_MTU: usize = 6;
    /// The link (u32): 1 up, 0 down.
    pub const LINK_UP: usize = 8;
    /// Ready (u32): 1 once the rest is written, stored last with release
    /// order.
    pub const LINK_READY: usize = 12;

    /// The queues, a page each.
    pub const RX_FILLED: usize = 0x1000;
    pub const RX_FREE: usize = 0x2000;
    pub const TX_FILLED: usize = 0x3000;
    pub const TX_FREE: usize = 0x4000;
    /// In a queue: `head` (u32), written by the producer.
    pub const HEAD: usize = 0;
    /// `tail` (u32), written by the consumer, a cache line from `head`.
    pub const TAIL: usize = 64;
    /// The 128 entries (u32 each).
    pub const ENTRIES: usize = 128;

    /// Receive buffer `i` is at `RX_BUFFERS + 2048 i`.
    pub const RX_BUFFERS: usize = 0x1_0000;
    /// Transmit buffer `i` is at `TX_BUFFERS + 2048 i`.
    pub const TX_BUFFERS: usize = 0x5_0000;
    /// The end of the last transmit buffer; the rest of the frame is
    /// unused.
    pub const END: usize = 0x9_0000;
}

const _: () = {
    assert!(layout::ENTRIES + 4 * BUFFERS <= 0x1000);
    assert!(layout::RX_BUFFERS + BUFFERS * BUFFER_SIZE == layout::TX_BUFFERS);
    assert!(layout::TX_BUFFERS + BUFFERS * BUFFER_SIZE == layout::END);
    assert!(layout::END <= SIZE);
    assert!(MAX_FRAME <= BUFFER_SIZE);
};

/// An Ethernet address, as the link block holds it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    pub const ZERO: Mac = Mac([0; 6]);
    pub const BROADCAST: Mac = Mac([0xFF; 6]);

    /// Its bytes in the low 48 bits of a word, byte 0 lowest.
    pub const fn to_word(self) -> u64 {
        let b = self.0;
        u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], 0, 0])
    }

    /// The low 48 bits of `w`, byte 0 lowest; the rest is ignored.
    pub const fn from_word(w: u64) -> Mac {
        let b = w.to_le_bytes();
        Mac([b[0], b[1], b[2], b[3], b[4], b[5]])
    }

    pub const fn is_zero(self) -> bool {
        self.to_word() == 0
    }

    /// The group bit, bit 0 of byte 0; the broadcast address has it.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 1 != 0
    }

    /// An address a station may have: not 0 and not a group.
    pub const fn is_unicast(self) -> bool {
        !self.is_zero() && !self.is_multicast()
    }
}

/// `52:54:00:12:34:56`, as the scenarios match it.
impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let b = self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            b[0], b[1], b[2], b[3], b[4], b[5]
        )
    }
}

/// A side of the queues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    Driver,
    Net,
}

impl Role {
    /// The pool whose buffers this side fills: the driver receive
    /// buffers, `net` transmit buffers. It takes the other pool's buffers
    /// filled and hands them back free.
    pub const fn fills(self) -> Pool {
        match self {
            Role::Driver => Pool::Rx,
            Role::Net => Pool::Tx,
        }
    }

    pub const fn peer(self) -> Role {
        match self {
            Role::Driver => Role::Net,
            Role::Net => Role::Driver,
        }
    }
}

/// A pool of 128 buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Pool {
    /// Receive buffers: frames from the network, filled by the driver.
    Rx,
    /// Transmit buffers: frames to the network, filled by `net`.
    Tx,
}

impl Pool {
    pub const ALL: [Pool; 2] = [Pool::Rx, Pool::Tx];

    /// The offset of buffer `index`, which must be below 128.
    pub const fn buffer(self, index: usize) -> usize {
        assert!(index < BUFFERS);
        let base = match self {
            Pool::Rx => layout::RX_BUFFERS,
            Pool::Tx => layout::TX_BUFFERS,
        };
        base + index * BUFFER_SIZE
    }

    /// The queue its buffers travel on filled.
    pub const fn filled(self) -> Queue {
        match self {
            Pool::Rx => Queue::RxFilled,
            Pool::Tx => Queue::TxFilled,
        }
    }

    /// The queue they travel back on free.
    pub const fn free(self) -> Queue {
        match self {
            Pool::Rx => Queue::RxFree,
            Pool::Tx => Queue::TxFree,
        }
    }

    /// The side that fills it.
    pub const fn filler(self) -> Role {
        match self {
            Pool::Rx => Role::Driver,
            Pool::Tx => Role::Net,
        }
    }
}

/// One of the four queues.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Queue {
    /// Received frames, the driver to `net`.
    RxFilled,
    /// Receive buffers handed back, `net` to the driver.
    RxFree,
    /// Frames to send, `net` to the driver.
    TxFilled,
    /// Transmit buffers handed back, the driver to `net`.
    TxFree,
}

impl Queue {
    pub const ALL: [Queue; 4] = [
        Queue::RxFilled,
        Queue::RxFree,
        Queue::TxFilled,
        Queue::TxFree,
    ];

    /// Where its page starts.
    pub const fn offset(self) -> usize {
        match self {
            Queue::RxFilled => layout::RX_FILLED,
            Queue::RxFree => layout::RX_FREE,
            Queue::TxFilled => layout::TX_FILLED,
            Queue::TxFree => layout::TX_FREE,
        }
    }

    /// The offset of its `head`.
    pub const fn head(self) -> usize {
        self.offset() + layout::HEAD
    }

    /// The offset of its `tail`.
    pub const fn tail(self) -> usize {
        self.offset() + layout::TAIL
    }

    /// The offset of entry `k`, `k` a free-running index: slot `k mod
    /// 128`.
    pub const fn entry(self, k: u32) -> usize {
        self.offset() + layout::ENTRIES + 4 * (k as usize % BUFFERS)
    }

    pub const fn pool(self) -> Pool {
        match self {
            Queue::RxFilled | Queue::RxFree => Pool::Rx,
            Queue::TxFilled | Queue::TxFree => Pool::Tx,
        }
    }

    /// Whether its entries carry frames, not free buffers.
    pub const fn is_filled(self) -> bool {
        matches!(self, Queue::RxFilled | Queue::TxFilled)
    }

    /// The side that writes its entries and `head`; the other writes its
    /// `tail`.
    pub const fn producer(self) -> Role {
        let filler = self.pool().filler();
        if self.is_filled() {
            filler
        } else {
            filler.peer()
        }
    }
}

/// A queue entry: a buffer index in bits 0 to 15, a length in bits 16 to
/// 31.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Entry {
    pub index: u16,
    pub len: u16,
}

impl Entry {
    /// A free buffer: length 0.
    pub const fn free(index: u16) -> Entry {
        Entry { index, len: 0 }
    }

    pub const fn word(self) -> u32 {
        self.index as u32 | (self.len as u32) << 16
    }

    pub const fn from_word(w: u32) -> Entry {
        Entry {
            index: w as u16,
            len: (w >> 16) as u16,
        }
    }

    /// Whether its index and length may be taken from a queue whose
    /// entries are filled (`filled`) or free; whether its buffer may is
    /// the taker's map's question.
    pub const fn fits(self, filled: bool) -> bool {
        let len = self.len as usize;
        (self.index as usize) < BUFFERS
            && if filled {
                MIN_FRAME <= len && len <= MAX_FRAME
            } else {
                len == 0
            }
    }
}

/// A map of the buffers of one pool a side owns: bit `i`, buffer `i`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Owned(pub u128);

impl Owned {
    pub const NONE: Owned = Owned(0);
    pub const ALL: Owned = Owned(u128::MAX);

    /// Whether it holds buffer `index`; never one at or above 128.
    pub const fn has(self, index: u16) -> bool {
        (index as usize) < BUFFERS && self.0 & 1 << index != 0
    }

    const fn with(self, index: u16) -> Owned {
        Owned(self.0 | 1 << index)
    }

    const fn without(self, index: u16) -> Owned {
        Owned(self.0 & !(1 << index))
    }

    /// The lowest buffer it holds.
    pub const fn first(self) -> Option<u16> {
        if self.0 == 0 {
            None
        } else {
            Some(self.0.trailing_zeros() as u16)
        }
    }

    pub const fn count(self) -> usize {
        self.0.count_ones() as usize
    }

    pub const fn is_empty(self) -> bool {
        self.0 == 0
    }
}

/// The link block, which the driver writes once and `net` reads once.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub mac: Mac,
    pub mtu: u16,
    pub up: bool,
}

impl Link {
    /// A link with this MAC and [`MTU`].
    pub const fn new(mac: Mac, up: bool) -> Link {
        Link { mac, mtu: MTU, up }
    }

    /// Writes the MAC, MTU and link, then ready with release order.
    fn write(&self, mem: &impl Memory) {
        mem.write(layout::LINK + layout::LINK_MAC, &self.mac.0);
        mem.store16(layout::LINK + layout::LINK_MTU, self.mtu, Relaxed);
        mem.store32(layout::LINK + layout::LINK_UP, self.up.into(), Relaxed);
        mem.store32(layout::LINK + layout::LINK_READY, 1, Release);
    }

    /// Reads ready with acquire order, then the rest, and checks each.
    fn read(mem: &impl Memory) -> Result<Link, LinkError> {
        let ready = mem.load32(layout::LINK + layout::LINK_READY, Acquire);
        if ready != 1 {
            return Err(LinkError::NotReady(ready));
        }
        let mut mac = [0; 6];
        mem.read(layout::LINK + layout::LINK_MAC, &mut mac);
        let mac = Mac(mac);
        let mtu = mem.load16(layout::LINK + layout::LINK_MTU, Relaxed);
        let up = mem.load32(layout::LINK + layout::LINK_UP, Relaxed);
        if !mac.is_unicast() {
            return Err(LinkError::BadMac(mac));
        }
        if mtu != MTU {
            return Err(LinkError::BadMtu(mtu));
        }
        if up > 1 {
            return Err(LinkError::BadUp(up));
        }
        Ok(Link {
            mac,
            mtu,
            up: up == 1,
        })
    }
}

/// Why `net` refused the link block.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LinkError {
    /// Ready is not 1.
    NotReady(u32),
    /// The MAC is 0, multicast or broadcast.
    BadMac(Mac),
    /// The MTU is not 1,500.
    BadMtu(u16),
    /// The link word is neither 0 nor 1.
    BadUp(u32),
}

impl fmt::Display for LinkError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            LinkError::NotReady(r) => write!(f, "the link block is not ready ({r})"),
            LinkError::BadMac(m) => write!(f, "the link block's MAC {m} is not unicast"),
            LinkError::BadMtu(m) => write!(f, "the link block's MTU is {m}, not {MTU}"),
            LinkError::BadUp(u) => write!(f, "the link block's link word is {u}"),
        }
    }
}

/// Why a frame was not pushed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PushError {
    /// The frame is not 14 to 1,514 bytes; nothing is counted.
    Length(usize),
    /// No buffer of the pool this side fills is free, even after taking
    /// back what its free queue holds: the frame is dropped and counted
    /// in [`Counters::dropped`].
    NoBuffer,
    /// The queue has no room by the other side's `tail`, which only a
    /// broken peer causes: dropped and counted in [`Counters::bad`].
    Full,
}

impl fmt::Display for PushError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            PushError::Length(n) => write!(f, "a frame of {n} bytes"),
            PushError::NoBuffer => f.write_str("no free buffer"),
            PushError::Full => f.write_str("the queue is full"),
        }
    }
}

/// What a side has counted since it began.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Frames pushed on the filled queue it produces.
    pub sent: u64,
    /// Frames taken from the filled queue it consumes.
    pub received: u64,
    /// Free buffers taken back from the free queue it consumes.
    pub reclaimed: u64,
    /// Frames dropped for want of a free buffer ([`PushError::NoBuffer`]).
    pub dropped: u64,
    /// Bad entries skipped, queues that claimed more than 128 entries, and
    /// pushes refused for a queue a broken peer left full.
    pub bad: u64,
    /// Batches after which it owed the other side a signal.
    pub signals: u64,
}

/// A queue this side produces: its own `head`, never read back.
#[derive(Clone, Copy, Debug)]
struct Producer {
    queue: Queue,
    head: u32,
}

impl Producer {
    const fn new(queue: Queue) -> Producer {
        Producer { queue, head: 0 }
    }

    /// Whether one more entry fits, by the consumer's `tail` (acquire, so
    /// that its reads of the slot come first). With an honest consumer it
    /// always does when this side holds a buffer to push, since a pool
    /// has 128; so no room, a `tail` that leaves 128 entries or more or is
    /// ahead of `head`, means a broken peer, which the caller counts.
    fn room(&self, mem: &impl Memory) -> bool {
        let tail = mem.load32(self.queue.tail(), Acquire);
        self.head.wrapping_sub(tail) < BUFFERS as u32
    }

    /// Writes `entry` and then `head` with release order, so that the
    /// buffer and the entry are written before the consumer sees them.
    /// [`Producer::room`] must have said yes.
    fn publish(&mut self, mem: &impl Memory, entry: Entry) {
        mem.store32(self.queue.entry(self.head), entry.word(), Relaxed);
        self.head = self.head.wrapping_add(1);
        mem.store32(self.queue.head(), self.head, Release);
    }
}

/// A queue this side consumes: its own `tail`, never read back, and the
/// entry it has looked at but not taken.
#[derive(Clone, Copy, Debug)]
struct Consumer {
    queue: Queue,
    tail: u32,
    peeked: Option<Entry>,
}

impl Consumer {
    const fn new(queue: Queue) -> Consumer {
        Consumer {
            queue,
            tail: 0,
            peeked: None,
        }
    }

    /// The next entry that fits the queue and names a buffer `owned` does
    /// not hold, without taking it; the bad entries before it are passed
    /// and counted in `bad`. It reads `head` (acquire) once, and at most
    /// the 128 entries that leaves; a `head` more than 128 ahead is taken
    /// as an empty queue and counted. The entry is kept until taken, so
    /// asking again reads nothing.
    fn peek(&mut self, mem: &impl Memory, owned: Owned, bad: &mut u64) -> Option<Entry> {
        if let Some(e) = self.peeked {
            return Some(e);
        }
        let head = mem.load32(self.queue.head(), Acquire);
        let n = head.wrapping_sub(self.tail);
        if n > BUFFERS as u32 {
            *bad += 1;
            return None;
        }
        for _ in 0..n {
            let e = Entry::from_word(mem.load32(self.queue.entry(self.tail), Relaxed));
            if e.fits(self.queue.is_filled()) && !owned.has(e.index) {
                self.peeked = Some(e);
                return Some(e);
            }
            *bad += 1;
            self.advance(mem);
        }
        None
    }

    /// Passes the entry at `tail`: writes the new `tail` with release
    /// order, so that the producer reuses the slot only after this side's
    /// reads of it.
    fn advance(&mut self, mem: &impl Memory) {
        self.tail = self.tail.wrapping_add(1);
        self.peeked = None;
        mem.store32(self.queue.tail(), self.tail, Release);
    }
}

/// What the two sides share: one side's state, by its role.
#[derive(Debug)]
struct Side<M> {
    mem: M,
    role: Role,
    started: bool,
    /// The pool it fills: the free queue it takes buffers from, the
    /// filled queue it pushes them on, and the map of those it holds.
    take_free: Consumer,
    push_filled: Producer,
    fills: Owned,
    /// The pool it empties: the filled queue it takes frames from, the
    /// free queue it hands buffers back on, and the map of those it
    /// holds, which it hands back at once.
    take_filled: Consumer,
    push_free: Producer,
    empties: Owned,
    pushed: bool,
    counters: Counters,
}

impl<M: Memory> Side<M> {
    #[track_caller]
    fn new(mem: M, role: Role) -> Side<M> {
        assert!(
            mem.len() >= layout::END,
            "frames: a window of {:#x} bytes is too small",
            mem.len()
        );
        let fills = role.fills();
        let empties = role.peer().fills();
        Side {
            mem,
            role,
            started: false,
            take_free: Consumer::new(fills.free()),
            push_filled: Producer::new(fills.filled()),
            fills: Owned::NONE,
            take_filled: Consumer::new(empties.filled()),
            push_free: Producer::new(empties.free()),
            // At start each side owns every buffer of the pool the other
            // fills, and hands them all over.
            empties: Owned::ALL,
            pushed: false,
            counters: Counters::default(),
        }
    }

    #[track_caller]
    fn started(&self) {
        assert!(
            self.started,
            "frames: {:?} side used before it started",
            self.role
        );
    }

    /// Hands back every buffer of the pool it empties that it still
    /// holds, lowest first, while its free queue has room.
    fn hand_back(&mut self) {
        while let Some(i) = self.empties.first() {
            if !self.push_free.room(&self.mem) {
                self.counters.bad += 1;
                return;
            }
            self.push_free.publish(&self.mem, Entry::free(i));
            self.empties = self.empties.without(i);
            self.pushed = true;
        }
    }

    fn start(&mut self) {
        assert!(!self.started, "frames: {:?} side started twice", self.role);
        self.started = true;
        self.hand_back();
    }

    fn reclaim(&mut self) -> usize {
        self.started();
        let mut n = 0;
        while let Some(e) = self
            .take_free
            .peek(&self.mem, self.fills, &mut self.counters.bad)
        {
            self.take_free.advance(&self.mem);
            self.fills = self.fills.with(e.index);
            self.counters.reclaimed += 1;
            n += 1;
        }
        n
    }

    fn push(&mut self, len: usize, fill: impl FnOnce(&Part<&M>)) -> Result<(), PushError> {
        self.started();
        if !(MIN_FRAME..=MAX_FRAME).contains(&len) {
            return Err(PushError::Length(len));
        }
        if self.fills.is_empty() {
            self.reclaim();
        }
        let Some(i) = self.fills.first() else {
            self.counters.dropped += 1;
            return Err(PushError::NoBuffer);
        };
        if !self.push_filled.room(&self.mem) {
            self.counters.bad += 1;
            return Err(PushError::Full);
        }
        let pool = self.role.fills();
        fill(&Part::memory(&self.mem, pool.buffer(i.into()), len));
        self.push_filled.publish(
            &self.mem,
            Entry {
                index: i,
                len: len as u16,
            },
        );
        self.fills = self.fills.without(i);
        self.pushed = true;
        self.counters.sent += 1;
        Ok(())
    }

    fn peek(&mut self) -> Option<usize> {
        self.started();
        self.hand_back();
        self.take_filled
            .peek(&self.mem, self.empties, &mut self.counters.bad)
            .map(|e| e.len.into())
    }

    fn pop<R>(&mut self, f: impl FnOnce(&Part<&M>) -> R) -> Option<R> {
        self.started();
        self.hand_back();
        let e = self
            .take_filled
            .peek(&self.mem, self.empties, &mut self.counters.bad)?;
        self.empties = self.empties.with(e.index);
        self.counters.received += 1;
        let pool = self.role.peer().fills();
        let r = f(&Part::memory(
            &self.mem,
            pool.buffer(e.index.into()),
            e.len.into(),
        ));
        self.take_filled.advance(&self.mem);
        self.hand_back();
        Some(r)
    }

    fn take(&mut self, out: &mut [u8; MAX_FRAME]) -> Option<usize> {
        self.pop(|frame| {
            let n = frame.len();
            frame.read(0, &mut out[..n]);
            n
        })
    }

    fn end_batch(&mut self) -> bool {
        self.started();
        self.hand_back();
        let pushed = core::mem::take(&mut self.pushed);
        if pushed {
            self.counters.signals += 1;
        }
        pushed
    }

    fn owned(&self, pool: Pool) -> Owned {
        if pool == self.role.fills() {
            self.fills
        } else {
            self.empties
        }
    }
}

/// The driver's side: it fills receive buffers from the device and
/// pushes them on `RX_FILLED`, takes them back from `RX_FREE`, and takes
/// frames to send from `TX_FILLED`, handing each transmit buffer back on
/// `TX_FREE` at once.
#[derive(Debug)]
pub struct Driver<M>(Side<M>);

impl<M: Memory> Driver<M> {
    /// The driver's side of the frame `mem`, which must be zeroed and at
    /// least [`layout::END`] bytes (panics otherwise). It owns every
    /// transmit buffer until [`Driver::start`].
    #[track_caller]
    pub fn new(mem: M) -> Driver<M> {
        Driver(Side::new(mem, Role::Driver))
    }

    /// Hands every transmit buffer to `net` on `TX_FREE`, then writes the
    /// link block, ready last; signal `net` after. Once only, before
    /// anything else.
    pub fn start(&mut self, link: Link) {
        self.0.start();
        link.write(&self.0.mem);
    }

    /// Takes back every receive buffer `RX_FREE` holds; returns how many.
    /// [`Driver::deliver`] does this itself when it holds none.
    pub fn reclaim(&mut self) -> usize {
        self.0.reclaim()
    }

    /// Receive buffers it holds free.
    pub fn free_buffers(&self) -> usize {
        self.0.fills.count()
    }

    /// Copies `frame` into a free receive buffer and pushes it on
    /// `RX_FILLED`.
    pub fn deliver(&mut self, frame: &[u8]) -> Result<(), PushError> {
        self.0.push(frame.len(), |buf| buf.write(0, frame))
    }

    /// As [`Driver::deliver`], with `fill` writing the `len` bytes of the
    /// frame into the window it is given, for a copy straight from the
    /// device's memory ([`crate::mem::copy`]). `fill` runs only once a
    /// buffer and room are found.
    pub fn deliver_with(
        &mut self,
        len: usize,
        fill: impl FnOnce(&Part<&M>),
    ) -> Result<(), PushError> {
        self.0.push(len, fill)
    }

    /// The length of the next frame on `TX_FILLED`, which stays there
    /// until taken; bad entries before it are passed and counted.
    pub fn peek_tx(&mut self) -> Option<usize> {
        self.0.peek()
    }

    /// Takes the next frame from `TX_FILLED` into `out`, hands its buffer
    /// back on `TX_FREE`, and returns its length.
    pub fn take_tx(&mut self, out: &mut [u8; MAX_FRAME]) -> Option<usize> {
        self.0.take(out)
    }

    /// As [`Driver::take_tx`], with `f` reading the frame from the window
    /// it is given, exactly the frame's bytes, for a copy straight to the
    /// device's memory.
    pub fn take_tx_with<R>(&mut self, f: impl FnOnce(&Part<&M>) -> R) -> Option<R> {
        self.0.pop(f)
    }

    /// Ends a batch: whether it pushed anything since the last, in which
    /// case signal `net` now, once.
    pub fn end_batch(&mut self) -> bool {
        self.0.end_batch()
    }

    pub fn counters(&self) -> Counters {
        self.0.counters
    }

    /// The buffers of `pool` it holds.
    pub fn owned(&self, pool: Pool) -> Owned {
        self.0.owned(pool)
    }

    pub fn memory(&self) -> &M {
        &self.0.mem
    }
}

/// `net`'s side: it fills transmit buffers and pushes them on
/// `TX_FILLED`, takes them back from `TX_FREE`, and takes received frames
/// from `RX_FILLED`, handing each receive buffer back on `RX_FREE` at
/// once.
#[derive(Debug)]
pub struct Net<M>(Side<M>);

impl<M: Memory> Net<M> {
    /// `net`'s side of the frame `mem`, at least [`layout::END`] bytes
    /// (panics otherwise). It owns every receive buffer until
    /// [`Net::attach`].
    #[track_caller]
    pub fn new(mem: M) -> Net<M> {
        Net(Side::new(mem, Role::Net))
    }

    /// At the driver's first signal: reads and checks the link block, then
    /// hands every receive buffer to the driver on `RX_FREE`; signal the
    /// driver after. A refused link block hands nothing over, and may be
    /// read again later.
    pub fn attach(&mut self) -> Result<Link, LinkError> {
        let link = Link::read(&self.0.mem)?;
        self.0.start();
        Ok(link)
    }

    /// Takes back every transmit buffer `TX_FREE` holds; returns how many.
    /// [`Net::send`] does this itself when it holds none.
    pub fn reclaim(&mut self) -> usize {
        self.0.reclaim()
    }

    /// Transmit buffers it holds free.
    pub fn free_buffers(&self) -> usize {
        self.0.fills.count()
    }

    /// Copies `frame` into a free transmit buffer and pushes it on
    /// `TX_FILLED`.
    pub fn send(&mut self, frame: &[u8]) -> Result<(), PushError> {
        self.0.push(frame.len(), |buf| buf.write(0, frame))
    }

    /// As [`Net::send`], with `fill` writing the frame's `len` bytes.
    pub fn send_with(&mut self, len: usize, fill: impl FnOnce(&Part<&M>)) -> Result<(), PushError> {
        self.0.push(len, fill)
    }

    /// The length of the next frame on `RX_FILLED`, which stays there
    /// until taken.
    pub fn peek_rx(&mut self) -> Option<usize> {
        self.0.peek()
    }

    /// Takes the next received frame into `out`, hands its buffer back on
    /// `RX_FREE`, and returns its length: the stack then parses `out`, a
    /// copy nothing else writes.
    pub fn take_rx(&mut self, out: &mut [u8; MAX_FRAME]) -> Option<usize> {
        self.0.take(out)
    }

    /// As [`Net::take_rx`], with `f` reading the frame's window.
    pub fn take_rx_with<R>(&mut self, f: impl FnOnce(&Part<&M>) -> R) -> Option<R> {
        self.0.pop(f)
    }

    /// Ends a batch: whether it pushed anything since the last, in which
    /// case signal the driver now, once.
    pub fn end_batch(&mut self) -> bool {
        self.0.end_batch()
    }

    pub fn counters(&self) -> Counters {
        self.0.counters
    }

    /// The buffers of `pool` it holds.
    pub fn owned(&self, pool: Pool) -> Owned {
        self.0.owned(pool)
    }

    pub fn memory(&self) -> &M {
        &self.0.mem
    }
}

#[cfg(test)]
mod tests;
