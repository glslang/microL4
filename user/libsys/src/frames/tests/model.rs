//! The frame queues against a model of their two owners
//! (`docs/design.md`, "Code and tests"): random pushes, pops and corrupt
//! entries; every buffer owned once; bad entries counted, never followed.
//!
//! - [`two_honest_sides_hand_every_buffer_on_once`] runs a driver and `net`
//!   in random order against a model that knows where every buffer is: on
//!   one side or in one queue, and in exactly one of these. Every frame
//!   arrives once, whole and in order, and nothing is bad.
//! - [`a_hostile_peer_is_counted_and_never_followed`] runs one honest side
//!   against a peer that writes anything anywhere in the queues and
//!   buffers, beside a reference model of that side written from the
//!   note's rules on a second copy of the memory. After every step the two
//!   agree on what was taken, the maps of owned buffers, the counters and
//!   every word of the queues; so the side takes only entries the rules
//!   allow, never a buffer it holds, and does bounded work.
//! - [`two_threads_hand_frames_back_and_forth`] runs the two sides in two
//!   threads, so that Miri's race detector checks the orderings.

use std::collections::{BTreeSet, VecDeque};
use std::vec::Vec;

use proptest::prelude::*;

use super::super::*;
use super::ram;
use crate::mem::Ram;
use core::sync::atomic::Ordering::Relaxed;

const MAC: Mac = Mac([0x02, 0, 0, 0, 0, 1]);

/// The bytes of the frame numbered `seq`, `len` long.
fn frame(len: usize, seq: u32) -> Vec<u8> {
    let s = seq.to_le_bytes();
    (0..len)
        .map(|i| s[i % 4] ^ (i as u8).wrapping_mul(13))
        .collect()
}

fn queue_no(q: Queue) -> usize {
    Queue::ALL.iter().position(|&x| x == q).unwrap()
}

fn pool_no(p: Pool) -> usize {
    match p {
        Pool::Rx => 0,
        Pool::Tx => 1,
    }
}

fn role_no(r: Role) -> usize {
    match r {
        Role::Driver => 0,
        Role::Net => 1,
    }
}

fn owned(set: &BTreeSet<u16>) -> Owned {
    Owned(set.iter().fold(0, |m, &i| m | 1 << i))
}

/// One side, by its role, through the public interface.
enum Honest<'a> {
    Driver(Driver<&'a Ram>),
    Net(Net<&'a Ram>),
}

impl<'a> Honest<'a> {
    fn push(&mut self, frame: &[u8]) -> Result<(), PushError> {
        match self {
            Honest::Driver(d) => d.deliver(frame),
            Honest::Net(n) => n.send(frame),
        }
    }
    fn reclaim(&mut self) -> usize {
        match self {
            Honest::Driver(d) => d.reclaim(),
            Honest::Net(n) => n.reclaim(),
        }
    }
    fn peek(&mut self) -> Option<usize> {
        match self {
            Honest::Driver(d) => d.peek_tx(),
            Honest::Net(n) => n.peek_rx(),
        }
    }
    fn take(&mut self) -> Option<Vec<u8>> {
        let mut out = [0; MAX_FRAME];
        let n = match self {
            Honest::Driver(d) => d.take_tx(&mut out),
            Honest::Net(n) => n.take_rx(&mut out),
        }?;
        Some(out[..n].to_vec())
    }
    fn end(&mut self) -> bool {
        match self {
            Honest::Driver(d) => d.end_batch(),
            Honest::Net(n) => n.end_batch(),
        }
    }
    fn owned(&self, p: Pool) -> Owned {
        match self {
            Honest::Driver(d) => d.owned(p),
            Honest::Net(n) => n.owned(p),
        }
    }
    fn counters(&self) -> Counters {
        match self {
            Honest::Driver(d) => d.counters(),
            Honest::Net(n) => n.counters(),
        }
    }
}

/// A side's operation.
#[derive(Clone, Copy, Debug)]
enum Step {
    /// Push a frame of this length (`deliver` or `send`).
    Push(usize),
    Reclaim,
    Peek,
    Take,
    End,
}

fn frame_len() -> impl Strategy<Value = usize> {
    prop_oneof![
        8 => 14..=MAX_FRAME,
        2 => Just(MIN_FRAME),
        2 => Just(MAX_FRAME),
        1 => prop_oneof![Just(0), Just(13), Just(1515), Just(2048)],
    ]
}

fn step() -> impl Strategy<Value = Step> {
    prop_oneof![
        6 => frame_len().prop_map(Step::Push),
        1 => Just(Step::Reclaim),
        1 => Just(Step::Peek),
        5 => Just(Step::Take),
        2 => Just(Step::End),
    ]
}

/// Where the buffers are, as the design says they move: each side's own,
/// and each queue's entries in order with the number of the frame a
/// filled one carries.
struct Owners {
    owned: [[BTreeSet<u16>; 2]; 2],
    queues: [VecDeque<(Entry, u32)>; 4],
    pushed: [bool; 2],
    counters: [Counters; 2],
    seq: u32,
}

impl Owners {
    /// After both sides started: each handed the other every buffer of
    /// the pool the other fills.
    fn started() -> Owners {
        let mut o = Owners {
            owned: Default::default(),
            queues: Default::default(),
            pushed: [true, true],
            counters: Default::default(),
            seq: 0,
        };
        for p in Pool::ALL {
            for i in 0..BUFFERS as u16 {
                o.queues[queue_no(p.free())].push_back((Entry::free(i), 0));
            }
        }
        o
    }

    fn reclaim(&mut self, r: Role) -> usize {
        let p = r.fills();
        let q = &mut self.queues[queue_no(p.free())];
        let n = q.len();
        for (e, _) in q.drain(..) {
            assert!(self.owned[role_no(r)][pool_no(p)].insert(e.index));
        }
        self.counters[role_no(r)].reclaimed += n as u64;
        n
    }

    fn push(&mut self, r: Role, len: usize) -> Result<u32, PushError> {
        if !(MIN_FRAME..=MAX_FRAME).contains(&len) {
            return Err(PushError::Length(len));
        }
        let p = r.fills();
        if self.owned[role_no(r)][pool_no(p)].is_empty() {
            self.reclaim(r);
        }
        let Some(i) = self.owned[role_no(r)][pool_no(p)].pop_first() else {
            self.counters[role_no(r)].dropped += 1;
            return Err(PushError::NoBuffer);
        };
        self.seq += 1;
        let e = Entry {
            index: i,
            len: len as u16,
        };
        self.queues[queue_no(p.filled())].push_back((e, self.seq));
        self.pushed[role_no(r)] = true;
        self.counters[role_no(r)].sent += 1;
        Ok(self.seq)
    }

    fn peek(&self, r: Role) -> Option<usize> {
        let p = r.peer().fills();
        self.queues[queue_no(p.filled())]
            .front()
            .map(|(e, _)| e.len.into())
    }

    /// The frame taken, and its number; its buffer goes straight back.
    fn take(&mut self, r: Role) -> Option<(usize, u32)> {
        let p = r.peer().fills();
        let (e, seq) = self.queues[queue_no(p.filled())].pop_front()?;
        self.queues[queue_no(p.free())].push_back((Entry::free(e.index), 0));
        self.pushed[role_no(r)] = true;
        self.counters[role_no(r)].received += 1;
        Some((e.len.into(), seq))
    }

    fn end(&mut self, r: Role) -> bool {
        let p = core::mem::take(&mut self.pushed[role_no(r)]);
        if p {
            self.counters[role_no(r)].signals += 1;
        }
        p
    }

    /// Every buffer of each pool is in exactly one place: a side's map or
    /// one entry of one of the pool's two queues.
    fn check_every_buffer_owned_once(&self) {
        for p in Pool::ALL {
            let mut seen = [0u32; BUFFERS];
            for r in [Role::Driver, Role::Net] {
                for &i in &self.owned[role_no(r)][pool_no(p)] {
                    seen[i as usize] += 1;
                }
            }
            for q in [p.filled(), p.free()] {
                for (e, _) in &self.queues[queue_no(q)] {
                    seen[e.index as usize] += 1;
                }
            }
            assert!(seen.iter().all(|&n| n == 1), "{p:?}: {seen:?}");
        }
    }

    /// The memory holds each queue as the model does, between the
    /// consumer's `tail` and the producer's `head`.
    fn check_memory(&self, ram: &Ram) {
        for q in Queue::ALL {
            let head = ram.load32(q.head(), Relaxed);
            let tail = ram.load32(q.tail(), Relaxed);
            let model = &self.queues[queue_no(q)];
            assert_eq!(head.wrapping_sub(tail) as usize, model.len(), "{q:?}");
            for (k, (e, _)) in model.iter().enumerate() {
                let w = ram.load32(q.entry(tail.wrapping_add(k as u32)), Relaxed);
                assert_eq!(Entry::from_word(w), *e, "{q:?} entry {k}");
            }
        }
    }
}

fn honest_run(steps: &[(Role, Step)]) {
    let ram = ram();
    let mut d = Driver::new(&ram);
    d.start(Link::new(MAC, true));
    let mut n = Net::new(&ram);
    assert_eq!(n.attach(), Ok(Link::new(MAC, true)));
    let mut sides = [Honest::Driver(d), Honest::Net(n)];
    let mut model = Owners::started();
    model.check_every_buffer_owned_once();
    model.check_memory(&ram);
    for &(r, s) in steps {
        let side = &mut sides[role_no(r)];
        match s {
            Step::Push(len) => match model.push(r, len) {
                Ok(seq) => assert_eq!(side.push(&frame(len, seq)), Ok(())),
                Err(e) => assert_eq!(side.push(&frame(len, 0)), Err(e)),
            },
            Step::Reclaim => assert_eq!(side.reclaim(), model.reclaim(r)),
            Step::Peek => assert_eq!(side.peek(), model.peek(r)),
            Step::Take => {
                let got = side.take();
                let want = model.take(r).map(|(len, seq)| frame(len, seq));
                assert_eq!(got, want, "{r:?} took");
            }
            Step::End => assert_eq!(side.end(), model.end(r)),
        }
        for r in [Role::Driver, Role::Net] {
            let side = &sides[role_no(r)];
            for p in Pool::ALL {
                assert_eq!(side.owned(p), owned(&model.owned[role_no(r)][pool_no(p)]));
            }
            assert_eq!(side.counters(), model.counters[role_no(r)], "{r:?}");
            assert_eq!(side.counters().bad, 0);
        }
        model.check_every_buffer_owned_once();
        model.check_memory(&ram);
    }
}

/// A peer that breaks the rules: what it writes, and where.
#[derive(Clone, Copy, Debug)]
enum Peer {
    /// Pushes `word` on one of the two queues the honest side consumes, at
    /// the `head` the memory holds now.
    Push { queue: usize, word: u32 },
    /// Writes `word` into slot `slot` of one of those queues.
    Entry { queue: usize, slot: u8, word: u32 },
    /// Moves an index the honest side reads (a consumed queue's `head`, a
    /// produced queue's `tail`) or writes (its own), by `delta`, or sets
    /// it to `delta` with `absolute`.
    Index {
        which: u8,
        delta: u32,
        absolute: bool,
    },
    /// Writes a byte into a buffer.
    Buffer {
        tx: bool,
        index: u8,
        offset: u16,
        byte: u8,
    },
}

/// Entries that are often good, and bad in every way the rules name.
fn entry_word() -> impl Strategy<Value = u32> {
    let index = prop_oneof![8 => 0..BUFFERS as u32, 1 => 128..131u32, 1 => any::<u16>().prop_map(u32::from)];
    let len = prop_oneof![
        3 => Just(0u32),
        3 => 14..=MAX_FRAME as u32,
        2 => prop_oneof![
            Just(1),
            1..14u32,
            Just(13),
            Just(1515),
            Just(MIN_FRAME as u32),
            Just(MAX_FRAME as u32)
        ],
        1 => any::<u16>().prop_map(u32::from),
    ];
    prop_oneof![9 => (index, len).prop_map(|(i, l)| i | l << 16), 1 => any::<u32>()]
}

fn peer() -> impl Strategy<Value = Peer> {
    let delta = prop_oneof![
        6 => 0..4u32,
        2 => 125..131u32,
        2 => (1..4u32).prop_map(u32::wrapping_neg),
        1 => any::<u32>(),
    ];
    prop_oneof![
        6 => (0..2usize, entry_word()).prop_map(|(queue, word)| Peer::Push { queue, word }),
        2 => (0..2usize, 0..BUFFERS as u8, entry_word())
            .prop_map(|(queue, slot, word)| Peer::Entry { queue, slot, word }),
        3 => (0..8u8, delta, any::<bool>()).prop_map(|(which, delta, absolute)| Peer::Index {
            which,
            delta,
            absolute: absolute && which % 2 == 1,
        }),
        1 => (any::<bool>(), 0..BUFFERS as u8, 0..BUFFER_SIZE as u16, any::<u8>())
            .prop_map(|(tx, index, offset, byte)| Peer::Buffer { tx, index, offset, byte }),
    ]
}

#[derive(Clone, Copy, Debug)]
enum Hostile {
    Side(Step),
    Peer(Peer),
}

fn hostile() -> impl Strategy<Value = Hostile> {
    prop_oneof![
        1 => step().prop_map(Hostile::Side),
        1 => peer().prop_map(Hostile::Peer),
    ]
}

/// The rules of "The frame queues" for one side, written out plainly on
/// a memory of its own: the queues it consumes (the free queue of the pool
/// it fills, the filled queue of the pool it empties) and those it
/// produces, its own copies of their indices, and the buffers it owns.
struct Reference<'a> {
    mem: &'a Ram,
    role: Role,
    fills: BTreeSet<u16>,
    empties: BTreeSet<u16>,
    /// `head`s it writes: the fill pool's filled queue, the empty pool's
    /// free queue.
    filled_head: u32,
    free_head: u32,
    /// `tail`s it writes: the fill pool's free queue, the empty pool's
    /// filled queue.
    free_tail: u32,
    filled_tail: u32,
    /// The filled entry it has looked at and not taken.
    peeked: Option<Entry>,
    pushed: bool,
    counters: Counters,
}

impl<'a> Reference<'a> {
    fn fill_pool(&self) -> Pool {
        self.role.fills()
    }

    fn empty_pool(&self) -> Pool {
        self.role.peer().fills()
    }

    /// Whether `q`, which it produces from `head`, has room by the
    /// consumer's `tail`; a full one is a broken peer, counted.
    fn room(&mut self, q: Queue, head: u32) -> bool {
        let tail = self.mem.load32(q.tail(), Relaxed);
        let used = head.wrapping_sub(tail);
        if used >= BUFFERS as u32 {
            self.counters.bad += 1;
            false
        } else {
            true
        }
    }

    fn put(&mut self, q: Queue, head: u32, e: Entry) -> u32 {
        self.mem.store32(q.entry(head), e.word(), Relaxed);
        let head = head.wrapping_add(1);
        self.mem.store32(q.head(), head, Relaxed);
        head
    }

    /// Hands back every buffer of the pool it empties, lowest first.
    fn hand_back(&mut self) {
        let q = self.empty_pool().free();
        while let Some(&i) = self.empties.first() {
            if !self.room(q, self.free_head) {
                return;
            }
            self.free_head = self.put(q, self.free_head, Entry::free(i));
            self.empties.remove(&i);
            self.pushed = true;
        }
    }

    fn start(mem: &'a Ram, role: Role) -> Reference<'a> {
        let mut r = Reference {
            mem,
            role,
            fills: BTreeSet::new(),
            empties: (0..BUFFERS as u16).collect(),
            filled_head: 0,
            free_head: 0,
            free_tail: 0,
            filled_tail: 0,
            peeked: None,
            pushed: false,
            counters: Counters::default(),
        };
        r.hand_back();
        r
    }

    /// The next entry of `q` from `tail` it may take, given the buffers
    /// `held`: bad ones are passed, counted, and `tail` moved past them.
    fn next(&mut self, q: Queue, tail: &mut u32, held: &BTreeSet<u16>) -> Option<Entry> {
        let head = self.mem.load32(q.head(), Relaxed);
        let waiting = head.wrapping_sub(*tail);
        if waiting > BUFFERS as u32 {
            self.counters.bad += 1;
            return None;
        }
        for _ in 0..waiting {
            let e = Entry::from_word(self.mem.load32(q.entry(*tail), Relaxed));
            let len = usize::from(e.len);
            let fits = usize::from(e.index) < BUFFERS
                && !held.contains(&e.index)
                && if q.is_filled() {
                    (MIN_FRAME..=MAX_FRAME).contains(&len)
                } else {
                    len == 0
                };
            if fits {
                return Some(e);
            }
            self.counters.bad += 1;
            *tail = tail.wrapping_add(1);
            self.mem.store32(q.tail(), *tail, Relaxed);
        }
        None
    }

    fn reclaim(&mut self) -> usize {
        let q = self.fill_pool().free();
        let mut tail = self.free_tail;
        let mut held = self.fills.clone();
        let mut n = 0;
        while let Some(e) = self.next(q, &mut tail, &held) {
            tail = tail.wrapping_add(1);
            self.mem.store32(q.tail(), tail, Relaxed);
            held.insert(e.index);
            n += 1;
        }
        self.free_tail = tail;
        self.fills = held;
        self.counters.reclaimed += n as u64;
        n
    }

    fn push(&mut self, frame: &[u8]) -> Result<(), PushError> {
        if !(MIN_FRAME..=MAX_FRAME).contains(&frame.len()) {
            return Err(PushError::Length(frame.len()));
        }
        if self.fills.is_empty() {
            self.reclaim();
        }
        let Some(&i) = self.fills.first() else {
            self.counters.dropped += 1;
            return Err(PushError::NoBuffer);
        };
        let q = self.fill_pool().filled();
        if !self.room(q, self.filled_head) {
            return Err(PushError::Full);
        }
        self.mem.write(self.fill_pool().buffer(i.into()), frame);
        let e = Entry {
            index: i,
            len: frame.len() as u16,
        };
        self.filled_head = self.put(q, self.filled_head, e);
        self.fills.remove(&i);
        self.pushed = true;
        self.counters.sent += 1;
        Ok(())
    }

    fn peek(&mut self) -> Option<usize> {
        self.hand_back();
        if self.peeked.is_none() {
            let mut tail = self.filled_tail;
            let held = self.empties.clone();
            self.peeked = self.next(self.empty_pool().filled(), &mut tail, &held);
            self.filled_tail = tail;
        }
        self.peeked.map(|e| e.len.into())
    }

    fn take(&mut self) -> Option<Vec<u8>> {
        self.peek()?;
        let e = self.peeked.take().unwrap();
        self.empties.insert(e.index);
        self.counters.received += 1;
        let mut out = std::vec![0; e.len.into()];
        self.mem
            .read(self.empty_pool().buffer(e.index.into()), &mut out);
        self.filled_tail = self.filled_tail.wrapping_add(1);
        self.mem
            .store32(self.empty_pool().filled().tail(), self.filled_tail, Relaxed);
        self.hand_back();
        Some(out)
    }

    fn end(&mut self) -> bool {
        self.hand_back();
        let p = core::mem::take(&mut self.pushed);
        if p {
            self.counters.signals += 1;
        }
        p
    }
}

/// The peer's write `p` to `ram`, where the honest side is `role`.
fn apply(ram: &Ram, role: Role, p: Peer) {
    let fills = role.fills();
    let empties = role.peer().fills();
    // The queues the honest side consumes, which the peer produces.
    let consumed = [fills.free(), empties.filled()];
    match p {
        Peer::Push { queue, word } => {
            let q = consumed[queue];
            let head = ram.load32(q.head(), Relaxed);
            ram.store32(q.entry(head), word, Relaxed);
            ram.store32(q.head(), head.wrapping_add(1), Relaxed);
        }
        Peer::Entry { queue, slot, word } => {
            ram.store32(consumed[queue].entry(slot.into()), word, Relaxed);
        }
        Peer::Index {
            which,
            delta,
            absolute,
        } => {
            // Even: the indices the peer owns (consumed queues' heads,
            // produced queues' tails); odd: the honest side's own.
            let q = Queue::ALL[usize::from(which / 2)];
            let theirs = which % 2 == 0;
            let at = if (q.producer() == role) != theirs {
                q.head()
            } else {
                q.tail()
            };
            let v = if absolute {
                delta
            } else {
                ram.load32(at, Relaxed).wrapping_add(delta)
            };
            ram.store32(at, v, Relaxed);
        }
        Peer::Buffer {
            tx,
            index,
            offset,
            byte,
        } => {
            let pool = if tx { Pool::Tx } else { Pool::Rx };
            ram.store8(
                pool.buffer(index.into()) + usize::from(offset),
                byte,
                Relaxed,
            );
        }
    }
}

/// The queue pages, where the two runs must agree word for word.
fn same_queues(a: &Ram, b: &Ram) {
    for q in Queue::ALL {
        let mut x = [0; layout::ENTRIES + 4 * BUFFERS];
        let mut y = [0; layout::ENTRIES + 4 * BUFFERS];
        a.read(q.offset(), &mut x);
        b.read(q.offset(), &mut y);
        assert_eq!(&x[..], &y[..], "{q:?}");
    }
}

fn hostile_run(role: Role, steps: &[Hostile]) {
    let (ram, mirror) = (ram(), ram());
    for m in [&ram, &mirror] {
        Link::new(MAC, true).write(m);
    }
    let mut side = match role {
        Role::Driver => {
            let mut d = Driver::new(&ram);
            d.start(Link::new(MAC, true));
            Honest::Driver(d)
        }
        Role::Net => {
            let mut n = Net::new(&ram);
            assert_eq!(n.attach(), Ok(Link::new(MAC, true)));
            Honest::Net(n)
        }
    };
    let mut reference = Reference::start(&mirror, role);
    let mut seq = 0;
    for &s in steps {
        match s {
            Hostile::Side(Step::Push(len)) => {
                seq += 1;
                let f = frame(len, seq);
                assert_eq!(side.push(&f), reference.push(&f));
            }
            Hostile::Side(Step::Reclaim) => assert_eq!(side.reclaim(), reference.reclaim()),
            Hostile::Side(Step::Peek) => assert_eq!(side.peek(), reference.peek()),
            Hostile::Side(Step::Take) => {
                let got = side.take();
                if let Some(f) = &got {
                    // Never followed: what it takes fits a buffer.
                    assert!((MIN_FRAME..=MAX_FRAME).contains(&f.len()));
                }
                assert_eq!(got, reference.take());
            }
            Hostile::Side(Step::End) => assert_eq!(side.end(), reference.end()),
            Hostile::Peer(p) => {
                apply(&ram, role, p);
                apply(&mirror, role, p);
            }
        }
        assert_eq!(side.owned(role.fills()), owned(&reference.fills));
        assert_eq!(side.owned(role.peer().fills()), owned(&reference.empties));
        assert_eq!(side.counters(), reference.counters);
        same_queues(&ram, &mirror);
    }
    // And every buffer it filled, at the end (too slow for Miri).
    if !cfg!(miri) {
        assert_eq!(ram.to_vec(), mirror.to_vec());
    }
}

const CASES: u32 = if cfg!(miri) { 2 } else { 256 };
const STEPS: usize = if cfg!(miri) { 24 } else { 200 };

proptest! {
    #![proptest_config(ProptestConfig {
        cases: CASES,
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn two_honest_sides_hand_every_buffer_on_once(
        steps in prop::collection::vec((prop_oneof![Just(Role::Driver), Just(Role::Net)], step()), 1..STEPS)
    ) {
        honest_run(&steps);
    }

    #[test]
    fn a_hostile_peer_is_counted_and_never_followed(
        driver in any::<bool>(),
        steps in prop::collection::vec(hostile(), 1..STEPS)
    ) {
        hostile_run(if driver { Role::Driver } else { Role::Net }, &steps);
    }
}

/// The free-running 32-bit indices wrap past 2^32 with nothing lost: both
/// sides and the memory start every index just below it.
#[test]
fn indices_wrap_past_two_to_the_32() {
    let ram = ram();
    let start = u32::MAX - 20;
    for q in Queue::ALL {
        ram.store32(q.head(), start, Relaxed);
        ram.store32(q.tail(), start, Relaxed);
    }
    let mut d = Driver::new(&ram);
    let mut n = Net::new(&ram);
    for c in [
        &mut d.0.take_free,
        &mut d.0.take_filled,
        &mut n.0.take_free,
        &mut n.0.take_filled,
    ] {
        c.tail = start;
    }
    for p in [
        &mut d.0.push_filled,
        &mut d.0.push_free,
        &mut n.0.push_filled,
        &mut n.0.push_free,
    ] {
        p.head = start;
    }
    d.start(Link::new(MAC, true));
    n.attach().unwrap();
    let mut out = [0; MAX_FRAME];
    let (rounds, lens) = if cfg!(miri) { (40, 100) } else { (600, 1501) };
    for seq in 0..rounds {
        let len = 14 + (seq as usize * 97) % lens;
        d.deliver(&frame(len, seq)).unwrap();
        n.send(&frame(len, !seq)).unwrap();
        assert_eq!(n.take_rx(&mut out), Some(len));
        assert_eq!(&out[..len], &frame(len, seq)[..]);
        assert_eq!(d.take_tx(&mut out), Some(len));
        assert_eq!(&out[..len], &frame(len, !seq)[..]);
    }
    assert_eq!(
        ram.load32(Queue::RxFilled.head(), Relaxed),
        start.wrapping_add(rounds)
    );
    assert!(ram.load32(Queue::TxFree.head(), Relaxed) < start);
    assert_eq!(d.counters().bad + n.counters().bad, 0);
    let rounds = u64::from(rounds);
    assert_eq!((d.counters().sent, n.counters().received), (rounds, rounds));
}

/// The two sides in two threads, each spinning until the other moves:
/// under Miri the race detector checks that each buffer's bytes, written
/// and read with plain volatile accesses, are ordered by the queues'
/// release and acquire.
#[test]
fn two_threads_hand_frames_back_and_forth() {
    use crate::mem::Shared;
    const FRAMES: u32 = if cfg!(miri) { 12 } else { 5000 };
    // Each thread gives up after this many turns without finishing, so a
    // side that stops moving fails the test instead of hanging it.
    const TURNS: u64 = 10_000 * FRAMES as u64 + 100_000;
    let mut backing = std::vec![0u64; layout::END / 8];
    let base = backing.as_mut_ptr().cast::<u8>();
    // SAFETY: `backing` outlives both threads, which the scope joins, and
    // nothing touches it through a reference meanwhile; every access is
    // through the windows.
    let mem = unsafe { Shared::new(base, layout::END) };
    let mut d = Driver::new(mem);
    d.start(Link::new(MAC, true));
    let mut n = Net::new(mem);
    std::thread::scope(|s| {
        s.spawn(move || {
            // The driver: delivers frames, and takes what net sends.
            let mut out = [0; MAX_FRAME];
            let (mut sent, mut got) = (0, 0);
            for turn in 0.. {
                if sent == FRAMES && got == FRAMES {
                    break;
                }
                assert!(turn < TURNS, "the driver: {sent} sent, {got} taken");
                if sent < FRAMES && d.deliver(&frame(60 + sent as usize % 900, sent)).is_ok() {
                    sent += 1;
                }
                if let Some(len) = d.take_tx(&mut out) {
                    assert_eq!(&out[..len], &frame(len, got ^ 0x5555)[..]);
                    got += 1;
                }
                d.end_batch();
                std::thread::yield_now();
            }
            assert_eq!(d.counters().bad, 0);
        });
        s.spawn(move || {
            // net: waits for the link, then echoes each frame back.
            while n.attach().is_err() {
                std::thread::yield_now();
            }
            let mut out = [0; MAX_FRAME];
            let mut got = 0;
            let mut sent = 0;
            for turn in 0.. {
                if sent == FRAMES {
                    break;
                }
                assert!(turn < TURNS, "net: {got} taken, {sent} sent");
                if got < FRAMES
                    && let Some(len) = n.take_rx(&mut out)
                {
                    assert_eq!(&out[..len], &frame(len, got)[..]);
                    got += 1;
                }
                if sent < got
                    && n.send(&frame(14 + sent as usize % 1500, sent ^ 0x5555))
                        .is_ok()
                {
                    sent += 1;
                }
                n.end_batch();
                std::thread::yield_now();
            }
            assert_eq!(n.counters().bad, 0);
        });
    });
    drop(backing);
}
