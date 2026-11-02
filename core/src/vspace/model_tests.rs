//! The address-space proptest (`docs/design.md`, "Where the code lives"):
//! random sequences of map, remap and unmap invocations through
//! [`crate::invoke::invoke`], and of deletes, revokes (preempted at random
//! points and restarted), copies, moves, rotates and swaps through the
//! capability core, whose `finalise` and `moved` hooks call the paging code
//! as `arch` does. Nested CNodes carry mapped capabilities into Zombie
//! swaps. Dead objects are made again, as a retype after a reset would.
//!
//! A model of the mappings, plain maps from entries to what they hold,
//! predicts every invocation's result and flush, and follows the hooks.
//! After every step, preempted ones included, memory must equal the model
//! entry for entry, back-reference for back-reference and record for
//! record, and [`check`] must hold: L1 to L3, the tree shape, the entry
//! formats, and the TLB model, which cached every translation of the
//! loaded PML4 before the step and before every hook.

use std::collections::{BTreeMap, BTreeSet};
use std::format;
use std::string::String;
use std::vec::Vec;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config as ProptestConfig, TestRunner};

use super::paging::{
    self, Flush, FrameMapping, Link, PagingStore, TableMapping, USER_MIN, USER_TOP,
};
use super::testkit::*;
use super::{
    CacheType, PAGE_2M, PAGE_4K, UserAccess, index, label, user_pde_2m, user_pte, user_table,
};
use crate::cap::{Cap, CapType, FRAME_2M_BITS, Rights, low_mask};
use crate::cdt;
use crate::cnode;
use crate::error::{LookupFailure, SyscallError};
use crate::invoke::{InvokeError, Reply};
use crate::kernel::Kernel;
use crate::slot::{SlotAddr, SlotMemory};
use crate::testing::Event;

/// What a present entry holds, in the model.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Entry {
    Table(u64),
    Leaf {
        frame: u64,
        large: bool,
        write: bool,
        execute: bool,
        cache: CacheType,
    },
}

impl Entry {
    fn word(self) -> u64 {
        match self {
            Entry::Table(t) => user_table(t),
            Entry::Leaf {
                frame,
                large,
                write,
                execute,
                cache,
            } => {
                let access = UserAccess { write, execute };
                if large {
                    user_pde_2m(frame, access, cache)
                } else {
                    user_pte(frame, access, cache)
                }
            }
        }
    }
}

/// The mappings: every live structure's level and present entries, and
/// for each present entry the slot its back-reference names and the record
/// the capability there holds. Keyed by entry, not slot, so that the two
/// halves of a swap can be replayed one after the other.
#[derive(Clone, Debug, Default)]
struct Model {
    tables: BTreeMap<u64, (u32, BTreeMap<usize, Entry>)>,
    names: BTreeMap<(u64, usize), (SlotAddr, u64)>,
}

const fn missing(bits_left: u32) -> SyscallError {
    SyscallError::FailedLookup {
        source: false,
        failure: LookupFailure::MissingCapability { bits_left },
    }
}

/// The cache type and execute bit an attributes word gives a RAM or a
/// device frame, written out from `docs/abi.md`'s table.
fn model_attrs(word: u64, device: bool) -> Option<(CacheType, bool)> {
    match (word, device) {
        (0, false) => Some((CacheType::WriteBack, false)),
        (8, false) => Some((CacheType::WriteBack, true)),
        (3, true) => Some((CacheType::Uncached, false)),
        (11, true) => Some((CacheType::Uncached, true)),
        (4, true) => Some((CacheType::WriteCombining, false)),
        (12, true) => Some((CacheType::WriteCombining, true)),
        _ => None,
    }
}

/// Whether a mapping is writable: `None` if the rights lack Read.
fn model_write(cap: &Cap, word: u64) -> Option<bool> {
    let r = cap.rights().0 & (word & 3) as u8;
    (r & Rights::READ.0 != 0).then_some(r & Rights::WRITE.0 != 0)
}

impl Model {
    fn new(w: &World) -> Model {
        let mut m = Model::default();
        for (t, level) in live_structures(&w.k.mem) {
            m.tables.insert(t, (level, BTreeMap::new()));
        }
        m
    }

    fn map(&mut self, slot: SlotAddr, link: Link, entry: Entry, data: u64) {
        let (_, entries) = self.tables.get_mut(&link.table).expect("a live table");
        assert!(entries.insert(link.index, entry).is_none());
        let named = self.names.insert((link.table, link.index), (slot, data));
        assert!(named.is_none());
    }

    /// The entry the capability in `slot` installed, and its record.
    fn record_of(&self, slot: SlotAddr) -> Option<(u64, Link)> {
        self.names
            .iter()
            .find(|(_, (s, _))| *s == slot)
            .map(|(&(table, index), &(_, data))| (data, Link { table, index }))
    }

    /// Clears the entry at `link` and unmaps the capability it names.
    fn unmap(&mut self, link: Link) {
        self.names
            .remove(&(link.table, link.index))
            .expect("the model maps the entry");
        self.tables
            .get_mut(&link.table)
            .unwrap()
            .1
            .remove(&link.index);
    }

    /// Empties a structure; returns whether it held anything.
    fn empty(&mut self, t: u64) -> bool {
        let indices: Vec<usize> = self.tables[&t].1.keys().copied().collect();
        for &i in &indices {
            self.unmap(Link { table: t, index: i });
        }
        !indices.is_empty()
    }

    /// The base addresses of the structures of level `level` the PML4 at
    /// `pml4` reaches, by ascending address.
    fn bases(&self, pml4: u64, level: u32) -> Vec<u64> {
        let mut out = Vec::new();
        let mut todo = std::vec![(pml4, 3u32, 0u64)];
        while let Some((t, l, base)) = todo.pop() {
            if l == level {
                out.push(base);
                continue;
            }
            for (&i, e) in &self.tables[&t].1 {
                if let Entry::Table(next) = e {
                    todo.push((*next, l - 1, base | (i as u64) << (12 + 9 * l)));
                }
            }
        }
        out.sort_unstable();
        out
    }

    fn walk(&self, pml4: u64, vaddr: u64, holder: u32) -> Result<u64, SyscallError> {
        let mut t = pml4;
        for l in (holder + 1..=3).rev() {
            match self.tables[&t].1.get(&index(vaddr, l)) {
                Some(Entry::Table(next)) => t = *next,
                _ => return Err(missing(12 + 9 * l)),
            }
        }
        Ok(t)
    }

    /// The result and flush of invoking `cap`, in `slot`, with `label`,
    /// `mrs` and the extra capability `extra`; applies it to the model.
    fn predict(
        &mut self,
        slot: SlotAddr,
        cap: Cap,
        label: u64,
        mrs: &[u64],
        extra: Option<Cap>,
    ) -> Result<Flush, SyscallError> {
        use SyscallError::*;
        let ty = cap.cap_type();
        let (map, unmap, holder) = match ty {
            CapType::Pdpt => (label::PDPT_MAP, label::PDPT_UNMAP, 3),
            CapType::PageDirectory => (label::PAGE_DIRECTORY_MAP, label::PAGE_DIRECTORY_UNMAP, 2),
            CapType::PageTable => (label::PAGE_TABLE_MAP, label::PAGE_TABLE_UNMAP, 1),
            CapType::Frame if cap.size_bits() == FRAME_2M_BITS => {
                (label::FRAME_MAP, label::FRAME_UNMAP, 1)
            }
            CapType::Frame => (label::FRAME_MAP, label::FRAME_UNMAP, 0),
            _ => return Err(IllegalOperation),
        };
        let frame = ty == CapType::Frame;
        let mapped = self.record_of(slot);
        if label == map {
            let n = if frame { 3 } else { 1 };
            let vspace = match extra {
                Some(v) if mrs.len() >= n => v,
                _ => return Err(TruncatedMessage),
            };
            if vspace.cap_type() != CapType::Pml4 {
                return Err(InvalidCapability(1));
            }
            let vaddr = mrs[0];
            let entry = if frame {
                if mapped.is_some() {
                    return Err(InvalidCapability(0));
                }
                let size = 1u64 << cap.size_bits();
                if !vaddr.is_multiple_of(size) {
                    return Err(AlignmentError);
                }
                if vaddr < USER_MIN || vaddr > USER_TOP - size {
                    return Err(InvalidArgument(0));
                }
                let write = model_write(&cap, mrs[1]).ok_or(InvalidArgument(1))?;
                let (cache, execute) =
                    model_attrs(mrs[2], cap.is_device()).ok_or(InvalidArgument(2))?;
                Entry::Leaf {
                    frame: cap.object(),
                    large: holder == 1,
                    write,
                    execute,
                    cache,
                }
            } else {
                if mapped.is_some() || !self.tables[&cap.object()].1.is_empty() {
                    return Err(InvalidCapability(0));
                }
                if vaddr & !low_mask(12 + 9 * holder) >= USER_TOP {
                    return Err(InvalidArgument(0));
                }
                Entry::Table(cap.object())
            };
            let vaddr = if frame {
                vaddr
            } else {
                vaddr & !low_mask(12 + 9 * holder)
            };
            let table = self.walk(vspace.object(), vaddr, holder)?;
            let link = Link {
                table,
                index: index(vaddr, holder),
            };
            if self.tables[&table].1.contains_key(&link.index) {
                return Err(DeleteFirst);
            }
            let data = if frame {
                FrameMapping { table, vaddr }.encode()
            } else {
                TableMapping {
                    parent: table,
                    index: link.index,
                }
                .encode()
            };
            self.map(slot, link, entry, data);
            Ok(Flush::None)
        } else if label == unmap {
            if frame {
                Ok(match mapped {
                    Some((data, link)) => {
                        self.unmap(link);
                        Flush::Page(FrameMapping::decode(data).unwrap().vaddr)
                    }
                    None => Flush::None,
                })
            } else {
                let mut changed = false;
                if let Some((_, link)) = mapped {
                    self.unmap(link);
                    changed = true;
                }
                changed |= self.empty(cap.object());
                Ok(if changed { Flush::All } else { Flush::None })
            }
        } else if frame && label == label::FRAME_REMAP {
            if mrs.len() < 2 {
                return Err(TruncatedMessage);
            }
            let Some((data, link)) = mapped else {
                return Err(IllegalOperation);
            };
            let w = model_write(&cap, mrs[0]).ok_or(InvalidArgument(0))?;
            let (c, x) = model_attrs(mrs[1], cap.is_device()).ok_or(InvalidArgument(1))?;
            let e = self
                .tables
                .get_mut(&link.table)
                .unwrap()
                .1
                .get_mut(&link.index);
            let Some(Entry::Leaf {
                write,
                execute,
                cache,
                ..
            }) = e
            else {
                panic!("model: a mapped frame without a leaf");
            };
            (*write, *execute, *cache) = (w, x, c);
            Ok(Flush::Page(FrameMapping::decode(data).unwrap().vaddr))
        } else {
            Err(IllegalOperation)
        }
    }

    /// The `finalise` hook: what deleting `cap` does to the mappings.
    fn finalise(&mut self, cap: Cap, last: bool) {
        let unmap_own = |m: &mut Model| {
            if let Some(link) = paging::link_of(&cap) {
                let (_, data) = m.names[&(link.table, link.index)];
                assert_eq!(data, cap.data, "model: the record differs");
                m.unmap(link);
            }
        };
        match cap.cap_type() {
            CapType::Frame => unmap_own(self),
            CapType::Pdpt | CapType::PageDirectory | CapType::PageTable => {
                assert!(last, "a paging structure has one capability");
                unmap_own(self);
                self.empty(cap.object());
                self.tables.remove(&cap.object());
            }
            CapType::Pml4 if last => {
                self.empty(cap.object());
                self.tables.remove(&cap.object());
            }
            _ => {}
        }
    }

    /// The `moved` hook: the entry `cap` records now names `to`.
    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        if let Some(link) = paging::link_of(&cap) {
            let named = self
                .names
                .get_mut(&(link.table, link.index))
                .expect("model: a mapped capability moved from an entry it does not map");
            assert_eq!(*named, (from, cap.data), "model: moved from another slot");
            named.0 = to;
        }
    }

    /// Memory equals the model.
    fn compare(&self, k: &Space) -> Result<(), String> {
        let mem = &k.mem;
        let live = live_structures(mem);
        let modelled: BTreeMap<u64, u32> = self.tables.iter().map(|(t, (l, _))| (*t, *l)).collect();
        if live != modelled {
            return Err(format!("live structures {live:x?}, model {modelled:x?}"));
        }
        for (&t, (level, entries)) in &self.tables {
            let n = if *level == 3 { 256 } else { 512 };
            // Only entries one side holds can differ.
            let used = mem.used(t).into_iter().filter(|i| *i < n);
            for i in used.chain(entries.keys().copied()) {
                let (e, b) = (mem.entry(t, i), mem.backref(t, i));
                let want = match entries.get(&i) {
                    None => (0, 0),
                    Some(entry) => (entry.word(), self.names[&(t, i)].0.get() | 1),
                };
                if (e, b) != want {
                    return Err(format!(
                        "{t:#x}[{i}]: entry {e:#x}, backref {b:#x}; model {want:x?}"
                    ));
                }
            }
        }
        let named: BTreeSet<SlotAddr> = self.names.values().map(|(s, _)| *s).collect();
        if named.len() != self.names.len() {
            return Err(format!(
                "model: two entries name one slot: {:x?}",
                self.names
            ));
        }
        for s in all_slots() {
            let cap = mem.load(s).cap;
            let record = self.record_of(s).map(|r| r.0);
            if paging::holder_level(&cap).is_some() {
                if cap.data != record.unwrap_or(0) {
                    return Err(format!("slot {:#x}: {cap:x?}, model {record:x?}", s.get()));
                }
            } else if record.is_some() {
                return Err(format!("slot {:#x} holds {cap:x?}, model mapped", s.get()));
            }
        }
        Ok(())
    }
}

/// One step. Indices pick among what exists when the step runs.
#[derive(Clone, Debug)]
enum Op {
    /// An invocation of a Frame or paging-structure capability.
    Invoke {
        slot: u8,
        label: u8,
        vspace: u8,
        /// Below 200: an address under a structure the VSpace has at the
        /// right level, entry `aim % 5` of [`AIMS`]; else `vaddr`.
        aim: u8,
        vaddr: u64,
        /// Below 240: rights and attributes the frame may have.
        rights: u8,
        attrs: u8,
        /// Below 5: one register short; 5 to 8: no extra capability.
        cut: u8,
    },
    Delete {
        slot: u8,
        preempt: Option<u8>,
        /// Delete a CNode capability, if there is one.
        container: bool,
    },
    Revoke {
        slot: u8,
        preempt: Option<u8>,
    },
    Copy {
        src: u8,
        dst: u8,
        rights: u8,
    },
    Move {
        src: u8,
        dst: u8,
    },
    Rotate {
        dst: u8,
        pivot: u8,
        src: u8,
        swap: bool,
    },
    /// Makes a dead object again, as a retype after a reset would.
    Recreate {
        object: u8,
        dst: u8,
    },
    /// Deletes everything in a CNode no lookup reaches, as a revoke of its
    /// untyped would.
    Reap,
    /// Loads a PML4, or the kernel's.
    Load {
        pml4: u8,
    },
}

/// Addresses near every index and bound the paging code has.
fn vaddr() -> impl Strategy<Value = u64> {
    let near = (
        prop::sample::select(&[0u64, 1, 255][..]),
        prop::sample::select(&[0u64, 1, 511][..]),
        prop::sample::select(&[0u64, 1, 2, 511][..]),
        prop::sample::select(&[0u64, 1, 2, 511][..]),
    )
        .prop_map(|(a, b, c, d)| a << 39 | b << 30 | c << 21 | d << 12);
    let edges = prop::sample::select(
        &[
            0,
            USER_MIN,
            USER_TOP - PAGE_4K,
            USER_TOP,
            (USER_TOP - PAGE_2M) & !(PAGE_2M - 1),
            1 << 47,
            u64::MAX,
            0x40_0800,
            0x60_1000,
        ][..],
    );
    prop_oneof![6 => near, 1 => edges]
}

/// Entry indices an aimed address uses at the level it maps.
const AIMS: [u64; 5] = [0, 1, 2, 255, 511];

/// Rights words: valid ones (with Read), then ones without Read.
const RIGHTS: ([u64; 5], [u64; 3]) = ([3, 3, 2, 0xF, 0x102], [0, 1, 4]);
/// Attribute words for RAM and for device frames, then invalid ones.
const RAM_ATTRS: [u64; 2] = [0, 8];
const DEVICE_ATTRS: [u64; 4] = [3, 4, 11, 12];
const BAD_ATTRS: [u64; 4] = [1, 0x10, 7, 1 << 63];

fn op() -> impl Strategy<Value = Op> {
    let preempt = prop::option::weighted(0.5, 0u8..8);
    let invoke = (
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        vaddr(),
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
    );
    prop_oneof![
        14 => invoke.prop_map(
            |(slot, label, vspace, aim, vaddr, rights, attrs, cut)| Op::Invoke {
                slot,
                label,
                vspace,
                aim,
                vaddr,
                rights,
                attrs,
                cut,
            }
        ),
        2 => (any::<u8>(), preempt.clone(), any::<bool>())
            .prop_map(|(slot, preempt, container)| Op::Delete { slot, preempt, container }),
        1 => (any::<u8>(), preempt).prop_map(|(slot, preempt)| Op::Revoke { slot, preempt }),
        2 => (any::<u8>(), any::<u8>(), any::<u8>()).prop_map(|(src, dst, rights)| Op::Copy {
            src,
            dst,
            rights
        }),
        2 => (any::<u8>(), any::<u8>()).prop_map(|(src, dst)| Op::Move { src, dst }),
        2 => (any::<u8>(), any::<u8>(), any::<u8>(), any::<bool>())
            .prop_map(|(dst, pivot, src, swap)| Op::Rotate { dst, pivot, src, swap }),
        1 => (any::<u8>(), any::<u8>()).prop_map(|(object, dst)| Op::Recreate { object, dst }),
        1 => Just(Op::Reap),
        1 => any::<u8>().prop_map(|pml4| Op::Load { pml4 }),
    ]
}

/// What a run did, for the coverage test.
#[derive(Clone, Copy, Debug, Default)]
struct Tally {
    maps: u64,
    unmaps_that_flushed: u64,
    remaps: u64,
    errors: u64,
    finalised_mapped: u64,
    moved_mapped: u64,
    preempted: u64,
    recreated: u64,
    loaded_flushes: u64,
}

struct Run {
    w: World,
    model: Model,
    tally: Tally,
}

/// The slots a lookup could reach: the root CNode's, and those of every
/// CNode a reachable slot holds a CNode capability to.
fn reachable(mem: &Store) -> Vec<SlotAddr> {
    let mut out: Vec<SlotAddr> = (0..1 << ROOT_RADIX).map(rs).collect();
    let mut seen = BTreeSet::new();
    let mut i = 0;
    while i < out.len() {
        let cap = mem.load(out[i]).cap;
        if cap.cap_type() == CapType::CNode && seen.insert(cap.object()) {
            out.extend((0..1u64 << cap.radix()).map(|j| sa(cap.object() + 32 * j)));
        }
        i += 1;
    }
    out
}

fn pick<T: Copy>(v: &[T], i: u8) -> Option<T> {
    (!v.is_empty()).then(|| v[i as usize % v.len()])
}

/// The objects the world started with, for [`Op::Recreate`].
fn objects() -> Vec<Cap> {
    initial_caps()
        .into_iter()
        .map(|(_, c)| c)
        .filter(|c| c.cap_type() != CapType::Endpoint)
        .collect()
}

impl Run {
    /// The world with a page table under each PML4, so that frames can map
    /// from the first step: PDPT0, PD0 and PT0 under PML4 A over
    /// `0x40_0000`, PDPT1, PD1 and PT1 under PML4 B over `0x7F_FFE0_0000`.
    fn new() -> Run {
        let w = World::new();
        let model = Model::new(&w);
        let mut run = Run {
            w,
            model,
            tally: Tally::default(),
        };
        let start = Op::Reap;
        for (pml4, at, tables) in [
            (PML4_A, 0x40_0000, [PDPT0, PD0, PT0]),
            (PML4_B, 0x7F_FFE0_0000, [PDPT1, PD1, PT1]),
        ] {
            let labels = [
                label::PDPT_MAP,
                label::PAGE_DIRECTORY_MAP,
                label::PAGE_TABLE_MAP,
            ];
            for (t, l) in tables.into_iter().zip(labels) {
                run.invoke(&start, rs(t), l, &[at], &[rs(pml4)]);
            }
        }
        run.tally = Tally::default();
        run
    }

    /// Invokes the capability in `slot`, which the model predicts first:
    /// result, flush and memory must agree, and a failure changes nothing.
    fn invoke(&mut self, op: &Op, slot: SlotAddr, l: u64, mrs: &[u64], extra: &[SlotAddr]) {
        let cap = self.mem().load(slot).cap;
        let extra_cap = extra.first().map(|s| self.mem().load(*s).cap);
        let want = self.model.predict(slot, cap, l, mrs, extra_cap);
        let before = self.mem().clone();
        let got = self.w.call(slot, l, mrs, extra);
        match (want, got) {
            (Ok(flush), Ok(Reply { length: 0 })) => {
                assert_eq!(self.w.k.flushes, [flush], "after {op:x?}");
                let is_map = matches!(
                    l,
                    label::PDPT_MAP
                        | label::PAGE_DIRECTORY_MAP
                        | label::PAGE_TABLE_MAP
                        | label::FRAME_MAP
                );
                match flush {
                    _ if is_map => self.tally.maps += 1,
                    Flush::Page(_) if l == label::FRAME_REMAP => self.tally.remaps += 1,
                    Flush::Page(_) | Flush::All => self.tally.unmaps_that_flushed += 1,
                    Flush::None => {}
                }
                if self.w.k.loaded.is_some() && flush != Flush::None {
                    self.tally.loaded_flushes += 1;
                }
            }
            (Err(e), Err(InvokeError::Error(g))) if e == g => {
                assert!(*self.mem() == before, "a failed {op:x?} changed memory");
                assert!(self.w.k.flushes.is_empty());
                self.tally.errors += 1;
            }
            (want, got) => panic!("{op:x?} on {cap:x?}: model {want:?}, got {got:?}"),
        }
        assert!(self.w.k.events.is_empty(), "an invocation called a hook");
        self.settle(op);
    }

    fn mem(&self) -> &Store {
        &self.w.k.mem
    }

    fn slots_where(&self, f: impl Fn(&Cap) -> bool) -> Vec<SlotAddr> {
        reachable(self.mem())
            .into_iter()
            .filter(|s| f(&self.mem().load(*s).cap))
            .collect()
    }

    /// Replays the hooks into the model, then checks everything.
    fn settle(&mut self, what: &Op) {
        for e in core::mem::take(&mut self.w.k.events) {
            match e {
                Event::Finalise { cap, last } => {
                    if paging::link_of(&cap).is_some() {
                        self.tally.finalised_mapped += 1;
                    }
                    self.model.finalise(cap, last)
                }
                Event::Moved { cap, from, to } => {
                    if paging::link_of(&cap).is_some() {
                        self.tally.moved_mapped += 1;
                    }
                    self.model.moved(cap, from, to)
                }
                _ => {}
            }
        }
        if let Err(e) = self
            .model
            .compare(&self.w.k)
            .and_then(|()| check(&self.w.k))
        {
            panic!("after {what:x?}: {e}");
        }
    }

    /// Runs a preemptible operation on `slot` until it finishes, settling
    /// after every attempt, or until `slot` can no longer be looked up.
    fn restartable(
        &mut self,
        what: &Op,
        slot: SlotAddr,
        preempt: Option<u8>,
        f: fn(&mut Space, SlotAddr) -> Result<(), crate::kernel::Preempted>,
    ) {
        self.w.k.preempt_in = preempt.map(u64::from);
        loop {
            self.w.k.fill_tlb();
            let done = f(&mut self.w.k, slot).is_ok();
            self.settle(what);
            if done {
                break;
            }
            self.tally.preempted += 1;
            if !reachable(self.mem()).contains(&slot) {
                break;
            }
        }
        self.w.k.preempt_in = None;
    }

    fn step(&mut self, op: &Op) {
        let any = |c: &Cap| !c.is_null();
        let empty = |c: &Cap| c.is_null();
        match *op {
            Op::Invoke {
                slot,
                label,
                vspace,
                aim,
                vaddr,
                rights,
                attrs,
                cut,
            } => {
                // A PML4, which has no invocations, only now and then.
                let paging = |c: &Cap| {
                    paging::holder_level(c).is_some()
                        || (label >= 240 && c.cap_type() == CapType::Pml4)
                };
                let Some(slot) = pick(&self.slots_where(paging), slot) else {
                    return;
                };
                let cap = self.mem().load(slot).cap;
                let labels: &[u64] = match cap.cap_type() {
                    CapType::Frame => &[label::FRAME_MAP, label::FRAME_UNMAP, label::FRAME_REMAP],
                    CapType::Pdpt => &[label::PDPT_MAP, label::PDPT_UNMAP],
                    CapType::PageDirectory => {
                        &[label::PAGE_DIRECTORY_MAP, label::PAGE_DIRECTORY_UNMAP]
                    }
                    _ => &[label::PAGE_TABLE_MAP, label::PAGE_TABLE_UNMAP],
                };
                let others = [
                    0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x50, 0x51, 0x52, 0x53, 0x46,
                ];
                let l = if label >= 240 {
                    pick(&others, label).unwrap()
                } else {
                    // Map twice as often as the rest.
                    let l = label as usize % (labels.len() + 1);
                    labels[l.saturating_sub(1)]
                };
                // Aimed: a VSpace that has a structure where this one maps.
                let holder = paging::holder_level(&cap);
                let pml4s = self.slots_where(|c| c.cap_type() == CapType::Pml4);
                let ready: Vec<SlotAddr> = pml4s
                    .iter()
                    .copied()
                    .filter(|s| {
                        let pml4 = self.mem().load(*s).cap.object();
                        holder.is_some_and(|h| !self.model.bases(pml4, h).is_empty())
                    })
                    .collect();
                let vs = if aim < 200 && !ready.is_empty() {
                    pick(&ready, vspace).unwrap()
                } else if vspace % 16 != 15 && !pml4s.is_empty() {
                    pick(&pml4s, vspace).unwrap()
                } else {
                    pick(&reachable(self.mem()), vspace).unwrap()
                };
                let root = self.mem().load(vs).cap;
                let vaddr = match holder {
                    Some(holder) if aim < 200 && root.cap_type() == CapType::Pml4 => {
                        let bases = self.model.bases(root.object(), holder);
                        match pick(&bases, aim / 5) {
                            Some(base) => base | AIMS[aim as usize % 5] << (12 + 9 * holder),
                            None => vaddr,
                        }
                    }
                    _ => vaddr,
                };
                let rights = if rights < 240 {
                    pick(&RIGHTS.0, rights).unwrap()
                } else {
                    pick(&RIGHTS.1, rights).unwrap()
                };
                let attrs = match attrs {
                    0..240 if cap.is_device() => pick(&DEVICE_ATTRS, attrs).unwrap(),
                    0..240 => pick(&RAM_ATTRS, attrs).unwrap(),
                    _ => pick(&BAD_ATTRS, attrs).unwrap(),
                };
                let mut mrs: Vec<u64> = match l {
                    label::FRAME_MAP => std::vec![vaddr, rights, attrs],
                    label::FRAME_REMAP => std::vec![rights, attrs],
                    _ => std::vec![vaddr],
                };
                let mut extra = std::vec![vs];
                match cut {
                    0..=4 => {
                        mrs.pop();
                    }
                    5..=8 => extra.clear(),
                    _ => {}
                }
                self.invoke(op, slot, l, &mrs, &extra);
            }
            Op::Delete {
                slot,
                preempt,
                container,
            } => {
                let cnodes = self.slots_where(|c| c.cap_type() == CapType::CNode);
                let from = if container && !cnodes.is_empty() {
                    cnodes
                } else {
                    self.slots_where(any)
                };
                let Some(slot) = pick(&from, slot) else {
                    return;
                };
                self.restartable(op, slot, preempt, cnode::delete);
            }
            Op::Revoke { slot, preempt } => {
                // Revoke something with children, if anything has.
                let roots: Vec<SlotAddr> = (0..1 << ROOT_RADIX)
                    .map(rs)
                    .filter(|s| any(&self.mem().load(*s).cap))
                    .collect();
                let parents: Vec<SlotAddr> = roots
                    .iter()
                    .copied()
                    .filter(|s| cdt::has_children(self.mem(), *s))
                    .collect();
                let roots = if parents.is_empty() { roots } else { parents };
                let Some(slot) = pick(&roots, slot) else {
                    return;
                };
                self.restartable(op, slot, preempt, cnode::revoke);
            }
            Op::Copy { src, dst, rights } => {
                let (Some(s), Some(d)) = (
                    pick(&self.slots_where(any), src),
                    pick(&self.slots_where(empty), dst),
                ) else {
                    return;
                };
                self.w.k.fill_tlb();
                let _ = cnode::copy(&mut self.w.k, s, d, u64::from(rights));
                self.settle(op);
            }
            Op::Move { src, dst } => {
                let (Some(s), Some(d)) = (
                    pick(&self.slots_where(any), src),
                    pick(&self.slots_where(empty), dst),
                ) else {
                    return;
                };
                self.w.k.fill_tlb();
                let _ = cnode::move_cap(&mut self.w.k, s, d);
                self.settle(op);
            }
            Op::Rotate {
                dst,
                pivot,
                src,
                swap,
            } => {
                let full = self.slots_where(any);
                let (Some(s), Some(p)) = (pick(&full, src), pick(&full, pivot)) else {
                    return;
                };
                let d = if swap {
                    s
                } else {
                    match pick(&self.slots_where(empty), dst) {
                        Some(d) => d,
                        None => return,
                    }
                };
                self.w.k.fill_tlb();
                let _ = cnode::rotate(&mut self.w.k, d, 0, p, 0, s);
                self.settle(op);
            }
            Op::Recreate { object, dst } => self.recreate(op, object, dst),
            Op::Reap => self.reap(op),
            Op::Load { pml4 } => {
                let live: Vec<u64> = live_structures(self.mem())
                    .into_iter()
                    .filter(|(_, l)| *l == 3)
                    .map(|(t, _)| t)
                    .collect();
                let root = if pml4 % 4 == 3 {
                    None
                } else {
                    pick(&live, pml4)
                };
                self.w.k.set_root(root);
                self.settle(op);
            }
        }
    }

    /// Whether any slot holds a capability to the object `cap` names (a
    /// Zombie names the container it destroys).
    fn alive(&self, cap: &Cap) -> bool {
        all_slots().into_iter().any(|s| {
            let c = self.mem().load(s).cap;
            c.object() == cap.object()
                && (c.cap_type() == cap.cap_type()
                    || (c.cap_type() == CapType::Zombie && cap.cap_type() == CapType::CNode))
        })
    }

    fn recreate(&mut self, op: &Op, object: u8, dst: u8) {
        let all = objects();
        let cap = all[object as usize % all.len()];
        if self.alive(&cap) {
            return;
        }
        let slots: Vec<SlotAddr> = (0..1u64 << cap.radix())
            .map(|j| sa(cap.object() + 32 * j))
            .collect();
        if cap.cap_type() == CapType::CNode
            && slots.iter().any(|s| !self.mem().load(*s).cap.is_null())
        {
            return;
        }
        let roots: Vec<SlotAddr> = (0..1 << ROOT_RADIX)
            .map(rs)
            .filter(|s| self.mem().load(*s).cap.is_null())
            .collect();
        let Some(at) = pick(&roots, dst) else {
            return;
        };
        let k = &mut self.w.k;
        match cap.cap_type() {
            CapType::Frame => {}
            CapType::CNode => k.zero(cap.object(), 32 << cap.radix()),
            _ => {
                k.zero(cap.object(), 1 << cap.size_bits());
                k.init_object(cap);
                let level = paging::structure_level(cap.cap_type()).unwrap();
                self.model
                    .tables
                    .insert(cap.object(), (level, BTreeMap::new()));
            }
        }
        cdt::insert_root(&mut self.w.k, at, cap);
        self.tally.recreated += 1;
        self.settle(op);
    }

    fn reap(&mut self, op: &Op) {
        for _ in 0..64 {
            let reach = reachable(self.mem());
            let stuck: Vec<SlotAddr> = [C0, C1]
                .into_iter()
                .flat_map(|c| (0..1 << SUB_RADIX).map(move |i| cs(c, i)))
                .filter(|s| !reach.contains(s) && !self.mem().load(*s).cap.is_null())
                .collect();
            // Zombies first: deleting one clears its whole container.
            let zombie = stuck
                .iter()
                .copied()
                .find(|s| self.mem().load(*s).cap.cap_type() == CapType::Zombie);
            let Some(slot) = zombie.or(stuck.first().copied()) else {
                return;
            };
            self.w.k.fill_tlb();
            while cnode::delete(&mut self.w.k, slot).is_err() {}
            self.settle(op);
        }
        panic!("reaping did not end");
    }
}

fn config() -> ProptestConfig {
    ProptestConfig {
        // Under Miri every step takes seconds: the paging code scans 512
        // back-references for each table it maps or empties.
        cases: if cfg!(miri) { 1 } else { 512 },
        // No files: Miri forbids them.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Steps in one sequence.
const STEPS: usize = if cfg!(miri) { 12 } else { 120 };

proptest! {
    #![proptest_config(config())]

    #[test]
    fn random_sequences_keep_the_links_the_model_and_the_tlb(
        ops in prop::collection::vec(op(), 1..STEPS)
    ) {
        let mut run = Run::new();
        for op in &ops {
            run.step(op);
        }
    }
}

/// The random sequences reach what they are meant to: successful maps,
/// remaps and flushing unmaps with the PML4 loaded, deletes and moves of
/// mapped capabilities, preempted deletes and revokes, and objects made
/// again.
#[test]
#[cfg_attr(
    miri,
    ignore = "forty sequences take an hour under Miri; the proptest runs"
)]
fn the_random_sequences_cover_every_path() {
    let mut runner = TestRunner::deterministic();
    let mut total = Tally::default();
    let sequences = 40;
    for _ in 0..sequences {
        let ops = prop::collection::vec(op(), STEPS)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let mut run = Run::new();
        for op in &ops {
            run.step(op);
        }
        let t = run.tally;
        total.maps += t.maps;
        total.unmaps_that_flushed += t.unmaps_that_flushed;
        total.remaps += t.remaps;
        total.errors += t.errors;
        total.finalised_mapped += t.finalised_mapped;
        total.moved_mapped += t.moved_mapped;
        total.preempted += t.preempted;
        total.recreated += t.recreated;
        total.loaded_flushes += t.loaded_flushes;
    }
    std::println!("{total:?}");
    let Tally {
        maps,
        unmaps_that_flushed,
        remaps,
        errors,
        finalised_mapped,
        moved_mapped,
        preempted,
        recreated,
        loaded_flushes,
    } = total;
    for (what, n) in [
        ("maps", maps),
        ("unmaps that flushed", unmaps_that_flushed),
        ("remaps", remaps),
        ("errors", errors),
        ("deletions of mapped capabilities", finalised_mapped),
        ("moves of mapped capabilities", moved_mapped),
        ("preemptions", preempted),
        ("objects made again", recreated),
        ("flushes with the PML4 loaded", loaded_flushes),
    ] {
        assert!(n >= 10, "only {n} {what}: {total:?}");
    }
}
