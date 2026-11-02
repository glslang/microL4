//! A test world for the paging code: a [`Kernel`] over fake memory whose
//! hooks call `vspace` as `arch` will, a TLB model, and the checks of L1 to
//! L3, the tree shape and the leaf rules, made from memory alone.
//!
//! The TLB model is the worst case the SDM allows [H13]: before every step
//! and every hook it caches every translation and every non-leaf entry
//! reachable from the loaded PML4, and it drops them only as the flushes
//! the paging code returns say [H4, H5]. After a step, every cached
//! translation must still agree with the tables.

use std::collections::{BTreeMap, BTreeSet};
use std::format;
use std::string::String;
use std::vec::Vec;

use super::paging::{self, Flush, PagingStore};
use super::{
    ADDR_4K, CacheType, G, P, PAGE_2M, PAGE_4K, PS, RW, Table, Translation, US, index, user_table,
};
use crate::cap::{Cap, CapType, FRAME_2M_BITS, FRAME_4K_BITS, PAGING_STRUCTURE_BITS, Rights};
use crate::cdt;
use crate::invoke::{self, ExtraCap, InvokeError, Message, Reply};
use crate::kernel::{Kernel, Preempted};
use crate::slot::{Slot, SlotAddr, SlotMemory};
use crate::testing::{Event, FakeMemory};

/// Fake physical memory: the CNodes' slots in one small [`FakeMemory`],
/// and the paging structures as a map of their non-zero words. Under Miri
/// a read through a `Vec` retags the whole buffer, so one `FakeMemory`
/// over every structure made each read as slow as the structures are big;
/// and the checks visit only the words that are not zero.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Store {
    slots: FakeMemory,
    words: BTreeMap<(u64, usize), u64>,
}

impl Store {
    fn new() -> Store {
        Store {
            slots: FakeMemory::new(BASE, SLOTS_END - BASE),
            words: BTreeMap::new(),
        }
    }

    /// Panics unless `table` is one of the world's paging structures.
    fn structure_index(table: u64) -> u64 {
        let n = table.wrapping_sub(structure(0)) / 0x2000;
        assert!(
            table.is_multiple_of(0x2000) && table >= structure(0) && n < STRUCTURES,
            "no paging structure at {table:#x}"
        );
        n
    }

    /// Writes zeros to a whole paging structure, or to slot memory.
    pub fn zero(&mut self, paddr: u64, len: u64) {
        if paddr >= structure(0) {
            Store::structure_index(paddr);
            assert_eq!(len, 0x2000, "a paging structure is zeroed whole");
            self.words.retain(|(t, _), _| *t != paddr);
        } else {
            self.slots.zero(paddr, len)
        }
    }

    fn word(&self, table: u64, i: usize) -> u64 {
        Store::structure_index(table);
        assert!(i < 1024);
        self.words.get(&(table, i)).copied().unwrap_or(0)
    }

    fn set_word(&mut self, table: u64, i: usize, w: u64) {
        Store::structure_index(table);
        assert!(i < 1024);
        if w == 0 {
            self.words.remove(&(table, i));
        } else {
            self.words.insert((table, i), w);
        }
    }

    /// The entries of `table` whose entry or back-reference is not zero.
    pub fn used(&self, table: u64) -> BTreeSet<usize> {
        self.words
            .range((table, 0)..(table, 1024))
            .map(|((_, i), _)| i % 512)
            .collect()
    }
}

impl SlotMemory for Store {
    fn load(&self, at: SlotAddr) -> Slot {
        self.slots.load(at)
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        self.slots.store(at, slot)
    }
}

impl PagingStore for Store {
    fn entry(&self, table: u64, i: usize) -> u64 {
        assert!(i < 512);
        self.word(table, i)
    }

    fn set_entry(&mut self, table: u64, i: usize, entry: u64) {
        assert!(i < 512);
        self.set_word(table, i, entry)
    }

    fn backref(&self, table: u64, i: usize) -> u64 {
        assert!(i < 512);
        self.word(table, 512 + i)
    }

    fn set_backref(&mut self, table: u64, i: usize, backref: u64) {
        assert!(i < 512);
        self.set_word(table, 512 + i, backref)
    }

    fn flush(&mut self, _: Flush) {}
}

/// Fake memory: the CNodes, then the paging structures.
pub const BASE: u64 = 0x10_0000;
/// The end of slot memory.
pub const SLOTS_END: u64 = BASE + 0x900;
pub const ROOT: u64 = BASE;
pub const ROOT_RADIX: u32 = 6;
/// Two small CNodes, radix 2.
pub const C0: u64 = BASE + 0x800;
pub const C1: u64 = BASE + 0x880;
pub const SUB_RADIX: u32 = 2;
/// Paging structure `n`, 8 KiB each.
pub const fn structure(n: u64) -> u64 {
    BASE + 0x2000 * (n + 1)
}
pub const STRUCTURES: u64 = 9;

/// Frames lie outside fake memory: nothing reads or writes them.
pub const RAM_4K: u64 = 0x4000_0000;
pub const DEV_4K: u64 = 0xFEB0_0000;
pub const RAM_2M: u64 = 0x8000_0000;
pub const DEV_2M: u64 = 0xC000_0000;

/// The kernel PML4's half, as `init_object` copies it.
pub fn kernel_pml4() -> Table {
    let mut t = [0; 512];
    t[256] = 0x0123_4000 | P | RW;
    t[511] = 0x0567_8000 | P | RW;
    t
}

/// Root CNode slots of the world's objects.
pub const PML4_A: u64 = 1;
pub const PML4_B: u64 = 2;
pub const PDPT0: u64 = 3;
pub const PDPT1: u64 = 4;
pub const PD0: u64 = 5;
pub const PD1: u64 = 6;
pub const PT0: u64 = 7;
pub const PT1: u64 = 8;
pub const PT2: u64 = 9;
/// Four 4 KiB RAM frames, read-write.
pub const F0: u64 = 10;
/// A 4 KiB device frame.
pub const DF: u64 = 14;
/// Two 2 MiB RAM frames.
pub const G0: u64 = 15;
pub const G1: u64 = 16;
/// A 2 MiB device frame.
pub const DG: u64 = 17;
/// A read-only 4 KiB RAM frame.
pub const FR: u64 = 18;
/// The two small CNodes.
pub const SC0: u64 = 20;
pub const SC1: u64 = 21;
/// An endpoint.
pub const EP: u64 = 30;
/// The first slot the world leaves empty.
pub const FREE: u64 = 32;

pub const RW_RIGHTS: Rights = Rights(Rights::READ.0 | Rights::WRITE.0);

pub fn sa(a: u64) -> SlotAddr {
    SlotAddr::new(a).unwrap()
}

/// Root CNode slot `i`.
pub fn rs(i: u64) -> SlotAddr {
    sa(ROOT + 32 * i)
}

/// Slot `i` of the small CNode at `cnode`.
pub fn cs(cnode: u64, i: u64) -> SlotAddr {
    sa(cnode + 32 * i)
}

pub fn frame(paddr: u64, bits: u32, rights: Rights, device: bool) -> Cap {
    Cap::new(CapType::Frame, paddr, bits, rights, device, 0)
}

pub fn structure_cap(ty: CapType, paddr: u64) -> Cap {
    Cap::new(ty, paddr, PAGING_STRUCTURE_BITS, Rights::NONE, false, 0)
}

/// The world's capabilities, by root slot, as boot or retype makes them.
pub fn initial_caps() -> Vec<(u64, Cap)> {
    let mut caps = std::vec![
        (PML4_A, structure_cap(CapType::Pml4, structure(0))),
        (PML4_B, structure_cap(CapType::Pml4, structure(1))),
        (PDPT0, structure_cap(CapType::Pdpt, structure(2))),
        (PDPT1, structure_cap(CapType::Pdpt, structure(3))),
        (PD0, structure_cap(CapType::PageDirectory, structure(4))),
        (PD1, structure_cap(CapType::PageDirectory, structure(5))),
        (PT0, structure_cap(CapType::PageTable, structure(6))),
        (PT1, structure_cap(CapType::PageTable, structure(7))),
        (PT2, structure_cap(CapType::PageTable, structure(8))),
        (DF, frame(DEV_4K, FRAME_4K_BITS, RW_RIGHTS, true)),
        (G0, frame(RAM_2M, FRAME_2M_BITS, RW_RIGHTS, false)),
        (G1, frame(RAM_2M + PAGE_2M, FRAME_2M_BITS, RW_RIGHTS, false)),
        (DG, frame(DEV_2M, FRAME_2M_BITS, RW_RIGHTS, true)),
        (
            FR,
            frame(RAM_4K + 4 * PAGE_4K, FRAME_4K_BITS, Rights::READ, false)
        ),
        (SC0, Cap::cnode(C0, SUB_RADIX, 0, 0)),
        (SC1, Cap::cnode(C1, SUB_RADIX, 0, 0)),
        (
            EP,
            Cap::new(CapType::Endpoint, BASE + 0x1000, 5, Rights::ALL, false, 0),
        ),
    ];
    for i in 0..4 {
        caps.push((
            F0 + i,
            frame(RAM_4K + i * PAGE_4K, FRAME_4K_BITS, RW_RIGHTS, false),
        ));
    }
    caps
}

/// Every slot in fake memory: the root CNode's and both small CNodes'.
pub fn all_slots() -> Vec<SlotAddr> {
    let mut v: Vec<SlotAddr> = (0..1 << ROOT_RADIX).map(rs).collect();
    for c in [C0, C1] {
        v.extend((0..1 << SUB_RADIX).map(|i| cs(c, i)));
    }
    v
}

/// What the TLB holds: leaf translations by (page base, size), and cached
/// non-leaf entries by (level, base of the range the entry covers).
#[derive(Clone, Debug, Default)]
pub struct Tlb {
    pub leaves: BTreeMap<(u64, u64), Translation>,
    pub walks: BTreeMap<(u32, u64), u64>,
}

impl Tlb {
    fn apply(&mut self, flush: Flush) {
        match flush {
            Flush::None => {}
            Flush::Page(v) => {
                self.leaves.retain(|(b, s), _| !(*b <= v && v < b + s));
                // `invlpg` drops every paging-structure-cache entry [H5].
                self.walks.clear();
            }
            Flush::All => self.clear(),
        }
    }

    fn clear(&mut self) {
        self.leaves.clear();
        self.walks.clear();
    }
}

/// A [`Kernel`] over fake memory whose hooks call the paging code as
/// `arch` does, applying each flush at once, with a CR3 and a TLB.
#[derive(Clone, Debug)]
pub struct Space {
    pub mem: Store,
    /// The PML4 in CR3; `None` for the kernel PML4.
    pub loaded: Option<u64>,
    pub tlb: Tlb,
    /// Every flush applied, in order.
    pub flushes: Vec<Flush>,
    /// The `finalise` and `moved` calls, in order.
    pub events: Vec<Event>,
    /// As `TestKernel::preempt_in`.
    pub preempt_in: Option<u64>,
}

impl Space {
    pub fn new() -> Space {
        Space {
            mem: Store::new(),
            loaded: None,
            tlb: Tlb::default(),
            flushes: Vec::new(),
            events: Vec::new(),
            preempt_in: None,
        }
    }

    /// The CPU may cache anything present, at any time [H13].
    pub fn fill_tlb(&mut self) {
        if let Some(pml4) = self.loaded {
            fill_leaves(&mut self.tlb, &self.mem, pml4);
        }
    }

    /// `arch::paging::apply`.
    pub fn apply(&mut self, flush: Flush) {
        self.flushes.push(flush);
        self.tlb.apply(flush);
    }

    /// `arch::paging::set_vm_root`: a CR3 write when the root changes,
    /// which drops every user translation [H4].
    pub fn set_root(&mut self, pml4: Option<u64>) {
        if self.loaded != pml4 {
            self.loaded = pml4;
            self.tlb.clear();
        }
    }
}

/// Caches every leaf and non-leaf entry reachable from `pml4`.
fn fill_leaves(tlb: &mut Tlb, mem: &Store, pml4: u64) {
    fn walk(tlb: &mut Tlb, mem: &Store, pml4: u64, table: u64, level: u32, base: u64) {
        let n = if level == 3 { 256 } else { 512 };
        for i in mem.used(table).into_iter().filter(|i| *i < n) {
            let e = mem.entry(table, i);
            if e & P == 0 {
                continue;
            }
            let at = base | (i as u64) << (12 + 9 * level);
            if level == 0 || (level == 1 && e & PS != 0) {
                let t = paging::translate(mem, pml4, at).expect("a present leaf translates");
                tlb.leaves.entry((at, t.page_size)).or_insert(t);
            } else {
                tlb.walks.entry((level, at)).or_insert(e & ADDR_4K);
                walk(tlb, mem, pml4, e & ADDR_4K, level - 1, at);
            }
        }
    }
    walk(tlb, mem, pml4, pml4, 3, 0);
}

impl SlotMemory for Space {
    fn load(&self, at: SlotAddr) -> Slot {
        self.mem.load(at)
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        self.mem.store(at, slot)
    }
}

impl PagingStore for Space {
    fn entry(&self, table: u64, i: usize) -> u64 {
        self.mem.entry(table, i)
    }

    fn set_entry(&mut self, table: u64, i: usize, entry: u64) {
        self.mem.set_entry(table, i, entry)
    }

    fn backref(&self, table: u64, i: usize) -> u64 {
        self.mem.backref(table, i)
    }

    fn set_backref(&mut self, table: u64, i: usize, backref: u64) {
        self.mem.set_backref(table, i, backref)
    }

    fn flush(&mut self, flush: Flush) {
        self.apply(flush)
    }
}

impl Kernel for Space {
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
        self.events.push(Event::Finalise { cap, last });
        self.fill_tlb();
        // PML4 finalisation loads the kernel PML4 first if CR3 holds it.
        if cap.cap_type() == CapType::Pml4 && last && self.loaded == Some(cap.object()) {
            self.set_root(None);
        }
        let flush = paging::finalise(self, cap, last);
        self.apply(flush);
        None
    }

    fn after_delete(&mut self, _: Cap) {}

    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        self.events.push(Event::Moved { cap, from, to });
        self.fill_tlb();
        let flush = paging::moved(self, cap, from, to);
        self.apply(flush);
    }

    fn zero(&mut self, paddr: u64, len: u64) {
        self.mem.zero(paddr, len)
    }

    fn init_object(&mut self, cap: Cap) {
        if cap.cap_type() == CapType::Pml4 {
            paging::init_pml4(self, cap.object(), &kernel_pml4());
        }
    }

    fn preempt(&mut self) -> Result<(), Preempted> {
        match self.preempt_in {
            Some(0) => {
                self.preempt_in = None;
                Err(Preempted)
            }
            Some(n) => {
                self.preempt_in = Some(n - 1);
                Ok(())
            }
            None => Ok(()),
        }
    }
}

/// The fixture: the root CNode with [`initial_caps`], both PML4s with
/// their kernel half, nothing mapped, and the kernel PML4 loaded.
#[derive(Clone, Debug)]
pub struct World {
    pub k: Space,
}

impl World {
    pub fn new() -> World {
        let mut k = Space::new();
        for (slot, cap) in initial_caps() {
            cdt::insert_root(&mut k, rs(slot), cap);
            if cap.cap_type() == CapType::Pml4 {
                k.init_object(cap);
            }
        }
        World { k }
    }

    pub fn cap(&self, s: SlotAddr) -> Cap {
        self.k.load(s).cap
    }

    pub fn root(&self, slot: u64) -> Cap {
        self.cap(rs(slot))
    }

    /// Calls `invoke` on the capability in `invoked`, with the extra
    /// capabilities in `extra`, after caching every translation.
    pub fn call(
        &mut self,
        invoked: SlotAddr,
        label: u64,
        mrs: &[u64],
        extra: &[SlotAddr],
    ) -> Result<Reply, InvokeError> {
        let extra: Vec<ExtraCap> = extra.iter().map(|s| ExtraCap::load(&self.k, *s)).collect();
        let msg = Message {
            label,
            mrs,
            extra_caps: &extra,
        };
        self.k.fill_tlb();
        self.k.flushes.clear();
        invoke::invoke(&mut self.k, invoked, &msg)
    }

    /// [`World::call`] on root slots, which must succeed; then [`check`].
    pub fn ok(&mut self, invoked: u64, label: u64, mrs: &[u64], extra: &[u64]) {
        let extra: Vec<SlotAddr> = extra.iter().map(|s| rs(*s)).collect();
        let r = self.call(rs(invoked), label, mrs, &extra);
        assert_eq!(
            r,
            Ok(Reply::EMPTY),
            "label {label:#x} on root slot {invoked}"
        );
        check(&self.k).unwrap();
    }

    /// [`World::call`] on root slots, which must fail with `e` and change
    /// nothing.
    pub fn fails(
        &mut self,
        invoked: u64,
        label: u64,
        mrs: &[u64],
        extra: &[u64],
        e: crate::error::SyscallError,
    ) {
        let before = self.k.mem.clone();
        let extra: Vec<SlotAddr> = extra.iter().map(|s| rs(*s)).collect();
        let r = self.call(rs(invoked), label, mrs, &extra);
        assert_eq!(
            r,
            Err(InvokeError::Error(e)),
            "label {label:#x} on root slot {invoked} with {mrs:x?}"
        );
        assert!(self.k.mem == before, "a failed call changed memory");
        assert!(self.k.flushes.is_empty(), "a failed call flushed");
    }

    /// Loads the PML4 whose capability is in root slot `slot`.
    pub fn load(&mut self, slot: u64) {
        let pml4 = self.root(slot).object();
        self.k.set_root(Some(pml4));
    }

    /// What the loaded tables translate `vaddr` to.
    pub fn translate(&self, pml4_slot: u64, vaddr: u64) -> Option<Translation> {
        paging::translate(&self.k.mem, self.root(pml4_slot).object(), vaddr)
    }
}

/// The live paging structures, from the capabilities in every slot: their
/// address and level.
pub fn live_structures(mem: &Store) -> BTreeMap<u64, u32> {
    let mut live = BTreeMap::new();
    for s in all_slots() {
        let cap = mem.load(s).cap;
        if let Some(level) = paging::structure_level(cap.cap_type()) {
            live.insert(cap.object(), level);
        }
    }
    live
}

/// Checks, from memory alone: L1 to L3 for every live structure and every
/// mapped capability; that each structure is mapped at most once, never a
/// PML4; the format of every user entry (tables P, RW, U/S only; leaves
/// user, not global, rights within the capability's, the cache type its
/// memory allows); every PML4's kernel half; that CR3 holds a live PML4 or
/// the kernel's; and that no cached translation disagrees with the tables.
pub fn check(k: &Space) -> Result<(), String> {
    let mem = &k.mem;
    let live = live_structures(mem);
    let kernel = kernel_pml4();
    let slots: BTreeSet<SlotAddr> = all_slots().into_iter().collect();
    let mut pointed = BTreeSet::new();
    for (&t, &level) in &live {
        let n = if level == 3 { 256 } else { 512 };
        let used = mem.used(t);
        if level == 3 {
            let half = used.iter().copied().filter(|i| *i >= 256);
            for i in half.chain((256..512).filter(|i| kernel[*i] != 0)) {
                if mem.entry(t, i) != kernel[i] || mem.backref(t, i) != 0 {
                    return Err(format!("PML4 {t:#x}: kernel half entry {i} differs"));
                }
            }
        }
        // Entries with a zero entry and a zero back-reference keep L1.
        for i in used.into_iter().filter(|i| *i < n) {
            let (e, b) = (mem.entry(t, i), mem.backref(t, i));
            if (b != 0) != (e & P != 0) {
                return Err(format!("L1: {t:#x}[{i}] entry {e:#x} backref {b:#x}"));
            }
            if b == 0 {
                continue;
            }
            let slot = SlotAddr::new(b & !1)
                .filter(|s| b & 1 == 1 && slots.contains(s))
                .ok_or_else(|| format!("{t:#x}[{i}]: bad backref {b:#x}"))?;
            let cap = mem.load(slot).cap;
            let link = paging::Link { table: t, index: i };
            if paging::holder_level(&cap) != Some(level) || paging::link_of(&cap) != Some(link) {
                return Err(format!("L2: {t:#x}[{i}] names {:#x} holding {cap:x?}", b));
            }
            let leaf = cap.cap_type() == CapType::Frame;
            if leaf {
                let mask = if cap.size_bits() == FRAME_2M_BITS {
                    !(PAGE_2M - 1) & ADDR_4K
                } else {
                    ADDR_4K
                };
                let large = cap.size_bits() == FRAME_2M_BITS;
                let cache_bit = if large { super::PAT_2M } else { super::PAT_4K };
                let cache = CacheType::of_leaf(e, cache_bit);
                let cache_ok = if cap.is_device() {
                    matches!(cache, CacheType::Uncached | CacheType::WriteCombining)
                } else {
                    cache == CacheType::WriteBack
                };
                // In a 4 KiB PTE bit 7 is PAT, not PS.
                if e & mask != cap.object()
                    || (level == 1 && e & PS == 0)
                    || e & US == 0
                    || e & G != 0
                    || (e & RW != 0 && !cap.rights().contains(Rights::WRITE))
                    || !cap.rights().contains(Rights::READ)
                    || !cache_ok
                {
                    return Err(format!("leaf {t:#x}[{i}] = {e:#x} for {cap:x?}"));
                }
            } else {
                if e != user_table(cap.object()) {
                    return Err(format!("table entry {t:#x}[{i}] = {e:#x} for {cap:x?}"));
                }
                if live.get(&cap.object()) != Some(&(level - 1)) {
                    return Err(format!("{t:#x}[{i}] points at {:#x}", cap.object()));
                }
                if !pointed.insert(cap.object()) {
                    return Err(format!("{:#x} is mapped twice", cap.object()));
                }
            }
        }
    }
    for &s in &slots {
        let cap = mem.load(s).cap;
        if let Some(link) = paging::link_of(&cap) {
            let level = paging::holder_level(&cap).unwrap();
            if live.get(&link.table) != Some(&level) {
                return Err(format!(
                    "L3: {cap:x?} in {:#x} names a dead or wrong-level table",
                    s.get()
                ));
            }
            if mem.backref(link.table, link.index) != s.get() | 1 {
                return Err(format!("L3: {cap:x?} in {:#x} is not named back", s.get()));
            }
        }
    }
    if let Some(pml4) = k.loaded
        && live.get(&pml4) != Some(&3)
    {
        return Err(format!("CR3 holds {pml4:#x}, not a live PML4"));
    }
    check_tlb(k)
}

/// No translation the TLB caches disagrees with the tables under the
/// loaded PML4.
pub fn check_tlb(k: &Space) -> Result<(), String> {
    let Some(pml4) = k.loaded else {
        return if k.tlb.leaves.is_empty() && k.tlb.walks.is_empty() {
            Ok(())
        } else {
            Err(String::from(
                "the kernel PML4 is loaded, but the TLB holds user translations",
            ))
        };
    };
    for (&(base, size), t) in &k.tlb.leaves {
        let now = paging::translate(&k.mem, pml4, base);
        if now.map(|n| (n, n.page_size)) != Some((*t, size)) {
            return Err(format!(
                "stale TLB entry at {base:#x}: {t:x?}, tables say {now:x?}"
            ));
        }
    }
    for (&(level, base), &table) in &k.tlb.walks {
        let mut at = pml4;
        let mut ok = true;
        for l in (level..=3).rev() {
            let e = k.mem.entry(at, index(base, l));
            if e & P == 0 || e & PS != 0 {
                ok = false;
                break;
            }
            at = e & ADDR_4K;
        }
        if !ok || at != table {
            return Err(format!(
                "stale paging-structure cache entry: level {level} at {base:#x} -> {table:#x}"
            ));
        }
    }
    Ok(())
}
