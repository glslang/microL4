//! Address spaces from M5 (`docs/design.md`, "Address spaces"; ADR 0005):
//! the paging objects, their back-references, and every write to a user
//! entry, a back-reference or a mapping record.
//!
//! A paging structure (PML4, PDPT, page directory, page table) is 8 KiB: the
//! hardware table, then 512 back-reference words at [`BACKREFS`]. Entry `i`
//! is present exactly when back-reference `i` names the slot of the
//! capability that installed it (L1), that capability's mapping record names
//! entry `i` (L2), and every mapped capability's record names an entry whose
//! back-reference names its slot (L3). Every function here keeps L1 to L3,
//! and checks a link in both directions before it uses it, panicking on a
//! mismatch: a broken link would otherwise be a write into reused memory.
//!
//! Everything is written against two traits: [`PagingStore`], which reads
//! and writes the entries and back-references of the structure at a
//! physical address, and the capability core's [`SlotMemory`]. Every
//! operation that can change a present entry returns a `#[must_use]`
//! [`Flush`], which `arch` applies after the writes and before the next user
//! instruction ("TLB maintenance").
//!
//! # Levels
//!
//! A table's level is the `level` argument of [`super::index`] for its
//! entries: 0 for a page table, 1 for a page directory, 2 for a PDPT, 3 for
//! a PML4. A capability mapped at level `l` sits in an entry of a table of
//! level `l`: a 4 KiB frame at 0, a page table or a 2 MiB frame at 1, a page
//! directory at 2, a PDPT at 3.
//!
//! # Mapping records
//!
//! The data word of a Frame or a PDPT, page-directory or page-table
//! capability, 0 when unmapped (`docs/design.md`, "Capabilities"):
//!
//! | Bits | Frame | PDPT, PageDirectory, PageTable |
//! | --- | --- | --- |
//! | 0 | `mapped`, 1 | `mapped`, 1 |
//! | 1 to 23 | `table >> 13` | parent `table >> 13` |
//! | 24 to 58 | `vaddr >> 12` | `index`, bits 24 to 32 |

use core::ops::Range;

use crate::cap::{Cap, CapType, FRAME_2M_BITS, PAGING_STRUCTURE_BITS, Rights, low_mask};
use crate::error::{LookupFailure, SyscallError};
use crate::slot::{SlotAddr, SlotMemory};

use super::{
    ADDR_2M, ADDR_4K, CacheType, ENTRIES, P, PAGE_2M, PAGE_4K, PAT_2M, PAT_4K, PS, RW, Span, Table,
    Translation, US, UserAccess, XD, index, user_pde_2m, user_pte, user_table,
};

/// The lowest address a frame may map: page 0 never maps.
pub const USER_MIN: u64 = 0x0000_0000_0000_1000;
/// A frame mapping must end at or below this address, so the last page
/// below the non-canonical hole never maps ("User address range").
pub const USER_TOP: u64 = 0x0000_7FFF_FFFF_F000;
/// The PML4 entries every address space shares with the kernel PML4.
pub const KERNEL_HALF: Range<usize> = 256..512;
/// Offset of the back-references in a paging structure.
pub const BACKREFS: u64 = 0x1000;
/// Paging structures and the tables holding entries lie below this
/// address, inside the direct map, so `table >> 13` fits 23 bits.
pub const STRUCTURE_LIMIT: u64 = 1 << 36;

const STRUCTURE_BYTES: u64 = 1 << PAGING_STRUCTURE_BITS;
/// The user half of the virtual address space: `[0, 2^47)`.
const USER_HALF_END: u64 = 1 << 47;

/// The TLB maintenance an operation needs ("TLB maintenance"). `arch`
/// applies it after the operation returns and before the next user
/// instruction: a flush must follow the entry write it covers [H13].
#[must_use = "a Flush must reach `arch`, which applies it before the next user instruction"]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flush {
    /// Nothing changed a present entry.
    None,
    /// A leaf for the page holding this user address was cleared or
    /// changed: `invlpg` [H5].
    Page(u64),
    /// A non-leaf entry was cleared or a structure emptied: reload CR3 [H4].
    All,
}

impl Flush {
    /// A flush that covers both.
    pub const fn and(self, other: Flush) -> Flush {
        match (self, other) {
            (Flush::None, f) | (f, Flush::None) => f,
            (Flush::Page(a), Flush::Page(b)) if a == b => Flush::Page(a),
            _ => Flush::All,
        }
    }
}

/// Reads and writes the entries and back-references of paging structures,
/// named by physical address. The kernel implements it in `arch` over the
/// direct map, the host tests over fake memory.
///
/// `table` is always an 8 KiB-aligned paging structure below
/// [`STRUCTURE_LIMIT`] and `i` below 512.
pub trait PagingStore {
    /// Entry `i` of the structure at `table`.
    fn entry(&self, table: u64, i: usize) -> u64;
    /// Overwrites entry `i`.
    fn set_entry(&mut self, table: u64, i: usize, entry: u64);
    /// Back-reference `i`: 0, or the slot address with bit 0 set.
    fn backref(&self, table: u64, i: usize) -> u64;
    /// Overwrites back-reference `i`.
    fn set_backref(&mut self, table: u64, i: usize, backref: u64);
    /// Applies a flush an invocation returned, after the writes it covers.
    /// The invocation decoder calls it, since `invoke` returns only a
    /// reply; the kernel's hooks apply the flushes they get themselves.
    fn flush(&mut self, flush: Flush);
}

/// A mapping record: where a mapped capability's entry lives. `table` is
/// the structure holding the entry; `index` its index there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Link {
    pub table: u64,
    pub index: usize,
}

/// A Frame capability's mapping record: the table holding its entry (a page
/// table for 4 KiB, a page directory for 2 MiB) and its virtual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FrameMapping {
    pub table: u64,
    pub vaddr: u64,
}

/// A PDPT, page-directory or page-table capability's mapping record: the
/// parent table and the index of the entry there.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableMapping {
    pub parent: u64,
    pub index: usize,
}

const MAPPED: u64 = 1;
const TABLE_SHIFT: u32 = 1;
const TABLE_FIELD_BITS: u32 = 23;
const SECOND_SHIFT: u32 = 24;

fn encode(table: u64, second: u64) -> u64 {
    assert!(
        table != 0 && table.is_multiple_of(STRUCTURE_BYTES) && table < STRUCTURE_LIMIT,
        "paging structure {table:#x} cannot be recorded"
    );
    MAPPED | (table >> PAGING_STRUCTURE_BITS) << TABLE_SHIFT | second << SECOND_SHIFT
}

/// The `table` and second field of a non-zero record; panics on a record
/// no function here writes.
fn decode(data: u64) -> Option<(u64, u64)> {
    if data == 0 {
        return None;
    }
    assert!(data & MAPPED != 0, "corrupt mapping record {data:#x}");
    let table = (data >> TABLE_SHIFT & low_mask(TABLE_FIELD_BITS)) << PAGING_STRUCTURE_BITS;
    Some((table, data >> SECOND_SHIFT))
}

impl FrameMapping {
    /// The data word. Panics if `vaddr` is not a page address in the user
    /// half or `table` cannot be recorded.
    pub fn encode(self) -> u64 {
        assert!(
            self.vaddr.is_multiple_of(PAGE_4K) && self.vaddr < USER_HALF_END,
            "frame mapping at {:#x} cannot be recorded",
            self.vaddr
        );
        encode(self.table, self.vaddr >> 12)
    }

    /// The record in a Frame capability's data word; `None` if unmapped.
    pub fn decode(data: u64) -> Option<FrameMapping> {
        decode(data).map(|(table, vpn)| FrameMapping {
            table,
            vaddr: vpn << 12,
        })
    }
}

impl TableMapping {
    /// The data word. Panics if `index` is not below 512 or `parent`
    /// cannot be recorded.
    pub fn encode(self) -> u64 {
        assert!(self.index < ENTRIES, "index {} out of range", self.index);
        encode(self.parent, self.index as u64)
    }

    /// The record in a paging-structure capability's data word; `None` if
    /// unmapped.
    pub fn decode(data: u64) -> Option<TableMapping> {
        decode(data).map(|(parent, index)| {
            assert!(index < ENTRIES as u64, "corrupt mapping record {data:#x}");
            TableMapping {
                parent,
                index: index as usize,
            }
        })
    }
}

/// The level of a paging structure's own entries: page table 0 to PML4 3.
pub const fn structure_level(ty: CapType) -> Option<u32> {
    match ty {
        CapType::PageTable => Some(0),
        CapType::PageDirectory => Some(1),
        CapType::Pdpt => Some(2),
        CapType::Pml4 => Some(3),
        _ => None,
    }
}

/// The level of the table that holds the entry of `cap` when it is mapped;
/// `None` for capabilities that are never mapped (PML4s among them).
pub fn holder_level(cap: &Cap) -> Option<u32> {
    match cap.cap_type() {
        CapType::Frame if cap.size_bits() == FRAME_2M_BITS => Some(1),
        CapType::Frame => Some(0),
        ty => structure_level(ty).filter(|l| *l < 3).map(|l| l + 1),
    }
}

/// The mapping record of `cap`, if it is a mapped Frame or a mapped PDPT,
/// page directory or page table.
pub fn link_of(cap: &Cap) -> Option<Link> {
    let level = holder_level(cap)?;
    if cap.cap_type() == CapType::Frame {
        FrameMapping::decode(cap.data).map(|m| Link {
            table: m.table,
            index: index(m.vaddr, level),
        })
    } else {
        TableMapping::decode(cap.data).map(|m| Link {
            table: m.parent,
            index: m.index,
        })
    }
}

/// The back-reference naming `slot`.
const fn tag(slot: SlotAddr) -> u64 {
    slot.get() | 1
}

/// Whether entry `e` is present and points at the object of `cap` in the
/// format its type maps with: a 2 MiB leaf, a 4 KiB leaf, or a table entry.
fn points_at(e: u64, cap: &Cap) -> bool {
    if e & P == 0 {
        return false;
    }
    match cap.cap_type() {
        CapType::Frame if cap.size_bits() == FRAME_2M_BITS => {
            e & PS != 0 && e & ADDR_2M == cap.object()
        }
        // In a 4 KiB PTE bit 7 is PAT, not PS.
        CapType::Frame => e & ADDR_4K == cap.object(),
        _ => e & PS == 0 && e & ADDR_4K == cap.object(),
    }
}

/// Checks the link of `cap`, held in `slot` and mapped at `link`, from the
/// capability's side: the back-reference names `slot` and the entry points
/// at the object. Panics on a mismatch.
fn check_cap_link<K: PagingStore + ?Sized>(k: &K, slot: SlotAddr, cap: &Cap, link: Link) {
    let b = k.backref(link.table, link.index);
    let e = k.entry(link.table, link.index);
    assert!(
        b == tag(slot) && points_at(e, cap),
        "broken paging link: {cap:x?} in slot {:#x} records entry {} of {:#x}, which holds {e:#x} \
         with back-reference {b:#x}",
        slot.get(),
        link.index,
        link.table
    );
}

/// What entry `i` of the table at `table`, of level `level`, holds: `None`,
/// or the slot its back-reference names and the capability there, after
/// checking the link from the table's side (L1, L2). Panics on a mismatch.
fn child<K: SlotMemory + PagingStore + ?Sized>(
    k: &K,
    table: u64,
    level: u32,
    i: usize,
) -> Option<(SlotAddr, Cap)> {
    assert!(
        level < 3 || i < KERNEL_HALF.start,
        "the kernel half has no back-references"
    );
    let b = k.backref(table, i);
    let e = k.entry(table, i);
    if b == 0 {
        assert!(
            e & P == 0,
            "entry {i} of {table:#x} is present ({e:#x}) without a back-reference"
        );
        return None;
    }
    let slot = (b & 1 == 1)
        .then(|| SlotAddr::new(b & !1))
        .flatten()
        .unwrap_or_else(|| panic!("entry {i} of {table:#x}: bad back-reference {b:#x}"));
    let cap = k.load(slot).cap;
    assert!(
        holder_level(&cap) == Some(level)
            && link_of(&cap) == Some(Link { table, index: i })
            && points_at(e, &cap),
        "broken paging link: entry {i} of {table:#x} (level {level}) holds {e:#x} and names slot \
         {:#x}, which holds {cap:x?}",
        slot.get()
    );
    Some((slot, cap))
}

/// The slot holding `cap`, which is mapped at `link`: the one its
/// back-reference names, checked to hold exactly `cap`. For the deletion
/// hook, which is not told the slot; `cap` is still in it.
fn slot_of<K: SlotMemory + PagingStore + ?Sized>(k: &K, cap: &Cap, link: Link) -> SlotAddr {
    let b = k.backref(link.table, link.index);
    let slot = (b & 1 == 1)
        .then(|| SlotAddr::new(b & !1))
        .flatten()
        .filter(|s| k.load(*s).cap == *cap)
        .unwrap_or_else(|| {
            panic!(
                "broken paging link: {cap:x?} records entry {} of {:#x}, whose back-reference \
                 {b:#x} names no slot holding it",
                link.index, link.table
            )
        });
    check_cap_link(k, slot, cap, link);
    slot
}

/// Rewrites the mapping record of the capability in `slot`, which must
/// still be `cap`.
fn set_record<M: SlotMemory + ?Sized>(mem: &mut M, slot: SlotAddr, cap: Cap, record: u64) {
    let mut s = mem.load(slot);
    debug_assert!(
        s.cap == cap,
        "slot {:#x} changed under the paging code",
        slot.get()
    );
    s.cap = cap.with_data(record);
    mem.store(slot, s);
}

/// Writes entry `i` of `table`, its back-reference to `slot` and the
/// record of `cap`, the capability in `slot`: a map.
fn install<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    cap: Cap,
    link: Link,
    entry: u64,
    record: u64,
) {
    k.set_entry(link.table, link.index, entry);
    k.set_backref(link.table, link.index, tag(slot));
    set_record(k, slot, cap, record);
}

/// Clears entry `link`, its back-reference and the record of `cap`, the
/// capability in `slot`, after checking the link.
fn remove<K: SlotMemory + PagingStore + ?Sized>(k: &mut K, slot: SlotAddr, cap: Cap, link: Link) {
    check_cap_link(k, slot, &cap, link);
    k.set_entry(link.table, link.index, 0);
    k.set_backref(link.table, link.index, 0);
    set_record(k, slot, cap, 0);
}

/// Whether the structure at `table` holds no entries: a scan of its
/// back-references (L1).
fn is_empty<K: PagingStore + ?Sized>(k: &K, table: u64) -> bool {
    (0..ENTRIES).all(|i| k.backref(table, i) == 0)
}

/// Clears every entry of the structure at `table`, of level `level`, and
/// unmaps the capability each names; a child structure keeps its own
/// entries. Returns whether there was any. Touches at most 512 entries.
fn empty<K: SlotMemory + PagingStore + ?Sized>(k: &mut K, table: u64, level: u32) -> bool {
    let n = if level == 3 {
        KERNEL_HALF.start
    } else {
        ENTRIES
    };
    let mut any = false;
    for i in 0..n {
        if let Some((slot, cap)) = child(k, table, level, i) {
            k.set_entry(table, i, 0);
            k.set_backref(table, i, 0);
            set_record(k, slot, cap, 0);
            any = true;
        }
    }
    any
}

/// A failed lookup of a missing paging structure, `bits_left` address bits
/// unresolved below it.
const fn missing(bits_left: u32) -> SyscallError {
    SyscallError::FailedLookup {
        source: false,
        failure: LookupFailure::MissingCapability { bits_left },
    }
}

/// The structure of level `level` that covers `vaddr` under the PML4 at
/// `pml4`, walking through present table entries and checking each link;
/// `FailedLookup` with 39, 30 or 21 bits left where one is missing or a 2
/// MiB frame stands in the way.
fn walk_to<K: SlotMemory + PagingStore + ?Sized>(
    k: &K,
    pml4: u64,
    vaddr: u64,
    level: u32,
) -> Result<u64, SyscallError> {
    let mut table = pml4;
    let mut l = 3;
    while l > level {
        match child(k, table, l, index(vaddr, l)) {
            Some((_, cap)) if cap.cap_type() != CapType::Frame => table = cap.object(),
            _ => return Err(missing(12 + 9 * l)),
        }
        l -= 1;
    }
    Ok(table)
}

/// The attributes word of `Frame_Map` and `Frame_Remap` (`docs/abi.md`,
/// "Attributes word"): the cache type, as its PAT index, in bits 0 to 2;
/// execute in bit 3; bits 4 to 63 zero.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Attributes {
    pub cache: CacheType,
    pub execute: bool,
}

impl Attributes {
    /// Bit 3: the mapping is executable.
    pub const EXECUTE: u64 = 1 << 3;
    /// Write-back, no-execute: the word 0.
    pub const RAM: Attributes = Attributes {
        cache: CacheType::WriteBack,
        execute: false,
    };

    /// The word.
    pub const fn word(self) -> u64 {
        self.cache.pat_index() as u64 | if self.execute { Self::EXECUTE } else { 0 }
    }

    /// The attributes in `word` for a RAM frame or a device frame; `None`
    /// if reserved bits are set, the cache type is not `WriteBack`,
    /// `Uncached` or `WriteCombining`, or the frame may not use it: RAM only
    /// `WriteBack`, device memory only the other two.
    pub fn decode(word: u64, device: bool) -> Option<Attributes> {
        if word >> 4 != 0 {
            return None;
        }
        let cache = match word & 7 {
            0 if !device => CacheType::WriteBack,
            3 if device => CacheType::Uncached,
            4 if device => CacheType::WriteCombining,
            _ => return None,
        };
        Some(Attributes {
            cache,
            execute: word & Self::EXECUTE != 0,
        })
    }
}

/// Whether a mapping of `cap` with the rights word `rights` is writable;
/// `None` if the requested rights masked by the capability's lack Read.
fn writable(cap: &Cap, rights: u64) -> Option<bool> {
    let r = cap.rights().intersect(Rights::from_word(rights));
    r.contains(Rights::READ).then(|| r.contains(Rights::WRITE))
}

/// The leaf entry mapping the Frame `cap`.
fn leaf(cap: &Cap, write: bool, attrs: Attributes) -> u64 {
    let access = UserAccess {
        write,
        execute: attrs.execute,
    };
    if cap.size_bits() == FRAME_2M_BITS {
        user_pde_2m(cap.object(), access, attrs.cache)
    } else {
        user_pte(cap.object(), access, attrs.cache)
    }
}

/// The capability in `slot`, which must be of a type `ok` accepts: the
/// decoder routes only those here.
fn load_kind<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr, ok: fn(CapType) -> bool) -> Cap {
    let cap = mem.load(slot).cap;
    assert!(ok(cap.cap_type()), "{cap:x?} cannot be used here");
    cap
}

fn is_frame(ty: CapType) -> bool {
    ty == CapType::Frame
}

fn is_lower_structure(ty: CapType) -> bool {
    matches!(
        ty,
        CapType::Pdpt | CapType::PageDirectory | CapType::PageTable
    )
}

/// `PDPT_Map`, `PageDirectory_Map`, `PageTable_Map` after the length
/// checks: maps the structure whose capability is in `slot` into the VSpace
/// `vspace`, one level below the structure that covers `vaddr`. Errors in
/// `docs/abi.md`'s order; nothing changes unless all checks pass. A fresh
/// entry needs no flush [H6].
pub fn map_table<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    vspace: Cap,
    vaddr: u64,
) -> Result<Flush, SyscallError> {
    let cap = load_kind(k, slot, is_lower_structure);
    let level = holder_level(&cap).expect("a lower structure is mapped one level up");
    if vspace.cap_type() != CapType::Pml4 {
        return Err(SyscallError::InvalidCapability(1));
    }
    if cap.data != 0 || !is_empty(k, cap.object()) {
        return Err(SyscallError::InvalidCapability(0));
    }
    // A structure at level `level - 1` covers 2^(12 + 9 * level) bytes.
    let base = vaddr & !low_mask(12 + 9 * level);
    if base >= USER_TOP {
        return Err(SyscallError::InvalidArgument(0));
    }
    let table = walk_to(k, vspace.object(), base, level)?;
    let link = Link {
        table,
        index: index(base, level),
    };
    if child(k, table, level, link.index).is_some() {
        return Err(SyscallError::DeleteFirst);
    }
    let record = TableMapping {
        parent: table,
        index: link.index,
    }
    .encode();
    install(k, slot, cap, link, user_table(cap.object()), record);
    Ok(Flush::None)
}

/// `Frame_Map` after the length checks: maps the frame whose capability is
/// in `slot` at `vaddr` in the VSpace `vspace`, with the rights word
/// `rights` masked by the capability's and the attributes word `attrs`.
/// Errors in `docs/abi.md`'s order; nothing changes unless all checks
/// pass. A fresh entry needs no flush [H6].
pub fn map_frame<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    vspace: Cap,
    vaddr: u64,
    rights: u64,
    attrs: u64,
) -> Result<Flush, SyscallError> {
    let cap = load_kind(k, slot, is_frame);
    let level = holder_level(&cap).expect("a frame maps at level 0 or 1");
    let size = 1u64 << cap.size_bits();
    if vspace.cap_type() != CapType::Pml4 {
        return Err(SyscallError::InvalidCapability(1));
    }
    if cap.data != 0 {
        return Err(SyscallError::InvalidCapability(0));
    }
    if !vaddr.is_multiple_of(size) {
        return Err(SyscallError::AlignmentError);
    }
    if vaddr < USER_MIN || vaddr > USER_TOP - size {
        return Err(SyscallError::InvalidArgument(0));
    }
    let write = writable(&cap, rights).ok_or(SyscallError::InvalidArgument(1))?;
    let attrs =
        Attributes::decode(attrs, cap.is_device()).ok_or(SyscallError::InvalidArgument(2))?;
    let table = walk_to(k, vspace.object(), vaddr, level)?;
    let link = Link {
        table,
        index: index(vaddr, level),
    };
    if child(k, table, level, link.index).is_some() {
        return Err(SyscallError::DeleteFirst);
    }
    let record = FrameMapping { table, vaddr }.encode();
    install(k, slot, cap, link, leaf(&cap, write, attrs), record);
    Ok(Flush::None)
}

/// `Frame_Remap` after the length check: rewrites the existing mapping of
/// the frame whose capability is in `slot` with new rights and attributes.
/// Flushes the page.
pub fn remap_frame<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    rights: u64,
    attrs: u64,
) -> Result<Flush, SyscallError> {
    let cap = load_kind(k, slot, is_frame);
    let Some(m) = FrameMapping::decode(cap.data) else {
        return Err(SyscallError::IllegalOperation);
    };
    let write = writable(&cap, rights).ok_or(SyscallError::InvalidArgument(0))?;
    let attrs =
        Attributes::decode(attrs, cap.is_device()).ok_or(SyscallError::InvalidArgument(1))?;
    let link = link_of(&cap).expect("a mapped frame has a link");
    check_cap_link(k, slot, &cap, link);
    k.set_entry(link.table, link.index, leaf(&cap, write, attrs));
    Ok(Flush::Page(m.vaddr))
}

/// `Frame_Unmap`: removes the mapping of the frame whose capability is in
/// `slot`, if it has one, and flushes the page.
pub fn unmap_frame<K: SlotMemory + PagingStore + ?Sized>(k: &mut K, slot: SlotAddr) -> Flush {
    let cap = load_kind(k, slot, is_frame);
    let Some(m) = FrameMapping::decode(cap.data) else {
        return Flush::None;
    };
    let link = link_of(&cap).expect("a mapped frame has a link");
    remove(k, slot, cap, link);
    Flush::Page(m.vaddr)
}

/// Detaches the structure `cap` from its parent if it is mapped (`slot`
/// holds it), then empties it. CR3 reload if anything changed.
fn clear_structure<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    slot: Option<SlotAddr>,
    cap: Cap,
) -> Flush {
    let level = structure_level(cap.cap_type()).expect("a paging structure");
    let mut changed = false;
    if let Some(link) = link_of(&cap) {
        let slot = slot.unwrap_or_else(|| slot_of(k, &cap, link));
        remove(k, slot, cap, link);
        changed = true;
    }
    changed |= empty(k, cap.object(), level);
    if changed { Flush::All } else { Flush::None }
}

/// `PDPT_Unmap`, `PageDirectory_Unmap`, `PageTable_Unmap`: detaches the
/// structure whose capability is in `slot`, if it is mapped, then empties
/// it: each frame or child structure mapped there becomes unmapped, and a
/// child structure keeps its own entries. Reloads CR3 if anything changed;
/// on an unmapped, empty structure it does nothing.
pub fn unmap_table<K: SlotMemory + PagingStore + ?Sized>(k: &mut K, slot: SlotAddr) -> Flush {
    let cap = load_kind(k, slot, is_lower_structure);
    clear_structure(k, Some(slot), cap)
}

/// The paging part of deleting `cap` (`docs/design.md`, "Deletion"), for
/// the kernel's `finalise` hook, which `core` calls with `cap` still in its
/// slot; `last` says whether it is the last capability to its object.
///
/// - A Frame, on every deletion: as [`unmap_frame`].
/// - A PDPT, page directory or page table, whose capability is always the
///   only one: as [`unmap_table`].
/// - The last PML4 capability: the PDPT capabilities its entries 0 to 255
///   name become unmapped, and those entries are cleared; lower levels
///   keep theirs, as orphans. If CR3 holds this PML4, `arch` must load the
///   kernel PML4 before calling this; that CR3 write is the flush, and
///   this returns `None`.
/// - Anything else: nothing.
///
/// The hook is not told the slot, so it is found through the mapping's
/// back-reference and checked to hold exactly `cap`.
pub fn finalise<K: SlotMemory + PagingStore + ?Sized>(k: &mut K, cap: Cap, last: bool) -> Flush {
    match cap.cap_type() {
        CapType::Frame => match link_of(&cap) {
            Some(link) => {
                let slot = slot_of(k, &cap, link);
                unmap_frame(k, slot)
            }
            None => Flush::None,
        },
        CapType::Pdpt | CapType::PageDirectory | CapType::PageTable => {
            clear_structure(k, None, cap)
        }
        // No flush: the PML4 is not loaded, and the TLB holds translations
        // of the loaded PML4 only [H4].
        CapType::Pml4 if last => {
            empty(k, cap.object(), 3);
            Flush::None
        }
        _ => Flush::None,
    }
}

/// The paging part of moving `cap` from slot `from` to slot `to`, which
/// now holds it, for the kernel's `moved` hook: a mapped Frame or paging
/// structure's back-reference is rewritten to `to`. Changes no entry, so
/// the flush is always `None`.
pub fn moved<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    cap: Cap,
    from: SlotAddr,
    to: SlotAddr,
) -> Flush {
    if let Some(link) = link_of(&cap) {
        let now = k.load(to).cap;
        assert!(
            now == cap,
            "moved: slot {:#x} holds {now:x?}, not the moved {cap:x?}",
            to.get()
        );
        check_cap_link(k, from, &cap, link);
        k.set_backref(link.table, link.index, tag(to));
    }
    Flush::None
}

/// A new PML4's kernel half, for the kernel's `init_object` hook after
/// retype zeroed it: entries 256 to 511 become `kernel_pml4`'s, the kernel
/// PML4's entries. Back-references 256 to 511 stay zero.
pub fn init_pml4<P: PagingStore + ?Sized>(p: &mut P, pml4: u64, kernel_pml4: &Table) {
    for i in KERNEL_HALF {
        debug_assert!(
            p.entry(pml4, i) == 0 && p.backref(pml4, i) == 0,
            "a new PML4 is zero"
        );
        p.set_entry(pml4, i, kernel_pml4[i]);
    }
}

/// Translates user address `vaddr` through the tables under the PML4 at
/// `pml4`, as the CPU would with CR0.WP and EFER.NXE set: `None` if no
/// translation exists. Follows entries only, without checking links, for
/// tests and self-tests. Panics on an address outside the user half, and
/// on a PS bit in a PML4E or PDPTE, which nothing here writes.
pub fn translate<P: PagingStore + ?Sized>(p: &P, pml4: u64, vaddr: u64) -> Option<Translation> {
    assert!(vaddr < USER_HALF_END, "{vaddr:#x} is not a user address");
    let mut table = pml4;
    let (mut write, mut user, mut nx) = (true, true, false);
    for level in (0..=3u32).rev() {
        let e = p.entry(table, index(vaddr, level));
        if e & P == 0 {
            return None;
        }
        write &= e & RW != 0;
        user &= e & US != 0;
        nx |= e & XD != 0;
        let leaf = match level {
            0 => Some((PAGE_4K, ADDR_4K, PAT_4K)),
            1 if e & PS != 0 => Some((PAGE_2M, ADDR_2M, PAT_2M)),
            2 | 3 if e & PS != 0 => panic!("a 1 GiB page at {vaddr:#x}"),
            _ => None,
        };
        if let Some((size, mask, pat_bit)) = leaf {
            return Some(Translation {
                phys: (e & mask) + (vaddr & (size - 1)),
                page_size: size,
                write,
                user,
                execute: !nx,
                global: e & super::G != 0,
                cache: CacheType::of_leaf(e, pat_bit),
            });
        }
        table = e & ADDR_4K;
    }
    unreachable!("a level-0 entry is always a leaf")
}

/// The paging structures that map every page of `span`: how many PDPTs,
/// page directories and page tables, each covering a naturally aligned
/// 512 GiB, 1 GiB or 2 MiB, for boot step 8's `RootNeeds`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TableCounts {
    pub pdpts: u64,
    pub pds: u64,
    pub pts: u64,
}

/// Address bits a PDPT, a page directory and a page table cover.
const COVER_BITS: [(CapType, u32); 3] = [
    (CapType::Pdpt, 39),
    (CapType::PageDirectory, 30),
    (CapType::PageTable, 21),
];

/// How many naturally aligned `2^bits` blocks `span` touches.
fn blocks(span: Span, bits: u32) -> u64 {
    if span.end <= span.start {
        0
    } else {
        ((span.end - 1) >> bits) - (span.start >> bits) + 1
    }
}

impl TableCounts {
    /// The structures [`map_boot_tables`] maps for `span`.
    pub fn covering(span: Span) -> TableCounts {
        TableCounts {
            pdpts: blocks(span, COVER_BITS[0].1),
            pds: blocks(span, COVER_BITS[1].1),
            pts: blocks(span, COVER_BITS[2].1),
        }
    }
}

/// Boot step 8: maps the root task's paging structures, whose capabilities
/// `tables` yields in `user_image_paging` order (PDPTs, then page
/// directories, then page tables, each by ascending address), into the
/// VSpace whose capability is in `vspace`, so that every page of `span` has
/// a page table. Each must be unmapped and empty, and `tables` must hold
/// exactly what [`TableCounts::covering`] counts for `span`; anything else
/// panics, as does a span outside the user range. Then map each page with
/// [`map_frame`], or [`map_boot_frame`].
pub fn map_boot_tables<K, I>(k: &mut K, vspace: SlotAddr, span: Span, tables: I)
where
    K: SlotMemory + PagingStore + ?Sized,
    I: IntoIterator<Item = SlotAddr>,
{
    let root = k.load(vspace).cap;
    let mut tables = tables.into_iter();
    for (ty, bits) in COVER_BITS {
        for n in 0..blocks(span, bits) {
            let slot = tables
                .next()
                .unwrap_or_else(|| panic!("boot: too few paging structures for {span:x?}"));
            let cap = k.load(slot).cap;
            assert_eq!(cap.cap_type(), ty, "boot: slot {:#x}", slot.get());
            let vaddr = ((span.start >> bits) + n) << bits;
            match map_table(k, slot, root, vaddr) {
                Ok(Flush::None) => {}
                other => panic!("boot: mapping {cap:x?} at {vaddr:#x} gave {other:?}"),
            }
        }
    }
    assert!(
        tables.next().is_none(),
        "boot: more paging structures than {span:x?} needs"
    );
}

/// Boot step 8: maps the 4 KiB RAM frame whose capability is in `frame` at
/// `vaddr` in the VSpace whose capability is in `vspace`, write-back, with
/// `access`. Panics if [`map_frame`] fails.
pub fn map_boot_frame<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    frame: SlotAddr,
    vspace: SlotAddr,
    vaddr: u64,
    access: UserAccess,
) {
    let root = k.load(vspace).cap;
    let rights = if access.write {
        Rights::READ.0 | Rights::WRITE.0
    } else {
        Rights::READ.0
    };
    let attrs = Attributes {
        cache: CacheType::WriteBack,
        execute: access.execute,
    };
    match map_frame(k, frame, root, vaddr, rights.into(), attrs.word()) {
        Ok(Flush::None) => {}
        other => panic!(
            "boot: mapping frame slot {:#x} at {vaddr:#x} gave {other:?}",
            frame.get()
        ),
    }
}

/// Fake memory as paging structures, for host tests and `model/`.
#[cfg(any(test, feature = "testing"))]
mod fake {
    use super::{BACKREFS, Flush, PagingStore};
    use crate::testing::{FakeMemory, TestKernel};

    fn at(table: u64, i: usize) -> u64 {
        assert!(i < super::ENTRIES, "entry {i} out of range");
        table + 8 * i as u64
    }

    impl PagingStore for FakeMemory {
        fn entry(&self, table: u64, i: usize) -> u64 {
            self.read(at(table, i))
        }

        fn set_entry(&mut self, table: u64, i: usize, entry: u64) {
            self.write(at(table, i), entry)
        }

        fn backref(&self, table: u64, i: usize) -> u64 {
            self.read(at(table, i) + BACKREFS)
        }

        fn set_backref(&mut self, table: u64, i: usize, backref: u64) {
            self.write(at(table, i) + BACKREFS, backref)
        }

        fn flush(&mut self, _: Flush) {}
    }

    /// [`TestKernel`] records hook calls only; its flushes go nowhere.
    impl PagingStore for TestKernel {
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

        fn flush(&mut self, _: Flush) {}
    }
}
