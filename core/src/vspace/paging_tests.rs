//! Host tests of the paging objects and their invocations: the bounds and
//! every error of `docs/abi.md`, "Address spaces", in its order; the
//! entries, back-references and records each operation writes; the flush
//! each returns; deletion and moves through the capability core; the
//! two-way link checks; and the boot helpers. Every successful call is
//! followed by the full check of [`check`], TLB model included.

use std::vec::Vec;

use super::paging::{
    self, Attributes, Flush, FrameMapping, KERNEL_HALF, PagingStore, STRUCTURE_LIMIT, TableCounts,
    TableMapping, USER_MIN, USER_TOP,
};
use super::testkit::*;
use super::{CacheType, PAGE_2M, PAGE_4K, Span, UserAccess, index, label, user_pte, user_table};
use crate::cap::{Cap, CapType, Rights};
use crate::cnode;
use crate::error::{LookupFailure, SyscallError};
use crate::invoke::InvokeError;
use crate::kernel::Kernel;
use crate::slot::SlotMemory;
use crate::testing::Event;

const PDPT_MAP: u64 = label::PDPT_MAP;
const PD_MAP: u64 = label::PAGE_DIRECTORY_MAP;
const PT_MAP: u64 = label::PAGE_TABLE_MAP;
const PDPT_UNMAP: u64 = label::PDPT_UNMAP;
const PD_UNMAP: u64 = label::PAGE_DIRECTORY_UNMAP;
const PT_UNMAP: u64 = label::PAGE_TABLE_UNMAP;
const MAP: u64 = label::FRAME_MAP;
const UNMAP: u64 = label::FRAME_UNMAP;
const REMAP: u64 = label::FRAME_REMAP;

/// Rights words.
const R: u64 = 2;
const W: u64 = 1;
const RWX: u64 = 3;
/// Attributes words.
const WB: u64 = 0;
const X: u64 = Attributes::EXECUTE;
const UC: u64 = 3;
const WC: u64 = 4;

/// PML4 0, PDPT 0, page directory 2, page table 0.
const V: u64 = 0x40_0000;
/// The 2 MiB page after `V`'s page table: page directory entry 3.
const V2: u64 = 0x60_0000;

const ILLEGAL: SyscallError = SyscallError::IllegalOperation;
const TRUNCATED: SyscallError = SyscallError::TruncatedMessage;
const DELETE_FIRST: SyscallError = SyscallError::DeleteFirst;

const fn missing(bits_left: u32) -> SyscallError {
    SyscallError::FailedLookup {
        source: false,
        failure: LookupFailure::MissingCapability { bits_left },
    }
}

/// PDPT0, PD0 and PT0 mapped under PML4 A over `V`, and F0 at `V`,
/// read-write.
fn stocked() -> World {
    let mut w = World::new();
    w.ok(PDPT0, PDPT_MAP, &[V], &[PML4_A]);
    w.ok(PD0, PD_MAP, &[V], &[PML4_A]);
    w.ok(PT0, PT_MAP, &[V], &[PML4_A]);
    w.ok(F0, MAP, &[V, RWX, WB], &[PML4_A]);
    w
}

fn object(w: &World, slot: u64) -> u64 {
    w.root(slot).object()
}

#[test]
fn the_user_range_constants() {
    assert_eq!(USER_MIN, 0x1000);
    assert_eq!(USER_TOP, 0x0000_7FFF_FFFF_F000);
    const _: () = assert!(USER_TOP < 1 << 47);
    assert_eq!(index(USER_TOP - PAGE_4K, 3), 255);
    assert_eq!(KERNEL_HALF, 256..512);
    // The highest frames `docs/abi.md` names.
    assert_eq!(USER_TOP - PAGE_4K, 0x0000_7FFF_FFFF_E000);
    assert_eq!((USER_TOP - PAGE_2M) & !(PAGE_2M - 1), 0x0000_7FFF_FFC0_0000);
}

#[test]
fn mapping_records_round_trip_at_their_extremes() {
    let top = STRUCTURE_LIMIT - 0x2000;
    for (table, vaddr) in [(0x2000, 0), (top, USER_TOP - PAGE_4K), (top, 0x1000)] {
        let m = FrameMapping { table, vaddr };
        let word = m.encode();
        assert_eq!(word >> 59, 0, "the record fits 59 bits");
        assert_eq!(word & 1, 1);
        assert_eq!(FrameMapping::decode(word), Some(m));
    }
    for (parent, index) in [(0x2000, 0), (top, 511)] {
        let m = TableMapping { parent, index };
        let word = m.encode();
        assert_eq!(word >> 33, 0, "the record fits 33 bits");
        assert_eq!(TableMapping::decode(word), Some(m));
    }
    assert_eq!(FrameMapping::decode(0), None);
    assert_eq!(TableMapping::decode(0), None);
}

#[test]
#[should_panic(expected = "cannot be recorded")]
fn a_table_above_the_limit_cannot_be_recorded() {
    let _ = TableMapping {
        parent: STRUCTURE_LIMIT,
        index: 0,
    }
    .encode();
}

#[test]
#[should_panic(expected = "corrupt mapping record")]
fn a_record_without_its_mapped_bit_panics() {
    let _ = FrameMapping::decode(2);
}

#[test]
fn the_attributes_word() {
    let ram: Vec<u64> = (0..32)
        .filter(|w| Attributes::decode(*w, false).is_some())
        .collect();
    assert_eq!(ram, [0, 8]);
    let device: Vec<u64> = (0..32)
        .filter(|w| Attributes::decode(*w, true).is_some())
        .collect();
    assert_eq!(device, [3, 4, 11, 12]);
    for word in [0, 8, 3, 4, 11, 12] {
        let a = Attributes::decode(word, word != 0 && word != 8).unwrap();
        assert_eq!(a.word(), word);
    }
    assert_eq!(Attributes::decode(1 << 63, false), None);
    assert_eq!(Attributes::RAM.word(), 0);
}

#[test]
fn flushes_combine() {
    use Flush::{All, None, Page};
    assert_eq!(None.and(None), None);
    assert_eq!(None.and(Page(1)), Page(1));
    assert_eq!(Page(1).and(None), Page(1));
    assert_eq!(Page(1).and(Page(1)), Page(1));
    assert_eq!(Page(1).and(Page(2)), All);
    assert_eq!(All.and(None), All);
    assert_eq!(None.and(All), All);
}

#[test]
fn map_writes_the_entry_the_back_reference_and_the_record() {
    let w = stocked();
    let (pml4, pdpt, pd, pt) = (
        object(&w, PML4_A),
        object(&w, PDPT0),
        object(&w, PD0),
        object(&w, PT0),
    );
    let m = &w.k.mem;
    for (table, i, child, slot) in [(pml4, 0, pdpt, PDPT0), (pdpt, 0, pd, PD0), (pd, 2, pt, PT0)] {
        assert_eq!(m.entry(table, i), user_table(child));
        assert_eq!(m.backref(table, i), rs(slot).get() | 1);
        let record = TableMapping {
            parent: table,
            index: i,
        };
        assert_eq!(w.root(slot).data, record.encode());
    }
    let access = UserAccess {
        write: true,
        execute: false,
    };
    assert_eq!(
        m.entry(pt, 0),
        user_pte(RAM_4K, access, CacheType::WriteBack)
    );
    assert_eq!(m.backref(pt, 0), rs(F0).get() | 1);
    let record = FrameMapping {
        table: pt,
        vaddr: V,
    };
    assert_eq!(w.root(F0).data, record.encode());
    let t = w.translate(PML4_A, V + 0x123).unwrap();
    assert_eq!(t.phys, RAM_4K + 0x123);
    assert!(t.write && t.user && !t.execute && !t.global);
    assert_eq!(t.cache, CacheType::WriteBack);
    // The other PML4 maps nothing; the kernel half is the kernel's.
    assert_eq!(w.translate(PML4_B, V), None);
    for i in KERNEL_HALF {
        assert_eq!(m.entry(pml4, i), kernel_pml4()[i]);
    }
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn a_map_needs_no_flush() {
    let mut w = World::new();
    w.load(PML4_A);
    w.ok(PDPT0, PDPT_MAP, &[V], &[PML4_A]);
    assert_eq!(w.k.flushes, [Flush::None]);
    w.ok(PD0, PD_MAP, &[V], &[PML4_A]);
    w.ok(PT0, PT_MAP, &[V], &[PML4_A]);
    w.ok(F0, MAP, &[V, RWX, WB], &[PML4_A]);
    assert_eq!(w.k.flushes, [Flush::None]);
    assert_eq!(w.k.tlb.leaves.len(), 0, "nothing was cached before the map");
    w.k.fill_tlb();
    assert_eq!(w.k.tlb.leaves.len(), 1);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn table_map_errors_in_abi_order() {
    let mut w = stocked();
    // The length: one register and the VSpace.
    w.fails(PDPT1, PDPT_MAP, &[], &[PML4_B], TRUNCATED);
    w.fails(PDPT1, PDPT_MAP, &[V], &[], TRUNCATED);
    w.fails(PT1, PT_MAP, &[], &[], TRUNCATED);
    // The VSpace: a PML4 capability, nothing else.
    for not_pml4 in [F0, PDPT1, EP, FREE, SC0] {
        w.fails(
            PDPT1,
            PDPT_MAP,
            &[V],
            &[not_pml4],
            SyscallError::InvalidCapability(1),
        );
    }
    // Mapped already.
    w.fails(
        PDPT0,
        PDPT_MAP,
        &[V],
        &[PML4_B],
        SyscallError::InvalidCapability(0),
    );
    w.fails(
        PT0,
        PT_MAP,
        &[V],
        &[PML4_A],
        SyscallError::InvalidCapability(0),
    );
    // The range: the base of what the structure covers below USER_TOP.
    for (slot, label, vaddr) in [
        (PDPT1, PDPT_MAP, 1 << 47),
        (PDPT1, PDPT_MAP, u64::MAX),
        (PDPT1, PDPT_MAP, 0xFFFF_8000_0000_0000),
        (PD1, PD_MAP, 1 << 47),
        (PT1, PT_MAP, 0x0000_8000_0000_0000),
    ] {
        w.fails(
            slot,
            label,
            &[vaddr],
            &[PML4_A],
            SyscallError::InvalidArgument(0),
        );
    }
    // A missing level: 39 bits left without a PDPT, 30 without a page
    // directory.
    let far = 0x0000_0080_0000_0000; // PML4 entry 1.
    w.fails(PD1, PD_MAP, &[far], &[PML4_A], missing(39));
    w.fails(PT1, PT_MAP, &[far], &[PML4_A], missing(39));
    w.fails(PT1, PT_MAP, &[0x4000_0000], &[PML4_A], missing(30));
    // The entry is taken: a structure, or for a page table a 2 MiB frame.
    w.fails(PDPT1, PDPT_MAP, &[V], &[PML4_A], DELETE_FIRST);
    w.fails(PD1, PD_MAP, &[V], &[PML4_A], DELETE_FIRST);
    w.fails(PT1, PT_MAP, &[V], &[PML4_A], DELETE_FIRST);
    w.ok(G0, MAP, &[V2, RWX, WB], &[PML4_A]);
    w.fails(PT1, PT_MAP, &[V2], &[PML4_A], DELETE_FIRST);
    // Errors that occur together come in the ABI's order.
    w.fails(
        PDPT0,
        PDPT_MAP,
        &[1 << 47],
        &[F0],
        SyscallError::InvalidCapability(1),
    );
    w.fails(
        PDPT0,
        PDPT_MAP,
        &[1 << 47],
        &[PML4_A],
        SyscallError::InvalidCapability(0),
    );
    w.fails(
        PD1,
        PD_MAP,
        &[u64::MAX],
        &[PML4_B],
        SyscallError::InvalidArgument(0),
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn table_maps_ignore_the_low_bits_and_reach_the_top() {
    let mut w = World::new();
    // The highest PDPT, page directory and page table: PML4 entry 255,
    // PDPT entry 511, page directory entry 511.
    let top = USER_TOP - 1;
    w.ok(PDPT0, PDPT_MAP, &[top], &[PML4_A]);
    w.ok(PD0, PD_MAP, &[top], &[PML4_A]);
    w.ok(PT0, PT_MAP, &[top], &[PML4_A]);
    assert_eq!(TableMapping::decode(w.root(PDPT0).data).unwrap().index, 255);
    assert_eq!(TableMapping::decode(w.root(PD0).data).unwrap().index, 511);
    assert_eq!(TableMapping::decode(w.root(PT0).data).unwrap().index, 511);
    // The highest 4 KiB frame maps; the page above it never does.
    w.ok(F0, MAP, &[USER_TOP - PAGE_4K, RWX, WB], &[PML4_A]);
    w.fails(
        F0 + 1,
        MAP,
        &[USER_TOP, RWX, WB],
        &[PML4_A],
        SyscallError::InvalidArgument(0),
    );
    // A page directory mapped through a misaligned address lands on its
    // base.
    w.ok(PDPT1, PDPT_MAP, &[0x1234_5678], &[PML4_A]);
    w.ok(PD1, PD_MAP, &[0x1234_5678], &[PML4_A]);
    assert_eq!(
        TableMapping::decode(w.root(PD1).data),
        Some(TableMapping {
            parent: object(&w, PDPT1),
            index: 0
        })
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn frame_map_errors_in_abi_order() {
    let mut w = stocked();
    let f1 = F0 + 1;
    // The length: three registers and the VSpace.
    w.fails(f1, MAP, &[V + PAGE_4K, RWX], &[PML4_A], TRUNCATED);
    w.fails(f1, MAP, &[V + PAGE_4K, RWX, WB], &[], TRUNCATED);
    for not_pml4 in [F0, PDPT1, EP, FREE] {
        w.fails(
            f1,
            MAP,
            &[V + PAGE_4K, RWX, WB],
            &[not_pml4],
            SyscallError::InvalidCapability(1),
        );
    }
    // Mapped already: map a copy, or use Frame_Remap.
    w.fails(
        F0,
        MAP,
        &[V + PAGE_4K, RWX, WB],
        &[PML4_A],
        SyscallError::InvalidCapability(0),
    );
    // Alignment to the frame's size.
    for vaddr in [V + 1, V + 0x800, V + PAGE_4K + 8] {
        w.fails(
            f1,
            MAP,
            &[vaddr, RWX, WB],
            &[PML4_A],
            SyscallError::AlignmentError,
        );
    }
    w.fails(
        G0,
        MAP,
        &[V2 + PAGE_4K, RWX, WB],
        &[PML4_A],
        SyscallError::AlignmentError,
    );
    // The range: [USER_MIN, USER_TOP - size].
    for (slot, vaddr) in [
        (f1, 0),
        (f1, USER_TOP),
        (f1, 1 << 47),
        (f1, 0xFFFF_FFFF_FFFF_F000),
        (G0, 0),
        (G0, 0x0000_8000_0000_0000),
        (G0, USER_TOP + PAGE_4K - PAGE_2M),
    ] {
        w.fails(
            slot,
            MAP,
            &[vaddr, RWX, WB],
            &[PML4_A],
            SyscallError::InvalidArgument(0),
        );
    }
    // Rights: the request masked by the capability's must include Read.
    for rights in [0, W, 4, 8, 0xFFFF_FFFF_FFFF_FFF0] {
        w.fails(
            f1,
            MAP,
            &[V + PAGE_4K, rights, WB],
            &[PML4_A],
            SyscallError::InvalidArgument(1),
        );
    }
    w.fails(
        FR,
        MAP,
        &[V + PAGE_4K, W, WB],
        &[PML4_A],
        SyscallError::InvalidArgument(1),
    );
    // Attributes: reserved bits, unknown cache types, and the cache types
    // RAM and device frames may not use.
    for attrs in [1, 2, 5, 6, 7, UC, WC, UC | X, 0x10, 1 << 63] {
        w.fails(
            f1,
            MAP,
            &[V + PAGE_4K, RWX, attrs],
            &[PML4_A],
            SyscallError::InvalidArgument(2),
        );
    }
    for attrs in [WB, X, 1, 0x13] {
        w.fails(
            DF,
            MAP,
            &[V + PAGE_4K, RWX, attrs],
            &[PML4_A],
            SyscallError::InvalidArgument(2),
        );
    }
    // A missing level: 39, 30 or 21 bits left; a 2 MiB frame where the
    // page table would be counts as missing.
    w.fails(
        f1,
        MAP,
        &[0x0000_0080_0000_0000, RWX, WB],
        &[PML4_A],
        missing(39),
    );
    w.fails(f1, MAP, &[0x4000_0000, RWX, WB], &[PML4_A], missing(30));
    w.fails(f1, MAP, &[V2, RWX, WB], &[PML4_A], missing(21));
    w.fails(
        G0,
        MAP,
        &[0x0000_0080_0000_0000, RWX, WB],
        &[PML4_A],
        missing(39),
    );
    w.fails(G0, MAP, &[0x4000_0000, RWX, WB], &[PML4_A], missing(30));
    w.ok(G0, MAP, &[V2, RWX, WB], &[PML4_A]);
    w.fails(f1, MAP, &[V2 + PAGE_4K, RWX, WB], &[PML4_A], missing(21));
    // The entry is taken: a frame, or for a 2 MiB frame a page table.
    w.fails(f1, MAP, &[V, RWX, WB], &[PML4_A], DELETE_FIRST);
    w.fails(G1, MAP, &[V2, RWX, WB], &[PML4_A], DELETE_FIRST);
    w.fails(G1, MAP, &[V, RWX, WB], &[PML4_A], DELETE_FIRST);
    // Errors that occur together come in the ABI's order.
    let bad = [0x8000_0000_0001, 0, 0x10];
    w.fails(F0, MAP, &bad, &[EP], SyscallError::InvalidCapability(1));
    w.fails(F0, MAP, &bad, &[PML4_A], SyscallError::InvalidCapability(0));
    w.fails(f1, MAP, &bad, &[PML4_A], SyscallError::AlignmentError);
    w.fails(
        f1,
        MAP,
        &[1 << 47, 0, 0x10],
        &[PML4_A],
        SyscallError::InvalidArgument(0),
    );
    w.fails(
        f1,
        MAP,
        &[V, 0, 0x10],
        &[PML4_A],
        SyscallError::InvalidArgument(1),
    );
    w.fails(
        f1,
        MAP,
        &[0x4000_0000, R, 0x10],
        &[PML4_A],
        SyscallError::InvalidArgument(2),
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn frame_rights_and_attributes_reach_the_entry() {
    let mut w = stocked();
    // A read-only capability asked for read-write maps read-only, silently.
    w.ok(FR, MAP, &[V + PAGE_4K, RWX, X], &[PML4_A]);
    let t = w.translate(PML4_A, V + PAGE_4K).unwrap();
    assert!(!t.write && t.execute && t.user);
    // Bits other than Read and Write in the rights word are ignored.
    w.ok(F0 + 1, MAP, &[V + 2 * PAGE_4K, 0xFFFF_FFF2, WB], &[PML4_A]);
    let t = w.translate(PML4_A, V + 2 * PAGE_4K).unwrap();
    assert!(!t.write && !t.execute);
    // Device frames: uncached and write-combining, 4 KiB and 2 MiB.
    w.ok(DF, MAP, &[V + 3 * PAGE_4K, RWX, WC], &[PML4_A]);
    let t = w.translate(PML4_A, V + 3 * PAGE_4K).unwrap();
    assert_eq!((t.phys, t.cache), (DEV_4K, CacheType::WriteCombining));
    w.ok(DG, MAP, &[V2, RWX, UC | X], &[PML4_A]);
    let t = w.translate(PML4_A, V2 + 0x1_2345).unwrap();
    assert_eq!(t.phys, DEV_2M + 0x1_2345);
    assert_eq!((t.page_size, t.cache), (PAGE_2M, CacheType::Uncached));
    assert!(t.write && t.execute && !t.global);
    // The lowest page maps.
    w.ok(PDPT1, PDPT_MAP, &[0], &[PML4_B]);
    w.ok(PD1, PD_MAP, &[0], &[PML4_B]);
    w.ok(PT1, PT_MAP, &[0], &[PML4_B]);
    w.ok(F0 + 2, MAP, &[USER_MIN, R, WB], &[PML4_B]);
    assert_eq!(
        w.translate(PML4_B, USER_MIN).unwrap().phys,
        RAM_4K + 2 * PAGE_4K
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn remap_errors_and_effects() {
    let mut w = stocked();
    w.load(PML4_A);
    w.fails(F0, REMAP, &[R], &[], TRUNCATED);
    w.fails(F0 + 1, REMAP, &[R, WB], &[], ILLEGAL);
    w.fails(F0 + 1, REMAP, &[0, 0x10], &[], ILLEGAL);
    w.fails(F0, REMAP, &[W, WB], &[], SyscallError::InvalidArgument(0));
    w.fails(F0, REMAP, &[0, 0x10], &[], SyscallError::InvalidArgument(0));
    w.fails(F0, REMAP, &[R, UC], &[], SyscallError::InvalidArgument(1));
    // An ELF loader maps writable, fills, then remaps read-execute.
    w.k.fill_tlb();
    assert!(w.k.tlb.leaves.contains_key(&(V, PAGE_4K)));
    w.ok(F0, REMAP, &[R, X], &[]);
    assert_eq!(w.k.flushes, [Flush::Page(V)]);
    let t = w.translate(PML4_A, V).unwrap();
    assert!(!t.write && t.execute);
    // The record is unchanged.
    assert_eq!(
        FrameMapping::decode(w.root(F0).data),
        Some(FrameMapping {
            table: object(&w, PT0),
            vaddr: V
        })
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn a_label_of_another_type_or_level_is_illegal_before_the_length() {
    let mut w = stocked();
    // Every paging label, the reserved ones at each end of their ranges,
    // and others.
    let labels: Vec<u64> = (0x40..=0x46)
        .chain(0x4F..=0x54)
        .chain([0x3F, 0x5F, 0x60, 0, 1, 0x10, u64::MAX])
        .collect();
    let own: [(u64, &[u64]); 8] = [
        (PDPT0, &[PDPT_MAP, PDPT_UNMAP]),
        (PDPT1, &[PDPT_MAP, PDPT_UNMAP]),
        (PD1, &[PD_MAP, PD_UNMAP]),
        (PT1, &[PT_MAP, PT_UNMAP]),
        (F0 + 1, &[MAP, UNMAP, REMAP]),
        (G1, &[MAP, UNMAP, REMAP]),
        (PML4_A, &[]),
        (PML4_B, &[]),
    ];
    for (slot, own) in own {
        for &l in &labels {
            if own.contains(&l) {
                continue;
            }
            for (mrs, extra) in [(&[][..], &[][..]), (&[V, RWX, WB][..], &[PML4_B][..])] {
                w.fails(slot, l, mrs, extra, ILLEGAL);
            }
        }
    }
    // Frame_GetAddress is M9's.
    w.fails(F0, label::FRAME_GET_ADDRESS, &[], &[], ILLEGAL);
    // An empty slot is InvalidCapability 0 whatever the label.
    w.fails(FREE, MAP, &[], &[], SyscallError::InvalidCapability(0));
}

#[test]
fn frame_unmap_clears_both_sides_and_flushes_the_page() {
    let mut w = stocked();
    w.load(PML4_A);
    let pt = object(&w, PT0);
    w.ok(F0, UNMAP, &[], &[]);
    assert_eq!(w.k.flushes, [Flush::Page(V)]);
    assert_eq!((w.k.mem.entry(pt, 0), w.k.mem.backref(pt, 0)), (0, 0));
    assert_eq!(w.root(F0).data, 0);
    assert_eq!(w.translate(PML4_A, V), None);
    // Unmapped: nothing to do, nothing to flush; extra words are ignored.
    w.ok(F0, UNMAP, &[1, 2, 3], &[EP]);
    assert_eq!(w.k.flushes, [Flush::None]);
    // And it maps again, at another address.
    w.ok(F0, MAP, &[V + PAGE_4K, RWX, WB], &[PML4_A]);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn table_unmap_detaches_then_empties() {
    let mut w = stocked();
    w.load(PML4_A);
    w.ok(F0 + 1, MAP, &[V + PAGE_4K, RWX, WB], &[PML4_A]);
    w.ok(G0, MAP, &[V2, RWX, WB], &[PML4_A]);
    let (pdpt, pd, pt) = (object(&w, PDPT0), object(&w, PD0), object(&w, PT0));
    w.ok(PD0, PD_UNMAP, &[], &[]);
    assert_eq!(w.k.flushes, [Flush::All]);
    assert_eq!((w.k.mem.entry(pdpt, 0), w.k.mem.backref(pdpt, 0)), (0, 0));
    for slot in [PD0, PT0, G0] {
        assert_eq!(w.root(slot).data, 0, "root slot {slot} is unmapped");
    }
    assert!((0..512).all(|i| w.k.mem.entry(pd, i) == 0 && w.k.mem.backref(pd, i) == 0));
    // The page table keeps its own entries, unreachable: an orphan.
    assert_ne!(w.root(F0).data, 0);
    assert_ne!(w.k.mem.entry(pt, 1), 0);
    assert_eq!(w.translate(PML4_A, V), None);
    // Map refuses the orphan until its own Unmap empties it.
    w.ok(PD0, PD_MAP, &[V], &[PML4_A]);
    w.fails(
        PT0,
        PT_MAP,
        &[V],
        &[PML4_A],
        SyscallError::InvalidCapability(0),
    );
    w.ok(PT0, PT_UNMAP, &[], &[]);
    assert_eq!(w.k.flushes, [Flush::All]);
    assert_eq!((w.root(F0).data, w.root(F0 + 1).data), (0, 0));
    // An unmapped, empty structure: nothing to do.
    w.ok(PT0, PT_UNMAP, &[], &[]);
    assert_eq!(w.k.flushes, [Flush::None]);
    w.ok(PT0, PT_MAP, &[V], &[PML4_A]);
    w.ok(F0, MAP, &[V, R, WB], &[PML4_A]);
    // A PDPT's Unmap empties it too.
    w.ok(PDPT0, PDPT_UNMAP, &[], &[]);
    assert_eq!(w.k.flushes, [Flush::All]);
    assert_eq!((w.root(PDPT0).data, w.root(PD0).data), (0, 0));
    assert_eq!(w.translate(PML4_A, V), None);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn deleting_a_mapped_frame_or_structure_unmaps_it() {
    let mut w = stocked();
    w.load(PML4_A);
    w.ok(G0, MAP, &[V2, RWX, WB], &[PML4_A]);
    // A frame unmaps on every deletion, its copies' included; a copy
    // starts unmapped.
    cnode::copy(&mut w.k, rs(F0), rs(FREE), RWX).unwrap();
    assert_eq!(w.cap(rs(FREE)).data, 0);
    w.k.flushes.clear();
    cnode::delete(&mut w.k, rs(FREE)).unwrap();
    assert_eq!(w.k.flushes, [Flush::None]);
    check(&w.k).unwrap();
    w.k.fill_tlb();
    cnode::delete(&mut w.k, rs(F0)).unwrap();
    assert_eq!(w.k.flushes, [Flush::None, Flush::Page(V)]);
    assert_eq!(w.translate(PML4_A, V), None);
    check(&w.k).unwrap();
    // A structure's only capability: detach, then empty.
    w.ok(F0 + 1, MAP, &[V, RWX, WB], &[PML4_A]);
    w.k.fill_tlb();
    w.k.flushes.clear();
    cnode::delete(&mut w.k, rs(PD0)).unwrap();
    assert_eq!(w.k.flushes, [Flush::All]);
    assert_eq!(w.root(G0).data, 0);
    assert_eq!(w.root(PT0).data, 0);
    assert_ne!(
        w.root(F0 + 1).data,
        0,
        "the orphan page table keeps its entry"
    );
    check(&w.k).unwrap();
    assert!(w.k.events.iter().any(|e| matches!(
        e,
        Event::Finalise { cap, last: true } if cap.cap_type() == CapType::PageDirectory
    )));
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn deleting_a_vspace_unmaps_its_pdpts_only_with_its_last_capability() {
    let mut w = stocked();
    let pml4 = object(&w, PML4_A);
    w.ok(PDPT1, PDPT_MAP, &[1 << 39], &[PML4_A]);
    w.load(PML4_A);
    w.k.fill_tlb();
    cnode::copy(&mut w.k, rs(PML4_A), rs(FREE), 0).unwrap();
    w.k.flushes.clear();
    cnode::delete(&mut w.k, rs(PML4_A)).unwrap();
    assert_eq!(w.k.flushes, [Flush::None]);
    assert_eq!(w.k.loaded, Some(pml4), "not the last capability: nothing");
    assert_ne!(w.root(PDPT0).data, 0);
    check(&w.k).unwrap();
    // The last one: the kernel PML4 is loaded first, then the PDPTs named
    // by entries 0 to 255 are unmapped; lower levels keep their entries.
    cnode::delete(&mut w.k, rs(FREE)).unwrap();
    assert_eq!(w.k.loaded, None);
    // The CR3 write is the flush.
    assert_eq!(w.k.flushes, [Flush::None, Flush::None]);
    assert_eq!((w.root(PDPT0).data, w.root(PDPT1).data), (0, 0));
    assert_ne!(w.root(PD0).data, 0, "the PDPT keeps its entry");
    assert!((0..256).all(|i| w.k.mem.entry(pml4, i) == 0 && w.k.mem.backref(pml4, i) == 0));
    check(&w.k).unwrap();
    // The orphan PDPT cannot be mapped until it is emptied.
    w.fails(
        PDPT0,
        PDPT_MAP,
        &[V],
        &[PML4_B],
        SyscallError::InvalidCapability(0),
    );
    w.ok(PDPT0, PDPT_UNMAP, &[], &[]);
    w.ok(PDPT0, PDPT_MAP, &[V], &[PML4_B]);
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn moves_rotates_and_swaps_rewrite_back_references() {
    let mut w = stocked();
    w.load(PML4_A);
    w.ok(G0, MAP, &[V2, RWX, WB], &[PML4_A]);
    let pt = object(&w, PT0);
    cnode::move_cap(&mut w.k, rs(F0), rs(FREE)).unwrap();
    assert_eq!(w.k.mem.backref(pt, 0), rs(FREE).get() | 1);
    check(&w.k).unwrap();
    cnode::mutate(&mut w.k, rs(FREE), rs(FREE + 1), 0x55).unwrap();
    assert_eq!(w.k.mem.backref(pt, 0), rs(FREE + 1).get() | 1);
    check(&w.k).unwrap();
    // A swap of two mapped capabilities.
    cnode::rotate(&mut w.k, rs(G0), 0, rs(PT0), 0, rs(G0)).unwrap();
    check(&w.k).unwrap();
    assert_eq!(w.root(G0).cap_type(), CapType::PageTable);
    // A rotate through three slots: the page table to a free slot, the 2
    // MiB frame to the pivot.
    cnode::rotate(&mut w.k, rs(FREE + 2), 0, rs(G0), 0, rs(PT0)).unwrap();
    check(&w.k).unwrap();
    assert!(w.k.flushes.iter().all(|f| *f == Flush::None));
    // Every link still works from its new slot.
    w.ok(FREE + 1, UNMAP, &[], &[]);
    w.ok(FREE + 2, PT_UNMAP, &[], &[]);
    w.ok(G0, UNMAP, &[], &[]);
    assert!(w.k.tlb.leaves.is_empty());
}

#[test]
fn a_nested_cnode_deletion_swaps_and_unmaps_mapped_capabilities() {
    let mut w = stocked();
    w.load(PML4_A);
    w.ok(F0 + 1, MAP, &[V + PAGE_4K, RWX, WB], &[PML4_A]);
    w.ok(F0 + 2, MAP, &[V + 2 * PAGE_4K, RWX, WB], &[PML4_A]);
    // C0 holds F0 in slot 0 and C1's only capability in slot 1; C1 holds
    // F1 in its slot 0, which the nested deletion swaps out, and F2 in
    // slot 2, which stays with C1, unreachable.
    cnode::move_cap(&mut w.k, rs(F0), cs(C0, 0)).unwrap();
    cnode::move_cap(&mut w.k, rs(SC1), cs(C0, 1)).unwrap();
    cnode::move_cap(&mut w.k, rs(F0 + 1), cs(C1, 0)).unwrap();
    cnode::move_cap(&mut w.k, rs(F0 + 2), cs(C1, 2)).unwrap();
    check(&w.k).unwrap();
    w.k.events.clear();
    w.k.fill_tlb();
    cnode::delete(&mut w.k, rs(SC0)).unwrap();
    check(&w.k).unwrap();
    let moved_f1 = w.k.events.iter().any(|e| {
        matches!(
            e,
            Event::Moved { cap, from, .. } if *from == cs(C1, 0) && cap.cap_type() == CapType::Frame
        )
    });
    assert!(moved_f1, "{:x?}", w.k.events);
    assert_eq!(w.translate(PML4_A, V), None);
    assert_eq!(w.translate(PML4_A, V + PAGE_4K), None);
    assert!(w.translate(PML4_A, V + 2 * PAGE_4K).is_some());
    assert_eq!(w.cap(cs(C1, 0)).cap_type(), CapType::Zombie);
    // A revoke of their untyped would reach C1's Zombie and finish it.
    cnode::delete(&mut w.k, cs(C1, 0)).unwrap();
    check(&w.k).unwrap();
    assert_eq!(w.translate(PML4_A, V + 2 * PAGE_4K), None);
    assert!(w.k.tlb.leaves.is_empty());
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn a_preempted_revoke_leaves_every_link_whole() {
    let base = stocked();
    let mut points = 0;
    for n in 0.. {
        let mut w = base.clone();
        w.ok(F0 + 1, MAP, &[V + PAGE_4K, RWX, WB], &[PML4_A]);
        for i in 0..3 {
            cnode::copy(&mut w.k, rs(F0), rs(FREE + i), RWX).unwrap();
        }
        cnode::move_cap(&mut w.k, rs(F0 + 1), rs(FREE + 3)).unwrap();
        // F0 + 1 is no child of F0, so the revoke leaves it.
        w.load(PML4_A);
        w.k.preempt_in = Some(n);
        let mut done = false;
        while !done {
            w.k.fill_tlb();
            done = cnode::revoke(&mut w.k, rs(F0)).is_ok();
            check(&w.k).unwrap();
            points += 1;
        }
        if w.k.preempt_in.is_some() {
            break;
        }
        assert_ne!(w.root(F0).data, 0, "the revoked capability stays mapped");
        assert!((0..3).all(|i| w.cap(rs(FREE + i)).is_null()));
        assert_ne!(w.cap(rs(FREE + 3)).data, 0);
    }
    assert!(points > 3);
}

/// Each corruption of one side of a link, then the operation that uses
/// it; every one must panic rather than write.
fn broken(corrupt: impl FnOnce(&mut World), then: impl FnOnce(&mut World)) {
    let mut w = stocked();
    w.ok(G0, MAP, &[V2, RWX, WB], &[PML4_A]);
    corrupt(&mut w);
    then(&mut w);
}

#[test]
#[should_panic(expected = "broken paging link")]
fn unmap_through_a_back_reference_naming_another_slot_panics() {
    broken(
        |w| {
            let pt = object(w, PT0);
            w.k.mem.set_backref(pt, 0, rs(FREE).get() | 1);
        },
        |w| {
            let _ = w.call(rs(F0), UNMAP, &[], &[]);
        },
    );
}

#[test]
#[should_panic(expected = "broken paging link")]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn remap_of_an_entry_pointing_elsewhere_panics() {
    broken(
        |w| {
            let pt = object(w, PT0);
            let e = w.k.mem.entry(pt, 0);
            w.k.mem.set_entry(pt, 0, e + PAGE_4K);
        },
        |w| {
            let _ = w.call(rs(F0), REMAP, &[R, WB], &[]);
        },
    );
}

#[test]
#[should_panic(expected = "broken paging link")]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn a_record_naming_another_entry_panics() {
    broken(
        |w| {
            let mut s = w.k.load(rs(F0));
            let m = FrameMapping {
                table: object(w, PT0),
                vaddr: V + PAGE_4K,
            };
            s.cap = s.cap.with_data(m.encode());
            w.k.store(rs(F0), s);
        },
        |w| {
            let _ = w.call(rs(F0), UNMAP, &[], &[]);
        },
    );
}

#[test]
#[should_panic(expected = "without a back-reference")]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn a_walk_through_an_entry_without_a_back_reference_panics() {
    broken(
        |w| {
            let pml4 = object(w, PML4_A);
            w.k.mem.set_backref(pml4, 0, 0);
        },
        |w| {
            let _ = w.call(rs(F0 + 1), MAP, &[V + PAGE_4K, RWX, WB], &[rs(PML4_A)]);
        },
    );
}

#[test]
#[should_panic(expected = "broken paging link")]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn emptying_a_table_whose_back_reference_names_the_wrong_capability_panics() {
    broken(
        |w| {
            // Entry 2 of PD0 names PT0's slot, but G0's slot holds the
            // record for entry 3, which now names PT0's slot.
            let pd = object(w, PD0);
            w.k.mem.set_backref(pd, 3, rs(PT0).get() | 1);
        },
        |w| {
            let _ = w.call(rs(PD0), PD_UNMAP, &[], &[]);
        },
    );
}

#[test]
#[should_panic(expected = "broken paging link")]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn a_move_from_a_slot_the_back_reference_does_not_name_panics() {
    broken(
        |_| {},
        |w| {
            let cap = w.root(F0);
            let _ = paging::moved(&mut w.k, cap, rs(FREE), rs(F0));
        },
    );
}

#[test]
#[should_panic(expected = "names no slot holding it")]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn finalising_a_capability_its_back_reference_does_not_name_panics() {
    broken(
        |_| {},
        |w| {
            let cap = w.root(F0).with_rights(Rights::READ);
            let _ = paging::finalise(&mut w.k, cap, false);
        },
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn the_tlb_model_catches_a_missing_flush() {
    let mut w = stocked();
    w.load(PML4_A);
    w.k.fill_tlb();
    check(&w.k).unwrap();
    // A leaf made read-only without `invlpg`.
    let pt = object(&w, PT0);
    let e = w.k.mem.entry(pt, 0);
    w.k.mem.set_entry(pt, 0, e & !super::RW);
    assert!(check_tlb(&w.k).is_err());
    w.k.apply(Flush::Page(V + 0x10));
    check_tlb(&w.k).unwrap();
    // A page table detached with only an `invlpg` of another page: its
    // leaves stay cached.
    w.k.fill_tlb();
    let pd = object(&w, PD0);
    w.k.mem.set_entry(pd, 2, 0);
    w.k.apply(Flush::Page(V2));
    assert!(check_tlb(&w.k).is_err());
    w.k.apply(Flush::All);
    check_tlb(&w.k).unwrap();
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn a_new_pml4_gets_the_kernel_half_and_nothing_else() {
    let mut w = World::new();
    let t = structure(8);
    paging::init_pml4(&mut w.k, t, &kernel_pml4());
    for i in 0..512 {
        let want = if i >= 256 { kernel_pml4()[i] } else { 0 };
        assert_eq!(w.k.mem.entry(t, i), want);
        assert_eq!(w.k.mem.backref(t, i), 0);
    }
    // Retype calls it through `init_object`.
    let mut k = Space::new();
    k.init_object(structure_cap(CapType::Pml4, structure(7)));
    assert_eq!(k.mem.entry(structure(7), 511), kernel_pml4()[511]);
}

#[test]
fn boot_counts_the_tables_a_span_needs() {
    let span = |start, end| Span { start, end };
    // An 8 MiB image at 0x40_0000 and the three pages after it.
    let image = span(0x40_0000, 0x40_0000 + (8 << 20) + 3 * PAGE_4K);
    assert_eq!(
        TableCounts::covering(image),
        TableCounts {
            pdpts: 1,
            pds: 1,
            pts: 5
        }
    );
    // The worst 8 MiB span and its three pages: across a 512 GiB
    // boundary, from the last page of a 2 MiB block.
    let edge = 1u64 << 39;
    let worst = span(
        edge - 2 * PAGE_2M - PAGE_4K,
        edge + 2 * PAGE_2M + 2 * PAGE_4K,
    );
    assert_eq!(worst.end - worst.start, (8 << 20) + 3 * PAGE_4K);
    assert_eq!(
        TableCounts::covering(worst),
        TableCounts {
            pdpts: 2,
            pds: 2,
            pts: 6
        }
    );
    assert_eq!(TableCounts::covering(span(V, V)), TableCounts::default());
    assert_eq!(
        TableCounts::covering(span(V, V + PAGE_4K)),
        TableCounts {
            pdpts: 1,
            pds: 1,
            pts: 1
        }
    );
}

#[test]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn boot_maps_the_root_vspace() {
    let mut w = World::new();
    // Across a 1 GiB boundary: one PDPT, two page directories, two page
    // tables.
    let start = 0x4000_0000 - 2 * PAGE_4K;
    let span = Span {
        start,
        end: start + 4 * PAGE_4K,
    };
    let counts = TableCounts::covering(span);
    assert_eq!((counts.pdpts, counts.pds, counts.pts), (1, 2, 2));
    paging::map_boot_tables(
        &mut w.k,
        rs(PML4_A),
        span,
        [PDPT0, PD0, PD1, PT0, PT1].map(rs),
    );
    check(&w.k).unwrap();
    for (i, access) in [
        (0, (false, true)),
        (1, (false, false)),
        (2, (true, false)),
        (3, (true, false)),
    ] {
        let access = UserAccess {
            write: access.0,
            execute: access.1,
        };
        paging::map_boot_frame(
            &mut w.k,
            rs(F0 + i),
            rs(PML4_A),
            start + i * PAGE_4K,
            access,
        );
        let t = w.translate(PML4_A, start + i * PAGE_4K).unwrap();
        assert_eq!((t.write, t.execute), (access.write, access.execute));
    }
    check(&w.k).unwrap();
}

#[test]
#[should_panic(expected = "boot:")]
fn boot_refuses_tables_in_the_wrong_order() {
    let mut w = World::new();
    let span = Span {
        start: V,
        end: V + PAGE_4K,
    };
    paging::map_boot_tables(&mut w.k, rs(PML4_A), span, [PD0, PDPT0, PT0].map(rs));
}

#[test]
#[should_panic(expected = "too few paging structures")]
#[cfg_attr(miri, ignore = "slow under Miri, and safe code: run natively")]
fn boot_refuses_too_few_tables() {
    let mut w = World::new();
    let span = Span {
        start: V,
        end: V + PAGE_4K,
    };
    paging::map_boot_tables(&mut w.k, rs(PML4_A), span, [PDPT0, PD0].map(rs));
}

#[test]
fn errors_convert_into_invoke_errors() {
    let mut w = World::new();
    let r = w.call(rs(PT0), PT_MAP, &[V], &[rs(PML4_A)]);
    assert_eq!(r, Err(InvokeError::Error(missing(39))));
    let f: Cap = w.root(F0);
    assert_eq!(paging::link_of(&f), None);
}
