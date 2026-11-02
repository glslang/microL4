//! Host tests of the root image checks and the root VSpace layout.

use std::collections::BTreeSet;
use std::vec::Vec;

use proptest::prelude::*;

use super::*;
use crate::boot::{BootInput, UntypedSummary, plan, root_cap, slot_plan};
use crate::bootinfo::{NUM_INITIAL_SLOTS, SlotRegion};
use crate::cap::{FRAME_4K_BITS, PAGING_STRUCTURE_BITS};
use crate::elf::{PF_R, PF_W, PF_X};
use crate::handoff::{Framebuffer, MemoryRegion, RegionKind};
use crate::window::DeviceWindow;

const K4: u64 = 4096;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

const X: u32 = PF_R | PF_X;
const R: u32 = PF_R;
const W: u32 = PF_R | PF_W;

const EHDR: usize = 64;
const PHDR: usize = 56;

#[derive(Clone, Copy, Debug)]
struct Seg {
    flags: u32,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
}

const fn seg(flags: u32, vaddr: u64, filesz: u64, memsz: u64) -> Seg {
    Seg {
        flags,
        vaddr,
        filesz,
        memsz,
    }
}

/// The byte a test image holds at virtual address `v`, so that a frame's
/// contents can be checked byte by byte.
fn byte_at(v: u64) -> u8 {
    (v ^ (v >> 8) ^ (v >> 17) ^ 0x5A) as u8
}

/// An x86_64 `ET_EXEC` with one `PT_LOAD` per segment, its file bytes
/// following the program headers, plus a `PT_GNU_STACK`.
fn elf(entry: u64, segs: &[Seg]) -> Vec<u8> {
    let phnum = segs.len() + 1;
    let mut f = std::vec![0u8; EHDR + PHDR * phnum];
    f[0..4].copy_from_slice(b"\x7fELF");
    f[4] = 2; // 64-bit
    f[5] = 1; // little-endian
    f[6] = 1;
    f[16..18].copy_from_slice(&2u16.to_le_bytes()); // ET_EXEC
    f[18..20].copy_from_slice(&62u16.to_le_bytes()); // x86_64
    f[20..24].copy_from_slice(&1u32.to_le_bytes());
    f[24..32].copy_from_slice(&entry.to_le_bytes());
    f[32..40].copy_from_slice(&(EHDR as u64).to_le_bytes());
    f[52..54].copy_from_slice(&(EHDR as u16).to_le_bytes());
    f[54..56].copy_from_slice(&(PHDR as u16).to_le_bytes());
    f[56..58].copy_from_slice(&(phnum as u16).to_le_bytes());
    for (i, s) in segs.iter().enumerate() {
        let offset = f.len() as u64;
        f.extend((0..s.filesz).map(|k| byte_at(s.vaddr + k)));
        let h = &mut f[EHDR + PHDR * i..][..PHDR];
        h[0..4].copy_from_slice(&1u32.to_le_bytes()); // PT_LOAD
        h[4..8].copy_from_slice(&s.flags.to_le_bytes());
        h[8..16].copy_from_slice(&offset.to_le_bytes());
        h[16..24].copy_from_slice(&s.vaddr.to_le_bytes());
        h[24..32].copy_from_slice(&s.vaddr.to_le_bytes());
        h[32..40].copy_from_slice(&s.filesz.to_le_bytes());
        h[40..48].copy_from_slice(&s.memsz.to_le_bytes());
        h[48..56].copy_from_slice(&K4.to_le_bytes());
    }
    let stack = &mut f[EHDR + PHDR * segs.len()..][..PHDR];
    stack[0..4].copy_from_slice(&0x6474_e551u32.to_le_bytes());
    stack[4..8].copy_from_slice(&W.to_le_bytes());
    f
}

fn check(entry: u64, segs: &[Seg]) -> Result<(Vec<u8>, RootNeeds), RootImageError> {
    let file = elf(entry, segs);
    let needs = RootImage::check(&file)?.needs();
    Ok((file, needs))
}

fn span(start: u64, end: u64) -> Span {
    Span { start, end }
}

fn access(flags: u32) -> UserAccess {
    UserAccess {
        write: flags & PF_W != 0,
        execute: flags & PF_X != 0,
    }
}

/// `image`'s frames as loaded: each covered page's 4 KiB, file bytes at
/// their offset and zero elsewhere.
fn loaded(image: &RootImage) -> Vec<(u64, UserAccess, Vec<u8>)> {
    image
        .pages()
        .map(|p| {
            assert!(p.offset + p.bytes.len() <= K4 as usize, "{p:?}");
            let mut frame = std::vec![0u8; K4 as usize];
            frame[p.offset..p.offset + p.bytes.len()].copy_from_slice(p.bytes);
            (p.vaddr, p.access, frame)
        })
        .collect()
}

/// The same pages computed byte by byte from the segments: what a page
/// holds is the file byte if a segment's file part covers it, else 0.
fn expected(segs: &[Seg]) -> Vec<(u64, UserAccess, Vec<u8>)> {
    let mut pages: Vec<u64> = segs
        .iter()
        .filter(|s| s.memsz > 0)
        .flat_map(|s| (s.vaddr & !(K4 - 1)..s.vaddr + s.memsz).step_by(K4 as usize))
        .collect();
    pages.sort();
    pages.dedup();
    pages
        .into_iter()
        .map(|v| {
            let s = segs
                .iter()
                .find(|s| s.vaddr & !(K4 - 1) <= v && v < s.vaddr + s.memsz)
                .unwrap();
            let mut frame = std::vec![0u8; K4 as usize];
            for a in v.max(s.vaddr)..(v + K4).min(s.vaddr + s.filesz) {
                frame[(a - v) as usize] = byte_at(a);
            }
            (v, access(s.flags), frame)
        })
        .collect()
}

/// The paging structures counted page by page: every 512 GiB, 1 GiB and
/// 2 MiB that some page of `mapped` lies in.
fn counted(mapped: Span) -> (u64, u64, u64) {
    let mut sets = [BTreeSet::new(), BTreeSet::new(), BTreeSet::new()];
    let mut v = mapped.start;
    while v < mapped.end {
        sets[0].insert(v >> 39);
        sets[1].insert(v >> 30);
        sets[2].insert(v >> 21);
        v += K4;
    }
    (
        sets[0].len() as u64,
        sets[1].len() as u64,
        sets[2].len() as u64,
    )
}

// ---------------------------------------------------------------------
// The checks.

/// A small image laid out as `user/link.ld` lays out root: text, rodata,
/// data and `.bss`, a guard page, then the stack.
fn typical() -> Vec<Seg> {
    std::vec![
        seg(X, 0x40_0000, 0x1830, 0x1830),
        seg(R, 0x40_2000, 0x123, 0x123),
        seg(W, 0x40_3000, 0x10, 0x1100),
        seg(W, 0x40_6000, 0, 0x2000),
    ]
}

#[test]
fn a_typical_image() {
    let segs = typical();
    let file = elf(0x40_0010, &segs);
    let image = RootImage::check(&file).unwrap();
    assert_eq!(image.entry(), 0x40_0010);
    assert_eq!(image.image(), span(0x40_0000, 0x40_8000));
    assert_eq!(image.ipc_buffer(), 0x40_8000);
    assert_eq!(image.bootinfo(), 0x40_9000);
    assert_eq!(image.mapped(), span(0x40_0000, 0x40_B000));
    assert_eq!(loaded(&image), expected(&segs));
    let vaddrs: Vec<u64> = image.pages().map(|p| p.vaddr).collect();
    // 0x405000, between `.bss` and the stack, is the guard page.
    assert_eq!(
        vaddrs,
        [
            0x40_0000, 0x40_1000, 0x40_2000, 0x40_3000, 0x40_4000, 0x40_6000, 0x40_7000
        ]
    );
    let p: Vec<ImagePage> = image.pages().collect();
    assert_eq!((p[1].offset, p[1].bytes.len()), (0, 0x830));
    assert_eq!((p[3].offset, p[3].bytes.len()), (0, 0x10));
    assert!(p[4].bytes.is_empty() && p[5].bytes.is_empty());
    assert_eq!(
        image.needs(),
        RootNeeds {
            tcb: true,
            pml4: true,
            pdpts: 1,
            pds: 1,
            pts: 1,
            image_frames: 7,
            hypervisor: None,
        }
    );
    let r = image.entry_regs();
    assert_eq!((r.next_ip, r.rdi, r.rflags), (0x40_0010, 0x40_9000, 0x202));
    assert_eq!(r.exit(), crate::regs::Exit::Iret);
    assert_eq!(
        Regs {
            next_ip: 0,
            rdi: 0,
            rflags: 0,
            exit: 0,
            ..r
        },
        Regs::default(),
        "every other register is 0"
    );
}

#[test]
fn a_page_between_segments_gets_no_frame() {
    let segs = [seg(X, 0x40_0000, 0x10, 0x10), seg(W, 0x40_3800, 0x10, 0x10)];
    let file = elf(0x40_0000, &segs);
    let image = RootImage::check(&file).unwrap();
    assert_eq!(image.image(), span(0x40_0000, 0x40_4000));
    let pages: Vec<ImagePage> = image.pages().collect();
    assert_eq!(pages.len(), 2);
    assert_eq!(pages[0].vaddr, 0x40_0000);
    assert_eq!(pages[1].vaddr, 0x40_3000);
    // A segment that starts inside its page puts its bytes at that offset.
    assert_eq!((pages[1].offset, pages[1].bytes.len()), (0x800, 0x10));
    assert_eq!(pages[1].bytes[0], byte_at(0x40_3800));
    assert_eq!(image.image_frames(), 2);
    assert_eq!(loaded(&image), expected(&segs));
}

#[test]
fn segments_are_found_whatever_their_order_in_the_file() {
    let segs = [seg(W, 0x40_2000, 0x10, 0x10), seg(X, 0x40_0000, 0x10, 0x10)];
    let file = elf(0x40_0000, &segs);
    let image = RootImage::check(&file).unwrap();
    assert_eq!(loaded(&image), expected(&segs));
    assert_eq!(image.pages().next().unwrap().access, access(X));
}

#[test]
fn a_writable_and_executable_segment_is_refused() {
    let segs = [
        seg(X, 0x40_0000, 0x10, 0x10),
        seg(PF_R | PF_W | PF_X, 0x40_1000, 0x10, 0x10),
    ];
    assert_eq!(
        check(0x40_0000, &segs).unwrap_err(),
        RootImageError::WritableAndExecutable { vaddr: 0x40_1000 }
    );
    // Without PF_R too.
    let segs = [seg(PF_W | PF_X, 0x40_0000, 0x10, 0x10)];
    assert!(matches!(
        check(0x40_0000, &segs),
        Err(RootImageError::WritableAndExecutable { .. })
    ));
}

#[test]
fn segments_must_lie_inside_the_user_range() {
    let refused = |segs: &[Seg], entry| match check(entry, segs) {
        Err(RootImageError::OutsideUserRange { start, end }) => (start, end),
        other => panic!("{segs:?}: {other:?}"),
    };
    // Page 0 never maps, even for a segment that starts inside it.
    assert_eq!(refused(&[seg(X, 0, 0x10, 0x10)], 0), (0, K4));
    assert_eq!(refused(&[seg(X, 0x800, 0x10, 0x900)], 0x800), (0, 2 * K4));
    assert!(check(USER_MIN, &[seg(X, USER_MIN, 0x10, 0x10)]).is_ok());
    // The image may end at USER_TOP - 12 KiB, no later.
    let top = ROOT_IMAGE_TOP;
    assert_eq!(top, 0x7FFF_FFFF_C000);
    let at_top = [seg(X, top - 2 * K4, 0x10, 2 * K4)];
    let file = elf(top - 2 * K4, &at_top);
    let image = RootImage::check(&file).unwrap();
    assert_eq!(image.mapped().end, USER_TOP);
    assert_eq!(image.bootinfo() + 2 * K4, USER_TOP);
    assert_eq!(
        refused(&[seg(X, top - 2 * K4, 0x10, 2 * K4 + 1)], top - 2 * K4),
        (top - 2 * K4, top + K4)
    );
    assert_eq!(
        refused(&[seg(X, USER_TOP - K4, 0x10, 0x10)], USER_TOP - K4),
        (USER_TOP - K4, USER_TOP)
    );
    // One segment out of range is enough, in any position.
    assert_eq!(
        refused(
            &[seg(X, 0x40_0000, 0x10, 0x10), seg(W, 1 << 47, 0x10, 0x10)],
            0x40_0000
        ),
        (1 << 47, (1 << 47) + K4)
    );
    let kernel = 0xFFFF_FFFF_8000_0000;
    assert_eq!(
        refused(&[seg(X, kernel, 0x10, 0x10)], kernel),
        (kernel, kernel + K4)
    );
}

#[test]
fn the_segments_span_at_most_8_mib() {
    let base = 0x40_0000;
    let segs = |end| {
        [
            seg(X, base, 0x10, 0x10),
            seg(W, base + K4, 0x10, end - base - K4),
        ]
    };
    let file = elf(base, &segs(base + 8 * MIB));
    let image = RootImage::check(&file).unwrap();
    assert_eq!(image.image(), span(base, base + 8 * MIB));
    assert_eq!(image.image_frames(), 2048);
    // One byte more is a page more.
    assert_eq!(
        check(base, &segs(base + 8 * MIB + 1)).unwrap_err(),
        RootImageError::TooLarge { span: 8 * MIB + K4 }
    );
    // The span runs from the first segment's page, not its first byte.
    let late = [
        seg(X, base + 0x800, 0x10, 0x10),
        seg(W, base + K4, 0, 8 * MIB - K4),
    ];
    assert!(check(base + 0x800, &late).is_ok());
    let late = [
        seg(X, base + 0x800, 0x10, 0x10),
        seg(W, base + K4, 0, 8 * MIB - K4 + 1),
    ];
    assert_eq!(
        check(base + 0x800, &late).unwrap_err(),
        RootImageError::TooLarge { span: 8 * MIB + K4 }
    );
}

#[test]
fn the_entry_must_lie_in_an_executable_segment() {
    let segs = [
        seg(X, 0x40_0000, 0x100, 0x100),
        seg(W, 0x40_1000, 0x10, 0x10),
    ];
    for entry in [0x40_1000, 0x40_0100, 0x3F_FFFF, 0] {
        assert_eq!(
            check(entry, &segs).unwrap_err(),
            RootImageError::Elf(ElfError::BadEntry(entry))
        );
    }
    assert!(check(0x40_00FF, &segs).is_ok());
}

#[test]
fn the_elf_checks_still_apply() {
    // Two segments on one page.
    let segs = [seg(X, 0x40_0000, 0x10, 0x10), seg(W, 0x40_0800, 0x10, 0x10)];
    assert_eq!(
        check(0x40_0000, &segs).unwrap_err(),
        RootImageError::Elf(ElfError::OverlappingSegments)
    );
    let mut file = elf(0x40_0000, &[seg(X, 0x40_0000, 0x10, 0x10)]);
    file[16] = 3; // ET_DYN: a position-independent executable
    assert_eq!(
        RootImage::check(&file).unwrap_err(),
        RootImageError::Elf(ElfError::NotExecutable(3))
    );
    assert_eq!(
        RootImage::check(&file[..63]).unwrap_err(),
        RootImageError::Elf(ElfError::TooShort)
    );
}

#[test]
fn errors_say_what_is_wrong() {
    let text = |e: RootImageError| std::format!("{e}");
    assert_eq!(
        text(RootImageError::TooLarge { span: 8 * MIB + K4 }),
        "the segments span 0x801000 bytes, more than 8 MiB"
    );
    assert_eq!(
        text(RootImageError::OutsideUserRange { start: 0, end: K4 }),
        "the segment's pages 0x0-0x1000 are not inside 0x1000-0x7fffffffc000"
    );
    assert_eq!(
        text(RootImageError::WritableAndExecutable { vaddr: 0x40_1000 }),
        "the segment at 0x401000 is writable and executable"
    );
    assert_eq!(
        text(RootImageError::Elf(ElfError::BadEntry(0x10))),
        "entry point 0x10 is not in an executable segment"
    );
}

// ---------------------------------------------------------------------
// The layout.

/// An image of one text page at `base` and data up to `end`.
fn spanning(base: u64, end: u64) -> Vec<u8> {
    let mut segs = std::vec![seg(X, base, 0x10, K4)];
    if end > base + K4 {
        segs.push(seg(W, base + K4, 0x10, end - base - K4));
    }
    elf(base, &segs)
}

fn paging_of(file: &[u8]) -> Vec<(CapType, u64, u64)> {
    let image = RootImage::check(file).unwrap();
    let list: Vec<_> = image
        .paging()
        .map(|p| (p.ty, p.span.start, p.span.end))
        .collect();
    let n = image.needs();
    assert_eq!(list.len() as u64, n.paging());
    assert_eq!(counted(image.mapped()), (n.pdpts, n.pds, n.pts));
    list
}

const PDPT: CapType = CapType::Pdpt;
const PD: CapType = CapType::PageDirectory;
const PT: CapType = CapType::PageTable;

#[test]
fn an_image_inside_one_2_mib_page() {
    assert_eq!(
        paging_of(&spanning(0x40_0000, 0x41_0000)),
        [(PDPT, 0, 1 << 39), (PD, 0, GIB), (PT, 0x40_0000, 0x60_0000)]
    );
}

#[test]
fn the_pages_after_the_image_can_need_the_next_page_table() {
    // The image ends on a 2 MiB boundary: the IPC buffer and BootInfo are
    // in the next 2 MiB.
    assert_eq!(
        paging_of(&spanning(0x40_0000, 0x60_0000)),
        [
            (PDPT, 0, 1 << 39),
            (PD, 0, GIB),
            (PT, 0x40_0000, 0x60_0000),
            (PT, 0x60_0000, 0x80_0000)
        ]
    );
    // BootInfo's second page alone crosses.
    let list = paging_of(&spanning(0x40_0000, 0x5F_E000));
    assert_eq!(list.len(), 4);
    let list = paging_of(&spanning(0x40_0000, 0x5F_D000));
    assert_eq!(list.len(), 3);
}

#[test]
fn an_image_across_a_2_mib_boundary() {
    assert_eq!(
        paging_of(&spanning(0x5F_F000, 0x60_1000)),
        [
            (PDPT, 0, 1 << 39),
            (PD, 0, GIB),
            (PT, 0x40_0000, 0x60_0000),
            (PT, 0x60_0000, 0x80_0000)
        ]
    );
}

#[test]
fn an_image_across_a_1_gib_boundary() {
    assert_eq!(
        paging_of(&spanning(GIB - K4, GIB + K4)),
        [
            (PDPT, 0, 1 << 39),
            (PD, 0, GIB),
            (PD, GIB, 2 * GIB),
            (PT, GIB - 2 * MIB, GIB),
            (PT, GIB, GIB + 2 * MIB)
        ]
    );
}

#[test]
fn an_image_across_a_512_gib_boundary() {
    let b = 1u64 << 39;
    assert_eq!(
        paging_of(&spanning(b - K4, b + K4)),
        [
            (PDPT, 0, b),
            (PDPT, b, 2 * b),
            (PD, b - GIB, b),
            (PD, b, b + GIB),
            (PT, b - 2 * MIB, b),
            (PT, b, b + 2 * MIB)
        ]
    );
}

#[test]
fn the_largest_image_needs_at_most_2_2_and_6() {
    // 8 MiB starting a page below a 512 GiB boundary: the most of every
    // level the design allows for.
    let b = (1u64 << 39) - K4;
    let file = spanning(b, b + 8 * MIB);
    let image = RootImage::check(&file).unwrap();
    let n = image.needs();
    assert_eq!((n.pdpts, n.pds, n.pts, n.image_frames), (2, 2, 6, 2048));
    // And no image needs more, wherever its 8 MiB start in a 2 MiB page.
    for start in (0..512).map(|i| (1u64 << 39) - 2 * MIB + i * K4) {
        let file = spanning(start, start + 8 * MIB);
        let n = RootImage::check(&file).unwrap().needs();
        assert!(
            n.pdpts <= 2 && n.pds <= 2 && n.pts <= 6,
            "{start:#x}: {n:?}"
        );
        if cfg!(miri) {
            break;
        }
    }
    // So the slots always fit: 16 fixed, 1 BootInfo frame, 10 paging
    // structures, 2048 frames and 448 untyped.
    const { assert!(NUM_INITIAL_SLOTS + 1 + 10 + 2048 + 448 < 4096) };
}

#[test]
fn the_highest_image_needs_no_structure_past_user_top() {
    let top = ROOT_IMAGE_TOP;
    let file = spanning(top - 8 * MIB, top);
    let image = RootImage::check(&file).unwrap();
    for p in image.paging() {
        assert!(p.span.start < USER_TOP, "{p:?}");
    }
    assert_eq!(image.needs().pdpts, 1);
}

// ---------------------------------------------------------------------
// The mappings for boot step 8.

/// A machine with RAM from 1 MiB to 512 MiB and the kernel image at
/// 64 MiB, `.rootimage` inside it.
fn machine() -> Vec<MemoryRegion> {
    std::vec![
        MemoryRegion::new(MIB, 63 * MIB, RegionKind::USABLE),
        MemoryRegion::new(64 * MIB, 2 * MIB, RegionKind::LOADER),
        MemoryRegion::new(66 * MIB, 446 * MIB, RegionKind::USABLE),
    ]
}

fn input<'a>(map: &'a [MemoryRegion], needs: RootNeeds) -> BootInput<'a> {
    BootInput {
        memory_map: map,
        kernel_image: span(64 * MIB, 64 * MIB + 1200 * 1024),
        rootimage: Some(span(64 * MIB + 0x8_0000, 64 * MIB + 0x9_0000)),
        direct_map_end: 4 * GIB,
        phys_addr_bits: 36,
        window: DeviceWindow::default(),
        locked_hypercall_page: None,
        framebuffer: Framebuffer::default(),
        root: needs,
    }
}

/// Checks [`root_mappings`] for `file` against the boot plan and the
/// capabilities `root_cap` puts in each slot.
fn check_mappings(file: &[u8]) {
    let image = RootImage::check(file).unwrap();
    let map = machine();
    let needs = image.needs();
    let plan = plan(input(&map, needs)).unwrap();
    let untyped = UntypedSummary {
        count: 40,
        ..UntypedSummary::default()
    };
    let slots = slot_plan(&needs, &untyped).unwrap();
    let list: Vec<RootMapping> = root_mappings(&image, &plan.layout, &slots).collect();

    let mut slots_seen = BTreeSet::new();
    let mut frames = Vec::new();
    let mut tables: Vec<PagingObject> = Vec::new();
    let mut frame_phase = false;
    for m in &list {
        match *m {
            RootMapping::Table {
                slot,
                ty,
                paddr,
                vaddr,
            } => {
                assert!(!frame_phase, "a table after a frame: {m:?}");
                let cap = root_cap(&plan, &slots, &[], slot);
                assert_eq!(
                    (cap.cap_type(), cap.object(), cap.size_bits()),
                    (ty, paddr, PAGING_STRUCTURE_BITS)
                );
                assert!(slots.user_image_paging.contains(slot));
                // Each table's parent is mapped already: a PD's PDPT, a
                // PT's PD.
                let reach = match ty {
                    CapType::Pdpt => 1u64 << 39,
                    CapType::PageDirectory => 1 << 30,
                    _ => 1 << 21,
                };
                assert_eq!(vaddr % reach, 0);
                if ty != CapType::Pdpt {
                    assert!(tables.iter().any(|t| t.span.start <= vaddr
                        && vaddr < t.span.end
                        && t.span.end - t.span.start == reach << 9));
                }
                tables.push(PagingObject {
                    ty,
                    span: span(vaddr, vaddr + reach),
                });
                assert!(slots_seen.insert(slot));
            }
            RootMapping::Frame {
                slot,
                paddr,
                vaddr,
                access,
                offset,
                bytes,
            } => {
                frame_phase = true;
                let cap = root_cap(&plan, &slots, &[], slot);
                assert_eq!(
                    (cap.cap_type(), cap.object(), cap.size_bits()),
                    (CapType::Frame, paddr, FRAME_4K_BITS)
                );
                assert!(offset + bytes.len() <= K4 as usize);
                assert_eq!(vaddr % K4, 0);
                // A page table translates it.
                assert!(tables.iter().any(|t| t.ty == CapType::PageTable
                    && t.span.start <= vaddr
                    && vaddr < t.span.end));
                assert!(slots_seen.insert(slot));
                frames.push((slot, vaddr, access));
            }
        }
    }

    // Every slot of the regions, and 9 and 10, each once.
    let region = |r: SlotRegion| r.start..r.end;
    let mut want: BTreeSet<u64> = region(slots.user_image_paging)
        .chain(region(slots.user_image_frames))
        .chain(region(slots.extra_bootinfo_frames))
        .collect();
    want.extend([CAP_BOOTINFO_FRAME, CAP_INIT_IPC_BUFFER]);
    assert_eq!(slots_seen, want);

    // Frames by ascending address, the image's first, then the IPC buffer
    // and BootInfo's two frames, RW and NX.
    assert!(frames.windows(2).all(|w| w[0].1 < w[1].1));
    let rw = access(W);
    let n = frames.len();
    assert_eq!(
        frames[n - 3..],
        [
            (CAP_INIT_IPC_BUFFER, image.ipc_buffer(), rw),
            (CAP_BOOTINFO_FRAME, image.bootinfo(), rw),
            (slots.extra_bootinfo_frames.start, image.bootinfo() + K4, rw),
        ]
    );
    let pages: Vec<ImagePage> = image.pages().collect();
    assert_eq!(pages.len(), n - 3);
    for (i, (p, f)) in pages.iter().zip(&frames).enumerate() {
        assert_eq!(
            *f,
            (slots.user_image_frames.start + i as u64, p.vaddr, p.access)
        );
    }
    let expected_tables: Vec<PagingObject> = image.paging().collect();
    assert_eq!(tables, expected_tables);
}

#[test]
fn root_mappings_name_the_slots_root_cap_fills() {
    check_mappings(&elf(0x40_0010, &typical()));
    // Smaller under Miri, each still across its boundary.
    let (more, less) = if cfg!(miri) {
        (K4, 2 * K4)
    } else {
        (3 * MIB, 2 * MIB)
    };
    check_mappings(&spanning((1 << 39) - K4, (1 << 39) + more));
    check_mappings(&spanning(GIB - less, GIB + K4));
}

#[test]
#[should_panic(expected = "the boot plan was not made for this root image")]
fn root_mappings_refuse_a_plan_for_other_needs() {
    let file = elf(0x40_0010, &typical());
    let image = RootImage::check(&file).unwrap();
    let map = machine();
    let mut needs = image.needs();
    needs.image_frames += 1;
    let plan = plan(input(&map, needs)).unwrap();
    let slots = slot_plan(&needs, &UntypedSummary::default()).unwrap();
    let _ = root_mappings(&image, &plan.layout, &slots).count();
}

// ---------------------------------------------------------------------
// Random images.

/// Segments with random flags, sizes, offsets in their first page and
/// gaps, from a base near a USER_MIN, 2 MiB, 1 GiB, 512 GiB or
/// ROOT_IMAGE_TOP boundary.
fn random_image() -> impl Strategy<Value = (u64, Vec<Seg>)> {
    let bases = prop_oneof![
        Just(USER_MIN),
        (0u64..8).prop_map(|i| 2 * MIB - 4 * K4 + i * K4),
        (0u64..8).prop_map(|i| GIB - 4 * K4 + i * K4),
        (0u64..8).prop_map(|i| (1 << 39) - 4 * K4 + i * K4),
        Just(ROOT_IMAGE_TOP - 64 * K4),
    ];
    let segment = (
        prop_oneof![Just(X), Just(R), Just(W), Just(PF_X), Just(0)],
        0u64..3,
        0u64..K4,
        1u64..3 * K4,
        0u64..=100,
    );
    (bases, prop::collection::vec(segment, 1..5)).prop_map(|(base, raw)| {
        let mut segs = Vec::new();
        let mut next = base;
        for (i, (flags, gap, start, memsz, file_pct)) in raw.into_iter().enumerate() {
            let page = next + if i == 0 { 0 } else { gap * K4 };
            let vaddr = page + if i == 0 { 0 } else { start };
            let flags = if i == 0 { X } else { flags };
            segs.push(seg(flags, vaddr, memsz * file_pct / 100, memsz));
            next = (vaddr + memsz).next_multiple_of(K4);
        }
        (base, segs)
    })
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 256 },
        // No files: Miri forbids them.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn random_images_load_as_their_segments_say((base, segs) in random_image()) {
        let file = elf(base, &segs);
        let image = match RootImage::check(&file) {
            Ok(image) => image,
            Err(RootImageError::OutsideUserRange { end, .. }) => {
                // Only past the top can a generated image fall outside.
                prop_assert!(end > ROOT_IMAGE_TOP);
                return Ok(());
            }
            Err(e) => return Err(TestCaseError::fail(std::format!("{e}"))),
        };
        prop_assert_eq!(loaded(&image), expected(&segs));
        let n = image.needs();
        prop_assert_eq!(counted(image.mapped()), (n.pdpts, n.pds, n.pts));
        prop_assert!(n.pdpts <= 2 && n.pds <= 2 && n.pts <= 6);
        let paging: Vec<PagingObject> = image.paging().collect();
        prop_assert_eq!(paging.len() as u64, n.paging());
        // Each level by ascending address, PDPTs first.
        let rank = |t: CapType| match t {
            CapType::Pdpt => 0,
            CapType::PageDirectory => 1,
            _ => 2,
        };
        let ordered = paging
            .windows(2)
            .all(|w| (rank(w[0].ty), w[0].span.start) < (rank(w[1].ty), w[1].span.start));
        prop_assert!(ordered);
        // Every mapped page has a structure at every level.
        for v in (image.mapped().start..image.mapped().end).step_by(K4 as usize) {
            for ty in [CapType::Pdpt, CapType::PageDirectory, CapType::PageTable] {
                prop_assert!(paging.iter().any(|p| p.ty == ty && p.span.contains(v)));
            }
        }
    }
}
