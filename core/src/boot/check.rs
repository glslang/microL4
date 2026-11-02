//! The invariants of `docs/design.md`, "Boot", that `l4core::boot`
//! enforces, restated as checks over its results. The host tests run them
//! on every plan they make, and the kernel's self-test runs them on the
//! BootInfo and root CNode it built.
//!
//! Each check is written from the rule it states, not from the code that
//! computes the plan: a descriptor is tested against each range no untyped
//! may cover, and full coverage of the RAM the rules allow is tested by
//! measure. Device coverage is not checked here; the host tests compare the
//! whole descriptor list against a second implementation of the rules.

use core::fmt;

use super::{
    BootPlan, FramebufferStatus, LOW_MEMORY_END, PAGE_2M, PAGE_4K, PAGING_BYTES, PageClass,
    ROOT_CNODE_BYTES, SlotPlan, is_firmware_or_bad, kind_class, overlaps, region_at, root_cap,
    round_down, widen_2m, write_back,
};
use crate::bootinfo::{
    BOOTINFO_FRAMES, BOOTINFO_MAGIC, BOOTINFO_SIZE, BOOTINFO_VERSION, BootInfo, CAP_INIT_CNODE,
    CAP_INIT_IPC_BUFFER, CAP_INIT_VSPACE, MAX_ECAM, MAX_IOAPICS, MAX_UNTYPED, NUM_INITIAL_SLOTS,
    ROOT_CNODE_RADIX, ROOT_CNODE_SLOTS, SlotRegion, UntypedDesc,
};
use crate::cap::{
    CapType, MAX_UNTYPED_BITS, TCB_BITS, TCB_SLOT_CSPACE, TCB_SLOT_IPC_BUFFER, TCB_SLOT_VSPACE,
};
use crate::handoff::{CMDLINE_MAX, RegionKind};
use crate::slot::SlotMemory;
use crate::vspace::Span;

/// A broken invariant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Violation {
    /// The boot region or an object in it breaks `rule`.
    BootRegion(&'static str),
    /// Descriptor `index` breaks `rule`.
    Untyped { index: usize, rule: &'static str },
    /// Descriptor `b` does not lie wholly after descriptor `a`, so they
    /// overlap or are out of order.
    Order { a: usize, b: usize },
    /// The RAM untyped cover `covered` bytes of the `allowed` bytes the
    /// rules turn into RAM untyped.
    Uncovered { allowed: u64, covered: u64 },
    /// The framebuffer's descriptors break `rule`.
    Framebuffer(&'static str),
    /// A BootInfo field or slot region breaks `rule`.
    BootInfo(&'static str),
    /// Root CNode slot `slot` does not hold what boot put there.
    RootCNode { slot: u64 },
}

impl fmt::Display for Violation {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BootRegion(rule) => write!(f, "boot region: {rule}"),
            Self::Untyped { index, rule } => write!(f, "untyped {index}: {rule}"),
            Self::Order { a, b } => write!(f, "untyped {b} does not lie after untyped {a}"),
            Self::Uncovered { allowed, covered } => write!(
                f,
                "RAM untyped cover {covered:#x} of the {allowed:#x} bytes allowed"
            ),
            Self::Framebuffer(rule) => write!(f, "framebuffer untyped: {rule}"),
            Self::BootInfo(rule) => write!(f, "BootInfo: {rule}"),
            Self::RootCNode { slot } => write!(f, "root CNode slot {slot} differs"),
        }
    }
}

/// The kernel image less `.rootimage`: at most two ranges.
fn image_holes(plan: &BootPlan) -> [Span; 2] {
    let k = plan.input.kernel_image;
    match plan.input.rootimage {
        Some(r) => [
            Span {
                start: k.start,
                end: r.start,
            },
            Span {
                start: r.end,
                end: k.end,
            },
        ],
        None => [k, Span { start: 0, end: 0 }],
    }
}

/// The boot region's invariants: aligned to the root CNode, inside one
/// `USABLE` range above 1 MiB and inside the direct map, clear of the
/// kernel image and of every 2 MiB page holding a `kernel_reserved` page;
/// its objects in order, each aligned to its size and inside it.
pub fn check_plan(plan: &BootPlan) -> Result<(), Violation> {
    let input = &plan.input;
    let l = &plan.layout;
    let region = l.region;
    let bad = |rule| Err(Violation::BootRegion(rule));
    if !region.start.is_multiple_of(ROOT_CNODE_BYTES) || !region.end.is_multiple_of(PAGE_4K) {
        return bad("not aligned to the root CNode");
    }
    if region.start < LOW_MEMORY_END {
        return bad("below 1 MiB");
    }
    if region.end > input.direct_map_end || region.end > input.top() {
        return bad("outside the direct map");
    }
    match region_at(input.memory_map, region.start) {
        Some(r) if r.kind == RegionKind::USABLE && region.end <= r.end() => {}
        _ => return bad("not inside one usable range"),
    }
    if overlaps(region, input.kernel_image) {
        return bad("overlaps the kernel image");
    }
    if plan.kernel_reserved.overlaps(widen_2m(region)) {
        return bad("touches a 2 MiB page holding a kernel-reserved page");
    }
    let needs = l.needs();
    let objects = [
        Some((l.cnode, ROOT_CNODE_BYTES, ROOT_CNODE_BYTES)),
        l.pml4.map(|p| (p, PAGING_BYTES, PAGING_BYTES)),
        Some((l.paging, needs.paging() * PAGING_BYTES, PAGING_BYTES)),
        Some((l.ipc_buffer, PAGE_4K, PAGE_4K)),
        Some((l.bootinfo, BOOTINFO_FRAMES * PAGE_4K, PAGE_4K)),
        Some((l.image_frames, needs.image_frames * PAGE_4K, PAGE_4K)),
        l.synic.map(|s| (s.message, PAGE_4K, PAGE_4K)),
        l.synic.map(|s| (s.event, PAGE_4K, PAGE_4K)),
        l.tcb.map(|t| (t, 1 << TCB_BITS, 1 << TCB_BITS)),
    ];
    let mut next = region.start;
    for (start, size, align) in objects.into_iter().flatten() {
        if start < next || !start.is_multiple_of(align) || start + size > region.end {
            return bad("objects out of order, unaligned or outside it");
        }
        next = start + size;
    }
    if needs.tcb != l.tcb.is_some()
        || needs.pml4 != l.pml4.is_some()
        || needs.hypervisor.is_some() != l.synic.is_some()
    {
        return bad("objects differ from the needs");
    }
    Ok(())
}

/// The first write-back 2 MiB page `span` touches, if any.
fn write_back_page(plan: &BootPlan, span: Span) -> Option<u64> {
    let input = &plan.input;
    // Only a 2 MiB page overlapping RAM-like memory can be write-back, and
    // each one is unless it holds a device page, so each region needs at
    // most a few tests.
    for r in input.memory_map.iter().filter(|r| r.len != 0) {
        if !crate::vspace::is_ram_like(r.kind) {
            continue;
        }
        let ram = widen_2m(Span {
            start: r.base,
            end: r.end(),
        });
        let mut page = round_down(span.start, PAGE_2M).max(ram.start);
        let end = span.end.min(ram.end).min(input.direct_map_end);
        while page < end {
            if write_back(input, page) {
                return Some(page);
            }
            page += PAGE_2M;
        }
    }
    None
}

/// Whether RAM-kind memory-map entries cover every byte of `span`.
fn ram_kind(plan: &BootPlan, span: Span) -> bool {
    let mut at = span.start;
    while at < span.end {
        match region_at(plan.input.memory_map, at) {
            Some(r) if kind_class(r.kind) == PageClass::Ram => at = r.end(),
            _ => return false,
        }
    }
    true
}

/// Whether any RAM-kind memory-map entry shares a byte with `span`.
fn touches_ram_kind(plan: &BootPlan, span: Span) -> bool {
    plan.input.memory_map.iter().any(|r| {
        kind_class(r.kind) == PageClass::Ram
            && overlaps(
                span,
                Span {
                    start: r.base,
                    end: r.end(),
                },
            )
    })
}

/// The invariants on the untyped boot made from `plan`: `descs` are
/// BootInfo's descriptors, the first `framebuffer` of them the
/// framebuffer's.
///
/// - Each is 4 KiB to `2^47`, aligned to its size, below
///   `2^phys_addr_bits`, and covers no byte of `[0, 1 MiB)`, the kernel
///   image (less `.rootimage`), the boot region, a `kernel_reserved` page,
///   or `ACPI_NVS`, `FIRMWARE`, `BAD` or unknown memory.
/// - RAM untyped cover only RAM-kind entries, inside the direct map, in
///   2 MiB pages holding no kernel device page, and not the framebuffer.
/// - Device untyped lie in no write-back 2 MiB page, and outside the
///   framebuffer cover no RAM-kind entry.
/// - The framebuffer's descriptors come first and cover its page-rounded
///   range exactly, if and only if the plan gave it untyped; the rest are
///   in ascending order and disjoint from each other and from it.
/// - The RAM untyped cover every byte the rules allow: boot drops no RAM.
pub fn check_untyped(
    plan: &BootPlan,
    descs: &[UntypedDesc],
    framebuffer: usize,
) -> Result<(), Violation> {
    let input = &plan.input;
    if descs.len() > MAX_UNTYPED {
        return Err(Violation::BootInfo("more untyped than BootInfo holds"));
    }
    if framebuffer > descs.len() {
        return Err(Violation::Framebuffer("more than there are untyped"));
    }
    let fb_span = plan.framebuffer.span();
    let images = image_holes(plan);
    let mut ram_covered = 0u64;
    for (index, d) in descs.iter().enumerate() {
        let bad = |rule| Err(Violation::Untyped { index, rule });
        let bits = u32::from(d.size_bits);
        if !(12..=MAX_UNTYPED_BITS).contains(&bits) {
            return bad("size outside 4 KiB to 2^47 bytes");
        }
        if !d.paddr.is_multiple_of(d.size()) {
            return bad("not aligned to its size");
        }
        if d.is_device > 1 || d.padding != [0; 6] {
            return bad("device flag or padding not 0 or 1");
        }
        let span = match d.paddr.checked_add(d.size()) {
            Some(end) if end <= input.top() => Span {
                start: d.paddr,
                end,
            },
            _ => return bad("reaches 2^phys_addr_bits"),
        };
        if span.start < LOW_MEMORY_END {
            return bad("covers memory below 1 MiB");
        }
        if images.iter().any(|&k| overlaps(span, k)) {
            return bad("covers the kernel image");
        }
        if overlaps(span, plan.layout.region) {
            return bad("covers the boot region");
        }
        if plan.kernel_reserved.overlaps(span) {
            return bad("covers a kernel-reserved page");
        }
        let firmware = input.memory_map.iter().any(|r| {
            is_firmware_or_bad(r.kind)
                && overlaps(
                    span,
                    Span {
                        start: r.base,
                        end: r.end(),
                    },
                )
        });
        if firmware {
            return bad("covers ACPI_NVS, FIRMWARE, BAD or unknown memory");
        }
        if d.device() {
            if write_back_page(plan, span).is_some() {
                return bad("device untyped in a write-back 2 MiB page");
            }
            if index >= framebuffer && touches_ram_kind(plan, span) {
                return bad("device untyped over RAM");
            }
        } else {
            if index < framebuffer {
                return Err(Violation::Framebuffer("RAM untyped"));
            }
            if span.end > input.direct_map_end {
                return bad("RAM untyped outside the direct map");
            }
            let device_page = input.window.pages.iter().flatten().any(|&w| {
                let page = round_down(w, PAGE_2M);
                overlaps(
                    span,
                    Span {
                        start: page,
                        end: page + PAGE_2M,
                    },
                )
            });
            if device_page {
                return bad("RAM untyped in a 2 MiB page holding a kernel device page");
            }
            if !ram_kind(plan, span) {
                return bad("RAM untyped over memory that is not RAM");
            }
            ram_covered += d.size();
        }
        if index >= framebuffer && fb_span.is_some_and(|f| overlaps(span, f)) {
            return bad("covers the framebuffer");
        }
    }

    // The framebuffer's descriptors, then the rest by ascending address.
    let (fb, rest) = descs.split_at(framebuffer);
    match plan.framebuffer {
        FramebufferStatus::Untyped(span) => {
            let mut at = span.start;
            for d in fb {
                if d.paddr != at {
                    return Err(Violation::Framebuffer("gap or overlap"));
                }
                at = d.end();
            }
            if at != span.end {
                return Err(Violation::Framebuffer("does not cover it exactly"));
            }
        }
        _ if framebuffer != 0 => {
            return Err(Violation::Framebuffer("present though the plan gave none"));
        }
        _ => {}
    }
    for (i, pair) in rest.windows(2).enumerate() {
        if pair[0].end() > pair[1].paddr {
            return Err(Violation::Order {
                a: framebuffer + i,
                b: framebuffer + i + 1,
            });
        }
    }

    let allowed = allowed_ram(plan);
    if ram_covered != allowed {
        return Err(Violation::Uncovered {
            allowed,
            covered: ram_covered,
        });
    }
    Ok(())
}

/// Bytes of RAM the rules turn into RAM untyped: RAM-kind entries from
/// 1 MiB to the direct map's end, less the kernel image (not
/// `.rootimage`), the boot region, `kernel_reserved`, the 2 MiB pages
/// holding kernel device pages, and the framebuffer.
fn allowed_ram(plan: &BootPlan) -> u64 {
    let input = &plan.input;
    const N: usize = 2 + 1 + super::MAX_KERNEL_RESERVED + crate::window::PAGES + 1;
    let mut holes = [Span { start: 0, end: 0 }; N];
    let mut n = 0;
    let mut add = |s: Span| {
        holes[n] = s;
        n += 1;
    };
    image_holes(plan).into_iter().for_each(&mut add);
    add(plan.layout.region);
    plan.kernel_reserved.iter().for_each(&mut add);
    for &w in input.window.pages.iter().flatten() {
        let page = round_down(w, PAGE_2M);
        add(Span {
            start: page,
            end: page + PAGE_2M,
        });
    }
    if let Some(f) = plan.framebuffer.span() {
        add(f);
    }
    let holes = merge(&mut holes[..n]);

    let ceiling = input.direct_map_end.min(input.top());
    let mut total = 0;
    for r in input.memory_map {
        if kind_class(r.kind) != PageClass::Ram {
            continue;
        }
        let start = r.base.max(LOW_MEMORY_END);
        let end = r.end().min(ceiling);
        if start >= end {
            continue;
        }
        let mut bytes = end - start;
        for h in holes.iter() {
            let (s, e) = (h.start.max(start), h.end.min(end));
            if s < e {
                bytes -= e - s;
            }
        }
        total += bytes;
    }
    total
}

/// Sorts `spans` and merges those that overlap or touch, in place; returns
/// the disjoint, non-empty spans.
fn merge(spans: &mut [Span]) -> &[Span] {
    spans.sort_unstable_by_key(|s| s.start);
    let mut out = 0;
    for i in 0..spans.len() {
        let s = spans[i];
        if s.start >= s.end {
            continue;
        }
        if out > 0 && spans[out - 1].end >= s.start {
            spans[out - 1].end = spans[out - 1].end.max(s.end);
        } else {
            spans[out] = s;
            out += 1;
        }
    }
    &spans[..out]
}

/// The slot plan BootInfo records.
pub fn slot_plan_of(bi: &BootInfo) -> SlotPlan {
    SlotPlan {
        extra_bootinfo_frames: bi.extra_bootinfo_frames,
        user_image_paging: bi.user_image_paging,
        user_image_frames: bi.user_image_frames,
        untyped: bi.untyped,
        framebuffer_untyped: bi.framebuffer_untyped,
        empty: bi.empty,
    }
}

/// BootInfo as boot wrote it for `plan`: its fixed fields, slot regions
/// that follow each other from slot 16 in the ABI's order with the sizes
/// the plan needs, zeros where nothing is, then [`check_untyped`] on its
/// descriptors.
pub fn check_bootinfo(plan: &BootPlan, bi: &BootInfo) -> Result<(), Violation> {
    let bad = |rule| Err(Violation::BootInfo(rule));
    if bi.magic != BOOTINFO_MAGIC
        || bi.version != BOOTINFO_VERSION
        || bi.size as usize != BOOTINFO_SIZE
        || bi.root_cnode_bits != u64::from(ROOT_CNODE_RADIX)
    {
        return bad("magic, version, size or root CNode bits");
    }
    if bi.phys_addr_bits != plan.input.phys_addr_bits {
        return bad("physical address width differs from the plan's");
    }
    if bi.cmdline_len as usize > CMDLINE_MAX
        || bi.cmdline[bi.cmdline_len as usize..]
            .iter()
            .any(|&b| b != 0)
    {
        return bad("command line length or bytes after it");
    }
    if bi.reserved0 != [0; 48] || bi.reserved1 != [0; 256] || bi.interrupts.reserved != [0; 24] {
        return bad("reserved bytes not 0");
    }
    let irq = &bi.interrupts;
    if irq.ecam_count as usize > MAX_ECAM
        || irq.ioapic_count as usize > MAX_IOAPICS
        || irq.ecam[irq.ecam_count as usize..]
            .iter()
            .any(|e| *e != Default::default())
        || irq.ioapics[irq.ioapic_count as usize..]
            .iter()
            .any(|e| *e != Default::default())
    {
        return bad("interrupt block counts or unused entries");
    }
    let needs = plan.layout.needs();
    let regions = [
        (bi.extra_bootinfo_frames, BOOTINFO_FRAMES - 1),
        (bi.user_image_paging, needs.paging()),
        (bi.user_image_frames, needs.image_frames),
    ];
    let mut next = NUM_INITIAL_SLOTS;
    for (r, len) in regions {
        if r.start != next || r.len() != len || r.end < r.start {
            return bad("slot regions out of order or of the wrong size");
        }
        next = r.end;
    }
    let untyped = bi.untyped;
    let n = untyped.len() as usize;
    if untyped.start != next || untyped.end < untyped.start || n > MAX_UNTYPED {
        return bad("untyped slot region");
    }
    let fb = bi.framebuffer_untyped;
    if fb.start != untyped.start || fb.end < fb.start || fb.end > untyped.end {
        return bad("framebuffer_untyped is not a leading part of untyped");
    }
    let empty = SlotRegion {
        start: untyped.end,
        end: ROOT_CNODE_SLOTS,
    };
    if bi.empty != empty || untyped.end > ROOT_CNODE_SLOTS {
        return bad("empty is not the rest of the root CNode");
    }
    if bi.untyped_list[n..]
        .iter()
        .any(|d| *d != UntypedDesc::default())
    {
        return bad("descriptors past the untyped region not 0");
    }
    match plan.framebuffer {
        FramebufferStatus::Absent if bi.framebuffer != Default::default() => {
            return bad("framebuffer recorded though there is none");
        }
        FramebufferStatus::Untyped(_) | FramebufferStatus::Rejected { .. }
            if bi.framebuffer != plan.input.framebuffer =>
        {
            return bad("framebuffer differs from the handoff's");
        }
        _ => {}
    }
    check_untyped(plan, &bi.untyped_list[..n], fb.len() as usize)
}

/// Every root CNode slot holds what [`root_cap`] says for `plan` and `bi`,
/// as a derivation root: an original at depth 0. Holds right after boot,
/// before anything has been derived; every slot in `empty` is then null.
/// Boot step 8 (M5) leaves two marks this allows: the mapping records of
/// the frames and paging structures it mapped, and the root TCB's copies
/// of the CNode, VSpace and IPC buffer capabilities, each its original's
/// only child, so the original's next link names that TCB slot.
pub fn check_root_cnode<M: SlotMemory + ?Sized>(
    mem: &M,
    plan: &BootPlan,
    bi: &BootInfo,
) -> Result<(), Violation> {
    let slots = slot_plan_of(bi);
    let untyped = bi.untyped();
    let tcb_slot = |n: u64| {
        let t = crate::tcb::TcbRef::new(plan.layout.tcb?)?;
        Some(t.slot(n))
    };
    for slot in 0..ROOT_CNODE_SLOTS {
        let found = mem.load(plan.layout.slot(slot));
        let expected = root_cap(plan, &slots, untyped, slot);
        let cap = match found.cap.cap_type() {
            CapType::Frame | CapType::PageTable | CapType::PageDirectory | CapType::Pdpt => {
                found.cap.with_data(0)
            }
            _ => found.cap,
        };
        let child = match slot {
            CAP_INIT_CNODE => tcb_slot(TCB_SLOT_CSPACE),
            CAP_INIT_VSPACE => tcb_slot(TCB_SLOT_VSPACE),
            CAP_INIT_IPC_BUFFER => tcb_slot(TCB_SLOT_IPC_BUFFER),
            _ => None,
        };
        let next_ok = found.node.next().is_none() || found.node.next() == child;
        let node_ok = expected.is_null()
            || (found.node.original()
                && found.node.depth() == 0
                && found.node.prev().is_none()
                && next_ok);
        if cap != expected || !node_ok {
            return Err(Violation::RootCNode { slot });
        }
    }
    Ok(())
}
