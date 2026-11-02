//! The boot plan: where the root task's objects go, what every physical
//! page becomes, and the slot plan (`docs/design.md`, "Boot"; ADR 0007).
//!
//! Everything here is a pure function of a [`BootInput`], so the kernel's
//! boot steps 6, 7 and 9 are the functions the host tests check on the
//! memory maps recorded from QEMU and Hyper-V and on random maps:
//!
//! 1. [`plan`] (step 6) places the boot region and lays out the root
//!    task's objects in it. The kernel zeroes the region.
//! 2. [`write_bootinfo`] (step 9) computes the untyped straight into
//!    BootInfo's descriptor list, then the slot plan, then every other
//!    BootInfo field. BootInfo's frames are [`RootLayout::bootinfo`]; the
//!    kernel views them as one `&mut BootInfo`, valid because the region is
//!    zeroed and every BootInfo field is a plain integer.
//! 3. [`write_root_cnode`] (steps 7 and 9) puts every boot capability in
//!    the root CNode with `cdt::insert_root`: slot `n` gets [`root_cap`].
//!
//! Errors are values; the kernel panics on them with their `Display`.
//! [`check`] restates the invariants of "Boot" as checks over the result,
//! for the host tests and the kernel's self-test.
//!
//! In M4 the root task needs nothing ([`RootNeeds::default`]): the boot
//! region holds the root CNode, the IPC buffer and BootInfo. M5 asks for a
//! TCB, a PML4, paging structures and image frames, and M9 for the
//! Hypervisor capability with its two SynIC frames, by changing only the
//! input.

pub mod check;

#[cfg(test)]
mod tests;

use core::fmt;

use crate::bootinfo::{
    BOOTINFO_FRAMES, BOOTINFO_MAGIC, BOOTINFO_SIZE, BOOTINFO_VERSION, BootInfo, CAP_BOOTINFO_FRAME,
    CAP_HYPERVISOR, CAP_INIT_CNODE, CAP_INIT_IPC_BUFFER, CAP_INIT_TCB, CAP_INIT_VSPACE,
    CAP_IO_PORT_CONTROL, CAP_IRQ_CONTROL, CAP_SYNIC_EVENT_FRAME, CAP_SYNIC_MESSAGE_FRAME,
    InterruptInfo, MAX_UNTYPED, NUM_INITIAL_SLOTS, ROOT_CNODE_GUARD_SIZE, ROOT_CNODE_RADIX,
    ROOT_CNODE_SLOTS, SlotRegion, UntypedDesc,
};
use crate::cap::{
    Cap, CapType, FRAME_4K_BITS, MAX_UNTYPED_BITS, ObjectType, PAGING_STRUCTURE_BITS, Rights,
    SLOT_BITS, TCB_BITS,
};
use crate::cdt;
use crate::handoff::{CMDLINE_MAX, DIRECT_MAP_MAX, Framebuffer, MemoryRegion, RegionKind};
use crate::slot::{SlotAddr, SlotMemory};
use crate::vspace::{self, CacheType, PAGE_2M, PAGE_4K, Span};
use crate::window::{self, DeviceWindow};

/// No untyped and no boot region below 1 MiB: no kernel object at physical
/// address 0, the legacy areas, and the AP trampoline of the multi-core
/// stretch goal.
pub const LOW_MEMORY_END: u64 = 1 << 20;

/// The MSI window: writes here are interrupt messages, and the local APIC's
/// page lies inside it. Never untyped.
pub const MSI_WINDOW: Span = Span {
    start: 0xFEE0_0000,
    end: 0xFEF0_0000,
};

/// The narrowest physical address width [`plan`] accepts.
pub const MIN_PHYS_ADDR_BITS: u32 = 32;
/// The widest: 4-level paging's 52 bits.
pub const MAX_PHYS_ADDR_BITS: u32 = 52;

/// Spans in [`KernelReserved`]: the device window's pages, the MSI window
/// and a locked hypercall page.
pub const MAX_KERNEL_RESERVED: usize = window::PAGES + 2;

/// Bytes of the root CNode, which sets the boot region's alignment.
pub const ROOT_CNODE_BYTES: u64 = 1 << (ROOT_CNODE_RADIX + SLOT_BITS);

/// Bytes of a paging structure (PML4, PDPT, PD, PT): table and
/// back-references.
const PAGING_BYTES: u64 = 1 << PAGING_STRUCTURE_BITS;

const fn round_down(a: u64, align: u64) -> u64 {
    a & !(align - 1)
}

/// `a` rounded up to `align`, saturating at the highest multiple.
const fn round_up(a: u64, align: u64) -> u64 {
    match a.checked_add(align - 1) {
        Some(b) => b & !(align - 1),
        None => !(align - 1),
    }
}

/// Whether two ranges share a byte; an empty range shares none.
pub const fn overlaps(a: Span, b: Span) -> bool {
    a.start < a.end && b.start < b.end && a.start < b.end && b.start < a.end
}

/// The 2 MiB pages a range touches, as a range.
const fn widen_2m(s: Span) -> Span {
    Span {
        start: round_down(s.start, PAGE_2M),
        end: round_up(s.end, PAGE_2M),
    }
}

/// The pages no untyped and no boot region may cover
/// (`docs/design.md`, "What each physical page becomes"): the pages the
/// kernel device window maps, the MSI window and a hypercall page the
/// firmware locked.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct KernelReserved {
    spans: [Option<Span>; MAX_KERNEL_RESERVED],
}

impl KernelReserved {
    /// The reserved ranges, page-aligned, in the order [`kernel_reserved`]
    /// adds them; they may overlap.
    pub fn iter(&self) -> impl Iterator<Item = Span> + '_ {
        self.spans.iter().flatten().copied()
    }

    /// Whether `addr` is reserved.
    pub fn contains(&self, addr: u64) -> bool {
        self.iter().any(|s| s.contains(addr))
    }

    /// Whether any byte of `span` is reserved.
    pub fn overlaps(&self, span: Span) -> bool {
        self.iter().any(|s| overlaps(s, span))
    }
}

/// `BootPlan.kernel_reserved` from the device window M3 built and the
/// hypercall page the firmware locked, if any.
pub fn kernel_reserved(
    window: &DeviceWindow,
    locked_hypercall_page: Option<u64>,
) -> KernelReserved {
    let page = |p: u64| {
        let start = round_down(p, PAGE_4K);
        Span {
            start,
            end: start.saturating_add(PAGE_4K),
        }
    };
    let mut r = KernelReserved::default();
    for (slot, p) in r.spans.iter_mut().zip(window.pages) {
        *slot = p.map(page);
    }
    r.spans[window::PAGES] = Some(MSI_WINDOW);
    r.spans[window::PAGES + 1] = locked_hypercall_page.map(page);
    r
}

/// What the root task needs from the boot region besides its CNode, IPC
/// buffer and BootInfo. All zero in M4.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RootNeeds {
    /// The root task's TCB, 2 KiB (M5).
    pub tcb: bool,
    /// Its PML4 (M5).
    pub pml4: bool,
    /// Its VSpace's PDPTs, page directories and page tables (M5), at most
    /// 2, 2 and 6 for an 8 MiB image.
    pub pdpts: u64,
    pub pds: u64,
    pub pts: u64,
    /// One frame per image page a segment covers (M5), at most 2048.
    pub image_frames: u64,
    /// The unrestricted Hypervisor capability for slot 12, on Hyper-V from
    /// M9. With it come the two SynIC frames for slots 13 and 14; without
    /// it all three slots are null.
    pub hypervisor: Option<Cap>,
}

impl RootNeeds {
    /// The paging structures in `user_image_paging`, PML4 excluded.
    pub const fn paging(&self) -> u64 {
        self.pdpts + self.pds + self.pts
    }
}

/// What the boot plan is computed from, all physical.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInput<'a> {
    /// The handoff's memory map: sorted by base, not overlapping, 4 KiB
    /// granular, as the loader leaves it.
    pub memory_map: &'a [MemoryRegion],
    /// `[kernel_phys_base, kernel_phys_base + kernel_size)`.
    pub kernel_image: Span,
    /// `.rootimage`, inside the kernel image, once step 8 has unmapped it
    /// (M5); its pages then become RAM untyped. `None` in M4.
    pub rootimage: Option<Span>,
    /// The end of the kernel's direct map, `min(phys_map_size, 64 GiB)`.
    pub direct_map_end: u64,
    /// The CPU's physical address width (CPUID `0x8000_0008`).
    pub phys_addr_bits: u32,
    /// The kernel device window M3 mapped.
    pub window: DeviceWindow,
    /// The hypercall page the firmware locked, if any (M3).
    pub locked_hypercall_page: Option<u64>,
    /// The handoff's framebuffer; all zero if there is none.
    pub framebuffer: Framebuffer,
    /// What the root task needs.
    pub root: RootNeeds,
}

impl BootInput<'_> {
    /// `2^phys_addr_bits`: no untyped reaches it.
    pub const fn top(&self) -> u64 {
        1u64 << self.phys_addr_bits
    }
}

/// The two SynIC frames, on Hyper-V from M9.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SynicFrames {
    /// The SynIC message page (SIM), slot 13.
    pub message: u64,
    /// The SynIC event-flag page (SIEF), slot 14.
    pub event: u64,
}

/// The boot region and the physical address of every object in it, in
/// order of decreasing alignment, as seL4's `create_rootserver_objects`
/// lays out its rootserver region.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RootLayout {
    /// The whole region, page-rounded, aligned to the root CNode.
    pub region: Span,
    /// The root CNode, `2^12` slots, 128 KiB.
    pub cnode: u64,
    /// The root PML4, 8 KiB.
    pub pml4: Option<u64>,
    /// The first paging structure: PDPTs, then page directories, then page
    /// tables, 8 KiB each, in `user_image_paging` order.
    pub paging: u64,
    /// The IPC buffer frame.
    pub ipc_buffer: u64,
    /// BootInfo's two frames.
    pub bootinfo: u64,
    /// The first image frame; frame `i` is at `image_frames + 4 KiB * i`.
    pub image_frames: u64,
    /// The SynIC frames.
    pub synic: Option<SynicFrames>,
    /// The root TCB, 2 KiB, last.
    pub tcb: Option<u64>,
    needs: RootNeeds,
}

impl RootLayout {
    /// Lays the objects out from `start`.
    fn at(start: u64, needs: &RootNeeds) -> RootLayout {
        let mut next = start;
        let mut take = |bytes: u64| {
            let at = next;
            next += bytes;
            at
        };
        let cnode = take(ROOT_CNODE_BYTES);
        let pml4 = needs.pml4.then(|| take(PAGING_BYTES));
        let paging = take(needs.paging() * PAGING_BYTES);
        let ipc_buffer = take(PAGE_4K);
        let bootinfo = take(BOOTINFO_FRAMES * PAGE_4K);
        let image_frames = take(needs.image_frames * PAGE_4K);
        let synic = needs.hypervisor.map(|_| SynicFrames {
            message: take(PAGE_4K),
            event: take(PAGE_4K),
        });
        let tcb = needs.tcb.then(|| take(1 << TCB_BITS));
        RootLayout {
            region: Span {
                start,
                end: round_up(next, PAGE_4K),
            },
            cnode,
            pml4,
            paging,
            ipc_buffer,
            bootinfo,
            image_frames,
            synic,
            tcb,
            needs: *needs,
        }
    }

    /// Bytes the boot region needs.
    pub fn size(needs: &RootNeeds) -> u64 {
        let l = RootLayout::at(0, needs);
        l.region.end
    }

    /// The root CNode's slot `slot`. Panics if `slot` is not below 4096.
    pub fn slot(&self, slot: u64) -> SlotAddr {
        assert!(
            slot < ROOT_CNODE_SLOTS,
            "root CNode slot {slot} out of range"
        );
        SlotAddr::new(self.cnode)
            .expect("the root CNode is above 1 MiB and aligned")
            .offset(slot)
    }

    /// Paging structure `i` of `user_image_paging`: its type and address.
    pub fn paging_object(&self, i: u64) -> (CapType, u64) {
        let n = &self.needs;
        let ty = if i < n.pdpts {
            CapType::Pdpt
        } else if i < n.pdpts + n.pds {
            CapType::PageDirectory
        } else {
            CapType::PageTable
        };
        (ty, self.paging + i * PAGING_BYTES)
    }

    /// Image frame `i`.
    pub fn image_frame(&self, i: u64) -> u64 {
        self.image_frames + i * PAGE_4K
    }

    /// What the layout was made for.
    pub const fn needs(&self) -> &RootNeeds {
        &self.needs
    }
}

/// What becomes of the GOP framebuffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferStatus {
    /// There is none.
    Absent,
    /// Its own device untyped, listed first, cover this page-rounded range.
    Untyped(Span),
    /// No untyped covers any of `span`, its page-rounded range; a debug
    /// kernel warns with `reason`.
    Rejected {
        span: Span,
        reason: FramebufferRejection,
    },
}

impl FramebufferStatus {
    /// The page-rounded range, if there is a framebuffer.
    pub const fn span(&self) -> Option<Span> {
        match *self {
            Self::Absent => None,
            Self::Untyped(span) | Self::Rejected { span, .. } => Some(span),
        }
    }
}

/// Why the framebuffer gets no untyped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum FramebufferRejection {
    /// The 2 MiB page at this address is write-back in the direct map, so a
    /// device frame there would alias it.
    WriteBack { page: u64 },
    /// It reaches below 1 MiB or to `2^phys_addr_bits`, or wraps.
    OutOfRange,
    /// It overlaps what is named here, which no untyped may cover.
    Overlaps(&'static str),
}

impl fmt::Display for FramebufferRejection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::WriteBack { page } => write!(
                f,
                "the 2 MiB page at {page:#x} is write-back in the direct map"
            ),
            Self::OutOfRange => {
                f.write_str("it reaches below 1 MiB or past the physical address width")
            }
            Self::Overlaps(what) => write!(f, "it overlaps {what}"),
        }
    }
}

/// The boot plan: the input, `kernel_reserved`, the boot region's layout
/// and the framebuffer's fate. [`untyped`] and [`write_bootinfo`] take it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootPlan<'a> {
    pub input: BootInput<'a>,
    pub kernel_reserved: KernelReserved,
    pub layout: RootLayout,
    pub framebuffer: FramebufferStatus,
}

/// Why boot cannot go on. The kernel panics with the `Display` text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BootError {
    /// The physical address width is outside 32 to 52 bits.
    PhysAddrBits(u32),
    /// The direct map's end is 0, above 64 GiB or not a multiple of 2 MiB.
    DirectMapEnd(u64),
    /// Memory-map entry `index` is not 4 KiB-granular, wraps, or starts
    /// before the previous entry ends.
    MemoryMap { index: usize },
    /// The kernel image is empty, unaligned, or not inside the direct map.
    KernelImage(Span),
    /// `.rootimage` is unaligned or not inside the kernel image.
    RootImage(Span),
    /// The root task's objects alone need more slots than the root CNode
    /// has, counting the 16 fixed ones.
    TooManySlots { needed: u64 },
    /// No `USABLE` range above 1 MiB inside the direct map holds `size`
    /// bytes aligned to `align` away from every kernel-reserved 2 MiB page.
    NoRoom { size: u64, align: u64 },
    /// More untyped than BootInfo's descriptors.
    TooManyUntyped { count: usize },
}

impl fmt::Display for BootError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::PhysAddrBits(b) => write!(
                f,
                "physical address width {b} outside {MIN_PHYS_ADDR_BITS} to {MAX_PHYS_ADDR_BITS} bits"
            ),
            Self::DirectMapEnd(e) => write!(f, "direct map end {e:#x} is not usable"),
            Self::MemoryMap { index } => write!(
                f,
                "memory-map entry {index} is unaligned, wraps, or overlaps the one before"
            ),
            Self::KernelImage(s) => write!(
                f,
                "kernel image {:#x}-{:#x} is empty, unaligned or outside the direct map",
                s.start, s.end
            ),
            Self::RootImage(s) => write!(
                f,
                ".rootimage {:#x}-{:#x} is unaligned or outside the kernel image",
                s.start, s.end
            ),
            Self::TooManySlots { needed } => write!(
                f,
                "the initial capabilities need {needed} slots, more than the root CNode's {ROOT_CNODE_SLOTS}"
            ),
            Self::NoRoom { size, align } => write!(
                f,
                "no usable range above 1 MiB inside the direct map holds the {} KiB boot region aligned to {} KiB",
                size >> 10,
                align >> 10
            ),
            Self::TooManyUntyped { count } => {
                write!(f, "{count} untyped, more than BootInfo's {MAX_UNTYPED}")
            }
        }
    }
}

fn validate(input: &BootInput) -> Result<(), BootError> {
    let bits = input.phys_addr_bits;
    if !(MIN_PHYS_ADDR_BITS..=MAX_PHYS_ADDR_BITS).contains(&bits) {
        return Err(BootError::PhysAddrBits(bits));
    }
    let dme = input.direct_map_end;
    if dme == 0 || dme > DIRECT_MAP_MAX || !dme.is_multiple_of(PAGE_2M) {
        return Err(BootError::DirectMapEnd(dme));
    }
    let mut prev_end = 0;
    for (index, r) in input.memory_map.iter().enumerate() {
        let ok = r.base.is_multiple_of(PAGE_4K)
            && r.len.is_multiple_of(PAGE_4K)
            && r.base.checked_add(r.len).is_some()
            && r.base >= prev_end;
        if !ok {
            return Err(BootError::MemoryMap { index });
        }
        prev_end = r.end();
    }
    let k = input.kernel_image;
    if k.start >= k.end
        || !k.start.is_multiple_of(PAGE_4K)
        || !k.end.is_multiple_of(PAGE_4K)
        || k.end > dme
    {
        return Err(BootError::KernelImage(k));
    }
    if let Some(r) = input.rootimage
        && (r.start > r.end
            || !r.start.is_multiple_of(PAGE_4K)
            || !r.end.is_multiple_of(PAGE_4K)
            || r.start < k.start
            || r.end > k.end)
    {
        return Err(BootError::RootImage(r));
    }
    let needed = NUM_INITIAL_SLOTS
        .saturating_add(BOOTINFO_FRAMES - 1)
        .saturating_add(input.root.pdpts)
        .saturating_add(input.root.pds)
        .saturating_add(input.root.pts)
        .saturating_add(input.root.image_frames);
    if needed > ROOT_CNODE_SLOTS {
        return Err(BootError::TooManySlots { needed });
    }
    Ok(())
}

/// Step 6: places the boot region and lays out the root task's objects.
///
/// The region is at the top of the highest `USABLE` range above 1 MiB,
/// inside the direct map, that holds it aligned to the root CNode without
/// touching a `kernel_reserved` page or a 2 MiB page holding one (seL4's
/// `init_freemem`, with `kernel_reserved` subtracted first). The kernel
/// image is never `USABLE`, but is avoided too.
pub fn plan(input: BootInput<'_>) -> Result<BootPlan<'_>, BootError> {
    validate(&input)?;
    let kernel_reserved = kernel_reserved(&input.window, input.locked_hypercall_page);
    let size = RootLayout::size(&input.root);
    let start = place(&input, &kernel_reserved, size)?;
    let mut plan = BootPlan {
        input,
        kernel_reserved,
        layout: RootLayout::at(start, &input.root),
        framebuffer: FramebufferStatus::Absent,
    };
    plan.framebuffer = framebuffer_status(&plan);
    Ok(plan)
}

fn place(input: &BootInput, reserved: &KernelReserved, size: u64) -> Result<u64, BootError> {
    let ceiling = input.direct_map_end.min(input.top());
    let usable = input
        .memory_map
        .iter()
        .rev()
        .filter(|r| r.kind == RegionKind::USABLE);
    for r in usable {
        let low = r.base.max(LOW_MEMORY_END);
        let mut high = r.end().min(ceiling);
        while high > low && high - low >= size {
            let start = round_down(high - size, ROOT_CNODE_BYTES);
            if start < low {
                break;
            }
            let span = Span {
                start,
                end: start + size,
            };
            // Move below the lowest forbidden range it touches.
            let conflict = reserved
                .iter()
                .map(widen_2m)
                .chain([input.kernel_image])
                .filter(|z| overlaps(*z, span))
                .map(|z| z.start)
                .min();
            match conflict {
                Some(z) => high = z,
                None => return Ok(start),
            }
        }
    }
    Err(BootError::NoRoom {
        size,
        align: ROOT_CNODE_BYTES,
    })
}

/// Whether the direct map maps the 2 MiB page holding `addr` write-back.
/// Pages at or above its end are not mapped at all.
pub fn write_back(input: &BootInput, addr: u64) -> bool {
    let page = round_down(addr, PAGE_2M);
    page < input.direct_map_end
        && vspace::direct_map_type(input.memory_map, &input.window, page) == CacheType::WriteBack
}

/// Whether the 2 MiB page holding `addr` holds a kernel device page, so the
/// direct map maps it uncached.
pub fn holds_device_page(window: &DeviceWindow, addr: u64) -> bool {
    let page = round_down(addr, PAGE_2M);
    window
        .pages
        .iter()
        .flatten()
        .any(|&d| round_down(d, PAGE_2M) == page)
}

/// The class a memory-map kind gives its pages before the later rules.
fn kind_class(kind: RegionKind) -> PageClass {
    match kind {
        RegionKind::USABLE | RegionKind::LOADER | RegionKind::ACPI_RECLAIMABLE => PageClass::Ram,
        RegionKind::RESERVED | RegionKind::MMIO => PageClass::Device,
        // ACPI_NVS, FIRMWARE, BAD, and kinds the loader never writes.
        _ => PageClass::Nothing,
    }
}

/// Whether a region of `kind` is firmware's or broken: no untyped of any
/// kind may cover it.
pub fn is_firmware_or_bad(kind: RegionKind) -> bool {
    kind_class(kind) == PageClass::Nothing
}

/// The region holding `addr`, in a sorted map.
fn region_at(map: &[MemoryRegion], addr: u64) -> Option<&MemoryRegion> {
    let i = map.partition_point(|r| r.end() <= addr);
    map.get(i).filter(|r| r.base <= addr && addr < r.end())
}

fn framebuffer_status(plan: &BootPlan) -> FramebufferStatus {
    let input = &plan.input;
    let fb = input.framebuffer;
    if fb.base == 0 || fb.size == 0 {
        return FramebufferStatus::Absent;
    }
    let end = fb.base.checked_add(fb.size);
    let span = Span {
        start: round_down(fb.base, PAGE_4K),
        end: round_up(end.unwrap_or(u64::MAX), PAGE_4K),
    };
    let reject = |reason| FramebufferStatus::Rejected { span, reason };
    if end.is_none() || span.start < LOW_MEMORY_END || span.end > input.top() {
        return reject(FramebufferRejection::OutOfRange);
    }
    // Every mapped 2 MiB page that overlaps RAM-like memory is write-back
    // unless it holds one of the window's pages, so each region needs a few
    // checks.
    let wide = widen_2m(span);
    for r in input
        .memory_map
        .iter()
        .filter(|r| vspace::is_ram_like(r.kind))
    {
        let ram = widen_2m(Span {
            start: r.base,
            end: r.end(),
        });
        let mut page = wide.start.max(ram.start);
        while page < wide.end.min(ram.end).min(input.direct_map_end) {
            if write_back(input, page) {
                return reject(FramebufferRejection::WriteBack { page });
            }
            page += PAGE_2M;
        }
    }
    let k = input.kernel_image;
    if overlaps(span, k) {
        return reject(FramebufferRejection::Overlaps("the kernel image"));
    }
    if overlaps(span, plan.layout.region) {
        return reject(FramebufferRejection::Overlaps("the boot region"));
    }
    if plan.kernel_reserved.overlaps(span) {
        return reject(FramebufferRejection::Overlaps("a kernel-reserved page"));
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
        return reject(FramebufferRejection::Overlaps("firmware or bad memory"));
    }
    FramebufferStatus::Untyped(span)
}

/// What a physical page becomes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PageClass {
    /// RAM untyped.
    Ram,
    /// Device untyped.
    Device,
    /// The framebuffer's own device untyped, listed first.
    Framebuffer,
    /// No untyped.
    Nothing,
}

/// What the page at `page` becomes: `docs/design.md`, "What each physical
/// page becomes", its rows applied in order, each overriding the ones
/// before.
pub fn page_class(plan: &BootPlan, page: u64) -> PageClass {
    let input = &plan.input;
    if page >= input.top() {
        return PageClass::Nothing;
    }
    // USABLE, LOADER, ACPI_RECLAIMABLE: RAM. RESERVED, MMIO and gaps:
    // device. ACPI_NVS, FIRMWARE, BAD: nothing.
    let mut class =
        region_at(input.memory_map, page).map_or(PageClass::Device, |r| kind_class(r.kind));
    // The kernel image, except `.rootimage`, which keeps the LOADER row's.
    if input.kernel_image.contains(page) && !input.rootimage.is_some_and(|r| r.contains(page)) {
        class = PageClass::Nothing;
    }
    // The framebuffer: its own device untyped, or none at all.
    match plan.framebuffer {
        FramebufferStatus::Untyped(span) if span.contains(page) => class = PageClass::Framebuffer,
        FramebufferStatus::Rejected { span, .. } if span.contains(page) => {
            class = PageClass::Nothing
        }
        _ => {}
    }
    // No device untyped in a write-back 2 MiB page.
    if class == PageClass::Device && write_back(input, page) {
        class = PageClass::Nothing;
    }
    // No RAM untyped in a 2 MiB page holding a kernel device page.
    if class == PageClass::Ram && holds_device_page(&input.window, page) {
        class = PageClass::Nothing;
    }
    // Low memory, the boot region and `kernel_reserved`.
    if page < LOW_MEMORY_END
        || plan.layout.region.contains(page)
        || plan.kernel_reserved.contains(page)
    {
        class = PageClass::Nothing;
    }
    // RAM the direct map does not reach, last.
    if class == PageClass::Ram && page >= input.direct_map_end {
        class = PageClass::Nothing;
    }
    class
}

/// The lowest address above `at` where [`page_class`] may change. Between
/// two of these, every page lies in the same memory-map entry or gap, on the
/// same side of every fixed bound, and in 2 MiB pages of one cache type
/// that hold no kernel device page or all hold one: a 2 MiB page's type can
/// only differ from its neighbour's where a region bound or a device page
/// lies within 2 MiB, and both roundings of those are here.
fn next_boundary(plan: &BootPlan, at: u64) -> u64 {
    let input = &plan.input;
    let top = input.top();
    let mut best = top;
    let mut consider = |c: u64| {
        if c > at && c < best {
            best = c;
        }
    };
    for r in input.memory_map {
        for x in [r.base, r.end()] {
            consider(x);
            consider(round_down(x, PAGE_2M));
            consider(round_up(x, PAGE_2M));
        }
    }
    for &d in input.window.pages.iter().flatten() {
        let page = round_down(d, PAGE_2M);
        consider(page);
        consider(page.saturating_add(PAGE_2M));
    }
    for s in plan.kernel_reserved.iter() {
        consider(s.start);
        consider(s.end);
    }
    let fixed = [
        Some(input.kernel_image),
        input.rootimage,
        plan.framebuffer.span(),
        Some(plan.layout.region),
    ];
    for s in fixed.into_iter().flatten() {
        consider(s.start);
        consider(s.end);
    }
    consider(LOW_MEMORY_END);
    consider(input.direct_map_end);
    best
}

/// Maximal runs of one class, by ascending address, up to
/// `2^phys_addr_bits`.
pub fn runs<'p, 'a>(plan: &'p BootPlan<'a>) -> impl Iterator<Item = (Span, PageClass)> + 'p {
    let top = plan.input.top();
    let mut at = 0;
    core::iter::from_fn(move || {
        if at >= top {
            return None;
        }
        let class = page_class(plan, at);
        let mut end = next_boundary(plan, at);
        while end < top && page_class(plan, end) == class {
            end = next_boundary(plan, end);
        }
        let run = Span { start: at, end };
        at = end;
        Some((run, class))
    })
}

/// The largest naturally aligned power-of-two pieces of `span`, at most
/// `2^MAX_UNTYPED_BITS`, by ascending address (seL4's
/// `create_untypeds_for_region`): `(base, size_bits)`. A page-aligned span
/// gives pieces of at least 4 KiB.
pub fn chunks(span: Span) -> impl Iterator<Item = (u64, u32)> {
    let mut at = span.start;
    core::iter::from_fn(move || {
        if at >= span.end {
            return None;
        }
        let mut bits = (span.end - at).ilog2().min(MAX_UNTYPED_BITS);
        if at != 0 {
            bits = bits.min(at.trailing_zeros());
        }
        let base = at;
        at += 1 << bits;
        Some((base, bits))
    })
}

/// What [`untyped`] made.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UntypedSummary {
    /// Descriptors written.
    pub count: usize,
    /// The leading descriptors that cover the framebuffer.
    pub framebuffer: usize,
    /// Bytes of RAM untyped.
    pub ram_bytes: u64,
    /// Bytes of device untyped, the framebuffer's included.
    pub device_bytes: u64,
}

/// Step 9: classifies every page below `2^phys_addr_bits` with
/// [`page_class`], merges runs of one class, cuts each into [`chunks`],
/// and writes the descriptors to `out`: the framebuffer's first, then the
/// rest by ascending address. The rest of `out` is zeroed. More than
/// [`MAX_UNTYPED`] is an error carrying the count; nothing is dropped.
pub fn untyped(
    plan: &BootPlan,
    out: &mut [UntypedDesc; MAX_UNTYPED],
) -> Result<UntypedSummary, BootError> {
    let mut summary = UntypedSummary::default();
    let mut push = |s: &mut UntypedSummary, (paddr, bits): (u64, u32), device: bool| {
        if let Some(d) = out.get_mut(s.count) {
            *d = UntypedDesc::new(paddr, bits, device);
        }
        s.count += 1;
        if device {
            s.device_bytes += 1 << bits;
        } else {
            s.ram_bytes += 1 << bits;
        }
    };
    if let FramebufferStatus::Untyped(span) = plan.framebuffer {
        for c in chunks(span) {
            push(&mut summary, c, true);
        }
        summary.framebuffer = summary.count;
    }
    for (span, class) in runs(plan) {
        let device = match class {
            PageClass::Ram => false,
            PageClass::Device => true,
            PageClass::Framebuffer | PageClass::Nothing => continue,
        };
        for c in chunks(span) {
            push(&mut summary, c, device);
        }
    }
    if summary.count > MAX_UNTYPED {
        return Err(BootError::TooManyUntyped {
            count: summary.count,
        });
    }
    out[summary.count..].fill(UntypedDesc::default());
    Ok(summary)
}

/// BootInfo's slot regions (`docs/abi.md`, "Initial CSpace"): from slot 16,
/// the second BootInfo frame, the paging structures, the image frames, the
/// untyped, then empty slots to the root CNode's end.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotPlan {
    pub extra_bootinfo_frames: SlotRegion,
    pub user_image_paging: SlotRegion,
    pub user_image_frames: SlotRegion,
    pub untyped: SlotRegion,
    pub framebuffer_untyped: SlotRegion,
    pub empty: SlotRegion,
}

/// The slot regions for the root task's needs and the untyped [`untyped`]
/// made; an error if they do not fit the root CNode.
pub fn slot_plan(needs: &RootNeeds, untyped: &UntypedSummary) -> Result<SlotPlan, BootError> {
    let mut next = NUM_INITIAL_SLOTS;
    let mut region = |n: u64| {
        let r = SlotRegion {
            start: next,
            end: next.saturating_add(n),
        };
        next = r.end;
        r
    };
    let extra_bootinfo_frames = region(BOOTINFO_FRAMES - 1);
    let user_image_paging = region(needs.paging());
    let user_image_frames = region(needs.image_frames);
    let untyped_slots = region(untyped.count as u64);
    if next > ROOT_CNODE_SLOTS {
        return Err(BootError::TooManySlots { needed: next });
    }
    Ok(SlotPlan {
        extra_bootinfo_frames,
        user_image_paging,
        user_image_frames,
        untyped: untyped_slots,
        framebuffer_untyped: SlotRegion {
            start: untyped_slots.start,
            end: untyped_slots.start + untyped.framebuffer as u64,
        },
        empty: SlotRegion {
            start: next,
            end: ROOT_CNODE_SLOTS,
        },
    })
}

/// The BootInfo fields the plan does not decide.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootFacts<'a> {
    /// The IPC buffer's virtual address in the root task; 0 until M5.
    pub ipc_buffer: u64,
    /// The root image's virtual pages; empty (0 to 0) until M5.
    pub user_image: Span,
    /// The handoff's RSDP address.
    pub rsdp: u64,
    /// The calibrated TSC rate.
    pub tsc_hz: u64,
    /// One of the `bootinfo::HYPERVISOR_*` numbers.
    pub hypervisor_vendor: u32,
    /// The handoff's command line; cut at 256 bytes.
    pub cmdline: &'a [u8],
    /// From [`InterruptInfo::from_platform`].
    pub interrupts: InterruptInfo,
}

/// Writes every BootInfo field except `untyped_list`, which [`untyped`]
/// writes.
pub fn fill_bootinfo(bi: &mut BootInfo, plan: &BootPlan, slots: &SlotPlan, facts: &BootFacts) {
    let cmdline_len = facts.cmdline.len().min(CMDLINE_MAX);
    let mut cmdline = [0; CMDLINE_MAX];
    cmdline[..cmdline_len].copy_from_slice(&facts.cmdline[..cmdline_len]);
    let framebuffer = match plan.framebuffer {
        FramebufferStatus::Absent => Framebuffer::default(),
        _ => plan.input.framebuffer,
    };
    // Field by field: BootInfo is 8 KiB, too big for a temporary on the
    // kernel stack.
    bi.magic = BOOTINFO_MAGIC;
    bi.version = BOOTINFO_VERSION;
    bi.size = BOOTINFO_SIZE as u32;
    bi.ipc_buffer = facts.ipc_buffer;
    bi.root_cnode_bits = u64::from(ROOT_CNODE_RADIX);
    bi.empty = slots.empty;
    bi.user_image_frames = slots.user_image_frames;
    bi.user_image_paging = slots.user_image_paging;
    bi.extra_bootinfo_frames = slots.extra_bootinfo_frames;
    bi.untyped = slots.untyped;
    bi.framebuffer_untyped = slots.framebuffer_untyped;
    bi.user_image_start = facts.user_image.start;
    bi.user_image_end = facts.user_image.end;
    bi.framebuffer = framebuffer;
    bi.rsdp = facts.rsdp;
    bi.tsc_hz = facts.tsc_hz;
    bi.hypervisor_vendor = facts.hypervisor_vendor;
    bi.phys_addr_bits = plan.input.phys_addr_bits;
    bi.cmdline_len = cmdline_len as u64;
    bi.cmdline = cmdline;
    bi.reserved0 = [0; 48];
    bi.interrupts = facts.interrupts;
    bi.reserved1 = [0; 256];
}

/// Step 9 in one call: [`untyped`] into `bi.untyped_list`, then
/// [`slot_plan`], then [`fill_bootinfo`].
pub fn write_bootinfo(
    bi: &mut BootInfo,
    plan: &BootPlan,
    facts: &BootFacts,
) -> Result<(UntypedSummary, SlotPlan), BootError> {
    let summary = untyped(plan, &mut bi.untyped_list)?;
    let slots = slot_plan(&plan.input.root, &summary)?;
    fill_bootinfo(bi, plan, &slots, facts);
    Ok((summary, slots))
}

/// A 4 KiB RAM Frame capability with full rights, unmapped (data word 0).
fn frame_cap(paddr: u64) -> Cap {
    Cap::new(
        CapType::Frame,
        paddr,
        FRAME_4K_BITS,
        ObjectType::Frame4K.full_rights(),
        false,
        0,
    )
}

/// The root CNode's own capability: radix 12, guard 0 of size 52.
pub fn root_cnode_cap(cnode: u64) -> Cap {
    Cap::cnode(cnode, ROOT_CNODE_RADIX, ROOT_CNODE_GUARD_SIZE, 0)
}

/// The capability boot puts in root CNode slot `slot`: null where there is
/// none. Every one is an original with full rights; frames and paging
/// structures are unmapped (M5 maps the image's, writing their mapping
/// records); untyped have their watermark at their size, so the first
/// retype clears them. `untyped` is BootInfo's list, which slot
/// `slots.untyped.start + i` follows.
pub fn root_cap(plan: &BootPlan, slots: &SlotPlan, untyped: &[UntypedDesc], slot: u64) -> Cap {
    let l = &plan.layout;
    let object =
        |ty: CapType, paddr: u64, bits: u32| Cap::new(ty, paddr, bits, Rights::NONE, false, 0);
    match slot {
        CAP_INIT_TCB => l
            .tcb
            .map_or(Cap::NULL, |t| object(CapType::Tcb, t, TCB_BITS)),
        CAP_INIT_CNODE => root_cnode_cap(l.cnode),
        CAP_INIT_VSPACE => l.pml4.map_or(Cap::NULL, |p| {
            object(CapType::Pml4, p, PAGING_STRUCTURE_BITS)
        }),
        CAP_IRQ_CONTROL => object(CapType::IrqControl, 0, 0),
        CAP_IO_PORT_CONTROL => object(CapType::IoPortControl, 0, 0),
        CAP_BOOTINFO_FRAME => frame_cap(l.bootinfo),
        CAP_INIT_IPC_BUFFER => frame_cap(l.ipc_buffer),
        CAP_HYPERVISOR => match (plan.input.root.hypervisor, l.synic) {
            (Some(cap), Some(_)) => cap,
            _ => Cap::NULL,
        },
        CAP_SYNIC_MESSAGE_FRAME => l.synic.map_or(Cap::NULL, |s| frame_cap(s.message)),
        CAP_SYNIC_EVENT_FRAME => l.synic.map_or(Cap::NULL, |s| frame_cap(s.event)),
        s if slots.extra_bootinfo_frames.contains(s) => {
            frame_cap(l.bootinfo + PAGE_4K * (1 + s - slots.extra_bootinfo_frames.start))
        }
        s if slots.user_image_paging.contains(s) => {
            let (ty, paddr) = l.paging_object(s - slots.user_image_paging.start);
            object(ty, paddr, PAGING_STRUCTURE_BITS)
        }
        s if slots.user_image_frames.contains(s) => {
            frame_cap(l.image_frame(s - slots.user_image_frames.start))
        }
        s if slots.untyped.contains(s) => untyped
            .get((s - slots.untyped.start) as usize)
            .map_or(Cap::NULL, |d| {
                Cap::untyped(d.paddr, u32::from(d.size_bits), d.device(), d.size())
            }),
        _ => Cap::NULL,
    }
}

/// Steps 7 and 9: puts [`root_cap`] of every slot in the zeroed root CNode,
/// each as a derivation root (`cdt::insert_root`).
pub fn write_root_cnode<M: SlotMemory + ?Sized>(
    mem: &mut M,
    plan: &BootPlan,
    slots: &SlotPlan,
    untyped: &[UntypedDesc],
) {
    for slot in 0..ROOT_CNODE_SLOTS {
        let cap = root_cap(plan, slots, untyped, slot);
        if !cap.is_null() {
            cdt::insert_root(mem, plan.layout.slot(slot), cap);
        }
    }
}
