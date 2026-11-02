//! Host tests for the boot plan: the memory maps recorded from QEMU and
//! Hyper-V, hand-made edge cases, and random maps. Every plan is checked
//! with `check` and its descriptor list compared with [`reference`], a
//! second implementation of the rules that paints intervals.

use alloc::format;
use alloc::string::String;
use alloc::vec;
use alloc::vec::Vec;
use std::println;
use std::sync::OnceLock;

use proptest::prelude::*;
use proptest::sample::Index;

use super::check::{self, Violation};
use super::*;
use crate::acpi::{self, dump::DumpMemory};
use crate::bootinfo::{
    CAP_NULL, HYPERVISOR_QEMU_TCG, IsaRoute, ROOT_CNODE_GUARD_SIZE, ROOT_CNODE_SLOTS,
};
use crate::handoff::PixelFormat;
use crate::testing::FakeMemory;

const Q35_MAP: &str = include_str!("../../tests/boot/q35.memmap");
const HYPERV_MAP: &str = include_str!("../../tests/boot/hyperv-gen2.memmap");
const Q35_ACPI: &str = include_str!("../../tests/acpi/q35.dump");
const HYPERV_ACPI: &str = include_str!("../../tests/acpi/hyperv-gen2.dump");

const K4: u64 = 1 << 12;
const KIB: u64 = 1 << 10;
const MIB: u64 = 1 << 20;
const GIB: u64 = 1 << 30;

/// `IA32_APIC_BASE` as both firmwares hand it over.
const APIC_BASE_MSR: u64 = 0xFEE0_0900;

const U: RegionKind = RegionKind::USABLE;
const L: RegionKind = RegionKind::LOADER;
const R: RegionKind = RegionKind::RESERVED;
const NVS: RegionKind = RegionKind::ACPI_NVS;
const BAD: RegionKind = RegionKind::BAD;

fn region(base: u64, len: u64, kind: RegionKind) -> MemoryRegion {
    MemoryRegion::new(base, len, kind)
}

fn span(start: u64, end: u64) -> Span {
    Span { start, end }
}

// ---------------------------------------------------------------------
// The recorded boots.

/// What a boot log's memory lines give.
#[derive(Clone, Debug)]
struct Recorded {
    regions: Vec<MemoryRegion>,
    kernel: Span,
    direct_map_end: u64,
    framebuffer: Framebuffer,
}

fn hex(s: &str) -> u64 {
    let s = s.trim_end_matches(',');
    u64::from_str_radix(s.strip_prefix("0x").unwrap(), 16).unwrap()
}

fn kind_named(name: &str) -> RegionKind {
    (1..=8).map(RegionKind).find(|k| k.name() == name).unwrap()
}

/// Reads the `kernel:`, `memory:`, region and `framebuffer:` lines the
/// kernel prints at boot.
fn parse_log(text: &str) -> Recorded {
    let mut rec = Recorded {
        regions: Vec::new(),
        kernel: span(0, 0),
        direct_map_end: 0,
        framebuffer: Framebuffer::default(),
    };
    for line in text.lines().filter(|l| !l.starts_with('#')) {
        let words: Vec<&str> = line.split_whitespace().collect();
        if let Some(rest) = line.strip_prefix("kernel: ") {
            // "600 KiB at phys 0xdead000, virt 0xffffffff80000000"
            let w: Vec<&str> = rest.split_whitespace().collect();
            assert_eq!((w[1], w[3]), ("KiB", "phys"));
            let base = hex(w[4]);
            rec.kernel = span(base, base + w[0].parse::<u64>().unwrap() * KIB);
        } else if line.starts_with("memory: ") {
            // "... direct map covers 4 GiB"
            let n = words.len();
            assert_eq!((words[n - 3], words[n - 1]), ("covers", "GiB"));
            let phys_map_size = words[n - 2].parse::<u64>().unwrap() * GIB;
            rec.direct_map_end = phys_map_size.min(DIRECT_MAP_MAX);
        } else if let Some(rest) = line.strip_prefix("framebuffer: ") {
            // "1280x800, stride 1280, BGR at 0x80000000"
            let w: Vec<&str> = rest.split_whitespace().collect();
            let (width, height) = w[0].trim_end_matches(',').split_once('x').unwrap();
            let (width, height): (u32, u32) = (width.parse().unwrap(), height.parse().unwrap());
            let stride: u32 = w[2].trim_end_matches(',').parse().unwrap();
            rec.framebuffer = Framebuffer {
                base: hex(w[5]),
                size: u64::from(stride) * u64::from(height) * 4,
                width,
                height,
                stride,
                format: if w[3] == "BGR" {
                    PixelFormat::BGR
                } else {
                    PixelFormat::RGB
                },
            };
        } else if words.len() == 2 && words[0].starts_with("0x") {
            // "0x000000000000-0x0000000a0000 usable"
            let (base, end) = words[0].split_once('-').unwrap();
            let (base, end) = (hex(base), hex(end));
            rec.regions
                .push(region(base, end - base, kind_named(words[1])));
        }
    }
    assert!(!rec.regions.is_empty() && rec.kernel.start != 0 && rec.direct_map_end != 0);
    rec
}

fn q35_log() -> &'static Recorded {
    static R: OnceLock<Recorded> = OnceLock::new();
    R.get_or_init(|| parse_log(Q35_MAP))
}

fn hyperv_log() -> &'static Recorded {
    static R: OnceLock<Recorded> = OnceLock::new();
    R.get_or_init(|| parse_log(HYPERV_MAP))
}

/// Each ACPI dump, parsed once per test process: the hex is slow under
/// Miri.
fn q35_acpi() -> &'static acpi::Platform {
    static P: OnceLock<acpi::Platform> = OnceLock::new();
    P.get_or_init(|| {
        let m = DumpMemory::parse(Q35_ACPI).unwrap();
        acpi::parse(&m, m.rsdp().unwrap()).unwrap()
    })
}

fn hyperv_acpi() -> &'static acpi::Platform {
    static P: OnceLock<acpi::Platform> = OnceLock::new();
    P.get_or_init(|| {
        let m = DumpMemory::parse(HYPERV_ACPI).unwrap();
        acpi::parse(&m, m.rsdp().unwrap()).unwrap()
    })
}

/// A recorded boot.
#[derive(Clone, Copy, Debug)]
enum Boot {
    Q35,
    HyperV,
}

impl Boot {
    fn log(self) -> &'static Recorded {
        match self {
            Boot::Q35 => q35_log(),
            Boot::HyperV => hyperv_log(),
        }
    }

    fn acpi(self) -> &'static acpi::Platform {
        match self {
            Boot::Q35 => q35_acpi(),
            Boot::HyperV => hyperv_acpi(),
        }
    }

    /// The device window the boot had: the local APIC from
    /// `IA32_APIC_BASE`, the I/O APIC and, on q35, the HPET from the ACPI
    /// dump. Constants, so the tests under Miri need not decode the dumps;
    /// `recorded_windows_are_the_dumps` checks them.
    fn window(self) -> DeviceWindow {
        let mut w = DeviceWindow::default();
        w.pages[window::LAPIC_PAGE] = Some(0xFEE0_0000);
        w.pages[window::ioapic_page(0)] = Some(0xFEC0_0000);
        if let Boot::Q35 = self {
            w.pages[window::HPET_PAGE] = Some(0xFED0_0000);
        }
        w
    }

    /// `InterruptInfo` from the dump, with QEMU's and Hyper-V's 24 pins;
    /// zero under Miri, where decoding the dumps takes minutes.
    fn interrupts(self) -> InterruptInfo {
        if cfg!(miri) {
            InterruptInfo::ZERO
        } else {
            InterruptInfo::from_platform(self.acpi(), &[24])
        }
    }

    fn input(self, bits: u32) -> BootInput<'static> {
        let rec = self.log();
        BootInput {
            memory_map: &rec.regions,
            kernel_image: rec.kernel,
            rootimage: None,
            direct_map_end: rec.direct_map_end,
            phys_addr_bits: bits,
            window: self.window(),
            locked_hypercall_page: None,
            framebuffer: rec.framebuffer,
            root: RootNeeds::default(),
        }
    }
}

#[test]
#[cfg_attr(miri, ignore = "decodes the ACPI dumps: minutes under Miri")]
fn recorded_windows_are_the_dumps() {
    for boot in [Boot::Q35, Boot::HyperV] {
        assert_eq!(boot.acpi().device_window(APIC_BASE_MSR), boot.window());
    }
}

fn facts(interrupts: InterruptInfo) -> BootFacts<'static> {
    BootFacts {
        ipc_buffer: 0,
        user_image: span(0, 0),
        rsdp: 0xFB7_E014,
        tsc_hz: 2_100_106_846,
        hypervisor_vendor: HYPERVISOR_QEMU_TCG,
        cmdline: b"test=hello",
        interrupts,
    }
}

// ---------------------------------------------------------------------
// A second implementation of "What each physical page becomes": paint
// intervals row by row, each row over the ones before.

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum C {
    Ram,
    Dev,
    Fb,
    No,
}

/// Contiguous `(start, end, class)` intervals covering `[0, top)`.
struct Paint {
    top: u64,
    v: Vec<(u64, u64, C)>,
}

impl Paint {
    fn new(top: u64) -> Paint {
        Paint {
            top,
            v: vec![(0, top, C::Dev)],
        }
    }

    fn split(&mut self, x: u64) {
        if let Some(i) = self.v.iter().position(|&(s, e, _)| s < x && x < e) {
            let (s, e, c) = self.v[i];
            self.v[i] = (s, x, c);
            self.v.insert(i + 1, (x, e, c));
        }
    }

    /// Applies `f` to the class of every byte in `[a, b)`.
    fn set(&mut self, a: u64, b: u64, f: impl Fn(C) -> C) {
        let b = b.min(self.top);
        if a >= b {
            return;
        }
        self.split(a);
        self.split(b);
        for iv in self.v.iter_mut().filter(|iv| iv.0 >= a && iv.1 <= b) {
            iv.2 = f(iv.2);
        }
    }

    fn fill(&mut self, a: u64, b: u64, c: C) {
        self.set(a, b, |_| c);
    }

    /// Merged runs of one class.
    fn runs(&self) -> Vec<(u64, u64, C)> {
        let mut out: Vec<(u64, u64, C)> = Vec::new();
        for &(s, e, c) in &self.v {
            match out.last_mut() {
                Some(last) if last.2 == c && last.1 == s => last.1 = e,
                _ => out.push((s, e, c)),
            }
        }
        out
    }
}

fn ref_kind(kind: RegionKind) -> C {
    match kind {
        RegionKind::USABLE | RegionKind::LOADER | RegionKind::ACPI_RECLAIMABLE => C::Ram,
        RegionKind::RESERVED | RegionKind::MMIO => C::Dev,
        _ => C::No,
    }
}

fn ref_ram_like(kind: RegionKind) -> bool {
    matches!(
        kind,
        RegionKind::USABLE
            | RegionKind::LOADER
            | RegionKind::ACPI_RECLAIMABLE
            | RegionKind::ACPI_NVS
            | RegionKind::FIRMWARE
    )
}

/// Whether the direct map maps the 2 MiB page at `page` write-back: it is
/// mapped, overlaps RAM-like memory, and holds no window page.
fn ref_wb(input: &BootInput, page: u64) -> bool {
    page < input.direct_map_end
        && input
            .memory_map
            .iter()
            .any(|r| ref_ram_like(r.kind) && r.len > 0 && r.base < page + PAGE_2M && r.end() > page)
        && !input
            .window
            .pages
            .iter()
            .flatten()
            .any(|&w| w / PAGE_2M == page / PAGE_2M)
}

fn ref_overlap(a: Span, b: Span) -> bool {
    a.start.max(b.start) < a.end.min(b.end)
}

/// The framebuffer's page-rounded range and whether it gets untyped.
fn ref_framebuffer(plan: &BootPlan) -> Option<(Span, bool)> {
    let input = &plan.input;
    let fb = input.framebuffer;
    if fb.base == 0 || fb.size == 0 {
        return None;
    }
    let start = fb.base / K4 * K4;
    let Some(end) = fb
        .base
        .checked_add(fb.size)
        .and_then(|e| e.checked_add(K4 - 1))
    else {
        return Some((span(start, u64::MAX / K4 * K4), false));
    };
    let s = span(start, end / K4 * K4);
    let mut ok = s.start >= MIB && s.end <= input.top();
    let mut page = s.start / PAGE_2M * PAGE_2M;
    while ok && page < s.end {
        ok = !ref_wb(input, page);
        page += PAGE_2M;
    }
    ok = ok
        && !ref_overlap(s, input.kernel_image)
        && !ref_overlap(s, plan.layout.region)
        && !plan.kernel_reserved.iter().any(|k| ref_overlap(s, k))
        && !input
            .memory_map
            .iter()
            .any(|r| ref_kind(r.kind) == C::No && ref_overlap(s, span(r.base, r.end())));
    Some((s, ok))
}

/// Naturally aligned power-of-two pieces, at most 2^47, largest first.
fn ref_chunks(mut a: u64, end: u64, device: bool, out: &mut Vec<UntypedDesc>) {
    while a < end {
        let mut bits = 47;
        while !a.is_multiple_of(1 << bits) || a + (1 << bits) > end {
            bits -= 1;
        }
        assert!(bits >= 12, "a run that is not page-aligned");
        out.push(UntypedDesc::new(a, bits, device));
        a += 1 << bits;
    }
}

/// The descriptor list and the framebuffer's share of it, by painting.
fn reference(plan: &BootPlan) -> (Vec<UntypedDesc>, usize) {
    let input = &plan.input;
    let top = input.top();
    let mut p = Paint::new(top);
    for r in input.memory_map {
        p.fill(r.base, r.end(), ref_kind(r.kind));
    }
    let k = input.kernel_image;
    p.fill(k.start, k.end, C::No);
    if let Some(ri) = input.rootimage {
        // Back to what the rows before gave it.
        p.fill(ri.start, ri.end, C::Dev);
        for r in input.memory_map {
            p.fill(r.base.max(ri.start), r.end().min(ri.end), ref_kind(r.kind));
        }
    }
    if let Some((s, ok)) = ref_framebuffer(plan) {
        p.fill(s.start, s.end, if ok { C::Fb } else { C::No });
    }
    for r in input
        .memory_map
        .iter()
        .filter(|r| ref_ram_like(r.kind) && r.len > 0)
    {
        // Runs of write-back pages, one paint each.
        let mut page = r.base / PAGE_2M * PAGE_2M;
        while page < r.end() {
            let start = page;
            while page < r.end() && ref_wb(input, page) {
                page += PAGE_2M;
            }
            p.set(start, page, |c| if c == C::Dev { C::No } else { c });
            page = page.max(start + PAGE_2M);
        }
    }
    for &w in input.window.pages.iter().flatten() {
        let page = w / PAGE_2M * PAGE_2M;
        p.set(
            page,
            page + PAGE_2M,
            |c| if c == C::Ram { C::No } else { c },
        );
    }
    p.fill(0, MIB, C::No);
    p.fill(plan.layout.region.start, plan.layout.region.end, C::No);
    for s in plan.kernel_reserved.iter() {
        p.fill(s.start, s.end, C::No);
    }
    p.set(input.direct_map_end, top, |c| {
        if c == C::Ram { C::No } else { c }
    });

    let runs = p.runs();
    let mut out = Vec::new();
    for &(s, e, _) in runs.iter().filter(|r| r.2 == C::Fb) {
        ref_chunks(s, e, true, &mut out);
    }
    let fb = out.len();
    for &(s, e, c) in &runs {
        match c {
            C::Ram => ref_chunks(s, e, false, &mut out),
            C::Dev => ref_chunks(s, e, true, &mut out),
            _ => {}
        }
    }
    (out, fb)
}

/// The highest aligned place for `size` bytes, by trying every one.
fn ref_place(input: &BootInput, size: u64) -> Option<u64> {
    let reserved = kernel_reserved(&input.window, input.locked_hypercall_page);
    let mut forbidden: Vec<Span> = reserved
        .iter()
        .map(|s| {
            span(
                s.start / PAGE_2M * PAGE_2M,
                s.end.div_ceil(PAGE_2M) * PAGE_2M,
            )
        })
        .collect();
    forbidden.push(input.kernel_image);
    let ceiling = input.direct_map_end.min(input.top());
    for r in input.memory_map.iter().rev().filter(|r| r.kind == U) {
        let (lo, hi) = (r.base.max(MIB), r.end().min(ceiling));
        if hi < lo + size {
            continue;
        }
        let mut s = (hi - size) / ROOT_CNODE_BYTES * ROOT_CNODE_BYTES;
        while s >= lo {
            if !forbidden.iter().any(|&f| ref_overlap(f, span(s, s + size))) {
                return Some(s);
            }
            if s < ROOT_CNODE_BYTES {
                break;
            }
            s -= ROOT_CNODE_BYTES;
        }
    }
    None
}

// ---------------------------------------------------------------------
// Checking a plan end to end.

/// What [`build`] made.
struct Built {
    bi: BootInfo,
    summary: UntypedSummary,
    slots: SlotPlan,
}

/// Steps 6 to 9 for `input`, with every check: the plan, BootInfo, and,
/// on the host, the descriptors against [`reference`] and the root CNode
/// in fake memory. Under Miri those two take seconds a plan and test only
/// test code and fake memory, so it leaves them out.
fn build(input: BootInput, interrupts: InterruptInfo) -> Result<Built, BootError> {
    let full = !cfg!(miri);
    let plan = plan(input)?;
    check::check_plan(&plan).unwrap();
    if full {
        assert_eq!(
            Some(plan.layout.region.start),
            ref_place(&plan.input, RootLayout::size(&plan.input.root))
        );
    }
    let mut bi = BootInfo::ZERO;
    let result = write_bootinfo(&mut bi, &plan, &facts(interrupts));
    if full {
        let (want, want_fb) = reference(&plan);
        match result {
            Ok((summary, _)) => {
                assert_eq!(bi.untyped(), &want[..]);
                assert_eq!(summary.framebuffer, want_fb);
            }
            Err(BootError::TooManyUntyped { count }) => assert_eq!(count, want.len()),
            Err(_) => {}
        }
    }
    let (summary, slots) = match result {
        Ok(r) => r,
        Err(e) => {
            if let BootError::TooManyUntyped { count } = e {
                assert!(count > MAX_UNTYPED);
            }
            return Err(e);
        }
    };
    assert_eq!(summary.count, bi.untyped().len());
    let bytes = |device: bool| {
        bi.untyped()
            .iter()
            .filter(|d| d.device() == device)
            .map(|d| d.size())
            .sum::<u64>()
    };
    assert_eq!(
        (summary.ram_bytes, summary.device_bytes),
        (bytes(false), bytes(true))
    );
    if let Err(v) = check::check_bootinfo(&plan, &bi) {
        panic!("{v}: {:#x?}", bi.untyped());
    }
    assert_eq!(check::slot_plan_of(&bi), slots);
    if full {
        for (i, d) in bi.untyped().iter().enumerate() {
            assert_eq!(
                page_class(&plan, d.paddr),
                if i < summary.framebuffer {
                    PageClass::Framebuffer
                } else if d.device() {
                    PageClass::Device
                } else {
                    PageClass::Ram
                }
            );
        }
        check_root_cnode(&plan, &bi, &slots);
    }
    Ok(Built { bi, summary, slots })
}

/// Writes the root CNode into fake memory and checks every slot.
fn check_root_cnode(plan: &BootPlan, bi: &BootInfo, slots: &SlotPlan) -> FakeMemory {
    let mut mem = FakeMemory::new(plan.layout.cnode, ROOT_CNODE_BYTES);
    write_root_cnode(&mut mem, plan, slots, bi.untyped());
    check::check_root_cnode(&mem, plan, bi).unwrap();
    for (i, d) in bi.untyped().iter().enumerate() {
        let cap = mem
            .load(plan.layout.slot(slots.untyped.start + i as u64))
            .cap;
        assert_eq!(cap.cap_type(), CapType::Untyped);
        assert_eq!(
            (
                cap.object(),
                cap.size_bits(),
                cap.is_device(),
                cap.watermark()
            ),
            (d.paddr, u32::from(d.size_bits), d.device(), d.size())
        );
    }
    mem
}

// ---------------------------------------------------------------------
// The recorded maps.

fn widths() -> Vec<u32> {
    if cfg!(miri) {
        vec![52]
    } else {
        (36..=52).collect()
    }
}

/// Builds every width for a recorded boot and prints the untyped count and
/// its margin under BootInfo's 448.
fn sweep(name: &str, boot: Boot) -> Vec<(u32, usize)> {
    let interrupts = boot.interrupts();
    let mut counts = Vec::new();
    for bits in widths() {
        let b = build(boot.input(bits), interrupts).unwrap();
        let n = b.summary.count;
        println!(
            "{name}: {bits}-bit physical addresses: {n} untyped ({} RAM MiB, framebuffer {}), margin {} of {MAX_UNTYPED}",
            b.summary.ram_bytes >> 20,
            b.summary.framebuffer,
            MAX_UNTYPED - n
        );
        assert!(n < MAX_UNTYPED);
        counts.push((bits, n));
    }
    counts
}

#[test]
fn q35_untyped_fit_at_every_width() {
    let counts = sweep("q35", Boot::Q35);
    // The count grows with the width: the gap above the map is device.
    assert!(counts.windows(2).all(|w| w[0].1 <= w[1].1));
}

#[test]
fn hyperv_untyped_fit_at_every_width() {
    let counts = sweep("hyperv", Boot::HyperV);
    assert!(counts.windows(2).all(|w| w[0].1 <= w[1].1));
}

#[test]
fn q35_plan_in_detail() {
    let rec = q35_log();
    assert_eq!(rec.kernel, span(0xDEA_D000, 0xDEA_D000 + 600 * KIB));
    assert_eq!(rec.framebuffer.size, 0x3E_8000);
    let input = Boot::Q35.input(40);
    let plan = plan(input).unwrap();
    // The highest USABLE range above 1 MiB is 0xfbff000-0xfef4000: 140 KiB
    // for the CNode, the IPC buffer and BootInfo, aligned to 128 KiB.
    assert_eq!(plan.layout.region, span(0xFEC_0000, 0xFEE_3000));
    assert_eq!(
        (
            plan.layout.cnode,
            plan.layout.ipc_buffer,
            plan.layout.bootinfo
        ),
        (0xFEC_0000, 0xFEE_0000, 0xFEE_1000)
    );
    assert_eq!(
        (plan.layout.pml4, plan.layout.tcb, plan.layout.synic),
        (None, None, None)
    );
    assert_eq!(
        plan.framebuffer,
        FramebufferStatus::Untyped(span(0x8000_0000, 0x803E_8000))
    );
    let reserved: Vec<Span> = plan.kernel_reserved.iter().collect();
    assert_eq!(
        reserved,
        [
            span(0xFEE0_0000, 0xFEE0_1000),
            span(0xFEC0_0000, 0xFEC0_1000),
            span(0xFED0_0000, 0xFED0_1000),
            MSI_WINDOW
        ]
    );

    let b = build(input, Boot::Q35.interrupts()).unwrap();
    let d = |paddr: u64, bits: u32, device: bool| UntypedDesc::new(paddr, bits, device);
    let list = b.bi.untyped();
    // The framebuffer first: 4,000 KiB at 2 GiB.
    assert_eq!(b.summary.framebuffer, 6);
    assert_eq!(
        &list[..6],
        [
            d(0x8000_0000, 21, true),
            d(0x8020_0000, 20, true),
            d(0x8030_0000, 19, true),
            d(0x8038_0000, 18, true),
            d(0x803C_0000, 17, true),
            d(0x803E_0000, 15, true),
        ]
    );
    // Then RAM from 1 MiB, up to the ACPI_NVS at 8 MiB.
    assert_eq!(
        &list[6..12],
        [
            d(0x10_0000, 20, false),
            d(0x20_0000, 21, false),
            d(0x40_0000, 22, false),
            d(0x80_8000, 13, false),
            d(0x80_A000, 12, false),
            d(0x80_C000, 14, false),
        ]
    );
    // The kernel image is a hole in the RAM: 0xdead000-0xdf43000 is
    // nothing; the LOADER pages around it are RAM.
    let image = span(0xDEA_D000, 0xDF4_3000);
    assert!(
        list.iter()
            .all(|d| !overlaps(span(d.paddr, d.end()), image))
    );
    assert!(list.contains(&d(0xDEA_C000, 12, false)));
    assert!(list.contains(&d(0xDF4_4000, 14, false)));
    // The 2 MiB pages holding the I/O APIC and HPET pages, and the MSI
    // window, are gaps: device untyped up to each reserved page.
    assert!(list.contains(&d(0xFEC0_1000, 12, true)));
    assert!(list.contains(&d(0xFED0_1000, 12, true)));
    assert!(list.contains(&d(0xFEF0_0000, 20, true)));
    // 2^40 bounds the last one; q35's reserved range below 1 TiB is device.
    assert_eq!(list.last().unwrap().end(), 1 << 40);
    // Every RAM-kind byte above 1 MiB but the image and the boot region.
    assert_eq!(b.summary.ram_bytes, 0xF88_1000);
    let s = b.slots;
    assert_eq!(s.extra_bootinfo_frames, SlotRegion { start: 16, end: 17 });
    assert!(s.user_image_paging.is_empty() && s.user_image_frames.is_empty());
    assert_eq!(s.untyped.start, 17);
    assert_eq!(s.framebuffer_untyped, SlotRegion { start: 17, end: 23 });
    assert_eq!(
        s.empty,
        SlotRegion {
            start: s.untyped.end,
            end: 4096
        }
    );
}

#[test]
fn hyperv_plan_in_detail() {
    let rec = hyperv_log();
    assert_eq!(rec.framebuffer.size, 0x30_0000);
    let input = Boot::HyperV.input(40);
    let plan = plan(input).unwrap();
    // The two highest USABLE ranges hold 4 KiB and 60 KiB; the third,
    // 0x1eb41000-0x1ff41000, holds the region.
    assert_eq!(plan.layout.region, span(0x1FF0_0000, 0x1FF2_3000));
    assert_eq!(
        plan.framebuffer,
        FramebufferStatus::Untyped(span(0xF800_0000, 0xF830_0000))
    );
    let b = build(input, Boot::HyperV.interrupts()).unwrap();
    let list = b.bi.untyped();
    let d = |paddr: u64, bits: u32, device: bool| UntypedDesc::new(paddr, bits, device);
    assert_eq!(
        &list[..2],
        [d(0xF800_0000, 21, true), d(0xF820_0000, 20, true)]
    );
    assert_eq!(
        &list[2..5],
        [
            d(0x10_0000, 20, false),
            d(0x20_0000, 21, false),
            d(0x40_0000, 22, false)
        ]
    );
    // The ACPI tables become RAM untyped; the ACPI_NVS page after them,
    // the firmware's pages and low memory do not.
    assert!(all_covered(list, span(0x1FFC_5000, 0x1FFF_B000), false));
    let nvs = span(0x1FFF_B000, 0x1FFF_F000);
    assert!(list.iter().all(|d| !overlaps(span(d.paddr, d.end()), nvs)));
    assert!(list.contains(&d(0x1FFF_F000, 12, false)));
    // Device untyped start where the RAM's last 2 MiB page ends.
    assert!(list.contains(&d(0x2000_0000, 29, true)));
}

#[test]
#[cfg_attr(miri, ignore = "decodes the ACPI dumps: minutes under Miri")]
fn interrupt_info_from_the_dumps() {
    let q = InterruptInfo::from_platform(q35_acpi(), &[24]);
    assert_eq!((q.ecam_count, q.ioapic_count), (1, 1));
    assert_eq!(
        q.ecam[0],
        crate::bootinfo::Ecam {
            base: 0xE000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 255,
            reserved: 0
        }
    );
    assert_eq!(
        q.ioapics[0],
        crate::bootinfo::IoApicInfo {
            gsi_base: 0,
            pins: 24,
            id: 0,
            reserved: 0
        }
    );
    let route = |gsi, flags, routed| IsaRoute {
        gsi,
        flags,
        routed,
        reserved: 0,
    };
    // IRQ 0 on GSI 2, so IRQ 2 has no route; the SCI and PCI IRQs level.
    assert_eq!(q.isa_routes[0], route(2, 0, 1));
    assert_eq!(q.isa_routes[2], route(0, 0, 0));
    assert_eq!(q.isa_routes[4], route(4, 0, 1));
    for irq in [5, 9, 10, 11] {
        assert_eq!(q.isa_routes[irq], route(irq as u32, 1, 1));
    }
    assert_eq!(q.reserved, [0; 24]);

    let h = InterruptInfo::from_platform(hyperv_acpi(), &[24]);
    assert_eq!((h.ecam_count, h.ioapic_count), (0, 1));
    assert_eq!(h.ecam, [crate::bootinfo::Ecam::default(); 4]);
    assert_eq!((h.ioapics[0].id, h.ioapics[0].pins), (1, 24));
    assert_eq!(h.isa_routes[0], route(0, 0, 1));
    assert_eq!(h.isa_routes[2], route(2, 0, 1));
    assert_eq!(h.isa_routes[9], route(9, 1, 1));
    assert!(h.isa_routes.iter().all(|r| r.routed == 1));

    // Without a pin count no I/O APIC serves a GSI: routes but not routed.
    let none = InterruptInfo::from_platform(hyperv_acpi(), &[]);
    assert_eq!(none.ioapics[0].pins, 0);
    assert_eq!(none.isa_routes[4], route(4, 0, 0));
    // A 4-pin I/O APIC serves IRQs 0 to 3 only.
    let small = InterruptInfo::from_platform(hyperv_acpi(), &[4]);
    assert_eq!(
        (small.isa_routes[3].routed, small.isa_routes[4].routed),
        (1, 0)
    );
}

#[test]
fn bootinfo_fields() {
    let rec = q35_log();
    let plan = plan(Boot::Q35.input(40)).unwrap();
    let mut bi = BootInfo::ZERO;
    write_bootinfo(&mut bi, &plan, &facts(Boot::Q35.interrupts())).unwrap();
    let bi = &bi;
    assert_eq!(bi.magic, BOOTINFO_MAGIC);
    assert_eq!((bi.version, bi.size, bi.root_cnode_bits), (1, 8192, 12));
    assert_eq!(
        (bi.ipc_buffer, bi.user_image_start, bi.user_image_end),
        (0, 0, 0)
    );
    assert_eq!(bi.framebuffer, rec.framebuffer);
    assert_eq!((bi.rsdp, bi.tsc_hz), (0xFB7_E014, 2_100_106_846));
    assert_eq!((bi.hypervisor_vendor, bi.phys_addr_bits), (1, 40));
    assert_eq!(bi.cmdline(), "test=hello");
    assert_eq!(bi.interrupts, Boot::Q35.interrupts());
    check::check_bootinfo(&plan, bi).unwrap();
    // A long command line is cut at 256 bytes.
    let long = [b'x'; 300];
    let mut bi = *bi;
    let mut f = facts(InterruptInfo::ZERO);
    f.cmdline = &long;
    let slots = check::slot_plan_of(&bi);
    fill_bootinfo(&mut bi, &plan, &slots, &f);
    assert_eq!(bi.cmdline_len, 256);
    assert_eq!(bi.cmdline, [b'x'; 256]);
}

#[test]
fn root_cnode_slots() {
    let plan = plan(Boot::Q35.input(40)).unwrap();
    let mut bi = BootInfo::ZERO;
    let (_, slots) = write_bootinfo(&mut bi, &plan, &facts(InterruptInfo::ZERO)).unwrap();
    let b = Built {
        bi,
        summary: UntypedSummary::default(),
        slots,
    };
    let cap = |slot| root_cap(&plan, &b.slots, b.bi.untyped(), slot);
    let l = plan.layout;
    assert_eq!(cap(CAP_NULL), Cap::NULL);
    // M4: no TCB, VSpace, Hypervisor or SynIC frames.
    for slot in [1, 3, 5, 6, 8, 11, 12, 13, 14, 15] {
        assert_eq!(cap(slot), Cap::NULL, "slot {slot}");
    }
    let cnode = cap(CAP_INIT_CNODE);
    assert_eq!(cnode.cap_type(), CapType::CNode);
    assert_eq!(
        (
            cnode.object(),
            cnode.radix(),
            cnode.guard_size(),
            cnode.guard()
        ),
        (l.cnode, 12, ROOT_CNODE_GUARD_SIZE, 0)
    );
    assert_eq!(cap(CAP_IRQ_CONTROL).cap_type(), CapType::IrqControl);
    assert_eq!(cap(CAP_IO_PORT_CONTROL).cap_type(), CapType::IoPortControl);
    for (slot, paddr) in [
        (CAP_BOOTINFO_FRAME, l.bootinfo),
        (CAP_INIT_IPC_BUFFER, l.ipc_buffer),
        (16, l.bootinfo + K4),
    ] {
        let f = cap(slot);
        assert_eq!(f.cap_type(), CapType::Frame);
        assert_eq!((f.object(), f.size_bits(), f.data), (paddr, 12, 0));
        assert_eq!(f.rights(), Rights(Rights::READ.0 | Rights::WRITE.0));
        assert!(!f.is_device());
    }
    assert_eq!(cap(b.slots.empty.start), Cap::NULL);
    assert_eq!(cap(ROOT_CNODE_SLOTS - 1), Cap::NULL);
    // A slot holding the wrong capability is found.
    let mut mem = check_root_cnode(&plan, &b.bi, &b.slots);
    let at = l.slot(b.slots.untyped.start + 3);
    let mut s = mem.load(at);
    s.cap = s.cap.with_data(0);
    mem.store(at, s);
    assert_eq!(
        check::check_root_cnode(&mem, &plan, &b.bi),
        Err(Violation::RootCNode {
            slot: b.slots.untyped.start + 3
        })
    );
}

// ---------------------------------------------------------------------
// Hand-made maps.

/// A small machine: RAM from 1 MiB to 128 MiB with the 600 KiB kernel image
/// in a LOADER range at 64 MiB, q35's device pages, 36-bit addresses.
fn small_map() -> Vec<MemoryRegion> {
    vec![
        region(0, 0xA_0000, U),
        region(MIB, 63 * MIB, U),
        region(64 * MIB, MIB, L),
        region(65 * MIB, 63 * MIB, U),
    ]
}

fn q35_window() -> DeviceWindow {
    let mut w = DeviceWindow::default();
    w.pages[window::LAPIC_PAGE] = Some(0xFEE0_0000);
    w.pages[window::ioapic_page(0)] = Some(0xFEC0_0000);
    w.pages[window::HPET_PAGE] = Some(0xFED0_0000);
    w
}

fn small_input(map: &[MemoryRegion]) -> BootInput<'_> {
    BootInput {
        memory_map: map,
        kernel_image: span(64 * MIB, 64 * MIB + 600 * KIB),
        rootimage: None,
        direct_map_end: 4 * GIB,
        phys_addr_bits: 36,
        window: q35_window(),
        locked_hypercall_page: None,
        framebuffer: Framebuffer::default(),
        root: RootNeeds::default(),
    }
}

fn build_ok(input: BootInput) -> Built {
    build(input, InterruptInfo::ZERO).unwrap()
}

fn covers(list: &[UntypedDesc], s: Span) -> bool {
    list.iter().any(|d| overlaps(span(d.paddr, d.end()), s))
}

/// Whether untyped of one kind cover every byte of `s`.
fn all_covered(list: &[UntypedDesc], s: Span, device: bool) -> bool {
    let mut at = s.start;
    while at < s.end {
        match list
            .iter()
            .find(|d| d.device() == device && d.paddr <= at && at < d.end())
        {
            Some(d) => at = d.end(),
            None => return false,
        }
    }
    true
}

#[test]
fn a_small_machine() {
    let map = small_map();
    let b = build_ok(small_input(&map));
    let plan = plan(small_input(&map)).unwrap();
    assert_eq!(
        plan.layout.region,
        span(128 * MIB - 0x40000, 128 * MIB - 0x1D000)
    );
    assert_eq!(plan.framebuffer, FramebufferStatus::Absent);
    assert_eq!(b.summary.framebuffer, 0);
    assert!(b.slots.framebuffer_untyped.is_empty());
    assert_eq!(b.bi.framebuffer, Framebuffer::default());
    // All the RAM above 1 MiB but the image and the boot region.
    assert_eq!(
        b.summary.ram_bytes,
        127 * MIB - 600 * KIB - (plan.layout.region.end - plan.layout.region.start)
    );
}

#[test]
fn rootimage_becomes_ram() {
    let map = small_map();
    let mut input = small_input(&map);
    let root = span(64 * MIB + 256 * KIB, 64 * MIB + 512 * KIB);
    input.rootimage = Some(root);
    let b = build_ok(input);
    let list = b.bi.untyped();
    assert!(list.contains(&UntypedDesc::new(root.start, 18, false)));
    assert!(!covers(list, span(64 * MIB, root.start)));
    assert!(!covers(list, span(root.end, 64 * MIB + 600 * KIB)));
    // An empty one changes nothing.
    input.rootimage = Some(span(root.start, root.start));
    let none = build_ok(input);
    assert!(!covers(
        none.bi.untyped(),
        span(64 * MIB, 64 * MIB + 600 * KIB)
    ));
}

#[test]
fn framebuffer_sharing_a_2mib_page_with_ram() {
    let mut map = small_map();
    map.push(region(128 * MIB, MIB, U));
    let mut input = small_input(&map);
    // In the gap after the RAM, starting in the RAM's last 2 MiB page.
    input.framebuffer = Framebuffer {
        base: 129 * MIB,
        size: 4 * MIB,
        width: 1024,
        height: 1024,
        stride: 1024,
        format: PixelFormat::BGR,
    };
    let b = build_ok(input);
    let plan = plan(input).unwrap();
    assert_eq!(
        plan.framebuffer,
        FramebufferStatus::Rejected {
            span: span(129 * MIB, 133 * MIB),
            reason: FramebufferRejection::WriteBack { page: 128 * MIB }
        }
    );
    assert!(b.slots.framebuffer_untyped.is_empty());
    // BootInfo still describes it; no untyped covers any of it, and the gap
    // after it is device from the first uncached 2 MiB page.
    assert_eq!(b.bi.framebuffer, input.framebuffer);
    let list = b.bi.untyped();
    assert!(!covers(list, span(129 * MIB, 133 * MIB)));
    let region = plan.layout.region;
    assert_eq!(region.start, 129 * MIB - 0x4_0000);
    assert!(all_covered(list, span(128 * MIB, region.start), false));
    assert!(list.contains(&UntypedDesc::new(133 * MIB, 20, true)));
    assert!(!covers(list, span(130 * MIB - 1, 130 * MIB)));
}

#[test]
fn framebuffer_edge_cases() {
    let map = small_map();
    let mut input = small_input(&map);
    let fb = |base: u64, size: u64| Framebuffer {
        base,
        size,
        width: 1,
        height: 1,
        stride: 1,
        format: PixelFormat::RGB,
    };
    let status = |input: BootInput| plan(input).unwrap().framebuffer;
    // An unaligned base and size are page-rounded.
    input.framebuffer = fb(0xC000_0010, 0x1000);
    assert_eq!(
        status(input),
        FramebufferStatus::Untyped(span(0xC000_0000, 0xC000_2000))
    );
    build_ok(input);
    // Below 1 MiB, past the address width, or wrapping.
    for f in [
        fb(0xA_0000, 0x2_0000),
        fb((1 << 36) - K4, 2 * K4),
        fb(u64::MAX - K4, 2 * K4),
    ] {
        input.framebuffer = f;
        assert!(matches!(
            status(input),
            FramebufferStatus::Rejected {
                reason: FramebufferRejection::OutOfRange,
                ..
            }
        ));
        build_ok(input);
    }
    // Inside the UC page of the I/O APIC, over the page itself.
    input.framebuffer = fb(0xFEC0_0000, 0x10_0000);
    assert!(matches!(
        status(input),
        FramebufferStatus::Rejected {
            reason: FramebufferRejection::Overlaps(_),
            ..
        }
    ));
    build_ok(input);
    // Over BAD memory in an otherwise uncached page.
    let mut map2 = small_map();
    map2.push(region(0xFEC1_0000, K4, BAD));
    let mut input2 = small_input(&map2);
    input2.framebuffer = fb(0xFEC1_0000, 0x1_0000);
    assert_eq!(
        status(input2),
        FramebufferStatus::Rejected {
            span: span(0xFEC1_0000, 0xFEC2_0000),
            reason: FramebufferRejection::Overlaps("firmware or bad memory")
        }
    );
    build_ok(input2);
    // A size of 0 is no framebuffer.
    input.framebuffer = fb(0xC000_0000, 0);
    assert_eq!(status(input), FramebufferStatus::Absent);
}

#[test]
fn no_room_for_the_boot_region() {
    let map = [region(MIB, 64 * KIB, U), region(64 * MIB, MIB, L)];
    let err = plan(small_input(&map)).unwrap_err();
    assert_eq!(
        err,
        BootError::NoRoom {
            size: 0x2_3000,
            align: 0x2_0000
        }
    );
    assert_eq!(
        format!("{err}"),
        "no usable range above 1 MiB inside the direct map holds the 140 KiB boot region aligned to 128 KiB"
    );
    // Room only below 1 MiB does not count.
    let map = [region(0, 0xA_0000, U), region(64 * MIB, MIB, L)];
    assert!(matches!(
        plan(small_input(&map)),
        Err(BootError::NoRoom { .. })
    ));
}

#[test]
fn the_boot_region_avoids_kernel_reserved_2mib_pages() {
    let map = small_map();
    let base = plan(small_input(&map)).unwrap().layout.region;
    // A hypercall page the firmware locked inside it.
    let mut input = small_input(&map);
    input.locked_hypercall_page = Some(base.start + K4);
    let moved = plan(input).unwrap().layout.region;
    assert_eq!(moved.end, round_down(base.start, PAGE_2M) - 0x1D000);
    let b = build_ok(input);
    assert!(!covers(
        b.bi.untyped(),
        span(base.start + K4, base.start + 2 * K4)
    ));
    // RAM untyped still cover the rest of that 2 MiB page.
    assert!(covers(b.bi.untyped(), span(base.start, base.start + K4)));

    // An I/O APIC page inside it: no RAM untyped in its whole 2 MiB page.
    let mut input = small_input(&map);
    input.window.pages[window::ioapic_page(1)] = Some(base.start);
    let b = build_ok(input);
    let page = round_down(base.start, PAGE_2M);
    assert!(!covers(b.bi.untyped(), span(page, page + PAGE_2M)));

    // Reserved pages that leave no room at all.
    let map = [region(MIB, 3 * MIB, U), region(64 * MIB, MIB, L)];
    let mut input = small_input(&map);
    input.locked_hypercall_page = Some(2 * MIB);
    assert_eq!(plan(input).unwrap().layout.region.start, 0x1C_0000);
    input.window.pages[window::HPET_PAGE] = Some(MIB);
    assert!(matches!(plan(input), Err(BootError::NoRoom { .. })));
}

#[test]
fn more_untyped_than_bootinfo_holds() {
    // 1 GiB blocks from 8 GiB: a reserved range between two BAD pages,
    // device untyped in 36 pieces.
    let mut map = small_map();
    for i in 0..13 {
        let b = 8 * GIB + i * GIB;
        map.push(region(b, K4, BAD));
        map.push(region(b + K4, GIB - 2 * K4, R));
        map.push(region(b + GIB - K4, K4, BAD));
    }
    let err = build(small_input(&map), InterruptInfo::ZERO).err().unwrap();
    let BootError::TooManyUntyped { count } = err else {
        panic!("{err:?}");
    };
    assert!(count > 13 * 36, "{count}");
    assert_eq!(
        format!("{err}"),
        format!("{count} untyped, more than BootInfo's 448")
    );
}

#[test]
fn ram_past_the_direct_map() {
    let map = [
        region(MIB, 63 * MIB, U),
        region(64 * MIB, MIB, L),
        region(65 * MIB, 63 * MIB, U),
    ];
    let mut input = small_input(&map);
    input.direct_map_end = 96 * MIB;
    let b = build_ok(input);
    let plan = plan(input).unwrap();
    assert_eq!(plan.layout.region.end, 96 * MIB - 0x1D000);
    let list = b.bi.untyped();
    assert!(
        list.iter()
            .filter(|d| !d.device())
            .all(|d| d.end() <= 96 * MIB)
    );
    // Neither RAM nor device untyped above it.
    assert!(!covers(list, span(96 * MIB, 128 * MIB)));
    assert!(list.contains(&UntypedDesc::new(128 * MIB, 27, true)));
}

#[test]
fn regions_above_the_address_width() {
    let mut map = small_map();
    map.push(region(4 * GIB - 2 * MIB, 4 * MIB, R));
    map.push(region(5 * GIB, GIB, U));
    let mut input = small_input(&map);
    input.phys_addr_bits = 32;
    let b = build_ok(input);
    let list = b.bi.untyped();
    assert_eq!(list.last().unwrap().end(), 4 * GIB);
    assert!(list.iter().all(|d| d.end() <= 4 * GIB));
    // The same map at 36 bits: the RAM at 5 GiB is past the direct map,
    // the reserved range is device to its end.
    input.phys_addr_bits = 36;
    let b = build_ok(input);
    let list = b.bi.untyped();
    assert!(!covers(list, span(5 * GIB, 6 * GIB)));
    assert!(covers(list, span(4 * GIB, 4 * GIB + 2 * MIB)));
}

#[test]
fn unknown_kinds_and_firmware_memory_become_nothing() {
    let mut map = small_map();
    map.push(region(130 * MIB, MIB, RegionKind(0)));
    map.push(region(132 * MIB, MIB, RegionKind(42)));
    map.push(region(134 * MIB, MIB, NVS));
    map.push(region(136 * MIB, MIB, RegionKind::FIRMWARE));
    map.push(region(137 * MIB, 8 * MIB, R));
    let b = build_ok(small_input(&map));
    let list = b.bi.untyped();
    for s in [130, 132, 134, 136] {
        assert!(!covers(list, span(s * MIB, (s + 1) * MIB)));
    }
    // The reserved range's first MiB shares a write-back 2 MiB page with
    // the firmware's; the rest is device.
    assert!(!covers(list, span(137 * MIB, 138 * MIB)));
    assert!(list.contains(&UntypedDesc::new(138 * MIB, 21, true)));
}

#[test]
fn an_m5_root_task_on_hyper_v() {
    let map = small_map();
    let mut input = small_input(&map);
    let hv = Cap::new(CapType::Hypervisor, 0, 0, Rights::NONE, false, 0);
    input.root = RootNeeds {
        tcb: true,
        pml4: true,
        pdpts: 1,
        pds: 1,
        pts: 2,
        image_frames: 5,
        hypervisor: Some(hv),
    };
    let plan = plan(input).unwrap();
    let l = plan.layout;
    let s = l.region.start;
    assert_eq!(l.cnode, s);
    assert_eq!(l.pml4, Some(s + 128 * KIB));
    assert_eq!(l.paging, s + 136 * KIB);
    assert_eq!(l.ipc_buffer, s + 168 * KIB);
    assert_eq!(l.bootinfo, s + 172 * KIB);
    assert_eq!(l.image_frames, s + 180 * KIB);
    assert_eq!(
        l.synic,
        Some(SynicFrames {
            message: s + 200 * KIB,
            event: s + 204 * KIB
        })
    );
    assert_eq!(l.tcb, Some(s + 208 * KIB));
    assert_eq!(l.region.end, s + 212 * KIB);
    assert_eq!(l.paging_object(0), (CapType::Pdpt, s + 136 * KIB));
    assert_eq!(l.paging_object(1), (CapType::PageDirectory, s + 144 * KIB));
    assert_eq!(l.paging_object(3), (CapType::PageTable, s + 160 * KIB));

    let b = build_ok(input);
    let slots = b.slots;
    assert_eq!(
        slots.extra_bootinfo_frames,
        SlotRegion { start: 16, end: 17 }
    );
    assert_eq!(slots.user_image_paging, SlotRegion { start: 17, end: 21 });
    assert_eq!(slots.user_image_frames, SlotRegion { start: 21, end: 26 });
    assert_eq!(slots.untyped.start, 26);
    let cap = |slot| root_cap(&plan, &slots, b.bi.untyped(), slot);
    assert_eq!(cap(CAP_INIT_TCB).cap_type(), CapType::Tcb);
    assert_eq!(cap(CAP_INIT_TCB).object(), s + 208 * KIB);
    assert_eq!(cap(CAP_INIT_VSPACE).cap_type(), CapType::Pml4);
    assert_eq!(cap(CAP_HYPERVISOR), hv);
    assert_eq!(cap(CAP_SYNIC_MESSAGE_FRAME).object(), s + 200 * KIB);
    assert_eq!(cap(CAP_SYNIC_EVENT_FRAME).object(), s + 204 * KIB);
    assert_eq!(cap(17).cap_type(), CapType::Pdpt);
    assert_eq!(cap(18).cap_type(), CapType::PageDirectory);
    assert_eq!(cap(20).cap_type(), CapType::PageTable);
    assert_eq!(cap(25).object(), s + 196 * KIB);
    assert_eq!(cap(26).cap_type(), CapType::Untyped);
}

#[test]
fn bad_inputs_are_errors() {
    let map = small_map();
    let mut input = small_input(&map);
    input.phys_addr_bits = 53;
    assert_eq!(plan(input), Err(BootError::PhysAddrBits(53)));
    input.phys_addr_bits = 31;
    assert_eq!(plan(input), Err(BootError::PhysAddrBits(31)));

    for dme in [0, 4 * GIB + MIB, 128 * GIB] {
        let mut input = small_input(&map);
        input.direct_map_end = dme;
        assert_eq!(plan(input), Err(BootError::DirectMapEnd(dme)));
    }

    let unsorted = [region(64 * MIB, MIB, L), region(MIB, MIB, U)];
    assert_eq!(
        plan(small_input(&unsorted)),
        Err(BootError::MemoryMap { index: 1 })
    );
    let overlapping = [region(MIB, 2 * MIB, U), region(2 * MIB, MIB, R)];
    assert_eq!(
        plan(small_input(&overlapping)),
        Err(BootError::MemoryMap { index: 1 })
    );
    let unaligned = [region(MIB + 8, MIB, U)];
    assert_eq!(
        plan(small_input(&unaligned)),
        Err(BootError::MemoryMap { index: 0 })
    );
    let wrapping = [region(u64::MAX - K4 + 1, 2 * K4, U)];
    assert_eq!(
        plan(small_input(&wrapping)),
        Err(BootError::MemoryMap { index: 0 })
    );

    for k in [
        span(0, 0),
        span(MIB + 8, 2 * MIB),
        span(8 * GIB, 8 * GIB + K4),
    ] {
        let mut input = small_input(&map);
        input.kernel_image = k;
        assert_eq!(plan(input), Err(BootError::KernelImage(k)));
    }
    let mut input = small_input(&map);
    let r = span(63 * MIB, 64 * MIB + K4);
    input.rootimage = Some(r);
    assert_eq!(plan(input), Err(BootError::RootImage(r)));

    let mut input = small_input(&map);
    input.root.image_frames = 4096;
    assert_eq!(
        plan(input),
        Err(BootError::TooManySlots {
            needed: 16 + 1 + 4096
        })
    );
    // The slot plan's own check, with the root objects at their limit.
    let needs = RootNeeds {
        image_frames: 4096 - 17 - 448,
        ..RootNeeds::default()
    };
    let n = |count| UntypedSummary {
        count,
        ..UntypedSummary::default()
    };
    assert!(slot_plan(&needs, &n(448)).is_ok());
    assert_eq!(
        slot_plan(&needs, &n(449)),
        Err(BootError::TooManySlots { needed: 4097 })
    );
    assert_eq!(slot_plan(&needs, &n(448)).unwrap().empty.len(), 0);

    // Every message names its numbers.
    let messages: Vec<String> = [
        BootError::PhysAddrBits(53),
        BootError::DirectMapEnd(3),
        BootError::MemoryMap { index: 4 },
        BootError::KernelImage(span(1, 2)),
        BootError::RootImage(span(3, 4)),
        BootError::TooManySlots { needed: 5000 },
    ]
    .iter()
    .map(|e| format!("{e}"))
    .collect();
    assert_eq!(
        messages,
        [
            "physical address width 53 outside 32 to 52 bits",
            "direct map end 0x3 is not usable",
            "memory-map entry 4 is unaligned, wraps, or overlaps the one before",
            "kernel image 0x1-0x2 is empty, unaligned or outside the direct map",
            ".rootimage 0x3-0x4 is unaligned or outside the kernel image",
            "the initial capabilities need 5000 slots, more than the root CNode's 4096",
        ]
    );
}

#[test]
fn chunks_are_naturally_aligned() {
    let c: Vec<_> = chunks(span(0x10_1000, 0x40_0000)).collect();
    assert_eq!(
        c,
        [
            (0x10_1000, 12),
            (0x10_2000, 13),
            (0x10_4000, 14),
            (0x10_8000, 15),
            (0x11_0000, 16),
            (0x12_0000, 17),
            (0x14_0000, 18),
            (0x18_0000, 19),
            (0x20_0000, 21)
        ]
    );
    // Capped at 2^47; 0 is aligned to anything.
    let c: Vec<_> = chunks(span(0, 1 << 52)).collect();
    assert_eq!(c.len(), 32);
    assert!(c.iter().all(|&(_, bits)| bits == 47));
    assert_eq!(chunks(span(5, 5)).count(), 0);
}

#[test]
fn kernel_reserved_pages() {
    let r = kernel_reserved(&q35_window(), Some(0x1234_5678));
    let spans: Vec<Span> = r.iter().collect();
    assert_eq!(
        spans,
        [
            span(0xFEE0_0000, 0xFEE0_1000),
            span(0xFEC0_0000, 0xFEC0_1000),
            span(0xFED0_0000, 0xFED0_1000),
            MSI_WINDOW,
            span(0x1234_5000, 0x1234_6000),
        ]
    );
    assert!(r.contains(0xFEEF_FFFF) && !r.contains(0xFEF0_0000));
    assert!(r.overlaps(span(0x1234_5FFF, 0x2000_0000)));
    assert!(!r.overlaps(span(0x1234_6000, 0x2000_0000)));
    let none = kernel_reserved(&DeviceWindow::default(), None);
    assert_eq!(none.iter().collect::<Vec<_>>(), [MSI_WINDOW]);
}

#[test]
#[cfg_attr(miri, ignore = "dozens of checks of a full list: slow under Miri")]
fn the_checks_catch_broken_lists() {
    let plan = plan(Boot::Q35.input(40)).unwrap();
    let b = build(Boot::Q35.input(40), InterruptInfo::ZERO).unwrap();
    let good: Vec<UntypedDesc> = b.bi.untyped().to_vec();
    let fb = b.summary.framebuffer;
    assert_eq!(check::check_untyped(&plan, &good, fb), Ok(()));
    let first_ram = good.iter().position(|d| !d.device()).unwrap();
    let broken = |f: &dyn Fn(&mut Vec<UntypedDesc>)| {
        let mut v = good.clone();
        f(&mut v);
        check::check_untyped(&plan, &v, fb)
    };
    let untyped_rule = |r: Result<(), Violation>| match r {
        Err(Violation::Untyped { rule, .. }) => rule,
        other => panic!("{other:?}"),
    };
    // A dropped RAM descriptor.
    assert!(matches!(
        broken(&|v| {
            v.remove(first_ram);
        }),
        Err(Violation::Uncovered { .. })
    ));
    // Two the same.
    assert!(matches!(
        broken(&|v| v.insert(first_ram, v[first_ram])),
        Err(Violation::Order { .. })
    ));
    // Out of order.
    assert!(matches!(
        broken(&|v| v.swap(first_ram, first_ram + 1)),
        Err(Violation::Order { .. })
    ));
    assert_eq!(
        untyped_rule(broken(&|v| v[first_ram].paddr += K4)),
        "not aligned to its size"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(0, 12, true)))),
        "covers memory below 1 MiB"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(0xDEA_D000, 12, false)))),
        "covers the kernel image"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(0xFEC_0000, 12, false)))),
        "covers the boot region"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(0xFEE0_0000, 12, true)))),
        "covers a kernel-reserved page"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(0xF01_0000, 12, false)))),
        "covers ACPI_NVS, FIRMWARE, BAD or unknown memory"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(0xFAE_E000, 12, true)))),
        "device untyped in a write-back 2 MiB page"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(
            0x1000_0000,
            12,
            false
        )))),
        "RAM untyped over memory that is not RAM"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v[first_ram].is_device = 1)),
        "device untyped in a write-back 2 MiB page"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v.push(UntypedDesc::new(1 << 40, 12, true)))),
        "reaches 2^phys_addr_bits"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v[0].padding[1] = 1)),
        "device flag or padding not 0 or 1"
    );
    assert_eq!(
        untyped_rule(broken(&|v| v[0].size_bits = 48)),
        "size outside 4 KiB to 2^47 bytes"
    );
    // Dropping a framebuffer descriptor, or claiming none.
    assert_eq!(
        broken(&|v| v[1].paddr = 0x8030_0000),
        Err(Violation::Framebuffer("gap or overlap"))
    );
    assert_eq!(
        check::check_untyped(&plan, &good[fb..], 0),
        Err(Violation::Framebuffer("does not cover it exactly"))
    );
    // A RAM untyped in the 2 MiB page of a device page.
    let mut map = small_map();
    map.push(region(0xFEC1_0000, K4, U));
    let plan = super::plan(small_input(&map)).unwrap();
    let b = build_ok(small_input(&map));
    let mut v = b.bi.untyped().to_vec();
    v.push(UntypedDesc::new(0xFEC1_0000, 12, false));
    assert_eq!(
        untyped_rule(check::check_untyped(&plan, &v, 0)),
        "RAM untyped in a 2 MiB page holding a kernel device page"
    );
    assert_eq!(
        format!(
            "{}",
            Violation::Uncovered {
                allowed: 2,
                covered: 1
            }
        ),
        "RAM untyped cover 0x1 of the 0x2 bytes allowed"
    );
}

#[test]
fn the_checks_catch_broken_bootinfo_and_plans() {
    let map = small_map();
    let plan = plan(small_input(&map)).unwrap();
    let b = build_ok(small_input(&map));
    let broken = |f: &dyn Fn(&mut BootInfo)| {
        let mut bi = b.bi;
        f(&mut bi);
        check::check_bootinfo(&plan, &bi)
    };
    assert_eq!(broken(&|_| {}), Ok(()));
    for f in [
        &(|bi: &mut BootInfo| bi.magic = 0) as &dyn Fn(&mut BootInfo),
        &|bi| bi.phys_addr_bits = 40,
        &|bi| bi.cmdline[200] = 1,
        &|bi| bi.reserved1[3] = 1,
        &|bi| bi.interrupts.ecam_count = 5,
        &|bi| bi.untyped.start += 1,
        &|bi| bi.extra_bootinfo_frames.end += 1,
        &|bi| bi.framebuffer_untyped.end = bi.untyped.end + 1,
        &|bi| bi.empty.end = 4095,
        &|bi| bi.untyped_list[447].paddr = 1,
        &|bi| bi.framebuffer.base = 0x8000_0000,
    ] {
        assert!(matches!(broken(f), Err(Violation::BootInfo(_))));
    }
    let mut p = plan;
    p.layout.region.start += K4;
    assert!(check::check_plan(&p).is_err());
    let mut p = plan;
    p.layout.ipc_buffer = p.layout.cnode;
    assert_eq!(
        check::check_plan(&p),
        Err(Violation::BootRegion(
            "objects out of order, unaligned or outside it"
        ))
    );
    let mut p = plan;
    p.input.locked_hypercall_page = Some(p.layout.region.start);
    p.kernel_reserved = kernel_reserved(&p.input.window, p.input.locked_hypercall_page);
    assert_eq!(
        check::check_plan(&p),
        Err(Violation::BootRegion(
            "touches a 2 MiB page holding a kernel-reserved page"
        ))
    );
}

// ---------------------------------------------------------------------
// Random maps.

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 3 } else { 256 },
        // No files: Miri forbids them.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// A random machine, as plain data so proptest can shrink and print it.
#[derive(Clone, Debug)]
struct Machine {
    regions: Vec<MemoryRegion>,
    kernel: Span,
    rootimage: Option<Span>,
    direct_map_end: u64,
    bits: u32,
    window: DeviceWindow,
    hypercall: Option<u64>,
    framebuffer: Framebuffer,
    root: RootNeeds,
}

impl Machine {
    fn input(&self) -> BootInput<'_> {
        BootInput {
            memory_map: &self.regions,
            kernel_image: self.kernel,
            rootimage: self.rootimage,
            direct_map_end: self.direct_map_end,
            phys_addr_bits: self.bits,
            window: self.window,
            locked_hypercall_page: self.hypercall,
            framebuffer: self.framebuffer,
            root: self.root,
        }
    }
}

fn kind() -> impl Strategy<Value = RegionKind> {
    prop_oneof![
        8 => Just(RegionKind::USABLE),
        1 => Just(RegionKind::LOADER),
        1 => Just(RegionKind::ACPI_RECLAIMABLE),
        1 => Just(RegionKind::ACPI_NVS),
        2 => Just(RegionKind::RESERVED),
        1 => Just(RegionKind::MMIO),
        1 => Just(RegionKind::FIRMWARE),
        1 => Just(RegionKind::BAD),
        1 => (0u32..=12).prop_map(RegionKind),
    ]
}

/// Pages: mostly small, sometimes megabytes, so 2 MiB pages mix kinds.
fn pages(max: u64) -> impl Strategy<Value = u64> {
    prop_oneof![0..4u64, 0..64u64, 0..max]
}

fn root_needs() -> impl Strategy<Value = RootNeeds> {
    prop_oneof![
        3 => Just(RootNeeds::default()),
        1 => (1u64..=2, 1u64..=2, 1u64..=6, 0u64..=300, any::<bool>()).prop_map(
            |(pdpts, pds, pts, image_frames, hv)| RootNeeds {
                tcb: true,
                pml4: true,
                pdpts,
                pds,
                pts,
                image_frames,
                hypervisor: hv
                    .then(|| Cap::new(CapType::Hypervisor, 0, 0, Rights::NONE, false, 0)),
            }
        ),
    ]
}

/// Fewer regions under Miri, where each costs quadratically.
fn max_regions() -> usize {
    if cfg!(miri) { 6 } else { 14 }
}

prop_compose! {
    fn machine()(
        start in 0u64..512,
        layout in prop::collection::vec((pages(2048), 1u64..4096, kind()), 1..max_regions()),
        far in prop::option::of((32u32..40, 1u64..4096, kind())),
        image in (any::<Index>(), any::<Index>(), any::<Index>(), any::<Option<(Index, Index)>>()),
        dme in prop_oneof![Just(4 * GIB), Just(32 * MIB), Just(128 * MIB), Just(64 * GIB)],
        bits in 32u32..=52,
        device in (any::<Option<Index>>(), prop::collection::vec(any::<Index>(), 0..3), any::<Option<Index>>()),
        hypercall in any::<Option<Index>>(),
        fb in any::<Option<(Index, u64, u64)>>(),
        root in root_needs(),
    ) -> Machine {
        let mut regions = Vec::new();
        let mut at = start * K4;
        for (gap, len, kind) in layout {
            at += gap * K4;
            regions.push(region(at, len * K4, kind));
            at += len * K4;
        }
        // The kernel image, in a range the loader marks LOADER.
        let (which, off, len, root_span) = image;
        let k = which.index(regions.len());
        regions[k].kind = RegionKind::LOADER;
        let r = regions[k];
        let pages_in = r.len / K4;
        let first = off.index(pages_in as usize) as u64;
        let n = 1 + len.index((pages_in - first) as usize) as u64;
        let kernel = span(r.base + first * K4, r.base + (first + n) * K4);
        let rootimage = root_span.map(|(a, b)| {
            let a = a.index(n as usize + 1) as u64;
            let b = a + b.index((n - a) as usize + 1) as u64;
            span(kernel.start + a * K4, kernel.start + b * K4)
        });
        if let Some((shift, len, kind)) = far {
            let base = (1u64 << shift).max(at);
            regions.push(region(base, len * K4, kind));
            at = base + len * K4;
        }
        // Device pages, the hypercall page and the framebuffer land
        // anywhere up to 16 MiB past the map, RAM included.
        let limit = (at / K4 + 4096) as usize;
        let page = |i: Index| i.index(limit) as u64 * K4;
        let (lapic, ioapics, hpet) = device;
        let mut w = DeviceWindow::default();
        w.pages[window::LAPIC_PAGE] = Some(lapic.map_or(0xFEE0_0000, page));
        for (i, &io) in ioapics.iter().enumerate() {
            w.pages[window::ioapic_page(i)] = Some(page(io));
        }
        w.pages[window::HPET_PAGE] = hpet.map(page);
        let framebuffer = fb.map_or(Framebuffer::default(), |(base, offset, size)| Framebuffer {
            base: page(base) + offset % 64,
            size: 1 + size % (16 * MIB),
            width: 1,
            height: 1,
            stride: 1,
            format: PixelFormat::BGR,
        });
        Machine {
            regions,
            kernel,
            rootimage,
            direct_map_end: dme,
            bits,
            window: w,
            hypercall: hypercall.map(page),
            framebuffer,
            root,
        }
    }
}

/// Runs a random machine through every check; returns the plan's region
/// if it has one.
fn run(m: &Machine) -> Result<Span, TestCaseError> {
    let input = m.input();
    match plan(input) {
        Ok(p) => {
            let region = p.layout.region;
            match build(input, InterruptInfo::ZERO) {
                Ok(_) | Err(BootError::TooManyUntyped { .. }) => Ok(region),
                Err(e) => Err(TestCaseError::fail(format!("{e}"))),
            }
        }
        Err(BootError::NoRoom { size, .. }) => {
            prop_assert_eq!(ref_place(&input, size), None);
            Err(TestCaseError::reject("no room"))
        }
        Err(BootError::KernelImage(k)) => {
            prop_assert!(k.end > m.direct_map_end);
            Err(TestCaseError::reject("kernel above the direct map"))
        }
        Err(e) => Err(TestCaseError::fail(format!("{e}"))),
    }
}

proptest! {
    #![proptest_config(config())]

    /// Every plan a random machine gets passes every check and matches the
    /// painted reference.
    #[test]
    fn random_machines(m in machine()) {
        match run(&m) {
            Ok(_) | Err(TestCaseError::Reject(_)) => {}
            Err(e) => return Err(e),
        }
    }

    /// A kernel-reserved page inside the range the boot region would take
    /// moves it out of that page's 2 MiB page, and no untyped covers the
    /// page.
    #[test]
    fn a_reserved_page_where_the_boot_region_would_go(
        m in machine(),
        at in any::<Index>(),
        as_device_page in any::<bool>(),
    ) {
        let region = match run(&m) {
            Ok(r) => r,
            Err(TestCaseError::Reject(_)) => return Ok(()),
            Err(e) => return Err(e),
        };
        let mut m = m;
        let page = region.start + at.index(((region.end - region.start) / K4) as usize) as u64 * K4;
        if as_device_page {
            m.window.pages[window::HPET_PAGE] = Some(page);
        } else {
            m.hypercall = Some(page);
        }
        match run(&m) {
            Ok(moved) => {
                let wide = widen_2m(span(page, page + K4));
                prop_assert!(!overlaps(moved, wide));
            }
            Err(TestCaseError::Reject(_)) => {}
            Err(e) => return Err(e),
        }
    }
}
