//! The kernel's own page tables (`docs/design.md`, "The kernel half"): step 4
//! of the M3 boot sequence, and the `test=paging` and `test=lowmem` hooks.
//!
//! `l4core::vspace` decides every entry; this file finds the image's
//! sections from the linker script, owns the static tables in `.bss`, and
//! writes the MSR and control registers.

use core::arch::asm;
use core::cell::UnsafeCell;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use l4core::cpu::Feature;
use l4core::handoff::{Handoff, KERNEL_VIRT_BASE, PHYS_MAP_BASE};
use l4core::vspace::{self, BuildInput, CacheType, KernelLayout, KernelTables, PML4};
use l4core::window::{DeviceWindow, LAPIC_PAGE};

use super::{ExitCode, cpu, exit, phys_to_virt};
use crate::boot::BootState;

const CR0_WP: u64 = 1 << 16;
const CR4_PGE: u64 = 1 << 7;
const CR4_UMIP: u64 = 1 << 11;
const CR4_FSGSBASE: u64 = 1 << 16;
const CR4_PCIDE: u64 = 1 << 17;
const CR4_SMEP: u64 = 1 << 20;
const CR4_SMAP: u64 = 1 << 21;
const EFER_NXE: u64 = 1 << 11;
/// `IA32_APIC_BASE` bit 10: the local APIC is in x2APIC mode, and its MMIO
/// page reads nothing useful.
const APIC_BASE_X2APIC: u64 = 1 << 10;

/// The address of linker-script symbol `$sym`. Read with `lea` rather than
/// `&raw const` of an extern static: the compiler assumes distinct statics
/// have distinct addresses, but `__data_end` and `__kernel_end` share one.
macro_rules! linker_addr {
    ($sym:literal) => {{
        let addr: u64;
        // SAFETY: `lea` only computes the address the linker gave `$sym`;
        // nothing is read.
        unsafe {
            asm!(
                concat!("lea {}, [rip + ", $sym, "]"),
                out(reg) addr,
                options(pure, nomem, nostack, preserves_flags)
            )
        };
        addr
    }};
}

/// The kernel's page tables: 87 page-aligned pages of `.bss`.
struct Tables(UnsafeCell<KernelTables>);

// SAFETY: the tables are written only through the one `&mut` that
// `take_tables` hands out, during boot on the one core, and only read
// afterwards.
unsafe impl Sync for Tables {}

static TABLES: Tables = Tables(UnsafeCell::new(KernelTables::new()));
static TAKEN: AtomicBool = AtomicBool::new(false);
/// The kernel PML4's physical address once CR3 holds it, else 0.
static PML4_PHYS: AtomicU64 = AtomicU64::new(0);

/// The one mutable reference to the tables. Panics if called twice.
fn take_tables() -> &'static mut KernelTables {
    assert!(
        !TAKEN.swap(true, Ordering::AcqRel),
        "kernel page tables taken twice"
    );
    // SAFETY: the swap above lets exactly one caller past, so this is the
    // only reference to TABLES until `built` hands out shared ones, which it
    // does only after `init` has stopped using this one.
    unsafe { &mut *TABLES.0.get() }
}

/// The tables and the PML4's physical address, once `init` has loaded
/// them.
fn built() -> Option<(&'static KernelTables, u64)> {
    let pml4 = PML4_PHYS.load(Ordering::Acquire);
    // SAFETY: PML4_PHYS is set only after `init` finished writing the
    // tables through the reference `take_tables` gave it, and nothing writes
    // them again: not the kernel, and not the CPU, since every kernel entry
    // has Accessed, and every writable leaf Dirty, already set.
    (pml4 != 0).then(|| (unsafe { &*TABLES.0.get() }, pml4))
}

/// The image's layout from the linker script's symbols and the handoff.
fn kernel_layout(h: &Handoff) -> KernelLayout {
    let data_end = linker_addr!("__data_end");
    assert_eq!(
        linker_addr!("__kernel_end"),
        data_end,
        "the data segment must end the image"
    );
    KernelLayout {
        phys_base: h.kernel_phys_base,
        size: h.kernel_size,
        text_start: linker_addr!("__text_start"),
        text_end: linker_addr!("__text_end"),
        rodata_start: linker_addr!("__rodata_start"),
        rodata_end: linker_addr!("__rodata_end"),
        data_start: linker_addr!("__data_start"),
        data_end,
        guards: [
            linker_addr!("__kernel_stack_guard"),
            linker_addr!("__ist1_guard"),
            linker_addr!("__ist2_guard"),
            linker_addr!("__ist3_guard"),
            linker_addr!("__ist4_guard"),
        ],
    }
}

/// Loads CR3.
///
/// # Safety
///
/// `pml4` must be the physical address of a PML4 that maps the running
/// code, its stack and everything the kernel goes on to use, as the code
/// expects them.
unsafe fn write_cr3(pml4: u64) {
    // SAFETY: the caller vouches for the tables. The write changes every
    // translation, so it is not `nomem`.
    unsafe { asm!("mov cr3, {}", in(reg) pml4, options(nostack, preserves_flags)) };
}

/// Step 4 of the M3 boot sequence, after the descriptor tables: checks
/// EFER.NXE and CR0.WP, programs `IA32_PAT`, builds the kernel's tables in
/// `.bss`, sets CR4.SMEP, SMAP, PGE and (if present) UMIP, loads CR3 and
/// toggles CR4.PGE, which drops every translation the loader left, global
/// ones included [H4]. Afterwards the lower half is empty and the device
/// registers are reachable only through `window`.
pub fn init(boot: &'static BootState, window: &DeviceWindow) {
    let h = &boot.handoff;
    assert!(
        cpu::read_msr(cpu::IA32_EFER) & EFER_NXE != 0,
        "EFER.NXE is clear; the loader sets it"
    );
    assert!(
        cpu::read_cr0() & CR0_WP != 0,
        "CR0.WP is clear; the loader sets it"
    );

    let old_pat = cpu::read_msr(vspace::IA32_PAT);
    // SAFETY: the CPU has PAT (`check_cpu`). The loader's tables use only
    // PAT index 0, which is WB before and after, so no live mapping changes
    // type.
    unsafe { cpu::write_msr(vspace::IA32_PAT, vspace::PAT_MSR) };
    kprintln!(
        "paging: IA32_PAT {old_pat:#018x}, now {:#018x}",
        vspace::PAT_MSR
    );

    let layout = kernel_layout(h);
    let tables = take_tables();
    let tables_phys = layout.virt_to_phys(&raw const *tables as u64);
    let input = BuildInput {
        layout: &layout,
        regions: boot.memory_map(),
        direct_map_end: h.direct_map_end(),
        window,
    };
    let summary = match vspace::build(tables, tables_phys, &input) {
        Ok(s) => s,
        Err(e) => panic!("kernel page tables: {e}"),
    };
    let pml4 = KernelTables::table_phys(tables_phys, PML4);

    // PCID stays off and the kernel switches FS and GS bases itself
    // (`docs/design.md`, CPU features; ADR 0015), whatever the firmware left.
    let mut cr4 = (cpu::read_cr4() | CR4_SMEP | CR4_SMAP | CR4_PGE) & !(CR4_PCIDE | CR4_FSGSBASE);
    if cpu::cpuid_features().has(Feature::Umip) {
        cr4 |= CR4_UMIP;
    }
    // SAFETY: `check_cpu` found SMEP, SMAP and PGE, and UMIP is set only
    // when CPUID reports it. No page the kernel uses is user-accessible in
    // the loader's tables or in its own, so SMEP and SMAP stop nothing it
    // does; PGE only lets the new tables' global bits take effect. Clearing
    // PCIDE is allowed at any time, and the CR3 load below then uses no
    // PCID; nothing in the kernel uses the FS or GS base instructions.
    unsafe { cpu::write_cr4(cr4) };
    // SAFETY: `build` mapped the image at KERNEL_VIRT_BASE with this code,
    // the stack (minus its guard pages) and BootState, and the direct map
    // the kernel's `phys_to_virt` relies on; the host tests check both.
    // Nothing the kernel uses after this point is in the lower half.
    unsafe { write_cr3(pml4) };
    // SAFETY: clearing and setting PGE only flushes the TLB [H4]; the
    // tables just loaded hold every translation the kernel needs.
    unsafe {
        cpu::write_cr4(cr4 & !CR4_PGE);
        cpu::write_cr4(cr4);
    }
    PML4_PHYS.store(pml4, Ordering::Release);

    kprintln!(
        "paging: kernel PML4 at {pml4:#x}; image {} KiB; device window pages: {}",
        layout.size >> 10,
        summary.window_pages
    );
    kprintln!(
        "paging: direct map {} GiB; 2 MiB pages: {} WB, {} UC, {} split into 4 KiB pages",
        h.direct_map_end() >> 30,
        summary.direct_wb,
        summary.direct_uc,
        summary.alias_pts
    );
}

/// Records one check of `test=paging`; returns whether it held.
fn check(ok: bool, what: &str) -> bool {
    kprintln!("paging: {} {what}", if ok { "ok  " } else { "FAIL" });
    ok
}

/// `test=paging`: the kernel runs on its own tables. CR3 holds the kernel
/// PML4 and CR4 the required bits; the software walk of the live tables
/// agrees with the design; a write through the direct map's alias of `.bss`
/// is seen at `KERNEL_VIRT_BASE`; the direct map's alias of `.text` reads
/// the same bytes; and the local APIC answers through the device window.
pub fn test_paging(boot: &BootState) -> ! {
    let Some((tables, pml4)) = built() else {
        panic!("test=paging: the kernel's tables are not loaded");
    };
    let layout = kernel_layout(&boot.handoff);
    let tables_phys = layout.virt_to_phys(&raw const *tables as u64);
    let cr3 = cpu::read_cr3();
    let cr4 = cpu::read_cr4();
    kprintln!("paging: CR3 {cr3:#x}, CR4 {cr4:#x}");
    let mut ok = check(cr3 & vspace::ADDR_4K == pml4, "CR3 holds the kernel PML4");
    let required = CR4_SMEP | CR4_SMAP | CR4_PGE;
    ok &= check(cr4 & required == required, "CR4.SMEP, SMAP and PGE are set");

    let walk = |virt| tables.walk(tables_phys, virt).ok().flatten();
    ok &= check(
        walk(0x20_0000).is_none() && walk(boot.handoff.kernel_phys_base).is_none(),
        "the lower half maps nothing",
    );
    ok &= check(
        layout.guards.iter().all(|&g| walk(g).is_none()),
        "the five guard pages are unmapped",
    );
    ok &= check(
        walk(KERNEL_VIRT_BASE).is_some_and(|t| t.execute && !t.write && t.global && !t.user),
        "KERNEL_VIRT_BASE is RX, global and supervisor-only",
    );
    let text_alias = PHYS_MAP_BASE + boot.handoff.kernel_phys_base;
    ok &= check(
        walk(text_alias).is_some_and(|t| !t.execute && !t.write),
        "the direct map's alias of .text is read-only and NX",
    );

    // A write through the direct map's alias of `.data` lands where the
    // image mapping reads.
    static PROBE: AtomicU64 = AtomicU64::new(0);
    let probe_alias = phys_to_virt(layout.virt_to_phys(&raw const PROBE as u64));
    // SAFETY: `probe_alias` is PROBE's own physical page through the direct
    // map, RW in the kernel's tables, and an AtomicU64 tolerates the alias.
    unsafe { (*(probe_alias as *const AtomicU64)).store(0x5EED_CAFE, Ordering::SeqCst) };
    ok &= check(
        PROBE.load(Ordering::SeqCst) == 0x5EED_CAFE,
        "a write through the direct map reaches .bss",
    );
    // SAFETY: both addresses map the image's first page of text, readable
    // in the kernel's tables; reading code bytes as data is harmless.
    let (a, b) = unsafe {
        (
            core::ptr::read_volatile(KERNEL_VIRT_BASE as *const u64),
            core::ptr::read_volatile(text_alias as *const u64),
        )
    };
    ok &= check(
        a == b,
        "the direct map's alias of .text reads the same bytes",
    );

    let lapic = DeviceWindow::virt(LAPIC_PAGE);
    ok &= check(
        walk(lapic).is_some_and(|t| t.cache == CacheType::Uncached && !t.execute && t.write),
        "the local APIC's window page is UC, RW and NX",
    );
    if cpu::read_msr(cpu::IA32_APIC_BASE) & APIC_BASE_X2APIC != 0 {
        kprintln!("paging: the local APIC is in x2APIC mode; skipping its MMIO read");
    } else {
        // SAFETY: the window maps the local APIC's page UC; offset 0x30 is
        // its read-only version register, and reading it has no side effect.
        let version = unsafe { core::ptr::read_volatile((lapic + 0x30) as *const u32) };
        kprintln!("paging: local APIC version register {version:#x}");
        ok &= check(
            (0x10..=0x1F).contains(&(version & 0xFF)),
            "the local APIC answers through the device window",
        );
    }

    if ok {
        kprintln!("TEST PASS");
        exit(ExitCode::Success)
    } else {
        kprintln!("TEST FAIL");
        exit(ExitCode::Failure)
    }
}

/// `test=lowmem`: the loader's 1:1 map is gone. Physical `LOW` is RAM and
/// reads through the direct map, but virtual `LOW`, which the loader mapped
/// 1:1, must fault. With the kernel's fault report the run ends in a
/// `KERNEL PANIC` naming CR2 = `LOW`; without it, in a triple fault.
pub fn test_lowmem() -> ! {
    const LOW: u64 = 0x20_0000;
    // SAFETY: physical 2 MiB is RAM on QEMU and Hyper-V and lies inside the
    // direct map; reading it changes nothing.
    let v = unsafe { core::ptr::read_volatile(phys_to_virt(LOW) as *const u64) };
    kprintln!("lowmem: physical {LOW:#x} reads {v:#x} through the direct map");
    kprintln!("lowmem: reading virtual {LOW:#x}, which the loader mapped 1:1; this must fault");
    let w: u64;
    // SAFETY: a read of a lower-half address, which the kernel's tables
    // leave unmapped: it touches no memory Rust knows about, and its page
    // fault ends the run.
    unsafe {
        asm!("mov {}, qword ptr [{}]", out(reg) w, in(reg) LOW, options(nostack, readonly));
    }
    kprintln!("TEST FAIL: virtual {LOW:#x} read {w:#x}; the 1:1 map is still there");
    exit(ExitCode::Failure)
}
