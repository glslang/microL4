//! x86_64 support: boot entry, port I/O, COM1, CPUID, control registers and
//! MSRs, descriptor tables and traps, the kernel's page tables, the
//! interrupt controllers and the timer, kernel-object memory for the
//! capability core, and stopping the machine.

mod acpi;
mod apic;
mod cell;
mod cpu;
mod entry;
mod fpu;
mod gdt;
mod hpet;
mod hyperv;
mod idt;
mod io;
mod ioapic;
mod irq;
mod objects;
mod paging;
mod pic;
#[cfg(feature = "selftest")]
mod ring3;
mod rootimage;
pub mod serial;
mod thread;
mod timer;
mod trap;

use core::arch::{asm, global_asm};
use core::ops::Range;

use l4core::acpi::Platform;
use l4core::handoff::{Handoff, MemoryRegion, PHYS_MAP_BASE};
use l4core::window::{DeviceWindow, MAX_IOAPICS};

use crate::boot::BootState;

pub use cell::StaticCell;
pub use cpu::{check_cpu, hypervisor, print_cpu_state};
#[cfg(feature = "debug")]
pub use objects::for_each_tcb;
pub use objects::{Objects, bootinfo_frames, set_invoked_by_call};
pub use rootimage::take_rootimage;
pub use thread::exit_to_scheduled;
#[cfg_attr(
    not(feature = "selftest"),
    expect(unused_imports, reason = "only the self-tests idle through `arch`")
)]
pub use trap::idle;

#[cfg(feature = "selftest")]
pub use apic::test_nmi_stack;
#[cfg(feature = "selftest")]
pub use objects::{inject_preemption, poll_stats, reset_stretches};
#[cfg(feature = "selftest")]
pub use paging::{
    direct_map_page, test_lowmem, test_paging, test_vspace, translate as kernel_translation,
};
#[cfg(feature = "selftest")]
pub use ring3::test_ring3;
#[cfg(feature = "selftest")]
pub use timer::start_ticks_test;
#[cfg(feature = "selftest")]
pub use trap::{Provoke, idle_self_test, print_stack_use, provoke, set_resume_hook};

// The Hyper-V hypercall page (`docs/design.md`, "The kernel half"): one page
// of the text segment of its own. M9 points `HV_X64_MSR_HYPERCALL` at it and
// the hypervisor overlays it; until then it holds `int3`s.
global_asm!(
    ".section .hvcall, \"ax\", @progbits",
    ".balign 4096",
    ".fill 4096, 1, 0xCC",
);

/// What steps 2 to 5 found that the boot plan, the untyped and BootInfo
/// need (M4), collected once at the end of [`init`].
pub struct BootFacts {
    /// The CPU's physical address width, CPUID `0x8000_0008`: no untyped
    /// reaches `2^phys_addr_bits`.
    pub phys_addr_bits: u32,
    /// TSC ticks per second, calibrated in step 5: BootInfo's `tsc_hz`.
    pub tsc_hz: u64,
    /// What ACPI described: the I/O APICs, the ISA overrides, the ECAM
    /// ranges and the HPET, for BootInfo's `InterruptInfo`.
    pub platform: &'static Platform,
    /// Each I/O APIC's pin count as step 5 read it from its version
    /// register, in MADT order; 0 past the last.
    pub ioapic_pins: [u16; MAX_IOAPICS],
    /// The kernel device window's pages: part of `kernel_reserved`, and
    /// what makes a direct-map 2 MiB page uncached.
    pub device_window: DeviceWindow,
    /// The hypercall page the firmware locked enabled, if any: kept out of
    /// every untyped and the boot region.
    pub locked_hypercall_page: Option<u64>,
    /// BootInfo's `hypervisor_vendor`, one of `l4core::bootinfo`'s
    /// `HYPERVISOR_*` numbers.
    pub hypervisor_vendor: u32,
    /// The kernel image, physical: `[kernel_phys_base, + kernel_size)`.
    pub kernel_image: Range<u64>,
}

static FACTS: StaticCell<BootFacts> = StaticCell::new();

/// Steps 3 to 5 of the M3 boot sequence (`docs/design.md`, "Boot
/// sequence"), after the CPU check and the copy of the handoff into `boot`.
/// Runs with interrupts off, on the loader's page tables until `paging`
/// replaces them. Afterwards the timer ticks at 100 Hz, and the first tick
/// is taken when the kernel idles; `USABLE`, `LOADER` and
/// `ACPI_RECLAIMABLE` memory outside the kernel image is free, and
/// [`Objects`] can be used. Returns what the boot steps found.
pub fn init(boot: &'static BootState) -> &'static BootFacts {
    // Step 3: GDT, TSS, IDT, CR4.MCE, GS base, DR7.
    gdt::init();
    // Step 4: ACPI, read through the loader's direct map, then the
    // kernel's page tables, PAT, CR4 and CR3.
    let window = acpi::init(boot);
    paging::init(boot, &window);
    // Step 5: Hyper-V's leftovers off (a synthetic timer can raise an
    // NMI); the local APIC, LINT0 masked before the PIC is reprogrammed;
    // the I/O APICs; the HPET; then calibration and the 100 Hz timer.
    let hv = hyperv::init();
    let platform = acpi::platform();
    apic::init();
    pic::init(platform.madt.pcat_compat());
    let ioapic_pins = ioapic::init(platform);
    let hpet = hpet::init(platform);
    let calibration = timer::init(hv, hpet);

    let h = &boot.handoff;
    let facts = FACTS.init(BootFacts {
        phys_addr_bits: cpu::phys_addr_bits(),
        tsc_hz: calibration.tsc_hz,
        platform,
        ioapic_pins,
        device_window: window,
        locked_hypercall_page: hv.locked_hypercall_page,
        hypervisor_vendor: hypervisor().vendor(),
        kernel_image: h.kernel_phys_base..h.kernel_phys_base + h.kernel_size,
    });
    kprintln!("cpu: physical address width {} bits", facts.phys_addr_bits);
    objects::init(boot, facts);
    facts
}

/// Kernel memory as `arch` sees it, for `test=bootinfo`: physical ranges
/// found from the CPU's registers (GDTR, IDTR, `IA32_GS_BASE`, CR3), the
/// linker's stack symbols and statics, translated through the live page
/// tables, and the pages the device window maps. None of it comes from the
/// boot plan. `None` for a device-window page not in use.
#[cfg(feature = "selftest")]
pub fn kernel_memory(boot: &BootState) -> [Option<(&'static str, Range<u64>)>; 18] {
    use l4core::vspace::ADDR_4K;
    use l4core::window::{self, DeviceWindow};

    let mut out = [const { None }; 18];
    let s = gdt::stack_layout();
    let [ist1, ist2, ist3, ist4] = s.ist;
    let state = boot as *const BootState as u64;
    let virt = [
        ("the kernel stack", s.kernel),
        ("IST1", ist1),
        ("IST2", ist2),
        ("IST3", ist3),
        ("IST4", ist4),
        ("the kernel page tables", paging::tables_virt()),
        (
            "BootState",
            state..state + core::mem::size_of::<BootState>() as u64,
        ),
    ];
    let pml4 = cpu::read_cr3() & ADDR_4K;
    let all = virt.into_iter().chain(gdt::tables_in_use());
    for (slot, (name, v)) in out.iter_mut().zip(all) {
        let phys = paging::translate(boot, v.clone())
            .unwrap_or_else(|| panic!("{name} at {:#x} is not mapped", v.start));
        *slot = Some((name, phys));
    }
    out[11] = Some(("the PML4 in CR3", pml4..pml4 + 4096));
    for (i, slot) in out[12..12 + window::PAGES].iter_mut().enumerate() {
        let page = DeviceWindow::virt(i);
        *slot = paging::translate(boot, page..page + 4096).map(|p| ("a device-window page", p));
    }
    out
}

/// Spins with interrupts off until the preemption point's poll sees an
/// interrupt pending, for at most `ns` nanoseconds by the TSC; whether one
/// did. For `test=retype`, whose first call must be preempted by a real
/// interrupt on any host.
#[cfg(feature = "selftest")]
pub fn wait_interrupt_pending(ns: u64) -> bool {
    let hz = FACTS.get().map_or(0, |f| f.tsc_hz);
    let limit = (u128::from(ns) * u128::from(hz) / 1_000_000_000) as u64;
    let start = cpu::rdtsc();
    while !apic::interrupt_pending() {
        if cpu::rdtsc().wrapping_sub(start) > limit {
            return false;
        }
        core::hint::spin_loop();
    }
    true
}

/// QEMU's `isa-debug-exit` device, configured by `cargo xtask` at this port.
const DEBUG_EXIT_PORT: u16 = 0xF4;

/// How a test run ends. QEMU's `isa-debug-exit` turns a write of `v` into
/// host exit status `(v << 1) | 1`: 33 for success, 35 for failure. Both are
/// distinct from the statuses QEMU itself uses (0 and 1).
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum ExitCode {
    #[cfg_attr(
        not(feature = "debug"),
        expect(dead_code, reason = "a passing self-test, and `DebugHalt(0)`")
    )]
    Success = 0x10,
    Failure = 0x11,
}

/// Ends the run. Under QEMU this exits through `isa-debug-exit`; anywhere
/// else, including Hyper-V, it halts and the host stops the VM.
pub fn exit(code: ExitCode) -> ! {
    if hypervisor().is_qemu() {
        // SAFETY: under QEMU, xtask always attaches isa-debug-exit at this
        // port, and writing to it only ends the emulator.
        unsafe { io::outl(DEBUG_EXIT_PORT, code as u32) };
    }
    halt()
}

/// Stops this core for good.
pub fn halt() -> ! {
    loop {
        // SAFETY: `cli; hlt` touches no memory. With interrupts off only an
        // NMI wakes the core, and the loop halts it again.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Virtual address of physical address `phys` in the direct map.
pub const fn phys_to_virt(phys: u64) -> u64 {
    PHYS_MAP_BASE + phys
}

/// A copy of the handoff the loader left at `handoff_phys`. Call only on the
/// loader's page tables, before `init`.
pub fn read_handoff(handoff_phys: u64) -> Handoff {
    if handoff_phys == 0 || !handoff_phys.is_multiple_of(align_of::<Handoff>() as u64) {
        panic!("bad handoff pointer {handoff_phys:#x}");
    }
    // SAFETY: the loader passes the physical address of a Handoff it wrote,
    // inside the direct map it built, and nothing else writes it. Its fields
    // are plain integers, so any bit pattern is a valid Handoff; the caller
    // validates the contents before relying on them.
    unsafe { core::ptr::read(phys_to_virt(handoff_phys) as *const Handoff) }
}

/// Copies the first `out.len()` entries of the memory map the loader left
/// into `out`. Panics if the handoff is invalid or the map is shorter, so
/// that safe code cannot read outside it. Call only on the loader's page
/// tables, before `init`.
pub fn read_memory_map(h: &Handoff, out: &mut [MemoryRegion]) {
    if let Err(e) = h.validate() {
        panic!("bad handoff: {e}");
    }
    assert!(out.len() as u64 <= h.memory_map_len);
    // SAFETY: `validate` just checked that the array is aligned and lies
    // inside the direct map, which the loader built, and `out` is no longer
    // than it. The loader wrote it, and nothing writes loader memory
    // afterwards. MemoryRegion is plain integers, so any contents are valid.
    let map = unsafe {
        core::slice::from_raw_parts(phys_to_virt(h.memory_map) as *const MemoryRegion, out.len())
    };
    out.copy_from_slice(map);
}
