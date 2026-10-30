//! x86_64 support: boot entry, port I/O, COM1, CPUID, control registers and
//! MSRs, descriptor tables and traps, the kernel's page tables, and stopping
//! the machine.

mod cell;
mod cpu;
mod entry;
mod gdt;
mod idt;
mod io;
mod irq;
mod paging;
pub mod serial;
mod trap;

use core::arch::{asm, global_asm};

use l4core::handoff::{Handoff, MemoryRegion, PHYS_MAP_BASE};

use crate::boot::BootState;

pub use cell::StaticCell;
pub use cpu::{check_cpu, hypervisor, print_cpu_state};
pub use paging::{test_lowmem, test_paging};
pub use trap::{Provoke, idle_self_test, print_stack_use, provoke};

// The Hyper-V hypercall page (`docs/design.md`, "The kernel half"): one page
// of the text segment of its own. M9 points `HV_X64_MSR_HYPERCALL` at it and
// the hypervisor overlays it; until then it holds `int3`s.
global_asm!(
    ".section .hvcall, \"ax\", @progbits",
    ".balign 4096",
    ".fill 4096, 1, 0xCC",
);

/// Steps 3 to 5 of the M3 boot sequence (`docs/design.md`, "Boot
/// sequence"), after the CPU check and the copy of the handoff into `boot`.
/// Runs with interrupts off, on the loader's page tables until `paging`
/// replaces them.
pub fn init(boot: &'static BootState) {
    // Step 3: GDT, TSS, IDT, CR4.MCE, GS base, DR7.
    gdt::init();
    // Step 4: the kernel's page tables, PAT, CR4 and CR3.
    let mut window = l4core::window::DeviceWindow::default(); // replaced by acpi::init at merge
    window.pages[0] = Some(cpu::read_msr(cpu::IA32_APIC_BASE) & 0x000F_FFFF_FFFF_F000); // replaced by acpi::init at merge
    paging::init(boot, &window);
}

/// QEMU's `isa-debug-exit` device, configured by `cargo xtask` at this port.
const DEBUG_EXIT_PORT: u16 = 0xF4;

/// How a test run ends. QEMU's `isa-debug-exit` turns a write of `v` into
/// host exit status `(v << 1) | 1`: 33 for success, 35 for failure. Both are
/// distinct from the statuses QEMU itself uses (0 and 1).
#[derive(Clone, Copy, Debug)]
#[repr(u32)]
pub enum ExitCode {
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
