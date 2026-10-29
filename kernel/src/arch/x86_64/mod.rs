//! x86_64 support: boot entry, port I/O, COM1, CPUID and stopping the machine.

mod cpu;
mod entry;
mod io;
pub mod serial;

use core::arch::asm;

use l4core::handoff::{Handoff, MemoryRegion, PHYS_MAP_BASE};

pub use cpu::hypervisor;

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

/// The memory map the loader left, as a slice.
///
/// The caller must have called [`Handoff::validate`] on `h` first.
pub fn memory_map(h: &Handoff) -> &'static [MemoryRegion] {
    // SAFETY: `validate` checked that the array is aligned and lies inside the
    // direct map, which the loader built. The loader wrote it, and nothing
    // writes loader memory afterwards: the kernel allocates nothing yet.
    unsafe {
        core::slice::from_raw_parts(
            phys_to_virt(h.memory_map) as *const MemoryRegion,
            h.memory_map_len as usize,
        )
    }
}
