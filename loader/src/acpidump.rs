//! The ACPI dump: with the word `acpidump` on the kernel command line, the
//! loader prints every ACPI table it can reach to COM1 in the line format of
//! `l4core::acpi::dump`, for `cargo xtask acpidump` to turn into a test file
//! (`core/tests/acpi/`, `tools/hyperv/README.md`).

use core::ptr;

use l4core::acpi::{PhysRead, dump};
use l4core::handoff::DIRECT_MAP_MAX;

/// Physical memory as the firmware maps it: 1:1 while boot services run.
struct Firmware;

impl PhysRead for Firmware {
    fn read_u8(&self, addr: u64) -> Option<u8> {
        // The firmware may leave page 0 unmapped to catch null pointers, and
        // the tables of both platforms lie far below the bound.
        if !(0x1000..DIRECT_MAP_MAX).contains(&addr) {
            return None;
        }
        // SAFETY: boot services are still running, so the firmware's page
        // tables map physical memory 1:1, and every address the dump reads
        // comes from the firmware's own ACPI tables. A byte read has no side
        // effect on RAM, and the value is copied out, so no reference to
        // firmware memory outlives the read.
        Some(unsafe { ptr::read_volatile(addr as *const u8) })
    }
}

/// Prints the dump of every table reachable from the RSDP at `rsdp`.
pub fn dump(rsdp: u64) {
    log!("dumping ACPI tables for `cargo xtask acpidump`");
    dump::write(&Firmware, rsdp, |line| log!("{line}"));
}
