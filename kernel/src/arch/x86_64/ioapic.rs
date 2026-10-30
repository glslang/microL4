//! The I/O APICs (`docs/design.md`, "Local APIC, PIC and I/O APIC (M3)"):
//! part of step 5 of the M3 boot sequence. Every redirection entry is
//! masked, keeping its old vector, until M7 issues the pin. Each I/O APIC is
//! reached only through its page of the kernel device window.

use core::ptr;

use l4core::acpi::Platform;
use l4core::apic::{self as a, IoApicVersion};
use l4core::window::{DeviceWindow, MAX_IOAPICS, ioapic_page};

/// COM1's ISA IRQ on both platforms.
const COM1_IRQ: u8 = 4;

/// I/O APIC `index`'s registers, at `base` in the device window.
struct IoApic {
    base: u64,
}

impl IoApic {
    fn new(index: usize, phys: u64) -> Self {
        // The 32-byte register block must lie in the one page the window
        // maps for it; past it is another device's page.
        assert!(
            phys & 0xFFF <= 0x1000 - 0x20,
            "ioapic: {index}: registers at {phys:#x} cross a page"
        );
        IoApic {
            base: DeviceWindow::virt(ioapic_page(index)) + (phys & 0xFFF),
        }
    }

    /// Reads indirect register `reg`.
    fn read(&self, reg: u32) -> u32 {
        // SAFETY: `paging::init` mapped this I/O APIC's page UC, RW in the
        // device window, and its register select and window are 32-bit
        // registers at offsets 0 and 0x10 of its block, which `new` checked
        // lies in that page. Selecting and reading a register touches no
        // memory.
        unsafe {
            ptr::write_volatile((self.base + u64::from(a::IOREGSEL)) as *mut u32, reg);
            ptr::read_volatile((self.base + u64::from(a::IOWIN)) as *const u32)
        }
    }

    /// Writes indirect register `reg`.
    fn write(&self, reg: u32, value: u32) {
        // SAFETY: as in `read`; the callers only set mask bits.
        unsafe {
            ptr::write_volatile((self.base + u64::from(a::IOREGSEL)) as *mut u32, reg);
            ptr::write_volatile((self.base + u64::from(a::IOWIN)) as *mut u32, value);
        }
    }
}

/// Masks every pin of every I/O APIC the MADT lists, and prints each one
/// and where COM1's IRQ lands.
pub fn init(p: &Platform) {
    let mut pins = [0u16; MAX_IOAPICS];
    for (i, io) in p.ioapics.iter().enumerate() {
        let ioapic = IoApic::new(i, io.address);
        let version = IoApicVersion(ioapic.read(a::IOAPIC_VERSION));
        let id = ioapic.read(a::IOAPIC_ID) >> 24 & 0xF;
        pins[i] = version.pins();
        let mut were_unmasked = 0;
        for pin in 0..pins[i] {
            let reg = a::redirection_low(pin);
            let low = ioapic.read(reg);
            if low & a::REDIRECTION_MASKED == 0 {
                ioapic.write(reg, a::redirection_masked(low));
                were_unmasked += 1;
            }
        }
        kprintln!(
            "ioapic: {i}: ID {id}, version {:#x}, {} pins for GSI {}-{}, all masked ({were_unmasked} were not)",
            version.version(),
            pins[i],
            io.gsi_base,
            u64::from(io.gsi_base) + u64::from(pins[i]) - 1
        );
    }
    match p.isa_route(COM1_IRQ) {
        Some(r) => match p.ioapic_for_gsi(r.gsi, &pins) {
            Some(i) => kprintln!(
                "ioapic: COM1's GSI {} is I/O APIC {i} pin {}",
                r.gsi,
                r.gsi - p.ioapics.get(i).map_or(0, |io| io.gsi_base)
            ),
            None => kprintln!("ioapic: no I/O APIC serves COM1's GSI {}", r.gsi),
        },
        None => kprintln!("ioapic: COM1 has no ISA route"),
    }
}
