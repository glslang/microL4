//! ACPI at boot (`docs/design.md`, "ACPI and the timer"): the first half of
//! step 4 of the M3 boot sequence.
//!
//! `l4core::acpi` parses the tables once, through the loader's direct map,
//! before `paging` replaces the loader's page tables. The kernel keeps the
//! result in a static and never reads ACPI memory again, so M4 can make it
//! RAM untyped. No device register is touched here.

use l4core::acpi::{self, PhysRead, Platform};
use l4core::window::{DeviceWindow, LAPIC_PAGE};

use super::cpu::{IA32_APIC_BASE, read_msr};
use super::{StaticCell, phys_to_virt};
use crate::boot::BootState;

/// Physical memory below `end`, read one byte at a time through the
/// loader's direct map.
struct LoaderDirectMap {
    end: u64,
}

impl PhysRead for LoaderDirectMap {
    fn read_u8(&self, addr: u64) -> Option<u8> {
        if addr >= self.end {
            return None;
        }
        // SAFETY: `init` runs before `paging::init`, on the loader's page
        // tables, which map all of `[0, phys_map_size)` at `PHYS_MAP_BASE`,
        // holes included; `end` is `phys_map_size`, so the read cannot
        // fault. The parser reads only
        // where the RSDP and the tables it validated point: the firmware's
        // ACPI memory, which nothing writes while the kernel runs with
        // interrupts off. A byte read through a raw pointer makes no Rust
        // reference to that memory, and every `u8` is valid.
        Some(unsafe { core::ptr::read_volatile(phys_to_virt(addr) as *const u8) })
    }
}

static PLATFORM: StaticCell<Platform> = StaticCell::new();

/// Parses ACPI, panicking where `docs/design.md` says (no valid MADT, more
/// than four I/O APICs, two MADT or HPET tables), keeps the result for
/// [`platform`], prints the boot summary and returns the kernel device
/// window's pages: the local APIC's from `IA32_APIC_BASE`, each I/O APIC's
/// and the HPET's.
pub fn init(boot: &'static BootState) -> DeviceWindow {
    let h = &boot.handoff;
    // The whole loader direct map, not just the part the kernel's own will
    // cover: firmware may put ACPI tables above 64 GiB, and nothing reads
    // them after this parse (docs/design.md, "Tables and validation").
    let mem = LoaderDirectMap {
        end: h.phys_map_size,
    };
    let p = match acpi::parse(&mem, h.rsdp) {
        Ok(p) => PLATFORM.init(p),
        Err(e) => panic!("acpi: {e}"),
    };
    let window = p.device_window(read_msr(IA32_APIC_BASE));
    print_summary(p, &window);
    window
}

/// What the kernel took from ACPI. Panics before [`init`].
#[expect(
    dead_code,
    reason = "M3's interrupt controllers and timer read it (builder D)"
)]
pub fn platform() -> &'static Platform {
    PLATFORM.get().expect("ACPI is parsed in arch::init")
}

fn print_summary(p: &Platform, window: &DeviceWindow) {
    kprintln!(
        "acpi: RSDP revision {} at {:#x}, {} at {:#x}",
        p.revision,
        p.rsdp,
        p.root.signature,
        p.root.address
    );
    for t in p.tables.iter() {
        kprintln!(
            "acpi:   {} at {:#x}, {} bytes",
            t.signature,
            t.address,
            t.length
        );
    }
    let m = &p.madt;
    kprintln!(
        "acpi: MADT flags {:#x}{}, {} processor{}, LAPIC {:#x}",
        m.flags,
        if m.pcat_compat() { " PCAT_COMPAT" } else { "" },
        m.processors,
        if m.processors == 1 { "" } else { "s" },
        m.lapic
    );
    if let Some(page) = window.pages[LAPIC_PAGE]
        && page != m.lapic & !0xFFF
    {
        kprintln!(
            "acpi: warning: the MADT's LAPIC {:#x} is not IA32_APIC_BASE's {page:#x}; the kernel uses IA32_APIC_BASE",
            m.lapic
        );
    }
    for (i, io) in p.ioapics.iter().enumerate() {
        kprintln!(
            "acpi: I/O APIC {i}: ID {} at {:#x}, GSI base {}",
            io.id,
            io.address,
            io.gsi_base
        );
    }
    for o in p.overrides.iter() {
        kprintln!(
            "acpi: override ISA IRQ {} -> {} (flags {:#x})",
            o.source,
            o.route(),
            o.flags
        );
    }
    match p.isa_route(COM1_IRQ) {
        Some(r) => kprintln!("acpi: COM1 is ISA IRQ {COM1_IRQ} -> {r}"),
        None => kprintln!("acpi: COM1 (ISA IRQ {COM1_IRQ}) has no route"),
    }
    match p.hpet {
        Some(hpet) => kprintln!("acpi: HPET at {:#x}", hpet.base),
        None => kprintln!("acpi: no HPET"),
    }
    if p.ecam.is_empty() {
        kprintln!("acpi: no ECAM");
    }
    for e in p.ecam.iter() {
        kprintln!(
            "acpi: ECAM segment {}, buses {}-{}, at {:#x}",
            e.segment,
            e.start_bus,
            e.end_bus,
            e.base
        );
    }
    for w in p.warnings.iter() {
        kprintln!("acpi: warning: {w}");
    }
    if p.warnings_dropped > 0 {
        kprintln!("acpi: warning: {} more warnings", p.warnings_dropped);
    }
}

/// COM1's ISA IRQ on both platforms.
const COM1_IRQ: u8 = 4;
