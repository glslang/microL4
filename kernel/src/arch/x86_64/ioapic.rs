//! The I/O APICs (`docs/design.md`, "Local APIC, PIC and I/O APIC (M3)",
//! "IRQControl and IRQHandler"): part of step 5 of the M3 boot sequence,
//! which masks every redirection entry, keeping its old vector, and from
//! M7 the actions `l4core::irq` asks for ([`perform`]): mask, unmask, read
//! Remote IRR, clear a stale one (ADR 0027) and program an issued pin.
//! Each I/O APIC is reached only through its page of the kernel device
//! window.

use core::ptr;

use l4core::acpi::Platform;
use l4core::apic::{self as a, IoApicVersion};
use l4core::irq::{Action, RteWrite};
use l4core::window::{DeviceWindow, MAX_IOAPICS, ioapic_page};

use super::StaticCell;

/// COM1's ISA IRQ on both platforms.
const COM1_IRQ: u8 = 4;

/// I/O APIC `index`'s registers, at `base` in the device window, and its
/// version, which says whether it has the EOI register.
#[derive(Clone, Copy)]
struct IoApic {
    base: u64,
    version: IoApicVersion,
}

/// Each I/O APIC in MADT order, as step 5 found it: its registers in the
/// device window and the boot CPU's local APIC ID, for [`perform`].
struct IoApics {
    ioapics: [Option<IoApic>; MAX_IOAPICS],
    apic_id: u8,
}

static IOAPICS: StaticCell<IoApics> = StaticCell::new();

impl IoApic {
    /// I/O APIC `index`, its registers at `phys`, and its version, read
    /// from its version register. Its 32-bit register block, `0x20` bytes,
    /// or `0x44` from version `0x20`, must lie in the one page the window
    /// maps for it: past it is another device's page. The `0x20` bytes are
    /// checked before the version is read, the block of that version once
    /// it is known.
    fn new(index: usize, phys: u64) -> Self {
        check_block(phys, 0x20);
        let mut io = IoApic {
            base: DeviceWindow::virt(ioapic_page(index)) + (phys & 0xFFF),
            version: IoApicVersion(0),
        };
        io.version = IoApicVersion(io.read(a::IOAPIC_VERSION));
        check_block(phys, a::ioapic_block(io.version.version()));
        io
    }

    /// Reads indirect register `reg`.
    fn read(&self, reg: u32) -> u32 {
        // SAFETY: `paging::init` mapped this I/O APIC's page UC, RW in the
        // device window, and its register select and window are 32-bit
        // registers at offsets 0 and 0x10 of its block, whose first 0x20
        // bytes `new` checked lie in that page before its first read.
        // Selecting and reading a register touches no memory.
        unsafe {
            ptr::write_volatile((self.base + u64::from(a::IOREGSEL)) as *mut u32, reg);
            ptr::read_volatile((self.base + u64::from(a::IOWIN)) as *const u32)
        }
    }

    /// Writes indirect register `reg`.
    fn write(&self, reg: u32, value: u32) {
        // SAFETY: as in `read`. The callers write only redirection entries,
        // and none sends an NMI, SMI or INIT: step 5 sets the mask bit of
        // the entry it read; `MaskRte` and `ClearRemoteIrr` write back the
        // entry as read, mask set, so a delivery mode the firmware left
        // stays but cannot fire; `UnmaskRte` follows `ProgramRte` on an
        // issued pin, so it unmasks the fixed delivery mode `ProgramRte`
        // wrote; and `ProgramRte` writes fixed delivery mode. With
        // `selftest`, `write_low` writes what `test=irq_stale` gives.
        unsafe {
            ptr::write_volatile((self.base + u64::from(a::IOREGSEL)) as *mut u32, reg);
            ptr::write_volatile((self.base + u64::from(a::IOWIN)) as *mut u32, value);
        }
    }

    /// Writes `vector` to the EOI register, which version `0x20` and later
    /// have. An older I/O APIC has none: then it writes nothing and
    /// returns false (Remote IRR stays set, and the issue that asked for
    /// the write reads it set again and refuses with `RevokeFirst`).
    fn eoi(&self, vector: u32) -> bool {
        if self.version.version() < a::IOAPIC_EOI_VERSION {
            return false;
        }
        // SAFETY: as in `read`. This I/O APIC's version is `0x20` or
        // later, so its block is the 0x44 bytes `new` checked lie in the
        // mapped page, and the 32-bit EOI register at offset 0x40 is in
        // it. Writing a vector there only clears Remote IRR in the level
        // entries that name it.
        unsafe { ptr::write_volatile((self.base + u64::from(a::IOAPIC_EOI)) as *mut u32, vector) };
        true
    }
}

/// Asserts that an I/O APIC's register block, `len` bytes at `phys`, lies
/// in the one page the window maps for it.
fn check_block(phys: u64, len: u32) {
    assert!(
        phys & 0xFFF <= 0x1000 - u64::from(len),
        "ioapic: registers at {phys:#x} ({len:#x} bytes) cross a page"
    );
}

/// What step 5 found of the I/O APICs: each one's pin count and version,
/// in MADT order; 0 past the last.
pub struct Found {
    pub pins: [u16; MAX_IOAPICS],
    pub versions: [u8; MAX_IOAPICS],
}

/// Masks every pin of every I/O APIC the MADT lists, and prints each one
/// and where COM1's IRQ lands. Records each I/O APIC and the boot CPU's
/// local APIC ID `apic_id` for [`perform`]. Returns each I/O APIC's pin
/// count and version, read from its version register, in MADT order.
pub fn init(p: &Platform, apic_id: u8) -> Found {
    let mut found = Found {
        pins: [0; MAX_IOAPICS],
        versions: [0; MAX_IOAPICS],
    };
    let mut ioapics = [None; MAX_IOAPICS];
    for (i, io) in p.ioapics.iter().enumerate() {
        let ioapic = IoApic::new(i, io.address);
        let version = ioapic.version;
        let id = ioapic.read(a::IOAPIC_ID) >> 24 & 0xF;
        found.pins[i] = version.pins();
        found.versions[i] = version.version();
        ioapics[i] = Some(ioapic);
        let mut were_unmasked = 0;
        for pin in 0..found.pins[i] {
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
            found.pins[i],
            io.gsi_base,
            u64::from(io.gsi_base) + u64::from(found.pins[i]) - 1
        );
    }
    IOAPICS.init(IoApics { ioapics, apic_id });
    match p.isa_route(COM1_IRQ) {
        Some(r) => match p.ioapic_for_gsi(r.gsi, &found.pins) {
            Some(i) => kprintln!(
                "ioapic: COM1's GSI {} is I/O APIC {i} pin {}",
                r.gsi,
                r.gsi - p.ioapics.get(i).map_or(0, |io| io.gsi_base)
            ),
            None => kprintln!("ioapic: no I/O APIC serves COM1's GSI {}", r.gsi),
        },
        None => kprintln!("ioapic: COM1 has no ISA route"),
    }
    found
}

/// Performs one of `l4core::irq`'s actions on its pin: reads the entry's
/// low word, then makes the writes [`Action::writes`] gives, in order.
/// Returns whether Remote IRR is set for `CheckRemoteIrr`, false for every
/// other action. Panics for a pin of an I/O APIC step 5 did not find,
/// which no issued pin names.
pub fn perform(action: Action) -> bool {
    let all = IOAPICS.get().expect("the I/O APICs are set up at step 5");
    let pin = action.pin();
    let io = all.ioapics[usize::from(pin.ioapic)].expect("an I/O APIC step 5 found");
    let reg = a::redirection_low(pin.pin);
    let low = io.read(reg);
    if let Action::CheckRemoteIrr(_) = action {
        return a::remote_irr(low);
    }
    for w in action.writes(low, all.apic_id).into_iter().flatten() {
        match w {
            RteWrite::Low(v) => io.write(reg, v),
            RteWrite::High(v) => io.write(a::redirection_high(pin.pin), v),
            // core asks for it only of version 0x20 and later; were it to
            // ask of an older one, nothing is written and the issue's next
            // `CheckRemoteIrr` refuses it.
            RteWrite::Eoi(v) => {
                io.eoi(v);
            }
        }
    }
    false
}
/// `test=irq_stale`'s view of pin `pin` of I/O APIC `ioapic`: its entry's
/// low word.
#[cfg(feature = "selftest")]
pub fn read_low(ioapic: u8, pin: u16) -> u32 {
    let all = IOAPICS.get().expect("the I/O APICs are set up at step 5");
    let io = all.ioapics[usize::from(ioapic)].expect("an I/O APIC step 5 found");
    io.read(a::redirection_low(pin))
}

/// `test=irq_stale`: writes pin `pin`'s entry's low word directly, to
/// strand its Remote IRR.
#[cfg(feature = "selftest")]
pub fn write_low(ioapic: u8, pin: u16, value: u32) {
    let all = IOAPICS.get().expect("the I/O APICs are set up at step 5");
    let io = all.ioapics[usize::from(ioapic)].expect("an I/O APIC step 5 found");
    io.write(a::redirection_low(pin), value);
}
