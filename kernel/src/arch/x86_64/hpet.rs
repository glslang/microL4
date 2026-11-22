//! The HPET (`docs/design.md`, "The timer"): part of step 5 of the M3 boot
//! sequence. The kernel uses only its main counter, as a calibration
//! reference; it first turns off whatever the firmware left that could
//! interrupt (comparator interrupts, FSB delivery, legacy replacement), then
//! runs the counter. Reached only through [`HPET_PAGE`] of the device window.

use core::hint::spin_loop;
use core::ptr;

use l4core::acpi::Platform;
use l4core::hpet::{self as h, Capabilities};
use l4core::timer::Reference;
use l4core::window::{DeviceWindow, HPET_PAGE};

/// The HPET's main counter, running.
pub struct Hpet {
    base: u64,
    caps: Capabilities,
    reference: Reference,
}

/// Reads the 64-bit register at `offset` of the HPET block at `base` in the
/// device window.
fn read_at(base: u64, offset: u32) -> u64 {
    // SAFETY: `paging::init` mapped the HPET's page UC, RW in the device
    // window, and `base` is the block's address there; `l4core::acpi`
    // accepts an HPET only if its 1 KiB register block lies in one page,
    // and `offset` is a 64-bit register below 0x400, 8-byte aligned.
    // Reading it touches no memory.
    unsafe { ptr::read_volatile((base + u64::from(offset)) as *const u64) }
}

impl Hpet {
    fn read(&self, offset: u32) -> u64 {
        read_at(self.base, offset)
    }

    fn write(&self, offset: u32, value: u64) {
        // SAFETY: as in `read_at`; the callers turn interrupt routing off and
        // the main counter on, nothing else.
        unsafe { ptr::write_volatile((self.base + u64::from(offset)) as *mut u64, value) }
    }

    /// The main counter, [`Hpet::mask`] bits wide.
    pub fn counter(&self) -> u64 {
        self.read(h::MAIN_COUNTER) & self.caps.counter_mask()
    }

    /// The counter's width as a mask: it wraps after `mask + 1` ticks.
    pub fn mask(&self) -> u64 {
        self.caps.counter_mask()
    }

    pub fn reference(&self) -> Reference {
        self.reference
    }

    /// Whether the main counter moves within a few hundred reads.
    fn counter_moves(&self) -> bool {
        let first = self.counter();
        (0..1000).any(|_| {
            spin_loop();
            self.counter() != first
        })
    }
}

/// Checks and cleans up the HPET the ACPI table names, if any, and returns
/// its running main counter; `None` if there is none or its period is
/// implausible. Interrupts must be off.
pub fn init(p: &Platform) -> Option<Hpet> {
    let table = p.hpet?;
    let base = DeviceWindow::virt(HPET_PAGE) + (table.base & 0xFFF);
    let caps = Capabilities(read_at(base, h::GCAP_ID));
    kprintln!("hpet: {caps}");
    let reference = match caps.reference() {
        Ok(r) => r,
        Err(e) => {
            kprintln!("hpet: {e}; not used");
            return None;
        }
    };
    let hpet = Hpet {
        base,
        caps,
        reference,
    };
    if caps.comparators() > caps.comparators_in_block() {
        kprintln!(
            "hpet: only the first {} comparators fit the register block",
            caps.comparators_in_block()
        );
    }

    let config = hpet.read(h::GEN_CONF);
    let was_running = config & h::ENABLE_CNF != 0;
    let moved_before = hpet.counter_moves();
    // Legacy replacement off first, the counter as it was.
    hpet.write(h::GEN_CONF, config & !h::LEG_RT_CNF);
    let mut quietened = 0u32;
    for n in 0..caps.comparators_in_block() {
        let reg = h::comparator_config(n);
        if let Some(v) = h::quiet_comparator(hpet.read(reg)) {
            hpet.write(reg, v);
            quietened |= 1 << n;
        }
    }
    // Clear any level-triggered status the firmware left: write 1s.
    let status = hpet.read(h::GINTR_STA);
    hpet.write(h::GINTR_STA, status);
    hpet.write(h::GEN_CONF, h::general_config(config));
    let moves = hpet.counter_moves();
    kprintln!(
        "hpet: found config {config:#x} (counter {}{}), comparators interrupting {quietened:#x}, status {status:#x}",
        if was_running { "on" } else { "off" },
        match (was_running, moved_before) {
            (true, true) | (false, false) => "",
            (true, false) => ", but not moving",
            (false, true) => ", but moving",
        }
    );
    if !moves {
        kprintln!("hpet: the main counter does not move with ENABLE_CNF set; not used");
        return None;
    }
    kprintln!(
        "hpet: legacy replacement and comparator interrupts off, main counter on: {} Hz",
        reference.hz()
    );
    Some(hpet)
}

/// `test=irq_stale`: the HPET's last comparator as a level-triggered
/// interrupt source, the one device whose line the kernel can raise and
/// hold to strand an I/O APIC pin's Remote IRR.
#[cfg(feature = "selftest")]
pub struct LevelSource {
    base: u64,
    n: u8,
}

/// The HPET the ACPI table names, if it has a comparator and its main
/// counter runs (step 5 left it so), as a [`LevelSource`].
#[cfg(feature = "selftest")]
pub fn level_source(p: &Platform) -> Option<LevelSource> {
    let table = p.hpet?;
    let base = DeviceWindow::virt(HPET_PAGE) + (table.base & 0xFFF);
    let caps = Capabilities(read_at(base, h::GCAP_ID));
    let n = caps
        .comparators()
        .min(caps.comparators_in_block())
        .checked_sub(1)?;
    (read_at(base, h::GEN_CONF) & h::ENABLE_CNF != 0).then_some(LevelSource { base, n })
}

#[cfg(feature = "selftest")]
impl LevelSource {
    fn write(&self, offset: u32, value: u64) {
        // SAFETY: as in `read_at`, for a 64-bit register of the block. The
        // self-test writes only this comparator's configuration and value
        // and the status register: a level interrupt on the one I/O APIC
        // input it picked, which it then lowers and turns off.
        unsafe { ptr::write_volatile((self.base + u64::from(offset)) as *mut u64, value) }
    }

    /// The comparator's number.
    pub fn comparator(&self) -> u8 {
        self.n
    }

    /// The I/O APIC inputs it can drive, bit `i` for input `i`.
    pub fn route_cap(&self) -> u32 {
        h::route_cap(read_at(self.base, h::comparator_config(self.n)))
    }

    /// Raises its level-triggered interrupt on I/O APIC input `route`
    /// `ticks` main-counter ticks from now, and holds it.
    pub fn fire(&self, route: u8, ticks: u64) {
        let reg = h::comparator_config(self.n);
        let config = read_at(self.base, reg);
        let now = read_at(self.base, h::MAIN_COUNTER);
        self.write(h::comparator_value(self.n), now.wrapping_add(ticks));
        self.write(reg, h::level_config(config, route));
    }

    /// Lowers its line, by clearing its status bit, and turns it off.
    pub fn stop(&self) {
        let reg = h::comparator_config(self.n);
        let config = read_at(self.base, reg);
        if let Some(quiet) = h::quiet_comparator(config) {
            self.write(reg, quiet);
        }
        self.write(h::GINTR_STA, 1 << self.n);
    }
}
