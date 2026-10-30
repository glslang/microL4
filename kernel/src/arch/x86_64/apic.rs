//! The local APIC (`docs/design.md`, "Local APIC, PIC and I/O APIC (M3)"):
//! part of step 5 of the M3 boot sequence, the EOI and ISR, IRR and ESR
//! reads of the interrupt path, the timer registers [`super::timer`]
//! programs, and the `test=nmi_stack` hook.
//!
//! The kernel runs the local APIC in xAPIC mode and reaches it only through
//! the kernel device window, at [`LAPIC_PAGE`]; `l4core::apic` gives every
//! register and value.

use core::hint::spin_loop;
use core::ptr;

use l4core::apic::{self as a, ApicMode, Esr, Version};
use l4core::window::{DeviceWindow, LAPIC_PAGE};

use super::cpu::{self, IA32_APIC_BASE};

/// CPUID.1:ECX bit 21: the CPU offers x2APIC mode.
const CPUID_X2APIC: u32 = 1 << 21;

/// The address of local APIC register `offset` in the device window.
fn reg(offset: u32) -> u64 {
    DeviceWindow::virt(LAPIC_PAGE) + u64::from(offset)
}

fn read(offset: u32) -> u32 {
    // SAFETY: from `paging::init` on, which runs before any caller (step 5
    // and the interrupt path), the device window maps the local APIC's page
    // UC, RW. `offset` is one of `l4core::apic`'s register offsets, 16-byte
    // aligned inside the page. Reading a local APIC register touches no
    // memory and makes no Rust reference to the page.
    unsafe { ptr::read_volatile(reg(offset) as *const u32) }
}

fn write(offset: u32, value: u32) {
    // SAFETY: as in `read`. A register write changes only the local APIC's
    // interrupt state; the callers write the values `l4core::apic` and the
    // design give, never an INIT or SIPI.
    unsafe { ptr::write_volatile(reg(offset) as *mut u32, value) }
}

/// Part of step 5: puts the local APIC in xAPIC mode (leaving x2APIC
/// through the disabled state if the firmware left it on), masks every
/// LVT, sets TPR 0 and the SVR (enabled, spurious vector `0xFF`),
/// acknowledges any vector the firmware left in service, clears ESR and
/// unmasks the error LVT at `0xFE`. Interrupts must be off; the PIC is
/// reprogrammed after this, with LINT0 masked.
pub fn init() {
    let found = cpu::read_msr(IA32_APIC_BASE);
    let mode = ApicMode::of(found);
    for value in a::xapic_writes(found).into_iter().flatten() {
        // SAFETY: each value keeps the base address and changes only EN and
        // EXTD, in an order the SDM allows (never x2APIC to xAPIC
        // directly). The device window maps that base: `acpi::init` read
        // it from this MSR. Interrupts are off, and leaving x2APIC only
        // resets the local APIC, which this function programs next.
        unsafe { cpu::write_msr(IA32_APIC_BASE, value) };
    }
    let x2apic = cpu::cpuid(1).2 & CPUID_X2APIC != 0;
    kprintln!(
        "apic: IA32_APIC_BASE {found:#x} at handover: {}; CPUID {} x2APIC",
        mode.name(),
        if x2apic { "offers" } else { "does not offer" }
    );
    if mode != ApicMode::XApic {
        kprintln!(
            "apic: switched to xAPIC through the disabled state: IA32_APIC_BASE {:#x}",
            cpu::read_msr(IA32_APIC_BASE)
        );
    }

    let version = Version(read(a::VERSION));
    if !version.integrated() {
        panic!(
            "apic: version register {:#x} is not an integrated local APIC",
            version.0
        );
    }
    for lvt in version.lvts() {
        write(lvt, a::lvt_masked(read(lvt)));
    }
    write(a::TPR, 0);
    write(a::SVR, a::SVR_VALUE);
    let stale = acknowledge_stale();
    let esr = read_esr();
    write(a::LVT_ERROR, a::LVT_ERROR_VALUE);
    kprintln!(
        "apic: xAPIC ID {}, version {:#x}, {} LVT entries, all masked; TPR 0, SVR {:#x}, LVT error {:#x}",
        read(a::ID) >> 24,
        version.0,
        u32::from(version.max_lvt()) + 1,
        read(a::SVR),
        read(a::LVT_ERROR)
    );
    kprintln!(
        "apic: ESR {:#x} ({}); {stale} vectors left in service acknowledged",
        esr.0,
        esr
    );
}

/// Writes EOI until no ISR bit is set, at most 256 times: the firmware may
/// have left a vector in service, which would hold back every vector of its
/// priority class and below. Returns how many EOIs it took.
fn acknowledge_stale() -> u32 {
    let in_service = || (0..8).any(|w| read(a::ISR + w * 0x10) != 0);
    let mut n = 0;
    while n < 256 && in_service() {
        eoi();
        n += 1;
    }
    n
}

/// Signals the end of the interrupt in service.
pub fn eoi() {
    write(a::EOI, 0);
}

/// Whether `vector`'s ISR bit is set.
pub fn in_service(vector: u8) -> bool {
    let (offset, bit) = a::vector_bit(a::ISR, vector);
    read(offset) & bit != 0
}

/// Whether `vector`'s IRR bit is set.
pub fn requested(vector: u8) -> bool {
    let (offset, bit) = a::vector_bit(a::IRR, vector);
    read(offset) & bit != 0
}

/// The preemption point's poll (`docs/design.md`, "Vector map"): whether
/// any vector `0x30`-`0xFE` is pending in the IRR. Never enables
/// interrupts.
pub fn interrupt_pending() -> bool {
    a::PREEMPT_IRR_WORDS
        .into_iter()
        .any(|w| read(a::IRR + w as u32 * 0x10) & a::preempt_irr_mask(w) != 0)
}

/// Reads and clears the error status: the write latches the errors since
/// the last write and clears them, then the read returns them.
pub fn read_esr() -> Esr {
    write(a::ESR, 0);
    Esr(read(a::ESR))
}

/// Starts a calibration countdown: divide by 1, the timer LVT masked and
/// one-shot, from `0xFFFF_FFFF`.
pub fn timer_start_countdown() {
    write(a::TIMER_DIVIDE, a::TIMER_DIVIDE_BY_1);
    write(a::LVT_TIMER, a::LVT_TIMER_CALIBRATE);
    write(a::TIMER_INITIAL, a::TIMER_CALIBRATE_COUNT);
}

/// The timer's current count.
pub fn timer_current() -> u32 {
    read(a::TIMER_CURRENT)
}

/// Stops the timer.
pub fn timer_stop() {
    write(a::TIMER_INITIAL, 0);
}

/// Starts the periodic timer: divide by 1, vector `0xFD`, unmasked, one
/// interrupt every `initial_count` ticks.
pub fn timer_start_periodic(initial_count: u32) {
    write(a::TIMER_DIVIDE, a::TIMER_DIVIDE_BY_1);
    write(a::LVT_TIMER, a::LVT_TIMER_TICK);
    write(a::TIMER_INITIAL, initial_count);
}

/// `test=nmi_stack`: arms the NMI handler's test-only recursion, then sends
/// this CPU an NMI through the ICR. The handler recurses on IST2 until it
/// runs into the guard page below, which must end in the `#DF` report.
pub fn test_nmi_stack() -> ! {
    let id = (read(a::ID) >> 24) as u8;
    super::trap::arm_nmi_overflow();
    kprintln!("nmi_stack: sending an NMI to local APIC {id} through the ICR");
    while read(a::ICR_LOW) & a::ICR_SEND_PENDING != 0 {
        spin_loop();
    }
    let (high, low) = a::icr_nmi(id);
    write(a::ICR_HIGH, high);
    write(a::ICR_LOW, low);
    // The NMI arrives with interrupts off; give it time before failing.
    for _ in 0..1u32 << 26 {
        spin_loop();
    }
    panic!(
        "nmi_stack: no NMI arrived; ICR {:#x}, ESR {:#x}",
        read(a::ICR_LOW),
        read_esr().0
    )
}
