//! The interrupt path (`docs/design.md`, "Vector map", "Timer tick", "Idle
//! thread"): what the kernel does with an interrupt, a vector of 32 or
//! more, taken in the idle loop.
//!
//! - `0xFD`, the local APIC timer: EOI, then the tick.
//! - `0xFE`, the local APIC error: read and clear ESR, log, EOI.
//! - `0xFF`, the spurious vector: nothing, no EOI.
//! - `0x20`-`0x2F`, the masked PIC: log; EOI only if the ISR bit is set.
//! - `0xF0`-`0xFC`, IPIs, and `0x30`-`0xEF`, devices, which no one can
//!   issue before M7: log, EOI.
//!
//! `l4core::apic::needs_eoi` decides every EOI.

use core::sync::atomic::{AtomicU64, Ordering};

use l4core::apic::needs_eoi;
use l4core::trap::{self, Kind};

use super::{StaticCell, apic};

/// Timer ticks since the periodic timer started.
static TICKS: AtomicU64 = AtomicU64::new(0);
/// Called on every tick with the tick count, if a test installed it.
static TICK_HOOK: StaticCell<fn(u64)> = StaticCell::new();

/// Handles interrupt `vector`, taken in the idle loop. Runs with interrupts
/// off, at the top of the kernel stack; the idle loop resumes afterwards.
pub fn handle(vector: u8) {
    let kind = trap::kind(vector);
    let in_service = match kind {
        Kind::Pic { .. } => apic::in_service(vector),
        _ => false,
    };
    match kind {
        Kind::Timer | Kind::Spurious => {}
        Kind::ApicError => {
            let esr = apic::read_esr();
            kprintln!("irq: local APIC error, ESR {:#x} ({esr})", esr.0);
        }
        Kind::Pic { line } => kprintln!(
            "irq: spurious PIC vector {vector:#04x} (line {line}), {}",
            if in_service {
                "in service: EOI"
            } else {
                "not in service"
            }
        ),
        Kind::Ipi => kprintln!("irq: unexpected IPI vector {vector:#04x}"),
        Kind::Device { irq } => {
            kprintln!("irq: device vector {vector:#04x} (IRQ {irq}) before any was issued");
        }
        Kind::Exception | Kind::Fatal | Kind::CannotOccur => {
            panic!("vector {vector:#04x} is not an interrupt")
        }
    }
    if needs_eoi(vector, in_service) {
        apic::eoi();
    }
    if kind == Kind::Timer {
        tick();
    }
}

/// The timer tick, after its EOI. M5's `sched::tick()` is called here.
fn tick() {
    let n = TICKS.fetch_add(1, Ordering::Relaxed) + 1;
    if let Some(hook) = TICK_HOOK.get() {
        hook(n);
    }
}

/// Installs `hook`, called with the tick count on every timer tick from
/// now on. Once per boot: tests use it.
pub fn set_tick_hook(hook: fn(u64)) {
    TICK_HOOK.init(hook);
}
