//! `test=irq_stale` (ADR 0027): an issue clears a stale Remote IRR, on the
//! I/O APIC version QEMU gives: `0x20` by default, with the EOI register,
//! and `0x11` with `-global ioapic.version=0x11`, without one, where the
//! kernel toggles the trigger.
//!
//! The HPET's last comparator raises a level-triggered interrupt on an I/O
//! APIC input it can drive, programmed with vector `0xEF`. Once the local
//! APIC holds that vector, Remote IRR is set; the test rewrites the entry
//! masked with vector `0xEE` before any EOI and lowers the line, so no EOI
//! can clear it: a delivery whose EOI never came, as the firmware can leave
//! one. Then `IRQControl_GetIOAPIC` for that GSI, made through
//! `l4core::invoke` on the root task's IRQControl as the root task would
//! make it, must succeed, leaving the entry unmasked with Remote IRR clear;
//! and the comparator's next interrupt must arrive with the issued vector.

use core::hint::spin_loop;

use l4core::apic as a;
use l4core::bootinfo::{BootInfo, CAP_INIT_CNODE, CAP_IRQ_CONTROL};
use l4core::invoke::{self, ExtraCap, Message};
use l4core::irq::{self, Action, Interrupts, Pin, label};
use l4core::slot::SlotMemory;

use super::{ExitCode, FACTS, Objects, apic, cpu, exit, hpet, ioapic};
use crate::boot::RootSpace;

/// The vector the stranded delivery is sent with: IRQ 191's, issued to
/// nobody.
const SENT: u8 = 0xEF;
/// The vector the entry names once stranded.
const STRANDED: u8 = 0xEE;
/// HPET ticks before the comparator fires: 10 µs at QEMU's 100 MHz.
const TICKS: u64 = 1000;

fn fail(why: core::fmt::Arguments<'_>) -> ! {
    kprintln!("TEST FAIL: irq_stale: {why}");
    exit(ExitCode::Failure)
}

/// Waits up to 100 ms by the TSC for the local APIC to hold `vector`.
fn wait_requested(vector: u8, tsc_hz: u64) -> bool {
    let start = cpu::rdtsc();
    while !apic::requested(vector) {
        if cpu::rdtsc().wrapping_sub(start) > tsc_hz / 10 {
            return false;
        }
        spin_loop();
    }
    true
}

fn low(pin: Pin) -> u32 {
    ioapic::read_low(pin.ioapic, pin.pin)
}

pub fn test_irq_stale(root: &RootSpace, bi: &BootInfo) -> ! {
    let facts = FACTS.get().expect("boot facts before the self-tests");
    let Some(src) = hpet::level_source(facts.platform) else {
        fail(format_args!(
            "no HPET comparator to raise a level interrupt"
        ))
    };
    let mut k = Objects::begin();
    let routing = *k.routing();
    let cap = src.route_cap();
    let Some((gsi, pin, io)) = (0..32u32)
        .rev()
        .filter(|i| cap >> i & 1 == 1)
        .find_map(|g| routing.pin(g.into()).map(|(p, io)| (g, p, io)))
    else {
        fail(format_args!(
            "HPET comparator {} reaches no I/O APIC input (route capability {cap:#x})",
            src.comparator()
        ))
    };
    let path = if io.has_eoi_register() {
        "through the EOI register"
    } else {
        "by toggling the trigger, as it has no EOI register"
    };
    kprintln!(
        "irq_stale: I/O APIC {} is version {:#x}; HPET comparator {} (route capability {cap:#x}) drives GSI {gsi}, level-triggered",
        pin.ioapic,
        io.version,
        src.comparator()
    );

    // A level delivery whose EOI never matches its entry.
    ioapic::perform(Action::ProgramRte {
        pin,
        vector: SENT,
        level: true,
        active_low: false,
    });
    src.fire(gsi as u8, TICKS);
    if !wait_requested(SENT, facts.tsc_hz) {
        src.stop();
        fail(format_args!(
            "GSI {gsi} never sent vector {SENT:#x}: entry {:#x}",
            low(pin)
        ))
    }
    let sent = low(pin);
    ioapic::write_low(
        pin.ioapic,
        pin.pin,
        u32::from(STRANDED) | a::REDIRECTION_LEVEL | a::REDIRECTION_MASKED,
    );
    src.stop();
    let stranded = low(pin);
    let masked = stranded & a::REDIRECTION_MASKED != 0;
    if !a::remote_irr(sent)
        || !a::remote_irr(stranded)
        || !masked
        || stranded & 0xFF != u32::from(STRANDED)
    {
        fail(format_args!(
            "Remote IRR not stranded: entry {sent:#x} when sent, {stranded:#x} rewritten"
        ))
    }
    kprintln!(
        "irq_stale: GSI {gsi} sent vector {SENT:#x} with Remote IRR set (entry {sent:#x}); rewritten masked with vector {STRANDED:#x} before any EOI, and its line lowered: Remote IRR stranded (entry {stranded:#x})"
    );

    // GetIOAPIC through the root task's IRQControl.
    let layout = &root.plan.layout;
    let dest = bi.empty.start;
    let extra = [ExtraCap::load(&k, layout.slot(CAP_INIT_CNODE))];
    let mrs = [u64::from(gsi), 1, 0, dest, 64];
    let msg = Message {
        label: label::GET_IOAPIC,
        mrs: &mrs,
        extra_caps: &extra,
    };
    if let Err(e) = invoke::invoke(&mut k, layout.slot(CAP_IRQ_CONTROL), &msg) {
        fail(format_args!(
            "GetIOAPIC({gsi}, level) failed: {e:?}; entry {:#x}",
            low(pin)
        ))
    }
    let Some(n) = irq::handler_irq(&k.load(layout.slot(dest)).cap) else {
        fail(format_args!("GetIOAPIC left no IRQHandler in slot {dest}"))
    };
    let vector = irq::vector(n);
    let issued = low(pin);
    let want = a::redirection_entry(vector, true, false);
    if issued != want {
        fail(format_args!(
            "GetIOAPIC left entry {issued:#x}, not {want:#x}"
        ))
    }
    kprintln!(
        "irq_stale: ok   GetIOAPIC({gsi}, level) cleared Remote IRR {path} and issued IRQ {n} in slot {dest}: entry {issued:#x}, unmasked, Remote IRR clear"
    );

    // The pin works: the comparator's next interrupt arrives.
    src.fire(gsi as u8, TICKS);
    let arrived = wait_requested(vector, facts.tsc_hz);
    let after = low(pin);
    src.stop();
    if !arrived || !a::remote_irr(after) {
        fail(format_args!(
            "the comparator's next interrupt did not arrive as vector {vector:#x}: entry {after:#x}"
        ))
    }
    kprintln!("irq_stale: ok   the comparator's next interrupt arrived as vector {vector:#x}");
    kprintln!("TEST PASS");
    exit(ExitCode::Success)
}
