//! The interrupt path (`docs/design.md`, "Vector map", "Idle thread"): what
//! the kernel does with an interrupt, a vector of 32 or more, taken in the
//! idle loop. The local APIC and timer code fills it in later in M3, the
//! device vectors in M7.

use l4core::trap;

/// Handles interrupt `vector`, taken in the idle loop. Runs with interrupts
/// off, at the top of the kernel stack; the idle loop resumes afterwards.
pub fn handle(vector: u8) {
    match vector {
        // The local APIC's spurious vector: nothing to do, and no EOI.
        trap::SPURIOUS => {}
        _ => panic!("unexpected interrupt {vector:#04x}"),
    }
}
