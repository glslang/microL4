//! The 8259 PIC pair (`docs/design.md`, "Local APIC, PIC and I/O APIC
//! (M3)"): part of step 5 of the M3 boot sequence. The kernel never uses
//! it; if the MADT says one exists, it is remapped to `0x20`/`0x28`, where
//! a stray vector cannot look like an exception, and every line is masked.

use l4core::apic::{PIC_INIT, PIC1_DATA, PIC2_DATA};
use l4core::trap::PIC_BASE;

use super::io;

/// Remaps and masks both 8259s if `pcat_compat` (the MADT flag) says they
/// exist. Interrupts must be off and the local APIC's LINT0 masked: the
/// first initialisation word clears the masks until the last write sets
/// them again.
pub fn init(pcat_compat: bool) {
    if !pcat_compat {
        kprintln!("pic: no PCAT_COMPAT; the 8259s are left alone");
        return;
    }
    for &(port, value) in &PIC_INIT {
        // SAFETY: the 8259s' command and data ports. Reprogramming them
        // changes only which vector a line would raise, and with LINT0
        // and IF masked none reaches the CPU; the last two writes mask
        // every line.
        unsafe { io::outb(port, value) };
    }
    // SAFETY: reading an 8259's data port returns its mask register and
    // has no side effect.
    let masks = unsafe { (io::inb(PIC1_DATA), io::inb(PIC2_DATA)) };
    kprintln!(
        "pic: remapped to {PIC_BASE:#04x} and {:#04x}, every line masked: masks {:#04x} {:#04x}",
        PIC_BASE + 8,
        masks.0,
        masks.1
    );
}
