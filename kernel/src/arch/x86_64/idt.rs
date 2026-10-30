//! The IDT (`docs/design.md`, "Descriptor tables and MSRs", "Vector map"):
//! 256 64-bit interrupt gates on the kernel code selector, each to its
//! vector's stub in [`super::trap`], with the DPL and IST `l4core::trap`
//! gives. Built and loaded by [`super::gdt::init`].

use core::arch::asm;
use core::mem::size_of;

use super::gdt::DescriptorPointer;
use super::{StaticCell, trap};

#[repr(C, align(16))]
pub struct Idt([[u64; 2]; 256]);

static IDT: StaticCell<Idt> = StaticCell::new();

/// Builds the IDT in its static. Called once.
pub fn build() -> &'static Idt {
    let stubs = trap::stubs();
    let mut gates = [[0; 2]; 256];
    for (v, gate) in gates.iter_mut().enumerate() {
        *gate = l4core::trap::idt_gate(stubs[v], v as u8);
    }
    IDT.init(Idt(gates))
}

/// Loads `idt`. The GDT and the TSS its IST gates use must be loaded.
pub fn load(idt: &'static Idt) {
    let pointer = DescriptorPointer {
        // The gates only; `Idt` has no padding, but the limit must never
        // cover any.
        limit: (size_of::<[[u64; 2]; 256]>() - 1) as u16,
        base: idt as *const Idt as u64,
    };
    // SAFETY: the IDT is complete and static, every gate names a stub in
    // `trap` on the kernel code selector, and the caller has loaded the GDT
    // and the TSS. Interrupts are off; from here an exception reaches the
    // kernel's handlers instead of the firmware's.
    unsafe {
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
}
