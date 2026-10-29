//! The kernel entry point.
//!
//! The loader jumps to `_start` in 64-bit mode on its own page tables, with
//! interrupts off and the physical address of the [`Handoff`] in `rdi`. Those
//! tables map this image at KERNEL_VIRT_BASE, physical memory at
//! PHYS_MAP_BASE and, for now, low memory 1:1. See docs/boot.md.

use core::arch::global_asm;

use l4core::handoff::Handoff;

use super::{phys_to_virt, serial};

const BOOT_STACK_SIZE: usize = 64 * 1024;

global_asm!(
    // The boot stack, in .bss so the loader zeroes it and it costs no file
    // space.
    ".section .bss.boot_stack, \"aw\", @nobits",
    ".balign 16",
    "boot_stack_bottom:",
    ".skip {stack_size}",
    "boot_stack_top:",
    "",
    ".section .text._start, \"ax\", @progbits",
    ".global _start",
    "_start:",
    "    cli",
    "    cld",
    // Keep the handoff pointer out of the way of `rep stosb`.
    "    mov r12, rdi",
    // Zero BSS. The loader has already done so, but the kernel does not rely
    // on it. Nothing here uses the stack, which lives in BSS.
    "    lea rdi, [rip + __bss_start]",
    "    lea rcx, [rip + __bss_end]",
    "    sub rcx, rdi",
    "    xor eax, eax",
    "    rep stosb",
    "    lea rsp, [rip + boot_stack_top]",
    "    xor ebp, ebp",
    "    mov rdi, r12",
    "    call {entry}",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
    stack_size = const BOOT_STACK_SIZE,
    entry = sym rust_entry,
);

/// First Rust code to run, on the boot stack with BSS zeroed.
extern "C" fn rust_entry(handoff_phys: u64) -> ! {
    serial::init();
    if handoff_phys == 0 || !handoff_phys.is_multiple_of(align_of::<Handoff>() as u64) {
        panic!("bad handoff pointer {handoff_phys:#x}");
    }
    // SAFETY: the loader passes the physical address of a Handoff it wrote,
    // inside the direct map it built, and nothing else writes it. Its fields
    // are plain integers, so any bit pattern is a valid Handoff; kmain
    // validates the contents before relying on them.
    let handoff = unsafe { &*(phys_to_virt(handoff_phys) as *const Handoff) };
    crate::kmain(handoff)
}
