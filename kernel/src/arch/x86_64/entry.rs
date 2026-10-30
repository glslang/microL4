//! The kernel entry point.
//!
//! The loader jumps to `_start` in 64-bit mode on its own page tables, with
//! interrupts off and the physical address of the handoff in `rdi`. Those
//! tables map this image at KERNEL_VIRT_BASE, physical memory at
//! PHYS_MAP_BASE and low memory 1:1, until the kernel replaces them (M3).
//! See docs/abi.md, "Boot handoff".

use core::arch::global_asm;

use super::serial;

global_asm!(
    // The kernel stack is the linker script's `.stacks` section, above an
    // unmapped guard page once the kernel's own page tables are in place.
    ".section .text._start, \"ax\", @progbits",
    ".global _start",
    "_start:",
    "    cli",
    "    cld",
    // Keep the handoff pointer out of the way of `rep stosb`.
    "    mov r12, rdi",
    // Zero BSS. The loader has already done so, but the kernel does not rely
    // on it. Nothing here uses a stack: RSP is still the loader's.
    "    lea rdi, [rip + __bss_start]",
    "    lea rcx, [rip + __bss_end]",
    "    sub rcx, rdi",
    "    xor eax, eax",
    "    rep stosb",
    "    lea rsp, [rip + __kernel_stack_top]",
    "    xor ebp, ebp",
    "    mov rdi, r12",
    "    call {entry}",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
    entry = sym rust_entry,
);

/// First Rust code to run, on the kernel stack with BSS zeroed.
extern "C" fn rust_entry(handoff_phys: u64) -> ! {
    serial::init();
    crate::kmain(handoff_phys)
}
