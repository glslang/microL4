//! Port I/O: the only `in` and `out` instructions in the kernel.
//!
//! Each function is `#[inline(never)]` and takes its port as its first
//! argument, which it moves into `dx` itself, so every `in` and `out` in a
//! kernel image sits inside one of these symbols and no caller loads a port
//! into `dx`. `cargo xtask test` disassembles the kernel built without
//! `debug` and fails on any `in` or `out` outside them, any immediate
//! `0x3F8` to `0x3FF` moved into `dx`, `edx` or `rdx`, any call to them with
//! such an immediate as the port, and any `serial` symbol (`docs/design.md`,
//! "A release kernel without UART code"). A release kernel calls them from
//! three places only: the IOPort invocations, `pic::init` at boot and
//! `arch::exit`.

use core::arch::asm;

/// Writes a byte to an I/O port.
///
/// # Safety
///
/// Writing to an I/O port can have any effect the device behind it allows,
/// including on memory. The caller must know what is at `port`.
#[inline(never)]
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller vouches for the port; `out` touches no memory.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

/// Writes a 16-bit value to an I/O port.
///
/// # Safety
///
/// As for [`outb`].
#[inline(never)]
#[expect(dead_code, reason = "IOPort_Out16 (M7) is its only caller")]
pub unsafe fn outw(port: u16, value: u16) {
    // SAFETY: the caller vouches for the port; `out` touches no memory.
    unsafe {
        asm!("out dx, ax", in("dx") port, in("ax") value, options(nomem, nostack, preserves_flags))
    };
}

/// Writes a 32-bit value to an I/O port.
///
/// # Safety
///
/// As for [`outb`].
#[inline(never)]
pub unsafe fn outl(port: u16, value: u32) {
    // SAFETY: the caller vouches for the port; `out` touches no memory.
    unsafe {
        asm!("out dx, eax", in("dx") port, in("eax") value, options(nomem, nostack, preserves_flags))
    };
}

/// Reads a byte from an I/O port.
///
/// # Safety
///
/// Reading a port can have side effects, such as acknowledging an interrupt.
/// The caller must know what is at `port`.
#[inline(never)]
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller vouches for the port; `in` touches no memory.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Reads a 16-bit value from an I/O port.
///
/// # Safety
///
/// As for [`inb`].
#[inline(never)]
#[expect(dead_code, reason = "IOPort_In16 (M7) is its only caller")]
pub unsafe fn inw(port: u16) -> u16 {
    let value: u16;
    // SAFETY: the caller vouches for the port; `in` touches no memory.
    unsafe {
        asm!("in ax, dx", out("ax") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

/// Reads a 32-bit value from an I/O port.
///
/// # Safety
///
/// As for [`inb`].
#[inline(never)]
#[expect(dead_code, reason = "IOPort_In32 (M7) is its only caller")]
pub unsafe fn inl(port: u16) -> u32 {
    let value: u32;
    // SAFETY: the caller vouches for the port; `in` touches no memory.
    unsafe {
        asm!("in eax, dx", out("eax") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}
