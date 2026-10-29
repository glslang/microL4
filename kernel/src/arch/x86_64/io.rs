//! Port I/O.

use core::arch::asm;

/// Writes a byte to an I/O port.
///
/// # Safety
///
/// Writing to an I/O port can have any effect the device behind it allows,
/// including on memory. The caller must know what is at `port`.
pub unsafe fn outb(port: u16, value: u8) {
    // SAFETY: the caller vouches for the port; `out` touches no memory.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

/// Writes a 32-bit value to an I/O port.
///
/// # Safety
///
/// As for [`outb`].
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
pub unsafe fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: the caller vouches for the port; `in` touches no memory.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}
