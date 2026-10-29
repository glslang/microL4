//! Polled COM1 output for loader messages. Writes go straight to the UART,
//! so they work before and after ExitBootServices alike.

use core::arch::asm;
use core::fmt;

const COM1: u16 = 0x3F8;
const MAX_SPINS: u32 = 100_000;

macro_rules! log {
    ($($arg:tt)*) => {
        $crate::serial::print(format_args!("loader: {}\n", format_args!($($arg)*)))
    };
}

fn outb(port: u16, value: u8) {
    // SAFETY: only called with COM1's registers, which have no effect on
    // memory.
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nomem, nostack, preserves_flags))
    };
}

fn inb(port: u16) -> u8 {
    let value: u8;
    // SAFETY: as for `outb`; reading the line status register has no side
    // effects.
    unsafe {
        asm!("in al, dx", out("al") value, in("dx") port, options(nomem, nostack, preserves_flags))
    };
    value
}

/// 115200 baud, 8N1, FIFOs on, interrupts off; the same as the kernel uses.
pub fn init() {
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x80);
    outb(COM1, 0x01);
    outb(COM1 + 1, 0x00);
    outb(COM1 + 3, 0x03);
    outb(COM1 + 2, 0xC7);
    outb(COM1 + 4, 0x03);
}

fn write_byte(b: u8) {
    for _ in 0..MAX_SPINS {
        if inb(COM1 + 5) & 0x20 != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    outb(COM1, b);
}

struct Writer;

impl fmt::Write for Writer {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                write_byte(b'\r');
            }
            write_byte(b);
        }
        Ok(())
    }
}

pub fn print(args: fmt::Arguments<'_>) {
    let _ = fmt::Write::write_fmt(&mut Writer, args);
}
