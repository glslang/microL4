//! A polled 16550 UART on COM1, for kernel debug output.
//!
//! COM1 is at the same I/O ports on QEMU's q35 and on Hyper-V Generation 2.
//! Hyper-V connects it to a named pipe on the host.

use core::fmt;

use super::io::{inb, outb};

const COM1: u16 = 0x3F8;
const DATA: u16 = COM1;
const IER: u16 = COM1 + 1;
const FCR: u16 = COM1 + 2;
const LCR: u16 = COM1 + 3;
const MCR: u16 = COM1 + 4;
const LSR: u16 = COM1 + 5;

const LCR_DLAB: u8 = 0x80;
const LCR_8N1: u8 = 0x03;
const LSR_THR_EMPTY: u8 = 0x20;

/// Polls before giving up on one byte, so a missing or stuck UART cannot hang
/// the kernel. At 115200 baud a byte takes about 87 µs; this is far longer.
const MAX_SPINS: u32 = 100_000;

/// Sets COM1 to 115200 baud, 8N1, FIFOs on, interrupts off.
pub fn init() {
    // SAFETY: these are the standard 16550 registers at COM1, which both
    // supported platforms provide, and programming them has no effect on
    // memory.
    unsafe {
        outb(IER, 0x00);
        outb(LCR, LCR_DLAB);
        outb(DATA, 0x01); // divisor 1: 115200 baud
        outb(IER, 0x00); // divisor high byte
        outb(LCR, LCR_8N1);
        outb(FCR, 0xC7); // enable and clear FIFOs, 14-byte threshold
        outb(MCR, 0x03); // DTR and RTS; OUT2 stays off, so no IRQs
    }
}

fn write_byte(b: u8) {
    for _ in 0..MAX_SPINS {
        // SAFETY: reading the line status register has no side effects.
        if unsafe { inb(LSR) } & LSR_THR_EMPTY != 0 {
            break;
        }
        core::hint::spin_loop();
    }
    // SAFETY: writing the transmit register only sends the byte.
    unsafe { outb(DATA, b) };
}

/// Writes to COM1, turning `\n` into `\r\n`.
pub struct Writer;

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
