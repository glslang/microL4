//! The 16550's registers, by offset from its base port, and the bits uart
//! uses.

/// Receive buffer (read, DLAB clear).
pub const RBR: u8 = 0;
/// Transmit holding register (write, DLAB clear).
pub const THR: u8 = 0;
/// Divisor latch, low and high (DLAB set).
pub const DLL: u8 = 0;
pub const DLM: u8 = 1;
/// Interrupt enable (DLAB clear).
pub const IER: u8 = 1;
/// Interrupt identification (read).
pub const IIR: u8 = 2;
/// FIFO control (write).
pub const FCR: u8 = 2;
/// Line control.
pub const LCR: u8 = 3;
/// Modem control.
pub const MCR: u8 = 4;
/// Line status.
pub const LSR: u8 = 5;
/// Modem status.
pub const MSR: u8 = 6;
/// Scratch.
pub const SCR: u8 = 7;

pub const IER_RDI: u8 = 0x01;
pub const IER_THRI: u8 = 0x02;
pub const IER_RLSI: u8 = 0x04;
pub const IER_MSI: u8 = 0x08;
/// Received data (with the character timeout) and line status.
pub const IER_SETUP: u8 = IER_RDI | IER_RLSI;

/// Bit 0 set: no interrupt pending.
pub const IIR_NO_INT: u8 = 0x01;
/// Bits 1 to 3: the cause.
pub const IIR_ID: u8 = 0x0E;
pub const IIR_MSI: u8 = 0x00;
pub const IIR_THRI: u8 = 0x02;
pub const IIR_RDI: u8 = 0x04;
pub const IIR_RLSI: u8 = 0x06;
pub const IIR_CTI: u8 = 0x0C;
/// Bits 6 and 7: FIFOs enabled and working.
pub const IIR_FIFOS: u8 = 0xC0;

/// FIFOs on, both cleared, receive trigger at 8 bytes.
pub const FCR_SETUP: u8 = 0x87;

pub const LCR_8N1: u8 = 0x03;
pub const LCR_DLAB: u8 = 0x80;

pub const MCR_DTR: u8 = 0x01;
pub const MCR_RTS: u8 = 0x02;
pub const MCR_OUT2: u8 = 0x08;
/// DTR, RTS and OUT2.
pub const MCR_SETUP: u8 = MCR_DTR | MCR_RTS | MCR_OUT2;

pub const LSR_DR: u8 = 0x01;
pub const LSR_OE: u8 = 0x02;
pub const LSR_PE: u8 = 0x04;
pub const LSR_FE: u8 = 0x08;
pub const LSR_BI: u8 = 0x10;
pub const LSR_THRE: u8 = 0x20;
pub const LSR_TEMT: u8 = 0x40;
