//! MSI-X (`docs/design.md`, "MSI (M9) and the trust model" and "PCI on
//! QEMU", "Interrupt"), with the fields FreeBSD's `pcireg.h` names (the
//! PCI specification itself was not read): the capability's Message
//! Control at offset 2, Table Offset/BIR at 4 and PBA Offset/BIR at 8; the
//! table's 16-byte entries in the BAR the BIR names.

use core::fmt;

use crate::{Config, Function, HEADER_BYTES};

/// The MSI-X capability's ID.
pub const CAP_ID: u8 = 0x11;
/// Bytes of the capability from its offset.
const CAP_BYTES: usize = 12;
/// Message Control and its bits: 10:0 the table size minus 1, 14 Function
/// Mask, 15 MSI-X Enable.
const CONTROL: u16 = 2;
const TABLE_SIZE: u16 = 0x7FF;
pub const FUNCTION_MASK: u16 = 1 << 14;
pub const ENABLE: u16 = 1 << 15;
const TABLE: u16 = 4;
const PBA: u16 = 8;
/// A table entry: address low and high dwords, data, Vector Control (bit
/// 0 masks the entry).
pub const ENTRY_BYTES: u64 = 16;
const ADDRESS_LOW: u16 = 0;
const ADDRESS_HIGH: u16 = 4;
const DATA: u16 = 8;
const VECTOR_CONTROL: u16 = 12;
pub const VECTOR_MASKED: u32 = 1;

/// A BAR and an offset in it: the low 3 bits of a Table or PBA
/// Offset/BIR dword name the BAR (BIR 6 and 7 are reserved), the rest is
/// the offset.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    /// 0 to 7, as read; only 0 to 5 name a BAR.
    pub bar: u8,
    /// A multiple of 8.
    pub offset: u32,
}

impl Location {
    const fn decode(dword: u32) -> Location {
        Location {
            bar: (dword & 7) as u8,
            offset: dword & !7,
        }
    }
}

/// `BAR1+0x800`.
impl fmt::Display for Location {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "BAR{}+{:#x}", self.bar, self.offset)
    }
}

/// A function's MSI-X capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Msix {
    /// Its offset in configuration space.
    pub cap: u8,
    /// Message Control as read.
    pub control: u16,
    /// Table entries: 1 to 2,048.
    pub vectors: u16,
    pub table: Location,
    pub pba: Location,
}

/// The message an entry sends: `IRQControl_GetMSI`'s address (MR1) and
/// data (MR2).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    pub address: u64,
    pub data: u32,
}

impl Msix {
    /// The first MSI-X capability in `f`'s list whose 12 bytes lie in the
    /// header.
    pub fn find(f: &Function, cfg: &impl Config) -> Option<Msix> {
        f.capabilities
            .with_id(CAP_ID)
            .find(|&at| usize::from(at) + CAP_BYTES <= HEADER_BYTES)
            .map(|at| Msix::read(cfg, at))
    }

    /// The capability at `cap`, a multiple of 4 with its 12 bytes in the
    /// header.
    pub fn read(cfg: &impl Config, cap: u8) -> Msix {
        let at = u16::from(cap);
        let control = cfg.read16(at + CONTROL);
        Msix {
            cap,
            control,
            vectors: (control & TABLE_SIZE) + 1,
            table: Location::decode(cfg.read32(at + TABLE)),
            pba: Location::decode(cfg.read32(at + PBA)),
        }
    }

    /// The table's bytes: 16 a vector.
    pub const fn table_bytes(&self) -> u64 {
        ENTRY_BYTES * self.vectors as u64
    }

    /// The pending-bit array's bytes: 8 per 64 vectors.
    pub const fn pba_bytes(&self) -> u64 {
        8 * (self.vectors as u64).div_ceil(64)
    }

    /// Programs entry 0 to send `message`, as Linux and FreeBSD do: MSI-X
    /// Enable and Function Mask set, so the table is reachable while no
    /// entry can fire; entry 0's address, data and Vector Control with its
    /// mask bit clear; then Function Mask clear. `table` is the page that
    /// holds entry 0, at offset `entry` in it (the plan's
    /// [`Plan::entry0_in_page`](crate::Plan::entry0_in_page)). The other
    /// entries keep their reset state, masked.
    pub fn program(&self, cfg: &impl Config, table: &impl Config, entry: u16, message: Message) {
        let control = u16::from(self.cap) + CONTROL;
        let was = cfg.read16(control);
        cfg.write16(control, was | ENABLE | FUNCTION_MASK);
        table.write32(entry + ADDRESS_LOW, message.address as u32);
        table.write32(entry + ADDRESS_HIGH, (message.address >> 32) as u32);
        table.write32(entry + DATA, message.data);
        let vc = table.read32(entry + VECTOR_CONTROL);
        table.write32(entry + VECTOR_CONTROL, vc & !VECTOR_MASKED);
        cfg.write16(control, (was | ENABLE) & !FUNCTION_MASK);
    }

    /// Entry `entry`'s Vector Control word, read from `table`, the page
    /// that holds it at offset `entry`.
    pub fn vector_control(table: &impl Config, entry: u16) -> u32 {
        table.read32(entry + VECTOR_CONTROL)
    }
}
