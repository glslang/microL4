//! BARs and their sizing (`docs/design.md`, "PCI on QEMU", the checks'
//! table): with the command register's memory and I/O decode off, each
//! BAR is written all ones, its mask read back and its value restored, as
//! firmware does; a 64-bit BAR's two halves together. The decode bits come
//! back as they were.

use core::fmt;

use crate::{Bytes, Config, Function, command, reg};

/// What a BAR decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Space {
    Io,
    Memory32,
    /// A 64-bit memory BAR, which takes this BAR and the next.
    Memory64,
}

/// A sized BAR: implemented, of a type this crate knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bar {
    /// 0 to 5; a 64-bit BAR's lower half.
    pub index: u8,
    pub space: Space,
    pub prefetchable: bool,
    /// The address the firmware programmed: a bus (here physical)
    /// address, or an I/O port.
    pub base: u64,
    /// A power of two, at least 16 bytes for memory and 4 for I/O.
    pub size: u64,
}

impl Bar {
    pub const fn is_memory(&self) -> bool {
        !matches!(self.space, Space::Io)
    }

    /// One past its last byte, if that does not overflow.
    pub const fn end(&self) -> Option<u64> {
        self.base.checked_add(self.size)
    }
}

/// `BAR4 memory64 prefetchable 0x800000000, 16 KiB`.
impl fmt::Display for Bar {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let space = match self.space {
            Space::Io => "I/O",
            Space::Memory32 => "memory32",
            Space::Memory64 => "memory64",
        };
        let pf = if self.prefetchable {
            " prefetchable"
        } else {
            ""
        };
        write!(
            f,
            "BAR{} {space}{pf} {:#x}, {}",
            self.index,
            self.base,
            Bytes(self.size)
        )
    }
}

/// A function's sized BARs, by index: `None` for a BAR not implemented
/// (it reads back 0), the upper half of a 64-bit BAR, a 64-bit BAR in the
/// last slot, or a memory BAR of a reserved type.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Bars([Option<Bar>; 6]);

impl Bars {
    pub const fn new(bars: [Option<Bar>; 6]) -> Bars {
        Bars(bars)
    }

    /// BAR `index`, if it is one.
    pub fn get(&self, index: u8) -> Option<Bar> {
        self.0.get(usize::from(index)).copied().flatten()
    }

    /// BAR `index`, if it is a memory BAR.
    pub fn memory(&self, index: u8) -> Option<Bar> {
        self.get(index).filter(Bar::is_memory)
    }

    pub fn iter(&self) -> impl Iterator<Item = Bar> + '_ {
        self.0.iter().flatten().copied()
    }
}

/// The type bits of a memory BAR's low dword (bits 2:1).
const TYPE_32: u32 = 0b00 << 1;
const TYPE_64: u32 = 0b10 << 1;
const TYPE_MASK: u32 = 0b11 << 1;
const PREFETCHABLE: u32 = 1 << 3;
const IO: u32 = 1;

/// Sizes `f`'s BARs: the command register's memory and I/O decode go off
/// first and come back last, so no BAR decodes while it holds all ones;
/// every BAR gets back the value it had.
pub fn size(cfg: &impl Config, f: &Function) -> Bars {
    let count = f.bar_count();
    let mut bars = [None; 6];
    if count == 0 {
        return Bars(bars);
    }
    let was = cfg.read16(reg::COMMAND);
    cfg.write16(reg::COMMAND, was & !(command::IO | command::MEMORY));
    let mut i = 0;
    while i < count {
        let at = reg::BAR0 + 4 * i as u16;
        let low = cfg.read32(at);
        let index = i as u8;
        if low & IO != 0 {
            let mask = probe(cfg, at) & !0x3;
            bars[i] = sized(index, Space::Io, false, u64::from(low & !0x3), mask.into());
            i += 1;
            continue;
        }
        let prefetchable = low & PREFETCHABLE != 0;
        match low & TYPE_MASK {
            TYPE_32 => {
                let mask = probe(cfg, at) & !0xF;
                let base = u64::from(low & !0xF);
                bars[i] = sized(index, Space::Memory32, prefetchable, base, mask.into());
                i += 1;
            }
            TYPE_64 if i + 1 < count => {
                let high = cfg.read32(at + 4);
                cfg.write32(at, !0);
                cfg.write32(at + 4, !0);
                let mask = (u64::from(cfg.read32(at + 4)) << 32 | u64::from(cfg.read32(at))) & !0xF;
                cfg.write32(at, low);
                cfg.write32(at + 4, high);
                let base = u64::from(high) << 32 | u64::from(low & !0xF);
                bars[i] = sized(index, Space::Memory64, prefetchable, base, mask);
                i += 2;
            }
            // A 64-bit BAR with no upper half, or a reserved type.
            _ => i += 1,
        }
    }
    cfg.write16(reg::COMMAND, was);
    Bars(bars)
}

/// Writes all ones to the 32-bit BAR at `at`, reads the mask back and
/// restores its value.
fn probe(cfg: &impl Config, at: u16) -> u32 {
    let value = cfg.read32(at);
    cfg.write32(at, !0);
    let mask = cfg.read32(at);
    cfg.write32(at, value);
    mask
}

/// The BAR whose address bits read back as `mask`: its size is the lowest
/// bit set; none set means not implemented.
fn sized(index: u8, space: Space, prefetchable: bool, base: u64, mask: u64) -> Option<Bar> {
    (mask != 0).then(|| Bar {
        index,
        space,
        prefetchable,
        base,
        size: 1 << mask.trailing_zeros(),
    })
}
