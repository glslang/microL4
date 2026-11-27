//! A model of configuration space written from what the scan, sizing and
//! MSI-X rely on, not from this crate's code: a function is 4 KiB of
//! bytes whose BARs behave as hardware's do (a size that masks what is
//! written, read-only type bits, nothing at all for one not implemented),
//! and that records a violation for any BAR write while the command
//! register decodes that BAR's space; an absent function reads all ones.
//! A segment is a map of functions that fails a test reading a bus before
//! reaching it, or reaching one twice.

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::format;
use std::string::String;
use std::vec::Vec;

use crate::{Address, CONFIG_BYTES, Config, Segment, command};

/// A function's header as a test builds it, with its BARs' sizes.
#[derive(Clone, Debug)]
pub struct Header {
    pub bytes: [u8; 256],
    /// Each BAR's size, 0 for one not implemented; a 64-bit BAR's in its
    /// lower index.
    pub sizes: [u64; 6],
}

impl Header {
    /// A type 0 device with no class, BARs or capabilities.
    pub fn device(vendor: u16, device: u16) -> Header {
        Header {
            bytes: [0; 256],
            sizes: [0; 6],
        }
        .w16(0x00, vendor)
        .w16(0x02, device)
    }

    /// A PCI-to-PCI bridge to `secondary`.
    pub fn bridge(secondary: u8) -> Header {
        Header::device(0x8086, 0x244e)
            .class(0x06_04_00)
            .w8(0x0E, 1)
            .w8(0x18, 0)
            .w8(0x19, secondary)
            .w8(0x1A, secondary)
    }

    pub fn w8(mut self, at: usize, v: u8) -> Header {
        self.bytes[at] = v;
        self
    }

    pub fn w16(mut self, at: usize, v: u16) -> Header {
        self.bytes[at..at + 2].copy_from_slice(&v.to_le_bytes());
        self
    }

    pub fn w32(mut self, at: usize, v: u32) -> Header {
        self.bytes[at..at + 4].copy_from_slice(&v.to_le_bytes());
        self
    }

    pub fn class(self, class: u32) -> Header {
        let rev = self.bytes[0x08];
        self.w32(0x08, class << 8 | u32::from(rev))
    }

    pub fn multi(self) -> Header {
        let t = self.bytes[0x0E];
        self.w8(0x0E, t | 0x80)
    }

    pub fn command(self, c: u16) -> Header {
        self.w16(0x04, c)
    }

    pub fn subsystem(self, vendor: u16, id: u16) -> Header {
        self.w16(0x2C, vendor).w16(0x2E, id)
    }

    /// BAR `i` as the firmware programmed it, `value` with its type bits,
    /// of `size` bytes; a 64-bit BAR's upper dword goes in BAR `i + 1`.
    pub fn bar(mut self, i: usize, value: u64, size: u64) -> Header {
        self.sizes[i] = size;
        let low = value as u32;
        let wide = low & 1 == 0 && (low >> 1) & 3 == 2;
        let mut h = self.w32(0x10 + 4 * i, low);
        if wide && i < 5 {
            h = h.w32(0x14 + 4 * i, (value >> 32) as u32);
        }
        h
    }

    /// A capability list from `first`: status bit 4 and the pointer.
    pub fn caps(self, first: u8) -> Header {
        let s = u16::from_le_bytes([self.bytes[6], self.bytes[7]]);
        self.w16(0x06, s | 0x10).w8(0x34, first)
    }

    /// A capability header at `at`: its ID and next pointer.
    pub fn cap(self, at: u8, id: u8, next: u8) -> Header {
        self.w8(at.into(), id).w8(usize::from(at) + 1, next)
    }

    /// A `struct virtio_pci_cap` at `at` of `cap_len` 16.
    pub fn virtio(self, at: u8, next: u8, cfg_type: u8, bar: u8, offset: u32, len: u32) -> Header {
        let a = usize::from(at);
        self.cap(at, 0x09, next)
            .w8(a + 2, 16)
            .w8(a + 3, cfg_type)
            .w8(a + 4, bar)
            .w32(a + 8, offset)
            .w32(a + 12, len)
    }

    /// A `struct virtio_pci_notify_cap` at `at`.
    pub fn notify(self, at: u8, next: u8, bar: u8, offset: u32, len: u32, mult: u32) -> Header {
        let a = usize::from(at);
        self.virtio(at, next, 2, bar, offset, len)
            .w8(a + 2, 20)
            .w32(a + 16, mult)
    }

    /// An MSI-X capability at `at` with `vectors` entries.
    pub fn msix(self, at: u8, next: u8, vectors: u16, table: (u8, u32), pba: (u8, u32)) -> Header {
        let a = usize::from(at);
        self.cap(at, 0x11, next)
            .w16(a + 2, vectors - 1)
            .w32(a + 4, table.1 | u32::from(table.0))
            .w32(a + 8, pba.1 | u32::from(pba.0))
    }

    pub fn model(&self) -> Model {
        Model::new(self)
    }
}

/// What kind of register a BAR dword is, from its first value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Dword {
    Io { size: u64 },
    Memory32 { size: u64 },
    Low64 { size: u64 },
    High64 { size: u64 },
}

/// One function's configuration space.
#[derive(Debug)]
pub struct Model {
    bytes: RefCell<[u8; CONFIG_BYTES]>,
    bars: [Option<Dword>; 6],
    pub violations: RefCell<Vec<String>>,
}

impl Model {
    pub fn new(h: &Header) -> Model {
        let mut bytes = [0u8; CONFIG_BYTES];
        bytes[..256].copy_from_slice(&h.bytes);
        let layout = h.bytes[0x0E] & 0x7F;
        let count = match layout {
            0 => 6,
            1 => 2,
            _ => 0,
        };
        let mut bars = [None; 6];
        let mut i = 0;
        while i < count {
            let low = u32::from_le_bytes(h.bytes[0x10 + 4 * i..0x14 + 4 * i].try_into().unwrap());
            let size = h.sizes[i];
            if low & 1 != 0 {
                bars[i] = Some(Dword::Io { size });
            } else if (low >> 1) & 3 == 2 && i + 1 < count {
                bars[i] = Some(Dword::Low64 { size });
                bars[i + 1] = Some(Dword::High64 { size });
                i += 1;
            } else {
                bars[i] = Some(Dword::Memory32 { size });
            }
            i += 1;
        }
        let m = Model {
            bytes: RefCell::new(bytes),
            bars,
            violations: RefCell::new(Vec::new()),
        };
        // A BAR holds only what its size lets it: none of a BAR not
        // implemented, no address bits below its size.
        for i in 0..count {
            if let Some(d) = m.bars[i] {
                let at = 0x10 + 4 * i;
                let v = u32::from_le_bytes(h.bytes[at..at + 4].try_into().unwrap());
                let v = m.masked(d, v, v);
                m.bytes.borrow_mut()[at..at + 4].copy_from_slice(&v.to_le_bytes());
            }
        }
        m
    }

    /// What a BAR dword of kind `d` holding `old` keeps of a write of
    /// `v`.
    fn masked(&self, d: Dword, v: u32, old: u32) -> u32 {
        match d {
            Dword::Io { size: 0 }
            | Dword::Memory32 { size: 0 }
            | Dword::Low64 { size: 0 }
            | Dword::High64 { size: 0 } => 0,
            // A 32-bit BAR of 4 GiB or more keeps no address bits.
            Dword::Io { size } => ((u64::from(v) & !(size - 1)) as u32 & !3) | 1,
            Dword::Memory32 { size } => ((u64::from(v) & !(size - 1)) as u32 & !0xF) | (old & 0xF),
            Dword::Low64 { size } => (v & (!(size - 1)) as u32 & !0xF) | (old & 0xF),
            Dword::High64 { size } => v & ((!(size - 1)) >> 32) as u32,
        }
    }

    fn get(&self, at: u16, n: usize) -> u32 {
        let at = usize::from(at);
        assert!(
            at + n <= CONFIG_BYTES && at.is_multiple_of(n),
            "{n}-byte read at {at:#x}"
        );
        let b = self.bytes.borrow();
        let mut v = [0u8; 4];
        v[..n].copy_from_slice(&b[at..at + n]);
        u32::from_le_bytes(v)
    }

    fn bar_at(&self, at: u16) -> Option<(usize, Dword)> {
        let at = usize::from(at);
        let i = at.checked_sub(0x10)? / 4;
        (i < 6).then_some(())?;
        self.bars[i].map(|d| (i, d))
    }

    fn put(&self, at: u16, n: usize, v: u32) {
        let off = usize::from(at);
        assert!(
            off + n <= CONFIG_BYTES && off.is_multiple_of(n),
            "{n}-byte write at {off:#x}"
        );
        let mut v = v;
        if (0x10..0x28).contains(&off) {
            if let Some((i, d)) = self.bar_at(at - (at % 4)) {
                if n != 4 {
                    self.violation(format!("a {n}-byte write to BAR{i}"));
                    return;
                }
                let cmd = self.get(0x04, 2) as u16;
                let decodes = match d {
                    Dword::Io { .. } => cmd & command::IO != 0,
                    _ => cmd & command::MEMORY != 0,
                };
                if decodes {
                    self.violation(format!("BAR{i} written with decode on ({cmd:#x})"));
                }
                v = self.masked(d, v, self.get(at, 4));
            }
        }
        let mut b = self.bytes.borrow_mut();
        b[off..off + n].copy_from_slice(&v.to_le_bytes()[..n]);
    }

    fn violation(&self, what: String) {
        self.violations.borrow_mut().push(what);
    }

    /// The header's bytes now.
    pub fn header(&self) -> [u8; 256] {
        self.bytes.borrow()[..256].try_into().unwrap()
    }
}

impl Config for Model {
    fn read8(&self, offset: u16) -> u8 {
        self.get(offset, 1) as u8
    }
    fn read16(&self, offset: u16) -> u16 {
        self.get(offset, 2) as u16
    }
    fn read32(&self, offset: u16) -> u32 {
        self.get(offset, 4)
    }
    fn write8(&self, offset: u16, value: u8) {
        self.put(offset, 1, value.into())
    }
    fn write16(&self, offset: u16, value: u16) {
        self.put(offset, 2, value.into())
    }
    fn write32(&self, offset: u16, value: u32) {
        self.put(offset, 4, value)
    }
}

/// A function slot of a segment: a model, or nothing (all ones).
pub struct Slot<'a>(Option<&'a Model>);

impl Config for Slot<'_> {
    fn read8(&self, offset: u16) -> u8 {
        self.0.map_or(0xFF, |m| m.read8(offset))
    }
    fn read16(&self, offset: u16) -> u16 {
        self.0.map_or(0xFFFF, |m| m.read16(offset))
    }
    fn read32(&self, offset: u16) -> u32 {
        self.0.map_or(!0, |m| m.read32(offset))
    }
    fn write8(&self, offset: u16, value: u8) {
        if let Some(m) = self.0 {
            m.write8(offset, value)
        }
    }
    fn write16(&self, offset: u16, value: u16) {
        if let Some(m) = self.0 {
            m.write16(offset, value)
        }
    }
    fn write32(&self, offset: u16, value: u32) {
        if let Some(m) = self.0 {
            m.write32(offset, value)
        }
    }
}

/// A segment of functions.
#[derive(Debug, Default)]
pub struct Space {
    pub functions: BTreeMap<Address, Model>,
    /// The buses reached, in order.
    pub reached: Vec<u8>,
    /// A bus `reach` refuses.
    pub refuse: Option<u8>,
}

impl Space {
    pub fn new(functions: &[(Address, Header)]) -> Space {
        Space {
            functions: functions.iter().map(|(a, h)| (*a, h.model())).collect(),
            ..Space::default()
        }
    }
}

impl Segment for Space {
    type Function<'a> = Slot<'a>;
    type Error = &'static str;

    fn reach(&mut self, bus: u8) -> Result<(), &'static str> {
        if self.refuse == Some(bus) {
            return Err("refused");
        }
        assert!(!self.reached.contains(&bus), "bus {bus} reached twice");
        self.reached.push(bus);
        Ok(())
    }

    fn function(&self, at: Address) -> Slot<'_> {
        assert!(
            self.reached.contains(&at.bus),
            "{at} read before its bus was reached"
        );
        Slot(self.functions.get(&at))
    }
}

/// Plain registers: 4 KiB of RAM, for the MSI-X table's page, logging
/// every write.
#[derive(Debug)]
pub struct Ram {
    pub bytes: RefCell<[u8; CONFIG_BYTES]>,
    pub writes: RefCell<Vec<(u16, u32)>>,
}

impl Ram {
    pub fn new() -> Ram {
        Ram {
            bytes: RefCell::new([0; CONFIG_BYTES]),
            writes: RefCell::new(Vec::new()),
        }
    }

    fn get(&self, at: u16, n: usize) -> u32 {
        let at = usize::from(at);
        assert!(at + n <= CONFIG_BYTES && at.is_multiple_of(n));
        let mut v = [0u8; 4];
        v[..n].copy_from_slice(&self.bytes.borrow()[at..at + n]);
        u32::from_le_bytes(v)
    }

    fn put(&self, at: u16, n: usize, v: u32) {
        let off = usize::from(at);
        assert!(off + n <= CONFIG_BYTES && off.is_multiple_of(n));
        self.bytes.borrow_mut()[off..off + n].copy_from_slice(&v.to_le_bytes()[..n]);
        self.writes.borrow_mut().push((at, v));
    }
}

impl Config for Ram {
    fn read8(&self, offset: u16) -> u8 {
        self.get(offset, 1) as u8
    }
    fn read16(&self, offset: u16) -> u16 {
        self.get(offset, 2) as u16
    }
    fn read32(&self, offset: u16) -> u32 {
        self.get(offset, 4)
    }
    fn write8(&self, offset: u16, value: u8) {
        self.put(offset, 1, value.into())
    }
    fn write16(&self, offset: u16, value: u16) {
        self.put(offset, 2, value.into())
    }
    fn write32(&self, offset: u16, value: u32) {
        self.put(offset, 4, value)
    }
}
