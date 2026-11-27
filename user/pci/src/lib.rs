//! `pci`: PCI enumeration through ECAM, as the root task does it at setup
//! (`docs/design.md`, "PCI on QEMU"). No PCI manager runs: root scans,
//! configures the one function it drives, and unmaps configuration space
//! before it starts the driver.
//!
//! Everything here is generic over [`Config`], 8-, 16- and 32-bit reads
//! and writes of 4 KiB of registers (one function's configuration space,
//! or the page that holds its MSI-X table), and [`Segment`], the functions
//! of the buses an ECAM range decodes, so the host tests run it on models.
//! Root implements both over `libsys::mem::Mmio` windows on the device
//! frames it carves (`user/root/src/pci.rs`).
//!
//! - [`scan`] visits every function the range reaches, through bridges,
//!   each bus at most once, and reads each into a [`Function`]: its IDs,
//!   class, header, BARs as the firmware programmed them and its
//!   [`Capabilities`].
//! - [`size`] sizes a function's BARs with decode off ([`Bars`]).
//! - [`Msix`] reads the MSI-X capability and programs entry 0.
//! - [`Plan::virtio_net`] checks a virtio-net function's modern regions
//!   and MSI-X against its BARs and gives the pages root carves and maps.
//!
//! Nothing here trusts configuration space: every pointer is masked and
//! bounded, every walk ends, and every region is checked against its BAR
//! with no overflow.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod bar;
pub mod msix;
mod scan;
pub mod virtio;

#[cfg(test)]
mod tests;

use core::fmt;

pub use bar::{Bar, Bars, Space, size};
pub use msix::{Location, Message, Msix};
pub use scan::{
    Capabilities, Capability, Function, Range, ScanError, Scanned, Segment, WalkEnd, scan,
};
pub use virtio::{Kind, Page, Plan, Refusal, Region, What, is_virtio_net};

/// Bytes of one function's configuration space through ECAM.
pub const CONFIG_BYTES: usize = 4096;
/// The conventional configuration space, where the capability list lives.
pub const HEADER_BYTES: usize = 256;
/// A small frame: the unit root carves and maps.
pub const PAGE: u64 = 1 << 12;

/// Configuration-space registers (PCI Local Bus specification's type 0
/// and type 1 headers, as FreeBSD's `pcireg.h` names them; from memory).
pub mod reg {
    pub const VENDOR: u16 = 0x00;
    pub const DEVICE: u16 = 0x02;
    pub const COMMAND: u16 = 0x04;
    pub const STATUS: u16 = 0x06;
    /// Revision (byte 0) and class code (bytes 1 to 3).
    pub const CLASS: u16 = 0x08;
    pub const HEADER_TYPE: u16 = 0x0E;
    pub const BAR0: u16 = 0x10;
    /// Type 0 only.
    pub const SUBSYSTEM_VENDOR: u16 = 0x2C;
    pub const SUBSYSTEM: u16 = 0x2E;
    /// Types 0 and 1.
    pub const CAPABILITIES: u16 = 0x34;
    /// Type 1 only.
    pub const SECONDARY_BUS: u16 = 0x19;
    pub const SUBORDINATE_BUS: u16 = 0x1A;
}

/// Command register bits.
pub mod command {
    pub const IO: u16 = 1 << 0;
    pub const MEMORY: u16 = 1 << 1;
    pub const BUS_MASTER: u16 = 1 << 2;
    pub const INTX_DISABLE: u16 = 1 << 10;
}

/// Status register bit 4: the function has a capability list.
pub const STATUS_CAPABILITIES: u16 = 1 << 4;
/// Header type bit 7: a multi-function device.
pub const MULTI_FUNCTION: u8 = 1 << 7;
/// Header layouts (header type bits 6:0).
pub const LAYOUT_DEVICE: u8 = 0;
pub const LAYOUT_BRIDGE: u8 = 1;
/// A vendor ID that reads all ones: no function there.
pub const NO_VENDOR: u16 = 0xFFFF;

/// 4 KiB of registers: 8-, 16- and 32-bit reads and writes at offsets
/// below [`CONFIG_BYTES`], each aligned to its width; an implementation
/// may panic on any other. This crate only makes such accesses. The
/// accesses take `&self`, as `libsys::mem::Regs`'s do: a window is a
/// handle, and the device changes what it reaches.
pub trait Config {
    fn read8(&self, offset: u16) -> u8;
    fn read16(&self, offset: u16) -> u16;
    fn read32(&self, offset: u16) -> u32;
    fn write8(&self, offset: u16, value: u8);
    fn write16(&self, offset: u16, value: u16);
    fn write32(&self, offset: u16, value: u32);
}

impl<T: Config + ?Sized> Config for &T {
    fn read8(&self, offset: u16) -> u8 {
        (**self).read8(offset)
    }
    fn read16(&self, offset: u16) -> u16 {
        (**self).read16(offset)
    }
    fn read32(&self, offset: u16) -> u32 {
        (**self).read32(offset)
    }
    fn write8(&self, offset: u16, value: u8) {
        (**self).write8(offset, value)
    }
    fn write16(&self, offset: u16, value: u16) {
        (**self).write16(offset, value)
    }
    fn write32(&self, offset: u16, value: u32) {
        (**self).write32(offset, value)
    }
}

/// A function's place on its segment.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Address {
    pub bus: u8,
    /// 0 to 31.
    pub device: u8,
    /// 0 to 7.
    pub function: u8,
}

impl Address {
    /// `None` unless `device` < 32 and `function` < 8.
    pub const fn new(bus: u8, device: u8, function: u8) -> Option<Address> {
        if device < 32 && function < 8 {
            Some(Address {
                bus,
                device,
                function,
            })
        } else {
            None
        }
    }

    /// Where its 4 KiB start, from bus 0's configuration space:
    /// `bus << 20 | device << 15 | function << 12` (`docs/abi.md`,
    /// "BootInfo fields for interrupts and Hyper-V").
    pub const fn ecam_offset(self) -> u64 {
        (self.bus as u64) << 20
            | ((self.device & 31) as u64) << 15
            | ((self.function & 7) as u64) << 12
    }
}

impl fmt::Display for Address {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{:02x}:{:02x}.{:x}",
            self.bus, self.device, self.function
        )
    }
}

/// Memory decode on, I/O decode off and INTx disabled, with bus
/// mastering on if `bus_master` (a function that sends MSIs or does DMA
/// needs it), the command register's other bits kept; returns the
/// register as it was. With MSI-X the driver never takes INTx, which the
/// kernel routes nowhere anyway (`docs/design.md`, "MSI (M9) and the trust
/// model").
pub fn enable_memory(cfg: &impl Config, bus_master: bool) -> u16 {
    let was = cfg.read16(reg::COMMAND);
    let mut now = (was & !command::IO & !command::BUS_MASTER) | command::MEMORY;
    now |= command::INTX_DISABLE;
    if bus_master {
        now |= command::BUS_MASTER;
    }
    cfg.write16(reg::COMMAND, now);
    was
}

/// Writes `bytes` as `KiB`, `MiB` or `GiB` when it is a whole number of
/// them, else in bytes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Bytes(pub u64);

impl fmt::Display for Bytes {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let n = self.0;
        for (shift, unit) in [(30, "GiB"), (20, "MiB"), (10, "KiB")] {
            if n >= 1 << shift && n.trailing_zeros() >= shift {
                return write!(f, "{} {unit}", n >> shift);
            }
        }
        write!(f, "{n} bytes")
    }
}
