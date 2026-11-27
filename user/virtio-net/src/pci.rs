//! The virtio PCI transport (virtio 1.2, 4.1, read in the OASIS
//! specification's sources, `transport-pci.tex`, fetched 2026-11-27): the
//! IDs that name a network device, the vendor-specific capabilities that
//! locate the common configuration, notify, ISR and device configuration
//! structures in the function's BARs, and the registers of each.
//!
//! Root's PCI setup walks the capability list (crate `pci`) and hands each
//! vendor-specific capability's bytes to [`Cap::parse`], then [`Caps`]
//! keeps the first of each type that names a memory BAR, as the
//! specification asks (4.1.4: the driver SHOULD use the first instance of
//! each type it can support, and MUST ignore a reserved `cfg_type` or
//! `bar`). The driver itself never reads configuration space: it sees
//! only the three regions' pages ([`crate::Regions`]).

use core::fmt;

/// The vendor ID of every virtio device.
pub const VENDOR: u16 = 0x1AF4;
/// The network device's ID: `0x1040` plus virtio device ID 1.
pub const DEVICE: u16 = 0x1041;
/// The network device's transitional ID, which QEMU gives a
/// `virtio-net-pci` on q35's root bus (from memory).
pub const TRANSITIONAL_DEVICE: u16 = 0x1000;
/// A transitional device's subsystem device ID is its virtio device ID:
/// 1, network.
pub const SUBSYSTEM_NETWORK: u16 = 1;

/// Whether a function with these IDs is a virtio network device: device
/// `0x1041`, or the transitional `0x1000` with subsystem device 1 (4.1.2;
/// any revision ID).
pub const fn is_network(vendor: u16, device: u16, subsystem_device: u16) -> bool {
    vendor == VENDOR
        && (device == DEVICE
            || (device == TRANSITIONAL_DEVICE && subsystem_device == SUBSYSTEM_NETWORK))
}

/// The PCI capability ID of a vendor-specific capability.
pub const CAP_VENDOR: u8 = 0x09;

/// The structure a capability locates (`cfg_type`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CfgType {
    /// `VIRTIO_PCI_CAP_COMMON_CFG`: [`common`].
    Common = 1,
    /// `VIRTIO_PCI_CAP_NOTIFY_CFG`: where queue notifications are written.
    Notify = 2,
    /// `VIRTIO_PCI_CAP_ISR_CFG`: [`isr`], unused with MSI-X.
    Isr = 3,
    /// `VIRTIO_PCI_CAP_DEVICE_CFG`: [`net`].
    Device = 4,
}

impl CfgType {
    /// The type of a `cfg_type` byte; `None` for the others (PCI
    /// configuration access 5, shared memory 8, vendor data 9, reserved),
    /// which the driver ignores.
    pub const fn from_byte(b: u8) -> Option<CfgType> {
        match b {
            1 => Some(CfgType::Common),
            2 => Some(CfgType::Notify),
            3 => Some(CfgType::Isr),
            4 => Some(CfgType::Device),
            _ => None,
        }
    }

    /// Its name in root's lines: `pci: virtio-net: no notify capability`.
    pub const fn name(self) -> &'static str {
        match self {
            CfgType::Common => "common",
            CfgType::Notify => "notify",
            CfgType::Isr => "ISR",
            CfgType::Device => "device",
        }
    }
}

/// Offsets in `struct virtio_pci_cap` and `struct virtio_pci_notify_cap`.
pub mod cap {
    pub const VNDR: usize = 0;
    pub const NEXT: usize = 1;
    pub const LEN: usize = 2;
    pub const CFG_TYPE: usize = 3;
    pub const BAR: usize = 4;
    pub const ID: usize = 5;
    /// `offset` (le32): where the structure starts in its BAR.
    pub const OFFSET: usize = 8;
    /// `length` (le32): its length.
    pub const LENGTH: usize = 12;
    /// `notify_off_multiplier` (le32), the notify capability's alone.
    pub const NOTIFY_OFF_MULTIPLIER: usize = 16;
    /// The least `cap_len`: 16, and 20 for the notify capability.
    pub const SIZE: usize = 16;
    pub const NOTIFY_SIZE: usize = 20;
    /// The highest BAR number; higher ones are reserved.
    pub const MAX_BAR: u8 = 5;
}

/// A virtio structure capability the driver can use.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cap {
    pub cfg_type: CfgType,
    /// The BAR, 0 to 5.
    pub bar: u8,
    /// Where the structure starts in the BAR.
    pub offset: u32,
    /// Its length in bytes.
    pub length: u32,
    /// The notify capability's `notify_off_multiplier`; 0 for the others.
    pub multiplier: u32,
}

impl Cap {
    /// The capability whose bytes from `cap_vndr` on are `bytes`: as many
    /// as configuration space holds from there, at least its `cap_len`.
    /// `None` for one the driver ignores: not vendor-specific, a type it
    /// does not use or reserved, a reserved `bar`, or a `cap_len` under
    /// 16 (20 for notify) or beyond `bytes`. A longer `cap_len` is
    /// accepted, as the specification asks.
    pub fn parse(bytes: &[u8]) -> Option<Cap> {
        let byte = |i: usize| bytes.get(i).copied();
        let dword = |i: usize| -> Option<u32> {
            Some(u32::from_le_bytes(bytes.get(i..i + 4)?.try_into().ok()?))
        };
        if byte(cap::VNDR)? != CAP_VENDOR {
            return None;
        }
        let len = usize::from(byte(cap::LEN)?);
        let cfg_type = CfgType::from_byte(byte(cap::CFG_TYPE)?)?;
        let need = match cfg_type {
            CfgType::Notify => cap::NOTIFY_SIZE,
            _ => cap::SIZE,
        };
        if len < need || len > bytes.len() {
            return None;
        }
        let bar = byte(cap::BAR)?;
        if bar > cap::MAX_BAR {
            return None;
        }
        Some(Cap {
            cfg_type,
            bar,
            offset: dword(cap::OFFSET)?,
            length: dword(cap::LENGTH)?,
            multiplier: match cfg_type {
                CfgType::Notify => dword(cap::NOTIFY_OFF_MULTIPLIER)?,
                _ => 0,
            },
        })
    }
}

/// The capabilities found so far: the first of each type that names a
/// memory BAR.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Caps {
    pub common: Option<Cap>,
    pub notify: Option<Cap>,
    pub isr: Option<Cap>,
    pub device: Option<Cap>,
}

impl Caps {
    /// Considers `cap`, in capability-list order: kept if it is the first
    /// of its type whose BAR decodes memory (`bar_is_memory`, from the BAR
    /// as the firmware programmed it). An I/O BAR's capability is passed
    /// over, since the driver maps only memory.
    pub fn consider(&mut self, cap: Cap, bar_is_memory: bool) {
        if !bar_is_memory {
            return;
        }
        let slot = match cap.cfg_type {
            CfgType::Common => &mut self.common,
            CfgType::Notify => &mut self.notify,
            CfgType::Isr => &mut self.isr,
            CfgType::Device => &mut self.device,
        };
        if slot.is_none() {
            *slot = Some(cap);
        }
    }

    /// The three the driver uses, common, notify and device; the first
    /// type missing otherwise.
    pub fn regions(&self) -> Result<[Cap; 3], Missing> {
        match (self.common, self.notify, self.device) {
            (Some(c), Some(n), Some(d)) => Ok([c, n, d]),
            (None, _, _) => Err(Missing(CfgType::Common)),
            (_, None, _) => Err(Missing(CfgType::Notify)),
            (_, _, None) => Err(Missing(CfgType::Device)),
        }
    }
}

/// A structure no usable capability locates.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Missing(pub CfgType);

/// `no common capability`, after root's `pci: virtio-net: `.
impl fmt::Display for Missing {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "no {} capability", self.0.name())
    }
}

/// The common configuration structure, `struct virtio_pci_common_cfg`
/// (4.1.4.3): each register's offset. A 64-bit register is written as two
/// 32-bit halves, low first; every access has its register's width.
pub mod common {
    /// le32: which 32 feature bits `DEVICE_FEATURE` shows.
    pub const DEVICE_FEATURE_SELECT: usize = 0x00;
    /// le32, read-only: the device's features, 32 at a time.
    pub const DEVICE_FEATURE: usize = 0x04;
    /// le32: which 32 bits `DRIVER_FEATURE` takes.
    pub const DRIVER_FEATURE_SELECT: usize = 0x08;
    /// le32: the features the driver accepts, 32 at a time.
    pub const DRIVER_FEATURE: usize = 0x0C;
    /// le16: the configuration-change interrupt's MSI-X vector.
    pub const CONFIG_MSIX_VECTOR: usize = 0x10;
    /// le16, read-only: the queues the device has.
    pub const NUM_QUEUES: usize = 0x12;
    /// u8: the device status ([`super::status`]); 0 resets.
    pub const DEVICE_STATUS: usize = 0x14;
    /// u8, read-only: changes whenever the device configuration may have.
    pub const CONFIG_GENERATION: usize = 0x15;
    /// le16: which queue the registers below are about.
    pub const QUEUE_SELECT: usize = 0x16;
    /// le16: its size; the device's maximum until written, 0 for none.
    pub const QUEUE_SIZE: usize = 0x18;
    /// le16: its MSI-X vector.
    pub const QUEUE_MSIX_VECTOR: usize = 0x1A;
    /// le16: 1 enables it; the driver never writes 0.
    pub const QUEUE_ENABLE: usize = 0x1C;
    /// le16, read-only: its notify offset, in multiplier units.
    pub const QUEUE_NOTIFY_OFF: usize = 0x1E;
    /// le64: the physical address of its descriptor table.
    pub const QUEUE_DESC: usize = 0x20;
    /// le64: of its available ring (the driver area).
    pub const QUEUE_DRIVER: usize = 0x28;
    /// le64: of its used ring (the device area).
    pub const QUEUE_DEVICE: usize = 0x30;
    /// The bytes up to `queue_device`'s end, all the driver uses.
    pub const SIZE: usize = 0x38;
}

/// The device status bits (2.1).
pub mod status {
    pub const ACKNOWLEDGE: u8 = 1;
    pub const DRIVER: u8 = 2;
    pub const DRIVER_OK: u8 = 4;
    pub const FEATURES_OK: u8 = 8;
    pub const DEVICE_NEEDS_RESET: u8 = 64;
    pub const FAILED: u8 = 128;
}

/// The ISR status bits (4.1.4.5), unused with MSI-X.
pub mod isr {
    pub const QUEUE: u8 = 1;
    pub const CONFIG: u8 = 2;
}

/// The network device's configuration, `struct virtio_net_config`
/// (5.1.4): the fields the driver reads.
pub mod net {
    /// `mac` (6 bytes): valid with `VIRTIO_NET_F_MAC`.
    pub const MAC: usize = 0;
    /// `status` (le16): present with `VIRTIO_NET_F_STATUS`.
    pub const STATUS: usize = 6;
    /// The bytes the driver reads.
    pub const SIZE: usize = 8;
    /// `VIRTIO_NET_S_LINK_UP`, in `status`.
    pub const LINK_UP: u16 = 1;
}

/// An MSI-X vector register's value for none (4.1.5.1.2).
pub const NO_VECTOR: u16 = 0xFFFF;
