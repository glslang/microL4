//! BootInfo: what the kernel tells the root task at boot (`docs/abi.md`,
//! "Boot and the root task" and "BootInfo fields for interrupts and
//! Hyper-V"; ADR 0007).
//!
//! One 8 KiB `#[repr(C)]` struct, shared by the kernel and `libsys`, with a
//! compile-time assert for every field offset and every struct size. Every
//! field is a plain integer or an array of them, so the all-zero bytes are a
//! valid value of every type here: the kernel builds BootInfo in place in
//! frames it has zeroed, and [`BootInfo::ZERO`] is that value.
//! `l4core::boot` computes what goes in it.

use crate::acpi;
use crate::handoff::{CMDLINE_MAX, Framebuffer};
use crate::window;

/// `"uL4BINFO"` read as a little-endian `u64`.
pub const BOOTINFO_MAGIC: u64 = u64::from_le_bytes(*b"uL4BINFO");
/// Bumped on every incompatible change to the structures in this module.
pub const BOOTINFO_VERSION: u32 = 1;
/// `size_of::<BootInfo>()`: two 4 KiB frames.
pub const BOOTINFO_SIZE: usize = 8192;
/// The frames BootInfo occupies, physically and virtually contiguous.
pub const BOOTINFO_FRAMES: u64 = 2;
/// Untyped descriptors BootInfo holds; boot panics rather than need more.
pub const MAX_UNTYPED: usize = 448;

/// The root CNode has `2^12` slots, 128 KiB.
pub const ROOT_CNODE_RADIX: u32 = 12;
/// Slots in the root CNode.
pub const ROOT_CNODE_SLOTS: u64 = 1 << ROOT_CNODE_RADIX;
/// The root CNode capability's guard size: with guard 0, CPtr `n` names
/// slot `n` with all 64 bits resolved.
pub const ROOT_CNODE_GUARD_SIZE: u32 = 64 - ROOT_CNODE_RADIX;

/// Initial slot 0: null.
pub const CAP_NULL: u64 = 0;
/// Initial slot 1: the root task's TCB (from M5).
pub const CAP_INIT_TCB: u64 = 1;
/// Initial slot 2: the root CNode itself.
pub const CAP_INIT_CNODE: u64 = 2;
/// Initial slot 3: the root task's PML4 (from M5).
pub const CAP_INIT_VSPACE: u64 = 3;
/// Initial slot 4: IRQControl.
pub const CAP_IRQ_CONTROL: u64 = 4;
/// Initial slot 7: IOPortControl.
pub const CAP_IO_PORT_CONTROL: u64 = 7;
/// Initial slot 9: BootInfo's first frame.
pub const CAP_BOOTINFO_FRAME: u64 = 9;
/// Initial slot 10: the root task's IPC buffer frame.
pub const CAP_INIT_IPC_BUFFER: u64 = 10;
/// Initial slot 12: the unrestricted Hypervisor capability (Hyper-V, M9).
pub const CAP_HYPERVISOR: u64 = 12;
/// Initial slot 13: the SynIC message frame; null whenever slot 12 is.
pub const CAP_SYNIC_MESSAGE_FRAME: u64 = 13;
/// Initial slot 14: the SynIC event-flag frame; null whenever slot 12 is.
pub const CAP_SYNIC_EVENT_FRAME: u64 = 14;
/// Slots 0 to 15 are fixed; the slot regions start here.
pub const NUM_INITIAL_SLOTS: u64 = 16;

/// `hypervisor_vendor`: no hypervisor.
pub const HYPERVISOR_NONE: u32 = 0;
/// `hypervisor_vendor`: QEMU's TCG emulator.
pub const HYPERVISOR_QEMU_TCG: u32 = 1;
/// `hypervisor_vendor`: QEMU on KVM.
pub const HYPERVISOR_QEMU_KVM: u32 = 2;
/// `hypervisor_vendor`: Hyper-V.
pub const HYPERVISOR_HYPERV: u32 = 3;
/// `hypervisor_vendor`: another hypervisor.
pub const HYPERVISOR_OTHER: u32 = 4;

/// Entries in [`InterruptInfo::ecam`].
pub const MAX_ECAM: usize = 4;
/// Entries in [`InterruptInfo::ioapics`].
pub const MAX_IOAPICS: usize = 4;
/// Entries in [`InterruptInfo::isa_routes`], one per ISA IRQ.
pub const ISA_IRQS: usize = 16;

/// Slots `start` to `end - 1` of the root CNode; empty when
/// `start == end`. seL4's `seL4_SlotRegion`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SlotRegion {
    pub start: u64,
    pub end: u64,
}

impl SlotRegion {
    /// Slots in the region.
    pub const fn len(&self) -> u64 {
        self.end.saturating_sub(self.start)
    }

    pub const fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Whether `slot` is in the region.
    pub const fn contains(&self, slot: u64) -> bool {
        self.start <= slot && slot < self.end
    }
}

/// One untyped capability, seL4's `seL4_UntypedDesc`.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UntypedDesc {
    /// Physical base, aligned to the size.
    pub paddr: u64,
    /// The size is `2^size_bits` bytes, at least 12.
    pub size_bits: u8,
    /// 1 for device untyped, 0 for RAM.
    pub is_device: u8,
    pub padding: [u8; 6],
}

impl UntypedDesc {
    pub const fn new(paddr: u64, size_bits: u32, device: bool) -> UntypedDesc {
        UntypedDesc {
            paddr,
            size_bits: size_bits as u8,
            is_device: device as u8,
            padding: [0; 6],
        }
    }

    /// Bytes covered.
    pub const fn size(&self) -> u64 {
        1u64 << (self.size_bits & 63)
    }

    /// One past the last byte, saturating.
    pub const fn end(&self) -> u64 {
        self.paddr.saturating_add(self.size())
    }

    pub const fn device(&self) -> bool {
        self.is_device != 0
    }
}

/// A PCI ECAM range from the MCFG.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Ecam {
    /// Physical address of bus 0's configuration space in this segment, as
    /// in the MCFG, even when `start_bus` > 0.
    pub base: u64,
    /// PCI segment group.
    pub segment: u16,
    /// First bus decoded.
    pub start_bus: u8,
    /// Last bus decoded.
    pub end_bus: u8,
    pub reserved: u32,
}

/// An I/O APIC and the GSI range `IRQControl_GetIOAPIC` accepts for it.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IoApicInfo {
    /// First GSI it serves.
    pub gsi_base: u32,
    /// Number of pins, the version register's MRE + 1.
    pub pins: u16,
    /// I/O APIC ID from the MADT.
    pub id: u8,
    pub reserved: u8,
}

/// Where one ISA IRQ goes: what `IRQControl_GetISA` would program.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct IsaRoute {
    /// The GSI the IRQ routes to.
    pub gsi: u32,
    /// Bit 0 level-triggered, bit 1 active low, as `GetISA`'s MR2.
    pub flags: u8,
    /// 1 if the IRQ has a route; 0 if its GSI is another IRQ's override
    /// target or no I/O APIC serves it.
    pub routed: u8,
    pub reserved: u16,
}

/// The ACPI facts user space needs, 256 bytes at BootInfo offset 512.
/// Unused entries and reserved bytes are 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct InterruptInfo {
    /// Entries used in `ecam`, 0 to 4.
    pub ecam_count: u32,
    /// Entries used in `ioapics`, 0 to 4.
    pub ioapic_count: u32,
    /// PCI ECAM ranges from the MCFG.
    pub ecam: [Ecam; MAX_ECAM],
    /// The I/O APICs, in MADT order.
    pub ioapics: [IoApicInfo; MAX_IOAPICS],
    /// Indexed by ISA IRQ.
    pub isa_routes: [IsaRoute; ISA_IRQS],
    pub reserved: [u8; 24],
}

impl InterruptInfo {
    /// The block for a parsed `platform`, given each I/O APIC's pin count
    /// in MADT order, as the kernel read it from the version register (a
    /// missing count reads as 0 pins). ISA IRQ `n` is routed if
    /// [`acpi::Platform::isa_route`] gives it a route and an I/O APIC
    /// serves that GSI; its `gsi` and `flags` are filled whenever it has a
    /// route, and left 0 when its GSI is another IRQ's override target.
    pub fn from_platform(platform: &acpi::Platform, pins: &[u16]) -> InterruptInfo {
        let mut info = InterruptInfo::default();
        for (slot, e) in info.ecam.iter_mut().zip(platform.ecam.iter()) {
            *slot = Ecam {
                base: e.base,
                segment: e.segment,
                start_bus: e.start_bus,
                end_bus: e.end_bus,
                reserved: 0,
            };
            info.ecam_count += 1;
        }
        for (i, (slot, io)) in info
            .ioapics
            .iter_mut()
            .zip(platform.ioapics.iter())
            .enumerate()
        {
            *slot = IoApicInfo {
                gsi_base: io.gsi_base,
                pins: pins.get(i).copied().unwrap_or(0),
                id: io.id,
                reserved: 0,
            };
            info.ioapic_count += 1;
        }
        let pins = &pins[..pins.len().min(info.ioapic_count as usize)];
        for (irq, slot) in info.isa_routes.iter_mut().enumerate() {
            if let Some(route) = platform.isa_route(irq as u8) {
                *slot = IsaRoute {
                    gsi: route.gsi,
                    flags: route.flags(),
                    routed: u8::from(platform.ioapic_for_gsi(route.gsi, pins).is_some()),
                    reserved: 0,
                };
            }
        }
        info
    }
}

/// BootInfo, mapped RW and NX at the address in the root task's `rdi`.
/// Every address is virtual unless the field says physical.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BootInfo {
    /// [`BOOTINFO_MAGIC`].
    pub magic: u64,
    /// [`BOOTINFO_VERSION`].
    pub version: u32,
    /// [`BOOTINFO_SIZE`].
    pub size: u32,
    /// The root task's IPC buffer.
    pub ipc_buffer: u64,
    /// [`ROOT_CNODE_RADIX`].
    pub root_cnode_bits: u64,
    /// Null slots, free for the root task, to the root CNode's last slot.
    pub empty: SlotRegion,
    /// One Frame per image page a `PT_LOAD` segment covers.
    pub user_image_frames: SlotRegion,
    /// The root VSpace's PDPTs, PDs and PTs.
    pub user_image_paging: SlotRegion,
    /// BootInfo frames after the first.
    pub extra_bootinfo_frames: SlotRegion,
    /// Every untyped.
    pub untyped: SlotRegion,
    /// The leading part of `untyped` that covers the framebuffer exactly,
    /// page-rounded; empty if there is none, or if any 2 MiB page it touches
    /// is write-back in the direct map.
    pub framebuffer_untyped: SlotRegion,
    /// First byte of the first image page.
    pub user_image_start: u64,
    /// One past the last image page.
    pub user_image_end: u64,
    /// The handoff's framebuffer, physical `base`; all zero if there is
    /// none.
    pub framebuffer: Framebuffer,
    /// Physical address of the ACPI RSDP, or 0; for information only.
    pub rsdp: u64,
    /// TSC ticks per second.
    pub tsc_hz: u64,
    /// One of the `HYPERVISOR_*` numbers.
    pub hypervisor_vendor: u32,
    /// The CPU's physical address width; no untyped reaches
    /// `2^phys_addr_bits`.
    pub phys_addr_bits: u32,
    /// Bytes used in `cmdline`, at most 256.
    pub cmdline_len: u64,
    /// The handoff's command line, unchanged.
    pub cmdline: [u8; CMDLINE_MAX],
    pub reserved0: [u8; 48],
    /// The ACPI facts user space needs.
    pub interrupts: InterruptInfo,
    pub reserved1: [u8; 256],
    /// `untyped_list[i]` describes slot `untyped.start + i`; entries from
    /// `untyped.len()` on are 0.
    pub untyped_list: [UntypedDesc; MAX_UNTYPED],
}

const ZERO_SLOTS: SlotRegion = SlotRegion { start: 0, end: 0 };
const ZERO_ECAM: Ecam = Ecam {
    base: 0,
    segment: 0,
    start_bus: 0,
    end_bus: 0,
    reserved: 0,
};
const ZERO_IOAPIC: IoApicInfo = IoApicInfo {
    gsi_base: 0,
    pins: 0,
    id: 0,
    reserved: 0,
};
const ZERO_ROUTE: IsaRoute = IsaRoute {
    gsi: 0,
    flags: 0,
    routed: 0,
    reserved: 0,
};

impl InterruptInfo {
    /// Every byte zero.
    pub const ZERO: InterruptInfo = InterruptInfo {
        ecam_count: 0,
        ioapic_count: 0,
        ecam: [ZERO_ECAM; MAX_ECAM],
        ioapics: [ZERO_IOAPIC; MAX_IOAPICS],
        isa_routes: [ZERO_ROUTE; ISA_IRQS],
        reserved: [0; 24],
    };
}

impl BootInfo {
    /// Every byte zero: what the kernel finds in the frames it zeroed.
    pub const ZERO: BootInfo = BootInfo {
        magic: 0,
        version: 0,
        size: 0,
        ipc_buffer: 0,
        root_cnode_bits: 0,
        empty: ZERO_SLOTS,
        user_image_frames: ZERO_SLOTS,
        user_image_paging: ZERO_SLOTS,
        extra_bootinfo_frames: ZERO_SLOTS,
        untyped: ZERO_SLOTS,
        framebuffer_untyped: ZERO_SLOTS,
        user_image_start: 0,
        user_image_end: 0,
        framebuffer: Framebuffer {
            base: 0,
            size: 0,
            width: 0,
            height: 0,
            stride: 0,
            format: crate::handoff::PixelFormat::NONE,
        },
        rsdp: 0,
        tsc_hz: 0,
        hypervisor_vendor: 0,
        phys_addr_bits: 0,
        cmdline_len: 0,
        cmdline: [0; CMDLINE_MAX],
        reserved0: [0; 48],
        interrupts: InterruptInfo::ZERO,
        reserved1: [0; 256],
        untyped_list: [UntypedDesc::new(0, 0, false); MAX_UNTYPED],
    };

    /// The command line, or `""` if it is not valid UTF-8.
    pub fn cmdline(&self) -> &str {
        let len = (self.cmdline_len as usize).min(CMDLINE_MAX);
        core::str::from_utf8(&self.cmdline[..len]).unwrap_or("")
    }

    /// The descriptors in use: `untyped_list[..untyped.len()]`, cut at
    /// [`MAX_UNTYPED`].
    pub fn untyped(&self) -> &[UntypedDesc] {
        let n = (self.untyped.len() as usize).min(MAX_UNTYPED);
        &self.untyped_list[..n]
    }
}

impl Default for BootInfo {
    fn default() -> Self {
        Self::ZERO
    }
}

// The kernel and `libsys` are built for different targets; each build checks
// the layout docs/abi.md specifies.
const _: () = {
    use core::mem::{align_of, offset_of, size_of};
    assert!(offset_of!(BootInfo, magic) == 0);
    assert!(offset_of!(BootInfo, version) == 8);
    assert!(offset_of!(BootInfo, size) == 12);
    assert!(offset_of!(BootInfo, ipc_buffer) == 16);
    assert!(offset_of!(BootInfo, root_cnode_bits) == 24);
    assert!(offset_of!(BootInfo, empty) == 32);
    assert!(offset_of!(BootInfo, user_image_frames) == 48);
    assert!(offset_of!(BootInfo, user_image_paging) == 64);
    assert!(offset_of!(BootInfo, extra_bootinfo_frames) == 80);
    assert!(offset_of!(BootInfo, untyped) == 96);
    assert!(offset_of!(BootInfo, framebuffer_untyped) == 112);
    assert!(offset_of!(BootInfo, user_image_start) == 128);
    assert!(offset_of!(BootInfo, user_image_end) == 136);
    assert!(offset_of!(BootInfo, framebuffer) == 144);
    assert!(offset_of!(BootInfo, rsdp) == 176);
    assert!(offset_of!(BootInfo, tsc_hz) == 184);
    assert!(offset_of!(BootInfo, hypervisor_vendor) == 192);
    assert!(offset_of!(BootInfo, phys_addr_bits) == 196);
    assert!(offset_of!(BootInfo, cmdline_len) == 200);
    assert!(offset_of!(BootInfo, cmdline) == 208);
    assert!(offset_of!(BootInfo, reserved0) == 464);
    assert!(offset_of!(BootInfo, interrupts) == 512);
    assert!(offset_of!(BootInfo, reserved1) == 768);
    assert!(offset_of!(BootInfo, untyped_list) == 1024);
    assert!(size_of::<BootInfo>() == BOOTINFO_SIZE);
    assert!(BOOTINFO_SIZE as u64 == BOOTINFO_FRAMES * 4096);
    assert!(align_of::<BootInfo>() <= 4096);

    assert!(size_of::<SlotRegion>() == 16);
    assert!(offset_of!(SlotRegion, start) == 0);
    assert!(offset_of!(SlotRegion, end) == 8);

    assert!(size_of::<UntypedDesc>() == 16);
    assert!(offset_of!(UntypedDesc, paddr) == 0);
    assert!(offset_of!(UntypedDesc, size_bits) == 8);
    assert!(offset_of!(UntypedDesc, is_device) == 9);
    assert!(offset_of!(UntypedDesc, padding) == 10);

    assert!(size_of::<InterruptInfo>() == 256);
    assert!(offset_of!(InterruptInfo, ecam_count) == 0);
    assert!(offset_of!(InterruptInfo, ioapic_count) == 4);
    assert!(offset_of!(InterruptInfo, ecam) == 8);
    assert!(offset_of!(InterruptInfo, ioapics) == 72);
    assert!(offset_of!(InterruptInfo, isa_routes) == 104);
    assert!(offset_of!(InterruptInfo, reserved) == 232);

    assert!(size_of::<Ecam>() == 16);
    assert!(offset_of!(Ecam, base) == 0);
    assert!(offset_of!(Ecam, segment) == 8);
    assert!(offset_of!(Ecam, start_bus) == 10);
    assert!(offset_of!(Ecam, end_bus) == 11);
    assert!(offset_of!(Ecam, reserved) == 12);

    assert!(size_of::<IoApicInfo>() == 8);
    assert!(offset_of!(IoApicInfo, gsi_base) == 0);
    assert!(offset_of!(IoApicInfo, pins) == 4);
    assert!(offset_of!(IoApicInfo, id) == 6);
    assert!(offset_of!(IoApicInfo, reserved) == 7);

    assert!(size_of::<IsaRoute>() == 8);
    assert!(offset_of!(IsaRoute, gsi) == 0);
    assert!(offset_of!(IsaRoute, flags) == 4);
    assert!(offset_of!(IsaRoute, routed) == 5);
    assert!(offset_of!(IsaRoute, reserved) == 6);

    // The kernel's limits fit the block.
    assert!(acpi::MAX_ECAM == MAX_ECAM);
    assert!(window::MAX_IOAPICS == MAX_IOAPICS);
    // 16 fixed slots, the second BootInfo frame, the most paging structures
    // and image frames an 8 MiB image needs, and every untyped fit the root
    // CNode (`docs/design.md`, "Initial CSpace and BootInfo").
    assert!(NUM_INITIAL_SLOTS + 1 + 10 + 2048 + MAX_UNTYPED as u64 <= ROOT_CNODE_SLOTS);
};

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    #[test]
    fn magic_spells_its_name() {
        assert_eq!(&BOOTINFO_MAGIC.to_le_bytes(), b"uL4BINFO");
    }

    #[test]
    fn zero_is_the_default_and_reads_as_empty() {
        let bi = BootInfo::default();
        assert_eq!(bi, BootInfo::ZERO);
        assert!(bi.untyped().is_empty());
        assert_eq!(bi.cmdline(), "");
        assert_eq!(InterruptInfo::default(), InterruptInfo::ZERO);
        assert!(SlotRegion::default().is_empty());
    }

    #[test]
    fn slot_regions_and_descriptors() {
        let r = SlotRegion { start: 16, end: 20 };
        assert_eq!(r.len(), 4);
        assert!(r.contains(16) && r.contains(19) && !r.contains(20));
        let reversed = SlotRegion { start: 5, end: 4 };
        assert!(reversed.is_empty());
        let d = UntypedDesc::new(0x10_0000, 20, true);
        assert_eq!((d.size(), d.end(), d.device()), (1 << 20, 0x20_0000, true));
    }

    #[test]
    fn untyped_view_stops_at_the_list() {
        let mut bi = BootInfo::ZERO;
        bi.untyped = SlotRegion {
            start: 20,
            end: 20 + MAX_UNTYPED as u64 + 5,
        };
        assert_eq!(bi.untyped().len(), MAX_UNTYPED);
        bi.cmdline[..10].copy_from_slice(b"test=hello");
        bi.cmdline_len = 10;
        assert_eq!(bi.cmdline(), "test=hello");
        bi.cmdline_len = 1000;
        assert_eq!(bi.cmdline().len(), CMDLINE_MAX, "cut at the buffer");
        bi.cmdline[0] = 0xFF;
        assert_eq!(bi.cmdline(), "");
        let zeros: Vec<_> = bi
            .untyped()
            .iter()
            .filter(|d| **d == UntypedDesc::default())
            .collect();
        assert_eq!(zeros.len(), MAX_UNTYPED);
    }
}
