//! The loader-to-kernel handoff.
//!
//! The UEFI loader leaves one [`Handoff`] in memory and enters the kernel with
//! its physical address in `rdi`. Every address inside it is physical; the
//! kernel reaches them through the direct map at [`PHYS_MAP_BASE`].
//!
//! This layout is a boot ABI, specified in `docs/abi.md`, "Boot handoff".
//! Change it only together with that section and an ADR, and bump
//! [`HANDOFF_VERSION`].

use core::fmt;

/// Virtual address the kernel image is linked at: the top 2 GiB.
pub const KERNEL_VIRT_BASE: u64 = 0xFFFF_FFFF_8000_0000;

/// Start of the direct map. Physical address `p` is mapped at
/// `PHYS_MAP_BASE + p` for every `p < Handoff::phys_map_size`.
pub const PHYS_MAP_BASE: u64 = 0xFFFF_8000_0000_0000;

/// `"uL4BOOT\0"` read as a little-endian `u64`.
pub const HANDOFF_MAGIC: u64 = u64::from_le_bytes(*b"uL4BOOT\0");

// The direct map may cover up to 512 GiB, one PML4 slot, without reaching the
// kernel image.
const _: () = assert!(PHYS_MAP_BASE + (512 << 30) <= KERNEL_VIRT_BASE);

/// Bumped on every incompatible change to the structures in this module.
pub const HANDOFF_VERSION: u32 = 1;

/// Longest command line the loader passes on; longer ones are cut.
pub const CMDLINE_MAX: usize = 256;

/// What the loader hands the kernel. `#[repr(C)]` and fixed-width fields only,
/// because the loader and the kernel are built for different targets.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct Handoff {
    /// [`HANDOFF_MAGIC`].
    pub magic: u64,
    /// [`HANDOFF_VERSION`].
    pub version: u32,
    /// `size_of::<Handoff>()` as the loader saw it.
    pub size: u32,
    /// Physical address of the first byte of the kernel image, page-aligned.
    pub kernel_phys_base: u64,
    /// Bytes of physical memory the kernel image occupies, a multiple of 4 KiB.
    /// The image is mapped at [`KERNEL_VIRT_BASE`] onwards, contiguously.
    pub kernel_size: u64,
    /// Bytes of physical memory covered by the direct map, from address 0.
    pub phys_map_size: u64,
    /// Physical address of `memory_map_len` [`MemoryRegion`]s, sorted by base
    /// and non-overlapping.
    pub memory_map: u64,
    /// Number of entries at `memory_map`.
    pub memory_map_len: u64,
    /// Physical address of the ACPI RSDP, or 0 if the firmware has none.
    pub rsdp: u64,
    /// The GOP framebuffer, or all zeros if there is none.
    pub framebuffer: Framebuffer,
    /// Number of meaningful bytes in `cmdline`.
    pub cmdline_len: u64,
    /// The command line, UTF-8 and not NUL-terminated.
    pub cmdline: [u8; CMDLINE_MAX],
}

impl Handoff {
    /// Checks the fields the kernel relies on before it touches anything else.
    pub fn validate(&self) -> Result<(), HandoffError> {
        if self.magic != HANDOFF_MAGIC {
            return Err(HandoffError::BadMagic(self.magic));
        }
        if self.version != HANDOFF_VERSION {
            return Err(HandoffError::BadVersion(self.version));
        }
        if self.size as usize != core::mem::size_of::<Handoff>() {
            return Err(HandoffError::BadSize(self.size));
        }
        if self.cmdline_len as usize > CMDLINE_MAX {
            return Err(HandoffError::BadCmdline);
        }
        if !self
            .memory_map
            .is_multiple_of(core::mem::align_of::<MemoryRegion>() as u64)
        {
            return Err(HandoffError::MisalignedMemoryMap);
        }
        let map_bytes = self
            .memory_map_len
            .checked_mul(core::mem::size_of::<MemoryRegion>() as u64)
            .and_then(|n| n.checked_add(self.memory_map));
        match map_bytes {
            Some(end) if end <= self.phys_map_size => {}
            _ => return Err(HandoffError::MemoryMapOutOfRange),
        }
        Ok(())
    }

    /// The command line, or `""` if it is not valid UTF-8.
    pub fn cmdline(&self) -> &str {
        let len = (self.cmdline_len as usize).min(CMDLINE_MAX);
        core::str::from_utf8(&self.cmdline[..len]).unwrap_or("")
    }
}

/// Why [`Handoff::validate`] rejected a handoff.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HandoffError {
    BadMagic(u64),
    BadVersion(u32),
    BadSize(u32),
    BadCmdline,
    MisalignedMemoryMap,
    MemoryMapOutOfRange,
}

impl fmt::Display for HandoffError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BadMagic(m) => write!(f, "bad magic {m:#018x}"),
            Self::BadVersion(v) => write!(f, "version {v}, expected {HANDOFF_VERSION}"),
            Self::BadSize(s) => write!(f, "size {s}, expected {}", core::mem::size_of::<Handoff>()),
            Self::BadCmdline => f.write_str("command line longer than its buffer"),
            Self::MisalignedMemoryMap => f.write_str("memory map is misaligned"),
            Self::MemoryMapOutOfRange => f.write_str("memory map outside the direct map"),
        }
    }
}

/// The GOP framebuffer as the firmware left it. There is no mode setting
/// after boot.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Framebuffer {
    /// Physical address of the first pixel, or 0 if there is no framebuffer.
    pub base: u64,
    /// Size in bytes.
    pub size: u64,
    pub width: u32,
    pub height: u32,
    /// Pixels per scan line, which may exceed `width`.
    pub stride: u32,
    /// One of the `PixelFormat` constants.
    pub format: PixelFormat,
}

/// Layout of a 32-bit framebuffer pixel. A transparent `u32` rather than an
/// enum, so that any value read from memory is a valid `PixelFormat`.
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PixelFormat(pub u32);

impl PixelFormat {
    pub const NONE: Self = Self(0);
    /// Byte 0 red, byte 1 green, byte 2 blue.
    pub const RGB: Self = Self(1);
    /// Byte 0 blue, byte 1 green, byte 2 red.
    pub const BGR: Self = Self(2);

    pub fn name(self) -> &'static str {
        match self {
            Self::RGB => "RGB",
            Self::BGR => "BGR",
            _ => "none",
        }
    }
}

/// One range of physical memory.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct MemoryRegion {
    pub base: u64,
    pub len: u64,
    pub kind: RegionKind,
    pub reserved: u32,
}

impl MemoryRegion {
    pub const fn new(base: u64, len: u64, kind: RegionKind) -> Self {
        Self {
            base,
            len,
            kind,
            reserved: 0,
        }
    }

    /// One past the last byte, saturating at `u64::MAX`.
    pub const fn end(&self) -> u64 {
        self.base.saturating_add(self.len)
    }
}

/// What a [`MemoryRegion`] holds. A transparent `u32` for the same reason as
/// [`PixelFormat`].
#[repr(transparent)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, PartialOrd, Ord)]
pub struct RegionKind(pub u32);

impl RegionKind {
    /// Free RAM, including what the firmware used before ExitBootServices.
    /// The kernel must load its own GDT and IDT before reusing it, because
    /// the firmware's live there.
    pub const USABLE: Self = Self(1);
    pub const RESERVED: Self = Self(2);
    /// ACPI tables; free once the kernel has parsed them.
    pub const ACPI_RECLAIMABLE: Self = Self(3);
    pub const ACPI_NVS: Self = Self(4);
    pub const MMIO: Self = Self(5);
    /// The kernel image, the initial page tables, this handoff and the loader
    /// itself. The kernel decides which parts to keep.
    pub const LOADER: Self = Self(6);
    /// UEFI runtime services code and data, which must stay untouched.
    pub const FIRMWARE: Self = Self(7);
    pub const BAD: Self = Self(8);

    pub fn name(self) -> &'static str {
        match self {
            Self::USABLE => "usable",
            Self::RESERVED => "reserved",
            Self::ACPI_RECLAIMABLE => "acpi-reclaimable",
            Self::ACPI_NVS => "acpi-nvs",
            Self::MMIO => "mmio",
            Self::LOADER => "loader",
            Self::FIRMWARE => "firmware",
            Self::BAD => "bad",
            _ => "unknown",
        }
    }
}

// The loader and the kernel are built for different targets, so each build
// checks the layout docs/abi.md specifies rather than trusting both compilers
// to agree.
const _: () = {
    use core::mem::{offset_of, size_of};
    assert!(offset_of!(Handoff, magic) == 0);
    assert!(offset_of!(Handoff, version) == 8);
    assert!(offset_of!(Handoff, size) == 12);
    assert!(offset_of!(Handoff, kernel_phys_base) == 16);
    assert!(offset_of!(Handoff, kernel_size) == 24);
    assert!(offset_of!(Handoff, phys_map_size) == 32);
    assert!(offset_of!(Handoff, memory_map) == 40);
    assert!(offset_of!(Handoff, memory_map_len) == 48);
    assert!(offset_of!(Handoff, rsdp) == 56);
    assert!(offset_of!(Handoff, framebuffer) == 64);
    assert!(offset_of!(Handoff, cmdline_len) == 96);
    assert!(offset_of!(Handoff, cmdline) == 104);
    assert!(size_of::<Handoff>() == 360);
    assert!(size_of::<Framebuffer>() == 32);
    assert!(offset_of!(Framebuffer, width) == 16);
    assert!(offset_of!(Framebuffer, stride) == 24);
    assert!(offset_of!(Framebuffer, format) == 28);
    assert!(size_of::<MemoryRegion>() == 24);
    assert!(offset_of!(MemoryRegion, kind) == 16);
};

/// Sorts `regions` by base, drops empty ones and merges neighbours of the same
/// kind that touch. Returns how many entries of `regions` are now meaningful.
///
/// Works in place without allocating, because the loader runs it after
/// ExitBootServices, when there is no allocator.
pub fn normalize_regions(regions: &mut [MemoryRegion]) -> usize {
    // Insertion sort: firmware maps are short and usually sorted already.
    for i in 1..regions.len() {
        let mut j = i;
        while j > 0 && regions[j - 1].base > regions[j].base {
            regions.swap(j - 1, j);
            j -= 1;
        }
    }
    let mut out = 0;
    for i in 0..regions.len() {
        let r = regions[i];
        if r.len == 0 {
            continue;
        }
        if out > 0 {
            let last = &mut regions[out - 1];
            if last.kind == r.kind && last.end() == r.base {
                last.len = r.end() - last.base;
                continue;
            }
        }
        regions[out] = r;
        out += 1;
    }
    out
}

/// Total bytes in regions of `kind`.
pub fn total_bytes(regions: &[MemoryRegion], kind: RegionKind) -> u64 {
    regions
        .iter()
        .filter(|r| r.kind == kind)
        .map(|r| r.len)
        .sum()
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::mem::size_of;
    use std::vec::Vec;

    #[test]
    fn magic_spells_its_name() {
        assert_eq!(&HANDOFF_MAGIC.to_le_bytes(), b"uL4BOOT\0");
    }

    #[test]
    fn address_layout_is_canonical_and_disjoint() {
        // Both bases sit in the upper half and are sign-extended from bit 47.
        for base in [KERNEL_VIRT_BASE, PHYS_MAP_BASE] {
            assert_eq!(
                base >> 47,
                0x1_FFFF,
                "{base:#x} is not an upper-half canonical address"
            );
        }
    }

    fn valid_handoff() -> Handoff {
        let mut h = Handoff {
            magic: HANDOFF_MAGIC,
            version: HANDOFF_VERSION,
            size: size_of::<Handoff>() as u32,
            kernel_phys_base: 0x10_0000,
            kernel_size: 0x4000,
            phys_map_size: 4 << 30,
            memory_map: 0x20_0000,
            memory_map_len: 10,
            rsdp: 0,
            framebuffer: Framebuffer::default(),
            cmdline_len: 10,
            cmdline: [0; CMDLINE_MAX],
        };
        h.cmdline[..10].copy_from_slice(b"test=hello");
        h
    }

    #[test]
    fn validate_accepts_a_good_handoff() {
        let h = valid_handoff();
        assert_eq!(h.validate(), Ok(()));
        assert_eq!(h.cmdline(), "test=hello");
    }

    #[test]
    fn validate_rejects_bad_fields() {
        let mut h = valid_handoff();
        h.magic ^= 1;
        assert!(matches!(h.validate(), Err(HandoffError::BadMagic(_))));

        let mut h = valid_handoff();
        h.version += 1;
        assert_eq!(
            h.validate(),
            Err(HandoffError::BadVersion(HANDOFF_VERSION + 1))
        );

        let mut h = valid_handoff();
        h.size -= 8;
        assert!(matches!(h.validate(), Err(HandoffError::BadSize(_))));

        let mut h = valid_handoff();
        h.cmdline_len = CMDLINE_MAX as u64 + 1;
        assert_eq!(h.validate(), Err(HandoffError::BadCmdline));

        let mut h = valid_handoff();
        h.memory_map += 4;
        assert_eq!(h.validate(), Err(HandoffError::MisalignedMemoryMap));

        let mut h = valid_handoff();
        h.memory_map = h.phys_map_size - 8;
        assert_eq!(h.validate(), Err(HandoffError::MemoryMapOutOfRange));

        let mut h = valid_handoff();
        h.memory_map_len = u64::MAX / 2;
        assert_eq!(h.validate(), Err(HandoffError::MemoryMapOutOfRange));
    }

    #[test]
    fn invalid_utf8_cmdline_reads_as_empty() {
        let mut h = valid_handoff();
        h.cmdline[0] = 0xFF;
        assert_eq!(h.cmdline(), "");
    }

    const U: RegionKind = RegionKind::USABLE;
    const R: RegionKind = RegionKind::RESERVED;
    const L: RegionKind = RegionKind::LOADER;

    fn normalized(mut v: Vec<MemoryRegion>) -> Vec<MemoryRegion> {
        let n = normalize_regions(&mut v);
        v.truncate(n);
        v
    }

    #[test]
    fn normalize_sorts_and_merges() {
        let got = normalized(std::vec![
            MemoryRegion::new(0x3000, 0x1000, U),
            MemoryRegion::new(0x0000, 0x1000, U),
            MemoryRegion::new(0x1000, 0x2000, U),
            MemoryRegion::new(0x5000, 0x1000, U), // gap before it: not merged
            MemoryRegion::new(0x6000, 0x1000, L), // other kind: not merged
        ]);
        assert_eq!(
            got,
            std::vec![
                MemoryRegion::new(0x0000, 0x4000, U),
                MemoryRegion::new(0x5000, 0x1000, U),
                MemoryRegion::new(0x6000, 0x1000, L),
            ]
        );
    }

    #[test]
    fn normalize_drops_empty_regions() {
        let got = normalized(std::vec![
            MemoryRegion::new(0x1000, 0, U),
            MemoryRegion::new(0x0000, 0x1000, R),
            MemoryRegion::new(0x2000, 0, R),
        ]);
        assert_eq!(got, std::vec![MemoryRegion::new(0, 0x1000, R)]);
    }

    #[test]
    fn normalize_handles_empty_and_single() {
        assert_eq!(normalized(Vec::new()), Vec::new());
        let one = std::vec![MemoryRegion::new(0x1000, 0x1000, U)];
        assert_eq!(normalized(one.clone()), one);
    }

    #[test]
    fn normalize_merges_a_long_run() {
        let v: Vec<_> = (0..100u64)
            .rev()
            .map(|i| MemoryRegion::new(i * 0x1000, 0x1000, U))
            .collect();
        assert_eq!(
            normalized(v),
            std::vec![MemoryRegion::new(0, 100 * 0x1000, U)]
        );
    }

    #[test]
    fn total_bytes_counts_one_kind() {
        let v = [
            MemoryRegion::new(0, 0x1000, U),
            MemoryRegion::new(0x1000, 0x2000, R),
            MemoryRegion::new(0x3000, 0x3000, U),
        ];
        assert_eq!(total_bytes(&v, U), 0x4000);
        assert_eq!(total_bytes(&v, R), 0x2000);
        assert_eq!(total_bytes(&v, L), 0);
    }
}
