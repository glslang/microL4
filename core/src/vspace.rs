//! Page-table entries, the PAT, the direct map's cache types and the
//! kernel's own page tables (`docs/design.md`, "The kernel half"; ADR 0004).
//!
//! The kernel builds its tables at boot (step 4 of the M3 boot sequence) by
//! handing [`build`] a zeroed [`KernelTables`] in its `.bss`, the linker's
//! section bounds and the handoff. Everything here is plain arithmetic on
//! `u64` arrays, so the tables the kernel loads into CR3 are the tables the
//! host tests check, entry for entry, on the QEMU and Hyper-V memory maps.
//!
//! Entry formats are the SDM's for 4-level paging with 4 KiB and 2 MiB
//! pages. Table entries (PML4E, PDPTE, PDE pointing at a page table) share
//! one format, so one encoder per half makes them. Leaves come from four
//! encoders: kernel and user, 4 KiB and 2 MiB. Kernel leaves are global and
//! supervisor-only and never writable and executable at once; user leaves
//! are user-accessible and never global.

use core::fmt;

use crate::handoff::{DIRECT_MAP_MAX, KERNEL_VIRT_BASE, MemoryRegion, PHYS_MAP_BASE, RegionKind};
use crate::window::{DeviceWindow, KERNEL_DEVICE_BASE};

/// Bytes in a 4 KiB page.
pub const PAGE_4K: u64 = 1 << 12;
/// Bytes in a 2 MiB page.
pub const PAGE_2M: u64 = 1 << 21;
/// Bytes one page directory maps: 1 GiB.
pub const PD_SPAN: u64 = 1 << 30;
/// Entries in every paging structure.
pub const ENTRIES: usize = 512;

/// The largest kernel image, `.rootimage` included (`docs/design.md`,
/// "Bounds"). `kernel/linker.ld` asserts the same number.
pub const KERNEL_IMAGE_MAX: u64 = 16 << 20;

/// Present.
pub const P: u64 = 1 << 0;
/// Writable (R/W).
pub const RW: u64 = 1 << 1;
/// User-accessible (U/S).
pub const US: u64 = 1 << 2;
/// Page-level write-through: PAT index bit 0.
pub const PWT: u64 = 1 << 3;
/// Page-level cache disable: PAT index bit 1.
pub const PCD: u64 = 1 << 4;
/// Accessed; set by the CPU.
pub const ACCESSED: u64 = 1 << 5;
/// Dirty, in a leaf; set by the CPU.
pub const DIRTY: u64 = 1 << 6;
/// Page size, in a PDE (2 MiB) or PDPTE (1 GiB); a table entry has it clear.
pub const PS: u64 = 1 << 7;
/// PAT index bit 2 in a 4 KiB PTE [H8].
pub const PAT_4K: u64 = 1 << 7;
/// Global, in a leaf.
pub const G: u64 = 1 << 8;
/// PAT index bit 2 in a 2 MiB PDE [H8].
pub const PAT_2M: u64 = 1 << 12;
/// Execute-disable (XD, NX).
pub const XD: u64 = 1 << 63;
/// The physical address of a table or 4 KiB page: bits 12 to 51.
pub const ADDR_4K: u64 = 0x000F_FFFF_FFFF_F000;
/// The physical address of a 2 MiB page: bits 21 to 51.
pub const ADDR_2M: u64 = 0x000F_FFFF_FFE0_0000;

/// `IA32_PAT` (MSR `0x277`) as the kernel programs it: WB, WT, UC-, UC, WC,
/// WT, UC-, UC [H8]. Entries 0 to 4 are what seL4's `init_pat_msr` writes;
/// 5 to 7 are the power-on values.
pub const PAT_MSR: u64 = 0x0007_0401_0007_0406;
/// The MSR's number.
pub const IA32_PAT: u32 = 0x277;

/// A memory type the PAT can select [H8].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CacheType {
    /// Write-back: the kernel image, RAM in the direct map, user RAM frames.
    WriteBack,
    /// Write-through: not used.
    WriteThrough,
    /// UC-, which an MTRR can turn into WC: not used.
    UncachedMinus,
    /// Strong uncacheable: the device window, direct-map pages without RAM
    /// or with a kernel device page, user device frames mapped `Uncached`.
    Uncached,
    /// Write-combining: user device frames mapped `WriteCombining`.
    WriteCombining,
}

impl CacheType {
    /// The type's encoding in a PAT entry.
    pub const fn encoding(self) -> u8 {
        match self {
            Self::Uncached => 0x00,
            Self::WriteCombining => 0x01,
            Self::WriteThrough => 0x04,
            Self::WriteBack => 0x06,
            Self::UncachedMinus => 0x07,
        }
    }

    /// The type with PAT-entry encoding `e`, if it is one of these.
    pub const fn from_encoding(e: u8) -> Option<Self> {
        Some(match e {
            0x00 => Self::Uncached,
            0x01 => Self::WriteCombining,
            0x04 => Self::WriteThrough,
            0x06 => Self::WriteBack,
            0x07 => Self::UncachedMinus,
            _ => return None,
        })
    }

    /// The type [`PAT_MSR`] gives PAT index `index` (0 to 7).
    pub const fn from_pat_index(index: u8) -> Self {
        let e = (PAT_MSR >> ((index as u64 & 7) * 8)) as u8;
        match Self::from_encoding(e) {
            Some(t) => t,
            None => panic!("PAT_MSR holds an unknown type"),
        }
    }

    /// The PAT index the kernel uses for this type: the lowest one
    /// [`PAT_MSR`] gives it.
    pub const fn pat_index(self) -> u8 {
        match self {
            Self::WriteBack => 0,
            Self::WriteThrough => 1,
            Self::UncachedMinus => 2,
            Self::Uncached => 3,
            Self::WriteCombining => 4,
        }
    }

    /// The PAT, PCD and PWT bits selecting this type in a 4 KiB PTE.
    pub const fn pte_bits(self) -> u64 {
        Self::index_bits(self.pat_index(), PAT_4K)
    }

    /// The PAT, PCD and PWT bits selecting this type in a 2 MiB PDE.
    pub const fn pde_2m_bits(self) -> u64 {
        Self::index_bits(self.pat_index(), PAT_2M)
    }

    /// PAT index = 4·PAT + 2·PCD + PWT [H8].
    const fn index_bits(index: u8, pat_bit: u64) -> u64 {
        let mut bits = 0;
        if index & 1 != 0 {
            bits |= PWT;
        }
        if index & 2 != 0 {
            bits |= PCD;
        }
        if index & 4 != 0 {
            bits |= pat_bit;
        }
        bits
    }

    /// The type a leaf selects, from its PAT, PCD and PWT bits; `pat_bit` is
    /// [`PAT_4K`] or [`PAT_2M`].
    pub const fn of_leaf(entry: u64, pat_bit: u64) -> Self {
        let index = (entry & PWT != 0) as u8
            | ((entry & PCD != 0) as u8) << 1
            | ((entry & pat_bit != 0) as u8) << 2;
        Self::from_pat_index(index)
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::WriteBack => "WB",
            Self::WriteThrough => "WT",
            Self::UncachedMinus => "UC-",
            Self::Uncached => "UC",
            Self::WriteCombining => "WC",
        }
    }
}

/// What a kernel leaf allows. Kernel mappings are never writable and
/// executable at once, so there is no such variant.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum KernelAccess {
    /// Read-only, no-execute: `.rodata`, the direct map's alias of the image
    /// text.
    Read,
    /// Read-write, no-execute: `.data`, `.bss`, the direct map, the device
    /// window.
    ReadWrite,
    /// Read and execute: `.text` and `.hvcall`.
    ReadExecute,
}

impl KernelAccess {
    /// R/W and XD, and Dirty preset on writable pages (see [`kernel_pte`]).
    const fn bits(self) -> u64 {
        match self {
            Self::Read => XD,
            Self::ReadWrite => RW | XD | DIRTY,
            Self::ReadExecute => 0,
        }
    }
}

/// What a user leaf allows (`docs/design.md`, "Mapping"): always read,
/// `write` from the rights, `execute` from the attributes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct UserAccess {
    pub write: bool,
    pub execute: bool,
}

impl UserAccess {
    const fn bits(self) -> u64 {
        let mut bits = 0;
        if self.write {
            bits |= RW;
        }
        if !self.execute {
            bits |= XD;
        }
        bits
    }
}

const fn check_addr(phys: u64, mask: u64) {
    assert!(phys & !mask == 0, "physical address misaligned or too wide");
}

/// A kernel-half PML4E, PDPTE or PDE pointing at the table at `table_phys`:
/// present, writable, executable and supervisor-only, so the leaf decides
/// [H7] and ring 3 reaches nothing below it.
///
/// Accessed is preset, as in every kernel entry, so the CPU never writes
/// the kernel's tables.
pub const fn kernel_table(table_phys: u64) -> u64 {
    check_addr(table_phys, ADDR_4K);
    table_phys | P | RW | ACCESSED
}

/// A user-half PML4E, PDPTE or PDE pointing at the table at `table_phys`:
/// present, writable and user-accessible, XD, PWT and PCD clear
/// (`docs/design.md`, "Mapping").
pub const fn user_table(table_phys: u64) -> u64 {
    check_addr(table_phys, ADDR_4K);
    table_phys | P | RW | US
}

/// A kernel 4 KiB PTE: global and supervisor-only.
///
/// Accessed, and Dirty on a writable page, are preset, as Linux presets
/// them on kernel mappings: the CPU then never writes the kernel's tables
/// after boot, so the kernel can hold them as plain shared data.
pub const fn kernel_pte(phys: u64, access: KernelAccess, cache: CacheType) -> u64 {
    check_addr(phys, ADDR_4K);
    phys | P | G | ACCESSED | access.bits() | cache.pte_bits()
}

/// A kernel 2 MiB PDE: global and supervisor-only, Accessed and Dirty
/// preset as in [`kernel_pte`].
pub const fn kernel_pde_2m(phys: u64, access: KernelAccess, cache: CacheType) -> u64 {
    check_addr(phys, ADDR_2M);
    phys | P | PS | G | ACCESSED | access.bits() | cache.pde_2m_bits()
}

/// A user 4 KiB PTE: user-accessible and never global.
pub const fn user_pte(phys: u64, access: UserAccess, cache: CacheType) -> u64 {
    check_addr(phys, ADDR_4K);
    phys | P | US | access.bits() | cache.pte_bits()
}

/// A user 2 MiB PDE: user-accessible and never global.
pub const fn user_pde_2m(phys: u64, access: UserAccess, cache: CacheType) -> u64 {
    check_addr(phys, ADDR_2M);
    phys | P | PS | US | access.bits() | cache.pde_2m_bits()
}

/// The index of `virt` in its PML4 (`level` 3), PDPT (2), page directory (1)
/// or page table (0).
pub const fn index(virt: u64, level: u32) -> usize {
    ((virt >> (12 + 9 * level)) & 0x1FF) as usize
}

/// Whether a memory-map region of `kind` holds RAM for the direct map's
/// cache rule: `USABLE`, `LOADER`, `ACPI_RECLAIMABLE`, `ACPI_NVS` and
/// `FIRMWARE`. Every other kind, unknown ones included, does not.
pub fn is_ram_like(kind: RegionKind) -> bool {
    matches!(
        kind,
        RegionKind::USABLE
            | RegionKind::LOADER
            | RegionKind::ACPI_RECLAIMABLE
            | RegionKind::ACPI_NVS
            | RegionKind::FIRMWARE
    )
}

/// The kernel device page in the 2 MiB page at `page_2m`, if any.
fn device_page_in(window: &DeviceWindow, page_2m: u64) -> Option<u64> {
    window
        .pages
        .iter()
        .flatten()
        .copied()
        .find(|&d| d & !(PAGE_2M - 1) == page_2m)
}

/// The cache type of the direct map's 2 MiB page at physical `page_2m`
/// (`docs/design.md`, "Direct-map cache types"): WB if it overlaps a
/// RAM-like region and holds no kernel device page, UC otherwise. Gaps in
/// the map, `MMIO`, `RESERVED`, `BAD` and unknown kinds are not RAM. A page
/// that mixes RAM with a hole is WB. `regions` need not be sorted.
pub fn direct_map_type(regions: &[MemoryRegion], window: &DeviceWindow, page_2m: u64) -> CacheType {
    assert!(page_2m.is_multiple_of(PAGE_2M), "unaligned 2 MiB page");
    let end = page_2m + PAGE_2M;
    let ram = regions
        .iter()
        .any(|r| is_ram_like(r.kind) && r.len != 0 && r.base < end && r.end() > page_2m);
    if ram && device_page_in(window, page_2m).is_none() {
        CacheType::WriteBack
    } else {
        CacheType::Uncached
    }
}

/// A 4 KiB-aligned range of addresses, `[start, end)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Span {
    pub start: u64,
    pub end: u64,
}

impl Span {
    pub const fn contains(&self, a: u64) -> bool {
        self.start <= a && a < self.end
    }
}

/// The page that holds `a`'s last byte, rounded up: `a` up to a 4 KiB
/// multiple.
const fn page_up(a: u64) -> u64 {
    (a + PAGE_4K - 1) & !(PAGE_4K - 1)
}

/// The kernel image: where the loader put it and what the linker script put
/// in it. Virtual addresses are at [`KERNEL_VIRT_BASE`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KernelLayout {
    /// `kernel_phys_base` from the handoff.
    pub phys_base: u64,
    /// `kernel_size` from the handoff.
    pub size: u64,
    /// `__text_start` to `__text_end`: `.text` and `.hvcall`, mapped RX.
    pub text_start: u64,
    pub text_end: u64,
    /// `__rodata_start` to `__rodata_end`, mapped read-only; the end need
    /// not be page-aligned.
    pub rodata_start: u64,
    pub rodata_end: u64,
    /// `__data_start` to `__data_end`: `.data`, `.bss` and the stacks,
    /// mapped RW and NX.
    pub data_start: u64,
    pub data_end: u64,
    /// `__kernel_stack_guard` and `__ist1_guard` to `__ist4_guard`: the
    /// pages the tables leave unmapped.
    pub guards: [u64; 5],
}

/// What a page of the kernel image holds, which decides its mappings.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Section {
    /// `.text` and `.hvcall`: RX at `KERNEL_VIRT_BASE`, R in the direct map.
    Text,
    /// `.rodata`: R everywhere.
    Rodata,
    /// `.data`, `.bss` and the stacks: RW and NX everywhere.
    Data,
    /// A stack guard page: mapped nowhere.
    Guard,
}

impl KernelLayout {
    /// The image as virtual addresses.
    pub const fn virt(&self) -> Span {
        Span {
            start: KERNEL_VIRT_BASE,
            end: KERNEL_VIRT_BASE + self.size,
        }
    }

    /// The image as physical addresses.
    pub const fn phys(&self) -> Span {
        Span {
            start: self.phys_base,
            end: self.phys_base + self.size,
        }
    }

    /// The physical address of image virtual address `virt`.
    pub const fn virt_to_phys(&self, virt: u64) -> u64 {
        virt - KERNEL_VIRT_BASE + self.phys_base
    }

    /// What the image page holding virtual address `virt` holds, or `None`
    /// outside the image. Call after [`KernelLayout::check`].
    pub fn section_of(&self, virt: u64) -> Option<Section> {
        let page = virt & !(PAGE_4K - 1);
        if !self.virt().contains(page) {
            None
        } else if page < self.rodata_start {
            Some(Section::Text)
        } else if page < self.data_start {
            Some(Section::Rodata)
        } else if self.guards.contains(&page) {
            Some(Section::Guard)
        } else {
            Some(Section::Data)
        }
    }

    /// Checks that the image is page-aligned, at most
    /// [`KERNEL_IMAGE_MAX`], and covered exactly by text, rodata and data
    /// in that order, with each guard page inside data.
    pub fn check(&self) -> Result<(), BuildError> {
        let bad = |what| Err(BuildError::BadLayout(what));
        if !self.phys_base.is_multiple_of(PAGE_4K) || self.phys_base & !ADDR_4K != 0 {
            return bad("kernel_phys_base is not a page address");
        }
        if self.size == 0 || !self.size.is_multiple_of(PAGE_4K) {
            return bad("kernel_size is not a whole number of pages");
        }
        if self.size > KERNEL_IMAGE_MAX {
            return Err(BuildError::ImageTooLarge(self.size));
        }
        if self.text_start != KERNEL_VIRT_BASE {
            return bad("text does not start at KERNEL_VIRT_BASE");
        }
        let ordered = self.text_start <= self.text_end
            && self.text_end <= self.rodata_start
            && self.rodata_start <= self.rodata_end
            && self.rodata_end <= self.data_start
            && self.data_start <= self.data_end;
        if !ordered {
            return bad("sections out of order");
        }
        if page_up(self.text_end) != self.rodata_start
            || page_up(self.rodata_end) != self.data_start
        {
            return bad("a gap or overlap between text, rodata and data");
        }
        if self.data_end != self.virt().end {
            return bad("data does not end where kernel_size says the image does");
        }
        for (i, &g) in self.guards.iter().enumerate() {
            if !g.is_multiple_of(PAGE_4K) || g < self.data_start || g >= self.data_end {
                return bad("a guard page is not a data page");
            }
            if self.guards[..i].contains(&g) {
                return bad("two guard pages coincide");
            }
        }
        Ok(())
    }
}

/// One paging structure: 512 entries, one 4 KiB page.
pub type Table = [u64; ENTRIES];

/// The PML4.
pub const PML4: usize = 0;
/// The direct map's PDPT, in PML4 entry 256.
pub const DIRECT_PDPT: usize = 1;
/// The direct map's 64 page directories, one per GiB.
pub const DIRECT_PDS: usize = 2;
/// Page directories for the 64 GiB of [`DIRECT_MAP_MAX`].
pub const DIRECT_PD_COUNT: usize = (DIRECT_MAP_MAX / PD_SPAN) as usize;
/// The direct map's page tables for the 2 MiB pages the image touches.
pub const ALIAS_PTS: usize = DIRECT_PDS + DIRECT_PD_COUNT;
/// A 16 MiB image at a 4 KiB boundary touches at most nine 2 MiB pages.
pub const ALIAS_PT_COUNT: usize = (KERNEL_IMAGE_MAX / PAGE_2M) as usize + 1;
/// The image's PDPT, in PML4 entry 511.
pub const IMAGE_PDPT: usize = ALIAS_PTS + ALIAS_PT_COUNT;
/// The image's page directory, in the image PDPT's entry 510.
pub const IMAGE_PD: usize = IMAGE_PDPT + 1;
/// The image's page tables, one per 2 MiB from `KERNEL_VIRT_BASE`.
pub const IMAGE_PTS: usize = IMAGE_PD + 1;
pub const IMAGE_PT_COUNT: usize = (KERNEL_IMAGE_MAX / PAGE_2M) as usize;
/// The device window's page directory, in the image PDPT's entry 511.
pub const WINDOW_PD: usize = IMAGE_PTS + IMAGE_PT_COUNT;
/// The device window's page table, in the window PD's entry 511.
pub const WINDOW_PT: usize = WINDOW_PD + 1;
/// Every table: 87 pages, 348 KiB.
pub const TABLE_COUNT: usize = WINDOW_PT + 1;

const _: () = assert!(TABLE_COUNT == 87);
const _: () = assert!(index(PHYS_MAP_BASE, 3) == 256);
const _: () = assert!(index(KERNEL_VIRT_BASE, 3) == 511 && index(KERNEL_VIRT_BASE, 2) == 510);
const _: () = assert!(index(KERNEL_VIRT_BASE, 1) == 0 && index(KERNEL_VIRT_BASE, 0) == 0);
const _: () = assert!(index(KERNEL_DEVICE_BASE, 3) == 511 && index(KERNEL_DEVICE_BASE, 2) == 511);
const _: () = assert!(index(KERNEL_DEVICE_BASE, 1) == 511 && index(KERNEL_DEVICE_BASE, 0) == 0);

/// The kernel's page tables (`docs/design.md`, "From what memory"): table
/// `i` lives at physical `tables_phys + i * 4096`, where `tables_phys` is
/// wherever the caller keeps this value. The indices are the constants
/// above. Every address space shares the PML4's entries 256 and 511.
#[repr(C, align(4096))]
pub struct KernelTables {
    pub tables: [Table; TABLE_COUNT],
}

const _: () = assert!(core::mem::size_of::<KernelTables>() == TABLE_COUNT * 4096);

impl Default for KernelTables {
    fn default() -> Self {
        Self::new()
    }
}

/// Why [`build`] refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum BuildError {
    /// The section bounds or the image placement are inconsistent.
    BadLayout(&'static str),
    /// The image is larger than [`KERNEL_IMAGE_MAX`].
    ImageTooLarge(u64),
    /// The direct map's end is 0, not a 2 MiB multiple, or above
    /// [`DIRECT_MAP_MAX`].
    BadDirectMapEnd(u64),
    /// The image ends above the direct map.
    ImageOutsideDirectMap,
    /// The tables' physical address is not 4 KiB-aligned or they are not
    /// in the image's data.
    TablesOutsideImage(u64),
    /// A device-window page address is not a 4 KiB page address.
    BadDevicePage(u64),
    /// The image shares a 2 MiB page with this kernel device page.
    ImageSharesDevicePage(u64),
    /// This 2 MiB page of the image overlaps no RAM-like region, so the
    /// direct map would map the image UC.
    ImageNotInRam(u64),
}

impl fmt::Display for BuildError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::BadLayout(what) => write!(f, "bad kernel layout: {what}"),
            Self::ImageTooLarge(n) => write!(
                f,
                "kernel image is {n:#x} bytes, over KERNEL_IMAGE_MAX ({KERNEL_IMAGE_MAX:#x})"
            ),
            Self::BadDirectMapEnd(e) => write!(f, "direct map end {e:#x} is not usable"),
            Self::ImageOutsideDirectMap => f.write_str("kernel image ends above the direct map"),
            Self::TablesOutsideImage(p) => {
                write!(f, "page tables at {p:#x} are not in the image's data")
            }
            Self::BadDevicePage(p) => write!(f, "device page {p:#x} is not a page address"),
            Self::ImageSharesDevicePage(p) => {
                write!(
                    f,
                    "kernel image shares a 2 MiB page with device page {p:#x}"
                )
            }
            Self::ImageNotInRam(p) => {
                write!(
                    f,
                    "kernel image's 2 MiB page {p:#x} holds no RAM in the memory map"
                )
            }
        }
    }
}

/// What [`build`] made, for the boot log.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct BuildSummary {
    /// 2 MiB pages of the direct map that are WB, counting those mapped
    /// with 4 KiB pages over the image.
    pub direct_wb: usize,
    /// 2 MiB pages of the direct map that are UC.
    pub direct_uc: usize,
    /// 2 MiB pages of the direct map mapped with 4 KiB pages.
    pub alias_pts: usize,
    /// Page tables mapping the image at `KERNEL_VIRT_BASE`.
    pub image_pts: usize,
    /// Device-window pages mapped.
    pub window_pages: usize,
}

/// The input to [`build`] beyond the tables themselves.
#[derive(Clone, Copy, Debug)]
pub struct BuildInput<'a> {
    /// The kernel image.
    pub layout: &'a KernelLayout,
    /// The memory map.
    pub regions: &'a [MemoryRegion],
    /// `Handoff::direct_map_end()`.
    pub direct_map_end: u64,
    /// The kernel device pages.
    pub window: &'a DeviceWindow,
}

impl KernelTables {
    /// All tables empty.
    pub const fn new() -> Self {
        Self {
            tables: [[0; ENTRIES]; TABLE_COUNT],
        }
    }

    /// The physical address of table `i`, if these tables are at
    /// `tables_phys`.
    pub const fn table_phys(tables_phys: u64, i: usize) -> u64 {
        tables_phys + (i as u64) * PAGE_4K
    }

    /// Empties every table in place (the value is too big for a kernel
    /// stack, so it is never rebuilt by value).
    pub fn clear(&mut self) {
        for t in self.tables.iter_mut() {
            t.fill(0);
        }
    }

    /// Translates `virt` by walking these tables, which are at physical
    /// `tables_phys`, as the CPU would with CR0.WP, EFER.NXE and CR4.PSE
    /// set: `Ok(None)` if no translation exists.
    pub fn walk(&self, tables_phys: u64, virt: u64) -> Result<Option<Translation>, WalkError> {
        let canonical = (virt as i64) << 16 >> 16 == virt as i64;
        if !canonical {
            return Err(WalkError::NonCanonical(virt));
        }
        let mut table = PML4;
        let (mut write, mut user, mut nx) = (true, true, false);
        for level in (0..=3u32).rev() {
            let e = self.tables[table][index(virt, level)];
            if e & P == 0 {
                return Ok(None);
            }
            write &= e & RW != 0;
            user &= e & US != 0;
            nx |= e & XD != 0;
            let leaf = match level {
                0 => Some((PAGE_4K, ADDR_4K, PAT_4K)),
                1 if e & PS != 0 => Some((PAGE_2M, ADDR_2M, PAT_2M)),
                3 | 2 if e & PS != 0 => return Err(WalkError::UnexpectedPageSize(virt)),
                _ => None,
            };
            if let Some((size, mask, pat_bit)) = leaf {
                return Ok(Some(Translation {
                    phys: (e & mask) + (virt & (size - 1)),
                    page_size: size,
                    write,
                    user,
                    execute: !nx,
                    global: e & G != 0,
                    cache: CacheType::of_leaf(e, pat_bit),
                }));
            }
            let next = e & ADDR_4K;
            let i = next.wrapping_sub(tables_phys) / PAGE_4K;
            if next < tables_phys || i >= TABLE_COUNT as u64 {
                return Err(WalkError::OutsideTables(next));
            }
            table = i as usize;
        }
        unreachable!("a level-0 entry is always a leaf")
    }
}

/// What [`KernelTables::walk`] found for one virtual address.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Translation {
    /// The physical address of the byte at the virtual address.
    pub phys: u64,
    /// The leaf's page size: [`PAGE_4K`] or [`PAGE_2M`].
    pub page_size: u64,
    /// Effective R/W: the AND over the walk [H7].
    pub write: bool,
    /// Effective U/S: the AND over the walk [H7].
    pub user: bool,
    /// Not XD anywhere on the walk [H7].
    pub execute: bool,
    /// The leaf's G bit.
    pub global: bool,
    /// The leaf's PAT type.
    pub cache: CacheType,
}

/// Why [`KernelTables::walk`] could not finish.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WalkError {
    NonCanonical(u64),
    /// A table entry points at this physical address, outside the tables.
    OutsideTables(u64),
    /// PS is set in a PML4E or PDPTE: the kernel makes no 1 GiB pages.
    UnexpectedPageSize(u64),
}

/// Fills `t`, which is at physical `tables_phys`, with the kernel's page
/// tables (`docs/design.md`, "The kernel half"):
///
/// - PML4 entry 256, the direct map: `[0, direct_map_end)` in 2 MiB pages,
///   RW, NX, global, of the type [`direct_map_type`] gives; the 2 MiB pages
///   the image touches in 4 KiB pages, the image's text and rodata
///   read-only, its guard pages unmapped, everything NX.
/// - PML4 entry 511: the image at `KERNEL_VIRT_BASE` in 4 KiB pages, text
///   RX, rodata R, data RW and NX, guard pages unmapped, all WB; and the
///   device window at `KERNEL_DEVICE_BASE`, RW, NX and UC.
/// - Everything else empty, the lower half included. Every entry is
///   supervisor-only and every leaf global.
///
/// Refuses, leaving `t` unchanged, if the layout is inconsistent, the image
/// shares a 2 MiB page with a kernel device page or lies outside RAM, or
/// the tables are not in the image's data.
pub fn build(
    t: &mut KernelTables,
    tables_phys: u64,
    input: &BuildInput<'_>,
) -> Result<BuildSummary, BuildError> {
    let BuildInput {
        layout,
        regions,
        direct_map_end,
        window,
    } = *input;
    layout.check()?;
    if direct_map_end == 0
        || !direct_map_end.is_multiple_of(PAGE_2M)
        || direct_map_end > DIRECT_MAP_MAX
    {
        return Err(BuildError::BadDirectMapEnd(direct_map_end));
    }
    let image = layout.phys();
    if image.end > direct_map_end {
        return Err(BuildError::ImageOutsideDirectMap);
    }
    let tables_size = core::mem::size_of::<KernelTables>() as u64;
    let data = Span {
        start: layout.virt_to_phys(layout.data_start),
        end: layout.virt_to_phys(layout.data_end),
    };
    if !tables_phys.is_multiple_of(PAGE_4K)
        || tables_phys < data.start
        || tables_phys.saturating_add(tables_size) > data.end
    {
        return Err(BuildError::TablesOutsideImage(tables_phys));
    }
    for &d in window.pages.iter().flatten() {
        if d & !ADDR_4K != 0 {
            return Err(BuildError::BadDevicePage(d));
        }
    }
    // The 2 MiB pages the image touches are mapped with 4 KiB pages, WB.
    let first_2m = image.start / PAGE_2M;
    let last_2m = (image.end - 1) / PAGE_2M;
    for p in first_2m..=last_2m {
        if let Some(d) = device_page_in(window, p * PAGE_2M) {
            return Err(BuildError::ImageSharesDevicePage(d));
        }
        if direct_map_type(regions, window, p * PAGE_2M) != CacheType::WriteBack {
            return Err(BuildError::ImageNotInRam(p * PAGE_2M));
        }
    }

    let phys = |i| KernelTables::table_phys(tables_phys, i);
    let mut summary = BuildSummary::default();
    t.clear();
    t.tables[PML4][index(PHYS_MAP_BASE, 3)] = kernel_table(phys(DIRECT_PDPT));
    t.tables[PML4][index(KERNEL_VIRT_BASE, 3)] = kernel_table(phys(IMAGE_PDPT));

    // The direct map.
    for gib in 0..direct_map_end.div_ceil(PD_SPAN) as usize {
        t.tables[DIRECT_PDPT][gib] = kernel_table(phys(DIRECT_PDS + gib));
    }
    for p in 0..direct_map_end / PAGE_2M {
        let base = p * PAGE_2M;
        let pd = DIRECT_PDS + (p / ENTRIES as u64) as usize;
        let slot = (p % ENTRIES as u64) as usize;
        let cache = direct_map_type(regions, window, base);
        match cache {
            CacheType::WriteBack => summary.direct_wb += 1,
            _ => summary.direct_uc += 1,
        }
        if !(first_2m..=last_2m).contains(&p) {
            t.tables[pd][slot] = kernel_pde_2m(base, KernelAccess::ReadWrite, cache);
            continue;
        }
        let pt = ALIAS_PTS + (p - first_2m) as usize;
        t.tables[pd][slot] = kernel_table(phys(pt));
        summary.alias_pts += 1;
        for (i, e) in t.tables[pt].iter_mut().enumerate() {
            let page = base + i as u64 * PAGE_4K;
            let access = if image.contains(page) {
                match layout.section_of(page - image.start + KERNEL_VIRT_BASE) {
                    Some(Section::Text | Section::Rodata) => Some(KernelAccess::Read),
                    Some(Section::Data) => Some(KernelAccess::ReadWrite),
                    Some(Section::Guard) | None => None,
                }
            } else {
                Some(KernelAccess::ReadWrite)
            };
            if let Some(access) = access {
                *e = kernel_pte(page, access, cache);
            }
        }
    }

    // The image at KERNEL_VIRT_BASE.
    t.tables[IMAGE_PDPT][index(KERNEL_VIRT_BASE, 2)] = kernel_table(phys(IMAGE_PD));
    let pts = layout.size.div_ceil(PAGE_2M) as usize;
    for j in 0..pts {
        t.tables[IMAGE_PD][j] = kernel_table(phys(IMAGE_PTS + j));
    }
    summary.image_pts = pts;
    for k in 0..layout.size / PAGE_4K {
        let virt = KERNEL_VIRT_BASE + k * PAGE_4K;
        let access = match layout.section_of(virt) {
            Some(Section::Text) => KernelAccess::ReadExecute,
            Some(Section::Rodata) => KernelAccess::Read,
            Some(Section::Data) => KernelAccess::ReadWrite,
            Some(Section::Guard) | None => continue,
        };
        let pt = IMAGE_PTS + (k / ENTRIES as u64) as usize;
        t.tables[pt][index(virt, 0)] =
            kernel_pte(layout.virt_to_phys(virt), access, CacheType::WriteBack);
    }

    // The device window.
    t.tables[IMAGE_PDPT][index(KERNEL_DEVICE_BASE, 2)] = kernel_table(phys(WINDOW_PD));
    t.tables[WINDOW_PD][index(KERNEL_DEVICE_BASE, 1)] = kernel_table(phys(WINDOW_PT));
    for (i, page) in window.pages.iter().enumerate() {
        if let Some(d) = *page {
            t.tables[WINDOW_PT][i] = kernel_pte(d, KernelAccess::ReadWrite, CacheType::Uncached);
            summary.window_pages += 1;
        }
    }
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::window::{HPET_PAGE, LAPIC_PAGE, ioapic_page};
    use std::boxed::Box;
    use std::vec::Vec;

    const USABLE: RegionKind = RegionKind::USABLE;
    const RESERVED: RegionKind = RegionKind::RESERVED;
    const ACPI_RECLAIM: RegionKind = RegionKind::ACPI_RECLAIMABLE;
    const ACPI_NVS: RegionKind = RegionKind::ACPI_NVS;
    const LOADER: RegionKind = RegionKind::LOADER;
    const FIRMWARE: RegionKind = RegionKind::FIRMWARE;

    const fn r(base: u64, end: u64, kind: RegionKind) -> MemoryRegion {
        MemoryRegion::new(base, end - base, kind)
    }

    /// QEMU q35 with 256 MiB and OVMF: the map the M3 kernel printed for
    /// `test=paging`, with the kernel at `0xdf81000`, 532 KiB.
    const QEMU_MAP: [MemoryRegion; 25] = [
        r(0x0000_0000, 0x000a_0000, USABLE),
        r(0x0010_0000, 0x0080_0000, USABLE),
        r(0x0080_0000, 0x0080_8000, ACPI_NVS),
        r(0x0080_8000, 0x0080_b000, USABLE),
        r(0x0080_b000, 0x0080_c000, ACPI_NVS),
        r(0x0080_c000, 0x0081_0000, USABLE),
        r(0x0081_0000, 0x0090_0000, ACPI_NVS),
        r(0x0090_0000, 0x0df7_1000, USABLE),
        r(0x0df7_1000, 0x0e13_9000, LOADER),
        r(0x0e13_9000, 0x0e14_0000, USABLE),
        r(0x0e14_0000, 0x0e14_4000, LOADER),
        r(0x0e14_4000, 0x0e3d_1000, USABLE),
        r(0x0e3d_1000, 0x0e3d_2000, LOADER),
        r(0x0e3d_2000, 0x0f01_0000, USABLE),
        r(0x0f01_0000, 0x0f0d_1000, FIRMWARE),
        r(0x0f0d_1000, 0x0f8e_d000, USABLE),
        r(0x0f8e_d000, 0x0fae_d000, FIRMWARE),
        r(0x0fae_d000, 0x0fb6_d000, RESERVED),
        r(0x0fb6_d000, 0x0fb7_f000, ACPI_RECLAIM),
        r(0x0fb7_f000, 0x0fbf_f000, ACPI_NVS),
        r(0x0fbf_f000, 0x0fef_4000, USABLE),
        r(0x0fef_4000, 0x0ff7_8000, FIRMWARE),
        r(0x0ff7_8000, 0x1000_0000, ACPI_NVS),
        r(0xe000_0000, 0xf000_0000, RESERVED),
        r(0x00fd_0000_0000, 0x0100_0000_0000, RESERVED),
    ];
    const QEMU_KERNEL: u64 = 0x0df8_1000;

    /// Hyper-V Generation 2 with 512 MiB: the map of the M0 boot log. The
    /// kernel was at `0x1ea31000` in the `LOADER` range; the M3 image, at
    /// the same address, still ends inside it.
    const HYPERV_MAP: [MemoryRegion; 10] = [
        r(0x0000_0000, 0x000a_0000, USABLE),
        r(0x000c_0000, 0x0010_0000, RESERVED),
        r(0x0010_0000, 0x1ea1_e000, USABLE),
        r(0x1ea1_e000, 0x1eb4_1000, LOADER),
        r(0x1eb4_1000, 0x1ff4_1000, USABLE),
        r(0x1ff4_1000, 0x1ffc_5000, FIRMWARE),
        r(0x1ffc_5000, 0x1ffd_4000, USABLE),
        r(0x1ffd_4000, 0x1fff_b000, ACPI_RECLAIM),
        r(0x1fff_b000, 0x1fff_f000, ACPI_NVS),
        r(0x1fff_f000, 0x2000_0000, USABLE),
    ];
    const HYPERV_KERNEL: u64 = 0x1ea3_1000;

    /// Both targets' direct map: `phys_map_size` is 4 GiB on each.
    const FOUR_GIB: u64 = 4 << 30;

    const LAPIC: u64 = 0xFEE0_0000;
    const IOAPIC: u64 = 0xFEC0_0000;
    const HPET: u64 = 0xFED0_0000;

    /// QEMU's kernel device pages: the local APIC, one I/O APIC, the HPET.
    fn qemu_window() -> DeviceWindow {
        let mut w = DeviceWindow::default();
        w.pages[LAPIC_PAGE] = Some(LAPIC);
        w.pages[ioapic_page(0)] = Some(IOAPIC);
        w.pages[HPET_PAGE] = Some(HPET);
        w
    }

    /// Hyper-V's: the local APIC and one I/O APIC at the same addresses as
    /// QEMU's, and no HPET (from memory; the MADT dump decides).
    fn hyperv_window() -> DeviceWindow {
        let mut w = DeviceWindow::default();
        w.pages[LAPIC_PAGE] = Some(LAPIC);
        w.pages[ioapic_page(0)] = Some(IOAPIC);
        w
    }

    /// What `kernel/linker.ld` makes of `text`, `rodata` and `data` bytes
    /// (`.data` and `.bss`, the tables included): text and the one-page
    /// `.hvcall` from `KERNEL_VIRT_BASE`, rodata from the next page, data
    /// from the page after rodata, then the stacks, each above a guard
    /// page: 64 KiB, then four of 8 KiB.
    fn linked(phys_base: u64, text: u64, rodata: u64, data: u64) -> KernelLayout {
        let text_end = KERNEL_VIRT_BASE + page_up(text) + PAGE_4K;
        let rodata_end = text_end + rodata;
        let data_start = page_up(rodata_end);
        let stacks = page_up(data_start + data);
        let mut guards = [stacks; 5];
        let mut at = stacks + PAGE_4K + (64 << 10);
        for g in &mut guards[1..] {
            *g = at;
            at += PAGE_4K + (8 << 10);
        }
        KernelLayout {
            phys_base,
            size: at - KERNEL_VIRT_BASE,
            text_start: KERNEL_VIRT_BASE,
            text_end,
            rodata_start: text_end,
            rodata_end,
            data_start,
            data_end: at,
            guards,
        }
    }

    /// The M3 debug kernel's sections as `nm` printed them: `.text` and
    /// `.hvcall` 36 KiB, `.rodata` to `+0xc06c`, `.data` and `.bss` from
    /// `+0xd000` to `+0x67990` with the tables at `+0xf000`, then the
    /// stacks; 532 KiB in all. Returns the layout and the tables' virtual
    /// address.
    fn m3_layout(phys_base: u64) -> (KernelLayout, u64) {
        let v = |off: u64| KERNEL_VIRT_BASE + off;
        let layout = KernelLayout {
            phys_base,
            size: 0x85000,
            text_start: v(0),
            text_end: v(0x9000),
            rodata_start: v(0x9000),
            rodata_end: v(0xc06c),
            data_start: v(0xd000),
            data_end: v(0x85000),
            guards: [v(0x68000), v(0x79000), v(0x7c000), v(0x7f000), v(0x82000)],
        };
        (layout, v(0xf000))
    }

    #[test]
    fn linked_reproduces_the_m3_kernel() {
        let (m3, _) = m3_layout(QEMU_KERNEL);
        assert_eq!(linked(QEMU_KERNEL, 0x8000, 0x306c, 0x5a990), m3);
        assert_eq!(m3.check(), Ok(()));
    }

    /// One build's inputs; the tables are at `tables_virt` in the image.
    struct Case<'a> {
        layout: KernelLayout,
        tables_virt: u64,
        regions: &'a [MemoryRegion],
        direct_map_end: u64,
        window: DeviceWindow,
    }

    impl Case<'_> {
        fn tables_phys(&self) -> u64 {
            self.layout.virt_to_phys(self.tables_virt)
        }

        fn input(&self) -> BuildInput<'_> {
            BuildInput {
                layout: &self.layout,
                regions: self.regions,
                direct_map_end: self.direct_map_end,
                window: &self.window,
            }
        }

        fn try_build(&self) -> (Box<KernelTables>, Result<BuildSummary, BuildError>) {
            let mut t = Box::new(KernelTables::new());
            let r = build(&mut t, self.tables_phys(), &self.input());
            (t, r)
        }

        fn build(&self) -> (Box<KernelTables>, BuildSummary) {
            let (t, r) = self.try_build();
            (t, r.expect("build"))
        }
    }

    fn qemu_case() -> Case<'static> {
        let (layout, tables_virt) = m3_layout(QEMU_KERNEL);
        Case {
            layout,
            tables_virt,
            regions: &QEMU_MAP,
            direct_map_end: FOUR_GIB,
            window: qemu_window(),
        }
    }

    fn hyperv_case() -> Case<'static> {
        let (layout, tables_virt) = m3_layout(HYPERV_KERNEL);
        Case {
            layout,
            tables_virt,
            regions: &HYPERV_MAP,
            direct_map_end: FOUR_GIB,
            window: hyperv_window(),
        }
    }

    /// A present leaf found by walking the tree from the PML4.
    struct Leaf {
        virt: u64,
        size: u64,
        entry: u64,
        tr: Translation,
    }

    fn sign_extend(v: u64) -> u64 {
        ((v as i64) << 16 >> 16) as u64
    }

    /// Every leaf reachable from the PML4, in virtual-address order. Checks
    /// on the way that every table is reached at most once and at its own
    /// level, that no table entry restricts (the leaves decide [H7]), that
    /// unreached tables are empty, and that `walk` agrees with each leaf.
    fn leaves(t: &KernelTables, tables_phys: u64) -> Vec<Leaf> {
        let mut reached = [false; TABLE_COUNT];
        let mut follow = |e: u64, level: u32| -> usize {
            assert_eq!(e & (PS | XD | US), 0, "table entry {e:#x}");
            assert_ne!(e & RW, 0, "table entry {e:#x} is read-only");
            assert_ne!(e & ACCESSED, 0, "table entry {e:#x}: the CPU would set A");
            let i = usize::try_from(((e & ADDR_4K) - tables_phys) / PAGE_4K).unwrap();
            let ok = match level {
                2 => [DIRECT_PDPT, IMAGE_PDPT].contains(&i),
                1 => (DIRECT_PDS..ALIAS_PTS).contains(&i) || [IMAGE_PD, WINDOW_PD].contains(&i),
                _ => {
                    (ALIAS_PTS..IMAGE_PDPT).contains(&i)
                        || (IMAGE_PTS..WINDOW_PD).contains(&i)
                        || i == WINDOW_PT
                }
            };
            assert!(ok, "table {i} reached at level {level}");
            assert!(!reached[i], "table {i} reached twice");
            reached[i] = true;
            i
        };
        let mut out = Vec::new();
        let mut leaf = |virt: u64, size: u64, entry: u64| {
            let tr = t.walk(tables_phys, virt).unwrap().unwrap();
            assert_eq!(tr.page_size, size);
            let mask = if size == PAGE_2M { ADDR_2M } else { ADDR_4K };
            assert_eq!(tr.phys, entry & mask);
            // The CPU never needs to set A or D in a kernel leaf.
            assert_ne!(entry & ACCESSED, 0, "leaf {entry:#x} at {virt:#x}");
            assert!(
                !tr.write || entry & DIRTY != 0,
                "leaf {entry:#x} at {virt:#x}"
            );
            out.push(Leaf {
                virt,
                size,
                entry,
                tr,
            });
        };
        for i4 in 0..ENTRIES {
            let e4 = t.tables[PML4][i4];
            if e4 & P == 0 {
                continue;
            }
            let pdpt = follow(e4, 2);
            for i3 in 0..ENTRIES {
                let e3 = t.tables[pdpt][i3];
                if e3 & P == 0 {
                    continue;
                }
                let pd = follow(e3, 1);
                for i2 in 0..ENTRIES {
                    let e2 = t.tables[pd][i2];
                    let base = sign_extend((i4 << 39 | i3 << 30 | i2 << 21) as u64);
                    if e2 & P == 0 {
                        continue;
                    } else if e2 & PS != 0 {
                        leaf(base, PAGE_2M, e2);
                        continue;
                    }
                    let pt = follow(e2, 0);
                    for i1 in 0..ENTRIES {
                        let e1 = t.tables[pt][i1];
                        if e1 & P != 0 {
                            leaf(base | (i1 as u64) << 12, PAGE_4K, e1);
                        }
                    }
                }
            }
        }
        for (i, table) in t.tables.iter().enumerate() {
            if i != PML4 && !reached[i] {
                assert!(
                    table.iter().all(|&e| e == 0),
                    "unreached table {i} is not empty"
                );
            }
        }
        out
    }

    /// Whether `[base, base + size)` overlaps a RAM-like region, with the
    /// kinds spelled out again rather than taken from `is_ram_like`.
    fn overlaps_ram(regions: &[MemoryRegion], base: u64, size: u64) -> bool {
        let ram = [USABLE, LOADER, ACPI_RECLAIM, ACPI_NVS, FIRMWARE];
        regions
            .iter()
            .any(|r| ram.contains(&r.kind) && r.len > 0 && r.base < base + size && r.end() > base)
    }

    /// Advances `at` past any of `guards`.
    fn skip_guards(mut at: u64, guards: &[u64]) -> u64 {
        while guards.contains(&at) {
            at += PAGE_4K;
        }
        at
    }

    /// Builds `c` and checks every row of "Privilege levels" that the
    /// tables carry, leaf by leaf.
    fn check_invariants(c: &Case<'_>) -> BuildSummary {
        let (t, summary) = c.build();
        let tables_phys = c.tables_phys();
        let layout = &c.layout;
        let image = layout.phys();
        let dme = c.direct_map_end;
        let devices: Vec<u64> = c.window.pages.iter().flatten().copied().collect();
        let guard_phys: Vec<u64> = layout
            .guards
            .iter()
            .map(|&g| layout.virt_to_phys(g))
            .collect();

        // Every upper-half entry is supervisor-only; the lower half and
        // PML4 slots 257 to 510 are empty.
        for (i, table) in t.tables.iter().enumerate() {
            for (j, &e) in table.iter().enumerate() {
                assert_eq!(e & US, 0, "table {i} entry {j} is user-accessible");
            }
        }
        for (i, &e) in t.tables[PML4].iter().enumerate() {
            assert_eq!(e & P != 0, i == 256 || i == 511, "PML4 entry {i}");
        }

        let all = leaves(&t, tables_phys);
        let mut direct_cursor = 0;
        let mut image_cursor = KERNEL_VIRT_BASE;
        for l in &all {
            let (v, tr) = (l.virt, l.tr);
            // Kernel leaves are global and supervisor-only; none is
            // writable and executable.
            assert!(tr.global && !tr.user, "leaf at {v:#x}");
            assert!(!(tr.write && tr.execute), "W+X leaf at {v:#x}");
            // No leaf holding a kernel device page is cacheable.
            if devices
                .iter()
                .any(|&d| d >= tr.phys && d < tr.phys + l.size)
            {
                assert_eq!(tr.cache, CacheType::Uncached, "device page at {v:#x}");
            }
            // Every alias of the image is as strict as its section says:
            // text and rodata read-only, data NX, guard pages nowhere; and
            // every alias is WB.
            let mut p = tr.phys;
            while p < tr.phys + l.size {
                if image.contains(p) {
                    match layout
                        .section_of(p - image.start + KERNEL_VIRT_BASE)
                        .unwrap()
                    {
                        Section::Text | Section::Rodata => {
                            assert!(!tr.write, "writable alias of {p:#x} at {v:#x}")
                        }
                        Section::Data => {
                            assert!(!tr.execute, "executable alias of {p:#x} at {v:#x}")
                        }
                        Section::Guard => panic!("guard page {p:#x} mapped at {v:#x}"),
                    }
                    assert_eq!(tr.cache, CacheType::WriteBack);
                }
                p += PAGE_4K;
            }

            if (PHYS_MAP_BASE..PHYS_MAP_BASE + (512 << 30)).contains(&v) {
                // The direct map: [0, dme) at PHYS_MAP_BASE, contiguous but
                // for the guard pages, NX, 4 KiB pages exactly over the
                // image's 2 MiB pages, read-only only inside the image.
                let phys = v - PHYS_MAP_BASE;
                assert_eq!(tr.phys, phys);
                direct_cursor = skip_guards(direct_cursor, &guard_phys);
                assert_eq!(phys, direct_cursor, "direct map hole or overlap");
                direct_cursor += l.size;
                assert!(!tr.execute, "executable direct-map page {phys:#x}");
                let page_2m = phys & !(PAGE_2M - 1);
                let touches_image = image.start < page_2m + PAGE_2M && image.end > page_2m;
                assert_eq!(l.size == PAGE_4K, touches_image, "page size at {phys:#x}");
                if !image.contains(phys) {
                    assert!(tr.write, "read-only direct-map page {phys:#x}");
                }
                // WB exactly when the 2 MiB page has RAM and no device page.
                let device = devices.iter().any(|&d| d & !(PAGE_2M - 1) == page_2m);
                let wb = overlaps_ram(c.regions, page_2m, PAGE_2M) && !device;
                let want = if wb {
                    CacheType::WriteBack
                } else {
                    CacheType::Uncached
                };
                assert_eq!(tr.cache, want, "cache type of direct-map page {phys:#x}");
            } else if layout.virt().contains(v) {
                // The image: every page but the guards, in order, WB, with
                // its section's rights.
                image_cursor = skip_guards(image_cursor, &layout.guards);
                assert_eq!(v, image_cursor, "image hole or overlap");
                image_cursor += PAGE_4K;
                assert_eq!(l.size, PAGE_4K);
                assert_eq!(tr.phys, layout.virt_to_phys(v));
                let (w, x) = match layout.section_of(v).unwrap() {
                    Section::Text => (false, true),
                    Section::Rodata => (false, false),
                    Section::Data => (true, false),
                    Section::Guard => unreachable!("walked to a guard page"),
                };
                assert_eq!((tr.write, tr.execute), (w, x), "image page {v:#x}");
                assert_eq!(tr.cache, CacheType::WriteBack);
            } else if v >= KERNEL_DEVICE_BASE {
                // The device window: exactly its pages, RW, NX, UC through
                // PAT index 3 (PCD and PWT, not PAT).
                let i = ((v - KERNEL_DEVICE_BASE) / PAGE_4K) as usize;
                assert_eq!(Some(tr.phys), c.window.pages.get(i).copied().flatten());
                assert_eq!(l.size, PAGE_4K);
                assert!(tr.write && !tr.execute);
                assert_eq!(l.entry & (PAT_4K | PCD | PWT), PCD | PWT);
                assert_eq!(tr.cache, CacheType::Uncached);
            } else {
                panic!("unexpected leaf at {v:#x}");
            }
        }
        assert_eq!(
            skip_guards(direct_cursor, &guard_phys),
            dme,
            "direct map end"
        );
        assert_eq!(skip_guards(image_cursor, &layout.guards), layout.virt().end);
        let window_leaves = all.iter().filter(|l| l.virt >= KERNEL_DEVICE_BASE).count();
        assert_eq!(window_leaves, devices.len());
        assert_eq!(summary.window_pages, devices.len());
        assert_eq!(
            summary.direct_wb + summary.direct_uc,
            (dme / PAGE_2M) as usize
        );

        // Spot checks with the walk: nothing above the direct map's end,
        // below or past the image, or in the lower half.
        let walk = |v| t.walk(tables_phys, v).unwrap();
        for v in [
            PHYS_MAP_BASE + dme,
            PHYS_MAP_BASE + DIRECT_MAP_MAX,
            PHYS_MAP_BASE + (512 << 30) - PAGE_4K,
            KERNEL_VIRT_BASE - PAGE_4K,
            KERNEL_VIRT_BASE + layout.size,
            KERNEL_VIRT_BASE + KERNEL_IMAGE_MAX,
            KERNEL_DEVICE_BASE - PAGE_4K,
            0,
            0x20_0000,
            layout.phys_base,
            0x0000_7FFF_FFFF_F000,
        ] {
            assert_eq!(walk(v), None, "{v:#x} is mapped");
        }
        assert!(walk(PHYS_MAP_BASE + dme - PAGE_4K).is_some());
        summary
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn qemu_tables_keep_every_invariant() {
        // The image straddles 0xe000000, so two 2 MiB pages of the direct
        // map need page tables.
        let s = check_invariants(&qemu_case());
        assert_eq!((s.alias_pts, s.image_pts, s.window_pages), (2, 1, 3));
        // RAM is the first 256 MiB: 128 WB pages; the rest of 4 GiB is UC.
        assert_eq!((s.direct_wb, s.direct_uc), (128, 2048 - 128));
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn hyperv_tables_keep_every_invariant() {
        let s = check_invariants(&hyperv_case());
        assert_eq!((s.alias_pts, s.image_pts, s.window_pages), (1, 1, 2));
        assert_eq!((s.direct_wb, s.direct_uc), (256, 2048 - 256));
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn a_16_mib_image_needs_nine_alias_tables() {
        // 16 MiB at a 4 KiB boundary touches nine 2 MiB pages.
        let layout = linked(0x0100_1000, 0x10_0000, 0x40_0000, 0xAE_2000);
        assert_eq!(layout.size, KERNEL_IMAGE_MAX);
        let regions = [
            r(0, 0x0100_0000, USABLE),
            r(0x0100_0000, 0x0300_0000, LOADER),
            r(0x0300_0000, 0x4000_0000, USABLE),
        ];
        let c = Case {
            tables_virt: layout.data_start,
            layout,
            regions: &regions,
            direct_map_end: FOUR_GIB,
            window: qemu_window(),
        };
        let s = check_invariants(&c);
        assert_eq!((s.alias_pts, s.image_pts), (ALIAS_PT_COUNT, IMAGE_PT_COUNT));
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn a_64_gib_direct_map_uses_every_page_directory() {
        // A machine with 70 GiB of RAM: the loader maps 512 GiB, the kernel
        // 64, and the image sits just below the top.
        let (layout, tables_virt) = m3_layout(DIRECT_MAP_MAX - 0x10_0000);
        let regions = [r(0x10_0000, 70 << 30, USABLE)];
        let c = Case {
            layout,
            tables_virt,
            regions: &regions,
            direct_map_end: DIRECT_MAP_MAX,
            window: qemu_window(),
        };
        let s = check_invariants(&c);
        assert_eq!(s.direct_wb + s.direct_uc, DIRECT_PD_COUNT * ENTRIES);
        // Only the 2 MiB pages of the I/O APIC and HPET (0xFEC00000 and
        // 0xFED00000 share one) and of the local APIC are UC.
        assert_eq!(s.direct_uc, 2);
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn rebuilding_over_garbage_gives_the_same_tables() {
        let c = hyperv_case();
        let (fresh, _) = c.build();
        let mut t = Box::new(KernelTables::new());
        for (i, table) in t.tables.iter_mut().enumerate() {
            table.fill(0xDEAD_0000_0000_0000 | i as u64);
        }
        build(&mut t, c.tables_phys(), &c.input()).unwrap();
        assert!(t.tables == fresh.tables);
    }

    #[test]
    fn pat_msr_is_the_design_table() {
        use CacheType::*;
        let want = [
            WriteBack,
            WriteThrough,
            UncachedMinus,
            Uncached,
            WriteCombining,
        ];
        for (i, &ty) in want.iter().enumerate() {
            assert_eq!(CacheType::from_pat_index(i as u8), ty);
            assert_eq!(ty.pat_index() as usize, i);
            assert_eq!(CacheType::from_encoding(ty.encoding()), Some(ty));
        }
        // Entries 0 to 4 are seL4's (`init_pat_msr`): WB, WT, UC-, UC, WC.
        assert_eq!(PAT_MSR & 0xFF_FFFF_FFFF, 0x01_0007_0406);
        // Entries 5 to 7 keep their power-on values, WT, UC- and UC; QEMU
        // reads 0x0007040600070406 before the kernel writes the MSR.
        let power_on: u64 = 0x0007_0406_0007_0406;
        assert_eq!(PAT_MSR >> 40, power_on >> 40);
        assert_eq!(
            [5, 6, 7].map(CacheType::from_pat_index),
            [WriteThrough, UncachedMinus, Uncached]
        );
        // Write-protected (05h) is not a type the kernel uses.
        assert_eq!(CacheType::from_encoding(0x05), None);
    }

    #[test]
    fn pat_index_bits_sit_where_the_sdm_says() {
        use CacheType::*;
        assert_eq!(WriteBack.pte_bits(), 0);
        assert_eq!(Uncached.pte_bits(), PCD | PWT);
        assert_eq!(Uncached.pde_2m_bits(), PCD | PWT);
        assert_eq!(WriteCombining.pte_bits(), 1 << 7);
        assert_eq!(WriteCombining.pde_2m_bits(), 1 << 12);
        for ty in [
            WriteBack,
            WriteThrough,
            UncachedMinus,
            Uncached,
            WriteCombining,
        ] {
            let e = kernel_pte(0x1000, KernelAccess::Read, ty);
            assert_eq!(CacheType::of_leaf(e, PAT_4K), ty);
            let e = kernel_pde_2m(PAGE_2M, KernelAccess::Read, ty);
            assert_eq!(CacheType::of_leaf(e, PAT_2M), ty);
            // Bit 7 of a 2 MiB PDE is PS, never the PAT bit.
            assert_ne!(e & PS, 0);
        }
    }

    #[test]
    fn kernel_leaves_are_global_supervisor_and_never_wx() {
        use KernelAccess::*;
        // Accessed is preset everywhere and Dirty on writable pages, so the
        // CPU never writes the kernel's tables.
        let a = ACCESSED;
        for (access, bits) in [(Read, XD), (ReadWrite, RW | XD | DIRTY), (ReadExecute, 0)] {
            let e = kernel_pte(0x1234_5000, access, CacheType::WriteBack);
            assert_eq!(e, 0x1234_5000 | P | G | a | bits);
            let e = kernel_pde_2m(0x1240_0000, access, CacheType::Uncached);
            assert_eq!(e, 0x1240_0000 | P | PS | G | a | bits | PCD | PWT);
        }
        assert_eq!(kernel_table(0xABC_D000), 0xABC_D000 | P | RW | a);
    }

    #[test]
    fn user_leaves_are_user_and_never_global() {
        let rx = UserAccess {
            write: false,
            execute: true,
        };
        let rw = UserAccess {
            write: true,
            execute: false,
        };
        let a = user_pte(0x5000, rx, CacheType::WriteBack);
        assert_eq!(a, 0x5000 | P | US);
        let b = user_pte(0x5000, rw, CacheType::WriteCombining);
        assert_eq!(b, 0x5000 | P | US | RW | XD | PAT_4K);
        let c = user_pde_2m(0x40_0000, rw, CacheType::Uncached);
        assert_eq!(c, 0x40_0000 | P | PS | US | RW | XD | PCD | PWT);
        assert_eq!(user_table(0x7000), 0x7000 | P | RW | US);
        for e in [a, b, c] {
            assert_eq!(e & G, 0);
        }
    }

    #[test]
    #[should_panic(expected = "misaligned")]
    fn a_misaligned_4k_page_panics() {
        kernel_pte(0x1001_0800, KernelAccess::Read, CacheType::WriteBack);
    }

    #[test]
    #[should_panic(expected = "misaligned")]
    fn a_misaligned_2m_page_panics() {
        let ro = UserAccess {
            write: false,
            execute: false,
        };
        user_pde_2m(0x1000, ro, CacheType::WriteBack);
    }

    #[test]
    #[should_panic(expected = "too wide")]
    fn an_address_above_52_bits_panics() {
        kernel_table(1 << 52);
    }

    #[test]
    fn direct_map_types_on_qemu() {
        use CacheType::*;
        let w = qemu_window();
        let ty = |p| direct_map_type(&QEMU_MAP, &w, p);
        // RAM with the legacy hole at 0xA0000: WB, relying on the MTRRs.
        assert_eq!(ty(0), WriteBack);
        // ACPI NVS and firmware ranges are RAM-like.
        assert_eq!(ty(0x0080_0000), WriteBack);
        assert_eq!(ty(0x0FE0_0000), WriteBack);
        // Beyond RAM, the framebuffer's gap, ECAM, and the device pages.
        assert_eq!(ty(0x1000_0000), Uncached);
        assert_eq!(ty(0x8000_0000), Uncached);
        assert_eq!(ty(0xE000_0000), Uncached);
        assert_eq!(ty(IOAPIC & !(PAGE_2M - 1)), Uncached);
        assert_eq!(ty(LAPIC & !(PAGE_2M - 1)), Uncached);
        assert_eq!(ty(FOUR_GIB - PAGE_2M), Uncached);
    }

    #[test]
    fn direct_map_types_by_rule() {
        use CacheType::*;
        let none = DeviceWindow::default();
        let one = |kind| [r(0x20_0000, 0x40_0000, kind)];
        for kind in [USABLE, LOADER, ACPI_RECLAIM, ACPI_NVS, FIRMWARE] {
            assert!(is_ram_like(kind));
            assert_eq!(direct_map_type(&one(kind), &none, 0x20_0000), WriteBack);
        }
        let not_ram = [
            RESERVED,
            RegionKind::MMIO,
            RegionKind::BAD,
            RegionKind(0),
            RegionKind(99),
        ];
        for kind in not_ram {
            assert!(!is_ram_like(kind));
            assert_eq!(direct_map_type(&one(kind), &none, 0x20_0000), Uncached);
        }
        // Touching is not overlapping; empty regions count for nothing; one
        // RAM page in 2 MiB is enough; the order of the map does not matter.
        let map = [
            r(0x60_0000, 0x60_1000, USABLE),
            r(0x40_0000, 0x40_0000, USABLE),
            r(0x20_0000, 0x40_0000, RESERVED),
            r(0, 0x20_0000, USABLE),
        ];
        assert_eq!(direct_map_type(&map, &none, 0), WriteBack);
        assert_eq!(direct_map_type(&map, &none, 0x20_0000), Uncached);
        assert_eq!(direct_map_type(&map, &none, 0x40_0000), Uncached);
        assert_eq!(direct_map_type(&map, &none, 0x60_0000), WriteBack);
        // A kernel device page in RAM makes its 2 MiB page UC, and only it.
        let mut w = DeviceWindow::default();
        w.pages[LAPIC_PAGE] = Some(0x7F_F000);
        assert_eq!(direct_map_type(&map, &w, 0x60_0000), Uncached);
        assert_eq!(direct_map_type(&map, &w, 0), WriteBack);
    }

    #[test]
    #[should_panic(expected = "unaligned")]
    fn direct_map_type_wants_a_2m_page() {
        direct_map_type(&QEMU_MAP, &qemu_window(), 0x1000);
    }

    /// The error `c`'s build returns, after checking that the refusal left
    /// the tables untouched.
    fn build_err(c: &Case<'_>) -> BuildError {
        let (t, r) = c.try_build();
        assert!(t.tables.iter().all(|table| table.iter().all(|&e| e == 0)));
        r.unwrap_err()
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn the_image_must_not_share_a_2m_page_with_a_device() {
        // A device page below the image, in its first 2 MiB page.
        let mut c = hyperv_case();
        let dev = (HYPERV_KERNEL & !(PAGE_2M - 1)) + 0x1000;
        c.window.pages[HPET_PAGE] = Some(dev);
        assert_eq!(build_err(&c), BuildError::ImageSharesDevicePage(dev));
        // One in the last 2 MiB page of the QEMU image, which straddles a
        // boundary.
        let mut c = qemu_case();
        let dev = (c.layout.phys().end - 1) & !(PAGE_2M - 1);
        c.window.pages[ioapic_page(3)] = Some(dev);
        assert_eq!(build_err(&c), BuildError::ImageSharesDevicePage(dev));
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn the_image_must_be_in_ram() {
        let map = [
            r(0, 0x1E00_0000, USABLE),
            r(0x1E00_0000, 0x2000_0000, RESERVED),
        ];
        let c = Case {
            regions: &map,
            ..hyperv_case()
        };
        assert_eq!(build_err(&c), BuildError::ImageNotInRam(0x1EA0_0000));
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn the_image_must_fit() {
        let layout = linked(0x0100_0000, 0x10_0000, 0x40_0000, 0xAE_3000);
        assert_eq!(layout.size, KERNEL_IMAGE_MAX + PAGE_4K);
        let c = Case {
            tables_virt: layout.data_start,
            layout,
            regions: &[r(0, 0x4000_0000, USABLE)],
            direct_map_end: FOUR_GIB,
            window: qemu_window(),
        };
        assert_eq!(
            build_err(&c),
            BuildError::ImageTooLarge(KERNEL_IMAGE_MAX + PAGE_4K)
        );

        let c = Case {
            direct_map_end: 0x1EA0_0000,
            ..hyperv_case()
        };
        assert_eq!(build_err(&c), BuildError::ImageOutsideDirectMap);
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn the_direct_map_end_must_be_usable() {
        for end in [0, FOUR_GIB + PAGE_4K, DIRECT_MAP_MAX + PAGE_2M, 512 << 30] {
            let c = Case {
                direct_map_end: end,
                ..hyperv_case()
            };
            assert_eq!(build_err(&c), BuildError::BadDirectMapEnd(end));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn the_tables_must_be_in_the_image_data() {
        let good = hyperv_case();
        for virt in [
            KERNEL_VIRT_BASE,
            good.layout.rodata_start,
            good.layout.data_start - PAGE_4K,
            good.tables_virt + 8,
            good.layout.data_end - PAGE_4K,
        ] {
            let c = Case {
                tables_virt: virt,
                ..hyperv_case()
            };
            let phys = c.layout.virt_to_phys(virt);
            assert_eq!(build_err(&c), BuildError::TablesOutsideImage(phys));
        }
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn device_pages_must_be_page_addresses() {
        let mut c = qemu_case();
        c.window.pages[HPET_PAGE] = Some(HPET + 0xF0);
        assert_eq!(build_err(&c), BuildError::BadDevicePage(HPET + 0xF0));
        c.window.pages[HPET_PAGE] = Some(1 << 52);
        assert_eq!(build_err(&c), BuildError::BadDevicePage(1 << 52));
    }

    #[test]
    fn layouts_are_checked() {
        let (good, _) = m3_layout(HYPERV_KERNEL);
        let check = |f: fn(&mut KernelLayout)| {
            let mut l = good;
            f(&mut l);
            l.check()
        };
        let bad = |f| matches!(check(f), Err(BuildError::BadLayout(_)));
        assert_eq!(check(|_| {}), Ok(()));
        assert!(bad(|l| l.phys_base += 0x800));
        assert!(bad(|l| l.phys_base = 1 << 52));
        assert!(bad(|l| l.size += 0x800));
        assert!(bad(|l| l.size = 0));
        assert!(bad(|l| l.text_start += PAGE_4K));
        assert!(bad(|l| l.rodata_start += PAGE_4K));
        assert!(bad(|l| l.data_start += PAGE_4K));
        assert!(bad(|l| l.rodata_end = l.data_start + 1));
        assert!(bad(|l| l.data_end -= PAGE_4K));
        assert!(bad(|l| l.guards[2] = l.guards[1]));
        assert!(bad(|l| l.guards[0] = l.rodata_start));
        assert!(bad(|l| l.guards[4] = l.data_end));
        assert!(bad(|l| l.guards[3] += 8));
        assert_eq!(good.section_of(KERNEL_VIRT_BASE), Some(Section::Text));
        assert_eq!(good.section_of(good.text_end - 1), Some(Section::Text));
        assert_eq!(good.section_of(good.rodata_end), Some(Section::Rodata));
        assert_eq!(good.section_of(good.data_start), Some(Section::Data));
        assert_eq!(
            good.section_of(good.guards[0] + 0xFFF),
            Some(Section::Guard)
        );
        assert_eq!(good.section_of(good.data_end), None);
        assert_eq!(good.section_of(KERNEL_VIRT_BASE - 1), None);
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn walk_reports_broken_tables() {
        let c = hyperv_case();
        let phys = c.tables_phys();
        let (mut t, _) = c.build();
        let at = PHYS_MAP_BASE + PD_SPAN;
        let hole = 0x0000_8000_0000_0000;
        assert_eq!(t.walk(phys, hole), Err(WalkError::NonCanonical(hole)));
        t.tables[DIRECT_PDPT][1] = kernel_table(0x1000);
        assert_eq!(t.walk(phys, at), Err(WalkError::OutsideTables(0x1000)));
        let past = KernelTables::table_phys(phys, TABLE_COUNT);
        t.tables[DIRECT_PDPT][1] = kernel_table(past);
        assert_eq!(t.walk(phys, at), Err(WalkError::OutsideTables(past)));
        t.tables[DIRECT_PDPT][1] |= PS;
        assert_eq!(t.walk(phys, at), Err(WalkError::UnexpectedPageSize(at)));
    }

    #[test]
    #[cfg_attr(miri, ignore = "builds 348 KiB of tables: minutes under Miri")]
    fn walk_combines_rights_over_levels() {
        // R/W and U/S are the AND over the walk, XD the OR [H7].
        let c = hyperv_case();
        let phys = c.tables_phys();
        let (mut t, _) = c.build();
        let at = PHYS_MAP_BASE + 0x1234_5678;
        let tr = t.walk(phys, at).unwrap().unwrap();
        assert_eq!((tr.phys, tr.page_size), (0x1234_5678, PAGE_2M));
        assert!(tr.write && !tr.execute && !tr.user && tr.global);
        let pde = &mut t.tables[DIRECT_PDS][index(at, 1)];
        *pde = (*pde & !XD) | US;
        assert!(t.walk(phys, at).unwrap().unwrap().execute);
        assert!(!t.walk(phys, at).unwrap().unwrap().user);
        t.tables[DIRECT_PDPT][0] |= XD | US;
        t.tables[DIRECT_PDPT][0] &= !RW;
        let tr = t.walk(phys, at).unwrap().unwrap();
        assert!(!tr.write && !tr.execute && !tr.user);
        t.tables[PML4][256] |= US;
        assert!(t.walk(phys, at).unwrap().unwrap().user);
    }

    #[test]
    fn errors_display() {
        use std::string::ToString;
        let s = BuildError::ImageSharesDevicePage(0xFEE0_0000).to_string();
        assert_eq!(
            s,
            "kernel image shares a 2 MiB page with device page 0xfee00000"
        );
        assert!(BuildError::BadLayout("gap").to_string().ends_with("gap"));
    }
}
