//! The ACPI tables the kernel reads (`docs/design.md`, "ACPI and the
//! timer"): the RSDP, the XSDT (the RSDT for revision 0), the MADT, the HPET
//! table and the MCFG.
//!
//! [`parse`] runs once at boot, through a [`PhysRead`] the kernel implements
//! over the direct map, and returns a fixed-size [`Platform`]. Every read is
//! a bounds-checked byte read; nothing casts table memory, so `core` needs no
//! `unsafe`. No input makes the parser panic or read outside a validated
//! table, and every loop is bounded by a validated length, so it terminates.
//! Layouts follow ACPI 6.5; the host tests check them against tables dumped
//! from QEMU and Hyper-V ([`dump`], `core/tests/acpi/`).

use core::fmt;

use crate::window::{self, DeviceWindow, MAX_IOAPICS};

pub mod dump;

#[cfg(test)]
mod tests;

/// Bounds-checked byte reads of physical memory.
pub trait PhysRead {
    /// The byte at physical address `addr`, or `None` if it lies outside
    /// what this reader can read.
    fn read_u8(&self, addr: u64) -> Option<u8>;
}

impl<T: PhysRead + ?Sized> PhysRead for &T {
    fn read_u8(&self, addr: u64) -> Option<u8> {
        (**self).read_u8(addr)
    }
}

/// The longest table the parser accepts.
pub const MAX_TABLE_LEN: u32 = 1 << 20;
/// Tables [`Platform::tables`] lists; later ones are parsed but not listed.
pub const MAX_TABLES: usize = 32;
/// Interrupt source overrides kept; later ones are dropped with a warning.
pub const MAX_OVERRIDES: usize = 16;
/// ECAM ranges kept; later ones are dropped with a warning.
pub const MAX_ECAM: usize = 4;
/// Warnings kept; [`Platform::warnings_dropped`] counts the rest.
pub const MAX_WARNINGS: usize = 16;
/// The MADT flag saying the machine also has dual 8259 PICs.
pub const PCAT_COMPAT: u32 = 1 << 0;

/// The common table header: signature, length, revision, checksum, OEM and
/// creator fields.
const HEADER_LEN: u32 = 36;
/// RSDP: the ACPI 1.0 part, then the whole revision-2 structure, and the
/// longest `length` accepted.
const RSDP_V1_LEN: u32 = 20;
const RSDP_V2_LEN: u32 = 36;
const RSDP_MAX_LEN: u32 = 4096;
/// The MADT's entries start after the LAPIC address and the flags.
const MADT_ENTRIES: u32 = 44;
/// The HPET table has a fixed length.
const HPET_LEN: u32 = 56;
/// The MCFG's entries start after 8 reserved bytes, 16 bytes each.
const MCFG_ENTRIES: u32 = 44;
const MCFG_ENTRY_LEN: u32 = 16;
/// The HPET's register block.
const HPET_REGS: u64 = 0x400;

/// MADT entry types the parser reads, and the length each needs.
const MADT_LOCAL_APIC: u8 = 0;
const MADT_IO_APIC: u8 = 1;
const MADT_OVERRIDE: u8 = 2;
const MADT_LAPIC_ADDRESS: u8 = 5;
const MADT_LOCAL_X2APIC: u8 = 9;

fn madt_min_len(kind: u8) -> Option<u32> {
    match kind {
        MADT_LOCAL_APIC => Some(8),
        MADT_IO_APIC => Some(12),
        MADT_OVERRIDE => Some(10),
        MADT_LAPIC_ADDRESS => Some(12),
        MADT_LOCAL_X2APIC => Some(16),
        _ => None,
    }
}

/// A table signature. Displays as text, with `?` for any byte that is not
/// printable ASCII, so a log line never holds a space or control byte from
/// one.
#[derive(Clone, Copy, PartialEq, Eq, Default)]
pub struct Signature(pub [u8; 4]);

impl Signature {
    pub const RSDT: Self = Self(*b"RSDT");
    pub const XSDT: Self = Self(*b"XSDT");
    pub const MADT: Self = Self(*b"APIC");
    pub const HPET: Self = Self(*b"HPET");
    pub const MCFG: Self = Self(*b"MCFG");
    pub const FADT: Self = Self(*b"FACP");
}

impl fmt::Display for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for &b in &self.0 {
            let c = if b.is_ascii_graphic() { b as char } else { '?' };
            fmt::Write::write_char(f, c)?;
        }
        Ok(())
    }
}

impl fmt::Debug for Signature {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Signature(\"{self}\")")
    }
}

/// Why a table failed validation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Fault {
    /// Its signature and length cannot be read.
    Unreadable,
    /// The RSDP does not start with `"RSD PTR "`.
    NotRsdp,
    /// Another table's signature.
    Signature(Signature),
    /// `length` below the table's minimum or above [`MAX_TABLE_LEN`] (for
    /// the RSDP, outside 36 to 4096).
    Length(u32),
    /// `[address, address + length)` overflows or leaves readable memory.
    OutOfRange,
    /// The bytes do not sum to zero: the first 20 for the RSDP.
    Checksum,
    /// The RSDP's bytes up to its `length` do not sum to zero.
    ExtendedChecksum,
    /// The RSDP names no root table.
    NullRoot,
    /// The entry area is not a whole number of entries.
    Entries,
    /// A MADT entry with a length below 2 or past the table's end, at this
    /// offset.
    MadtEntry(u32),
}

impl fmt::Display for Fault {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Unreadable => f.write_str("header cannot be read"),
            Self::NotRsdp => f.write_str("no \"RSD PTR \" signature"),
            Self::Signature(s) => write!(f, "signature \"{s}\""),
            Self::Length(n) => write!(f, "length {n}"),
            Self::OutOfRange => f.write_str("outside readable memory"),
            Self::Checksum => f.write_str("bad checksum"),
            Self::ExtendedChecksum => f.write_str("bad extended checksum"),
            Self::NullRoot => f.write_str("root table address is 0"),
            Self::Entries => f.write_str("entry area is not whole entries"),
            Self::MadtEntry(off) => write!(f, "malformed entry at offset {off}"),
        }
    }
}

/// Why [`parse`] failed. The kernel panics on each: without the MADT it
/// cannot route interrupts, and a device page missing from the window would
/// become device untyped (`docs/design.md`, Tables and validation).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AcpiError {
    /// The loader found no RSDP.
    NoRsdp,
    /// The RSDP is invalid.
    Rsdp { address: u64, fault: Fault },
    /// The XSDT, or the RSDT for revision 0, is invalid.
    Root {
        signature: Signature,
        address: u64,
        fault: Fault,
    },
    /// The root table lists no MADT.
    NoMadt,
    /// The MADT is invalid.
    Madt { address: u64, fault: Fault },
    /// The MADT lists more than [`MAX_IOAPICS`] I/O APICs.
    TooManyIoApics,
    /// The root table lists two MADTs or two HPET tables.
    Duplicate {
        signature: Signature,
        first: u64,
        second: u64,
    },
}

impl fmt::Display for AcpiError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoRsdp => f.write_str("no RSDP"),
            Self::Rsdp { address, fault } => write!(f, "RSDP at {address:#x}: {fault}"),
            Self::Root {
                signature,
                address,
                fault,
            } => write!(f, "{signature} at {address:#x}: {fault}"),
            Self::NoMadt => f.write_str("no MADT"),
            Self::Madt { address, fault } => write!(f, "MADT at {address:#x}: {fault}"),
            Self::TooManyIoApics => write!(f, "more than {MAX_IOAPICS} I/O APICs"),
            Self::Duplicate {
                signature,
                first,
                second,
            } => write!(f, "two {signature} tables, at {first:#x} and {second:#x}"),
        }
    }
}

/// Something the parser skipped or dropped; the boot log prints each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Warning {
    /// A root-table entry whose header cannot be read, or 0; skipped.
    Unreadable { address: u64 },
    /// A table listed again at the same address; the repeat is skipped.
    Repeated { signature: Signature, address: u64 },
    /// Tables the root lists beyond [`MAX_TABLES`]; parsed, not listed.
    Unlisted { count: u32 },
    /// The HPET table or the MCFG failed validation and counts as absent.
    BadTable {
        signature: Signature,
        address: u64,
        fault: Fault,
    },
    /// A second MCFG at another address; ignored.
    ExtraMcfg { address: u64 },
    /// A MADT entry of a type the parser reads, shorter than that type's
    /// layout; skipped, as seL4's `acpi_madt_valid` does.
    ShortEntry { kind: u8, length: u8 },
    /// An I/O APIC entry with address 0; skipped.
    NullIoApic { id: u8 },
    /// An interrupt source override for a bus other than ISA (0); skipped.
    NonIsaOverride { bus: u8, source: u8 },
    /// Override flags with a reserved polarity or trigger mode; the ISA
    /// default stands in for the reserved field.
    ReservedFlags { source: u8, flags: u16 },
    /// An override beyond [`MAX_OVERRIDES`]; dropped.
    OverrideDropped { source: u8, gsi: u32 },
    /// The HPET's registers are not in system memory; no HPET.
    HpetNotMemory { space: u8 },
    /// The HPET's base is 0 or not below 2^52, the architectural limit of a
    /// physical address, or its 1 KiB register block crosses a page; no
    /// HPET.
    HpetBase { base: u64 },
    /// An ECAM range with a reversed bus range or a region that overflows;
    /// dropped (`docs/abi.md`, `Ecam`).
    BadEcam {
        base: u64,
        segment: u16,
        start_bus: u8,
        end_bus: u8,
    },
    /// An ECAM range beyond [`MAX_ECAM`]; dropped.
    EcamDropped { base: u64, segment: u16 },
}

impl fmt::Display for Warning {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Unreadable { address } => {
                write!(f, "table at {address:#x} cannot be read; skipped")
            }
            Self::Repeated { signature, address } => {
                write!(f, "{signature} at {address:#x} listed again; skipped")
            }
            Self::Unlisted { count } => write!(f, "{count} more tables, not listed"),
            Self::BadTable {
                signature,
                address,
                fault,
            } => write!(f, "{signature} at {address:#x}: {fault}; ignored"),
            Self::ExtraMcfg { address } => write!(f, "second MCFG at {address:#x}; ignored"),
            Self::ShortEntry { kind, length } => {
                write!(f, "MADT entry type {kind} of length {length}; skipped")
            }
            Self::NullIoApic { id } => write!(f, "I/O APIC {id} at address 0; skipped"),
            Self::NonIsaOverride { bus, source } => {
                write!(f, "override for bus {bus} source {source}; skipped")
            }
            Self::ReservedFlags { source, flags } => write!(
                f,
                "override for ISA IRQ {source} has reserved flags {flags:#x}"
            ),
            Self::OverrideDropped { source, gsi } => write!(
                f,
                "more than {MAX_OVERRIDES} overrides; ISA IRQ {source} -> GSI {gsi} dropped"
            ),
            Self::HpetNotMemory { space } => {
                write!(f, "HPET in address space {space}, not memory; no HPET")
            }
            Self::HpetBase { base } => write!(f, "HPET base {base:#x} unusable; no HPET"),
            Self::BadEcam {
                base,
                segment,
                start_bus,
                end_bus,
            } => write!(
                f,
                "ECAM segment {segment} buses {start_bus}-{end_bus} at {base:#x} is invalid; dropped"
            ),
            Self::EcamDropped { base, segment } => write!(
                f,
                "more than {MAX_ECAM} ECAM ranges; segment {segment} at {base:#x} dropped"
            ),
        }
    }
}

/// A fixed-capacity list, so [`Platform`] has a fixed size.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct List<T, const N: usize> {
    items: [Option<T>; N],
}

impl<T: Copy, const N: usize> List<T, N> {
    pub const fn new() -> Self {
        Self { items: [None; N] }
    }

    /// Appends `item`, or returns `false` if the list is full.
    pub fn push(&mut self, item: T) -> bool {
        match self.items.iter_mut().find(|slot| slot.is_none()) {
            Some(slot) => {
                *slot = Some(item);
                true
            }
            None => false,
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = &T> {
        self.items.iter().map_while(Option::as_ref)
    }

    pub fn get(&self, i: usize) -> Option<&T> {
        self.items.get(i)?.as_ref()
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

impl<T: Copy, const N: usize> Default for List<T, N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<T: Copy + fmt::Debug, const N: usize> fmt::Debug for List<T, N> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// A table the root table lists, as its header gives it, for the boot log.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TableInfo {
    pub signature: Signature,
    pub address: u64,
    /// The header's `length`, unchecked unless the parser used the table.
    pub length: u32,
}

/// The MADT's fixed fields.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Madt {
    /// The table's physical address.
    pub address: u64,
    /// The local APIC's physical address: the header field, or the first
    /// Local APIC Address Override entry.
    pub lapic: u64,
    /// Whether an override entry gave [`Madt::lapic`].
    pub lapic_overridden: bool,
    /// `PCAT_COMPAT` and the reserved bits.
    pub flags: u32,
    /// Local APIC and local x2APIC entries marked enabled.
    pub processors: u32,
}

impl Madt {
    pub fn pcat_compat(&self) -> bool {
        self.flags & PCAT_COMPAT != 0
    }
}

/// An I/O APIC, in MADT order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApic {
    pub id: u8,
    pub address: u64,
    /// The first global system interrupt it serves.
    pub gsi_base: u32,
}

/// An interrupt source override for the ISA bus.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Override {
    /// The ISA IRQ.
    pub source: u8,
    pub gsi: u32,
    /// MPS INTI flags: polarity in bits 0-1, trigger mode in bits 2-3.
    pub flags: u16,
}

impl Override {
    /// Level-triggered: trigger mode 3. Mode 0 ("conforms to the bus") and
    /// the reserved mode 2 mean ISA's edge trigger.
    pub fn level(&self) -> bool {
        (self.flags >> 2) & 3 == 3
    }

    /// Active low: polarity 3. Polarity 0 ("conforms to the bus") and the
    /// reserved 2 mean ISA's active high.
    pub fn active_low(&self) -> bool {
        self.flags & 3 == 3
    }

    /// Where the override sends its IRQ.
    pub fn route(&self) -> IsaRoute {
        IsaRoute {
            gsi: self.gsi,
            level: self.level(),
            active_low: self.active_low(),
        }
    }

    fn reserved(&self) -> bool {
        self.flags & 3 == 2 || (self.flags >> 2) & 3 == 2
    }
}

/// The HPET, from its ACPI table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Hpet {
    /// The table's physical address.
    pub address: u64,
    /// The register block's physical address.
    pub base: u64,
    /// The Event Timer Block ID: comparators, counter size, vendor.
    pub block_id: u32,
    pub number: u8,
    /// The main counter's minimum tick in periodic mode.
    pub min_tick: u16,
}

/// A PCI ECAM range from the MCFG, as `docs/abi.md`'s `Ecam` gives it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ecam {
    /// Bus 0's configuration space in this segment, even when
    /// `start_bus` > 0.
    pub base: u64,
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

/// Where an ISA IRQ goes: `docs/abi.md`'s `IsaRoute` and `GetISA` result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsaRoute {
    pub gsi: u32,
    pub level: bool,
    pub active_low: bool,
}

impl IsaRoute {
    /// Bit 0 level-triggered, bit 1 active low.
    pub fn flags(&self) -> u8 {
        u8::from(self.level) | u8::from(self.active_low) << 1
    }
}

impl fmt::Display for IsaRoute {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "GSI {}, {}, active {}",
            self.gsi,
            if self.level { "level" } else { "edge" },
            if self.active_low { "low" } else { "high" }
        )
    }
}

/// What the kernel takes from ACPI. Fixed size: the kernel keeps it in a
/// static, and nothing reads ACPI memory after [`parse`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Platform {
    /// The RSDP's address and revision.
    pub rsdp: u64,
    pub revision: u8,
    /// The XSDT, or the RSDT for revision 0.
    pub root: TableInfo,
    /// The tables the root lists, in order, up to [`MAX_TABLES`].
    pub tables: List<TableInfo, MAX_TABLES>,
    pub madt: Madt,
    pub ioapics: List<IoApic, MAX_IOAPICS>,
    pub overrides: List<Override, MAX_OVERRIDES>,
    /// The HPET, if its table is valid and its registers are in memory.
    pub hpet: Option<Hpet>,
    pub ecam: List<Ecam, MAX_ECAM>,
    pub warnings: List<Warning, MAX_WARNINGS>,
    /// Warnings beyond [`MAX_WARNINGS`].
    pub warnings_dropped: u32,
}

impl Platform {
    fn warn(&mut self, w: Warning) {
        if !self.warnings.push(w) {
            self.warnings_dropped = self.warnings_dropped.saturating_add(1);
        }
    }

    /// Where ISA IRQ `irq` goes (`docs/design.md`, Local APIC, PIC and I/O
    /// APIC): GSI `irq`, edge, active high, unless an override for `irq`
    /// gives the GSI and flags. `None` for `irq` > 15, or if the GSI is
    /// another IRQ's override target (IRQ 2 when IRQ 0 goes to GSI 2).
    /// Whether an I/O APIC serves the GSI is [`Platform::ioapic_for_gsi`]'s
    /// question.
    pub fn isa_route(&self, irq: u8) -> Option<IsaRoute> {
        if irq > 15 {
            return None;
        }
        let route = match self.overrides.iter().find(|o| o.source == irq) {
            Some(o) => o.route(),
            None => IsaRoute {
                gsi: u32::from(irq),
                level: false,
                active_low: false,
            },
        };
        let taken = self
            .overrides
            .iter()
            .any(|o| o.source != irq && o.gsi == route.gsi);
        (!taken).then_some(route)
    }

    /// The I/O APIC, by MADT index, that serves `gsi`, given each one's pin
    /// count (its version register's MRE + 1, which only the hardware
    /// knows). The first match wins.
    pub fn ioapic_for_gsi(&self, gsi: u32, pins: &[u16]) -> Option<usize> {
        self.ioapics.iter().zip(pins).position(|(io, &n)| {
            gsi >= io.gsi_base && u64::from(gsi) < u64::from(io.gsi_base) + u64::from(n)
        })
    }

    /// The kernel device window (`docs/design.md`, The kernel half): the
    /// local APIC's page from `IA32_APIC_BASE` (bits 12 to 51), each I/O
    /// APIC's page in MADT order, and the HPET's page.
    pub fn device_window(&self, apic_base_msr: u64) -> DeviceWindow {
        const PAGE: u64 = !0xFFF;
        let mut w = DeviceWindow::default();
        w.pages[window::LAPIC_PAGE] = Some(apic_base_msr & 0x000F_FFFF_FFFF_F000);
        for (i, io) in self.ioapics.iter().enumerate() {
            w.pages[window::ioapic_page(i)] = Some(io.address & PAGE);
        }
        w.pages[window::HPET_PAGE] = self.hpet.map(|h| h.base & PAGE);
        w
    }
}

/// Parses the tables reachable from the RSDP at `rsdp` (`docs/design.md`,
/// Tables and validation). Table memory is read only through `mem`, one
/// byte at a time, and only inside tables whose length, bounds and checksum
/// passed.
pub fn parse<M: PhysRead + ?Sized>(mem: &M, rsdp: u64) -> Result<Platform, AcpiError> {
    let root = read_rsdp(mem, rsdp)?;
    let root_err = |fault| AcpiError::Root {
        signature: root.signature,
        address: root.address,
        fault,
    };
    let table = validate(mem, root.address, root.signature, HEADER_LEN).map_err(root_err)?;
    let area = table.len - HEADER_LEN;
    if !area.is_multiple_of(root.entry) {
        return Err(root_err(Fault::Entries));
    }
    let mut p = Platform {
        rsdp,
        revision: root.revision,
        root: TableInfo {
            signature: root.signature,
            address: root.address,
            length: table.len,
        },
        tables: List::new(),
        madt: Madt::default(),
        ioapics: List::new(),
        overrides: List::new(),
        hpet: None,
        ecam: List::new(),
        warnings: List::new(),
        warnings_dropped: 0,
    };

    let (mut madt, mut hpet, mut mcfg) = (None, None, None);
    let mut unlisted = 0u32;
    for i in 0..area / root.entry {
        let off = HEADER_LEN + i * root.entry;
        let address = match root.entry {
            8 => table.u64(off),
            _ => table.u32(off).map(u64::from),
        };
        let Some(address) = address else {
            return Err(root_err(Fault::OutOfRange));
        };
        let Some((signature, length)) = (address != 0).then(|| read_header(mem, address)).flatten()
        else {
            p.warn(Warning::Unreadable { address });
            continue;
        };
        if !p.tables.push(TableInfo {
            signature,
            address,
            length,
        }) {
            unlisted = unlisted.saturating_add(1);
        }
        let slot = match signature {
            Signature::MADT => &mut madt,
            Signature::HPET => &mut hpet,
            Signature::MCFG => &mut mcfg,
            _ => continue,
        };
        match *slot {
            None => *slot = Some(address),
            Some(first) if first == address => p.warn(Warning::Repeated { signature, address }),
            Some(_) if signature == Signature::MCFG => p.warn(Warning::ExtraMcfg { address }),
            Some(first) => {
                return Err(AcpiError::Duplicate {
                    signature,
                    first,
                    second: address,
                });
            }
        }
    }
    if unlisted > 0 {
        p.warn(Warning::Unlisted { count: unlisted });
    }

    let address = madt.ok_or(AcpiError::NoMadt)?;
    let t = validate(mem, address, Signature::MADT, MADT_ENTRIES)
        .map_err(|fault| AcpiError::Madt { address, fault })?;
    parse_madt(&t, &mut p)?;

    if let Some(address) = hpet {
        match validate(mem, address, Signature::HPET, HPET_LEN) {
            Ok(t) => parse_hpet(&t, &mut p),
            Err(fault) => p.warn(Warning::BadTable {
                signature: Signature::HPET,
                address,
                fault,
            }),
        }
    }
    if let Some(address) = mcfg {
        match validate(mem, address, Signature::MCFG, MCFG_ENTRIES) {
            Ok(t) => parse_mcfg(&t, &mut p),
            Err(fault) => p.warn(Warning::BadTable {
                signature: Signature::MCFG,
                address,
                fault,
            }),
        }
    }
    Ok(p)
}

/// The root table the RSDP names.
struct Root {
    signature: Signature,
    address: u64,
    /// Bytes per entry: 8 for the XSDT, 4 for the RSDT.
    entry: u32,
    revision: u8,
}

/// Checks the RSDP: signature and 20-byte checksum; revision 0 names the
/// RSDT, any other revision needs a `length` of 36 to 4096, a checksum over
/// it and a non-zero XSDT.
fn read_rsdp<M: PhysRead + ?Sized>(mem: &M, address: u64) -> Result<Root, AcpiError> {
    if address == 0 {
        return Err(AcpiError::NoRsdp);
    }
    let err = |fault| AcpiError::Rsdp { address, fault };
    match read_bytes::<8, _>(mem, address, 0) {
        None => return Err(err(Fault::Unreadable)),
        Some(sig) if &sig != b"RSD PTR " => return Err(err(Fault::NotRsdp)),
        Some(_) => {}
    }
    match checksum(mem, address, RSDP_V1_LEN) {
        None => return Err(err(Fault::OutOfRange)),
        Some(0) => {}
        Some(_) => return Err(err(Fault::Checksum)),
    }
    // Inside the 20 bytes just read.
    let revision = read_bytes::<1, _>(mem, address, 15).ok_or(err(Fault::OutOfRange))?[0];
    if revision == 0 {
        let rsdt = read_u32(mem, address, 16).ok_or(err(Fault::OutOfRange))?;
        if rsdt == 0 {
            return Err(err(Fault::NullRoot));
        }
        return Ok(Root {
            signature: Signature::RSDT,
            address: rsdt.into(),
            entry: 4,
            revision,
        });
    }
    let length = read_u32(mem, address, 20).ok_or(err(Fault::OutOfRange))?;
    if !(RSDP_V2_LEN..=RSDP_MAX_LEN).contains(&length) {
        return Err(err(Fault::Length(length)));
    }
    match checksum(mem, address, length) {
        None => return Err(err(Fault::OutOfRange)),
        Some(0) => {}
        Some(_) => return Err(err(Fault::ExtendedChecksum)),
    }
    let xsdt = read_u64(mem, address, 24).ok_or(err(Fault::OutOfRange))?;
    if xsdt == 0 {
        return Err(err(Fault::NullRoot));
    }
    Ok(Root {
        signature: Signature::XSDT,
        address: xsdt,
        entry: 8,
        revision,
    })
}

/// A table that passed [`validate`]: every field read is bounded by its
/// length, which lies inside readable memory.
struct Table<'m, M: ?Sized> {
    mem: &'m M,
    address: u64,
    len: u32,
}

impl<M: PhysRead + ?Sized> Table<'_, M> {
    fn bytes<const N: usize>(&self, off: u32) -> Option<[u8; N]> {
        let end = off.checked_add(u32::try_from(N).ok()?)?;
        if end > self.len {
            return None;
        }
        read_bytes(self.mem, self.address, off.into())
    }

    fn u8(&self, off: u32) -> Option<u8> {
        self.bytes::<1>(off).map(u8::from_le_bytes)
    }

    fn u16(&self, off: u32) -> Option<u16> {
        self.bytes(off).map(u16::from_le_bytes)
    }

    fn u32(&self, off: u32) -> Option<u32> {
        self.bytes(off).map(u32::from_le_bytes)
    }

    fn u64(&self, off: u32) -> Option<u64> {
        self.bytes(off).map(u64::from_le_bytes)
    }
}

/// Header first, then: the expected signature; `length` from `min_len` to
/// [`MAX_TABLE_LEN`]; `[address, address + length)` readable without
/// overflow; byte sum 0.
fn validate<M: PhysRead + ?Sized>(
    mem: &M,
    address: u64,
    expected: Signature,
    min_len: u32,
) -> Result<Table<'_, M>, Fault> {
    let (signature, len) = read_header(mem, address).ok_or(Fault::Unreadable)?;
    if signature != expected {
        return Err(Fault::Signature(signature));
    }
    if !(min_len..=MAX_TABLE_LEN).contains(&len) {
        return Err(Fault::Length(len));
    }
    match checksum(mem, address, len) {
        None => Err(Fault::OutOfRange),
        Some(0) => Ok(Table { mem, address, len }),
        Some(_) => Err(Fault::Checksum),
    }
}

fn parse_madt<M: PhysRead + ?Sized>(t: &Table<'_, M>, p: &mut Platform) -> Result<(), AcpiError> {
    let bad = |off| AcpiError::Madt {
        address: t.address,
        fault: Fault::MadtEntry(off),
    };
    // `validate` checked the length covers both fields.
    let (Some(lapic), Some(flags)) = (t.u32(36), t.u32(40)) else {
        return Err(bad(36));
    };
    p.madt = Madt {
        address: t.address,
        lapic: lapic.into(),
        lapic_overridden: false,
        flags,
        processors: 0,
    };
    let mut off = MADT_ENTRIES;
    while off < t.len {
        let (Some(kind), Some(length)) = (t.u8(off), t.u8(off + 1)) else {
            return Err(bad(off));
        };
        let len = u32::from(length);
        if len < 2 || len > t.len - off {
            return Err(bad(off));
        }
        match madt_min_len(kind) {
            Some(min) if len < min => p.warn(Warning::ShortEntry { kind, length }),
            Some(_) => madt_entry(t, off, kind, p).ok_or(bad(off))??,
            None => {}
        }
        // At least 2, and `off + len` <= `t.len` <= 1 MiB.
        off += len;
    }
    Ok(())
}

/// One MADT entry of a type the parser reads, at least as long as its
/// layout. `None` only if a field cannot be read, which validation rules
/// out.
fn madt_entry<M: PhysRead + ?Sized>(
    t: &Table<'_, M>,
    off: u32,
    kind: u8,
    p: &mut Platform,
) -> Option<Result<(), AcpiError>> {
    const ENABLED: u32 = 1 << 0;
    match kind {
        MADT_LOCAL_APIC | MADT_LOCAL_X2APIC => {
            let flags = t.u32(off + if kind == MADT_LOCAL_APIC { 4 } else { 8 })?;
            if flags & ENABLED != 0 {
                p.madt.processors = p.madt.processors.saturating_add(1);
            }
        }
        MADT_IO_APIC => {
            let id = t.u8(off + 2)?;
            let address = t.u32(off + 4)?;
            let gsi_base = t.u32(off + 8)?;
            if address == 0 {
                p.warn(Warning::NullIoApic { id });
            } else if !p.ioapics.push(IoApic {
                id,
                address: address.into(),
                gsi_base,
            }) {
                return Some(Err(AcpiError::TooManyIoApics));
            }
        }
        MADT_OVERRIDE => {
            let bus = t.u8(off + 2)?;
            let source = t.u8(off + 3)?;
            let gsi = t.u32(off + 4)?;
            let flags = t.u16(off + 8)?;
            let o = Override { source, gsi, flags };
            if bus != 0 {
                p.warn(Warning::NonIsaOverride { bus, source });
            } else {
                if o.reserved() {
                    p.warn(Warning::ReservedFlags { source, flags });
                }
                if !p.overrides.push(o) {
                    p.warn(Warning::OverrideDropped { source, gsi });
                }
            }
        }
        MADT_LAPIC_ADDRESS => {
            let address = t.u64(off + 4)?;
            if !p.madt.lapic_overridden {
                p.madt.lapic = address;
                p.madt.lapic_overridden = true;
            }
        }
        _ => {}
    }
    Some(Ok(()))
}

fn parse_hpet<M: PhysRead + ?Sized>(t: &Table<'_, M>, p: &mut Platform) {
    // Generic Address Structure at 40: space ID, bit width, bit offset,
    // access size, then the 64-bit address at 44.
    let (Some(block_id), Some(space), Some(base), Some(number), Some(min_tick)) =
        (t.u32(36), t.u8(40), t.u64(44), t.u8(52), t.u16(53))
    else {
        return;
    };
    if space != 0 {
        p.warn(Warning::HpetNotMemory { space });
    } else if base == 0 || base >= 1 << 52 || (base & 0xFFF) + HPET_REGS > 0x1000 {
        p.warn(Warning::HpetBase { base });
    } else {
        p.hpet = Some(Hpet {
            address: t.address,
            base,
            block_id,
            number,
            min_tick,
        });
    }
}

fn parse_mcfg<M: PhysRead + ?Sized>(t: &Table<'_, M>, p: &mut Platform) {
    let area = t.len - MCFG_ENTRIES;
    if !area.is_multiple_of(MCFG_ENTRY_LEN) {
        p.warn(Warning::BadTable {
            signature: Signature::MCFG,
            address: t.address,
            fault: Fault::Entries,
        });
        return;
    }
    for i in 0..area / MCFG_ENTRY_LEN {
        let off = MCFG_ENTRIES + i * MCFG_ENTRY_LEN;
        let (Some(base), Some(segment), Some(start_bus), Some(end_bus)) =
            (t.u64(off), t.u16(off + 8), t.u8(off + 10), t.u8(off + 11))
        else {
            return;
        };
        let span = (u64::from(end_bus) + 1) << 20;
        if start_bus > end_bus || base.checked_add(span).is_none() {
            p.warn(Warning::BadEcam {
                base,
                segment,
                start_bus,
                end_bus,
            });
        } else if !p.ecam.push(Ecam {
            base,
            segment,
            start_bus,
            end_bus,
        }) {
            p.warn(Warning::EcamDropped { base, segment });
        }
    }
}

/// `N` bytes at `base + off`, if every one is readable.
fn read_bytes<const N: usize, M: PhysRead + ?Sized>(
    mem: &M,
    base: u64,
    off: u64,
) -> Option<[u8; N]> {
    let start = base.checked_add(off)?;
    let mut out = [0u8; N];
    for (i, b) in (0u64..).zip(out.iter_mut()) {
        *b = mem.read_u8(start.checked_add(i)?)?;
    }
    Some(out)
}

fn read_u32<M: PhysRead + ?Sized>(mem: &M, base: u64, off: u64) -> Option<u32> {
    read_bytes(mem, base, off).map(u32::from_le_bytes)
}

fn read_u64<M: PhysRead + ?Sized>(mem: &M, base: u64, off: u64) -> Option<u64> {
    read_bytes(mem, base, off).map(u64::from_le_bytes)
}

/// A table's signature and `length`, the first 8 bytes of its header.
fn read_header<M: PhysRead + ?Sized>(mem: &M, address: u64) -> Option<(Signature, u32)> {
    let b = read_bytes::<8, _>(mem, address, 0)?;
    let [s0, s1, s2, s3, l0, l1, l2, l3] = b;
    Some((
        Signature([s0, s1, s2, s3]),
        u32::from_le_bytes([l0, l1, l2, l3]),
    ))
}

/// The byte sum of `[address, address + len)`, or `None` if any byte is
/// unreadable or the range overflows.
fn checksum<M: PhysRead + ?Sized>(mem: &M, address: u64, len: u32) -> Option<u8> {
    let end = address.checked_add(len.into())?;
    let mut sum = 0u8;
    for a in address..end {
        sum = sum.wrapping_add(mem.read_u8(a)?);
    }
    Some(sum)
}
