//! Host tests for the ACPI parser: the tables dumped from each platform
//! (`core/tests/acpi/`), corrupted copies of each, hand-made edge cases, the
//! dump format, and random bytes. All of it runs under Miri, with fewer
//! random cases there.

use alloc::format;
use alloc::string::{String, ToString};
use alloc::vec;
use alloc::vec::Vec;
use core::cell::Cell;
use std::sync::OnceLock;

use proptest::prelude::*;
use proptest::sample::Index;

use super::dump::{self, DumpMemory, Line};
use super::*;

const Q35: &str = include_str!("../../tests/acpi/q35.dump");
const Q35_HPET_OFF: &str = include_str!("../../tests/acpi/q35-hpet-off.dump");
/// The owner's Hyper-V Generation 2 VM, from the M3 Hyper-V check; the DSDT
/// is left out of the dump.
const HYPERV: &str = include_str!("../../tests/acpi/hyperv-gen2.dump");

/// Each dump, parsed once per test process: decoding the hex is the slow
/// part under Miri.
fn q35() -> DumpMemory {
    static M: OnceLock<DumpMemory> = OnceLock::new();
    M.get_or_init(|| DumpMemory::parse(Q35).unwrap()).clone()
}

fn q35_hpet_off() -> DumpMemory {
    static M: OnceLock<DumpMemory> = OnceLock::new();
    M.get_or_init(|| DumpMemory::parse(Q35_HPET_OFF).unwrap())
        .clone()
}

fn hyperv() -> DumpMemory {
    static M: OnceLock<DumpMemory> = OnceLock::new();
    M.get_or_init(|| DumpMemory::parse(HYPERV).unwrap()).clone()
}

fn parse_dump(m: &DumpMemory) -> Result<Platform, AcpiError> {
    parse(m, m.rsdp().unwrap())
}

// ---------------------------------------------------------------------
// Memory and table builders.

/// One run of RAM at `base`, counting reads so tests can bound them.
struct Ram {
    base: u64,
    bytes: Vec<u8>,
    reads: Cell<u64>,
}

impl Ram {
    fn new(base: u64, size: usize) -> Self {
        Ram {
            base,
            bytes: vec![0; size],
            reads: Cell::new(0),
        }
    }

    fn put(&mut self, addr: u64, data: &[u8]) {
        let at = usize::try_from(addr - self.base).unwrap();
        self.bytes[at..at + data.len()].copy_from_slice(data);
    }
}

impl PhysRead for Ram {
    fn read_u8(&self, addr: u64) -> Option<u8> {
        self.reads.set(self.reads.get() + 1);
        let i = usize::try_from(addr.checked_sub(self.base)?).ok()?;
        self.bytes.get(i).copied()
    }
}

/// Counts the reads made through another reader.
struct Counted<'a, M> {
    mem: &'a M,
    reads: Cell<u64>,
}

impl<M: PhysRead> PhysRead for Counted<'_, M> {
    fn read_u8(&self, addr: u64) -> Option<u8> {
        self.reads.set(self.reads.get() + 1);
        self.mem.read_u8(addr)
    }
}

/// A generous bound on the reads `parse` makes over `readable` bytes:
/// every table it validates is read at most twice and lies inside them,
/// each root entry costs at most 8 header reads, and the RSDP at most 4 KiB.
fn read_bound(readable: usize) -> u64 {
    12 * readable as u64 + 10_000
}

/// Sets `t[at]` so the bytes of `t` sum to zero.
fn fix_checksum(t: &mut [u8], at: usize) {
    t[at] = 0;
    let sum = t.iter().fold(0u8, |a, b| a.wrapping_add(*b));
    t[at] = sum.wrapping_neg();
}

/// A table with a full header, `body` after it, and a correct checksum.
fn sdt(sig: &[u8; 4], body: &[u8]) -> Vec<u8> {
    let len = u32::try_from(36 + body.len()).unwrap();
    let mut t = Vec::new();
    t.extend_from_slice(sig);
    t.extend_from_slice(&len.to_le_bytes());
    t.extend_from_slice(&[1, 0]); // revision, checksum
    t.extend_from_slice(b"MICROL"); // OEM ID
    t.extend_from_slice(b"TESTTABL"); // OEM table ID
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(b"L4TS");
    t.extend_from_slice(&1u32.to_le_bytes());
    t.extend_from_slice(body);
    fix_checksum(&mut t, 9);
    t
}

fn rsdp(revision: u8, rsdt: u32, xsdt: u64) -> Vec<u8> {
    let mut r = Vec::new();
    r.extend_from_slice(b"RSD PTR ");
    r.push(0);
    r.extend_from_slice(b"MICROL");
    r.push(revision);
    r.extend_from_slice(&rsdt.to_le_bytes());
    if revision != 0 {
        r.extend_from_slice(&36u32.to_le_bytes());
        r.extend_from_slice(&xsdt.to_le_bytes());
        r.extend_from_slice(&[0; 4]);
    }
    fix_checksum(&mut r[..20], 8);
    if revision != 0 {
        fix_checksum(&mut r, 32);
    }
    r
}

fn xsdt(addrs: &[u64]) -> Vec<u8> {
    let body: Vec<u8> = addrs.iter().flat_map(|a| a.to_le_bytes()).collect();
    sdt(b"XSDT", &body)
}

fn rsdt(addrs: &[u64]) -> Vec<u8> {
    let body: Vec<u8> = addrs
        .iter()
        .flat_map(|a| u32::try_from(*a).unwrap().to_le_bytes())
        .collect();
    sdt(b"RSDT", &body)
}

fn madt_with(lapic: u32, flags: u32, entries: &[Vec<u8>]) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&lapic.to_le_bytes());
    body.extend_from_slice(&flags.to_le_bytes());
    for e in entries {
        body.extend_from_slice(e);
    }
    sdt(b"APIC", &body)
}

fn madt(entries: &[Vec<u8>]) -> Vec<u8> {
    madt_with(0xFEE0_0000, PCAT_COMPAT, entries)
}

fn lapic(id: u8, flags: u32) -> Vec<u8> {
    let mut e = vec![0, 8, id, id];
    e.extend_from_slice(&flags.to_le_bytes());
    e
}

fn x2apic(id: u32, flags: u32) -> Vec<u8> {
    let mut e = vec![9, 16, 0, 0];
    e.extend_from_slice(&id.to_le_bytes());
    e.extend_from_slice(&flags.to_le_bytes());
    e.extend_from_slice(&id.to_le_bytes());
    e
}

fn ioapic(id: u8, address: u32, gsi_base: u32) -> Vec<u8> {
    let mut e = vec![1, 12, id, 0];
    e.extend_from_slice(&address.to_le_bytes());
    e.extend_from_slice(&gsi_base.to_le_bytes());
    e
}

fn iso(bus: u8, source: u8, gsi: u32, flags: u16) -> Vec<u8> {
    let mut e = vec![2, 10, bus, source];
    e.extend_from_slice(&gsi.to_le_bytes());
    e.extend_from_slice(&flags.to_le_bytes());
    e
}

fn lapic_override(address: u64) -> Vec<u8> {
    let mut e = vec![5, 12, 0, 0];
    e.extend_from_slice(&address.to_le_bytes());
    e
}

/// MPS INTI flags: active low and level.
const LOW_LEVEL: u16 = 0b1111;
/// Active high and level, as QEMU gives IRQs 5, 9, 10 and 11.
const HIGH_LEVEL: u16 = 0b1101;

fn hpet_table(space: u8, base: u64) -> Vec<u8> {
    let mut body = Vec::new();
    body.extend_from_slice(&0x8086_A201u32.to_le_bytes());
    body.extend_from_slice(&[space, 64, 0, 0]);
    body.extend_from_slice(&base.to_le_bytes());
    body.push(0); // HPET number
    body.extend_from_slice(&0x80u16.to_le_bytes());
    body.push(0); // page protection
    sdt(b"HPET", &body)
}

fn mcfg(entries: &[(u64, u16, u8, u8)]) -> Vec<u8> {
    let mut body = vec![0; 8];
    for &(base, segment, start, end) in entries {
        body.extend_from_slice(&base.to_le_bytes());
        body.extend_from_slice(&segment.to_le_bytes());
        body.extend_from_slice(&[start, end, 0, 0, 0, 0]);
    }
    sdt(b"MCFG", &body)
}

/// A typical MADT: one CPU, one I/O APIC, IRQ 0 on GSI 2 and IRQ 9 level.
fn std_madt() -> Vec<u8> {
    madt(&[
        lapic(0, 1),
        ioapic(0, 0xFEC0_0000, 0),
        iso(0, 0, 2, 0),
        iso(0, 9, 9, HIGH_LEVEL),
    ])
}

const BASE: u64 = 0x000E_0000;
const RSDP: u64 = BASE;
const ROOT: u64 = BASE + 0x100;
const SIZE: usize = 0x1_0000 * 4;

/// Where [`machine`] puts table `i`.
fn at(i: usize) -> u64 {
    BASE + 0x1000 * (i as u64 + 1)
}

/// RAM with a revision-2 RSDP at [`RSDP`], an XSDT at [`ROOT`] listing
/// each of `tables`, and table `i` at [`at`]`(i)`.
fn machine(tables: &[Vec<u8>]) -> Ram {
    let addrs: Vec<u64> = (0..tables.len()).map(at).collect();
    machine_listing(tables, &xsdt(&addrs))
}

/// As [`machine`], with `root` as the XSDT.
fn machine_listing(tables: &[Vec<u8>], root: &[u8]) -> Ram {
    let mut ram = Ram::new(BASE, SIZE);
    ram.put(RSDP, &rsdp(2, 0, ROOT));
    ram.put(ROOT, root);
    for (i, t) in tables.iter().enumerate() {
        ram.put(at(i), t);
    }
    ram
}

/// The same tables under a revision-0 RSDP and an RSDT.
fn machine_v0(tables: &[Vec<u8>]) -> Ram {
    let mut ram = Ram::new(BASE, SIZE);
    ram.put(RSDP, &rsdp(0, u32::try_from(ROOT).unwrap(), 0));
    let addrs: Vec<u64> = (0..tables.len()).map(at).collect();
    ram.put(ROOT, &rsdt(&addrs));
    for (i, t) in tables.iter().enumerate() {
        ram.put(at(i), t);
    }
    ram
}

fn warnings(p: &Platform) -> Vec<Warning> {
    p.warnings.iter().copied().collect()
}

// ---------------------------------------------------------------------
// The dumped tables.

const COM1: IsaRoute = IsaRoute {
    gsi: 4,
    level: false,
    active_low: false,
};

/// What both q35 dumps share: the MADT and the MCFG.
fn check_q35_common(p: &Platform) {
    assert_eq!(p.revision, 2, "QEMU's OVMF gives an ACPI 2.0+ RSDP");
    assert_eq!(p.root.signature, Signature::XSDT);
    assert_eq!(
        (p.madt.lapic, p.madt.flags, p.madt.processors),
        (0xFEE0_0000, PCAT_COMPAT, 1)
    );
    assert!(p.madt.pcat_compat() && !p.madt.lapic_overridden);
    let ioapics: Vec<_> = p.ioapics.iter().copied().collect();
    assert_eq!(
        ioapics,
        [IoApic {
            id: 0,
            address: 0xFEC0_0000,
            gsi_base: 0
        }]
    );
    let overrides: Vec<_> = p
        .overrides
        .iter()
        .map(|o| (o.source, o.gsi, o.flags))
        .collect();
    assert_eq!(
        overrides,
        [
            (0, 2, 0),
            (5, 5, HIGH_LEVEL),
            (9, 9, HIGH_LEVEL),
            (10, 10, HIGH_LEVEL),
            (11, 11, HIGH_LEVEL)
        ]
    );
    let ecam: Vec<_> = p.ecam.iter().copied().collect();
    assert_eq!(
        ecam,
        [Ecam {
            base: 0xE000_0000,
            segment: 0,
            start_bus: 0,
            end_bus: 255
        }]
    );
    assert_eq!(warnings(p), []);
    assert_eq!(p.warnings_dropped, 0);

    // ISA routing: COM1 on GSI 4, IRQ 0 on GSI 2, so IRQ 2 has no route.
    assert_eq!(p.isa_route(4), Some(COM1));
    assert_eq!(p.isa_route(0).map(|r| r.gsi), Some(2));
    assert_eq!(p.isa_route(2), None);
    let sci = p.isa_route(9).unwrap();
    assert_eq!((sci.gsi, sci.level, sci.active_low), (9, true, false));
    assert_eq!(sci.flags(), 1);
    assert_eq!(p.isa_route(16), None);
    // QEMU's I/O APIC has 24 pins.
    assert_eq!(p.ioapic_for_gsi(4, &[24]), Some(0));
    assert_eq!(p.ioapic_for_gsi(23, &[24]), Some(0));
    assert_eq!(p.ioapic_for_gsi(24, &[24]), None);
}

#[test]
fn q35_tables() {
    let m = q35();
    m.check().unwrap();
    let p = parse_dump(&m).unwrap();
    check_q35_common(&p);
    let tables: Vec<_> = p.tables.iter().map(|t| t.signature).collect();
    assert_eq!(
        tables,
        [b"FACP", b"APIC", b"HPET", b"MCFG", b"WAET", b"BGRT"].map(|s| Signature(*s))
    );
    let hpet = p.hpet.unwrap();
    assert_eq!(hpet.base, 0xFED0_0000);
    // OVMF leaves IA32_APIC_BASE at 0xfee00900: enabled, xAPIC, BSP.
    let w = p.device_window(0xFEE0_0900);
    assert_eq!(
        w.pages,
        [
            Some(0xFEE0_0000),
            Some(0xFEC0_0000),
            None,
            None,
            None,
            Some(0xFED0_0000)
        ]
    );
}

#[test]
fn hyperv_gen2_tables() {
    let m = hyperv();
    m.check().unwrap();
    let p = parse_dump(&m).unwrap();
    assert_eq!(p.revision, 2);
    assert_eq!(p.root.signature, Signature::XSDT);
    let tables: Vec<_> = p.tables.iter().map(|t| t.signature).collect();
    assert_eq!(
        tables,
        [b"FACP", b"OEM0", b"WAET", b"APIC", b"SRAT", b"BGRT"].map(|s| Signature(*s))
    );
    // No PCAT_COMPAT, so the kernel leaves the 8259s alone; no HPET, so the
    // timer calibrates against the reference counter; no MCFG.
    assert_eq!(
        (p.madt.lapic, p.madt.flags, p.madt.processors),
        (0xFEE0_0000, 0, 1)
    );
    assert!(!p.madt.pcat_compat() && !p.madt.lapic_overridden);
    assert_eq!(p.hpet, None);
    assert_eq!(p.ecam.iter().count(), 0);
    let ioapics: Vec<_> = p.ioapics.iter().copied().collect();
    assert_eq!(
        ioapics,
        [IoApic {
            id: 1,
            address: 0xFEC0_0000,
            gsi_base: 0
        }]
    );
    // One override, the SCI; unlike q35, IRQ 0 stays on GSI 0.
    let overrides: Vec<_> = p
        .overrides
        .iter()
        .map(|o| (o.source, o.gsi, o.flags))
        .collect();
    assert_eq!(overrides, [(9, 9, HIGH_LEVEL)]);
    assert_eq!(p.isa_route(4), Some(COM1));
    assert_eq!(p.isa_route(0).map(|r| r.gsi), Some(0));
    assert_eq!(p.isa_route(2).map(|r| r.gsi), Some(2));
    assert!(p.isa_route(9).unwrap().level);
    assert_eq!(warnings(&p), []);
    // The firmware hands over with IA32_APIC_BASE 0xfee00900, as OVMF does.
    let w = p.device_window(0xFEE0_0900);
    assert_eq!(
        w.pages,
        [Some(0xFEE0_0000), Some(0xFEC0_0000), None, None, None, None]
    );
}

#[test]
fn q35_without_hpet() {
    let m = q35_hpet_off();
    m.check().unwrap();
    let p = parse_dump(&m).unwrap();
    check_q35_common(&p);
    assert_eq!(p.hpet, None);
    assert!(p.tables.iter().all(|t| t.signature != Signature::HPET));
    assert_eq!(p.device_window(0xFEE0_0900).pages[window::HPET_PAGE], None);
}

#[test]
fn q35_through_its_rsdt() {
    // The same tables, reached as an ACPI 1.0 firmware would: revision 0
    // and the RSDT the q35 RSDP also names.
    let mut m = q35();
    let rsdp = m.rsdp().unwrap();
    let mut head: Vec<u8> = (0..20).map(|i| m.read_u8(rsdp + i).unwrap()).collect();
    head[15] = 0;
    fix_checksum(&mut head, 8);
    for (i, b) in (0..).zip(&head) {
        assert!(m.poke(rsdp + i, *b));
    }
    let p = parse_dump(&m).unwrap();
    assert_eq!((p.revision, p.root.signature), (0, Signature::RSDT));
    let full = parse_dump(&q35()).unwrap();
    assert_eq!(p.tables, full.tables);
    assert_eq!((p.madt, p.hpet), (full.madt, full.hpet));
    assert_eq!(
        (p.ioapics, p.overrides, p.ecam),
        (full.ioapics, full.overrides, full.ecam)
    );
}

#[test]
fn dumps_list_each_table_once() {
    for m in [q35(), q35_hpet_off()] {
        let mut addrs: Vec<u64> = m.tables().iter().map(|t| t.address).collect();
        addrs.sort_unstable();
        addrs.dedup();
        assert_eq!(addrs.len(), m.tables().len());
        // The RSDT, the XSDT, the FADT's DSDT and FACS are all there.
        for name in ["RSDP", "RSDT", "XSDT", "FACP", "DSDT", "FACS", "APIC"] {
            assert!(m.tables().iter().any(|t| t.name == name), "{name}");
        }
    }
}

/// What parsing a dump with table `name` corrupted must give, against the
/// clean result `clean`.
fn expect_corrupt(name: &str, address: u64, p: Result<Platform, AcpiError>, clean: &Platform) {
    let bad = |signature| Warning::BadTable {
        signature,
        address,
        fault: Fault::Checksum,
    };
    match name {
        "RSDP" => assert!(
            matches!(
                p,
                Err(AcpiError::Rsdp {
                    fault: Fault::Checksum | Fault::ExtendedChecksum,
                    ..
                })
            ),
            "{p:?}"
        ),
        "XSDT" => assert_eq!(
            p,
            Err(AcpiError::Root {
                signature: Signature::XSDT,
                address,
                fault: Fault::Checksum
            })
        ),
        "APIC" => assert_eq!(
            p,
            Err(AcpiError::Madt {
                address,
                fault: Fault::Checksum
            })
        ),
        "HPET" => {
            let p = p.unwrap();
            assert_eq!(p.hpet, None);
            assert_eq!(warnings(&p), [bad(Signature::HPET)]);
        }
        "MCFG" => {
            let p = p.unwrap();
            assert!(p.ecam.is_empty());
            assert_eq!(warnings(&p), [bad(Signature::MCFG)]);
        }
        // The RSDT under a revision-2 RSDP, the FADT, DSDT, FACS and the
        // rest: never read beyond their headers.
        _ => assert_eq!(p.as_ref(), Ok(clean), "{name}"),
    }
}

#[test]
fn corrupted_copies_of_each_dumped_table() {
    for m in [q35(), q35_hpet_off(), hyperv()] {
        let clean = parse_dump(&m).unwrap();
        for t in m.tables() {
            // Bytes in the header, in the middle, and the last: each breaks
            // the checksum. The RSDP's byte 18 is inside its first 20.
            // Under Miri, which is slow, only the middle one.
            let offsets = match t.name.as_str() {
                "RSDP" if cfg!(miri) => vec![18],
                "RSDP" => vec![18, 30],
                _ if cfg!(miri) => vec![u64::from(t.length / 2)],
                _ => vec![10, u64::from(t.length / 2), u64::from(t.length - 1)],
            };
            for off in offsets {
                let mut bad = m.clone();
                let addr = t.address + off;
                let old = bad.read_u8(addr).unwrap();
                assert!(bad.poke(addr, old ^ 0x5A));
                expect_corrupt(&t.name, t.address, parse_dump(&bad), &clean);
            }
        }
    }
}

#[test]
fn corrupted_signatures_and_lengths() {
    let m = q35();
    let clean = parse_dump(&m).unwrap();
    let find = |name: &str| m.tables().iter().find(|t| t.name == name).unwrap().clone();

    // A MADT under another signature is no MADT.
    let apic = find("APIC");
    let mut bad = m.clone();
    bad.poke(apic.address, b'X');
    assert_eq!(parse_dump(&bad), Err(AcpiError::NoMadt));

    // An HPET table under another signature is just another table.
    let hpet = find("HPET");
    let mut bad = m.clone();
    bad.poke(hpet.address + 3, b'X');
    let p = parse_dump(&bad).unwrap();
    assert_eq!((p.hpet, warnings(&p)), (None, vec![]));
    assert!(p.tables.iter().any(|t| t.signature == Signature(*b"HPEX")));

    // Lengths: too short, past the dumped bytes, above 1 MiB.
    for (len, fault) in [
        (43, Fault::Length(43)),
        (0x2000, Fault::OutOfRange),
        (MAX_TABLE_LEN + 1, Fault::Length(MAX_TABLE_LEN + 1)),
    ] {
        let mut bad = m.clone();
        for (i, b) in (0..).zip(len.to_le_bytes()) {
            bad.poke(apic.address + 4 + i, b);
        }
        assert_eq!(
            parse_dump(&bad),
            Err(AcpiError::Madt {
                address: apic.address,
                fault
            })
        );
        let mut bad = m.clone();
        for (i, b) in (0..).zip(len.to_le_bytes()) {
            bad.poke(hpet.address + 4 + i, b);
        }
        let p = parse_dump(&bad).unwrap();
        assert_eq!(p.hpet, None);
        let want = if len == 43 { Fault::Length(43) } else { fault };
        assert_eq!(
            warnings(&p),
            [Warning::BadTable {
                signature: Signature::HPET,
                address: hpet.address,
                fault: want
            }]
        );
        assert_eq!((p.madt, p.ecam), (clean.madt, clean.ecam));
    }
}

// ---------------------------------------------------------------------
// Hand-made tables.

#[test]
fn a_minimal_machine() {
    let ram = machine(&[
        std_madt(),
        hpet_table(0, 0xFED0_0000),
        mcfg(&[(0xB000_0000, 0, 0, 63)]),
    ]);
    let p = parse(&ram, RSDP).unwrap();
    assert_eq!(p.rsdp, RSDP);
    assert_eq!(p.root.address, ROOT);
    assert_eq!(p.tables.len(), 3);
    assert_eq!(p.madt.address, at(0));
    assert_eq!(p.ioapics.len(), 1);
    assert_eq!(p.hpet.unwrap().base, 0xFED0_0000);
    assert_eq!(p.hpet.unwrap().address, at(1));
    assert_eq!(p.ecam.get(0).unwrap().end_bus, 63);
    assert_eq!(warnings(&p), []);
    assert!(ram.reads.get() <= read_bound(SIZE));
}

#[test]
fn revision_0_reads_the_rsdt() {
    let ram = machine_v0(&[std_madt(), hpet_table(0, 0xFED0_0000)]);
    let p = parse(&ram, RSDP).unwrap();
    assert_eq!(
        (p.revision, p.root.signature, p.root.address),
        (0, Signature::RSDT, ROOT)
    );
    assert_eq!(p.tables.len(), 2);
    assert!(p.hpet.is_some());
    assert_eq!(p.isa_route(0).unwrap().gsi, 2);
}

#[test]
fn rsdp_checks() {
    let tables = [std_madt()];
    let rsdp_err = |fault| {
        Err(AcpiError::Rsdp {
            address: RSDP,
            fault,
        })
    };
    let ram = machine(&tables);
    assert_eq!(parse(&ram, 0), Err(AcpiError::NoRsdp));
    assert_eq!(
        parse(&ram, 0xFFFF_FFFF),
        Err(AcpiError::Rsdp {
            address: 0xFFFF_FFFF,
            fault: Fault::Unreadable
        })
    );

    let with = |r: Vec<u8>| {
        let mut ram = machine(&tables);
        ram.put(RSDP, &r);
        parse(&ram, RSDP)
    };
    let mut r = rsdp(2, 0, ROOT);
    r[0] = b'r';
    assert_eq!(with(r), rsdp_err(Fault::NotRsdp));
    let mut r = rsdp(2, 0, ROOT);
    r[12] ^= 1;
    assert_eq!(with(r), rsdp_err(Fault::Checksum));
    let mut r = rsdp(2, 0, ROOT);
    r[33] ^= 1;
    assert_eq!(with(r), rsdp_err(Fault::ExtendedChecksum));
    for len in [0, 20, 35, 4097, u32::MAX] {
        let mut r = rsdp(2, 0, ROOT);
        r[20..24].copy_from_slice(&len.to_le_bytes());
        fix_checksum(&mut r[..20], 8);
        assert_eq!(with(r), rsdp_err(Fault::Length(len)), "{len}");
    }
    // A long RSDP is fine if its checksum covers it.
    let mut r = rsdp(2, 0, ROOT);
    r.resize(64, 0xAB);
    r[20..24].copy_from_slice(&64u32.to_le_bytes());
    fix_checksum(&mut r[..20], 8);
    fix_checksum(&mut r, 32);
    assert!(with(r).is_ok());
    assert_eq!(with(rsdp(2, 0, 0)), rsdp_err(Fault::NullRoot));
    assert_eq!(with(rsdp(0, 0, 0)), rsdp_err(Fault::NullRoot));

    // A revision-2 RSDP never falls back to its RSDT.
    let mut ram = machine(&tables);
    ram.put(RSDP, &rsdp(2, u32::try_from(ROOT).unwrap(), ROOT + 0x80));
    ram.put(ROOT, &rsdt(&[at(0)]));
    assert!(matches!(parse(&ram, RSDP), Err(AcpiError::Root { .. })));

    // An RSDP at the end of readable memory.
    let mut ram = Ram::new(BASE, 25);
    ram.put(BASE + 10, &rsdp(0, 0x1000, 0)[..15]);
    assert_eq!(
        parse(&ram, BASE + 10),
        Err(AcpiError::Rsdp {
            address: BASE + 10,
            fault: Fault::OutOfRange
        })
    );
    let mut ram = Ram::new(BASE, 30);
    ram.put(BASE, &rsdp(2, 0, ROOT)[..30]);
    assert_eq!(parse(&ram, BASE), rsdp_err(Fault::OutOfRange));
    // At the top of the address space.
    assert_eq!(
        parse(&Ram::new(u64::MAX - 3, 4), u64::MAX - 3),
        Err(AcpiError::Rsdp {
            address: u64::MAX - 3,
            fault: Fault::Unreadable
        })
    );
}

#[test]
fn root_table_checks() {
    let tables = [std_madt()];
    let root_err = |signature, fault| {
        Err(AcpiError::Root {
            signature,
            address: ROOT,
            fault,
        })
    };
    let with = |root: &[u8]| parse(&machine_listing(&tables, root), RSDP);

    let mut wrong = xsdt(&[at(0)]);
    wrong[..4].copy_from_slice(b"RSDT");
    fix_checksum(&mut wrong, 9);
    assert_eq!(
        with(&wrong),
        root_err(Signature::XSDT, Fault::Signature(Signature::RSDT))
    );
    let mut bad = xsdt(&[at(0)]);
    bad[40] ^= 1;
    assert_eq!(with(&bad), root_err(Signature::XSDT, Fault::Checksum));
    for len in [0, 35, MAX_TABLE_LEN + 1] {
        let mut t = xsdt(&[at(0)]);
        t[4..8].copy_from_slice(&len.to_le_bytes());
        assert_eq!(with(&t), root_err(Signature::XSDT, Fault::Length(len)));
    }
    // An entry area of 12 bytes is not whole 8-byte entries.
    let mut body = at(0).to_le_bytes().to_vec();
    body.extend_from_slice(&[0; 4]);
    assert_eq!(
        with(&sdt(b"XSDT", &body)),
        root_err(Signature::XSDT, Fault::Entries)
    );
    // An RSDT's is 4-byte entries: 6 bytes is not.
    let mut ram = machine_v0(&tables);
    ram.put(ROOT, &sdt(b"RSDT", &[0; 6]));
    assert_eq!(parse(&ram, RSDP), root_err(Signature::RSDT, Fault::Entries));
    // A root that runs past readable memory.
    let mut ram = machine(&tables);
    ram.put(RSDP, &rsdp(2, 0, BASE + SIZE as u64 - 40));
    let mut t = xsdt(&[at(0)]);
    t.truncate(40);
    ram.put(BASE + SIZE as u64 - 40, &t);
    assert!(matches!(
        parse(&ram, RSDP),
        Err(AcpiError::Root {
            fault: Fault::OutOfRange,
            ..
        })
    ));
    // A root whose end would overflow the address space.
    let mut ram = machine(&tables);
    ram.put(RSDP, &rsdp(2, 0, u64::MAX - 7));
    assert!(matches!(
        parse(&ram, RSDP),
        Err(AcpiError::Root {
            fault: Fault::Unreadable,
            ..
        })
    ));
    // An empty root lists no MADT.
    assert_eq!(with(&xsdt(&[])), Err(AcpiError::NoMadt));
}

#[test]
fn unreadable_and_repeated_entries() {
    let outside = BASE + SIZE as u64 + 0x1000;
    let root = xsdt(&[0, outside, at(0), at(0), u64::MAX - 2, at(1)]);
    let ram = machine_listing(&[std_madt(), hpet_table(0, 0xFED0_0000)], &root);
    let p = parse(&ram, RSDP).unwrap();
    assert_eq!(
        warnings(&p),
        [
            Warning::Unreadable { address: 0 },
            Warning::Unreadable { address: outside },
            Warning::Repeated {
                signature: Signature::MADT,
                address: at(0)
            },
            Warning::Unreadable {
                address: u64::MAX - 2
            },
        ]
    );
    assert_eq!(p.tables.len(), 3);
    assert!(p.hpet.is_some());
}

#[test]
fn madt_absent_twice_or_invalid() {
    assert_eq!(
        parse(&machine(&[hpet_table(0, 0xFED0_0000)]), RSDP),
        Err(AcpiError::NoMadt)
    );
    assert_eq!(
        parse(&machine(&[std_madt(), std_madt()]), RSDP),
        Err(AcpiError::Duplicate {
            signature: Signature::MADT,
            first: at(0),
            second: at(1)
        })
    );
    // A MADT outside readable memory.
    let outside = BASE + SIZE as u64;
    let ram = machine_listing(&[], &xsdt(&[outside]));
    assert_eq!(
        parse(&ram, RSDP),
        Err(AcpiError::NoMadt),
        "an unreadable header is not a MADT"
    );
    // A MADT whose header is readable but whose body is not.
    let mut ram = machine_listing(&[], &xsdt(&[BASE + SIZE as u64 - 40]));
    ram.put(BASE + SIZE as u64 - 40, &std_madt()[..40]);
    assert_eq!(
        parse(&ram, RSDP),
        Err(AcpiError::Madt {
            address: BASE + SIZE as u64 - 40,
            fault: Fault::OutOfRange
        })
    );
    // Shorter than its fixed fields.
    let short = sdt(b"APIC", &[0; 7]);
    assert_eq!(
        parse(&machine(&[short]), RSDP),
        Err(AcpiError::Madt {
            address: at(0),
            fault: Fault::Length(43)
        })
    );
    // Just the fixed fields: valid, with nothing in it.
    let p = parse(&machine(&[madt(&[])]), RSDP).unwrap();
    assert!(p.ioapics.is_empty() && p.overrides.is_empty());
    assert_eq!(p.madt.processors, 0);
}

#[test]
fn malformed_madt_entries_reject_the_madt() {
    let entry_err = |off| {
        Err(AcpiError::Madt {
            address: at(0),
            fault: Fault::MadtEntry(off),
        })
    };
    // Length 0 would loop forever; 1 cannot hold the header.
    for len in [0u8, 1] {
        let t = madt(&[lapic(0, 1), vec![0x7F, len, 0, 0]]);
        assert_eq!(parse(&machine(&[t]), RSDP), entry_err(52));
    }
    // An entry running past the end.
    let mut e = ioapic(0, 0xFEC0_0000, 0);
    e[1] = 13;
    assert_eq!(parse(&machine(&[madt(&[e])]), RSDP), entry_err(44));
    // A lone type byte at the end.
    let t = madt(&[lapic(0, 1), vec![0]]);
    assert_eq!(parse(&machine(&[t]), RSDP), entry_err(52));
}

#[test]
fn madt_entry_types() {
    let p = parse(
        &machine(&[madt(&[
            lapic(0, 1),
            lapic(1, 0), // disabled
            x2apic(300, 1),
            x2apic(301, 0),
            vec![3, 8, 0, 0, 0, 0, 0, 0],              // NMI source
            vec![4, 6, 0xFF, 5, 0, 1],                 // local APIC NMI
            vec![0x7F, 5, 1, 2, 3],                    // unknown
            vec![0xFF, 2],                             // unknown, header only
            vec![1, 10, 7, 0, 0, 0, 0xC0, 0xFE, 0, 0], // short I/O APIC
            ioapic(1, 0xFEC0_0000, 0),
            ioapic(2, 0, 24),     // address 0
            iso(1, 3, 3, 0),      // not ISA
            iso(0, 7, 7, 0b1010), // reserved polarity and trigger
            lapic_override(0x1_FEE0_0000),
            lapic_override(0x2_FEE0_0000),
        ])]),
        RSDP,
    )
    .unwrap();
    assert_eq!(p.madt.processors, 2);
    assert_eq!(p.madt.lapic, 0x1_FEE0_0000);
    assert!(p.madt.lapic_overridden);
    assert_eq!(p.ioapics.len(), 1);
    assert_eq!(p.ioapics.get(0).unwrap().id, 1);
    assert_eq!(p.overrides.len(), 1);
    assert_eq!(
        warnings(&p),
        [
            Warning::ShortEntry {
                kind: 1,
                length: 10
            },
            Warning::NullIoApic { id: 2 },
            Warning::NonIsaOverride { bus: 1, source: 3 },
            Warning::ReservedFlags {
                source: 7,
                flags: 0b1010
            },
        ]
    );
    // Reserved fields fall back to ISA's edge, active high.
    let r = p.isa_route(7).unwrap();
    assert_eq!((r.gsi, r.level, r.active_low), (7, false, false));
}

#[test]
fn io_apic_limit() {
    let four: Vec<_> = (0..4)
        .map(|i| ioapic(i, 0xFEC0_0000 + 0x1000 * u32::from(i), 24 * u32::from(i)))
        .collect();
    let p = parse(&machine(&[madt(&four)]), RSDP).unwrap();
    assert_eq!(p.ioapics.len(), 4);
    assert_eq!(p.ioapic_for_gsi(50, &[24, 24, 24, 24]), Some(2));
    assert_eq!(p.ioapic_for_gsi(96, &[24, 24, 24, 24]), None);
    assert_eq!(p.ioapic_for_gsi(30, &[24]), None, "no pin count, no match");
    let w = p.device_window(0xFEE0_0D00);
    assert_eq!(w.pages[window::ioapic_page(3)], Some(0xFEC0_3000));
    assert_eq!(w.pages[window::HPET_PAGE], None);

    let mut five = four.clone();
    five.push(ioapic(4, 0xFEC0_4000, 96));
    assert_eq!(
        parse(&machine(&[madt(&five)]), RSDP),
        Err(AcpiError::TooManyIoApics)
    );
}

#[test]
fn override_limit_and_routing() {
    let mut entries: Vec<_> = (0..16).map(|i| iso(0, i, 16 + u32::from(i), 0)).collect();
    entries.push(iso(0, 3, 99, 0));
    let p = parse(&machine(&[madt(&entries)]), RSDP).unwrap();
    assert_eq!(p.overrides.len(), MAX_OVERRIDES);
    assert_eq!(
        warnings(&p),
        [Warning::OverrideDropped { source: 3, gsi: 99 }]
    );
    assert_eq!(p.isa_route(3).unwrap().gsi, 19);

    // IRQ 4 moved to GSI 9 takes GSI 9 from IRQ 9; an active-low, level
    // override decodes as such.
    let p = parse(
        &machine(&[madt(&[iso(0, 4, 9, LOW_LEVEL), iso(0, 1, 1, 0b0001)])]),
        RSDP,
    )
    .unwrap();
    let r = p.isa_route(4).unwrap();
    assert_eq!(
        (r.gsi, r.level, r.active_low, r.flags()),
        (9, true, true, 3)
    );
    assert_eq!(p.isa_route(9), None);
    assert_eq!(p.isa_route(1).unwrap().flags(), 0, "explicit edge, high");
    assert_eq!(
        p.isa_route(4).unwrap().to_string(),
        "GSI 9, level, active low"
    );
    // Two IRQs moved onto one GSI: neither has a route.
    let p = parse(
        &machine(&[madt(&[iso(0, 3, 20, 0), iso(0, 5, 20, 0)])]),
        RSDP,
    )
    .unwrap();
    assert_eq!((p.isa_route(3), p.isa_route(5)), (None, None));
}

#[test]
fn hpet_table_checks() {
    let hpet = |space, base| {
        let p = parse(&machine(&[std_madt(), hpet_table(space, base)]), RSDP).unwrap();
        (p.hpet.map(|h| h.base), warnings(&p))
    };
    assert_eq!(hpet(0, 0xFED0_0000), (Some(0xFED0_0000), vec![]));
    assert_eq!(hpet(0, 0xFED0_0C00), (Some(0xFED0_0C00), vec![]));
    assert_eq!(
        hpet(1, 0xFED0_0000),
        (None, vec![Warning::HpetNotMemory { space: 1 }])
    );
    assert_eq!(hpet(0, 0), (None, vec![Warning::HpetBase { base: 0 }]));
    assert_eq!(
        hpet(0, 0xFED0_0C01),
        (None, vec![Warning::HpetBase { base: 0xFED0_0C01 }])
    );
    // Above any physical address, which no page table can map.
    assert_eq!(
        hpet(0, 1 << 52),
        (None, vec![Warning::HpetBase { base: 1 << 52 }])
    );
    assert_eq!(
        hpet(0, (1 << 52) - 0x1000),
        (Some((1 << 52) - 0x1000), vec![])
    );
    // One byte short of the fixed layout.
    let mut short = hpet_table(0, 0xFED0_0000);
    short.truncate(55);
    short[4..8].copy_from_slice(&55u32.to_le_bytes());
    fix_checksum(&mut short, 9);
    let p = parse(&machine(&[std_madt(), short]), RSDP).unwrap();
    assert_eq!(
        warnings(&p),
        [Warning::BadTable {
            signature: Signature::HPET,
            address: at(1),
            fault: Fault::Length(55)
        }]
    );
    // Two HPET tables.
    assert_eq!(
        parse(
            &machine(&[
                std_madt(),
                hpet_table(0, 0xFED0_0000),
                hpet_table(0, 0xFED0_1000)
            ]),
            RSDP
        ),
        Err(AcpiError::Duplicate {
            signature: Signature::HPET,
            first: at(1),
            second: at(2)
        })
    );
}

#[test]
fn mcfg_checks() {
    let ecam = |t: Vec<u8>| {
        let p = parse(&machine(&[std_madt(), t]), RSDP).unwrap();
        (p.ecam.iter().copied().collect::<Vec<_>>(), warnings(&p))
    };
    assert_eq!(ecam(mcfg(&[])), (vec![], vec![]));
    let (got, w) = ecam(mcfg(&[
        (0xE000_0000, 0, 0, 255),
        (0xD000_0000, 1, 9, 8),         // reversed
        (u64::MAX - 0xF_FFFF, 2, 0, 0), // overflows
        (0xC000_0000, 3, 0, 0),
        (0xC010_0000, 4, 0, 0),
        (0xC020_0000, 5, 2, 7),
        (0xC030_0000, 6, 0, 0), // the fifth good one
    ]));
    assert_eq!(got.len(), MAX_ECAM);
    assert_eq!(got[3].segment, 5);
    assert_eq!((got[3].start_bus, got[3].end_bus), (2, 7));
    assert_eq!(
        w,
        [
            Warning::BadEcam {
                base: 0xD000_0000,
                segment: 1,
                start_bus: 9,
                end_bus: 8
            },
            Warning::BadEcam {
                base: u64::MAX - 0xF_FFFF,
                segment: 2,
                start_bus: 0,
                end_bus: 0
            },
            Warning::EcamDropped {
                base: 0xC030_0000,
                segment: 6
            },
        ]
    );
    // A trailing part-entry rejects the table.
    let mut body = vec![0; 8];
    body.extend_from_slice(&[0; 20]);
    assert_eq!(
        ecam(sdt(b"MCFG", &body)),
        (
            vec![],
            vec![Warning::BadTable {
                signature: Signature::MCFG,
                address: at(1),
                fault: Fault::Entries
            }]
        )
    );
    // A second MCFG is ignored; the first is used.
    let p = parse(
        &machine(&[
            std_madt(),
            mcfg(&[(0xE000_0000, 0, 0, 255)]),
            mcfg(&[(0xD000_0000, 1, 0, 255)]),
        ]),
        RSDP,
    )
    .unwrap();
    assert_eq!(p.ecam.len(), 1);
    assert_eq!(p.ecam.get(0).unwrap().base, 0xE000_0000);
    assert_eq!(warnings(&p), [Warning::ExtraMcfg { address: at(2) }]);
}

#[test]
fn table_and_warning_lists_are_bounded() {
    // 40 tables of other kinds, then the MADT: 32 listed, all scanned.
    let mut tables: Vec<Vec<u8>> = (0..40).map(|_| sdt(b"OEMX", &[])).collect();
    tables.push(std_madt());
    let p = parse(&machine(&tables), RSDP).unwrap();
    assert_eq!(p.tables.len(), MAX_TABLES);
    assert_eq!(warnings(&p), [Warning::Unlisted { count: 9 }]);
    assert_eq!(p.ioapics.len(), 1);

    // 20 bad overrides: 16 warnings kept, 4 counted.
    let entries: Vec<_> = (0..20).map(|i| iso(1, i, 0, 0)).collect();
    let p = parse(&machine(&[madt(&entries)]), RSDP).unwrap();
    assert_eq!(p.warnings.len(), MAX_WARNINGS);
    assert_eq!(p.warnings_dropped, 4);
}

#[test]
fn messages() {
    assert_eq!(Signature(*b"AP\x00\xFF").to_string(), "AP??");
    assert_eq!(format!("{:?}", Signature::MADT), "Signature(\"APIC\")");
    assert_eq!(
        AcpiError::Root {
            signature: Signature::XSDT,
            address: 0x1000,
            fault: Fault::Checksum
        }
        .to_string(),
        "XSDT at 0x1000: bad checksum"
    );
    assert_eq!(
        AcpiError::TooManyIoApics.to_string(),
        "more than 4 I/O APICs"
    );
    assert_eq!(
        Warning::HpetNotMemory { space: 1 }.to_string(),
        "HPET in address space 1, not memory; no HPET"
    );
    // Every variant formats without panicking.
    let faults = [
        Fault::Unreadable,
        Fault::NotRsdp,
        Fault::Signature(Signature::RSDT),
        Fault::Length(3),
        Fault::OutOfRange,
        Fault::Checksum,
        Fault::ExtendedChecksum,
        Fault::NullRoot,
        Fault::Entries,
        Fault::MadtEntry(44),
    ];
    for f in faults {
        assert!(!f.to_string().is_empty());
    }
    let warnings = [
        Warning::Unreadable { address: 1 },
        Warning::Repeated {
            signature: Signature::MADT,
            address: 1,
        },
        Warning::Unlisted { count: 1 },
        Warning::BadTable {
            signature: Signature::HPET,
            address: 1,
            fault: Fault::Checksum,
        },
        Warning::ExtraMcfg { address: 1 },
        Warning::ShortEntry { kind: 1, length: 2 },
        Warning::NullIoApic { id: 1 },
        Warning::NonIsaOverride { bus: 1, source: 2 },
        Warning::ReservedFlags {
            source: 1,
            flags: 2,
        },
        Warning::OverrideDropped { source: 1, gsi: 2 },
        Warning::HpetBase { base: 1 },
        Warning::BadEcam {
            base: 1,
            segment: 2,
            start_bus: 3,
            end_bus: 4,
        },
        Warning::EcamDropped {
            base: 1,
            segment: 2,
        },
    ];
    for w in warnings {
        assert!(!w.to_string().is_empty());
    }
}

// ---------------------------------------------------------------------
// The dump format.

/// The dump of a small hand-made machine, as the loader would print it.
fn sample_ram() -> Ram {
    machine(&[
        std_madt(),
        hpet_table(0, 0xFED0_0000),
        mcfg(&[(0xE000_0000, 0, 0, 255)]),
    ])
}

fn sample_dump() -> String {
    let mut text = String::new();
    dump::write(&sample_ram(), RSDP, |line| {
        text.push_str(&format!("{line}\n"));
    });
    text
}

#[test]
fn dump_round_trip() {
    let ram = sample_ram();
    let m = DumpMemory::parse(&sample_dump()).unwrap();
    m.check().unwrap();
    assert_eq!(m.rsdp(), Some(RSDP));
    let names: Vec<_> = m.tables().iter().map(|t| t.name.as_str()).collect();
    assert_eq!(names, ["RSDP", "XSDT", "APIC", "HPET", "MCFG"]);
    assert_eq!(m.end(), Some(5));
    assert_eq!(parse(&m, RSDP), parse(&ram, RSDP));
    for t in m.tables() {
        for i in 0..u64::from(t.length) {
            assert_eq!(m.read_u8(t.address + i), ram.read_u8(t.address + i));
        }
        let at = usize::try_from(t.address - BASE).unwrap();
        assert_eq!(
            m.slice(t.address, t.length as usize),
            Some(&ram.bytes[at..at + t.length as usize])
        );
    }
    assert_eq!(m.read_u8(RSDP + 36), None, "no byte the dump lacks");
    assert_eq!(m.slice(RSDP, 37), None);
}

#[test]
fn dump_walk_follows_the_fadt_and_skips_repeats() {
    // A FADT naming a FACS and a DSDT through both its 32- and 64-bit
    // fields, listed by both an RSDT and an XSDT.
    let mut fadt_body = vec![0; 244 - 36];
    let facs = at(2);
    let dsdt = at(3);
    fadt_body[0..4].copy_from_slice(&u32::try_from(facs).unwrap().to_le_bytes());
    fadt_body[4..8].copy_from_slice(&u32::try_from(dsdt).unwrap().to_le_bytes());
    fadt_body[96..104].copy_from_slice(&facs.to_le_bytes());
    fadt_body[104..112].copy_from_slice(&dsdt.to_le_bytes());
    let mut facs_table = b"FACS".to_vec();
    facs_table.extend_from_slice(&64u32.to_le_bytes());
    facs_table.resize(64, 0);
    let tables = [
        std_madt(),
        sdt(b"FACP", &fadt_body),
        facs_table,
        sdt(b"DSDT", &[0x10; 100]),
    ];
    let mut ram = Ram::new(BASE, SIZE);
    ram.put(RSDP, &rsdp(2, u32::try_from(ROOT + 0x80).unwrap(), ROOT));
    ram.put(ROOT, &xsdt(&[at(0), at(1)]));
    ram.put(ROOT + 0x80, &rsdt(&[at(0), at(1)]));
    for (i, t) in tables.iter().enumerate() {
        ram.put(at(i), t);
    }
    let mut found = Vec::new();
    dump::walk(&ram, RSDP, |f| found.push((f.name, f.address, f.length)));
    let sig = |s: &[u8; 4]| Signature(*s);
    assert_eq!(
        found,
        [
            (sig(b"RSDP"), RSDP, 36),
            (sig(b"RSDT"), ROOT + 0x80, 44),
            (sig(b"APIC"), at(0), u32::try_from(tables[0].len()).unwrap()),
            (sig(b"FACP"), at(1), 244),
            (sig(b"FACS"), facs, 64),
            (sig(b"DSDT"), dsdt, 136),
            (sig(b"XSDT"), ROOT, 52),
        ]
    );
}

#[test]
fn dump_walk_is_lenient_and_bounded() {
    // A table with an absurd length is dumped as its header; an unreadable
    // one is skipped; a revision-0 RSDP is 20 bytes.
    let mut ram = Ram::new(BASE, SIZE);
    ram.put(RSDP, &rsdp(0, u32::try_from(ROOT).unwrap(), 0));
    ram.put(ROOT, &rsdt(&[at(0), 0xFFFF_F000, at(1)]));
    let mut huge = sdt(b"HUGE", &[]);
    huge[4..8].copy_from_slice(&u32::MAX.to_le_bytes());
    ram.put(at(0), &huge);
    ram.put(at(1), &sdt(b"OKAY", &[1, 2, 3]));
    let mut found = Vec::new();
    dump::walk(&ram, RSDP, |f| found.push((f.address, f.length)));
    assert_eq!(found, [(RSDP, 20), (ROOT, 48), (at(0), 36), (at(1), 39)]);
    // Nothing at all for an unreadable RSDP.
    let mut n = 0;
    dump::walk(&ram, 0x10, |_| n += 1);
    dump::walk(&ram, 0, |_| n += 1);
    assert_eq!(n, 0);
}

#[test]
fn dump_lines() {
    let line = |s| dump::parse_line(s);
    assert_eq!(line("BdsDxe: loading Boot0001"), None);
    assert_eq!(
        line("loader: acpidump: rsdp 000000000fb7e014\r"),
        Some(Ok(Line::Rsdp(0xFB7E014)))
    );
    assert_eq!(
        line("\x1b[0macpidump: table 000000000fb7e014 36 RSDP"),
        Some(Ok(Line::Table {
            address: 0xFB7E014,
            length: 36,
            name: "RSDP"
        }))
    );
    let data = line("acpidump: data 0000000000001000 00ff10Ab")
        .unwrap()
        .unwrap();
    assert!(matches!(
        data,
        Line::Data {
            address: 0x1000,
            len: 4,
            ..
        }
    ));
    assert_eq!(data.data(), [0x00, 0xFF, 0x10, 0xAB]);
    assert_eq!(Line::End(1).data(), []);
    assert_eq!(line("acpidump: end 11"), Some(Ok(Line::End(11))));
    for bad in [
        "acpidump: rsdp 1000",
        "acpidump: rsdp 000000000000100g",
        "acpidump: data 0000000000001000 0",
        "acpidump: data 0000000000001000 zz",
        "acpidump: data 0000000000001000",
        "acpidump: end",
        "acpidump: table 0000000000001000 -1 X",
        "acpidump: frob 1",
        "acpidump: end 3 extra",
        "acpidump: ",
    ] {
        assert!(matches!(line(bad), Some(Err(_))), "{bad:?}");
    }
    assert_eq!(line("acpidump:rsdp 0000000000001000"), None);
    let mut buf = [0; dump::BYTES_PER_LINE];
    assert_eq!(dump::decode_hex(&"ab".repeat(32), &mut buf), Some(32));
    assert_eq!(dump::decode_hex(&"ab".repeat(33), &mut buf), None);
    assert_eq!(dump::decode_hex("", &mut buf), None);
    assert_eq!(dump::decode_hex("+1", &mut buf), None);
    assert_eq!(dump::decode_hex("é1", &mut buf), None);
}

#[test]
fn dump_survives_a_windows_log() {
    // The owner's Hyper-V log: `\r\n` line ends, the loader's prefix, other
    // output in between, a terminal escape at the start of a line.
    let clean = sample_dump();
    let mut log = String::from("\x1b[2J\x1b[01;01HBdsDxe: starting Boot0001\r\n");
    for (i, l) in clean.lines().enumerate() {
        log.push_str("loader: ");
        log.push_str(l);
        log.push_str("\r\n");
        if i % 5 == 0 {
            log.push_str("some other line\r\n\r\n");
        }
    }
    log.push_str("microL4 kernel 0.1.0 (debug)\r\n");
    let m = DumpMemory::parse(&log).unwrap();
    m.check().unwrap();
    let want = DumpMemory::parse(&clean).unwrap();
    assert!(m.lines().eq(want.lines()));
    assert!(m.lines().eq(clean.lines().map(String::from)));
    assert_eq!(parse(&m, RSDP), parse(&want, RSDP));
}

#[test]
fn dump_check_finds_a_cut_log() {
    let text = sample_dump();
    let without = |pred: &dyn Fn(&str) -> bool| {
        let cut: String = text
            .lines()
            .filter(|l| !pred(l))
            .flat_map(|l| [l, "\n"])
            .collect();
        DumpMemory::parse(&cut).unwrap().check()
    };
    assert!(without(&|_| false).is_ok());
    assert!(without(&|l| l.contains("end ")).is_err());
    assert!(without(&|l| l.contains("rsdp ")).is_err());
    // A data line of the MADT, at `at(0)`, and the HPET's table line.
    assert!(text.contains("data 00000000000e1020"));
    assert!(without(&|l| l.contains("data 00000000000e1020")).is_err());
    assert!(without(&|l| l.contains("table 00000000000e2000")).is_err());
    let err = DumpMemory::parse("x\nacpidump: data 01 zz\n").unwrap_err();
    assert!(err.starts_with("line 2: "), "{err}");
}

// ---------------------------------------------------------------------
// Random input: `parse` returns, without panicking, within a read bound.

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 6 } else { 256 },
        // No files: Miri forbids them, and minimal failures worth keeping
        // become named tests here.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// A table at `at(i)` with signature `sig`, a body of random bytes, and,
/// if `fix`, a checksum that holds.
fn random_table(sig: &[u8; 4], body: &[u8], fix: bool) -> Vec<u8> {
    let mut t = sdt(sig, body);
    if !fix {
        t[9] = t[9].wrapping_add(1);
    }
    t
}

fn signature() -> impl Strategy<Value = [u8; 4]> {
    prop_oneof![
        Just(*b"APIC"),
        Just(*b"HPET"),
        Just(*b"MCFG"),
        Just(*b"FACP"),
        any::<[u8; 4]>(),
    ]
}

proptest! {
    #![proptest_config(config())]

    /// Pure noise, with the RSDP anywhere in or near it.
    #[test]
    fn random_bytes(
        bytes in prop::collection::vec(any::<u8>(), 0..512),
        base in prop_oneof![Just(BASE), Just(u64::MAX - 256), any::<u64>()],
        rsdp_off in 0u64..600,
    ) {
        let ram = Ram { base, bytes, reads: Cell::new(0) };
        let _ = parse(&ram, base.wrapping_add(rsdp_off));
        prop_assert!(ram.reads.get() <= read_bound(ram.bytes.len()));
        let mut n = 0u32;
        dump::write(&ram, base.wrapping_add(rsdp_off), |_| n += 1);
    }

    /// A valid RSDP and XSDT naming tables of random kinds, lengths and
    /// contents, some with good checksums, plus addresses anywhere.
    #[test]
    fn random_tables(
        tables in prop::collection::vec(
            (signature(), prop::collection::vec(any::<u8>(), 0..160), any::<bool>()),
            0..6,
        ),
        extra in prop::collection::vec(any::<u64>(), 0..3),
        v0 in any::<bool>(),
    ) {
        let built: Vec<Vec<u8>> = tables.iter().map(|(s, b, fix)| random_table(s, b, *fix)).collect();
        let ram = if v0 { machine_v0(&built) } else {
            let mut addrs: Vec<u64> = (0..built.len()).map(at).collect();
            addrs.extend(&extra);
            machine_listing(&built, &xsdt(&addrs))
        };
        let _ = parse(&ram, RSDP);
        prop_assert!(ram.reads.get() <= read_bound(SIZE));
    }

    /// A valid MADT around random entry bytes.
    #[test]
    fn random_madt_entries(
        entries in prop::collection::vec(any::<u8>(), 0..400),
        lapic in any::<u32>(),
        flags in any::<u32>(),
    ) {
        let mut body = lapic.to_le_bytes().to_vec();
        body.extend_from_slice(&flags.to_le_bytes());
        body.extend_from_slice(&entries);
        let ram = machine(&[sdt(b"APIC", &body)]);
        if let Ok(p) = parse(&ram, RSDP) {
            prop_assert!(p.ioapics.len() <= MAX_IOAPICS);
            for irq in 0..=255 {
                let _ = p.isa_route(irq);
            }
        }
        prop_assert!(ram.reads.get() <= read_bound(SIZE));
    }

    /// The q35 dump with random bytes changed, its checksums sometimes
    /// repaired so the change reaches the parser.
    #[test]
    fn mutated_dump(
        pokes in prop::collection::vec((any::<Index>(), any::<Index>(), any::<u8>()), 1..6),
        repair in any::<bool>(),
    ) {
        let mut m = q35();
        let tables = m.tables().to_vec();
        for (t, off, v) in &pokes {
            let t = t.get(&tables);
            m.poke(t.address + off.index(t.length as usize) as u64, *v);
        }
        if repair {
            for t in &tables {
                let bytes = m.slice_mut(t.address, t.length as usize).unwrap();
                match t.name.as_str() {
                    "RSDP" => {
                        fix_checksum(&mut bytes[..20], 8);
                        fix_checksum(bytes, 32);
                    }
                    "FACS" => {}
                    _ => fix_checksum(bytes, 9),
                }
            }
        }
        let counted = Counted { mem: &m, reads: Cell::new(0) };
        let _ = parse(&counted, m.rsdp().unwrap());
        prop_assert!(counted.reads.get() <= read_bound(m.bytes()));
    }
}
