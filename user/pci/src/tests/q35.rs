//! The q35 fixture: the virtio-net function's 256 bytes as OVMF left
//! them, recorded by `test=pci` (`user/pci/tests/q35-virtio-net.cfg`), on
//! a q35-shaped segment, with the BAR sizes the same boot found. What root
//! printed is what these give.

use std::format;
use std::string::String;
use std::vec::Vec;

use super::model::{Header, Ram, Space};
use super::scan::{at, q35, visit};
use crate::{
    Config, Function, Kind, Message, Msix, Plan, Range, WalkEnd, command, is_virtio_net, size,
};

const FIXTURE: &str = include_str!("../../tests/q35-virtio-net.cfg");

/// The fixture's bytes: lines `pci: cfg <offset>: <16 bytes>`, `#`
/// comments.
fn fixture() -> [u8; 256] {
    let mut bytes = [0u8; 256];
    let mut rows = 0;
    for line in FIXTURE.lines().filter(|l| !l.starts_with('#')) {
        let rest = line.strip_prefix("pci: cfg ").expect(line);
        let (offset, hex) = rest.split_once(':').expect(line);
        let offset = usize::from_str_radix(offset, 16).unwrap();
        assert_eq!(offset, 16 * rows, "rows in order");
        let row: Vec<u8> = hex
            .split_whitespace()
            .map(|b| u8::from_str_radix(b, 16).unwrap())
            .collect();
        bytes[offset..offset + 16].copy_from_slice(&row);
        rows += 1;
    }
    assert_eq!(rows, 16);
    bytes
}

/// The function with the sizes the `pci` scenario printed.
pub fn virtio_net() -> Header {
    Header {
        bytes: fixture(),
        sizes: [32, 4096, 0, 0, 16384, 0],
    }
}

fn found() -> (Space, Function) {
    let mut s = Space::new(&q35(virtio_net()));
    let (fs, r) = visit(
        &mut s,
        Range {
            segment: 0,
            start_bus: 0,
            end_bus: 255,
        },
    );
    assert_eq!(r.unwrap().functions, 6);
    let nic: Vec<_> = fs.iter().filter(|f| is_virtio_net(f)).collect();
    assert_eq!(nic.len(), 1);
    (s, *nic[0])
}

#[test]
fn the_fixture_is_a_transitional_virtio_net_with_ovmfs_bars() {
    let (_, f) = found();
    assert_eq!(f.address, at(0, 2, 0));
    assert_eq!(format!("{f}"), "00:02.0 1af4:1000 class 020000");
    assert_eq!((f.subsystem_vendor, f.subsystem), (0x1af4, 1));
    // OVMF left I/O, memory and bus mastering on.
    assert_eq!(
        f.command,
        command::IO | command::MEMORY | command::BUS_MASTER
    );
    assert_eq!(f.bars, [0x6061, 0x8101_1000, 0, 0, 0xc, 0xc0]);
    let caps: Vec<_> = f
        .capabilities
        .as_slice()
        .iter()
        .map(|c| (c.id, c.offset))
        .collect();
    assert_eq!(
        caps,
        [
            (0x11, 0x98),
            (9, 0x84),
            (9, 0x70),
            (9, 0x60),
            (9, 0x50),
            (9, 0x40)
        ]
    );
    assert_eq!(f.capabilities.end, WalkEnd::Null);
}

#[test]
fn the_fixtures_plan_is_what_root_printed() {
    let (s, f) = found();
    let m = &s.functions[&f.address];
    let bars = size(m, &f);
    assert!(m.violations.borrow().is_empty(), "{:?}", m.violations);
    assert_eq!(m.header(), fixture(), "sizing restored everything");
    let line: Vec<String> = bars.iter().map(|b| format!("{b}")).collect();
    assert_eq!(
        line.join("; "),
        "BAR0 I/O 0x6060, 32 bytes; BAR1 memory32 0x81011000, 4 KiB; \
         BAR4 memory64 prefetchable 0xc000000000, 16 KiB"
    );
    let plan = Plan::virtio_net(&f, m, &bars).unwrap();
    let r = |k| format!("{}", plan.region(k));
    assert_eq!(
        format!(
            "{}; {}, notify_off_multiplier {}; {}",
            r(Kind::Common),
            r(Kind::Notify),
            plan.notify_off_multiplier,
            r(Kind::Device)
        ),
        "common at BAR4+0x0, 4 KiB; notify at BAR4+0x3000, 4 KiB, notify_off_multiplier 4; \
         device at BAR4+0x2000, 4 KiB"
    );
    assert_eq!(
        format!(
            "MSI-X {} vectors, table at {} ({:#x}), PBA at {} ({:#x})",
            plan.msix.vectors, plan.msix.table, plan.table, plan.msix.pba, plan.pba
        ),
        "MSI-X 4 vectors, table at BAR1+0x0 (0x81011000), PBA at BAR1+0x800 (0x81011800)"
    );
    // The pages the driver maps, one a region, in its windows.
    let pages: Vec<_> = plan.pages().map(|p| (p.kind, p.paddr, p.offset)).collect();
    assert_eq!(
        pages,
        [
            (Kind::Common, 0xC0_0000_0000, 0),
            (Kind::Notify, 0xC0_0000_3000, 0x1_0000),
            (Kind::Device, 0xC0_0000_2000, 0x2_0000),
        ]
    );
    assert_eq!(plan.page_count(), 3);
    // Each region whole in its window, 4 KiB long: the driver's words.
    assert_eq!(plan.regions.map(|r| r.word()), [0x1000_0000; 3]);
    assert_eq!((plan.table_page(), plan.entry0_in_page()), (0x8101_1000, 0));
    // The ISR region (type 3, at 0x50) and the PCI configuration access
    // capability (type 5, at 0x84) are not the plan's.
    assert!(plan.regions.iter().all(|r| r.cap != 0x50 && r.cap != 0x84));
}

/// Entry 0 programmed as root programs it, with the message
/// `IRQControl_GetMSI` gives for IRQ 1 (vector `0x31`): the table written
/// only while Function Mask is set, then MSI-X enabled and unmasked.
#[test]
fn msix_entry_0_programs_on_the_fixture() {
    let (s, f) = found();
    let m = &s.functions[&f.address];
    let msix = Msix::find(&f, m).unwrap();
    assert_eq!((msix.cap, msix.vectors, msix.control), (0x98, 4, 3));
    let table = Ram::new();
    for e in 0..4 {
        table.write32(16 * e + 12, 1);
    }
    table.writes.borrow_mut().clear();
    let msg = Message {
        address: 0xFEE0_0000,
        data: 0x31,
    };
    msix.program(m, &table, 0, msg);
    assert_eq!(m.read16(0x9A), 0x8003, "Enable set, Function Mask clear");
    assert_eq!(
        *table.writes.borrow(),
        [(0, 0xFEE0_0000), (4, 0), (8, 0x31), (12, 0)]
    );
    for e in 1..4 {
        assert_eq!(
            Msix::vector_control(&table, 16 * e),
            1,
            "entry {e} still masked"
        );
    }
}
