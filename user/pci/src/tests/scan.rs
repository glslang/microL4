//! The scan on synthetic segments: q35's shape, multi-function devices,
//! bridges, bus loops, ranges, a bus that cannot be reached, and the
//! capability walk's ends.

use std::vec::Vec;

use super::model::{Header, Space};
use crate::{
    Address, Capabilities, Capability, Function, Range, ScanError, Scanned, WalkEnd, scan,
};

pub fn at(bus: u8, device: u8, function: u8) -> Address {
    Address::new(bus, device, function).unwrap()
}

const ALL: Range = Range {
    segment: 0,
    start_bus: 0,
    end_bus: 255,
};

/// Every function `scan` visits, in order, and its result.
pub fn visit(
    space: &mut Space,
    range: Range,
) -> (Vec<Function>, Result<Scanned, ScanError<&'static str>>) {
    let mut seen = Vec::new();
    let r = scan(space, range, |f| seen.push(*f));
    (seen, r)
}

fn addresses(fs: &[Function]) -> Vec<Address> {
    fs.iter().map(|f| f.address).collect()
}

/// q35's functions with a virtio-net NIC (the `pci` scenario's), as
/// headers with IDs and classes only.
pub fn q35(nic: Header) -> Vec<(Address, Header)> {
    std::vec![
        (
            at(0, 0, 0),
            Header::device(0x8086, 0x29c0).class(0x06_00_00)
        ),
        (
            at(0, 1, 0),
            Header::device(0x1234, 0x1111).class(0x03_00_00)
        ),
        (at(0, 2, 0), nic),
        (
            at(0, 0x1f, 0),
            Header::device(0x8086, 0x2918).class(0x06_01_00).multi()
        ),
        (
            at(0, 0x1f, 2),
            Header::device(0x8086, 0x2922).class(0x01_06_01).multi()
        ),
        (
            at(0, 0x1f, 3),
            Header::device(0x8086, 0x2930).class(0x0c_05_00).multi()
        ),
    ]
}

#[test]
fn q35_has_six_functions_on_one_bus() {
    let mut s = Space::new(&q35(Header::device(0x1af4, 0x1000).class(0x02_00_00)));
    let (fs, r) = visit(&mut s, ALL);
    assert_eq!(
        r,
        Ok(Scanned {
            functions: 6,
            buses: 1
        })
    );
    assert_eq!(s.reached, [0]);
    assert_eq!(
        addresses(&fs),
        [
            at(0, 0, 0),
            at(0, 1, 0),
            at(0, 2, 0),
            at(0, 0x1f, 0),
            at(0, 0x1f, 2),
            at(0, 0x1f, 3)
        ]
    );
    let lines: Vec<_> = fs.iter().map(|f| std::format!("{f}")).collect();
    assert_eq!(lines[2], "00:02.0 1af4:1000 class 020000");
    assert_eq!(lines[3], "00:1f.0 8086:2918 class 060100");
    assert!(fs[3].multi_function() && !fs[0].multi_function());
}

#[test]
fn only_a_multi_function_devices_functions_1_to_7_are_read() {
    let mut s = Space::new(&[
        // Multi-function, with gaps.
        (at(0, 3, 0), Header::device(1, 1).multi()),
        (at(0, 3, 2), Header::device(1, 2)),
        (at(0, 3, 7), Header::device(1, 3)),
        // Not multi-function: function 1 is never read.
        (at(0, 4, 0), Header::device(2, 1)),
        (at(0, 4, 1), Header::device(2, 2)),
        // No function 0: no device, whatever else answers.
        (at(0, 5, 1), Header::device(3, 1)),
        (at(0, 31, 0), Header::device(4, 1)),
    ]);
    let (fs, r) = visit(&mut s, ALL);
    assert_eq!(r.unwrap().functions, 5);
    assert_eq!(
        addresses(&fs),
        [
            at(0, 3, 0),
            at(0, 3, 2),
            at(0, 3, 7),
            at(0, 4, 0),
            at(0, 31, 0)
        ]
    );
}

#[test]
fn bridges_add_each_secondary_bus_once_in_the_order_found() {
    let mut s = Space::new(&[
        (at(0, 1, 0), Header::bridge(1)),
        (at(0, 2, 0), Header::bridge(3)),
        (at(1, 0, 0), Header::bridge(2)),
        // A second bridge to bus 3, already queued.
        (at(1, 5, 0), Header::bridge(3)),
        (at(2, 0, 0), Header::device(0x1af4, 0x1041)),
        (at(3, 0, 0), Header::device(0x1af4, 0x1042)),
    ]);
    let (fs, r) = visit(&mut s, ALL);
    assert_eq!(
        r,
        Ok(Scanned {
            functions: 6,
            buses: 4
        })
    );
    assert_eq!(s.reached, [0, 1, 3, 2]);
    assert_eq!(
        addresses(&fs),
        [
            at(0, 1, 0),
            at(0, 2, 0),
            at(1, 0, 0),
            at(1, 5, 0),
            at(3, 0, 0),
            at(2, 0, 0)
        ]
    );
    assert_eq!(fs[0].secondary(), Some(1));
    assert_eq!(fs[0].bar_count(), 2);
    assert_eq!(fs[4].secondary(), None);
}

/// Bridges back to bus 0, to their own bus, and to each other's: every
/// bus is reached once (the model fails a second reach) and the scan
/// ends.
#[test]
fn bus_loops_end() {
    let mut s = Space::new(&[
        (at(0, 0, 0), Header::bridge(1)),
        (at(1, 0, 0), Header::bridge(0)),
        (at(1, 1, 0), Header::bridge(1)),
        (at(1, 2, 0), Header::bridge(2)),
        (at(2, 0, 0), Header::bridge(1)),
        (at(2, 1, 0), Header::bridge(2).multi()),
        (at(2, 1, 1), Header::bridge(0)),
    ]);
    let (fs, r) = visit(&mut s, ALL);
    assert_eq!(r.unwrap().buses, 3);
    assert_eq!(s.reached, [0, 1, 2]);
    assert_eq!(fs.len(), 7);
}

#[test]
fn only_buses_in_the_range_are_reached() {
    let range = Range {
        segment: 1,
        start_bus: 2,
        end_bus: 5,
    };
    let mut s = Space::new(&[
        (at(2, 0, 0), Header::bridge(7)),
        (at(2, 1, 0), Header::bridge(1)),
        (at(2, 2, 0), Header::bridge(4)),
        (at(4, 0, 0), Header::device(9, 9)),
        // Bus 0 is outside the range, so this is never read.
        (at(0, 0, 0), Header::device(8, 8)),
    ]);
    let (fs, r) = visit(&mut s, range);
    assert_eq!(s.reached, [2, 4]);
    assert_eq!(fs.len(), 4);
    assert_eq!(r.unwrap().buses, 2);
    assert!(range.contains(5) && !range.contains(6) && !range.contains(1));
}

#[test]
fn a_bus_that_cannot_be_reached_ends_the_scan() {
    let mut s = Space::new(&[
        (at(0, 0, 0), Header::bridge(1)),
        (at(0, 1, 0), Header::device(1, 1)),
        (at(1, 0, 0), Header::device(2, 2)),
    ]);
    s.refuse = Some(1);
    let (fs, r) = visit(&mut s, ALL);
    assert_eq!(
        r,
        Err(ScanError {
            bus: 1,
            error: "refused"
        })
    );
    assert_eq!(fs.len(), 2, "bus 0's functions came first");
}

#[test]
fn an_empty_segment_has_no_functions() {
    let mut s = Space::new(&[]);
    let (fs, r) = visit(&mut s, ALL);
    assert!(fs.is_empty());
    assert_eq!(
        r,
        Ok(Scanned {
            functions: 0,
            buses: 1
        })
    );
}

fn walk(h: Header) -> Capabilities {
    let m = h.model();
    let f = Function::read(&m, at(0, 0, 0)).unwrap();
    assert_eq!(f.capabilities, Capabilities::walk(&m, f.status, f.layout()));
    f.capabilities
}

fn list(c: &Capabilities) -> Vec<(u8, u8)> {
    c.as_slice().iter().map(|c| (c.id, c.offset)).collect()
}

#[test]
fn the_capability_walk_ends_on_null_loops_and_bad_pointers() {
    let base = || Header::device(1, 1);
    // A list as the specification has it.
    let c = walk(base().caps(0x40).cap(0x40, 0x05, 0x50).cap(0x50, 0x11, 0));
    assert_eq!(list(&c), [(0x05, 0x40), (0x11, 0x50)]);
    assert_eq!(c.end, WalkEnd::Null);
    assert_eq!(c.with_id(0x11).collect::<Vec<_>>(), [0x50]);
    // Back to the first, and to itself.
    let c = walk(base().caps(0x40).cap(0x40, 1, 0x50).cap(0x50, 2, 0x40));
    assert_eq!((c.len(), c.end), (2, WalkEnd::Loop(0x40)));
    let c = walk(base().caps(0x48).cap(0x48, 1, 0x48));
    assert_eq!((c.len(), c.end), (1, WalkEnd::Loop(0x48)));
    // Into the header, at the start and later.
    let c = walk(base().caps(0x20));
    assert_eq!((c.len(), c.end), (0, WalkEnd::BadPointer(0x20)));
    let c = walk(base().caps(0x40).cap(0x40, 1, 0x3C));
    assert_eq!((c.len(), c.end), (1, WalkEnd::BadPointer(0x3C)));
    // Pointers masked to multiples of 4: 0x43 is 0x40, 0x03 is null.
    let c = walk(base().caps(0x43).cap(0x40, 7, 0x52).cap(0x50, 8, 0x03));
    assert_eq!(list(&c), [(7, 0x40), (8, 0x50)]);
    assert_eq!(c.end, WalkEnd::Null);
    // No list: status bit 4 clear, whatever 0x34 holds; a CardBus header.
    let c = walk(base().w8(0x34, 0x40).cap(0x40, 1, 0));
    assert_eq!((c.len(), c.end), (0, WalkEnd::NoList));
    let c = walk(base().w8(0x0E, 2).caps(0x40).cap(0x40, 1, 0));
    assert_eq!((c.len(), c.end), (0, WalkEnd::NoList));
    assert!(c.is_empty());
}

/// Every multiple of 4 from `0x40` once: 48 entries, then a pointer back.
#[test]
fn a_full_list_holds_48_capabilities() {
    let mut h = Header::device(1, 1).caps(0x40);
    for k in 0..48u8 {
        let at = 0x40 + 4 * k;
        let next = if k == 47 { 0x40 } else { at + 4 };
        h = h.cap(at, k, next);
    }
    let c = walk(h);
    assert_eq!(c.len(), crate::scan::MAX_CAPABILITIES);
    assert_eq!(c.end, WalkEnd::Loop(0x40));
    assert_eq!(
        c.as_slice()[47],
        Capability {
            id: 47,
            offset: 0xFC
        }
    );
}

#[test]
fn a_function_reads_its_header() {
    let m = Header::device(0x1af4, 0x1000)
        .class(0x02_00_00)
        .w8(0x08, 0x01)
        .subsystem(0x1af4, 1)
        .command(0x0507)
        .bar(1, 0xC104_0000, 0x1000)
        .model();
    let f = Function::read(&m, at(0, 2, 0)).unwrap();
    assert_eq!(
        (f.vendor, f.device, f.revision, f.class),
        (0x1af4, 0x1000, 1, 0x02_00_00)
    );
    assert_eq!(
        (f.subsystem_vendor, f.subsystem, f.command),
        (0x1af4, 1, 0x0507)
    );
    assert_eq!(f.bars, [0, 0xC104_0000, 0, 0, 0, 0]);
    assert_eq!((f.layout(), f.bar_count(), f.secondary()), (0, 6, None));
    // A bridge's: two BARs, its buses, no subsystem.
    let b = Function::read(&Header::bridge(4).w32(0x2C, !0).model(), at(0, 1, 0)).unwrap();
    assert_eq!(
        (b.bar_count(), b.secondary(), b.subordinate_bus),
        (2, Some(4), 4)
    );
    assert_eq!((b.subsystem_vendor, b.subsystem), (0, 0));
    // Other layouts have no BARs.
    let c = Function::read(
        &Header::device(1, 1).w8(0x0E, 0x7F).w32(0x10, 5).model(),
        at(0, 0, 0),
    );
    assert_eq!(c.unwrap().bar_count(), 0);
    assert_eq!(c.unwrap().bars, [0; 6]);
    // All ones: no function.
    assert_eq!(
        Function::read(&Header::device(0xFFFF, 0).model(), at(0, 0, 0)),
        None
    );
}

#[test]
fn address_rules() {
    assert_eq!(Address::new(0, 32, 0), None);
    assert_eq!(Address::new(0, 0, 8), None);
    let a = at(0xab, 0x1f, 7);
    assert_eq!(std::format!("{a}"), "ab:1f.7");
    assert_eq!(a.ecam_offset(), 0xab << 20 | 0x1f << 15 | 7 << 12);
    assert_eq!(at(255, 31, 7).ecam_offset(), (256 << 20) - 4096);
}
