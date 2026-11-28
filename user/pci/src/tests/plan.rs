//! The plan of a virtio-net function on synthetic headers built like the
//! fixture: the capabilities each type takes and skips, MSI-X, regions
//! outside their BAR or sharing the MSI-X table's page, and every other
//! refusal, in the design's order.

use std::format;
use std::string::ToString;

use super::model::Header;
use super::q35;
use super::scan::at;
use crate::{Function, Kind, Plan, Refusal, What, is_virtio_net, size};

/// A virtio-net function as QEMU lays it out (the fixture): MSI-X at
/// `0x98`, then the vendor capabilities at `0x84` (PCI configuration
/// access, type 5), `0x70` (notify), `0x60` (device), `0x50` (ISR) and
/// `0x40` (common).
pub fn nic() -> Header {
    Header::device(0x1af4, 0x1000)
        .class(0x02_00_00)
        .subsystem(0x1af4, 1)
        .command(7)
        .w8(0x3C, 0x0b)
        .w8(0x3D, 1)
        .bar(0, 0x6061, 32)
        .bar(1, 0x8101_1000, 0x1000)
        .bar(4, 0xC0_0000_0000 | 0b1100, 0x4000)
        .caps(0x98)
        .msix(0x98, 0x84, 4, (1, 0), (1, 0x800))
        .virtio(0x84, 0x70, 5, 0, 0, 0)
        .w8(0x86, 20)
        .notify(0x70, 0x60, 4, 0x3000, 0x1000, 4)
        .virtio(0x60, 0x50, 4, 4, 0x2000, 0x1000)
        .virtio(0x50, 0x40, 3, 4, 0x1000, 0x1000)
        .virtio(0x40, 0, 1, 4, 0, 0x1000)
}

fn plan(h: &Header) -> Result<Plan, Refusal> {
    let m = h.model();
    let f = Function::read(&m, at(0, 2, 0)).unwrap();
    let bars = size(&m, &f);
    assert!(m.violations.borrow().is_empty());
    Plan::virtio_net(&f, &m, &bars)
}

fn refused(h: Header) -> Refusal {
    plan(&h).unwrap_err()
}

#[test]
fn the_synthetic_nic_is_the_fixture() {
    let (n, f) = (nic(), q35::virtio_net());
    assert_eq!(n.bytes, f.bytes);
    assert_eq!(n.sizes, f.sizes);
    assert_eq!(plan(&n), plan(&f));
}

#[test]
fn virtio_net_is_the_modern_id_or_the_transitional_with_subsystem_1() {
    let is = |h: Header| is_virtio_net(&Function::read(&h.model(), at(0, 0, 0)).unwrap());
    assert!(is(Header::device(0x1af4, 0x1041)));
    assert!(is(Header::device(0x1af4, 0x1000).subsystem(0x1af4, 1)));
    assert!(
        !is(Header::device(0x1af4, 0x1000).subsystem(0x1af4, 2)),
        "a block device"
    );
    assert!(!is(Header::device(0x1af4, 0x1042)));
    assert!(!is(Header::device(0x8086, 0x1041)));
    assert!(!is(Header::device(0x1af4, 0x1041).w8(0x0E, 1)), "a bridge");
}

#[test]
fn each_region_must_have_its_capability() {
    for (cap, kind) in [
        (0x40, Kind::Common),
        (0x70, Kind::Notify),
        (0x60, Kind::Device),
    ] {
        let r = refused(nic().w8(cap + 3, 7));
        assert_eq!(r, Refusal::NoCapability(kind));
        assert_eq!(
            r.to_string(),
            format!("virtio-net: no {} capability", kind.name())
        );
    }
}

/// A capability too short, past the header, naming BAR 6, an I/O BAR, a
/// BAR not implemented or the upper half of a 64-bit BAR is skipped.
#[test]
fn capabilities_that_name_no_memory_bar_are_skipped() {
    let common = Refusal::NoCapability(Kind::Common);
    assert_eq!(refused(nic().w8(0x42, 15)), common);
    assert_eq!(
        refused(nic().w8(0x72, 16)),
        Refusal::NoCapability(Kind::Notify)
    );
    for bar in [0, 2, 3, 5, 6, 7, 0xFF] {
        assert_eq!(refused(nic().w8(0x44, bar)), common, "BAR {bar}");
    }
    // The common capability moved to 0xF4, whose 16 bytes pass 0x100.
    let h = nic()
        .w8(0x41, 0xF4)
        .w8(0x43, 7)
        .cap(0xF4, 0x09, 0)
        .w8(0xF6, 16)
        .w8(0xF7, 1)
        .w8(0xF8, 4);
    assert_eq!(refused(h), common);
}

#[test]
fn the_first_of_each_type_that_names_a_memory_bar_is_taken() {
    // A second common capability at 0xB0, after the first.
    let second = |h: Header| h.w8(0x41, 0xB0).virtio(0xB0, 0, 1, 4, 0x100, 0x200);
    let p = plan(&second(nic())).unwrap();
    assert_eq!(p.region(Kind::Common).cap, 0x40);
    // With the first naming the I/O BAR, the second.
    let p = plan(&second(nic().w8(0x44, 0))).unwrap();
    let c = p.region(Kind::Common);
    assert_eq!(
        (c.cap, c.offset, c.length, c.in_page()),
        (0xB0, 0x100, 0x200, 0x100)
    );
}

#[test]
fn msix_must_be_there_in_memory_bars() {
    assert_eq!(refused(nic().w8(0x98, 0x05)), Refusal::NoMsix);
    assert_eq!(
        refused(nic().w32(0x9C, 0)),
        Refusal::NoMsix,
        "table in the I/O BAR"
    );
    assert_eq!(refused(nic().w32(0x9C, 6)), Refusal::NoMsix, "BIR 6");
    assert_eq!(
        refused(nic().w32(0xA0, 0x802)),
        Refusal::NoMsix,
        "PBA in no BAR"
    );
    // An MSI-X capability at 0xF8, whose 12 bytes pass 0x100.
    let h = nic()
        .w8(0x98, 0x05)
        .w8(0x41, 0xF8)
        .cap(0xF8, 0x11, 0)
        .w16(0xFA, 3)
        .w32(0xFC, 1);
    assert_eq!(refused(h), Refusal::NoMsix);
    assert_eq!(Refusal::NoMsix.to_string(), "virtio-net: no MSI-X");
}

#[test]
fn regions_too_short_or_too_long_are_refused() {
    for (cap, kind, min) in [
        (0x40, Kind::Common, 56),
        (0x70, Kind::Notify, 2),
        (0x60, Kind::Device, 8),
    ] {
        let r = refused(nic().w32(cap + 12, min - 1));
        assert_eq!(
            r,
            Refusal::TooShort {
                kind,
                length: min - 1
            }
        );
        assert!(plan(&nic().w32(cap + 12, min)).is_ok());
    }
    let wide = |h: Header| h.bar(4, 0xC0_0000_0000 | 0b1100, 0x2_0000);
    let p = plan(&wide(nic().w32(0x48, 0x1_0000).w32(0x4C, 60 << 10))).unwrap();
    assert_eq!(p.region(Kind::Common).pages(), 15);
    let r = refused(wide(nic().w32(0x48, 0x1_0000).w32(0x4C, (60 << 10) + 1)));
    assert_eq!(
        r,
        Refusal::TooLong {
            kind: Kind::Common,
            length: (60 << 10) + 1
        }
    );
    assert_eq!(
        r.to_string(),
        "virtio-net: common region of 61441 bytes, over 61440"
    );
}

#[test]
fn regions_and_the_table_must_lie_inside_their_bar() {
    let common = Refusal::Outside {
        what: What::Region(Kind::Common),
        bar: 4,
    };
    assert_eq!(refused(nic().w32(0x48, 0x3800)), common);
    assert_eq!(common.to_string(), "virtio-net: common outside BAR4");
    // An offset that would wrap a 32-bit sum.
    assert_eq!(
        refused(nic().w32(0x48, 0xFFFF_F000).w32(0x4C, 0x2000)),
        common
    );
    // A BAR at the top of the address space: its end overflows.
    let top = nic().bar(4, 0xFFFF_FFFF_FFFF_C000 | 0b1100, 0x4000);
    assert_eq!(refused(top), common);
    // 129 vectors' table from 0x800 passes BAR1's 4 KiB.
    let r = refused(nic().w16(0x9A, 128).w32(0x9C, 0x801).w32(0xA0, 1));
    assert_eq!(
        r,
        Refusal::Outside {
            what: What::Table,
            bar: 1
        }
    );
    assert_eq!(r.to_string(), "virtio-net: MSI-X table outside BAR1");
    let r = refused(nic().w16(0x9A, 64).w32(0xA0, 0xFF9));
    assert_eq!(
        r,
        Refusal::Outside {
            what: What::Pba,
            bar: 1
        }
    );
    assert_eq!(r.to_string(), "virtio-net: MSI-X PBA outside BAR1");
}

/// A 2 KiB BAR: the page under it holds more than the BAR, maybe another
/// device's registers, so the driver may not map it.
#[test]
fn a_regions_pages_must_lie_inside_its_bar() {
    let h = nic()
        .bar(2, 0x9000_0800, 0x800)
        .w8(0x64, 2)
        .w32(0x68, 0)
        .w32(0x6C, 0x800);
    let r = refused(h);
    assert_eq!(
        r,
        Refusal::PagesOutside {
            kind: Kind::Device,
            bar: 2
        }
    );
    assert_eq!(
        r.to_string(),
        "virtio-net: device's pages reach outside BAR2"
    );
}

#[test]
fn an_odd_notify_multiplier_is_refused() {
    assert_eq!(refused(nic().w32(0x80, 3)), Refusal::OddMultiplier(3));
    assert_eq!(plan(&nic().w32(0x80, 0)).unwrap().notify_off_multiplier, 0);
}

#[test]
fn no_region_shares_a_page_with_the_table_the_pba_or_another_region() {
    let shares = |kind, with| Refusal::SharesPage { kind, with };
    // The device region in BAR1, beside the table and the PBA.
    let r = refused(nic().w8(0x64, 1).w32(0x68, 0x900).w32(0x6C, 0x100));
    assert_eq!(r, shares(Kind::Device, What::Table));
    assert_eq!(
        r.to_string(),
        "virtio-net: device shares a page with the MSI-X table"
    );
    // The PBA in notify's page of BAR4.
    let r = refused(nic().w32(0xA0, 0x3804));
    assert_eq!(r, shares(Kind::Notify, What::Pba));
    assert_eq!(
        r.to_string(),
        "virtio-net: notify shares a page with the MSI-X PBA"
    );
    // The device region in common's page.
    let r = refused(nic().w32(0x68, 0x800).w32(0x6C, 0x100));
    assert_eq!(r, shares(Kind::Device, What::Region(Kind::Common)));
    assert_eq!(
        r.to_string(),
        "virtio-net: device shares a page with common"
    );
    // Next to each other but in pages of their own is fine.
    assert!(plan(&nic().w32(0x68, 0x1000)).is_ok());
}

#[test]
fn msix_entry_0_must_lie_in_one_page() {
    let h = nic()
        .bar(1, 0x8101_0000, 0x2000)
        .w32(0x9C, 0xFF9)
        .w32(0xA0, 0x1801);
    assert_eq!(refused(h), Refusal::EntryCrossesPage);
    let p = plan(
        &nic()
            .bar(1, 0x8101_0000, 0x2000)
            .w32(0x9C, 0xFF1)
            .w32(0xA0, 0x1801),
    );
    assert_eq!(p.unwrap().entry0_in_page(), 0xFF0);
}

#[test]
fn a_region_over_pages_maps_each_in_its_window() {
    let p = plan(
        &nic()
            .w32(0x48, 0x100)
            .w32(0x4C, 0x1F00)
            .w32(0x68, 0x2008)
            .w32(0x6C, 0x8),
    )
    .unwrap();
    let c = p.region(Kind::Common);
    assert_eq!(
        (c.pages(), c.in_page(), c.word()),
        (2, 0x100, 0x100 | 0x1F00 << 16)
    );
    let pages: std::vec::Vec<_> = p
        .pages()
        .map(|p| (p.kind, p.index, p.paddr, p.offset))
        .collect();
    assert_eq!(
        pages,
        [
            (Kind::Common, 0, 0xC0_0000_0000, 0),
            (Kind::Common, 1, 0xC0_0000_1000, 0x1000),
            (Kind::Notify, 0, 0xC0_0000_3000, 0x1_0000),
            (Kind::Device, 0, 0xC0_0000_2000, 0x2_0000),
        ]
    );
    assert_eq!(p.page_count(), 4);
    assert_eq!(p.region(Kind::Device).word(), 8 | 8 << 16);
}
