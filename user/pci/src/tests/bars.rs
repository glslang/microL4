//! BAR sizing on the model, which records a violation for a BAR written
//! while its space decodes: I/O, 32- and 64-bit memory, 64-bit BARs of 4
//! GiB and more, BARs not implemented, reserved types, and a bridge's two.

use std::format;
use std::vec::Vec;

use super::model::Header;
use super::scan::at;
use crate::{Bar, Bars, Bytes, Config, Function, Space, command, enable_memory, size};

const MEM64_PF: u64 = 0b1100;

fn sized(h: &Header) -> (Bars, super::model::Model) {
    let m = h.model();
    let f = Function::read(&m, at(0, 0, 0)).unwrap();
    let before = m.header();
    let bars = size(&m, &f);
    assert_eq!(*m.violations.borrow(), Vec::<std::string::String>::new());
    assert_eq!(
        m.header(),
        before,
        "every BAR and the command register restored"
    );
    (bars, m)
}

#[test]
fn bars_are_sized_with_decode_off_and_restored() {
    let h = Header::device(0x1af4, 0x1000)
        .command(command::IO | command::MEMORY | command::BUS_MASTER)
        .bar(0, 0xC040 | 1, 32)
        .bar(1, 0xC104_0000, 0x1000)
        .bar(4, 0xC0_0000_0000 | MEM64_PF, 0x4000);
    let (bars, _) = sized(&h);
    let got: Vec<_> = bars.iter().map(|b| format!("{b}")).collect();
    assert_eq!(
        got,
        [
            "BAR0 I/O 0xc040, 32 bytes",
            "BAR1 memory32 0xc1040000, 4 KiB",
            "BAR4 memory64 prefetchable 0xc000000000, 16 KiB",
        ]
    );
    assert_eq!(bars.get(2), None, "not implemented");
    assert_eq!(bars.get(5), None, "BAR4's upper half");
    assert_eq!(bars.get(6), None);
    assert_eq!(bars.memory(0), None, "an I/O BAR");
    assert_eq!(bars.memory(4).map(|b| b.end()), Some(Some(0xC0_0000_4000)));
}

/// The model itself: a BAR written with decode on is a violation.
#[test]
fn the_model_catches_a_bar_written_while_it_decodes() {
    let m = Header::device(1, 1)
        .command(command::MEMORY)
        .bar(0, 0xE000_0000, 0x1000)
        .bar(1, 0x1000 | 1, 16)
        .model();
    m.write32(0x10, !0);
    assert_eq!(m.violations.borrow().len(), 1);
    // The I/O BAR decodes only with I/O decode on.
    m.write32(0x14, !0);
    assert_eq!(m.violations.borrow().len(), 1);
    assert_eq!(m.read32(0x14), !0xF | 1);
    m.write16(0x04, command::IO);
    m.write32(0x14, 0x1000);
    assert_eq!(m.violations.borrow().len(), 2);
    m.write16(0x10, 0);
    assert_eq!(m.violations.borrow().len(), 3, "a partial write");
}

/// A 64-bit BAR of 4 GiB or more has no size bits in its lower dword:
/// only both halves together give the size.
#[test]
fn a_64_bit_bar_sizes_from_both_halves() {
    for (bits, text) in [(32, "4 GiB"), (33, "8 GiB"), (40, "1024 GiB")] {
        let base = 1u64 << 44;
        let h = Header::device(1, 1)
            .command(command::MEMORY)
            .bar(2, base | 0b100, 1 << bits);
        let (bars, _) = sized(&h);
        let b = bars.get(2).unwrap();
        assert_eq!((b.base, b.size), (base, 1 << bits));
        assert_eq!(format!("{b}"), format!("BAR2 memory64 {base:#x}, {text}"));
    }
}

#[test]
fn a_64_bit_bar_in_the_last_slot_and_reserved_types_are_no_bars() {
    let h = Header::device(1, 1)
        .bar(0, 0x8000_0000 | 0b010, 0x1000)
        .bar(2, 0x9000_0000 | 0b110, 0x1000)
        .bar(3, 0xA000_0000 | 0b1000, 0x100_0000)
        .bar(5, 0xB000_0000 | 0b100, 0x1000);
    let (bars, _) = sized(&h);
    let got: Vec<_> = bars
        .iter()
        .map(|b| (b.index, b.size, b.prefetchable))
        .collect();
    assert_eq!(got, [(3, 0x100_0000, true)]);
}

#[test]
fn bars_not_implemented_read_back_nothing() {
    // The firmware's value cannot stick in a BAR not implemented.
    let (bars, m) = sized(&Header::device(1, 1).bar(0, 0, 0).bar(1, 0xF000_0000, 0));
    assert_eq!(bars, Bars::default());
    assert_eq!(m.read32(0x14), 0);
    m.write32(0x14, !0);
    assert_eq!(m.read32(0x14), 0);
}

#[test]
fn a_bridge_has_two_bars_and_other_layouts_none() {
    let h = Header::bridge(1)
        .bar(0, 0xF000_0000, 0x4000)
        .bar(1, 0xF000_4000, 0x1000)
        .w32(0x18, 0x0001_0100);
    let (bars, m) = sized(&h);
    assert_eq!(bars.iter().count(), 2);
    assert_eq!(m.read32(0x18), 0x0001_0100, "the bus numbers are not a BAR");
    let f = Function::read(&Header::device(1, 1).w8(0x0E, 2).model(), at(0, 0, 0)).unwrap();
    assert_eq!(size(&Header::device(1, 1).model(), &f), Bars::default());
}

#[test]
fn a_bar_knows_its_space() {
    let b = Bar {
        index: 0,
        space: Space::Io,
        prefetchable: false,
        base: 0x6000,
        size: 0x20,
    };
    assert!(!b.is_memory());
    let m = Bar {
        base: u64::MAX - 0xF,
        size: 0x20,
        space: Space::Memory64,
        ..b
    };
    assert!(m.is_memory());
    assert_eq!(m.end(), None);
}

#[test]
fn memory_decode_on_keeps_the_other_bits() {
    let m = Header::device(1, 1)
        .command(command::IO | command::BUS_MASTER | 1 << 8)
        .model();
    assert_eq!(
        enable_memory(&m, false),
        command::IO | command::BUS_MASTER | 1 << 8
    );
    assert_eq!(
        m.read16(0x04),
        command::MEMORY | command::INTX_DISABLE | 1 << 8
    );
    enable_memory(&m, true);
    assert_eq!(
        m.read16(0x04),
        command::MEMORY | command::BUS_MASTER | command::INTX_DISABLE | 1 << 8
    );
}

#[test]
fn sizes_print_in_their_unit() {
    let s = |n| format!("{}", Bytes(n));
    assert_eq!(s(16), "16 bytes");
    assert_eq!(s(1024), "1 KiB");
    assert_eq!(s(1536), "1536 bytes");
    assert_eq!(s(16 << 20), "16 MiB");
    assert_eq!(s(3 << 30), "3 GiB");
    assert_eq!(s(0), "0 bytes");
}
