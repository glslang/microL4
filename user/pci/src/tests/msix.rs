//! MSI-X: the capability found and read, its table's and PBA's sizes,
//! and entry 0 programmed in the order Linux and FreeBSD use, watched
//! across configuration space and the table page together.

use std::cell::RefCell;
use std::format;
use std::vec::Vec;

use super::model::{Header, Ram};
use super::plan::nic;
use super::scan::at;
use crate::msix::{ENABLE, FUNCTION_MASK};
use crate::{Config, Function, Location, Message, Msix};

#[test]
fn the_capability_reads_its_vectors_table_and_pba() {
    let h = nic()
        .w16(0x9A, 0x07FF)
        .w32(0x9C, 0x2000 | 4)
        .w32(0xA0, 0x3000 | 5);
    let m = h.model();
    let f = Function::read(&m, at(0, 2, 0)).unwrap();
    let x = Msix::find(&f, &m).unwrap();
    assert_eq!(x.vectors, 2048);
    assert_eq!(
        x.table,
        Location {
            bar: 4,
            offset: 0x2000
        }
    );
    assert_eq!(
        x.pba,
        Location {
            bar: 5,
            offset: 0x3000
        }
    );
    assert_eq!((x.table_bytes(), x.pba_bytes()), (32768, 256));
    assert_eq!(format!("{}", x.table), "BAR4+0x2000");
    let one = Msix { vectors: 1, ..x };
    assert_eq!((one.table_bytes(), one.pba_bytes()), (16, 8));
    let sixty_five = Msix { vectors: 65, ..x };
    assert_eq!(sixty_five.pba_bytes(), 16);
}

#[test]
fn the_first_msix_capability_that_fits_the_header_is_found() {
    // One at 0xF8 first in the list, whose 12 bytes pass 0x100, then the
    // real one.
    let h = nic().w8(0x34, 0xF8).cap(0xF8, 0x11, 0x98).w16(0xFA, 7);
    let m = h.model();
    let f = Function::read(&m, at(0, 2, 0)).unwrap();
    assert_eq!(
        f.capabilities.with_id(0x11).collect::<Vec<_>>(),
        [0xF8, 0x98]
    );
    assert_eq!(Msix::find(&f, &m).unwrap().cap, 0x98);
    let none = Header::device(1, 1).model();
    assert_eq!(
        Msix::find(&Function::read(&none, at(0, 0, 0)).unwrap(), &none),
        None
    );
}

/// Every write to either window, in order, with the control register's
/// value at the time.
struct Watched<'a, C> {
    inner: C,
    name: &'static str,
    log: &'a RefCell<Vec<(&'static str, u16, u32)>>,
}

impl<C: Config> Config for Watched<'_, C> {
    fn read8(&self, offset: u16) -> u8 {
        self.inner.read8(offset)
    }
    fn read16(&self, offset: u16) -> u16 {
        self.inner.read16(offset)
    }
    fn read32(&self, offset: u16) -> u32 {
        self.inner.read32(offset)
    }
    fn write8(&self, offset: u16, value: u8) {
        self.log
            .borrow_mut()
            .push((self.name, offset, value.into()));
        self.inner.write8(offset, value)
    }
    fn write16(&self, offset: u16, value: u16) {
        self.log
            .borrow_mut()
            .push((self.name, offset, value.into()));
        self.inner.write16(offset, value)
    }
    fn write32(&self, offset: u16, value: u32) {
        self.log.borrow_mut().push((self.name, offset, value));
        self.inner.write32(offset, value)
    }
}

#[test]
fn entry_0_is_written_under_function_mask_then_unmasked() {
    let m = nic().w16(0x9A, 0x4003).model();
    let f = Function::read(&m, at(0, 2, 0)).unwrap();
    let x = Msix::find(&f, &m).unwrap();
    let table = Ram::new();
    // Entry 0 at 0x40 in its page, its Vector Control masked with a
    // reserved bit set, which stays.
    table.write32(0x40 + 12, 0x8000_0001);
    let log = RefCell::new(Vec::new());
    let cfg = Watched {
        inner: &m,
        name: "cfg",
        log: &log,
    };
    let page = Watched {
        inner: &table,
        name: "table",
        log: &log,
    };
    let msg = Message {
        address: 0x1_FEE0_1000,
        data: 0x4031,
    };
    x.program(&cfg, &page, 0x40, msg);
    assert_eq!(
        *log.borrow(),
        [
            ("cfg", 0x9A, u32::from(ENABLE | FUNCTION_MASK | 3)),
            ("table", 0x40, 0xFEE0_1000),
            ("table", 0x44, 1),
            ("table", 0x48, 0x4031),
            ("table", 0x4C, 0x8000_0000),
            ("cfg", 0x9A, u32::from(ENABLE | 3)),
        ]
    );
    assert_eq!(Msix::vector_control(&table, 0x40), 0x8000_0000);
}
