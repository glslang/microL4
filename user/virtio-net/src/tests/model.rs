//! The model's own checks: each plays a driver that breaks one of the
//! specification's rules and shows that the model fails it. Without them
//! a model that checked nothing would pass every other test.

use core::sync::atomic::Ordering::{Relaxed, Release};
use std::string::String;

use libsys::mem::{Memory, Regs};

use super::device::{Config, Device, f, failure};
use super::{BASE, Mem, World, frame};
use crate::layout;
use crate::pci::{common, net, status};
use crate::virtq::{DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, off};

fn fails(f: impl FnOnce(), says: &str) {
    let msg: String = failure(f);
    assert!(msg.contains(says), "the model said {msg:?}, not {says:?}");
}

/// A device whose driver got as far as FEATURES_OK by hand.
fn negotiated(dev: &Device<'_>) {
    let c = dev.regions().common;
    c.write8(common::DEVICE_STATUS, 0);
    assert_eq!(c.read8(common::DEVICE_STATUS), 0);
    c.write8(common::DEVICE_STATUS, status::ACKNOWLEDGE);
    c.write8(common::DEVICE_STATUS, status::ACKNOWLEDGE | status::DRIVER);
    c.write32(common::DRIVER_FEATURE_SELECT, 1);
    c.write32(common::DRIVER_FEATURE, 1);
    c.write32(common::DRIVER_FEATURE_SELECT, 0);
    c.write32(common::DRIVER_FEATURE, f::MAC as u32);
    c.write8(common::DEVICE_STATUS, 11);
    assert_eq!(c.read8(common::DEVICE_STATUS), 11);
}

#[test]
fn status_rules() {
    let mem = Mem::new();
    fails(
        || {
            let dev = Device::new(&mem.dma, BASE, Config::qemu());
            let c = dev.regions().common;
            c.write8(common::DEVICE_STATUS, status::ACKNOWLEDGE);
            c.write8(common::DEVICE_STATUS, status::DRIVER);
        },
        "clears bits",
    );
    fails(
        || {
            let dev = Device::new(&mem.dma, BASE, Config::qemu());
            let c = dev.regions().common;
            c.write8(common::DEVICE_STATUS, status::ACKNOWLEDGE);
            c.write8(common::DEVICE_STATUS, 0x7);
        },
        "set before",
    );
    fails(
        || {
            let dev = Device::new(&mem.dma, BASE, Config::qemu());
            dev.regions().common.write8(common::DEVICE_STATUS, 0x40);
        },
        "sets a bit the driver may not",
    );
    fails(
        || {
            let cfg = Config {
                dirty: true,
                reset_reads: 5,
                ..Config::qemu()
            };
            let dev = Device::new(&mem.dma, BASE, cfg);
            let c = dev.regions().common;
            c.write8(common::DEVICE_STATUS, 0);
            c.write8(common::DEVICE_STATUS, 1);
        },
        "before the reset was seen to finish",
    );
    // A device that refuses the features clears FEATURES_OK: the model
    // does not fail the driver for asking.
    let dev = Device::new(&mem.dma, BASE, Config::qemu());
    let c = dev.regions().common;
    c.write8(common::DEVICE_STATUS, 1);
    c.write8(common::DEVICE_STATUS, 3);
    c.write32(common::DRIVER_FEATURE, f::MAC as u32);
    c.write8(common::DEVICE_STATUS, 11);
    assert_eq!(c.read8(common::DEVICE_STATUS), 3, "no VERSION_1: refused");
}

#[test]
fn register_rules() {
    let mem = Mem::new();
    let dev = || Device::new(&mem.dma, BASE, Config::qemu());
    fails(
        || {
            let _ = dev().regions().common.read16(common::DEVICE_STATUS);
        },
        "2 bytes wide, not 1",
    );
    fails(
        || {
            let _ = dev().regions().common.read32(common::QUEUE_SELECT);
        },
        "misaligned",
    );
    fails(
        || {
            let _ = dev().regions().common.read16(0x38);
        },
        "accessed 2 bytes wide, not 0",
    );
    fails(
        || dev().regions().common.write16(common::NUM_QUEUES, 3),
        "MUST NOT",
    );
    fails(
        || {
            let _ = dev().regions().common.read32(0x1000);
        },
        "outside the common region",
    );
    fails(
        || {
            let d = dev();
            negotiated(&d);
            d.regions().common.write32(common::DRIVER_FEATURE, 0);
        },
        "after FEATURES_OK",
    );
    fails(
        || dev().regions().device.write8(net::MAC, 0),
        "wrote the device configuration",
    );
    fails(
        || {
            let cfg = Config {
                features: f::QEMU & !f::STATUS,
                ..Config::qemu()
            };
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, cfg);
            let _ = d.regions().device.read16(net::STATUS);
        },
        "STATUS is not offered",
    );
    fails(
        || {
            let _ = dev().regions().device.read16(net::MAC);
        },
        "does not need",
    );
}

#[test]
fn queue_rules() {
    let mem = Mem::new();
    let dev = || Device::new(&mem.dma, BASE, Config::qemu());
    fails(
        || dev().regions().common.write16(common::QUEUE_SELECT, 0),
        "not between FEATURES_OK and DRIVER_OK",
    );
    fails(
        || {
            let d = dev();
            negotiated(&d);
            d.regions().common.write16(common::QUEUE_SIZE, 48);
        },
        "not a power of 2",
    );
    fails(
        || {
            let d = dev();
            negotiated(&d);
            d.regions().common.write16(common::QUEUE_SIZE, 512);
        },
        "not a power of 2 up to 256",
    );
    fails(
        || {
            let d = dev();
            negotiated(&d);
            let c = d.regions().common;
            c.write32(common::QUEUE_DESC, (BASE + 8) as u32);
            c.write32(common::QUEUE_DRIVER, (BASE + 0x400) as u32);
            c.write32(common::QUEUE_DEVICE, (BASE + 0x800) as u32);
            c.write16(common::QUEUE_ENABLE, 1);
        },
        "not 16-aligned",
    );
    fails(
        || {
            let d = dev();
            negotiated(&d);
            d.regions().common.write16(common::QUEUE_ENABLE, 0);
        },
        "queue_enable written 0",
    );
    fails(
        || {
            let d = dev();
            negotiated(&d);
            let c = d.regions().common;
            for (r, a) in [(common::QUEUE_DESC, 0), (common::QUEUE_DRIVER, 0x400)] {
                c.write32(r, (BASE + a) as u32);
            }
            c.write32(common::QUEUE_DEVICE, (BASE + 0x800) as u32);
            c.write16(common::QUEUE_ENABLE, 1);
            c.write32(common::QUEUE_DESC, (BASE + 0x2000) as u32);
        },
        "after it was enabled",
    );
    fails(
        || {
            let d = dev();
            negotiated(&d);
            let c = d.regions().common;
            c.write16(common::QUEUE_SELECT, 3);
            c.write16(common::QUEUE_SIZE, 64);
        },
        "which does not exist",
    );
    // After DRIVER_OK, too.
    fails(
        || {
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            let w = World::up(&d, &mem);
            w.driver.regions().common.write16(common::QUEUE_SIZE, 64);
        },
        "not between FEATURES_OK and DRIVER_OK",
    );
}

#[test]
fn notify_rules() {
    let mem = Mem::new();
    fails(
        || {
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            d.regions().notify.write16(0, 0);
        },
        "before DRIVER_OK",
    );
    fails(
        || {
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            let w = World::up(&d, &mem);
            // Queue 1's address is 1 x 4.
            w.driver.regions().notify.write16(0, 1);
        },
        "not its 0x4",
    );
    fails(
        || {
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            let w = World::up(&d, &mem);
            w.driver.regions().notify.write32(0, 0);
        },
        "not 16 bits",
    );
    fails(
        || {
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            let w = World::up(&d, &mem);
            let _ = w.driver.regions().notify.read16(0);
        },
        "read the notify region",
    );
}

/// Makes transmit descriptor `id` available as a broken driver would:
/// its fields as given, then the entry and the index, then the notify.
fn post_tx(mem: &Mem, dev: &Device<'_>, id: u16, addr: u64, len: u32, flags: u16, next: u16) {
    let ring = layout::ring(1);
    let d = ring + off::desc(id);
    let m = &mem.dma;
    m.store64(d + off::DESC_ADDR, addr, Relaxed);
    m.store32(d + off::DESC_LEN, len, Relaxed);
    m.store16(d + off::DESC_FLAGS, flags, Relaxed);
    m.store16(d + off::DESC_NEXT, next, Relaxed);
    let idx = m.load16(ring + off::AVAIL_IDX, Relaxed);
    m.store16(ring + off::avail_entry(idx), id, Relaxed);
    m.store16(ring + off::AVAIL_IDX, idx.wrapping_add(1), Release);
    dev.regions().notify.write16(4, 1);
}

#[test]
fn descriptor_rules() {
    let tx = BASE + layout::TX_BUFFERS as u64;
    let up = |f: &dyn Fn(&Mem, &Device<'_>)| {
        let mem = Mem::new();
        let d = Device::new(&mem.dma, BASE, Config::qemu());
        let _w = World::up(&d, &mem);
        f(&mem, &d);
    };
    // Outside the DMA frame: past its end, below its base, or wrapping.
    for addr in [BASE + layout::END as u64 - 70, BASE - 0x1000, u64::MAX - 10] {
        fails(
            || {
                up(&|mem, d| {
                    post_tx(mem, d, 0, addr, 72, 0, 0);
                    d.fetch(1);
                })
            },
            "outside the DMA frame",
        );
    }
    fails(
        || {
            up(&|mem, d| {
                post_tx(mem, d, 0, tx, 72, DESC_F_WRITE, 0);
                d.fetch(1);
            })
        },
        "direction is wrong",
    );
    fails(
        || {
            up(&|mem, d| {
                post_tx(mem, d, 0, tx, 72, DESC_F_NEXT, 0);
                d.fetch(1);
            })
        },
        "loops",
    );
    fails(
        || {
            up(&|mem, d| {
                post_tx(mem, d, 0, tx, 64, DESC_F_INDIRECT, 0);
                d.fetch(1);
            })
        },
        "indirect",
    );
    fails(
        || {
            up(&|mem, d| {
                post_tx(mem, d, 70, tx, 72, 0, 0);
                d.fetch(1);
            })
        },
        "out of its 64",
    );
    fails(
        || {
            up(&|mem, d| {
                mem.dma.store8(layout::TX_BUFFERS, 1, Relaxed);
                post_tx(mem, d, 0, tx, 72, 0, 0);
                d.fetch_tx();
            })
        },
        "transmit header flags",
    );
    fails(
        || {
            up(&|mem, d| {
                mem.dma.store8(layout::TX_BUFFERS + 10, 1, Relaxed);
                post_tx(mem, d, 0, tx, 72, 0, 0);
                d.fetch_tx();
            })
        },
        "num_buffers",
    );
    fails(
        || {
            up(&|mem, d| {
                post_tx(mem, d, 0, tx, 12 + 13, 0, 0);
                d.fetch_tx();
            })
        },
        "a transmitted frame of 13 bytes",
    );
}

#[test]
fn ring_rules() {
    // A descriptor made available again while the device holds it.
    fails(
        || {
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            let _w = World::up(&d, &mem);
            assert_eq!(d.fetch(0), 64);
            post_tx(&mem, &d, 0, BASE + layout::TX_BUFFERS as u64, 72, 0, 0);
            post_tx(&mem, &d, 0, BASE + layout::TX_BUFFERS as u64, 72, 0, 0);
            d.fetch(1);
        },
        "while the device holds it",
    );
    // The available index moved back.
    fails(
        || {
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            let _w = World::up(&d, &mem);
            assert_eq!(d.fetch(0), 64);
            mem.dma.store16(off::AVAIL_IDX, 63, Release);
            d.regions().notify.write16(0, 0);
            d.fetch(0);
        },
        "available index moved from 64 to 63",
    );
    // A held descriptor changed before the device gave it back.
    fails(
        || {
            let mem = Mem::new();
            let d = Device::new(&mem.dma, BASE, Config::qemu());
            let mut w = World::up(&d, &mem);
            w.net_send(&[frame(60, 1)]);
            assert!(w.signal());
            assert_eq!(d.fetch_tx().len(), 1);
            mem.dma
                .store32(layout::ring(1) + off::desc(0) + off::DESC_LEN, 99, Relaxed);
            d.complete_tx(0);
        },
        "changed while the device held it",
    );
}
