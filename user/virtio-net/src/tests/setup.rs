//! The setup: each step in the specification's order, every refusal, the
//! arguments' words, the PCI capabilities and the request check.

use core::sync::atomic::Ordering::Relaxed;
use std::format;
use std::string::ToString;
use std::vec;

use libsys::frames::{self, Link, Mac};
use libsys::mem::Memory;
use libsys::proto::{Refusal, label, virtio_feature};

use super::device::{Config, Device, Event, f};
use super::{BASE, MAC, Mem, World, args};
use crate::pci::{self, Cap, Caps, CfgType, Missing, NO_VECTOR, status};
use crate::virtq::{AVAIL_F_NO_INTERRUPT, DESC_F_WRITE, off};
use crate::{
    Driver, FEATURES, GENERATION_TRIES, RESET_READS, Refused, Region, Start, StartError, Which,
    layout, request,
};

const ALL: u8 = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK;

#[test]
fn setup_follows_the_specifications_order() {
    let mem = Mem::new();
    let dev = Device::new(&mem.dma, BASE, Config::qemu());
    let w = World::up(&dev, &mem);
    // Reset, ACKNOWLEDGE, DRIVER, the features, FEATURES_OK, no
    // configuration vector, the two queues on vector 0, the configuration
    // between two generations, DRIVER_OK, and only then queue 0's notify
    // with all 64 receive buffers available.
    assert_eq!(
        dev.log(),
        vec![
            Event::Reset,
            Event::Status(1),
            Event::Status(3),
            Event::Status(11),
            Event::Accepted(FEATURES),
            Event::ConfigVector(NO_VECTOR),
            Event::Enabled {
                queue: 0,
                size: 64,
                vector: 0
            },
            Event::Enabled {
                queue: 1,
                size: 64,
                vector: 0
            },
            Event::ConfigRead,
            Event::ConfigRead,
            Event::Status(15),
            Event::Notify {
                queue: 0,
                avail: 64
            },
        ]
    );
    assert_eq!(dev.status(), ALL);
    // Of QEMU's many features, only VERSION_1, MAC and STATUS.
    assert_eq!(dev.accepted(), f::VERSION_1 | f::MAC | f::STATUS);
    assert_eq!(w.driver.features(), FEATURES);
    assert_eq!(dev.config_vector(), NO_VECTOR);
    for q in 0..2 {
        assert_eq!(dev.queue(q), (64, 0, true));
        let ring = BASE + 0x1000 * u64::from(q);
        assert_eq!(dev.rings(q), [ring, ring + 0x400, ring + 0x800]);
    }
    assert_eq!(dev.queue(2), (256, NO_VECTOR, false));
    assert_eq!(
        w.driver.up().to_string(),
        "virtio-net: up: MAC 52:54:00:12:34:56, features VERSION_1 MAC STATUS, link up, queues 64 and 64"
    );
    assert_eq!((w.driver.mac(), w.driver.link_up()), (MAC, true));
    // No interrupt yet, on any vector.
    assert_eq!(dev.interrupts(), vec![0, 0, 0]);
}

#[test]
fn every_descriptor_names_its_own_buffer() {
    let mem = Mem::new();
    let dev = Device::new(&mem.dma, BASE, Config::qemu());
    let _w = World::up(&dev, &mem);
    let d = &mem.dma;
    for (q, buffers, flags, len) in [(0u16, 0x1_0000, DESC_F_WRITE, 2048), (1, 0x3_0000, 0, 0)] {
        let ring = layout::ring(q);
        for i in 0..64u16 {
            let at = ring + off::desc(i);
            assert_eq!(
                d.load64(at + off::DESC_ADDR, Relaxed),
                BASE + buffers + 2048 * u64::from(i)
            );
            assert_eq!(d.load32(at + off::DESC_LEN, Relaxed), len);
            assert_eq!(d.load16(at + off::DESC_FLAGS, Relaxed), flags);
            assert_eq!(d.load16(at + off::DESC_NEXT, Relaxed), 0);
        }
    }
    // Every receive descriptor available, in order; transmit completions
    // off, receive ones on; the used rings as the driver zeroed them.
    for i in 0..64u16 {
        assert_eq!(d.load16(off::avail_entry(i), Relaxed), i);
    }
    assert_eq!(d.load16(off::AVAIL_IDX, Relaxed), 64);
    assert_eq!(d.load16(off::AVAIL_FLAGS, Relaxed), 0);
    assert_eq!(d.load16(0x1000 + off::AVAIL_IDX, Relaxed), 0);
    assert_eq!(
        d.load16(0x1000 + off::AVAIL_FLAGS, Relaxed),
        AVAIL_F_NO_INTERRUPT
    );
    assert_eq!(dev.held(0).len(), 0, "nothing taken before a frame comes");
    assert_eq!(dev.fetch(0), 64);
}

#[test]
fn the_link_block_and_transmit_buffers_follow_setup() {
    let mem = Mem::new();
    let dev = Device::new(&mem.dma, BASE, Config::qemu());
    let mut queues = frames::Driver::new(&mem.queues);
    let d = Driver::start(&args(), dev.regions(), &mem.dma, &mut queues).unwrap();
    assert!(queues.end_batch());
    assert_eq!(
        queues.owned(frames::Pool::Tx),
        frames::Owned::NONE,
        "every transmit buffer handed to net"
    );
    let mut net = frames::Net::new(&mem.queues);
    assert_eq!(net.attach(), Ok(Link::new(MAC, true)));
    assert_eq!(net.reclaim(), 128);
    assert_eq!(d.counters(), Default::default());
}

/// Starts the driver on a device made by `cfg`; the result, the device's
/// final status, and whether the queues' link block was written.
fn try_start(cfg: Config) -> (Result<(), Refused>, u8, bool) {
    let mem = Mem::new();
    let start = Start {
        multiplier: cfg.multiplier,
        ..args()
    };
    let dev = Device::new(&mem.dma, BASE, cfg);
    let mut queues = frames::Driver::new(&mem.queues);
    let r = Driver::start(&start, dev.regions(), &mem.dma, &mut queues).map(|_| ());
    let ready = mem
        .queues
        .load32(frames::layout::LINK + frames::layout::LINK_READY, Relaxed);
    (r, dev.status(), ready == 1)
}

#[test]
fn every_refusal_fails_the_device_and_starts_nothing() {
    let qemu = Config::qemu;
    let with = |change: fn(&mut Config)| {
        let mut c = qemu();
        change(&mut c);
        c
    };
    let cases: [(Config, Refused); 14] = [
        (
            with(|c| c.features &= !f::VERSION_1),
            Refused::NoVersion1(f::QEMU & !f::VERSION_1),
        ),
        (
            with(|c| c.features &= !f::MAC),
            Refused::NoMac(f::QEMU & !f::MAC),
        ),
        (
            with(|c| c.refuse_features = true),
            Refused::FeaturesRefused {
                accepted: FEATURES,
                status: 3,
            },
        ),
        (with(|c| c.num_queues = 1), Refused::FewQueues(1)),
        (
            with(|c| c.max_size = 32),
            Refused::SmallQueue { queue: 0, size: 32 },
        ),
        (
            with(|c| c.table_size = 0),
            Refused::VectorRefused {
                queue: 0,
                read: NO_VECTOR,
            },
        ),
        (
            with(|c| c.refuse_vectors = true),
            Refused::VectorRefused {
                queue: 0,
                read: NO_VECTOR,
            },
        ),
        (
            with(|c| c.notify_off[1] = 1024),
            Refused::NotifyOutside {
                queue: 1,
                notify_off: 1024,
                multiplier: 4,
                len: 0x1000,
            },
        ),
        (
            with(|c| {
                c.dirty = true;
                c.reset_reads = RESET_READS;
            }),
            Refused::NoReset(ALL),
        ),
        (
            with(|c| c.churn = GENERATION_TRIES),
            Refused::ConfigUnstable,
        ),
        (with(|c| c.mac = [0xFF; 6]), Refused::BadMac(Mac::BROADCAST)),
        (with(|c| c.mac = [0; 6]), Refused::BadMac(Mac::ZERO)),
        (
            with(|c| c.mac = [0x01, 0x00, 0x5E, 0, 0, 1]),
            Refused::BadMac(Mac([0x01, 0x00, 0x5E, 0, 0, 1])),
        ),
        (
            with(|c| {
                c.dirty = true;
                c.reset_reads = u32::MAX;
            }),
            Refused::NoReset(ALL),
        ),
    ];
    for (cfg, refused) in cases {
        let (r, st, ready) = try_start(cfg);
        assert_eq!(r, Err(refused));
        if let Refused::NoReset(_) = refused {
            // Never written again: the reset had not shown.
            assert_eq!(st & status::FAILED, 0);
        } else {
            assert!(st & status::FAILED != 0, "{refused:?}: status {st:#x}");
        }
        assert!(!ready, "{refused:?}: the link block was written");
    }
}

#[test]
fn the_limits_are_exact() {
    let ok = |change: fn(&mut Config)| {
        let mut c = Config::qemu();
        change(&mut c);
        let (r, st, ready) = try_start(c);
        assert_eq!(r, Ok(()));
        assert_eq!((st, ready), (ALL, true));
    };
    // The last of the 1,000 reads may show the reset; a device already
    // at 0 shows it at once.
    ok(|c| {
        c.dirty = true;
        c.reset_reads = RESET_READS - 1;
    });
    ok(|c| c.reset_reads = u32::MAX);
    // The 16th read of the configuration may be the first stable one.
    ok(|c| c.churn = GENERATION_TRIES - 1);
    // A notify address whose 2 bytes end the region.
    ok(|c| c.notify_off[1] = 1023);
    // Queues of exactly 64, and a multiplier of 0: one address for all.
    ok(|c| c.max_size = 64);
    ok(|c| {
        c.multiplier = 0;
        c.notify_off = vec![7, 9, 11];
    });
    // One MSI-X vector is enough.
    ok(|c| c.table_size = 1);
}

#[test]
fn of_every_feature_offered_only_three_are_accepted() {
    // A device offering all 64 bits, the packed ring, ACCESS_PLATFORM and
    // MTU among them, which the driver SHOULD accept and does not: the
    // stack needs none, and an IOMMU it does not have (the model takes
    // the set, as 2.2.2 lets a device).
    for offered in [
        u64::MAX,
        f::QEMU | f::MTU | f::ACCESS_PLATFORM | f::RING_PACKED,
    ] {
        let mem = Mem::new();
        let cfg = Config {
            features: offered,
            ..Config::qemu()
        };
        let dev = Device::new(&mem.dma, BASE, cfg);
        let w = World::up(&dev, &mem);
        assert_eq!(dev.accepted(), FEATURES);
        assert_eq!(w.driver.features(), FEATURES);
    }
}

#[test]
fn a_torn_configuration_is_read_again() {
    let mem = Mem::new();
    let cfg = Config {
        churn: 3,
        ..Config::qemu()
    };
    let dev = Device::new(&mem.dma, BASE, cfg);
    let w = World::up(&dev, &mem);
    assert_eq!(w.driver.mac(), MAC);
    let reads = dev
        .log()
        .iter()
        .filter(|e| **e == Event::ConfigRead)
        .count();
    assert_eq!(reads, 2 * 4);
}

#[test]
fn without_status_the_link_is_up_and_status_is_never_read() {
    let mem = Mem::new();
    let cfg = Config {
        features: f::QEMU & !f::STATUS,
        link: 0,
        ..Config::qemu()
    };
    // The model fails the test if the driver reads `status` unoffered.
    let dev = Device::new(&mem.dma, BASE, cfg);
    let w = World::up(&dev, &mem);
    assert_eq!(dev.accepted(), f::VERSION_1 | f::MAC);
    assert!(w.driver.link_up());
    assert_eq!(
        w.driver.up().to_string(),
        "virtio-net: up: MAC 52:54:00:12:34:56, features VERSION_1 MAC, link up, queues 64 and 64"
    );
    assert_eq!(w.net.counters().bad, 0);
}

#[test]
fn a_link_down_is_reported() {
    let mem = Mem::new();
    let cfg = Config {
        link: 0,
        ..Config::qemu()
    };
    let dev = Device::new(&mem.dma, BASE, cfg);
    let mut queues = frames::Driver::new(&mem.queues);
    let d = Driver::start(&args(), dev.regions(), &mem.dma, &mut queues).unwrap();
    assert!(d.up().to_string().contains(", link down, "));
    let mut net = frames::Net::new(&mem.queues);
    assert_eq!(net.attach(), Ok(Link::new(MAC, false)));
}

#[test]
fn a_device_the_firmware_left_running_is_reset_first() {
    let mem = Mem::new();
    let cfg = Config {
        dirty: true,
        reset_reads: 5,
        ..Config::qemu()
    };
    let dev = Device::new(&mem.dma, BASE, cfg);
    let w = World::up(&dev, &mem);
    assert_eq!(dev.log()[0], Event::Reset);
    assert_eq!(dev.status(), ALL);
    assert_eq!(dev.rings(0), [BASE, BASE + 0x400, BASE + 0x800]);
    assert_eq!(w.driver.mac(), MAC);
}

#[test]
fn short_windows_are_refused_before_the_device_is_touched() {
    for (lens, what, len) in [
        ([55, 0x1000, 0x1000], "common", 55),
        ([0x1000, 1, 0x1000], "notify", 1),
        ([0x1000, 0x1000, 7], "device", 7),
    ] {
        let mem = Mem::new();
        let cfg = Config {
            lens,
            ..Config::qemu()
        };
        let dev = Device::new(&mem.dma, BASE, cfg);
        let mut queues = frames::Driver::new(&mem.queues);
        let r = Driver::start(&args(), dev.regions(), &mem.dma, &mut queues);
        assert_eq!(r.map(|_| ()), Err(Refused::Window { what, len }));
        assert!(dev.log().is_empty());
    }
    let mem = Mem::new();
    let small = libsys::mem::Ram::new(layout::END - 1);
    let dev = Device::new(&mem.dma, BASE, Config::qemu());
    let mut queues = frames::Driver::new(&mem.queues);
    let r = Driver::start(&args(), dev.regions(), &small, &mut queues);
    assert_eq!(
        r.map(|_| ()),
        Err(Refused::Window {
            what: "DMA",
            len: layout::END - 1
        })
    );
}

#[test]
fn refusals_say_why() {
    let text = |r: Refused| r.to_string();
    assert_eq!(
        text(Refused::NoVersion1(0x30)),
        "the device does not offer VERSION_1 (features 0x30)"
    );
    assert_eq!(
        text(Refused::FeaturesRefused {
            accepted: FEATURES,
            status: 3
        }),
        "the device refused features VERSION_1 MAC STATUS: FEATURES_OK clear (status 0x03)"
    );
    assert_eq!(
        text(Refused::NoReset(0x0f)),
        "the device did not reset: status 0x0f after 1000 reads"
    );
    assert_eq!(
        text(Refused::NotifyOutside {
            queue: 1,
            notify_off: 1024,
            multiplier: 4,
            len: 4096
        }),
        "queue 1's notify offset 1024 x 4 is outside the notify region of 4096 bytes"
    );
    assert_eq!(
        text(Refused::BadMac(Mac::BROADCAST)),
        "the device's MAC ff:ff:ff:ff:ff:ff is not unicast"
    );
    assert_eq!(
        text(Refused::SmallQueue { queue: 0, size: 32 }),
        "queue 0 has at most 32 entries, fewer than 64"
    );
}

#[test]
fn the_arguments_round_trip() {
    let s = Start {
        dma: 0x1_2340_0000,
        common: Region {
            offset: 0x000,
            len: 0x1000,
        },
        notify: Region {
            offset: 0x0,
            len: 0x1000,
        },
        device: Region {
            offset: 0xFF8,
            len: 8,
        },
        multiplier: 4,
    };
    let w = s.to_words();
    assert_eq!(
        w,
        [
            0x1_2340_0000,
            0x1000 << 16 | (0x1000u64 << 16) << 32,
            8 << 16 | 0xFF8,
            4
        ]
    );
    assert_eq!(Start::from_words(w), Ok(s));
    assert_eq!(
        s.window(Which::Common),
        (layout::REGIONS, 0x1000),
        "region r in window r"
    );
    assert_eq!(s.window(Which::Notify), (0x0C01_0000, 0x1000));
    assert_eq!(s.window(Which::Device), (0x0C02_0FF8, 8));
    // The largest: a 60 KiB region from the page's last byte.
    let big = Region {
        offset: 0xFFF,
        len: 0xF000,
    };
    let s2 = Start {
        common: big,
        notify: big,
        device: big,
        multiplier: 0,
        dma: crate::PHYS_LIMIT - (1 << 21),
    };
    assert_eq!(Start::from_words(s2.to_words()), Ok(s2));
    assert!(big.fits());
}

#[test]
fn the_entry_stub_refuses_bad_words() {
    let good = args().to_words();
    let with = |i: usize, v: u64| {
        let mut w = good;
        w[i] = v;
        Start::from_words(w)
    };
    for dma in [0, 0x1000, 0x1_2340_1000, crate::PHYS_LIMIT, !0x1F_FFFF] {
        assert_eq!(with(0, dma), Err(StartError::Dma(dma)));
    }
    let r = |offset: u16, len: u16| u64::from(Region { offset, len }.word());
    // Past the window: an offset beyond the first page, or more than 60
    // KiB.
    assert_eq!(
        with(1, r(0x1000, 0x1000)),
        Err(StartError::Region {
            which: Which::Common,
            word: r(0x1000, 0x1000)
        })
    );
    assert_eq!(
        with(1, r(0, 0x1000) | r(0, 0xF001) << 32),
        Err(StartError::Region {
            which: Which::Notify,
            word: r(0, 0xF001)
        })
    );
    // rdx's high half is not the device region's.
    assert_eq!(
        with(2, r(0, 8) | 1 << 32),
        Err(StartError::Region {
            which: Which::Device,
            word: r(0, 8) | 1 << 32
        })
    );
    // Too short for what the driver reads.
    for (i, word, which, len) in [
        (1, r(0, 55) | r(0, 2) << 32, Which::Common, 55),
        (1, r(0, 56) | r(0, 1) << 32, Which::Notify, 1),
        (2, r(0, 7), Which::Device, 7),
    ] {
        assert_eq!(with(i, word), Err(StartError::Short { which, len }));
    }
    assert!(with(1, r(0, 56) | r(0, 2) << 32).is_ok());
    assert!(with(2, r(0, 8)).is_ok());
    // notify_off_multiplier: 0 or an even power of 2.
    for m in [1, 3, 6, 12, 0x1_0000_0000] {
        assert_eq!(with(3, m), Err(StartError::Multiplier(m)));
    }
    for m in [0, 2, 4, 0x1000, 1 << 31] {
        assert!(with(3, m).is_ok(), "{m}");
    }
    assert_eq!(
        StartError::Short {
            which: Which::Common,
            len: 55
        }
        .to_string(),
        "the common region is 55 bytes, under 56"
    );
}

/// A vendor-specific capability as QEMU lays one out (from memory).
fn cap(cfg_type: u8, bar: u8, offset: u32, length: u32, extra: Option<u32>) -> std::vec::Vec<u8> {
    let mut b = vec![
        pci::CAP_VENDOR,
        0x70,
        if extra.is_some() { 20 } else { 16 },
        cfg_type,
        bar,
        0,
        0,
        0,
    ];
    b.extend(offset.to_le_bytes());
    b.extend(length.to_le_bytes());
    if let Some(m) = extra {
        b.extend(m.to_le_bytes());
    }
    b
}

#[test]
fn capabilities_parse_as_the_specification_lays_them_out() {
    assert_eq!(
        Cap::parse(&cap(1, 4, 0, 0x1000, None)),
        Some(Cap {
            cfg_type: CfgType::Common,
            bar: 4,
            offset: 0,
            length: 0x1000,
            multiplier: 0
        })
    );
    assert_eq!(
        Cap::parse(&cap(2, 4, 0x3000, 0x1000, Some(4))),
        Some(Cap {
            cfg_type: CfgType::Notify,
            bar: 4,
            offset: 0x3000,
            length: 0x1000,
            multiplier: 4
        })
    );
    // A longer cap_len is accepted; bytes past the structure are not read.
    let mut long = cap(4, 4, 0x2000, 0x1000, None);
    long[2] = 24;
    long.extend([0xEE; 8]);
    assert_eq!(Cap::parse(&long).map(|c| c.cfg_type), Some(CfgType::Device));
    // Ignored: not vendor-specific, PCI configuration access (5), shared
    // memory (8), a reserved type, a reserved BAR, a short cap_len, a
    // notify without its multiplier, a cap_len past the bytes given.
    let mut not_vendor = cap(1, 4, 0, 16, None);
    not_vendor[0] = 0x11;
    let mut short = cap(1, 4, 0, 16, None);
    short[2] = 15;
    let mut short_notify = cap(2, 4, 0, 16, Some(4));
    short_notify[2] = 16;
    let mut past = cap(1, 4, 0, 16, None);
    past[2] = 17;
    for bytes in [
        not_vendor,
        cap(5, 0, 0, 4, None),
        cap(8, 2, 0, 16, None),
        cap(0, 4, 0, 16, None),
        cap(1, 6, 0, 16, None),
        short,
        short_notify,
        past,
        vec![pci::CAP_VENDOR, 0, 16],
    ] {
        assert_eq!(Cap::parse(&bytes), None, "{bytes:x?}");
    }
}

#[test]
fn the_first_of_each_type_in_a_memory_bar_is_kept() {
    let c = |t, bar, off| Cap::parse(&cap(t, bar, off, 0x1000, (t == 2).then_some(4))).unwrap();
    let mut caps = Caps::default();
    assert_eq!(caps.regions(), Err(Missing(CfgType::Common)));
    // An I/O BAR's notify is passed over, then QEMU's BAR4 set.
    caps.consider(c(2, 0, 0), false);
    for (t, off) in [(1, 0), (3, 0x1000), (4, 0x2000), (2, 0x3000)] {
        caps.consider(c(t, 4, off), true);
    }
    // Later ones of a type already kept are not.
    caps.consider(c(1, 2, 0x8000), true);
    let [common, notify, device] = caps.regions().unwrap();
    assert_eq!((common.bar, common.offset), (4, 0));
    assert_eq!((notify.offset, notify.multiplier), (0x3000, 4));
    assert_eq!(device.offset, 0x2000);
    assert_eq!(caps.isr.map(|i| i.offset), Some(0x1000));
    let mut no_device = Caps::default();
    no_device.consider(c(1, 4, 0), true);
    no_device.consider(c(2, 4, 0x3000), true);
    assert_eq!(no_device.regions(), Err(Missing(CfgType::Device)));
    assert_eq!(Missing(CfgType::Notify).to_string(), "no notify capability");
}

#[test]
fn the_network_device_ids() {
    assert!(pci::is_network(0x1AF4, 0x1041, 0x1100));
    assert!(pci::is_network(0x1AF4, 0x1000, 1));
    // A transitional block device, another subsystem, another vendor.
    assert!(!pci::is_network(0x1AF4, 0x1001, 2));
    assert!(!pci::is_network(0x1AF4, 0x1000, 2));
    assert!(!pci::is_network(0x8086, 0x1041, 1));
    assert!(!pci::is_network(0x1AF4, 0x1042, 1));
}

#[test]
fn only_stats_with_no_words_is_answered() {
    assert_eq!(request(label::VIRTIO_NET_STATS, 0), Ok(()));
    assert_eq!(request(label::VIRTIO_NET_STATS, 1), Err(Refusal::BadLength));
    for l in [0, label::NET_STATS, label::UART_STATS, 0x151] {
        assert_eq!(request(l, 0), Err(Refusal::BadLabel), "{l:#x}");
    }
}

#[test]
fn the_features_are_libsys_own() {
    assert_eq!(
        FEATURES,
        virtio_feature::VERSION_1 | virtio_feature::MAC | virtio_feature::STATUS
    );
    assert_eq!(
        (f::VERSION_1, f::MAC, f::STATUS),
        (
            virtio_feature::VERSION_1,
            virtio_feature::MAC,
            virtio_feature::STATUS
        )
    );
    assert_eq!(format!("{:?}", Which::ALL), "[Common, Notify, Device]");
}
