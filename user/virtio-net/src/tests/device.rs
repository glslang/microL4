//! A model of a virtio 1.x PCI network device, written from the
//! specification, not from the driver (virtio 1.2, read in the OASIS TeX
//! sources fetched 2026-11-27: 2.1 the device status, 2.2 the feature
//! bits, 2.4 reset, 2.5 the device configuration and its generation, 2.7
//! split virtqueues, 3.1 initialization, 4.1 the PCI transport's common
//! configuration, notifications and MSI-X vectors, and 5.1 the network
//! device; what it says of QEMU is from memory).
//!
//! It is the device's three regions, as [`Regs`] ([`Port`]), over the
//! model's guest memory, a [`Ram`] standing for the physical range `[base,
//! base + len)`: the DMA frame. The test plays the device's other side:
//! the network delivers frames into posted receive buffers
//! ([`Device::receive`]), the device takes transmit buffers in available
//! order ([`Device::fetch_tx`]) and completes them in any order
//! ([`Device::complete_tx`]), and interrupts are a pending count per MSI-X
//! vector ([`Device::take_interrupts`]).
//!
//! It fails the test, by panicking, when the driver breaks a rule the
//! specification gives a driver: a status bit cleared or set out of
//! order, a write to a read-only register or a device-configuration field,
//! an access of the wrong width, a feature accepted after FEATURES_OK, a
//! queue register written outside FEATURES_OK to DRIVER_OK or after the
//! queue is enabled, a queue size that is not a power of 2 or above the
//! maximum, misaligned rings, a notify before DRIVER_OK or at the wrong
//! address, an available index that moves backwards or more than the
//! queue size ahead, a descriptor posted while the device holds it or
//! changed while it does, a descriptor of the wrong direction, chained in
//! a loop, indirect, or naming memory outside the DMA frame, and a
//! transmit header with flags, a GSO type or `num_buffers` set.
//! Hostile modes write the used ring as no honest device would.

use core::cell::RefCell;
use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use libsys::mem::{Memory, Ram, Regs};

use crate::pci::{NO_VECTOR, common, net, status};
use crate::virtq::{
    AVAIL_F_NO_INTERRUPT, DESC_F_INDIRECT, DESC_F_NEXT, DESC_F_WRITE, USED_F_NO_NOTIFY,
};
use crate::{HEADER, Regions, Which};

/// Feature bits (virtio 1.2, 5.1.3 and 6).
pub mod f {
    pub const CSUM: u64 = 1 << 0;
    pub const GUEST_CSUM: u64 = 1 << 1;
    pub const CTRL_GUEST_OFFLOADS: u64 = 1 << 2;
    pub const MTU: u64 = 1 << 3;
    pub const MAC: u64 = 1 << 5;
    pub const GUEST_TSO4: u64 = 1 << 7;
    pub const GUEST_TSO6: u64 = 1 << 8;
    pub const GUEST_ECN: u64 = 1 << 9;
    pub const GUEST_UFO: u64 = 1 << 10;
    pub const HOST_TSO4: u64 = 1 << 11;
    pub const HOST_TSO6: u64 = 1 << 12;
    pub const HOST_ECN: u64 = 1 << 13;
    pub const HOST_UFO: u64 = 1 << 14;
    pub const MRG_RXBUF: u64 = 1 << 15;
    pub const STATUS: u64 = 1 << 16;
    pub const CTRL_VQ: u64 = 1 << 17;
    pub const CTRL_RX: u64 = 1 << 18;
    pub const CTRL_VLAN: u64 = 1 << 19;
    pub const GUEST_ANNOUNCE: u64 = 1 << 21;
    pub const MQ: u64 = 1 << 22;
    pub const CTRL_MAC_ADDR: u64 = 1 << 23;
    pub const INDIRECT_DESC: u64 = 1 << 28;
    pub const EVENT_IDX: u64 = 1 << 29;
    pub const VERSION_1: u64 = 1 << 32;
    pub const ACCESS_PLATFORM: u64 = 1 << 33;
    pub const RING_PACKED: u64 = 1 << 34;
    pub const RING_RESET: u64 = 1 << 40;

    /// What a `virtio-net-pci` on QEMU 8.2 offers by default, from memory:
    /// the offloads, mergeable buffers, the control queue and its
    /// features, indirect descriptors, the event index, VERSION_1 and
    /// queue reset.
    pub const QEMU: u64 = CSUM
        | GUEST_CSUM
        | CTRL_GUEST_OFFLOADS
        | MAC
        | GUEST_TSO4
        | GUEST_TSO6
        | GUEST_ECN
        | GUEST_UFO
        | HOST_TSO4
        | HOST_TSO6
        | HOST_ECN
        | HOST_UFO
        | MRG_RXBUF
        | STATUS
        | CTRL_VQ
        | CTRL_RX
        | CTRL_VLAN
        | GUEST_ANNOUNCE
        | CTRL_MAC_ADDR
        | INDIRECT_DESC
        | EVENT_IDX
        | VERSION_1
        | RING_RESET;

    /// Each feature and what it needs (5.1.3.1): one of the second set.
    pub const NEEDS: [(u64, u64); 13] = [
        (GUEST_TSO4, GUEST_CSUM),
        (GUEST_TSO6, GUEST_CSUM),
        (GUEST_ECN, GUEST_TSO4 | GUEST_TSO6),
        (GUEST_UFO, GUEST_CSUM),
        (HOST_TSO4, CSUM),
        (HOST_TSO6, CSUM),
        (HOST_ECN, HOST_TSO4 | HOST_TSO6),
        (HOST_UFO, CSUM),
        (CTRL_RX, CTRL_VQ),
        (CTRL_VLAN, CTRL_VQ),
        (GUEST_ANNOUNCE, CTRL_VQ),
        (MQ, CTRL_VQ),
        (CTRL_MAC_ADDR, CTRL_VQ),
    ];
}

/// The model's make and its hostile knobs.
#[derive(Clone, Debug)]
pub struct Config {
    /// The features it offers.
    pub features: u64,
    pub num_queues: u16,
    /// Each queue's maximum size, a power of 2.
    pub max_size: u16,
    /// MSI-X vectors in the table root programmed.
    pub table_size: u16,
    pub mac: [u8; 6],
    /// `virtio_net_config.status`.
    pub link: u16,
    /// Each queue's `queue_notify_off`.
    pub notify_off: Vec<u16>,
    pub multiplier: u32,
    /// The three regions' lengths.
    pub lens: [usize; 3],
    /// Reads of `device_status` after a reset that still show the old
    /// status; `u32::MAX` for a device that never resets.
    pub reset_reads: u32,
    /// Clears FEATURES_OK whatever the driver accepts.
    pub refuse_features: bool,
    /// Refuses every MSI-X vector mapping: they read back `NO_VECTOR`.
    pub refuse_vectors: bool,
    /// Times the configuration changes while the driver reads it: each
    /// read pass until then sees a torn MAC and a new generation after.
    pub churn: u32,
    /// Starts as the firmware left it: running, with queues enabled at
    /// stale addresses.
    pub dirty: bool,
}

impl Config {
    /// A QEMU-like device (from memory): its features, 3 queues (the
    /// control queue's included) of 256, 3 MSI-X vectors, MAC
    /// `52:54:00:12:34:56`, link up, notify offsets 0, 1 and 2 with
    /// multiplier 4, and 4 KiB regions.
    pub fn qemu() -> Config {
        Config {
            features: f::QEMU,
            num_queues: 3,
            max_size: 256,
            table_size: 3,
            mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            link: net::LINK_UP,
            notify_off: vec![0, 1, 2],
            multiplier: 4,
            lens: [0x1000; 3],
            reset_reads: 0,
            refuse_features: false,
            refuse_vectors: false,
            churn: 0,
            dirty: false,
        }
    }
}

/// What the model saw, in order, for tests of the setup's order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// `device_status` written 0.
    Reset,
    /// `device_status` written this.
    Status(u8),
    /// The 64 accepted bits, as the driver last wrote them, when
    /// FEATURES_OK was written.
    Accepted(u64),
    /// `config_msix_vector` written.
    ConfigVector(u16),
    /// Queue `q` enabled, with its size and vector.
    Enabled { queue: u16, size: u16, vector: u16 },
    /// The device configuration read, generation to generation.
    ConfigRead,
    /// Queue `q` notified, with its available index then.
    Notify { queue: u16, avail: u16 },
}

/// A descriptor as the device read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Desc {
    pub addr: u64,
    pub len: u32,
    pub flags: u16,
    pub next: u16,
}

/// A buffer the device took from the available ring and has not used.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Held {
    pub head: u16,
    pub chain: Vec<Desc>,
}

#[derive(Clone, Debug, Default)]
struct Queue {
    size: u16,
    vector: u16,
    enabled: bool,
    desc: u64,
    driver: u64,
    device: u64,
    /// The device's next available entry.
    next_avail: u16,
    /// The available index it may read up to: as at the last notify, or
    /// the ring's own while it asks for no notifications.
    seen: u16,
    no_notify: bool,
    /// Its used index.
    used: u16,
    held: Vec<Held>,
}

#[derive(Debug)]
struct State {
    cfg: Config,
    status: u8,
    /// Reads left before a reset shows.
    resetting: u32,
    device_feature_select: u32,
    driver_feature_select: u32,
    driver_features: u64,
    config_vector: u16,
    generation: u8,
    churn: u32,
    /// Whether the device configuration was read since the last read of
    /// `config_generation`.
    config_read: bool,
    select: u16,
    queues: Vec<Queue>,
    /// Pending MSI-X messages per vector.
    interrupts: Vec<u32>,
    notifies: Vec<u32>,
    /// Frames the network sent that found no receive buffer.
    no_buffer: u64,
    log: Vec<Event>,
}

/// The model device over the guest memory `[base, base + mem.len())`.
pub struct Device<'m> {
    mem: &'m Ram,
    base: u64,
    s: RefCell<State>,
}

/// One of the device's regions, as the driver's [`Regs`].
#[derive(Clone, Copy)]
pub struct Port<'a> {
    dev: &'a Device<'a>,
    which: Which,
    len: usize,
}

impl Regs for Port<'_> {
    fn len(&self) -> usize {
        self.len
    }
    fn read8(&self, offset: usize) -> u8 {
        self.dev.access(self, offset, 1, None) as u8
    }
    fn read16(&self, offset: usize) -> u16 {
        self.dev.access(self, offset, 2, None) as u16
    }
    fn read32(&self, offset: usize) -> u32 {
        self.dev.access(self, offset, 4, None)
    }
    fn write8(&self, offset: usize, value: u8) {
        self.dev.access(self, offset, 1, Some(value.into()));
    }
    fn write16(&self, offset: usize, value: u16) {
        self.dev.access(self, offset, 2, Some(value.into()));
    }
    fn write32(&self, offset: usize, value: u32) {
        self.dev.access(self, offset, 4, Some(value));
    }
}

/// The common configuration's registers: offset, width, name.
const COMMON: [(usize, usize, &str); 20] = [
    (common::DEVICE_FEATURE_SELECT, 4, "device_feature_select"),
    (common::DEVICE_FEATURE, 4, "device_feature"),
    (common::DRIVER_FEATURE_SELECT, 4, "driver_feature_select"),
    (common::DRIVER_FEATURE, 4, "driver_feature"),
    (common::CONFIG_MSIX_VECTOR, 2, "config_msix_vector"),
    (common::NUM_QUEUES, 2, "num_queues"),
    (common::DEVICE_STATUS, 1, "device_status"),
    (common::CONFIG_GENERATION, 1, "config_generation"),
    (common::QUEUE_SELECT, 2, "queue_select"),
    (common::QUEUE_SIZE, 2, "queue_size"),
    (common::QUEUE_MSIX_VECTOR, 2, "queue_msix_vector"),
    (common::QUEUE_ENABLE, 2, "queue_enable"),
    (common::QUEUE_NOTIFY_OFF, 2, "queue_notify_off"),
    (common::QUEUE_DESC, 4, "queue_desc low"),
    (common::QUEUE_DESC + 4, 4, "queue_desc high"),
    (common::QUEUE_DRIVER, 4, "queue_driver low"),
    (common::QUEUE_DRIVER + 4, 4, "queue_driver high"),
    (common::QUEUE_DEVICE, 4, "queue_device low"),
    (common::QUEUE_DEVICE + 4, 4, "queue_device high"),
    // queue_notif_config_data and queue_reset exist only with features
    // the driver may not accept; any access there fails below.
    (0x38, 0, "queue_notif_config_data"),
];

impl<'m> Device<'m> {
    /// A device as `cfg` makes it, whose DMA frame is `mem` at physical
    /// `base`.
    pub fn new(mem: &'m Ram, base: u64, cfg: Config) -> Device<'m> {
        let n = usize::from(cfg.num_queues);
        assert!(cfg.notify_off.len() >= n);
        let mut s = State {
            status: 0,
            resetting: 0,
            device_feature_select: 0,
            driver_feature_select: 0,
            driver_features: 0,
            config_vector: NO_VECTOR,
            generation: 0,
            churn: cfg.churn,
            config_read: false,
            select: 0,
            queues: vec![Queue::default(); n],
            interrupts: vec![0; usize::from(cfg.table_size)],
            notifies: vec![0; n],
            no_buffer: 0,
            log: Vec::new(),
            cfg,
        };
        s.reset_registers();
        if s.cfg.dirty {
            s.status =
                status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK;
            s.driver_features = s.cfg.features;
            for q in &mut s.queues {
                q.enabled = true;
                q.desc = 0xDEAD_0000;
                q.driver = 0xDEAD_1000;
                q.device = 0xDEAD_2000;
                q.vector = 0;
            }
        }
        Device {
            mem,
            base,
            s: RefCell::new(s),
        }
    }

    /// The three regions, as the driver gets them.
    pub fn regions(&self) -> Regions<Port<'_>> {
        let lens = self.s.borrow().cfg.lens;
        let port = |which: Which| Port {
            dev: self,
            which,
            len: lens[which as usize],
        };
        Regions {
            common: port(Which::Common),
            notify: port(Which::Notify),
            device: port(Which::Device),
        }
    }

    pub fn status(&self) -> u8 {
        self.s.borrow().status
    }

    /// The features the driver accepted.
    pub fn accepted(&self) -> u64 {
        self.s.borrow().driver_features
    }

    pub fn log(&self) -> Vec<Event> {
        self.s.borrow().log.clone()
    }

    pub fn notifies(&self, q: u16) -> u32 {
        self.s.borrow().notifies[usize::from(q)]
    }

    pub fn config_vector(&self) -> u16 {
        self.s.borrow().config_vector
    }

    /// Queue `q`'s size, vector, and whether it is enabled.
    pub fn queue(&self, q: u16) -> (u16, u16, bool) {
        let s = self.s.borrow();
        let q = &s.queues[usize::from(q)];
        (q.size, q.vector, q.enabled)
    }

    /// Queue `q`'s descriptor table, driver and device areas.
    pub fn rings(&self, q: u16) -> [u64; 3] {
        let s = self.s.borrow();
        let q = &s.queues[usize::from(q)];
        [q.desc, q.driver, q.device]
    }

    /// The buffers the device holds on queue `q`.
    pub fn held(&self, q: u16) -> Vec<Held> {
        self.s.borrow().queues[usize::from(q)].held.clone()
    }

    /// Frames the network sent that found no receive buffer.
    pub fn no_buffer(&self) -> u64 {
        self.s.borrow().no_buffer
    }

    /// The pending MSI-X messages on vector 0, now taken: what the
    /// driver's notification would see as one `IRQ` signal.
    pub fn take_interrupts(&self) -> u32 {
        let mut s = self.s.borrow_mut();
        s.interrupts.first_mut().map_or(0, core::mem::take)
    }

    /// Pending MSI-X messages on every vector, not taken.
    pub fn interrupts(&self) -> Vec<u32> {
        self.s.borrow().interrupts.clone()
    }

    /// The configuration changes: a new link status, a new generation,
    /// and a configuration interrupt if the driver mapped one (4.1.5.3).
    pub fn set_link(&self, link: u16) {
        let mut s = self.s.borrow_mut();
        s.cfg.link = link;
        s.generation = s.generation.wrapping_add(1);
        let v = s.config_vector;
        s.interrupt(v);
    }

    /// Sets or clears `VIRTQ_USED_F_NO_NOTIFY` on queue `q`. Clearing it,
    /// the device looks at the available ring once more, as a device that
    /// stops polling must.
    pub fn set_no_notify(&self, q: u16, on: bool) {
        let mut s = self.s.borrow_mut();
        let used = s.queues[usize::from(q)].device;
        self.store16(used, if on { USED_F_NO_NOTIFY } else { 0 }, Release);
        let avail = self.avail_idx(&s.queues[usize::from(q)]);
        let queue = &mut s.queues[usize::from(q)];
        queue.no_notify = on;
        if !on {
            queue.seen = avail;
        }
    }

    // The driver's accesses.

    fn access(&self, port: &Port<'_>, offset: usize, width: usize, write: Option<u32>) -> u32 {
        assert!(
            offset.checked_add(width).is_some_and(|e| e <= port.len),
            "model: {} access of {width} bytes at {offset:#x} outside the {} region of {:#x}",
            if write.is_some() { "a write" } else { "a read" },
            port.which.name(),
            port.len
        );
        assert!(
            offset.is_multiple_of(width),
            "model: a misaligned {width}-byte access at {offset:#x} in the {} region",
            port.which.name()
        );
        match port.which {
            Which::Common => self.common(offset, width, write),
            Which::Notify => {
                let Some(v) = write else {
                    panic!("model: the driver read the notify region at {offset:#x}")
                };
                assert_eq!(
                    width, 2,
                    "model: a {width}-byte notify, not 16 bits (4.1.5.2)"
                );
                self.notify(offset, v as u16);
                0
            }
            Which::Device => self.device_config(offset, width, write),
        }
    }

    fn common(&self, offset: usize, width: usize, write: Option<u32>) -> u32 {
        let Some(&(_, w, name)) = COMMON.iter().find(|r| r.0 == offset) else {
            panic!("model: no common register starts at {offset:#x}")
        };
        assert_eq!(
            w, width,
            "model: {name} accessed {width} bytes wide, not {w} (4.1.3.1)"
        );
        let mut s = self.s.borrow_mut();
        let Some(v) = write else {
            return s.read_common(offset);
        };
        match offset {
            common::DEVICE_FEATURE
            | common::NUM_QUEUES
            | common::CONFIG_GENERATION
            | common::QUEUE_NOTIFY_OFF => {
                panic!("model: the driver wrote {name}, which it MUST NOT (4.1.4.3.2)")
            }
            common::DEVICE_STATUS => self.write_status(&mut s, v as u8),
            _ => s.write_common(offset, name, v),
        }
        0
    }

    fn write_status(&self, s: &mut State, v: u8) {
        if v == 0 {
            s.log.push(Event::Reset);
            s.reset();
            return;
        }
        s.log.push(Event::Status(v));
        assert!(
            s.resetting == 0,
            "model: status {v:#x} written before the reset was seen to finish (4.1.4.3.2)"
        );
        let old = s.status;
        assert!(
            old & !v == 0,
            "model: status {v:#x} clears bits of {old:#x} (2.1.1)"
        );
        if v & status::FAILED != 0 {
            s.status = v;
            return;
        }
        let new = v & !old;
        let order = [
            (status::ACKNOWLEDGE, 0),
            (status::DRIVER, status::ACKNOWLEDGE),
            (status::FEATURES_OK, status::ACKNOWLEDGE | status::DRIVER),
            (
                status::DRIVER_OK,
                status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK,
            ),
        ];
        for (bit, needs) in order {
            if new & bit != 0 {
                assert!(
                    old & needs == needs,
                    "model: status bit {bit:#x} set before {needs:#x} (3.1.1), status {old:#x}"
                );
            }
        }
        let known = status::ACKNOWLEDGE | status::DRIVER | status::FEATURES_OK | status::DRIVER_OK;
        assert!(
            v & !known == 0,
            "model: status {v:#x} sets a bit the driver may not"
        );
        s.status = v;
        if new & status::FEATURES_OK != 0 {
            s.log.push(Event::Accepted(s.driver_features));
            if !s.features_ok() {
                s.status &= !status::FEATURES_OK;
            }
        }
    }

    fn device_config(&self, offset: usize, width: usize, write: Option<u32>) -> u32 {
        assert!(
            write.is_none(),
            "model: the driver wrote the device configuration at {offset:#x} (5.1.4.2)"
        );
        let mut s = self.s.borrow_mut();
        s.config_read = true;
        let torn = s.churn > 0;
        match (offset, width) {
            (o, 1) if o < net::MAC + 6 => {
                let b = s.cfg.mac[o - net::MAC];
                u32::from(if torn { !b } else { b })
            }
            (net::STATUS, 2) => {
                assert!(
                    s.cfg.features & f::STATUS != 0,
                    "model: status read though STATUS is not offered (2.5.1)"
                );
                u32::from(s.cfg.link)
            }
            _ => panic!(
                "model: a {width}-byte device configuration read at {offset:#x} the driver does not need"
            ),
        }
    }

    fn notify(&self, offset: usize, q: u16) {
        let mut s = self.s.borrow_mut();
        assert!(
            s.status & status::DRIVER_OK != 0,
            "model: queue {q} notified before DRIVER_OK (3.1.1)"
        );
        assert!(
            q < s.cfg.num_queues,
            "model: notify of queue {q}, which does not exist"
        );
        let at = usize::from(s.cfg.notify_off[usize::from(q)]) * s.cfg.multiplier as usize;
        assert_eq!(
            offset, at,
            "model: queue {q} notified at {offset:#x}, not its {at:#x} (4.1.4.4)"
        );
        let queue = &s.queues[usize::from(q)];
        assert!(queue.enabled, "model: queue {q} notified but not enabled");
        let avail = self.avail_idx(queue);
        s.queues[usize::from(q)].seen = avail;
        s.notifies[usize::from(q)] += 1;
        s.log.push(Event::Notify { queue: q, avail });
    }

    // Guest memory.

    /// The offset in the DMA frame of `[addr, addr + len)`; fails the test
    /// if the range leaves it.
    fn at(&self, addr: u64, len: usize, what: &str) -> usize {
        let end = addr.checked_add(len as u64);
        let frame = self.base + self.mem.len() as u64;
        assert!(
            addr >= self.base && end.is_some_and(|e| e <= frame),
            "model: {what} at {addr:#x}, {len} bytes, outside the DMA frame [{:#x}, {frame:#x})",
            self.base
        );
        (addr - self.base) as usize
    }

    fn load16(&self, addr: u64, order: core::sync::atomic::Ordering) -> u16 {
        self.mem.load16(self.at(addr, 2, "a ring field"), order)
    }

    fn store16(&self, addr: u64, v: u16, order: core::sync::atomic::Ordering) {
        self.mem.store16(self.at(addr, 2, "a ring field"), v, order)
    }

    fn avail_idx(&self, q: &Queue) -> u16 {
        self.load16(q.driver + 2, Acquire)
    }

    fn read_desc(&self, q: &Queue, i: u16) -> Desc {
        let a = self.at(q.desc + 16 * u64::from(i), 16, "a descriptor");
        Desc {
            addr: self.mem.load64(a, Relaxed),
            len: self.mem.load32(a + 8, Relaxed),
            flags: self.mem.load16(a + 12, Relaxed),
            next: self.mem.load16(a + 14, Relaxed),
        }
    }

    /// The chain from `head`, as 2.7.5 has it: each descriptor checked.
    fn chain(&self, q: &Queue, head: u16, writable: bool, name: u16) -> Vec<Desc> {
        let mut chain = Vec::new();
        let mut i = head;
        loop {
            assert!(
                i < q.size,
                "model: queue {name} descriptor {i} out of its {}",
                q.size
            );
            assert!(
                chain.len() < usize::from(q.size),
                "model: queue {name}'s chain from {head} loops (2.7.5.2)"
            );
            let d = self.read_desc(q, i);
            assert!(
                d.flags & DESC_F_INDIRECT == 0,
                "model: queue {name} descriptor {i} indirect, not negotiated (2.7.5.3.1)"
            );
            assert_eq!(
                d.flags & DESC_F_WRITE != 0,
                writable,
                "model: queue {name} descriptor {i}'s direction is wrong (flags {:#x})",
                d.flags
            );
            self.at(
                d.addr,
                d.len as usize,
                &format!("queue {name} descriptor {i}'s buffer"),
            );
            chain.push(d);
            if d.flags & DESC_F_NEXT == 0 {
                return chain;
            }
            i = d.next;
        }
    }

    /// Takes queue `q`'s newly available buffers, as far as the device may
    /// look: to the index at the last notify, or the ring's own while it
    /// asked for none. Nothing before DRIVER_OK (2.1.2). How many.
    pub fn fetch(&self, q: u16) -> usize {
        let mut s = self.s.borrow_mut();
        if s.status & status::DRIVER_OK == 0 || s.status & status::FAILED != 0 {
            return 0;
        }
        let i = usize::from(q);
        if s.queues[i].no_notify {
            let avail = self.avail_idx(&s.queues[i]);
            s.queues[i].seen = avail;
        }
        let queue = &s.queues[i];
        let limit = queue.seen;
        // Never backwards, and never more than the queue's size ahead of
        // what the device has taken (2.7.6.1, 2.7.13).
        assert!(
            limit.wrapping_sub(queue.next_avail) <= queue.size,
            "model: queue {q}'s available index moved from {} to {limit} (2.7.6.1)",
            queue.next_avail
        );
        let mut taken = Vec::new();
        let mut k = queue.next_avail;
        while k != limit {
            let at = queue.driver + 4 + 2 * u64::from(k % queue.size);
            let head = self.load16(at, Relaxed);
            assert!(
                !queue
                    .held
                    .iter()
                    .chain(&taken)
                    .any(|h: &Held| h.head == head),
                "model: queue {q} descriptor {head} made available while the device holds it"
            );
            let chain = self.chain(queue, head, q == 0, q);
            taken.push(Held { head, chain });
            k = k.wrapping_add(1);
        }
        let n = taken.len();
        let queue = &mut s.queues[i];
        queue.next_avail = limit;
        queue.held.extend(taken);
        n
    }

    /// Writes a used element for `head` and then the used index, then
    /// interrupts unless the driver asked for none (2.7.7.2).
    fn push_used(&self, s: &mut State, q: u16, id: u32, len: u32) {
        let queue = &s.queues[usize::from(q)];
        let e = queue.device + 4 + 8 * u64::from(queue.used % queue.size);
        let e = self.at(e, 8, "a used element");
        self.mem.store32(e, id, Relaxed);
        self.mem.store32(e + 4, len, Relaxed);
        let used = queue.used.wrapping_add(1);
        self.store16(queue.device + 2, used, Release);
        let flags = self.load16(queue.driver, Acquire);
        let vector = queue.vector;
        s.queues[usize::from(q)].used = used;
        if flags & AVAIL_F_NO_INTERRUPT == 0 {
            s.interrupt(vector);
        }
    }

    /// Gives back held buffer `pick` of queue `q` with `len`, checking
    /// that the driver left its descriptors alone meanwhile.
    fn give_back(&self, s: &mut State, q: u16, pick: usize, len: u32) {
        let h = s.queues[usize::from(q)].held.remove(pick);
        let queue = &s.queues[usize::from(q)];
        let mut i = h.head;
        for d in &h.chain {
            assert_eq!(
                self.read_desc(queue, i),
                *d,
                "model: queue {q} descriptor {i} changed while the device held it"
            );
            i = d.next;
        }
        self.push_used(s, q, u32::from(h.head), len);
    }

    /// The network sends `frame`: the device writes the header and the
    /// frame into held receive buffer `pick` (mod how many it holds,
    /// after taking what is available) and uses it. `false` if it holds
    /// none: the frame is lost, as on a wire.
    pub fn receive_at(&self, frame: &[u8], pick: usize) -> bool {
        self.fetch(0);
        let mut s = self.s.borrow_mut();
        let held = &s.queues[0].held;
        if held.is_empty() {
            s.no_buffer += 1;
            return false;
        }
        let pick = pick % held.len();
        // virtio_net_hdr_v1: no flags, GSO none, num_buffers 1 (5.1.6.3.2).
        let mut bytes = vec![0u8; HEADER];
        bytes[10] = 1;
        bytes.extend_from_slice(frame);
        let room: usize = held[pick].chain.iter().map(|d| d.len as usize).sum();
        assert!(
            room >= HEADER + 1514,
            "model: a receive buffer of {room} bytes, under 1,526 (5.1.6.3.1)"
        );
        let mut done = 0;
        for d in &held[pick].chain {
            let n = (bytes.len() - done).min(d.len as usize);
            self.mem.write(
                self.at(d.addr, n, "a receive buffer"),
                &bytes[done..done + n],
            );
            done += n;
        }
        self.give_back(&mut s, 0, pick, bytes.len() as u32);
        true
    }

    /// [`Device::receive_at`] into the first buffer the device holds.
    pub fn receive(&self, frame: &[u8]) -> bool {
        self.receive_at(frame, 0)
    }

    /// Takes the newly available transmit buffers and reads each frame, in
    /// available order, as the device sends them; they stay held until
    /// [`Device::complete_tx`]. The frames sent.
    pub fn fetch_tx(&self) -> Vec<Vec<u8>> {
        let before = self.s.borrow().queues[1].held.len();
        self.fetch(1);
        let s = self.s.borrow();
        s.queues[1].held[before..]
            .iter()
            .map(|h| self.read_tx(h))
            .collect()
    }

    fn read_tx(&self, h: &Held) -> Vec<u8> {
        let mut bytes = Vec::new();
        for d in &h.chain {
            let mut b = vec![0; d.len as usize];
            self.mem
                .read(self.at(d.addr, b.len(), "a transmit buffer"), &mut b);
            bytes.extend(b);
        }
        assert!(
            bytes.len() >= HEADER,
            "model: a transmit buffer of {} bytes, under the header",
            bytes.len()
        );
        // 5.1.6.2.1: flags 0 without CSUM, GSO none without HOST_TSO4,
        // TSO6, UFO or USO, and num_buffers 0.
        assert_eq!(bytes[0], 0, "model: transmit header flags {:#x}", bytes[0]);
        assert_eq!(
            bytes[1], 0,
            "model: transmit header GSO type {:#x}",
            bytes[1]
        );
        assert_eq!(&bytes[10..12], &[0, 0], "model: transmit num_buffers not 0");
        let frame = bytes.split_off(HEADER);
        assert!(
            (14..=1514).contains(&frame.len()),
            "model: a transmitted frame of {} bytes",
            frame.len()
        );
        frame
    }

    /// Uses held transmit buffer `pick` (mod how many it holds); `false`
    /// if it holds none.
    pub fn complete_tx(&self, pick: usize) -> bool {
        let mut s = self.s.borrow_mut();
        let n = s.queues[1].held.len();
        if n == 0 {
            return false;
        }
        // A device writes nothing into a device-readable buffer: length 0.
        self.give_back(&mut s, 1, pick % n, 0);
        true
    }

    /// Sends and uses every available transmit buffer, in order.
    pub fn transmit(&self) -> Vec<Vec<u8>> {
        let frames = self.fetch_tx();
        while self.complete_tx(0) {}
        frames
    }

    // Hostile modes.

    /// Writes a used element no honest device would: `id` and `len` as
    /// given, whatever the device holds, then the used index.
    pub fn inject_used(&self, q: u16, id: u32, len: u32) {
        let mut s = self.s.borrow_mut();
        self.push_used(&mut s, q, id, len);
    }

    /// Uses held buffer `pick` of queue `q` with any length.
    pub fn complete_with(&self, q: u16, pick: usize, len: u32) {
        self.fetch(q);
        let mut s = self.s.borrow_mut();
        let n = s.queues[usize::from(q)].held.len();
        assert!(n > 0, "model: no buffer held on queue {q}");
        self.give_back(&mut s, q, pick % n, len);
    }

    /// Sets queue `q`'s used index, with no elements behind it, and
    /// interrupts.
    pub fn set_used_idx(&self, q: u16, idx: u16) {
        let mut s = self.s.borrow_mut();
        let queue = &s.queues[usize::from(q)];
        self.store16(queue.device + 2, idx, Release);
        let vector = queue.vector;
        s.queues[usize::from(q)].used = idx;
        s.interrupt(vector);
    }
}

impl State {
    /// Reset (2.4.1, 4.1.4.3.1): everything to its reset value; the
    /// status shows 0 once `reset_reads` reads have shown the old one.
    fn reset(&mut self) {
        // A status already 0 shows the reset at once.
        self.resetting = if self.status == 0 {
            0
        } else {
            self.cfg.reset_reads
        };
        if self.resetting == 0 {
            self.status = 0;
        }
        self.reset_registers();
    }

    fn reset_registers(&mut self) {
        self.device_feature_select = 0;
        self.driver_feature_select = 0;
        self.driver_features = 0;
        self.config_vector = NO_VECTOR;
        self.select = 0;
        for q in &mut self.queues {
            *q = Queue {
                size: self.cfg.max_size,
                vector: NO_VECTOR,
                ..Queue::default()
            };
        }
    }

    fn queue(&self) -> Option<&Queue> {
        self.queues.get(usize::from(self.select))
    }

    fn read_common(&mut self, offset: usize) -> u32 {
        let q = self.queue();
        match offset {
            common::DEVICE_FEATURE_SELECT => self.device_feature_select,
            common::DEVICE_FEATURE => match self.device_feature_select {
                0 => self.cfg.features as u32,
                1 => (self.cfg.features >> 32) as u32,
                _ => 0,
            },
            common::DRIVER_FEATURE_SELECT => self.driver_feature_select,
            common::DRIVER_FEATURE => match self.driver_feature_select {
                0 => self.driver_features as u32,
                1 => (self.driver_features >> 32) as u32,
                _ => 0,
            },
            common::CONFIG_MSIX_VECTOR => self.config_vector.into(),
            common::NUM_QUEUES => self.cfg.num_queues.into(),
            common::DEVICE_STATUS => {
                if self.resetting > 0 {
                    self.resetting = self.resetting.saturating_sub(1);
                    if self.resetting == 0 {
                        let shown = self.status;
                        self.status = 0;
                        return shown.into();
                    }
                    return self.status.into();
                }
                self.status.into()
            }
            common::CONFIG_GENERATION => {
                if self.config_read && self.churn > 0 {
                    self.churn -= 1;
                    self.generation = self.generation.wrapping_add(1);
                }
                self.config_read = false;
                self.log.push(Event::ConfigRead);
                self.generation.into()
            }
            common::QUEUE_SELECT => self.select.into(),
            common::QUEUE_SIZE => q.map_or(0, |q| q.size.into()),
            common::QUEUE_MSIX_VECTOR => q.map_or(NO_VECTOR, |q| q.vector).into(),
            common::QUEUE_ENABLE => q.map_or(0, |q| q.enabled.into()),
            common::QUEUE_NOTIFY_OFF => {
                q.map_or(0, |_| self.cfg.notify_off[usize::from(self.select)].into())
            }
            o if (common::QUEUE_DESC..common::SIZE).contains(&o) => {
                let Some(q) = q else { return 0 };
                let v = [q.desc, q.driver, q.device][(o - common::QUEUE_DESC) / 8];
                if o % 8 == 0 {
                    v as u32
                } else {
                    (v >> 32) as u32
                }
            }
            o => panic!("model: a read of common offset {o:#x}"),
        }
    }

    fn write_common(&mut self, offset: usize, name: &str, v: u32) {
        assert!(
            self.resetting == 0,
            "model: {name} written before the reset was seen to finish (4.1.4.3.2)"
        );
        match offset {
            common::DEVICE_FEATURE_SELECT => self.device_feature_select = v,
            common::DRIVER_FEATURE_SELECT => self.driver_feature_select = v,
            common::DRIVER_FEATURE => {
                assert!(
                    self.status & status::FEATURES_OK == 0,
                    "model: features accepted after FEATURES_OK (3.1.1)"
                );
                let shift = match self.driver_feature_select {
                    0 => 0,
                    1 => 32,
                    s => panic!("model: driver_feature written with select {s}"),
                };
                self.driver_features =
                    self.driver_features & !(0xFFFF_FFFF << shift) | u64::from(v) << shift;
            }
            common::CONFIG_MSIX_VECTOR => {
                self.config_vector = self.vector(v as u16);
                self.log.push(Event::ConfigVector(v as u16));
            }
            _ => self.write_queue(offset, name, v),
        }
    }

    /// The vector a mapping of `v` gets: `v` if it is in the table (or
    /// none), else none (4.1.5.1.2).
    fn vector(&self, v: u16) -> u16 {
        if v == NO_VECTOR || (v < self.cfg.table_size && !self.cfg.refuse_vectors) {
            v
        } else {
            NO_VECTOR
        }
    }

    fn write_queue(&mut self, offset: usize, name: &str, v: u32) {
        let s = self.status;
        assert!(
            s & status::FEATURES_OK != 0 && s & status::DRIVER_OK == 0,
            "model: {name} written in status {s:#x}, not between FEATURES_OK and DRIVER_OK"
        );
        if offset == common::QUEUE_SELECT {
            self.select = v as u16;
            return;
        }
        let select = self.select;
        let vector = self.vector(v as u16);
        let max = self.cfg.max_size;
        let Some(q) = self.queues.get_mut(usize::from(select)) else {
            panic!("model: {name} written for queue {select}, which does not exist")
        };
        assert!(
            !q.enabled,
            "model: queue {select}'s {name} written after it was enabled (4.1.4.3.2)"
        );
        match offset {
            common::QUEUE_SIZE => {
                let n = v as u16;
                assert!(
                    n.is_power_of_two() && n <= max,
                    "model: queue {select}'s size {n}: not a power of 2 up to {max} (4.1.4.3.2)"
                );
                q.size = n;
            }
            common::QUEUE_MSIX_VECTOR => q.vector = vector,
            common::QUEUE_ENABLE => {
                assert_eq!(v, 1, "model: queue_enable written {v} (4.1.4.3.2)");
                let size = u64::from(q.size);
                for (addr, align, len, part) in [
                    (q.desc, 16, 16 * size, "descriptor table"),
                    (q.driver, 2, 6 + 2 * size, "available ring"),
                    (q.device, 4, 6 + 8 * size, "used ring"),
                ] {
                    assert!(
                        addr.is_multiple_of(align),
                        "model: queue {select}'s {part} at {addr:#x}, not {align}-aligned (2.7.1)"
                    );
                    assert!(len > 0 && addr != 0, "model: queue {select}'s {part} unset");
                }
                q.enabled = true;
                let (size, vector) = (q.size, q.vector);
                self.log.push(Event::Enabled {
                    queue: select,
                    size,
                    vector,
                });
            }
            o => {
                let part = (o - common::QUEUE_DESC) / 8;
                let shift = if o % 8 == 0 { 0 } else { 32 };
                let r = [&mut q.desc, &mut q.driver, &mut q.device];
                let r = r.into_iter().nth(part).expect("a ring address");
                *r = *r & !(0xFFFF_FFFF << shift) | u64::from(v) << shift;
            }
        }
    }

    /// Whether the accepted features make a set the device takes: offered,
    /// VERSION_1 among them (a modern device), each with what it needs
    /// (2.2.2, 6.2).
    fn features_ok(&self) -> bool {
        let a = self.driver_features;
        !self.cfg.refuse_features
            && a & !self.cfg.features == 0
            && a & f::VERSION_1 != 0
            && f::NEEDS
                .iter()
                .all(|&(feature, needs)| a & feature == 0 || a & needs != 0)
    }

    /// Sends an MSI-X message on vector `v`, if it is one.
    fn interrupt(&mut self, v: u16) {
        if let Some(n) = self.interrupts.get_mut(usize::from(v)) {
            *n += 1;
        }
    }
}

/// A failure the model reported, for tests of the model itself.
pub fn failure(f: impl FnOnce()) -> String {
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(f));
    match r {
        Ok(()) => panic!("the model did not fail the test"),
        Err(e) => e
            .downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| String::from(*s)))
            .unwrap_or_default(),
    }
}
