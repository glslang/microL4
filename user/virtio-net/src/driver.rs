//! The driver: its setup ([`Driver::start`]) and one signal's work
//! ([`Driver::on_signal`]) (`docs/design.md`, "`virtio-net`", "Setup" and
//! "The loop").

use core::fmt;

use libsys::frames::{self, Link, MAX_FRAME, MIN_FRAME, Mac, PushError};
use libsys::mem::{self, Memory, Regs};
use libsys::proto::{VirtioFeatures, VirtioNetStats, virtio_feature};

use crate::layout::{self, BUFFER_SIZE, QUEUE_SIZE};
use crate::pci::{NO_VECTOR, common, net, status};
use crate::virtq::{DESC_F_WRITE, Virtq};
use crate::{FEATURES, HEADER, Regions, Start, Up, Which};

/// Reads of `device_status` after a reset before the driver gives up.
pub const RESET_READS: u32 = 1000;
/// Reads of the device configuration before the driver gives up on two
/// equal `config_generation`s around one.
pub const GENERATION_TRIES: u32 = 16;

/// The receive queue and the transmit queue.
const RX: u16 = 0;
const TX: u16 = 1;

/// What the driver counts, MR0 to MR5 of its `Stats` reply.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counters {
    /// Notification signals handled, `IRQ` and `FRAMES` alike.
    pub signals: u64,
    /// Frames the device delivered that went on `RX_FILLED`.
    pub received: u64,
    /// Frames the device delivered that found no receive buffer free.
    pub dropped: u64,
    /// Used elements naming a descriptor the device did not hold, receive
    /// elements with a length outside 12 + 14 to 12 + 1,514, and used
    /// indices more than 64 ahead.
    pub bad_used: u64,
    /// Frames from `TX_FILLED` given to the device.
    pub sent: u64,
    /// Times a frame began to wait in `TX_FILLED` for a free transmit
    /// descriptor.
    pub waits: u64,
}

/// Why the device was refused at setup. Each but [`Refused::Window`] and
/// [`Refused::NoReset`] is reported to the device with FAILED first;
/// `virtio_net::run` panics with the reason.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refused {
    /// A window shorter than the driver uses: a region, or the DMA frame.
    Window { what: &'static str, len: usize },
    /// `device_status` did not read 0 after the reset, in
    /// [`RESET_READS`] reads: the last value read.
    NoReset(u8),
    /// The device does not offer `VIRTIO_F_VERSION_1`: what it offers.
    NoVersion1(u64),
    /// The device offers no `VIRTIO_NET_F_MAC`, and `net` needs an
    /// address.
    NoMac(u64),
    /// FEATURES_OK did not read back: the device refused the set.
    FeaturesRefused { accepted: u64, status: u8 },
    /// `num_queues` under 2.
    FewQueues(u16),
    /// A queue whose maximum size is under 64.
    SmallQueue { queue: u16, size: u16 },
    /// A queue's `queue_msix_vector` did not read back 0.
    VectorRefused { queue: u16, read: u16 },
    /// A queue's notify address outside the notify region.
    NotifyOutside {
        queue: u16,
        notify_off: u16,
        multiplier: u32,
        len: usize,
    },
    /// `config_generation` changed across each of [`GENERATION_TRIES`]
    /// reads of the configuration.
    ConfigUnstable,
    /// The MAC is 0 or a group address, which no station may have.
    BadMac(Mac),
}

impl fmt::Display for Refused {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Refused::Window { what, len } => write!(f, "the {what} window is {len} bytes"),
            Refused::NoReset(s) => write!(
                f,
                "the device did not reset: status {s:#04x} after {RESET_READS} reads"
            ),
            Refused::NoVersion1(o) => {
                write!(f, "the device does not offer VERSION_1 (features {o:#x})")
            }
            Refused::NoMac(o) => write!(
                f,
                "the device does not offer MAC (features {o:#x}), and net needs its address"
            ),
            Refused::FeaturesRefused { accepted, status } => write!(
                f,
                "the device refused features {}: FEATURES_OK clear (status {status:#04x})",
                VirtioFeatures(accepted)
            ),
            Refused::FewQueues(n) => write!(f, "the device has {n} queues, fewer than 2"),
            Refused::SmallQueue { queue, size } => write!(
                f,
                "queue {queue} has at most {size} entries, fewer than {QUEUE_SIZE}"
            ),
            Refused::VectorRefused { queue, read } => write!(
                f,
                "queue {queue}'s MSI-X vector 0 was refused (read {read:#x})"
            ),
            Refused::NotifyOutside {
                queue,
                notify_off,
                multiplier,
                len,
            } => write!(
                f,
                "queue {queue}'s notify offset {notify_off} x {multiplier} is outside the notify region of {len} bytes"
            ),
            Refused::ConfigUnstable => write!(
                f,
                "the device configuration changed during each of {GENERATION_TRIES} reads"
            ),
            Refused::BadMac(m) => write!(f, "the device's MAC {m} is not unicast"),
        }
    }
}

/// The driver's state: the device's regions, the DMA frame, the two
/// queues, what it negotiated and read, and its counters.
#[derive(Debug)]
pub struct Driver<R, M> {
    regions: Regions<R>,
    dma: M,
    rx: Virtq,
    tx: Virtq,
    /// `device_status` as the driver last wrote it.
    status: u8,
    features: u64,
    mac: Mac,
    link_up: bool,
    /// Whether a frame waits in `TX_FILLED` for a transmit descriptor, so
    /// transmit completions are on.
    waiting: bool,
    counters: Counters,
}

impl<R: Regs, M: Memory> Driver<R, M> {
    /// Sets up the device (`docs/design.md`, `virtio-net`'s "Setup",
    /// steps 1 to 10) with its regions' windows `regions`, the DMA frame
    /// `dma` at the physical base `start.dma`, and `start.multiplier`:
    /// reset, ACKNOWLEDGE and DRIVER, the features, FEATURES_OK read back,
    /// no configuration interrupt, the two queues on MSI-X entry 0, the
    /// MAC and link, all 64 receive buffers posted, DRIVER_OK and queue
    /// 0's notify; then the frame queues' start, `TX_FREE` and the link
    /// block. Signal `net` after, if `queues.end_batch()` says so.
    ///
    /// A device it refuses after its reset gets FAILED, and the reason is
    /// returned.
    pub fn start<Q: Memory>(
        start: &Start,
        regions: Regions<R>,
        dma: M,
        queues: &mut frames::Driver<Q>,
    ) -> Result<Driver<R, M>, Refused> {
        for which in Which::ALL {
            let len = regions.get(which).len();
            if len < which.min_len() {
                return Err(Refused::Window {
                    what: which.name(),
                    len,
                });
            }
        }
        if dma.len() < layout::END {
            return Err(Refused::Window {
                what: "DMA",
                len: dma.len(),
            });
        }
        let mut d = Driver {
            regions,
            dma,
            rx: Virtq::new(RX),
            tx: Virtq::new(TX),
            status: 0,
            features: 0,
            mac: Mac::ZERO,
            link_up: false,
            waiting: false,
            counters: Counters::default(),
        };
        if let Err(e) = d.setup(start) {
            // A device whose reset never showed may not be written again
            // (4.1.4.3.2); any other is told the driver gave up (3.1.1).
            if !matches!(e, Refused::NoReset(_)) {
                d.set_status(status::FAILED);
            }
            return Err(e);
        }
        queues.start(Link::new(d.mac, d.link_up));
        Ok(d)
    }

    fn common(&self) -> &R {
        &self.regions.common
    }

    /// Sets `bits` in `device_status`, keeping those already set: the
    /// driver never clears one (2.1.1).
    fn set_status(&mut self, bits: u8) {
        self.status |= bits;
        self.regions
            .common
            .write8(common::DEVICE_STATUS, self.status);
    }

    fn setup(&mut self, start: &Start) -> Result<(), Refused> {
        // 1: reset, and wait for it.
        self.common().write8(common::DEVICE_STATUS, 0);
        let mut last = 0;
        if !(0..RESET_READS).any(|_| {
            last = self.common().read8(common::DEVICE_STATUS);
            last == 0
        }) {
            return Err(Refused::NoReset(last));
        }
        // 2.
        self.set_status(status::ACKNOWLEDGE);
        self.set_status(status::DRIVER);
        // 3: the 64 feature bits, in two halves; accept only ours.
        let c = self.common();
        c.write32(common::DEVICE_FEATURE_SELECT, 0);
        let low = c.read32(common::DEVICE_FEATURE);
        c.write32(common::DEVICE_FEATURE_SELECT, 1);
        let high = c.read32(common::DEVICE_FEATURE);
        let offered = u64::from(high) << 32 | u64::from(low);
        if offered & virtio_feature::VERSION_1 == 0 {
            return Err(Refused::NoVersion1(offered));
        }
        if offered & virtio_feature::MAC == 0 {
            return Err(Refused::NoMac(offered));
        }
        let accepted = offered & FEATURES;
        c.write32(common::DRIVER_FEATURE_SELECT, 0);
        c.write32(common::DRIVER_FEATURE, accepted as u32);
        c.write32(common::DRIVER_FEATURE_SELECT, 1);
        c.write32(common::DRIVER_FEATURE, (accepted >> 32) as u32);
        self.features = accepted;
        // 4: a device that clears FEATURES_OK refuses the set.
        self.set_status(status::FEATURES_OK);
        let s = self.common().read8(common::DEVICE_STATUS);
        if s & status::FEATURES_OK == 0 {
            return Err(Refused::FeaturesRefused {
                accepted,
                status: s,
            });
        }
        // 5: no configuration interrupt; queue 0 receives, 1 transmits.
        let c = self.common();
        c.write16(common::CONFIG_MSIX_VECTOR, NO_VECTOR);
        let n = c.read16(common::NUM_QUEUES);
        if n < layout::QUEUES {
            return Err(Refused::FewQueues(n));
        }
        // 6.
        self.setup_queue(RX, start)?;
        self.setup_queue(TX, start)?;
        // 7.
        self.read_config()?;
        // 8: every receive buffer posted; transmit completions off until
        // a frame waits for a descriptor.
        for i in 0..QUEUE_SIZE {
            self.rx.post(&self.dma, i, BUFFER_SIZE as u32);
        }
        self.rx.publish(&self.dma);
        self.tx.set_interrupts(&self.dma, false);
        // 9: no notify before DRIVER_OK (3.1.1).
        self.set_status(status::DRIVER_OK);
        self.kick(RX);
        Ok(())
    }

    /// Step 6 for queue `q`: its size, its vector, its rings' addresses,
    /// its notify offset, and enable.
    fn setup_queue(&mut self, q: u16, start: &Start) -> Result<(), Refused> {
        let c = &self.regions.common;
        c.write16(common::QUEUE_SELECT, q);
        let size = c.read16(common::QUEUE_SIZE);
        if size < QUEUE_SIZE {
            return Err(Refused::SmallQueue { queue: q, size });
        }
        c.write16(common::QUEUE_SIZE, QUEUE_SIZE);
        c.write16(common::QUEUE_MSIX_VECTOR, 0);
        let read = c.read16(common::QUEUE_MSIX_VECTOR);
        if read != 0 {
            return Err(Refused::VectorRefused { queue: q, read });
        }
        let vq = if q == RX { &mut self.rx } else { &mut self.tx };
        let flags = if q == RX { DESC_F_WRITE } else { 0 };
        vq.init(&self.dma, start.dma, flags);
        let regs = [
            common::QUEUE_DESC,
            common::QUEUE_DRIVER,
            common::QUEUE_DEVICE,
        ];
        for (reg, part) in regs.into_iter().zip(vq.parts()) {
            let addr = start.dma + part as u64;
            c.write32(reg, addr as u32);
            c.write32(reg + 4, (addr >> 32) as u32);
        }
        let notify_off = c.read16(common::QUEUE_NOTIFY_OFF);
        let at = usize::from(notify_off) * start.multiplier as usize;
        let len = self.regions.notify.len();
        if at.checked_add(2).is_none_or(|end| end > len) {
            return Err(Refused::NotifyOutside {
                queue: q,
                notify_off,
                multiplier: start.multiplier,
                len,
            });
        }
        vq.set_notify(at);
        c.write16(common::QUEUE_ENABLE, 1);
        Ok(())
    }

    /// Step 7: the MAC and, with `STATUS`, the link, between two equal
    /// reads of `config_generation` (2.5.1's loop), at most
    /// [`GENERATION_TRIES`] times.
    fn read_config(&mut self) -> Result<(), Refused> {
        let (c, d) = (&self.regions.common, &self.regions.device);
        for _ in 0..GENERATION_TRIES {
            let before = c.read8(common::CONFIG_GENERATION);
            let mut mac = [0; 6];
            for (i, b) in mac.iter_mut().enumerate() {
                *b = d.read8(net::MAC + i);
            }
            let link = if self.features & virtio_feature::STATUS != 0 {
                d.read16(net::STATUS)
            } else {
                // Without STATUS the link is up (5.1.4.2).
                net::LINK_UP
            };
            if c.read8(common::CONFIG_GENERATION) != before {
                continue;
            }
            let mac = Mac(mac);
            if !mac.is_unicast() {
                return Err(Refused::BadMac(mac));
            }
            self.mac = mac;
            self.link_up = link & net::LINK_UP != 0;
            return Ok(());
        }
        Err(Refused::ConfigUnstable)
    }

    /// Notifies queue `q` of what [`Virtq::publish`] showed it, unless the
    /// device asked for no notifications: a 16-bit write of the queue's
    /// index at its notify offset, which setup checked lies inside the
    /// region.
    fn kick(&self, q: u16) {
        let vq = if q == RX { &self.rx } else { &self.tx };
        if vq.wants_notify(&self.dma) {
            self.regions.notify.write16(vq.notify(), q);
        }
    }

    /// One signal's work, `IRQ` or `FRAMES` or both, since one MSI-X vector
    /// serves both queues and a notification merges its signals: takes
    /// back `RX_FREE`'s buffers, drains the receive queue's used ring into
    /// `RX_FILLED`, reclaims transmit descriptors, and copies `TX_FILLED`'s
    /// frames to the device. Whether to signal `net` now
    /// ([`frames::Driver::end_batch`]).
    pub fn on_signal<Q: Memory>(&mut self, queues: &mut frames::Driver<Q>) -> bool {
        self.counters.signals += 1;
        queues.reclaim();
        self.receive(queues);
        self.transmit(queues);
        queues.end_batch()
    }

    /// Each used receive element the driver posted, with a length of 12 +
    /// 14 to 12 + 1,514, is copied without its header into a free buffer
    /// and pushed on `RX_FILLED`, or dropped when none is free; any other
    /// is counted as bad. Every descriptor goes back on the available ring
    /// at once, and one notify follows the batch.
    fn receive<Q: Memory>(&mut self, queues: &mut frames::Driver<Q>) {
        self.rx.poll(&self.dma, &mut self.counters.bad_used);
        while let Some(u) = self.rx.take(&self.dma, &mut self.counters.bad_used) {
            let len = u.len as usize;
            if (HEADER + MIN_FRAME..=HEADER + MAX_FRAME).contains(&len) {
                let n = len - HEADER;
                let at = layout::buffer(RX, u.id) + HEADER;
                let dma = &self.dma;
                match queues.deliver_with(n, |buf| mem::copy(dma, at, buf, 0, n)) {
                    Ok(()) => self.counters.received += 1,
                    Err(PushError::NoBuffer) => self.counters.dropped += 1,
                    // A queue a broken `net` left full: counted in the
                    // queues' bad entries.
                    Err(_) => {}
                }
            } else {
                self.counters.bad_used += 1;
            }
            self.rx.post(&self.dma, u.id, BUFFER_SIZE as u32);
        }
        if self.rx.publish(&self.dma) {
            self.kick(RX);
        }
    }

    /// Takes back the transmit descriptors the device has used; how many.
    fn reclaim_tx(&mut self) -> usize {
        self.tx.poll(&self.dma, &mut self.counters.bad_used);
        let mut n = 0;
        while self
            .tx
            .take(&self.dma, &mut self.counters.bad_used)
            .is_some()
        {
            n += 1;
        }
        n
    }

    /// Copies each `TX_FILLED` frame, behind a zeroed header, into a free
    /// transmit descriptor's buffer, handing the queue's buffer back on
    /// `TX_FREE` at once. With no descriptor free the frame stays in
    /// `TX_FILLED` and transmit completions are turned on, then the used
    /// ring is read again (2.7.14's re-check), so that a completion that
    /// came first is not missed; once nothing waits they are off again.
    fn transmit<Q: Memory>(&mut self, queues: &mut frames::Driver<Q>) {
        self.reclaim_tx();
        while queues.peek_tx().is_some() {
            let Some(id) = self.tx.free() else {
                if !self.waiting {
                    self.waiting = true;
                    self.counters.waits += 1;
                    self.tx.set_interrupts(&self.dma, true);
                    if self.reclaim_tx() > 0 {
                        continue;
                    }
                }
                break;
            };
            let at = layout::buffer(TX, id);
            let dma = &self.dma;
            let sent = queues.take_tx_with(|frame| {
                dma.fill(at, HEADER, 0);
                mem::copy(frame, 0, dma, at + HEADER, frame.len());
                frame.len()
            });
            let Some(n) = sent else { break };
            self.tx.post(&self.dma, id, (HEADER + n) as u32);
            self.counters.sent += 1;
        }
        if self.waiting && queues.peek_tx().is_none() {
            self.waiting = false;
            self.tx.set_interrupts(&self.dma, false);
        }
        if self.tx.publish(&self.dma) {
            self.kick(TX);
        }
    }

    /// The answer to root's `Stats`; `queues` gives the bad entries.
    pub fn stats<Q: Memory>(&self, queues: &frames::Driver<Q>) -> VirtioNetStats {
        let c = self.counters;
        VirtioNetStats {
            signals: c.signals,
            received: c.received,
            dropped: c.dropped,
            bad_used: c.bad_used,
            sent: c.sent,
            waits: c.waits,
            bad_entries: queues.counters().bad,
            features: self.features,
            mac: self.mac.to_word(),
        }
    }

    /// The line it prints once up.
    pub fn up(&self) -> Up {
        Up {
            mac: self.mac,
            features: self.features,
            link_up: self.link_up,
            sizes: [QUEUE_SIZE; 2],
        }
    }

    pub fn counters(&self) -> Counters {
        self.counters
    }

    pub fn features(&self) -> u64 {
        self.features
    }

    pub fn mac(&self) -> Mac {
        self.mac
    }

    pub fn link_up(&self) -> bool {
        self.link_up
    }

    /// Whether a frame waits for a transmit descriptor, so transmit
    /// completions are on.
    pub fn waiting(&self) -> bool {
        self.waiting
    }

    /// The receive queue and the transmit queue.
    pub fn queues(&self) -> [&Virtq; 2] {
        [&self.rx, &self.tx]
    }

    pub fn regions(&self) -> &Regions<R> {
        &self.regions
    }

    pub fn dma(&self) -> &M {
        &self.dma
    }
}
