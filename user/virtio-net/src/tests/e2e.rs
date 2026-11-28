//! The done-when on the host (`docs/design.md`, "`virtio-net`", "Tests"):
//! the model device ([`super::device`]), `virtio_net::Driver` and
//! `net::link` sharing the frame queues' frame (one `Ram` both sides see,
//! as the driver's and `net`'s VSpaces share it), and behind the device
//! the end-to-end tests' scripted peer, libslirp's part: it answers ARP
//! and pings for the gateway, pings the guest four times, then sends the
//! harness's 100 `udp_echo:` datagrams, window 8, each of which must come
//! back once, unaltered and in order, with the stats `root::check::net`
//! requires.
//!
//! - [`a_hundred_datagrams_echo_through_the_model`] steps the threads as
//!   the scheduler runs them: the driver (140) whenever its notification
//!   holds a signal, then `net` (130), and the device and the network
//!   when both wait.
//! - [`random_interleavings_through_net_lose_nothing`] steps them in any
//!   order (`net` before a signalled driver, signals merged and late, the
//!   device delivering and completing late and out of order, or so rarely
//!   that the transmit ring fills, polling instead of notifications, up to
//!   three flows and windows up to 100), and at random accesses lets the
//!   device act inside the driver's `on_signal`, as it does on its own
//!   processor, and the driver preempt `net` inside its pump, as its
//!   priority makes it, on a stale wake too: nothing is lost, duplicated or
//!   reordered within a flow, every queue buffer has one owner after every
//!   turn, the stats are clean, and the run never stalls.
//!   [`preempted_at_every_access_loses_nothing`] is one such run with a
//!   preemption at every access.
//! - [`completions_just_before_the_driver_asks_for_them_are_not_lost`]:
//!   the device uses every transmit buffer just before the driver turns
//!   completions on, which only the driver's second look at the used ring
//!   (virtio 1.2, 2.7.14) catches.

use core::cell::{Cell, RefCell};
use std::collections::VecDeque;
use std::rc::Rc;
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, vec};

use libsys::frames::{self, Pool};
use libsys::mem::Ram;
use libsys::proto::{VirtioNetStats, virtio_feature};
use net::link::{self, Report, Up};
use net::{Config, Stack, echo};
use proptest::prelude::*;

use super::device::{Config as DeviceConfig, Device, Port};
use super::{BASE, MAC, Mem, args};
use crate::{Driver, layout};

// The peer, the preemption points and the owners' check are net's, shared
// by the three crates' end-to-end tests; each uses part of them.
#[allow(dead_code)]
#[path = "../../../net/src/tests/owners.rs"]
mod owners;
#[allow(dead_code)]
#[path = "../../../net/src/tests/peer.rs"]
mod peer;
#[allow(dead_code)]
#[path = "../../../net/src/tests/preempt.rs"]
mod preempt;

use owners::owned_once;
use peer::{Peer, Spec};
use preempt::{Access, Hook, Preempt, Rng};

/// The DMA frame as the driver reaches it: through preemption points at
/// which the device may act.
type Dma<'a> = Preempt<'a, &'a Ram>;

/// The driver's thread, which its notification NV wakes: the device's
/// MSI-X messages (`IRQ`) or `net`'s `FRAMES`.
struct DriverThread<'a> {
    driver: Driver<Port<'a>, Dma<'a>>,
    queues: frames::Driver<&'a Ram>,
    /// NV's `FRAMES` bit.
    frames: bool,
    /// NN's: it signalled `net`.
    to_net: bool,
}

/// `net`'s thread, which NN wakes.
struct NetThread<'a> {
    queues: frames::Net<Preempt<'a, &'a Ram>>,
    config: Config,
    stack: Option<Stack>,
    lines: Vec<String>,
}

impl NetThread<'_> {
    /// One wake: `net::run`'s start at the first, then a pump. Whether to
    /// signal the driver.
    fn run(&mut self) -> bool {
        let signal = match &mut self.stack {
            None => {
                let s = link::start(self.config, &mut self.queues).expect("the link block");
                self.lines.push(Up(self.config, s.mac()).to_string());
                self.lines.push(echo::LISTENING.to_string());
                self.stack = Some(s);
                self.queues.end_batch()
            }
            Some(s) => link::pump(s, &mut self.queues),
        };
        if let Some(s) = &mut self.stack {
            while let Some(e) = s.event() {
                self.lines.push(e.to_string());
            }
        }
        signal
    }

    fn report(&self) -> Report {
        Report {
            stack: *self.stack.as_ref().expect("net is up").stats(),
            queues: self.queues.counters(),
        }
    }
}

/// The device's other side: the network.
struct Network {
    peer: Peer,
    /// Frames on their way to the device, which takes one only into a
    /// posted receive buffer: QEMU queues a frame while the guest has
    /// posted none (from memory), where the model would lose it.
    to_device: VecDeque<Vec<u8>>,
}

/// What the device and the network may do in a turn.
#[derive(Clone, Copy, Debug)]
enum DevOp {
    /// Write the next frame into held receive buffer `pick`.
    Deliver(usize),
    /// Take the transmit buffers made available, and send their frames.
    Send,
    /// Use held transmit buffer `pick`.
    Complete(usize),
    /// Use every held transmit buffer at once: a device that works in
    /// batches, so that no later completion is left to interrupt.
    CompleteAll,
    /// The peer sends what it may.
    Peer,
    /// Start or stop polling queue `q` (`VIRTQ_USED_F_NO_NOTIFY`).
    Poll(u16, bool),
}

impl DevOp {
    /// A random op; a `lazy` device completes rarely, so that the
    /// transmit ring fills and the driver waits for completions.
    fn random(rng: &mut Rng, lazy: bool) -> DevOp {
        match rng.below(16) {
            0..=4 => DevOp::Deliver(rng.below(64) as usize),
            5..=8 => DevOp::Send,
            9..=11 if lazy && !rng.chance(30) => DevOp::Send,
            9..=10 => DevOp::Complete(rng.below(64) as usize),
            11 => DevOp::CompleteAll,
            12..=14 => DevOp::Peer,
            _ => DevOp::Poll(rng.below(2) as u16, rng.chance(300)),
        }
    }
}

/// The device, its network, and the two threads.
struct World<'a> {
    dev: &'a Device<'a>,
    queues: &'a Ram,
    net: NetThread<'a>,
    driver: Rc<RefCell<DriverThread<'a>>>,
    network: Rc<RefCell<Network>>,
    lines: Vec<String>,
}

/// Does `op`; whether anything happened.
fn device(dev: &Device<'_>, network: &RefCell<Network>, op: DevOp) -> bool {
    let mut n = network.borrow_mut();
    match op {
        DevOp::Deliver(pick) => {
            if n.to_device.is_empty() {
                return false;
            }
            dev.fetch(0);
            if dev.held(0).is_empty() {
                return false;
            }
            let f = n.to_device.pop_front().unwrap();
            assert!(dev.receive_at(&f, pick));
            true
        }
        DevOp::Send => {
            let sent = dev.fetch_tx();
            for f in &sent {
                let answers = n.peer.input(f);
                n.to_device.extend(answers);
            }
            !sent.is_empty()
        }
        DevOp::Complete(pick) => dev.complete_tx(pick),
        DevOp::CompleteAll => {
            let mut did = false;
            while dev.complete_tx(0) {
                did = true;
            }
            did
        }
        DevOp::Peer => {
            let frames = n.peer.poll();
            let did = !frames.is_empty();
            n.to_device.extend(frames);
            did
        }
        DevOp::Poll(q, on) => {
            dev.set_no_notify(q, on);
            false
        }
    }
}

impl DriverThread<'_> {
    fn ready(&self, dev: &Device<'_>) -> bool {
        self.frames || dev.interrupts()[0] > 0
    }

    /// One wake: the interrupts and `FRAMES` merged into one signal.
    fn run(&mut self, dev: &Device<'_>) {
        dev.take_interrupts();
        self.frames = false;
        self.to_net |= self.driver.on_signal(&mut self.queues);
    }
}

/// The hooks a world's windows go through, and how often each fires.
struct Hooks<'a> {
    /// In the DMA frame: the device acts inside the driver.
    dma: Rc<Hook<'a>>,
    /// In `net`'s copy of the queues: the driver preempts `net`.
    net: Rc<Hook<'a>>,
}

impl Hooks<'_> {
    fn new() -> Self {
        Hooks {
            dma: Rc::new(Hook::new()),
            net: Rc::new(Hook::new()),
        }
    }
}

impl<'a> World<'a> {
    /// The driver started on `dev` (`Driver::start`, its up line, and its
    /// signal to `net`), `net` not yet run.
    fn new(dev: &'a Device<'a>, mem: &'a Mem, hooks: &Hooks<'a>, spec: Spec) -> World<'a> {
        let config = Config::parse(&spec.cmdline(), Some(Config::QEMU)).unwrap();
        let mut queues = frames::Driver::new(&mem.queues);
        let driver = Driver::start(
            &args(),
            dev.regions(),
            Preempt::new(&mem.dma, hooks.dma.clone()),
            &mut queues,
        )
        .unwrap_or_else(|e| panic!("refused: {e}"));
        let lines = vec![driver.up().to_string()];
        let to_net = queues.end_batch();
        assert!(to_net, "the driver's start signals net");
        World {
            dev,
            queues: &mem.queues,
            net: NetThread {
                queues: frames::Net::new(Preempt::new(&mem.queues, hooks.net.clone())),
                config,
                stack: None,
                lines: Vec::new(),
            },
            driver: Rc::new(RefCell::new(DriverThread {
                driver,
                queues,
                frames: false,
                to_net,
            })),
            network: Rc::new(RefCell::new(Network {
                peer: Peer::new(spec),
                to_device: VecDeque::new(),
            })),
            lines,
        }
    }

    /// Lets the device act inside the driver, and the driver preempt
    /// `net`, each at an access with a chance of `rates` per mille, until
    /// `rates` are set to 0.
    fn preempt(
        &self,
        hooks: &Hooks<'a>,
        rates: Rc<Cell<(u32, u32)>>,
        rng: Rc<RefCell<Rng>>,
        lazy: bool,
    ) {
        let (dev, network) = (self.dev, self.network.clone());
        let (r, g) = (rates.clone(), rng.clone());
        hooks.dma.set(move |_| {
            let mut rng = g.borrow_mut();
            if rng.chance(r.get().0) {
                let op = DevOp::random(&mut rng, lazy);
                drop(rng);
                device(dev, &network, op);
            }
        });
        let (dev, driver) = (self.dev, self.driver.clone());
        // The driver runs whether or not its notification holds a bit: a
        // wake may be stale, an MSI-X message for a used element an earlier
        // run already took.
        hooks.net.set(move |_| {
            if rng.borrow_mut().chance(rates.get().1) {
                driver.borrow_mut().run(dev);
            }
        });
    }

    fn driver_ready(&self) -> bool {
        self.driver.borrow().ready(self.dev)
    }

    fn net_ready(&self) -> bool {
        self.driver.borrow().to_net
    }

    fn run_driver(&mut self) {
        self.driver.borrow_mut().run(self.dev);
    }

    fn run_net(&mut self) {
        self.driver.borrow_mut().to_net = false;
        let signal = self.net.run();
        self.driver.borrow_mut().frames |= signal;
        self.lines.append(&mut self.net.lines);
    }

    /// The device and the network when both threads wait: everything sent
    /// goes out and is completed, the peer sends what it may, and every
    /// frame on the way is delivered while the device holds buffers.
    fn device_eagerly(&mut self) -> bool {
        let mut did = device(self.dev, &self.network, DevOp::Send);
        while device(self.dev, &self.network, DevOp::Complete(0)) {
            did = true;
        }
        did |= device(self.dev, &self.network, DevOp::Peer);
        while device(self.dev, &self.network, DevOp::Deliver(0)) {
            did = true;
        }
        did
    }

    /// One turn by priority: the driver if signalled, else `net` if
    /// signalled, else the device. Whether anything happened.
    fn turn(&mut self) -> bool {
        if self.driver_ready() {
            self.run_driver();
            true
        } else if self.net_ready() {
            self.run_net();
            true
        } else {
            self.device_eagerly()
        }
    }

    /// Turns by priority until nothing happens.
    fn settle(&mut self) {
        for _ in 0..100_000 {
            if !self.turn() {
                return;
            }
        }
        panic!("the world never settles");
    }

    /// Every queue buffer has one owner.
    fn owners(&self) {
        let d = self.driver.borrow();
        let n = &self.net.queues;
        owned_once(
            self.queues,
            [d.queues.owned(Pool::Rx), d.queues.owned(Pool::Tx)],
            [n.owned(Pool::Rx), n.owned(Pool::Tx)],
        );
    }

    fn stats(&self) -> VirtioNetStats {
        let d = self.driver.borrow();
        d.driver.stats(&d.queues)
    }
}

/// What `root::check::net` requires of the counters once the harness's
/// datagrams are echoed (`docs/design.md`, "Network scenarios"): no bad
/// queue entry or used element, no IP or UDP checksum error, no frame
/// dropped for want of a buffer on either side, and every datagram
/// echoed; and here, with the peer's own count, every frame in and out
/// accounted for.
fn check_net(v: &VirtioNetStats, r: &Report, peer: &Peer, count: u32) {
    let s = &r.stack;
    assert_eq!(
        (v.bad_used, v.bad_entries, r.queues.bad),
        (0, 0, 0),
        "{v:?} {r:?}"
    );
    assert_eq!((s.ip_checksum, s.udp_checksum, s.icmp_checksum), (0, 0, 0));
    assert_eq!((v.dropped, r.queues.dropped, s.tx_full), (0, 0, 0));
    assert_eq!(s.udp_echoed, u64::from(count), "{r}");
    assert_eq!(s.dropped(), 0, "every frame handled: {r}");
    assert_eq!(
        (s.held_replaced, s.held_full, s.held_evicted),
        (0, 0, 0),
        "{r}"
    );
    // Every frame the peer sent reached the stack, and every frame the
    // stack sent reached the peer, through the driver both ways.
    let p = peer.counts;
    assert_eq!(
        (v.received, r.queues.received, s.frames_in),
        (p.to_guest, p.to_guest, p.to_guest)
    );
    assert_eq!(
        (v.sent, r.queues.sent, s.frames_out),
        (p.from_guest, p.from_guest, p.from_guest)
    );
    assert_eq!(s.icmp_answered, peer.spec.pings.len() as u64);
    assert_eq!(p.ping_replies, peer.spec.pings.len() as u64);
    assert_eq!((s.ping_sent, s.icmp_replies), (1, 1));
}

/// The datagrams: the scenario's 100, fewer under Miri.
const COUNT: u32 = if cfg!(miri) { 13 } else { 100 };

#[test]
fn a_hundred_datagrams_echo_through_the_model() {
    let mem = Mem::new();
    let dev = Device::new(&mem.dma, BASE, DeviceConfig::qemu());
    let hooks = Hooks::new();
    let mut w = World::new(&dev, &mem, &hooks, Spec::qemu(COUNT));
    w.settle();
    // The scenario's lines up to its `udp_echo: 100`.
    assert_eq!(
        w.lines,
        [
            "virtio-net: up: MAC 52:54:00:12:34:56, features VERSION_1 MAC STATUS, link up, queues 64 and 64",
            "net: up: 10.0.2.15/24 via 10.0.2.2, MAC 52:54:00:12:34:56",
            "echo: listening on UDP port 7",
            "net: gateway 10.0.2.2 is at 52:55:0a:00:02:02",
            "net: ping 10.0.2.2: reply 1, 56 bytes",
        ]
    );
    w.network.borrow_mut().peer.begin();
    w.settle();
    let network = w.network.borrow();
    let peer = &network.peer;
    assert!(peer.done(), "missing {:?}", peer.missing());
    let (v, r) = (w.stats(), w.net.report());
    check_net(&v, &r, peer, COUNT);
    assert_eq!(dev.no_buffer(), 0);
    assert_eq!(
        v.features,
        virtio_feature::VERSION_1 | virtio_feature::MAC | virtio_feature::STATUS
    );
    assert_eq!(v.mac(), MAC);
    // The ARP exchange: the stack's request for the gateway answered, no
    // other.
    let s = &r.stack;
    assert_eq!((s.arp_sent, s.arp_learnt, s.arp_answered), (1, 1, 0));
    assert_eq!(peer.counts.arp_asked, 0);
    // The scenario's lines after the `\r`.
    let line = format!("net: stats: {r}");
    let want = format!(", {COUNT} datagrams echoed,");
    assert!(line.contains(&want), "{line}");
    assert!(line.contains(", 4 ICMP echo requests answered,"), "{line}");
    assert!(
        line.contains(", 0 frames dropped, 0 bad entries,"),
        "{line}"
    );
    let driver = format!("virtio-net: stats: {v}");
    assert!(
        driver.contains(", 0 dropped for no buffer, 0 bad used elements,")
            && driver.contains(
                ", 0 bad queue entries, features VERSION_1 MAC STATUS, MAC 52:54:00:12:34:56"
            ),
        "{driver}"
    );
    w.owners();
    // Every receive descriptor is back with the device.
    dev.fetch(0);
    assert_eq!(dev.held(0).len(), 64);
    assert!(dev.held(1).is_empty());
}

/// The transmit ring full, the device sends every frame and uses every
/// buffer just before the driver turns completions on, so none of them
/// interrupts: the driver must look at the used ring again after asking
/// (virtio 1.2, 2.7.14), or the last echo waits in `TX_FILLED` for good.
/// The device uses no transmit buffer of its own accord before then: the
/// four ping replies hold four descriptors, the first 60 echoes the other
/// 60, all of them published; the 61st datagram's echo finds none free,
/// in a pass that posts nothing, so no later completion would interrupt,
/// and the peer, waiting for that echo, sends nothing more.
#[test]
fn completions_just_before_the_driver_asks_for_them_are_not_lost() {
    let mem = Mem::new();
    let dev = Device::new(&mem.dma, BASE, DeviceConfig::qemu());
    let hooks = Hooks::new();
    let count = 61;
    let mut spec = Spec::qemu(count);
    spec.window = 60;
    let mut w = World::new(&dev, &mem, &hooks, spec);
    w.settle();
    let fired = Rc::new(Cell::new(false));
    {
        let (dev, network, fired) = (w.dev, w.network.clone(), fired.clone());
        let flags = layout::ring(1) + layout::AVAIL;
        hooks.dma.set(move |at| {
            if at.offset == flags && at.access == Access::Store(0) && !fired.get() {
                fired.set(true);
                device(dev, &network, DevOp::Send);
                device(dev, &network, DevOp::CompleteAll);
            }
        });
    }
    w.network.borrow_mut().peer.begin();
    // By priority, with a device that uses no transmit buffer of its own
    // accord until the hook has.
    for _ in 0..100_000 {
        if w.driver_ready() {
            w.run_driver();
        } else if w.net_ready() {
            w.run_net();
        } else {
            let mut did = device(w.dev, &w.network, DevOp::Send);
            did |= device(w.dev, &w.network, DevOp::Peer);
            while device(w.dev, &w.network, DevOp::Deliver(0)) {
                did = true;
            }
            if fired.get() {
                did |= device(w.dev, &w.network, DevOp::CompleteAll);
            }
            if !did {
                break;
            }
        }
    }
    assert!(fired.get(), "the transmit ring never filled");
    let network = w.network.borrow();
    let peer = &network.peer;
    assert!(
        peer.done(),
        "stalled: {} echoes missing, {:?}",
        peer.missing().len(),
        w.stats()
    );
    let v = w.stats();
    assert!(v.waits >= 1, "{v:?}");
    check_net(&v, &w.net.report(), peer, count);
}

/// One random run's knobs.
#[derive(Clone, Copy, Debug)]
struct Run {
    seed: u64,
    /// Random turns at most, before the run goes on by priority.
    turns: usize,
    /// The chance, per mille, that a turn goes by priority.
    prio: u32,
    /// Preemption rates per mille: the device inside the driver, the
    /// driver inside `net`.
    rates: (u32, u32),
    /// A device that completes transmit buffers rarely.
    lazy: bool,
    /// The peer's flows, its window and its datagrams.
    ports: usize,
    window: u32,
    count: u32,
}

/// One random run: turns in any order until every datagram is answered
/// or `turns` run out, with preemption at `rates` and a turn by priority
/// at a chance of `prio`; then turns by priority, without preemption,
/// until everything is answered, which must not stall.
fn interleaved(run: Run) {
    let mem = Mem::new();
    let dev = Device::new(&mem.dma, BASE, DeviceConfig::qemu());
    let hooks = Hooks::new();
    let mut spec = Spec::qemu(run.count);
    spec.ports = (0..run.ports as u16).map(|i| 40_000 + 11 * i).collect();
    spec.window = run.window;
    let mut w = World::new(&dev, &mem, &hooks, spec);
    let rng = Rc::new(RefCell::new(Rng::new(run.seed)));
    let rate = Rc::new(Cell::new(run.rates));
    w.preempt(&hooks, rate.clone(), rng.clone(), run.lazy);
    for _ in 0..run.turns {
        // The peer begins once net is up, as the harness waits for its
        // lines; it may then come before the gateway's reply.
        if w.net.stack.is_some() {
            w.network.borrow_mut().peer.begin();
        }
        if w.network.borrow().peer.done() {
            break;
        }
        let (by_priority, pick) = {
            let mut r = rng.borrow_mut();
            (r.chance(run.prio), r.below(4))
        };
        if by_priority {
            w.turn();
        } else {
            match pick {
                0 if w.driver_ready() => w.run_driver(),
                1 if w.net_ready() => w.run_net(),
                _ => {
                    let op = DevOp::random(&mut rng.borrow_mut(), run.lazy);
                    device(w.dev, &w.network, op);
                }
            }
        }
        w.owners();
        let v = w.stats();
        assert_eq!((v.bad_used, v.bad_entries, v.dropped), (0, 0, 0), "{v:?}");
    }
    // The device stops polling, which looks at both rings once more, and
    // nothing preempts any more.
    rate.set((0, 0));
    dev.set_no_notify(0, false);
    dev.set_no_notify(1, false);
    w.network.borrow_mut().peer.begin();
    w.settle();
    w.owners();
    let network = w.network.borrow();
    let peer = &network.peer;
    assert!(
        peer.done(),
        "stalled: missing {:?}; {:?}; lines {:?}",
        peer.missing(),
        w.stats(),
        w.lines
    );
    check_net(&w.stats(), &w.net.report(), peer, run.count);
    let l = &w.lines;
    assert_eq!(l.len(), 5, "{l:?}");
    assert!(
        l[3].starts_with("net: gateway ") && l[4].starts_with("net: ping "),
        "{l:?}"
    );
}

/// At every access the device acts, and the driver preempts `net`
/// whenever it holds a signal; a window of 100 fills the transmit ring.
#[test]
fn preempted_at_every_access_loses_nothing() {
    for window in [8, 100] {
        interleaved(Run {
            seed: 7,
            turns: 1_000_000,
            prio: 0,
            rates: (1000, 1000),
            lazy: window > 64,
            ports: 2,
            window,
            count: if cfg!(miri) { 4 } else { 200 },
        });
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 128 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_interleavings_through_net_lose_nothing(
        seed in any::<u64>(),
        turns in prop_oneof![0usize..200, Just(1_000_000)],
        prio in prop_oneof![Just(0u32), 0u32..1000, Just(1000u32)],
        dev_rate in prop_oneof![Just(0u32), 1u32..100, Just(1000u32)],
        drv_rate in prop_oneof![Just(0u32), 1u32..100, Just(1000u32)],
        ports in 1usize..=3,
        window in prop_oneof![Just(8u32), 1u32..=100, Just(100u32)],
        lazy in any::<bool>(),
    ) {
        interleaved(Run {
            seed,
            turns: if cfg!(miri) { turns.min(300) } else { turns },
            prio,
            rates: (dev_rate, drv_rate),
            lazy,
            ports,
            window,
            count: if cfg!(miri) { 6 } else { 120 },
        });
    }
}
