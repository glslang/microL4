//! The Hyper-V done-when on the host (`docs/design.md`, "The mock VMBus
//! host": `a_hundred_datagrams_echo_through_the_mock_host`): `hvmock`'s
//! host with its netvsc device, `vmbus::Bus`, `netvsc::Adapter` and
//! `net::link` sharing the frame queues' frame, and behind the host the
//! end-to-end tests' scripted peer as the M9 Hyper-V check's host: the
//! switch's `192.168.77.1`, which answers ARP and the stack's ping, pings
//! the guest four times as `Send-L4Udp.ps1` does, then sends the
//! harness's 100 datagrams, window 8; every echo must come back once,
//! unaltered and in order, with the stats `root::check::net` requires.
//! Both with `SignalEvent` and with `netvsc.mnf=1`'s monitor page.
//!
//! - The `a_hundred_datagrams_*` tests step the threads as the scheduler
//!   runs them: vmbus (145) when SINT 2 has an edge, netvsc (140) when its
//!   notification holds `CHANNEL` or `FRAMES`, net (130) at its `FRAMES`,
//!   and the host and the peer when all three wait.
//! - [`random_interleavings_through_the_mock_host_lose_nothing`] steps
//!   them in any order, with the host holding send completions and giving
//!   them back in any order, reading the outbound ring late, packing
//!   several frames a packet with per-packet information, offering as few
//!   as 8 send sections, both ways of signalling, up to three flows and
//!   windows up to 100, and at random accesses lets the host act inside
//!   netvsc (on its own processor) and vmbus and netvsc preempt net (by
//!   priority, on a stale wake too): nothing is lost, duplicated or
//!   reordered within a flow, every queue buffer has one owner after every
//!   turn, every receive-buffer packet is acknowledged, the stats are
//!   clean, and the run never stalls. [`preempted_at_every_access_loses_nothing`]
//!   is one such run with a preemption at every access, both ways of
//!   signalling.
//! - [`a_host_that_drains_the_ring_before_the_request_for_room_still_hears_netvsc`]:
//!   the outbound ring full of acknowledgements, the host reads all of it
//!   after netvsc found no room and before netvsc's request for room
//!   reaches it, so it never signals for that room; netvsc must find it.

use core::cell::{Cell, RefCell};
use std::boxed::Box;
use std::rc::Rc;
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, vec};

use hvmock::netvsc::{self as nic, Netvsc};
use hvmock::{Host, Machine, Page, Restriction, machine};
use libsys::frames::{self, Driver, Pool};
use libsys::mem::Ram;
use libsys::proto::NetvscStats;
use net::link::{self, Report, Up};
use net::{Config, Stack, echo};
use proptest::prelude::*;

use super::{NETVSC, channel, queues, vmbus_start};
use crate::{Adapter, CHANNEL, FRAMES, Signal, Start, Status, Step, layout, ring};

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

/// netvsc's windows, the channel frame and the monitor pages, through
/// preemption points at which the host may act.
type Window<'m> = Preempt<'m, Page<'m>>;

/// vmbus's hypercalls on the shared host.
struct Hyp<'a, 'm>(&'a RefCell<Host<'m>>);

impl vmbus::Hypervisor for Hyp<'_, '_> {
    fn post_message(&mut self, connection: u32, message_type: u32, payload: &[u8]) -> Status {
        self.0
            .borrow_mut()
            .post_message(connection, message_type, payload)
    }
    fn signal_event(&mut self, connection: u32, flag: u16) -> Status {
        self.0.borrow_mut().signal_event(connection, flag)
    }
    fn eom(&mut self) {
        self.0.borrow_mut().eom()
    }
    fn vp_index(&mut self) -> u32 {
        self.0.borrow().vp_index()
    }
}

/// What vmbus does to the rest of the system: its lines, its signal to
/// netvsc and its Mint.
#[derive(Default)]
struct Sys {
    lines: Vec<String>,
    netvsc: bool,
    mints: Vec<u64>,
}

impl vmbus::System for Sys {
    fn say(&mut self, note: &vmbus::Note) {
        self.lines.push(note.to_string());
    }
    fn signal_netvsc(&mut self) {
        self.netvsc = true;
    }
    fn mint(&mut self, data: u64) {
        self.mints.push(data);
    }
    fn revoke(&mut self) {
        panic!("vmbus revoked netvsc's capability");
    }
    fn back_off(&mut self, _ms: u32) {}
}

/// netvsc's restricted capability on the shared host, which fails a test
/// that signals another connection.
struct Cap<'a, 'm> {
    host: &'a RefCell<Host<'m>>,
    cap: Restriction,
}

impl Signal for Cap<'_, '_> {
    fn signal_event(&mut self, connection: u32) -> Status {
        self.host
            .borrow_mut()
            .signal_restricted(self.cap, connection, 0)
    }
}

/// vmbus's thread, which SINT 2's edge wakes.
struct VmbusThread<'m> {
    bus: vmbus::Bus<Page<'m>>,
    sys: Sys,
}

/// netvsc's thread, which NH wakes with `CHANNEL` or `FRAMES`.
struct NetvscThread<'m> {
    a: Adapter<Window<'m>, &'m Ram>,
    cap: Restriction,
    /// NH's bits, which vmbus sets too.
    bits: Rc<Cell<u64>>,
    /// NN's: it signalled net.
    to_net: bool,
    lines: Vec<String>,
}

impl NetvscThread<'_> {
    fn run(&mut self, host: &RefCell<Host<'_>>) {
        let bits = self.bits.replace(0);
        let r = self.a.on_signal(
            bits,
            &mut Cap {
                host,
                cap: self.cap,
            },
        );
        match r {
            Ok(wake) => self.to_net |= wake,
            Err(f) => panic!("netvsc failed: {f}"),
        }
        while let Some(n) = self.a.note() {
            self.lines.push(n.to_string());
        }
    }
}

/// net's thread, which NN wakes.
struct NetThread<'m> {
    queues: frames::Net<Preempt<'m, &'m Ram>>,
    config: Config,
    stack: Option<Stack>,
    lines: Vec<String>,
}

impl NetThread<'_> {
    /// One wake: `net::run`'s start at the first, then a pump. Whether to
    /// signal netvsc.
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

/// The hooks: in netvsc's windows the host acts inside netvsc, in net's
/// copy of the queues netvsc preempts net.
struct Hooks<'m> {
    channel: Rc<Hook<'m>>,
    net: Rc<Hook<'m>>,
}

impl Hooks<'_> {
    fn new() -> Self {
        Hooks {
            channel: Rc::new(Hook::new()),
            net: Rc::new(Hook::new()),
        }
    }
}

/// How a world is made.
#[derive(Clone)]
struct Setup {
    spec: Spec,
    nic: nic::Config,
    mnf: bool,
}

impl Setup {
    fn new(count: u32, mnf: bool) -> Setup {
        Setup {
            spec: Spec::hyperv(count),
            nic: nic::Config::default(),
            mnf,
        }
    }
}

/// The machine, the host, the three threads and the peer.
struct World<'m> {
    m: &'m Machine,
    q: &'m Ram,
    host: Rc<RefCell<Host<'m>>>,
    nic: Netvsc,
    vmbus: Rc<RefCell<VmbusThread<'m>>>,
    /// NH's bits.
    bits: Rc<Cell<u64>>,
    netvsc: Rc<RefCell<NetvscThread<'m>>>,
    net: NetThread<'m>,
    peer: Peer,
}

impl<'m> World<'m> {
    /// vmbus opens netvsc's channel on the host as on Hyper-V, and
    /// answers netvsc's `Attach`; netvsc is made over its windows and
    /// started.
    fn new(m: &'m Machine, q: &'m Ram, hooks: &Hooks<'m>, s: Setup) -> World<'m> {
        let nic = Netvsc::new(s.nic);
        let mut host = Host::new(m, hvmock::Config::default());
        host.attach(NETVSC, Box::new(nic.clone()));
        let host = Rc::new(RefCell::new(host));
        let mut vmbus = VmbusThread {
            bus: vmbus::Bus::new(vmbus_start(), m.sim(), m.sief()),
            sys: Sys::default(),
        };
        vmbus.bus.start(&mut Hyp(&host), &mut vmbus.sys);
        for _ in 0..1000 {
            let mut did = false;
            if m.take_interrupt() {
                vmbus.bus.on_signal(&mut Hyp(&host), &mut vmbus.sys);
                did = true;
            }
            if !(did | host.borrow_mut().step()) {
                break;
            }
        }
        let attach = vmbus.bus.attached().expect("vmbus opened netvsc's channel");
        let cap = Restriction::from_data(vmbus.sys.mints[0]).expect("a restriction");
        vmbus.sys.netvsc = false;
        let start = Start {
            channel: machine::CHANNEL,
            mnf: s.mnf,
        };
        let mnf = s.mnf.then(|| {
            Preempt::new(
                m.window(machine::MONITOR + machine::PAGE, 2 * machine::PAGE),
                hooks.channel.clone(),
            )
        });
        let window = Preempt::new(channel(m), hooks.channel.clone());
        let config = Config::parse(&s.spec.cmdline(), None).expect("the command line");
        let a = Adapter::new(start, attach, window, mnf, Driver::new(q)).expect("an adapter");
        let bits = Rc::new(Cell::new(0));
        let mut netvsc = NetvscThread {
            a,
            cap,
            bits: bits.clone(),
            to_net: false,
            lines: Vec::new(),
        };
        netvsc
            .a
            .start(&mut Cap { host: &host, cap })
            .expect("netvsc starts");
        World {
            m,
            q,
            host,
            nic,
            vmbus: Rc::new(RefCell::new(vmbus)),
            bits,
            netvsc: Rc::new(RefCell::new(netvsc)),
            net: NetThread {
                queues: frames::Net::new(Preempt::new(q, hooks.net.clone())),
                config,
                stack: None,
                lines: Vec::new(),
            },
            peer: Peer::new(s.spec),
        }
    }

    fn vmbus_ready(&self) -> bool {
        self.m.interrupt_pending()
    }

    fn netvsc_ready(&self) -> bool {
        self.bits.get() != 0
    }

    fn net_ready(&self) -> bool {
        self.netvsc.borrow().to_net
    }

    fn run_vmbus(&mut self) {
        run_vmbus(self.m, &self.host, &self.vmbus, &self.bits);
    }

    fn run_netvsc(&mut self) {
        self.netvsc.borrow_mut().run(&self.host);
    }

    fn run_net(&mut self) {
        self.netvsc.borrow_mut().to_net = false;
        if self.net.run() {
            self.bits.set(self.bits.get() | FRAMES);
        }
    }

    /// The peer takes what the host has from the guest and gives the host
    /// its answers, then sends what it may. Whether anything moved.
    fn peer(&mut self) -> bool {
        let sent = self.nic.take_sent();
        let mut did = !sent.is_empty();
        for f in &sent {
            for a in self.peer.input(f) {
                self.nic.deliver(&a);
            }
        }
        for f in self.peer.poll() {
            self.nic.deliver(&f);
            did = true;
        }
        did
    }

    fn host_step(&mut self) -> bool {
        self.host.borrow_mut().step()
    }

    /// One turn by priority: vmbus, netvsc, net, else the host and the
    /// peer. Whether anything happened.
    fn turn(&mut self) -> bool {
        if self.vmbus_ready() {
            self.run_vmbus();
        } else if self.netvsc_ready() {
            self.run_netvsc();
        } else if self.net_ready() {
            self.run_net();
        } else {
            let did = self.host_step();
            return self.peer() | did;
        }
        true
    }

    fn settle(&mut self) {
        for _ in 0..200_000 {
            if !self.turn() {
                return;
            }
        }
        panic!("the world never settles");
    }

    fn owners(&self) {
        let n = self.netvsc.borrow();
        let d = n.a.queues();
        let q = &self.net.queues;
        owned_once(
            self.q,
            [d.owned(Pool::Rx), d.owned(Pool::Tx)],
            [q.owned(Pool::Rx), q.owned(Pool::Tx)],
        );
    }

    fn stats(&self) -> NetvscStats {
        self.netvsc.borrow().a.stats()
    }

    /// The host saw nothing it would refuse and has every receive-buffer
    /// packet acknowledged.
    fn honest(&self) {
        assert_eq!(self.nic.faults(), Vec::<String>::new());
        let host = self.host.borrow();
        assert!(host.log().is_empty(), "{:#?}", host.log());
        assert_eq!(
            self.nic.unacked(),
            0,
            "receive-buffer packets unacknowledged"
        );
    }
}

/// vmbus's wake: SINT 2's edge; its relay of channel events to netvsc.
fn run_vmbus<'m>(
    m: &Machine,
    host: &RefCell<Host<'m>>,
    vmbus: &RefCell<VmbusThread<'m>>,
    bits: &Cell<u64>,
) {
    if !m.take_interrupt() {
        return;
    }
    let mut v = vmbus.borrow_mut();
    let v = &mut *v;
    v.bus.on_signal(&mut Hyp(host), &mut v.sys);
    if core::mem::take(&mut v.sys.netvsc) {
        bits.set(bits.get() | CHANNEL);
    }
}

/// What `root::check::net` requires once the datagrams are echoed, for
/// netvsc and net: no bad queue entry, no broken or skipped packet, no IP
/// or UDP checksum error, no frame dropped for want of a buffer on either
/// side, every datagram echoed; and every acknowledgement sent and every
/// frame accounted for against the peer's count.
fn check_net(v: &NetvscStats, r: &Report, peer: &Peer, count: u32) {
    let s = &r.stack;
    assert_eq!((v.bad_entries, r.queues.bad), (0, 0), "{v:?} {r:?}");
    assert_eq!((v.broken, v.skipped), (0, 0), "{v}");
    assert_eq!((s.ip_checksum, s.udp_checksum, s.icmp_checksum), (0, 0, 0));
    assert_eq!((v.dropped, r.queues.dropped, s.tx_full), (0, 0, 0));
    assert_eq!(s.udp_echoed, u64::from(count), "{r}");
    assert_eq!(s.dropped(), 0, "every frame handled: {r}");
    assert_eq!(
        (s.held_replaced, s.held_full, s.held_evicted),
        (0, 0, 0),
        "{r}"
    );
    assert_eq!((v.acks, v.acks_waiting), (v.rxbuf_packets, 0), "{v}");
    assert_eq!(v.completions, v.sent, "{v}");
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

fn a_hundred_datagrams(mnf: bool) {
    let m = Machine::new();
    let q = queues();
    let hooks = Hooks::new();
    let mut w = World::new(&m, &q, &hooks, Setup::new(COUNT, mnf));
    w.settle();
    assert_eq!(w.netvsc.borrow().a.step(), Step::Up);
    // The M9 Hyper-V check's lines up to its `udp_echo: 100`.
    assert_eq!(
        w.vmbus.borrow().sys.lines,
        [
            "vmbus: version 4.0",
            "vmbus: offer 1: storvsc, connection 1, monitor trigger 1",
            "vmbus: offer 3: heartbeat, connection 3",
            "vmbus: offer 14: netvsc, connection 14, monitor trigger 14",
            "vmbus: offer 17: a5a5a511-a5a5-a5a5-a5a5-a5a5a5a5a5a5, connection 17, monitor trigger 17",
            "vmbus: netvsc channel 14 open, connection 14",
        ]
    );
    assert_eq!(
        w.netvsc.borrow().lines,
        [
            "netvsc: up: NVSP 5, NDIS 6.30, MAC 00:15:5d:4c:34:01, link up, 128 send sections of 6144 bytes"
        ]
    );
    assert_eq!(
        w.net.lines,
        [
            "net: up: 192.168.77.2/24 via 192.168.77.1, MAC 00:15:5d:4c:34:01",
            "echo: listening on UDP port 7",
            "net: gateway 192.168.77.1 is at 00:15:5d:00:00:77",
            "net: ping 192.168.77.1: reply 1, 56 bytes",
        ]
    );
    w.peer.begin();
    w.settle();
    assert!(w.peer.done(), "missing {:?}", w.peer.missing());
    w.honest();
    let (v, r) = (w.stats(), w.net.report());
    check_net(&v, &r, &w.peer, COUNT);
    let s = &r.stack;
    assert_eq!((s.arp_sent, s.arp_learnt, s.arp_answered), (1, 1, 0));
    let line = format!("net: stats: {r}");
    assert!(
        line.contains(&format!(", {COUNT} datagrams echoed,")),
        "{line}"
    );
    assert!(line.contains(", 4 ICMP echo requests answered,"), "{line}");
    assert!(
        line.contains(", 0 frames dropped, 0 bad entries,"),
        "{line}"
    );
    assert_eq!(v.ignored, 0, "{v}");
    assert!(v.max_in_flight >= 1 && v.max_in_flight <= 128, "{v}");
    // vmbus relayed the channel's events and took nothing it ignored.
    let b = w.vmbus.borrow().bus.stats();
    assert_eq!(
        (b.netvsc_channel, b.stray, b.retries, b.ignored),
        (u64::from(NETVSC), 0, 0, 0),
        "{b}"
    );
    assert!(b.events > 0 && b.messages > 0, "{b}");
    w.owners();
    let host = w.host.borrow();
    if mnf {
        assert_eq!(host.signals(NETVSC), 0, "netvsc.mnf=1 never signals");
        assert!(host.monitor_signals() > 0);
    } else {
        assert!(host.signals(NETVSC) > 0);
        assert_eq!(host.monitor_signals(), 0);
    }
}

#[test]
fn a_hundred_datagrams_echo_through_the_mock_host() {
    a_hundred_datagrams(false);
}

#[test]
fn a_hundred_datagrams_echo_through_the_mock_host_with_the_monitor_page() {
    a_hundred_datagrams(true);
}

/// One random run's knobs.
#[derive(Clone, Copy, Debug)]
struct Run {
    seed: u64,
    /// Random turns at most, before the run goes on by priority.
    turns: usize,
    /// The chance, per mille, that a turn goes by priority.
    prio: u32,
    /// Preemption rates per mille: the host inside netvsc, netvsc or
    /// vmbus inside net.
    rates: (u32, u32),
    mnf: bool,
    /// The host holds send completions until a turn gives them back.
    hold: bool,
    /// Frames a receive-buffer packet, and per-packet information.
    frames_per_packet: usize,
    pktinfo: bool,
    /// The send sections' size: 128 of 6,144 bytes, or fewer, larger
    /// ones, so that frames wait in `TX_FILLED` for a section.
    section_size: u32,
    ports: usize,
    window: u32,
    count: u32,
}

/// One random run: turns in any order until every datagram is answered
/// or `turns` run out; then turns by priority, without preemption, the
/// host reading and completing, until everything is answered, which must
/// not stall.
fn interleaved(run: Run) {
    let m = Machine::new();
    let q = queues();
    let hooks = Hooks::new();
    let mut setup = Setup::new(run.count, run.mnf);
    setup.spec.ports = (0..run.ports as u16).map(|i| 50_000 + 13 * i).collect();
    setup.spec.window = run.window;
    setup.nic.hold_completions = run.hold;
    setup.nic.frames_per_packet = run.frames_per_packet;
    setup.nic.pktinfo = run.pktinfo;
    setup.nic.section_size = run.section_size;
    let mut w = World::new(&m, &q, &hooks, setup);
    let rng = Rc::new(RefCell::new(Rng::new(run.seed)));
    let rates = Rc::new(Cell::new(run.rates));
    {
        let machine = w.m;
        let (host, nic, r, g) = (w.host.clone(), w.nic.clone(), rates.clone(), rng.clone());
        // Not netvsc itself, whose windows hold this hook.
        let (vmbus, bits) = (w.vmbus.clone(), w.bits.clone());
        hooks.channel.set(move |_| {
            let mut g = g.borrow_mut();
            if !g.chance(r.get().0) {
                return;
            }
            // The host on its own processor; or vmbus, above netvsc, at
            // SINT 2's edge.
            match g.below(4) {
                0 => {
                    drop(g);
                    run_vmbus(machine, &host, &vmbus, &bits);
                }
                1 => {
                    let mut order = Rng::new(g.next());
                    drop(g);
                    nic.release(|held| shuffle(held, &mut order));
                }
                _ => {
                    drop(g);
                    host.borrow_mut().step();
                }
            }
        });
        let (host, netvsc) = (w.host.clone(), w.netvsc.clone());
        let (vmbus, bits) = (w.vmbus.clone(), w.bits.clone());
        let (r, g) = (rates.clone(), rng.clone());
        hooks.net.set(move |_| {
            if !g.borrow_mut().chance(r.get().1) {
                return;
            }
            // vmbus, then netvsc, each above net; netvsc whether or not
            // its notification holds a bit, since a wake may be stale.
            run_vmbus(machine, &host, &vmbus, &bits);
            netvsc.borrow_mut().run(&host);
        });
    }
    for _ in 0..run.turns {
        if w.net.stack.is_some() {
            w.peer.begin();
        }
        if w.peer.done() {
            break;
        }
        let (by_priority, pick) = {
            let mut r = rng.borrow_mut();
            (r.chance(run.prio), r.below(8))
        };
        if by_priority {
            if !w.turn() {
                // Everything waits: the host gives back the completions it
                // holds, in any order.
                let mut order = Rng::new(rng.borrow_mut().next());
                w.nic.release(|held| shuffle(held, &mut order));
            }
        } else {
            match pick {
                0 if w.vmbus_ready() => w.run_vmbus(),
                1 if w.netvsc_ready() => w.run_netvsc(),
                2 if w.net_ready() => w.run_net(),
                0..=3 => {
                    w.host_step();
                }
                4 => {
                    w.peer();
                }
                5 => {
                    let mut order = Rng::new(rng.borrow_mut().next());
                    w.nic.release(|held| shuffle(held, &mut order));
                }
                6 => w.nic.pause_reading(),
                _ => w.nic.resume_reading(),
            }
        }
        w.owners();
        let v = w.stats();
        assert_eq!(
            (v.bad_entries, v.dropped, v.broken, v.skipped),
            (0, 0, 0, 0),
            "{v:?}"
        );
        assert_eq!(w.nic.faults(), Vec::<String>::new());
    }
    // The host reads again and stops holding completions, and nothing
    // preempts any more.
    rates.set((0, 0));
    w.nic.resume_reading();
    w.nic.configure(|c| c.hold_completions = false);
    w.nic.release(|_| {});
    w.peer.begin();
    w.settle();
    w.owners();
    assert!(
        w.peer.done(),
        "stalled: missing {:?}; {}; {:?}",
        w.peer.missing(),
        w.stats(),
        w.net.lines
    );
    w.honest();
    check_net(&w.stats(), &w.net.report(), &w.peer, run.count);
    let l = &w.net.lines;
    assert_eq!(l.len(), 4, "{l:?}");
    assert!(
        l[2].starts_with("net: gateway ") && l[3].starts_with("net: ping "),
        "{l:?}"
    );
}

/// `v` in an order `rng` picks.
fn shuffle(v: &mut [u64], rng: &mut Rng) {
    for i in (1..v.len()).rev() {
        let j = rng.below(i as u64 + 1) as usize;
        v.swap(i, j);
    }
}

/// At every access the host acts inside netvsc and netvsc preempts net,
/// with completions held and given back in any order.
#[test]
fn preempted_at_every_access_loses_nothing() {
    for mnf in [false, true] {
        interleaved(Run {
            seed: 11,
            turns: 1_000_000,
            prio: 0,
            rates: (1000, 1000),
            mnf,
            hold: true,
            frames_per_packet: 3,
            pktinfo: true,
            section_size: 6144 * 8,
            ports: 2,
            window: 50,
            count: if cfg!(miri) { 4 } else { 150 },
        });
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 96 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_interleavings_through_the_mock_host_lose_nothing(
        seed in any::<u64>(),
        turns in prop_oneof![0usize..200, Just(1_000_000)],
        prio in prop_oneof![Just(0u32), 0u32..1000, Just(1000u32)],
        host_rate in prop_oneof![Just(0u32), 1u32..100, Just(1000u32)],
        net_rate in prop_oneof![Just(0u32), 1u32..100, Just(1000u32)],
        mnf in any::<bool>(),
        hold in any::<bool>(),
        frames_per_packet in 1usize..=4,
        pktinfo in any::<bool>(),
        section_size in prop_oneof![Just(6144u32), Just(6144 * 4), Just(6144 * 16)],
        ports in 1usize..=3,
        window in prop_oneof![Just(8u32), 1u32..=100],
    ) {
        interleaved(Run {
            seed,
            turns: if cfg!(miri) { turns.min(300) } else { turns },
            prio,
            rates: (host_rate, net_rate),
            mnf,
            hold,
            frames_per_packet,
            pktinfo,
            section_size,
            ports,
            window,
            count: if cfg!(miri) { 6 } else { 120 },
        });
    }
}

/// The lost wakeup b121abd fixed, end to end. A host slow to read: the
/// outbound ring fills with acknowledgements of a flood of status
/// indications (small receive sections, so that more packets can be
/// outstanding than the ring holds acknowledgements for; indications,
/// since they give net nothing, so no `FRAMES` signal of net's wakes
/// netvsc). When netvsc finds no room for the next acknowledgement and
/// writes its request for room, the host reads the whole ring just before
/// that request lands, so it sees none and will never signal for the room
/// it made. The flood stops there: nothing else will wake netvsc, which
/// must look for the room again after asking. Then the peer's pings and
/// echoes, in short datagrams, still go through.
#[test]
#[cfg_attr(
    miri,
    ignore = "a thousand packets to fill the ring: minutes under Miri"
)]
fn a_host_that_drains_the_ring_before_the_request_for_room_still_hears_netvsc() {
    let m = Machine::new();
    let q = queues();
    let hooks = Hooks::new();
    let mut setup = Setup::new(40, false);
    setup.nic.receive_section = 256;
    // What fits a 256-byte section: an RNDIS packet message of 44 bytes
    // and a frame of up to 212, the stack's own 56-byte ping among them.
    setup.spec.pings = vec![32, 0, 1, 56];
    setup.spec.lengths = peer::LENGTHS[..6].to_vec();
    let mut w = World::new(&m, &q, &hooks, setup);
    w.settle();
    assert_eq!(w.net.lines.len(), 4);
    let fired = Rc::new(Cell::new(false));
    {
        let (host, nic, fired) = (w.host.clone(), w.nic.clone(), fired.clone());
        let pending = layout::OUTBOUND + ring::PENDING_SEND_SIZE;
        hooks.channel.set(move |at| {
            if at.offset == pending
                && matches!(at.access, Access::Store(n) if n != 0)
                && !fired.replace(true)
            {
                let before = nic.seen().rxbuf;
                nic.resume_reading();
                let mut host = host.borrow_mut();
                while host.step() {}
                assert_eq!(
                    nic.seen().rxbuf,
                    before,
                    "the host sent more, which would signal netvsc"
                );
            }
        });
    }
    w.nic.pause_reading();
    let mut flooded = 0;
    for batch in 0.. {
        assert!(batch < 100, "the outbound ring never filled");
        for _ in 0..50 {
            w.nic.indicate(nic::rndis::MEDIA_CONNECT);
            flooded += 1;
        }
        w.settle();
        if fired.get() {
            break;
        }
    }
    let v = w.stats();
    assert_eq!(
        (v.acks_waiting, w.nic.unacked()),
        (0, 0),
        "netvsc waits for a signal that will not come: {v}"
    );
    assert_eq!((v.acks, v.status), (v.rxbuf_packets, flooded), "{v}");
    // The host reads as it should from now on, and the peer's traffic
    // goes through.
    w.peer.begin();
    w.settle();
    assert!(w.peer.done(), "missing {:?}", w.peer.missing());
    w.honest();
    check_net(&w.stats(), &w.net.report(), &w.peer, 40);
}
