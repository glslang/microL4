//! netvsc against `hvmock`'s netvsc device (`docs/design.md`, "The mock
//! VMBus host"): `vmbus` brings the channel up on the mock host as it
//! would on Hyper-V, and the test plays `net`'s side of the frame queues.
//!
//! - [`setup`]: NVSP and NDIS negotiation and fallback, the buffers and
//!   their sections, RNDIS's setup, every refusal, the arguments, the
//!   `Attach` reply, the requests and the stats text.
//! - [`data`]: receiving and sending through the sections, completions in
//!   any order, acknowledgements waiting on a full ring, the rings at
//!   every wrap, and both signalling paths.
//! - [`hostile`]: what a host may write that netvsc must count and
//!   refuse, never follow, and a proptest of hostile packets.

mod data;
mod hostile;
mod setup;

use std::boxed::Box;
use std::string::String;
use std::vec::Vec;
use std::{format, vec};

use hvmock::netvsc::{self as nic, Netvsc};
use hvmock::{Host, Machine, Page, Restriction, machine};
use libsys::frames::{self, Driver, Net};
use libsys::mem::Ram;
use libsys::proto::VmbusAttach;

use super::*;

/// netvsc's channel and connection in the mock's default offers.
const NETVSC: u32 = 14;
/// The mock device's MAC.
const MAC: [u8; 6] = [0x00, 0x15, 0x5d, 0x4c, 0x34, 0x01];
/// Another station's.
const PEER: [u8; 6] = [0x00, 0x15, 0x5d, 0x00, 0x00, 0x77];

/// vmbus's hypercalls, on the mock host.
struct Hyp<'a, 'm>(&'a mut Host<'m>);

impl vmbus::Hypervisor for Hyp<'_, '_> {
    fn post_message(&mut self, connection: u32, message_type: u32, payload: &[u8]) -> Status {
        self.0.post_message(connection, message_type, payload)
    }
    fn signal_event(&mut self, connection: u32, flag: u16) -> Status {
        self.0.signal_event(connection, flag)
    }
    fn eom(&mut self) {
        self.0.eom()
    }
    fn vp_index(&mut self) -> u32 {
        self.0.vp_index()
    }
}

/// What vmbus does to the rest of the system: its signals to netvsc.
#[derive(Default)]
struct Sys {
    netvsc: bool,
    mints: Vec<u64>,
}

impl vmbus::System for Sys {
    fn say(&mut self, _: &vmbus::Note) {}
    fn signal_netvsc(&mut self) {
        self.netvsc = true;
    }
    fn mint(&mut self, data: u64) {
        self.mints.push(data);
    }
    fn revoke(&mut self) {}
    fn yield_now(&mut self) {}
}

/// netvsc's restricted capability, on the mock host, which fails a test
/// that signals another connection.
struct Cap<'a, 'm> {
    host: &'a mut Host<'m>,
    cap: Restriction,
    signals: &'a mut u64,
    status: Status,
}

impl Signal for Cap<'_, '_> {
    fn signal_event(&mut self, connection: u32) -> Status {
        *self.signals += 1;
        if !self.status.is_success() {
            return self.status;
        }
        self.host.signal_restricted(self.cap, connection, 0)
    }
}

/// How a rig is made.
struct Setup {
    host: hvmock::Config,
    nic: nic::Config,
    mnf: bool,
    /// Indices to start both rings at, before netvsc reads them.
    ring_start: u32,
}

impl Default for Setup {
    fn default() -> Setup {
        Setup {
            host: hvmock::Config::default(),
            nic: nic::Config::default(),
            mnf: false,
            ring_start: 0,
        }
    }
}

/// The frame queues' memory: its used part.
fn queues() -> Ram {
    Ram::new(frames::layout::END)
}

/// vmbus, the mock host and its netvsc device, netvsc, and the test as
/// `net`.
struct Rig<'m> {
    m: &'m Machine,
    host: Host<'m>,
    bus: vmbus::Bus<Page<'m>>,
    sys: Sys,
    nic: Netvsc,
    a: Adapter<Page<'m>, &'m Ram>,
    cap: Restriction,
    /// `net`'s side, and whether it has attached.
    net: Net<&'m Ram>,
    attached: bool,
    /// Whether to signal netvsc with `FRAMES`, or `net`.
    to_netvsc: bool,
    to_net: bool,
    /// Frames `net` took from `RX_FILLED`.
    received: Vec<Vec<u8>>,
    /// netvsc's lines, `SignalEvent`s, and what it returned.
    lines: Vec<String>,
    signals: u64,
    signal_status: Status,
    failure: Option<Failure>,
    /// Whether `net` takes what netvsc delivers.
    net_reads: bool,
    /// Whether `net` does not run at all.
    net_asleep: bool,
}

impl<'m> Rig<'m> {
    /// vmbus opens the channel and answers `Attach`; netvsc is made but
    /// not started.
    fn new(m: &'m Machine, q: &'m Ram, s: Setup) -> Rig<'m> {
        let nic = Netvsc::new(s.nic);
        let mut host = Host::new(m, s.host);
        host.attach(NETVSC, Box::new(nic.clone()));
        let mut bus = vmbus::Bus::new(vmbus_start(), m.sim(), m.sief());
        let mut sys = Sys::default();
        bus.start(&mut Hyp(&mut host), &mut sys);
        for _ in 0..1000 {
            let mut did = false;
            if m.take_interrupt() {
                bus.on_signal(&mut Hyp(&mut host), &mut sys);
                did = true;
            }
            if !(did | host.step()) {
                break;
            }
        }
        let attach = bus.attached().expect("vmbus opened netvsc's channel");
        assert_eq!(attach.channel, NETVSC);
        let cap = Restriction::from_data(sys.mints[0]).expect("a restriction");
        sys.netvsc = false;
        let start = Start {
            channel: machine::CHANNEL,
            mnf: s.mnf,
        };
        if s.ring_start != 0 {
            for base in [layout::OUTBOUND, layout::INBOUND] {
                let ctl = channel(m);
                ctl.store32(base + ring::WRITE_INDEX, s.ring_start, Relaxed);
                ctl.store32(base + ring::READ_INDEX, s.ring_start, Relaxed);
            }
        }
        let mnf = s
            .mnf
            .then(|| m.window(machine::MONITOR + machine::PAGE, 2 * machine::PAGE));
        let a = Adapter::new(start, attach, channel(m), mnf, Driver::new(q)).expect("an adapter");
        Rig {
            m,
            host,
            bus,
            sys,
            nic,
            a,
            cap,
            net: Net::new(q),
            attached: false,
            to_netvsc: false,
            to_net: false,
            received: Vec::new(),
            lines: Vec::new(),
            signals: 0,
            signal_status: Status::SUCCESS,
            failure: None,
            net_reads: true,
            net_asleep: false,
        }
    }

    /// Starts netvsc and runs until nothing happens.
    fn start(&mut self) {
        let cap = self.cap;
        let r = self.a.start(&mut Cap {
            host: &mut self.host,
            cap,
            signals: &mut self.signals,
            status: self.signal_status,
        });
        self.took(r.map(|()| false));
        self.run();
    }

    fn took(&mut self, r: Result<bool, Failure>) {
        match r {
            Ok(wake) => self.to_net |= wake,
            Err(f) => self.failure = Some(f),
        }
        while let Some(n) = self.a.note() {
            self.lines.push(format!("{n}"));
        }
    }

    /// One turn of every party; whether anything happened.
    fn turn(&mut self) -> bool {
        let mut did = false;
        if self.m.take_interrupt() {
            self.bus.on_signal(&mut Hyp(&mut self.host), &mut self.sys);
            did = true;
        }
        let mut bits = 0;
        if std::mem::take(&mut self.sys.netvsc) {
            bits |= CHANNEL;
        }
        if std::mem::take(&mut self.to_netvsc) {
            bits |= FRAMES;
        }
        if bits != 0 && self.failure.is_none() {
            let cap = self.cap;
            let r = self.a.on_signal(
                bits,
                &mut Cap {
                    host: &mut self.host,
                    cap,
                    signals: &mut self.signals,
                    status: self.signal_status,
                },
            );
            self.took(r);
            did = true;
        }
        if !self.net_asleep && std::mem::take(&mut self.to_net) {
            self.net_turn();
            did = true;
        }
        did | self.host.step()
    }

    /// `net`'s turn at a signal: attach once, then take every frame.
    fn net_turn(&mut self) {
        if !self.attached {
            self.net.attach().expect("netvsc's link block");
            self.attached = true;
        }
        if self.net_reads {
            let mut buf = [0u8; frames::MAX_FRAME];
            while let Some(n) = self.net.take_rx(&mut buf) {
                self.received.push(buf[..n].to_vec());
            }
        }
        self.net.reclaim();
        if self.net.end_batch() {
            self.to_netvsc = true;
        }
    }

    /// Turns until nothing happens and no interrupt waits; panics after
    /// 100,000.
    fn run(&mut self) {
        for _ in 0..100_000 {
            if !self.turn() && !self.m.interrupt_pending() {
                return;
            }
        }
        panic!("the rig never settled");
    }

    /// `net` sends a frame, and signals netvsc.
    fn send(&mut self, frame: &[u8]) {
        self.net.send(frame).expect("a transmit buffer");
        if self.net.end_batch() {
            self.to_netvsc = true;
        }
    }

    /// Asserts the device saw nothing a host would refuse, and every
    /// receive-buffer packet was acknowledged.
    fn honest(&self) {
        assert_eq!(self.nic.faults(), Vec::<String>::new());
        assert!(self.host.log().is_empty(), "{:#?}", self.host.log());
        assert_eq!(
            self.nic.unacked(),
            0,
            "receive-buffer packets unacknowledged"
        );
        assert_eq!(self.failure, None);
    }

    /// The counters, with the ones every honest run keeps at 0 checked.
    fn clean_stats(&self) -> libsys::proto::NetvscStats {
        let s = self.a.stats();
        assert_eq!(
            (
                s.broken,
                s.skipped,
                s.ignored,
                s.bad_entries,
                s.dropped,
                s.acks_waiting
            ),
            (0, 0, 0, 0, 0, 0),
            "{s:?}"
        );
        s
    }
}

/// The standard machine's arguments to vmbus.
fn vmbus_start() -> vmbus::Start {
    vmbus::Start {
        channel: machine::CHANNEL,
        monitor: machine::MONITOR,
        event_flags: machine::EVENT_FLAGS,
    }
}

/// The channel frame, as netvsc maps it.
fn channel(m: &Machine) -> Page<'_> {
    m.window(machine::CHANNEL, layout::CHANNEL_SIZE as u64)
}

/// A rig over the defaults, set up and with `net` attached.
fn up<'m>(m: &'m Machine, q: &'m Ram, s: Setup) -> Rig<'m> {
    let mut r = Rig::new(m, q, s);
    r.start();
    assert_eq!(r.failure, None);
    assert_eq!(r.a.step(), Step::Up, "{:?}", r.nic.seen());
    assert!(r.attached);
    r
}

/// An Ethernet frame of `len` bytes to `dst`, from [`PEER`], its payload
/// made from `seed`.
fn frame(dst: [u8; 6], len: usize, seed: u64) -> Vec<u8> {
    let mut f = Vec::with_capacity(len);
    f.extend_from_slice(&dst);
    f.extend_from_slice(&PEER);
    f.extend_from_slice(&[0x08, 0x00]);
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    while f.len() < len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        f.push(x as u8);
    }
    f.truncate(len);
    f
}

/// xorshift64*: small, deterministic and fast under Miri.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// A valid `VmbusAttach` for argument tests.
fn some_attach() -> VmbusAttach {
    VmbusAttach {
        channel: NETVSC,
        connection: NETVSC,
        ring_gpadl: 0xE1E10,
        rx_gpadl: 0xE1E11,
        tx_gpadl: 0xE1E12,
        version: vmbus::version(4, 0),
        flags1: 1,
        montrig: 14,
        flags2: 0,
        vp_index: 0,
    }
}

use core::sync::atomic::Ordering::Relaxed;
