//! The stack against the end-to-end tests' scripted peer ([`peer`]), with
//! no driver between: first straight, then over the frame queues with a
//! model driver that preempts `net` at any access ([`preempt`]); and the
//! peer's own checks, each shown to fail a guest that breaks its rule.
//! `virtio-net`'s and `netvsc`'s tests run the same peer through their
//! drivers.

use core::cell::RefCell;
use std::collections::VecDeque;
use std::format;
use std::rc::Rc;
use std::string::{String, ToString};
use std::vec::Vec;

use proptest::prelude::*;

use super::Wire;
use super::owners::owned_once;
use super::peer::{self, Peer, Spec};
use super::preempt::{Hook, Preempt, Rng};
use super::wire::{csum, put16};
use crate::link::{self, Up};
use crate::{Config, Mac, Stack, echo};
use libsys::frames::{self, Pool};
use libsys::mem::Ram;

/// The datagrams a run sends: the scenario's 100, fewer under Miri.
const COUNT: u32 = if cfg!(miri) { 26 } else { 100 };

/// The stack and the peer, frames passed straight between them: the
/// stack's frames to the peer at once, the peer's to the stack in order.
struct Direct {
    stack: Stack,
    wire: Wire,
    peer: Peer,
    to_stack: VecDeque<Vec<u8>>,
    lines: Vec<String>,
}

impl Direct {
    fn new(spec: Spec, config: Config) -> Direct {
        let mut d = Direct {
            stack: Stack::new(config, Mac(spec.guest_mac)),
            wire: Wire::new(),
            peer: Peer::new(spec),
            to_stack: VecDeque::new(),
            lines: Vec::new(),
        };
        d.stack.start(&mut d.wire);
        d
    }

    /// One frame each way, or the peer's own; whether anything moved.
    fn step(&mut self) -> bool {
        for f in self.wire.take() {
            let answers = self.peer.input(&f);
            self.to_stack.extend(answers);
        }
        self.to_stack.extend(self.peer.poll());
        while let Some(e) = self.stack.event() {
            self.lines.push(e.to_string());
        }
        match self.to_stack.pop_front() {
            Some(f) => {
                self.stack.input(&f, &mut self.wire);
                true
            }
            None => !self.wire.frames.is_empty(),
        }
    }

    fn settle(&mut self) {
        for _ in 0..100_000 {
            if !self.step() {
                return;
            }
        }
        panic!("the stack and the peer never settle");
    }
}

/// The stack's counters for an honest run of `spec` with `pings_to_gw`
/// echo requests of its own answered: every frame handled, nothing
/// dropped.
fn honest_stats(s: &crate::Stats, spec: &Spec, datagrams: u32) {
    let n = u64::from(datagrams);
    let pings = spec.pings.len() as u64;
    assert_eq!(
        (s.udp_received, s.udp_echoed, s.icmp_answered),
        (n, n, pings),
        "{s:?}"
    );
    assert_eq!((s.ping_sent, s.icmp_replies), (1, 1), "{s:?}");
    assert_eq!(s.dropped(), 0, "{s:?}");
    assert_eq!(
        (s.tx_full, s.held_replaced, s.held_full, s.held_evicted),
        (0, 0, 0, 0)
    );
    assert_eq!(s.frames_in, s.frames_out, "{s:?}");
}

#[test]
fn the_stack_answers_the_peer_straight() {
    for spec in [Spec::qemu(COUNT), Spec::hyperv(COUNT)] {
        let config = Config::parse(&spec.cmdline(), None).unwrap();
        let mut d = Direct::new(spec.clone(), config);
        d.settle();
        let gw = format!("net: gateway {} is at {}", config.gateway(), Mac(spec.mac));
        assert_eq!(
            d.lines,
            [
                gw,
                format!("net: ping {}: reply 1, 56 bytes", config.gateway())
            ]
        );
        d.peer.begin();
        d.settle();
        assert!(d.peer.done(), "missing {:?}", d.peer.missing());
        let s = d.stack.stats();
        honest_stats(s, &spec, COUNT);
        assert_eq!((s.arp_sent, s.arp_learnt, s.arp_answered), (1, 1, 0));
        let p = d.peer.counts;
        assert_eq!((p.arp_requests, p.arp_asked, p.ping_replies), (1, 0, 4));
        assert_eq!(p.from_guest, s.frames_out);
        assert_eq!(p.to_guest, s.frames_in);
        assert_eq!(
            d.peer.guest_pings,
            [peer::GuestPing {
                ident: peer::PING_IDENT,
                seq: 1,
                len: 56
            }]
        );
    }
}

/// A peer that begins before the guest has asked for it sends its own
/// ARP request, which the stack answers and learns from (RFC 826's merge:
/// the target is its address).
#[test]
fn a_peer_that_asks_first_is_answered() {
    let spec = Spec::hyperv(13);
    let config = Config::parse(&spec.cmdline(), None).unwrap();
    let mut d = Direct::new(spec.clone(), config);
    // The stack's request for the gateway is lost on the way.
    assert_eq!(d.wire.take().len(), 1);
    d.peer.begin();
    d.settle();
    assert!(d.peer.done());
    let s = d.stack.stats();
    assert_eq!((s.arp_sent, s.arp_answered, s.arp_learnt), (1, 1, 0));
    // The stack's own ping waits in its ARP entry no longer: the
    // peer's request resolved the gateway.
    assert_eq!((s.ping_sent, s.icmp_replies), (1, 1));
    assert_eq!(d.peer.counts.arp_asked, 1);
    assert_eq!(s.udp_echoed, 13);
}

/// `udp_echo:`'s payloads (`docs/design.md`, "The harness: `nic:` and
/// `udp_echo:`"), as `xtask/src/udp.rs` makes them.
#[test]
fn the_peers_payloads_are_the_harnesss() {
    let lengths: Vec<usize> = (0..26).map(|k| peer::payload(k).len()).collect();
    assert_eq!(lengths[..13], peer::LENGTHS);
    assert_eq!(lengths[13..], peer::LENGTHS);
    assert_eq!(peer::payload(0), b"uL4E\0\0\0\0");
    let p = peer::payload(0x0102_0307);
    assert_eq!(&p[..8], b"uL4E\x07\x03\x02\x01");
    assert_eq!(p.len(), 17);
    for (j, &b) in p.iter().enumerate().skip(8) {
        assert_eq!(b, (0x0102_0307 + 3 * j) as u8);
    }
}

// The peer's own checks: each a guest frame that breaks one rule.

/// The stack up, the peer begun and its pings answered, and `window`
/// datagrams given to the stack: its echoes wait in `wire`.
fn echoes(window: u32) -> Direct {
    let mut spec = Spec::qemu(window);
    spec.window = window;
    let mut d = Direct::new(spec, Config::QEMU);
    d.settle();
    d.peer.begin();
    // The pings, one at a time, each answered.
    while d.peer.counts.ping_replies < 4 {
        assert!(d.step());
    }
    // The step that took the last reply sent the datagrams, and gave the
    // stack the first.
    let mut sent: Vec<Vec<u8>> = d.to_stack.drain(..).collect();
    sent.extend(d.peer.poll());
    for f in &sent {
        d.stack.input(f, &mut d.wire);
    }
    assert_eq!(d.peer.counts.sent, u64::from(window));
    d
}

/// `frame`'s IPv4 identification set to `ident`, the header checksum
/// again.
fn reident(frame: &mut [u8], ident: u16) {
    put16(frame, 14 + 4, ident);
    put16(frame, 14 + 10, 0);
    let c = csum(&frame[14..34]);
    put16(frame, 14 + 10, c);
}

/// The UDP checksum of the datagram in `frame` again.
fn resum_udp(frame: &mut [u8]) {
    let total = usize::from(u16::from_be_bytes([frame[16], frame[17]]));
    put16(frame, 14 + 26, 0);
    let ip = &frame[14..14 + total];
    let c = match peer::checksum(&[&ip[12..16], &ip[16..20], &[0, 17], &ip[24..26], &ip[20..]]) {
        0 => 0xFFFF,
        c => c,
    };
    put16(frame, 14 + 26, c);
}

/// Runs `echoes(window)`, then `f` on the stack's echoes and the peer.
fn with_echoes(window: u32, f: impl FnOnce(&mut Peer, Vec<Vec<u8>>)) {
    let mut d = echoes(window);
    let frames = d.wire.take();
    assert_eq!(frames.len(), window as usize);
    f(&mut d.peer, frames);
}

#[test]
fn the_peer_takes_the_stacks_echoes() {
    with_echoes(3, |p, frames| {
        for f in &frames {
            assert!(p.input(f).is_empty());
        }
        assert!(p.done());
    });
}

#[test]
#[should_panic(
    expected = "peer: an echo of nothing unanswered (datagram 1 waits): datagram 1 altered"
)]
fn the_peer_refuses_an_altered_echo() {
    with_echoes(2, |p, mut frames| {
        p.input(&frames[0]);
        // Datagram 1's ninth and last byte, before the frame's padding.
        let f = &mut frames[1];
        f[14 + 20 + 8 + 8] ^= 1;
        resum_udp(f);
        p.input(f);
    });
}

#[test]
#[should_panic(expected = "a second echo of datagram 0")]
fn the_peer_refuses_a_second_echo() {
    with_echoes(2, |p, frames| {
        p.input(&frames[0]);
        let mut again = frames[0].clone();
        let next = u16::from_be_bytes([frames[1][18], frames[1][19]]);
        reident(&mut again, next);
        p.input(&again);
    });
}

#[test]
#[should_panic(expected = "peer: datagram 1's echo before datagram 0's")]
fn the_peer_refuses_echoes_out_of_order() {
    with_echoes(2, |p, frames| {
        let mut second = frames[1].clone();
        let first = u16::from_be_bytes([frames[0][18], frames[0][19]]);
        reident(&mut second, first);
        p.input(&second);
    });
}

#[test]
#[should_panic(expected = "peer: the UDP checksum")]
fn the_peer_refuses_a_bad_udp_checksum() {
    with_echoes(1, |p, mut frames| {
        frames[0][14 + 27] ^= 0x10;
        p.input(&frames[0]);
    });
}

#[test]
#[should_panic(expected = "peer: the identification counts up from 1")]
fn the_peer_refuses_an_identification_out_of_turn() {
    with_echoes(1, |p, mut frames| {
        reident(&mut frames[0], 1);
        p.input(&frames[0]);
    });
}

#[test]
#[should_panic(expected = "peer: padding that is not zeros")]
fn the_peer_refuses_padding_that_is_not_zeros() {
    let spec = Spec::qemu(1);
    let mut d = Direct::new(spec, Config::QEMU);
    let mut request = d.wire.take().remove(0);
    assert_eq!(request.len(), 60, "the stack pads its ARP request");
    request[59] = 0xA5;
    d.peer.input(&request);
}

// net over the frame queues, preempted by a model driver.

/// A model driver: the driver's side of the queues over the same memory,
/// with a wire of its own to the peer in place of a device. It delivers
/// the peer's frames while it holds receive buffers (the rest wait, as a
/// device's queue holds them), and gives the peer every frame `net` sends.
struct Model<'r> {
    q: frames::Driver<&'r Ram>,
    peer: Peer,
    wire: VecDeque<Vec<u8>>,
    /// net signalled it, and it owes net a signal.
    frames: bool,
    to_net: bool,
}

impl Model<'_> {
    /// Whether it would run: a signal from net, or frames on the wire (its
    /// device's interrupt).
    fn ready(&self) -> bool {
        self.frames || !self.wire.is_empty()
    }

    fn run(&mut self) {
        self.frames = false;
        self.q.reclaim();
        while let Some(f) = self.wire.front() {
            if self.q.free_buffers() == 0 && self.q.reclaim() == 0 {
                break;
            }
            self.q.deliver(f).expect("a receive buffer");
            self.wire.pop_front();
        }
        let mut out = [0u8; crate::MAX_FRAME];
        while let Some(n) = self.q.take_tx(&mut out) {
            let answers = self.peer.input(&out[..n]);
            self.wire.extend(answers);
        }
        self.to_net |= self.q.end_batch();
    }
}

/// `count` datagrams through net and a model driver that preempts it at
/// any access to the queues with a chance of `per_mille`, and runs
/// between net's turns as `seed` picks.
fn preempted(seed: u64, per_mille: u32, count: u32) {
    let spec = Spec::qemu(count);
    let ram = Ram::new(frames::layout::END);
    let mut q = frames::Driver::new(&ram);
    q.start(frames::Link::new(Mac(spec.guest_mac), true));
    assert!(q.end_batch());
    let model = Rc::new(RefCell::new(Model {
        q,
        peer: Peer::new(spec.clone()),
        wire: VecDeque::new(),
        frames: false,
        to_net: true,
    }));
    let hook = Rc::new(Hook::new());
    let rng = Rc::new(RefCell::new(Rng::new(seed)));
    {
        let (model, rng) = (model.clone(), rng.clone());
        // The driver runs whether or not it has work: a wake may be stale,
        // an interrupt for an element an earlier run already took.
        hook.set(move |_| {
            if rng.borrow_mut().chance(per_mille) {
                model.borrow_mut().run();
            }
        });
    }
    let mut n = frames::Net::new(Preempt::new(&ram, hook.clone()));
    let mut stack: Option<Stack> = None;
    let mut lines = Vec::new();
    let mut idle = 0;
    for _ in 0..1_000_000 {
        let net_ready = model.borrow().to_net;
        let model_ready = model.borrow().ready();
        let pick = rng.borrow_mut().below(3);
        if pick == 0 && net_ready {
            model.borrow_mut().to_net = false;
            let signal = match &mut stack {
                None => {
                    let s = link::start(Config::QEMU, &mut n).expect("the link");
                    lines.push(Up(Config::QEMU, s.mac()).to_string());
                    lines.push(echo::LISTENING.to_string());
                    stack = Some(s);
                    n.end_batch()
                }
                Some(s) => link::pump(s, &mut n),
            };
            model.borrow_mut().frames |= signal;
            if let Some(s) = &mut stack {
                while let Some(e) = s.event() {
                    lines.push(e.to_string());
                }
            }
        } else if pick == 1 && model_ready {
            model.borrow_mut().run();
        } else {
            let mut m = model.borrow_mut();
            if lines.len() >= 4 {
                m.peer.begin();
            }
            let frames = m.peer.poll();
            let quiet = frames.is_empty();
            m.wire.extend(frames);
            if quiet && !net_ready && !model_ready {
                idle += 1;
                if idle > 3 {
                    break;
                }
                continue;
            }
        }
        idle = 0;
        let m = model.borrow();
        owned_once(
            &ram,
            [m.q.owned(Pool::Rx), m.q.owned(Pool::Tx)],
            [n.owned(Pool::Rx), n.owned(Pool::Tx)],
        );
    }
    let m = model.borrow();
    assert!(
        m.peer.done(),
        "stalled: missing {:?}, lines {lines:?}",
        m.peer.missing()
    );
    assert!(hook.points.get() > 0);
    let s = stack.unwrap();
    honest_stats(s.stats(), &spec, count);
    let (qd, qn) = (m.q.counters(), n.counters());
    assert_eq!((qd.bad, qd.dropped, qn.bad, qn.dropped), (0, 0, 0, 0));
    assert_eq!(qn.received, s.stats().frames_in);
    assert_eq!(qn.sent, s.stats().frames_out);
}

#[test]
fn net_preempted_at_every_access_loses_nothing() {
    preempted(1, 1000, COUNT);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 64 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn net_preempted_by_its_driver_anywhere_loses_nothing(
        seed in any::<u64>(),
        per_mille in prop_oneof![Just(0u32), 1u32..50, 50u32..=1000],
    ) {
        preempted(seed, per_mille, if cfg!(miri) { 13 } else { 40 });
    }
}
