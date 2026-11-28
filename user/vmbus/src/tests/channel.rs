//! netvsc's channel once vmbus has opened it: the test plays netvsc on the
//! rings vmbus named, through the mock's loopback device, so that the
//! ring indices wrap, the host's signals come back as SINT 2 events that
//! vmbus relays, and netvsc's capability signals only its connection.

use std::boxed::Box;
use std::collections::VecDeque;

use hvmock::ring::{FLAG_COMPLETION, Ring, kind};
use hvmock::{Loopback, Restriction};

use super::*;
use crate::layout::{OUTBOUND_PAGES, PAGE};

/// The channel frame's outbound and inbound rings, as netvsc maps them.
fn rings(m: &Machine) -> (Ring<Page<'_>>, Ring<Page<'_>>) {
    let half = u64::from(OUTBOUND_PAGES) * PAGE;
    (
        Ring::new(m.window(machine::CHANNEL, half)),
        Ring::new(m.window(machine::CHANNEL + half, half)),
    )
}

#[test]
fn a_channel_s_rings_wrap_through_the_loopback() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.host.attach(NETVSC, Box::new(Loopback::default()));
    r.start();
    r.honest();
    let a = r.bus.attached().unwrap();
    let cap = Restriction::from_data(r.sys.mints[0]).unwrap();
    let (out, inb) = rings(&m);
    let data = out.size();
    assert_eq!(data, 15 * 4096);
    // Both rings start 4 KiB before their end, empty, as if they had
    // carried 56 KiB already: the first rounds wrap, under Miri too.
    let near = (data - 4096) as u32;
    for ring in [&out, &inb] {
        ring.set_write_index(near);
        ring.set_read_index(near);
    }
    let mut rng = Rng::new(7);
    let mut expect = VecDeque::new();
    let (mut xid, mut bytes) = (1u64, 0usize);
    let rounds = if cfg!(miri) { 6 } else { 400 };
    for round in 0..rounds {
        for _ in 0..1 + rng.below(3) {
            let len = 1 + rng.below(4000) as usize;
            let body: Vec<u8> = (0..len).map(|j| (j as u64 ^ xid) as u8).collect();
            out.write(kind::INBAND, FLAG_COMPLETION, xid, &body)
                .expect("the loopback drained the ring");
            bytes += 16 + len.div_ceil(8) * 8 + 8;
            expect.push_back((xid, body));
            xid += 1;
        }
        assert_eq!(
            r.host.signal_restricted(cap, a.connection, 0),
            Status::SUCCESS
        );
        r.run();
        // The host's echo signalled the guest (the ring was empty), and
        // vmbus relayed it to netvsc once.
        assert_eq!(r.sys.signals, round + 1);
        for p in inb.read_all().unwrap() {
            let (x, body) = expect.pop_front().unwrap();
            assert_eq!((p.kind, p.xid), (kind::INBAND, x));
            assert_eq!(p.body()[..body.len()], body[..]);
            assert!(p.body()[body.len()..].iter().all(|&b| b == 0));
        }
        assert!(expect.is_empty());
    }
    // Both rings wrapped, more than once natively.
    assert!(bytes > if cfg!(miri) { 4096 } else { 10 * data }, "{bytes}");
    assert_eq!(r.bus.stats().events, rounds);
    assert_eq!(r.bus.stats().stray, 0);
    assert_eq!(r.host.signals(a.connection), rounds);
    let lb = r.host.device(NETVSC).unwrap();
    assert!(lb.faults().is_empty(), "{:?}", lb.faults());
}

/// An inbound ring the guest masked gets no signal from the host, and a
/// write to a ring that was not empty none either (FreeBSD's rule).
#[test]
fn the_host_signals_only_an_empty_unmasked_ring() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    let (_, inb) = rings(&m);
    let ch = r.host.chan(NETVSC).unwrap();
    let raised = m.interrupts();
    ch.send(kind::INBAND, 0, 1, b"one").unwrap();
    assert_eq!(m.interrupts(), raised + 1);
    ch.send(kind::INBAND, 0, 2, b"two").unwrap();
    assert_eq!(m.interrupts(), raised + 1);
    r.run();
    assert_eq!(inb.read_all().unwrap().len(), 2);
    inb.set_interrupt_mask(1);
    let ch = r.host.chan(NETVSC).unwrap();
    ch.send(kind::INBAND, 0, 3, b"three").unwrap();
    assert_eq!(m.interrupts(), raised + 1);
    assert_eq!(r.sys.signals, 1);
}

#[test]
#[should_panic(expected = "signalled connection 3")]
fn netvsc_s_capability_signals_only_its_connection() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    let cap = Restriction::from_data(r.sys.mints[0]).unwrap();
    assert!(!cap.post);
    r.host.signal_restricted(cap, 3, 0);
}

/// netvsc.mnf=1's signal: its flag in the event-flags page's
/// guest-to-host half, then its monitor trigger in monitor page 2; the
/// host takes it on its next step.
#[test]
fn the_host_takes_a_monitor_page_signal() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.host.attach(NETVSC, Box::new(Loopback::default()));
    r.start();
    let a = r.bus.attached().unwrap();
    assert!(a.has_mnf());
    let (out, inb) = rings(&m);
    out.write(kind::INBAND, 0, 9, b"monitored").unwrap();
    let flags = m.window(machine::EVENT_FLAGS, PAGE);
    let monitor2 = m.window(START.monitor2(), PAGE);
    let ch = a.channel as usize;
    flags.or(
        2048 + ch / 8,
        libsys::mem::Width::Byte,
        1 << (ch % 8),
        Relaxed,
    );
    let t = usize::from(a.montrig);
    monitor2.or32(8 + 8 * (t / 32), 1 << (t % 32), Relaxed);
    r.run();
    assert_eq!(r.host.monitor_signals(), 1);
    assert_eq!(monitor2.load32(8 + 8 * (t / 32), Relaxed), 0);
    assert_eq!(flags.load8(2048 + ch / 8, Relaxed), 0);
    let p = inb.read().unwrap().unwrap();
    assert_eq!(p.xid, 9);
    assert_eq!(r.sys.signals, 1);
    // No SignalEvent was needed.
    assert_eq!(r.host.signals(a.connection), 0);
}

use core::sync::atomic::Ordering::Relaxed;
