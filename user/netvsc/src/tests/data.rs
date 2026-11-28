//! Receiving and sending through the sections: frames each way, several
//! frames a packet with per-packet information, completions in any
//! order, a full receive pool, acknowledgements waiting on a full
//! outbound ring, the rings at every wrap, the host's interrupt mask and
//! pending send size, and both signalling paths.

use hvmock::netvsc::rndis as hr;
use hvmock::{OfferSpec, ring as hring};

use super::*;

/// Frames to the MAC and to broadcast of every length class; under
/// Miri, which takes a second over each 1,514-byte frame, only the third
/// is that long and the rest short.
fn mixed(n: usize, rng: &mut Rng) -> Vec<Vec<u8>> {
    let most = if cfg!(miri) { 200 } else { 1514 };
    (0..n)
        .map(|k| {
            let len = match k % 5 {
                0 => 14,
                1 => 60,
                2 if !cfg!(miri) || k == 2 => 1514,
                _ => 14 + rng.below(most - 13) as usize,
            };
            let dst = if k % 7 == 3 { [0xFF; 6] } else { MAC };
            frame(dst, len, k as u64)
        })
        .collect()
}

/// The outbound ring's control page, as the host sees it.
fn outbound(m: &Machine) -> hring::Ring<Page<'_>> {
    hring::Ring::new(m.window(
        machine::CHANNEL,
        (layout::OUTBOUND_PAGES * layout::PAGE) as u64,
    ))
}

#[test]
fn frames_from_the_network_reach_net_and_the_filter_takes_only_ours() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    let mut rng = Rng::new(1);
    let n = if cfg!(miri) { 12 } else { 100 };
    let want = mixed(n, &mut rng);
    for (i, f) in want.iter().enumerate() {
        r.nic.deliver(f);
        if i % 3 == 0 {
            // Another station's, and a multicast: the host's filter drops
            // them.
            r.nic.deliver(&frame(PEER, 60, 0));
            r.nic.deliver(&frame([0x01, 0, 0x5e, 0, 0, 1], 60, 0));
        }
        if i % 16 == 15 {
            r.run();
        }
    }
    r.run();
    r.honest();
    assert_eq!(r.received, want);
    assert_eq!(r.nic.seen().filtered, 2 * n.div_ceil(3) as u64);
    let s = r.clean_stats();
    assert_eq!(s.received, n as u64);
    assert_eq!(s.rxbuf_packets, 4 + n as u64);
    assert_eq!(s.acks, s.rxbuf_packets);
    // Every receive section is back with the host.
    assert_eq!(r.nic.free_sections(), layout::RECEIVE_SIZE / 1728);
}

#[test]
fn several_frames_a_packet_with_per_packet_information() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(
        &m,
        &q,
        Setup {
            nic: nic::Config {
                frames_per_packet: 5,
                pktinfo: true,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    let mut rng = Rng::new(2);
    let n = if cfg!(miri) { 11 } else { 101 };
    let want = mixed(n, &mut rng);
    for f in &want {
        r.nic.deliver(f);
    }
    r.run();
    r.honest();
    assert_eq!(r.received, want);
    let s = r.clean_stats();
    assert_eq!(s.received, n as u64);
    // Five frames a packet, the last packet short.
    assert_eq!(s.rxbuf_packets, 4 + n.div_ceil(5) as u64);
}

#[test]
fn frames_from_net_reach_the_host() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    let mut rng = Rng::new(3);
    let n = if cfg!(miri) { 20 } else { 300 };
    let want = mixed(n, &mut rng);
    for chunk in want.chunks(50) {
        for f in chunk {
            r.send(f);
        }
        r.run();
    }
    r.honest();
    assert_eq!(r.nic.take_sent(), want);
    let s = r.clean_stats();
    assert_eq!((s.sent, s.completions), (n as u64, n as u64));
    assert!(s.max_in_flight >= 1);
    assert_eq!(r.a.in_flight(), 0);
    assert_eq!(r.nic.seen().completions, n as u64);
    // Every transmit buffer is back with net.
    r.net.reclaim();
    assert_eq!(r.net.free_buffers(), frames::BUFFERS);
}

/// The host completes sends in any order; a section is reused only after
/// its completion (the device fails a test that reuses one sooner), and
/// a frame with no free section waits in `TX_FILLED`, never dropped.
#[test]
fn completions_out_of_order_free_their_sections() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(
        &m,
        &q,
        Setup {
            nic: nic::Config {
                hold_completions: true,
                // 16 sections, so that frames wait for them.
                section_size: 48 * 1024,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    assert_eq!(r.a.sections(), (48 * 1024, 16));
    let mut rng = Rng::new(4);
    let (rounds, frames) = if cfg!(miri) { (1, 20) } else { (6, 40) };
    let mut want = Vec::new();
    for round in 0..rounds {
        let batch = mixed(frames, &mut rng);
        for f in &batch {
            r.send(f);
        }
        want.extend(batch);
        r.run();
        // Sixteen in flight, the rest waiting in TX_FILLED.
        assert_eq!(r.a.in_flight().count_ones(), 16, "round {round}");
        assert_eq!(r.a.stats().max_in_flight, 16);
        while !r.nic.held().is_empty() {
            let mode = rng.below(3);
            r.nic.release(|h| match mode {
                0 => h.reverse(),
                1 => {
                    for i in (1..h.len()).rev() {
                        h.swap(i, rng.below(i as u64 + 1) as usize);
                    }
                }
                _ => {
                    let half = h.len() / 2;
                    h.rotate_left(half)
                }
            });
            r.run();
        }
    }
    r.honest();
    assert_eq!(r.nic.take_sent(), want);
    let s = r.clean_stats();
    assert_eq!(
        (s.sent, s.completions),
        (want.len() as u64, want.len() as u64)
    );
}

/// With no receive buffer free (net took none back), a frame is dropped
/// and counted, and its packet acknowledged all the same.
#[test]
fn a_full_receive_pool_drops_frames_and_still_acknowledges() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    r.net_reads = false;
    let want: Vec<Vec<u8>> = (0..130).map(|k| frame(MAC, 60, k)).collect();
    for f in &want {
        r.nic.deliver(f);
    }
    r.run();
    assert_eq!(r.nic.unacked(), 0);
    let s = r.a.stats();
    assert_eq!((s.received, s.dropped), (128, 2));
    assert_eq!(s.acks, s.rxbuf_packets);
    // net catches up: the first 128.
    r.net_reads = true;
    r.to_net = true;
    r.run();
    assert_eq!(r.received, want[..128]);
}

/// A host slow to read its ring: acknowledgements fill the outbound ring,
/// then wait in netvsc's queue of 64, then netvsc stops reading the
/// inbound ring; a frame from net waits behind them. Once the host reads,
/// its signal for the room netvsc asked for moves everything on.
#[test]
#[cfg_attr(miri, ignore = "thousands of packets: minutes under Miri")]
fn acknowledgements_wait_on_a_full_ring_ahead_of_frames() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(
        &m,
        &q,
        Setup {
            nic: nic::Config {
                // Small sections, so that more packets than the outbound
                // ring holds acknowledgements for can be outstanding.
                receive_section: 128,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    r.nic.pause_reading();
    let want: Vec<Vec<u8>> = (0..2000).map(|k| frame(MAC, 60, k)).collect();
    for f in &want {
        r.nic.deliver(f);
    }
    r.run();
    let s = r.a.stats();
    assert_eq!(s.acks_waiting, ACKS as u64);
    assert!(s.rxbuf_packets < 2000, "{s:?}");
    // The outbound ring holds acknowledgements up to its last bytes: no
    // room for another (64 bytes and one more).
    let data = (layout::OUTBOUND_PAGES - 1) * layout::PAGE;
    let free = data - outbound(&m).held().unwrap();
    assert!(free <= 64, "{free} bytes free");
    // A frame from net waits behind them.
    let late = frame(PEER, 100, 7);
    r.send(&late);
    r.run();
    assert_eq!(r.a.stats().sent, 0);
    r.nic.resume_reading();
    r.run();
    r.honest();
    let s = r.a.stats();
    assert_eq!(
        (s.rxbuf_packets, s.acks, s.acks_waiting),
        (4 + 2000, 4 + 2000, 0)
    );
    // net, with 128 buffers, cannot keep up with a burst of 2,000: the
    // rest are dropped and counted, never waited for.
    assert_eq!(s.received + s.dropped, 2000);
    assert_eq!(s.received, r.received.len() as u64);
    let mut at = 0;
    for f in &r.received {
        at += want[at..].iter().position(|w| w == f).expect("in order") + 1;
    }
    assert_eq!((s.broken, s.skipped, s.ignored), (0, 0, 0));
    assert_eq!(r.nic.take_sent(), [late]);
}

/// The host waits for room in the inbound ring (its pending send size),
/// and only netvsc's signal after a batch tells it there is: the host has
/// masked the outbound ring, so netvsc's writes signal nothing. (A masked
/// host reads the ring again when it unmasks; the test does that last.)
#[test]
#[cfg_attr(miri, ignore = "thousands of packets: minutes under Miri")]
fn a_host_waiting_for_room_is_signalled_once_there_is() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(
        &m,
        &q,
        Setup {
            nic: nic::Config {
                receive_section: 128,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    outbound(&m).set_interrupt_mask(1);
    let signals = r.signals;
    for k in 0..2000 {
        r.nic.deliver(&frame(MAC, 60, k));
    }
    r.run();
    let room = r.signals - signals;
    assert_eq!(r.nic.waiting(), 0);
    outbound(&m).set_interrupt_mask(0);
    assert_eq!(r.host.signal_restricted(r.cap, NETVSC, 0), Status::SUCCESS);
    r.run();
    r.honest();
    let s = r.a.stats();
    assert_eq!((s.rxbuf_packets, s.acks), (4 + 2000, 4 + 2000));
    assert_eq!(s.received + s.dropped, 2000);
    // Signals only for room: the inbound ring holds 768 packets at a time.
    assert!((2..=100).contains(&room), "{room} signals");
}

/// The host masked: netvsc writes and does not signal; unmasked, it
/// signals again.
#[test]
fn a_masked_host_is_not_signalled() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    let ring = outbound(&m);
    ring.set_interrupt_mask(1);
    let signals = r.signals;
    let a = frame(PEER, 60, 1);
    r.send(&a);
    r.run();
    assert_eq!(r.signals, signals);
    assert_eq!(r.a.stats().sent, 1);
    assert!(r.nic.take_sent().is_empty(), "the host read unsignalled");
    ring.set_interrupt_mask(0);
    let b = frame(PEER, 61, 2);
    r.send(&b);
    r.run();
    r.honest();
    assert_eq!(r.signals, signals + 1);
    assert_eq!(r.nic.take_sent(), [a, b]);
}

/// Both rings start 4 KiB before their end, so that setup and traffic
/// cross the wrap, and run on past it.
#[test]
fn the_rings_wrap() {
    let m = Machine::new();
    let q = queues();
    let data = (layout::OUTBOUND_PAGES - 1) * layout::PAGE;
    let mut r = up(
        &m,
        &q,
        Setup {
            // Under Miri 512 bytes, which setup's packets already cross.
            ring_start: (data - if cfg!(miri) { 512 } else { 4096 }) as u32,
            nic: nic::Config {
                frames_per_packet: 3,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    let mut rng = Rng::new(5);
    let n = if cfg!(miri) { 12 } else { 1500 };
    let (mut got, mut sent) = (Vec::new(), Vec::new());
    for chunk in mixed(n, &mut rng).chunks(30) {
        for f in chunk {
            r.nic.deliver(f);
            r.send(f);
        }
        r.run();
        got.extend_from_slice(chunk);
        sent.extend_from_slice(chunk);
    }
    r.honest();
    assert_eq!(r.received, got);
    assert_eq!(r.nic.take_sent(), sent);
    // Both rings went past their end.
    let out = outbound(&m);
    assert!(out.write_index() < (data - 4096) as u32 || cfg!(miri));
    r.clean_stats();
}

/// netvsc.mnf=1: FreeBSD's signalling through the event-flags page and
/// monitor page 2, and no SignalEvent at all.
#[test]
fn the_monitor_page_signals_the_host() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(
        &m,
        &q,
        Setup {
            mnf: true,
            ..Setup::default()
        },
    );
    let f = frame(PEER, 60, 1);
    r.send(&f);
    r.nic.deliver(&frame(MAC, 60, 2));
    r.run();
    r.honest();
    assert_eq!(r.signals, 0);
    assert_eq!(r.host.signals(NETVSC), 0);
    assert!(r.host.monitor_signals() > 0);
    assert_eq!(r.nic.take_sent(), [f]);
    assert_eq!(r.received, [frame(MAC, 60, 2)]);
    // The host took every trigger and flag.
    let mnf = m.window(machine::MONITOR + machine::PAGE, 2 * machine::PAGE);
    let t = 14usize;
    assert_eq!(mnf.load32(8 + 8 * (t / 32), Relaxed), 0);
    assert_eq!(
        mnf.load8(layout::MNF_EVENT_FLAGS + 2048 + t / 8, Relaxed),
        0
    );
}

/// netvsc.mnf=1 on an offer the host does not monitor: the event flag,
/// then SignalEvent, as FreeBSD's `vmbus_chan_signal`.
#[test]
fn an_unmonitored_offer_takes_the_flag_and_signal_event() {
    let m = Machine::new();
    let q = queues();
    let mut host = hvmock::Config::default();
    host.offers[2] = OfferSpec {
        flags1: 0,
        ..OfferSpec::netvsc(NETVSC, NETVSC)
    };
    let mut r = up(
        &m,
        &q,
        Setup {
            host,
            mnf: true,
            ..Setup::default()
        },
    );
    r.send(&frame(PEER, 60, 1));
    r.run();
    r.honest();
    assert!(r.signals > 0);
    assert_eq!(r.host.monitor_signals(), 0);
    let flags = m.window(machine::EVENT_FLAGS, machine::PAGE);
    let ch = NETVSC as usize;
    assert_ne!(flags.load8(2048 + ch / 8, Relaxed) & (1 << (ch % 8)), 0);
    assert_eq!(r.nic.take_sent().len(), 1);
}

#[test]
fn the_stats_text_after_traffic() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    for k in 0..3 {
        r.nic.deliver(&frame(MAC, 60, k));
        r.send(&frame(PEER, 60, k));
    }
    r.nic.indicate(hr::MEDIA_CONNECT);
    r.run();
    r.honest();
    assert_eq!(
        format!("{}", r.a.stats()),
        "NVSP 5, NDIS 6.30, 8 receive-buffer packets, 3 frames received, 0 dropped for no buffer, 8 acknowledgements sent, 0 acknowledgements waiting, 3 frames sent, 3 sections in flight at most, 3 send completions, 1 status indications, 0 broken packets, 0 packets skipped, 0 ignored messages, 0 bad queue entries"
    );
}

/// The outbound ring of a fresh `mem`, written full of 64-byte packets:
/// the ring and the room the next one needs.
fn full_outbound(mem: &Ram) -> (ring::Outbound, usize) {
    let mut out = ring::Outbound::new(mem);
    for xid in 0.. {
        match out.write(mem, ring::kind::INBAND, 0, xid, &[], &[0x5A; 48]) {
            Ok(_) => {}
            Err(ring::WriteError::Full { need, .. }) => return (out, need),
            Err(e) => panic!("{e:?}"),
        }
    }
    unreachable!()
}

/// netvsc found the outbound ring full; the host read it all before the
/// request for room reached it, so it will never signal for that room.
/// Asking reads the room again after the request, and the write goes
/// ahead; with no room, the request stands and netvsc waits.
#[test]
fn room_made_before_the_request_is_seen_at_once() {
    use core::sync::atomic::Ordering::SeqCst;

    let mem = Ram::new(ring::CONTROL + layout::PAGE);
    let (mut out, need) = full_outbound(&mem);
    assert_eq!(out.ask_room(&mem, need), Ok(false));
    assert_eq!(mem.load32(ring::PENDING_SEND_SIZE, SeqCst), need as u32);

    let mem = Ram::new(ring::CONTROL + layout::PAGE);
    let (mut out, need) = full_outbound(&mem);
    mem.store32(ring::READ_INDEX, out.write_index(), SeqCst);
    assert_eq!(out.ask_room(&mem, need), Ok(true));
    assert!(
        out.write(&mem, ring::kind::INBAND, 0, 0, &[], &[0x5A; 48])
            .is_ok()
    );
    // The write took the request back.
    assert_eq!(mem.load32(ring::PENDING_SEND_SIZE, SeqCst), 0);

    // A bad read index, found by the second look, breaks the ring.
    let mem = Ram::new(ring::CONTROL + layout::PAGE);
    let (mut out, need) = full_outbound(&mem);
    mem.store32(ring::READ_INDEX, 3, SeqCst);
    assert_eq!(out.ask_room(&mem, need), Err(ring::Broken::Index(3)));
    assert_eq!(out.broken(), Some(ring::Broken::Index(3)));
}
