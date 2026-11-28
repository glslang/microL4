//! The mock's own round trips: windows, the ring at every wrap, the
//! message codec, the message slot's delivery and `MessagePending`, GPADL
//! reassembly and its checks, the hypercalls' checks, and the devices.

use core::sync::atomic::Ordering::Relaxed;

use libsys::hyperv::{Restriction, Status};
use libsys::mem::Memory;

use crate::machine::{self, CHANNEL, Machine, PAGE, SIM};
use crate::ring::{self, Broken, Ring};
use crate::wire::{self, Request, kind};
use crate::{Config, Host, Loopback, OfferSpec, REFUSED, version};

const SLOT: usize = SIM as usize + 512;

/// A guest's message bytes: what vmbus would post.
fn msg(k: u32, fields: &[&[u8]]) -> Vec<u8> {
    let mut v = k.to_le_bytes().to_vec();
    v.extend_from_slice(&[0; 4]);
    for f in fields {
        v.extend_from_slice(f);
    }
    v
}

fn connect(version: u32) -> Vec<u8> {
    msg(
        kind::CONNECT,
        &[
            &version.to_le_bytes(),
            &[0; 4],
            &machine::EVENT_FLAGS.to_le_bytes(),
            &machine::MONITOR.to_le_bytes(),
            &(machine::MONITOR + PAGE).to_le_bytes(),
        ],
    )
}

/// GPADL_CONN of `total` pages from `first`, with the first `n` of them.
fn gpadl_conn(channel: u32, gpadl: u32, first: u64, total: u64, n: u64) -> Vec<u8> {
    let mut v = msg(
        kind::GPADL_CONN,
        &[
            &channel.to_le_bytes(),
            &gpadl.to_le_bytes(),
            &((8 + 8 * total) as u16).to_le_bytes(),
            &1u16.to_le_bytes(),
            &((total * PAGE) as u32).to_le_bytes(),
            &0u32.to_le_bytes(),
        ],
    );
    for p in first..first + n {
        v.extend_from_slice(&p.to_le_bytes());
    }
    v
}

fn gpadl_subconn(gpadl: u32, pages: core::ops::Range<u64>) -> Vec<u8> {
    let mut v = msg(
        kind::GPADL_SUBCONN,
        &[&0u32.to_le_bytes(), &gpadl.to_le_bytes()],
    );
    for p in pages {
        v.extend_from_slice(&p.to_le_bytes());
    }
    v
}

fn chopen(channel: u32, gpadl: u32, outbound: u32) -> Vec<u8> {
    msg(
        kind::CHOPEN,
        &[
            &channel.to_le_bytes(),
            &channel.to_le_bytes(),
            &gpadl.to_le_bytes(),
            &0u32.to_le_bytes(),
            &outbound.to_le_bytes(),
            &[0; 120],
        ],
    )
}

/// Takes the message in the slot as a guest should: copy, empty, fence,
/// `Eom` if pending.
fn take(m: &Machine, host: &mut Host<'_>) -> Option<Vec<u8>> {
    let sim = m.sim();
    if sim.load32(512, Relaxed) == 0 {
        return None;
    }
    let mut b = [0u8; 256];
    sim.read(512, &mut b);
    sim.store32(512, 0, Relaxed);
    sim.fence(core::sync::atomic::Ordering::SeqCst);
    if sim.load8(512 + 5, Relaxed) & machine::PENDING != 0 {
        host.eom();
    }
    Some(b[16..16 + usize::from(b[4])].to_vec())
}

fn kind_of(b: &[u8]) -> u32 {
    u32::from_le_bytes(b[..4].try_into().unwrap())
}

/// A host in contact, its offers taken.
fn contacted(m: &Machine, cfg: Config) -> Host<'_> {
    let mut h = Host::new(m, cfg);
    assert_eq!(
        h.post_message(1, 1, &connect(version(4, 0))),
        Status::SUCCESS
    );
    assert_eq!(take(m, &mut h), Some(wire::connect_resp(true)));
    h.post_message(1, 1, &msg(kind::CHREQUEST, &[]));
    while take(m, &mut h).is_some() {}
    h
}

const RING_PAGES: u64 = 32;

/// `contacted`, with channel 14's ring GPADL made from the channel
/// frame's first 32 pages and the channel open, 16 pages outbound.
fn opened(m: &Machine) -> Host<'_> {
    let mut h = contacted(m, Config::default());
    let first = CHANNEL / PAGE;
    h.post_message(1, 1, &gpadl_conn(14, 7, first, RING_PAGES, 26));
    h.post_message(1, 1, &gpadl_subconn(7, first + 26..first + 32));
    assert_eq!(take(m, &mut h), Some(wire::gpadl_connresp(14, 7, 0)));
    h.post_message(1, 1, &chopen(14, 7, 16));
    assert_eq!(take(m, &mut h), Some(wire::chopen_resp(14, 14, 0)));
    assert!(h.log().is_empty(), "{:?}", h.log());
    h
}

#[test]
fn a_view_crosses_pages_in_the_gpadl_s_order() {
    let m = Machine::new();
    let pages = [9u64, 3, 700];
    let v = m.view(&pages);
    assert_eq!(v.len(), 3 * 4096);
    let bytes: Vec<u8> = (0..300).map(|i| i as u8).collect();
    v.write(4096 - 100, &bytes);
    let mut back = vec![0; 300];
    v.read(4096 - 100, &mut back);
    assert_eq!(back, bytes);
    // Byte 4095 is page 9's last, byte 4096 page 3's first.
    assert_eq!(m.ram().load8(9 * 4096 + 4095, Relaxed), 99);
    assert_eq!(m.ram().load8(3 * 4096, Relaxed), 100);
    v.store64(2 * 4096 + 8, 0xDEAD, Relaxed);
    assert_eq!(m.ram().load64(700 * 4096 + 8, Relaxed), 0xDEAD);
    assert_eq!(v.gpa(4096 + 5), 3 * 4096 + 5);
}

#[test]
#[should_panic(expected = "outside a view")]
fn a_view_refuses_a_byte_past_its_end() {
    let m = Machine::new();
    let pages = [1u64];
    m.view(&pages).read(4090, &mut [0; 7]);
}

/// Every packet size at every starting offset of a small ring: what is
/// written is read back whole, the indices wrap, and a full ring refuses.
#[test]
fn a_ring_round_trips_at_every_wrap() {
    let m = Machine::new();
    // Two pages: a control page and 4 KiB of data.
    let ring = Ring::new(m.window(0x10_0000, 2 * PAGE));
    let size = ring.size();
    assert_eq!(size, 4096);
    let lens: &[usize] = if cfg!(miri) {
        &[0, 1, 9, 100, 2000]
    } else {
        &[0, 1, 7, 8, 9, 100, 1000, 2000, 4056]
    };
    let starts = if cfg!(miri) { 8 } else { 512 };
    for start in 0..starts {
        for &len in lens {
            let at = (start * 8) as u32;
            ring.set_read_index(at);
            ring.set_write_index(at);
            let body: Vec<u8> = (0..len).map(|i| (i * 31 + start) as u8).collect();
            let total = 16 + len.div_ceil(8) * 8;
            let w = ring.write(
                ring::kind::INBAND,
                ring::FLAG_COMPLETION,
                start as u64,
                &body,
            );
            if total + 8 >= size {
                assert!(w.is_err(), "{len} bytes fit");
                continue;
            }
            let w = w.unwrap();
            assert_eq!((w.old, w.was_empty), (at, true));
            assert_eq!(ring.held().unwrap(), total + 8);
            let p = ring.read().unwrap().unwrap();
            assert_eq!(
                (p.kind, p.flags, p.xid, p.header_len),
                (ring::kind::INBAND, ring::FLAG_COMPLETION, start as u64, 16)
            );
            assert_eq!(p.bytes.len(), total);
            assert_eq!(&p.body()[..len], &body[..]);
            assert_eq!(p.trailer, u64::from(at) << 32);
            assert_eq!(ring.read_index(), ((at as usize + total + 8) % size) as u32);
            assert_eq!(ring.read(), Ok(None));
        }
    }
    // Full: a packet that would leave no byte free is refused.
    ring.set_read_index(0);
    ring.set_write_index(0);
    let big = vec![1u8; size - 16 - 8];
    assert!(ring.write(6, 0, 0, &big).is_err());
    assert!(ring.write(6, 0, 0, &big[8..]).is_ok());
    assert_eq!(ring.free().unwrap(), 8);
    assert!(ring.write(6, 0, 0, &[]).is_err());
}

#[test]
fn a_broken_ring_is_refused_not_followed() {
    let m = Machine::new();
    let ring = Ring::new(m.window(0x10_0000, 2 * PAGE));
    ring.write(6, 0, 1, b"x").unwrap();
    // An index outside the data, or not a multiple of 8.
    for (r, w) in [(0, 4096), (4096, 0), (4, 32), (0, 36)] {
        ring.set_read_index(r);
        ring.set_write_index(w);
        assert!(matches!(ring.read(), Err(Broken::Index { .. })), "{r} {w}");
    }
    // A header whose lengths do not fit what the ring holds.
    for (hlen, tlen) in [(1u16, 3u16), (3, 2), (2, 200)] {
        ring.set_read_index(0);
        ring.set_write_index(32);
        let c = m.window(0x10_0000 + PAGE, PAGE);
        c.store16(2, hlen, Relaxed);
        c.store16(4, tlen, Relaxed);
        assert!(
            matches!(ring.read(), Err(Broken::Header { .. })),
            "{hlen} {tlen}"
        );
        assert_eq!(ring.read_index(), 0);
    }
}

#[test]
fn a_reader_signals_a_writer_waiting_for_room() {
    let m = Machine::new();
    let ring = Ring::new(m.window(0x10_0000, 2 * PAGE));
    // Packets of 1,024 bytes with their trailers: three leave 1,024 free.
    for _ in 0..3 {
        ring.write(6, 0, 0, &[0; 1000]).unwrap();
    }
    // The writer waits for 2,000 bytes, but without its feature bit it
    // gets no signal.
    ring.set_pending_send_size(2000);
    let p = ring.read().unwrap().unwrap();
    assert_eq!(ring.free().unwrap(), 2048);
    assert!(!ring.reader_should_signal(p.bytes.len() + 8));
    ring.write(6, 0, 0, &[0; 1000]).unwrap();
    ring.set_features(ring::FEATURE_PENDING_SEND_SIZE);
    // The read that brings the free space past 2,000 signals; the next,
    // which found enough already, does not.
    let p = ring.read().unwrap().unwrap();
    assert!(ring.reader_should_signal(p.bytes.len() + 8));
    let p = ring.read().unwrap().unwrap();
    assert!(!ring.reader_should_signal(p.bytes.len() + 8));
}

#[test]
fn messages_wait_behind_a_full_slot_with_pending_set() {
    let m = Machine::new();
    let mut h = Host::new(&m, Config::default());
    h.inject(b"one-----");
    assert!(m.take_interrupt());
    h.inject(b"two-----");
    h.inject(b"three---");
    assert!(!m.take_interrupt());
    assert_eq!(h.queued(), 2);
    assert_eq!(m.ram().load8(SLOT + 5, Relaxed), machine::PENDING);
    assert_eq!(take(&m, &mut h).unwrap(), b"one-----");
    assert!(m.take_interrupt());
    assert_eq!(take(&m, &mut h).unwrap(), b"two-----");
    assert_eq!(take(&m, &mut h).unwrap(), b"three---");
    assert_eq!(take(&m, &mut h), None);
    assert_eq!((h.delivered(), h.eoms()), (3, 2));
    // An Eom with nothing queued does nothing.
    assert!(m.take_interrupt());
    h.eom();
    assert!(!m.take_interrupt());
}

/// With the late flag, a guest that trusts its copy's flags stalls; one
/// that reads them after emptying the slot does not.
#[test]
fn a_late_pending_flag_comes_only_with_the_emptying_store() {
    let m = Machine::new();
    m.set_late_pending(true);
    let mut h = Host::new(&m, Config::default());
    h.inject(b"one-----");
    h.inject(b"two-----");
    let sim = m.sim();
    let mut b = [0u8; 256];
    sim.read(512, &mut b);
    assert_eq!(b[5], 0);
    sim.store32(512, 0, Relaxed);
    assert_eq!(sim.load8(512 + 5, Relaxed), machine::PENDING);
    assert_eq!(m.late_sets(), 1);
    h.eom();
    assert_eq!(take(&m, &mut h).unwrap(), b"two-----");
    assert_eq!(m.late_sets(), 1);
}

#[test]
fn contact_takes_only_its_versions_and_checks_the_pages() {
    let m = Machine::new();
    let mut h = Host::new(&m, Config::default());
    h.post_message(1, 1, &msg(kind::CHREQUEST, &[]));
    assert_eq!(h.log().len(), 1);
    h.post_message(1, 1, &connect(version(3, 0)));
    assert_eq!(take(&m, &mut h), Some(wire::connect_resp(false)));
    assert_eq!(h.contact(), None);
    h.post_message(1, 1, &connect(version(4, 0)));
    assert_eq!(take(&m, &mut h), Some(wire::connect_resp(true)));
    assert_eq!(h.contact().unwrap().monitor2, machine::MONITOR + PAGE);
    // Offers in order, then done.
    h.post_message(1, 1, &msg(kind::CHREQUEST, &[]));
    let mut got = Vec::new();
    while let Some(b) = take(&m, &mut h) {
        got.push(b);
    }
    assert_eq!(got.len(), 5);
    assert_eq!(got[2], wire::offer(&OfferSpec::netvsc(14, 14)));
    assert_eq!(got[4], wire::offers_done());
    assert!(
        got[..4]
            .iter()
            .all(|b| b.len() == 196 && kind_of(b) == kind::CHOFFER)
    );
}

#[test]
#[should_panic(expected = "outside the pages root gave it")]
fn a_connect_naming_another_page_fails_the_test() {
    let m = Machine::new();
    let mut h = Host::new(&m, Config::default());
    let mut c = connect(version(4, 0));
    c[16..24].copy_from_slice(&0x8000u64.to_le_bytes());
    h.post_message(1, 1, &c);
}

#[test]
#[should_panic(expected = "outside the pages root gave it")]
fn a_gpadl_naming_another_page_fails_the_test() {
    let m = Machine::new();
    let mut h = contacted(&m, Config::default());
    let first = CHANNEL / PAGE;
    h.post_message(1, 1, &gpadl_conn(14, 7, first, 30, 26));
    h.post_message(1, 1, &gpadl_subconn(7, first + 511..first + 515));
}

#[test]
fn gpadls_are_reassembled_and_checked() {
    let m = Machine::new();
    let mut h = contacted(&m, Config::default());
    let first = CHANNEL / PAGE;
    // 60 pages: 26, 28, 6.
    h.post_message(1, 1, &gpadl_conn(14, 7, first, 60, 26));
    assert_eq!(take(&m, &mut h), None);
    h.post_message(1, 1, &gpadl_subconn(7, first + 26..first + 54));
    assert_eq!(take(&m, &mut h), None);
    h.post_message(1, 1, &gpadl_subconn(7, first + 54..first + 60));
    assert_eq!(take(&m, &mut h), Some(wire::gpadl_connresp(14, 7, 0)));
    let g = h.gpadl(7).unwrap();
    assert_eq!((g.channel, g.messages), (14, 3));
    assert_eq!(g.pages, (first..first + 60).collect::<Vec<_>>());
    assert!(h.log().is_empty());
    // Refused: a handle in use, a channel not offered, a short first
    // message, pages past the range, two ranges.
    for (bad, what) in [
        (gpadl_conn(14, 7, first, 1, 1), "handle in use"),
        (gpadl_conn(99, 8, first, 1, 1), "channel"),
        (gpadl_conn(14, 9, first, 30, 20), "short first message"),
        (
            {
                let mut b = gpadl_conn(14, 10, first, 1, 1);
                b[18] = 2;
                b
            },
            "two ranges",
        ),
    ] {
        let logged = h.log().len();
        h.post_message(1, 1, &bad);
        let answer = take(&m, &mut h).unwrap();
        assert_eq!(&answer[16..20], &REFUSED.to_le_bytes(), "{what}");
        assert_eq!(h.log().len(), logged + 1, "{what}");
    }
    h.post_message(1, 1, &gpadl_conn(14, 11, first, 27, 26));
    h.post_message(1, 1, &gpadl_subconn(11, first + 26..first + 28));
    assert_eq!(
        take(&m, &mut h),
        Some(wire::gpadl_connresp(14, 11, REFUSED))
    );
    // A SUBCONN for nothing is logged and answered by nothing.
    h.post_message(1, 1, &gpadl_subconn(12, first..first + 1));
    assert_eq!(take(&m, &mut h), None);
    // Teardown.
    h.post_message(
        1,
        1,
        &msg(
            kind::GPADL_DISCONN,
            &[&14u32.to_le_bytes(), &7u32.to_le_bytes()],
        ),
    );
    assert_eq!(take(&m, &mut h), Some(wire::gpadl_disconnresp(7)));
    assert!(h.gpadl(7).is_none());
}

#[test]
fn an_open_is_checked_against_its_gpadl() {
    let m = Machine::new();
    let mut h = contacted(&m, Config::default());
    let first = CHANNEL / PAGE;
    h.post_message(1, 1, &gpadl_conn(14, 7, first, 4, 4));
    take(&m, &mut h);
    for (bad, what) in [
        (chopen(14, 8, 2), "no such GPADL"),
        (chopen(3, 7, 2), "another channel's GPADL"),
        (chopen(14, 7, 1), "one outbound page"),
        (chopen(14, 7, 3), "one inbound page"),
    ] {
        h.post_message(1, 1, &bad);
        let a = take(&m, &mut h).unwrap();
        assert_eq!(&a[16..20], &REFUSED.to_le_bytes(), "{what}");
    }
    assert!(h.channel(14).unwrap().open.is_none());
    h.post_message(1, 1, &chopen(14, 7, 2));
    assert_eq!(take(&m, &mut h), Some(wire::chopen_resp(14, 14, 0)));
    assert!(h.channel(14).unwrap().open.is_some());
    // A ring GPADL in use is not torn down.
    h.post_message(
        1,
        1,
        &msg(
            kind::GPADL_DISCONN,
            &[&14u32.to_le_bytes(), &7u32.to_le_bytes()],
        ),
    );
    assert!(h.gpadl(7).is_some());
    h.post_message(1, 1, &msg(kind::CHCLOSE, &[&14u32.to_le_bytes()]));
    assert!(h.channel(14).unwrap().open.is_none());
}

#[test]
fn the_hypercalls_are_checked_as_the_kernel_and_hypervisor_would() {
    let m = Machine::new();
    let cfg = Config {
        busy_posts: 2,
        ..Config::default()
    };
    let mut h = Host::new(&m, cfg);
    let c = connect(version(4, 0));
    assert_eq!(h.post_message(2, 1, &c), Status::INVALID_CONNECTION_ID);
    assert_eq!(h.post_message(1, 1, &c), Status::INSUFFICIENT_BUFFERS);
    assert_eq!(h.post_message(1, 1, &c), Status::INSUFFICIENT_BUFFERS);
    assert_eq!(h.busy(), 2);
    assert!(h.posts().is_empty());
    assert_eq!(h.post_message(1, 1, &c), Status::SUCCESS);
    assert_eq!(h.posts().len(), 1);
    assert_eq!(h.vp_index(), 0);
}

#[test]
#[should_panic(expected = "which no open channel has")]
fn a_signal_on_a_connection_no_channel_has_fails_the_test() {
    let m = Machine::new();
    let mut h = opened(&m);
    h.signal_event(3, 0);
}

#[test]
#[should_panic(expected = "signalled connection 14")]
fn a_restricted_capability_without_signal_fails_the_test() {
    let m = Machine::new();
    let mut h = opened(&m);
    let cap = Restriction {
        connection: 14,
        post: true,
        signal: false,
    };
    h.signal_restricted(cap, 14, 0);
}

#[test]
fn the_loopback_answers_on_the_inbound_ring() {
    let m = Machine::new();
    let mut h = Host::new(&m, Config::default());
    h.attach(14, Box::new(Loopback::default()));
    let first = CHANNEL / PAGE;
    h.post_message(1, 1, &connect(version(4, 0)));
    take(&m, &mut h);
    h.post_message(1, 1, &msg(kind::CHREQUEST, &[]));
    while take(&m, &mut h).is_some() {}
    h.post_message(1, 1, &gpadl_conn(14, 7, first, RING_PAGES, 26));
    h.post_message(1, 1, &gpadl_subconn(7, first + 26..first + 32));
    take(&m, &mut h);
    h.post_message(1, 1, &chopen(14, 7, 16));
    take(&m, &mut h);
    let out = Ring::new(m.window(CHANNEL, 16 * PAGE));
    let inb = Ring::new(m.window(CHANNEL + 16 * PAGE, 16 * PAGE));
    assert_eq!(inb.features(), ring::FEATURE_PENDING_SEND_SIZE);
    out.write(6, 1, 42, b"ping").unwrap();
    assert!(!h.step());
    assert_eq!(
        h.signal_restricted(Restriction::signal_only(14), 14, 0),
        Status::SUCCESS
    );
    m.take_interrupt();
    assert!(h.step());
    assert!(m.take_interrupt());
    let p = inb.read().unwrap().unwrap();
    assert_eq!((p.kind, p.xid, &p.body()[..4]), (6, 42, &b"ping"[..]));
    assert_eq!(
        m.ram().load64(machine::SIEF as usize + 512, Relaxed),
        1 << 14
    );
    assert_eq!(h.signals(14), 1);
    // Full inbound: the device waits and asks for room.
    let ch = h.chan(14).unwrap();
    let mut n = 0;
    while ch.send(6, 0, 0, &[0; 4000]).is_ok() {
        n += 1;
    }
    // Packets of 4,024 bytes with their trailers: 15 fit in 60 KiB.
    assert_eq!(n, 15);
    assert_ne!(inb.pending_send_size(), 0);
    inb.read().unwrap();
    assert!(ch.send(6, 0, 0, &[0; 8]).is_ok());
    assert_eq!(inb.pending_send_size(), 0);
}

#[test]
fn requests_parse_with_their_lengths_checked() {
    assert_eq!(
        wire::parse(&connect(version(4, 0))),
        Ok(Request::Connect {
            version: version(4, 0),
            event_flags: machine::EVENT_FLAGS,
            monitor1: machine::MONITOR,
            monitor2: machine::MONITOR + PAGE,
        })
    );
    assert!(wire::parse(&connect(1)[..39]).is_err());
    assert!(wire::parse(&[0; 7]).is_err());
    assert!(wire::parse(&[0; 241]).is_err());
    let g = gpadl_conn(14, 7, 100, 3, 3);
    assert!(
        matches!(wire::parse(&g), Ok(Request::GpadlConn { ref pages, .. }) if pages == &[100, 101, 102])
    );
    assert!(wire::parse(&g[..g.len() - 1]).is_err());
    assert!(wire::parse(&gpadl_conn(14, 7, 0, 27, 27)).is_err());
    assert!(wire::parse(&gpadl_subconn(7, 0..29)).is_err());
    assert!(wire::parse(&chopen(14, 7, 16)[..147]).is_err());
    let mut o = chopen(14, 7, 16);
    o[100] = 1;
    assert!(matches!(
        wire::parse(&o),
        Ok(Request::ChOpen {
            user_data_zero: false,
            ..
        })
    ));
    assert_eq!(wire::parse(&msg(30, &[])), Ok(Request::Other(30)));
    assert_eq!(wire::offer(&OfferSpec::netvsc(1, 1)).len(), 196);
    assert_eq!(
        wire::guid_text(&crate::guid::NETVSC),
        "f8615163-df3e-46c5-913f-f2d2f965ed0e"
    );
    assert_eq!(
        wire::guid_text(&crate::guid::STORVSC),
        "ba6163d9-04a1-4d29-b605-72e2ffb1dc7f"
    );
    assert_eq!(
        wire::guid_text(&crate::guid::HEARTBEAT),
        "57164f39-9115-4e78-ab55-382f3bd5422d"
    );
}

#[test]
fn unanswered_and_held_requests() {
    let m = Machine::new();
    let cfg = Config {
        unanswered: vec![kind::CONNECT],
        ..Config::default()
    };
    let mut h = Host::new(&m, cfg);
    h.post_message(1, 1, &connect(version(4, 0)));
    assert_eq!(take(&m, &mut h), None);
    assert!(h.contact().is_some());
    let cfg = Config {
        hold_from: Some(0),
        ..Config::default()
    };
    let mut h = Host::new(&m, cfg);
    h.post_message(1, 1, &connect(version(4, 0)));
    h.inject(b"hostile-");
    assert_eq!(take(&m, &mut h).unwrap(), b"hostile-");
    assert_eq!((take(&m, &mut h), h.held()), (None, 1));
    h.resume();
    assert_eq!(take(&m, &mut h), Some(wire::connect_resp(true)));
}
