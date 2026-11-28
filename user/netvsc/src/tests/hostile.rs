//! What a host may write that netvsc must count and refuse, never follow:
//! broken ring headers and indices, packets over 4 KiB, unknown types and
//! host notes, completions of nothing, receive-buffer packets with bad
//! IDs, counts, bodies and ranges, RNDIS messages with bad lengths and
//! offsets; and proptests of hostile packets and raw ring bytes, under
//! which netvsc never panics, never reads outside its windows, and
//! acknowledges every receive-buffer packet once.

use hvmock::netvsc::{nvs as hn, packet_msg, rndis as hr, status_msg, words};
use hvmock::ring as hring;
use proptest::prelude::*;

use super::*;
use crate::ring::kind;
use crate::rndis::{Bad, Data};

/// The inbound ring, as the host writes it.
fn inbound(m: &Machine) -> hring::Ring<Page<'_>> {
    hring::Ring::new(m.window(
        machine::CHANNEL + layout::INBOUND as u64,
        (layout::INBOUND_PAGES * layout::PAGE) as u64,
    ))
}

/// The outbound ring, as the host reads it.
fn outbound(m: &Machine) -> hring::Ring<Page<'_>> {
    hring::Ring::new(m.window(
        machine::CHANNEL,
        (layout::OUTBOUND_PAGES * layout::PAGE) as u64,
    ))
}

/// Writes `bytes` (padded to 8) at the host's write index, moves the
/// index past them and signals the guest: a host that writes whatever it
/// likes.
fn raw(r: &mut Rig<'_>, bytes: &[u8]) {
    let ring = inbound(r.m);
    let size = ring.size();
    let w = ring.write_index() as usize;
    for (i, chunk) in bytes.chunks(8).enumerate() {
        let mut b = [0u8; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        let at = ring::CONTROL + (w + 8 * i) % size;
        ring.memory().store64(at, u64::from_le_bytes(b), Relaxed);
    }
    ring.set_write_index(((w + bytes.len().div_ceil(8) * 8) % size) as u32);
    r.host.signal_guest(NETVSC);
}

/// A packet header: type, header and total length in 8-byte units,
/// flags, transaction ID.
fn header(kind: u16, hlen: u16, tlen: u16, xid: u64) -> Vec<u8> {
    let mut h = Vec::new();
    for v in [kind, hlen, tlen, 0] {
        h.extend_from_slice(&v.to_le_bytes());
    }
    h.extend_from_slice(&xid.to_le_bytes());
    h
}

/// An NVS RNDIS body, as a receive-buffer packet carries it.
fn rndis_body() -> Vec<u8> {
    let mut b = words(&[hn::RNDIS, 0, hn::CHIM_NONE, 0]);
    b.resize(40, 0);
    b
}

/// A receive-buffer packet's header extension: ID, count, ranges.
fn rxbuf_ext(id: u16, count: u32, ranges: &[(u32, u32)]) -> Vec<u8> {
    let mut e = Vec::new();
    e.extend_from_slice(&id.to_le_bytes());
    e.extend_from_slice(&0u16.to_le_bytes());
    e.extend_from_slice(&count.to_le_bytes());
    for &(len, ofs) in ranges {
        e.extend_from_slice(&len.to_le_bytes());
        e.extend_from_slice(&ofs.to_le_bytes());
    }
    e
}

/// Writes an RNDIS message straight into the receive buffer at `ofs`.
fn put(m: &Machine, ofs: usize, msg: &[u8]) {
    channel(m).write(layout::RECEIVE + ofs, msg);
}

#[test]
fn broken_headers_break_the_inbound_ring_once() {
    for (what, bytes) in [
        // A header under 16 bytes.
        ("header", [header(6, 1, 4, 1), vec![0; 24]].concat()),
        // A header longer than its packet.
        ("longer", [header(6, 4, 2, 1), vec![0; 8]].concat()),
        // A packet longer than the ring holds.
        ("held", [header(6, 2, 200, 1), vec![0; 24]].concat()),
        // Less than a header and trailer.
        ("short", header(6, 2, 2, 1)),
    ] {
        let m = Machine::new();
        let q = queues();
        let mut r = up(&m, &q, Setup::default());
        raw(&mut r, &bytes);
        r.run();
        let s = r.a.stats();
        assert_eq!(s.broken, 1, "{what}");
        assert!(
            r.lines[1].starts_with("netvsc: the inbound ring is broken ("),
            "{what}: {:?}",
            r.lines
        );
        assert!(r.lines[1].ends_with("; it is no longer read"));
        // Nothing more is read, and nothing panics; frames still go out.
        r.nic.deliver(&frame(MAC, 60, 1));
        r.send(&frame(PEER, 60, 2));
        r.run();
        assert_eq!(r.a.stats().broken, 1);
        assert!(r.received.is_empty());
        assert_eq!(r.nic.take_sent().len(), 1);
    }
}

#[test]
fn a_bad_write_index_breaks_the_inbound_ring() {
    let data = ((layout::INBOUND_PAGES - 1) * layout::PAGE) as u32;
    for bad in [13, data, data + 8, !7] {
        let m = Machine::new();
        let q = queues();
        let mut r = up(&m, &q, Setup::default());
        inbound(&m).set_write_index(bad);
        r.host.signal_guest(NETVSC);
        r.run();
        assert_eq!(r.a.stats().broken, 1, "{bad:#x}");
        assert_eq!(
            r.lines[1],
            format!(
                "netvsc: the inbound ring is broken (the host's index {bad:#x}); it is no longer read"
            )
        );
    }
}

#[test]
fn a_bad_read_index_breaks_the_outbound_ring() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    outbound(&m).set_read_index(7);
    r.send(&frame(PEER, 60, 1));
    r.run();
    r.send(&frame(PEER, 60, 2));
    r.run();
    let s = r.a.stats();
    assert_eq!((s.broken, s.sent), (1, 0));
    assert_eq!(
        r.lines[1],
        "netvsc: the outbound ring is broken (the host's index 0x7); it is no longer written"
    );
    // The frames wait in TX_FILLED: none is dropped.
    assert_eq!(r.a.queues().counters().received, 0);
}

#[test]
fn packets_over_4_kib_are_skipped_and_receive_buffer_ones_acknowledged() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    r.nic.inject(kind::INBAND, 0, 1, &[], &[0xAB; 5000]);
    // 520 ranges: a 4,184-byte header.
    let ranges: Vec<(u32, u32)> = (0..520).map(|i| (60, 64 * i)).collect();
    r.nic.inject_rxbuf(nvs::RXBUF_SIG, &ranges, &rndis_body());
    r.nic.deliver(&frame(MAC, 60, 1));
    r.run();
    r.honest();
    let s = r.a.stats();
    assert_eq!((s.skipped, s.ignored), (2, 0));
    // The receive-buffer packet among them was acknowledged; the frame
    // after them arrived.
    assert_eq!(s.acks, s.rxbuf_packets);
    assert_eq!(r.received, [frame(MAC, 60, 1)]);
}

#[test]
fn unknown_types_and_host_notes_are_counted_and_ignored() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    let note = |t| {
        let mut b = words(&[t, 1, 2]);
        b.resize(40, 0);
        b
    };
    r.nic.inject(5, 0, 1, &[], &[0; 8]);
    r.nic.inject(kind::GPA, 0, 2, &[0; 24], &rndis_body());
    r.nic.inject(kind::INBAND, 0, 3, &[], &note(hn::TXTBL_NOTE));
    r.nic
        .inject(kind::INBAND, 0, 4, &[], &note(hn::VFASSOC_NOTE));
    r.nic.inject(kind::INBAND, 0, 5, &[], &[]);
    r.run();
    r.honest();
    let s = r.a.stats();
    assert_eq!((s.ignored, s.acks, s.broken), (5, 4, 0));
}

#[test]
fn completions_of_nothing_are_counted_and_ignored() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(
        &m,
        &q,
        Setup {
            nic: nic::Config {
                hold_completions: true,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    let ack = |s| hvmock::netvsc::rndis_ack(s);
    for xid in [
        999,
        // Setup's, long answered: INIT, the receive buffer, RNDIS's.
        1,
        4,
        u64::from(rndis::request_id(2)),
        // A section past the 128, one not in flight, a 2^32 + 2^32.
        ring::xid::send(128),
        ring::xid::send(3),
        ring::xid::SEND << 1,
        u64::MAX,
    ] {
        r.nic.inject(kind::COMP, 0, xid, &[], &ack(hn::OK));
    }
    r.run();
    assert_eq!(r.a.stats().ignored, 8);
    // A completion with a failed status frees its section, and is
    // counted; the host's own one, later, completes nothing.
    r.send(&frame(PEER, 60, 1));
    r.run();
    assert_eq!(r.a.in_flight(), 1);
    r.nic
        .inject(kind::COMP, 0, ring::xid::send(0), &[], &ack(hn::FAILED));
    r.run();
    assert_eq!(r.a.in_flight(), 0);
    let s = r.a.stats();
    assert_eq!((s.completions, s.ignored), (1, 9));
    r.nic.release(|_| {});
    r.run();
    assert_eq!(r.a.stats().ignored, 10);
    assert_eq!(r.a.stats().completions, 1);
}

#[test]
fn receive_buffer_packets_with_bad_headers_are_ignored_and_acknowledged() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    let good = frame(MAC, 60, 1);
    put(&m, 0x8_0000, &packet_msg(&good, false));
    let range = [(104u32, 0x8_0000u32)];
    let not_rndis = {
        let mut b = words(&[hn::RNDIS_ACK, 1]);
        b.resize(40, 0);
        b
    };
    for (xid, ext, body) in [
        // Another ID.
        (0x7001, rxbuf_ext(0xBEEF, 1, &range), rndis_body()),
        // More ranges than its header holds.
        (0x7002, rxbuf_ext(nvs::RXBUF_SIG, 5, &range), rndis_body()),
        // Not an NVS RNDIS body.
        (0x7003, rxbuf_ext(nvs::RXBUF_SIG, 1, &range), not_rndis),
        // A header too short for the ID and count.
        (0x7004, Vec::new(), rndis_body()),
    ] {
        r.nic.expect_ack(xid);
        r.nic
            .inject(kind::RXBUF, ring::FLAG_COMPLETION, xid, &ext, &body);
    }
    r.run();
    r.honest();
    let s = r.a.stats();
    assert_eq!((s.ignored, s.received), (4, 0));
    assert!(r.received.is_empty());
    // The same range in a good packet is taken.
    r.nic.expect_ack(0x7005);
    r.nic.inject(
        kind::RXBUF,
        ring::FLAG_COMPLETION,
        0x7005,
        &rxbuf_ext(nvs::RXBUF_SIG, 1, &range),
        &rndis_body(),
    );
    r.run();
    r.honest();
    assert_eq!(r.received, [good]);
}

#[test]
fn ranges_outside_the_receive_buffer_are_skipped_and_the_rest_taken() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    let mb = layout::RECEIVE_SIZE as u32;
    let good = frame(MAC, 77, 3);
    let msg = packet_msg(&good, true);
    // At an odd offset: the host picks where a message starts.
    let odd = mb - 4096 + 1;
    put(&m, odd as usize, &msg);
    let n = msg.len() as u32;
    r.nic.inject_rxbuf(
        nvs::RXBUF_SIG,
        &[
            (60, mb - 10),
            (u32::MAX, 16),
            (16, u32::MAX),
            (n, odd),
            (1, mb),
            (0, mb),
            (n, odd),
        ],
        &rndis_body(),
    );
    r.run();
    r.honest();
    let s = r.a.stats();
    // An empty range at the end is inside; its message is too short.
    assert_eq!((s.skipped, s.ignored, s.received), (4, 1, 2));
    assert_eq!(r.received, [good.clone(), good]);
}

/// A valid PACKET_MSG with per-packet information, and every way to
/// spoil it, through `rndis::packet` alone.
#[test]
fn rndis_packet_checks() {
    let f = frame(MAC, 60, 9);
    let check = |m: &[u8]| rndis::packet(&Ram::from_bytes(m));
    let base = packet_msg(&f, true);
    let set = |at: usize, v: u32| {
        let mut m = base.clone();
        m[at..at + 4].copy_from_slice(&v.to_le_bytes());
        m
    };
    // Header: type 0, len 4, data offset 8, data len 12, oob offset 16,
    // oob len 20, oob elements 24, pktinfo offset 28, pktinfo len 32.
    assert_eq!(
        check(&base),
        Ok(Data {
            offset: 76,
            len: 60
        })
    );
    assert_eq!(
        check(&packet_msg(&f, false)),
        Ok(Data {
            offset: 44,
            len: 60
        })
    );
    let n = base.len() as u32;
    for (m, want) in [
        (base[..43].to_vec(), Bad::Short(43)),
        (set(4, n + 1), Bad::Length(n + 1)),
        (set(4, 40), Bad::Length(40)),
        (set(20, 100), Bad::Lengths),
        (set(12, 0), Bad::NoData),
        (set(8, 32), Bad::DataOffset(32)),
        ([set(16, 37), vec![]].concat(), Bad::Oob(37)),
        (set(16, 32), Bad::Oob(32)),
        // Out-of-band data with no offset.
        (set(20, 4), Bad::Oob(0)),
        (set(28, 38), Bad::Pktinfo(38)),
        // Per-packet information into the data.
        (set(32, 36), Bad::Pktinfo(36)),
        // An element of size 0, of 14, past what is left, its data past
        // it.
        (set(44, 0), Bad::Pktinfo(36)),
        (set(44, 14), Bad::Pktinfo(36)),
        (set(44, 36), Bad::Pktinfo(36)),
        (set(52, 17), Bad::Pktinfo(36)),
        // Data past the message.
        (set(8, n), Bad::Data(n)),
        (set(12, 61), Bad::Data(68)),
    ] {
        assert_eq!(check(&m), Err(want), "{want:?}");
    }
    // Out-of-band data over the data, and over the per-packet
    // information, and past the message.
    let oob = |off: u32, len: u32| {
        let mut m = base.clone();
        m.extend_from_slice(&[0; 16]);
        let total = m.len() as u32;
        for (at, v) in [(4, total), (16, off), (20, len)] {
            m[at..at + 4].copy_from_slice(&v.to_le_bytes());
        }
        m
    };
    assert_eq!(check(&oob(68, 4)), Err(Bad::Oob(68)));
    assert_eq!(check(&oob(40, 4)), Err(Bad::Oob(40)));
    assert_eq!(
        check(&oob(128, 8)),
        Ok(Data {
            offset: 76,
            len: 60
        })
    );
    assert_eq!(check(&oob(140, 8)), Err(Bad::Oob(140)));
    // Seventeen elements of 12 bytes: past the most netvsc walks.
    let many = {
        let pi: Vec<u8> = (0..17).flat_map(|_| words(&[12, 0, 12])).collect();
        let mut m = words(&[
            1,
            (44 + pi.len() + f.len()) as u32,
            36 + pi.len() as u32,
            f.len() as u32,
            0,
            0,
            0,
            36,
            pi.len() as u32,
            0,
            0,
        ]);
        m.extend_from_slice(&pi);
        m.extend_from_slice(&f);
        m
    };
    assert_eq!(check(&many), Err(Bad::Pktinfo(36)));
    // Frames of 13 and 1,515 bytes.
    for len in [13, 1515] {
        let mut m = packet_msg(&vec![0xEE; len], false);
        assert_eq!(check(&m), Err(Bad::Frame(len as u32)));
        m.resize(44 + 14, 0xEE);
        m[4..8].copy_from_slice(&58u32.to_le_bytes());
        m[12..16].copy_from_slice(&14u32.to_le_bytes());
        assert!(check(&m).is_ok());
    }
}

/// Bad RNDIS messages through the ring: counted, never delivered, every
/// packet acknowledged.
#[test]
fn bad_rndis_messages_are_ignored() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(&m, &q, Setup::default());
    let f = frame(MAC, 60, 1);
    let base = packet_msg(&f, true);
    let set = |at: usize, v: u32| {
        let mut m = base.clone();
        m[at..at + 4].copy_from_slice(&v.to_le_bytes());
        m
    };
    let bad = [
        set(4, 40),
        set(8, 32),
        set(28, 38),
        set(44, 0),
        set(12, 0),
        // Not a message type netvsc takes; a keepalive; too short.
        words(&[0, 8]),
        words(&[hr::INDICATE_STATUS - 1, 12, 0]),
        words(&[8, 12, 5]),
        words(&[hr::PACKET]),
        status_msg(hr::MEDIA_CONNECT)[..16].to_vec(),
        // A completion when no request is out.
        words(&[hr::QUERY_CMPLT, 30, 2 << 16, 0, 6, 16, 0, 0]),
        words(&[hr::SET_CMPLT, 16, 4 << 16, 0]),
    ];
    let refs: Vec<&[u8]> = bad.iter().map(|b| &b[..]).collect();
    r.nic.inject_rndis(&refs);
    r.nic.deliver(&f);
    r.run();
    r.honest();
    let s = r.a.stats();
    assert_eq!((s.ignored, s.received, s.status), (bad.len() as u64, 1, 0));
    assert_eq!(r.received, [f]);
}

/// A hostile action after setup.
#[derive(Clone, Debug)]
enum Act {
    /// Any packet of any type but a receive-buffer one.
    Packet { kind: u16, xid: u64, body: Vec<u8> },
    /// A completion of something netvsc has not sent.
    Completion { xid: u64, body: Vec<u8> },
    /// A receive-buffer packet with any ID, ranges and body.
    Rxbuf {
        id: u16,
        ranges: Vec<(u32, u32)>,
        rndis: bool,
    },
    /// RNDIS messages: a valid packet's bytes, some changed.
    Rndis(Vec<(usize, u32)>, bool),
    /// Raw words in the receive buffer, where ranges may point.
    Scribble { ofs: u32, bytes: Vec<u8> },
    /// A frame from the network, honestly.
    Frame(usize),
    /// A frame from net.
    Send(usize),
    /// A status indication.
    Status(u32),
}

fn act() -> impl Strategy<Value = Act> {
    let mb = layout::RECEIVE_SIZE as u32;
    let offset = prop_oneof![0..mb, mb - 64..mb + 64, Just(u32::MAX - 3)];
    let range = (prop_oneof![0u32..2000, Just(u32::MAX)], offset.clone());
    prop_oneof![
        (
            prop_oneof![Just(5u16), Just(6), Just(9), Just(12), any::<u16>()],
            any::<u64>(),
            prop::collection::vec(any::<u8>(), 0..64)
        )
            .prop_filter("not a receive-buffer packet or completion", |(k, _, _)| {
                *k != kind::RXBUF && *k != kind::COMP
            })
            .prop_map(|(kind, xid, body)| Act::Packet { kind, xid, body }),
        (
            prop_oneof![
                0u64..0x1_0000,
                Just(1 << 16),
                Just(2 << 16),
                0x1_0000_0080u64..0x1_0000_0100,
                Just(u64::MAX)
            ],
            prop::collection::vec(any::<u8>(), 0..48)
        )
            .prop_map(|(xid, body)| Act::Completion { xid, body }),
        (
            prop_oneof![Just(nvs::RXBUF_SIG), any::<u16>()],
            prop::collection::vec(range, 0..6),
            any::<bool>()
        )
            .prop_map(|(id, ranges, rndis)| Act::Rxbuf { id, ranges, rndis }),
        (
            prop::collection::vec((0usize..30, any::<u32>()), 0..4),
            any::<bool>()
        )
            .prop_map(|(edits, pi)| Act::Rndis(edits, pi)),
        (0..mb - 64, prop::collection::vec(any::<u8>(), 1..64))
            .prop_map(|(ofs, bytes)| Act::Scribble { ofs, bytes }),
        (14usize..=1514).prop_map(Act::Frame),
        (14usize..=1514).prop_map(Act::Send),
        prop_oneof![
            Just(hr::MEDIA_CONNECT),
            Just(hr::MEDIA_DISCONNECT),
            any::<u32>()
        ]
        .prop_map(Act::Status),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 3 } else { 96 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Under any mix of hostile packets after setup, netvsc never panics
    /// or reads outside its windows (each panics on an access outside),
    /// acknowledges every receive-buffer packet once (the device fails a
    /// second, and counts the missing), never breaks the device's rules
    /// for what it sends, and every honest frame arrives in order.
    #[test]
    fn hostile_packets_are_refused_never_followed(acts in prop::collection::vec(act(), 1..if cfg!(miri) { 6 } else { 30 })) {
        let m = Machine::new();
        let q = queues();
        let mut r = up(&m, &q, Setup::default());
        let (mut honest, mut sent) = (Vec::new(), Vec::new());
        for (k, a) in acts.into_iter().enumerate() {
            match a {
                Act::Packet { kind, xid, body } => r.nic.inject(kind, 0, xid, &[], &body),
                Act::Completion { xid, body } => r.nic.inject(kind::COMP, 0, xid, &[], &body),
                Act::Rxbuf { id, ranges, rndis } => {
                    let body = if rndis { rndis_body() } else { words(&[hn::RNDIS_ACK]) };
                    r.nic.inject_rxbuf(id, &ranges, &body);
                }
                Act::Rndis(edits, pi) => {
                    let mut msg = packet_msg(&frame(MAC, 60, k as u64), pi);
                    for (word, v) in edits {
                        let at = 4 * (word % (msg.len() / 4));
                        msg[at..at + 4].copy_from_slice(&v.to_le_bytes());
                    }
                    r.nic.inject_rndis(&[&msg]);
                }
                Act::Scribble { ofs, bytes } => put(&m, ofs as usize, &bytes),
                Act::Frame(len) => {
                    let f = frame(MAC, len, 1000 + k as u64);
                    r.nic.deliver(&f);
                    honest.push(f);
                }
                Act::Send(len) => {
                    let f = frame(PEER, len, 2000 + k as u64);
                    r.send(&f);
                    sent.push(f);
                }
                Act::Status(s) => r.nic.indicate(s),
            }
            r.run();
        }
        r.honest();
        let s = r.a.stats();
        prop_assert_eq!(s.broken, 0);
        prop_assert_eq!(s.acks, s.rxbuf_packets);
        prop_assert_eq!(s.acks_waiting, 0);
        prop_assert_eq!(s.bad_entries, 0);
        let mut at = 0;
        for f in &honest {
            let found = r.received[at..].iter().position(|g| g == f);
            prop_assert!(found.is_some(), "an honest frame lost");
            at += found.unwrap() + 1;
        }
        prop_assert_eq!(r.nic.take_sent(), sent);
    }

    /// Raw bytes anywhere in the inbound ring's data, with any write
    /// index: netvsc reads what parses and breaks the ring at what does
    /// not, and never panics.
    #[test]
    fn raw_ring_bytes_never_panic(
        words in prop::collection::vec(any::<u64>(), 1..if cfg!(miri) { 8 } else { 64 }),
        header in (any::<u16>(), 0u16..8, 0u16..80, any::<u64>()),
    ) {
        let m = Machine::new();
        let q = queues();
        let mut r = up(&m, &q, Setup::default());
        let (kind, hlen, tlen, xid) = header;
        let mut bytes = super::hostile::header(kind, hlen, tlen, xid);
        for w in words {
            bytes.extend_from_slice(&w.to_le_bytes());
        }
        raw(&mut r, &bytes);
        r.run();
        let s = r.a.stats();
        prop_assert!(s.broken <= 1);
        prop_assert!(r.failure.is_none());
    }
}
