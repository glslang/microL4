//! The stack's proptests (`docs/design.md`, "`net`", "Tests", and
//! "Invariants"):
//!
//! - random bytes and random mutations of valid frames, cut at any
//!   length, in sequences: `input` never panics, sends at most three
//!   frames, every one from the stack's MAC and address, never to a zero,
//!   broadcast, multicast or own address (an ARP request's broadcast frame
//!   apart), each with checksums that verify, its padding zero; every
//!   frame is counted once; the cache and the waiting packets stay within
//!   their bounds;
//! - random valid datagrams to port 7, with payloads of 0 to 1,472 bytes,
//!   any source port but 0 and 7, IP options, bytes past the UDP length,
//!   Ethernet padding, with or without a checksum, from the subnet or
//!   beyond the gateway: each echo equals the frame an oracle with its own
//!   checksum code builds;
//! - any single byte of a valid request's IPv4 header changed to any
//!   other value: never answered unless the header is still valid, which
//!   a ones' complement sum makes impossible;
//! - the ARP cache against a model of its replacement and merge rules.

use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use proptest::sample::select;

use super::Wire;
use super::wire::{V4, arp, csum, eth, get16, icmp_echo, ones_sum, padded, udp, udp_checksum};
use crate::arp::{CACHE, Cache, State};
use crate::{Config, Ip, Mac, Outcome, Stack, Stats};

const US: [u8; 4] = [10, 0, 2, 15];
const GW: [u8; 4] = [10, 0, 2, 2];
const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

/// Addresses frames come from or go to: peers, the gateway, beyond it,
/// more than the cache holds, and every address the stack must refuse.
const ADDRS: &[[u8; 4]] = &[
    GW,
    [10, 0, 2, 3],
    [10, 0, 2, 4],
    [10, 0, 2, 5],
    [10, 0, 2, 6],
    [10, 0, 2, 7],
    [10, 0, 2, 8],
    [10, 0, 2, 9],
    [10, 0, 2, 10],
    [10, 0, 2, 11],
    [8, 8, 8, 8],
    [192, 168, 1, 1],
    US,
    [0, 0, 0, 0],
    [255, 255, 255, 255],
    [10, 0, 2, 255],
    [10, 0, 2, 0],
    [224, 0, 0, 1],
    [239, 1, 2, 3],
];

const MACS: &[[u8; 6]] = &[
    GW_MAC,
    [0x02, 0, 0, 0, 0, 3],
    [0x02, 0, 0, 0, 0, 4],
    [0x02, 0, 0, 0, 0, 5],
    MAC,
    [0xFF; 6],
    [0x01, 0x00, 0x5E, 0, 0, 1],
    [0; 6],
];

fn stack() -> Stack {
    Stack::new(Config::QEMU, Mac(MAC))
}

/// A valid frame of some kind, before any mutation.
#[derive(Clone, Debug)]
enum Valid {
    Arp {
        op: u16,
        dst: [u8; 6],
        sha: [u8; 6],
        spa: [u8; 4],
        tpa: [u8; 4],
    },
    Icmp {
        dst_mac: [u8; 6],
        src: [u8; 4],
        dst: [u8; 4],
        kind: u8,
        ident: u16,
        seq: u16,
        data: Vec<u8>,
    },
    Udp {
        dst_mac: [u8; 6],
        src: [u8; 4],
        dst: [u8; 4],
        sport: u16,
        dport: u16,
        payload: Vec<u8>,
        checksum: bool,
    },
}

impl Valid {
    fn frame(&self) -> Vec<u8> {
        match self {
            Valid::Arp {
                op,
                dst,
                sha,
                spa,
                tpa,
            } => eth(*dst, *sha, 0x0806, &arp(*op, *sha, *spa, [0; 6], *tpa)),
            Valid::Icmp {
                dst_mac,
                src,
                dst,
                kind,
                ident,
                seq,
                data,
            } => eth(
                *dst_mac,
                GW_MAC,
                0x0800,
                &V4::new(*src, *dst, 1).packet(&icmp_echo(*kind, *ident, *seq, data)),
            ),
            Valid::Udp {
                dst_mac,
                src,
                dst,
                sport,
                dport,
                payload,
                checksum,
            } => eth(
                *dst_mac,
                GW_MAC,
                0x0800,
                &V4::new(*src, *dst, 17)
                    .packet(&udp(*src, *dst, *sport, *dport, payload, *checksum)),
            ),
        }
    }
}

fn addr() -> impl Strategy<Value = [u8; 4]> {
    prop_oneof![
        6 => select(&ADDRS[..12]),
        1 => select(ADDRS),
        1 => any::<[u8; 4]>(),
    ]
}

fn mac() -> impl Strategy<Value = [u8; 6]> {
    prop_oneof![
        6 => select(&MACS[..4]),
        1 => select(MACS),
        1 => any::<[u8; 6]>(),
    ]
}

fn dst_mac() -> impl Strategy<Value = [u8; 6]> {
    prop_oneof![
        8 => Just(MAC),
        2 => Just([0xFF; 6]),
        1 => mac(),
    ]
}

fn dst_ip() -> impl Strategy<Value = [u8; 4]> {
    prop_oneof![
        8 => Just(US),
        1 => Just([255; 4]),
        1 => addr(),
    ]
}

fn bytes(max: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(any::<u8>(), 0..=max)
}

fn valid() -> impl Strategy<Value = Valid> {
    let max = if cfg!(miri) { 24 } else { 1472 };
    prop_oneof![
        (
            select(&[1u16, 2][..]),
            prop_oneof![Just([0xFF; 6]), dst_mac()],
            mac(),
            addr(),
            prop_oneof![3 => Just(US), 1 => addr()]
        )
            .prop_map(|(op, dst, sha, spa, tpa)| Valid::Arp {
                op,
                dst,
                sha,
                spa,
                tpa
            }),
        (
            dst_mac(),
            addr(),
            dst_ip(),
            prop_oneof![4 => Just(8u8), 2 => Just(0u8), 1 => any::<u8>()],
            prop_oneof![Just(0x4C34u16), any::<u16>()],
            prop_oneof![Just(1u16), any::<u16>()],
            bytes(max),
        )
            .prop_map(|(dst_mac, src, dst, kind, ident, seq, mut data)| {
                // Keep the packet inside one frame.
                data.truncate(1472);
                Valid::Icmp {
                    dst_mac,
                    src,
                    dst,
                    kind,
                    ident,
                    seq,
                    data,
                }
            }),
        (
            dst_mac(),
            addr(),
            dst_ip(),
            prop_oneof![1 => Just(0u16), 1 => Just(7u16), 6 => any::<u16>()],
            prop_oneof![6 => Just(7u16), 1 => any::<u16>()],
            bytes(max),
            any::<bool>(),
        )
            .prop_map(
                |(dst_mac, src, dst, sport, dport, payload, checksum)| Valid::Udp {
                    dst_mac,
                    src,
                    dst,
                    sport,
                    dport,
                    payload,
                    checksum,
                }
            ),
    ]
}

/// A change to a valid frame.
#[derive(Clone, Debug)]
enum Mutation {
    None,
    /// Set byte `at` (modulo the length) to `value`.
    Set(usize, u8),
    /// Cut the frame to `at` (modulo its length plus one) bytes.
    Cut(usize),
    /// Add bytes at the end.
    Pad(Vec<u8>),
}

fn mutation() -> impl Strategy<Value = Mutation> {
    prop_oneof![
        4 => Just(Mutation::None),
        4 => (any::<usize>(), any::<u8>()).prop_map(|(a, v)| Mutation::Set(a, v)),
        2 => any::<usize>().prop_map(Mutation::Cut),
        1 => bytes(64).prop_map(Mutation::Pad),
    ]
}

/// One input: a mutated valid frame, or random bytes.
fn input() -> impl Strategy<Value = Vec<u8>> {
    let random = if cfg!(miri) { 80 } else { 1600 };
    prop_oneof![
        8 => (valid(), prop::collection::vec(mutation(), 0..4)).prop_map(|(v, ms)| {
            let mut f = v.frame();
            for m in ms {
                match m {
                    Mutation::None => {}
                    Mutation::Set(at, value) => {
                        if !f.is_empty() {
                            let i = at % f.len();
                            f[i] = value;
                        }
                    }
                    Mutation::Cut(at) => f.truncate(at % (f.len() + 1)),
                    Mutation::Pad(p) => f.extend_from_slice(&p),
                }
            }
            f
        }),
        1 => bytes(random),
        1 => bytes(60).prop_map(|mut b| {
            // Random bytes, but to the stack's MAC as IPv4 or ARP.
            let mut f = MAC.to_vec();
            f.extend_from_slice(&GW_MAC);
            f.extend_from_slice(if b.first().is_some_and(|x| x & 1 == 0) {
                &[8, 0]
            } else {
                &[8, 6]
            });
            f.append(&mut b);
            f
        }),
    ]
}

/// Not 0, a broadcast, multicast or the stack's own address.
fn is_peer(ip: [u8; 4]) -> bool {
    ip != [0; 4] && ip != [255; 4] && ip[0] >> 4 != 0xE && ip != US && ip != [10, 0, 2, 255]
}

fn is_unicast_mac(m: &[u8]) -> bool {
    m[0] & 1 == 0 && m[..6] != [0; 6]
}

/// Checks one frame the stack sent.
fn check_sent(f: &[u8]) -> Result<(), TestCaseError> {
    prop_assert!(f.len() >= 60, "a {}-byte frame, not padded", f.len());
    prop_assert_eq!(&f[6..12], &MAC[..], "a frame from another MAC");
    let body = &f[14..];
    match get16(f, 12) {
        0x0806 => {
            prop_assert!(f.len() == 60);
            prop_assert_eq!(&body[..8], &[0, 1, 8, 0, 6, 4, 0, get16(body, 6) as u8][..]);
            prop_assert_eq!(&body[8..14], &MAC[..]);
            prop_assert_eq!(&body[14..18], &US[..]);
            let tpa: [u8; 4] = body[24..28].try_into().unwrap();
            prop_assert!(is_peer(tpa), "ARP for {:?}", tpa);
            match get16(body, 6) {
                1 => {
                    prop_assert_eq!(&f[..6], &[0xFF; 6][..]);
                    prop_assert_eq!(&body[18..24], &[0; 6][..]);
                }
                2 => {
                    prop_assert!(is_unicast_mac(&f[..6]) && f[..6] != MAC);
                    prop_assert_eq!(&f[..6], &body[18..24]);
                }
                op => prop_assert!(false, "ARP op {}", op),
            }
            prop_assert!(body[28..].iter().all(|&b| b == 0), "padding not zero");
        }
        0x0800 => {
            prop_assert!(is_unicast_mac(&f[..6]) && f[..6] != MAC);
            prop_assert_eq!(body[0], 0x45);
            prop_assert_eq!(body[1], 0);
            let total = usize::from(get16(body, 2));
            prop_assert!(total >= 28 && total <= body.len() && total <= 1500);
            prop_assert_eq!(get16(body, 6), 0x4000);
            prop_assert_eq!(body[8], 64);
            prop_assert_eq!(ones_sum(&body[..20]), 0xFFFF, "a bad header checksum");
            prop_assert_eq!(&body[12..16], &US[..]);
            let dst: [u8; 4] = body[16..20].try_into().unwrap();
            prop_assert!(is_peer(dst), "a packet to {:?}", dst);
            let l4 = &body[20..total];
            match body[9] {
                1 => {
                    prop_assert!(l4[0] == 0 || l4[0] == 8);
                    prop_assert_eq!(l4[1], 0);
                    prop_assert_eq!(ones_sum(l4), 0xFFFF, "a bad ICMP checksum");
                }
                17 => {
                    prop_assert_eq!(usize::from(get16(l4, 4)), l4.len());
                    prop_assert_eq!(get16(l4, 0), 7);
                    let dport = get16(l4, 2);
                    prop_assert!(dport != 0 && dport != 7, "an echo to port {}", dport);
                    let mut d = l4.to_vec();
                    d[6] = 0;
                    d[7] = 0;
                    prop_assert_eq!(udp_checksum(US, dst, &d), get16(l4, 6));
                }
                p => prop_assert!(false, "protocol {}", p),
            }
            prop_assert!(body[total..].iter().all(|&b| b == 0), "padding not zero");
        }
        t => prop_assert!(false, "EtherType {:#x}", t),
    }
    Ok(())
}

/// The bounds that hold after every input.
fn check_state(stack: &Stack, inputs: u64) -> Result<(), TestCaseError> {
    let s = stack.stats();
    prop_assert_eq!(s.frames_in, inputs);
    let sum: u64 = Outcome::ALL.iter().map(|&o| s.outcome(o)).sum();
    prop_assert_eq!(sum, s.frames_in, "a frame counted {} times", sum);
    prop_assert!(stack.cache().len() <= CACHE);
    prop_assert!(stack.waiting() <= 4);
    for hop in stack.waiting_for() {
        prop_assert_eq!(stack.cache().peek(hop), Some(State::Pending));
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 1024 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_and_mutated_frames_keep_the_invariants(
        start in any::<bool>(),
        tx_limit in prop_oneof![4 => Just(None), 1 => (0usize..4).prop_map(Some)],
        inputs in prop::collection::vec(input(), 1..if cfg!(miri) { 4 } else { 48 }),
    ) {
        let mut stack = stack();
        let mut wire = Wire::new();
        if start {
            stack.start(&mut wire);
        }
        wire.take();
        let mut sent_before = stack.stats().frames_out;
        for (n, f) in inputs.iter().enumerate() {
            wire.free = tx_limit;
            stack.input(f, &mut wire);
            let sent = wire.take();
            prop_assert!(sent.len() <= 3, "{} frames for one input", sent.len());
            prop_assert_eq!(stack.stats().frames_out - sent_before, sent.len() as u64);
            sent_before = stack.stats().frames_out;
            for s in &sent {
                check_sent(s)?;
            }
            check_state(&stack, n as u64 + 1)?;
            while stack.event().is_some() {}
        }
    }
}

/// A datagram the echo test sends.
#[derive(Clone, Debug)]
struct Datagram {
    sport: u16,
    payload: Vec<u8>,
    checksum: bool,
    /// IP options, in 4-byte words.
    options: Vec<u8>,
    /// Bytes inside the IP payload past the UDP length.
    trailer: Vec<u8>,
    /// Bytes after the packet in the frame.
    padding: Vec<u8>,
    /// The request's IP identification.
    ident: u16,
}

fn payload_len() -> impl Strategy<Value = usize> {
    if cfg!(miri) {
        return prop_oneof![Just(0usize), Just(1), Just(17), Just(18)].boxed();
    }
    prop_oneof![
        1 => select(&[0usize, 1, 8, 9, 17, 18, 19, 64, 255, 256, 512, 952, 953, 1471, 1472][..]),
        2 => 0usize..=1472,
    ]
    .boxed()
}

fn datagram() -> impl Strategy<Value = Datagram> {
    (
        prop_oneof![Just(1u16), Just(8u16), Just(65535u16), 1u16..=65535],
        payload_len(),
        any::<u8>(),
        any::<bool>(),
        0usize..=10,
        bytes(if cfg!(miri) { 4 } else { 40 }),
        bytes(if cfg!(miri) { 4 } else { 40 }),
        any::<u16>(),
    )
        .prop_filter("source port 7", |d| d.0 != 7)
        .prop_map(
            |(sport, len, seed, checksum, words, trailer, padding, ident)| {
                let payload = (0..len).map(|j| seed.wrapping_add((3 * j) as u8)).collect();
                Datagram {
                    sport,
                    payload,
                    checksum,
                    options: vec![1; 4 * words],
                    trailer,
                    padding,
                    ident,
                }
            },
        )
}

/// The peers echoes go to: their address, the MAC frames to them go to,
/// and the ARP frame that tells the stack the MAC.
fn peer(i: u8) -> ([u8; 4], [u8; 6], Vec<u8>) {
    let (src, mac) = match i % 3 {
        // In the subnet: its own ARP request for the stack.
        0 => ([10, 0, 2, 3 + i], [0x02, 0, 0, 0, 0, 3 + i]),
        // Beyond the gateway.
        1 => ([93, 184, 216, i], GW_MAC),
        _ => (GW, GW_MAC),
    };
    let learn = if mac == GW_MAC {
        // The gateway's reply to the stack's request.
        eth(MAC, GW_MAC, 0x0806, &arp(2, GW_MAC, GW, MAC, US))
    } else {
        eth([0xFF; 6], mac, 0x0806, &arp(1, mac, src, [0; 6], US))
    };
    (src, mac, learn)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 3 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn every_echo_equals_the_oracles(
        who in 0u8..9,
        datagrams in prop::collection::vec(datagram(), 1..if cfg!(miri) { 2 } else { 8 }),
    ) {
        let (src, peer_mac, learn) = peer(who);
        let mut stack = stack();
        let mut wire = Wire::new();
        stack.input(&learn, &mut wire);
        wire.take();
        for (ident, d) in (1u16..).zip(&datagrams) {
            let mut l4 = udp(src, US, d.sport, 7, &d.payload, d.checksum);
            l4.extend_from_slice(&d.trailer);
            let v4 = V4 { ident: d.ident, options: d.options.clone(), ..V4::new(src, US, 17) };
            let mut packet = v4.packet(&l4);
            if packet.len() > 1500 {
                // Options and trailer past the MTU: keep the payload.
                packet = V4::new(src, US, 17).packet(&udp(src, US, d.sport, 7, &d.payload, d.checksum));
            }
            let mut frame = eth(MAC, peer_mac, 0x0800, &packet);
            if frame.len() + d.padding.len() <= 1514 {
                frame.extend_from_slice(&d.padding);
            }
            stack.input(&frame, &mut wire);
            let sent = wire.take();
            let reply = V4 { ident, ..V4::new(US, src, 17) }
                .packet(&udp(US, src, 7, d.sport, &d.payload, true));
            let expect = padded(eth(peer_mac, MAC, 0x0800, &reply));
            prop_assert_eq!(sent, vec![expect]);
        }
        let s = stack.stats();
        prop_assert_eq!(s.udp_received, datagrams.len() as u64);
        prop_assert_eq!(s.udp_echoed, datagrams.len() as u64);
        prop_assert_eq!(s.dropped(), 0);
    }
}

/// The oracle's verdict on an IPv4 header: would the stack take it?
fn header_valid(p: &[u8], frame_payload: usize) -> bool {
    if p.len() < 20 || p[0] >> 4 != 4 {
        return false;
    }
    let hl = usize::from(p[0] & 0xF) * 4;
    let total = usize::from(get16(p, 2));
    hl >= 20
        && hl <= p.len()
        && total >= hl
        && total <= frame_payload
        && ones_sum(&p[..hl]) == 0xFFFF
        && get16(p, 6) & 0x3FFF == 0
        && (p[16..20] == US || p[16..20] == [255; 4])
        && is_peer(p[12..16].try_into().unwrap())
        && (p[9] == 1 || p[9] == 17)
}

#[test]
fn a_changed_header_byte_is_never_answered() {
    let requests = [
        V4::new(GW, US, 1).packet(&icmp_echo(8, 0x77, 3, b"ping data")),
        V4::new(GW, US, 17).packet(&udp(GW, US, 4000, 7, b"echo me", true)),
        V4 {
            options: vec![0x94, 4, 0, 0],
            ..V4::new(GW, US, 17)
        }
        .packet(&udp(GW, US, 4000, 7, b"with options", false)),
    ];
    let resolve = eth(MAC, GW_MAC, 0x0806, &arp(2, GW_MAC, GW, MAC, US));
    for packet in &requests {
        let mut base = stack();
        let mut wire = Wire::new();
        base.input(&resolve, &mut wire);
        wire.take();
        // Unchanged, it is answered.
        let mut s = base.clone();
        s.input(&eth(MAC, GW_MAC, 0x0800, packet), &mut wire);
        assert_eq!(wire.take().len(), 1);
        let hl = usize::from(packet[0] & 0xF) * 4;
        let positions: Vec<usize> = if cfg!(miri) {
            vec![0, 2, 9, 10, hl - 1]
        } else {
            (0..hl).collect()
        };
        for at in positions {
            let values: Vec<u8> = if cfg!(miri) {
                vec![packet[at] ^ 1, packet[at] ^ 0x80, !packet[at]]
            } else {
                (0..=255).filter(|&v| v != packet[at]).collect()
            };
            for v in values {
                let mut p = packet.clone();
                p[at] = v;
                let valid = header_valid(&p, p.len());
                assert!(
                    !valid,
                    "byte {at} = {v:#04x} left a header that verifies: {p:02x?}"
                );
                let mut s = base.clone();
                s.input(&eth(MAC, GW_MAC, 0x0800, &p), &mut wire);
                assert_eq!(
                    wire.take(),
                    Vec::<Vec<u8>>::new(),
                    "byte {at} of the header set to {v:#04x} was answered"
                );
                assert_eq!(s.stats().frames_in, 2);
                assert!(s.stats().dropped() == 1, "{:?}", s.stats());
            }
        }
    }
}

#[test]
fn the_oracles_checksum_agrees_on_rfc_1071s_example() {
    assert_eq!(
        ones_sum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
        0xddf2
    );
    assert_eq!(
        csum(&[0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7]),
        0x220d
    );
}

/// The cache's model: entries least recently used first.
#[derive(Default)]
struct Model(Vec<(Ip, State)>);

impl Model {
    fn find(&self, ip: Ip) -> Option<usize> {
        self.0.iter().position(|e| e.0 == ip)
    }

    fn touch(&mut self, i: usize) -> State {
        let e = self.0.remove(i);
        self.0.push(e);
        e.1
    }
}

#[derive(Clone, Debug)]
enum Op {
    Lookup(u8),
    Peek(u8),
    Merge(u8, u8),
    Insert(u8, Option<u8>),
}

fn op() -> impl Strategy<Value = Op> {
    let ip = 0u8..14;
    prop_oneof![
        ip.clone().prop_map(Op::Lookup),
        ip.clone().prop_map(Op::Peek),
        (ip.clone(), any::<u8>()).prop_map(|(i, m)| Op::Merge(i, m)),
        (ip, prop::option::of(any::<u8>())).prop_map(|(i, m)| Op::Insert(i, m)),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn the_arp_cache_follows_its_model(ops in prop::collection::vec(op(), 0..if cfg!(miri) { 16 } else { 200 })) {
        let ip = |i: u8| Ip::new(10, 0, 2, 100 + i);
        let state = |m: Option<u8>| m.map_or(State::Pending, |m| State::Resolved(Mac([2, 0, 0, 0, 0, m])));
        let mut cache = Cache::new();
        let mut model = Model::default();
        for o in ops {
            match o {
                Op::Lookup(i) => {
                    let want = model.find(ip(i)).map(|k| model.touch(k));
                    prop_assert_eq!(cache.lookup(ip(i)), want);
                }
                Op::Peek(i) => {
                    let want = model.find(ip(i)).map(|k| model.0[k].1);
                    prop_assert_eq!(cache.peek(ip(i)), want);
                }
                Op::Merge(i, m) => {
                    let s = state(Some(m));
                    let want = match model.find(ip(i)) {
                        Some(k) => {
                            model.0[k].1 = s;
                            model.touch(k);
                            true
                        }
                        None => false,
                    };
                    prop_assert_eq!(cache.merge(ip(i), Mac([2, 0, 0, 0, 0, m])), want);
                }
                Op::Insert(i, m) => {
                    if model.find(ip(i)).is_some() {
                        continue;
                    }
                    let evicted = (model.0.len() == CACHE).then(|| model.0.remove(0).0);
                    model.0.push((ip(i), state(m)));
                    prop_assert_eq!(cache.insert(ip(i), state(m)), evicted);
                }
            }
            let entries: Vec<(Ip, State)> = cache.entries().collect();
            prop_assert_eq!(&entries, &model.0);
            prop_assert_eq!(cache.len(), model.0.len());
        }
    }
}

/// Stats' words carry every counter.
#[test]
fn stats_survive_their_words() {
    let mut w = [0u64; Stats::WORDS];
    for (i, x) in w.iter_mut().enumerate() {
        *x = 1000 + i as u64;
    }
    assert_eq!(Stats::from_words(w).to_words(), w);
}
