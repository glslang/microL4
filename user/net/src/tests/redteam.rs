//! M9's red-team pass on the stack (`docs/redteam/m9-martian-sources.md`,
//! `docs/redteam/m9-echo-service-loop.md`): what a frame from the wire
//! makes `net` answer.
//!
//! The two findings' tests failed until the fix round (Ip::is_unicast,
//! udp::FIRST_CLIENT_PORT); they now pass and stay as regressions. The
//! rest are the pass's strongest attacks that held, kept as ordinary
//! tests: pings of every length, total-length lies, and checksums that
//! sum to 0 or `0xFFFF`.

use std::vec::Vec;

use super::Wire;
use super::wire::{V4, arp, csum, eth, get16, icmp_echo, ones_sum, put16, udp};
use crate::{Config, Mac, Stack};

const US: [u8; 4] = [10, 0, 2, 15];
const GW: [u8; 4] = [10, 0, 2, 2];
const MAC: [u8; 6] = [0x52, 0x54, 0x00, 0x12, 0x34, 0x56];
const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
const PEER: [u8; 4] = [10, 0, 2, 3];
const PEER_MAC: [u8; 6] = [0x02, 0, 0, 0, 0, 3];

/// A stack whose gateway has resolved and been pinged: what it sends next
/// answers only what the test feeds it.
fn up() -> (Stack, Wire) {
    let mut s = Stack::new(Config::QEMU, Mac(MAC));
    let mut w = Wire::new();
    s.start(&mut w);
    let reply = arp(2, GW_MAC, GW, MAC, US);
    s.input(&eth(MAC, GW_MAC, 0x0806, &reply), &mut w);
    w.take();
    (s, w)
}

/// An echo request from `src`, at `src_mac`, to the stack.
fn ping(src: [u8; 4], src_mac: [u8; 6], data: &[u8]) -> Vec<u8> {
    let ip = V4::new(src, US, 1).packet(&icmp_echo(8, 0x77, 1, data));
    eth(MAC, src_mac, 0x0800, &ip)
}

/// A datagram from `src`:`sport` to the stack's port 7.
fn datagram(src: [u8; 4], src_mac: [u8; 6], sport: u16, payload: &[u8]) -> Vec<u8> {
    let ip = V4::new(src, US, 17).packet(&udp(src, US, sport, 7, payload, true));
    eth(MAC, src_mac, 0x0800, &ip)
}

/// The IPv4 destination of a frame the stack sent, if it is IPv4.
fn ip_dst(f: &[u8]) -> Option<[u8; 4]> {
    (get16(f, 12) == 0x0800).then(|| f[30..34].try_into().unwrap())
}

/// Sources RFC 1122 (3.2.1.3) says a host MUST silently discard: loopback
/// (127/8, "MUST NOT appear outside a host"), "this network" with a
/// non-zero host (0/8), and class E (240/4, reserved; 255.255.255.255
/// apart). `Stack::is_peer` took them as peers until the fix round,
/// answering their pings and datagrams through the gateway and caching
/// them from ARP; it now uses `Ip::is_unicast`, as `Config::new` does.
const MARTIANS: &[[u8; 4]] = &[
    [127, 0, 0, 1],
    [127, 1, 2, 3],
    [0, 1, 2, 3],
    [240, 0, 0, 1],
    [255, 255, 255, 254],
];

#[test]
fn martian_sources_are_never_answered() {
    let (mut answered, mut learnt) = (Vec::new(), Vec::new());
    for &src in MARTIANS {
        let (mut s, mut w) = up();
        s.input(&ping(src, PEER_MAC, b"martian"), &mut w);
        s.input(&datagram(src, PEER_MAC, 4000, b"martian"), &mut w);
        for f in w.take() {
            if let Some(dst) = ip_dst(&f) {
                answered.push((src, dst, f[14 + 9]));
            }
        }
        // ARP: a request for our address from a martian sender is
        // answered and its sender cached.
        let req = arp(1, PEER_MAC, src, [0; 6], US);
        s.input(&eth([0xFF; 6], PEER_MAC, 0x0806, &req), &mut w);
        let arp_answered = !w.take().is_empty();
        let cached = s.cache().peek(crate::Ip(src)).is_some();
        if arp_answered || cached {
            learnt.push((src, arp_answered, cached));
        }
    }
    assert!(
        answered.is_empty() && learnt.is_empty(),
        "{} packets sent to martian sources (source, destination, protocol): {answered:?}; \
         ARP requests from martian senders (sender, answered, cached): {learnt:?}",
        answered.len()
    );
}

/// The UDP small services an echo can loop with: chargen (19) answers
/// every datagram with 0 to 512 bytes, daytime (13), qotd (17) and time
/// (37) with a line or a word, each to the datagram's source port. A
/// datagram to the stack's port 7 from one of them, its source spoofed by
/// anyone, is echoed back to that service, whose answer comes back to
/// port 7 from the same port and is echoed again, forever: the
/// echo-chargen loop (CVE-1999-0103, "Fraggle"). The stack refused only
/// source ports 0 and 7 until the fix round; it now refuses every one
/// below `udp::FIRST_CLIENT_PORT` (`Outcome::UdpRefused`).
#[test]
fn one_spoofed_datagram_cannot_start_an_endless_loop() {
    let (mut s, mut w) = up();
    // PEER is resolved: it asks first, as a host on the subnet would.
    let req = arp(1, PEER_MAC, PEER, [0; 6], US);
    s.input(&eth([0xFF; 6], PEER_MAC, 0x0806, &req), &mut w);
    w.take();
    // The attacker's one frame: from PEER's chargen port, spoofed.
    let mut next = datagram(PEER, PEER_MAC, 19, b"x");
    let mut rounds = 0;
    for _ in 0..1000 {
        s.input(&next, &mut w);
        let sent = w.take();
        let Some(echo) = sent.iter().find(|f| ip_dst(f) == Some(PEER)) else {
            break;
        };
        rounds += 1;
        let udp_at = 14 + 20;
        assert_eq!(get16(echo, udp_at), 7, "from port 7");
        let dport = get16(echo, udp_at + 2);
        // PEER's chargen answers to the echo's source, port 7, from the
        // port the echo went to: 72 bytes of its pattern each time.
        let line: Vec<u8> = (0..72).map(|i| b' ' + ((rounds + i) % 95) as u8).collect();
        next = datagram(PEER, PEER_MAC, dport, &line);
    }
    assert!(
        rounds <= 1,
        "the stack echoed {rounds} times to {PEER:?}'s chargen port from one spoofed datagram ({} datagrams echoed)",
        s.stats().udp_echoed
    );
}

/// The oracle's echo reply to `request` (a frame [`ping`] built from
/// PEER, which is resolved): the stack's next identification `ident`.
fn echo_reply(request: &[u8], ident: u16) -> Vec<u8> {
    let ip = &request[14..];
    let hl = usize::from(ip[0] & 0xF) * 4;
    let total = usize::from(get16(ip, 2));
    let mut m = ip[hl..total].to_vec();
    m[0] = 0;
    put16(&mut m, 2, 0);
    let c = csum(&m);
    put16(&mut m, 2, c);
    let mut v = V4::new(US, PEER, 1);
    v.ident = ident;
    let mut f = eth(PEER_MAC, MAC, 0x0800, &v.packet(&m));
    if f.len() < 60 {
        f.resize(60, 0);
    }
    f
}

#[test]
fn pings_of_every_length_are_echoed_exactly_and_only_once() {
    let (mut s, mut w) = up();
    let req = arp(1, PEER_MAC, PEER, [0; 6], US);
    s.input(&eth([0xFF; 6], PEER_MAC, 0x0806, &req), &mut w);
    w.take();
    // up() sent the ping (identification 1); the next is 2.
    let mut ident = 2u16;
    let mut answered = 0;
    // Under Miri every 61st length, the ends included.
    let step = if cfg!(miri) { 61 } else { 1 };
    for len in (0..=1472usize).step_by(step).chain([1472]) {
        let data: Vec<u8> = (0..len).map(|i| (i * 7 + len) as u8).collect();
        let f = ping(PEER, PEER_MAC, &data);
        s.input(&f, &mut w);
        let sent = w.take();
        assert_eq!(sent.len(), 1, "a ping of {len} bytes");
        assert_eq!(sent[0], echo_reply(&f, ident), "the echo of {len} bytes");
        assert!(
            sent[0].len() <= f.len().max(60),
            "a reply larger than its request"
        );
        ident = ident.wrapping_add(1);
        answered += 1;
    }
    // 1,473 bytes of data make a 1,501-byte packet, a frame past 1,514.
    let f = ping(PEER, PEER_MAC, &[0u8; 1473]);
    s.input(&f, &mut w);
    assert!(w.take().is_empty(), "a frame of {} bytes answered", f.len());
    assert_eq!(s.stats().icmp_answered, answered);
}

#[test]
fn total_length_lies_are_never_answered_and_never_read_past() {
    let (mut s, mut w) = up();
    let req = arp(1, PEER_MAC, PEER, [0; 6], US);
    s.input(&eth([0xFF; 6], PEER_MAC, 0x0806, &req), &mut w);
    w.take();
    let honest = ping(PEER, PEER_MAC, &[0x5A; 64]);
    let total = honest.len() - 14;
    // Under Miri the lengths around the honest one and a few far ones.
    let claims: Vec<u16> = if cfg!(miri) {
        (0..=100).chain([1500, 1514, u16::MAX]).collect()
    } else {
        (0..=u16::MAX).collect()
    };
    for claim in claims {
        let mut f = honest.clone();
        put16(&mut f, 14 + 2, claim);
        put16(&mut f, 14 + 10, 0);
        let c = csum(&f[14..34]);
        put16(&mut f, 14 + 10, c);
        // And the frame cut short: whole, one byte short, at the ICMP
        // header's end and at the IPv4 header's.
        for cut in [total, total - 1, 28, 20] {
            let frame = &f[..14 + cut];
            s.input(frame, &mut w);
            let sent = w.take();
            let claim = usize::from(claim);
            if claim == total && cut == total {
                assert_eq!(sent.len(), 1);
                continue;
            }
            // Shorter claims cut the ICMP message, whose checksum then
            // fails; longer ones run past the frame. Only a claim equal
            // to the message's length, or one shorter that happens to
            // checksum, may be answered, and then only with what the
            // claim covers.
            for r in &sent {
                let rt = usize::from(get16(r, 16));
                assert!(
                    rt <= claim && claim <= cut,
                    "claim {claim} in a {cut}-byte packet answered with {rt} bytes"
                );
            }
        }
    }
}

#[test]
fn checksums_that_sum_to_0_or_0xffff_verify_either_way() {
    let (mut s, mut w) = up();
    let req = arp(1, PEER_MAC, PEER, [0; 6], US);
    s.input(&eth([0xFF; 6], PEER_MAC, 0x0806, &req), &mut w);
    w.take();
    // An echo request whose words other than the checksum sum to 0xFFFF:
    // type 8 code 0 (0x0800), identifier 0xF7FF, so the checksum is 0
    // computed, and 0xFFFF, its other representation of zero, verifies
    // as well.
    let mut m = icmp_echo(8, 0xF7FF, 0, &[]);
    assert_eq!(get16(&m, 2), 0, "the computed checksum");
    for field in [0x0000, 0xFFFF] {
        put16(&mut m, 2, field);
        assert_eq!(ones_sum(&m), 0xFFFF);
        let ip = V4::new(PEER, US, 1).packet(&m);
        s.input(&eth(MAC, PEER_MAC, 0x0800, &ip), &mut w);
        let sent = w.take();
        assert_eq!(sent.len(), 1, "checksum field {field:#06x}");
        // The reply (type 0) sums to 0xF7FF, so its checksum is 0x0800.
        assert_eq!(get16(&sent[0], 14 + 20 + 2), 0x0800);
        assert_eq!(ones_sum(&sent[0][34..42]), 0xFFFF);
    }
}
