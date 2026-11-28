//! A model network behind the model device, playing libslirp's part in
//! QEMU's user networking (`docs/design.md`, "`virtio-net`", "Tests";
//! everything said here of libslirp is from memory): the gateway
//! `10.0.2.2`, at `52:55:0a:00:02:02`, answers ARP requests for its
//! address and reflects ICMP echo requests sent to it, and the host sends
//! UDP datagrams from the gateway's address to `10.0.2.15` port 7, as the
//! forwarded port does, and collects what comes back.
//!
//! It learns the guest's MAC from the guest's ARP packets, as libslirp's
//! ARP table does; a datagram for a guest it has no MAC for waits behind
//! an ARP request of its own, sent once the guest answers. It checks
//! every frame the guest sends with its own checksum code, written here
//! from RFC 1071 and RFC 768, and counts and drops what libslirp would
//! drop: a bad IPv4 header, ICMP or UDP checksum, or a frame not to it.

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

/// The gateway's address and MAC.
pub const GATEWAY: [u8; 4] = [10, 0, 2, 2];
pub const GATEWAY_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];
/// The guest's address.
pub const GUEST: [u8; 4] = [10, 0, 2, 15];
/// Where the forwarded port's datagrams go.
pub const ECHO_PORT: u16 = 7;

const BROADCAST: [u8; 6] = [0xFF; 6];

/// RFC 1071's ones' complement sum of `parts`, as one byte string, an odd
/// last byte padded with 0, folded and complemented.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let bytes: Vec<u8> = parts.concat();
    let mut sum: u32 = 0;
    for pair in bytes.chunks(2) {
        let hi = u32::from(pair[0]) << 8;
        let lo = pair.get(1).copied().map_or(0, u32::from);
        sum += hi | lo;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

/// What the network counted.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    pub arp_answered: u64,
    pub pings_answered: u64,
    /// Frames it dropped: a bad checksum, a malformed packet, or nothing
    /// for it.
    pub dropped: u64,
}

/// The network.
#[derive(Debug, Default)]
pub struct Slirp {
    /// The guest's MAC, once an ARP packet from it gave it.
    pub guest_mac: Option<[u8; 6]>,
    /// UDP datagrams the guest sent to the host: source port, destination
    /// port, payload.
    pub udp: Vec<(u16, u16, Vec<u8>)>,
    /// Datagrams waiting for the guest's MAC.
    waiting: VecDeque<(u16, Vec<u8>)>,
    ident: u16,
    pub counts: Counts,
}

fn ethernet(dst: [u8; 6], ty: u16, body: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + body.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&GATEWAY_MAC);
    f.extend_from_slice(&ty.to_be_bytes());
    f.extend_from_slice(body);
    f
}

fn arp(op: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0, 1, 0x08, 0x00, 6, 4];
    b.extend_from_slice(&op.to_be_bytes());
    b.extend_from_slice(&sha);
    b.extend_from_slice(&spa);
    b.extend_from_slice(&tha);
    b.extend_from_slice(&tpa);
    b
}

impl Slirp {
    pub fn new() -> Slirp {
        Slirp::default()
    }

    /// An IPv4 packet from the gateway to the guest: header and checksum,
    /// then `payload`.
    fn ipv4(&mut self, proto: u8, payload: &[u8]) -> Vec<u8> {
        self.ident = self.ident.wrapping_add(1);
        let total = (20 + payload.len()) as u16;
        let mut h = vec![0x45, 0];
        h.extend_from_slice(&total.to_be_bytes());
        h.extend_from_slice(&self.ident.to_be_bytes());
        h.extend_from_slice(&[0, 0, 64, proto, 0, 0]);
        h.extend_from_slice(&GATEWAY);
        h.extend_from_slice(&GUEST);
        let c = checksum(&[&h]);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h.extend_from_slice(payload);
        h
    }

    fn udp_frame(&mut self, mac: [u8; 6], port: u16, payload: &[u8]) -> Vec<u8> {
        let len = (8 + payload.len()) as u16;
        let mut u = Vec::new();
        u.extend_from_slice(&port.to_be_bytes());
        u.extend_from_slice(&ECHO_PORT.to_be_bytes());
        u.extend_from_slice(&len.to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(payload);
        let pseudo = [&GATEWAY[..], &GUEST[..], &[0, 17], &len.to_be_bytes()[..]].concat();
        let c = match checksum(&[&pseudo, &u]) {
            0 => 0xFFFF,
            c => c,
        };
        u[6..8].copy_from_slice(&c.to_be_bytes());
        let ip = self.ipv4(17, &u);
        ethernet(mac, 0x0800, &ip)
    }

    /// A datagram from the host's port `port` to the guest's port 7, as
    /// the frames the network sends: the datagram itself, or an ARP
    /// request for the guest while it has no MAC for it (the datagram
    /// then waits for the answer).
    pub fn datagram(&mut self, port: u16, payload: &[u8]) -> Vec<Vec<u8>> {
        assert!(payload.len() <= 1472, "a datagram that would be fragmented");
        match self.guest_mac {
            Some(mac) => vec![self.udp_frame(mac, port, payload)],
            None => {
                let first = self.waiting.is_empty();
                self.waiting.push_back((port, payload.to_vec()));
                if first {
                    let req = arp(1, GATEWAY_MAC, GATEWAY, [0; 6], GUEST);
                    vec![ethernet(BROADCAST, 0x0806, &req)]
                } else {
                    Vec::new()
                }
            }
        }
    }

    /// Takes a frame the guest sent; the frames the network answers with.
    pub fn input(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        let out = self.input_inner(frame);
        if out.is_none() {
            self.counts.dropped += 1;
        }
        out.unwrap_or_default()
    }

    fn input_inner(&mut self, frame: &[u8]) -> Option<Vec<Vec<u8>>> {
        let dst: [u8; 6] = frame.get(0..6)?.try_into().ok()?;
        let src: [u8; 6] = frame.get(6..12)?.try_into().ok()?;
        if dst != GATEWAY_MAC && dst != BROADCAST {
            return None;
        }
        let ty = u16::from_be_bytes(frame.get(12..14)?.try_into().ok()?);
        let body = &frame[14..];
        match ty {
            0x0806 => self.arp_input(src, body),
            0x0800 => self.ip_input(src, body),
            _ => None,
        }
    }

    fn arp_input(&mut self, src: [u8; 6], b: &[u8]) -> Option<Vec<Vec<u8>>> {
        if b.len() < 28 || b[..6] != [0, 1, 0x08, 0x00, 6, 4] {
            return None;
        }
        let op = u16::from_be_bytes([b[6], b[7]]);
        let sha: [u8; 6] = b[8..14].try_into().ok()?;
        let spa: [u8; 4] = b[14..18].try_into().ok()?;
        let tpa: [u8; 4] = b[24..28].try_into().ok()?;
        if spa != GUEST || sha != src {
            return None;
        }
        let mut out = Vec::new();
        match op {
            1 if tpa == GATEWAY => {
                self.guest_mac = Some(sha);
                let reply = arp(2, GATEWAY_MAC, GATEWAY, sha, spa);
                out.push(ethernet(sha, 0x0806, &reply));
                self.counts.arp_answered += 1;
            }
            2 if tpa == GATEWAY => self.guest_mac = Some(sha),
            _ => return None,
        }
        while let Some((port, payload)) = self.waiting.pop_front() {
            out.push(self.udp_frame(sha, port, &payload));
        }
        Some(out)
    }

    fn ip_input(&mut self, src: [u8; 6], p: &[u8]) -> Option<Vec<Vec<u8>>> {
        if p.len() < 20 || p[0] != 0x45 || checksum(&[&p[..20]]) != 0 {
            return None;
        }
        let total = usize::from(u16::from_be_bytes([p[2], p[3]]));
        if total < 20 || total > p.len() || p[6] & 0x3F != 0 || p[7] != 0 {
            return None;
        }
        if p[12..16] != GUEST || Some(src) != self.guest_mac {
            return None;
        }
        let dst: [u8; 4] = p[16..20].try_into().ok()?;
        let data = &p[20..total];
        match p[9] {
            1 if dst == GATEWAY => {
                // icmp_reflect: an echo request to the gateway comes back
                // as a reply with the same identifier, sequence and data.
                if data.len() < 8 || data[0] != 8 || data[1] != 0 || checksum(&[data]) != 0 {
                    return None;
                }
                let mut r = data.to_vec();
                r[0] = 0;
                r[2..4].copy_from_slice(&[0, 0]);
                let c = checksum(&[&r]);
                r[2..4].copy_from_slice(&c.to_be_bytes());
                self.counts.pings_answered += 1;
                let ip = self.ipv4(1, &r);
                Some(vec![ethernet(src, 0x0800, &ip)])
            }
            17 => {
                if data.len() < 8 {
                    return None;
                }
                let len = usize::from(u16::from_be_bytes([data[4], data[5]]));
                if len < 8 || len > data.len() {
                    return None;
                }
                let u = &data[..len];
                let sum = u16::from_be_bytes([u[6], u[7]]);
                let pseudo = [
                    &p[12..16],
                    &dst[..],
                    &[0, 17],
                    &(len as u16).to_be_bytes()[..],
                ]
                .concat();
                if sum != 0 && checksum(&[&pseudo, u]) != 0 {
                    return None;
                }
                let sport = u16::from_be_bytes([u[0], u[1]]);
                let dport = u16::from_be_bytes([u[2], u[3]]);
                self.udp.push((sport, dport, u[8..].to_vec()));
                Some(Vec::new())
            }
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use std::vec;
    use std::vec::Vec;

    use super::super::device::{Config, Device};
    use super::super::{BASE, MAC, Mem, World};
    use super::*;

    /// A frame from the guest to `dst`: Ethernet from its MAC, then
    /// `body`.
    fn from_guest(dst: [u8; 6], ty: u16, body: &[u8]) -> Vec<u8> {
        [&dst[..], &MAC.0, &ty.to_be_bytes(), body].concat()
    }

    /// An IPv4 packet from the guest to `dst`, its header checksummed.
    fn guest_ipv4(dst: [u8; 4], proto: u8, payload: &[u8]) -> Vec<u8> {
        let total = (20 + payload.len()) as u16;
        let mut h = vec![0x45, 0];
        h.extend_from_slice(&total.to_be_bytes());
        h.extend_from_slice(&[0, 1, 0x40, 0, 64, proto, 0, 0]);
        h.extend_from_slice(&GUEST);
        h.extend_from_slice(&dst);
        let c = checksum(&[&h]);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h.extend_from_slice(payload);
        h
    }

    fn arp_request() -> Vec<u8> {
        let body = arp(1, MAC.0, GUEST, [0; 6], GATEWAY);
        from_guest(BROADCAST, 0x0806, &body)
    }

    fn echo_request(data: &[u8]) -> Vec<u8> {
        let mut m = vec![8, 0, 0, 0, 0x4C, 0x34, 0, 1];
        m.extend_from_slice(data);
        let c = checksum(&[&m]);
        m[2..4].copy_from_slice(&c.to_be_bytes());
        from_guest(GATEWAY_MAC, 0x0800, &guest_ipv4(GATEWAY, 1, &m))
    }

    /// Sends `frames` from net through the driver and the device to the
    /// network, and its answers back the same way to net.
    fn exchange(
        w: &mut World<'_>,
        dev: &Device<'_>,
        net: &mut Slirp,
        frames: &[Vec<u8>],
    ) -> Vec<Vec<u8>> {
        assert_eq!(w.net_send(frames), frames.len());
        w.settle();
        for f in dev.transmit() {
            for answer in net.input(&f) {
                assert!(dev.receive(&answer));
            }
        }
        w.settle();
        w.net_take()
    }

    #[test]
    fn checksum_is_rfc_1071s() {
        // RFC 1071, 3: the sum of 00 01 f2 03 f4 f5 f6 f7 is ddf2.
        let b = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
        assert_eq!(checksum(&[&b]), !0xddf2);
        assert_eq!(checksum(&[&b[..4], &b[4..]]), !0xddf2);
        // An odd last byte is padded with 0; nothing sums to 0, which
        // complements to ffff.
        assert_eq!(checksum(&[&[0x01]]), !0x0100);
        assert_eq!(checksum(&[]), 0xFFFF);
    }

    #[test]
    fn the_gateway_answers_arp_and_ping_through_the_driver() {
        let mem = Mem::new();
        let dev = Device::new(&mem.dma, BASE, Config::qemu());
        let mut w = World::up(&dev, &mem);
        let mut net = Slirp::new();
        let got = exchange(&mut w, &dev, &mut net, &[arp_request()]);
        assert_eq!(got.len(), 1);
        let r = &got[0];
        assert_eq!(&r[..6], &MAC.0);
        assert_eq!(&r[6..12], &GATEWAY_MAC);
        assert_eq!(&r[12..14], &[0x08, 0x06]);
        assert_eq!(&r[14..42], &arp(2, GATEWAY_MAC, GATEWAY, MAC.0, GUEST)[..]);
        assert_eq!(net.guest_mac, Some(MAC.0));
        // An echo request to the gateway comes back with its identifier,
        // sequence and 56 bytes of data.
        let data: Vec<u8> = (0..56).collect();
        let got = exchange(&mut w, &dev, &mut net, &[echo_request(&data)]);
        assert_eq!(got.len(), 1);
        let ip = &got[0][14..];
        assert_eq!(checksum(&[&ip[..20]]), 0, "the IPv4 header's checksum");
        assert_eq!(
            (&ip[12..16], &ip[16..20], ip[9]),
            (&GATEWAY[..], &GUEST[..], 1)
        );
        let icmp = &ip[20..];
        assert_eq!(checksum(&[icmp]), 0, "the ICMP checksum");
        assert_eq!(&icmp[..2], &[0, 0]);
        assert_eq!(&icmp[4..8], &[0x4C, 0x34, 0, 1]);
        assert_eq!(&icmp[8..], &data[..]);
        assert_eq!(
            net.counts,
            Counts {
                arp_answered: 1,
                pings_answered: 1,
                dropped: 0
            }
        );
    }

    #[test]
    fn datagrams_reach_port_7_and_echoes_reach_the_host() {
        let mem = Mem::new();
        let dev = Device::new(&mem.dma, BASE, Config::qemu());
        let mut w = World::up(&dev, &mem);
        let mut net = Slirp::new();
        exchange(&mut w, &dev, &mut net, &[arp_request()]);
        for len in [0usize, 1, 17, 18, 1471, 1472] {
            let payload: Vec<u8> = (0..len).map(|j| (j * 3 + len) as u8).collect();
            let frames = net.datagram(40_000, &payload);
            assert_eq!(frames.len(), 1);
            assert!(dev.receive(&frames[0]));
            assert!(w.signal());
            let got = w.net_take();
            let ip = &got[0][14..];
            assert_eq!(checksum(&[&ip[..20]]), 0);
            let u = &ip[20..];
            assert_eq!(&u[..4], &[0x9C, 0x40, 0, 7], "from 40000 to 7");
            assert_eq!(usize::from(u16::from_be_bytes([u[4], u[5]])), 8 + len);
            let pseudo = [&ip[12..16], &ip[16..20], &[0, 17], &u[4..6]].concat();
            assert_eq!(checksum(&[&pseudo, u]), 0, "the UDP checksum");
            assert_eq!(&u[8..], &payload[..]);
            // The guest's echo, back from port 7, with no checksum.
            let mut e = vec![0, 7, 0x9C, 0x40];
            e.extend_from_slice(&u[4..6]);
            e.extend_from_slice(&[0, 0]);
            e.extend_from_slice(&payload);
            let echo = from_guest(GATEWAY_MAC, 0x0800, &guest_ipv4(GATEWAY, 17, &e));
            exchange(&mut w, &dev, &mut net, &[echo]);
            assert_eq!(net.udp.pop(), Some((7, 40_000, payload)));
        }
        assert_eq!(net.counts.dropped, 0);
        assert_eq!(w.driver.counters().bad_used, 0);
    }

    #[test]
    fn a_datagram_for_an_unknown_guest_waits_for_its_arp_reply() {
        let mut net = Slirp::new();
        let first = net.datagram(5555, b"one");
        assert_eq!(first.len(), 1);
        let req = &first[0];
        assert_eq!(
            (&req[..6], &req[12..14]),
            (&BROADCAST[..], &[0x08, 0x06][..])
        );
        assert_eq!(&req[14..], &arp(1, GATEWAY_MAC, GATEWAY, [0; 6], GUEST)[..]);
        assert!(
            net.datagram(5556, b"two").is_empty(),
            "one request is enough"
        );
        let reply = from_guest(
            GATEWAY_MAC,
            0x0806,
            &arp(2, MAC.0, GUEST, GATEWAY_MAC, GATEWAY),
        );
        let out = net.input(&reply);
        assert_eq!(out.len(), 2);
        assert_eq!(&out[0][..6], &MAC.0);
        assert_eq!(&out[1][14 + 20..14 + 22], &5556u16.to_be_bytes());
        assert!(net.datagram(5557, b"three")[0].ends_with(b"three"));
    }

    #[test]
    fn what_libslirp_would_drop_is_dropped() {
        let mut net = Slirp::new();
        assert_eq!(net.input(&arp_request()).len(), 1);
        let mut bad_ip = echo_request(&[1, 2, 3]);
        bad_ip[14 + 10] ^= 1;
        let mut bad_icmp = echo_request(&[1, 2, 3]);
        bad_icmp[14 + 20 + 2] ^= 1;
        let mut short = echo_request(&[]);
        short.truncate(14 + 20 + 4);
        let udp = [0, 7, 0, 9, 0, 9, 0x12, 0x34, 0xAA];
        let bad_udp = from_guest(GATEWAY_MAC, 0x0800, &guest_ipv4(GATEWAY, 17, &udp));
        let to_other = from_guest(
            [2, 0, 0, 0, 0, 1],
            0x0806,
            &arp(1, MAC.0, GUEST, [0; 6], GATEWAY),
        );
        for f in [bad_ip, bad_icmp, short, bad_udp, to_other, vec![0; 10]] {
            assert!(net.input(&f).is_empty());
        }
        assert_eq!(net.counts.dropped, 6);
        assert!(net.udp.is_empty());
        // A UDP checksum of 0 is none, which IPv4 allows.
        let udp = [0, 7, 0, 9, 0, 9, 0, 0, 0xAA];
        let none = from_guest(GATEWAY_MAC, 0x0800, &guest_ipv4(GATEWAY, 17, &udp));
        assert!(net.input(&none).is_empty());
        assert_eq!(net.udp, [(7, 9, vec![0xAA])]);
        assert_eq!(net.counts.dropped, 6);
    }
}
