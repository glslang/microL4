//! A scripted peer for the end-to-end tests (`docs/design.md`, "Code and
//! tests", "Network scenarios" and "The M9 Hyper-V check"): the station at
//! the far end of the guest's link, which is also its gateway, as
//! libslirp's `10.0.2.2` is on QEMU and the host's adapter on the internal
//! switch is on Hyper-V.
//!
//! It answers ARP requests for its address and echo requests sent to it,
//! learns the guest's MAC from the guest's ARP packets (asking for it
//! once if it must), and, once [`Peer::begin`] lets it, does what the
//! harness does: [`Spec::pings`] echo requests to the guest, one at a
//! time, as `Send-L4Udp.ps1` pings first, then [`Spec::count`] datagrams
//! with `udp_echo:`'s payloads ([`payload`], from "The harness: `nic:` and
//! `udp_echo:`"), at most [`Spec::window`] unanswered, each from one of
//! [`Spec::ports`] to the guest's port 7.
//!
//! It checks every frame the guest sends, with its own builders and its
//! own RFC 1071 checksum, written from the note and never from `net`:
//! the Ethernet addresses, the ARP fields, an IPv4 header as "Sending
//! IPv4" has it (version 4, IHL 5, TOS 0, an identification counting up
//! from 1, DF, TTL 64, a header checksum that verifies), the ICMP and UDP
//! checksums ("UDP send: the checksum always"), zeros in any padding, and
//! that each echo answers an unanswered datagram with its payload byte
//! for byte, once, and in the order its flow (its source port) sent them.
//! Whatever breaks a rule panics with `peer: ...`, which fails the test.
//!
//! Three crates' tests share this file: `net`'s, where the peer talks to
//! the stack directly, and `virtio-net`'s and `netvsc`'s, which include it
//! by path and put a driver, its device or host, and the frame queues
//! between the two.

use std::collections::VecDeque;
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

/// `udp_echo:`'s payload lengths: datagram `k` is `LENGTHS[k mod 13]`
/// bytes.
pub const LENGTHS: [usize; 13] = [8, 9, 17, 18, 19, 64, 255, 256, 512, 952, 953, 1471, 1472];

/// The echo service's port.
pub const ECHO: u16 = 7;
/// The identifier of the stack's one echo request to its gateway.
pub const PING_IDENT: u16 = 0x4C34;
/// The identifier of the peer's echo requests to the guest.
pub const PEER_IDENT: u16 = 0x0001;

const BROADCAST: [u8; 6] = [0xFF; 6];
const ARP: u16 = 0x0806;
const IPV4: u16 = 0x0800;

/// Datagram `k`'s payload: `LENGTHS[k mod 13]` bytes, of which bytes 0 to
/// 3 are `uL4E`, 4 to 7 `k` as a little-endian u32, and byte `j` from 8 on
/// `(k + 3j) mod 256`.
pub fn payload(k: u32) -> Vec<u8> {
    payload_of(k, &LENGTHS)
}

/// As [`payload`], with `lengths` in place of `LENGTHS`.
pub fn payload_of(k: u32, lengths: &[usize]) -> Vec<u8> {
    let len = lengths[k as usize % lengths.len()];
    let mut p = Vec::with_capacity(len);
    p.extend_from_slice(b"uL4E");
    p.extend_from_slice(&k.to_le_bytes());
    p.extend((8..len).map(|j| (k as usize + 3 * j) as u8));
    p
}

/// RFC 1071's checksum of the concatenation of `parts`: 16-bit words
/// summed in 32 bits, an odd last byte padded with 0, the carries folded
/// back, complemented.
pub fn checksum(parts: &[&[u8]]) -> u16 {
    let bytes: Vec<u8> = parts.concat();
    let mut sum: u32 = 0;
    for pair in bytes.chunks(2) {
        let word = u32::from(pair[0]) << 8 | pair.get(1).copied().map_or(0, u32::from);
        sum += word;
    }
    while sum > 0xFFFF {
        sum = (sum & 0xFFFF) + (sum >> 16);
    }
    !(sum as u16)
}

fn be16(b: &[u8], at: usize) -> u16 {
    u16::from_be_bytes([b[at], b[at + 1]])
}

fn ip_text(ip: [u8; 4]) -> String {
    format!("{}.{}.{}.{}", ip[0], ip[1], ip[2], ip[3])
}

/// A UDP datagram's pseudo-header.
fn pseudo(src: [u8; 4], dst: [u8; 4], len: usize) -> Vec<u8> {
    [
        &src[..],
        &dst[..],
        &[0, 17],
        &(len as u16).to_be_bytes()[..],
    ]
    .concat()
}

/// What the peer is, and what it does once begun.
#[derive(Clone, Debug)]
pub struct Spec {
    /// The peer, the guest's gateway: its MAC and address.
    pub mac: [u8; 6],
    pub ip: [u8; 4],
    /// The guest: the MAC its driver reads from the device, and the
    /// address its command line gives it.
    pub guest_mac: [u8; 6],
    pub guest: [u8; 4],
    /// The data lengths of the echo requests the peer sends the guest,
    /// one at a time, before any datagram.
    pub pings: Vec<usize>,
    /// The datagrams it sends, and at most how many unanswered.
    pub count: u32,
    pub window: u32,
    /// The source ports: datagram `k` comes from `ports[k mod n]`, one
    /// flow per port.
    pub ports: Vec<u16>,
    /// The payloads' lengths: `udp_echo:`'s [`LENGTHS`], unless a test
    /// needs only short ones.
    pub lengths: Vec<usize>,
    /// Frames under 60 bytes padded with zeros to 60, as a switch's
    /// adapter sends them; libslirp sends them as they are (from memory).
    pub pad: bool,
}

impl Spec {
    /// QEMU's user networking: libslirp's gateway `10.0.2.2` at
    /// `52:55:0a:00:02:02`, the guest `10.0.2.15` at the model device's
    /// `52:54:00:12:34:56`; the forwarded port's datagrams come from the
    /// gateway's address, unpadded.
    pub fn qemu(count: u32) -> Spec {
        Spec {
            mac: [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02],
            ip: [10, 0, 2, 2],
            guest_mac: [0x52, 0x54, 0x00, 0x12, 0x34, 0x56],
            guest: [10, 0, 2, 15],
            pings: vec![32, 0, 1, 1472],
            count,
            window: 8,
            ports: vec![40_123],
            lengths: LENGTHS.to_vec(),
            pad: false,
        }
    }

    /// The M9 Hyper-V check's switch: the host's adapter `192.168.77.1`,
    /// the guest `192.168.77.2/24` at the mock device's
    /// `00:15:5d:4c:34:01`; `Send-L4Udp.ps1`'s four pings, then the
    /// datagrams, padded as an adapter sends them.
    pub fn hyperv(count: u32) -> Spec {
        Spec {
            mac: [0x00, 0x15, 0x5d, 0x00, 0x00, 0x77],
            ip: [192, 168, 77, 1],
            guest_mac: [0x00, 0x15, 0x5d, 0x4c, 0x34, 0x01],
            guest: [192, 168, 77, 2],
            pings: vec![32, 0, 1, 1472],
            count,
            window: 8,
            ports: vec![50_007],
            lengths: LENGTHS.to_vec(),
            pad: true,
        }
    }

    /// The command line's words for the guest's address and gateway.
    pub fn cmdline(&self) -> String {
        format!(
            "net.ip={}/24 net.gw={}",
            ip_text(self.guest),
            ip_text(self.ip)
        )
    }
}

/// What the peer has seen and done.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Counts {
    /// Frames from the guest, all checked, and frames to it.
    pub from_guest: u64,
    pub to_guest: u64,
    /// The guest's ARP requests for the peer's address, each answered,
    /// and its replies to the peer's.
    pub arp_requests: u64,
    pub arp_replies: u64,
    /// The peer's own ARP requests for the guest.
    pub arp_asked: u64,
    /// The guest's echo requests to the peer, each answered.
    pub pings_answered: u64,
    /// The peer's echo requests, and the guest's replies to them.
    pub pings_sent: u64,
    pub ping_replies: u64,
    /// Datagrams sent, and echoes taken.
    pub sent: u64,
    pub echoed: u64,
}

/// An echo request the guest sent the peer: identifier, sequence and data
/// length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct GuestPing {
    pub ident: u16,
    pub seq: u16,
    pub len: usize,
}

/// The peer.
#[derive(Debug)]
pub struct Peer {
    pub spec: Spec,
    /// The guest's MAC, once one of its ARP packets gave it.
    learnt: bool,
    begun: bool,
    /// Its own IPv4 identification.
    ident: u16,
    /// The guest's next IPv4 identification.
    guest_ident: u16,
    /// The next of [`Spec::pings`], and the one waiting for its reply:
    /// sequence and data.
    next_ping: usize,
    ping_out: Option<(u16, Vec<u8>)>,
    /// The next datagram, and each flow's unanswered ones in the order
    /// sent.
    next: u32,
    flows: Vec<VecDeque<u32>>,
    /// Which datagrams have come back.
    answered: Vec<bool>,
    /// The guest's echo requests to the peer.
    pub guest_pings: Vec<GuestPing>,
    pub counts: Counts,
}

impl Peer {
    pub fn new(spec: Spec) -> Peer {
        assert!(!spec.ports.is_empty() && spec.window > 0);
        assert!(spec.pings.iter().all(|&n| n <= 1472));
        assert!(!spec.lengths.is_empty() && spec.lengths.iter().all(|&n| (8..=1472).contains(&n)));
        let flows = vec![VecDeque::new(); spec.ports.len()];
        let answered = vec![false; spec.count as usize];
        Peer {
            spec,
            learnt: false,
            begun: false,
            ident: 0,
            guest_ident: 1,
            next_ping: 0,
            ping_out: None,
            next: 0,
            flows,
            answered,
            guest_pings: Vec::new(),
            counts: Counts::default(),
        }
    }

    /// From now on [`Peer::poll`] sends the pings, then the datagrams: the
    /// harness's step once the line above its `udp_echo:` has matched.
    pub fn begin(&mut self) {
        self.begun = true;
    }

    /// Every ping answered and every datagram echoed.
    pub fn done(&self) -> bool {
        self.begun
            && self.next_ping == self.spec.pings.len()
            && self.ping_out.is_none()
            && self.counts.echoed == u64::from(self.spec.count)
    }

    /// Datagrams sent and not yet echoed.
    pub fn unanswered(&self) -> u32 {
        self.flows.iter().map(|f| f.len() as u32).sum()
    }

    /// The datagrams no echo has answered, by index.
    pub fn missing(&self) -> Vec<u32> {
        (0..self.next)
            .filter(|&k| !self.answered[k as usize])
            .collect()
    }

    fn ethernet(&mut self, dst: [u8; 6], ty: u16, body: &[u8]) -> Vec<u8> {
        let mut f = Vec::with_capacity(60.max(14 + body.len()));
        f.extend_from_slice(&dst);
        f.extend_from_slice(&self.spec.mac);
        f.extend_from_slice(&ty.to_be_bytes());
        f.extend_from_slice(body);
        if self.spec.pad && f.len() < 60 {
            f.resize(60, 0);
        }
        self.counts.to_guest += 1;
        f
    }

    fn arp_body(op: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
        let mut b = vec![0, 1, 0x08, 0x00, 6, 4];
        b.extend_from_slice(&op.to_be_bytes());
        b.extend_from_slice(&sha);
        b.extend_from_slice(&spa);
        b.extend_from_slice(&tha);
        b.extend_from_slice(&tpa);
        b
    }

    /// An IPv4 packet from the peer to the guest, in a frame.
    fn ipv4(&mut self, proto: u8, payload: &[u8]) -> Vec<u8> {
        self.ident = self.ident.wrapping_add(1);
        let total = 20 + payload.len();
        assert!(total <= 1500, "peer: a {total}-byte packet would fragment");
        let mut h = vec![0x45, 0];
        h.extend_from_slice(&(total as u16).to_be_bytes());
        h.extend_from_slice(&self.ident.to_be_bytes());
        h.extend_from_slice(&[0x40, 0, 128, proto, 0, 0]);
        h.extend_from_slice(&self.spec.ip);
        h.extend_from_slice(&self.spec.guest);
        let c = checksum(&[&h]);
        h[10..12].copy_from_slice(&c.to_be_bytes());
        h.extend_from_slice(payload);
        let mac = self.spec.guest_mac;
        self.ethernet(mac, IPV4, &h)
    }

    fn icmp(&mut self, kind: u8, ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
        let mut m = vec![kind, 0, 0, 0];
        m.extend_from_slice(&ident.to_be_bytes());
        m.extend_from_slice(&seq.to_be_bytes());
        m.extend_from_slice(data);
        let c = checksum(&[&m]);
        m[2..4].copy_from_slice(&c.to_be_bytes());
        self.ipv4(1, &m)
    }

    /// A UDP datagram from the peer's `sport` to the guest's `dport`,
    /// with its checksum: any datagram, for a test's own traffic beside
    /// the scripted one.
    pub fn datagram(&mut self, sport: u16, dport: u16, data: &[u8]) -> Vec<u8> {
        let len = 8 + data.len();
        let mut u = Vec::with_capacity(len);
        u.extend_from_slice(&sport.to_be_bytes());
        u.extend_from_slice(&dport.to_be_bytes());
        u.extend_from_slice(&(len as u16).to_be_bytes());
        u.extend_from_slice(&[0, 0]);
        u.extend_from_slice(data);
        let c = match checksum(&[&pseudo(self.spec.ip, self.spec.guest, len), &u]) {
            0 => 0xFFFF,
            c => c,
        };
        u[6..8].copy_from_slice(&c.to_be_bytes());
        self.ipv4(17, &u)
    }

    /// Datagram `k`'s payload.
    fn payload(&self, k: u32) -> Vec<u8> {
        payload_of(k, &self.spec.lengths)
    }

    fn ping_data(seq: u16, len: usize) -> Vec<u8> {
        (0..len).map(|i| (usize::from(seq) * 7 + i) as u8).collect()
    }

    /// The frames the peer sends of its own accord now: once begun, an
    /// ARP request for the guest if it has no MAC for it yet, else the
    /// next ping when none is waiting, else datagrams while fewer than the
    /// window are unanswered.
    pub fn poll(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        if !self.begun || self.done() {
            return out;
        }
        if !self.learnt {
            if self.counts.arp_asked == 0 {
                let body = Self::arp_body(1, self.spec.mac, self.spec.ip, [0; 6], self.spec.guest);
                self.counts.arp_asked += 1;
                out.push(self.ethernet(BROADCAST, ARP, &body));
            }
            return out;
        }
        if self.ping_out.is_some() {
            return out;
        }
        if self.next_ping < self.spec.pings.len() {
            let seq = self.next_ping as u16 + 1;
            let data = Self::ping_data(seq, self.spec.pings[self.next_ping]);
            self.next_ping += 1;
            self.counts.pings_sent += 1;
            out.push(self.icmp(8, PEER_IDENT, seq, &data));
            self.ping_out = Some((seq, data));
            return out;
        }
        while self.next < self.spec.count && self.unanswered() < self.spec.window {
            let k = self.next;
            self.next += 1;
            let flow = k as usize % self.spec.ports.len();
            self.flows[flow].push_back(k);
            let port = self.spec.ports[flow];
            self.counts.sent += 1;
            let data = self.payload(k);
            out.push(self.datagram(port, ECHO, &data));
        }
        out
    }

    /// Takes a frame the guest sent and checks it; the frames the peer
    /// answers with at once.
    #[track_caller]
    pub fn input(&mut self, frame: &[u8]) -> Vec<Vec<u8>> {
        self.counts.from_guest += 1;
        assert!(
            (14..=1514).contains(&frame.len()),
            "peer: a {}-byte frame from the guest",
            frame.len()
        );
        let dst: [u8; 6] = frame[0..6].try_into().unwrap();
        let src: [u8; 6] = frame[6..12].try_into().unwrap();
        assert_eq!(src, self.spec.guest_mac, "peer: a frame from another MAC");
        match be16(frame, 12) {
            ARP => self.arp(dst, &frame[14..]),
            IPV4 => {
                assert_eq!(dst, self.spec.mac, "peer: an IPv4 frame to {dst:02x?}");
                self.ip(&frame[14..])
            }
            t => panic!("peer: a frame of EtherType {t:#06x} from the guest"),
        }
    }

    /// Bytes past what the frame carries: none, or zeros up to 60 bytes.
    #[track_caller]
    fn padding(&self, body: &[u8], used: usize) {
        let pad = &body[used..];
        if !pad.is_empty() {
            assert_eq!(
                14 + body.len(),
                60,
                "peer: {} bytes after a {used}-byte body",
                pad.len()
            );
            assert!(
                pad.iter().all(|&b| b == 0),
                "peer: padding that is not zeros: {pad:02x?}"
            );
        }
    }

    #[track_caller]
    fn arp(&mut self, dst: [u8; 6], b: &[u8]) -> Vec<Vec<u8>> {
        assert!(b.len() >= 28, "peer: a {}-byte ARP body", b.len());
        assert_eq!(
            &b[..6],
            &[0, 1, 0x08, 0x00, 6, 4],
            "peer: ARP's types and lengths"
        );
        self.padding(b, 28);
        let op = be16(b, 6);
        let sha: [u8; 6] = b[8..14].try_into().unwrap();
        let spa: [u8; 4] = b[14..18].try_into().unwrap();
        let tha: [u8; 6] = b[18..24].try_into().unwrap();
        let tpa: [u8; 4] = b[24..28].try_into().unwrap();
        assert_eq!(
            (sha, spa),
            (self.spec.guest_mac, self.spec.guest),
            "peer: ARP's sender"
        );
        match op {
            1 => {
                assert_eq!(dst, BROADCAST, "peer: an ARP request not broadcast");
                assert_eq!(tpa, self.spec.ip, "peer: an ARP request for another host");
                self.learnt = true;
                self.counts.arp_requests += 1;
                let body = Self::arp_body(2, self.spec.mac, self.spec.ip, sha, spa);
                vec![self.ethernet(sha, ARP, &body)]
            }
            2 => {
                assert!(
                    self.counts.arp_asked > 0,
                    "peer: an ARP reply it did not ask for"
                );
                assert_eq!(
                    (dst, tha, tpa),
                    (self.spec.mac, self.spec.mac, self.spec.ip),
                    "peer: an ARP reply to another host"
                );
                self.learnt = true;
                self.counts.arp_replies += 1;
                Vec::new()
            }
            op => panic!("peer: ARP operation {op}"),
        }
    }

    #[track_caller]
    fn ip(&mut self, p: &[u8]) -> Vec<Vec<u8>> {
        assert!(p.len() >= 20, "peer: a {}-byte IPv4 packet", p.len());
        assert_eq!(p[0], 0x45, "peer: version and IHL");
        assert_eq!(p[1], 0, "peer: TOS");
        let total = usize::from(be16(p, 2));
        assert!(
            (20..=p.len()).contains(&total),
            "peer: total length {total} in a {}-byte payload",
            p.len()
        );
        self.padding(p, total);
        assert_eq!(
            be16(p, 4),
            self.guest_ident,
            "peer: the identification counts up from 1"
        );
        self.guest_ident = self.guest_ident.wrapping_add(1);
        assert_eq!(be16(p, 6), 0x4000, "peer: DF set, no fragment");
        assert_eq!(p[8], 64, "peer: TTL");
        assert_eq!(checksum(&[&p[..20]]), 0, "peer: the IPv4 header checksum");
        assert_eq!(&p[12..16], &self.spec.guest, "peer: the source address");
        assert_eq!(&p[16..20], &self.spec.ip, "peer: the destination address");
        let data = &p[20..total];
        match p[9] {
            1 => self.icmp_input(data),
            17 => {
                self.udp_input(data);
                Vec::new()
            }
            proto => panic!("peer: IPv4 protocol {proto}"),
        }
    }

    #[track_caller]
    fn icmp_input(&mut self, m: &[u8]) -> Vec<Vec<u8>> {
        assert!(m.len() >= 8, "peer: a {}-byte ICMP message", m.len());
        assert_eq!(checksum(&[m]), 0, "peer: the ICMP checksum");
        let (kind, code) = (m[0], m[1]);
        let (ident, seq) = (be16(m, 4), be16(m, 6));
        let data = &m[8..];
        match (kind, code) {
            (8, 0) => {
                self.guest_pings.push(GuestPing {
                    ident,
                    seq,
                    len: data.len(),
                });
                self.counts.pings_answered += 1;
                vec![self.icmp(0, ident, seq, data)]
            }
            (0, 0) => {
                let Some((want, sent)) = self.ping_out.take() else {
                    panic!("peer: an echo reply ({ident:#x}, {seq}) to no request")
                };
                assert_eq!(
                    (ident, seq),
                    (PEER_IDENT, want),
                    "peer: an echo reply to another request"
                );
                assert_eq!(data, &sent[..], "peer: an echo reply's data altered");
                self.counts.ping_replies += 1;
                Vec::new()
            }
            _ => panic!("peer: ICMP type {kind} code {code} from the guest"),
        }
    }

    #[track_caller]
    fn udp_input(&mut self, u: &[u8]) {
        assert!(u.len() >= 8, "peer: a {}-byte datagram", u.len());
        let len = usize::from(be16(u, 4));
        assert_eq!(len, u.len(), "peer: UDP's length against IPv4's");
        let sum = be16(u, 6);
        assert_ne!(sum, 0, "peer: an echo without a UDP checksum");
        assert_eq!(
            checksum(&[&pseudo(self.spec.guest, self.spec.ip, len), u]),
            0,
            "peer: the UDP checksum"
        );
        let (sport, dport) = (be16(u, 0), be16(u, 2));
        assert_eq!(sport, ECHO, "peer: an echo from port {sport}");
        let Some(flow) = self.spec.ports.iter().position(|&p| p == dport) else {
            panic!("peer: a datagram to port {dport}, which sent nothing")
        };
        let data = &u[8..];
        let Some(&first) = self.flows[flow].front() else {
            panic!(
                "peer: an echo to port {dport} with nothing unanswered: {}",
                self.describe(data)
            )
        };
        if data != &self.payload(first)[..] {
            let later = self.flows[flow]
                .iter()
                .find(|&&k| data == &self.payload(k)[..])
                .copied();
            match later {
                Some(k) => panic!("peer: datagram {k}'s echo before datagram {first}'s"),
                None => panic!(
                    "peer: an echo of nothing unanswered (datagram {first} waits): {}",
                    self.describe(data)
                ),
            }
        }
        self.flows[flow].pop_front();
        self.answered[first as usize] = true;
        self.counts.echoed += 1;
    }

    /// What an echo's payload looks like: the datagram it names, and
    /// whether that one came back already.
    fn describe(&self, data: &[u8]) -> String {
        if data.len() >= 8 && data[..4] == *b"uL4E" {
            let k = u32::from_le_bytes(data[4..8].try_into().unwrap());
            if k < self.next && self.answered[k as usize] {
                return format!("a second echo of datagram {k}");
            }
            if k < self.next {
                return format!("datagram {k} altered ({} bytes)", data.len());
            }
            return format!("datagram {k}, never sent");
        }
        format!("{} bytes that are no datagram", data.len())
    }
}
