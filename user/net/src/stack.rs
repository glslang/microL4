//! The stack (`docs/design.md`, "`net`"): one received frame in, at most
//! three frames out, every frame counted once.
//!
//! The layers check in order and stop at the first refusal, which names
//! the frame's [`Outcome`]: Ethernet (length, destination, EtherType),
//! then ARP or IPv4, then ICMP or UDP. Addresses the stack answers or
//! learns are unicast peers ([`Ip::is_unicast`]: never in `0.0.0.0/8`,
//! `127.0.0.0/8` or from `224.0.0.0` up, RFC 1122's martians among them),
//! never the subnet's broadcast or its own address; the echo answers no
//! source port below [`udp::FIRST_CLIENT_PORT`]. A packet to a next
//! hop the ARP cache has not resolved waits in its entry, one per entry
//! and four in all, and goes out when an ARP packet resolves the address.

use core::fmt;

use crate::arp::{self, Cache, Packet, State};
use crate::config::Config;
use crate::echo::Echo;
use crate::ethernet::{self, Header as Eth, Mac};
use crate::held::{Held, Kind};
use crate::icmp::{self, Message};
use crate::ipv4::{self, Ip};
use crate::stats::{Outcome, Stats};
use crate::udp::{self, Datagram, Endpoint, Reply, Service};
use crate::{MAX_FRAME, Tx};

/// What `net` prints, each once in a run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Event {
    /// ARP resolved the gateway for the first time.
    Gateway { ip: Ip, mac: Mac },
    /// The stack's echo request to the gateway was answered, with `bytes`
    /// of data.
    Ping { ip: Ip, seq: u16, bytes: usize },
}

/// `net: gateway 10.0.2.2 is at 52:55:0a:00:02:02`, `net: ping 10.0.2.2:
/// reply 1, 56 bytes`.
impl fmt::Display for Event {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Event::Gateway { ip, mac } => write!(f, "net: gateway {ip} is at {mac}"),
            Event::Ping { ip, seq, bytes } => {
                write!(f, "net: ping {ip}: reply {seq}, {bytes} bytes")
            }
        }
    }
}

/// The stack's one echo request to the gateway.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Ping {
    /// [`Stack::start`] has not run.
    Idle,
    /// Started: it goes out once the gateway resolves.
    Armed,
    /// Sent (or dropped for want of a buffer), not answered.
    Sent,
    Answered,
}

/// The stack, with the service it calls for datagrams to the service's
/// port: the echo service unless a test gives another.
#[derive(Clone)]
pub struct Stack<S: Service = Echo> {
    config: Config,
    mac: Mac,
    service: S,
    cache: Cache,
    held: Held,
    /// The next packet's identification.
    ident: u16,
    ping: Ping,
    /// The gateway has resolved once.
    gateway_seen: bool,
    /// What to print: the gateway's line, then the ping's.
    events: [Option<Event>; 2],
    stats: Stats,
}

impl Stack<Echo> {
    /// The stack at `config`'s address with the driver's `mac`, which is
    /// unicast, serving echo on port 7.
    pub fn new(config: Config, mac: Mac) -> Stack<Echo> {
        Stack::with_service(config, mac, Echo)
    }
}

impl<S: Service> Stack<S> {
    /// The stack with another service.
    pub fn with_service(config: Config, mac: Mac, service: S) -> Stack<S> {
        Stack {
            config,
            mac,
            service,
            cache: Cache::new(),
            held: Held::new(),
            ident: 1,
            ping: Ping::Idle,
            gateway_seen: false,
            events: [None; 2],
            stats: Stats::default(),
        }
    }

    pub fn config(&self) -> Config {
        self.config
    }

    pub fn mac(&self) -> Mac {
        self.mac
    }

    pub fn stats(&self) -> &Stats {
        &self.stats
    }

    pub fn service(&self) -> &S {
        &self.service
    }

    /// The ARP cache.
    pub fn cache(&self) -> &Cache {
        &self.cache
    }

    /// The packets waiting for an address.
    pub fn waiting(&self) -> usize {
        self.held.len()
    }

    /// The next hops packets wait for.
    pub fn waiting_for(&self) -> impl Iterator<Item = Ip> + '_ {
        self.held.hops()
    }

    /// The next line to print, if any.
    pub fn event(&mut self) -> Option<Event> {
        self.events.iter_mut().find_map(Option::take)
    }

    /// The stack's first frames: an ARP request for the gateway and, once
    /// it is resolved, one ICMP echo request to it. Only the first call
    /// does anything.
    pub fn start(&mut self, tx: &mut impl Tx) {
        if self.ping != Ping::Idle {
            return;
        }
        self.ping = Ping::Armed;
        let gw = self.config.gateway();
        match self.cache.lookup(gw) {
            Some(State::Resolved(mac)) => self.send_ping(tx, mac),
            Some(State::Pending) => self.send_request(tx, gw),
            None => {
                self.add(gw, State::Pending);
                self.send_request(tx, gw);
            }
        }
    }

    /// Processes one received frame, borrowed for the call only, and
    /// sends what it answers through `tx`: at most three frames.
    pub fn input(&mut self, frame: &[u8], tx: &mut impl Tx) {
        let o = self.ethernet(frame, tx);
        self.stats.count(o);
    }

    fn ethernet(&mut self, frame: &[u8], tx: &mut impl Tx) -> Outcome {
        if frame.len() > MAX_FRAME {
            return Outcome::EthLong;
        }
        let Some((eth, payload)) = Eth::parse(frame) else {
            return Outcome::EthShort;
        };
        let broadcast = eth.dst == Mac::BROADCAST;
        if eth.dst != self.mac && !broadcast {
            return Outcome::EthNotOurs;
        }
        match eth.ethertype {
            ethernet::ARP => self.arp(payload, tx),
            ethernet::IPV4 => self.ipv4(payload, broadcast, tx),
            _ => Outcome::EthType,
        }
    }

    /// Whether the stack may answer or learn `ip`.
    fn is_peer(&self, ip: Ip) -> bool {
        ip.is_unicast() && ip != self.config.address() && ip != self.config.broadcast()
    }

    fn arp(&mut self, body: &[u8], tx: &mut impl Tx) -> Outcome {
        let Some(p) = Packet::parse(body) else {
            return Outcome::ArpMalformed;
        };
        if !p.sha.is_unicast() || p.sha == self.mac || !self.is_peer(p.spa) {
            return Outcome::ArpBadSender;
        }
        let merged = self.cache.merge(p.spa, p.sha);
        let ours = p.tpa == self.config.address();
        if ours && !merged {
            self.add(p.spa, State::Resolved(p.sha));
        }
        if ours && p.op == arp::REQUEST {
            self.send_arp(tx, arp::REPLY, p.sha, p.sha, p.spa);
        }
        if merged || ours {
            self.resolved(tx, p.spa, p.sha);
        }
        match (ours, p.op) {
            (false, _) => Outcome::ArpNotOurs,
            (true, arp::REQUEST) => Outcome::ArpAnswered,
            (true, _) => Outcome::ArpLearnt,
        }
    }

    /// Adds `ip` to the cache; a packet waiting in the entry it replaced
    /// is lost.
    fn add(&mut self, ip: Ip, state: State) {
        if let Some(old) = self.cache.insert(ip, state)
            && let Some(i) = self.held.find(old)
        {
            self.held.clear(i);
            self.stats.held_evicted += 1;
        }
    }

    /// `ip` is at `mac`: the packet waiting for it goes out, and the
    /// gateway's first resolution is reported and pings it.
    fn resolved(&mut self, tx: &mut impl Tx, ip: Ip, mac: Mac) {
        if let Some(i) = self.held.find(ip) {
            let kind = self.held.kind(i);
            let held = &self.held;
            let sent = tx.send(|buf| held.copy(i, mac, buf));
            self.held.clear(i);
            self.sent(sent, Some(kind));
        }
        if ip == self.config.gateway() {
            if !self.gateway_seen {
                self.gateway_seen = true;
                self.events[0] = Some(Event::Gateway { ip, mac });
            }
            if self.ping == Ping::Armed {
                self.send_ping(tx, mac);
            }
        }
    }

    fn ipv4(&mut self, packet: &[u8], eth_broadcast: bool, tx: &mut impl Tx) -> Outcome {
        let (h, data) = match ipv4::Header::parse(packet) {
            Ok(p) => p,
            Err(ipv4::Bad::Malformed) => return Outcome::IpMalformed,
            Err(ipv4::Bad::Checksum) => return Outcome::IpChecksum,
            Err(ipv4::Bad::Fragment) => return Outcome::IpFragment,
        };
        let unicast = h.dst == self.config.address();
        if !unicast && h.dst != Ip::BROADCAST {
            return Outcome::IpNotOurs;
        }
        if !self.is_peer(h.src) {
            return Outcome::IpBadSource;
        }
        // A packet to the stack's address in a broadcast frame is as much
        // a broadcast as one to 255.255.255.255: neither is answered.
        let broadcast = eth_broadcast || !unicast;
        match h.protocol {
            ipv4::ICMP => self.icmp(&h, data, broadcast, tx),
            ipv4::UDP => self.udp(&h, data, broadcast, tx),
            _ => Outcome::IpProtocol,
        }
    }

    fn icmp(&mut self, h: &ipv4::Header, msg: &[u8], broadcast: bool, tx: &mut impl Tx) -> Outcome {
        match Message::parse(msg) {
            Err(icmp::Bad::Short) => Outcome::IcmpShort,
            Err(icmp::Bad::Checksum) => Outcome::IcmpChecksum,
            Ok(Message::EchoRequest { ident, seq, data }) => {
                if broadcast {
                    return Outcome::IcmpBroadcast;
                }
                let len = icmp::HEADER + data.len();
                self.send_ipv4(tx, h.src, ipv4::ICMP, Kind::Icmp, len, |m| {
                    icmp::write_echo(m, icmp::ECHO_REPLY, ident, seq, data);
                });
                Outcome::IcmpAnswered
            }
            Ok(Message::EchoReply { ident, seq, data }) => {
                let ours = ident == icmp::PING_IDENT
                    && seq == icmp::PING_SEQ
                    && h.src == self.config.gateway()
                    && !broadcast
                    && matches!(self.ping, Ping::Sent | Ping::Answered);
                if !ours {
                    return Outcome::IcmpOther;
                }
                if self.ping == Ping::Sent {
                    self.ping = Ping::Answered;
                    self.events[1] = Some(Event::Ping {
                        ip: h.src,
                        seq,
                        bytes: data.len(),
                    });
                }
                Outcome::IcmpReply
            }
            Ok(Message::Other { .. }) => Outcome::IcmpOther,
        }
    }

    fn udp(&mut self, h: &ipv4::Header, data: &[u8], broadcast: bool, tx: &mut impl Tx) -> Outcome {
        let d = match Datagram::parse(h.src, h.dst, data) {
            Ok(d) => d,
            Err(udp::Bad::Length) => return Outcome::UdpLength,
            Err(udp::Bad::Checksum) => return Outcome::UdpChecksum,
        };
        if d.dst_port != S::PORT {
            return Outcome::UdpPort;
        }
        if broadcast || d.src_port < udp::FIRST_CLIENT_PORT {
            return Outcome::UdpRefused;
        }
        let from = Endpoint {
            ip: h.src,
            port: d.src_port,
        };
        let mut reply = Reply::new();
        self.service.datagram(from, d.payload, &mut reply);
        if let Some(payload) = reply.take() {
            let src = Endpoint {
                ip: self.config.address(),
                port: S::PORT,
            };
            let len = udp::HEADER + payload.len();
            self.send_ipv4(tx, h.src, ipv4::UDP, Kind::Udp, len, |d| {
                udp::write(d, src, from, payload);
            });
        }
        Outcome::UdpReceived
    }

    /// Counts a frame built: out, or dropped for want of a buffer.
    fn sent(&mut self, sent: bool, kind: Option<Kind>) {
        if !sent {
            self.stats.tx_full += 1;
            return;
        }
        self.stats.frames_out += 1;
        if kind == Some(Kind::Udp) {
            self.stats.udp_echoed += 1;
        }
    }

    /// Sends an IPv4 packet to `dst` whose `len` bytes after the header
    /// `fill` writes, through the next hop: at once if the cache has it,
    /// else once it resolves.
    fn send_ipv4(
        &mut self,
        tx: &mut impl Tx,
        dst: Ip,
        protocol: u8,
        kind: Kind,
        len: usize,
        fill: impl FnOnce(&mut [u8]),
    ) {
        let end = ethernet::HEADER + ipv4::HEADER + len;
        if end > MAX_FRAME {
            // Never: an echo reply is no longer than its request, and a
            // service's payload is at most 1,472 bytes.
            return;
        }
        let hop = self.config.next_hop(dst);
        let ident = self.ident;
        self.ident = self.ident.wrapping_add(1);
        let (src_mac, src) = (self.mac, self.config.address());
        let build = move |buf: &mut [u8; MAX_FRAME], mac: Mac| {
            let eth = Eth {
                dst: mac,
                src: src_mac,
                ethertype: ethernet::IPV4,
            };
            eth.write(buf);
            ipv4::write(&mut buf[ethernet::HEADER..], ident, protocol, src, dst, len);
            fill(&mut buf[ethernet::HEADER + ipv4::HEADER..end]);
            ethernet::pad(buf, end)
        };
        match self.cache.lookup(hop) {
            Some(State::Resolved(mac)) => {
                let sent = tx.send(|buf| build(buf, mac));
                self.sent(sent, Some(kind));
            }
            known => self.hold(tx, hop, known.is_some(), kind, |buf| build(buf, Mac::ZERO)),
        }
    }

    /// Keeps a packet for `hop`, which is pending (`known`) or not in the
    /// cache, and asks for its address again.
    fn hold(
        &mut self,
        tx: &mut impl Tx,
        hop: Ip,
        known: bool,
        kind: Kind,
        build: impl FnOnce(&mut [u8; MAX_FRAME]) -> usize,
    ) {
        if !known {
            self.add(hop, State::Pending);
        }
        let slot = match self.held.find(hop) {
            Some(i) => {
                self.stats.held_replaced += 1;
                Some(i)
            }
            None => self.held.free(),
        };
        match slot {
            Some(i) => self.held.store(i, hop, kind, build),
            None => self.stats.held_full += 1,
        }
        self.send_request(tx, hop);
    }

    /// An ARP request for `ip`, to everyone.
    fn send_request(&mut self, tx: &mut impl Tx, ip: Ip) {
        if self.send_arp(tx, arp::REQUEST, Mac::BROADCAST, Mac::ZERO, ip) {
            self.stats.arp_sent += 1;
        }
    }

    /// An ARP packet from the stack, in a frame to `dst`, whose target is
    /// `tha` at `tpa`. Returns whether it went out.
    fn send_arp(&mut self, tx: &mut impl Tx, op: u16, dst: Mac, tha: Mac, tpa: Ip) -> bool {
        let eth = Eth {
            dst,
            src: self.mac,
            ethertype: ethernet::ARP,
        };
        let p = Packet {
            op,
            sha: self.mac,
            spa: self.config.address(),
            tha,
            tpa,
        };
        let sent = tx.send(|buf| {
            eth.write(buf);
            p.write(&mut buf[ethernet::HEADER..]);
            ethernet::pad(buf, ethernet::HEADER + arp::BODY)
        });
        self.sent(sent, None);
        sent
    }

    /// The stack's one echo request, to the gateway at `mac`.
    fn send_ping(&mut self, tx: &mut impl Tx, mac: Mac) {
        self.ping = Ping::Sent;
        let ident = self.ident;
        self.ident = self.ident.wrapping_add(1);
        let (src_mac, src, gw) = (self.mac, self.config.address(), self.config.gateway());
        let len = icmp::HEADER + icmp::PING_DATA;
        let sent = tx.send(|buf| {
            let eth = Eth {
                dst: mac,
                src: src_mac,
                ethertype: ethernet::IPV4,
            };
            eth.write(buf);
            ipv4::write(
                &mut buf[ethernet::HEADER..],
                ident,
                ipv4::ICMP,
                src,
                gw,
                len,
            );
            icmp::write_ping(&mut buf[ethernet::HEADER + ipv4::HEADER..]);
            ethernet::HEADER + ipv4::HEADER + len
        });
        self.sent(sent, None);
        if sent {
            self.stats.ping_sent += 1;
        }
    }
}
