//! The verdicts of `test=virtio_net` and `test=net` (`docs/design.md`,
//! "Network scenarios"): the `servers:` line with the root CNode's slot
//! count, the probe's ARP line, the `Stats` lines the scenarios match,
//! and what the counters must hold once the harness's datagrams are
//! echoed (`root::check::net`): no bad queue entry or used element, no IP
//! or UDP checksum error, no frame dropped for want of a buffer on either
//! side, and at least the datagrams the scenario sends echoed. On Hyper-V
//! (the M9 Hyper-V check) the drivers are `vmbus` and `netvsc`: the
//! netvsc channel open, no packet that broke a ring, and, beside the
//! datagrams, the script's four pings answered.

use core::fmt;

use libsys::frames::Mac;
use libsys::proto::{NetvscStats, VirtioNetStats, VmbusStats};
use net::Ip;
pub use net::link::Report;

use crate::network::VMBUS_SINT;

/// The datagrams the `net` scenario sends (`udp_echo: 100`), each of
/// which must come back.
pub const DATAGRAMS: u64 = 100;

/// The pings `Send-L4Udp.ps1` sends the guest before its datagrams, on
/// Hyper-V, each of which `net` must answer.
pub const PINGS: u64 = 4;

/// What runs beside the driver: `net`, or `test=virtio_net`'s probe, a
/// thread of root's own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Client {
    Net,
    Probe,
}

impl Client {
    const fn name(self) -> &'static str {
        match self {
            Client::Net => "net",
            Client::Probe => "probe",
        }
    }
}

/// The drivers the `servers:` line names, with their priorities and
/// interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drivers {
    /// QEMU's: `virtio-net (priority 140, MSI-X IRQ <irq>)`.
    VirtioNet { priority: u64, irq: u8 },
    /// Hyper-V's: `vmbus (priority 145, SINT 2 IRQ <irq>), netvsc
    /// (priority 140)`.
    HyperV {
        vmbus_priority: u64,
        irq: u8,
        netvsc_priority: u64,
    },
}

/// `servers: virtio-net (priority 140, MSI-X IRQ <irq>), net (priority
/// 130); root CNode <used> of <slots> slots used`, once both run; on
/// Hyper-V `servers: vmbus (priority 145, SINT 2 IRQ <irq>), netvsc
/// (priority 140), net (priority 130); ...`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Started {
    pub drivers: Drivers,
    pub client: Client,
    pub client_priority: u64,
    pub used: u64,
    pub slots: u64,
}

impl fmt::Display for Started {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("servers: ")?;
        match self.drivers {
            Drivers::VirtioNet { priority, irq } => {
                write!(f, "virtio-net (priority {priority}, MSI-X IRQ {irq})")?
            }
            Drivers::HyperV {
                vmbus_priority,
                irq,
                netvsc_priority,
            } => write!(
                f,
                "vmbus (priority {vmbus_priority}, SINT {VMBUS_SINT} IRQ {irq}), netvsc (priority {netvsc_priority})"
            )?,
        }
        write!(
            f,
            ", {} (priority {}); root CNode {} of {} slots used",
            self.client.name(),
            self.client_priority,
            self.used,
            self.slots
        )
    }
}

/// `virtio_net: ARP reply: 10.0.2.2 is at 52:55:0a:00:02:02`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ArpLine {
    pub gateway: Ip,
    pub mac: Mac,
}

impl fmt::Display for ArpLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "virtio_net: ARP reply: {} is at {}",
            self.gateway, self.mac
        )
    }
}

/// `virtio-net: stats: <its counters>`.
pub struct DriverLine(pub VirtioNetStats);

impl fmt::Display for DriverLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "virtio-net: stats: {}", self.0)
    }
}

/// `vmbus: stats: <its counters>` (Hyper-V).
pub struct VmbusLine(pub VmbusStats);

impl fmt::Display for VmbusLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "vmbus: stats: {}", self.0)
    }
}

/// `netvsc: stats: <its counters>` (Hyper-V).
pub struct NetvscLine(pub NetvscStats);

impl fmt::Display for NetvscLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "netvsc: stats: {}", self.0)
    }
}

/// `net: stats: <the stack's counters>; queues: <its side's>`; the
/// scenario matches `, 100 datagrams echoed,` on it.
pub struct NetLine(pub Report);

impl fmt::Display for NetLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "net: stats: {}", self.0)
    }
}

/// Why a network test fails: the counter and its value.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The driver took used elements it had not posted, or of a bad
    /// length.
    BadUsed(u64),
    /// The driver's side of the frame queues skipped bad entries.
    DriverBadEntries(u64),
    /// net's side did.
    NetBadEntries(u64),
    /// IPv4 header checksums that did not verify.
    IpChecksum(u64),
    /// UDP checksums that did not verify.
    UdpChecksum(u64),
    /// The driver dropped received frames with no receive buffer free.
    DriverDropped(u64),
    /// The stack built frames with no transmit buffer free.
    NetTxFull(u64),
    /// net's side of the queues dropped frames with no buffer free.
    NetDropped(u64),
    /// Fewer datagrams echoed than the harness sent.
    TooFewEchoed { echoed: u64, want: u64 },
    /// The probe's run: the driver received or sent no frame, or was
    /// never signalled.
    Probe(&'static str),
    /// Hyper-V: vmbus opened no netvsc channel.
    NoChannel,
    /// netvsc found a ring broken, which it then no longer uses; its own
    /// line said which and why.
    Broken(u64),
    /// netvsc's side of the frame queues skipped bad entries.
    NetvscBadEntries(u64),
    /// netvsc dropped received frames with no receive buffer free.
    NetvscDropped(u64),
    /// Fewer ICMP echo requests answered than the Hyper-V script sends.
    TooFewPings { answered: u64, want: u64 },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Failure::BadUsed(n) => write!(f, "virtio-net took {n} bad used elements"),
            Failure::DriverBadEntries(n) => {
                write!(f, "virtio-net skipped {n} bad frame-queue entries")
            }
            Failure::NetBadEntries(n) => write!(f, "net skipped {n} bad frame-queue entries"),
            Failure::IpChecksum(n) => write!(f, "net counted {n} IPv4 header checksum errors"),
            Failure::UdpChecksum(n) => write!(f, "net counted {n} UDP checksum errors"),
            Failure::DriverDropped(n) => {
                write!(
                    f,
                    "virtio-net dropped {n} frames for want of a receive buffer"
                )
            }
            Failure::NetTxFull(n) => {
                write!(f, "net dropped {n} frames for want of a transmit buffer")
            }
            Failure::NetDropped(n) => {
                write!(
                    f,
                    "net's side of the queues dropped {n} frames for want of a buffer"
                )
            }
            Failure::TooFewEchoed { echoed, want } => {
                write!(f, "net echoed {echoed} datagrams, fewer than {want}")
            }
            Failure::Probe(what) => write!(f, "virtio-net's Stats: {what}"),
            Failure::NoChannel => f.write_str("vmbus opened no netvsc channel"),
            Failure::Broken(n) => write!(
                f,
                "netvsc counted {n} broken packets and stopped using the ring they broke"
            ),
            Failure::NetvscBadEntries(n) => {
                write!(f, "netvsc skipped {n} bad frame-queue entries")
            }
            Failure::NetvscDropped(n) => {
                write!(f, "netvsc dropped {n} frames for want of a receive buffer")
            }
            Failure::TooFewPings { answered, want } => write!(
                f,
                "net answered {answered} ICMP echo requests, fewer than {want}"
            ),
        }
    }
}

/// The driver's counters: no bad used element, no bad queue entry, no
/// frame dropped for want of a receive buffer.
pub fn virtio_net(s: &VirtioNetStats) -> Result<(), Failure> {
    if s.bad_used != 0 {
        return Err(Failure::BadUsed(s.bad_used));
    }
    if s.bad_entries != 0 {
        return Err(Failure::DriverBadEntries(s.bad_entries));
    }
    if s.dropped != 0 {
        return Err(Failure::DriverDropped(s.dropped));
    }
    Ok(())
}

/// net's counters, whichever driver it ran over: no bad queue entry, no
/// IP or UDP checksum error, no frame dropped for want of a buffer, and
/// at least `want` datagrams echoed.
pub fn stack(r: &Report, want: u64) -> Result<(), Failure> {
    let s = &r.stack;
    if r.queues.bad != 0 {
        return Err(Failure::NetBadEntries(r.queues.bad));
    }
    if s.ip_checksum != 0 {
        return Err(Failure::IpChecksum(s.ip_checksum));
    }
    if s.udp_checksum != 0 {
        return Err(Failure::UdpChecksum(s.udp_checksum));
    }
    if s.tx_full != 0 {
        return Err(Failure::NetTxFull(s.tx_full));
    }
    if r.queues.dropped != 0 {
        return Err(Failure::NetDropped(r.queues.dropped));
    }
    if s.udp_echoed < want {
        return Err(Failure::TooFewEchoed {
            echoed: s.udp_echoed,
            want,
        });
    }
    Ok(())
}

/// `test=net` on QEMU: the driver's counters, then net's with
/// [`DATAGRAMS`] echoed.
pub fn net(driver: &VirtioNetStats, report: &Report) -> Result<(), Failure> {
    virtio_net(driver)?;
    stack(report, DATAGRAMS)
}

/// vmbus's counters: the netvsc channel open. Its stray events and
/// ignored messages are no failure: a real host may send what vmbus does
/// not use, and netvsc's and net's counters show whether anything was
/// lost.
pub fn vmbus(s: &VmbusStats) -> Result<(), Failure> {
    if s.netvsc_channel == 0 {
        return Err(Failure::NoChannel);
    }
    Ok(())
}

/// netvsc's counters: no packet that broke a ring, no bad queue entry, no
/// frame dropped for want of a receive buffer. Its ignored messages are
/// no failure: the host's notes (`TXTBL_NOTE`, `VFASSOC_NOTE`) are
/// counted there (`docs/design.md`, "`netvsc`"), and so is a send
/// completion with a status other than OK, a frame the host says it did
/// not send, which the echoes then miss. Packets skipped (over 4 KiB, or
/// ranges outside the receive buffer) are printed but no failure either:
/// a datagram they held is missing from the echoes.
pub fn netvsc(s: &NetvscStats) -> Result<(), Failure> {
    if s.broken != 0 {
        return Err(Failure::Broken(s.broken));
    }
    if s.bad_entries != 0 {
        return Err(Failure::NetvscBadEntries(s.bad_entries));
    }
    if s.dropped != 0 {
        return Err(Failure::NetvscDropped(s.dropped));
    }
    Ok(())
}

/// `test=net` on Hyper-V: vmbus's and netvsc's counters, then net's with
/// [`DATAGRAMS`] echoed and the script's [`PINGS`] answered.
pub fn hyperv(bus: &VmbusStats, driver: &NetvscStats, report: &Report) -> Result<(), Failure> {
    vmbus(bus)?;
    netvsc(driver)?;
    stack(report, DATAGRAMS)?;
    let answered = report.stack.icmp_answered;
    if answered < PINGS {
        return Err(Failure::TooFewPings {
            answered,
            want: PINGS,
        });
    }
    Ok(())
}

/// `test=virtio_net`: the driver's counters, and frames each way (the
/// probe's request out, at least its reply in) and a signal handled.
pub fn probe(s: &VirtioNetStats) -> Result<(), Failure> {
    virtio_net(s)?;
    if s.sent == 0 {
        return Err(Failure::Probe("no frame sent"));
    }
    if s.received == 0 {
        return Err(Failure::Probe("no frame received"));
    }
    if s.signals == 0 {
        return Err(Failure::Probe("no signal handled"));
    }
    Ok(())
}

/// Why a `Stats` reply is not one: its label and length.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BadReply {
    pub label: u64,
    pub length: u64,
}

impl fmt::Display for BadReply {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "a reply with label {:#x} and length {}",
            self.label, self.length
        )
    }
}

/// A `Stats` reply carries `N` words with label 0; anything else is a
/// [`BadReply`].
pub fn reply<const N: usize>(
    label: u64,
    length: u64,
    word: impl Fn(usize) -> u64,
) -> Result<[u64; N], BadReply> {
    if label != 0 || length != N as u64 {
        return Err(BadReply { label, length });
    }
    Ok(core::array::from_fn(word))
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsys::frames::Counters;
    use libsys::proto::virtio_feature;
    use net::Stats;
    use std::format;
    use std::string::ToString;

    const MAC: Mac = Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]);

    /// The driver's counters after the `net` scenario, roughly: ARP and
    /// ping each way, then 100 datagrams.
    fn driver() -> VirtioNetStats {
        VirtioNetStats {
            signals: 210,
            received: 102,
            dropped: 0,
            bad_used: 0,
            sent: 103,
            waits: 0,
            bad_entries: 0,
            features: virtio_feature::VERSION_1 | virtio_feature::MAC | virtio_feature::STATUS,
            mac: MAC.to_word(),
        }
    }

    fn report() -> Report {
        Report {
            stack: Stats {
                frames_in: 102,
                frames_out: 103,
                arp_sent: 1,
                arp_learnt: 1,
                ping_sent: 1,
                icmp_replies: 1,
                udp_received: 100,
                udp_echoed: 100,
                ..Stats::default()
            },
            queues: Counters {
                sent: 103,
                received: 102,
                reclaimed: 103,
                dropped: 0,
                bad: 0,
                signals: 105,
            },
        }
    }

    #[test]
    fn the_servers_line() {
        let s = Started {
            drivers: Drivers::VirtioNet {
                priority: 140,
                irq: 1,
            },
            client: Client::Net,
            client_priority: 130,
            used: 1187,
            slots: 4096,
        };
        assert_eq!(
            s.to_string(),
            "servers: virtio-net (priority 140, MSI-X IRQ 1), net (priority 130); root CNode 1187 of 4096 slots used"
        );
        // What the scenario expects of it.
        assert!(
            s.to_string()
                .starts_with("servers: virtio-net (priority 140, MSI-X IRQ")
        );
        let p = Started {
            client: Client::Probe,
            ..s
        };
        assert_eq!(
            p.to_string(),
            "servers: virtio-net (priority 140, MSI-X IRQ 1), probe (priority 130); root CNode 1187 of 4096 slots used"
        );
    }

    #[test]
    fn the_arp_line() {
        assert_eq!(
            ArpLine {
                gateway: Ip::new(10, 0, 2, 2),
                mac: Mac([0x52, 0x55, 10, 0, 2, 2])
            }
            .to_string(),
            "virtio_net: ARP reply: 10.0.2.2 is at 52:55:0a:00:02:02"
        );
    }

    /// The lines the scenarios match.
    #[test]
    fn the_stats_lines() {
        let d = DriverLine(driver()).to_string();
        assert_eq!(
            d,
            "virtio-net: stats: 210 signals, 102 frames received, 0 dropped for no buffer, 0 bad used elements, 103 frames sent, 0 waits for a descriptor, 0 bad queue entries, features VERSION_1 MAC STATUS, MAC 52:54:00:12:34:56"
        );
        assert!(d.starts_with("virtio-net: stats:"));
        let n = NetLine(report()).to_string();
        assert!(
            n.starts_with("net: stats: 102 frames in, 103 frames out, "),
            "{n}"
        );
        assert!(n.contains(", 100 datagrams echoed,"), "{n}");
        assert!(n.contains(", 1 ICMP echo replies received,"), "{n}");
        assert!(n.ends_with(
            "; queues: 103 frames sent, 102 received, 103 buffers reclaimed, 0 frames dropped, 0 bad entries, 105 signals"
        ));
        // 99 or 1,000 echoed does not match the scenario's `, 100 ...`.
        for k in [99, 1000] {
            let mut r = report();
            r.stack.udp_echoed = k;
            assert!(!NetLine(r).to_string().contains(", 100 datagrams echoed,"));
        }
    }

    #[test]
    fn the_net_verdict() {
        assert_eq!(net(&driver(), &report()), Ok(()));
        // Waits for a descriptor are no failure; more echoed than sent is
        // none either (the scenario pins exactly 100).
        let d = VirtioNetStats {
            waits: 3,
            ..driver()
        };
        let mut r = report();
        r.stack.udp_echoed = 101;
        assert_eq!(net(&d, &r), Ok(()));
        // Drops the stack counts for what the network sent are no
        // failure: frames to other MACs, other ports.
        let mut r = report();
        r.stack.eth_not_ours = 4;
        r.stack.udp_port = 2;
        r.stack.icmp_checksum = 0;
        assert_eq!(net(&driver(), &r), Ok(()));
        for (d, why) in [
            (
                VirtioNetStats {
                    bad_used: 1,
                    ..driver()
                },
                Failure::BadUsed(1),
            ),
            (
                VirtioNetStats {
                    bad_entries: 2,
                    ..driver()
                },
                Failure::DriverBadEntries(2),
            ),
            (
                VirtioNetStats {
                    dropped: 3,
                    ..driver()
                },
                Failure::DriverDropped(3),
            ),
        ] {
            assert_eq!(net(&d, &report()), Err(why), "{d:?}");
        }
        let with = |f: fn(&mut Report)| {
            let mut r = report();
            f(&mut r);
            net(&driver(), &r)
        };
        assert_eq!(with(|r| r.queues.bad = 1), Err(Failure::NetBadEntries(1)));
        assert_eq!(
            with(|r| r.stack.ip_checksum = 2),
            Err(Failure::IpChecksum(2))
        );
        assert_eq!(
            with(|r| r.stack.udp_checksum = 3),
            Err(Failure::UdpChecksum(3))
        );
        assert_eq!(with(|r| r.stack.tx_full = 4), Err(Failure::NetTxFull(4)));
        assert_eq!(with(|r| r.queues.dropped = 5), Err(Failure::NetDropped(5)));
        assert_eq!(
            with(|r| r.stack.udp_echoed = 99),
            Err(Failure::TooFewEchoed {
                echoed: 99,
                want: 100
            })
        );
        assert_eq!(
            stack(&report(), 101).unwrap_err().to_string(),
            "net echoed 100 datagrams, fewer than 101"
        );
        assert_eq!(
            Failure::DriverDropped(3).to_string(),
            "virtio-net dropped 3 frames for want of a receive buffer"
        );
    }

    #[test]
    fn the_probe_verdict() {
        let after = VirtioNetStats {
            signals: 3,
            received: 1,
            sent: 1,
            ..driver()
        };
        assert_eq!(probe(&after), Ok(()));
        let no = |f: fn(&mut VirtioNetStats)| {
            let mut s = after;
            f(&mut s);
            probe(&s)
        };
        assert_eq!(no(|s| s.sent = 0), Err(Failure::Probe("no frame sent")));
        assert_eq!(
            no(|s| s.received = 0),
            Err(Failure::Probe("no frame received"))
        );
        assert_eq!(
            no(|s| s.signals = 0),
            Err(Failure::Probe("no signal handled"))
        );
        assert_eq!(no(|s| s.bad_used = 1), Err(Failure::BadUsed(1)));
        assert_eq!(no(|s| s.bad_entries = 1), Err(Failure::DriverBadEntries(1)));
        assert_eq!(
            format!("{}", Failure::Probe("no frame sent")),
            "virtio-net's Stats: no frame sent"
        );
    }

    /// vmbus's counters after the M9 Hyper-V check, roughly.
    fn bus() -> VmbusStats {
        VmbusStats {
            version: 0x4_0000,
            offers: 9,
            netvsc_channel: 14,
            messages: 24,
            events: 310,
            stray: 0,
            eoms: 0,
            retries: 0,
            ignored: 0,
        }
    }

    /// netvsc's: the host's ARP request and four pings besides the 100
    /// datagrams each way, and one TXTBL_NOTE, ignored.
    fn netvsc_stats() -> NetvscStats {
        NetvscStats {
            nvsp: 0x5_0000,
            ndis: 0x6_001E,
            rxbuf_packets: 106,
            received: 106,
            dropped: 0,
            acks: 106,
            acks_waiting: 0,
            sent: 106,
            max_in_flight: 8,
            completions: 106,
            status: 1,
            broken: 0,
            skipped: 0,
            ignored: 1,
            bad_entries: 0,
        }
    }

    fn hyperv_report() -> Report {
        let mut r = report();
        r.stack.icmp_answered = 4;
        r.stack.arp_answered = 1;
        r
    }

    #[test]
    fn the_hyperv_servers_line() {
        let s = Started {
            drivers: Drivers::HyperV {
                vmbus_priority: 145,
                irq: 1,
                netvsc_priority: 140,
            },
            client: Client::Net,
            client_priority: 130,
            used: 1320,
            slots: 4096,
        };
        assert_eq!(
            s.to_string(),
            "servers: vmbus (priority 145, SINT 2 IRQ 1), netvsc (priority 140), net (priority 130); root CNode 1320 of 4096 slots used"
        );
        // What the Hyper-V scenarios expect of it.
        let line = s.to_string();
        assert!(line.starts_with("servers: vmbus (priority 145, SINT 2 IRQ "));
        assert!(line.contains("), netvsc (priority 140), net (priority 130); root CNode "));
    }

    #[test]
    fn the_hyperv_stats_lines() {
        let v = VmbusLine(bus()).to_string();
        assert_eq!(
            v,
            "vmbus: stats: version 4.0, 9 offers, netvsc channel 14, 24 messages, 310 events relayed, 0 stray events, 0 Eoms, 0 post retries, 0 ignored messages"
        );
        let n = NetvscLine(netvsc_stats()).to_string();
        assert!(n.starts_with("netvsc: stats: NVSP 5, NDIS 6.30, "), "{n}");
        for want in [
            ", 0 dropped for no buffer,",
            ", 0 broken packets,",
            ", 0 packets skipped,",
            ", 0 bad queue entries",
        ] {
            assert!(n.contains(want), "{n} has no {want:?}");
        }
        assert!(n.ends_with(", 0 bad queue entries"), "{n}");
        let net = NetLine(hyperv_report()).to_string();
        // The two the scenarios expect, in the order they come.
        let pings = net.find(", 4 ICMP echo requests answered,").unwrap();
        let echoed = net.find(", 100 datagrams echoed,").unwrap();
        assert!(pings < echoed, "{net}");
    }

    #[test]
    fn the_hyperv_verdict() {
        assert_eq!(hyperv(&bus(), &netvsc_stats(), &hyperv_report()), Ok(()));
        // Ignored messages, stray events and skipped packets are no
        // failure on either side; more pings than four are none either.
        let mut b = bus();
        b.ignored = 3;
        b.stray = 2;
        let mut n = netvsc_stats();
        n.ignored = 5;
        n.skipped = 1;
        let mut r = hyperv_report();
        r.stack.icmp_answered = 9;
        assert_eq!(hyperv(&b, &n, &r), Ok(()));
        let mut b = bus();
        b.netvsc_channel = 0;
        assert_eq!(
            hyperv(&b, &netvsc_stats(), &hyperv_report()),
            Err(Failure::NoChannel)
        );
        for (f, why) in [
            (
                (|s: &mut NetvscStats| s.broken = 1) as fn(&mut NetvscStats),
                Failure::Broken(1),
            ),
            (|s| s.bad_entries = 2, Failure::NetvscBadEntries(2)),
            (|s| s.dropped = 3, Failure::NetvscDropped(3)),
        ] {
            let mut n = netvsc_stats();
            f(&mut n);
            assert_eq!(hyperv(&bus(), &n, &hyperv_report()), Err(why));
        }
        // net's own verdict holds on Hyper-V too.
        let mut r = hyperv_report();
        r.stack.udp_echoed = 99;
        assert_eq!(
            hyperv(&bus(), &netvsc_stats(), &r),
            Err(Failure::TooFewEchoed {
                echoed: 99,
                want: 100
            })
        );
        let mut r = hyperv_report();
        r.queues.bad = 1;
        assert_eq!(
            hyperv(&bus(), &netvsc_stats(), &r),
            Err(Failure::NetBadEntries(1))
        );
        let mut r = hyperv_report();
        r.stack.icmp_answered = 3;
        assert_eq!(
            hyperv(&bus(), &netvsc_stats(), &r),
            Err(Failure::TooFewPings {
                answered: 3,
                want: 4
            })
        );
        for (f, text) in [
            (Failure::NoChannel, "vmbus opened no netvsc channel"),
            (
                Failure::Broken(1),
                "netvsc counted 1 broken packets and stopped using the ring they broke",
            ),
            (
                Failure::NetvscBadEntries(2),
                "netvsc skipped 2 bad frame-queue entries",
            ),
            (
                Failure::NetvscDropped(3),
                "netvsc dropped 3 frames for want of a receive buffer",
            ),
            (
                Failure::TooFewPings {
                    answered: 0,
                    want: 4,
                },
                "net answered 0 ICMP echo requests, fewer than 4",
            ),
        ] {
            assert_eq!(f.to_string(), text);
        }
        // The replies root asks for on Hyper-V: 9, 15 and 41 words.
        assert_eq!((VmbusStats::WORDS, NetvscStats::WORDS), (9, 15));
    }

    #[test]
    fn stats_replies() {
        let words = [7u64, 8, 9];
        assert_eq!(reply::<3>(0, 3, |i| words[i]), Ok([7, 8, 9]));
        // A refusal, a kernel error, or a short or long reply.
        for (label, length) in [(0x101, 0), (2, 1), (0, 2), (0, 4)] {
            assert_eq!(
                reply::<3>(label, length, |i| words[i % 3]),
                Err(BadReply { label, length })
            );
        }
        assert_eq!(
            BadReply {
                label: 0x101,
                length: 0
            }
            .to_string(),
            "a reply with label 0x101 and length 0"
        );
        // The two replies root asks for: 9 and 41 words.
        assert_eq!(VirtioNetStats::WORDS, 9);
        assert_eq!(Report::WORDS, 41);
        let w = report().to_words();
        assert_eq!(
            reply::<{ Report::WORDS }>(0, 41, |i| w[i]).map(Report::from_words),
            Ok(report())
        );
    }
}
