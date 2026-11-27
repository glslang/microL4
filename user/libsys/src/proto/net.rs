//! The network servers' `Stats` replies and texts, and `vmbus`'s `Attach`
//! reply (`docs/design.md`, "Networking"): each reply's words, MR0 first,
//! and the text root prints after `<server>: stats: `, which gives each
//! counter as `<n> <what>` between commas, as `UartStats`'s does, so a
//! scenario can match `, 100 datagrams echoed,`.

use core::fmt;

use super::Mac;

/// A `Stats` reply of plain counters: the struct, its `WORDS` and the
/// conversions, in field order.
macro_rules! stats {
    (
        $(#[$meta:meta])*
        pub struct $name:ident {
            $($(#[$field_meta:meta])* $field:ident,)*
        }
    ) => {
        $(#[$meta])*
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct $name {
            $($(#[$field_meta])* pub $field: u64,)*
        }

        impl $name {
            /// The reply's words.
            pub const WORDS: usize = [$(stringify!($field)),*].len();

            pub const fn to_words(&self) -> [u64; Self::WORDS] {
                [$(self.$field),*]
            }

            pub const fn from_words(w: [u64; Self::WORDS]) -> $name {
                let [$($field),*] = w;
                $name { $($field),* }
            }
        }
    };
}

/// Virtio feature bits `virtio-net` may accept (virtio 1.2, 6 and 5.1.3).
pub mod virtio_feature {
    /// `VIRTIO_NET_F_MAC`: the device has a MAC.
    pub const MAC: u64 = 1 << 5;
    /// `VIRTIO_NET_F_STATUS`: the device reports the link.
    pub const STATUS: u64 = 1 << 16;
    /// `VIRTIO_F_VERSION_1`: virtio 1.x, required.
    pub const VERSION_1: u64 = 1 << 32;
}

/// A virtio feature set as `virtio-net`'s lines show it: `VERSION_1 MAC
/// STATUS`, the names in that order, any other bits as one hex word after
/// them, and `none` for none.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VirtioFeatures(pub u64);

impl fmt::Display for VirtioFeatures {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let names = [
            (virtio_feature::VERSION_1, "VERSION_1"),
            (virtio_feature::MAC, "MAC"),
            (virtio_feature::STATUS, "STATUS"),
        ];
        let mut sep = "";
        for (bit, name) in names {
            if self.0 & bit != 0 {
                write!(f, "{sep}{name}")?;
                sep = " ";
            }
        }
        let rest = names.iter().fold(self.0, |r, (bit, _)| r & !bit);
        if rest != 0 {
            write!(f, "{sep}{rest:#x}")?;
        } else if self.0 == 0 {
            f.write_str("none")?;
        }
        Ok(())
    }
}

/// A VMBus version word, `major << 16 | minor`, as `4.0`; 0 is `none`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct VmbusVersion(pub u32);

impl fmt::Display for VmbusVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("none"),
            v => write!(f, "{}.{}", v >> 16, v & 0xFFFF),
        }
    }
}

/// An NVSP version word as FreeBSD's `HN_NVS_VERSION_*` names it: `5` for
/// `0x50000`, `4` for `0x40000`, `2` for `0x30002`, `1`, `6` and `6.1`; any
/// other in hex; 0 is `none`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NvspVersion(pub u32);

impl fmt::Display for NvspVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let name = match self.0 {
            0 => "none",
            0x0_0002 => "1",
            0x3_0002 => "2",
            0x4_0000 => "4",
            0x5_0000 => "5",
            0x6_0000 => "6",
            0x6_0001 => "6.1",
            v => return write!(f, "{v:#x}"),
        };
        f.write_str(name)
    }
}

/// An NDIS version word, `major << 16 | minor`, in decimal: `6.30` for
/// `0x0006001E`; 0 is `none`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NdisVersion(pub u32);

impl fmt::Display for NdisVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            0 => f.write_str("none"),
            v => write!(f, "{}.{}", v >> 16, v & 0xFFFF),
        }
    }
}

/// A word's low 32 bits; the rest is not the field's.
const fn low(w: u64) -> u32 {
    w as u32
}

stats! {
    /// `virtio-net`'s counters, the reply to `Stats` (`0x150`).
    pub struct VirtioNetStats {
        /// MR0: notification signals handled, `IRQ` and `FRAMES` alike.
        signals,
        /// MR1: frames the device delivered that went on `RX_FILLED`.
        received,
        /// MR2: frames the device delivered and the driver dropped, with no
        /// receive buffer free.
        dropped,
        /// MR3: used elements naming a descriptor it had not posted, or a
        /// length outside 12 + 14 to 12 + 1,514.
        bad_used,
        /// MR4: frames from `TX_FILLED` given to the device.
        sent,
        /// MR5: times a frame waited in `TX_FILLED` for a free transmit
        /// descriptor.
        waits,
        /// MR6: bad frame-queue entries ([`crate::frames::Counters::bad`]).
        bad_entries,
        /// MR7: the features negotiated ([`VirtioFeatures`]).
        features,
        /// MR8: the device's MAC ([`Mac::to_word`]).
        mac,
    }
}

impl VirtioNetStats {
    pub const fn mac(&self) -> Mac {
        Mac::from_word(self.mac)
    }
}

/// What root's `virtio-net: stats:` line shows.
impl fmt::Display for VirtioNetStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} signals, {} frames received, {} dropped for no buffer, {} bad used elements, {} frames sent, {} waits for a descriptor, {} bad queue entries, features {}, MAC {}",
            self.signals,
            self.received,
            self.dropped,
            self.bad_used,
            self.sent,
            self.waits,
            self.bad_entries,
            VirtioFeatures(self.features),
            self.mac()
        )
    }
}

stats! {
    /// `vmbus`'s counters, the reply to `Stats` (`0x161`).
    pub struct VmbusStats {
        /// MR0: the VMBus version the host accepted, 0 before contact
        /// ([`VmbusVersion`]).
        version,
        /// MR1: channel offers kept.
        offers,
        /// MR2: the netvsc channel's ID, 0 while there is none.
        netvsc_channel,
        /// MR3: messages taken from the SIM's slot 2.
        messages,
        /// MR4: channel events relayed to `netvsc`.
        events,
        /// MR5: event flags set for no channel it relays.
        stray,
        /// MR6: `Hypervisor_Eom`s invoked.
        eoms,
        /// MR7: `PostMessage`s retried after `HV_STATUS_INSUFFICIENT_BUFFERS`.
        retries,
        /// MR8: messages counted and ignored: a bad type, size or channel
        /// message, an offer out of range or repeated, an answer to nothing.
        ignored,
    }
}

/// What root's `vmbus: stats:` line shows.
impl fmt::Display for VmbusStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "version {}, {} offers, ",
            VmbusVersion(low(self.version)),
            self.offers
        )?;
        match self.netvsc_channel {
            0 => f.write_str("no netvsc channel")?,
            c => write!(f, "netvsc channel {c}")?,
        }
        write!(
            f,
            ", {} messages, {} events relayed, {} stray events, {} Eoms, {} post retries, {} ignored messages",
            self.messages, self.events, self.stray, self.eoms, self.retries, self.ignored
        )
    }
}

stats! {
    /// `netvsc`'s counters, the reply to `Stats` (`0x170`).
    pub struct NetvscStats {
        /// MR0: the NVSP version the host accepted, 0 before
        /// ([`NvspVersion`]).
        nvsp,
        /// MR1: the NDIS version it sent ([`NdisVersion`]).
        ndis,
        /// MR2: receive-buffer packets (type 7) taken from the inbound ring.
        rxbuf_packets,
        /// MR3: frames that went on `RX_FILLED`.
        received,
        /// MR4: frames dropped with no receive buffer free.
        dropped,
        /// MR5: acknowledgements (RNDIS_ACK completions) sent.
        acks,
        /// MR6: acknowledgements waiting now for room in the outbound ring.
        acks_waiting,
        /// MR7: frames from `TX_FILLED` sent.
        sent,
        /// MR8: the most send sections in flight at once.
        max_in_flight,
        /// MR9: send completions taken.
        completions,
        /// MR10: RNDIS status indications.
        status,
        /// MR11: inbound packets that broke the ring, after which it is no
        /// longer read.
        broken,
        /// MR12: packets skipped: over 4 KiB, or ranges outside the receive
        /// buffer.
        skipped,
        /// MR13: messages counted and ignored.
        ignored,
        /// MR14: bad frame-queue entries ([`crate::frames::Counters::bad`]).
        bad_entries,
    }
}

/// What root's `netvsc: stats:` line shows.
impl fmt::Display for NetvscStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "NVSP {}, NDIS {}, {} receive-buffer packets, {} frames received, {} dropped for no buffer, {} acknowledgements sent, {} acknowledgements waiting, {} frames sent, {} sections in flight at most, {} send completions, {} status indications, {} broken packets, {} packets skipped, {} ignored messages, {} bad queue entries",
            NvspVersion(low(self.nvsp)),
            NdisVersion(low(self.ndis)),
            self.rxbuf_packets,
            self.received,
            self.dropped,
            self.acks,
            self.acks_waiting,
            self.sent,
            self.max_in_flight,
            self.completions,
            self.status,
            self.broken,
            self.skipped,
            self.ignored,
            self.bad_entries
        )
    }
}

stats! {
    /// `net`'s counters, the reply to `Stats` (`0x180`): frames and what
    /// the stack did with them, then each drop by its reason, as the
    /// tables of `docs/design.md`, "`net`", give them. Every frame
    /// `Stack::input` takes counts once in `frames_in` and, if it is
    /// dropped, once under one reason.
    pub struct NetStats {
        /// MR0: frames `Stack::input` took.
        frames_in,
        /// MR1: frames the stack sent.
        frames_out,
        /// MR2: ARP requests for its address answered.
        arp_answered,
        /// MR3: ARP requests it sent.
        arp_requests,
        /// MR4: ARP replies it learnt from.
        arp_learnt,
        /// MR5: ICMP echo requests answered.
        icmp_answered,
        /// MR6: ICMP echo replies to its own request.
        icmp_replies,
        /// MR7: UDP datagrams to port 7 taken.
        udp_received,
        /// MR8: datagrams echoed.
        udp_echoed,
        /// MR9, Ethernet: frames under 14 bytes.
        eth_short,
        /// MR10: frames to another destination, multicast among them.
        eth_not_ours,
        /// MR11: frames of another EtherType, VLAN and IPv6 among them.
        eth_type,
        /// MR12, ARP: anything but Ethernet and IPv4, lengths 6 and 4, a
        /// request or a reply.
        arp_malformed,
        /// MR13: a sender address of 0, broadcast or its own.
        arp_sender,
        /// MR14, IPv4: a bad version, IHL or total length.
        ip_malformed,
        /// MR15: a header checksum that does not verify.
        ip_checksum,
        /// MR16: a destination neither its address nor broadcast.
        ip_not_ours,
        /// MR17: a protocol neither 1 nor 17.
        ip_protocol,
        /// MR18: fragments, which it does not reassemble.
        ip_fragments,
        /// MR19: a source of 0, broadcast, multicast, its own or its
        /// subnet's broadcast.
        ip_source,
        /// MR20, ICMP: other types, and echo replies it did not ask for.
        icmp_other,
        /// MR21: a checksum that does not verify.
        icmp_checksum,
        /// MR22: an echo request sent to broadcast.
        icmp_broadcast,
        /// MR23, UDP: a length under 8 or past the IP payload.
        udp_malformed,
        /// MR24: a checksum that does not verify.
        udp_checksum,
        /// MR25: datagrams to another port, dropped silently.
        udp_port,
        /// MR26: datagrams to port 7 from port 0 or 7, or to broadcast.
        udp_refused,
        /// MR27, resolving: waiting packets replaced by a later one to the
        /// same address.
        held_replaced,
        /// MR28: packets dropped because 4 already waited.
        held_dropped,
        /// MR29, sending: frames dropped with no transmit buffer free.
        tx_dropped,
        /// MR30: bad frame-queue entries ([`crate::frames::Counters::bad`]).
        bad_entries,
    }
}

/// What root's `net: stats:` line shows; the `net` scenario matches `, 100
/// datagrams echoed,` and the Hyper-V check `, 4 ICMP echo requests
/// answered,`.
impl fmt::Display for NetStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let s = self;
        let items: [(u64, &str); NetStats::WORDS] = [
            (s.frames_in, "frames in"),
            (s.frames_out, "frames out"),
            (s.arp_answered, "ARP requests answered"),
            (s.arp_requests, "ARP requests sent"),
            (s.arp_learnt, "ARP replies learnt"),
            (s.icmp_answered, "ICMP echo requests answered"),
            (s.icmp_replies, "ICMP echo replies received"),
            (s.udp_received, "UDP datagrams received"),
            (s.udp_echoed, "datagrams echoed"),
            (s.eth_short, "frames too short"),
            (s.eth_not_ours, "frames for other addresses"),
            (s.eth_type, "frames of other EtherTypes"),
            (s.arp_malformed, "ARP packets malformed"),
            (s.arp_sender, "ARP packets from bad senders"),
            (s.ip_malformed, "IPv4 headers malformed"),
            (s.ip_checksum, "IPv4 checksum errors"),
            (s.ip_not_ours, "IPv4 packets for other addresses"),
            (s.ip_protocol, "IPv4 packets of other protocols"),
            (s.ip_fragments, "IPv4 fragments"),
            (s.ip_source, "IPv4 packets from bad sources"),
            (s.icmp_other, "ICMP messages ignored"),
            (s.icmp_checksum, "ICMP checksum errors"),
            (s.icmp_broadcast, "ICMP echo requests to broadcast"),
            (s.udp_malformed, "UDP lengths bad"),
            (s.udp_checksum, "UDP checksum errors"),
            (s.udp_port, "datagrams to other ports"),
            (s.udp_refused, "datagrams refused"),
            (s.held_replaced, "waiting packets replaced"),
            (s.held_dropped, "packets dropped with 4 waiting"),
            (s.tx_dropped, "frames dropped for no buffer"),
            (s.bad_entries, "bad queue entries"),
        ];
        for (i, (n, what)) in items.into_iter().enumerate() {
            let sep = if i == 0 { "" } else { ", " };
            write!(f, "{sep}{n} {what}")?;
        }
        Ok(())
    }
}

/// `vmbus`'s reply to `Attach` (`0x160`), once `netvsc`'s channel is open:
/// MR0 to MR7, and with it the restricted Hypervisor capability in the
/// caller's receive slot.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct VmbusAttach {
    /// MR0: the channel ID (`chm_chanid`), 1 to 2,047.
    pub channel: u32,
    /// MR1: the connection ID netvsc signals (`chm_connid`), below 2^24.
    pub connection: u32,
    /// MR2: the ring's GPADL handle.
    pub ring_gpadl: u32,
    /// MR3: the receive buffer's.
    pub rx_gpadl: u32,
    /// MR4: the send buffer's.
    pub tx_gpadl: u32,
    /// MR5: the VMBus version ([`VmbusVersion`]).
    pub version: u32,
    /// MR6 bits 0 to 7: the offer's `chm_flags1`, bit 0 `HASMNF`.
    pub flags1: u8,
    /// MR6 bits 8 to 15: `chm_montrig`, the monitor trigger.
    pub montrig: u8,
    /// MR6 bits 16 to 31: `chm_flags2`.
    pub flags2: u16,
    /// MR7: the VP index the channel's messages name.
    pub vp_index: u32,
}

impl VmbusAttach {
    /// The reply's words.
    pub const WORDS: usize = 8;
    /// `chm_flags1`'s `HASMNF`: the host may monitor the channel.
    pub const HAS_MNF: u8 = 1;
    /// Channel IDs VMBus gives a channel; 0 is not one.
    pub const MAX_CHANNEL: u32 = 2047;
    /// Connection IDs a Hypervisor capability takes: below 2^24.
    pub const CONNECTIONS: u32 = 1 << 24;

    pub const fn to_words(&self) -> [u64; Self::WORDS] {
        [
            self.channel as u64,
            self.connection as u64,
            self.ring_gpadl as u64,
            self.rx_gpadl as u64,
            self.tx_gpadl as u64,
            self.version as u64,
            self.flags1 as u64 | (self.montrig as u64) << 8 | (self.flags2 as u64) << 16,
            self.vp_index as u64,
        ]
    }

    /// The reply in `w`, or `None` for words `vmbus` never sends: a word
    /// past its field's width, a channel ID of 0 or above 2,047, or a
    /// connection ID of 2^24 or more.
    pub fn from_words(w: [u64; Self::WORDS]) -> Option<VmbusAttach> {
        let u32_of = |x: u64| u32::try_from(x).ok();
        let a = VmbusAttach {
            channel: u32_of(w[0])?,
            connection: u32_of(w[1])?,
            ring_gpadl: u32_of(w[2])?,
            rx_gpadl: u32_of(w[3])?,
            tx_gpadl: u32_of(w[4])?,
            version: u32_of(w[5])?,
            flags1: w[6] as u8,
            montrig: (w[6] >> 8) as u8,
            flags2: (w[6] >> 16) as u16,
            vp_index: u32_of(w[7])?,
        };
        let fits = w[6] >> 32 == 0
            && (1..=Self::MAX_CHANNEL).contains(&a.channel)
            && a.connection < Self::CONNECTIONS;
        fits.then_some(a)
    }

    pub const fn has_mnf(&self) -> bool {
        self.flags1 & Self::HAS_MNF != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::String;

    /// Distinct words, so that a field moved or dropped shows.
    fn counting<const N: usize>() -> [u64; N] {
        core::array::from_fn(|i| 100 + i as u64)
    }

    #[test]
    fn stats_round_trip_in_field_order() {
        let w = counting::<{ VirtioNetStats::WORDS }>();
        let v = VirtioNetStats::from_words(w);
        assert_eq!((v.signals, v.mac), (100, 108));
        assert_eq!(v.to_words(), w);
        let w = counting::<{ VmbusStats::WORDS }>();
        let s = VmbusStats::from_words(w);
        assert_eq!((s.version, s.ignored), (100, 108));
        assert_eq!(s.to_words(), w);
        let w = counting::<{ NetvscStats::WORDS }>();
        let s = NetvscStats::from_words(w);
        assert_eq!((s.nvsp, s.bad_entries), (100, 114));
        assert_eq!(s.to_words(), w);
        let w = counting::<{ NetStats::WORDS }>();
        let s = NetStats::from_words(w);
        assert_eq!((s.frames_in, s.udp_echoed, s.bad_entries), (100, 108, 130));
        assert_eq!(s.to_words(), w);
        // Every reply fits one message, past MR3 in the IPC buffers.
        assert_eq!(
            [
                VirtioNetStats::WORDS,
                VmbusStats::WORDS,
                NetvscStats::WORDS,
                NetStats::WORDS,
                VmbusAttach::WORDS
            ],
            [9, 9, 15, 31, 8]
        );
        const { assert!(NetStats::WORDS <= super::super::MAX_WORDS) };
    }

    #[test]
    fn version_and_feature_names() {
        let f = |x: u64| format!("{}", VirtioFeatures(x));
        use virtio_feature::{MAC as M, STATUS as S, VERSION_1 as V};
        assert_eq!(f(V | M | S), "VERSION_1 MAC STATUS");
        assert_eq!(f(S | M), "MAC STATUS");
        assert_eq!(f(V | 1 << 3), "VERSION_1 0x8");
        assert_eq!(f(1 << 40), "0x10000000000");
        assert_eq!(f(0), "none");
        let v = |x: u32| format!("{}", VmbusVersion(x));
        assert_eq!(
            [
                v(0x0004_0000),
                v(0x0003_0000),
                v(0x0002_0004),
                v(0x0001_0001),
                v(0)
            ],
            ["4.0", "3.0", "2.4", "1.1", "none"]
        );
        let n = |x: u32| format!("{}", NvspVersion(x));
        assert_eq!(
            [
                n(0x50000),
                n(0x40000),
                n(0x30002),
                n(0x2),
                n(0x60001),
                n(0),
                n(0x70000)
            ],
            ["5", "4", "2", "1", "6.1", "none", "0x70000"]
        );
        let d = |x: u32| format!("{}", NdisVersion(x));
        assert_eq!(
            [d(0x0006_001E), d(0x0006_0001), d(0)],
            ["6.30", "6.1", "none"]
        );
    }

    /// The `virtio_net` scenario reads the driver's counters and its 0 bad
    /// elements and entries; the `net` one expects the line's start.
    #[test]
    fn virtio_net_stats_text() {
        let s = VirtioNetStats {
            signals: 230,
            received: 104,
            sent: 103,
            features: virtio_feature::VERSION_1 | virtio_feature::MAC | virtio_feature::STATUS,
            mac: Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]).to_word(),
            ..VirtioNetStats::default()
        };
        assert_eq!(
            format!("virtio-net: stats: {s}"),
            "virtio-net: stats: 230 signals, 104 frames received, 0 dropped for no buffer, 0 bad used elements, 103 frames sent, 0 waits for a descriptor, 0 bad queue entries, features VERSION_1 MAC STATUS, MAC 52:54:00:12:34:56"
        );
    }

    #[test]
    fn vmbus_and_netvsc_stats_texts() {
        let s = VmbusStats {
            version: 0x0004_0000,
            offers: 9,
            netvsc_channel: 14,
            messages: 30,
            events: 250,
            eoms: 2,
            ..VmbusStats::default()
        };
        assert_eq!(
            format!("{s}"),
            "version 4.0, 9 offers, netvsc channel 14, 30 messages, 250 events relayed, 0 stray events, 2 Eoms, 0 post retries, 0 ignored messages"
        );
        let none = format!("{}", VmbusStats::default());
        assert!(none.starts_with("version none, 0 offers, no netvsc channel, 0 messages"));
        let s = NetvscStats {
            nvsp: 0x50000,
            ndis: 0x0006_001E,
            received: 104,
            sent: 103,
            ..NetvscStats::default()
        };
        let t = format!("{s}");
        assert!(t.starts_with("NVSP 5, NDIS 6.30, 0 receive-buffer packets, 104 frames received,"));
        assert!(t.ends_with(", 0 ignored messages, 0 bad queue entries"));
        assert!(t.contains(", 103 frames sent,"));
    }

    /// What the `net` scenario and the Hyper-V check match, each between
    /// commas, and every counter once.
    #[test]
    fn net_stats_text() {
        let s = NetStats {
            frames_in: 108,
            frames_out: 106,
            icmp_answered: 4,
            udp_received: 100,
            udp_echoed: 100,
            ..NetStats::default()
        };
        let t = format!("net: stats: {s}");
        assert!(
            t.starts_with("net: stats: 108 frames in, 106 frames out, 0 ARP requests answered,")
        );
        assert!(t.contains(", 100 datagrams echoed,"), "{t}");
        assert!(t.contains(", 4 ICMP echo requests answered,"), "{t}");
        assert!(t.contains(", 0 IPv4 checksum errors,"), "{t}");
        assert!(t.ends_with(", 0 bad queue entries"));
        // One item a word, each a number then words.
        let items: std::vec::Vec<String> = t["net: stats: ".len()..]
            .split(", ")
            .map(String::from)
            .collect();
        assert_eq!(items.len(), NetStats::WORDS);
        let n = NetStats::from_words(core::array::from_fn(|i| i as u64 + 1));
        let t = format!("{n}");
        for (i, item) in t.split(", ").enumerate() {
            let (num, what) = item.split_once(' ').unwrap();
            assert_eq!(num, format!("{}", i + 1), "{item}");
            assert!(!what.is_empty() && !what.contains(','));
        }
        // No item's text is another's.
        let whats: std::vec::Vec<&str> = t
            .split(", ")
            .map(|i| i.split_once(' ').unwrap().1)
            .collect();
        for (i, a) in whats.iter().enumerate() {
            assert!(whats[i + 1..].iter().all(|b| b != a), "{a}");
        }
    }

    #[test]
    fn attach_replies_round_trip_and_refuse_what_vmbus_never_sends() {
        let a = VmbusAttach {
            channel: 14,
            connection: 0x1_000E,
            ring_gpadl: 0xE1E10,
            rx_gpadl: 0xE1E11,
            tx_gpadl: 0xE1E12,
            version: 0x0004_0000,
            flags1: 1,
            montrig: 0x23,
            flags2: 0xBEEF,
            vp_index: 0,
        };
        let w = a.to_words();
        assert_eq!(w[6], 0xBEEF_2301);
        assert_eq!(VmbusAttach::from_words(w), Some(a));
        assert!(a.has_mnf());
        assert!(!VmbusAttach { flags1: 2, ..a }.has_mnf());
        for (i, bad) in [
            (0, 0),
            (0, 2048),
            (0, 1 << 32),
            (1, 1 << 24),
            (2, 1 << 32),
            (5, u64::MAX),
            (6, 1 << 32),
            (7, 1 << 32),
        ] {
            let mut w = w;
            w[i] = bad;
            assert_eq!(VmbusAttach::from_words(w), None, "MR{i} = {bad:#x}");
        }
        let mut w = w;
        w[0] = 2047;
        w[1] = (1 << 24) - 1;
        assert!(VmbusAttach::from_words(w).is_some());
    }
}
