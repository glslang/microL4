//! The stack's counters (`docs/design.md`, "`net`"): frames in and out,
//! what it answered, sent and learnt, and every drop by its reason.
//!
//! Every frame [`crate::Stack::input`] takes adds 1 to `frames_in` and 1
//! to exactly one [`Outcome`]'s counter, so `frames_in` is their sum. The
//! rest count what goes out: frames, requests and echoes sent, and the
//! frames the stack built but could not send. Root's `Stats` reply carries
//! [`Stats::to_words`], MR0 first; its line is `net: stats: ` and the
//! [`Display`](core::fmt::Display) text, each counter as `<n> <what>`.

use core::fmt;

macro_rules! counters {
    ($($(#[$doc:meta])* $field:ident: $text:literal,)*) => {
        /// The counters, in their words' order.
        #[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
        pub struct Stats {
            $($(#[$doc])* pub $field: u64,)*
        }

        impl Stats {
            /// The reply's words.
            pub const WORDS: usize = [$(stringify!($field)),*].len();
            /// Each counter's field name, as the goldens' `stats:` lines
            /// give it.
            pub const NAMES: [&'static str; Self::WORDS] = [$(stringify!($field)),*];
            /// What each counter counts, as the text gives it.
            pub const TEXTS: [&'static str; Self::WORDS] = [$($text),*];

            pub const fn to_words(&self) -> [u64; Self::WORDS] {
                [$(self.$field),*]
            }

            pub const fn from_words(w: [u64; Self::WORDS]) -> Stats {
                let mut i = 0;
                $(
                    let $field = w[i];
                    i += 1;
                )*
                let _ = i;
                Stats { $($field),* }
            }
        }
    };
}

counters! {
    /// MR0: frames `input` took.
    frames_in: "frames in",
    /// MR1: frames handed to the driver.
    frames_out: "frames out",
    /// ARP requests for the stack's address, each answered.
    arp_answered: "ARP requests answered",
    /// ARP requests sent.
    arp_sent: "ARP requests sent",
    /// ARP replies to the stack's address, each learnt.
    arp_learnt: "ARP replies learnt",
    /// ICMP echo requests to the stack's address, each answered.
    icmp_answered: "ICMP echo requests answered",
    /// The stack's one echo request to the gateway, once sent.
    ping_sent: "ICMP echo requests sent",
    /// Echo replies matching it.
    icmp_replies: "ICMP echo replies received",
    /// Datagrams to port 7 given to the echo service.
    udp_received: "datagrams received",
    /// The echoes sent.
    udp_echoed: "datagrams echoed",
    /// Frames shorter than an Ethernet header.
    eth_short: "frames under 14 bytes",
    /// Frames longer than 1,514 bytes.
    eth_long: "frames over 1514 bytes",
    /// Frames to another MAC, multicast among them.
    eth_not_ours: "frames to other MACs",
    /// Frames of an EtherType but IPv4 and ARP, VLAN and IPv6 among them.
    eth_type: "frames of other EtherTypes",
    /// ARP packets not Ethernet and IPv4, not a request or reply, or
    /// short.
    arp_malformed: "ARP packets malformed",
    /// ARP packets whose sender is 0, a broadcast, a group or the stack.
    arp_bad_sender: "ARP packets from bad senders",
    /// ARP packets for another address: merged if their sender is in the
    /// cache, never answered.
    arp_not_ours: "ARP packets for other addresses",
    /// IPv4 packets with a bad version, IHL or length.
    ip_malformed: "IPv4 packets malformed",
    /// IPv4 headers whose checksum does not verify.
    ip_checksum: "IPv4 header checksum errors",
    /// IPv4 fragments: no reassembly.
    ip_fragment: "IPv4 fragments",
    /// IPv4 packets to an address but the stack's and `255.255.255.255`.
    ip_not_ours: "IPv4 packets to other addresses",
    /// IPv4 packets from 0, a broadcast, a multicast group or the stack.
    ip_bad_source: "IPv4 packets from bad sources",
    /// IPv4 packets of a protocol but ICMP and UDP.
    ip_protocol: "IPv4 packets of other protocols",
    /// ICMP messages shorter than their header.
    icmp_short: "ICMP messages too short",
    /// ICMP messages whose checksum does not verify.
    icmp_checksum: "ICMP checksum errors",
    /// Echo requests to a broadcast address, never answered.
    icmp_broadcast: "ICMP echo requests to broadcast",
    /// Other types and codes, and echo replies the stack did not ask for.
    icmp_other: "ICMP messages of other kinds",
    /// UDP datagrams whose length is under 8 or past the IP payload.
    udp_length: "UDP length errors",
    /// UDP datagrams whose checksum does not verify.
    udp_checksum: "UDP checksum errors",
    /// Datagrams to a port but 7, dropped silently.
    udp_port: "datagrams to other ports",
    /// Datagrams to port 7 from port 0 or 7, or to a broadcast.
    udp_refused: "datagrams refused",
    /// Frames built with no transmit buffer free.
    tx_full: "frames dropped for want of a transmit buffer",
    /// Waiting packets replaced by a later one to the same address.
    held_replaced: "waiting packets replaced",
    /// Packets dropped because four already waited.
    held_full: "packets dropped with 4 waiting",
    /// Waiting packets dropped with the ARP entry they waited in, which a
    /// new address replaced.
    held_evicted: "waiting packets lost with their ARP entry",
}

/// What became of one frame `input` took: handled, or dropped for one
/// reason, in the order the checks run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Outcome {
    ArpAnswered,
    ArpLearnt,
    IcmpAnswered,
    IcmpReply,
    UdpReceived,
    EthShort,
    EthLong,
    EthNotOurs,
    EthType,
    ArpMalformed,
    ArpBadSender,
    ArpNotOurs,
    IpMalformed,
    IpChecksum,
    IpFragment,
    IpNotOurs,
    IpBadSource,
    IpProtocol,
    IcmpShort,
    IcmpChecksum,
    IcmpBroadcast,
    IcmpOther,
    UdpLength,
    UdpChecksum,
    UdpPort,
    UdpRefused,
}

impl Outcome {
    /// Every outcome.
    pub const ALL: [Outcome; 26] = [
        Outcome::ArpAnswered,
        Outcome::ArpLearnt,
        Outcome::IcmpAnswered,
        Outcome::IcmpReply,
        Outcome::UdpReceived,
        Outcome::EthShort,
        Outcome::EthLong,
        Outcome::EthNotOurs,
        Outcome::EthType,
        Outcome::ArpMalformed,
        Outcome::ArpBadSender,
        Outcome::ArpNotOurs,
        Outcome::IpMalformed,
        Outcome::IpChecksum,
        Outcome::IpFragment,
        Outcome::IpNotOurs,
        Outcome::IpBadSource,
        Outcome::IpProtocol,
        Outcome::IcmpShort,
        Outcome::IcmpChecksum,
        Outcome::IcmpBroadcast,
        Outcome::IcmpOther,
        Outcome::UdpLength,
        Outcome::UdpChecksum,
        Outcome::UdpPort,
        Outcome::UdpRefused,
    ];

    /// Whether the frame was handled rather than dropped.
    pub const fn handled(self) -> bool {
        matches!(
            self,
            Outcome::ArpAnswered
                | Outcome::ArpLearnt
                | Outcome::IcmpAnswered
                | Outcome::IcmpReply
                | Outcome::UdpReceived
        )
    }
}

impl Stats {
    /// The counter of `o`.
    pub const fn outcome(&self, o: Outcome) -> u64 {
        match o {
            Outcome::ArpAnswered => self.arp_answered,
            Outcome::ArpLearnt => self.arp_learnt,
            Outcome::IcmpAnswered => self.icmp_answered,
            Outcome::IcmpReply => self.icmp_replies,
            Outcome::UdpReceived => self.udp_received,
            Outcome::EthShort => self.eth_short,
            Outcome::EthLong => self.eth_long,
            Outcome::EthNotOurs => self.eth_not_ours,
            Outcome::EthType => self.eth_type,
            Outcome::ArpMalformed => self.arp_malformed,
            Outcome::ArpBadSender => self.arp_bad_sender,
            Outcome::ArpNotOurs => self.arp_not_ours,
            Outcome::IpMalformed => self.ip_malformed,
            Outcome::IpChecksum => self.ip_checksum,
            Outcome::IpFragment => self.ip_fragment,
            Outcome::IpNotOurs => self.ip_not_ours,
            Outcome::IpBadSource => self.ip_bad_source,
            Outcome::IpProtocol => self.ip_protocol,
            Outcome::IcmpShort => self.icmp_short,
            Outcome::IcmpChecksum => self.icmp_checksum,
            Outcome::IcmpBroadcast => self.icmp_broadcast,
            Outcome::IcmpOther => self.icmp_other,
            Outcome::UdpLength => self.udp_length,
            Outcome::UdpChecksum => self.udp_checksum,
            Outcome::UdpPort => self.udp_port,
            Outcome::UdpRefused => self.udp_refused,
        }
    }

    /// Counts one frame in, with its outcome.
    pub fn count(&mut self, o: Outcome) {
        self.frames_in += 1;
        let c = match o {
            Outcome::ArpAnswered => &mut self.arp_answered,
            Outcome::ArpLearnt => &mut self.arp_learnt,
            Outcome::IcmpAnswered => &mut self.icmp_answered,
            Outcome::IcmpReply => &mut self.icmp_replies,
            Outcome::UdpReceived => &mut self.udp_received,
            Outcome::EthShort => &mut self.eth_short,
            Outcome::EthLong => &mut self.eth_long,
            Outcome::EthNotOurs => &mut self.eth_not_ours,
            Outcome::EthType => &mut self.eth_type,
            Outcome::ArpMalformed => &mut self.arp_malformed,
            Outcome::ArpBadSender => &mut self.arp_bad_sender,
            Outcome::ArpNotOurs => &mut self.arp_not_ours,
            Outcome::IpMalformed => &mut self.ip_malformed,
            Outcome::IpChecksum => &mut self.ip_checksum,
            Outcome::IpFragment => &mut self.ip_fragment,
            Outcome::IpNotOurs => &mut self.ip_not_ours,
            Outcome::IpBadSource => &mut self.ip_bad_source,
            Outcome::IpProtocol => &mut self.ip_protocol,
            Outcome::IcmpShort => &mut self.icmp_short,
            Outcome::IcmpChecksum => &mut self.icmp_checksum,
            Outcome::IcmpBroadcast => &mut self.icmp_broadcast,
            Outcome::IcmpOther => &mut self.icmp_other,
            Outcome::UdpLength => &mut self.udp_length,
            Outcome::UdpChecksum => &mut self.udp_checksum,
            Outcome::UdpPort => &mut self.udp_port,
            Outcome::UdpRefused => &mut self.udp_refused,
        };
        *c += 1;
    }

    /// The frames in that were dropped, for any reason.
    pub fn dropped(&self) -> u64 {
        Outcome::ALL
            .iter()
            .filter(|o| !o.handled())
            .map(|&o| self.outcome(o))
            .sum()
    }
}

/// `1 frames in, 1 frames out, ...`, every counter in its words' order,
/// so `, 100 datagrams echoed,` and `, 4 ICMP echo requests answered,`
/// can be matched whole.
impl fmt::Display for Stats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        for (i, (n, what)) in self.to_words().iter().zip(Stats::TEXTS).enumerate() {
            if i > 0 {
                f.write_str(", ")?;
            }
            write!(f, "{n} {what}")?;
        }
        Ok(())
    }
}
