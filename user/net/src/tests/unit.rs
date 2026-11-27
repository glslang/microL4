//! Unit tests: the checksum against a naive sum and RFC 1071's examples,
//! addresses, the configuration and its words, the texts root and the
//! scenarios match, the echo service's reply, and `link`'s start and pump
//! over a model of the frame queues.

use std::string::ToString;
use std::vec::Vec;
use std::{format, vec};

use proptest::prelude::*;

use super::wire::{arp, eth, ones_sum};
use crate::checksum::{self, Sum};
use libsys::frames::{self, Driver, LinkError, Net};
use libsys::mem::Ram;

use crate::link::{self, Report, Up};
use crate::{
    Config, ConfigError, Echo, Endpoint, Event, Ip, MAX_FRAME, Mac, NET_STATS, Reply, Service,
    Stack, Stats, echo,
};

const MAC: Mac = Mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);
const GW_MAC: [u8; 6] = [0x52, 0x55, 0x0a, 0x00, 0x02, 0x02];

#[test]
fn rfc_1071s_example_sums() {
    // RFC 1071, 3: the bytes 00 01 f2 03 f4 f5 f6 f7 sum to ddf2.
    let data = [0x00, 0x01, 0xf2, 0x03, 0xf4, 0xf5, 0xf6, 0xf7];
    assert_eq!(checksum::sum(&data), 0xddf2);
    assert_eq!(checksum::checksum(&data), 0x220d);
    // Byte-order independence (RFC 1071, 2(B)): swapping every pair swaps
    // the sum.
    let swapped = [0x01, 0x00, 0x03, 0xf2, 0xf5, 0xf4, 0xf7, 0xf6];
    assert_eq!(checksum::sum(&swapped), 0xf2dd);
    // Data with its checksum appended verifies.
    let mut with = data.to_vec();
    with.extend_from_slice(&0x220du16.to_be_bytes());
    assert!(checksum::verifies(&with));
    assert!(!checksum::verifies(&data));
}

#[test]
fn sums_of_nothing_zeros_and_odd_bytes() {
    assert_eq!(checksum::sum(&[]), 0);
    assert_eq!(checksum::checksum(&[]), 0xFFFF);
    assert_eq!(checksum::sum(&[0; 9]), 0);
    // An odd last byte is the high half of a word padded with 0.
    assert_eq!(checksum::sum(&[0x12]), 0x1200);
    assert_eq!(checksum::sum(&[0x00, 0x01, 0x02]), 0x0201);
    // Carries fold back in: ffff + 0001 is 0001.
    assert_eq!(checksum::sum(&[0xff, 0xff, 0x00, 0x01]), 0x0001);
    // Any length: far past a frame's.
    let n = if cfg!(miri) { 4_000 } else { 200_000 };
    let big = vec![0xFFu8; n];
    assert_eq!(checksum::sum(&big), ones_sum(&big));
    assert_eq!(checksum::sum(&big), 0xFFFF);
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 8 } else { 1024 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn the_sum_is_the_naive_sum_however_it_is_split(
        data in prop::collection::vec(any::<u8>(), 0..if cfg!(miri) { 64 } else { 2000 }),
        cuts in prop::collection::vec(any::<usize>(), 0..6),
    ) {
        prop_assert_eq!(checksum::sum(&data), ones_sum(&data));
        let mut at: Vec<usize> = cuts.iter().map(|c| c % (data.len() + 1)).collect();
        at.sort_unstable();
        let mut s = Sum::new();
        let mut from = 0;
        for c in at {
            s.add(&data[from..c]);
            from = c;
        }
        s.add(&data[from..]);
        prop_assert_eq!(s.fold(), ones_sum(&data));
        // With its checksum in an aligned, zeroed field, data verifies.
        let mut with = data.clone();
        if with.len() % 2 == 1 {
            with.push(0);
        }
        with.extend_from_slice(&[0, 0]);
        let c = checksum::checksum(&with);
        let n = with.len();
        with[n - 2..].copy_from_slice(&c.to_be_bytes());
        prop_assert!(checksum::verifies(&with));
    }

    #[test]
    fn config_parse_never_panics(text in "\\PC{0,40}", hyperv in any::<bool>()) {
        let line = format!("net.ip={text} net.gw={text}");
        let default = (!hyperv).then_some(Config::QEMU);
        let _ = Config::parse(&line, default).map(|c| c.to_string());
        let _ = Config::parse(&text, default);
    }

    #[test]
    fn config_words_round_trip(a in any::<u32>(), prefix in 0u8..40, g in any::<u32>()) {
        match Config::new(Ip::from_u32(a), prefix, Ip::from_u32(g)) {
            Ok(c) => prop_assert_eq!(Config::from_words(c.to_words()), Some(c)),
            Err(_) => {
                let w = [u64::from(a) | u64::from(prefix) << 32, u64::from(g), 0, 0];
                prop_assert_eq!(Config::from_words(w), None);
            }
        }
    }
}

#[test]
fn addresses_parse_strictly() {
    assert_eq!(Ip::parse("10.0.2.15"), Some(Ip::new(10, 0, 2, 15)));
    assert_eq!(Ip::parse("0.0.0.0"), Some(Ip::UNSPECIFIED));
    assert_eq!(Ip::parse("255.255.255.255"), Some(Ip::BROADCAST));
    for bad in [
        "",
        "10",
        "10.0.2",
        "10.0.2.15.1",
        "10.0.2.256",
        "10.0.2.015",
        "10.0.2.-1",
        "10.0.2.+1",
        "10..2.15",
        "10.0.2.15 ",
        " 10.0.2.15",
        "a.b.c.d",
        "1000.0.0.1",
        "10.0.2.1/24",
    ] {
        assert_eq!(Ip::parse(bad), None, "{bad:?}");
    }
    assert_eq!(Ip::new(192, 168, 77, 2).to_string(), "192.168.77.2");
    assert_eq!(Ip::new(10, 0, 2, 15).to_u32(), 0x0A00_020F);
    assert!(Ip::new(224, 0, 0, 1).is_multicast());
    assert!(Ip::new(239, 255, 255, 255).is_multicast());
    assert!(!Ip::new(240, 0, 0, 1).is_multicast());
    assert!(!Ip::new(223, 255, 255, 255).is_multicast());
}

#[test]
fn macs() {
    assert_eq!(MAC.to_string(), "52:54:00:12:34:56");
    assert!(MAC.is_unicast());
    assert!(!Mac::ZERO.is_unicast());
    assert!(!Mac::BROADCAST.is_unicast() && Mac::BROADCAST.is_multicast());
    assert!(!Mac([0x01, 0, 0x5E, 0, 0, 1]).is_unicast());
    assert!(Mac([0x02, 0, 0, 0, 0, 0]).is_unicast());
}

#[test]
fn qemus_default_and_the_command_line() {
    let q = Some(Config::QEMU);
    assert_eq!(Config::parse("test=net", q), Ok(Config::QEMU));
    assert_eq!(Config::QEMU.to_string(), "10.0.2.15/24 via 10.0.2.2");
    let c = Config::parse("test=net net.ip=192.168.77.2/24 net.gw=192.168.77.1", None).unwrap();
    assert_eq!(c.address(), Ip::new(192, 168, 77, 2));
    assert_eq!(c.prefix(), 24);
    assert_eq!(c.gateway(), Ip::new(192, 168, 77, 1));
    assert_eq!(c.network(), Ip::new(192, 168, 77, 0));
    assert_eq!(c.broadcast(), Ip::new(192, 168, 77, 255));
    // On QEMU each word has its default; the address alone keeps
    // 10.0.2.2, which must then be in its subnet.
    assert_eq!(
        Config::parse("net.ip=10.0.2.20/16", q).unwrap().to_string(),
        "10.0.2.20/16 via 10.0.2.2"
    );
    assert_eq!(
        Config::parse("net.gw=10.0.2.3", q).unwrap().to_string(),
        "10.0.2.15/24 via 10.0.2.3"
    );
    assert!(matches!(
        Config::parse("net.ip=192.168.1.5/24", q),
        Err(ConfigError::Gateway(_))
    ));
}

#[test]
fn hyperv_needs_both_words() {
    let none = Err(ConfigError::NoAddress);
    assert_eq!(Config::parse("test=net", None), none);
    assert_eq!(Config::parse("net.ip=192.168.77.2/24", None), none);
    assert_eq!(Config::parse("net.gw=192.168.77.1", None), none);
    assert_eq!(
        ConfigError::NoAddress.to_string(),
        "net: no address: pass net.ip=<a.b.c.d>/<n> net.gw=<a.b.c.d>"
    );
}

#[test]
fn configurations_refused() {
    fn p(s: &str) -> Result<Config, ConfigError<'_>> {
        Config::parse(s, None)
    }
    let gw = " net.gw=10.0.0.1";
    for (line, why) in [
        (
            "net.ip=10.0.0.2",
            "net: net.ip=\"10.0.0.2\" is not <a.b.c.d>/<n>",
        ),
        (
            "net.ip=10.0.0.2/",
            "net: net.ip=\"10.0.0.2/\" is not <a.b.c.d>/<n>",
        ),
        (
            "net.ip=10.0.0.2/024",
            "net: net.ip=\"10.0.0.2/024\" is not <a.b.c.d>/<n>",
        ),
        (
            "net.ip=10.0.0.2/08",
            "net: net.ip=\"10.0.0.2/08\" is not <a.b.c.d>/<n>",
        ),
        (
            "net.ip=10.0.0.02/24",
            "net: net.ip=\"10.0.0.02/24\" is not <a.b.c.d>/<n>",
        ),
        ("net.ip=10.0.0.2/7", "net: prefix /7 is not from 8 to 30"),
        ("net.ip=10.0.0.2/31", "net: prefix /31 is not from 8 to 30"),
        ("net.ip=10.0.0.2/32", "net: prefix /32 is not from 8 to 30"),
        (
            "net.ip=10.0.0.0/24",
            "net: 10.0.0.0/24 is not a unicast host address",
        ),
        (
            "net.ip=10.0.0.255/24",
            "net: 10.0.0.255/24 is not a unicast host address",
        ),
        (
            "net.ip=0.0.0.1/8",
            "net: 0.0.0.1/8 is not a unicast host address",
        ),
        (
            "net.ip=127.0.0.2/8",
            "net: 127.0.0.2/8 is not a unicast host address",
        ),
        (
            "net.ip=224.0.0.2/8",
            "net: 224.0.0.2/8 is not a unicast host address",
        ),
        (
            "net.ip=250.0.0.2/8",
            "net: 250.0.0.2/8 is not a unicast host address",
        ),
    ] {
        let line = format!("{line}{gw}");
        assert_eq!(p(&line).unwrap_err().to_string(), why, "{line}");
    }
    for (line, why) in [
        (
            "net.gw=10.0.1.1",
            "net: gateway 10.0.1.1 is not another host of 10.0.0.0/24",
        ),
        (
            "net.gw=10.0.0.2",
            "net: gateway 10.0.0.2 is not another host of 10.0.0.0/24",
        ),
        (
            "net.gw=10.0.0.0",
            "net: gateway 10.0.0.0 is not another host of 10.0.0.0/24",
        ),
        (
            "net.gw=10.0.0.255",
            "net: gateway 10.0.0.255 is not another host of 10.0.0.0/24",
        ),
        ("net.gw=10.0.0", "net: net.gw=\"10.0.0\" is not <a.b.c.d>"),
    ] {
        let line = format!("net.ip=10.0.0.2/24 {line}");
        assert_eq!(p(&line).unwrap_err().to_string(), why, "{line}");
    }
    // The widest and narrowest subnets.
    assert!(p("net.ip=10.1.2.3/8 net.gw=10.200.0.1").is_ok());
    assert!(p("net.ip=10.0.0.1/30 net.gw=10.0.0.2").is_ok());
    assert!(p("net.ip=10.0.0.1/30 net.gw=10.0.0.3").is_err());
}

#[test]
fn nets_arguments() {
    let w = Config::QEMU.to_words();
    assert_eq!(w, [0x18_0A00_020F, 0x0A00_0202, 0, 0]);
    assert_eq!(Config::from_words(w), Some(Config::QEMU));
    for bad in [
        [w[0] | 1 << 40, w[1], 0, 0],
        [w[0], w[1] | 1 << 32, 0, 0],
        [w[0], w[1], 1, 0],
        [w[0], w[1], 0, 1],
        [0x0A00_020F, w[1], 0, 0],
        [w[0], 0x0A00_020F, 0, 0],
    ] {
        assert_eq!(Config::from_words(bad), None, "{bad:x?}");
    }
}

#[test]
fn the_texts_root_and_the_scenarios_match() {
    let mut s = Stats {
        udp_echoed: 100,
        icmp_answered: 4,
        ..Stats::default()
    };
    s.frames_in = 7;
    let text = s.to_string();
    assert!(text.starts_with("7 frames in, 0 frames out, "), "{text}");
    assert!(text.contains(", 100 datagrams echoed,"), "{text}");
    assert!(text.contains(", 4 ICMP echo requests answered,"), "{text}");
    assert!(
        text.ends_with(", 0 waiting packets lost with their ARP entry"),
        "{text}"
    );
    assert_eq!(text.matches(", ").count(), Stats::WORDS - 1);
    assert_eq!(Stats::WORDS, 35);
    for (i, a) in Stats::NAMES.iter().enumerate() {
        assert!(!Stats::NAMES[i + 1..].contains(a), "{a} twice");
        assert!(!Stats::TEXTS[i].contains(','), "{}", Stats::TEXTS[i]);
    }
    const { assert!(Stats::WORDS < libsys::proto::MAX_WORDS) };
    assert_eq!(
        Event::Gateway {
            ip: Ip::new(10, 0, 2, 2),
            mac: Mac(GW_MAC)
        }
        .to_string(),
        "net: gateway 10.0.2.2 is at 52:55:0a:00:02:02"
    );
    assert_eq!(
        Event::Ping {
            ip: Ip::new(10, 0, 2, 2),
            seq: 1,
            bytes: 56
        }
        .to_string(),
        "net: ping 10.0.2.2: reply 1, 56 bytes"
    );
    assert_eq!(
        Up(Config::QEMU, MAC).to_string(),
        "net: up: 10.0.2.15/24 via 10.0.2.2, MAC 52:54:00:12:34:56"
    );
    assert_eq!(
        echo::LISTENING,
        format!("echo: listening on UDP port {}", echo::PORT)
    );
}

#[test]
fn every_outcome_has_its_own_counter() {
    use crate::Outcome;
    for (i, &o) in Outcome::ALL.iter().enumerate() {
        let mut s = Stats::default();
        s.count(o);
        assert_eq!(s.frames_in, 1);
        assert_eq!(s.outcome(o), 1);
        let ones = s.to_words().iter().filter(|&&w| w == 1).count();
        assert_eq!(ones, 2, "{o:?}");
        assert_eq!(s.dropped(), u64::from(!o.handled()));
        assert!(!Outcome::ALL[i + 1..].contains(&o));
    }
}

#[test]
fn nets_one_request() {
    use libsys::proto::Refusal;
    assert_eq!(link::request(NET_STATS, 0), Ok(()));
    assert_eq!(link::request(NET_STATS, 1), Err(Refusal::BadLength));
    assert_eq!(link::request(0x113, 0), Err(Refusal::BadLabel));
    assert_eq!(link::request(0, 0), Err(Refusal::BadLabel));
}

#[test]
fn a_reply_is_one_datagram_of_at_most_1472_bytes() {
    let big = [0u8; 1473];
    let mut r = Reply::new();
    assert!(!r.send(&big));
    assert!(r.send(&big[..1472]));
    assert!(!r.send(b"again"));
    assert_eq!(r.take().map(<[u8]>::len), Some(1472));
    let from = Endpoint {
        ip: Ip::new(10, 0, 2, 2),
        port: 9,
    };
    let mut r = Reply::new();
    Echo.datagram(from, b"hello", &mut r);
    assert_eq!(r.take(), Some(&b"hello"[..]));
    assert_eq!(<Echo as Service>::PORT, 7);
}

/// Zeroed memory for the queues: what their layout uses.
fn ram() -> Ram {
    Ram::new(frames::layout::END)
}

/// The driver's side, started with `mac`.
fn driver(ram: &Ram, mac: Mac) -> Driver<&Ram> {
    let mut d = Driver::new(ram);
    d.start(frames::Link::new(mac, true));
    assert!(d.end_batch());
    d
}

#[test]
fn start_reads_the_link_and_asks_for_the_gateway() {
    let r = ram();
    let mut n = Net::new(&r);
    assert_eq!(
        link::start(Config::QEMU, &mut n).err(),
        Some(LinkError::NotReady(0))
    );
    for bad in [Mac::ZERO, Mac::BROADCAST, Mac([0x33, 0x33, 0, 0, 0, 1])] {
        let r = ram();
        let _d = driver(&r, bad);
        let mut n = Net::new(&r);
        assert_eq!(
            link::start(Config::QEMU, &mut n).err(),
            Some(LinkError::BadMac(bad))
        );
    }
    let r = ram();
    let mut d = driver(&r, MAC);
    let mut n = Net::new(&r);
    let stack = link::start(Config::QEMU, &mut n).unwrap();
    assert_eq!(stack.mac(), MAC);
    assert!(n.end_batch());
    // The driver has every receive buffer, and the request for the
    // gateway, padded to 60 bytes.
    assert_eq!(d.reclaim(), 128);
    let mut out = [0u8; MAX_FRAME];
    assert_eq!(d.take_tx(&mut out), Some(60));
    assert_eq!(&out[..6], &[0xFF; 6]);
    assert_eq!(&out[38..42], &[10, 0, 2, 2]);
    assert_eq!(d.take_tx(&mut out), None);
    assert_eq!(stack.stats().arp_sent, 1);
}

#[test]
fn a_pump_answers_a_full_queue() {
    let r = ram();
    let mut d = driver(&r, MAC);
    let mut n = Net::new(&r);
    let mut stack = link::start(Config::QEMU, &mut n).unwrap();
    n.end_batch();
    let mut out = [0u8; MAX_FRAME];
    assert!(d.take_tx(&mut out).is_some());
    // The gateway's reply, then 127 requests from it for the stack: every
    // receive buffer.
    let us = [10, 0, 2, 15];
    let gw = [10, 0, 2, 2];
    d.deliver(&eth(MAC.0, GW_MAC, 0x0806, &arp(2, GW_MAC, gw, MAC.0, us)))
        .unwrap();
    let request = eth([0xFF; 6], GW_MAC, 0x0806, &arp(1, GW_MAC, gw, [0; 6], us));
    for _ in 0..127 {
        d.deliver(&request).unwrap();
    }
    assert!(d.end_batch());
    assert!(link::pump(&mut stack, &mut n));
    assert_eq!(stack.stats().frames_in, 128);
    // The ping, then 127 ARP replies: every transmit buffer.
    let mut sent = Vec::new();
    while let Some(len) = d.take_tx(&mut out) {
        sent.push(out[..len].to_vec());
    }
    assert_eq!(sent.len(), 128);
    assert_eq!(&sent[0][12..14], &[8, 0]);
    assert!(sent[1..].iter().all(|f| f[12..14] == [8, 6] && f[21] == 2));
    assert_eq!(stack.stats().ping_sent, 1);
    assert_eq!(stack.stats().arp_answered, 127);
    // An empty pump pushes nothing.
    assert!(!link::pump(&mut stack, &mut n));
    assert_eq!(
        stack.event(),
        Some(Event::Gateway {
            ip: Ip::new(10, 0, 2, 2),
            mac: Mac(GW_MAC)
        })
    );
    assert_eq!(stack.event(), None);
    let q = n.counters();
    assert_eq!((q.received, q.sent, q.bad, q.dropped), (128, 129, 0, 0));
}

#[test]
fn with_no_transmit_buffer_the_stack_drops_and_counts() {
    let r = ram();
    let mut d = driver(&r, MAC);
    let mut n = Net::new(&r);
    let mut stack = link::start(Config::QEMU, &mut n).unwrap();
    n.end_batch();
    let us = [10, 0, 2, 15];
    let gw = [10, 0, 2, 2];
    // The driver takes no frame to send, so it returns no transmit buffer:
    // net's 128 go to the request at the start, the ping once the first
    // request resolves the gateway, and 126 replies; the last is dropped.
    let request = eth([0xFF; 6], GW_MAC, 0x0806, &arp(1, GW_MAC, gw, [0; 6], us));
    for _ in 0..127 {
        d.deliver(&request).unwrap();
    }
    assert!(link::pump(&mut stack, &mut n));
    assert_eq!(stack.stats().ping_sent, 1);
    assert_eq!(stack.stats().tx_full, 1);
    for _ in 0..10 {
        d.deliver(&request).unwrap();
    }
    assert!(
        link::pump(&mut stack, &mut n),
        "the receive buffers go back"
    );
    assert_eq!(stack.stats().tx_full, 11);
    assert_eq!(stack.stats().frames_out, 128);
    assert_eq!(stack.stats().arp_answered, 137);
    assert_eq!(
        n.counters().dropped,
        0,
        "net never asks for a buffer it lacks"
    );
}

#[test]
fn nets_report() {
    let mut w = [0u64; Report::WORDS];
    for (i, x) in w.iter_mut().enumerate() {
        *x = 7 + i as u64;
    }
    let r = Report::from_words(w);
    assert_eq!(r.to_words(), w);
    assert_eq!(r.stack.frames_in, 7);
    assert_eq!(r.queues.signals, 7 + 40);
    assert_eq!(Report::WORDS, 41);
    const { assert!(Report::WORDS <= libsys::proto::MAX_WORDS) };
    let text = Report::default().to_string();
    assert!(text.contains(", 0 datagrams echoed,"), "{text}");
    assert!(
        text.ends_with(
            "; queues: 0 frames sent, 0 received, 0 buffers reclaimed, 0 frames dropped, 0 bad entries, 0 signals"
        ),
        "{text}"
    );
}

#[test]
fn a_stack_is_small_enough_for_nets_stack() {
    // net's thread keeps one on a 64 KiB stack, with two frames' buffers.
    assert!(core::mem::size_of::<Stack>() < 8 << 10);
}
