//! Hostile host messages: every malformed or unexpected one is counted
//! and ignored, never followed, and a proptest of random ones at random
//! moments, under which vmbus never panics, never stalls the slot, and
//! never names a page outside root's (the mock fails any other).

use core::sync::atomic::Ordering::Relaxed;

use hvmock::wire::{self, kind};
use hvmock::{OfferSpec, Restriction};
use proptest::prelude::*;

use super::*;
use crate::gpadl::START as H0;

/// A message with type `k` and `len` bytes.
fn of_kind(k: u32, len: usize) -> Vec<u8> {
    let mut v = vec![0u8; len.max(4)];
    v[..4].copy_from_slice(&k.to_le_bytes());
    v.truncate(len);
    v
}

/// Each of these is ignored, before, during and after setup, and setup
/// still brings the channel up.
fn hostile_messages() -> Vec<(&'static str, u32, u8, Vec<u8>)> {
    let ch = |m: Vec<u8>| (1, m.len() as u8, m);
    let offer_bytes = |o: OfferSpec| wire::offer(&o);
    let mut v: Vec<(&'static str, u32, u8, Vec<u8>)> = Vec::new();
    let mut add = |what: &'static str, (t, n, m): (u32, u8, Vec<u8>)| v.push((what, t, n, m));
    add("a SynIC message of type 2", (2, 12, wire::rescind(14)));
    add("a hypervisor message type", (0x8000_0010, 8, of_kind(4, 8)));
    add("PayloadSize 0", (1, 0, vec![]));
    add("PayloadSize 7", (1, 7, of_kind(4, 7)));
    add("PayloadSize 241", (1, 241, of_kind(4, 240)));
    add("PayloadSize 255", (1, 255, of_kind(4, 240)));
    for k in [0, kind::CHFREE, kind::DISCONNECT, 17, 23, 0xFFFF_FFFF] {
        add("an unknown channel message", ch(of_kind(k, 40)));
    }
    add("a short offer", {
        let mut o = offer_bytes(OfferSpec::netvsc(30, 30));
        o.truncate(195);
        ch(o)
    });
    add(
        "an offer of channel 0",
        ch(offer_bytes(OfferSpec::netvsc(0, 30))),
    );
    add(
        "an offer of channel 2048",
        ch(offer_bytes(OfferSpec::netvsc(2048, 30))),
    );
    add(
        "an offer whose connection has reserved bits",
        ch(offer_bytes(OfferSpec::storvsc(40, 1 << 24))),
    );
    add(
        "a repeated offer",
        ch(offer_bytes(OfferSpec::storvsc(1, 1))),
    );
    add("a short rescind", ch(of_kind(kind::CHRESCIND, 11)));
    add("a rescind of nothing", ch(wire::rescind(99)));
    add("a CONNECT_RESP after contact", ch(wire::connect_resp(true)));
    for h in [H0, H0 + 1, H0 + 2] {
        add(
            "a GPADL answer for another channel",
            ch(wire::gpadl_connresp(3, h, 0)),
        );
    }
    add(
        "a GPADL answer for another handle",
        ch(wire::gpadl_connresp(14, H0 + 9, 0)),
    );
    add(
        "an open answer for another open ID",
        ch(wire::chopen_resp(14, 15, 0)),
    );
    add(
        "an open answer for another channel",
        ch(wire::chopen_resp(3, 3, 0)),
    );
    add(
        "a short GPADL answer",
        ch(of_kind(kind::GPADL_CONNRESP, 19)),
    );
    add(
        "a teardown answer for nothing",
        ch(wire::gpadl_disconnresp(H0)),
    );
    add("a guest's own message", ch(of_kind(kind::CHOPEN, 148)));
    v
}

/// Each hostile message alone, injected before start (it is in the slot
/// before vmbus looks), ahead of the host's answer to each request that
/// waits for one, and after setup: it is counted and ignored, vmbus posts
/// nothing for it, and setup then brings the channel up as ever.
#[test]
fn hostile_messages_are_counted_and_ignored() {
    let all = hostile_messages();
    // CONNECT is request 0, CHREQUEST 1, the ring's GPADL 2 and 3, CHOPEN
    // 4, the receive buffer's GPADL 5 to 14 and the send buffer's 15 to
    // 21.
    let phases = [
        ("before", None),
        ("contact", Some(0)),
        ("offers", Some(1)),
        ("ring", Some(2)),
        ("open", Some(4)),
        ("receive", Some(5)),
        ("send", Some(15)),
        ("after", None),
    ];
    // Under Miri, two messages a phase, a different two each.
    let step = if cfg!(miri) { all.len() / 2 } else { 1 };
    for (p, (at, hold_from)) in phases.into_iter().enumerate() {
        for (what, t, n, b) in all.iter().skip(p % step).step_by(step) {
            let m = Machine::new();
            let cfg = Config {
                hold_from,
                ..Config::default()
            };
            let mut r = Rig::new(&m, cfg);
            if at == "before" {
                r.host.inject_raw(*t, *n, b);
                m.take_interrupt();
            }
            r.start();
            if hold_from.is_some() {
                assert!(r.host.held() >= 1, "{at}");
                let posted = r.host.posts().len();
                r.host.inject_raw(*t, *n, b);
                r.run();
                // A CONNECT_RESP carries no version: one that comes first
                // is the answer, and the host's own is ignored after.
                let taken = at == "contact" && *what == "a CONNECT_RESP after contact";
                if !taken {
                    assert_eq!(r.host.posts().len(), posted, "{what}, {at}: followed");
                }
                assert!(r.bus.stats().ignored <= 1, "{what}, {at}");
                r.host.resume();
                r.run();
            }
            if at == "after" {
                r.host.inject_raw(*t, *n, b);
                r.run();
            }
            r.honest();
            let s = r.bus.stats();
            assert_eq!(s.ignored, 1, "{what}, {at}");
            assert_eq!(s.messages, r.host.delivered(), "{what}, {at}");
            assert!(r.bus.attached().is_some(), "{what}, {at}");
            assert_eq!(r.sys.lines, default_lines(), "{what}, {at}");
            assert_eq!(r.sys.mints.len(), 1, "{what}, {at}");
        }
    }
}

/// A CONNECT_RESP that comes before the host's own is taken for it: an
/// answer carries no version. A hostile `done` of 0 moves vmbus to the
/// next version, as the host's own would; the host's real answer then
/// answers that, and the stale one after is ignored.
#[test]
fn an_early_connect_resp_moves_contact_on() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.host.inject(&wire::connect_resp(false));
    m.take_interrupt();
    r.start();
    assert_eq!(r.host.contact().unwrap().version, version(4, 0));
    assert_eq!(r.bus.stats().version, u64::from(version(3, 0)));
    // The host logged the second CONNECT, after contact.
    assert_eq!(r.host.log().len(), 1);
    assert!(r.bus.attached().is_some());
}

/// 32 offers are kept; the 33rd, netvsc's, is not, so there is none to
/// open.
#[test]
fn offers_past_32_are_ignored() {
    let m = Machine::new();
    let mut offers: Vec<OfferSpec> = (1..=32).map(|c| OfferSpec::heartbeat(c, c)).collect();
    offers.push(OfferSpec::netvsc(40, 40));
    let cfg = Config {
        offers,
        ..Config::default()
    };
    let mut r = Rig::new(&m, cfg);
    r.start();
    let s = r.bus.stats();
    assert_eq!((s.offers, s.ignored), (32, 1));
    assert!(r.bus.stopped());
    assert_eq!(r.lines().last(), Some(&"vmbus: no netvsc offer"));
}

/// A hostile message for the proptest.
#[derive(Clone, Debug)]
enum Hostile {
    /// Any SynIC message.
    Raw {
        kind: u32,
        size: u8,
        bytes: Vec<u8>,
    },
    /// A channel message of any type and bytes.
    Channel {
        kind: u32,
        bytes: Vec<u8>,
    },
    Offer {
        channel: u32,
        connection: u32,
        netvsc: bool,
        subchannel: u16,
    },
    GpadlAnswer {
        channel: u32,
        gpadl: u32,
        status: u32,
    },
    OpenAnswer {
        channel: u32,
        open_id: u32,
        status: u32,
    },
    Teardown {
        gpadl: u32,
    },
    Rescind {
        channel: u32,
    },
    Done,
    Connect {
        done: bool,
    },
}

impl Hostile {
    fn inject(&self, host: &mut Host<'_>) {
        match self {
            Hostile::Raw { kind, size, bytes } => host.inject_raw(*kind, *size, bytes),
            Hostile::Channel { kind, bytes } => {
                let mut b = kind.to_le_bytes().to_vec();
                b.extend_from_slice(bytes);
                host.inject(&b);
            }
            Hostile::Offer {
                channel,
                connection,
                netvsc,
                subchannel,
            } => {
                let o = if *netvsc {
                    OfferSpec::netvsc(*channel, *connection)
                } else {
                    OfferSpec::unknown(*channel, *connection)
                };
                let o = OfferSpec {
                    subchannel: *subchannel,
                    ..o
                };
                host.inject(&wire::offer(&o));
            }
            Hostile::GpadlAnswer {
                channel,
                gpadl,
                status,
            } => host.inject(&wire::gpadl_connresp(*channel, *gpadl, *status)),
            Hostile::OpenAnswer {
                channel,
                open_id,
                status,
            } => host.inject(&wire::chopen_resp(*channel, *open_id, *status)),
            Hostile::Teardown { gpadl } => host.inject(&wire::gpadl_disconnresp(*gpadl)),
            Hostile::Rescind { channel } => host.inject(&wire::rescind(*channel)),
            Hostile::Done => host.inject(&wire::offers_done()),
            Hostile::Connect { done } => host.inject(&wire::connect_resp(*done)),
        }
    }
}

/// IDs near the ones vmbus uses, and any.
fn channel() -> impl Strategy<Value = u32> {
    prop_oneof![Just(14), 0..20u32, 2040..2060u32, any::<u32>()]
}

fn handle() -> impl Strategy<Value = u32> {
    prop_oneof![H0..H0 + 4, any::<u32>()]
}

fn status() -> impl Strategy<Value = u32> {
    prop_oneof![Just(0), any::<u32>()]
}

fn hostile() -> impl Strategy<Value = Hostile> {
    prop_oneof![
        (
            prop_oneof![Just(1u32), Just(2), 1..u32::MAX],
            any::<u8>(),
            prop::collection::vec(any::<u8>(), 0..240)
        )
            .prop_map(|(kind, size, bytes)| Hostile::Raw { kind, size, bytes }),
        (0..20u32, prop::collection::vec(any::<u8>(), 0..236))
            .prop_map(|(kind, bytes)| Hostile::Channel { kind, bytes }),
        (channel(), channel(), any::<bool>(), 0..3u16).prop_map(
            |(channel, connection, netvsc, subchannel)| Hostile::Offer {
                channel,
                connection,
                netvsc,
                subchannel
            }
        ),
        (channel(), handle(), status()).prop_map(|(channel, gpadl, status)| {
            Hostile::GpadlAnswer {
                channel,
                gpadl,
                status,
            }
        }),
        (channel(), channel(), status()).prop_map(|(channel, open_id, status)| {
            Hostile::OpenAnswer {
                channel,
                open_id,
                status,
            }
        }),
        handle().prop_map(|gpadl| Hostile::Teardown { gpadl }),
        channel().prop_map(|channel| Hostile::Rescind { channel }),
        Just(Hostile::Done),
        any::<bool>().prop_map(|done| Hostile::Connect { done }),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// Random hostile messages, each after some turns, while the host may
    /// hold its answers from a random request on and let them go at a
    /// random point. Whatever they do, vmbus never panics, takes every
    /// message the host delivers, leaves the slot empty and nothing
    /// queued, names only root's pages (the mock fails any other), and
    /// ends either with netvsc's channel open on the host as it says, or
    /// stopped.
    #[test]
    fn random_hostile_messages_never_derail_vmbus(
        messages in prop::collection::vec((0..4usize, hostile()), 1..if cfg!(miri) { 6 } else { 40 }),
        hold_from in prop::option::of(1..26usize),
        resume_at in 0..40usize,
        late in any::<bool>(),
    ) {
        let m = Machine::new();
        m.set_late_pending(late);
        let cfg = Config { hold_from, ..Config::default() };
        let mut r = Rig::new(&m, cfg);
        r.bus.start(&mut r.host, &mut r.sys);
        // Contact first: a hostile CONNECT_RESP during contact can make
        // the host's refusals look like every version's.
        while r.bus.stats().version == 0 {
            prop_assert!(r.turn());
        }
        for (i, (turns, h)) in messages.iter().enumerate() {
            for _ in 0..*turns {
                r.turn();
            }
            if i == resume_at {
                r.host.resume();
            }
            h.inject(&mut r.host);
        }
        r.run();
        r.host.resume();
        r.run();
        let s = r.bus.stats();
        prop_assert_eq!(s.messages, r.host.delivered());
        prop_assert_eq!(r.host.queued(), 0);
        prop_assert_eq!(r.host.held(), 0);
        prop_assert_eq!(m.ram().load32(machine::SIM as usize + 512, Relaxed), 0);
        prop_assert!(!m.interrupt_pending());
        match r.bus.attached() {
            Some(a) => {
                prop_assert!(!r.bus.stopped());
                // The first primary netvsc offer kept: the host's, or a hostile
                // one of a channel the host offered as another device.
                prop_assert_eq!(Some(a.channel), r.bus.offers().netvsc().map(|o| o.channel));
                let open = r.host.channel(a.channel).unwrap().open.unwrap();
                prop_assert_eq!(open.gpadl, a.ring_gpadl);
                prop_assert!(r.host.gpadl(a.rx_gpadl).is_some());
                prop_assert!(r.host.gpadl(a.tx_gpadl).is_some());
                // The capability names the connection of the offer vmbus
                // kept for the channel: a hostile offer of channel 14 that
                // comes before the host's own is that offer, and its
                // connection is the one netvsc may signal.
                let kept = r.bus.offers().get(a.channel).unwrap();
                prop_assert!(kept.is_netvsc());
                prop_assert_eq!(a.connection, kept.connection);
                prop_assert_eq!(&r.sys.mints, &[Bus::<Page<'_>>::mint_data(a.connection)]);
                prop_assert_eq!(
                    Restriction::from_data(r.sys.mints[0]),
                    Some(Restriction::signal_only(a.connection))
                );
            }
            None => prop_assert!(r.bus.stopped() || r.sys.mints.is_empty()),
        }
        prop_assert!(r.sys.revokes as usize <= r.sys.mints.len());
    }
}
