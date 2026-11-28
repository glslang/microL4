//! Contact, offers, netvsc's channel, `Attach`, teardown, rescind, the
//! event scan, the message slot and post retries, against the mock host.

use hvmock::wire::kind as w;
use hvmock::{OfferSpec, REFUSED, Restriction};
use libsys::proto::{Refusal, VmbusAttach, VmbusStats};

use super::*;
use crate::gpadl::START as H0;
use crate::layout::{RECEIVE, RING, SEND};

/// The requests a whole bring-up posts after contact: CHREQUEST, the
/// ring's GPADL (2 messages), CHOPEN, the receive buffer's (10) and the
/// send buffer's (7).
fn bring_up_kinds() -> Vec<u32> {
    let mut v = vec![w::CHREQUEST, w::GPADL_CONN, w::GPADL_SUBCONN, w::CHOPEN];
    v.push(w::GPADL_CONN);
    v.extend([w::GPADL_SUBCONN; 9]);
    v.push(w::GPADL_CONN);
    v.extend([w::GPADL_SUBCONN; 6]);
    v
}

fn channel_pages(p: crate::gpadl::Pages) -> Vec<u64> {
    (p.first..p.end()).map(|i| START.channel_page(i)).collect()
}

#[test]
fn brings_netvsc_s_channel_up_and_answers_attach() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    r.honest();
    assert_eq!(r.lines(), default_lines());
    let mut kinds = vec![w::CONNECT];
    kinds.extend(bring_up_kinds());
    assert_eq!(r.kinds(), kinds);

    // Contact named root's pages.
    let c = r.host.contact().unwrap();
    assert_eq!(c.version, version(4, 0));
    assert_eq!(
        (c.event_flags, c.monitor1, c.monitor2),
        (
            machine::EVENT_FLAGS,
            machine::MONITOR,
            machine::MONITOR + 4096
        )
    );
    // The three GPADLs, page by page, as the host reassembled them.
    for (h, pages, messages) in [(H0, RING, 2), (H0 + 1, RECEIVE, 10), (H0 + 2, SEND, 7)] {
        let g = r.host.gpadl(h).unwrap();
        assert_eq!(g.channel, NETVSC);
        assert_eq!(g.pages, channel_pages(pages), "{h:#x}");
        assert_eq!(g.messages, messages);
    }
    let open = r.host.channel(NETVSC).unwrap().open.unwrap();
    assert_eq!((open.gpadl, open.outbound_pages, open.vp), (H0, 16, 0));

    // The capability vmbus minted: netvsc's connection, signal only.
    assert_eq!(r.sys.mints, [0x200_0000 | 14]);
    assert_eq!(
        Restriction::from_data(r.sys.mints[0]),
        Some(Restriction::signal_only(14))
    );
    let a = VmbusAttach {
        channel: 14,
        connection: 14,
        ring_gpadl: H0,
        rx_gpadl: H0 + 1,
        tx_gpadl: H0 + 2,
        version: version(4, 0),
        flags1: 1,
        montrig: 14,
        flags2: 0,
        vp_index: 0,
    };
    assert_eq!(r.bus.attached(), Some(a));
    assert_eq!(VmbusAttach::from_words(a.to_words()), Some(a));
    assert_eq!(
        r.bus.request(Request::Attach, || panic!("not saved")),
        Answer::Attach(a)
    );
    // Again: netvsc may ask twice.
    assert_eq!(r.bus.request(Request::Attach, || false), Answer::Attach(a));
    assert_eq!(r.bus.release(), None);

    // Every message taken, the slot left empty, nothing queued.
    let s = r.bus.stats();
    assert_eq!(s.messages, r.host.delivered());
    assert_eq!(s.messages, 1 + 4 + 1 + 4);
    assert_eq!(r.host.queued(), 0);
    assert_eq!(m.ram().load32(machine::SIM as usize + 512, Relaxed), 0);
    assert_eq!((s.ignored, s.events, s.stray, s.retries), (0, 0, 0, 0));
    assert_eq!((s.offers, s.netvsc_channel, s.version), (4, 14, 0x4_0000));
}

#[test]
fn the_stats_text() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    let s = r.bus.stats();
    assert_eq!(
        format!("{s}"),
        format!(
            "version 4.0, 4 offers, netvsc channel 14, 10 messages, 0 events relayed, 0 stray events, {} Eoms, 0 post retries, 0 ignored messages",
            s.eoms
        )
    );
    // Through the reply's words, as root prints them.
    let Answer::Stats(t) = r.bus.request(Request::Stats, || false) else {
        panic!()
    };
    assert_eq!(VmbusStats::from_words(t.to_words()), s);
    assert_eq!(
        format!("{}", VmbusStats::default()),
        "version none, 0 offers, no netvsc channel, 0 messages, 0 events relayed, 0 stray events, 0 Eoms, 0 post retries, 0 ignored messages"
    );
}

#[test]
fn contact_falls_back_from_4_0_to_3_0_and_2_4() {
    for (accepted, tries) in [(version(3, 0), 2), (version(2, 4), 3), (version(4, 0), 1)] {
        let m = Machine::new();
        let cfg = Config {
            versions: vec![accepted, version(1, 1)],
            ..Config::default()
        };
        let mut r = Rig::new(&m, cfg);
        r.start();
        r.honest();
        let connects: Vec<u32> = r
            .host
            .posts()
            .iter()
            .filter(|p| p.kind == w::CONNECT)
            .map(|p| u32::from_le_bytes(p.payload[8..12].try_into().unwrap()))
            .collect();
        assert_eq!(connects, VERSIONS[..tries]);
        assert_eq!(r.host.contact().unwrap().version, accepted);
        assert_eq!(
            r.sys.lines[0],
            format!("vmbus: version {}", VmbusVersion(accepted))
        );
        assert_eq!(r.bus.attached().unwrap().version, accepted);
        assert_eq!(r.bus.stats().version, u64::from(accepted));
    }
}

#[test]
#[should_panic(expected = "vmbus: the host accepts none of VMBus 4.0, 3.0, 2.4")]
fn a_host_that_takes_no_version_is_a_panic() {
    let m = Machine::new();
    let cfg = Config {
        // WIN7 and WS2008, which vmbus does not offer.
        versions: vec![version(1, 1), version(0, 13)],
        ..Config::default()
    };
    Rig::new(&m, cfg).start();
}

/// Offers in every order: vmbus opens the first primary netvsc offer that
/// arrives, whatever comes before or after it, and keeps the rest.
#[test]
fn offers_in_any_order() {
    let netvsc = OfferSpec::netvsc(14, 14);
    let offers = [
        netvsc,
        OfferSpec::netvsc(20, 20),
        netvsc.subchannel(1, 15, 15),
        OfferSpec::storvsc(1, 1),
    ];
    // Every order of the four, fewer under Miri.
    let mut orders = Vec::new();
    for a in 0..4 {
        for b in 0..4 {
            for c in 0..4 {
                for d in 0..4 {
                    let o = [a, b, c, d];
                    if (0..4).all(|i| o.contains(&i)) {
                        orders.push(o);
                    }
                }
            }
        }
    }
    assert_eq!(orders.len(), 24);
    if cfg!(miri) {
        orders.truncate(4);
    }
    for order in orders {
        let m = Machine::new();
        let cfg = Config {
            offers: order.iter().map(|&i| offers[i]).collect(),
            ..Config::default()
        };
        let mut r = Rig::new(&m, cfg);
        r.start();
        r.honest();
        // The first primary netvsc in arrival order.
        let first = order
            .iter()
            .map(|&i| offers[i])
            .find(|o| o.kind == hvmock::guid::NETVSC && o.subchannel == 0)
            .unwrap();
        let a = r.bus.attached().unwrap();
        assert_eq!(a.channel, first.channel, "{order:?}");
        assert_eq!(r.host.gpadl(H0).unwrap().channel, first.channel);
        assert_eq!(r.bus.offers().len(), 4);
        assert_eq!(r.sys.lines.len(), 1 + 4 + 1);
        let sub = String::from(
            "vmbus: offer 15: netvsc, connection 15, sub-channel 1, monitor trigger 15",
        );
        assert!(r.sys.lines.contains(&sub));
    }
}

#[test]
fn attach_saved_before_the_open_is_answered_after_it() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    // Before contact: saved.
    let mut saved = 0;
    assert_eq!(
        r.bus.request(Request::Attach, || {
            saved += 1;
            true
        }),
        Answer::Saved
    );
    // One saved at a time.
    assert_eq!(
        r.bus.request(Request::Attach, || panic!("already saved")),
        Answer::Refused(Refusal::Busy)
    );
    assert_eq!(r.bus.release(), None);
    r.bus.start(&mut r.host, &mut r.sys);
    // Answered once the channel is open, and only once.
    r.run();
    let a = r.bus.attached().unwrap();
    assert_eq!(r.bus.release(), Some(Answer::Attach(a)));
    assert_eq!(r.bus.release(), None);
    assert_eq!(saved, 1);
    // A save CNode_SaveCaller refuses is Busy.
    let m2 = Machine::new();
    let mut r2 = Rig::new(&m2, Config::default());
    assert_eq!(
        r2.bus.request(Request::Attach, || false),
        Answer::Refused(Refusal::Busy)
    );
    assert_eq!(r2.bus.release(), None);
}

#[test]
fn no_netvsc_offer_is_unavailable() {
    let m = Machine::new();
    let cfg = Config {
        offers: vec![OfferSpec::storvsc(1, 1), OfferSpec::heartbeat(3, 3)],
        ..Config::default()
    };
    let mut r = Rig::new(&m, cfg);
    assert_eq!(r.bus.request(Request::Attach, || true), Answer::Saved);
    r.start();
    r.honest();
    assert_eq!(r.lines().last(), Some(&"vmbus: no netvsc offer"));
    assert_eq!(r.kinds(), [w::CONNECT, w::CHREQUEST]);
    assert!(r.bus.stopped());
    assert_eq!(r.bus.release(), Some(Answer::Refused(Refusal::Unavailable)));
    assert_eq!(
        r.bus.request(Request::Attach, || panic!("not saved")),
        Answer::Refused(Refusal::Unavailable)
    );
    assert!(r.sys.mints.is_empty());
    assert_eq!(r.bus.stats().netvsc_channel, 0);
    // A sub-channel alone is not a channel to open.
    let m = Machine::new();
    let cfg = Config {
        offers: vec![OfferSpec::netvsc(14, 14).subchannel(1, 15, 15)],
        ..Config::default()
    };
    let mut r = Rig::new(&m, cfg);
    r.start();
    assert!(r.bus.stopped());
}

/// A refusal at each step tears down what came before it, in FreeBSD's
/// order, each GPADL's teardown answered before the next request; then
/// `Attach` is `Unavailable`, the host holds nothing, and events are
/// stray.
#[test]
fn a_refused_step_tears_down_what_came_before_it() {
    // (GPADL statuses, open status, the refused step, the requests after
    // the refused one, the line).
    let cases: [(&[u32], u32, &str, &[u32]); 4] = [
        (&[REFUSED], 0, "the ring's GPADL", &[]),
        (&[0], 5, "the open", &[w::GPADL_DISCONN]),
        (
            &[0, REFUSED],
            0,
            "the receive buffer's GPADL",
            &[w::CHCLOSE, w::GPADL_DISCONN],
        ),
        (
            &[0, 0, REFUSED],
            0,
            "the send buffer's GPADL",
            &[w::GPADL_DISCONN, w::CHCLOSE, w::GPADL_DISCONN],
        ),
    ];
    for (gpadl_status, open_status, step, undo) in cases {
        let m = Machine::new();
        let cfg = Config {
            gpadl_status: gpadl_status.to_vec(),
            open_status,
            ..Config::default()
        };
        let mut r = Rig::new(&m, cfg);
        assert_eq!(r.bus.request(Request::Attach, || true), Answer::Saved);
        r.start();
        r.honest();
        let status = if open_status != 0 {
            open_status
        } else {
            REFUSED
        };
        let mut lines = default_lines();
        lines.pop();
        lines.push(format!(
            "vmbus: netvsc channel 14: the host refused {step} (status {status:#x}); setup stopped"
        ));
        if !undo.is_empty() {
            lines.push("vmbus: netvsc channel 14: its GPADLs torn down".into());
        }
        assert_eq!(r.sys.lines, lines, "{step}");
        let kinds = r.kinds();
        assert_eq!(kinds[kinds.len() - undo.len()..], *undo, "{step}");
        // Torn down: no GPADL left, the channel closed.
        assert!(r.host.gpadls().is_empty(), "{step}: {:?}", r.host.gpadls());
        assert!(r.host.channel(NETVSC).unwrap().open.is_none());
        // The buffers' GPADLs before the ring's, as FreeBSD's hn detaches.
        let disconns: Vec<u32> = r
            .host
            .posts()
            .iter()
            .filter(|p| p.kind == w::GPADL_DISCONN)
            .map(|p| u32::from_le_bytes(p.payload[12..16].try_into().unwrap()))
            .collect();
        let expect: &[u32] = match undo.len() {
            0 => &[],
            1 | 2 => &[H0],
            _ => &[H0 + 1, H0],
        };
        assert_eq!(disconns, expect, "{step}");
        assert!(r.bus.stopped());
        assert_eq!(r.bus.release(), Some(Answer::Refused(Refusal::Unavailable)));
        assert!(r.sys.mints.is_empty());
        // No more relaying.
        r.host.signal_guest(NETVSC);
        r.run();
        assert_eq!((r.sys.signals, r.bus.stats().stray), (0, 1));
    }
}

/// A teardown waits for each GPADL_DISCONNRESP: a host that never sends
/// one leaves vmbus waiting there, and an answer for another GPADL does
/// not move it.
#[test]
fn a_teardown_waits_for_each_answer() {
    let m = Machine::new();
    let cfg = Config {
        gpadl_status: vec![0, 0, REFUSED],
        unanswered: vec![w::GPADL_DISCONN],
        ..Config::default()
    };
    let mut r = Rig::new(&m, cfg);
    r.start();
    let disconn = |r: &Rig<'_>| r.kinds().iter().filter(|&&k| k == w::GPADL_DISCONN).count();
    assert_eq!(*r.kinds().last().unwrap(), w::GPADL_DISCONN);
    assert_eq!(disconn(&r), 1);
    assert!(r.bus.stopped());
    // Another GPADL's answer: ignored, still waiting.
    r.host.inject(&hvmock::wire::gpadl_disconnresp(H0 + 7));
    r.run();
    assert_eq!((disconn(&r), r.bus.stats().ignored), (1, 1));
    // The receive buffer's: CHCLOSE, then the ring's teardown.
    r.host.inject(&hvmock::wire::gpadl_disconnresp(H0 + 1));
    r.run();
    let k = r.kinds();
    assert_eq!(k[k.len() - 2..], [w::CHCLOSE, w::GPADL_DISCONN]);
    assert_eq!(r.sys.lines.len(), 5 + 1);
    r.host.inject(&hvmock::wire::gpadl_disconnresp(H0));
    r.run();
    assert_eq!(
        r.lines().last(),
        Some(&"vmbus: netvsc channel 14: its GPADLs torn down")
    );
    assert_eq!(r.bus.stats().ignored, 1);
}

#[test]
fn a_rescind_of_netvsc_s_channel_revokes_its_capability() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    assert!(r.bus.attached().is_some());
    r.host.signal_guest(NETVSC);
    r.run();
    assert_eq!(r.sys.signals, 1);
    r.host.rescind(NETVSC);
    r.run();
    assert_eq!(r.sys.revokes, 1);
    assert_eq!(
        r.lines().last(),
        Some(&"vmbus: netvsc channel 14 rescinded")
    );
    assert!(r.bus.stopped());
    assert_eq!(
        r.bus.request(Request::Attach, || panic!()),
        Answer::Refused(Refusal::Unavailable)
    );
    let s = r.bus.stats();
    assert_eq!((s.offers, s.netvsc_channel), (3, 0));
    // Nothing more posted, and its events are stray now.
    let posted = r.host.posts().len();
    r.host.signal_guest(NETVSC);
    r.run();
    assert_eq!((r.sys.signals, r.bus.stats().stray), (1, 1));
    assert_eq!(r.host.posts().len(), posted);
    // Another channel's rescind is printed; one never offered is ignored.
    r.host.rescind(3);
    r.host.inject(&hvmock::wire::rescind(99));
    r.run();
    assert_eq!(r.lines().last(), Some(&"vmbus: offer 3 rescinded"));
    assert_eq!(r.bus.stats().ignored, 1);
    assert_eq!(r.sys.revokes, 1);
}

#[test]
fn a_rescind_during_setup_stops_it() {
    let m = Machine::new();
    // The host holds its answer to the receive buffer's GPADL, whose
    // first message is request 5, and rescinds the channel meanwhile.
    let cfg = Config {
        hold_from: Some(5),
        ..Config::default()
    };
    let mut r = Rig::new(&m, cfg);
    assert_eq!(r.bus.request(Request::Attach, || true), Answer::Saved);
    r.start();
    assert_eq!(r.host.held(), 1);
    assert!(!r.bus.stopped() && r.bus.attached().is_none());
    assert_eq!(r.bus.release(), None);
    r.host.rescind(NETVSC);
    r.run();
    assert!(r.bus.stopped());
    assert_eq!(r.bus.release(), Some(Answer::Refused(Refusal::Unavailable)));
    // The late answer is ignored, and nothing more is posted.
    let posted = r.host.posts().len();
    r.host.resume();
    r.run();
    assert_eq!(r.host.posts().len(), posted);
    assert_eq!(r.bus.stats().ignored, 1);
    assert!(r.sys.mints.is_empty());
    assert_eq!(r.sys.revokes, 0);
    assert_eq!(
        r.lines().last(),
        Some(&"vmbus: netvsc channel 14 rescinded")
    );
}

#[test]
fn events_are_relayed_once_a_batch_and_strays_counted() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    // netvsc's flag: one signal; another channel's, bit 0's: stray.
    r.host.signal_guest(NETVSC);
    r.host.signal_guest(3);
    r.host.signal_guest(0);
    r.run();
    let s = r.bus.stats();
    assert_eq!((r.sys.signals, s.events, s.stray), (1, 1, 2));
    // Flags clear: the next sets raise the SINT again.
    let raised = m.interrupts();
    r.host.signal_guest(NETVSC);
    assert_eq!(m.interrupts(), raised + 1);
    r.host.signal_guest(NETVSC);
    assert_eq!(m.interrupts(), raised + 1);
    r.run();
    assert_eq!((r.sys.signals, r.bus.stats().events), (2, 2));
    // Words above the highest offer (17) are not scanned: a flag there
    // stays set, and is no event.
    r.host.signal_guest(64);
    r.host.signal_guest(1000);
    r.run();
    let word = |n: usize| {
        m.ram()
            .load64(machine::SIEF as usize + 512 + 8 * n, Relaxed)
    };
    assert_eq!(word(1), 1);
    assert_eq!(word(15), 1 << (1000 % 64));
    assert_eq!(r.bus.stats().stray, 2);
    // An offer at 1000 makes the next scan reach both.
    r.host.offer(OfferSpec::heartbeat(1000, 1000));
    r.run();
    assert_eq!(word(15), 1 << (1000 % 64));
    r.host.signal_guest(NETVSC);
    r.run();
    assert_eq!((word(1), word(15)), (0, 0));
    let s = r.bus.stats();
    assert_eq!((r.sys.signals, s.events, s.stray, s.offers), (3, 3, 4, 5));
}

#[test]
fn a_flag_set_before_start_is_seen_at_start() {
    // A SINT before binding signalled nothing: start looks once.
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.host.signal_guest(5);
    m.take_interrupt();
    r.bus.start(&mut r.host, &mut r.sys);
    assert_eq!(r.bus.stats().stray, 1);
}

/// The late `MessagePending`: the host sets it only when vmbus's store
/// empties the slot, so a vmbus that trusted its copy of the flags would
/// never `Eom`, and the queued offers would never come.
#[test]
fn a_late_message_pending_is_not_missed() {
    let m = Machine::new();
    m.set_late_pending(true);
    let mut r = Rig::new(&m, Config::default());
    r.start();
    r.honest();
    assert_eq!(r.lines(), default_lines());
    assert!(m.late_sets() >= 4, "{}", m.late_sets());
    assert_eq!(r.bus.stats().eoms, r.host.eoms());
    assert_eq!(r.bus.stats().eoms, m.late_sets());
    // And on time, the same.
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    assert!(r.bus.stats().eoms >= 4);
    assert_eq!(m.late_sets(), 0);
}

#[test]
fn a_message_waiting_at_start_is_taken() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.host.inject(&[0xFF; 12]);
    assert!(m.take_interrupt());
    r.start();
    r.honest();
    assert_eq!(r.bus.stats().ignored, 1);
    assert!(r.bus.attached().is_some());
}

/// FreeBSD's waits between retries: 1 ms, doubling, at most 2 s.
const BACK_OFFS: [u32; 20] = [
    1, 2, 4, 8, 16, 32, 64, 128, 256, 512, 1024, 2000, 2000, 2000, 2000, 2000, 2000, 2000, 2000,
    2000,
];

#[test]
fn posts_are_retried_while_the_buffers_are_full() {
    let m = Machine::new();
    let cfg = Config {
        busy_posts: 20,
        ..Config::default()
    };
    let mut r = Rig::new(&m, cfg);
    r.start();
    r.honest();
    assert_eq!(r.bus.stats().retries, 20);
    assert_eq!(r.sys.back_offs, BACK_OFFS);
    assert_eq!(r.host.busy(), 20);
    assert!(r.bus.attached().is_some());
}

#[test]
#[should_panic(
    expected = "vmbus: PostMessage of CONNECT: HV_STATUS_INSUFFICIENT_BUFFERS (0x13), after 20 retries"
)]
fn posts_retried_20_times_then_a_panic() {
    let m = Machine::new();
    let cfg = Config {
        busy_posts: 21,
        ..Config::default()
    };
    Rig::new(&m, cfg).start();
}

#[test]
#[should_panic(
    expected = "vmbus: PostMessage of CONNECT: HV_STATUS_INVALID_CONNECTION_ID (0x12), after 20 retries"
)]
fn a_failed_post_is_a_panic() {
    struct Refuses<'a, 'm>(&'a mut Host<'m>);
    impl Hypervisor for Refuses<'_, '_> {
        fn post_message(&mut self, _: u32, _: u32, _: &[u8]) -> Status {
            Status::INVALID_CONNECTION_ID
        }
        fn signal_event(&mut self, c: u32, f: u16) -> Status {
            self.0.signal_event(c, f)
        }
        fn eom(&mut self) {
            self.0.eom()
        }
        fn vp_index(&mut self) -> u32 {
            7
        }
    }
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.bus.start(&mut Refuses(&mut r.host), &mut r.sys);
}

/// M9 fix-round recheck: a failure other than full buffers is retried
/// with the same waits, and contact goes on once a post succeeds.
/// `a_failed_post_is_a_panic` alone passes when only
/// `HV_STATUS_INSUFFICIENT_BUFFERS` is retried and any other status is a
/// panic at once (its message names `MAX_RETRIES`, not the count), which
/// was the policy before the fix round.
#[test]
fn a_post_failing_with_any_status_is_retried() {
    struct Fails<'a, 'm> {
        host: &'a mut Host<'m>,
        statuses: Vec<Status>,
    }
    impl Hypervisor for Fails<'_, '_> {
        fn post_message(&mut self, c: u32, t: u32, payload: &[u8]) -> Status {
            match self.statuses.pop() {
                Some(s) => s,
                None => self.host.post_message(c, t, payload),
            }
        }
        fn signal_event(&mut self, c: u32, f: u16) -> Status {
            self.host.signal_event(c, f)
        }
        fn eom(&mut self) {
            self.host.eom()
        }
        fn vp_index(&mut self) -> u32 {
            Hypervisor::vp_index(self.host)
        }
    }
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    let statuses = vec![
        Status(0x1234),
        Status::INVALID_PORT_ID,
        Status::INVALID_CONNECTION_ID,
    ];
    r.bus.start(
        &mut Fails {
            host: &mut r.host,
            statuses,
        },
        &mut r.sys,
    );
    r.run();
    r.honest();
    assert_eq!(r.bus.stats().retries, 3);
    assert_eq!(r.sys.back_offs, [1, 2, 4]);
    assert!(r.bus.attached().is_some());
}

#[test]
fn chopen_names_the_vp_index() {
    let m = Machine::new();
    let cfg = Config {
        vp_index: 3,
        ..Config::default()
    };
    let mut r = Rig::new(&m, cfg);
    r.start();
    r.honest();
    assert_eq!(r.bus.attached().unwrap().vp_index, 3);
    assert_eq!(r.host.channel(NETVSC).unwrap().open.unwrap().vp, 3);
}

#[test]
#[should_panic(expected = "vmbus: started twice")]
fn starting_twice_is_a_panic() {
    let m = Machine::new();
    let mut r = Rig::new(&m, Config::default());
    r.start();
    r.bus.start(&mut r.host, &mut r.sys);
}

use core::sync::atomic::Ordering::Relaxed;
use libsys::proto::VmbusVersion;
