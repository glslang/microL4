//! NVSP and RNDIS setup against the mock device: the requests in order,
//! NVSP's fallback and the NDIS version, the buffers and their sections,
//! RNDIS's answers, every refusal, the packet filter after `net`'s
//! buffers; and the arguments, the `Attach` reply, the requests on NS,
//! the layout and the stats text.

use hvmock::netvsc::{nvs as hn, rndis as hr};
use libsys::frames::Mac;
use libsys::proto::{NetvscStats, Refusal, label};

use super::*;
use crate::nvs::Bad as NvsBad;
use crate::rndis::Bad as RndisBad;

/// The requests a bring-up with NVSP `v` makes, in order, after the INITs
/// it tried.
fn requests(inits: &[&str], ndis: &str) -> Vec<String> {
    let mut v: Vec<String> = inits.iter().map(|i| format!("INIT {i}")).collect();
    v.extend([
        "NDIS_CONF 1514 0x8".into(),
        format!("NDIS_INIT {ndis}"),
        "RXBUF_CONN".into(),
        "CHIM_CONN".into(),
        "RNDIS INITIALIZE".into(),
        "RNDIS QUERY 0x1010101".into(),
        "RNDIS QUERY 0x10114".into(),
        "RNDIS SET 0x1010e 0x9".into(),
    ]);
    v
}

/// A rig started with `nic`'s configuration: up or failed.
fn started<'m>(m: &'m Machine, q: &'m Ram, nic: nic::Config) -> Rig<'m> {
    let mut r = Rig::new(
        m,
        q,
        Setup {
            nic,
            ..Setup::default()
        },
    );
    r.start();
    r
}

/// Runs a setup that must fail, and checks that nothing more happens.
fn refused(nic: nic::Config) -> (Failure, Vec<String>) {
    let m = Machine::new();
    let q = queues();
    let mut r = started(&m, &q, nic);
    let f = r.failure.expect("the setup failed");
    assert_eq!(r.a.failed(), Some(f));
    assert!(!r.attached, "net got a link block from a failed setup");
    // Stopped: a later signal does nothing and fails the same way.
    let written = r.a.stats();
    let cap = r.cap;
    let again = r.a.on_signal(
        CHANNEL | FRAMES,
        &mut Cap {
            host: &mut r.host,
            cap,
            signals: &mut r.signals,
            status: Status::SUCCESS,
        },
    );
    assert_eq!(again, Err(f));
    assert_eq!(r.a.stats(), written);
    (f, r.nic.seen().requests)
}

#[test]
fn sets_up_nvsp_5_and_rndis_and_hands_net_the_link() {
    let m = Machine::new();
    let q = queues();
    let r = up(&m, &q, Setup::default());
    r.honest();
    let seen = r.nic.seen();
    assert_eq!(seen.requests, requests(&["0x50000"], "6.30"));
    assert_eq!(seen.nvsp, Some(0x5_0000));
    assert_eq!(seen.ndis, Some(nvs::NDIS_6_30));
    assert_eq!(seen.filter, rndis::FILTER);
    // FreeBSD's request IDs, n << 16.
    assert_eq!(seen.rids, [1 << 16, 2 << 16, 3 << 16, 4 << 16]);
    assert_eq!(seen.gpa, 4);
    assert_eq!(
        r.lines,
        [
            "netvsc: up: NVSP 5, NDIS 6.30, MAC 00:15:5d:4c:34:01, link up, 128 send sections of 6144 bytes"
        ]
    );
    assert_eq!(r.a.mac(), Mac(MAC));
    assert!(r.a.link());
    assert_eq!(r.a.sections(), (6144, 128));
    assert_eq!(r.a.rndis_align(), 8);
    assert_eq!(r.a.attach().connection, NETVSC);
    // net's side: the link block, and every transmit buffer.
    assert_eq!(r.net.free_buffers(), frames::BUFFERS);
    assert_eq!(r.a.queues().free_buffers(), frames::BUFFERS);
    let s = r.clean_stats();
    assert_eq!((s.nvsp, s.ndis), (0x5_0000, u64::from(nvs::NDIS_6_30)));
    // Every answer came as a receive-buffer packet, each acknowledged.
    assert_eq!((s.rxbuf_packets, s.acks), (4, 4));
    assert_eq!((seen.rxbuf, seen.acks), (4, 4));
    // Signalled on the restricted capability, and only its connection.
    assert!(r.signals > 0);
    assert_eq!(r.host.signals(NETVSC), r.signals);
}

#[test]
fn nvsp_falls_back_from_5_to_4_and_2_with_ndis_6_1() {
    for (versions, inits, line) in sample(
        vec![
            (
                vec![hn::V4],
                &["0x50000", "0x40000"][..],
                "NVSP 4, NDIS 6.1",
            ),
            (
                vec![hn::V2, hn::V1],
                &["0x50000", "0x40000", "0x30002"][..],
                "NVSP 2, NDIS 6.1",
            ),
            (vec![hn::V5, hn::V4], &["0x50000"][..], "NVSP 5, NDIS 6.30"),
        ],
        1,
    ) {
        let m = Machine::new();
        let q = queues();
        let r = started(
            &m,
            &q,
            nic::Config {
                versions,
                ..nic::Config::default()
            },
        );
        r.honest();
        assert_eq!(r.a.step(), Step::Up);
        let ndis = if inits.len() == 1 { "6.30" } else { "6.1" };
        assert_eq!(r.nic.seen().requests, requests(inits, ndis));
        assert!(
            r.lines[0].starts_with(&format!("netvsc: up: {line}, ")),
            "{:?}",
            r.lines
        );
        assert_eq!(
            r.a.stats().ndis,
            u64::from(nvs::ndis_for(r.nic.seen().nvsp.unwrap()))
        );
    }
}

#[test]
fn a_host_that_takes_none_of_5_4_and_2_fails() {
    // FreeBSD's other versions, which netvsc does not offer.
    let (f, requests) = refused(nic::Config {
        versions: vec![hn::V61, hn::V6, hn::V1],
        ..nic::Config::default()
    });
    assert_eq!(f, Failure::NoVersion);
    assert_eq!(requests, ["INIT 0x50000", "INIT 0x40000", "INIT 0x30002"]);
    assert_eq!(
        format!("{f}"),
        "netvsc: the host accepts none of NVSP 5, 4, 2"
    );
}

/// INIT answers that are no answer count as a refusal of that version.
#[test]
fn a_malformed_init_answer_tries_the_next_version() {
    let (f, requests) = refused(nic::Config {
        tamper_nvs: Some(|_, b| b.truncate(12)),
        ..nic::Config::default()
    });
    assert_eq!(f, Failure::NoVersion);
    assert_eq!(requests.len(), 3);
    let m = Machine::new();
    let q = queues();
    let r = started(
        &m,
        &q,
        nic::Config {
            // Version 5's answer is of another type; 4 goes.
            versions: vec![hn::V5, hn::V4],
            tamper_nvs: Some(|t, b| {
                if t == hn::INIT
                    && b[12] == 1
                    && u32::from_le_bytes(b[..4].try_into().unwrap()) == 2
                {
                    static FIRST: std::sync::atomic::AtomicBool =
                        std::sync::atomic::AtomicBool::new(true);
                    if FIRST.swap(false, Relaxed) {
                        b[0] = 99;
                    }
                }
            }),
            ..nic::Config::default()
        },
    );
    assert_eq!(r.a.step(), Step::Up);
    assert_eq!(r.nic.seen().nvsp, Some(hn::V4));
}

#[test]
fn every_refusal_of_the_receive_buffer() {
    let mb = layout::RECEIVE_SIZE as u32;
    for (nic, why) in sample(
        vec![
            (
                nic::Config {
                    rxbuf_status: hn::FAILED,
                    ..nic::Config::default()
                },
                NvsBad::Status(hn::FAILED),
            ),
            (
                nic::Config {
                    rxbuf_sections: Some(vec![]),
                    ..nic::Config::default()
                },
                NvsBad::Sections(0),
            ),
            (
                nic::Config {
                    rxbuf_sections: Some(vec![[0, 1728, 100, 1728 * 100], [0, 1, 1, mb + 1]]),
                    ..nic::Config::default()
                },
                NvsBad::Section(1),
            ),
            (
                nic::Config {
                    // Its slots reach past the buffer.
                    rxbuf_sections: Some(vec![[4096, 1728, 606, 4096]]),
                    ..nic::Config::default()
                },
                NvsBad::Section(0),
            ),
            (
                nic::Config {
                    // Starts after it ends.
                    rxbuf_sections: Some(vec![[8, 0, 0, 4]]),
                    ..nic::Config::default()
                },
                NvsBad::Section(0),
            ),
            (
                nic::Config {
                    // A count past what the answer holds.
                    tamper_nvs: Some(|t, b| {
                        if t == hn::RXBUF_CONN {
                            b[8] = 9;
                        }
                    }),
                    ..nic::Config::default()
                },
                NvsBad::Sections(9),
            ),
            (
                nic::Config {
                    tamper_nvs: Some(|t, b| {
                        if t == hn::RXBUF_CONN {
                            b[0] = 105;
                        }
                    }),
                    ..nic::Config::default()
                },
                NvsBad::Kind(105),
            ),
        ],
        2,
    ) {
        let (f, _) = refused(nic);
        assert_eq!(f, Failure::Refused(Step::ReceiveBuffer, Why::Nvs(why)));
    }
    let (f, _) = refused(nic::Config {
        rxbuf_status: hn::FAILED,
        ..nic::Config::default()
    });
    assert_eq!(
        format!("{f}"),
        "netvsc: the host refused the receive buffer: status 0x2"
    );
}

#[test]
fn sections_inside_the_receive_buffer_are_taken() {
    let m = Machine::new();
    let q = queues();
    let r = started(
        &m,
        &q,
        nic::Config {
            // Two sections, as Linux's comment describes, the second ending
            // at the buffer's end.
            rxbuf_sections: Some(vec![
                [0, 1728, 300, 1728 * 300],
                [1728 * 300, 2048, 258, 1 << 20],
            ]),
            ..nic::Config::default()
        },
    );
    r.honest();
    assert_eq!(r.a.step(), Step::Up);
}

#[test]
fn every_refusal_of_the_send_buffer_and_the_sections_taken() {
    for size in sample(vec![0, 4, 1556, 1558, 1562, 768 * 1024 + 4], 1) {
        let (f, _) = refused(nic::Config {
            section_size: size,
            ..nic::Config::default()
        });
        assert_eq!(
            f,
            Failure::Refused(Step::SendBuffer, Why::Nvs(NvsBad::SectionSize(size)))
        );
    }
    let (f, _) = refused(nic::Config {
        chim_status: hn::FAILED,
        ..nic::Config::default()
    });
    assert_eq!(
        f,
        Failure::Refused(Step::SendBuffer, Why::Nvs(NvsBad::Status(hn::FAILED)))
    );
    assert_eq!(
        format!("{f}"),
        "netvsc: the host refused the send buffer: status 0x2"
    );
    // A whole frame's message fits; at most 128 sections.
    for (size, sections) in sample(
        vec![(1560, 128), (6144, 128), (8192, 96), (768 * 1024, 1)],
        1,
    ) {
        let m = Machine::new();
        let q = queues();
        let r = started(
            &m,
            &q,
            nic::Config {
                section_size: size,
                ..nic::Config::default()
            },
        );
        r.honest();
        assert_eq!(r.a.sections(), (size, sections));
        assert!(
            r.lines[0].ends_with(&format!(", {sections} send sections of {size} bytes")),
            "{:?}",
            r.lines
        );
    }
}

#[test]
fn every_refusal_of_rndis() {
    let cases: Vec<(nic::Config, Failure)> = vec![
        (
            nic::Config {
                init_status: hr::FAILURE,
                ..nic::Config::default()
            },
            Failure::Refused(Step::Initialize, Why::Rndis(RndisBad::Status(hr::FAILURE))),
        ),
        (
            nic::Config {
                tamper_rndis: Some(|t, m| {
                    if t == hr::INITIALIZE {
                        m.truncate(44);
                    }
                }),
                ..nic::Config::default()
            },
            Failure::Refused(Step::Initialize, Why::Rndis(RndisBad::Short(44))),
        ),
        (
            nic::Config {
                tamper_rndis: Some(|t, m| {
                    if t == hr::INITIALIZE {
                        m[4] = 40;
                    }
                }),
                ..nic::Config::default()
            },
            Failure::Refused(Step::Initialize, Why::Rndis(RndisBad::Length(40))),
        ),
        (
            nic::Config {
                tamper_rndis: Some(|t, m| {
                    if t == hr::INITIALIZE {
                        m[0] = 4;
                    }
                }),
                ..nic::Config::default()
            },
            // The request's ID, another completion's type.
            Failure::Refused(Step::Initialize, Why::Kind(hr::QUERY_CMPLT)),
        ),
        (
            nic::Config {
                mac_len: 8,
                ..nic::Config::default()
            },
            Failure::Refused(Step::Mac, Why::Rndis(RndisBad::InfoLength(8))),
        ),
        (
            nic::Config {
                mac: [0x01, 0, 0x5e, 0, 0, 1],
                ..nic::Config::default()
            },
            Failure::Refused(Step::Mac, Why::Mac(Mac([0x01, 0, 0x5e, 0, 0, 1]))),
        ),
        (
            nic::Config {
                mac: [0; 6],
                ..nic::Config::default()
            },
            Failure::Refused(Step::Mac, Why::Mac(Mac::ZERO)),
        ),
        (
            nic::Config {
                tamper_rndis: Some(|t, m| {
                    // The MAC's offset points past the message.
                    if t == hr::QUERY && m.len() == 30 {
                        m[20] = 20;
                    }
                }),
                ..nic::Config::default()
            },
            Failure::Refused(Step::Mac, Why::Rndis(RndisBad::InfoOffset(20))),
        ),
        (
            nic::Config {
                tamper_rndis: Some(|t, m| {
                    // Into the header.
                    if t == hr::QUERY && m.len() == 28 {
                        m[20] = 8;
                    }
                }),
                ..nic::Config::default()
            },
            Failure::Refused(Step::Link, Why::Rndis(RndisBad::InfoOffset(8))),
        ),
        (
            nic::Config {
                tamper_rndis: Some(|t, m| {
                    if t == hr::QUERY && m.len() == 28 {
                        m[12] = 0xBB;
                    }
                }),
                ..nic::Config::default()
            },
            Failure::Refused(Step::Link, Why::Rndis(RndisBad::Status(0xBB))),
        ),
        (
            nic::Config {
                filter_status: hr::NOT_SUPPORTED,
                ..nic::Config::default()
            },
            Failure::Refused(
                Step::Filter,
                Why::Rndis(RndisBad::Status(hr::NOT_SUPPORTED)),
            ),
        ),
    ];
    for (nic, want) in sample(cases, 3) {
        let m = Machine::new();
        let q = queues();
        let r = started(&m, &q, nic);
        assert_eq!(r.failure, Some(want), "{:?}", r.nic.seen().requests);
    }
    // Too short to carry an ID: no answer; the step waits, and the short
    // message is counted.
    let m = Machine::new();
    let q = queues();
    let r = started(
        &m,
        &q,
        nic::Config {
            tamper_rndis: Some(|t, m| {
                if t == hr::SET {
                    m.truncate(12);
                }
            }),
            ..nic::Config::default()
        },
    );
    assert_eq!(r.failure, None);
    assert_eq!(r.a.step(), Step::Filter);
    assert_eq!(r.a.stats().ignored, 1);
    let m = Machine::new();
    let q = queues();
    let r = started(
        &m,
        &q,
        nic::Config {
            mac: [0x01, 0, 0x5e, 0, 0, 1],
            ..nic::Config::default()
        },
    );
    assert_eq!(
        format!("{}", r.failure.unwrap()),
        "netvsc: the host's MAC 01:00:5e:00:00:01 is not unicast"
    );
    assert_eq!(
        format!(
            "{}",
            Failure::Refused(Step::Initialize, Why::Kind(hr::QUERY_CMPLT))
        ),
        "netvsc: the host answered RNDIS INITIALIZE with RNDIS message 0x80000004"
    );
    assert_eq!(
        format!(
            "{}",
            Failure::Refused(Step::Link, Why::Rndis(RndisBad::InfoOffset(8)))
        ),
        "netvsc: the host refused the link query: an answer at offset 8"
    );
}

/// An RNDIS answer whose ID is not the request's is counted and ignored;
/// the right one, after it, goes on.
#[test]
fn an_answer_to_another_request_is_ignored() {
    let m = Machine::new();
    let q = queues();
    let mut r = Rig::new(&m, &q, Setup::default());
    r.nic.configure(|c| {
        c.tamper_rndis = Some(|t, m| {
            if t == hr::QUERY && m.len() == 30 {
                // Request 3's ID on request 2's answer.
                m[10] = 3;
            }
        })
    });
    r.start();
    assert_eq!(r.failure, None);
    assert_eq!(r.a.step(), Step::Mac);
    assert_eq!(r.a.stats().ignored, 1);
    // The host answers again, rightly.
    r.nic.configure(|c| c.tamper_rndis = None);
    let mut answer = hvmock::netvsc::words(&[hr::QUERY_CMPLT, 30, 2 << 16, 0, 6, 16]);
    answer.extend_from_slice(&MAC);
    r.nic.inject_rndis(&[&answer]);
    r.run();
    r.honest();
    assert_eq!(r.a.step(), Step::Up);
    assert_eq!(r.a.stats().ignored, 1);
}

#[test]
fn the_link_down_at_setup_and_the_status_indications() {
    let m = Machine::new();
    let q = queues();
    let mut r = up(
        &m,
        &q,
        Setup {
            nic: nic::Config {
                link: 1,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    assert!(!r.a.link());
    assert!(r.lines[0].contains(", link down, "), "{:?}", r.lines);
    r.lines.clear();
    for s in [
        hr::MEDIA_CONNECT,
        hr::MEDIA_CONNECT,
        hr::LINK_SPEED_CHANGE,
        hr::MEDIA_DISCONNECT,
    ] {
        r.nic.indicate(s);
        r.run();
    }
    r.honest();
    assert_eq!(r.lines, ["netvsc: link up", "netvsc: link down"]);
    assert!(!r.a.link());
    let s = r.clean_stats();
    assert_eq!(s.status, 4);
}

/// The packet filter is set only once net has handed over its receive
/// buffers, so no frame the host sends finds none.
#[test]
fn the_filter_waits_for_net_s_buffers() {
    let m = Machine::new();
    let q = queues();
    let mut r = Rig::new(&m, &q, Setup::default());
    r.nic.deliver(&frame(MAC, 60, 1));
    r.a.start(&mut Cap {
        host: &mut r.host,
        cap: r.cap,
        signals: &mut r.signals,
        status: Status::SUCCESS,
    })
    .unwrap();
    // Turns without net.
    r.net_asleep = true;
    r.run();
    assert_eq!(r.a.step(), Step::Net);
    assert_eq!(
        r.nic.seen().requests.last().map(String::as_str),
        Some("RNDIS QUERY 0x10114")
    );
    assert_eq!(r.nic.seen().filter, 0);
    assert_eq!(r.nic.waiting(), 1);
    // net's first signal: then the filter, then the frame.
    assert!(r.to_net);
    r.net_asleep = false;
    r.run();
    r.honest();
    assert_eq!(r.a.step(), Step::Up);
    assert_eq!(r.received, [frame(MAC, 60, 1)]);
    assert_eq!(r.clean_stats().received, 1);
}

#[test]
fn control_packets_completed_after_their_answers() {
    let m = Machine::new();
    let q = queues();
    let r = up(
        &m,
        &q,
        Setup {
            nic: nic::Config {
                late_control_completion: true,
                ..nic::Config::default()
            },
            ..Setup::default()
        },
    );
    r.honest();
    r.clean_stats();
}

#[test]
fn rndis_alignment_below_4_is_taken_as_4() {
    for (shift, align) in sample(
        vec![(0, 4), (1, 4), (2, 4), (3, 8), (12, 4096), (40, 1 << 31)],
        2,
    ) {
        let m = Machine::new();
        let q = queues();
        let r = started(
            &m,
            &q,
            nic::Config {
                align: shift,
                ..nic::Config::default()
            },
        );
        assert_eq!(r.a.rndis_align(), align, "rm_align {shift}");
    }
}

#[test]
fn a_failed_signal_is_a_failure() {
    let m = Machine::new();
    let q = queues();
    let mut r = Rig::new(&m, &q, Setup::default());
    r.signal_status = Status::INVALID_CONNECTION_ID;
    r.start();
    let f = r.failure.unwrap();
    assert_eq!(
        f,
        Failure::Signal {
            connection: NETVSC,
            status: Status::INVALID_CONNECTION_ID
        }
    );
    assert_eq!(
        format!("{f}"),
        "netvsc: SignalEvent on connection 14: HV_STATUS_INVALID_CONNECTION_ID (0x12)"
    );
}

#[test]
fn start_words_round_trip_and_refuse_what_root_never_passes() {
    for mnf in [false, true] {
        let s = Start {
            channel: 0x20_0000,
            mnf,
        };
        assert_eq!(s.to_words(), [0x20_0000, mnf as u64, 0, 0]);
        assert_eq!(Start::from_words(s.to_words()), Some(s));
    }
    let top = Start::PHYSICAL - layout::CHANNEL_SIZE as u64;
    assert!(Start::from_words([top, 0, 0, 0]).is_some());
    for w in [
        [0, 0, 0, 0],
        [0x10_0000, 0, 0, 0],
        [0x20_1000, 0, 0, 0],
        [Start::PHYSICAL, 0, 0, 0],
        [!0x1F_FFFF, 0, 0, 0],
        [0x20_0000, 2, 0, 0],
        [0x20_0000, 0, 1, 0],
        [0x20_0000, 0, 0, 1],
    ] {
        assert_eq!(Start::from_words(w), None, "{w:x?}");
    }
    assert_eq!(
        Start {
            channel: 0x20_0000,
            mnf: false
        }
        .channel_page(32),
        0x220
    );
}

#[test]
fn the_attach_reply_is_read_and_refused() {
    let a = some_attach();
    let w = a.to_words();
    assert_eq!(attach_reply(0, &w, true), Ok(a));
    assert_eq!(attach_reply(0, &w, false), Err(AttachError::NoCapability));
    assert_eq!(
        attach_reply(Refusal::Unavailable.label(), &[], false),
        Err(AttachError::Refused(Refusal::Unavailable))
    );
    assert_eq!(
        attach_reply(0x99, &w, true),
        Err(AttachError::BadReply {
            label: 0x99,
            length: 8
        })
    );
    assert_eq!(
        attach_reply(0, &w[..7], true),
        Err(AttachError::BadReply {
            label: 0,
            length: 7
        })
    );
    assert_eq!(
        attach_reply(0, &[&w[..], &[0]].concat(), true),
        Err(AttachError::BadReply {
            label: 0,
            length: 9
        })
    );
    let mut bad = w;
    bad[0] = 0;
    assert!(matches!(
        attach_reply(0, &bad, true),
        Err(AttachError::BadReply { .. })
    ));
    assert_eq!(
        format!("{}", AttachError::Refused(Refusal::Unavailable)),
        "vmbus has no netvsc channel (Unavailable)"
    );
    assert_eq!(
        format!("{}", AttachError::Refused(Refusal::Busy)),
        "vmbus refused Attach: Busy"
    );
}

#[test]
fn requests_on_ns() {
    assert_eq!(request(label::NETVSC_STATS, 0), Ok(()));
    assert_eq!(request(label::NETVSC_STATS, 1), Err(Refusal::BadLength));
    assert_eq!(request(label::VMBUS_STATS, 0), Err(Refusal::BadLabel));
    assert_eq!(request(0, 0), Err(Refusal::BadLabel));
}

/// netvsc's pages are the ones vmbus names to the host.
#[test]
fn the_layout_matches_vmbus() {
    use vmbus::layout as v;
    let page = |p: u64| p as usize * layout::PAGE;
    assert_eq!(layout::CHANNEL_SIZE, page(v::CHANNEL_PAGES));
    assert_eq!(layout::OUTBOUND, page(v::RING.first));
    assert_eq!(layout::OUTBOUND_PAGES, v::OUTBOUND_PAGES as usize);
    assert_eq!(
        layout::INBOUND + layout::INBOUND_PAGES * layout::PAGE,
        page(v::RING.end())
    );
    assert_eq!(
        (layout::SEND, layout::SEND_SIZE),
        (page(v::SEND.first), page(v::SEND.count))
    );
    assert_eq!(
        (layout::RECEIVE, layout::RECEIVE_SIZE),
        (page(v::RECEIVE.first), page(v::RECEIVE.count))
    );
    // The request page is in no GPADL.
    for p in [v::RING, v::SEND, v::RECEIVE] {
        assert!(!(p.first..p.end()).contains(&layout::REQUEST_PAGE));
    }
    // netvsc's windows below the first GiB, apart from the frame queues'.
    assert!(layout::CHANNEL + layout::CHANNEL_SIZE as u64 <= layout::MNF);
    assert!(layout::MNF + layout::MNF_SIZE as u64 <= frames::WINDOW);
}

#[test]
fn the_stats_text_and_words() {
    let m = Machine::new();
    let q = queues();
    let r = up(&m, &q, Setup::default());
    let s = r.a.stats();
    assert_eq!(
        format!("netvsc: stats: {s}"),
        "netvsc: stats: NVSP 5, NDIS 6.30, 4 receive-buffer packets, 0 frames received, 0 dropped for no buffer, 4 acknowledgements sent, 0 acknowledgements waiting, 0 frames sent, 0 sections in flight at most, 0 send completions, 0 status indications, 0 broken packets, 0 packets skipped, 0 ignored messages, 0 bad queue entries"
    );
    assert_eq!(NetvscStats::from_words(s.to_words()), s);
    assert_eq!(
        format!("{}", NetvscStats::default()),
        "NVSP none, NDIS none, 0 receive-buffer packets, 0 frames received, 0 dropped for no buffer, 0 acknowledgements sent, 0 acknowledgements waiting, 0 frames sent, 0 sections in flight at most, 0 send completions, 0 status indications, 0 broken packets, 0 packets skipped, 0 ignored messages, 0 bad queue entries"
    );
}

#[test]
fn a_monitor_trigger_past_monitor_page_2_is_refused_with_mnf() {
    let m = Machine::new();
    let q = queues();
    let a = VmbusAttach {
        montrig: 128,
        ..some_attach()
    };
    let start = Start {
        channel: machine::CHANNEL,
        mnf: true,
    };
    let mnf = || Some(m.window(machine::MONITOR + machine::PAGE, 2 * machine::PAGE));
    let r = Adapter::new(start, a, channel(&m), mnf(), Driver::new(&q));
    assert_eq!(r.err(), Some(Failure::Trigger(128)));
    assert_eq!(
        format!("{}", Failure::Trigger(128)),
        "netvsc: monitor trigger 128 is past monitor page 2's 128"
    );
    // Without HASMNF, or without netvsc.mnf=1, it is never used.
    let no_mnf = VmbusAttach { flags1: 0, ..a };
    assert!(Adapter::new(start, no_mnf, channel(&m), mnf(), Driver::new(&q)).is_ok());
    let off = Start {
        mnf: false,
        ..start
    };
    assert!(Adapter::new(off, a, channel(&m), None, Driver::new(&q)).is_ok());
    let last = VmbusAttach { montrig: 127, ..a };
    assert!(Adapter::new(start, last, channel(&m), mnf(), Driver::new(&q)).is_ok());
}

#[test]
#[should_panic(expected = "netvsc: a monitor window that does not match netvsc.mnf")]
fn a_monitor_window_without_mnf_is_a_panic() {
    let m = Machine::new();
    let q = queues();
    let start = Start {
        channel: machine::CHANNEL,
        mnf: false,
    };
    let w = Some(m.window(machine::MONITOR + machine::PAGE, 2 * machine::PAGE));
    let _ = Adapter::new(start, some_attach(), channel(&m), w, Driver::new(&q));
}
