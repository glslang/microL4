//! The encodings: root's arguments, every channel message against the
//! mock's own codec, GUIDs, GPADL splitting and the request decoder.

use hvmock::wire::{self, Request as Wire};
use libsys::proto::{Refusal, label};

use super::*;
use crate::gpadl::Pages;
use crate::msg::{Bad, Msg, PageList, kind};
use crate::offer::{Guid, NETVSC, Offer, Offers, Refused};

#[test]
fn start_words_round_trip_and_refuse_what_root_never_passes() {
    assert_eq!(Start::from_words(START.to_words()), Some(START));
    let page = layout::PAGE;
    let good = START.to_words();
    let bad = |i: usize, v: u64| {
        let mut w = good;
        w[i] = v;
        w
    };
    for w in [
        bad(0, 0),
        bad(0, 0x10_0000),
        bad(0, Start::PHYSICAL - 0x10_0000),
        bad(0, Start::PHYSICAL),
        bad(1, 0),
        bad(1, machine::MONITOR + 8),
        bad(2, machine::MONITOR + page),
        bad(2, machine::MONITOR + 3 * page),
        // The three pages inside the channel frame, at its start, middle
        // and end.
        [START.channel, START.channel, START.channel + 2 * page, 0],
        [
            START.channel,
            START.channel + 0x1000,
            START.channel + 0x3000,
            0,
        ],
        [
            START.channel,
            START.channel + Start::CHANNEL_SIZE - page,
            START.channel + Start::CHANNEL_SIZE + page,
            0,
        ],
        [START.channel, START.channel - 2 * page, START.channel, 0],
    ] {
        assert_eq!(Start::from_words(w), None, "{w:x?}");
    }
    // Just outside the frame, either side.
    for monitor in [
        START.channel - 3 * page,
        START.channel + Start::CHANNEL_SIZE,
    ] {
        let w = [START.channel, monitor, monitor + 2 * page, 0];
        assert!(Start::from_words(w).is_some(), "{w:x?}");
    }
    // rcx is BootInfo's tsc_hz, whatever it is: 0 when the kernel did not
    // measure it.
    for hz in [0, 1, 2_400_000_000, u64::MAX] {
        let mut w = START.to_words();
        w[3] = hz;
        assert_eq!(Start::from_words(w).map(|s| s.tsc_hz), Some(hz));
    }
    assert_eq!(START.channel_page(3), machine::CHANNEL / page + 3);
    assert_eq!(START.monitor2(), machine::MONITOR + page);
}

/// One of each message, with distinct fields.
fn every_message() -> Vec<Msg> {
    let offer = Offer {
        channel: 14,
        kind: NETVSC,
        instance: Guid([7; 16]),
        subchannel: 2,
        flags1: 1,
        montrig: 0x41,
        flags2: 0xBEEF,
        connection: 0x00AB_CDEF,
    };
    vec![
        Msg::ChOffer(offer),
        Msg::ChRescind { channel: 9 },
        Msg::ChRequest,
        Msg::ChOfferDone,
        Msg::ChOpen {
            channel: 14,
            open_id: 15,
            gpadl: 0xE1E10,
            vp: 3,
            outbound_pages: 16,
        },
        Msg::ChOpenResp {
            channel: 14,
            open_id: 15,
            status: 0xC000_0001,
        },
        Msg::ChClose { channel: 14 },
        Msg::GpadlConn {
            channel: 14,
            gpadl: 0xE1E11,
            range_len: 8 + 8 * 32,
            range_count: 1,
            byte_len: 32 * 4096,
            byte_offset: 0,
            pages: PageList::run(0x200, 26).unwrap(),
        },
        Msg::GpadlSubconn {
            number: 0,
            gpadl: 0xE1E11,
            pages: PageList::run(0x21A, 6).unwrap(),
        },
        Msg::GpadlConnResp {
            channel: 14,
            gpadl: 0xE1E11,
            status: 0,
        },
        Msg::GpadlDisconn {
            channel: 14,
            gpadl: 0xE1E12,
        },
        Msg::GpadlDisconnResp { gpadl: 0xE1E12 },
        Msg::Connect {
            version: version(4, 0),
            event_flags: 0x6000,
            monitor1: 0x4000,
            monitor2: 0x5000,
        },
        Msg::ConnectResp { done: true },
        Msg::ConnectResp { done: false },
    ]
}

#[test]
fn messages_round_trip_at_their_sizes() {
    for m in every_message() {
        let mut b = [0u8; msg::MAX];
        let n = m.encode(&mut b);
        let need = msg::size(m.kind()).unwrap();
        match m {
            Msg::GpadlConn { pages, .. } => assert_eq!(n, msg::CONN_PAGE_OFFSET + 8 * pages.len()),
            Msg::GpadlSubconn { pages, .. } => {
                assert_eq!(n, msg::SUBCONN_PAGE_OFFSET + 8 * pages.len())
            }
            _ => assert_eq!(n, need, "{}", m.name()),
        }
        assert_eq!(u32::from_le_bytes(b[..4].try_into().unwrap()), m.kind());
        assert_eq!(Msg::decode(&b[..n]), Ok(m), "{}", m.name());
        // A longer message is the same message, but for GPADLs, whose
        // length is their page count.
        let gpadl = matches!(m, Msg::GpadlConn { .. } | Msg::GpadlSubconn { .. });
        if !gpadl {
            assert_eq!(Msg::decode(&b[..msg::MAX]), Ok(m), "{}", m.name());
        }
        // A byte short is refused.
        let short = if n - 1 < msg::HEADER {
            Bad::Short(n - 1)
        } else {
            Bad::Size {
                kind: m.kind(),
                len: n - 1,
            }
        };
        assert_eq!(Msg::decode(&b[..n - 1]), Err(short), "{}", m.name());
    }
}

#[test]
fn decoding_refuses_what_is_not_a_message() {
    for n in 0..msg::HEADER {
        assert_eq!(Msg::decode(&[0; 8][..n]), Err(Bad::Short(n)));
    }
    for k in [0, kind::CHFREE, kind::DISCONNECT, 17, 23, 24, u32::MAX] {
        let mut b = [0u8; 200];
        b[..4].copy_from_slice(&k.to_le_bytes());
        assert_eq!(Msg::decode(&b), Err(Bad::Kind(k)));
    }
    // Over 240 bytes.
    let mut b = [0u8; 241];
    b[0] = kind::CHOFFER_DONE as u8;
    assert!(Msg::decode(&b).is_err());
    // A GPADL message with a partial page number, too many pages or none.
    let conn = |len: usize| {
        let mut b = [0u8; 256];
        b[0] = kind::GPADL_CONN as u8;
        Msg::decode(&b[..len])
    };
    assert!(conn(msg::CONN_PAGE_OFFSET + 8).is_ok());
    assert!(conn(msg::CONN_PAGE_OFFSET + 8 * 26).is_ok());
    assert!(conn(msg::CONN_PAGE_OFFSET + 12).is_err());
    assert!(conn(msg::CONN_PAGE_OFFSET).is_err());
    assert!(conn(msg::CONN_PAGE_OFFSET + 8 * 26 + 8).is_err());
    let sub = |len: usize| {
        let mut b = [0u8; 256];
        b[0] = kind::GPADL_SUBCONN as u8;
        Msg::decode(&b[..len])
    };
    assert!(sub(msg::SUBCONN_PAGE_OFFSET + 8 * 28).is_ok());
    assert!(sub(msg::SUBCONN_PAGE_OFFSET + 3).is_err());
    assert_eq!(PageList::run(0, 29), None);
    assert_eq!(PageList::new(&[0; 29]), None);
}

/// What vmbus encodes, the mock parses to the same fields; what the mock
/// builds, vmbus decodes to the same fields.
#[test]
fn the_mock_reads_what_vmbus_writes_and_vmbus_what_the_mock_writes() {
    for m in every_message() {
        let mut b = [0u8; msg::MAX];
        let n = m.encode(&mut b);
        let w = wire::parse(&b[..n]);
        match m {
            Msg::ChRequest => assert_eq!(w, Ok(Wire::ChRequest)),
            Msg::ChOpen {
                channel,
                open_id,
                gpadl,
                vp,
                outbound_pages,
            } => assert_eq!(
                w,
                Ok(Wire::ChOpen {
                    channel,
                    open_id,
                    gpadl,
                    vp,
                    outbound_pages,
                    user_data_zero: true
                })
            ),
            Msg::ChClose { channel } => assert_eq!(w, Ok(Wire::ChClose { channel })),
            Msg::GpadlConn {
                channel,
                gpadl,
                range_len,
                range_count,
                byte_len,
                byte_offset,
                pages,
            } => assert_eq!(
                w,
                Ok(Wire::GpadlConn {
                    channel,
                    gpadl,
                    range_len,
                    range_count,
                    byte_len,
                    byte_offset,
                    pages: pages.as_slice().to_vec()
                })
            ),
            Msg::GpadlSubconn {
                number,
                gpadl,
                pages,
            } => assert_eq!(
                w,
                Ok(Wire::GpadlSubconn {
                    number,
                    gpadl,
                    pages: pages.as_slice().to_vec()
                })
            ),
            Msg::GpadlDisconn { channel, gpadl } => {
                assert_eq!(w, Ok(Wire::GpadlDisconn { channel, gpadl }))
            }
            Msg::Connect {
                version,
                event_flags,
                monitor1,
                monitor2,
            } => assert_eq!(
                w,
                Ok(Wire::Connect {
                    version,
                    event_flags,
                    monitor1,
                    monitor2
                })
            ),
            // The host's messages are not requests.
            _ => {}
        }
    }
    let spec = hvmock::OfferSpec::netvsc(14, 0x12_3456).subchannel(3, 15, 0x12_3457);
    let o = Msg::decode(&wire::offer(&spec)).unwrap();
    assert_eq!(
        o,
        Msg::ChOffer(Offer {
            channel: 15,
            kind: NETVSC,
            instance: Guid(spec.instance),
            subchannel: 3,
            flags1: spec.flags1,
            montrig: spec.montrig,
            flags2: spec.flags2,
            connection: 0x12_3457,
        })
    );
    let cases: [(Vec<u8>, Msg); 7] = [
        (wire::connect_resp(true), Msg::ConnectResp { done: true }),
        (wire::connect_resp(false), Msg::ConnectResp { done: false }),
        (wire::offers_done(), Msg::ChOfferDone),
        (wire::rescind(5), Msg::ChRescind { channel: 5 }),
        (
            wire::gpadl_connresp(14, 0xE1E10, 7),
            Msg::GpadlConnResp {
                channel: 14,
                gpadl: 0xE1E10,
                status: 7,
            },
        ),
        (
            wire::chopen_resp(14, 14, 0),
            Msg::ChOpenResp {
                channel: 14,
                open_id: 14,
                status: 0,
            },
        ),
        (
            wire::gpadl_disconnresp(0xE1E12),
            Msg::GpadlDisconnResp { gpadl: 0xE1E12 },
        ),
    ];
    for (bytes, m) in cases {
        assert_eq!(Msg::decode(&bytes), Ok(m));
    }
}

#[test]
fn guids_print_as_freebsd_does_and_name_their_devices() {
    assert_eq!(format!("{NETVSC}"), "f8615163-df3e-46c5-913f-f2d2f965ed0e");
    assert_eq!(NETVSC.0, hvmock::guid::NETVSC);
    assert_eq!(NETVSC.name(), Some("netvsc"));
    for (g, name) in crate::offer::KNOWN {
        let text = format!("{g}");
        assert_eq!(Guid::parse(&text), Some(g), "{name}");
        assert_eq!(text, wire::guid_text(&g.0), "{name}");
        assert_eq!(g.name(), Some(name));
    }
    assert_eq!(
        Guid::parse("BA6163D9-04A1-4D29-B605-72E2FFB1DC7F")
            .unwrap()
            .0,
        hvmock::guid::STORVSC
    );
    for bad in [
        "",
        "f8615163df3e46c5913ff2d2f965ed0e",
        "f8615163-df3e-46c5-913f-f2d2f965ed0",
        "f8615163-df3e-46c5-913f-f2d2f965ed0g",
        "f8615163+df3e-46c5-913f-f2d2f965ed0e",
    ] {
        assert_eq!(Guid::parse(bad), None, "{bad}");
    }
    assert_eq!(Guid([0xA5; 16]).name(), None);
    let mut o = Offer {
        channel: 17,
        kind: Guid([0xA5; 16]),
        connection: 99,
        ..Offer::default()
    };
    assert_eq!(
        format!("{o}"),
        "vmbus: offer 17: a5a5a5a5-a5a5-a5a5-a5a5-a5a5a5a5a5a5, connection 99"
    );
    o.kind = NETVSC;
    o.subchannel = 2;
    assert_eq!(
        format!("{o}"),
        "vmbus: offer 17: netvsc, connection 99, sub-channel 2"
    );
    // HASMNF: the host may monitor the channel, through this trigger.
    o.subchannel = 0;
    o.flags1 = 1;
    o.montrig = 77;
    assert_eq!(
        format!("{o}"),
        "vmbus: offer 17: netvsc, connection 99, monitor trigger 77"
    );
    o.flags1 = 0xFE;
    assert_eq!(format!("{o}"), "vmbus: offer 17: netvsc, connection 99");
}

#[test]
fn the_offer_table_keeps_32_distinct_channels_in_range() {
    let mut t = Offers::default();
    let o = |channel: u32| Offer {
        channel,
        connection: channel,
        ..Offer::default()
    };
    assert_eq!(t.add(o(0)), Err(Refused::Channel));
    assert_eq!(t.add(o(2048)), Err(Refused::Channel));
    assert_eq!(
        t.add(Offer {
            connection: 1 << 24,
            ..o(5)
        }),
        Err(Refused::Connection)
    );
    for c in 1..=32 {
        assert_eq!(t.add(o(c * 63)), Ok(()));
    }
    assert_eq!(t.add(o(63)), Err(Refused::Repeated));
    assert_eq!(t.add(o(2047)), Err(Refused::Full));
    assert_eq!(t.len(), 32);
    assert_eq!(t.max_channel(), Some(32 * 63));
    assert_eq!(t.remove(63).map(|x| x.channel), Some(63));
    assert_eq!(t.remove(63), None);
    assert_eq!(t.add(o(2047)), Ok(()));
    assert_eq!(t.max_channel(), Some(2047));
    assert!(t.netvsc().is_none());
    let order: Vec<u32> = t.iter().map(|x| x.channel).collect();
    assert_eq!(order[..2], [126, 189]);
    assert_eq!(*order.last().unwrap(), 2047);
}

/// GPADLs of 32, 192 and 256 pages: a CONN of 26, then SUBCONNs of 28 and
/// the rest, every page once, in order.
#[test]
fn gpadls_split_26_then_28_at_a_time() {
    for (count, sizes) in [
        (1, &[1][..]),
        (26, &[26]),
        (27, &[26, 1]),
        (32, &[26, 6]),
        (54, &[26, 28]),
        (192, &[26, 28, 28, 28, 28, 28, 26]),
        (256, &[26, 28, 28, 28, 28, 28, 28, 28, 28, 6]),
    ] {
        let pages = Pages {
            first: 0x1234,
            count,
        };
        let ms: Vec<Msg> = gpadl::messages(14, 0xE1E10, pages).unwrap().collect();
        assert_eq!(ms.len() as u64, gpadl::message_count(count));
        let mut next = 0x1234;
        for (i, m) in ms.iter().enumerate() {
            let p = match *m {
                Msg::GpadlConn {
                    channel,
                    gpadl,
                    range_len,
                    range_count,
                    byte_len,
                    byte_offset,
                    pages,
                } => {
                    assert_eq!(i, 0);
                    assert_eq!((channel, gpadl), (14, 0xE1E10));
                    assert_eq!(u64::from(range_len), 8 + 8 * count);
                    assert_eq!((range_count, byte_offset), (1, 0));
                    assert_eq!(u64::from(byte_len), 4096 * count);
                    pages
                }
                Msg::GpadlSubconn {
                    number,
                    gpadl,
                    pages,
                } => {
                    assert_ne!(i, 0);
                    assert_eq!((number, gpadl), (0, 0xE1E10));
                    pages
                }
                _ => panic!("{m:?}"),
            };
            assert_eq!(p.len(), sizes[i], "{count} pages, message {i}");
            for &page in p.as_slice() {
                assert_eq!(page, next);
                next += 1;
            }
            let mut b = [0u8; msg::MAX];
            assert!(m.encode(&mut b) <= msg::MAX);
        }
        assert_eq!(next, 0x1234 + count);
    }
    assert!(gpadl::messages(14, 1, Pages { first: 0, count: 0 }).is_none());
    assert!(
        gpadl::messages(
            14,
            1,
            Pages {
                first: 0,
                count: 8190
            }
        )
        .is_some()
    );
    assert!(
        gpadl::messages(
            14,
            1,
            Pages {
                first: 0,
                count: 8191
            }
        )
        .is_none()
    );
    assert!(
        gpadl::messages(
            14,
            1,
            Pages {
                first: u64::MAX,
                count: 1
            }
        )
        .is_none()
    );
    let mut h = gpadl::Handles::default();
    assert_eq!([h.take(), h.take()], [gpadl::START, gpadl::START + 1]);
}

#[test]
fn requests_decode_by_label_then_badge() {
    assert_eq!(
        decode(label::VMBUS_ATTACH, libsys::proto::VMBUS_CLIENT),
        Ok(Request::Attach)
    );
    for badge in [0, 2, 3, u64::MAX] {
        assert_eq!(decode(label::VMBUS_ATTACH, badge), Err(Refusal::BadBadge));
        assert_eq!(decode(label::VMBUS_STATS, badge), Ok(Request::Stats));
    }
    for l in [0, 1, label::UART_STATS, label::NETVSC_STATS, 0x162, 0x15F] {
        assert_eq!(decode(l, 1), Err(Refusal::BadLabel), "{l:#x}");
    }
    assert_eq!(Bus::<hvmock::Page<'_>>::mint_data(0x12_3456), 0x212_3456);
}
