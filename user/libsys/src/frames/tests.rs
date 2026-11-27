//! The frame queues' unit tests: the layout against the design's table,
//! the start, the round trips, and each refusal. The random tests against
//! a model of the two owners are in `model.rs`.

use super::*;
use crate::mem::Ram;
use core::sync::atomic::Ordering::Relaxed;
use std::vec::Vec;

mod model;

const MAC: Mac = Mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

/// Zeroed memory for the queues: only what the layout uses, which keeps
/// Miri fast.
pub(super) fn ram() -> Ram {
    Ram::new(layout::END)
}

/// A driver and `net` that have started, with nothing in flight but the
/// free buffers each handed the other.
fn started(ram: &Ram) -> (Driver<&Ram>, Net<&Ram>) {
    let mut d = Driver::new(ram);
    d.start(Link::new(MAC, true));
    assert!(d.end_batch());
    let mut n = Net::new(ram);
    assert_eq!(n.attach(), Ok(Link::new(MAC, true)));
    assert!(n.end_batch());
    (d, n)
}

fn frame(len: usize, seed: u8) -> Vec<u8> {
    (0..len)
        .map(|i| (i as u8).wrapping_mul(31) ^ seed)
        .collect()
}

fn head(ram: &Ram, q: Queue) -> u32 {
    ram.load32(q.head(), Relaxed)
}

fn tail(ram: &Ram, q: Queue) -> u32 {
    ram.load32(q.tail(), Relaxed)
}

fn entry(ram: &Ram, q: Queue, k: u32) -> Entry {
    Entry::from_word(ram.load32(q.entry(k), Relaxed))
}

#[test]
fn the_layout_is_the_designs() {
    assert_eq!(WINDOW, 0x1000_0000);
    assert_eq!(SIZE, 2 << 20);
    assert_eq!(
        Queue::ALL.map(Queue::offset),
        [0x1000, 0x2000, 0x3000, 0x4000]
    );
    assert_eq!(Queue::RxFree.head(), 0x2000);
    assert_eq!(Queue::RxFree.tail(), 0x2040);
    assert_eq!(Queue::TxFree.entry(0), 0x4080);
    assert_eq!(Queue::TxFree.entry(127), 0x4080 + 4 * 127);
    assert_eq!(Queue::TxFree.entry(128), 0x4080);
    assert_eq!(Queue::TxFree.entry(u32::MAX), 0x4080 + 4 * 127);
    assert_eq!(Pool::Rx.buffer(0), 0x1_0000);
    assert_eq!(Pool::Rx.buffer(127), 0x1_0000 + 2048 * 127);
    assert_eq!(Pool::Tx.buffer(0), 0x5_0000);
    assert_eq!(Pool::Tx.buffer(127) + BUFFER_SIZE, layout::END);
    // Who produces what.
    assert_eq!(
        Queue::ALL.map(Queue::producer),
        [Role::Driver, Role::Net, Role::Net, Role::Driver]
    );
    assert_eq!(Queue::ALL.map(Queue::is_filled), [true, false, true, false]);
    assert_eq!(
        Queue::ALL.map(Queue::pool),
        [Pool::Rx, Pool::Rx, Pool::Tx, Pool::Tx]
    );
    assert_eq!(
        (Role::Driver.fills(), Role::Net.fills()),
        (Pool::Rx, Pool::Tx)
    );
    for p in Pool::ALL {
        assert_eq!((p.filled().pool(), p.free().pool()), (p, p));
    }
}

#[test]
fn entries_and_what_fits() {
    let e = Entry {
        index: 5,
        len: 1514,
    };
    assert_eq!(e.word(), 5 | 1514 << 16);
    assert_eq!(Entry::from_word(e.word()), e);
    assert!(e.fits(true) && !e.fits(false));
    assert!(Entry::free(127).fits(false) && !Entry::free(127).fits(true));
    assert!(!Entry::free(128).fits(false));
    for len in [0, 13, 1515, u16::MAX] {
        assert!(!Entry { index: 0, len }.fits(true), "{len}");
    }
    for len in [14, 60, 1514] {
        assert!(Entry { index: 127, len }.fits(true), "{len}");
        assert!(!Entry { index: 128, len }.fits(true), "{len}");
    }
}

#[test]
fn owned_maps() {
    let o = Owned::NONE.with(3).with(127);
    assert!(o.has(3) && o.has(127) && !o.has(4) && !o.has(128) && !o.has(u16::MAX));
    assert_eq!((o.first(), o.count()), (Some(3), 2));
    assert_eq!(o.without(3).first(), Some(127));
    assert_eq!(Owned::NONE.first(), None);
    assert_eq!(Owned::ALL.count(), 128);
}

#[test]
fn macs() {
    assert_eq!(std::format!("{MAC}"), "52:54:00:12:34:56");
    assert_eq!(
        std::format!("{}", Mac([0x52, 0x55, 0x0a, 0, 2, 2])),
        "52:55:0a:00:02:02"
    );
    assert_eq!(MAC.to_word(), 0x5634_1200_5452);
    assert_eq!(Mac::from_word(MAC.to_word() | 0xFFFF << 48), MAC);
    assert!(MAC.is_unicast());
    assert!(!Mac::ZERO.is_unicast() && Mac::ZERO.is_zero());
    assert!(Mac::BROADCAST.is_multicast() && !Mac::BROADCAST.is_unicast());
    assert!(Mac([1, 0, 0x5e, 0, 0, 1]).is_multicast());
}

#[test]
fn start_hands_each_side_the_others_free_buffers() {
    let ram = ram();
    let mut d = Driver::new(&ram);
    assert_eq!(d.owned(Pool::Tx), Owned::ALL);
    d.start(Link::new(MAC, true));
    // Every transmit buffer is on TX_FREE, in order, then the link.
    assert_eq!(head(&ram, Queue::TxFree), 128);
    for k in 0..128 {
        assert_eq!(entry(&ram, Queue::TxFree, k), Entry::free(k as u16));
    }
    assert_eq!(d.owned(Pool::Tx), Owned::NONE);
    let mut link = [0; 16];
    ram.read(layout::LINK, &mut link);
    assert_eq!(
        link,
        [
            0x52, 0x54, 0, 0x12, 0x34, 0x56, 0xDC, 0x05, 1, 0, 0, 0, 1, 0, 0, 0
        ]
    );
    assert!(d.end_batch());
    assert!(!d.end_batch());
    assert_eq!(d.counters().signals, 1);

    let mut n = Net::new(&ram);
    assert_eq!(n.owned(Pool::Rx), Owned::ALL);
    assert_eq!(n.attach(), Ok(Link::new(MAC, true)));
    assert_eq!(head(&ram, Queue::RxFree), 128);
    assert_eq!(n.owned(Pool::Rx), Owned::NONE);
    assert!(n.end_batch());
    // Each takes the other's.
    assert_eq!(n.reclaim(), 128);
    assert_eq!(n.owned(Pool::Tx), Owned::ALL);
    assert_eq!(tail(&ram, Queue::TxFree), 128);
    assert_eq!(d.reclaim(), 128);
    assert_eq!((d.free_buffers(), n.free_buffers()), (128, 128));
    assert_eq!(d.counters().bad + n.counters().bad, 0);
    // Taking back pushes nothing, so no signal is owed.
    assert!(!n.end_batch() && !d.end_batch());
}

#[test]
fn received_frames_reach_net_whole_and_in_order() {
    let ram = ram();
    let (mut d, mut n) = started(&ram);
    for (i, len) in [14, 60, 1514, 777].into_iter().enumerate() {
        assert_eq!(d.deliver(&frame(len, i as u8)), Ok(()));
    }
    assert!(d.end_batch());
    let mut out = [0; MAX_FRAME];
    for (i, len) in [14, 60, 1514, 777].into_iter().enumerate() {
        assert_eq!(n.peek_rx(), Some(len));
        assert_eq!(n.take_rx(&mut out), Some(len));
        assert_eq!(&out[..len], &frame(len, i as u8)[..]);
    }
    assert_eq!(n.take_rx(&mut out), None);
    // net handed each buffer back at once, and owes a signal for that.
    assert_eq!(head(&ram, Queue::RxFree), 128 + 4);
    assert!(n.end_batch());
    assert_eq!(d.free_buffers(), 124);
    assert_eq!(d.reclaim(), 4);
    let (dc, nc) = (d.counters(), n.counters());
    assert_eq!((dc.sent, nc.received, dc.reclaimed), (4, 4, 128 + 4));
    assert_eq!(dc.bad + nc.bad + dc.dropped + nc.dropped, 0);
}

#[test]
fn frames_to_send_reach_the_driver_and_wait_until_taken() {
    let ram = ram();
    let (mut d, mut n) = started(&ram);
    n.send(&frame(42, 1)).unwrap();
    n.send_with(100, |buf| {
        assert_eq!(buf.len(), 100);
        buf.write(0, &frame(100, 2));
    })
    .unwrap();
    assert!(n.end_batch());
    // Peeking leaves the frame where it is.
    assert_eq!(d.peek_tx(), Some(42));
    assert_eq!(d.peek_tx(), Some(42));
    assert_eq!(tail(&ram, Queue::TxFilled), 0);
    let mut out = [0; MAX_FRAME];
    assert_eq!(d.take_tx(&mut out), Some(42));
    assert_eq!(&out[..42], &frame(42, 1)[..]);
    let got = d.take_tx_with(|buf| {
        let mut v = std::vec![0; buf.len()];
        buf.read(0, &mut v);
        v
    });
    assert_eq!(got, Some(frame(100, 2)));
    assert_eq!(d.peek_tx(), None);
    assert!(d.end_batch());
    assert_eq!(n.free_buffers(), 126);
    assert_eq!(n.reclaim(), 2);
}

#[test]
fn a_side_with_no_free_buffer_takes_them_back_then_drops() {
    let ram = ram();
    let (mut d, mut n) = started(&ram);
    // The driver takes back RX_FREE by itself.
    for i in 0..128 {
        d.deliver(&frame(64, i)).unwrap();
    }
    assert_eq!(d.free_buffers(), 0);
    assert_eq!(d.deliver(&frame(64, 0)), Err(PushError::NoBuffer));
    assert_eq!(d.counters().dropped, 1);
    let mut out = [0; MAX_FRAME];
    assert_eq!(n.take_rx(&mut out), Some(64));
    // One came back; deliver finds it without a reclaim.
    d.deliver(&frame(64, 9)).unwrap();
    assert_eq!(d.deliver(&frame(64, 9)), Err(PushError::NoBuffer));
    assert_eq!(d.counters().dropped, 2);
    // A frame of the wrong length is refused and not counted.
    assert_eq!(n.send(&[0; 13]), Err(PushError::Length(13)));
    assert_eq!(n.send(&[0; 1515]), Err(PushError::Length(1515)));
    assert_eq!((n.counters().received, n.counters().dropped), (1, 0));
    assert_eq!(d.counters().bad + n.counters().bad, 0);
}

#[test]
fn deliver_with_fills_only_once_a_buffer_is_found() {
    let ram = ram();
    let (mut d, _n) = started(&ram);
    for _ in 0..128 {
        d.deliver(&[1; 20]).unwrap();
    }
    let r = d.deliver_with(20, |_| panic!("filled with no buffer"));
    assert_eq!(r, Err(PushError::NoBuffer));
}

#[test]
fn net_refuses_a_bad_link_block_and_hands_nothing_over() {
    let ram = ram();
    let mut n = Net::new(&ram);
    assert_eq!(n.attach(), Err(LinkError::NotReady(0)));
    let mut d = Driver::new(&ram);
    for (mac, mtu, up, err) in [
        (Mac::ZERO, MTU, 1, LinkError::BadMac(Mac::ZERO)),
        (Mac::BROADCAST, MTU, 1, LinkError::BadMac(Mac::BROADCAST)),
        (
            Mac([0x33, 0x33, 0, 0, 0, 1]),
            MTU,
            0,
            LinkError::BadMac(Mac([0x33, 0x33, 0, 0, 0, 1])),
        ),
        (MAC, 1514, 1, LinkError::BadMtu(1514)),
        (MAC, MTU, 2, LinkError::BadUp(2)),
    ] {
        Link {
            mac,
            mtu,
            up: false,
        }
        .write(&ram);
        ram.store32(layout::LINK + layout::LINK_UP, up, Relaxed);
        assert_eq!(n.attach(), Err(err));
        assert_eq!(head(&ram, Queue::RxFree), 0);
    }
    ram.store32(layout::LINK + layout::LINK_READY, 2, Relaxed);
    assert_eq!(n.attach(), Err(LinkError::NotReady(2)));
    d.start(Link::new(MAC, false));
    assert_eq!(n.attach(), Ok(Link::new(MAC, false)));
    assert!(std::format!("{}", LinkError::BadMac(Mac::BROADCAST)).contains("ff:ff:ff:ff:ff:ff"));
}

#[test]
#[should_panic(expected = "used before it started")]
fn a_side_must_start_first() {
    let ram = ram();
    let mut n = Net::new(&ram);
    let _ = n.send(&[0; 64]);
}

#[test]
#[should_panic(expected = "started twice")]
fn a_side_starts_once() {
    let ram = ram();
    let (mut d, _) = started(&ram);
    d.start(Link::new(MAC, true));
}

#[test]
#[should_panic(expected = "too small")]
fn the_window_must_hold_the_layout() {
    let ram = Ram::new(layout::END - 1);
    let _ = Driver::new(&ram);
}

/// Each bad kind of entry a consumer can meet: counted once and passed,
/// and the good one behind it taken.
#[test]
fn bad_entries_are_counted_and_passed() {
    let ram = ram();
    let (mut d, mut n) = started(&ram);
    let mut out = [0; MAX_FRAME];
    // A driver that pushes these on RX_FILLED after two good frames.
    d.deliver(&frame(60, 0)).unwrap();
    d.deliver(&frame(60, 1)).unwrap();
    let bad = [
        Entry {
            index: 128,
            len: 60,
        },
        Entry { index: 7, len: 13 },
        Entry {
            index: 7,
            len: 1515,
        },
        Entry { index: 7, len: 0 },
    ];
    let mut h = head(&ram, Queue::RxFilled);
    for e in bad {
        ram.store32(Queue::RxFilled.entry(h), e.word(), Relaxed);
        h += 1;
    }
    // Then an entry that fits, naming buffer 2, which the driver never
    // filled.
    ram.store32(
        Queue::RxFilled.entry(h),
        Entry { index: 2, len: 60 }.word(),
        Relaxed,
    );
    h += 1;
    ram.store32(Queue::RxFilled.head(), h, Relaxed);
    assert_eq!(n.take_rx(&mut out), Some(60));
    assert_eq!(n.take_rx(&mut out), Some(60));
    assert_eq!(&out[..60], &frame(60, 1)[..]);
    // The bad four are passed. Buffer 2's entry fits and net holds no
    // buffer 2, so net takes it: only the driver could know it never
    // filled it, and its bytes are net's to read whatever they are.
    assert_eq!(n.take_rx(&mut out), Some(60));
    assert_eq!(n.take_rx(&mut out), None);
    assert_eq!(n.counters().bad, 4);
    assert_eq!(n.counters().received, 3);
    assert_eq!(tail(&ram, Queue::RxFilled), h);
}

/// A buffer named twice is taken once: the second entry names a buffer
/// the taker holds.
#[test]
fn a_buffer_handed_over_twice_is_taken_once() {
    let ram = ram();
    let mut d = Driver::new(&ram);
    d.start(Link::new(MAC, true));
    // net hands buffer 5 back twice, and 6 once.
    for (k, i) in [5u16, 5, 6].into_iter().enumerate() {
        ram.store32(
            Queue::RxFree.entry(k as u32),
            Entry::free(i).word(),
            Relaxed,
        );
    }
    ram.store32(Queue::RxFree.head(), 3, Relaxed);
    assert_eq!(d.reclaim(), 2);
    assert_eq!(d.owned(Pool::Rx), Owned::NONE.with(5).with(6));
    assert_eq!(d.counters().bad, 1);
    // And 5 again, while the driver holds it: refused too.
    ram.store32(Queue::RxFree.entry(3), Entry::free(5).word(), Relaxed);
    ram.store32(Queue::RxFree.head(), 4, Relaxed);
    assert_eq!(d.reclaim(), 0);
    assert_eq!(d.counters().bad, 2);
}

/// A queue whose `head` claims more than 128 entries is empty to its
/// consumer, and one whose `tail` leaves no room is full to its producer;
/// both are counted, and neither moves the side's own indices.
#[test]
fn broken_indices_are_counted_and_never_followed() {
    let ram = ram();
    let (mut d, mut n) = started(&ram);
    let mut out = [0; MAX_FRAME];
    d.deliver(&frame(60, 0)).unwrap();
    // head 129 ahead of net's tail.
    ram.store32(Queue::RxFilled.head(), 129, Relaxed);
    assert_eq!(n.take_rx(&mut out), None);
    assert_eq!(n.counters().bad, 1);
    assert_eq!(tail(&ram, Queue::RxFilled), 0);
    // head behind tail is as far ahead, modulo 2^32.
    ram.store32(Queue::RxFilled.head(), u32::MAX, Relaxed);
    assert_eq!(n.peek_rx(), None);
    assert_eq!(n.counters().bad, 2);
    // The driver's next push writes its own head again, 2.
    d.deliver(&frame(60, 1)).unwrap();
    assert_eq!(head(&ram, Queue::RxFilled), 2);
    assert_eq!(n.take_rx(&mut out), Some(60));
    assert_eq!(&out[..60], &frame(60, 0)[..]);
    // A tail net claims ahead of the driver's head: no room.
    ram.store32(Queue::RxFilled.tail(), 3, Relaxed);
    assert_eq!(d.deliver(&frame(60, 2)), Err(PushError::Full));
    assert_eq!(d.counters().bad, 1);
    // The buffer is still the driver's.
    assert_eq!(d.free_buffers(), 126);
    // Writing a side's own index behind its back changes nothing: net
    // writes TX_FILLED's head from its own count, the driver RX_FILLED's
    // tail.
    ram.store32(Queue::TxFilled.head(), 50, Relaxed);
    n.send(&frame(30, 3)).unwrap();
    assert_eq!(head(&ram, Queue::TxFilled), 1);
    assert_eq!(d.take_tx(&mut out), Some(30));
    ram.store32(Queue::RxFilled.tail(), 1, Relaxed);
    d.deliver(&frame(60, 4)).unwrap();
    ram.store32(Queue::RxFilled.tail(), 0, Relaxed);
    assert_eq!(n.take_rx(&mut out), Some(60));
    assert_eq!(&out[..60], &frame(60, 1)[..]);
    assert_eq!(tail(&ram, Queue::RxFilled), 2);
}

/// A consumer reads an entry once: one that changes after `peek` is taken
/// as peeked.
#[test]
fn a_peeked_entry_is_not_read_again() {
    let ram = ram();
    let (mut d, mut n) = started(&ram);
    n.send(&frame(50, 0)).unwrap();
    assert_eq!(d.peek_tx(), Some(50));
    ram.store32(
        Queue::TxFilled.entry(0),
        Entry { index: 200, len: 9 }.word(),
        Relaxed,
    );
    let mut out = [0; MAX_FRAME];
    assert_eq!(d.take_tx(&mut out), Some(50));
    assert_eq!(d.counters().bad, 0);
}

/// A free queue a broken peer left full: the buffer waits and goes back
/// once there is room.
#[test]
fn a_buffer_to_hand_back_waits_for_room() {
    let ram = ram();
    let (mut d, mut n) = started(&ram);
    let mut out = [0; MAX_FRAME];
    d.deliver(&frame(60, 0)).unwrap();
    // The driver's tail on RX_FREE says it took nothing: full.
    ram.store32(Queue::RxFree.tail(), 0, Relaxed);
    assert_eq!(n.take_rx(&mut out), Some(60));
    assert_eq!(n.owned(Pool::Rx), Owned::NONE.with(0));
    assert!(n.counters().bad >= 1);
    assert!(!n.end_batch());
    // Room again: it goes back at the end of the batch.
    ram.store32(Queue::RxFree.tail(), 128, Relaxed);
    assert!(n.end_batch());
    assert_eq!(n.owned(Pool::Rx), Owned::NONE);
    assert_eq!(entry(&ram, Queue::RxFree, 128), Entry::free(0));
}
