//! The rings at work: frames both ways at every ring wrap, a full
//! transmit ring, used rings filled out of order or with bad elements,
//! interrupts, `NO_NOTIFY`, the frame queues' ownership, and the stats
//! text.

use core::sync::atomic::Ordering::{Relaxed, Release};
use std::string::ToString;
use std::vec;
use std::vec::Vec;

use libsys::frames::{self, Entry, Owned, Pool, Queue};
use libsys::mem::Memory;
use libsys::proto::VirtioNetStats;

use super::device::{Config, Device};
use super::{BASE, MAC, Mem, World, frame};
use crate::virtq::{AVAIL_F_NO_INTERRUPT, off};
use crate::{FEATURES, HEADER, layout};

/// A world on a QEMU-like model.
fn qemu(mem: &Mem) -> Device<'_> {
    Device::new(&mem.dma, BASE, Config::qemu())
}

/// Every descriptor of a queue of 64.
const ALL: u64 = u64::MAX;

fn tx_flags(mem: &Mem) -> u16 {
    mem.dma.load16(layout::ring(1) + off::AVAIL_FLAGS, Relaxed)
}

#[test]
fn frames_cross_both_ways() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    let rx = [frame(14, 1), frame(60, 2), frame(1514, 3)];
    for f in &rx {
        assert!(dev.receive(f));
    }
    assert!(w.signal());
    assert_eq!(w.net_take(), rx);
    let tx = vec![frame(1514, 4), frame(14, 5), frame(342, 6)];
    assert_eq!(w.net_send(&tx), 3);
    assert!(w.signal());
    assert_eq!(dev.transmit(), tx);
    let c = w.driver.counters();
    assert_eq!(
        (c.received, c.sent, c.dropped, c.bad_used, c.waits),
        (3, 3, 0, 0, 0)
    );
    assert_eq!(
        w.driver.queues()[0].posted(),
        ALL,
        "every receive descriptor back"
    );
    assert_eq!(w.queues.counters().bad, 0);
}

#[test]
fn receive_and_transmit_at_every_ring_wrap() {
    // Batches of 1 to 64 frames in turn put a batch's end at every slot
    // of the 64-entry rings; natively, past 65,536 frames each way, the
    // 16-bit indices wrap too.
    let total: usize = if cfg!(miri) {
        3 * 64 + 5
    } else {
        65_536 + 3 * 64 + 5
    };
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    let len = |seq: usize| match seq % 1000 {
        0 => 1514,
        1 => 14,
        n => 42 + n % 23,
    };
    let (mut seq, mut batch) = (0usize, 1usize);
    while seq < total {
        let b = batch.min(total - seq);
        let frames: Vec<_> = (seq..seq + b).map(|s| frame(len(s), s as u32)).collect();
        for f in &frames {
            assert!(dev.receive(f), "frame {seq}: no receive buffer");
        }
        assert!(w.signal());
        assert_eq!(w.net_take(), frames, "receive batch from {seq}");
        assert_eq!(w.net_send(&frames), b);
        w.settle();
        assert_eq!(dev.transmit(), frames, "transmit batch from {seq}");
        seq += b;
        batch = batch % 64 + 1;
    }
    w.settle();
    let c = w.driver.counters();
    assert_eq!((c.received, c.sent), (total as u64, total as u64));
    assert_eq!((c.dropped, c.bad_used, c.waits), (0, 0, 0));
    let d = &mem.dma;
    let total16 = total as u16;
    assert_eq!(
        d.load16(off::AVAIL_IDX, Relaxed),
        64u16.wrapping_add(total16)
    );
    assert_eq!(d.load16(off::USED_IDX, Relaxed), total16);
    assert_eq!(d.load16(0x1000 + off::AVAIL_IDX, Relaxed), total16);
    assert_eq!(d.load16(0x1000 + off::USED_IDX, Relaxed), total16);
    assert_eq!(w.queues.counters().bad, 0);
    assert_eq!(dev.no_buffer(), 0);
}

#[test]
fn a_full_transmit_ring_turns_completions_on_until_it_drains() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    let frames: Vec<_> = (0..100).map(|i| frame(60 + i % 50, i as u32)).collect();
    assert_eq!(w.net_send(&frames), 100);
    assert!(w.signal());
    // 64 descriptors: the rest wait, with completions on.
    assert_eq!(w.driver.counters().sent, 64);
    assert!(w.driver.waiting());
    assert_eq!(w.driver.counters().waits, 1);
    assert_eq!(tx_flags(&mem), 0);
    let mut out = dev.fetch_tx();
    assert_eq!(out.len(), 64);
    assert!(!w.signal(), "nothing completed, nothing to do");
    // Each completion interrupts while frames wait; the driver sends one
    // more frame per descriptor it takes back.
    for k in 1..=36 {
        assert!(dev.complete_tx(0));
        assert_eq!(dev.interrupts()[0], 1);
        assert!(w.signal());
        assert_eq!(w.driver.counters().sent, 64 + k);
        out.extend(dev.fetch_tx());
        assert_eq!(w.driver.waiting(), k < 36, "after {k}");
    }
    assert_eq!(out, frames);
    // Nothing waits: completions are off again, and interrupt no more.
    assert_eq!(tx_flags(&mem), AVAIL_F_NO_INTERRUPT);
    while dev.complete_tx(0) {}
    assert_eq!(dev.interrupts()[0], 0);
    assert_eq!(w.driver.counters().waits, 1);
    // The next frames find every descriptor free again.
    let more: Vec<_> = (100..110).map(|i| frame(60, i)).collect();
    w.net_send(&more);
    assert!(w.signal());
    assert_eq!(dev.transmit(), more);
    assert!(!w.driver.waiting());
    assert_eq!(w.driver.counters().waits, 1);
    assert_eq!(w.driver.counters().bad_used, 0);
}

#[test]
fn completions_after_a_wait_began_are_taken_at_once() {
    // Completions the device made with interrupts off are found by the
    // driver's next look, whatever signal brings it.
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    let frames: Vec<_> = (0..64).map(|i| frame(60, i)).collect();
    w.net_send(&frames);
    assert!(w.signal());
    assert!(!w.driver.waiting());
    assert_eq!(dev.transmit(), frames);
    assert_eq!(dev.interrupts()[0], 0, "completions are off");
    let next: Vec<_> = (64..164).map(|i| frame(60, i)).collect();
    assert_eq!(w.net_send(&next), 100);
    assert!(w.signal());
    assert_eq!(w.driver.counters().sent, 128);
    assert!(w.driver.waiting());
    while !dev.held(1).is_empty() || w.driver.waiting() {
        dev.transmit();
        assert!(w.signal());
    }
    assert_eq!(w.driver.counters().sent, 164);
    assert_eq!(w.driver.counters().waits, 1);
}

#[test]
fn the_device_may_use_buffers_in_any_order() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    // Receive into the last buffer the device holds each time: the
    // descriptors come back in reverse, the frames in the order sent.
    let frames: Vec<_> = (0..64).map(|i| frame(100 + i, i as u32)).collect();
    for f in &frames {
        assert!(dev.receive_at(f, usize::MAX));
    }
    assert!(w.signal());
    assert_eq!(w.net_take(), frames);
    assert_eq!(w.driver.queues()[0].posted(), ALL);
    // Transmit: completed last first.
    let tx: Vec<_> = (0..10).map(|i| frame(60, 100 + i)).collect();
    w.net_send(&tx);
    w.settle();
    assert_eq!(dev.fetch_tx(), tx);
    while dev.complete_tx(usize::MAX) {}
    assert_eq!(w.driver.queues()[1].posted(), (1 << 10) - 1);
    w.net_send(&[frame(60, 200)]);
    assert!(w.signal());
    // The ten came back, and the next frame took the lowest descriptor.
    assert_eq!(w.driver.queues()[1].posted(), 1);
    assert_eq!(dev.transmit(), [frame(60, 200)]);
    assert_eq!(w.driver.counters().bad_used, 0);
}

#[test]
fn bad_used_elements_are_counted_never_followed() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    let bad = |w: &World| w.driver.counters().bad_used;
    // An id out of the ring, and one past 16 bits.
    dev.inject_used(0, 64, 100);
    dev.inject_used(0, 70_000, 100);
    assert!(w.signal());
    assert_eq!((bad(&w), w.driver.counters().received), (2, 0));
    // A frame, then the same descriptor again in the same batch, which
    // the driver no longer holds out.
    assert_eq!(dev.fetch(0), 64);
    let head = dev.held(0)[0].head;
    let f = frame(60, 1);
    assert!(dev.receive(&f));
    dev.inject_used(0, head.into(), (HEADER + 60) as u32);
    assert!(w.signal());
    assert_eq!((bad(&w), w.driver.counters().received), (3, 1));
    assert_eq!(w.net_take(), [f]);
    // Lengths outside 12 + 14 to 12 + 1,514: counted, nothing delivered,
    // and the descriptor posted again.
    let lens = [0, 12, 12 + 13, 12 + 1515, 2048, 4096, u32::MAX];
    for (i, &len) in lens.iter().enumerate() {
        dev.complete_with(0, i, len);
        assert!(w.signal());
        assert_eq!(bad(&w), 4 + i as u64);
        assert_eq!(w.driver.queues()[0].posted(), ALL);
    }
    assert_eq!(w.net_take(), Vec::<Vec<u8>>::new());
    assert_eq!(w.driver.counters().received, 1);
    // The device can take every descriptor back; nothing was lost.
    dev.fetch(0);
    assert_eq!(dev.held(0).len(), 64);
    // Transmit: an element for a descriptor never posted.
    dev.inject_used(1, 5, 0);
    w.net_send(&[frame(60, 2)]);
    assert!(w.signal());
    assert_eq!(bad(&w), 3 + lens.len() as u64 + 1);
    assert_eq!(dev.transmit(), [frame(60, 2)]);
    assert_eq!(w.queues.counters().bad, 0);
}

#[test]
fn a_used_index_out_of_reach_is_counted_and_taken_as_none() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    assert!(dev.receive(&frame(60, 1)));
    assert!(w.signal());
    w.net_take();
    w.settle();
    let used = mem.dma.load16(off::USED_IDX, Relaxed);
    // 65 ahead: more than the ring holds. Then one behind.
    for idx in [
        used.wrapping_add(65),
        used.wrapping_add(0x8000),
        used.wrapping_sub(1),
    ] {
        dev.set_used_idx(0, idx);
        assert!(w.signal());
    }
    let c = w.driver.counters();
    assert_eq!((c.bad_used, c.received), (3, 1));
    // Back where it was, the ring works again.
    dev.set_used_idx(0, used);
    assert!(w.signal());
    assert_eq!(w.driver.counters().bad_used, 3);
    assert!(dev.receive(&frame(70, 2)));
    assert!(w.signal());
    assert_eq!(w.net_take(), [frame(70, 2)]);
}

#[test]
fn interrupts_come_only_when_asked_for() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    assert_eq!(dev.interrupts(), vec![0, 0, 0]);
    // Receive interrupts are on.
    assert!(dev.receive(&frame(60, 1)));
    assert_eq!(dev.interrupts(), vec![1, 0, 0]);
    assert!(w.signal());
    w.net_take();
    w.settle();
    // Transmit completions are off while nothing waits.
    w.net_send(&[frame(60, 2)]);
    assert!(w.signal());
    assert_eq!(dev.transmit().len(), 1);
    assert_eq!(dev.interrupts(), vec![0, 0, 0]);
    // No configuration interrupt: the driver mapped none.
    dev.set_link(0);
    assert_eq!(dev.interrupts(), vec![0, 0, 0]);
    // A signal with nothing to do is counted and changes nothing else.
    let before = w.driver.counters();
    w.frames = true;
    assert!(w.signal());
    let after = w.driver.counters();
    assert_eq!(after.signals, before.signals + 1);
    assert_eq!(
        (after.received, after.sent, after.bad_used),
        (before.received, before.sent, before.bad_used)
    );
}

#[test]
fn no_notify_is_honoured() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    // Transmit: while the device polls, no notify; once it stops, one.
    dev.set_no_notify(1, true);
    let n = dev.notifies(1);
    let frames: Vec<_> = (0..3).map(|i| frame(60, i)).collect();
    w.net_send(&frames);
    assert!(w.signal());
    assert_eq!(dev.notifies(1), n);
    assert_eq!(dev.transmit(), frames);
    dev.set_no_notify(1, false);
    w.net_send(&[frame(60, 3)]);
    assert!(w.signal());
    assert_eq!(dev.notifies(1), n + 1);
    assert_eq!(dev.transmit(), [frame(60, 3)]);
    // Receive: the reposted descriptor is notified only when asked for.
    dev.set_no_notify(0, true);
    let n = dev.notifies(0);
    assert!(dev.receive(&frame(60, 4)));
    assert!(w.signal());
    assert_eq!(dev.notifies(0), n);
    dev.set_no_notify(0, false);
    assert!(dev.receive(&frame(60, 5)));
    assert!(w.signal());
    assert_eq!(dev.notifies(0), n + 1);
    assert_eq!(w.net_take(), [frame(60, 4), frame(60, 5)]);
    dev.fetch(0);
    assert_eq!(dev.held(0).len(), 64);
}

#[test]
fn receive_buffers_run_out_only_while_net_holds_them() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    assert_eq!(w.queues.owned(Pool::Rx).count(), 128);
    // net takes nothing: 128 frames fill RX_FILLED, the rest are dropped,
    // and the device's buffers still come back.
    let frames: Vec<_> = (0..200).map(|i| frame(60, i)).collect();
    for chunk in frames.chunks(50) {
        for f in chunk {
            assert!(dev.receive(f));
        }
        assert!(w.signal());
    }
    let c = w.driver.counters();
    assert_eq!((c.received, c.dropped), (128, 72));
    assert_eq!(w.queues.owned(Pool::Rx), Owned::NONE);
    assert_eq!(w.queues.counters().dropped, 72);
    assert_eq!(dev.no_buffer(), 0);
    // net takes the first 128, in order, and hands every buffer back.
    assert_eq!(w.net_take(), frames[..128]);
    w.settle();
    assert_eq!(w.queues.owned(Pool::Rx).count(), 128);
    assert_eq!(w.net.owned(Pool::Rx), Owned::NONE);
    // Transmit buffers go back as soon as their frames are copied, and a
    // frame with no descriptor stays in TX_FILLED: the driver keeps none.
    let tx: Vec<_> = (0..130).map(|i| frame(60, 1000 + i)).collect();
    assert_eq!(w.net_send(&tx), 128, "net has 128 transmit buffers");
    assert!(w.signal());
    assert_eq!(w.queues.owned(Pool::Tx), Owned::NONE);
    assert_eq!(w.net.reclaim(), 64);
    let mut out = Vec::new();
    while out.len() < 128 {
        out.extend(dev.transmit());
        w.settle();
        assert_eq!(w.queues.owned(Pool::Tx), Owned::NONE);
    }
    assert_eq!(out, tx[..128]);
    assert_eq!(w.net.reclaim(), 64);
    assert_eq!(w.net.owned(Pool::Tx), Owned::ALL);
}

#[test]
fn bad_queue_entries_are_counted_in_the_stats() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    // A broken net: a TX_FILLED entry naming buffer 200.
    let q = &mem.queues;
    let head = q.load32(Queue::TxFilled.head(), Relaxed);
    let e = Entry {
        index: 200,
        len: 60,
    };
    q.store32(Queue::TxFilled.entry(head), e.word(), Relaxed);
    q.store32(Queue::TxFilled.head(), head + 1, Release);
    w.frames = true;
    assert!(w.signal());
    assert_eq!(w.driver.counters().sent, 0);
    assert_eq!(w.driver.stats(&w.queues).bad_entries, 1);
    assert!(dev.transmit().is_empty());
}

#[test]
fn the_stats_text() {
    let mem = Mem::new();
    let dev = qemu(&mem);
    let mut w = World::up(&dev, &mem);
    assert!(dev.receive(&frame(60, 1)));
    assert!(dev.receive(&frame(61, 2)));
    assert!(w.signal());
    w.net_take();
    w.net_send(&[frame(62, 3)]);
    assert!(w.signal());
    dev.inject_used(0, 99, 0);
    assert!(w.signal());
    let s = w.driver.stats(&w.queues);
    assert_eq!(
        s.to_string(),
        "4 signals, 2 frames received, 0 dropped for no buffer, 1 bad used elements, 1 frames sent, 0 waits for a descriptor, 0 bad queue entries, features VERSION_1 MAC STATUS, MAC 52:54:00:12:34:56"
    );
    assert_eq!((s.features, s.mac()), (FEATURES, MAC));
    assert_eq!(VirtioNetStats::from_words(s.to_words()), s);
    assert_eq!(frames::BUFFERS, 128);
}
