//! Every frame-queue buffer has one owner (`docs/design.md`, "The frame
//! queues"): the check the end-to-end tests make between the threads'
//! turns. Shared by the tests of `net`, `virtio-net` and `netvsc`, which
//! include this file by path.

use core::sync::atomic::Ordering::Acquire;
use std::format;
use std::string::String;

use libsys::frames::{BUFFERS, Entry, Owned, Pool, Queue};
use libsys::mem::Memory;

/// Where a buffer is.
fn place(q: Queue) -> &'static str {
    match q {
        Queue::RxFilled => "RX_FILLED",
        Queue::RxFree => "RX_FREE",
        Queue::TxFilled => "TX_FILLED",
        Queue::TxFree => "TX_FREE",
    }
}

/// Asserts that each buffer of each pool is in exactly one place: held by
/// the driver (`driver`, its maps of `[Rx, Tx]`), held by `net` (`net`),
/// or named by one entry of one of its pool's two queues in `mem`, between
/// the queue's `tail` and `head`; and that no queue holds more than 128.
/// Called when no side is inside an operation, so that every `tail` and
/// `head` a side has passed is written.
#[track_caller]
pub fn owned_once(mem: &impl Memory, driver: [Owned; 2], net: [Owned; 2]) {
    for (p, pool) in Pool::ALL.into_iter().enumerate() {
        let mut seen: [Option<String>; BUFFERS] = core::array::from_fn(|_| None);
        let mut put = |i: usize, what: String| {
            assert!(i < BUFFERS, "{pool:?} buffer {i} named in {what}");
            if let Some(before) = &seen[i] {
                panic!("{pool:?} buffer {i} is both {before} and {what}");
            }
            seen[i] = Some(what);
        };
        for i in 0..BUFFERS as u16 {
            if driver[p].has(i) {
                put(i.into(), "the driver's".into());
            }
            if net[p].has(i) {
                put(i.into(), "net's".into());
            }
        }
        for q in [pool.filled(), pool.free()] {
            let head = mem.load32(q.head(), Acquire);
            let tail = mem.load32(q.tail(), Acquire);
            let n = head.wrapping_sub(tail);
            assert!(
                n <= BUFFERS as u32,
                "{} holds {n} entries (tail {tail}, head {head})",
                place(q)
            );
            for k in 0..n {
                let at = tail.wrapping_add(k);
                let e = Entry::from_word(mem.load32(q.entry(at), Acquire));
                assert!(
                    e.fits(q.is_filled()),
                    "{}'s entry {at} is bad: {e:?}",
                    place(q)
                );
                put(e.index.into(), format!("in {} (entry {at})", place(q)));
            }
        }
        if let Some(i) = seen.iter().position(Option::is_none) {
            panic!("{pool:?} buffer {i} has no owner and is in no queue");
        }
    }
}
