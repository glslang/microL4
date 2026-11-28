//! `random_interleavings_lose_nothing`: the device, the driver's signals
//! and `net` in random order, against an oracle written here.
//!
//! Every frame the network sends that the device takes (it holds a
//! posted receive buffer) reaches `RX_FILLED` once and in order, unless
//! the driver has no queue buffer free when it drains the used ring: a
//! drain of `k` frames with `b` buffers free (128 less those in
//! `RX_FILLED`, since `net` hands each back as it takes it) delivers the
//! first `min(k, b)` and drops the rest, exactly. Every frame `net` pushes
//! on `TX_FILLED` reaches the network once and in order, and once the
//! interleaving ends, the device's completions, the interrupts they send
//! and the driver's signals alone drain everything: a completion the
//! driver needed but asked no interrupt for would leave a frame behind.

use std::vec::Vec;

use proptest::prelude::*;

use libsys::frames::Pool;

use super::device::{Config, Device};
use super::{BASE, Mem, World, frame};

#[derive(Clone, Debug)]
enum Op {
    /// The network sends `n` frames of `len` bytes; the device writes
    /// each into held receive buffer `pick`.
    Wire { n: usize, len: usize, pick: usize },
    /// The device takes the transmit buffers made available and sends
    /// their frames.
    Fetch,
    /// The device uses held transmit buffer `pick`, `n` times.
    Complete { n: usize, pick: usize },
    /// `net` sends `n` frames of `len` bytes.
    Send { n: usize, len: usize },
    /// `net` takes what `RX_FILLED` holds.
    Take,
    /// The driver runs if its notification holds a signal.
    Signal,
    /// The device starts or stops polling queue `q` (`NO_NOTIFY`).
    Poll { q: u16, on: bool },
}

fn len() -> impl Strategy<Value = usize> {
    prop_oneof![8 => 14usize..=120, 1 => Just(1514), 1 => 1400usize..=1514]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        4 => (1usize..=24, len(), any::<usize>()).prop_map(|(n, len, pick)| Op::Wire { n, len, pick }),
        3 => Just(Op::Fetch),
        3 => (1usize..=24, any::<usize>()).prop_map(|(n, pick)| Op::Complete { n, pick }),
        4 => (1usize..=40, len()).prop_map(|(n, len)| Op::Send { n, len }),
        2 => Just(Op::Take),
        5 => Just(Op::Signal),
        1 => (0u16..2, any::<bool>()).prop_map(|(q, on)| Op::Poll { q, on }),
    ]
}

/// The oracle's view, beside the world.
#[derive(Default)]
struct Oracle {
    /// Frames the device took from the wire, in order.
    wire: Vec<Vec<u8>>,
    /// Of those, the driver has drained this many.
    drained: usize,
    /// The frames that should reach `RX_FILLED`, in order.
    delivered: Vec<Vec<u8>>,
    /// Of those, `net` has taken this many.
    taken: usize,
    dropped: u64,
    /// Frames `net` pushed on `TX_FILLED`, in order.
    pushed: Vec<Vec<u8>>,
    /// Frames the device sent, in order.
    sent: Vec<Vec<u8>>,
    seq: u32,
}

impl Oracle {
    fn next(&mut self) -> u32 {
        self.seq += 1;
        self.seq
    }

    /// Runs the driver if it has a signal, and checks what its drain
    /// delivered and dropped.
    fn signal(&mut self, w: &mut World<'_>, dev: &Device<'_>) {
        let pending = self.wire.len() - self.drained;
        let free = 128 - (self.delivered.len() - self.taken);
        if !w.signal() {
            assert_eq!(pending, 0, "used elements came with no interrupt");
            return;
        }
        let kept = pending.min(free);
        let batch = &self.wire[self.drained..self.drained + pending];
        self.delivered.extend_from_slice(&batch[..kept]);
        self.dropped += (pending - kept) as u64;
        self.drained += pending;
        let c = w.driver.counters();
        assert_eq!(c.received, self.delivered.len() as u64);
        assert_eq!(c.dropped, self.dropped);
        assert_eq!(
            w.driver.queues()[0].posted(),
            u64::MAX,
            "every receive descriptor back"
        );
        // And the device was told of each: it can take all 64.
        dev.fetch(0);
        assert_eq!(
            dev.held(0).len(),
            64,
            "a receive buffer the device was not told of"
        );
    }

    fn apply(&mut self, w: &mut World<'_>, dev: &Device<'_>, op: &Op) {
        match *op {
            Op::Wire { n, len, pick } => {
                for _ in 0..n {
                    let f = frame(len, self.next());
                    if dev.receive_at(&f, pick) {
                        self.wire.push(f);
                    }
                }
            }
            Op::Fetch => self.sent.extend(dev.fetch_tx()),
            Op::Complete { n, pick } => {
                for _ in 0..n {
                    dev.complete_tx(pick);
                }
            }
            Op::Send { n, len } => {
                for _ in 0..n {
                    let f = frame(len, self.next());
                    if w.net.send(&f).is_ok() {
                        self.pushed.push(f);
                    }
                }
                w.frames |= w.net.end_batch();
            }
            Op::Take => {
                let got = w.net_take();
                let want = &self.delivered[self.taken..];
                assert_eq!(got, want, "RX_FILLED from frame {}", self.taken);
                self.taken += got.len();
            }
            Op::Signal => self.signal(w, dev),
            Op::Poll { q, on } => dev.set_no_notify(q, on),
        }
        assert!(
            self.pushed.starts_with(&self.sent),
            "the network got a frame net did not push, or out of order"
        );
        for pool in Pool::ALL {
            let (d, n) = (w.queues.owned(pool).0, w.net.owned(pool).0);
            assert_eq!(d & n, 0, "a {pool:?} buffer with two owners");
        }
        assert_eq!(w.driver.counters().bad_used, 0);
        assert_eq!(w.queues.counters().bad, 0);
        assert_eq!(w.net.counters().bad, 0);
    }

    /// The device's completions and the interrupts they send drain the
    /// transmit side; `net` takes the rest of what was received.
    fn drain(&mut self, w: &mut World<'_>, dev: &Device<'_>) {
        for _ in 0..200 {
            self.sent.extend(dev.fetch_tx());
            while dev.complete_tx(0) {}
            self.signal(w, dev);
            self.apply(w, dev, &Op::Take);
            self.signal(w, dev);
            if self.sent.len() == self.pushed.len() && dev.held(1).is_empty() && !w.driver.waiting()
            {
                break;
            }
        }
        assert_eq!(
            self.sent, self.pushed,
            "net's frames all reached the network"
        );
        assert!(!w.driver.waiting());
        assert_eq!(self.drained, self.wire.len());
        assert_eq!(self.taken, self.delivered.len());
        assert_eq!(
            w.queues.owned(Pool::Rx).count(),
            128,
            "every receive buffer back"
        );
        assert_eq!(w.queues.owned(Pool::Tx).count(), 0);
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 3 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_interleavings_lose_nothing(
        ops in prop::collection::vec(op(), 1..if cfg!(miri) { 24 } else { 160 })
    ) {
        let mem = Mem::new();
        let dev = Device::new(&mem.dma, BASE, Config::qemu());
        let mut w = World::up(&dev, &mem);
        let mut o = Oracle::default();
        for op in &ops {
            o.apply(&mut w, &dev, op);
        }
        o.drain(&mut w, &dev);
        let c = w.driver.counters();
        prop_assert_eq!(c.sent, o.pushed.len() as u64);
        prop_assert_eq!(c.received + c.dropped, o.wire.len() as u64);
    }
}
