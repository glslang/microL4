//! Host tests: the driver against a model virtio network device written
//! from the specification ([`device`]), with `net`'s side of the frame
//! queues played by `libsys::frames::Net` over the same memory.
//!
//! - [`setup`]: each setup step in order, every refusal, the arguments'
//!   words, the PCI capabilities and the request check.
//! - [`rings`]: frames both ways at every ring wrap, a full transmit ring,
//!   used rings filled out of order or with bad elements, interrupts,
//!   `NO_NOTIFY`, the frame queues' ownership and the stats text.
//! - [`props`]: random interleavings of the device, the driver's signals
//!   and `net`, which lose nothing.
//! - [`model`]: the model's own checks, each failing a driver that breaks
//!   its rule.
//! - [`slirp`]: the model network behind the device, libslirp's part
//!   (ARP and ping for `10.0.2.2`, datagrams to `10.0.2.15` port 7), and
//!   its tests through the driver: what the end-to-end test with `net`
//!   needs.
//! - [`e2e`]: the done-when on the host with `net` and the end-to-end
//!   tests' scripted peer, and its interleavings.

use std::vec::Vec;

use libsys::frames::{self, MAX_FRAME, Mac};
use libsys::mem::Ram;

use crate::{Driver, Region, Start, layout};

mod device;
mod e2e;
mod model;
mod props;
mod rings;
mod setup;
pub mod slirp;

use device::{Device, Port};

/// The DMA frame's physical base in the tests: above 4 GiB, so that every
/// ring address has a high half.
pub const BASE: u64 = 0x1_2340_0000;
/// The model's MAC.
pub const MAC: Mac = Mac([0x52, 0x54, 0x00, 0x12, 0x34, 0x56]);

/// The arguments root would pass for the model's 4 KiB regions, each at
/// the start of its page.
pub fn args() -> Start {
    let r = Region {
        offset: 0,
        len: 0x1000,
    };
    Start {
        dma: BASE,
        common: r,
        notify: r,
        device: r,
        multiplier: 4,
    }
}

/// The two memories: the DMA frame, the device's guest memory, only as
/// much as the layout uses, which keeps Miri fast; and the frame queues'.
pub struct Mem {
    pub dma: Ram,
    pub queues: Ram,
}

impl Mem {
    pub fn new() -> Mem {
        Mem {
            dma: Ram::new(layout::END),
            queues: Ram::new(frames::layout::END),
        }
    }
}

/// A frame of `len` bytes that names `seq`: an Ethernet header to the
/// model's MAC, then the sequence number and a pattern.
pub fn frame(len: usize, seq: u32) -> Vec<u8> {
    assert!((frames::MIN_FRAME..=MAX_FRAME).contains(&len));
    let mut f: Vec<u8> = (0..len)
        .map(|i| (i as u32).wrapping_mul(7).wrapping_add(seq) as u8)
        .collect();
    f[..6].copy_from_slice(&MAC.0);
    f[6..12].copy_from_slice(&[0x52, 0x55, 0x0a, 0x00, 0x02, 0x02]);
    let tail = (len - 12).min(4);
    f[12..12 + tail].copy_from_slice(&seq.to_le_bytes()[..tail]);
    f
}

/// The driver, the device and `net`'s side of the queues, with the
/// driver's notification as two bits: the device's pending MSI-X messages
/// (`IRQ`) and [`World::frames`] (`FRAMES`).
pub struct World<'a> {
    pub dev: &'a Device<'a>,
    pub driver: Driver<Port<'a>, &'a Ram>,
    pub queues: frames::Driver<&'a Ram>,
    pub net: frames::Net<&'a Ram>,
    /// `net` signalled the driver since it last ran.
    pub frames: bool,
    /// Times the driver signalled `net`.
    pub net_signals: u32,
}

impl<'a> World<'a> {
    /// The driver started on `dev`, then `net` attached at its signal, and
    /// the driver run at `net`'s: up, as on the target.
    pub fn up(dev: &'a Device<'a>, mem: &'a Mem) -> World<'a> {
        let mut queues = frames::Driver::new(&mem.queues);
        let driver = Driver::start(&args(), dev.regions(), &mem.dma, &mut queues)
            .unwrap_or_else(|e| panic!("refused: {e}"));
        let mut w = World {
            dev,
            driver,
            queues,
            net: frames::Net::new(&mem.queues),
            frames: false,
            net_signals: 0,
        };
        assert!(w.queues.end_batch(), "the driver's start pushed TX_FREE");
        w.net.attach().expect("the link block");
        w.frames = w.net.end_batch();
        assert!(w.frames, "net's attach pushed RX_FREE");
        assert!(w.signal());
        w
    }

    /// Runs the driver if its notification holds a signal; whether it
    /// did.
    pub fn signal(&mut self) -> bool {
        let irq = self.dev.take_interrupts() > 0;
        let frames = core::mem::take(&mut self.frames);
        if !irq && !frames {
            return false;
        }
        if self.driver.on_signal(&mut self.queues) {
            self.net_signals += 1;
        }
        true
    }

    /// Runs the driver until its notification stays empty.
    pub fn settle(&mut self) {
        for _ in 0..10_000 {
            if !self.signal() {
                return;
            }
        }
        panic!("the driver's signals never stop");
    }

    /// `net` takes every received frame, handing each buffer back, and
    /// signals the driver if it pushed.
    pub fn net_take(&mut self) -> Vec<Vec<u8>> {
        let mut out = Vec::new();
        let mut buf = [0; MAX_FRAME];
        while let Some(n) = self.net.take_rx(&mut buf) {
            out.push(buf[..n].to_vec());
        }
        self.frames |= self.net.end_batch();
        out
    }

    /// `net` sends `frames` and signals the driver; how many found a
    /// buffer.
    pub fn net_send(&mut self, frames: &[Vec<u8>]) -> usize {
        let n = frames.iter().filter(|f| self.net.send(f).is_ok()).count();
        self.frames |= self.net.end_batch();
        n
    }
}
