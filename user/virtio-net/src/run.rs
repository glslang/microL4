//! The loop, on the user target: virtio-net's thread, which the root task
//! starts in a VSpace and CSpace of its own, bound to notification NV,
//! with the DMA frame at `layout::DMA`, the three regions' pages at
//! `layout::REGIONS` and the frame queues' original at
//! `libsys::frames::WINDOW` (`docs/design.md`, "`virtio-net`", "The
//! loop"). It blocks only in its receive on VN and in its calls to
//! console; it signals only `net` and answers only root's `Stats`.
//!
//! The windows come in made: root's entry stub makes the `Mmio` and
//! `Shared` windows over what it mapped, and virtio-net reaches the device
//! and the queues only through them.

use core::fmt::{Display, Write};

use libsys::console::{Buffered, Client};
use libsys::frames;
use libsys::mem::{Memory, Regs};
use libsys::proto::{FRAMES, IRQ, MAX_BYTES, VirtioNetStats};
use libsys::{Event, Ipc, Message, MessageInfo, Received, recv, reply_recv, signal};

use crate::{Driver, Regions, Start, request, slot};

/// One line through console.
fn say(console: &Client, line: impl Display) {
    let mut b = Buffered::new(MAX_BYTES, |p: &[u8]| console.write(p));
    let _ = writeln!(b, "{line}");
    b.finish()
        .unwrap_or_else(|e| panic!("virtio-net: console Write: {e}"));
}

/// The answer to a message on VN.
fn answer(ipc: Ipc, m: Received, stats: VirtioNetStats) -> Message {
    let info = m.msg.info;
    match request(info.label(), info.length() as usize) {
        Ok(()) => ipc.compose(0, &stats.to_words(), &[]),
        Err(r) => Message::new(MessageInfo::new(r.label(), 0, 0, 0), [0; 4]),
    }
}

/// virtio-net's thread: its slots are [`slot`]'s, `start` its arguments
/// ([`Start::from_words`]), `regions` the three regions' windows, `dma`
/// the DMA frame's and `queues` the driver's side of the frame queues. It
/// sets up the device, prints its line, signals `net`, and never returns.
pub fn run<R: Regs, M: Memory, Q: Memory>(
    start: Start,
    regions: Regions<R>,
    dma: M,
    mut queues: frames::Driver<Q>,
) -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let console = Client::new(slot::CONSOLE, Some(ipc));
    console
        .attach("virtio-net")
        .unwrap_or_else(|e| panic!("virtio-net: console Attach: {e}"));
    let mut driver = Driver::start(&start, regions, dma, &mut queues)
        .unwrap_or_else(|e| panic!("virtio-net: {e}"));
    // The line first, then net's signal, so that it comes before net's.
    say(&console, driver.up());
    if queues.end_batch() {
        signal(slot::NET);
    }
    let mut r = recv(slot::ENDPOINT);
    loop {
        r = match Event::classify(r, IRQ | FRAMES) {
            Event::Signal(_) => {
                if driver.on_signal(&mut queues) {
                    signal(slot::NET);
                }
                recv(slot::ENDPOINT)
            }
            Event::Message(m) => reply_recv(slot::ENDPOINT, &answer(ipc, m, driver.stats(&queues))),
        };
    }
}
