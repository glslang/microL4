//! The server loop, on the user target: netvsc's thread, which the root
//! task starts in a VSpace and CSpace of its own with its channel frame
//! at [`layout::CHANNEL`](crate::layout::CHANNEL), the monitor window at
//! [`layout::MNF`](crate::layout::MNF) with `netvsc.mnf=1`, the frame
//! queues' original at `libsys::frames::WINDOW`, bound to notification
//! NH, which `vmbus` signals with `CHANNEL` and `net` with `FRAMES`.

use core::fmt::{Display, Write};

use libsys::console::{Buffered, Client};
use libsys::frames::Driver;
use libsys::hyperv;
use libsys::mem::Memory;
use libsys::proto::{MAX_BYTES, label};
use libsys::transfer::ReceivedCaps;
use libsys::{Event, Ipc, Message, MessageInfo, Received, Slot, call, recv, reply_recv, signal};

use crate::{Adapter, CHANNEL, FRAMES, Signal, Start, Status, attach_reply, request, slot};

/// The restricted Hypervisor capability in slot 7.
struct Host;

impl Signal for Host {
    fn signal_event(&mut self, connection: u32) -> Status {
        hyperv::signal_event(slot::HYPERVISOR, connection, 0)
            .unwrap_or_else(|e| panic!("netvsc: Hypervisor_SignalEvent: {e}"))
    }
}

/// One line through console.
fn say(console: &Client, line: impl Display) {
    let mut b = Buffered::new(MAX_BYTES, |p: &[u8]| console.write(p));
    let _ = writeln!(b, "{line}");
    b.finish()
        .unwrap_or_else(|e| panic!("netvsc: console Write: {e}"));
}

/// The answer to a message on NS.
fn answer<M: Memory, Q: Memory>(ipc: Ipc, m: Received, a: &Adapter<M, Q>) -> Message {
    let info = m.msg.info;
    match request(info.label(), info.length() as usize) {
        Ok(()) => ipc.compose(0, &a.stats().to_words(), &[]),
        Err(r) => Message::new(MessageInfo::new(r.label(), 0, 0, 0), [0; 4]),
    }
}

/// netvsc's thread: its slots are [`slot`]'s; `start` is root's arguments
/// ([`Start::from_words`]), `channel` and `mnf` the windows root mapped,
/// `queues` the frame queues' driver side. It never returns.
///
/// It blocks in its `Attach` call until vmbus has opened the channel,
/// then only in its receive on NS, in calls to console, which always
/// answer, and never on `net` or the host.
pub fn run<M: Memory>(start: Start, channel: M, mnf: Option<M>, queues: Driver<M>) -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let console = Client::new(slot::CONSOLE, Some(ipc));
    console
        .attach("netvsc")
        .unwrap_or_else(|e| panic!("netvsc: console Attach: {e}"));

    // Attach: vmbus answers once the channel is open, with the restricted
    // capability in slot 7.
    let own = Slot::new(
        slot::CNODE,
        slot::HYPERVISOR,
        slot::RADIX + slot::GUARD_BITS,
    );
    ipc.set_receive_slot(Some(own));
    let reply = call(
        slot::VMBUS,
        &Message::new(MessageInfo::new(label::VMBUS_ATTACH, 0, 0, 0), [0; 4]),
    );
    ipc.set_receive_slot(None);
    let info = reply.info;
    let words: [u64; 8] = core::array::from_fn(|i| {
        if i < info.length() as usize && i < 8 {
            ipc.received_word(&reply, i)
        } else {
            0
        }
    });
    let n = (info.length() as usize).min(8);
    let copied = ReceivedCaps::read(info, ipc).copied().is_some();
    let attach =
        attach_reply(info.label(), &words[..n], copied).unwrap_or_else(|e| panic!("netvsc: {e}"));

    let mut host = Host;
    let mut a = Adapter::new(start, attach, channel, mnf, queues).unwrap_or_else(|f| panic!("{f}"));
    a.start(&mut host).unwrap_or_else(|f| panic!("{f}"));
    let mut r = recv(slot::ENDPOINT);
    loop {
        r = match Event::classify(r, CHANNEL | FRAMES) {
            Event::Signal(bits) => {
                let wake = a
                    .on_signal(bits, &mut host)
                    .unwrap_or_else(|f| panic!("{f}"));
                if wake {
                    signal(slot::NET_NTFN);
                }
                while let Some(n) = a.note() {
                    say(&console, n);
                }
                recv(slot::ENDPOINT)
            }
            Event::Message(m) => reply_recv(slot::ENDPOINT, &answer(ipc, m, &a)),
        };
    }
}
