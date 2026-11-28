//! The server loop, on the user target: vmbus's thread, which the root
//! task starts in a VSpace and CSpace of its own with the SIM and SIEF
//! frames mapped at [`layout::SYNIC`](crate::layout::SYNIC), bound to
//! notification NB, which SINT 2's handler signals with `SINT`.

use core::fmt::Write;

use libsys::console::Buffered;
use libsys::hyperv;
use libsys::invoke::{Slot, cnode_delete, cnode_mint, cnode_revoke, cnode_save_caller};
use libsys::mem::Memory;
use libsys::proto::{MAX_BYTES, Refusal, SINT};
use libsys::{CPtr, Event, Ipc, Message, MessageInfo, Rights, recv, reply_recv, send, signal};

use crate::{Answer, Bus, Hypervisor, Note, Start, Status, System, decode, slot};

/// The unrestricted Hypervisor capability in slot 3.
struct Kernel {
    ipc: Ipc,
    cap: CPtr,
}

impl Hypervisor for Kernel {
    fn post_message(&mut self, connection: u32, message_type: u32, payload: &[u8]) -> Status {
        hyperv::post_message(self.ipc, self.cap, connection, message_type, payload)
            .unwrap_or_else(|e| panic!("vmbus: Hypervisor_PostMessage: {e}"))
    }

    fn signal_event(&mut self, connection: u32, flag: u16) -> Status {
        hyperv::signal_event(self.cap, connection, flag)
            .unwrap_or_else(|e| panic!("vmbus: Hypervisor_SignalEvent: {e}"))
    }

    fn eom(&mut self) {
        hyperv::eom(self.cap).unwrap_or_else(|e| panic!("vmbus: Hypervisor_Eom: {e}"));
    }

    fn vp_index(&mut self) -> u32 {
        hyperv::vp_index(self.cap).unwrap_or_else(|e| panic!("vmbus: Hypervisor_VpIndex: {e}"))
    }
}

/// console, netvsc's notification and vmbus's own CNode.
struct Os<'a> {
    ipc: Ipc,
    console: &'a libsys::console::Client,
}

fn own(index: u64) -> Slot {
    Slot::new(slot::CNODE, index, slot::RADIX + slot::GUARD_BITS)
}

impl System for Os<'_> {
    fn say(&mut self, note: &Note) {
        let mut b = Buffered::new(MAX_BYTES, |p: &[u8]| self.console.write(p));
        let _ = writeln!(b, "{note}");
        b.finish()
            .unwrap_or_else(|e| panic!("vmbus: console Write: {e}"));
    }

    fn signal_netvsc(&mut self) {
        signal(slot::NETVSC_NTFN);
    }

    fn mint(&mut self, data: u64) {
        cnode_mint(
            self.ipc,
            own(slot::MINTED),
            own(slot::HYPERVISOR),
            Rights::ALL,
            data,
        )
        .unwrap_or_else(|e| panic!("vmbus: CNode_Mint of netvsc's capability: {e}"));
    }

    fn revoke(&mut self) {
        cnode_revoke(own(slot::MINTED))
            .and_then(|()| cnode_delete(own(slot::MINTED)))
            .unwrap_or_else(|e| panic!("vmbus: revoking netvsc's capability: {e}"));
    }

    fn yield_now(&mut self) {
        libsys::yield_now();
    }
}

/// vmbus's thread: attaches to console as `vmbus`, starts the bus on the
/// SIM and SIEF windows root mapped, then loops for ever, receiving on
/// VB. Its slots are [`slot`]'s; `start` is root's arguments, checked by
/// [`Start::from_words`].
///
/// It blocks only in its receive, in calls to console, which always
/// answer, and in `Yield`; it answers its clients by `ReplyRecv`, or a
/// saved `Attach` by `Send` on slot 7, never waiting for them.
pub fn run<M: Memory>(start: Start, sim: M, sief: M) -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let console = libsys::console::Client::new(slot::CONSOLE, Some(ipc));
    console
        .attach("vmbus")
        .unwrap_or_else(|e| panic!("vmbus: console Attach: {e}"));
    let mut hv = Kernel {
        ipc,
        cap: slot::HYPERVISOR,
    };
    let mut os = Os {
        ipc,
        console: &console,
    };
    let mut bus = Bus::new(start, sim, sief);
    bus.start(&mut hv, &mut os);
    let saved = own(slot::SAVED);
    let mut r = recv(slot::ENDPOINT);
    loop {
        let answer = match Event::classify(r, SINT) {
            Event::Signal(_) => {
                bus.on_signal(&mut hv, &mut os);
                None
            }
            Event::Message(m) => Some(match decode(m.msg.info.label(), m.badge) {
                Ok(req) => bus.request(req, || cnode_save_caller(saved).is_ok()),
                Err(refused) => Answer::Refused(refused),
            }),
        };
        if let Some(a) = bus.release() {
            send(slot::SAVED, &message(ipc, a));
        }
        r = match answer {
            None | Some(Answer::Saved) => recv(slot::ENDPOINT),
            Some(a) => reply_recv(slot::ENDPOINT, &message(ipc, a)),
        };
    }
}

/// The reply an answer sends: `Attach`'s carries netvsc's capability.
fn message(ipc: Ipc, a: Answer) -> Message {
    match a {
        Answer::Attach(w) => ipc.compose(0, &w.to_words(), &[slot::MINTED]),
        Answer::Stats(s) => ipc.compose(0, &s.to_words(), &[]),
        Answer::Refused(r) => refusal(r),
        Answer::Saved => unreachable!("a saved Attach has no reply yet"),
    }
}

fn refusal(r: Refusal) -> Message {
    Message::new(MessageInfo::new(r.label(), 0, 0, 0), [0; 4])
}
