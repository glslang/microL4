//! The server loop, on the user target: uart's thread, which the root task
//! starts in a VSpace and CSpace of its own, bound to notification NU.

use libsys::device::{ioport_in8, ioport_out8, irq_handler_ack};
use libsys::invoke::{Slot, cnode_save_caller};
use libsys::proto::{self, IRQ, MAX_BYTES, MAX_WORDS};
use libsys::{CPtr, Event, Ipc, Message, MessageInfo, Received, recv, reply_recv, send, signal};

use crate::{Answer, Irq, Outcome, Port, Release, Uart, decode, slot};

/// COM1's base port.
const COM1: u16 = 0x3F8;

/// The device through uart's IOPort capability, and IRQ 4's handler.
struct Device {
    port: CPtr,
    irq: CPtr,
}

impl Port for Device {
    fn read(&mut self, reg: u8) -> u8 {
        let port = COM1 + u16::from(reg);
        ioport_in8(self.port, port).unwrap_or_else(|e| panic!("uart: IOPort_In8 at {port:#x}: {e}"))
    }

    fn write(&mut self, reg: u8, value: u8) {
        let port = COM1 + u16::from(reg);
        ioport_out8(self.port, port, value)
            .unwrap_or_else(|e| panic!("uart: IOPort_Out8 at {port:#x}: {e}"))
    }
}

impl Irq for Device {
    fn ack(&mut self) {
        irq_handler_ack(self.irq).unwrap_or_else(|e| panic!("uart: IRQHandler_Ack: {e}"));
    }
}

/// uart's thread: programs COM1, then loops for ever, receiving on U.
/// Its slots are [`slot`]'s; it takes no arguments. It blocks only in its
/// receive: it sends only to reply capabilities and signals only NC.
pub fn run() -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let mut dev = Device {
        port: slot::IOPORT,
        irq: slot::IRQ,
    };
    let (mut uart, first) = Uart::start(&mut dev);
    act(ipc, first);
    let mut buf = [0u8; MAX_BYTES];
    let mut out = [0u8; MAX_BYTES];
    let mut r = recv(slot::ENDPOINT);
    loop {
        match Event::classify(r, IRQ) {
            Event::Signal(_) => {
                let o = uart.on_interrupt(&mut dev);
                act(ipc, o);
                r = recv(slot::ENDPOINT);
            }
            Event::Message(m) => {
                let answer = handle(ipc, &mut uart, &mut dev, m, &mut buf, &mut out);
                r = match answer {
                    Answer::Held => recv(slot::ENDPOINT),
                    a => reply_recv(slot::ENDPOINT, &reply(ipc, a, &out)),
                };
            }
        }
    }
}

fn handle(
    ipc: Ipc,
    uart: &mut Uart,
    dev: &mut Device,
    m: Received,
    buf: &mut [u8; MAX_BYTES],
    out: &mut [u8; MAX_BYTES],
) -> Answer {
    let info = m.msg.info;
    let length = info.length() as usize;
    let word = |i: usize| ipc.received_word(&m.msg, i);
    match decode(info.label(), m.badge, length, word, buf) {
        Ok(req) => uart.request(dev, req, out, || {
            cnode_save_caller(Slot::new(slot::CNODE, slot::HELD, 64)).is_ok()
        }),
        Err(refusal) => Answer::Refused(refusal),
    }
}

/// The reply to `answer`; a Read's bytes are in `out`.
fn reply(ipc: Ipc, answer: Answer, out: &[u8]) -> Message {
    match answer {
        Answer::Written(n) => ipc.compose(0, &[n as u64], &[]),
        Answer::Read(n) => {
            let mut words = [0; MAX_WORDS];
            let length = proto::encode(&out[..n], &mut words);
            ipc.compose(0, &words[..length], &[])
        }
        Answer::Drained | Answer::Held => Message::EMPTY,
        Answer::Stats(s) => ipc.compose(0, &s.to_words(), &[]),
        Answer::Refused(r) => Message::new(MessageInfo::new(r.label(), 0, 0, 0), [0; 4]),
    }
}

/// Signals console and answers a released request.
fn act(ipc: Ipc, o: Outcome) {
    if o.signal_console {
        signal(slot::CONSOLE_NTFN);
    }
    match o.release {
        Some(Release::Written(n)) => send(slot::HELD, &ipc.compose(0, &[n as u64], &[])),
        Some(Release::Drained) => send(slot::HELD, &Message::EMPTY),
        None => {}
    }
}
