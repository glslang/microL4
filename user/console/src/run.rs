//! The server loop, on the user target: console's thread, which the root
//! task starts in a VSpace and CSpace of its own, bound to notification
//! NC. From M8 it signals term's notification NT after each uart `Read`
//! that put bytes in the raw queue.

use libsys::invoke::{Slot, cnode_save_caller};
use libsys::proto::{self, MAX_BYTES, MAX_WORDS, RX_READY, Refusal};
use libsys::{Event, Ipc, Message, MessageInfo, Received, recv, reply_recv, send, signal};

use crate::terminal::{Chunks, EDIT, RAW_QUEUE, ReadAnswer, Terminal};
use crate::{Request, decode, slot};

/// console's thread: loops for ever, receiving on C. Its slots are
/// [`slot`]'s; it takes no arguments.
pub fn run() -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let uart = libsys::uart::Client::new(slot::UART, Some(ipc));
    let mut out = Chunks::new(|bytes: &[u8]| {
        uart.write(bytes)
            .unwrap_or_else(|e| panic!("console: uart Write: {e}"));
    });
    let mut term = Terminal::new();
    let mut buf = [0u8; MAX_BYTES];
    let mut line = [0u8; EDIT];
    let mut r = recv(slot::ENDPOINT);
    loop {
        match Event::classify(r, RX_READY) {
            Event::Signal(_) => {
                // One Read per signal: uart signals again for what comes
                // later.
                let n = uart
                    .read(&mut buf)
                    .unwrap_or_else(|e| panic!("console: uart Read: {e}"));
                for &b in &buf[..n] {
                    if let Some((c, len)) = term.input(b, &mut out, &mut line) {
                        out.flush();
                        send(
                            slot::saved_read(c as u64 + 1),
                            &line_reply(ipc, &line[..len]),
                        );
                    }
                }
                out.flush();
                // Once per Read, however many bytes it queued; NT keeps
                // the signal until term receives.
                if term.end_of_read() {
                    signal(slot::KEYS);
                }
                r = recv(slot::ENDPOINT);
            }
            Event::Message(m) => {
                let reply = handle(ipc, &mut term, &mut out, &uart, m, &mut buf, &mut line);
                // Every arm whose reply has words in the IPC buffer has
                // flushed already, so this flush, which writes that buffer
                // when it has bytes to send, finds nothing to send then.
                out.flush();
                r = match reply {
                    Some(msg) => reply_recv(slot::ENDPOINT, &msg),
                    None => recv(slot::ENDPOINT),
                };
            }
        }
    }
}

/// One request; `None` if its reply capability is saved for later.
fn handle<F: FnMut(&[u8])>(
    ipc: Ipc,
    term: &mut Terminal,
    out: &mut Chunks<F>,
    uart: &libsys::uart::Client,
    m: Received,
    buf: &mut [u8; MAX_BYTES],
    line: &mut [u8; EDIT],
) -> Option<Message> {
    let info = m.msg.info;
    let word = |i: usize| ipc.received_word(&m.msg, i);
    let (c, req) = match decode(info.label(), m.badge, info.length() as usize, word, buf) {
        Ok(x) => x,
        Err(r) => return Some(refusal(r)),
    };
    Some(match req {
        Request::Attach(name) => {
            term.attach(c, name);
            ipc.compose(0, &[c as u64 + 1], &[])
        }
        Request::Write(bytes) => {
            term.write(c, bytes, out);
            out.flush();
            ipc.compose(0, &[bytes.len() as u64], &[])
        }
        Request::Flush => {
            term.flush(c, out);
            Message::EMPTY
        }
        Request::Read => {
            let saved = Slot::new(slot::CNODE, slot::saved_read(c as u64 + 1), 64);
            match term.read(c, out, || cnode_save_caller(saved).is_ok(), line) {
                // `read` may have queued the client's unfinished output,
                // and flushing it calls `uart` through this same IPC
                // buffer: flush before the reply's words are written there,
                // as the saved-Read path does, not after.
                ReadAnswer::Line(n) => {
                    out.flush();
                    line_reply(ipc, &line[..n])
                }
                ReadAnswer::Saved => return None,
                ReadAnswer::Busy => refusal(Refusal::Busy),
            }
        }
        // At once, never saved: term blocks only in calls that answer.
        Request::ReadRaw => {
            let raw = buf
                .first_chunk_mut::<RAW_QUEUE>()
                .expect("a message holds the raw queue");
            let n = term.read_raw(raw);
            // Nothing to send: the reply's words may go in the buffer.
            out.flush();
            line_reply(ipc, &raw[..n])
        }
        Request::Sync => {
            term.flush(c, out);
            out.flush();
            uart.drain()
                .unwrap_or_else(|e| panic!("console: uart Drain: {e}"));
            Message::EMPTY
        }
    })
}

fn line_reply(ipc: Ipc, line: &[u8]) -> Message {
    let mut words = [0; MAX_WORDS];
    let length = proto::encode(line, &mut words);
    ipc.compose(0, &words[..length], &[])
}

fn refusal(r: Refusal) -> Message {
    Message::new(MessageInfo::new(r.label(), 0, 0, 0), [0; 4])
}
