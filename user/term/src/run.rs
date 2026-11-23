//! The server loop, on the user target: term's thread, which the root task
//! starts in a VSpace and CSpace of its own with its state window and the
//! framebuffer mapped, bound to notification NT, which console signals
//! with `KEYS` once per uart `Read` that put bytes in its raw queue.

use libsys::invoke::{Slot, cnode_save_caller};
use libsys::proto::{self, KEYS, MAX_BYTES, MAX_WORDS, Refusal};
use libsys::{Event, Ipc, Message, MessageInfo, recv, reply_recv, send};

use crate::server::{Answer, INPUT, Server, decode};
use crate::session::Session;
use crate::slot;

/// term's thread: starts its session on the framebuffer (`geometry`, its
/// visible pixels in `pixels` and its state window in `state`, as root
/// mapped them), attaches to console as `term`, then loops for ever,
/// receiving on T. Its slots are [`slot`]'s.
///
/// It blocks only in its receive and in calls to console, whose `Attach`
/// and `ReadRaw` always answer at once; it answers its client only by
/// `ReplyRecv` or by `Send` on slot 5, never waiting for it.
pub fn run(geometry: fb::Geometry, pixels: &'static mut [u32], state: &'static mut [u64]) -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let surface = fb::Surface::new(geometry, pixels)
        .unwrap_or_else(|| panic!("term: {} pixels for the framebuffer", geometry.pixels()));
    let mut server = Server::new(Session::start(surface, state));
    let console = libsys::console::Client::new(slot::CONSOLE, Some(ipc));
    console
        .attach("term")
        .unwrap_or_else(|e| panic!("term: console Attach: {e}"));
    let mut buf = [0u8; MAX_BYTES];
    let mut out = [0u8; INPUT];
    let mut released = [0u8; INPUT];
    let saved = Slot::new(slot::CNODE, slot::SAVED_READ, 64);
    let mut r = recv(slot::ENDPOINT);
    loop {
        let answer = match Event::classify(r, KEYS) {
            Event::Signal(_) => {
                // One ReadRaw per signal: console signals again for what
                // comes later, and NT keeps it until term receives.
                let raw = buf
                    .first_chunk_mut::<INPUT>()
                    .expect("a message holds the raw queue");
                let n = console
                    .read_raw(raw)
                    .unwrap_or_else(|e| panic!("term: console ReadRaw: {e}"));
                server.keys(&raw[..n]);
                None
            }
            Event::Message(m) => {
                let info = m.msg.info;
                let word = |i: usize| ipc.received_word(&m.msg, i);
                Some(
                    match decode(
                        info.label(),
                        m.badge,
                        info.length() as usize,
                        word,
                        &mut buf,
                    ) {
                        Ok(req) => {
                            server.request(req, || cnode_save_caller(saved).is_ok(), &mut out)
                        }
                        Err(refused) => Answer::Refused(refused),
                    },
                )
            }
        };
        // Before the reply's words go in the IPC buffer: the Send that
        // answers a saved Read writes its bytes there too.
        if let Some(n) = server.release(&mut released) {
            send(slot::SAVED_READ, &bytes(ipc, &released[..n]));
        }
        r = match answer {
            None | Some(Answer::Saved) => recv(slot::ENDPOINT),
            Some(a) => reply_recv(slot::ENDPOINT, &message(ipc, a, &out)),
        };
    }
}

/// A byte string reply.
fn bytes(ipc: Ipc, b: &[u8]) -> Message {
    let mut words = [0; MAX_WORDS];
    let length = proto::encode(b, &mut words);
    ipc.compose(0, &words[..length], &[])
}

/// The reply an answer sends; `out` holds a `Read`'s bytes.
fn message(ipc: Ipc, a: Answer, out: &[u8; INPUT]) -> Message {
    match a {
        Answer::Written(n) => ipc.compose(0, &[n as u64], &[]),
        Answer::Read(n) => bytes(ipc, &out[..n]),
        Answer::Size(s) => ipc.compose(0, &s.to_words(), &[]),
        Answer::Stats(s) => ipc.compose(0, &s.to_words(), &[]),
        Answer::Refused(r) => refusal(r),
        Answer::Saved => unreachable!("a saved Read has no reply yet"),
    }
}

fn refusal(r: Refusal) -> Message {
    Message::new(MessageInfo::new(r.label(), 0, 0, 0), [0; 4])
}
