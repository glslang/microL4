//! The loop, on the user target: net's thread, which the root task starts
//! in a VSpace and CSpace of its own, bound to notification NN, with the
//! frame queues' copy at `libsys::frames::WINDOW` (`docs/design.md`,
//! "`net::run`"). It blocks only in its receive on NE; it signals only its
//! driver and answers only root's `Stats`.
//!
//! The queues come in as a [`Queues`]: root's entry stub makes it over
//! `libsys::frames`' window, which net reaches only through it.

use core::fmt::{Display, Write};

use libsys::console::{Buffered, Client};
use libsys::notification::Event as Wake;
use libsys::proto::MAX_BYTES;
use libsys::{Ipc, Message, MessageInfo, Received, recv, reply_recv, signal};

use crate::link::{self, Queues, Up};
use crate::{Config, FRAMES, Stack, Stats, echo, slot};

/// One line through console.
fn say(console: &Client, line: impl Display) {
    let mut b = Buffered::new(MAX_BYTES, |p: &[u8]| console.write(p));
    let _ = writeln!(b, "{line}");
    b.finish()
        .unwrap_or_else(|e| panic!("net: console Write: {e}"));
}

/// The answer to a message on NE.
fn answer(ipc: Ipc, m: Received, stats: &Stats) -> Message {
    let info = m.msg.info;
    match link::request(info.label(), info.length() as usize) {
        Ok(()) => ipc.compose(0, &stats.to_words(), &[]),
        Err(r) => Message::new(MessageInfo::new(r.label(), 0, 0, 0), [0; 4]),
    }
}

/// Prints the stack's new lines, each once in a run.
fn report(console: &Client, stack: &mut Stack) {
    while let Some(e) = stack.event() {
        say(console, e);
    }
}

/// net's thread: its slots are [`slot`]'s; `config` is its arguments'
/// ([`Config::from_words`]). It never returns.
pub fn run<Q: Queues>(config: Config, mut queues: Q) -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let console = Client::new(slot::CONSOLE, Some(ipc));
    console
        .attach("net")
        .unwrap_or_else(|e| panic!("net: console Attach: {e}"));
    // Until the driver's first signal there is no stack: a Stats is all 0.
    let mut r = recv(slot::ENDPOINT);
    while let Wake::Message(m) = Wake::classify(r, FRAMES) {
        r = reply_recv(slot::ENDPOINT, &answer(ipc, m, &Stats::default()));
    }
    let mut stack = link::start(config, &mut queues).unwrap_or_else(|e| panic!("{e}"));
    if queues.take_pushed() {
        signal(slot::DRIVER);
    }
    say(&console, Up(config, stack.mac()));
    say(&console, echo::LISTENING);
    report(&console, &mut stack);
    r = recv(slot::ENDPOINT);
    loop {
        r = match Wake::classify(r, FRAMES) {
            Wake::Signal(_) => {
                if link::pump(&mut stack, &mut queues) {
                    signal(slot::DRIVER);
                }
                report(&console, &mut stack);
                recv(slot::ENDPOINT)
            }
            Wake::Message(m) => reply_recv(slot::ENDPOINT, &answer(ipc, m, stack.stats())),
        };
    }
}
