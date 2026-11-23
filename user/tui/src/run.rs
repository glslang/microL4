//! The loop, on the user target: tui's thread, which the root task starts
//! in a VSpace and CSpace of its own. It only calls: term, console and,
//! once it quits, root.

use core::fmt::Write;

use libsys::console::Buffered;
use libsys::proto::{self, MAX_BYTES, MAX_WORDS, label};
use libsys::{Ipc, call};

use crate::{App, Out, Step, slot};

/// A frame's bytes, gathered into term `Write`s of at most 952 bytes, each
/// drawn as term answers it.
struct ToTerm<'a> {
    term: &'a libsys::term::Client,
    buf: [u8; MAX_BYTES],
    len: usize,
}

impl ToTerm<'_> {
    /// Sends what is gathered; once it returns, term has drawn it all.
    fn flush(&mut self) {
        if self.len > 0 {
            self.term
                .write(&self.buf[..self.len])
                .unwrap_or_else(|e| panic!("tui: term Write: {e}"));
            self.len = 0;
        }
    }
}

impl Out for ToTerm<'_> {
    fn put(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() {
            let n = (MAX_BYTES - self.len).min(bytes.len());
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
            bytes = &bytes[n..];
            if self.len == MAX_BYTES {
                self.flush();
            }
        }
    }
}

/// One line through console.
fn say(console: &libsys::console::Client, line: impl core::fmt::Display) {
    let mut b = Buffered::new(MAX_BYTES, |p: &[u8]| console.write(p));
    let _ = writeln!(b, "{line}");
    b.finish()
        .unwrap_or_else(|e| panic!("tui: console Write: {e}"));
}

/// tui's thread: its slots are [`slot`]'s; it takes no arguments. It never
/// returns: after quitting it reports to root, which never answers.
pub fn run() -> ! {
    // The statics are a copy of the root task's, which name its slots.
    libsys::output::reset();
    let ipc = Ipc::root();
    let term = libsys::term::Client::new(slot::TERM, Some(ipc));
    let console = libsys::console::Client::new(slot::CONSOLE, Some(ipc));
    let size = term
        .size()
        .unwrap_or_else(|e| panic!("tui: term Size: {e}"));
    console
        .attach("tui")
        .unwrap_or_else(|e| panic!("tui: console Attach: {e}"));
    let mut app = App::new(size.cols, size.rows)
        .unwrap_or_else(|| panic!("tui: a {}x{} terminal", size.cols, size.rows));
    say(&console, app.size());
    let mut out = ToTerm {
        term: &term,
        buf: [0; MAX_BYTES],
        len: 0,
    };
    let first = app.start(&mut out);
    out.flush();
    say(&console, first);
    let mut buf = [0u8; libsys::term::MAX_READ];
    while !app.quit() {
        let n = term
            .read(&mut buf)
            .unwrap_or_else(|e| panic!("tui: term Read: {e}"));
        app.received(&buf[..n]);
        for &b in &buf[..n] {
            let Some(key) = app.decode(b) else { continue };
            match app.key(key, &mut out) {
                Some(Step::Drawn(d)) => {
                    out.flush();
                    say(&console, d);
                }
                Some(Step::Quit(q)) => {
                    out.flush();
                    say(&console, q);
                }
                None => {}
            }
        }
    }
    let mut words = [0; MAX_WORDS];
    let length = proto::encode(app.report(), &mut words);
    call(
        slot::REPORT,
        &ipc.compose(label::TUI_REPORT, &words[..length], &[]),
    );
    panic!("tui: root answered its report");
}
