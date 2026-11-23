//! The term protocol's decisions (`docs/design.md`, "Input and the term
//! protocol"), pure and host-tested: requests decoded and refused in M7's
//! order, the input queue of keys and replies, the client's saved `Read`
//! and its release. `term::run` does the system calls around them.
//!
//! | Label | Request | Reply | Errors |
//! | --- | --- | --- | --- |
//! | `0x140` | `Write`: at most 952 bytes | MR0 `n`, once every byte is applied and the frame drawn | `BadLength` |
//! | `0x141` | `Read` | the input queue, all of it, at once if it holds anything; else saved in slot 5 and sent when bytes arrive | `Busy` |
//! | `0x142` | `Size` | MR0 columns, MR1 rows, MR2 width, MR3 height | |
//! | `0x143` | `Stats` | MR0 to MR6 ([`TermStats`]) | |
//!
//! `Write`, `Read` and `Size` need badge 1, term's one client; `Stats`
//! takes any badge. The checks run in M7's order: the label, the badge,
//! the length, then whether term can hold the request. The input queue
//! holds the keys `ReadRaw` brings from console and the replies DSR and DA
//! queue, in the order they came; a byte that finds it full is dropped and
//! counted. Whenever it holds anything and the client's `Read` is saved,
//! term answers that `Read` with everything queued ([`Server::release`]),
//! so a `Write` that queues a reply releases a `Read` another thread of the
//! client saved.

use libsys::proto::{self, MAX_BYTES, Refusal, TERM_CLIENT, TermSize, TermStats, label};

use crate::session::Session;

/// The input queue's bytes: 512, a `Read`'s most and console's raw
/// queue's size, so one `ReadRaw` always fits an empty queue.
pub const INPUT: usize = libsys::term::MAX_READ;

const _: () = assert!(INPUT == libsys::console::MAX_RAW && INPUT <= MAX_BYTES);

/// A request, decoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    /// Bytes for the parser.
    Write(&'a [u8]),
    Read,
    Size,
    Stats,
}

/// Decodes a request: its label, then its badge (`Write`, `Read` and
/// `Size` only from badge 1; `Stats` from any), then its length, a
/// `Write`'s byte string into `buf`. `word` reads MR0 and up. Requests
/// without words ignore any sent.
pub fn decode<'a>(
    label: u64,
    badge: u64,
    length: usize,
    word: impl FnMut(usize) -> u64,
    buf: &'a mut [u8; MAX_BYTES],
) -> Result<Request<'a>, Refusal> {
    let client_only = match label {
        label::TERM_WRITE | label::TERM_READ | label::TERM_SIZE => true,
        label::TERM_STATS => false,
        _ => return Err(Refusal::BadLabel),
    };
    if client_only && badge != TERM_CLIENT {
        return Err(Refusal::BadBadge);
    }
    Ok(match label {
        label::TERM_WRITE => {
            let n = proto::decode(length, word, MAX_BYTES, buf)?;
            Request::Write(&buf[..n])
        }
        label::TERM_READ => Request::Read,
        label::TERM_SIZE => Request::Size,
        _ => Request::Stats,
    })
}

/// The input queue: the keys and the replies, in the order they came, and
/// the counts `Stats` reports of them.
#[derive(Clone, Debug)]
pub struct Input {
    bytes: [u8; INPUT],
    len: usize,
    from_console: u64,
    dropped: u64,
    replies: u64,
}

impl Default for Input {
    fn default() -> Input {
        Input::new()
    }
}

impl Input {
    pub const fn new() -> Input {
        Input {
            bytes: [0; INPUT],
            len: 0,
            from_console: 0,
            dropped: 0,
            replies: 0,
        }
    }

    /// Bytes `ReadRaw` brought from console: every one counts as from
    /// console (`Stats` MR4); those past the queue's room are dropped and
    /// counted (MR5).
    pub fn keys(&mut self, bytes: &[u8]) {
        self.from_console += bytes.len() as u64;
        self.push(bytes);
    }

    /// A reply DSR or DA owes the client: the bytes queued count as reply
    /// bytes (MR6), those past the queue's room as dropped (MR5).
    pub fn reply(&mut self, bytes: &[u8]) {
        self.replies += self.push(bytes) as u64;
    }

    /// Queues what fits; returns how many bytes.
    fn push(&mut self, bytes: &[u8]) -> usize {
        let n = bytes.len().min(INPUT - self.len);
        self.bytes[self.len..self.len + n].copy_from_slice(&bytes[..n]);
        self.len += n;
        self.dropped += (bytes.len() - n) as u64;
        n
    }

    /// Everything queued, into `out`, emptying the queue; returns how many
    /// bytes.
    pub fn take(&mut self, out: &mut [u8; INPUT]) -> usize {
        let n = self.len;
        out[..n].copy_from_slice(&self.bytes[..n]);
        self.len = 0;
        n
    }

    /// What is queued.
    pub fn queued(&self) -> &[u8] {
        &self.bytes[..self.len]
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn from_console(&self) -> u64 {
        self.from_console
    }

    pub fn dropped(&self) -> u64 {
        self.dropped
    }

    pub fn replies(&self) -> u64 {
        self.replies
    }
}

/// The answer to a request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// Reply MR0 `n`: the `Write`'s bytes are applied and drawn.
    Written(usize),
    /// Reply with this many bytes of the caller's `out`: the whole queue.
    Read(usize),
    /// The caller's reply capability is saved in slot 5; it is answered
    /// later, by [`Server::release`].
    Saved,
    Size(TermSize),
    Stats(TermStats),
    Refused(Refusal),
}

/// term's state: its session, the input queue and whether the client's
/// `Read` waits in slot 5.
pub struct Server<'a> {
    session: Session<'a>,
    input: Input,
    saved: bool,
}

impl<'a> Server<'a> {
    /// A server over a session [`Session::start`] began.
    pub fn new(session: Session<'a>) -> Server<'a> {
        Server {
            session,
            input: Input::new(),
            saved: false,
        }
    }

    /// Runs one decoded request. A `Write` is applied and drawn, its
    /// replies queued. A `Read` takes the whole queue into `out` if it
    /// holds anything; otherwise `save` moves the caller's reply capability
    /// into slot 5 (`CNode_SaveCaller`) and says whether it could: if it
    /// could the `Read` waits there, and if not another `Read` already
    /// does, which is `Busy`. The slot, not a flag, decides `Busy`, as in
    /// console. Follow every request with [`release`](Self::release).
    pub fn request(
        &mut self,
        req: Request<'_>,
        save: impl FnOnce() -> bool,
        out: &mut [u8; INPUT],
    ) -> Answer {
        match req {
            Request::Write(bytes) => {
                let input = &mut self.input;
                self.session.write(bytes, |r| input.reply(r));
                Answer::Written(bytes.len())
            }
            Request::Read if !self.input.is_empty() => Answer::Read(self.input.take(out)),
            Request::Read if save() => {
                self.saved = true;
                Answer::Saved
            }
            Request::Read => Answer::Refused(Refusal::Busy),
            Request::Size => Answer::Size(self.size()),
            Request::Stats => Answer::Stats(self.stats()),
        }
    }

    /// Bytes one `ReadRaw` brought from console.
    pub fn keys(&mut self, bytes: &[u8]) {
        self.input.keys(bytes);
    }

    /// After every event: if the client's `Read` waits in slot 5 and the
    /// queue holds anything, takes it all into `out` for the `Send` on
    /// slot 5 that answers that `Read`, and returns how many bytes.
    pub fn release(&mut self, out: &mut [u8; INPUT]) -> Option<usize> {
        (self.saved && !self.input.is_empty()).then(|| {
            self.saved = false;
            self.input.take(out)
        })
    }

    /// `Size`: the grid in cells and the framebuffer in pixels.
    pub fn size(&self) -> TermSize {
        let (cols, rows) = self.session.size();
        let g = self.session.geometry();
        TermSize {
            cols: cols as u64,
            rows: rows as u64,
            width: g.width().into(),
            height: g.height().into(),
        }
    }

    /// `Stats`.
    pub fn stats(&self) -> TermStats {
        TermStats {
            written: self.session.written(),
            frames: self.session.frames(),
            cells: self.session.cells(),
            ignored: self.session.ignored(),
            from_console: self.input.from_console(),
            dropped: self.input.dropped(),
            replies: self.input.replies(),
        }
    }

    /// Whether the client's `Read` waits in slot 5, as far as term knows.
    pub fn saved(&self) -> bool {
        self.saved
    }

    pub fn input(&self) -> &Input {
        &self.input
    }

    pub fn session(&self) -> &Session<'a> {
        &self.session
    }
}
