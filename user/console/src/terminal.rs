//! The terminal: clients' output lines, the owner of the terminal's
//! current line, line editing and focus (`docs/design.md`, "Output" and
//! "Input" under "console"). Pure: every event writes what the terminal
//! must show to an [`Out`], and the run loop sends that to uart.

use libsys::proto::MAX_BYTES;

/// Clients, by badge 1 to 8; index `c` here is badge `c + 1`.
pub const CLIENTS: usize = 8;
/// A client's unfinished output line.
pub const LINE: usize = 512;
/// A client's edit buffer: the longest line a Read returns.
pub const EDIT: usize = 255;
/// A client's complete typed lines waiting for a Read, each with its
/// terminator.
pub const WAITING: usize = 512;
/// The longest name `Attach` takes.
pub const NAME: usize = 16;

const BEL: u8 = 0x07;
const BS: u8 = 0x08;
const LF: u8 = 0x0A;
const CR: u8 = 0x0D;
const CTRL_T: u8 = 0x14;
const CTRL_U: u8 = 0x15;
const ESC: u8 = 0x1B;
const DEL: u8 = 0x7F;
const RUBOUT: &[u8] = b"\x08 \x08";

/// Where bytes on the terminal come from. Only `Client` bytes are a
/// client's output, each exactly once; the rest is the terminal's own:
/// prompts shown (possibly again), echo, breaks and status lines.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Client(usize),
    Prompt(usize),
    Console,
}

/// The terminal's output.
pub trait Out {
    fn put(&mut self, from: Source, bytes: &[u8]);
}

/// What the terminal's current line holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Owner {
    /// The cursor is at the start of a line.
    None,
    /// The client's unfinished line, flushed or over-long, is the last
    /// thing on the terminal.
    Output(usize),
    /// The client's input line, its prompt and its edit buffer, is the
    /// last thing on the terminal.
    Input(usize),
}

/// The answer to a `Read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadAnswer {
    /// A typed line was waiting: this many bytes, in the caller's buffer.
    Line(usize),
    /// The reply capability is saved; a line typed later answers it.
    Saved,
    /// The client's saved-Read slot is full.
    Busy,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Esc {
    None,
    /// After ESC.
    Start,
    /// After ESC `[`: parameters until a final byte.
    Csi,
}

#[derive(Clone, Debug)]
struct Client {
    name: [u8; NAME],
    name_len: usize,
    attached: bool,
    held: [u8; LINE],
    held_len: usize,
    prompt: [u8; LINE],
    prompt_len: usize,
    edit: [u8; EDIT],
    edit_len: usize,
    waiting: [u8; WAITING],
    waiting_len: usize,
    /// A Read is saved in its slot.
    reading: bool,
}

impl Client {
    const fn new() -> Client {
        Client {
            name: [0; NAME],
            name_len: 0,
            attached: false,
            held: [0; LINE],
            held_len: 0,
            prompt: [0; LINE],
            prompt_len: 0,
            edit: [0; EDIT],
            edit_len: 0,
            waiting: [0; WAITING],
            waiting_len: 0,
            reading: false,
        }
    }
}

/// The terminal's state.
#[derive(Clone, Debug)]
pub struct Terminal {
    clients: [Client; CLIENTS],
    owner: Owner,
    focus: usize,
    after_cr: bool,
    ctrl_t: bool,
    esc: Esc,
}

impl Default for Terminal {
    fn default() -> Self {
        Self::new()
    }
}

impl Terminal {
    /// Focus on client 1, nothing held.
    pub const fn new() -> Terminal {
        const C: Client = Client::new();
        Terminal {
            clients: [C; CLIENTS],
            owner: Owner::None,
            focus: 0,
            after_cr: false,
            ctrl_t: false,
            esc: Esc::None,
        }
    }

    pub fn owner(&self) -> Owner {
        self.owner
    }

    /// The focused client's index.
    pub fn focus(&self) -> usize {
        self.focus
    }

    /// Whether client `c` has a Read saved.
    pub fn reading(&self, c: usize) -> bool {
        self.clients[c].reading
    }

    /// Bytes client `c` wrote that console still holds.
    pub fn held(&self, c: usize) -> &[u8] {
        &self.clients[c].held[..self.clients[c].held_len]
    }

    /// Client `c`'s edit buffer.
    pub fn edit(&self, c: usize) -> &[u8] {
        &self.clients[c].edit[..self.clients[c].edit_len]
    }

    /// `Attach`: client `c`'s name in status lines; at most [`NAME`]
    /// bytes, which the decoder checked.
    pub fn attach(&mut self, c: usize, name: &[u8]) {
        let cl = &mut self.clients[c];
        let n = name.len().min(NAME);
        cl.name[..n].copy_from_slice(&name[..n]);
        cl.name_len = n;
        cl.attached = true;
    }

    /// `\r\n`, unless the cursor is at a line's start or after `c`'s own
    /// unfinished line.
    fn brk(&mut self, c: usize, out: &mut impl Out) {
        if self.owner != Owner::None && self.owner != Owner::Output(c) {
            out.put(Source::Console, b"\r\n");
            self.owner = Owner::None;
        }
    }

    /// `f`'s input line: `\r\n` unless at a line's start, then its prompt
    /// and edit buffer.
    fn show(&mut self, f: usize, out: &mut impl Out) {
        if self.owner != Owner::None {
            out.put(Source::Console, b"\r\n");
        }
        let cl = &self.clients[f];
        out.put(Source::Prompt(f), &cl.prompt[..cl.prompt_len]);
        out.put(Source::Console, &cl.edit[..cl.edit_len]);
        self.owner = Owner::Input(f);
    }

    /// The focused client's input line again, if the cursor is at a line's
    /// start and it has one: a Read saved, or typed bytes.
    fn restore(&mut self, out: &mut impl Out) {
        let f = self.focus;
        let cl = &self.clients[f];
        if self.owner == Owner::None && (cl.reading || cl.edit_len > 0) {
            self.show(f, out);
        }
    }

    /// Client `c`'s held bytes go to the terminal as they are, after a
    /// break.
    fn emit_held(&mut self, c: usize, out: &mut impl Out) {
        self.brk(c, out);
        let cl = &mut self.clients[c];
        out.put(Source::Client(c), &cl.held[..cl.held_len]);
        cl.held_len = 0;
        self.owner = Owner::Output(c);
    }

    /// `Write` by client `c`: each completed line goes out after a break
    /// with `\n` as `\r\n`; 512 held bytes with no `\n` go out as they are;
    /// then the focused client's input line is restored.
    pub fn write(&mut self, c: usize, bytes: &[u8], out: &mut impl Out) {
        for &b in bytes {
            if b == LF {
                self.brk(c, out);
                let cl = &mut self.clients[c];
                out.put(Source::Client(c), &cl.held[..cl.held_len]);
                out.put(Source::Client(c), b"\r\n");
                cl.held_len = 0;
                self.owner = Owner::None;
            } else {
                let cl = &mut self.clients[c];
                cl.held[cl.held_len] = b;
                cl.held_len += 1;
                if cl.held_len == LINE {
                    self.emit_held(c, out);
                }
            }
        }
        self.restore(out);
    }

    /// `Flush` by client `c`: its held bytes go out now, after a break.
    pub fn flush(&mut self, c: usize, out: &mut impl Out) {
        if self.clients[c].held_len > 0 {
            self.emit_held(c, out);
        }
    }

    /// `Read` by client `c`. With a typed line waiting: a flush, and the
    /// line, into `line`. Otherwise `save` moves the reply capability to
    /// the client's slot (`Busy` if it cannot), the held bytes become the
    /// prompt, and the input line shows if `c` has focus.
    pub fn read(
        &mut self,
        c: usize,
        out: &mut impl Out,
        save: impl FnOnce() -> bool,
        line: &mut [u8; EDIT],
    ) -> ReadAnswer {
        if self.clients[c].waiting_len > 0 {
            self.flush(c, out);
            let cl = &mut self.clients[c];
            let end = cl.waiting[..cl.waiting_len]
                .iter()
                .position(|&b| b == LF)
                .expect("waiting lines end with LF");
            line[..end].copy_from_slice(&cl.waiting[..end]);
            cl.waiting.copy_within(end + 1..cl.waiting_len, 0);
            cl.waiting_len -= end + 1;
            return ReadAnswer::Line(end);
        }
        if !save() {
            return ReadAnswer::Busy;
        }
        let cl = &mut self.clients[c];
        cl.prompt[..cl.held_len].copy_from_slice(&cl.held[..cl.held_len]);
        cl.prompt_len = cl.held_len;
        cl.held_len = 0;
        cl.reading = true;
        if self.focus == c {
            self.show(c, out);
        }
        ReadAnswer::Saved
    }

    /// A byte typed on the terminal. Returns `(c, n)` when it ends a line
    /// for client `c`'s saved Read: the line is the `n` bytes in `line`.
    pub fn input(
        &mut self,
        b: u8,
        out: &mut impl Out,
        line: &mut [u8; EDIT],
    ) -> Option<(usize, usize)> {
        let after_cr = core::mem::replace(&mut self.after_cr, false);
        match self.esc {
            Esc::Start => {
                self.esc = if b == b'[' { Esc::Csi } else { Esc::None };
                return None;
            }
            Esc::Csi => {
                if (0x40..=0x7E).contains(&b) {
                    self.esc = Esc::None;
                }
                return None;
            }
            Esc::None => {}
        }
        if self.ctrl_t {
            self.ctrl_t = false;
            if (b'1'..=b'8').contains(&b) {
                self.focus_on(usize::from(b - b'1'), out);
            }
            return None;
        }
        let f = self.focus;
        match b {
            0x20..=0x7E => {
                self.typed(f, out);
                let cl = &mut self.clients[f];
                if cl.edit_len < EDIT {
                    cl.edit[cl.edit_len] = b;
                    cl.edit_len += 1;
                    out.put(Source::Console, &[b]);
                } else {
                    out.put(Source::Console, &[BEL]);
                }
                None
            }
            BS | DEL => {
                self.typed(f, out);
                let cl = &mut self.clients[f];
                if cl.edit_len > 0 {
                    cl.edit_len -= 1;
                    out.put(Source::Console, RUBOUT);
                }
                None
            }
            CTRL_U => {
                self.typed(f, out);
                let cl = &mut self.clients[f];
                for _ in 0..cl.edit_len {
                    out.put(Source::Console, RUBOUT);
                }
                cl.edit_len = 0;
                None
            }
            CR => {
                self.after_cr = true;
                self.enter(out, line)
            }
            LF if after_cr => None,
            LF => self.enter(out, line),
            CTRL_T => {
                self.ctrl_t = true;
                None
            }
            ESC => {
                self.esc = Esc::Start;
                None
            }
            _ => None,
        }
    }

    /// A byte for the focused client `f`: its input line shows first,
    /// unless it already is the last thing on the terminal.
    fn typed(&mut self, f: usize, out: &mut impl Out) {
        if self.owner != Owner::Input(f) {
            self.show(f, out);
        }
    }

    /// Enter: the edit buffer becomes a line, for the focused client's
    /// saved Read or its waiting lines; BEL and nothing else if they have
    /// no room.
    fn enter(&mut self, out: &mut impl Out, line: &mut [u8; EDIT]) -> Option<(usize, usize)> {
        let f = self.focus;
        self.typed(f, out);
        let cl = &mut self.clients[f];
        let n = cl.edit_len;
        if cl.reading {
            line[..n].copy_from_slice(&cl.edit[..n]);
            cl.edit_len = 0;
            cl.reading = false;
            cl.prompt_len = 0;
            out.put(Source::Console, b"\r\n");
            self.owner = Owner::None;
            return Some((f, n));
        }
        if cl.waiting_len + n < WAITING {
            cl.waiting[cl.waiting_len..cl.waiting_len + n].copy_from_slice(&cl.edit[..n]);
            cl.waiting[cl.waiting_len + n] = LF;
            cl.waiting_len += n + 1;
            cl.edit_len = 0;
            out.put(Source::Console, b"\r\n");
            self.owner = Owner::None;
        } else {
            out.put(Source::Console, &[BEL]);
        }
        None
    }

    /// Ctrl-T and a digit: focus on client `n`, with a status line.
    fn focus_on(&mut self, n: usize, out: &mut impl Out) {
        if self.owner != Owner::None {
            out.put(Source::Console, b"\r\n");
        }
        out.put(Source::Console, b"[console] focus ");
        out.put(Source::Console, &[b'1' + n as u8]);
        out.put(Source::Console, b" (");
        let cl = &self.clients[n];
        if cl.attached {
            out.put(Source::Console, &cl.name[..cl.name_len]);
        } else {
            out.put(Source::Console, b"client ");
            out.put(Source::Console, &[b'1' + n as u8]);
        }
        out.put(Source::Console, b")\r\n");
        self.owner = Owner::None;
        self.focus = n;
        self.restore(out);
    }
}

/// Output gathered into uart Writes of at most 952 bytes.
pub struct Chunks<F: FnMut(&[u8])> {
    buf: [u8; MAX_BYTES],
    len: usize,
    send: F,
}

impl<F: FnMut(&[u8])> Chunks<F> {
    pub fn new(send: F) -> Chunks<F> {
        Chunks {
            buf: [0; MAX_BYTES],
            len: 0,
            send,
        }
    }

    /// Sends what is gathered.
    pub fn flush(&mut self) {
        if self.len > 0 {
            (self.send)(&self.buf[..self.len]);
            self.len = 0;
        }
    }
}

impl<F: FnMut(&[u8])> Out for Chunks<F> {
    fn put(&mut self, _: Source, mut bytes: &[u8]) {
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
