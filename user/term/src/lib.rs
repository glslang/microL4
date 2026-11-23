//! `term`: the terminal emulator (`docs/design.md`, "Framebuffer, terminal
//! and TUI").
//!
//! term parses its client's bytes as a VT100-family terminal does
//! ([`parser`], Paul Williams' DEC state machine adapted for UTF-8), keeps a
//! screen model of two buffers ([`screen`]), gives each cell's look and the
//! cells whose look changed ([`look`]) and draws them with an 8×16 bitmap
//! font ([`font`], Spleen's ASCII and generated box drawing) on a surface
//! ([`render`]). [`Terminal`] joins the parser and the screen. Everything
//! here is pure, uses nothing but `core` and is host-tested against golden
//! screens (`user/term/golden/`) and pixels.
//!
//! A server splits its state window with [`split_state`], makes a
//! [`Terminal`] over the first two grids and a [`Renderer`] over the third
//! (which fills the surface and records every cell as blank), and after
//! each `Write` ([`Terminal::write`]) draws a frame with
//! [`Renderer::frame`], which draws each cell whose [`Look`] changed
//! ([`Drawn::frame`]) and fences; [`palette`] gives the colours a look is
//! made of. [`Session`] does exactly that on an `fb::Surface`
//! ([`Pixels`]): [`Session::start`] is term's start-up, which host tests
//! call as the guest's term does.
//!
//! The term server (`docs/design.md`, "Input and the term protocol") is
//! [`server`], pure and host-tested: requests decoded and refused in M7's
//! order, the input queue of keys and replies, the saved `Read` and its
//! release. [`run`], its loop, exists only on the user target, where the
//! root task starts it in a VSpace and CSpace of its own with the
//! capabilities [`slot`] lists, its state window at [`layout::STATE`] and
//! the framebuffer at `fb::WINDOW`, bound to notification NT, which
//! console signals with `KEYS` when keys wait.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod font;
pub mod look;
pub mod palette;
pub mod parser;
pub mod render;
#[cfg(target_os = "none")]
mod run;
pub mod screen;
pub mod server;
pub mod session;
#[cfg(test)]
mod tests;

pub use look::{Drawn, Look};
pub use parser::Parser;
pub use render::{Renderer, Surface};
#[cfg(target_os = "none")]
pub use run::run;
pub use screen::{Cell, Screen};
pub use server::{Answer, Input, Request, Server, decode};
pub use session::{Pixels, Session, cells};

/// term's address space beyond root's image (`docs/design.md`, "Where it
/// runs").
pub mod layout {
    /// The state window: three grids of [`crate::GRID_WORDS`] words, the
    /// main screen, the alternate screen and what the renderer last drew,
    /// in fresh RAM frames mapped RW, NX, write-back. Below `fb::WINDOW`,
    /// in the first GiB, and 2 MiB-aligned, so one page table maps it.
    pub const STATE: u64 = 0x0800_0000;
    /// Its pages: 106, 434,176 bytes for 432,000.
    pub const STATE_PAGES: u64 = 106;
    /// Bytes in a page.
    pub const PAGE: u64 = 0x1000;

    const _: () = assert!(STATE_PAGES * PAGE >= 8 * crate::STATE_WORDS as u64);
    const _: () = assert!((STATE_PAGES - 1) * PAGE < 8 * crate::STATE_WORDS as u64);
    const _: () = assert!(STATE.is_multiple_of(1 << 21) && STATE_PAGES <= 512);
    const _: () = assert!(STATE + STATE_PAGES * PAGE <= fb::WINDOW);
}

/// term's CSpace: a 16-slot CNode with guard 0 of size 60, so `CPtr` `n`
/// is slot `n` (`docs/design.md`, "Capabilities" under "Framebuffer,
/// terminal and TUI").
pub mod slot {
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, with the same guard, for `CNode_SaveCaller`.
    pub const CNODE: u64 = 1;
    /// Endpoint T, term's requests, with Read.
    pub const ENDPOINT: u64 = 2;
    /// Endpoint C, with Write, GrantReply and badge 4: console's raw
    /// client.
    pub const CONSOLE: u64 = 3;
    /// Endpoint F, its fault endpoint, badge `TERM` (3).
    pub const FAULT: u64 = 4;
    /// Empty: its client's saved `Read`.
    pub const SAVED_READ: u64 = 5;
}

/// The widest screen: 1920 pixels of 8-pixel cells.
pub const MAX_COLS: usize = 240;
/// The tallest screen: 1200 pixels of 16-pixel cells.
pub const MAX_ROWS: usize = 75;
/// The words of one grid in the state window: the main screen, the
/// alternate screen and what the renderer last drew each take one.
pub const GRID_WORDS: usize = MAX_COLS * MAX_ROWS;
/// The state window's words: three grids, 432,000 bytes.
pub const STATE_WORDS: usize = 3 * GRID_WORDS;

/// The state window's three grids, in order: the main buffer, the
/// alternate buffer and what the renderer last drew. `state` holds at
/// least [`STATE_WORDS`].
pub fn split_state(state: &mut [u64]) -> (&mut [u64], &mut [u64], &mut [u64]) {
    let (main, rest) = state[..STATE_WORDS].split_at_mut(GRID_WORDS);
    let (alt, drawn) = rest.split_at_mut(GRID_WORDS);
    (main, alt, drawn)
}

/// The parser and the screen model.
pub struct Terminal<'a> {
    parser: Parser,
    screen: Screen<'a>,
}

impl<'a> Terminal<'a> {
    /// A terminal of `cols` × `rows` cells in its power-on state, its two
    /// buffers in `main` and `alt` ([`Screen::new`]).
    pub fn new(cols: usize, rows: usize, main: &'a mut [u64], alt: &'a mut [u64]) -> Terminal<'a> {
        Terminal {
            parser: Parser::new(),
            screen: Screen::new(cols, rows, main, alt),
        }
    }

    /// Applies `bytes`, one `Write`'s. `reply` gets the bytes term owes its
    /// client (DSR and DA answers), in order, as the sequences that ask for
    /// them are applied. The parser's state carries over to the next call.
    pub fn write(&mut self, bytes: &[u8], mut reply: impl FnMut(&[u8])) {
        let mut perform = screen::Perform {
            screen: &mut self.screen,
            reply: &mut reply,
        };
        self.parser.feed(&mut perform, bytes);
    }

    pub fn screen(&self) -> &Screen<'a> {
        &self.screen
    }

    pub fn parser(&self) -> &Parser {
        &self.parser
    }
}
