//! `term`: the terminal emulator (`docs/design.md`, "Framebuffer, terminal
//! and TUI").
//!
//! term parses its client's bytes as a VT100-family terminal does
//! ([`parser`], Paul Williams' DEC state machine adapted for UTF-8), keeps a
//! screen model of two buffers ([`screen`]) and gives the renderer each
//! cell's look and the cells whose look changed ([`look`]). [`Terminal`]
//! joins the parser and the screen. Everything here is pure, uses nothing
//! but `core` and is host-tested against golden screens
//! (`user/term/golden/`).
//!
//! A server splits its state window with [`split_state`], makes a
//! [`Terminal`] over the first two grids and a [`Drawn`] over the third,
//! and after each `Write` ([`Terminal::write`]) draws a frame with
//! [`Drawn::frame`], which hands the renderer each cell whose [`Look`]
//! changed; [`palette`] gives the colours a look is made of.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod look;
pub mod palette;
pub mod parser;
pub mod screen;
#[cfg(test)]
mod tests;

pub use look::{Drawn, Look};
pub use parser::Parser;
pub use screen::{Cell, Screen};

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
