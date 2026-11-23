//! What the renderer needs from the screen model (`docs/design.md`, "The
//! renderer"): each cell's look, and the damage, computed rather than
//! tracked, between the screen and what was last drawn. No pixel is written
//! here: the renderer turns a [`Look`] into pixels.
//!
//! A look is a glyph index, two 24-bit colours and five flags, so it packs
//! into one word and a frame compares one word per cell. Two cells with the
//! same look draw the same pixels, so a change that leaves a cell looking
//! the same draws nothing.

use crate::palette::{DEFAULT_BG, DEFAULT_FG};
use crate::screen::{Attrs, CursorStyle, Screen};

/// One cell as drawn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Look {
    /// The font's glyph index for the code point, or for a space if
    /// concealed; below [`Look::GLYPHS`].
    pub glyph: u16,
    /// `0xRRGGBB` after every step of the look: defaults resolved, inverse,
    /// DECSCNM, faint, a block cursor.
    pub fg: u32,
    pub bg: u32,
    /// [`Look::BOLD`], [`Look::UNDERLINE`], [`Look::STRIKE`],
    /// [`Look::CURSOR_UNDERLINE`] and [`Look::CURSOR_BAR`].
    pub flags: u8,
}

impl Look {
    /// Overstrike the glyph one pixel right.
    pub const BOLD: u8 = 1 << 0;
    /// Row 14 in the foreground.
    pub const UNDERLINE: u8 = 1 << 1;
    /// Row 8 in the foreground.
    pub const STRIKE: u8 = 1 << 2;
    /// The cursor as an underline: rows 14 and 15 in the foreground.
    pub const CURSOR_UNDERLINE: u8 = 1 << 3;
    /// The cursor as a bar: columns 0 and 1 in the foreground.
    pub const CURSOR_BAR: u8 = 1 << 4;
    /// Glyph indices a look can hold.
    pub const GLYPHS: u16 = 1 << 11;

    /// A blank cell with no cursor: what the renderer records for every
    /// cell once it has filled the screen with the default background.
    pub const fn blank(space: u16) -> Look {
        Look {
            glyph: space,
            fg: DEFAULT_FG,
            bg: DEFAULT_BG,
            flags: 0,
        }
    }

    /// The look as one word: the foreground in bits 0 to 23, the background
    /// in 24 to 47, the flags in 48 to 52 and the glyph in 53 to 63.
    pub const fn word(self) -> u64 {
        (self.fg & 0xFF_FFFF) as u64
            | ((self.bg & 0xFF_FFFF) as u64) << 24
            | ((self.flags & 0x1F) as u64) << 48
            | ((self.glyph % Look::GLYPHS) as u64) << 53
    }

    pub const fn from_word(w: u64) -> Look {
        Look {
            fg: (w & 0xFF_FFFF) as u32,
            bg: (w >> 24 & 0xFF_FFFF) as u32,
            flags: (w >> 48 & 0x1F) as u8,
            glyph: (w >> 53) as u16,
        }
    }
}

/// The channel-wise mean of two colours, rounded down.
const fn mean(a: u32, b: u32) -> u32 {
    let mut out = 0;
    let mut shift = 0;
    while shift < 24 {
        let x = (a >> shift & 0xFF) + (b >> shift & 0xFF);
        out |= (x / 2) << shift;
        shift += 8;
    }
    out
}

impl Screen<'_> {
    /// The look of the active buffer's cell at `row`, `col`, with `glyph`
    /// the font's index for a code point, by the renderer's table.
    pub fn look(&self, row: usize, col: usize, glyph: impl Fn(char) -> u16) -> Look {
        let cell = self.cell(row, col);
        let a = cell.pen.attrs;
        let mut fg = cell.pen.fg.rgb(DEFAULT_FG);
        let mut bg = cell.pen.bg.rgb(DEFAULT_BG);
        if a.contains(Attrs::INVERSE) {
            core::mem::swap(&mut fg, &mut bg);
        }
        if self.modes().reverse {
            core::mem::swap(&mut fg, &mut bg);
        }
        let mut flags = 0;
        let mut ch = cell.ch;
        if a.contains(Attrs::CONCEAL) {
            ch = ' ';
        } else {
            if a.contains(Attrs::UNDERLINE) {
                flags |= Look::UNDERLINE;
            }
            if a.contains(Attrs::STRIKE) {
                flags |= Look::STRIKE;
            }
        }
        if a.contains(Attrs::FAINT) {
            fg = mean(fg, bg);
        }
        if a.contains(Attrs::BOLD) {
            flags |= Look::BOLD;
        }
        let cursor = self.cursor();
        if cursor.visible && cursor.row == row && cursor.col == col {
            match cursor.style {
                CursorStyle::Block => core::mem::swap(&mut fg, &mut bg),
                CursorStyle::Underline => flags |= Look::CURSOR_UNDERLINE,
                CursorStyle::Bar => flags |= Look::CURSOR_BAR,
            }
        }
        Look {
            glyph: glyph(ch) % Look::GLYPHS,
            fg,
            bg,
            flags,
        }
    }
}

/// What the renderer last drew: one look word per cell, row by row, in the
/// state window's third grid.
pub struct Drawn<'a> {
    cols: usize,
    rows: usize,
    words: &'a mut [u64],
}

impl<'a> Drawn<'a> {
    /// Records every cell of a `cols` × `rows` screen as `blank`, as the
    /// renderer does once it has filled the visible area; `words` holds at
    /// least `cols × rows`.
    pub fn new(cols: usize, rows: usize, words: &'a mut [u64], blank: Look) -> Drawn<'a> {
        assert!(words.len() >= cols * rows);
        words[..cols * rows].fill(blank.word());
        Drawn { cols, rows, words }
    }

    /// What was last drawn at `row`, `col`.
    pub fn get(&self, row: usize, col: usize) -> Look {
        assert!(row < self.rows && col < self.cols);
        Look::from_word(self.words[row * self.cols + col])
    }

    /// One frame: for every cell of `screen`'s active buffer whose look
    /// differs from what was last drawn there, calls `draw` with its row,
    /// column and look, and records it. Returns the cells drawn (term's
    /// `Stats` MR2 counts them).
    pub fn frame(
        &mut self,
        screen: &Screen<'_>,
        glyph: impl Fn(char) -> u16,
        mut draw: impl FnMut(usize, usize, Look),
    ) -> usize {
        assert!(screen.cols() == self.cols && screen.rows() == self.rows);
        let mut drawn = 0;
        for row in 0..self.rows {
            for col in 0..self.cols {
                let look = screen.look(row, col, &glyph);
                let word = look.word();
                let at = row * self.cols + col;
                if self.words[at] != word {
                    draw(row, col, look);
                    self.words[at] = word;
                    drawn += 1;
                }
            }
        }
        drawn
    }
}
