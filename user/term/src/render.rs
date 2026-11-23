//! The renderer (`docs/design.md`, "The renderer"): each cell's [`Look`] to
//! pixels on a [`Surface`].
//!
//! After each `Write`, once every byte is applied, term draws a frame
//! ([`Renderer::frame`]): for each cell of the active buffer it computes the
//! look and compares it with what it last drew there ([`Drawn`], the state
//! window's third grid), draws exactly the cells whose look changed, and
//! ends with [`Surface::fence`], so that write-combining buffers have
//! drained before term replies. A look's pixels are its glyph's
//! ([`font::glyph`]), bold overstruck one pixel right, then the lines and
//! the cursor in the foreground ([`bits`]); the surface turns the two
//! colours into its pixel format.
//!
//! Nothing here reads a surface: the renderer keeps what it drew as looks.

use crate::font::{self, Glyph};
use crate::look::{Drawn, Look};
use crate::palette::DEFAULT_BG;
use crate::screen::Screen;

/// What the renderer draws on: on the target the framebuffer, through
/// `fb::Surface`, which bounds-checks every write against the visible area
/// and converts each colour to its pixel format; on the host a buffer.
/// Colours are `0xRRGGBB`, as a [`Look`] holds them.
pub trait Surface {
    /// Every visible pixel `colour`, margins included.
    fn fill(&mut self, colour: u32);

    /// The 8 × 16 cell in row `row` and column `col`, both from 0: each of
    /// `bits`' rows from the top, bit 7 the leftmost pixel, set bits `fg`
    /// and clear bits `bg`.
    fn cell(&mut self, row: usize, col: usize, bits: &Glyph, fg: u32, bg: u32);

    /// Called once at the end of every frame: drains the CPU's
    /// write-combining buffers (`sfence`, `libsys::cpu::store_fence`) on
    /// the target; nothing on the host.
    fn fence(&mut self);
}

/// The pixels of `look`, lit where the foreground goes: its glyph, ORed
/// with itself shifted one pixel right if bold; row 14 if underlined and
/// row 8 if struck; and the cursor's rows 14 and 15 as an underline or
/// columns 0 and 1 as a bar. A block cursor is already in the look's
/// colours.
pub fn bits(look: Look) -> Glyph {
    let mut g = *font::bitmap(look.glyph);
    if look.flags & Look::BOLD != 0 {
        for row in &mut g {
            *row |= *row >> 1;
        }
    }
    if look.flags & Look::UNDERLINE != 0 {
        g[14] = 0xFF;
    }
    if look.flags & Look::STRIKE != 0 {
        g[8] = 0xFF;
    }
    if look.flags & Look::CURSOR_UNDERLINE != 0 {
        g[14] = 0xFF;
        g[15] = 0xFF;
    }
    if look.flags & Look::CURSOR_BAR != 0 {
        for row in &mut g {
            *row |= 0xC0;
        }
    }
    g
}

/// Draws `look` in the cell at `row`, `col`.
pub fn draw(surface: &mut impl Surface, row: usize, col: usize, look: Look) {
    surface.cell(row, col, &bits(look), look.fg, look.bg);
}

/// What a blank cell with no cursor looks like: what [`Renderer::new`]
/// records for every cell once it has filled the surface.
pub const BLANK: Look = Look::blank(font::SPACE);

/// The renderer's state: what it last drew in each cell.
pub struct Renderer<'a> {
    drawn: Drawn<'a>,
}

impl<'a> Renderer<'a> {
    /// Starts drawing a `cols` × `rows` screen on `surface`: fills the whole
    /// visible area, margins included, with the default background and
    /// records every cell as [`BLANK`] in `words`, which holds at least
    /// `cols × rows` (the state window's third grid). The first
    /// [`frame`](Renderer::frame) then draws what differs from that, at
    /// least the cursor.
    pub fn new(
        surface: &mut impl Surface,
        cols: usize,
        rows: usize,
        words: &'a mut [u64],
    ) -> Renderer<'a> {
        surface.fill(DEFAULT_BG);
        Renderer {
            drawn: Drawn::new(cols, rows, words, BLANK),
        }
    }

    /// One frame, drawn after every `Write`: every cell of `screen`'s active
    /// buffer whose look differs from what was last drawn there, then
    /// [`Surface::fence`]. Returns the cells drawn (term's `Stats` MR2
    /// counts them). `screen` has the size the renderer was made for.
    pub fn frame(&mut self, screen: &Screen<'_>, surface: &mut impl Surface) -> usize {
        let n = self.drawn.frame(screen, font::glyph, |row, col, look| {
            draw(surface, row, col, look);
        });
        surface.fence();
        n
    }

    /// What was last drawn in each cell.
    pub fn drawn(&self) -> &Drawn<'a> {
        &self.drawn
    }
}

/// The whole screen, whatever was drawn before: the default background
/// over the visible area, every cell's look, then [`Surface::fence`]. What
/// the frames since [`Renderer::new`] have left on a surface equals this;
/// the host renders the screendump goldens with it.
pub fn full(screen: &Screen<'_>, surface: &mut impl Surface) {
    surface.fill(DEFAULT_BG);
    for row in 0..screen.rows() {
        for col in 0..screen.cols() {
            draw(surface, row, col, screen.look(row, col, font::glyph));
        }
    }
    surface.fence();
}
