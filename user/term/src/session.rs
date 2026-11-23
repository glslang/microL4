//! term's screen on the framebuffer (`docs/design.md`, "The renderer" and
//! "Input and the term protocol"): the parser, the screen model and the
//! renderer over an `fb::Surface`, started as the guest's term starts and
//! drawn after every `Write`.
//!
//! [`Session::start`] is term's whole start-up: it fills the visible area,
//! margins included, with the default background, records every cell as
//! blank, puts the model in RIS's power-on state and draws the first
//! frame, which shows the cursor at home. `term::run` starts its session
//! with it, so a host test that starts one on a host buffer and writes it
//! the bytes the guest's term was sent leaves the pixels the guest's term
//! left (the screendump goldens, `tui_screendumps_are_the_host_render`).

use fb::Rgb;

use crate::font::Glyph;
use crate::render::{Renderer, Surface};
use crate::screen::Screen;
use crate::{MAX_COLS, MAX_ROWS, Terminal, split_state};

/// term's grid on a framebuffer of `geometry`: its whole cells, `width /
/// 8` columns by `height / 16` rows, at most [`MAX_COLS`] × [`MAX_ROWS`].
/// 160 × 50 on QEMU's 1280 × 800, 128 × 48 on Hyper-V's 1024 × 768; `fb`
/// guarantees at least 80 × 24 on the target.
pub fn cells(geometry: fb::Geometry) -> (usize, usize) {
    let (cols, rows) = geometry.cells();
    ((cols as usize).min(MAX_COLS), (rows as usize).min(MAX_ROWS))
}

/// The renderer's [`Surface`] on the framebuffer: `fb::Surface`, which
/// bounds-checks every write against the visible area and converts each
/// colour to the pixel format, with the store fence
/// (`libsys::cpu::store_fence`, `sfence`) at the end of every frame. On the
/// host the fence costs nothing and the buffer is plain memory.
pub struct Pixels<'a>(pub fb::Surface<'a>);

impl Surface for Pixels<'_> {
    fn fill(&mut self, colour: u32) {
        self.0.fill(Rgb(colour));
    }

    fn cell(&mut self, row: usize, col: usize, bits: &Glyph, fg: u32, bg: u32) {
        // Both below 240 and 75: the grid is at most MAX_COLS x MAX_ROWS.
        self.0.cell(col as u32, row as u32, bits, Rgb(fg), Rgb(bg));
    }

    fn fence(&mut self) {
        libsys::cpu::store_fence();
    }
}

/// The terminal and its renderer over the framebuffer, with the counts
/// term's `Stats` reports of them.
pub struct Session<'a> {
    terminal: Terminal<'a>,
    renderer: Renderer<'a>,
    pixels: Pixels<'a>,
    cols: usize,
    rows: usize,
    written: u64,
    frames: u64,
    cells: u64,
}

impl<'a> Session<'a> {
    /// term's start-up, as the guest's term does it: the screen is
    /// [`cells`] of `surface`'s geometry; the whole visible area, margins
    /// included, is filled with the default background and every cell
    /// recorded as blank in the state window's third grid; the screen
    /// model starts in RIS's power-on state over its first two grids (the
    /// state window's words, zeroed or not, are not taken for blanks); and
    /// the first frame is drawn and fenced, showing the cursor, a block, at
    /// home. `state` holds at least [`crate::STATE_WORDS`] words. Panics
    /// if the surface holds no whole cell, which `fb::Geometry::from_words`
    /// rules out on the target.
    pub fn start(surface: fb::Surface<'a>, state: &'a mut [u64]) -> Session<'a> {
        let (cols, rows) = cells(surface.geometry());
        assert!(
            cols > 0 && rows > 0,
            "a {}x{} surface holds no 8x16 cell",
            surface.geometry().width(),
            surface.geometry().height()
        );
        let (main, alt, drawn) = split_state(state);
        let mut pixels = Pixels(surface);
        let renderer = Renderer::new(&mut pixels, cols, rows, drawn);
        let terminal = Terminal::new(cols, rows, main, alt);
        let mut s = Session {
            terminal,
            renderer,
            pixels,
            cols,
            rows,
            written: 0,
            frames: 0,
            cells: 0,
        };
        s.frame();
        s
    }

    /// One `Write`'s bytes: applies them all, then draws the frame (every
    /// cell whose look changed) and fences. `reply` gets the bytes DSR and
    /// DA owe the client, in order. Returns the cells drawn.
    pub fn write(&mut self, bytes: &[u8], reply: impl FnMut(&[u8])) -> usize {
        self.terminal.write(bytes, reply);
        self.written += bytes.len() as u64;
        self.frame()
    }

    fn frame(&mut self) -> usize {
        let n = self
            .renderer
            .frame(self.terminal.screen(), &mut self.pixels);
        self.frames += 1;
        self.cells += n as u64;
        n
    }

    /// The screen model.
    pub fn screen(&self) -> &Screen<'a> {
        self.terminal.screen()
    }

    pub fn terminal(&self) -> &Terminal<'a> {
        &self.terminal
    }

    /// The framebuffer's geometry.
    pub fn geometry(&self) -> fb::Geometry {
        self.pixels.0.geometry()
    }

    /// The grid: columns and rows.
    pub fn size(&self) -> (usize, usize) {
        (self.cols, self.rows)
    }

    /// Bytes written (`Stats` MR0).
    pub fn written(&self) -> u64 {
        self.written
    }

    /// Frames drawn, the first included (`Stats` MR1).
    pub fn frames(&self) -> u64 {
        self.frames
    }

    /// Cells drawn (`Stats` MR2).
    pub fn cells(&self) -> u64 {
        self.cells
    }

    /// Sequences the parser and the screen model ignored (`Stats` MR3).
    pub fn ignored(&self) -> u64 {
        self.terminal.screen().ignored()
    }
}
