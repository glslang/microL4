//! The surface: the geometry and the pixel slice, written only
//! (`docs/design.md`, "The surface").

use crate::{CELL_HEIGHT, CELL_WIDTH, Geometry, Rgb};

/// A checked geometry over its pixels: on the target the framebuffer's
/// visible pixels in term's window, on the host a buffer. Every write is
/// bounds-checked against `width` and `height`, so none touches the
/// stride's padding or anything past the last row; there is no read
/// method.
#[derive(Debug)]
pub struct Surface<'a> {
    geometry: Geometry,
    pixels: &'a mut [u32],
}

impl<'a> Surface<'a> {
    /// `pixels` must hold at least `stride x height` pixels, the first at
    /// the framebuffer's first pixel; `None` otherwise.
    pub fn new(geometry: Geometry, pixels: &'a mut [u32]) -> Option<Surface<'a>> {
        (pixels.len() >= geometry.pixels()).then_some(Surface { geometry, pixels })
    }

    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    /// Every visible pixel `colour`.
    pub fn fill(&mut self, colour: Rgb) {
        let px = self.geometry.format().pixel(colour);
        let (width, stride) = (
            self.geometry.width() as usize,
            self.geometry.stride() as usize,
        );
        for row in self
            .pixels
            .chunks_mut(stride)
            .take(self.geometry.height() as usize)
        {
            row[..width].fill(px);
        }
    }

    /// The 8 x 16 cell at column `col` and row `row`, both from 0: each of
    /// `glyph`'s rows from the top, bit 7 the leftmost pixel, set bits
    /// `fg` and clear bits `bg`. A cell past the right or bottom edge is
    /// cut there; one wholly past it writes nothing.
    pub fn cell(&mut self, col: u32, row: u32, glyph: &[u8; 16], fg: Rgb, bg: Rgb) {
        let format = self.geometry.format();
        let (f, b) = (format.pixel(fg), format.pixel(bg));
        let (width, height) = (
            self.geometry.width() as usize,
            self.geometry.height() as usize,
        );
        let stride = self.geometry.stride() as usize;
        let x0 = col as usize * CELL_WIDTH as usize;
        let y0 = row as usize * CELL_HEIGHT as usize;
        if x0 >= width || y0 >= height {
            return;
        }
        let w = (CELL_WIDTH as usize).min(width - x0);
        let h = (CELL_HEIGHT as usize).min(height - y0);
        for (dy, &bits) in glyph[..h].iter().enumerate() {
            let start = (y0 + dy) * stride + x0;
            for (dx, px) in self.pixels[start..start + w].iter_mut().enumerate() {
                *px = if bits & (0x80 >> dx) != 0 { f } else { b };
            }
        }
    }
}
