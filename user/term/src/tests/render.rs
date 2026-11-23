//! The renderer's pixel tests (`docs/design.md`, "The renderer" and "Code
//! and tests"): known cells rendered into an in-memory surface in both
//! pixel formats and compared pixel by pixel with hand-drawn cells, each
//! step of the look's table, the margins and the stride's padding, the
//! first frame, what a frame draws, and the proptest that the frames drawn
//! after random writes leave the same pixels as a full render.

use std::string::String;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use proptest::sample::select;

use crate::Terminal;
use crate::font::Glyph;
use crate::palette::{DEFAULT_BG, DEFAULT_FG};
use crate::render::{self, Renderer, Surface};

/// The framebuffer's two pixel formats, as `fb` converts colours to them.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Format {
    /// Byte 0 red.
    Rgb,
    /// Byte 0 blue: QEMU's and Hyper-V's.
    Bgr,
}

impl Format {
    pub fn pixel(self, rgb: u32) -> u32 {
        let (r, g, b) = (rgb >> 16 & 0xFF, rgb >> 8 & 0xFF, rgb & 0xFF);
        match self {
            Format::Rgb => r | g << 8 | b << 16,
            Format::Bgr => b | g << 8 | r << 16,
        }
    }

    pub fn colour(self, pixel: u32) -> u32 {
        // Byte 3 must be 0: the renderer never writes another value there.
        assert_eq!(pixel >> 24, 0, "pixel {pixel:#010X} was never written");
        let (b0, b1, b2) = (pixel & 0xFF, pixel >> 8 & 0xFF, pixel >> 16 & 0xFF);
        match self {
            Format::Rgb => b0 << 16 | b1 << 8 | b2,
            Format::Bgr => b2 << 16 | b1 << 8 | b0,
        }
    }
}

/// What a pixel holds before anything writes it: byte 3 set, which no
/// colour has.
pub const UNWRITTEN: u32 = 0xEE00_0000;

/// An in-memory surface laid out as the framebuffer is: `stride` pixels a
/// row, the first `width` of them visible; every write bounds-checked
/// against `width` and `height`, as `fb::Surface`'s are.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Canvas {
    pub width: usize,
    pub height: usize,
    pub stride: usize,
    pub format: Format,
    pub pixels: Vec<u32>,
    pub fences: usize,
    pub cells: usize,
}

impl Canvas {
    pub fn new(width: usize, height: usize, stride: usize, format: Format) -> Canvas {
        assert!(stride >= width);
        Canvas {
            width,
            height,
            stride,
            format,
            pixels: vec![UNWRITTEN; stride * height],
            fences: 0,
            cells: 0,
        }
    }

    /// A canvas exactly `cols` × `rows` cells, BGR.
    pub fn cells(cols: usize, rows: usize) -> Canvas {
        Canvas::new(8 * cols, 16 * rows, 8 * cols, Format::Bgr)
    }

    /// The colour at `x`, `y`, `0xRRGGBB`.
    pub fn rgb(&self, x: usize, y: usize) -> u32 {
        assert!(x < self.width && y < self.height);
        self.format.colour(self.pixels[y * self.stride + x])
    }

    /// The cell at `row`, `col` as 16 rows of 8 characters, each pixel's
    /// colour by `key` (`?` for another).
    pub fn picture(&self, row: usize, col: usize, key: &[(u32, char)]) -> Vec<String> {
        (0..16)
            .map(|y| {
                (0..8)
                    .map(|x| {
                        let c = self.rgb(8 * col + x, 16 * row + y);
                        key.iter().find(|k| k.0 == c).map_or('?', |k| k.1)
                    })
                    .collect()
            })
            .collect()
    }

    /// The first pixel where `self` and `other` differ, as `(x, y)`.
    pub fn first_difference(&self, other: &Canvas) -> Option<(usize, usize)> {
        assert_eq!((self.width, self.height), (other.width, other.height));
        (0..self.height)
            .flat_map(|y| (0..self.width).map(move |x| (x, y)))
            .find(|&(x, y)| self.rgb(x, y) != other.rgb(x, y))
    }
}

impl Surface for Canvas {
    fn fill(&mut self, colour: u32) {
        let px = self.format.pixel(colour);
        for row in self.pixels.chunks_mut(self.stride) {
            row[..self.width].fill(px);
        }
    }

    fn cell(&mut self, row: usize, col: usize, bits: &Glyph, fg: u32, bg: u32) {
        self.cells += 1;
        let (f, b) = (self.format.pixel(fg), self.format.pixel(bg));
        let (x0, y0) = (8 * col, 16 * row);
        for (dy, &r) in bits.iter().enumerate() {
            for dx in 0..8 {
                let (x, y) = (x0 + dx, y0 + dy);
                if x < self.width && y < self.height {
                    self.pixels[y * self.stride + x] = if r & (0x80 >> dx) != 0 { f } else { b };
                }
            }
        }
    }

    fn fence(&mut self) {
        self.fences += 1;
    }
}

/// `writes` applied to a fresh `cols` × `rows` terminal, then the whole
/// screen rendered on `canvas`.
fn full(cols: usize, rows: usize, writes: &[&[u8]], canvas: &mut Canvas) {
    let mut main = vec![0u64; cols * rows];
    let mut alt = vec![0u64; cols * rows];
    let mut t = Terminal::new(cols, rows, &mut main, &mut alt);
    for w in writes {
        t.write(w, |_| {});
    }
    render::full(t.screen(), canvas);
}

/// The renderer started on `canvas` over a fresh terminal, one frame drawn
/// at start and one after each of `writes`: the cells each frame drew.
fn frames(cols: usize, rows: usize, writes: &[&[u8]], canvas: &mut Canvas) -> Vec<usize> {
    let mut main = vec![0u64; cols * rows];
    let mut alt = vec![0u64; cols * rows];
    let mut words = vec![0u64; cols * rows];
    let mut t = Terminal::new(cols, rows, &mut main, &mut alt);
    let mut r = Renderer::new(canvas, cols, rows, &mut words);
    let mut drawn = vec![r.frame(t.screen(), canvas)];
    for w in writes {
        t.write(w, |_| {});
        drawn.push(r.frame(t.screen(), canvas));
    }
    drawn
}

/// One cell's picture after `bytes`, in the default colours.
fn one(bytes: &[u8]) -> Vec<String> {
    let mut c = Canvas::cells(2, 1);
    full(2, 1, &[bytes], &mut c);
    c.picture(0, 0, &[(DEFAULT_FG, '#'), (DEFAULT_BG, '.')])
}

/// Spleen's `A`, plain and bold.
const A_AND_BOLD: &str = "\
........ ........
........ ........
.#####.. .######.
##...##. ###..###
##...##. ###..###
##...##. ###..###
#######. ########
##...##. ###..###
##...##. ###..###
##...##. ###..###
##...##. ###..###
##...##. ###..###
........ ........
........ ........
........ ........
........ ........";

/// Picture `i` of a row of pictures one space apart.
fn nth(pictures: &str, i: usize) -> Vec<String> {
    pictures
        .lines()
        .map(|l| l.split(' ').nth(i).unwrap().into())
        .collect()
}

#[test]
fn a_cell_is_its_glyph_in_its_colours() {
    assert_eq!(one(b"\x1b[?25lA"), nth(A_AND_BOLD, 0));
    // DEC Special Graphics `q` is U+2500, row 7.
    let mut q = vec![String::from("........"); 16];
    q[7] = "########".into();
    assert_eq!(one(b"\x1b[?25l\x1b(0q"), q);
}

#[test]
fn bold_overstrikes_the_glyph_one_pixel_right() {
    assert_eq!(one(b"\x1b[?25l\x1b[1mA"), nth(A_AND_BOLD, 1));
}

#[test]
fn underline_is_row_14_and_strike_row_8_in_the_foreground() {
    let mut c = Canvas::cells(4, 1);
    full(4, 1, &[b"\x1b[?25l\x1b[31;4m \x1b[24;9m \x1b[4mA"], &mut c);
    let key = [(0xAA_0000, '#'), (DEFAULT_BG, '.')];
    let mut want = vec![String::from("........"); 16];
    want[14] = "########".into();
    assert_eq!(c.picture(0, 0, &key), want);
    let mut want = vec![String::from("........"); 16];
    want[8] = "########".into();
    assert_eq!(c.picture(0, 1, &key), want);
    let mut want = nth(A_AND_BOLD, 0);
    want[8] = "########".into();
    want[14] = "########".into();
    assert_eq!(c.picture(0, 2, &key), want);
}

#[test]
fn the_cursor_is_a_block_an_underline_or_a_bar() {
    let blank = vec![String::from("........"); 16];
    // A block swaps the cell's colours: a blank cell turns solid.
    assert_eq!(one(b""), vec![String::from("########"); 16]);
    let mut underline = blank.clone();
    underline[14] = "########".into();
    underline[15] = "########".into();
    assert_eq!(one(b"\x1b[4 q"), underline);
    assert_eq!(one(b"\x1b[6 q"), vec![String::from("##......"); 16]);
    assert_eq!(one(b"\x1b[?25l"), blank);
    // Over a glyph, and with the pending wrap in the last column.
    let mut c = Canvas::cells(3, 1);
    full(3, 1, &[b"abA"], &mut c);
    let inverse: Vec<String> = nth(A_AND_BOLD, 0)
        .iter()
        .map(|r| {
            r.chars()
                .map(|p| if p == '#' { '.' } else { '#' })
                .collect()
        })
        .collect();
    assert_eq!(
        c.picture(0, 2, &[(DEFAULT_FG, '#'), (DEFAULT_BG, '.')]),
        inverse
    );
}

#[test]
fn colours_follow_the_looks_steps() {
    // A lit pixel of `A` (column 1, row 2) and an unlit one (column 0, row
    // 0): the foreground and the background.
    let fg_bg = |bytes: &[u8]| {
        let mut c = Canvas::cells(2, 1);
        full(2, 1, &[b"\x1b[?25l", bytes], &mut c);
        (c.rgb(1, 2), c.rgb(0, 0))
    };
    assert_eq!(fg_bg(b"A"), (DEFAULT_FG, DEFAULT_BG));
    assert_eq!(fg_bg(b"\x1b[31;44mA"), (0xAA_0000, 0x00_00AA));
    assert_eq!(fg_bg(b"\x1b[31;44;7mA"), (0x00_00AA, 0xAA_0000));
    assert_eq!(fg_bg(b"\x1b[31;44;7m\x1b[?5hA"), (0xAA_0000, 0x00_00AA));
    assert_eq!(fg_bg(b"\x1b[?5hA"), (DEFAULT_BG, DEFAULT_FG));
    assert_eq!(fg_bg(b"\x1b[2;31;44mA"), (0x55_0055, 0x00_00AA));
    assert_eq!(fg_bg(b"\x1b[38;5;196;48;5;21mA"), (0xFF_0000, 0x00_00FF));
    // Concealed: the space, and no line.
    let mut c = Canvas::cells(2, 1);
    full(2, 1, &[b"\x1b[?25l\x1b[8;4;9;44mA"], &mut c);
    let blue = vec![String::from("........"); 16];
    assert_eq!(c.picture(0, 0, &[(0x00_00AA, '.')]), blue);
}

#[test]
fn both_pixel_formats_get_the_surfaces_bytes() {
    for (format, red, blue) in [
        (Format::Rgb, 0x0000_00FF, 0x00FF_0000),
        (Format::Bgr, 0x00FF_0000, 0x0000_00FF),
    ] {
        let mut c = Canvas::new(16, 16, 16, format);
        full(
            2,
            1,
            &[b"\x1b[?25l\x1b[38;2;255;0;0;48;2;0;0;255mA"],
            &mut c,
        );
        assert_eq!(
            (c.pixels[2 * 16 + 1], c.pixels[0]),
            (red, blue),
            "{format:?}"
        );
        // The second cell is blank: the default background, black.
        assert_eq!(c.pixels[8], 0, "{format:?}");
        assert_eq!(c.rgb(1, 2), 0xFF_0000);
    }
}

#[test]
fn margins_stay_the_default_background_and_padding_is_never_written() {
    // 3 × 2 cells on 29 × 39 visible pixels, 32 a row.
    for bytes in [&b"\x1b[44m\x1b[2J"[..], b"\x1b[?5h"] {
        let mut c = Canvas::new(29, 39, 32, Format::Bgr);
        let mut d = c.clone();
        full(3, 2, &[bytes], &mut c);
        frames(3, 2, &[bytes], &mut d);
        assert_eq!(c.pixels, d.pixels);
        for y in 0..39 {
            for x in 0..32 {
                let px = c.pixels[y * 32 + x];
                if x >= 29 {
                    assert_eq!(px, UNWRITTEN, "padding at {x},{y}");
                } else if x >= 24 || y >= 32 {
                    assert_eq!(c.rgb(x, y), DEFAULT_BG, "margin at {x},{y}");
                } else if x >= 8 || y >= 16 {
                    // Every cell but the cursor's has the erase's blue or
                    // DECSCNM's grey.
                    assert_ne!(c.rgb(x, y), DEFAULT_BG, "cell at {x},{y}");
                }
            }
        }
    }
}

#[test]
fn the_first_frame_fills_the_screen_and_draws_the_cursor_at_home() {
    let mut c = Canvas::new(29, 39, 32, Format::Bgr);
    let mut words = vec![0u64; 6];
    let _ = Renderer::new(&mut c, 3, 2, &mut words);
    assert!((0..39).all(|y| (0..29).all(|x| c.rgb(x, y) == DEFAULT_BG)));
    assert_eq!((c.cells, c.fences), (0, 0));
    let mut c = Canvas::cells(3, 2);
    assert_eq!(frames(3, 2, &[], &mut c), [1]);
    assert_eq!(c.fences, 1);
    for (row, col) in [(0, 0), (0, 1), (1, 2)] {
        let want = if (row, col) == (0, 0) { '#' } else { '.' };
        assert_eq!(
            c.picture(row, col, &[(DEFAULT_FG, '#'), (DEFAULT_BG, '.')]),
            vec![String::from(want).repeat(8); 16]
        );
    }
}

#[test]
fn a_frame_draws_exactly_the_cells_whose_look_changed() {
    let mut c = Canvas::cells(4, 2);
    let drawn = frames(
        4,
        2,
        &[
            // Two prints and the cursor: three cells.
            b"ab",
            // Nothing.
            b"",
            // The cursor back home: the cell it left and the one it reached.
            b"\x1b[H",
            // The cursor already home, and a print over the same `a` with
            // the cursor moving on.
            b"\x1b[1;1H",
            b"a",
            // Every cell erased in blue, the cursor moved; then hidden.
            b"\x1b[44m\x1b[2J\x1b[1;3H\x1b[0m",
            b"\x1b[?25l",
        ],
        &mut c,
    );
    assert_eq!(drawn, [1, 3, 0, 2, 0, 2, 8, 1]);
    assert_eq!(c.fences, drawn.len());
    assert_eq!(c.cells, drawn.iter().sum::<usize>());
}

/// Sequences that change looks: attributes, colours, the cursor's form
/// and visibility, DECSCNM, the buffers, moves, erases, scrolls and
/// characters the font draws in each of its ways.
const SEQUENCES: &[&[u8]] = &[
    b"\x1b[1m",
    b"\x1b[2m",
    b"\x1b[4m",
    b"\x1b[7m",
    b"\x1b[8m",
    b"\x1b[9m",
    b"\x1b[0m",
    b"\x1b[31m",
    b"\x1b[44m",
    b"\x1b[38;5;208m",
    b"\x1b[48;2;10;200;30m",
    b"\x1b[39;49m",
    b"\x1b[?25l",
    b"\x1b[?25h",
    b"\x1b[2 q",
    b"\x1b[4 q",
    b"\x1b[6 q",
    b"\x1b[?5h",
    b"\x1b[?5l",
    b"\x1b[?1049h",
    b"\x1b[?1049l",
    b"\x1b[H",
    b"\x1b[2;3H",
    b"\x1b[J",
    b"\x1b[2K",
    b"\x1b[S",
    b"\x1b[T",
    b"\x1b[2@",
    b"\x1b[P",
    b"\x1b(0lqk\x1b(B",
    b"\x1b#8",
    b"\r\n",
    "─│┌╔╬╟▀▄█░▒▓⎺⎽◆£°±·\u{A0}é\u{FFFD}".as_bytes(),
];

fn token() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        6 => select(SEQUENCES).prop_map(<[u8]>::to_vec),
        4 => (0x20u8..=0x7E).prop_map(|b| vec![b]),
        1 => Just(b"\x1b[".to_vec()),
        1 => any::<u8>().prop_map(|b| vec![b]),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 3 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// The frames drawn after each of random writes leave exactly the
    /// pixels of a full render of the final screen, margins included.
    #[test]
    fn frames_after_random_writes_equal_a_full_render(
        cols in 1usize..=if cfg!(miri) { 3 } else { 12 },
        rows in 1usize..=if cfg!(miri) { 2 } else { 6 },
        margin in (0usize..8, 0usize..16),
        tokens in prop::collection::vec(token(), 0..if cfg!(miri) { 6 } else { 120 }),
        splits in prop::collection::vec(1usize..=24, 1..16),
    ) {
        let bytes = tokens.concat();
        let mut writes: Vec<&[u8]> = Vec::new();
        let (mut i, mut k) = (0, 0);
        while i < bytes.len() {
            let end = (i + splits[k % splits.len()]).min(bytes.len());
            writes.push(&bytes[i..end]);
            i = end;
            k += 1;
        }
        let (w, h) = (8 * cols + margin.0, 16 * rows + margin.1);
        let mut damage = Canvas::new(w, h, w + 3, Format::Bgr);
        let mut whole = damage.clone();
        let drawn = frames(cols, rows, &writes, &mut damage);
        full(cols, rows, &writes, &mut whole);
        prop_assert_eq!(damage.first_difference(&whole), None);
        prop_assert_eq!(damage.fences, writes.len() + 1);
        prop_assert!(drawn.iter().all(|&n| n <= cols * rows));
    }
}

/// The pixels the frames drawn after each of `writes` leave on a canvas
/// of `cols` × `rows` cells, compared with a full render: the cells, 1
/// from 1, of the pixels that differ. The goldens run this for each way.
pub fn damage_in_pixels(cols: usize, rows: usize, writes: &[Vec<u8>]) -> Vec<(usize, usize)> {
    let writes: Vec<&[u8]> = writes.iter().map(Vec::as_slice).collect();
    let mut damage = Canvas::cells(cols, rows);
    let mut whole = damage.clone();
    frames(cols, rows, &writes, &mut damage);
    full(cols, rows, &writes, &mut whole);
    let mut cells = Vec::new();
    for y in 0..whole.height {
        for x in 0..whole.width {
            let cell = (y / 16 + 1, x / 8 + 1);
            if damage.rgb(x, y) != whole.rgb(x, y) && !cells.contains(&cell) {
                cells.push(cell);
            }
        }
    }
    cells
}
