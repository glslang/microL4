//! The font (`docs/design.md`, "The font"): 8×16 pixels, one byte per row
//! from the top, bit 7 the leftmost pixel; 266 glyphs, 4,256 bytes of
//! read-only data.
//!
//! | Indices | Code points | Source |
//! | --- | --- | --- |
//! | 0 to 94 | U+0020 to U+007E, printable ASCII | Spleen 8×16 ([`spleen`]) |
//! | 95 to 99 | U+00A0, U+00A3, U+00B0, U+00B1, U+00B7 | Spleen 8×16 |
//! | 100 to 227 | U+2500 to U+257F, box drawing | generated |
//! | 228 to 259 | U+2580 to U+259F, block elements | generated |
//! | 260 to 263 | U+23BA to U+23BD, scan lines 1, 3, 7 and 9 | generated |
//! | 264 | U+25C6, black diamond | generated |
//! | 265 | every other code point: the replacement glyph | generated |
//!
//! The generated glyphs are computed by `const fn` from a description, so
//! the whole table is built at compile time ([`GLYPHS`]) and always joins
//! across cells: every line ends at the same column or row as its
//! neighbour's.

pub mod spleen;

use crate::look::Look;

/// A glyph: 16 rows from the top, bit 7 the leftmost pixel.
pub type Glyph = [u8; 16];

/// Pixels across a glyph.
pub const WIDTH: usize = 8;
/// Pixels down a glyph.
pub const HEIGHT: usize = 16;
/// The glyphs in the font.
pub const COUNT: usize = 266;

/// The space's index: what a blank cell draws.
pub const SPACE: u16 = 0;
/// The replacement glyph's index: an outline box over rows 2 to 13 and
/// columns 1 to 6, for every code point the font lacks.
pub const REPLACEMENT: u16 = 265;

/// The five ISO 8859-1 characters DEC Special Graphics uses beyond ASCII,
/// at indices 95 to 99.
const LATIN1: [char; 5] = ['\u{A0}', '\u{A3}', '\u{B0}', '\u{B1}', '\u{B7}'];
const ASCII_GLYPHS: u16 = 95;
const BOXES: u16 = 100;
const BLOCKS: u16 = 228;
const SCAN_LINES: u16 = 260;
const DIAMOND: u16 = 264;

const _: () = assert!(spleen::GLYPHS.len() == BOXES as usize);
const _: () = assert!(COUNT == REPLACEMENT as usize + 1);
const _: () = assert!(COUNT <= Look::GLYPHS as usize);

/// The glyph index for `c`: the map [`Screen::look`](crate::Screen::look)
/// takes.
pub const fn glyph(c: char) -> u16 {
    let u = c as u32;
    match u {
        0x20..=0x7E => (u - 0x20) as u16,
        0xA0 => ASCII_GLYPHS,
        0xA3 => ASCII_GLYPHS + 1,
        0xB0 => ASCII_GLYPHS + 2,
        0xB1 => ASCII_GLYPHS + 3,
        0xB7 => ASCII_GLYPHS + 4,
        0x2500..=0x257F => BOXES + (u - 0x2500) as u16,
        0x2580..=0x259F => BLOCKS + (u - 0x2580) as u16,
        0x23BA..=0x23BD => SCAN_LINES + (u - 0x23BA) as u16,
        0x25C6 => DIAMOND,
        _ => REPLACEMENT,
    }
}

/// The code point glyph `index` draws, [`glyph`]'s inverse; `None` for the
/// replacement glyph and past the table.
pub const fn code_point(index: u16) -> Option<char> {
    let i = index as u32;
    let u = if index < ASCII_GLYPHS {
        0x20 + i
    } else if index < BOXES {
        LATIN1[(index - ASCII_GLYPHS) as usize] as u32
    } else if index < BLOCKS {
        0x2500 + i - BOXES as u32
    } else if index < SCAN_LINES {
        0x2580 + i - BLOCKS as u32
    } else if index < DIAMOND {
        0x23BA + i - SCAN_LINES as u32
    } else if index == DIAMOND {
        0x25C6
    } else {
        return None;
    };
    char::from_u32(u)
}

/// Glyph `index`'s rows; the replacement glyph past the table.
pub fn bitmap(index: u16) -> &'static Glyph {
    GLYPHS
        .get(usize::from(index))
        .unwrap_or(&GLYPHS[REPLACEMENT as usize])
}

/// Every glyph, by index.
pub static GLYPHS: [Glyph; COUNT] = build();

const fn build() -> [Glyph; COUNT] {
    let mut g = [[0; HEIGHT]; COUNT];
    let mut i = 0;
    while i < COUNT {
        let index = i as u16;
        g[i] = if index < BOXES {
            let (c, rows) = spleen::GLYPHS[i];
            match code_point(index) {
                Some(want) if want as u32 == c as u32 => {}
                _ => panic!("spleen::GLYPHS is not in the font's order"),
            }
            rows
        } else if index < BLOCKS {
            box_drawing(BOX_SHAPES[i - BOXES as usize])
        } else if index < SCAN_LINES {
            block(i - BLOCKS as usize)
        } else if index < DIAMOND {
            // Scan lines 1, 3, 7 and 9; U+2500's row 7 is scan line 5.
            let mut s = [0; HEIGHT];
            s[[1, 4, 10, 13][i - SCAN_LINES as usize]] = 0xFF;
            s
        } else if index == DIAMOND {
            diamond()
        } else {
            replacement()
        };
        i += 1;
    }
    g
}

/// Lights the pixel in column `x` of row `y`.
const fn set(g: &mut Glyph, x: usize, y: usize) {
    g[y] |= 0x80 >> x;
}

/// An outline box over rows 2 to 13 and columns 1 to 6.
const fn replacement() -> Glyph {
    let mut g = [0; HEIGHT];
    let mut y = 2;
    while y <= 13 {
        g[y] = if y == 2 || y == 13 { 0x7E } else { 0x42 };
        y += 1;
    }
    g
}

/// A filled diamond centred on the cell: the pixels whose centres lie
/// within 3 of the cell's centre, (3.5, 7.5), in the L1 norm.
const fn diamond() -> Glyph {
    let mut g = [0; HEIGHT];
    let mut y = 0;
    while y < HEIGHT {
        let mut x = 0;
        while x < WIDTH {
            if (2 * x).abs_diff(7) + (2 * y).abs_diff(15) <= 6 {
                set(&mut g, x, y);
            }
            x += 1;
        }
        y += 1;
    }
    g
}

/// The block element U+2580 + `i`: eighths, halves, quadrants of 4 × 8
/// pixels and the three shades.
const fn block(i: usize) -> Glyph {
    let mut g = [0; HEIGHT];
    let mut y = 0;
    while y < HEIGHT {
        let mut x = 0;
        while x < WIDTH {
            let quadrant: u8 = 1 << ((y >= 8) as usize * 2 + (x >= 4) as usize);
            let lit = match i {
                // Upper half.
                0x00 => y < 8,
                // Lower one eighth to full: the bottom 2, 4, ... 16 rows.
                0x01..=0x08 => y >= HEIGHT - 2 * i,
                // Left seven eighths to one eighth: 7 down to 1 columns.
                0x09..=0x0F => x < 16 - i,
                // Right half.
                0x10 => x >= 4,
                // Light, medium and dark shade.
                0x11 => (x + 2 * y) % 4 == 0,
                0x12 => (x + y) % 2 == 0,
                0x13 => (x + 2 * y) % 4 != 0,
                // Upper one eighth and right one eighth.
                0x14 => y < 2,
                0x15 => x == 7,
                // Quadrants: bit 0 upper left, 1 upper right, 2 lower left,
                // 3 lower right.
                _ => QUADRANTS[i - 0x16] & quadrant != 0,
            };
            if lit {
                set(&mut g, x, y);
            }
            x += 1;
        }
        y += 1;
    }
    g
}

/// U+2596 to U+259F's quadrants.
const QUADRANTS: [u8; 10] = [
    0b0100, // ▖ lower left
    0b1000, // ▗ lower right
    0b0001, // ▘ upper left
    0b1101, // ▙ upper left, lower left and lower right
    0b1001, // ▚ upper left and lower right
    0b0111, // ▛ upper left, upper right and lower left
    0b1011, // ▜ upper left, upper right and lower right
    0b0010, // ▝ upper right
    0b0110, // ▞ upper right and lower left
    0b1110, // ▟ upper right, lower left and lower right
];

/// No arm.
pub(crate) const N: u8 = 0;
/// A light arm: column 3 or row 7.
pub(crate) const L: u8 = 1;
/// A heavy arm: columns 3 and 4 or rows 7 and 8.
pub(crate) const H: u8 = 2;
/// A double arm: columns 2 and 5 or rows 6 and 9.
pub(crate) const D: u8 = 3;

pub(crate) const UP: usize = 0;
pub(crate) const RIGHT: usize = 1;
pub(crate) const DOWN: usize = 2;
pub(crate) const LEFT: usize = 3;

/// A box-drawing glyph's description: its four arms, up, right, down and
/// left, each [`N`], [`L`], [`H`] or [`D`]; the dashes per cell of a dashed
/// line, or 0; and the diagonals, bit 0 rising (U+2571) and bit 1 falling
/// (U+2572).
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) struct Shape {
    pub arms: [u8; 4],
    pub dashes: u8,
    pub diagonals: u8,
}

const fn a(up: u8, right: u8, down: u8, left: u8) -> Shape {
    Shape {
        arms: [up, right, down, left],
        dashes: 0,
        diagonals: 0,
    }
}

const fn dashed(dashes: u8, s: Shape) -> Shape {
    Shape { dashes, ..s }
}

const fn diagonal(diagonals: u8) -> Shape {
    Shape {
        diagonals,
        ..a(N, N, N, N)
    }
}

/// U+2500 to U+257F.
#[rustfmt::skip]
pub(crate) const BOX_SHAPES: [Shape; 128] = [
    a(N, L, N, L),            // ─ 2500
    a(N, H, N, H),            // ━
    a(L, N, L, N),            // │
    a(H, N, H, N),            // ┃
    dashed(3, a(N, L, N, L)), // ┄ 2504
    dashed(3, a(N, H, N, H)), // ┅
    dashed(3, a(L, N, L, N)), // ┆
    dashed(3, a(H, N, H, N)), // ┇
    dashed(4, a(N, L, N, L)), // ┈ 2508
    dashed(4, a(N, H, N, H)), // ┉
    dashed(4, a(L, N, L, N)), // ┊
    dashed(4, a(H, N, H, N)), // ┋
    a(N, L, L, N),            // ┌ 250C
    a(N, H, L, N),            // ┍
    a(N, L, H, N),            // ┎
    a(N, H, H, N),            // ┏
    a(N, N, L, L),            // ┐ 2510
    a(N, N, L, H),            // ┑
    a(N, N, H, L),            // ┒
    a(N, N, H, H),            // ┓
    a(L, L, N, N),            // └ 2514
    a(L, H, N, N),            // ┕
    a(H, L, N, N),            // ┖
    a(H, H, N, N),            // ┗
    a(L, N, N, L),            // ┘ 2518
    a(L, N, N, H),            // ┙
    a(H, N, N, L),            // ┚
    a(H, N, N, H),            // ┛
    a(L, L, L, N),            // ├ 251C
    a(L, H, L, N),            // ┝
    a(H, L, L, N),            // ┞
    a(L, L, H, N),            // ┟
    a(H, L, H, N),            // ┠ 2520
    a(H, H, L, N),            // ┡
    a(L, H, H, N),            // ┢
    a(H, H, H, N),            // ┣
    a(L, N, L, L),            // ┤ 2524
    a(L, N, L, H),            // ┥
    a(H, N, L, L),            // ┦
    a(L, N, H, L),            // ┧
    a(H, N, H, L),            // ┨ 2528
    a(H, N, L, H),            // ┩
    a(L, N, H, H),            // ┪
    a(H, N, H, H),            // ┫
    a(N, L, L, L),            // ┬ 252C
    a(N, L, L, H),            // ┭
    a(N, H, L, L),            // ┮
    a(N, H, L, H),            // ┯
    a(N, L, H, L),            // ┰ 2530
    a(N, L, H, H),            // ┱
    a(N, H, H, L),            // ┲
    a(N, H, H, H),            // ┳
    a(L, L, N, L),            // ┴ 2534
    a(L, L, N, H),            // ┵
    a(L, H, N, L),            // ┶
    a(L, H, N, H),            // ┷
    a(H, L, N, L),            // ┸ 2538
    a(H, L, N, H),            // ┹
    a(H, H, N, L),            // ┺
    a(H, H, N, H),            // ┻
    a(L, L, L, L),            // ┼ 253C
    a(L, L, L, H),            // ┽
    a(L, H, L, L),            // ┾
    a(L, H, L, H),            // ┿
    a(H, L, L, L),            // ╀ 2540
    a(L, L, H, L),            // ╁
    a(H, L, H, L),            // ╂
    a(H, L, L, H),            // ╃
    a(H, H, L, L),            // ╄ 2544
    a(L, L, H, H),            // ╅
    a(L, H, H, L),            // ╆
    a(H, H, L, H),            // ╇
    a(L, H, H, H),            // ╈ 2548
    a(H, L, H, H),            // ╉
    a(H, H, H, L),            // ╊
    a(H, H, H, H),            // ╋
    dashed(2, a(N, L, N, L)), // ╌ 254C
    dashed(2, a(N, H, N, H)), // ╍
    dashed(2, a(L, N, L, N)), // ╎
    dashed(2, a(H, N, H, N)), // ╏
    a(N, D, N, D),            // ═ 2550
    a(D, N, D, N),            // ║
    a(N, D, L, N),            // ╒
    a(N, L, D, N),            // ╓
    a(N, D, D, N),            // ╔ 2554
    a(N, N, L, D),            // ╕
    a(N, N, D, L),            // ╖
    a(N, N, D, D),            // ╗
    a(L, D, N, N),            // ╘ 2558
    a(D, L, N, N),            // ╙
    a(D, D, N, N),            // ╚
    a(L, N, N, D),            // ╛
    a(D, N, N, L),            // ╜ 255C
    a(D, N, N, D),            // ╝
    a(L, D, L, N),            // ╞
    a(D, L, D, N),            // ╟
    a(D, D, D, N),            // ╠ 2560
    a(L, N, L, D),            // ╡
    a(D, N, D, L),            // ╢
    a(D, N, D, D),            // ╣
    a(N, D, L, D),            // ╤ 2564
    a(N, L, D, L),            // ╥
    a(N, D, D, D),            // ╦
    a(L, D, N, D),            // ╧
    a(D, L, N, L),            // ╨ 2568
    a(D, D, N, D),            // ╩
    a(L, D, L, D),            // ╪
    a(D, L, D, L),            // ╫
    a(D, D, D, D),            // ╬ 256C
    a(N, L, L, N),            // ╭ drawn as ┌
    a(N, N, L, L),            // ╮ drawn as ┐
    a(L, N, N, L),            // ╯ drawn as ┘
    a(L, L, N, N),            // ╰ 2570, drawn as └
    diagonal(1),              // ╱
    diagonal(2),              // ╲
    diagonal(3),              // ╳
    a(N, N, N, L),            // ╴ 2574
    a(L, N, N, N),            // ╵
    a(N, L, N, N),            // ╶
    a(N, N, L, N),            // ╷
    a(N, N, N, H),            // ╸ 2578
    a(H, N, N, N),            // ╹
    a(N, H, N, N),            // ╺
    a(N, N, H, N),            // ╻
    a(N, H, N, L),            // ╼ 257C
    a(L, N, H, N),            // ╽
    a(N, L, N, H),            // ╾
    a(H, N, L, N),            // ╿
];

/// The lines of an arm of `weight` across its axis, the first and the
/// last: columns for a vertical arm; for a horizontal one add 4 for rows.
const fn span(weight: u8) -> (usize, usize) {
    match weight {
        L => (3, 3),
        H => (3, 4),
        _ => (2, 5),
    }
}

/// A box-drawing glyph: the union of its arms, then its dashes, or its
/// diagonals.
const fn box_drawing(s: Shape) -> Glyph {
    let mut g = [0; HEIGHT];
    let mut d = 0;
    while d < 4 {
        arm(&mut g, &s.arms, d);
        d += 1;
    }
    if s.dashes != 0 {
        // n dashes per cell, each followed by a gap of an eighth of the
        // cell's length: one pixel across, two down.
        let n = s.dashes as usize;
        let vertical = s.arms[UP] != N;
        let len = if vertical { HEIGHT } else { WIDTH };
        let mut i = 0;
        while i < len {
            if (n * i) % len >= len - n * len / 8 {
                if vertical {
                    g[i] = 0;
                } else {
                    let mut y = 0;
                    while y < HEIGHT {
                        g[y] &= !(0x80 >> i);
                        y += 1;
                    }
                }
            }
            i += 1;
        }
    }
    // Corner to corner: one pixel per row, two rows per column.
    let mut y = 0;
    while y < HEIGHT {
        if s.diagonals & 1 != 0 {
            set(&mut g, WIDTH - 1 - y / 2, y);
        }
        if s.diagonals & 2 != 0 {
            set(&mut g, y / 2, y);
        }
        y += 1;
    }
    g
}

/// Draws arm `d` of `arms` (`docs/design.md`, "Generated glyphs"). An arm
/// runs from its edge, along its axis (rows for up and down, columns for
/// left and right), to an end:
///
/// - a light or heavy arm through the centre square (row 7 or 8 for up,
///   from row 7 down, column 3 or 4 for left, from column 3 right);
/// - but a light arm across a double one (none of the font's glyphs mixes
///   heavy and double) to the double's farther line, so that a corner such
///   as ╖ or ╘ closes, or to its nearer line when the double runs straight
///   through the cell and nothing continues the light arm beyond it, so
///   that a T such as ╟ or ╤ stops at the double line;
/// - each line of a double arm to the arm beside it on that line's side:
///   that arm's nearer line if there is one, else the farther line of the
///   arm on the other side, else the centre row or column.
const fn arm(g: &mut Glyph, arms: &[u8; 4], d: usize) {
    let weight = arms[d];
    if weight == N {
        return;
    }
    let vertical = d == UP || d == DOWN;
    // Along this arm's axis, a crossing arm's lines lie at its span plus
    // `off`; across it, this arm's own lines at its span plus `across`.
    let (off, across, last) = if vertical {
        (4, 0, HEIGHT - 1)
    } else {
        (0, 4, WIDTH - 1)
    };
    // Up and left run from position 0; down and right from `last`.
    let low = d == UP || d == LEFT;
    let (side_lo, side_hi) = if vertical { (LEFT, RIGHT) } else { (UP, DOWN) };
    let (lo, hi) = (arms[side_lo], arms[side_hi]);
    let opposite = arms[(d + 2) % 4];
    if weight == D {
        let (first, second) = span(D);
        line(
            g,
            vertical,
            low,
            last,
            first + across,
            double_end(lo, hi, low, off),
        );
        line(
            g,
            vertical,
            low,
            last,
            second + across,
            double_end(hi, lo, low, off),
        );
        return;
    }
    let end = if weight == L && (lo == D || hi == D) {
        let (near, far) = if low { span(D) } else { (span(D).1, span(D).0) };
        if lo == D && hi == D && opposite == N {
            near + off
        } else {
            far + off
        }
    } else if low {
        span(weight).1 + off
    } else {
        span(weight).0 + off
    };
    let (first, second) = span(weight);
    let mut p = first;
    while p <= second {
        line(g, vertical, low, last, p + across, end);
        p += 1;
    }
}

/// Where a double arm's line ends: at the nearer line of `beside`, the arm
/// on its side, if there is one, else at the farther line of `other`, the
/// arm on the other side, else at the centre.
const fn double_end(beside: u8, other: u8, low: bool, off: usize) -> usize {
    if beside != N {
        let (first, second) = span(beside);
        (if low { first } else { second }) + off
    } else if other != N {
        let (first, second) = span(other);
        (if low { second } else { first }) + off
    } else {
        3 + off
    }
}

/// One line of an arm at `pos` across the axis, from position 0 to `end`
/// if `low`, else from `end` to `last`.
const fn line(g: &mut Glyph, vertical: bool, low: bool, last: usize, pos: usize, end: usize) {
    let (mut i, stop) = if low { (0, end) } else { (end, last) };
    while i <= stop {
        if vertical {
            set(g, pos, i);
        } else {
            set(g, i, pos);
        }
        i += 1;
    }
}
