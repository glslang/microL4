//! A reference model of exactly the sequences tui may write, written from
//! `docs/design.md`'s "The screen model" for the rows tui uses, for its
//! host tests, and for its goldens beside term's own screen model, which
//! checks them too (`golden.rs`). It panics on any other byte or
//! sequence, so feeding it `App`'s output also checks that tui keeps to
//! the sequences term acts on (`docs/design.md`, "`tui`": "tui uses only
//! sequences term acts on").
//!
//! Cells, the cursor with its pending wrap, the pen, the scroll region,
//! both buffers with a saved cursor each, G0 as ASCII or DEC Special
//! Graphics, DECTCEM, DECSCUSR, and UTF-8; LNM, DECOM and IRM stay reset
//! and DECAWM set, as tui leaves them.

use std::vec;
use std::vec::Vec;

pub const BOLD: u8 = 1 << 0;
pub const FAINT: u8 = 1 << 1;
pub const ITALIC: u8 = 1 << 2;
pub const UNDERLINE: u8 = 1 << 3;
pub const BLINK: u8 = 1 << 4;
pub const INVERSE: u8 = 1 << 5;
pub const CONCEAL: u8 = 1 << 6;
pub const STRIKE: u8 = 1 << 7;
/// The attributes' names in the goldens' order.
pub const ATTRS: [(u8, &str); 8] = [
    (BOLD, "bold"),
    (FAINT, "faint"),
    (ITALIC, "italic"),
    (UNDERLINE, "underline"),
    (BLINK, "blink"),
    (INVERSE, "inverse"),
    (CONCEAL, "conceal"),
    (STRIKE, "strike"),
];

/// A cell's colours and attributes; `None` is the default colour.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Style {
    pub fg: Option<u8>,
    pub bg: Option<u8>,
    pub attrs: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Cell {
    pub ch: char,
    pub style: Style,
}

/// The cursor's shape, DECSCUSR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Shape {
    Block,
    Underline,
    Bar,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Saved {
    row: usize,
    col: usize,
    pen: Style,
    dec: bool,
    wrap: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum State {
    Ground,
    Escape,
    /// ESC `(`: G0's set.
    Designate,
    Csi {
        private: Option<u8>,
        intermediate: Option<u8>,
        params: Vec<Option<u32>>,
    },
}

#[derive(Clone, Debug)]
pub struct Screen {
    pub cols: usize,
    pub rows: usize,
    grids: [Vec<Cell>; 2],
    /// The alternate buffer is active.
    pub alternate: bool,
    /// From 0.
    pub row: usize,
    pub col: usize,
    /// DEC's last-column flag.
    pub wrap: bool,
    pub visible: bool,
    pub shape: Shape,
    pen: Style,
    dec: bool,
    /// The region, from 0, inclusive.
    pub top: usize,
    pub bottom: usize,
    saved: [Option<Saved>; 2],
    state: State,
    /// A UTF-8 sequence: the code point so far and the bytes still due,
    /// and the range the next must lie in.
    utf8: (u32, u8, (u8, u8)),
    /// Code points printed, for tests.
    pub prints: usize,
}

const BLANK: Cell = Cell {
    ch: ' ',
    style: Style {
        fg: None,
        bg: None,
        attrs: 0,
    },
};

impl Screen {
    /// The power-on state.
    pub fn new(cols: usize, rows: usize) -> Screen {
        Screen {
            cols,
            rows,
            grids: [vec![BLANK; cols * rows], vec![BLANK; cols * rows]],
            alternate: false,
            row: 0,
            col: 0,
            wrap: false,
            visible: true,
            shape: Shape::Block,
            pen: Style::default(),
            dec: false,
            top: 0,
            bottom: rows - 1,
            saved: [None; 2],
            state: State::Ground,
            utf8: (0, 0, (0, 0)),
            prints: 0,
        }
    }

    /// The active buffer's cell at `row`, `col`, from 0.
    pub fn cell(&self, row: usize, col: usize) -> Cell {
        self.grids[usize::from(self.alternate)][row * self.cols + col]
    }

    /// Row `row`'s text, from 0, trailing blanks trimmed.
    pub fn text(&self, row: usize) -> std::string::String {
        let s: std::string::String = (0..self.cols).map(|c| self.cell(row, c).ch).collect();
        s.trim_end().into()
    }

    /// Every cell of the active buffer outside rows `keep` becomes junk,
    /// for the test that every frame draws all of them.
    pub fn scribble(&mut self, keep: core::ops::RangeInclusive<usize>) {
        let cols = self.cols;
        let g = &mut self.grids[usize::from(self.alternate)];
        for (i, c) in g.iter_mut().enumerate() {
            if !keep.contains(&(i / cols)) {
                *c = Cell {
                    ch: '#',
                    style: Style {
                        fg: Some(1),
                        bg: Some(2),
                        attrs: 0xFF,
                    },
                };
            }
        }
    }

    fn grid(&mut self) -> &mut Vec<Cell> {
        &mut self.grids[usize::from(self.alternate)]
    }

    fn blank(&self) -> Cell {
        Cell {
            ch: ' ',
            style: Style {
                fg: None,
                bg: self.pen.bg,
                attrs: 0,
            },
        }
    }

    pub fn write(&mut self, bytes: &[u8]) {
        for &b in bytes {
            self.byte(b);
        }
    }

    fn byte(&mut self, b: u8) {
        if self.utf8.1 > 0 {
            let (lo, hi) = self.utf8.2;
            assert!((lo..=hi).contains(&b), "ill-formed UTF-8 at {b:#x}");
            self.utf8 = (
                self.utf8.0 << 6 | u32::from(b & 0x3F),
                self.utf8.1 - 1,
                (0x80, 0xBF),
            );
            if self.utf8.1 == 0 {
                let ch = char::from_u32(self.utf8.0).expect("a scalar value");
                assert!(!('\u{80}'..='\u{9f}').contains(&ch), "a C1 control");
                self.print(ch);
            }
            return;
        }
        match core::mem::replace(&mut self.state, State::Ground) {
            State::Ground => self.ground(b),
            State::Escape => match b {
                b'[' => {
                    self.state = State::Csi {
                        private: None,
                        intermediate: None,
                        params: vec![None],
                    }
                }
                b'(' => self.state = State::Designate,
                _ => panic!("ESC {:?}: not a sequence tui may use", char::from(b)),
            },
            State::Designate => match b {
                b'0' => self.dec = true,
                b'B' => self.dec = false,
                _ => panic!("ESC ( {:?}", char::from(b)),
            },
            State::Csi {
                mut private,
                mut intermediate,
                mut params,
            } => match b {
                b'?' if private.is_none() && params == [None] => {
                    private = Some(b);
                    self.state = State::Csi {
                        private,
                        intermediate,
                        params,
                    };
                }
                b'0'..=b'9' if intermediate.is_none() => {
                    let p = params.last_mut().unwrap();
                    *p = Some(p.unwrap_or(0) * 10 + u32::from(b - b'0'));
                    assert!(p.unwrap() <= 65_535, "a parameter past 65535");
                    self.state = State::Csi {
                        private,
                        intermediate,
                        params,
                    };
                }
                b';' if intermediate.is_none() => {
                    params.push(None);
                    assert!(params.len() <= 16, "more than 16 parameters");
                    self.state = State::Csi {
                        private,
                        intermediate,
                        params,
                    };
                }
                b' ' if intermediate.is_none() => {
                    intermediate = Some(b);
                    self.state = State::Csi {
                        private,
                        intermediate,
                        params,
                    };
                }
                0x40..=0x7E => self.csi(private, intermediate, &params, b),
                _ => panic!("{b:#x} inside a CSI sequence"),
            },
        }
    }

    fn ground(&mut self, b: u8) {
        match b {
            0x1B => self.state = State::Escape,
            b'\r' => {
                self.col = 0;
                self.wrap = false;
            }
            b'\n' => self.index(),
            0x20..=0x7E => self.print(char::from(b)),
            0xC2..=0xDF => self.utf8 = (u32::from(b & 0x1F), 1, (0x80, 0xBF)),
            0xE0..=0xEF => {
                let next = match b {
                    0xE0 => (0xA0, 0xBF),
                    0xED => (0x80, 0x9F),
                    _ => (0x80, 0xBF),
                };
                self.utf8 = (u32::from(b & 0x0F), 2, next);
            }
            0xF0..=0xF4 => {
                let next = match b {
                    0xF0 => (0x90, 0xBF),
                    0xF4 => (0x80, 0x8F),
                    _ => (0x80, 0xBF),
                };
                self.utf8 = (u32::from(b & 0x07), 3, next);
            }
            _ => panic!("byte {b:#x}: not one tui may write"),
        }
    }

    fn print(&mut self, ch: char) {
        if self.wrap {
            self.col = 0;
            self.index();
        }
        let ch = if self.dec { dec_special(ch) } else { ch };
        let (row, col, pen) = (self.row, self.col, self.pen);
        let cols = self.cols;
        self.grid()[row * cols + col] = Cell { ch, style: pen };
        if self.col == self.cols - 1 {
            self.wrap = true;
        } else {
            self.col += 1;
        }
        self.prints += 1;
    }

    /// IND: down one, or on the region's bottom row scroll the region up.
    fn index(&mut self) {
        self.wrap = false;
        if self.row == self.bottom {
            let (cols, top, bottom) = (self.cols, self.top, self.bottom);
            let blank = self.blank();
            let g = self.grid();
            g.copy_within((top + 1) * cols..(bottom + 1) * cols, top * cols);
            g[bottom * cols..(bottom + 1) * cols].fill(blank);
        } else if self.row < self.rows - 1 {
            self.row += 1;
        }
    }

    fn csi(
        &mut self,
        private: Option<u8>,
        intermediate: Option<u8>,
        params: &[Option<u32>],
        f: u8,
    ) {
        let p = |i: usize| params.get(i).copied().flatten().unwrap_or(0);
        // Pn: 0 counts as 1.
        let n = |i: usize| p(i).max(1) as usize;
        match (private, intermediate, f) {
            (None, None, b'H') => {
                self.row = n(0).min(self.rows) - 1;
                self.col = n(1).min(self.cols) - 1;
                self.wrap = false;
            }
            (None, None, b'K') => {
                assert_eq!(params, [None], "only EL 0");
                let (row, col, cols) = (self.row, self.col, self.cols);
                let blank = self.blank();
                self.grid()[row * cols + col..(row + 1) * cols].fill(blank);
                self.wrap = false;
            }
            (None, None, b'J') => {
                assert_eq!(params, [Some(2)], "only ED 2");
                let blank = self.blank();
                self.grid().fill(blank);
                self.wrap = false;
            }
            (None, None, b'm') => self.sgr(params),
            (None, None, b'r') => {
                let t = n(0);
                let b = if p(1) == 0 { self.rows } else { n(1) }.min(self.rows);
                if t < b {
                    (self.top, self.bottom) = (t - 1, b - 1);
                    (self.row, self.col, self.wrap) = (0, 0, false);
                }
            }
            (Some(b'?'), None, b'h' | b'l') => {
                let set = f == b'h';
                for &m in params {
                    match m {
                        Some(25) => self.visible = set,
                        Some(1049) => self.alternate_screen(set),
                        _ => panic!("DEC mode {m:?}"),
                    }
                }
            }
            (None, Some(b' '), b'q') => {
                self.shape = match p(0) {
                    0..=2 => Shape::Block,
                    3 | 4 => Shape::Underline,
                    5 | 6 => Shape::Bar,
                    s => panic!("DECSCUSR {s}"),
                }
            }
            _ => panic!(
                "CSI {:?} {:?} {params:?} {:?}: not a sequence tui may use",
                private.map(char::from),
                intermediate.map(char::from),
                char::from(f)
            ),
        }
    }

    fn save(&self) -> Saved {
        Saved {
            row: self.row,
            col: self.col,
            pen: self.pen,
            dec: self.dec,
            wrap: self.wrap,
        }
    }

    fn restore(&mut self, s: Option<Saved>) {
        let s = s.unwrap_or(Saved {
            row: 0,
            col: 0,
            pen: Style::default(),
            dec: false,
            wrap: false,
        });
        (self.row, self.col, self.pen, self.dec, self.wrap) = (s.row, s.col, s.pen, s.dec, s.wrap);
    }

    /// Mode 1049: set, DECSC then the alternate buffer, cleared; reset,
    /// the main buffer then DECRC. Already where it would switch to, only
    /// the DECSC or DECRC acts, on the active buffer's saved cursor.
    fn alternate_screen(&mut self, set: bool) {
        let active = usize::from(self.alternate);
        if set {
            self.saved[active] = Some(self.save());
            if !self.alternate {
                self.alternate = true;
                let blank = self.blank();
                self.grid().fill(blank);
            }
        } else {
            self.alternate = false;
            self.restore(self.saved[0]);
        }
    }

    fn sgr(&mut self, params: &[Option<u32>]) {
        let mut it = params.iter().map(|p| p.unwrap_or(0));
        while let Some(p) = it.next() {
            let pen = &mut self.pen;
            match p {
                0 => *pen = Style::default(),
                1 => pen.attrs |= BOLD,
                2 => pen.attrs |= FAINT,
                3 => pen.attrs |= ITALIC,
                4 => pen.attrs |= UNDERLINE,
                5 => pen.attrs |= BLINK,
                7 => pen.attrs |= INVERSE,
                8 => pen.attrs |= CONCEAL,
                9 => pen.attrs |= STRIKE,
                22 => pen.attrs &= !(BOLD | FAINT),
                23 => pen.attrs &= !ITALIC,
                24 => pen.attrs &= !UNDERLINE,
                25 => pen.attrs &= !BLINK,
                27 => pen.attrs &= !INVERSE,
                28 => pen.attrs &= !CONCEAL,
                29 => pen.attrs &= !STRIKE,
                30..=37 => pen.fg = Some((p - 30) as u8),
                39 => pen.fg = None,
                40..=47 => pen.bg = Some((p - 40) as u8),
                49 => pen.bg = None,
                90..=97 => pen.fg = Some((p - 90 + 8) as u8),
                100..=107 => pen.bg = Some((p - 100 + 8) as u8),
                38 | 48 => {
                    let c = match it.next() {
                        Some(5) => it.next().filter(|&n| n <= 255).expect("38;5;n") as u8,
                        Some(2) => {
                            let mut rgb = [0u8; 3];
                            for c in &mut rgb {
                                *c = it.next().filter(|&n| n <= 255).expect("38;2;r;g;b") as u8;
                            }
                            nearest(rgb)
                        }
                        k => panic!("SGR {p};{k:?}: malformed"),
                    };
                    if p == 38 {
                        pen.fg = Some(c);
                    } else {
                        pen.bg = Some(c);
                    }
                }
                _ => panic!("SGR {p}: not one tui may use"),
            }
        }
    }
}

/// The xterm palette from 16: the 6 x 6 x 6 cube and the 24 greys.
const LEVELS: [u32; 6] = [0x00, 0x5F, 0x87, 0xAF, 0xD7, 0xFF];

/// A true colour's palette entry (`docs/design.md`, "The screen model"):
/// the cube's nearest entry, per channel the nearest level with ties to
/// the lower, or the ramp's, the nearest level to the channels' mean with
/// ties to the lower, whichever is nearer by squared distance, the cube
/// on a tie. The mean is compared exactly, as three times a level against
/// the channels' sum.
pub fn nearest(rgb: [u8; 3]) -> u8 {
    let level = |c: u32| (0..6).min_by_key(|&i| (LEVELS[i].abs_diff(c), i)).unwrap();
    let idx = rgb.map(|c| level(u32::from(c)));
    let cube = [LEVELS[idx[0]], LEVELS[idx[1]], LEVELS[idx[2]]];
    let sum: u32 = rgb.iter().map(|&c| u32::from(c)).sum();
    let grey = (0..24u32)
        .min_by_key(|&i| ((8 + 10 * i) * 3).abs_diff(sum))
        .unwrap();
    let g = 8 + 10 * grey;
    let dist = |c: [u32; 3]| -> u32 {
        (0..3)
            .map(|i| {
                let d = c[i].abs_diff(u32::from(rgb[i]));
                d * d
            })
            .sum()
    };
    if dist([g, g, g]) < dist(cube) {
        232 + grey as u8
    } else {
        16 + 36 * idx[0] as u8 + 6 * idx[1] as u8 + idx[2] as u8
    }
}

/// DEC Special Graphics for `0x5F` to `0x7E` (`docs/design.md`,
/// "Printing").
pub fn dec_special(ch: char) -> char {
    const TABLE: [char; 32] = [
        '\u{a0}', '◆', '▒', '␉', '␌', '␍', '␊', '°', '±', '␤', '␋', '┘', '┐', '┌', '└', '┼', '⎺',
        '⎻', '─', '⎼', '⎽', '├', '┤', '┴', '┬', '│', '≤', '≥', 'π', '≠', '£', '·',
    ];
    match ch {
        '\x5f'..='\x7e' => TABLE[ch as usize - 0x5F],
        _ => ch,
    }
}
