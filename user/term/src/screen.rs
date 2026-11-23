//! The screen model (`docs/design.md`, "The screen model"): it acts on the
//! parser's actions, writes cells into two grids of words, the main and the
//! alternate buffer, and hands the replies it owes the client to a sink.
//! It uses nothing but `core`.
//!
//! Rows and columns count from 0 here; the sequences count them from 1.

use crate::palette;
use crate::parser::Actions;
use crate::{MAX_COLS, MAX_ROWS};

/// A cell's colour: the default, or a palette index.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Color {
    #[default]
    Default,
    Index(u8),
}

impl Color {
    const fn bits(self) -> u64 {
        match self {
            Color::Default => 0,
            Color::Index(n) => 0x100 | n as u64,
        }
    }

    const fn from_bits(bits: u64) -> Color {
        if bits & 0x100 == 0 {
            Color::Default
        } else {
            Color::Index(bits as u8)
        }
    }

    /// `0xRRGGBB`, with the default `default`.
    pub const fn rgb(self, default: u32) -> u32 {
        match self {
            Color::Default => default,
            Color::Index(n) => palette::rgb(n),
        }
    }
}

/// A cell's attributes, one bit each.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Attrs(pub u8);

impl Attrs {
    pub const NONE: Attrs = Attrs(0);
    pub const BOLD: Attrs = Attrs(1 << 0);
    pub const FAINT: Attrs = Attrs(1 << 1);
    pub const ITALIC: Attrs = Attrs(1 << 2);
    pub const UNDERLINE: Attrs = Attrs(1 << 3);
    pub const BLINK: Attrs = Attrs(1 << 4);
    pub const INVERSE: Attrs = Attrs(1 << 5);
    pub const CONCEAL: Attrs = Attrs(1 << 6);
    pub const STRIKE: Attrs = Attrs(1 << 7);
    /// Every attribute with its name, in the goldens' order.
    pub const NAMES: [(Attrs, &'static str); 8] = [
        (Attrs::BOLD, "bold"),
        (Attrs::FAINT, "faint"),
        (Attrs::ITALIC, "italic"),
        (Attrs::UNDERLINE, "underline"),
        (Attrs::BLINK, "blink"),
        (Attrs::INVERSE, "inverse"),
        (Attrs::CONCEAL, "conceal"),
        (Attrs::STRIKE, "strike"),
    ];

    pub const fn contains(self, a: Attrs) -> bool {
        self.0 & a.0 == a.0
    }

    pub fn insert(&mut self, a: Attrs) {
        self.0 |= a.0;
    }

    pub fn remove(&mut self, a: Attrs) {
        self.0 &= !a.0;
    }
}

/// The colours and attributes the next print uses, and every cell has.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub struct Pen {
    pub fg: Color,
    pub bg: Color,
    pub attrs: Attrs,
}

/// One cell: a code point and its pen. It packs into one word of the state
/// window: the code point in bits 0 to 20, the attributes in 24 to 31, the
/// foreground in 32 to 40 and the background in 48 to 56, each colour bit 8
/// set for a palette index in bits 0 to 7.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cell {
    pub ch: char,
    pub pen: Pen,
}

impl Cell {
    /// A blank in the given background: a space in the default foreground
    /// with no attribute.
    pub const fn blank(bg: Color) -> Cell {
        Cell {
            ch: ' ',
            pen: Pen {
                fg: Color::Default,
                bg,
                attrs: Attrs::NONE,
            },
        }
    }

    pub const fn word(self) -> u64 {
        self.ch as u64
            | (self.pen.attrs.0 as u64) << 24
            | self.pen.fg.bits() << 32
            | self.pen.bg.bits() << 48
    }

    /// The cell a word holds. Every word the screen writes comes back as it
    /// went in; any other gives U+FFFD for a code point that is not one.
    pub const fn from_word(w: u64) -> Cell {
        let ch = match char::from_u32((w & 0x1F_FFFF) as u32) {
            Some(c) => c,
            None => char::REPLACEMENT_CHARACTER,
        };
        Cell {
            ch,
            pen: Pen {
                fg: Color::from_bits(w >> 32 & 0x1FF),
                bg: Color::from_bits(w >> 48 & 0x1FF),
                attrs: Attrs((w >> 24) as u8),
            },
        }
    }
}

/// A character set that G0 or G1 holds.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Charset {
    #[default]
    Ascii,
    /// DEC Special Graphics: `0x5F` to `0x7E` are line drawing and symbols.
    DecGraphics,
}

/// The cursor's shape, from DECSCUSR. It never blinks.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CursorStyle {
    #[default]
    Block,
    Underline,
    Bar,
}

/// Where the cursor is and how it is drawn.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Cursor {
    pub row: usize,
    pub col: usize,
    /// DEC's last-column flag: the next print wraps first.
    pub pending_wrap: bool,
    /// DECTCEM.
    pub visible: bool,
    pub style: CursorStyle,
}

/// The modes, each at its default by [`Modes::DEFAULT`].
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Modes {
    /// IRM (4): prints insert.
    pub insert: bool,
    /// LNM (20): LF, VT and FF also return to column 1.
    pub newline: bool,
    /// DECCKM (?1), stored only.
    pub cursor_keys: bool,
    /// DECSCNM (?5): every cell drawn with its colours swapped.
    pub reverse: bool,
    /// DECOM (?6): addressing relative to the region.
    pub origin: bool,
    /// DECAWM (?7): autowrap.
    pub autowrap: bool,
    /// DECTCEM (?25): the cursor is drawn.
    pub cursor_visible: bool,
    /// DECKPAM / DECKPNM, stored only.
    pub keypad: bool,
}

impl Modes {
    pub const DEFAULT: Modes = Modes {
        insert: false,
        newline: false,
        cursor_keys: false,
        reverse: false,
        origin: false,
        autowrap: true,
        cursor_visible: true,
        keypad: false,
    };
}

/// What DECSC saves for a buffer.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Saved {
    row: usize,
    col: usize,
    pending_wrap: bool,
    pen: Pen,
    g: [Charset; 2],
    gl: usize,
    origin: bool,
}

/// Room for the longest reply, `ESC [ 75 ; 240 R` (9 bytes).
const REPLY_MAX: usize = 16;
/// The bits of the tab stops, one per column.
const TAB_WORDS: usize = MAX_COLS.div_ceil(64);
/// The title's bytes kept: the OSC string's 64 less its `0;` or `2;`.
pub const TITLE_MAX: usize = crate::parser::MAX_OSC - 2;

/// The screen model over two grids of words.
pub struct Screen<'a> {
    cols: usize,
    rows: usize,
    main: &'a mut [u64],
    alt: &'a mut [u64],
    alternate: bool,
    row: usize,
    col: usize,
    pending_wrap: bool,
    style: CursorStyle,
    pen: Pen,
    g: [Charset; 2],
    gl: usize,
    saved: [Option<Saved>; 2],
    top: usize,
    bottom: usize,
    tabs: [u64; TAB_WORDS],
    modes: Modes,
    title: [u8; TITLE_MAX],
    title_len: usize,
    /// The code point the action just before printed, for REP.
    last_print: Option<char>,
    ignored: u64,
}

impl<'a> Screen<'a> {
    /// A screen of `cols` × `rows` cells (1 to [`MAX_COLS`] and
    /// [`MAX_ROWS`]) in its power-on state over `main` and `alt`, each of at
    /// least `cols × rows` words, of which it uses the first `cols × rows`,
    /// row by row.
    pub fn new(cols: usize, rows: usize, main: &'a mut [u64], alt: &'a mut [u64]) -> Screen<'a> {
        assert!((1..=MAX_COLS).contains(&cols) && (1..=MAX_ROWS).contains(&rows));
        assert!(main.len() >= cols * rows && alt.len() >= cols * rows);
        let mut s = Screen {
            cols,
            rows,
            main,
            alt,
            alternate: false,
            row: 0,
            col: 0,
            pending_wrap: false,
            style: CursorStyle::Block,
            pen: Pen::default(),
            g: [Charset::Ascii; 2],
            gl: 0,
            saved: [None; 2],
            top: 0,
            bottom: rows - 1,
            tabs: [0; TAB_WORDS],
            modes: Modes::DEFAULT,
            title: [0; TITLE_MAX],
            title_len: 0,
            last_print: None,
            ignored: 0,
        };
        s.reset();
        s
    }

    pub fn cols(&self) -> usize {
        self.cols
    }

    pub fn rows(&self) -> usize {
        self.rows
    }

    /// The active buffer's cell at `row`, `col`.
    pub fn cell(&self, row: usize, col: usize) -> Cell {
        assert!(row < self.rows && col < self.cols);
        Cell::from_word(self.grid()[row * self.cols + col])
    }

    pub fn cursor(&self) -> Cursor {
        Cursor {
            row: self.row,
            col: self.col,
            pending_wrap: self.pending_wrap,
            visible: self.modes.cursor_visible,
            style: self.style,
        }
    }

    pub fn modes(&self) -> Modes {
        self.modes
    }

    /// Whether the alternate buffer is active.
    pub fn alternate(&self) -> bool {
        self.alternate
    }

    /// The scroll region's top and bottom rows, inclusive.
    pub fn region(&self) -> (usize, usize) {
        (self.top, self.bottom)
    }

    pub fn pen(&self) -> Pen {
        self.pen
    }

    /// The first bytes of the last OSC 0 or 2's text.
    pub fn title(&self) -> &[u8] {
        &self.title[..self.title_len]
    }

    /// The sequences ignored since power-on (term's `Stats` MR3).
    pub fn ignored(&self) -> u64 {
        self.ignored
    }

    /// Whether column `col` holds a tab stop; no column past the screen
    /// does.
    pub fn tab_stop(&self, col: usize) -> bool {
        col < self.cols && self.tabs[col / 64] >> (col % 64) & 1 != 0
    }

    fn grid(&self) -> &[u64] {
        if self.alternate { self.alt } else { self.main }
    }

    fn grid_mut(&mut self) -> &mut [u64] {
        if self.alternate { self.alt } else { self.main }
    }

    /// The blank an erase writes: the pen's background, as `bce` does.
    fn blank(&self) -> u64 {
        Cell::blank(self.pen.bg).word()
    }

    /// Writes `word` into cells `from..to` of the active buffer, counted
    /// row by row.
    fn fill(&mut self, from: usize, to: usize, word: u64) {
        self.grid_mut()[from..to].fill(word);
    }

    fn set_tab(&mut self, col: usize, on: bool) {
        let bit = 1u64 << (col % 64);
        if on {
            self.tabs[col / 64] |= bit;
        } else {
            self.tabs[col / 64] &= !bit;
        }
    }

    /// The power-on state (RIS).
    fn reset(&mut self) {
        self.pen = Pen::default();
        self.modes = Modes::DEFAULT;
        self.style = CursorStyle::Block;
        self.g = [Charset::Ascii; 2];
        self.gl = 0;
        self.saved = [None; 2];
        self.top = 0;
        self.bottom = self.rows - 1;
        self.tabs = [0; TAB_WORDS];
        for col in (0..self.cols).step_by(8) {
            self.set_tab(col, true);
        }
        self.title_len = 0;
        let n = self.cols * self.rows;
        let blank = self.blank();
        self.main[..n].fill(blank);
        self.alt[..n].fill(blank);
        self.alternate = false;
        self.row = 0;
        self.col = 0;
        self.pending_wrap = false;
    }

    // Cursor movement. Every one clears the pending wrap.

    fn goto(&mut self, row: usize, col: usize) {
        self.row = row.min(self.rows - 1);
        self.col = col.min(self.cols - 1);
        self.pending_wrap = false;
    }

    /// Home: row 1, or the region's top with DECOM; column 1.
    fn home(&mut self) {
        let row = if self.modes.origin { self.top } else { 0 };
        self.goto(row, 0);
    }

    /// CUP's and VPA's row: `n` from 1, from the region's top and kept in
    /// it with DECOM.
    fn addressed_row(&self, n: usize) -> usize {
        if self.modes.origin {
            (self.top + n - 1).min(self.bottom)
        } else {
            (n - 1).min(self.rows - 1)
        }
    }

    /// CUU: up `n`, stopping at the region's top unless the cursor started
    /// above it, then at row 1.
    fn up(&mut self, n: usize) {
        let stop = if self.row >= self.top { self.top } else { 0 };
        self.goto(self.row.saturating_sub(n).max(stop), self.col);
    }

    /// CUD: down `n`, stopping at the region's bottom unless the cursor
    /// started below it, then at the last row.
    fn down(&mut self, n: usize) {
        let stop = if self.row <= self.bottom {
            self.bottom
        } else {
            self.rows - 1
        };
        self.goto((self.row + n).min(stop), self.col);
    }

    fn tab_forward(&mut self, n: usize) {
        let mut col = self.col;
        for _ in 0..n {
            match (col + 1..self.cols).find(|&c| self.tab_stop(c)) {
                Some(c) => col = c,
                None => {
                    col = self.cols - 1;
                    break;
                }
            }
        }
        self.goto(self.row, col);
    }

    fn tab_back(&mut self, n: usize) {
        let mut col = self.col;
        for _ in 0..n {
            match (0..col).rev().find(|&c| self.tab_stop(c)) {
                Some(c) => col = c,
                None => {
                    col = 0;
                    break;
                }
            }
        }
        self.goto(self.row, col);
    }

    // Scrolling and lines.

    /// Moves rows `top..=bottom` up `n`, blanks entering at the bottom.
    fn scroll_up_in(&mut self, top: usize, bottom: usize, n: usize) {
        let cols = self.cols;
        let n = n.min(bottom - top + 1);
        let blank = self.blank();
        let grid = self.grid_mut();
        grid.copy_within((top + n) * cols..(bottom + 1) * cols, top * cols);
        grid[(bottom + 1 - n) * cols..(bottom + 1) * cols].fill(blank);
    }

    /// Moves rows `top..=bottom` down `n`, blanks entering at the top.
    fn scroll_down_in(&mut self, top: usize, bottom: usize, n: usize) {
        let cols = self.cols;
        let n = n.min(bottom - top + 1);
        let blank = self.blank();
        let grid = self.grid_mut();
        grid.copy_within(top * cols..(bottom + 1 - n) * cols, (top + n) * cols);
        grid[top * cols..(top + n) * cols].fill(blank);
    }

    /// IND: down one; on the region's bottom row the region scrolls up
    /// instead; on the screen's last row below the region, nothing moves.
    fn index(&mut self) {
        if self.row == self.bottom {
            self.scroll_up_in(self.top, self.bottom, 1);
        } else if self.row + 1 < self.rows {
            self.row += 1;
        }
        self.pending_wrap = false;
    }

    /// RI: up one; on the region's top row the region scrolls down instead.
    fn reverse_index(&mut self) {
        if self.row == self.top {
            self.scroll_down_in(self.top, self.bottom, 1);
        } else if self.row > 0 {
            self.row -= 1;
        }
        self.pending_wrap = false;
    }

    fn in_region(&self) -> bool {
        (self.top..=self.bottom).contains(&self.row)
    }

    // Printing.

    /// How many prints REP `n` needs to leave the state `n` prints of one
    /// code point in one pen would, so that a REP costs at most a few
    /// passes over the screen rather than 65,535 prints.
    ///
    /// Without DECAWM, `cols` prints reach the last column, and every
    /// print after rewrites it the same. With DECAWM, at most `cols` prints
    /// end the cursor's row, then at most `rows - 1` rows of `cols` bring
    /// the cursor to the row it stays on (the region's bottom, or the last
    /// row below the region), and at most `rows` more rows fill the region
    /// with the code point; from there each `cols` prints, a scroll (or
    /// none) and a full row, give the same state again, IRM or not. So past
    /// `cols × (2 × rows + 2)` the state repeats every `cols` prints.
    fn rep_prints(&self, n: usize) -> usize {
        if !self.modes.autowrap {
            return n.min(self.cols);
        }
        let settled = self.cols * (2 * self.rows + 2);
        if n <= settled {
            n
        } else {
            settled + (n - settled) % self.cols
        }
    }

    fn print(&mut self, c: char) {
        let c = if self.g[self.gl] == Charset::DecGraphics {
            dec_graphics(c)
        } else {
            c
        };
        if self.pending_wrap && self.modes.autowrap {
            self.col = 0;
            self.index();
        }
        let cols = self.cols;
        let at = self.row * cols + self.col;
        let end = (self.row + 1) * cols;
        let word = Cell {
            ch: c,
            pen: self.pen,
        }
        .word();
        let insert = self.modes.insert;
        let grid = self.grid_mut();
        if insert {
            grid.copy_within(at..end - 1, at + 1);
        }
        grid[at] = word;
        if self.col + 1 < cols {
            self.col += 1;
            self.pending_wrap = false;
        } else {
            self.pending_wrap = self.modes.autowrap;
        }
        self.last_print = Some(c);
    }

    // Saving the cursor.

    fn save_cursor(&mut self) {
        self.saved[usize::from(self.alternate)] = Some(Saved {
            row: self.row,
            col: self.col,
            pending_wrap: self.pending_wrap,
            pen: self.pen,
            g: self.g,
            gl: self.gl,
            origin: self.modes.origin,
        });
    }

    fn restore_cursor(&mut self) {
        let s = self.saved[usize::from(self.alternate)].unwrap_or(Saved {
            row: 0,
            col: 0,
            pending_wrap: false,
            pen: Pen::default(),
            g: [Charset::Ascii; 2],
            gl: 0,
            origin: false,
        });
        self.pen = s.pen;
        self.g = s.g;
        self.gl = s.gl;
        self.modes.origin = s.origin;
        // With DECOM the cursor stays in the region, as xterm's
        // CursorRestore keeps it there.
        let row = if s.origin {
            s.row.clamp(self.top, self.bottom)
        } else {
            s.row
        };
        self.goto(row, s.col);
        self.pending_wrap = s.pending_wrap && self.col == self.cols - 1;
    }

    // Buffers.

    fn clear_buffer(&mut self) {
        let n = self.cols * self.rows;
        let blank = self.blank();
        self.fill(0, n, blank);
    }

    // Modes.

    /// SM or RM of ANSI mode `mode`; whether term knows it.
    fn ansi_mode(&mut self, mode: u16, on: bool) -> bool {
        match mode {
            4 => self.modes.insert = on,
            20 => self.modes.newline = on,
            _ => return false,
        }
        true
    }

    /// DECSET or DECRST of DEC mode `mode`; whether term knows it.
    fn dec_mode(&mut self, mode: u16, on: bool) -> bool {
        match mode {
            1 => self.modes.cursor_keys = on,
            5 => self.modes.reverse = on,
            6 => {
                self.modes.origin = on;
                self.home();
            }
            7 => self.modes.autowrap = on,
            25 => self.modes.cursor_visible = on,
            // Setting one while the alternate buffer is active, or resetting
            // one while the main is, switches and clears nothing; 1049's
            // DECSC and DECRC act all the same, on the active buffer's.
            47 => self.alternate = on,
            1047 => {
                if !on && self.alternate {
                    self.clear_buffer();
                }
                self.alternate = on;
            }
            1048 => {
                if on {
                    self.save_cursor();
                } else {
                    self.restore_cursor();
                }
            }
            1049 => {
                if on {
                    self.save_cursor();
                    if !self.alternate {
                        self.alternate = true;
                        self.clear_buffer();
                    }
                } else {
                    self.alternate = false;
                    self.restore_cursor();
                }
            }
            _ => return false,
        }
        true
    }

    // SGR.

    /// Applies an SGR; whether any parameter was acted on.
    fn sgr(&mut self, params: &[u16]) -> bool {
        if params.is_empty() {
            self.pen = Pen::default();
            return true;
        }
        let mut acted = false;
        let mut i = 0;
        while i < params.len() {
            let p = params[i];
            i += 1;
            let a = &mut self.pen.attrs;
            match p {
                0 => self.pen = Pen::default(),
                1 => a.insert(Attrs::BOLD),
                2 => a.insert(Attrs::FAINT),
                3 => a.insert(Attrs::ITALIC),
                4 | 21 => a.insert(Attrs::UNDERLINE),
                5 | 6 => a.insert(Attrs::BLINK),
                7 => a.insert(Attrs::INVERSE),
                8 => a.insert(Attrs::CONCEAL),
                9 => a.insert(Attrs::STRIKE),
                22 => {
                    a.remove(Attrs::BOLD);
                    a.remove(Attrs::FAINT);
                }
                23 => a.remove(Attrs::ITALIC),
                24 => a.remove(Attrs::UNDERLINE),
                25 => a.remove(Attrs::BLINK),
                27 => a.remove(Attrs::INVERSE),
                28 => a.remove(Attrs::CONCEAL),
                29 => a.remove(Attrs::STRIKE),
                30..=37 => self.pen.fg = Color::Index((p - 30) as u8),
                39 => self.pen.fg = Color::Default,
                40..=47 => self.pen.bg = Color::Index((p - 40) as u8),
                49 => self.pen.bg = Color::Default,
                90..=97 => self.pen.fg = Color::Index((p - 90 + 8) as u8),
                100..=107 => self.pen.bg = Color::Index((p - 100 + 8) as u8),
                38 | 48 => match extended_color(&params[i..]) {
                    Some((color, used)) => {
                        if p == 38 {
                            self.pen.fg = color;
                        } else {
                            self.pen.bg = color;
                        }
                        i += used;
                    }
                    // A malformed colour ends the SGR.
                    None => break,
                },
                _ => continue,
            }
            acted = true;
        }
        acted
    }

    // The parser's actions.

    fn execute(&mut self, byte: u8) {
        match byte {
            0x08 => self.goto(self.row, self.col.saturating_sub(1)),
            0x09 => self.tab_forward(1),
            0x0A..=0x0C => {
                self.index();
                if self.modes.newline {
                    self.col = 0;
                }
            }
            0x0D => self.goto(self.row, 0),
            0x0E => self.gl = 1,
            0x0F => self.gl = 0,
            // BEL makes no sound; the other C0 controls do nothing.
            _ => {}
        }
    }

    /// An ESC sequence; whether term acts on it.
    fn esc(&mut self, intermediates: &[u8], final_byte: u8) -> bool {
        match (intermediates, final_byte) {
            ([], b'7') => self.save_cursor(),
            ([], b'8') => self.restore_cursor(),
            ([], b'D') => self.index(),
            ([], b'E') => {
                self.col = 0;
                self.index();
            }
            ([], b'H') => self.set_tab(self.col, true),
            ([], b'M') => self.reverse_index(),
            ([], b'c') => self.reset(),
            ([b'#'], b'8') => {
                let n = self.cols * self.rows;
                let e = Cell {
                    ch: 'E',
                    pen: Pen::default(),
                };
                self.fill(0, n, e.word());
                self.top = 0;
                self.bottom = self.rows - 1;
                self.home();
            }
            ([b'('], b'0') => self.g[0] = Charset::DecGraphics,
            ([b'('], b'B') => self.g[0] = Charset::Ascii,
            ([b')'], b'0') => self.g[1] = Charset::DecGraphics,
            ([b')'], b'B') => self.g[1] = Charset::Ascii,
            ([], b'=') => self.modes.keypad = true,
            ([], b'>') => self.modes.keypad = false,
            // ST ends a string; on its own it does nothing.
            ([], b'\\') => {}
            _ => return false,
        }
        true
    }

    /// A control sequence; whether term acts on it.
    fn csi<R: FnMut(&[u8])>(
        &mut self,
        params: &[u16],
        intermediates: &[u8],
        final_byte: u8,
        reply: &mut R,
    ) -> bool {
        // `Pn` defaults to 1 and 0 counts as 1; `Ps` defaults to 0.
        let ps = |i: usize| params.get(i).copied().unwrap_or(0);
        let pn = |i: usize| usize::from(ps(i).max(1));
        let cols = self.cols;
        match (intermediates, final_byte) {
            ([], b'@') => {
                let n = pn(0).min(cols - self.col);
                let at = self.row * cols + self.col;
                let end = (self.row + 1) * cols;
                let blank = self.blank();
                let grid = self.grid_mut();
                grid.copy_within(at..end - n, at + n);
                grid[at..at + n].fill(blank);
                self.pending_wrap = false;
            }
            ([], b'A') => self.up(pn(0)),
            ([], b'B' | b'e') => self.down(pn(0)),
            ([], b'C' | b'a') => self.goto(self.row, self.col.saturating_add(pn(0))),
            ([], b'D') => self.goto(self.row, self.col.saturating_sub(pn(0))),
            ([], b'E') => {
                self.down(pn(0));
                self.col = 0;
            }
            ([], b'F') => {
                self.up(pn(0));
                self.col = 0;
            }
            ([], b'G' | b'`') => self.goto(self.row, pn(0) - 1),
            ([], b'H' | b'f') => {
                let row = self.addressed_row(pn(0));
                self.goto(row, pn(1) - 1);
            }
            ([], b'I') => self.tab_forward(pn(0)),
            ([], b'Z') => self.tab_back(pn(0)),
            ([], b'J') => {
                let n = cols * self.rows;
                let at = self.row * cols + self.col;
                let blank = self.blank();
                match ps(0) {
                    0 => self.fill(at, n, blank),
                    1 => self.fill(0, at + 1, blank),
                    2 => self.fill(0, n, blank),
                    // No scrollback to clear.
                    3 => return true,
                    _ => return false,
                }
                self.pending_wrap = false;
            }
            ([], b'K') => {
                let start = self.row * cols;
                let at = start + self.col;
                let blank = self.blank();
                match ps(0) {
                    0 => self.fill(at, start + cols, blank),
                    1 => self.fill(start, at + 1, blank),
                    2 => self.fill(start, start + cols, blank),
                    _ => return false,
                }
                self.pending_wrap = false;
            }
            ([], b'L' | b'M') => {
                if self.in_region() {
                    if final_byte == b'L' {
                        self.scroll_down_in(self.row, self.bottom, pn(0));
                    } else {
                        self.scroll_up_in(self.row, self.bottom, pn(0));
                    }
                    self.goto(self.row, 0);
                }
            }
            ([], b'P') => {
                let n = pn(0).min(cols - self.col);
                let at = self.row * cols + self.col;
                let end = (self.row + 1) * cols;
                let blank = self.blank();
                let grid = self.grid_mut();
                grid.copy_within(at + n..end, at);
                grid[end - n..end].fill(blank);
                self.pending_wrap = false;
            }
            ([], b'S') => self.scroll_up_in(self.top, self.bottom, pn(0)),
            ([], b'T') => self.scroll_down_in(self.top, self.bottom, pn(0)),
            ([], b'X') => {
                let n = pn(0).min(cols - self.col);
                let at = self.row * cols + self.col;
                let blank = self.blank();
                self.fill(at, at + n, blank);
                self.pending_wrap = false;
            }
            ([], b'b') => {
                // REP acts only straight after a print. The code point is
                // already through the character sets and maps to itself
                // again: nothing between the print and REP changed them.
                if let Some(c) = self.last_print {
                    for _ in 0..self.rep_prints(pn(0)) {
                        self.print(c);
                    }
                }
            }
            ([], b'c') => {
                if ps(0) != 0 {
                    return false;
                }
                reply(b"\x1b[?1;2c");
            }
            ([], b'd') => {
                let row = self.addressed_row(pn(0));
                self.goto(row, self.col);
            }
            ([], b'g') => match ps(0) {
                0 => self.set_tab(self.col, false),
                3 => self.tabs = [0; TAB_WORDS],
                _ => return false,
            },
            ([], b'h' | b'l') => {
                let on = final_byte == b'h';
                let mut acted = false;
                for &p in params_or_zero(params) {
                    acted |= self.ansi_mode(p, on);
                }
                return acted;
            }
            ([b'?'], b'h' | b'l') => {
                let on = final_byte == b'h';
                let mut acted = false;
                for &p in params_or_zero(params) {
                    acted |= self.dec_mode(p, on);
                }
                return acted;
            }
            ([], b'm') => return self.sgr(params),
            ([], b'n') => match ps(0) {
                5 => reply(b"\x1b[0n"),
                6 => {
                    let row = if self.modes.origin {
                        self.row.saturating_sub(self.top)
                    } else {
                        self.row
                    };
                    let mut buf = [0u8; REPLY_MAX];
                    let n = cursor_report(&mut buf, row + 1, self.col + 1);
                    reply(&buf[..n]);
                }
                _ => return false,
            },
            ([], b'r') => {
                let top = pn(0) - 1;
                let bottom = match ps(1) {
                    0 => self.rows - 1,
                    b => (usize::from(b) - 1).min(self.rows - 1),
                };
                if top < bottom {
                    self.top = top;
                    self.bottom = bottom;
                    self.home();
                }
            }
            ([], b's') if params.is_empty() => self.save_cursor(),
            ([], b'u') if params.is_empty() => self.restore_cursor(),
            ([b' '], b'q') => {
                self.style = match ps(0) {
                    0..=2 => CursorStyle::Block,
                    3 | 4 => CursorStyle::Underline,
                    5 | 6 => CursorStyle::Bar,
                    _ => return false,
                }
            }
            _ => return false,
        }
        true
    }

    /// An OSC string's first bytes; whether term acts on it: OSC 0 and 2
    /// set the title to what follows their `;`.
    fn osc(&mut self, string: &[u8]) -> bool {
        let Some(semi) = string.iter().position(|&b| b == b';') else {
            return false;
        };
        let (number, text) = (&string[..semi], &string[semi + 1..]);
        if !matches!(number, b"0" | b"2") {
            return false;
        }
        let n = text.len().min(TITLE_MAX);
        self.title[..n].copy_from_slice(&text[..n]);
        self.title_len = n;
        true
    }
}

/// SM, RM, DECSET and DECRST with no parameter act on mode 0.
fn params_or_zero(params: &[u16]) -> &[u16] {
    if params.is_empty() { &[0] } else { params }
}

/// The colour after an SGR 38 or 48, `5 ; n` or `2 ; r ; g ; b`, and how
/// many parameters it took; `None` if malformed or a value is above 255.
fn extended_color(rest: &[u16]) -> Option<(Color, usize)> {
    let byte = |i: usize| rest.get(i).and_then(|&v| u8::try_from(v).ok());
    match rest.first()? {
        5 => Some((Color::Index(byte(1)?), 2)),
        2 => {
            let (r, g, b) = (byte(1)?, byte(2)?, byte(3)?);
            Some((Color::Index(palette::nearest(r, g, b)), 4))
        }
        _ => None,
    }
}

/// Writes `ESC [ row ; col R` into `buf`; its length.
fn cursor_report(buf: &mut [u8; REPLY_MAX], row: usize, col: usize) -> usize {
    /// Writes `v` in decimal at `buf[at..]`; the index after it.
    fn decimal(buf: &mut [u8], at: usize, v: usize) -> usize {
        let digits = if v >= 100 {
            3
        } else if v >= 10 {
            2
        } else {
            1
        };
        let mut v = v;
        for i in (0..digits).rev() {
            buf[at + i] = b'0' + (v % 10) as u8;
            v /= 10;
        }
        at + digits
    }
    buf[..2].copy_from_slice(b"\x1b[");
    let n = decimal(buf, 2, row);
    buf[n] = b';';
    let n = decimal(buf, n + 1, col);
    buf[n] = b'R';
    n + 1
}

/// The DEC Special Graphics character for `c`, `0x5F` to `0x7E`; any other
/// code point is unchanged.
pub const fn dec_graphics(c: char) -> char {
    match c {
        '_' => '\u{A0}',
        '`' => '\u{25C6}',
        'a' => '\u{2592}',
        'b' => '\u{2409}',
        'c' => '\u{240C}',
        'd' => '\u{240D}',
        'e' => '\u{240A}',
        'f' => '\u{B0}',
        'g' => '\u{B1}',
        'h' => '\u{2424}',
        'i' => '\u{240B}',
        'j' => '\u{2518}',
        'k' => '\u{2510}',
        'l' => '\u{250C}',
        'm' => '\u{2514}',
        'n' => '\u{253C}',
        'o' => '\u{23BA}',
        'p' => '\u{23BB}',
        'q' => '\u{2500}',
        'r' => '\u{23BC}',
        's' => '\u{23BD}',
        't' => '\u{251C}',
        'u' => '\u{2524}',
        'v' => '\u{2534}',
        'w' => '\u{252C}',
        'x' => '\u{2502}',
        'y' => '\u{2264}',
        'z' => '\u{2265}',
        '{' => '\u{3C0}',
        '|' => '\u{2260}',
        '}' => '\u{A3}',
        '~' => '\u{B7}',
        c => c,
    }
}

/// The screen model and the reply sink, as the parser's [`Actions`].
pub(crate) struct Perform<'s, 'a, R> {
    pub screen: &'s mut Screen<'a>,
    pub reply: &'s mut R,
}

impl<R: FnMut(&[u8])> Actions for Perform<'_, '_, R> {
    fn print(&mut self, c: char) {
        self.screen.print(c);
    }

    fn execute(&mut self, byte: u8) {
        self.screen.execute(byte);
        self.screen.last_print = None;
    }

    fn esc_dispatch(&mut self, intermediates: &[u8], final_byte: u8) {
        if !self.screen.esc(intermediates, final_byte) {
            self.screen.ignored += 1;
        }
        self.screen.last_print = None;
    }

    fn csi_dispatch(&mut self, params: &[u16], intermediates: &[u8], final_byte: u8) {
        if !self
            .screen
            .csi(params, intermediates, final_byte, &mut *self.reply)
        {
            self.screen.ignored += 1;
        }
        self.screen.last_print = None;
    }

    fn osc_dispatch(&mut self, string: &[u8]) {
        if !self.screen.osc(string) {
            self.screen.ignored += 1;
        }
        self.screen.last_print = None;
    }

    fn ignored(&mut self) {
        self.screen.ignored += 1;
        self.screen.last_print = None;
    }
}
