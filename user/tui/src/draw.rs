//! Writing escape sequences and text: [`D`] puts bytes on an [`Out`],
//! [`Line`] a run of cells of a fixed width, cutting text at its end and
//! padding it with blanks. Only the sequences term acts on are written
//! (`docs/design.md`, "`tui`"): CR and LF, CUP, EL, ED 2, SGR, DECSTBM,
//! DECTCEM, DECSCUSR, mode 1049 and SCS `ESC ( 0` and `ESC ( B`.

use core::fmt;

use crate::Out;

/// Blanks to pad with, enough for any row term draws.
const BLANKS: &str = match core::str::from_utf8(&[b' '; 240]) {
    Ok(s) => s,
    Err(_) => panic!(),
};

/// The bytes of a frame, on their way to term.
pub struct D<'a>(pub &'a mut dyn Out);

impl D<'_> {
    pub fn s(&mut self, s: &str) {
        self.0.put(s.as_bytes());
    }

    /// Formatted text or sequences.
    pub fn f(&mut self, args: fmt::Arguments<'_>) {
        // Writing to an `Out` cannot fail.
        let _ = fmt::Write::write_fmt(self, args);
    }

    /// CUP: row and column, from 1.
    pub fn cup(&mut self, row: u16, col: u16) {
        self.f(format_args!("\x1b[{row};{col}H"));
    }

    /// `s`, `n` times.
    pub fn rep(&mut self, s: &str, n: usize) {
        for _ in 0..n {
            self.s(s);
        }
    }

    /// `n` blanks.
    pub fn blanks(&mut self, mut n: usize) {
        while n > 0 {
            let k = n.min(BLANKS.len());
            self.s(&BLANKS[..k]);
            n -= k;
        }
    }
}

impl fmt::Write for D<'_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.s(s);
        Ok(())
    }
}

/// A run of `width` cells from the cursor: text past the width is cut,
/// sequences always go out, and [`Line::finish`] turns every attribute
/// off and pads the rest with blanks. A line that selects DEC Special
/// Graphics selects ASCII again itself. Every character here takes one
/// cell, as in term.
pub struct Line<'d, 'a> {
    d: &'d mut D<'a>,
    width: usize,
    used: usize,
}

impl<'d, 'a> Line<'d, 'a> {
    pub fn new(d: &'d mut D<'a>, width: usize) -> Line<'d, 'a> {
        Line { d, width, used: 0 }
    }

    /// Text, cut at the line's end.
    pub fn t(&mut self, s: &str) {
        let room = self.width - self.used;
        let (end, n) = match s.char_indices().nth(room) {
            Some((i, _)) => (i, room),
            None => (s.len(), s.chars().count()),
        };
        self.d.s(&s[..end]);
        self.used += n;
    }

    /// A sequence: no cells.
    pub fn e(&mut self, s: &str) {
        self.d.s(s);
    }

    /// A formatted sequence.
    pub fn ef(&mut self, args: fmt::Arguments<'_>) {
        self.d.f(args);
    }

    /// Formatted text, cut as [`t`](Self::t) cuts.
    pub fn tf(&mut self, args: fmt::Arguments<'_>) {
        let _ = fmt::Write::write_fmt(self, args);
    }

    /// Blanks up to cell `col` of the line, from 0, in the current pen.
    pub fn to(&mut self, col: usize) {
        let col = col.min(self.width);
        if col > self.used {
            self.d.blanks(col - self.used);
            self.used = col;
        }
    }

    /// Every attribute off, then blanks to the end.
    pub fn finish(self) {
        self.d.s("\x1b[0m");
        self.d.blanks(self.width - self.used);
    }
}

impl fmt::Write for Line<'_, '_> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.t(s);
        Ok(())
    }
}

/// The decimal digits of `n`.
pub const fn digits(mut n: u64) -> usize {
    let mut d = 1;
    while n >= 10 {
        n /= 10;
        d += 1;
    }
    d
}
