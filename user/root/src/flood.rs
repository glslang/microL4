//! `test=release`'s flood (M9; `docs/design.md`, "The M9 Hyper-V check"):
//! with the command line's `release.flood=<n>`, `n` from 1 to 64, root
//! prints `n` numbered lines right after its summary, back to back, each
//! of which a scenario checks whole with `next:`. At 32 lines that is
//! 2,400 bytes, more than uart's 2,048-byte transmit queue, so uart holds
//! console's writes and keeps its FIFO fed, as root's summary did when the
//! M8 Hyper-V runs lost bytes.

use core::fmt;

/// The 52 characters a line ends with, before its rotation: `0`-`9`,
/// `a`-`z`, `A`-`P`.
pub const ALPHABET: &str = "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP";

/// The command line's `release.flood=<n>`. Its `Display` is the line root
/// prints for a word it ignores.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Flood<'a> {
    /// No `release.flood=` word: no flood.
    Absent,
    /// `n` lines, decimal, from 1 to [`Flood::MAX`].
    Lines(u32),
    /// Any other value, which root ignores.
    Ignored(&'a str),
}

impl<'a> Flood<'a> {
    /// The word's key.
    pub const KEY: &'static str = "release.flood";
    /// The most lines a flood has.
    pub const MAX: u32 = 64;

    /// The first `release.flood=` word of `cmdline`, as
    /// `l4core::cmdline` finds it.
    pub fn parse(cmdline: &'a str) -> Flood<'a> {
        let Some(v) = libsys::cmdline::value(cmdline, Self::KEY) else {
            return Flood::Absent;
        };
        let decimal = !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit());
        match decimal
            .then(|| v.parse().ok())
            .flatten()
            .filter(|n| (1..=Self::MAX).contains(n))
        {
            Some(n) => Flood::Lines(n),
            None => Flood::Ignored(v),
        }
    }

    /// Its lines, in order: none unless the word gave a count.
    pub fn lines(self) -> impl Iterator<Item = Line> {
        let n = match self {
            Flood::Lines(n) => n,
            Flood::Absent | Flood::Ignored(_) => 0,
        };
        (1..=n).map(move |i| Line { i, n })
    }
}

impl fmt::Display for Flood<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let key = Self::KEY;
        match *self {
            Flood::Absent => write!(f, "no {key}= word: no flood"),
            Flood::Lines(n) => write!(f, "{key}={n}: {n} lines"),
            Flood::Ignored(v) => write!(
                f,
                "{key}={v:?} ignored: not a number from 1 to {}",
                Self::MAX
            ),
        }
    }
}

/// Line `i` of a flood of `n`: `release: flood <i>/<n> ` and
/// [`ALPHABET`] rotated left by `i`, with `i` zero-padded to `n`'s width,
/// so every line of a flood has one length: 73 characters at 32 lines,
/// 75 bytes with console's CR LF.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Line {
    pub i: u32,
    pub n: u32,
}

impl fmt::Display for Line {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let width = self.n.checked_ilog10().unwrap_or(0) as usize + 1;
        let r = self.i as usize % ALPHABET.len();
        write!(
            f,
            "release: flood {:0width$}/{} {}{}",
            self.i,
            self.n,
            &ALPHABET[r..],
            &ALPHABET[..r]
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::string::{String, ToString};
    use std::vec::Vec;

    #[test]
    fn release_flood_takes_1_to_64_and_ignores_the_rest() {
        for line in [
            "",
            "test=release",
            "release.floodx=1 flood=1 test=release.flood=1",
        ] {
            assert_eq!(Flood::parse(line), Flood::Absent, "{line:?}");
            assert_eq!(Flood::parse(line).lines().count(), 0);
        }
        for n in 1..=64 {
            let line = format!("test=release uart.burst=1 release.flood={n}");
            assert_eq!(Flood::parse(&line), Flood::Lines(n), "{line:?}");
            assert_eq!(Flood::parse(&line).lines().count(), n as usize);
        }
        assert_eq!(Flood::parse("release.flood=032"), Flood::Lines(32));
        assert_eq!(
            Flood::parse("release.flood=32 release.flood=99"),
            Flood::Lines(32)
        );
        assert_eq!(
            Flood::parse("release.flood=99 release.flood=32"),
            Flood::Ignored("99")
        );
        for v in [
            "",
            "0",
            "00",
            "65",
            "100",
            "-1",
            "+1",
            "1.0",
            "0x20",
            "32,",
            "many",
            "4294967296",
            "99999999999999999999999",
        ] {
            let line = format!("test=release release.flood={v}");
            assert_eq!(Flood::parse(&line), Flood::Ignored(v), "{line:?}");
            assert_eq!(Flood::parse(&line).lines().count(), 0);
        }
        assert_eq!(Flood::parse("release.flood"), Flood::Ignored(""));
    }

    #[test]
    fn release_floods_lines() {
        let lines: Vec<String> = Flood::Lines(32).lines().map(|l| l.to_string()).collect();
        assert_eq!(lines.len(), 32);
        assert_eq!(
            lines[0],
            "release: flood 01/32 123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0"
        );
        assert_eq!(
            lines[9],
            "release: flood 10/32 abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0123456789"
        );
        assert_eq!(
            lines[31],
            "release: flood 32/32 wxyzABCDEFGHIJKLMNOP0123456789abcdefghijklmnopqrstuv"
        );
        // 75 bytes each with CR LF, 2,400 in all: more than uart's queue.
        assert!(lines.iter().all(|l| l.len() == 73), "{lines:?}");
        let bytes: usize = lines.iter().map(|l| l.len() + 2).sum();
        assert_eq!(bytes, 2400);
        assert!(bytes > uart::TX_QUEUE);
        // Each line is its own: none is another's, nor starts another.
        for (a, la) in lines.iter().enumerate() {
            for lb in &lines[..a] {
                assert!(!la.starts_with(lb.as_str()) && !lb.starts_with(la.as_str()));
            }
            assert_eq!(&la[21..], &rotated(a + 1));
        }
        // The width is n's.
        assert_eq!(
            Line { i: 3, n: 5 }.to_string(),
            "release: flood 3/5 3456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP012"
        );
        assert_eq!(
            Line { i: 52, n: 64 }.to_string(),
            format!("release: flood 52/64 {ALPHABET}")
        );
        assert_eq!(
            Line { i: 64, n: 64 }.to_string(),
            format!("release: flood 64/64 {}", rotated(64))
        );
    }

    /// [`ALPHABET`] rotated left by `i`, character by character.
    fn rotated(i: usize) -> String {
        let chars: Vec<char> = ALPHABET.chars().collect();
        (0..chars.len())
            .map(|j| chars[(i + j) % chars.len()])
            .collect()
    }

    #[test]
    fn release_floods_ignored_line() {
        let line = |cmdline: &str| format!("release: {}", Flood::parse(cmdline));
        assert_eq!(
            line("test=release release.flood=65"),
            "release: release.flood=\"65\" ignored: not a number from 1 to 64"
        );
        assert_eq!(
            line("release.flood=32"),
            "release: release.flood=32: 32 lines"
        );
        assert_eq!(line(""), "release: no release.flood= word: no flood");
    }
}
