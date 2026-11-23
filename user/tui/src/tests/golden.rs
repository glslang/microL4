//! tui's goldens (`docs/design.md`, "Golden tests", "tui's goldens"):
//! `user/tui/golden/<name>-<cols>x<rows>.golden`, every panel at 160 x 50
//! and the `tui` scenario's three moments (`main`, `colours` and `quit`)
//! at 160 x 50 and 128 x 48, in term's golden format with `keys:` lines in
//! place of `input:`: each `keys:` line is one `Read`'s bytes, which `App`
//! turns into frames, after its start.
//!
//! Each case's bytes, `App`'s whole output, go to `term::Terminal` in the
//! `Write`s `run` makes (each step's bytes, at most 952 at a time), and the
//! screen term's model leaves must be the file's: the grid, the attributes
//! and their keys, the cursor, the buffer and the lines term's goldens add
//! (`modes:`, `region:`). term must ignore nothing, after any frame: tui
//! uses only sequences term acts on. The same bytes also go through the
//! reference model of the sequences tui writes (`screen`), written apart
//! from term, which must leave the same screen: so a change in term that
//! moves tui's screens fails here, rather than being blessed into the
//! files unnoticed, until the reference model is changed to match.
//!
//! `MICROL4_BLESS=1` rewrites a failing case's expectation from term's
//! screen, keeping its comment, `size:` and `keys:` lines, and naming keys
//! in the order cells first use them; the commit's diff of the cases is
//! what the reviewer checks. It never blesses a case the two models
//! disagree on. Skipped under Miri, which cannot read files.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::string::String;
use std::vec::Vec;
use std::{format, println, vec};

use term::screen::{Color, CursorStyle, Modes};

use super::Run;
use super::screen::{ATTRS, Screen, Shape, Style};

/// The cases, each a file `<name>.golden`.
const CASES: [&str; 9] = [
    "main-160x50",
    "attributes-160x50",
    "colours-160x50",
    "boxes-160x50",
    "keys-160x50",
    "quit-160x50",
    "main-128x48",
    "colours-128x48",
    "quit-128x48",
];

/// The most bytes one term `Write` carries, `libsys::proto::MAX_BYTES`:
/// `run` gathers a step's bytes into `Write`s of this size.
const WRITE: usize = 952;

fn dir() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("golden")
}

/// A case's lines kept as written: its comment, `size:` and `keys:`.
struct Case {
    head: Vec<String>,
    cols: usize,
    rows: usize,
    keys: Vec<Vec<u8>>,
    /// Everything after `keys:`: what the screen must be.
    expected: String,
}

/// Unescapes a `keys:` line as the harness's `send:` is: `\e`, `\r`,
/// `\n`, `\t`, `\\` and `\xHH`.
fn unescape(s: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut it = s.bytes();
    while let Some(b) = it.next() {
        if b != b'\\' {
            out.push(b);
            continue;
        }
        match it.next() {
            Some(b'e') => out.push(0x1B),
            Some(b'r') => out.push(b'\r'),
            Some(b'n') => out.push(b'\n'),
            Some(b't') => out.push(b'\t'),
            Some(b'\\') => out.push(b'\\'),
            Some(b'x') => {
                let h: Vec<u8> = it.by_ref().take(2).collect();
                let h = core::str::from_utf8(&h).map_err(|_| "bad \\x")?;
                out.push(u8::from_str_radix(h, 16).map_err(|_| format!("bad \\x{h}"))?);
            }
            e => return Err(format!("unknown escape {e:?}")),
        }
    }
    Ok(out)
}

fn parse(text: &str) -> Result<Case, String> {
    let mut head = Vec::new();
    let mut size = None;
    let mut keys = Vec::new();
    let mut lines = text.lines().peekable();
    while let Some(l) = lines.next_if(|l| l.starts_with('#')) {
        head.push(l.into());
    }
    while let Some(l) = lines.next_if(|l| l.starts_with("size:") || l.starts_with("keys:")) {
        head.push(l.into());
        if let Some(s) = l.strip_prefix("size:") {
            let (c, r) = s.trim().split_once('x').ok_or("size: <cols>x<rows>")?;
            let c: usize = c.parse().map_err(|_| "size: columns")?;
            let r: usize = r.parse().map_err(|_| "size: rows")?;
            size = Some((c, r));
        } else {
            keys.push(unescape(l["keys:".len()..].trim())?);
        }
    }
    let (cols, rows) = size.ok_or("no size: line")?;
    let rest: Vec<&str> = lines.collect();
    let expected = if rest.is_empty() {
        String::new()
    } else {
        rest.join("\n") + "\n"
    };
    Ok(Case {
        head,
        cols,
        rows,
        keys,
        expected,
    })
}

/// The `i`th attribute key: letters, digits, then punctuation and Latin,
/// Greek and Cyrillic letters, never a space or `|`, for the Colours
/// panel's hundreds of styles.
fn key_char(i: usize) -> char {
    const ASCII: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!\"#$%&'()*+,-./:;<=>?@[\\]^_`{}~";
    let ascii: Vec<char> = ASCII.chars().collect();
    if i < ascii.len() {
        return ascii[i];
    }
    let more = (0xC0..=0x17Fu32)
        .filter(|&c| c != 0xD7 && c != 0xF7)
        .chain(0x391..=0x3A9)
        .chain(0x3B1..=0x3C9)
        .chain(0x410..=0x44F)
        .filter_map(char::from_u32)
        .filter(|c| c.is_alphabetic());
    more.into_iter()
        .nth(i - ascii.len())
        .expect("enough attribute keys")
}

fn words(s: &Style) -> String {
    let mut w: Vec<String> = ATTRS
        .iter()
        .filter(|(bit, _)| s.attrs & bit != 0)
        .map(|(_, name)| (*name).into())
        .collect();
    if let Some(fg) = s.fg {
        w.push(format!("fg {fg}"));
    }
    if let Some(bg) = s.bg {
        w.push(format!("bg {bg}"));
    }
    w.join(" ")
}

/// A `reply:` or `title:` value as term's goldens write it: printable
/// ASCII as itself (a space at either end as `\x20`), `\e`, `\r`, `\n`,
/// `\t`, `\\`, and `\xHH` for the rest.
fn escape(bytes: &[u8]) -> String {
    let mut s = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        let end = i == 0 || i + 1 == bytes.len();
        match b {
            0x1B => s.push_str("\\e"),
            b'\r' => s.push_str("\\r"),
            b'\n' => s.push_str("\\n"),
            b'\t' => s.push_str("\\t"),
            b'\\' => s.push_str("\\\\"),
            b' ' if end => s.push_str("\\x20"),
            0x20..=0x7E => s.push(char::from(b)),
            _ => s.push_str(&format!("\\x{b:02x}")),
        }
    }
    s
}

/// Everything a case's expectation shows, from either model.
#[derive(Clone, Debug, PartialEq, Eq)]
struct Snapshot {
    cols: usize,
    rows: usize,
    cells: Vec<(char, Style)>,
    /// The cursor, from 0.
    row: usize,
    col: usize,
    hidden: bool,
    wrap: bool,
    shape: Shape,
    alternate: bool,
    reply: Vec<u8>,
    title: Vec<u8>,
    ignored: u64,
    /// The modes `modes:` names, away from their defaults.
    modes: Vec<&'static str>,
    /// The region, from 0, if it is not the whole screen.
    region: Option<(usize, usize)>,
}

fn style(pen: term::screen::Pen) -> Style {
    let colour = |c| match c {
        Color::Default => None,
        Color::Index(n) => Some(n),
    };
    Style {
        fg: colour(pen.fg),
        bg: colour(pen.bg),
        attrs: pen.attrs.0,
    }
}

/// The modes term's goldens name in `modes:`, in their order, when away
/// from their defaults; DECTCEM shows in `cursor:` instead.
fn mode_words(m: &Modes) -> Vec<&'static str> {
    let d = Modes::DEFAULT;
    [
        (m.insert != d.insert, "insert"),
        (m.newline != d.newline, "newline"),
        (m.cursor_keys != d.cursor_keys, "cursor-keys"),
        (m.reverse != d.reverse, "reverse"),
        (m.origin != d.origin, "origin"),
        (m.autowrap != d.autowrap, "no-autowrap"),
        (m.keypad != d.keypad, "keypad"),
    ]
    .iter()
    .filter(|(on, _)| *on)
    .map(|&(_, w)| w)
    .collect()
}

impl Snapshot {
    fn of_term(t: &term::Terminal<'_>, reply: Vec<u8>) -> Snapshot {
        let s = t.screen();
        let (cols, rows) = (s.cols(), s.rows());
        let mut cells = Vec::with_capacity(cols * rows);
        for r in 0..rows {
            for c in 0..cols {
                let cell = s.cell(r, c);
                cells.push((cell.ch, style(cell.pen)));
            }
        }
        let cur = s.cursor();
        let (top, bottom) = s.region();
        Snapshot {
            cols,
            rows,
            cells,
            row: cur.row,
            col: cur.col,
            hidden: !cur.visible,
            wrap: cur.pending_wrap,
            shape: match cur.style {
                CursorStyle::Block => Shape::Block,
                CursorStyle::Underline => Shape::Underline,
                CursorStyle::Bar => Shape::Bar,
            },
            alternate: s.alternate(),
            reply,
            title: s.title().to_vec(),
            ignored: s.ignored(),
            modes: mode_words(&s.modes()),
            region: (top != 0 || bottom != rows - 1).then_some((top, bottom)),
        }
    }

    /// The reference model has no replies, title, ignored sequences or
    /// other modes: it panics on any sequence that would make them.
    fn of_reference(s: &Screen) -> Snapshot {
        let mut cells = Vec::with_capacity(s.cols * s.rows);
        for r in 0..s.rows {
            for c in 0..s.cols {
                let cell = s.cell(r, c);
                cells.push((cell.ch, cell.style));
            }
        }
        Snapshot {
            cols: s.cols,
            rows: s.rows,
            cells,
            row: s.row,
            col: s.col,
            hidden: !s.visible,
            wrap: s.wrap,
            shape: s.shape,
            alternate: s.alternate,
            reply: Vec::new(),
            title: Vec::new(),
            ignored: 0,
            modes: Vec::new(),
            region: (s.top != 0 || s.bottom != s.rows - 1).then_some((s.top, s.bottom)),
        }
    }

    /// The expectation, in term's golden format and its order: `screen:`;
    /// `attrs:` and `key:` lines if any cell is not default; `cursor:`;
    /// then, each only when away from its default, `buffer: alternate`,
    /// `reply:`, `title:`, `ignored:`, `modes:` and `region:`.
    fn expectation(&self) -> String {
        let mut out = String::from("screen:\n");
        for row in self.cells.chunks(self.cols) {
            out.push('|');
            out.extend(row.iter().map(|c| c.0));
            out.push_str("|\n");
        }
        let mut keys: Vec<Style> = Vec::new();
        let mut index: HashMap<Style, char> = HashMap::new();
        let mut attrs = String::new();
        for row in self.cells.chunks(self.cols) {
            attrs.push('|');
            for &(_, st) in row {
                if st == Style::default() {
                    attrs.push(' ');
                } else {
                    let n = keys.len();
                    let c = *index.entry(st).or_insert_with(|| {
                        keys.push(st);
                        key_char(n)
                    });
                    attrs.push(c);
                }
            }
            attrs.push_str("|\n");
        }
        if !keys.is_empty() {
            out.push_str("attrs:\n");
            out.push_str(&attrs);
            for st in &keys {
                out.push_str(&format!("key: {} = {}\n", index[st], words(st)));
            }
        }
        let mut cursor = format!("cursor: {},{}", self.row + 1, self.col + 1);
        if self.hidden {
            cursor.push_str(" hidden");
        }
        if self.wrap {
            cursor.push_str(" wrap");
        }
        match self.shape {
            Shape::Block => {}
            Shape::Underline => cursor.push_str(" underline"),
            Shape::Bar => cursor.push_str(" bar"),
        }
        out.push_str(&cursor);
        out.push('\n');
        if self.alternate {
            out.push_str("buffer: alternate\n");
        }
        // tui never makes term reply, set a title or ignore a sequence;
        // the lines are written only so a case shows it if it did.
        if !self.reply.is_empty() {
            out.push_str(&format!("reply: {}\n", escape(&self.reply)));
        }
        if !self.title.is_empty() {
            out.push_str(&format!("title: {}\n", escape(&self.title)));
        }
        if self.ignored != 0 {
            out.push_str(&format!("ignored: {}\n", self.ignored));
        }
        if !self.modes.is_empty() {
            out.push_str(&format!("modes: {}\n", self.modes.join(" ")));
        }
        if let Some((top, bottom)) = self.region {
            out.push_str(&format!("region: {},{}\n", top + 1, bottom + 1));
        }
        out
    }
}

/// `run`'s output through term's screen model, in its `Write`s: the
/// screen it leaves, and each frame after which term had ignored a
/// sequence, with the count.
fn on_term(cols: usize, rows: usize, outputs: &[&[u8]]) -> (Snapshot, Vec<(usize, u64)>) {
    let mut main = vec![0u64; cols * rows];
    let mut alt = vec![0u64; cols * rows];
    let mut t = term::Terminal::new(cols, rows, &mut main, &mut alt);
    let mut reply = Vec::new();
    let mut ignored = Vec::new();
    for (frame, out) in outputs.iter().enumerate() {
        for w in out.chunks(WRITE) {
            t.write(w, |r| reply.extend_from_slice(r));
        }
        let n = t.screen().ignored();
        if n != 0 {
            ignored.push((frame, n));
        }
    }
    (Snapshot::of_term(&t, reply), ignored)
}

/// The first rows where two expectations differ, side by side.
fn diff(want: &str, got: &str) -> String {
    let (w, g): (Vec<&str>, Vec<&str>) = (want.lines().collect(), got.lines().collect());
    let mut out = String::new();
    let mut shown = 0;
    for i in 0..w.len().max(g.len()) {
        let (a, b) = (
            w.get(i).copied().unwrap_or(""),
            g.get(i).copied().unwrap_or(""),
        );
        if a != b && shown < 12 {
            out.push_str(&format!("  line {}:\n    want {a}\n    got  {b}\n", i + 1));
            shown += 1;
        }
    }
    out
}

#[test]
#[cfg_attr(miri, ignore = "Miri cannot read files")]
fn the_panels_and_the_scenario_s_moments() {
    let bless = std::env::var_os("MICROL4_BLESS").is_some_and(|v| v == "1");
    let mut failures = Vec::new();
    for name in CASES {
        let path = dir().join(format!("{name}.golden"));
        let text = fs::read_to_string(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
        let case = parse(&text).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert!(
            name.ends_with(&format!("-{}x{}", case.cols, case.rows)),
            "{name}: its size: line"
        );
        let mut run = Run::new(case.cols as u64, case.rows as u64);
        for k in &case.keys {
            run.read(k);
        }
        let (term, ignored) = on_term(case.cols, case.rows, &run.outputs());
        for (frame, n) in ignored {
            failures.push(format!(
                "{name}: term had ignored {n} sequences after step {frame} (0 is the start)"
            ));
        }
        let got = term.expectation();
        let reference = Snapshot::of_reference(&run.screen());
        let agree = reference == term;
        if !agree {
            failures.push(format!(
                "{name}: term and the reference model disagree (left term, right the reference):\n{}",
                diff(&got, &reference.expectation())
            ));
        }
        if got == case.expected {
            continue;
        }
        if bless && agree {
            let mut out = case.head.join("\n");
            out.push('\n');
            out.push_str(&got);
            fs::write(&path, out).unwrap();
            println!("blessed {name}");
        } else if case.expected.is_empty() {
            failures.push(format!("{name}: no expectation (screen:, cursor:)"));
        } else {
            failures.push(format!("{name}:\n{}", diff(&case.expected, &got)));
        }
    }
    assert!(failures.is_empty(), "{}", failures.join("\n"));
}

/// The format's parts on a small screen, from both models.
#[test]
fn the_format_on_a_small_screen() {
    let bytes = "\x1b[1;31mab\x1b[0m\x1b[44m\x1b[K\r\n\x1b(0q\x1b(B\x1b[?25l\x1b[1;2r".as_bytes();
    let mut s = Screen::new(4, 3);
    s.write(bytes);
    let (t, ignored) = on_term(4, 3, &[bytes]);
    assert!(ignored.is_empty());
    assert_eq!(
        t.expectation(),
        "screen:\n|ab  |\n|─   |\n|    |\nattrs:\n|AABB|\n|B   |\n|    |\n\
         key: A = bold fg 1\nkey: B = bg 4\ncursor: 1,1 hidden\nregion: 1,2\n"
    );
    assert_eq!(Snapshot::of_reference(&s), t);
    // What tui never sends shows: an ignored sequence and a mode.
    let (t, ignored) = on_term(4, 3, &[b"\x1b[4h", b"\x1b[?999h"]);
    assert_eq!(ignored, [(1, 1)]);
    assert!(
        t.expectation()
            .ends_with("cursor: 1,1\nignored: 1\nmodes: insert\n"),
        "{}",
        t.expectation()
    );
    assert_eq!(unescape("\\e[B\\r\\x41\\\\").unwrap(), b"\x1b[B\rA\\");
    let c = parse("# a\nsize: 4x2\nkeys: q\nscreen:\n").unwrap();
    assert_eq!((c.cols, c.rows, c.keys.len()), (4, 2, 1));
    assert_eq!(c.expected, "screen:\n");
    // Keys never collide with the grid's frame or a blank.
    let all: Vec<char> = (0..380).map(key_char).collect();
    assert!(!all.contains(&' ') && !all.contains(&'|'));
    let mut sorted = all.clone();
    sorted.sort();
    sorted.dedup();
    assert_eq!(sorted.len(), all.len());
}

/// A frame is cut into `Write`s of at most 952 bytes, as `run` sends it.
#[test]
fn a_frame_goes_to_term_in_writes_of_952_bytes() {
    let r = Run::new(80, 24);
    let start = r.outputs()[0];
    assert!(start.len() > WRITE, "{} bytes", start.len());
    let writes: Vec<usize> = start.chunks(WRITE).map(<[u8]>::len).collect();
    assert!(writes[..writes.len() - 1].iter().all(|&n| n == WRITE));
}
