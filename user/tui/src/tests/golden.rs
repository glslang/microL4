//! tui's goldens (`docs/design.md`, "Golden tests", "tui's goldens"):
//! `user/tui/golden/<name>-<cols>x<rows>.golden`, every panel at 160 x 50
//! and the `tui` scenario's three moments (`main`, `colours` and `quit`)
//! at 160 x 50 and 128 x 48, in term's golden format with `keys:` lines in
//! place of `input:`: each `keys:` line is one `Read`'s bytes, which `App`
//! turns into frames, after its start.
//!
//! Each case's bytes, `App`'s whole output, go through the reference model
//! of the sequences tui writes (`screen`), and the screen it leaves must
//! be the file's: the grid, the attributes and their keys, the cursor and
//! the buffer. `MICROL4_BLESS=1` rewrites a failing case's expectation
//! from the result, keeping its comment, `size:` and `keys:` lines, and
//! naming keys in the order cells first use them; the commit's diff of the
//! cases is what the reviewer checks.
//!
//! term's screen model checks the same files once `term` is a
//! dev-dependency here: feed each case's bytes to `term::Terminal` too
//! and compare its screen with the same expectation, so the goldens rest
//! on two models written apart (the lead's step; see the report).
//! Skipped under Miri, which cannot read files.

use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::string::String;
use std::vec::Vec;
use std::{format, println};

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

/// The expectation for a screen: `screen:`, `attrs:` and `key:` lines if
/// any cell is not default, `cursor:`, and `buffer: alternate` if it is
/// active.
fn expectation(s: &Screen) -> String {
    let mut out = String::from("screen:\n");
    for row in 0..s.rows {
        out.push('|');
        out.extend((0..s.cols).map(|c| s.cell(row, c).ch));
        out.push_str("|\n");
    }
    let mut keys: Vec<Style> = Vec::new();
    let mut index: HashMap<Style, char> = HashMap::new();
    let mut attrs = String::new();
    for row in 0..s.rows {
        attrs.push('|');
        for col in 0..s.cols {
            let st = s.cell(row, col).style;
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
    let mut cursor = format!("cursor: {},{}", s.row + 1, s.col + 1);
    if !s.visible {
        cursor.push_str(" hidden");
    }
    if s.wrap {
        cursor.push_str(" wrap");
    }
    match s.shape {
        Shape::Block => {}
        Shape::Underline => cursor.push_str(" underline"),
        Shape::Bar => cursor.push_str(" bar"),
    }
    out.push_str(&cursor);
    out.push('\n');
    if s.alternate {
        out.push_str("buffer: alternate\n");
    }
    out
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
        let got = expectation(&run.screen());
        if got == case.expected {
            continue;
        }
        if bless {
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

/// The format's parts on a small screen.
#[test]
fn the_format_on_a_small_screen() {
    let mut s = Screen::new(4, 2);
    s.write("\x1b[1;31mab\x1b[0m\x1b[44m\x1b[K\r\n\x1b(0q\x1b(B\x1b[?25l".as_bytes());
    assert_eq!(
        expectation(&s),
        "screen:\n|ab  |\n|─   |\nattrs:\n|AABB|\n|B   |\nkey: A = bold fg 1\nkey: B = bg 4\ncursor: 2,2 hidden\n"
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
