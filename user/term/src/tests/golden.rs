//! The golden screens (`docs/design.md`, "Golden tests"): every case under
//! `user/term/golden/<group>/*.golden` runs four ways, one `Write` per
//! `input:` line, all of it in one `Write`, one byte per `Write`, and split
//! at points drawn from a generator seeded with the file's name. Each run
//! must give the expected state, and after each run the looks drawn frame by
//! frame, one frame after every `Write`, must equal the final state's full
//! render. `MICROL4_BLESS=1` rewrites the expected lines of each failing
//! case whose four runs agree, keeping its comment, `size:` and `input:`
//! lines.
//!
//! The format is the note's, with two lines added for state no other line
//! shows: `modes:` lists the modes away from their defaults that only the
//! renderer or input would show (`insert`, `newline`, `cursor-keys`,
//! `reverse`, `origin`, `no-autowrap`, `keypad`), and `region: <top>,<bottom>`
//! gives a scroll region other than the whole screen.

use std::collections::BTreeMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, fs, println, vec};

use crate::look::{Drawn, Look};
use crate::screen::{Attrs, Color, CursorStyle, Modes, Pen};
use crate::{MAX_COLS, MAX_ROWS, Terminal};

/// The note's groups and the cases each must have at least.
pub const GROUPS: &[(&str, usize)] = &[
    ("parser", 60),
    ("utf8", 25),
    ("print", 25),
    ("cursor", 35),
    ("erase", 25),
    ("edit", 25),
    ("scroll", 30),
    ("tabs", 12),
    ("sgr", 40),
    ("modes", 25),
    ("charsets", 8),
    ("reports", 6),
    // Beyond the note's twelve: realistic output of programs.
    ("programs", 6),
];

/// A glyph index for every code point the goldens use, distinct below
/// U+0800, so a look differs whenever the code point does.
pub fn glyph(c: char) -> u16 {
    (c as u32 % u32::from(Look::GLYPHS)) as u16
}

/// Everything a case checks.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Snapshot {
    pub cols: usize,
    pub rows: usize,
    pub cells: Vec<(char, Pen)>,
    pub row: usize,
    pub col: usize,
    pub hidden: bool,
    pub wrap: bool,
    pub style: CursorStyle,
    pub alternate: bool,
    pub reply: Vec<u8>,
    pub title: Vec<u8>,
    pub ignored: u64,
    pub modes: Vec<&'static str>,
    pub region: Option<(usize, usize)>,
}

/// The modes `modes:` names, each with whether it is away from its
/// default.
fn mode_words(m: &Modes) -> Vec<&'static str> {
    let d = Modes::DEFAULT;
    let all = [
        (m.insert != d.insert, "insert"),
        (m.newline != d.newline, "newline"),
        (m.cursor_keys != d.cursor_keys, "cursor-keys"),
        (m.reverse != d.reverse, "reverse"),
        (m.origin != d.origin, "origin"),
        (m.autowrap != d.autowrap, "no-autowrap"),
        (m.keypad != d.keypad, "keypad"),
    ];
    all.iter().filter(|(on, _)| *on).map(|&(_, w)| w).collect()
}

const MODE_WORDS: [&str; 7] = [
    "insert",
    "newline",
    "cursor-keys",
    "reverse",
    "origin",
    "no-autowrap",
    "keypad",
];

impl Snapshot {
    pub fn of(t: &Terminal<'_>, reply: Vec<u8>) -> Snapshot {
        let s = t.screen();
        let (cols, rows) = (s.cols(), s.rows());
        let mut cells = Vec::with_capacity(cols * rows);
        for r in 0..rows {
            for c in 0..cols {
                let cell = s.cell(r, c);
                cells.push((cell.ch, cell.pen));
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
            style: cur.style,
            alternate: s.alternate(),
            reply,
            title: s.title().to_vec(),
            ignored: s.ignored(),
            modes: mode_words(&s.modes()),
            region: (top != 0 || bottom != rows - 1).then_some((top, bottom)),
        }
    }
}

/// A case as read from its file.
pub struct Case {
    pub path: PathBuf,
    pub name: String,
    /// The comment, `size:` and `input:` lines, kept as written.
    pub head: Vec<String>,
    pub cols: usize,
    pub rows: usize,
    pub inputs: Vec<Vec<u8>>,
    /// `None` for a case with only its head.
    pub expect: Option<Snapshot>,
    /// The expected keys, so a blessed case keeps their letters.
    pub keys: Vec<(char, Pen)>,
}

/// Decodes an `input:`, `reply:` or `title:` value: `\e`, `\r`, `\n`,
/// `\t`, `\\` and `\xHH`, as `send:` is.
pub fn unescape(text: &str) -> Result<Vec<u8>, String> {
    let mut out = Vec::new();
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
            continue;
        }
        out.push(match chars.next() {
            Some('r') => b'\r',
            Some('n') => b'\n',
            Some('t') => b'\t',
            Some('e') => 0x1B,
            Some('\\') => b'\\',
            Some('x') => {
                let digit = |c: Option<char>| c.and_then(|c| c.to_digit(16));
                match (digit(chars.next()), digit(chars.next())) {
                    (Some(hi), Some(lo)) => (hi << 4 | lo) as u8,
                    _ => return Err(r"`\x` needs two hex digits".into()),
                }
            }
            Some(c) => return Err(format!("unknown escape `\\{c}`")),
            None => return Err(r"a `\` ends the text".into()),
        });
    }
    Ok(out)
}

/// The inverse of [`unescape`], for blessed `reply:` and `title:` lines:
/// printable ASCII as itself (a space at either end as `\x20`), the rest
/// escaped.
pub fn escape(bytes: &[u8]) -> String {
    let mut s = String::new();
    for (i, &b) in bytes.iter().enumerate() {
        let end = i == 0 || i + 1 == bytes.len();
        match b {
            0x1B => s.push_str(r"\e"),
            b'\r' => s.push_str(r"\r"),
            b'\n' => s.push_str(r"\n"),
            b'\t' => s.push_str(r"\t"),
            b'\\' => s.push_str(r"\\"),
            b' ' if end => s.push_str(r"\x20"),
            0x20..=0x7E => s.push(char::from(b)),
            _ => {
                let _ = write!(s, r"\x{b:02x}");
            }
        }
    }
    s
}

fn parse_pen(words: &str) -> Result<Pen, String> {
    let mut pen = Pen::default();
    let mut it = words.split_whitespace();
    while let Some(w) = it.next() {
        match w {
            "fg" | "bg" => {
                let n: u8 = it
                    .next()
                    .and_then(|n| n.parse().ok())
                    .ok_or_else(|| format!("`{w}` needs a colour 0 to 255"))?;
                if w == "fg" {
                    pen.fg = Color::Index(n);
                } else {
                    pen.bg = Color::Index(n);
                }
            }
            _ => match Attrs::NAMES.iter().find(|(_, name)| *name == w) {
                Some(&(a, _)) => pen.attrs.insert(a),
                None => return Err(format!("unknown key word `{w}`")),
            },
        }
    }
    Ok(pen)
}

fn pen_words(pen: &Pen) -> String {
    let mut words: Vec<String> = Attrs::NAMES
        .iter()
        .filter(|(a, _)| pen.attrs.contains(*a))
        .map(|(_, n)| n.to_string())
        .collect();
    if let Color::Index(n) = pen.fg {
        words.push(format!("fg {n}"));
    }
    if let Color::Index(n) = pen.bg {
        words.push(format!("bg {n}"));
    }
    words.join(" ")
}

fn parse_grid(
    lines: &mut std::iter::Peekable<std::vec::IntoIter<(usize, String)>>,
    cols: usize,
    rows: usize,
    what: &str,
) -> Result<Vec<char>, String> {
    let mut out = Vec::with_capacity(cols * rows);
    for r in 0..rows {
        let (n, line) = lines
            .next()
            .ok_or_else(|| format!("{what}: row {} missing", r + 1))?;
        let chars: Vec<char> = line.chars().collect();
        if chars.len() != cols + 2 || chars[0] != '|' || chars[cols + 1] != '|' {
            return Err(format!(
                "line {n}: a {what} row is `|`, {cols} cells and `|`: {line:?}"
            ));
        }
        out.extend_from_slice(&chars[1..=cols]);
    }
    Ok(out)
}

pub fn parse(path: &Path, name: &str, text: &str) -> Result<Case, String> {
    let mut head = Vec::new();
    let mut inputs = Vec::new();
    let mut size = None;
    let mut lines: std::iter::Peekable<_> = text
        .lines()
        .enumerate()
        .map(|(i, l)| (i + 1, l.to_string()))
        .collect::<Vec<_>>()
        .into_iter()
        .peekable();
    // The head: comments, `size:`, `input:`.
    while let Some((n, line)) = lines.peek().cloned() {
        if line.starts_with('#') || line.trim().is_empty() {
            if size.is_some() && line.starts_with('#') {
                return Err(format!("line {n}: comments go at the top"));
            }
        } else if let Some(v) = line.strip_prefix("size:") {
            let (c, r) = v
                .trim()
                .split_once('x')
                .and_then(|(c, r)| Some((c.parse().ok()?, r.parse().ok()?)))
                .ok_or_else(|| format!("line {n}: `size: <cols>x<rows>`"))?;
            if !(1..=MAX_COLS).contains(&c) || !(1..=MAX_ROWS).contains(&r) {
                return Err(format!("line {n}: size out of range"));
            }
            size = Some((c, r));
        } else if let Some(v) = line.strip_prefix("input:") {
            inputs.push(unescape(v.trim()).map_err(|e| format!("line {n}: {e}"))?);
        } else {
            break;
        }
        head.push(line);
        lines.next();
    }
    let (cols, rows) = size.ok_or("no `size:`")?;
    let mut screen = None;
    let mut attrs = None;
    let mut keys: Vec<(char, Pen)> = Vec::new();
    let mut cursor = None;
    let mut alternate = false;
    let mut reply = Vec::new();
    let mut title = Vec::new();
    let mut ignored = 0;
    let mut modes = Vec::new();
    let mut region = None;
    while let Some((n, line)) = lines.next() {
        let err = |e: &str| format!("line {n}: {e}");
        if line.trim().is_empty() {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| err("expected `<name>: <value>`"))?;
        let value = value.trim();
        match key {
            "screen" => screen = Some(parse_grid(&mut lines, cols, rows, "screen")?),
            "attrs" => attrs = Some(parse_grid(&mut lines, cols, rows, "attrs")?),
            "key" => {
                let (c, words) = value
                    .split_once('=')
                    .ok_or_else(|| err("`key: <c> = <words>`"))?;
                let mut c = c.trim().chars();
                let k = match (c.next(), c.next()) {
                    (Some(k), None) if k != ' ' => k,
                    _ => return Err(err("a key is one character")),
                };
                keys.push((k, parse_pen(words).map_err(|e| err(&e))?));
            }
            "cursor" => {
                let mut w = value.split_whitespace();
                let (r, c) = w
                    .next()
                    .and_then(|rc| rc.split_once(','))
                    .and_then(|(r, c)| Some((r.parse::<usize>().ok()?, c.parse::<usize>().ok()?)))
                    .filter(|&(r, c)| (1..=rows).contains(&r) && (1..=cols).contains(&c))
                    .ok_or_else(|| err("`cursor: <row>,<col>` inside the screen"))?;
                let mut cur = (r - 1, c - 1, false, false, CursorStyle::Block);
                for word in w {
                    match word {
                        "hidden" => cur.2 = true,
                        "wrap" => cur.3 = true,
                        "underline" => cur.4 = CursorStyle::Underline,
                        "bar" => cur.4 = CursorStyle::Bar,
                        _ => return Err(err(&format!("unknown cursor word `{word}`"))),
                    }
                }
                cursor = Some(cur);
            }
            "buffer" => match value {
                "alternate" => alternate = true,
                "main" => alternate = false,
                _ => return Err(err("`buffer: alternate` or `main`")),
            },
            "reply" => reply = unescape(value).map_err(|e| err(&e))?,
            "title" => title = unescape(value).map_err(|e| err(&e))?,
            "ignored" => ignored = value.parse().map_err(|_| err("`ignored: <n>`"))?,
            "modes" => {
                for w in value.split_whitespace() {
                    let w = MODE_WORDS
                        .iter()
                        .find(|m| **m == w)
                        .ok_or_else(|| err(&format!("unknown mode `{w}`")))?;
                    modes.push(*w);
                }
                modes.sort_by_key(|m| MODE_WORDS.iter().position(|x| x == m));
            }
            "region" => {
                let (t, b) = value
                    .split_once(',')
                    .and_then(|(t, b)| Some((t.parse::<usize>().ok()?, b.parse::<usize>().ok()?)))
                    .filter(|&(t, b)| 1 <= t && t <= b && b <= rows)
                    .ok_or_else(|| err("`region: <top>,<bottom>`"))?;
                region = Some((t - 1, b - 1));
            }
            "input" | "size" => return Err(err("`input:` and `size:` go before the screen")),
            _ => return Err(err(&format!("unknown line `{key}:`"))),
        }
    }
    let mut case = Case {
        path: path.to_path_buf(),
        name: name.to_string(),
        head,
        cols,
        rows,
        inputs,
        expect: None,
        keys,
    };
    if screen.is_none() && cursor.is_none() {
        // Only the head: a new case, for MICROL4_BLESS=1 to fill in.
        return Ok(case);
    }
    let screen = screen.ok_or("no `screen:`")?;
    let (row, col, hidden, wrap, style) = cursor.ok_or("no `cursor:`")?;
    let mut cells = Vec::with_capacity(cols * rows);
    for (i, &ch) in screen.iter().enumerate() {
        let pen = match attrs.as_ref().map(|a| a[i]) {
            None | Some(' ') => Pen::default(),
            Some(k) => case
                .keys
                .iter()
                .find(|(c, _)| *c == k)
                .map(|(_, p)| *p)
                .ok_or_else(|| format!("attrs: no key for `{k}`"))?,
        };
        cells.push((ch, pen));
    }
    case.expect = Some(Snapshot {
        cols,
        rows,
        cells,
        row,
        col,
        hidden,
        wrap,
        style,
        alternate,
        reply,
        title,
        ignored,
        modes,
        region,
    });
    Ok(case)
}

/// Key characters for blessed cases, after those a case already names.
const KEY_POOL: &str = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%&*+=?";

/// The expected lines for `s`, as a blessed case gets them: keys named in
/// the order cells first use them, reusing `keys`' letters where a key's
/// meaning is the same.
pub fn render(s: &Snapshot, keys: &[(char, Pen)]) -> Vec<String> {
    let mut out = vec!["screen:".to_string()];
    for r in 0..s.rows {
        let row: String = s.cells[r * s.cols..(r + 1) * s.cols]
            .iter()
            .map(|c| c.0)
            .collect();
        out.push(format!("|{row}|"));
    }
    let mut named: Vec<(char, Pen)> = Vec::new();
    let mut pool = KEY_POOL
        .chars()
        .filter(|c| !keys.iter().any(|(k, _)| k == c));
    let mut attrs = Vec::new();
    for r in 0..s.rows {
        let mut line = String::from("|");
        for &(_, pen) in &s.cells[r * s.cols..(r + 1) * s.cols] {
            if pen == Pen::default() {
                line.push(' ');
                continue;
            }
            let k = match named.iter().find(|(_, p)| *p == pen) {
                Some(&(k, _)) => k,
                None => {
                    let k = keys
                        .iter()
                        .find(|(_, p)| *p == pen)
                        .map(|&(k, _)| k)
                        .or_else(|| pool.next())
                        .unwrap_or('~');
                    named.push((k, pen));
                    k
                }
            };
            line.push(k);
        }
        line.push('|');
        attrs.push(line);
    }
    if !named.is_empty() {
        out.push("attrs:".into());
        out.extend(attrs);
        for (k, pen) in &named {
            out.push(format!("key: {k} = {}", pen_words(pen)));
        }
    }
    let mut cursor = format!("cursor: {},{}", s.row + 1, s.col + 1);
    if s.hidden {
        cursor.push_str(" hidden");
    }
    if s.wrap {
        cursor.push_str(" wrap");
    }
    match s.style {
        CursorStyle::Block => {}
        CursorStyle::Underline => cursor.push_str(" underline"),
        CursorStyle::Bar => cursor.push_str(" bar"),
    }
    out.push(cursor);
    if s.alternate {
        out.push("buffer: alternate".into());
    }
    if !s.reply.is_empty() {
        out.push(format!("reply: {}", escape(&s.reply)));
    }
    if !s.title.is_empty() {
        out.push(format!("title: {}", escape(&s.title)));
    }
    if s.ignored != 0 {
        out.push(format!("ignored: {}", s.ignored));
    }
    if !s.modes.is_empty() {
        out.push(format!("modes: {}", s.modes.join(" ")));
    }
    if let Some((t, b)) = s.region {
        out.push(format!("region: {},{}", t + 1, b + 1));
    }
    out
}

/// A generator for the random splits: SplitMix64.
pub struct Rng(pub u64);

impl Rng {
    pub fn seeded(name: &str) -> Rng {
        // FNV-1a of the name.
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        for b in name.bytes() {
            h = (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3);
        }
        Rng(h)
    }

    pub fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

/// The four ways of writing a case's bytes.
pub fn ways(name: &str, inputs: &[Vec<u8>]) -> [(&'static str, Vec<Vec<u8>>); 4] {
    let all: Vec<u8> = inputs.concat();
    let mut rng = Rng::seeded(name);
    let mut splits = Vec::new();
    let mut i = 0;
    while i < all.len() {
        let n = 1 + rng.below(8) as usize;
        let end = (i + n).min(all.len());
        splits.push(all[i..end].to_vec());
        i = end;
    }
    [
        ("as written", inputs.to_vec()),
        ("in one write", vec![all.clone()]),
        ("byte by byte", all.iter().map(|&b| vec![b]).collect()),
        ("in random splits", splits),
    ]
}

/// Runs `writes` on a fresh `cols` × `rows` terminal, drawing a frame after
/// each; the final state, and the cells where the drawn looks differ from
/// a full render.
pub fn run(cols: usize, rows: usize, writes: &[Vec<u8>]) -> (Snapshot, Vec<(usize, usize)>) {
    let mut main = vec![0u64; cols * rows];
    let mut alt = vec![0u64; cols * rows];
    let mut drawn_words = vec![0u64; cols * rows];
    let mut t = Terminal::new(cols, rows, &mut main, &mut alt);
    let mut drawn = Drawn::new(cols, rows, &mut drawn_words, Look::blank(glyph(' ')));
    let mut reply = Vec::new();
    drawn.frame(t.screen(), glyph, |_, _, _| {});
    for w in writes {
        t.write(w, |r| reply.extend_from_slice(r));
        drawn.frame(t.screen(), glyph, |_, _, _| {});
    }
    let mut damage = Vec::new();
    for r in 0..rows {
        for c in 0..cols {
            if drawn.get(r, c) != t.screen().look(r, c, glyph) {
                damage.push((r + 1, c + 1));
            }
        }
    }
    (Snapshot::of(&t, reply), damage)
}

/// The expected and actual lines side by side, differing lines marked.
fn side_by_side(expected: &[String], actual: &[String]) -> String {
    let width = expected
        .iter()
        .map(|l| l.chars().count())
        .max()
        .unwrap_or(0);
    let mut out = format!("    {:width$}    actual\n", "expected");
    for i in 0..expected.len().max(actual.len()) {
        let e = expected.get(i).map_or("", String::as_str);
        let a = actual.get(i).map_or("", String::as_str);
        let mark = if e == a { "  " } else { "!=" };
        let pad = width - e.chars().count();
        let _ = writeln!(out, " {mark} {e}{:pad$}    {a}", "");
    }
    out
}

/// The cases of `group`, sorted by name.
pub fn load_group(group: &str) -> Vec<Result<Case, String>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("golden")
        .join(group);
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "golden"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let name = format!("{group}/{}", p.file_name().unwrap().to_string_lossy());
            let text = fs::read_to_string(p).map_err(|e| format!("{name}: {e}"))?;
            parse(p, &name, &text).map_err(|e| format!("{name}: {e}"))
        })
        .collect()
}

/// Rewrites `case`'s file: its head as written, then `result`'s lines.
fn bless_case(case: &Case, result: &Snapshot) {
    let mut text = case.head.join("\n");
    text.push('\n');
    for l in render(result, &case.keys) {
        text.push_str(&l);
        text.push('\n');
    }
    fs::write(&case.path, text).unwrap();
    println!("blessed {}", case.name);
}

/// Runs every case of `group`; panics listing each failure.
pub fn check_group(group: &str) {
    let bless = std::env::var_os("MICROL4_BLESS").is_some_and(|v| v == "1");
    let min = GROUPS
        .iter()
        .find(|(g, _)| *g == group)
        .map_or(0, |&(_, n)| n);
    let mut failures = Vec::new();
    let mut blessed = 0;
    let cases = load_group(group);
    let count = cases.len();
    for case in cases {
        let case = match case {
            Ok(c) => c,
            Err(e) => {
                failures.push(e);
                continue;
            }
        };
        let file = case.path.file_name().unwrap().to_string_lossy().to_string();
        let mut results = Vec::new();
        for (way, writes) in ways(&file, &case.inputs) {
            results.push((way, run(case.cols, case.rows, &writes)));
        }
        let first = &results[0].1.0;
        let agree = results.iter().all(|(_, (s, d))| s == first && d.is_empty());
        let mut report = String::new();
        let Some(expect) = &case.expect else {
            let _ = writeln!(report, "{}: no expected state", case.name);
            if bless && agree {
                bless_case(&case, first);
                blessed += 1;
            } else {
                failures.push(report);
            }
            continue;
        };
        for (way, (snap, damage)) in &results {
            if !damage.is_empty() {
                let _ = writeln!(
                    report,
                    "{} ({way}): the frames drawn differ from a full render at (row, col) {damage:?}",
                    case.name
                );
            }
            if snap != expect {
                let _ = write!(
                    report,
                    "{} ({way}):\n{}",
                    case.name,
                    side_by_side(&render(expect, &case.keys), &render(snap, &case.keys))
                );
                // Name the first differing cell, which the grids may not
                // show: a no-break space looks like a space.
                if let Some(i) = (0..expect.cells.len()).find(|&i| expect.cells[i] != snap.cells[i])
                {
                    let (e, a) = (expect.cells[i], snap.cells[i]);
                    let _ = writeln!(
                        report,
                        "    first differing cell {},{}: expected U+{:04X} {:?}, got U+{:04X} {:?}",
                        i / expect.cols + 1,
                        i % expect.cols + 1,
                        e.0 as u32,
                        e.1,
                        a.0 as u32,
                        a.1
                    );
                }
            }
        }
        if report.is_empty() {
            continue;
        }
        if bless && agree {
            bless_case(&case, first);
            blessed += 1;
            continue;
        }
        if !agree {
            report.push_str("  (the four ways disagree, so this case cannot be blessed)\n");
        }
        failures.push(report);
    }
    if count < min {
        failures.push(format!(
            "group {group} has {count} cases; the note asks for at least {min}"
        ));
    }
    if blessed > 0 {
        println!("{group}: blessed {blessed} cases; review each diff");
    }
    assert!(
        failures.is_empty(),
        "{} of {count} cases in {group} fail:\n\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every directory under `golden/` is a group a test runs.
#[test]
#[cfg_attr(miri, ignore = "Miri cannot read files")]
fn every_group_directory_is_tested() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("golden");
    let mut counts = BTreeMap::new();
    for e in fs::read_dir(&dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        assert!(
            GROUPS.iter().any(|(g, _)| *g == name),
            "golden/{name} is not a group the tests run"
        );
        let n = fs::read_dir(e.path()).unwrap().count();
        counts.insert(name, n);
    }
    for (g, min) in GROUPS {
        assert!(
            counts.get(*g).copied().unwrap_or(0) >= *min,
            "golden/{g} needs at least {min} cases"
        );
    }
}

macro_rules! groups {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            #[cfg_attr(miri, ignore = "Miri cannot read files")]
            fn $name() {
                check_group(stringify!($name));
            }
        )*
    };
}

groups!(
    parser, utf8, print, cursor, erase, edit, scroll, tabs, sgr, modes, charsets, reports, programs
);
