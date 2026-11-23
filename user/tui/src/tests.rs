//! tui's rules (`docs/design.md`, "`tui`" and "Code and tests"): the key
//! decoder over every split of its sequences; the bytes `App` writes at
//! each moment of the `tui` scenario, and the console lines `run` prints;
//! that no frame uses a sequence term ignores; that every frame draws all
//! but the log whole; the log's scrolling; and the goldens (`golden`),
//! every panel at 160 x 50 and the scenario's moments at 160 x 50 and
//! 128 x 48, checked on a reference model of the sequences tui writes
//! (`screen`).

use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, vec};

use super::*;

mod golden;
mod screen;

use screen::Screen;

impl Out for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// An app driven as `run` drives it: started, then fed each `Read`'s
/// bytes, keeping every byte it wrote and what each key did, with the
/// bytes of each.
struct Run {
    app: App,
    bytes: Vec<u8>,
    first: Drawn,
    steps: Vec<(Step, Vec<u8>)>,
}

impl Run {
    fn new(cols: u64, rows: u64) -> Run {
        let mut app = App::new(cols, rows).unwrap();
        let mut bytes = Vec::new();
        let first = app.start(&mut bytes);
        Run {
            app,
            bytes,
            first,
            steps: Vec::new(),
        }
    }

    fn read(&mut self, bytes: &[u8]) -> &mut Run {
        self.app.received(bytes);
        for &b in bytes {
            if let Some(k) = self.app.decode(b) {
                let mut out = Vec::new();
                if let Some(s) = self.app.key(k, &mut out) {
                    self.bytes.extend_from_slice(&out);
                    self.steps.push((s, out));
                } else {
                    assert!(out.is_empty(), "nothing after quitting");
                }
            }
        }
        self
    }

    /// The reference screen of everything written.
    fn screen(&self) -> Screen {
        let mut s = Screen::new(self.app.cols.into(), self.app.rows.into());
        s.write(&self.bytes);
        s
    }

    fn drawn(&self) -> Vec<Drawn> {
        self.steps
            .iter()
            .filter_map(|(s, _)| match s {
                Step::Drawn(d) => Some(*d),
                Step::Quit(_) => None,
            })
            .collect()
    }
}

/// The sizes the frame tests draw at; under Miri, which interprets every
/// byte, only the smallest.
const SIZES: &[(usize, usize)] = if cfg!(miri) {
    &[(80, 24)]
} else {
    &[(80, 24), (128, 48), (160, 50), (240, 75), (81, 25)]
};
/// The scenario's size, or under Miri the smallest.
const BIG: (usize, usize) = if cfg!(miri) { (80, 24) } else { (160, 50) };

fn keys_of(bytes: &[u8]) -> Vec<Key> {
    let mut d = Decoder::new();
    bytes.iter().filter_map(|&b| d.push(b)).collect()
}

fn unknown(bytes: &[u8]) -> Key {
    match keys_of(bytes).as_slice() {
        [k @ Key::Unknown(_)] => *k,
        other => panic!("{bytes:?} gave {other:?}"),
    }
}

// The key decoder.

#[test]
fn every_key_of_the_table() {
    let table: [(&[u8], Key); 13] = [
        (b"\x1b[A", Key::Up),
        (b"\x1bOA", Key::Up),
        (b"k", Key::Up),
        (b"\x1b[B", Key::Down),
        (b"\x1bOB", Key::Down),
        (b"j", Key::Down),
        (b"\r", Key::Enter),
        (b"\n", Key::Enter),
        (b"1", Key::Item(1)),
        (b"6", Key::Item(6)),
        (b"q", Key::Quit),
        (b"x", unknown(b"x")),
        (b"\x1b[C", unknown(b"\x1b[C")),
    ];
    for (bytes, key) in table {
        assert_eq!(keys_of(bytes), [key], "{bytes:?}");
    }
    for n in 1..=6 {
        assert_eq!(keys_of(&[b'0' + n]), [Key::Item(n)]);
    }
    // Every other byte alone is an unknown key; CR LF is two Enters.
    for b in (0..=255u8).filter(|b| !b"\x1b\r\nkj123456q".contains(b)) {
        assert_eq!(keys_of(&[b]), [unknown(&[b])], "{b:#x}");
    }
    assert_eq!(keys_of(b"\r\n"), [Key::Enter, Key::Enter]);
}

#[test]
fn sequences_with_parameters_are_one_key_each() {
    for seq in [
        &b"\x1b[1;5A"[..],
        b"\x1b[2~",
        b"\x1b[15;2~",
        b"\x1b[?1;2c",
        b"\x1bOP",
        b"\x1bO2Q",
        b"\x1b[ q",
        b"\x1b[@",
    ] {
        assert_eq!(keys_of(seq).len(), 1, "{seq:?}");
        assert!(matches!(keys_of(seq)[0], Key::Unknown(_)), "{seq:?}");
    }
    // The longest are cut in the log.
    let k = keys_of(b"\x1b[1;2;3;4;5;6;7;8A");
    let Key::Unknown(u) = k[0] else { panic!() };
    assert_eq!(u.bytes(), b"\x1b[1;2;3;");
    assert_eq!(u.to_string(), "\\e[1;2;3;...");
}

#[test]
fn esc_and_anything_else_drops_the_esc() {
    assert_eq!(keys_of(b"\x1bq"), [Key::Quit]);
    assert_eq!(keys_of(b"\x1bx"), [unknown(b"x")]);
    assert_eq!(keys_of(b"\x1b\r"), [Key::Enter]);
    // A second ESC starts afresh.
    assert_eq!(keys_of(b"\x1b\x1b[A"), [Key::Up]);
    // A sequence cut short by a control, DEL or a byte from 0x80 is
    // dropped, and that byte decoded afresh.
    assert_eq!(keys_of(b"\x1b[1\rj"), [Key::Enter, Key::Down]);
    assert_eq!(keys_of(b"\x1b[\x1b[B"), [Key::Down]);
    assert_eq!(keys_of(b"\x1bO\x7f"), [unknown(b"\x7f")]);
    assert_eq!(keys_of(b"\x1b[2\xc3"), [unknown(b"\xc3")]);
    let mut d = Decoder::new();
    assert_eq!(d.push(0x1b), None);
    assert!(d.pending());
    assert_eq!(d.push(b'['), None);
    assert!(d.pending());
    assert_eq!(d.push(b'B'), Some(Key::Down));
    assert!(!d.pending());
}

/// Every way of cutting a stream of the table's sequences into `Read`s
/// gives the same keys: the decoder's state survives the end of a `Read`.
#[test]
fn every_split_of_every_sequence_decodes_the_same() {
    let seqs: [&[u8]; 10] = [
        b"\x1b[A",
        b"\x1bOB",
        b"\x1b[1;5A",
        b"\x1b\x1b[B",
        b"\x1bx",
        b"\x1b[2\r",
        b"\r\n",
        b"k3q",
        b"\x1bO",
        b"\x1b[15;2~",
    ];
    for seq in seqs {
        let whole = keys_of(seq);
        let n = seq.len();
        for cuts in 0..1u32 << (n - 1) {
            let mut d = Decoder::new();
            let mut got = Vec::new();
            let mut start = 0;
            for i in 1..=n {
                if i == n || cuts & 1 << (i - 1) != 0 {
                    got.extend(seq[start..i].iter().filter_map(|&b| d.push(b)));
                    start = i;
                }
            }
            assert_eq!(got, whole, "{seq:?} cut {cuts:b}");
        }
    }
    // The scenario's keys through the app, in every pair of Reads.
    let typed = b"\x1b[B\x1b[B\rq";
    let (cols, rows) = (BIG.0 as u64, BIG.1 as u64);
    let whole = Run::new(cols, rows).read(typed).bytes.clone();
    for cut in 0..=typed.len() {
        let mut r = Run::new(cols, rows);
        r.read(&typed[..cut]).read(&typed[cut..]);
        assert_eq!(r.bytes, whole, "cut at {cut}");
        assert_eq!(r.app.report(), typed);
    }
}

#[test]
fn an_unknown_key_shows_its_bytes_as_send_escapes_them() {
    for (bytes, shown) in [
        (&b"\x1b[C"[..], "\\e[C"),
        (b"x", "x"),
        (b"\\", "\\\\"),
        (b"\t", "\\t"),
        (b"\x00", "\\x00"),
        (b"\x7f", "\\x7f"),
        (b"\xff", "\\xff"),
        (b" ", " "),
    ] {
        let Key::Unknown(u) = unknown(bytes) else {
            panic!()
        };
        assert_eq!(u.to_string(), shown);
        assert_eq!(format!("{u:?}"), format!("Unknown({shown})"));
    }
}

// The app.

#[test]
fn the_layout_needs_80_by_24_and_term_gives_at_most_240_by_75() {
    assert!(App::new(80, 24).is_some());
    assert!(App::new(240, 75).is_some());
    for (c, r) in [
        (79, 24),
        (80, 23),
        (241, 50),
        (160, 76),
        (0, 0),
        (u64::MAX, 50),
    ] {
        assert!(App::new(c, r).is_none(), "{c}x{r}");
    }
    assert_eq!(
        App::new(160, 50).unwrap().size().to_string(),
        "tui: 160x50 terminal"
    );
}

/// The `tui` scenario's moments as bytes: the banner and the first frame,
/// Down, Down and Enter, then `q`, at 160 x 50 (80 x 24 under Miri).
#[test]
fn the_scenario_s_byte_stream() {
    let (cols, rows) = BIG;
    let mut r = Run::new(cols as u64, rows as u64);
    let start = format!(
        "tui: starting on a {cols}x{rows} terminal\r\n\x1b[?1049h\x1b[2J\x1b[2 q\x1b[{};{}r\x1b[?25l",
        rows - 9,
        rows - 2
    );
    assert!(r.bytes.starts_with(start.as_bytes()));
    if !cfg!(miri) {
        assert!(
            start.ends_with("\x1b[41;48r\x1b[?25l"),
            "160 x 50: rows 41 to 48"
        );
    }
    assert_eq!(
        r.first,
        Drawn {
            frame: 1,
            panel: Panel::Overview,
            item: 1
        }
    );
    assert_eq!(r.first.to_string(), "tui: frame 1 drawn: Overview, item 1");
    // The first frame ends with the prompt, the status line and the
    // cursor shown after the prompt.
    let frame_end = format!(
        "\x1b[{};1H> \x1b[K\x1b[{rows};1H\x1b[7m Up/Down j/k: move  Enter: open  1-6: jump  q: quit",
        rows - 1
    );
    let cursor = format!("\x1b[0m\x1b[{};3H\x1b[?25h", rows - 1);
    let text = String::from_utf8(r.bytes.clone()).unwrap();
    assert!(text.contains(&frame_end), "{text:?}");
    assert!(text.ends_with(&format!("frame 1 {cursor}")));
    r.read(b"\x1b[B\x1b[B\r");
    let lines: Vec<String> = r.drawn().iter().map(|d| d.to_string()).collect();
    assert_eq!(
        lines,
        [
            "tui: frame 2 drawn: Overview, item 2",
            "tui: frame 3 drawn: Overview, item 3",
            "tui: frame 4 drawn: Colours, item 3",
        ]
    );
    // Each key's frame appends its log line after an LF on the region's
    // bottom row.
    for (i, (_, bytes)) in r.steps.iter().enumerate() {
        let t = String::from_utf8(bytes.clone()).unwrap();
        let name = ["Down", "Down", "Enter"][i];
        assert!(t.starts_with("\x1b[?25l\x1b[0m\x1b[1;1H"), "{t:?}");
        let log = format!("\x1b[{};1H\nkey {}: {name}", rows - 2, i + 1);
        assert!(t.contains(&log), "{t:?}");
        assert!(t.ends_with(&format!("frame {} {cursor}", i + 2)));
    }
    r.read(b"q");
    let (quit, bytes) = r.steps.last().unwrap();
    assert_eq!(*quit, Step::Quit(Quit { keys: 4 }));
    assert_eq!(quit_line(quit), "tui: quit after 4 keys");
    // CSI r before leaving the alternate buffer, then the goodbye below
    // the banner.
    assert_eq!(bytes, b"\x1b[r\x1b[?1049ltui: bye after 4 keys\r\n");
    assert_eq!(r.app.report(), b"\x1b[B\x1b[B\rq");
    assert!(r.app.quit());
    // Nothing after: keys are ignored, though the bytes are reported.
    let n = r.bytes.len();
    r.read(b"j");
    assert_eq!(r.bytes.len(), n);
    assert_eq!(r.app.keys(), 4);
}

fn quit_line(s: &Step) -> String {
    match s {
        Step::Quit(q) => q.to_string(),
        Step::Drawn(d) => panic!("{d}"),
    }
}

#[test]
fn the_report_is_the_first_255_bytes_read() {
    let mut r = Run::new(80, 24);
    // One long sequence across three Reads, so one key: the report holds
    // bytes, not keys.
    let mut junk = b"\x1b[".to_vec();
    junk.extend((0..297).map(|i| b'0' + (i % 10) as u8));
    junk.push(b'~');
    r.read(&junk[..100])
        .read(&junk[100..299])
        .read(&junk[299..]);
    assert_eq!(r.app.report(), &junk[..REPORT]);
    assert_eq!(r.app.keys(), 1);
    assert_eq!(r.drawn().len(), 1);
}

#[test]
fn keys_move_the_selection_open_panels_and_quit() {
    let mut r = Run::new(80, 24);
    r.read(b"kkk\x1bOB\x1b[Bjjjjjjj");
    let items: Vec<u8> = r.drawn().iter().map(|d| d.item).collect();
    assert_eq!(items, [1, 1, 1, 2, 3, 4, 5, 6, 6, 6, 6, 6]);
    assert!(r.drawn().iter().all(|d| d.panel == Panel::Overview));
    // Digits select and open; Enter opens the selection.
    let mut r = Run::new(80, 24);
    r.read(b"2345\x1b[A\r1");
    let got: Vec<(u8, Panel)> = r.drawn().iter().map(|d| (d.item, d.panel)).collect();
    assert_eq!(
        got,
        [
            (2, Panel::Attributes),
            (3, Panel::Colours),
            (4, Panel::Boxes),
            (5, Panel::Keys),
            (4, Panel::Keys),
            (4, Panel::Boxes),
            (1, Panel::Overview),
        ]
    );
    // 6 quits, and so does Enter on item 6.
    for keys in [&b"6"[..], b"jjjjj\r", b"\x1b[B\x1b[B\x1b[B\x1b[B\x1b[B\n"] {
        let mut r = Run::new(80, 24);
        r.read(keys);
        assert_eq!(
            r.steps.last().unwrap().0,
            Step::Quit(Quit {
                keys: keys_of(keys).len() as u32
            })
        );
    }
    // Unknown keys draw a frame too.
    let mut r = Run::new(80, 24);
    r.read(b"x\x1b[C");
    assert_eq!(r.drawn().len(), 2);
    assert_eq!(r.drawn()[1].frame, 3);
}

/// Every escape sequence in `bytes`, checked against the sequences term
/// acts on that tui may use; C0 controls but CR and LF are refused.
fn sequences(bytes: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < bytes.len() {
        match bytes[i] {
            0x1B => {
                let start = i;
                i += 1;
                match bytes.get(i) {
                    Some(b'(') => i += 2,
                    Some(b'[') => {
                        i += 1;
                        while !(0x40..=0x7E).contains(&bytes[i]) {
                            i += 1;
                        }
                        i += 1;
                    }
                    b => panic!("ESC {b:?}"),
                }
                out.push(String::from_utf8(bytes[start..i].to_vec()).unwrap());
            }
            b'\r' | b'\n' => i += 1,
            b @ (0..0x20 | 0x7F) => panic!("control {b:#x}"),
            _ => i += 1,
        }
    }
    for s in &out {
        assert!(allowed(s), "{s:?} is not a sequence tui may use");
    }
    out
}

fn allowed(s: &str) -> bool {
    let num = |t: &str| !t.is_empty() && t.bytes().all(|b| b.is_ascii_digit());
    let Some(csi) = s.strip_prefix("\x1b[") else {
        return s == "\x1b(0" || s == "\x1b(B";
    };
    let (body, f) = csi.split_at(csi.len() - 1);
    match f {
        "H" => body.split(';').count() == 2 && body.split(';').all(num),
        "K" => body.is_empty(),
        "J" => body == "2",
        "r" => body.is_empty() || (body.split(';').count() == 2 && body.split(';').all(num)),
        "h" | "l" => body == "?25" || body == "?1049",
        "q" => body == "2 ",
        "m" => body.is_empty() || body.split(';').all(num),
        _ => false,
    }
}

/// The SGR parameters used, extended colours as `38;5`, `48;2` and so on.
fn sgr_rows(seqs: &[String]) -> std::collections::BTreeSet<String> {
    let mut rows = std::collections::BTreeSet::new();
    for s in seqs.iter().filter(|s| s.ends_with('m')) {
        let body = &s[2..s.len() - 1];
        let ps: Vec<&str> = if body.is_empty() {
            vec!["0"]
        } else {
            body.split(';').collect()
        };
        let mut i = 0;
        while i < ps.len() {
            if ps[i] == "38" || ps[i] == "48" {
                rows.insert(format!("{};{}", ps[i], ps[i + 1]));
                i += if ps[i + 1] == "5" { 3 } else { 5 };
            } else {
                rows.insert(ps[i].to_string());
                i += 1;
            }
        }
    }
    rows
}

/// A key stream visiting every panel, with moves, unknown keys and more
/// lines than the log holds, ending on the Boxes panel.
const TOUR: &[u8] = b"jx2\x1b[A3\x1bOB4\x1b[C5k1\x1b[1;5Bjj\rjj\rk\r";

/// tui uses only sequences term acts on (term's ignored count stays 0):
/// CR and LF, CUP, EL, ED 2, SGR (every row of its table but 6, 21 and
/// the ignored forms), DECSTBM, DECTCEM, DECSCUSR, mode 1049 and SCS.
#[test]
fn no_frame_uses_a_sequence_term_ignores() {
    for &(cols, rows) in SIZES {
        let mut r = Run::new(cols as u64, rows as u64);
        r.read(TOUR).read(b"q");
        let seqs = sequences(&r.bytes);
        // The reference model refuses anything else, too.
        r.screen();
        if (cols, rows) == (160, 50) {
            let mut want: Vec<String> = [
                "0", "1", "2", "3", "4", "5", "7", "8", "9", "22", "23", "24", "25", "27", "28",
                "29", "39", "49", "38;5", "48;5", "38;2", "48;2",
            ]
            .iter()
            .map(|s| s.to_string())
            .collect();
            want.extend(
                (30..=37)
                    .chain(40..=47)
                    .chain(90..=97)
                    .chain(100..=107)
                    .map(|n| n.to_string()),
            );
            want.sort();
            assert_eq!(sgr_rows(&seqs).into_iter().collect::<Vec<_>>(), want);
        }
    }
}

/// Every frame draws everything but the log whole: on a screen whose cells
/// outside the log are junk, a frame leaves the same screen as on the
/// last frame's.
#[test]
fn every_frame_draws_all_but_the_log() {
    for &(cols, rows) in &SIZES[..SIZES.len().min(3)] {
        let mut r = Run::new(cols as u64, rows as u64);
        r.read(TOUR);
        let mut s = Screen::new(cols, rows);
        // The banner and the first frame, then each key's frame.
        let mut frames = vec![
            r.bytes[..r.bytes.len() - r.steps.iter().map(|x| x.1.len()).sum::<usize>()].to_vec(),
        ];
        frames.extend(r.steps.iter().map(|(_, b)| b.clone()));
        for (i, f) in frames.iter().enumerate() {
            let mut junk = s.clone();
            if i > 0 {
                junk.scribble(rows - 9..=rows - 3);
            }
            s.write(f);
            junk.write(f);
            for row in 0..rows {
                for col in 0..cols {
                    assert_eq!(
                        junk.cell(row, col),
                        s.cell(row, col),
                        "frame {i}, {row},{col}"
                    );
                }
            }
            assert_eq!((s.row, s.col, s.visible), (rows - 2, 2, true));
            assert!(s.alternate && !s.wrap);
            assert_eq!((s.top, s.bottom), (rows - 10, rows - 3));
        }
    }
}

/// Each key appends its line at the log's bottom row, which scrolls the
/// region; nothing else moves.
#[test]
fn the_log_scrolls_inside_its_region() {
    let (cols, rows) = BIG;
    let mut r = Run::new(cols as u64, rows as u64);
    let typed = b"abcdefghio";
    r.read(typed);
    let s = r.screen();
    let log: Vec<String> = (rows - 10..rows - 2).map(|row| s.text(row)).collect();
    let want: Vec<String> = (3..=10)
        .map(|n| format!("key {n}: unknown {}", char::from(typed[n - 1])))
        .collect();
    assert_eq!(log, want);
    assert!(s.text(rows - 11).starts_with("━━ Log ━━━"));
    assert!(s.text(0).starts_with(" microL4 terminal demo"));
    assert!(s.text(0).ends_with(&format!("{cols}x{rows}")));
    assert_eq!(s.text(rows - 2), ">");
    assert!(s.text(rows - 1).ends_with("frame 11"));
}

/// The scenario's last moment: the main buffer back, the banner, the
/// goodbye, the cursor below them, and the whole screen as the region.
#[test]
fn quitting_restores_the_main_screen() {
    for &(cols, rows) in &SIZES[..SIZES.len().min(3)] {
        let mut r = Run::new(cols as u64, rows as u64);
        r.read(b"\x1b[B\x1b[B\r").read(b"q");
        let s = r.screen();
        assert!(!s.alternate);
        assert_eq!(
            s.text(0),
            format!("tui: starting on a {cols}x{rows} terminal")
        );
        assert_eq!(s.text(1), "tui: bye after 4 keys");
        assert!((2..rows).all(|row| s.text(row).is_empty()));
        assert_eq!((s.row, s.col, s.visible), (2, 0, true));
        assert_eq!((s.top, s.bottom), (0, rows - 1));
    }
}
