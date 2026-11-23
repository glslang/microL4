//! The M8 red team's tests (`PLAN.md`'s quick pass after M8; the findings
//! in `docs/redteam/m8-*.md`). One finding, `#[ignore]`d so the default
//! run passes: a DSR or DA reply cut short at the input queue's end turns
//! the next typed byte into a key nobody typed. The rest are the strongest
//! attacks on term's parser, screen model and renderer that held, kept as
//! ordinary tests: a later client that starts with CAN and RIS sees a
//! fresh terminal whatever an earlier one left; hostile streams on the
//! largest screen keep every write in the grid and act the same however
//! they are split; DSR answers every position, three-digit columns
//! included; REP's shortcut leaves the state its prints would at the
//! largest size; and no pixel is written outside the grid's cells, the
//! margins or the visible area.

use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use fb::{Format, Geometry};
use proptest::prelude::*;
use proptest::sample::select;

use crate::palette::DEFAULT_BG;
use crate::server::{Answer, INPUT, Request, Server};
use crate::session::{Session, cells};
use crate::{MAX_COLS, MAX_ROWS, STATE_WORDS, Terminal, split_state};

/// A host session's server over `g`, as `term::run` makes it.
fn with_server<R>(g: Geometry, f: impl FnOnce(&mut Server<'_>) -> R) -> R {
    let mut px = vec![0u32; g.pixels()];
    let mut st = vec![0u64; STATE_WORDS];
    let mut s = Server::new(Session::start(
        fb::Surface::new(g, &mut px).unwrap(),
        &mut st,
    ));
    f(&mut s)
}

/// Everything the client reads now: a `Read` with the queue non-empty.
fn read_all(s: &mut Server<'_>) -> Vec<u8> {
    let mut out = [0u8; INPUT];
    match s.request(Request::Read, || unreachable!("keys are queued"), &mut out) {
        Answer::Read(n) => out[..n].to_vec(),
        a => panic!("a Read with keys queued gave {a:?}"),
    }
}

/// A DSR 6 or DA asked while the input queue has room for only two bytes
/// keeps `ESC [` of its reply and drops the rest; the next byte typed then
/// completes `ESC [ A` or `ESC [ B`, what a VT100's Up and Down keys send
/// and what tui (`docs/design.md`, "`tui`") and most apps decode as Up and
/// Down, though the user typed `A` or `B`, an unknown key to tui. The
/// guarantee: the client reads the typed bytes with each reply whole or
/// not at all between them.
#[test]
#[ignore = "red team: a DSR or DA reply cut short at the input queue's end turns the next typed byte into a key (docs/redteam/m8-reply-cut-short.md)"]
fn a_reply_cut_short_never_turns_a_typed_byte_into_a_key() {
    let g = Geometry::new(84, 50, 90, Format::Bgr).unwrap();
    for (ask, reply, typed, key) in [
        (&b"\x1b[6n"[..], &b"\x1b[1;1R"[..], b'A', "Up"),
        (b"\x1b[c", b"\x1b[?1;2c", b'B', "Down"),
    ] {
        let stream = with_server(g, |s| {
            let mut out = [0u8; INPUT];
            // 510 bytes typed that the client has not read yet: a paste.
            s.keys(&[b'x'; INPUT - 2]);
            // The client asks where the cursor is, or what term is.
            s.request(Request::Write(ask), || unreachable!(), &mut out);
            let mut stream = read_all(s);
            // The user types one more key.
            s.keys(&[typed]);
            stream.extend(read_all(s));
            stream
        });
        let pasted = [b'x'; INPUT - 2];
        let without = [&pasted[..], &[typed]].concat();
        let with = [&pasted[..], reply, &[typed]].concat();
        let tail = &stream[INPUT - 2..];
        assert!(
            stream == without || stream == with,
            "the client reads {} after the paste: the {key} key, which nobody typed",
            tui_escaped(tail)
        );
    }
}

/// `bytes` as the harness's `send:` writes them.
fn tui_escaped(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| match b {
            0x1B => String::from("\\e"),
            0x20..=0x7E => String::from(char::from(b)),
            _ => format!("\\x{b:02x}"),
        })
        .collect()
}

/// Sequences that reach term's deepest states, and its costliest.
const SEQUENCES: &[&[u8]] = &[
    b"\x1b[?1049h",
    b"\x1b[?1049l",
    b"\x1b[?47h",
    b"\x1b[?47l",
    b"\x1b[?1047h",
    b"\x1b[?1047l",
    b"\x1b[?1048h",
    b"\x1b[?1048l",
    b"\x1b[?6h",
    b"\x1b[?6l",
    b"\x1b[?7l",
    b"\x1b[?7h",
    b"\x1b[?5h",
    b"\x1b[?25l",
    b"\x1b[4h",
    b"\x1b[4l",
    b"\x1b[20h",
    b"\x1b[2;65535r",
    b"\x1b[65534;65535r",
    b"\x1b[5;9r",
    b"\x1b[r",
    b"\x1b7",
    b"\x1b8",
    b"\x1b[s",
    b"\x1b[u",
    b"\x1b#8",
    b"\x1b(0",
    b"\x1b)0",
    b"\x1b(B",
    b"\x0e",
    b"\x0f",
    b"\x1bH",
    b"\x1b[3g",
    b"\x1b[g",
    b"\x1b[65535I",
    b"\x1b[65535Z",
    b"\x1b[65535@",
    b"\x1b[65535P",
    b"\x1b[65535X",
    b"\x1b[65535L",
    b"\x1b[65535M",
    b"\x1b[65535S",
    b"\x1b[65535T",
    b"\x1b[65535A",
    b"\x1b[65535B",
    b"\x1b[65535C",
    b"\x1b[65535D",
    b"\x1b[65535E",
    b"\x1b[65535F",
    b"\x1b[65535G",
    b"\x1b[65535d",
    b"\x1b[65535;65535H",
    b"\x1b[99999999999999999999;0H",
    b"\x1b[1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1;1H",
    b"\x1b[65535b",
    b"x\x1b[65535b",
    b"\x1b[J",
    b"\x1b[1J",
    b"\x1b[1K",
    b"\x1b[6n",
    b"\x1b[c",
    b"\x1b[38;5;255;48;2;255;255;255;1;2;3;4;5;7;8;9m",
    b"\x1b[38;2;256m",
    b"\x1b[38;5m",
    b"\x1b[48;2;1;2m",
    b"\x1b]0;",
    b"\x1b]2;a title longer than sixty-four bytes, so that the rest is dropped\x07",
    b"\x1bP",
    b"\x1b_",
    b"\x1b[?",
    b"\x1b[1:2m",
    b"\x1b[ !\"#q",
    b"\xf4\x8f\xbf",
    b"\xe2\x94",
    b"\xc2\x9b",
    b"\xed\xa0\x80",
    b"\r\n",
    b"\t\t\t",
    b"\x08",
];

fn token() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        3 => Just(vec![0x1B]),
        2 => Just(vec![b'[']),
        3 => (b'0'..=b'9').prop_map(|b| vec![b]),
        2 => Just(vec![b';']),
        3 => (0x40u8..=0x7E).prop_map(|b| vec![b]),
        1 => (0x00u8..=0x1F).prop_map(|b| vec![b]),
        2 => (0x80u8..=0xFF).prop_map(|b| vec![b]),
        3 => (0x20u8..=0x7E).prop_map(|b| vec![b]),
        8 => select(SEQUENCES).prop_map(<[u8]>::to_vec),
    ]
}

fn stream(tokens: usize) -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(token(), 0..tokens).prop_map(|t| t.concat())
}

/// What a terminal shows and keeps that its public state and its two
/// grids tell: every word of both buffers, the cursor, modes, region, pen,
/// title, tab stops and the active buffer.
#[derive(Debug, PartialEq, Eq)]
struct State {
    main: Vec<u64>,
    alt: Vec<u64>,
    public: String,
    reply: Vec<u8>,
}

/// `writes` on a fresh `cols` x `rows` terminal over grids with `spare`
/// canary words past their ends, which nothing may write.
fn run(cols: usize, rows: usize, writes: &[&[u8]]) -> Result<State, String> {
    const CANARY: u64 = 0xDEAD_BEEF_00FF_FFFF;
    const SPARE: usize = 8;
    let n = cols * rows;
    let mut main = vec![CANARY; n + SPARE];
    let mut alt = vec![CANARY; n + SPARE];
    let mut reply = Vec::new();
    let public;
    {
        let mut t = Terminal::new(cols, rows, &mut main, &mut alt);
        for w in writes {
            t.write(w, |r| reply.extend_from_slice(r));
            let s = t.screen();
            let c = s.cursor();
            if c.row >= rows || c.col >= cols || (c.pending_wrap && c.col != cols - 1) {
                return Err(format!("cursor {c:?} in {cols}x{rows}"));
            }
            let (top, bottom) = s.region();
            if top > bottom || bottom >= rows {
                return Err(format!("region {top}..={bottom} in {rows} rows"));
            }
        }
        let s = t.screen();
        let tabs: Vec<usize> = (0..cols).filter(|&c| s.tab_stop(c)).collect();
        public = format!(
            "{:?} {:?} {:?} {:?} {:?} {:?} {:?}",
            s.cursor(),
            s.modes(),
            s.region(),
            s.pen(),
            s.title(),
            s.alternate(),
            tabs
        );
    }
    if main[n..].iter().chain(&alt[n..]).any(|&w| w != CANARY) {
        return Err("a write landed past the grid".into());
    }
    main.truncate(n);
    alt.truncate(n);
    Ok(State {
        main,
        alt,
        public,
        reply,
    })
}

/// After RIS, what a later client's identical bytes show: each charset
/// (G0, then G1), the main buffer's saved cursor and the alternate's (with
/// the alternate buffer shown uncleared), the UTF-8 decoder, REP, and the
/// cursor through DSR.
const PROBE: &[u8] =
    b"\xc3\xa9q\x0eq\x0f\x1b[3b\x1b8r\x1b[?47h\x1b8a\x1b[6n\x1b[?47l\t\tz\x1b[?6h\x1b[6n";

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// A later client that starts with CAN and RIS sees and keeps exactly
    /// what it would on a fresh terminal, whatever an earlier client left:
    /// both buffers, both saved cursors, the charsets, the tab stops, the
    /// modes, the region, the title, the parser and the UTF-8 decoder. Only
    /// `Stats`' ignored count, which is not the screen, remembers.
    #[test]
    fn can_and_ris_leave_a_fresh_terminal_whatever_came_before(
        cols in 1usize..=24,
        rows in 1usize..=9,
        earlier in stream(if cfg!(miri) { 12 } else { 200 }),
    ) {
        let reset: &[u8] = b"\x18\x1bc";
        let fresh = run(cols, rows, &[PROBE]).map_err(TestCaseError::fail)?;
        let after = run(cols, rows, &[&earlier, reset, PROBE])
            .map_err(TestCaseError::fail)?;
        // The earlier client's own replies come first.
        let mut earlier_reply = run(cols, rows, &[&earlier, reset])
            .map_err(TestCaseError::fail)?
            .reply;
        earlier_reply.extend_from_slice(&fresh.reply);
        prop_assert_eq!(&after.reply, &earlier_reply);
        prop_assert_eq!(after.main, fresh.main);
        prop_assert_eq!(after.alt, fresh.alt);
        prop_assert_eq!(after.public, fresh.public);
    }

    /// Hostile streams of the costliest and deepest sequences on screens up
    /// to the largest, 240 x 75, where columns pass the first word of tab
    /// stops and DSR's three digits: nothing panics, the cursor and the
    /// region stay in the grid, no write lands past it, and the stream acts
    /// the same whole, byte by byte and in random chunks, both buffers and
    /// every reply included.
    #[test]
    fn hostile_streams_on_the_largest_screens_stay_in_the_grid_however_split(
        cols in if cfg!(miri) { 60usize..=70 } else { 60usize..=MAX_COLS },
        rows in if cfg!(miri) { 20usize..=22 } else { 20usize..=MAX_ROWS },
        bytes in stream(if cfg!(miri) { 6 } else { 160 }),
        splits in prop::collection::vec(1usize..=40, 1..16),
    ) {
        let whole: Vec<&[u8]> = vec![&bytes];
        let single: Vec<&[u8]> = bytes.chunks(1).collect();
        let mut chunks: Vec<&[u8]> = Vec::new();
        let (mut i, mut k) = (0, 0);
        while i < bytes.len() {
            let end = (i + splits[k % splits.len()]).min(bytes.len());
            chunks.push(&bytes[i..end]);
            i = end;
            k += 1;
        }
        let first = run(cols, rows, &whole).map_err(TestCaseError::fail)?;
        for (way, writes) in [("byte by byte", single), ("in chunks", chunks)] {
            let other = run(cols, rows, &writes)
                .map_err(|e| TestCaseError::fail(format!("{way}: {e}")))?;
            prop_assert!(other == first, "{} differs from whole", way);
        }
    }
}

/// DSR 6 answers every position of the largest screen, columns of three
/// digits and rows of two included, and counts the row from the region's
/// top under DECOM.
#[test]
fn dsr_answers_every_position_of_the_largest_screen() {
    let (cols, rows) = (MAX_COLS, MAX_ROWS);
    let step = if cfg!(miri) { 37 } else { 1 };
    let mut st = vec![0u64; STATE_WORDS];
    let (main, alt, _) = split_state(&mut st);
    let mut t = Terminal::new(cols, rows, main, alt);
    for row in (1..=rows).step_by(step) {
        for col in (1..=cols).step_by(step) {
            let mut reply = Vec::new();
            t.write(format!("\x1b[{row};{col}H\x1b[6n").as_bytes(), |r| {
                reply.extend_from_slice(r)
            });
            assert_eq!(reply, format!("\x1b[{row};{col}R").as_bytes());
        }
    }
    let mut reply = Vec::new();
    t.write(b"\x1b[70;75r\x1b[?6h\x1b[99;240H\x1b[6n\x1b[?6l", |r| {
        reply.extend_from_slice(r)
    });
    assert_eq!(reply, b"\x1b[6;240R");
}

/// REP's shortcut ([`crate::screen`]'s `rep_prints`) at the largest
/// screen: REP 65,535 from states with IRM, without DECAWM, in a region,
/// below it and under DECOM leaves what 65,535 prints leave. The proptest
/// in `props.rs` checks screens up to 6 x 4 only.
#[test]
fn rep_acts_as_its_prints_on_the_largest_screen() {
    let (cols, rows, n) = if cfg!(miri) {
        (24, 6, 700)
    } else {
        (MAX_COLS, MAX_ROWS, 65_535)
    };
    let rep = format!("\x1b[{n}b");
    let prints = vec![b'q'; n + 1];
    for start in [
        &b""[..],
        b"\x1b[4h",
        b"\x1b[?7l\x1b[4h\x1b[5;7H",
        b"\x1b[3;5r\x1b[9;3H\x1b(0",
        b"\x1b[3;5r\x1b[1;9H\x1b[4h",
        b"\x1b[2;4r\x1b[?6h\x1b[2;2H\x1b[4h\x1b[44m",
        b"\x1b[?1049h\x1b[2;3r\x1b[99;1H",
    ] {
        let by_rep = run(cols, rows, &[start, b"q", rep.as_bytes()]).unwrap();
        let by_prints = run(cols, rows, &[start, &prints]).unwrap();
        assert!(by_rep == by_prints, "REP after {start:?}");
    }
}

/// What a pixel holds before anything writes it: byte 3 set, which no
/// colour has.
const UNWRITTEN: u32 = 0xEE00_0000;

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 24 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// No pixel outside the visible area is ever written, and the margins
    /// right of and below the grid hold the default background after every
    /// frame, whatever the client writes: on a framebuffer wider and taller
    /// than the largest grid (whose cells stop at 240 x 75) and on one
    /// whose width and height are not whole cells, each with stride
    /// padding.
    #[test]
    fn no_pixel_outside_the_cells_changes_after_the_start(
        big in any::<bool>(),
        writes in prop::collection::vec(stream(if cfg!(miri) { 4 } else { 60 }), 1..6),
    ) {
        let (w, h, stride) = match (cfg!(miri), big) {
            (false, true) => (1930, 1210, 1937),
            _ => (85, 53, 91),
        };
        let g = Geometry::new(w, h, stride, Format::Bgr).unwrap();
        let (cols, rows) = cells(g);
        let (gw, gh) = (8 * cols, 16 * rows);
        let bg = g.format().pixel(fb::Rgb(DEFAULT_BG));
        let mut px = vec![UNWRITTEN; g.pixels()];
        let mut st = vec![0u64; STATE_WORDS];
        {
            let mut s = Session::start(fb::Surface::new(g, &mut px).unwrap(), &mut st);
            for w in &writes {
                s.write(w, |_| {});
            }
        }
        // Checked once the session lets go of the pixels: only the start
        // writes the margins, so a frame that wrote one would leave it
        // changed, and nothing writes the padding at all.
        let (w, h, stride) = (w as usize, h as usize, stride as usize);
        for y in 0..h {
            let row = &px[y * stride..(y + 1) * stride];
            prop_assert!(row[w..].iter().all(|&p| p == UNWRITTEN), "padding of row {} written", y);
            if y >= gh {
                prop_assert!(row[..w].iter().all(|&p| p == bg), "margin row {} not the background", y);
            } else {
                prop_assert!(row[gw..w].iter().all(|&p| p == bg), "right margin of row {} not the background", y);
            }
        }
    }
}
