//! The session and the term protocol (`docs/design.md`, "The renderer",
//! "Input and the term protocol" and "Code and tests"): term's start-up on
//! an `fb::Surface`, its frames against a full render, the grid's size;
//! requests decoded and refused in M7's order, `Read` answered at once,
//! saved and released by keys or by a reply, `Busy`, the queue's limit and
//! the counts `Stats` reports.

use std::vec;
use std::vec::Vec;

use fb::{Format, Geometry, Rgb};
use libsys::proto::{self, MAX_BYTES, MAX_WORDS, Refusal, TermSize, TermStats, label};

use crate::palette::{DEFAULT_BG, DEFAULT_FG};
use crate::render;
use crate::server::{Answer, INPUT, Input, Request, Server, decode};
use crate::session::{Pixels, Session, cells};
use crate::{STATE_WORDS, Terminal, split_state};

/// What a pixel holds before anything writes it: byte 3 set, which no
/// colour has.
const UNWRITTEN: u32 = 0xEE00_0000;

/// A 10 x 3 grid in 84 x 50 pixels, stride 90: a margin right of and
/// below the grid, and padding past each row.
fn small() -> Geometry {
    Geometry::new(84, 50, 90, Format::Bgr).unwrap()
}

fn buffer(g: Geometry) -> Vec<u32> {
    vec![UNWRITTEN; g.pixels()]
}

fn state() -> Vec<u64> {
    vec![0; STATE_WORDS]
}

fn colour(g: Geometry, px: &[u32], x: usize, y: usize) -> u32 {
    let p = px[y * g.stride() as usize + x];
    assert_eq!(p >> 24, 0, "pixel {x},{y} was never written");
    g.format().colour(p).0
}

/// The pixels a full render of `bytes` leaves on a fresh buffer.
fn full_render(g: Geometry, bytes: &[u8]) -> Vec<u32> {
    let (cols, rows) = cells(g);
    let mut st = state();
    let (main, alt, _) = split_state(&mut st);
    let mut t = Terminal::new(cols, rows, main, alt);
    t.write(bytes, |_| {});
    let mut px = buffer(g);
    render::full(
        t.screen(),
        &mut Pixels(fb::Surface::new(g, &mut px).unwrap()),
    );
    px
}

#[test]
fn the_start_fills_everything_and_draws_the_cursor_at_home() {
    let g = small();
    let mut px = buffer(g);
    let mut st = state();
    {
        let s = Session::start(fb::Surface::new(g, &mut px).unwrap(), &mut st);
        assert_eq!(s.size(), (10, 3));
        assert_eq!(
            (s.written(), s.frames(), s.cells(), s.ignored()),
            (0, 1, 1, 0)
        );
        assert!(!s.screen().alternate());
        assert_eq!(s.screen().cursor().row, 0);
        assert_eq!(s.screen().cursor().col, 0);
    }
    for y in 0..50 {
        for x in 0..84 {
            // The block cursor at home swaps a blank's colours.
            let want = if x < 8 && y < 16 {
                DEFAULT_FG
            } else {
                DEFAULT_BG
            };
            assert_eq!(colour(g, &px, x, y), want, "pixel {x},{y}");
        }
        // The stride's padding is never written.
        assert!(
            px[y * 90 + 84..(y + 1) * 90]
                .iter()
                .all(|&p| p == UNWRITTEN)
        );
    }
    assert_eq!(px, full_render(g, b""));
}

/// Whatever the state window held, the model starts from RIS's power-on
/// state and the renderer from blanks it drew itself.
#[test]
fn the_state_windows_old_words_are_not_taken_for_blanks() {
    let g = small();
    let mut clean = buffer(g);
    let mut st = state();
    Session::start(fb::Surface::new(g, &mut clean).unwrap(), &mut st);
    let mut px = buffer(g);
    let mut st = vec![0x5A5A_5A5A_5A5A_5A5A; STATE_WORDS];
    let cells = Session::start(fb::Surface::new(g, &mut px).unwrap(), &mut st).cells();
    assert_eq!(cells, 1);
    assert_eq!(px, clean);
}

#[test]
fn frames_after_each_write_leave_what_a_full_render_leaves() {
    let g = small();
    let writes: [&[u8]; 6] = [
        b"hello\r\n",
        b"\x1b[1;31mred\x1b[0m and \x1b[7mreverse",
        b"\x1b[2;5H\xe2\x94\x80\xe2\x94",
        b"\x82 \x1b[?25l",
        b"\nscrolled\nagain\nand again",
        b"\x1b[?1049h\x1b[2Jalt\x1b[?25h\x1b[4 q",
    ];
    let mut px = buffer(g);
    let mut st = state();
    let mut all = Vec::new();
    {
        let mut s = Session::start(fb::Surface::new(g, &mut px).unwrap(), &mut st);
        for (i, w) in writes.iter().enumerate() {
            s.write(w, |_| {});
            all.extend_from_slice(w);
            assert_eq!(s.frames(), i as u64 + 2);
        }
        assert_eq!(s.written(), all.len() as u64);
        assert!(s.cells() > 30);
    }
    assert_eq!(px, full_render(g, &all));
}

#[test]
fn the_grid_is_the_whole_cells_up_to_240_by_75() {
    for (w, h, want) in [
        (1280, 800, (160, 50)),
        (1024, 768, (128, 48)),
        (640, 384, (80, 24)),
        (647, 399, (80, 24)),
        (1920, 1200, (240, 75)),
        (2560, 1600, (240, 75)),
    ] {
        let g = Geometry::new(w, h, w, Format::Bgr).unwrap();
        assert_eq!(cells(g), want, "{w}x{h}");
    }
}

/// The words of a byte string, as a client sends them.
fn words(bytes: &[u8]) -> ([u64; MAX_WORDS], usize) {
    let mut w = [0; MAX_WORDS];
    let n = proto::encode(bytes, &mut w);
    (w, n)
}

fn dec<'b>(
    label: u64,
    badge: u64,
    length: usize,
    w: &[u64],
    buf: &'b mut [u8; MAX_BYTES],
) -> Result<Request<'b>, Refusal> {
    decode(
        label,
        badge,
        length,
        |i| w.get(i).copied().unwrap_or(0),
        buf,
    )
}

#[test]
fn requests_are_checked_label_badge_length() {
    let mut buf = [0u8; MAX_BYTES];
    let (w, n) = words(b"abc");
    // The label first: an unknown label with a bad badge and length.
    for l in [0, 0x13F, 0x144, 0x125, 0x121, label::TUI_REPORT] {
        assert_eq!(
            dec(l, 9, 77, &w, &mut buf),
            Err(Refusal::BadLabel),
            "{l:#x}"
        );
    }
    // Then the badge: Write, Read and Size only from badge 1, whatever the
    // length.
    for l in [label::TERM_WRITE, label::TERM_READ, label::TERM_SIZE] {
        for badge in [0, 2, 3, 4, 1 << 32] {
            assert_eq!(dec(l, badge, 77, &w, &mut buf), Err(Refusal::BadBadge));
        }
    }
    // Then the length.
    assert_eq!(
        dec(label::TERM_WRITE, 1, n + 1, &w, &mut buf),
        Err(Refusal::BadLength)
    );
    assert_eq!(
        dec(label::TERM_WRITE, 1, 0, &w, &mut buf),
        Err(Refusal::BadLength)
    );
    let big = [953u64, 0, 0];
    assert_eq!(
        dec(label::TERM_WRITE, 1, 121, &big, &mut buf),
        Err(Refusal::BadLength)
    );
    assert_eq!(
        dec(label::TERM_WRITE, 1, n, &w, &mut buf),
        Ok(Request::Write(b"abc"))
    );
    // Requests without words ignore any sent; Stats takes any badge.
    assert_eq!(dec(label::TERM_READ, 1, 5, &w, &mut buf), Ok(Request::Read));
    assert_eq!(dec(label::TERM_SIZE, 1, 0, &w, &mut buf), Ok(Request::Size));
    for badge in [0, 1, 2, 7, u64::MAX] {
        assert_eq!(
            dec(label::TERM_STATS, badge, 3, &w, &mut buf),
            Ok(Request::Stats)
        );
    }
    // A Write of 952 bytes, the most, through the IPC buffer.
    let long = [b'x'; MAX_BYTES];
    let (w, n) = words(&long);
    assert_eq!(n, MAX_WORDS);
    assert_eq!(
        dec(label::TERM_WRITE, 1, n, &w, &mut buf),
        Ok(Request::Write(&long[..]))
    );
}

/// A server on the small surface, its pixels and state in the caller's
/// buffers.
macro_rules! server {
    ($px:ident, $st:ident) => {{
        Server::new(Session::start(
            fb::Surface::new(small(), &mut $px).unwrap(),
            &mut $st,
        ))
    }};
}

#[test]
fn a_read_with_keys_queued_is_answered_at_once_with_all_of_them() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    s.keys(b"\x1b[B");
    s.keys(b"jj\r");
    let never = || panic!("a Read with keys queued is not saved");
    assert_eq!(s.request(Request::Read, never, &mut out), Answer::Read(6));
    assert_eq!(&out[..6], b"\x1b[Bjj\r");
    assert!(s.input().is_empty());
    assert_eq!(s.release(&mut out), None);
    assert_eq!(s.stats().from_console, 6);
}

#[test]
fn a_read_with_nothing_queued_is_saved_and_released_by_keys() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    assert_eq!(s.request(Request::Read, || true, &mut out), Answer::Saved);
    assert!(s.saved());
    // Nothing queued yet: nothing to release.
    assert_eq!(s.release(&mut out), None);
    // An empty ReadRaw releases nothing either.
    s.keys(b"");
    assert_eq!(s.release(&mut out), None);
    s.keys(b"q");
    assert_eq!(s.release(&mut out), Some(1));
    assert_eq!(out[0], b'q');
    assert!(!s.saved());
    // Released once: the next keys wait for the next Read.
    s.keys(b"k");
    assert_eq!(s.release(&mut out), None);
    assert_eq!(s.input().queued(), b"k");
}

#[test]
fn a_second_read_while_one_is_saved_is_busy() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    assert_eq!(s.request(Request::Read, || true, &mut out), Answer::Saved);
    // CNode_SaveCaller finds slot 5 full: DeleteFirst.
    assert_eq!(
        s.request(Request::Read, || false, &mut out),
        Answer::Refused(Refusal::Busy)
    );
    assert!(s.saved(), "the first Read still waits");
    s.keys(b"x");
    assert_eq!(s.release(&mut out), Some(1));
}

/// The slot, not the flag, decides `Busy`: a saved reply that vanished
/// (its client suspended) leaves the slot empty, and the next Read saves
/// into it.
#[test]
fn a_read_saves_whenever_the_slot_takes_it() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    assert_eq!(s.request(Request::Read, || true, &mut out), Answer::Saved);
    assert_eq!(s.request(Request::Read, || true, &mut out), Answer::Saved);
    // With nothing saved, a slot that refuses is still Busy.
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    assert_eq!(
        s.request(Request::Read, || false, &mut out),
        Answer::Refused(Refusal::Busy)
    );
    assert!(!s.saved());
}

#[test]
fn a_write_that_queues_a_reply_releases_a_saved_read() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    assert_eq!(s.request(Request::Read, || true, &mut out), Answer::Saved);
    // DSR 6 at row 2, column 4; then DA, in the same Write.
    let w = b"\r\n   \x1b[6n\x1b[c";
    assert_eq!(
        s.request(Request::Write(w), || unreachable!(), &mut out),
        Answer::Written(w.len())
    );
    let mut rel = [0u8; INPUT];
    let n = s.release(&mut rel).unwrap();
    assert_eq!(&rel[..n], b"\x1b[2;4R\x1b[?1;2c");
    let st = s.stats();
    assert_eq!(st.replies, n as u64);
    assert_eq!((st.from_console, st.dropped), (0, 0));
}

/// Keys and replies share the queue, in the order they came.
#[test]
fn keys_and_replies_queue_in_order() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    s.keys(b"a");
    s.request(Request::Write(b"\x1b[5n"), || unreachable!(), &mut out);
    s.keys(b"b");
    assert_eq!(
        s.request(Request::Read, || unreachable!(), &mut out),
        Answer::Read(6)
    );
    assert_eq!(&out[..6], b"a\x1b[0nb");
}

#[test]
fn bytes_past_the_queues_512_are_dropped_and_counted() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    let keys: Vec<u8> = (0..600u32).map(|i| b'a' + (i % 26) as u8).collect();
    s.keys(&keys[..500]);
    s.keys(&keys[500..]);
    assert_eq!(s.input().queued(), &keys[..INPUT]);
    // A reply that finds the queue full is dropped too.
    s.request(Request::Write(b"\x1b[6n"), || unreachable!(), &mut out);
    let st = s.stats();
    assert_eq!(st.from_console, 600);
    assert_eq!(st.dropped, 88 + 6);
    assert_eq!(st.replies, 0);
    assert_eq!(
        s.request(Request::Read, || unreachable!(), &mut out),
        Answer::Read(INPUT)
    );
    assert_eq!(&out[..], &keys[..INPUT]);
    // Room again; a reply partly fits.
    s.keys(&keys[..510]);
    s.request(Request::Write(b"\x1b[6n"), || unreachable!(), &mut out);
    let st = s.stats();
    assert_eq!((st.replies, st.dropped), (2, 88 + 6 + 4));
    assert_eq!(&s.input().queued()[510..], b"\x1b[");
}

#[test]
fn size_and_stats() {
    let (mut px, mut st) = (buffer(small()), state());
    let mut s = server!(px, st);
    let mut out = [0u8; INPUT];
    assert_eq!(
        s.request(Request::Size, || unreachable!(), &mut out),
        Answer::Size(TermSize {
            cols: 10,
            rows: 3,
            width: 84,
            height: 50
        })
    );
    assert_eq!(
        s.request(Request::Stats, || unreachable!(), &mut out),
        Answer::Stats(TermStats {
            frames: 1,
            cells: 1,
            ..TermStats::default()
        })
    );
    // "ab" draws two cells and moves the cursor: four cells. An unknown
    // CSI final is ignored, and its frame draws nothing.
    s.request(Request::Write(b"ab"), || unreachable!(), &mut out);
    s.request(Request::Write(b"\x1b[5y"), || unreachable!(), &mut out);
    s.keys(b"zz");
    assert_eq!(
        s.stats(),
        TermStats {
            written: 6,
            frames: 3,
            cells: 4,
            ignored: 1,
            from_console: 2,
            dropped: 0,
            replies: 0,
        }
    );
}

#[test]
fn the_input_queue_alone() {
    let mut q = Input::new();
    assert!(q.is_empty());
    q.reply(b"\x1b[0n");
    q.keys(b"k");
    assert_eq!(q.queued(), b"\x1b[0nk");
    let mut out = [0u8; INPUT];
    assert_eq!(q.take(&mut out), 5);
    assert!(q.is_empty());
    assert_eq!(q.take(&mut out), 0);
    assert_eq!((q.from_console(), q.dropped(), q.replies()), (1, 0, 4));
}

/// The framebuffer's colours come from the session's surface, which
/// converts them to the format.
#[test]
fn the_session_draws_through_the_format() {
    let g = Geometry::new(84, 50, 84, Format::Rgb).unwrap();
    let mut px = buffer(g);
    let mut st = state();
    Session::start(fb::Surface::new(g, &mut px).unwrap(), &mut st);
    assert_eq!(px[0], Format::Rgb.pixel(Rgb(DEFAULT_FG)));
    assert_eq!(px[8], Format::Rgb.pixel(Rgb(DEFAULT_BG)));
}
