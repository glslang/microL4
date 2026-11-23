//! The terminal's rules (`docs/design.md`, "Output" and "Input"): golden
//! byte transcripts for every row of the event and input tables, how a
//! client's control bytes are shown, the `console` scenario's input, the
//! raw client's rules (`raw`), and a proptest of eight clients' random
//! writes, flushes, reads and typed bytes against a model of their lines
//! and of client 4's raw queue.

use std::collections::VecDeque;
use std::string::String;
use std::vec::Vec;
use std::{format, vec};

use libsys::proto::{MAX_BYTES, Refusal, label};
use proptest::prelude::*;

use super::*;

mod raw;
mod redteam;

/// Everything the terminal sent, with where each byte came from.
#[derive(Default)]
struct Rec(Vec<(Source, u8)>);

impl Out for Rec {
    fn put(&mut self, from: Source, bytes: &[u8]) {
        self.0.extend(bytes.iter().map(|&b| (from, b)));
    }
}

impl Rec {
    fn text(&self) -> String {
        self.0.iter().map(|&(_, b)| b as char).collect()
    }

    fn take(&mut self) -> String {
        let t = self.text();
        self.0.clear();
        t
    }
}

/// A terminal and its transcript, for the goldens.
struct T {
    term: Terminal,
    rec: Rec,
    line: [u8; EDIT],
    delivered: Vec<(usize, String)>,
}

impl T {
    fn new() -> T {
        T {
            term: Terminal::new(),
            rec: Rec::default(),
            line: [0; EDIT],
            delivered: Vec::new(),
        }
    }

    fn write(&mut self, c: usize, s: &str) -> String {
        self.term.write(c, s.as_bytes(), &mut self.rec);
        self.rec.take()
    }

    fn flush(&mut self, c: usize) -> String {
        self.term.flush(c, &mut self.rec);
        self.rec.take()
    }

    /// A Read that can be saved; the answer and the transcript.
    fn read(&mut self, c: usize) -> (ReadAnswer, Option<String>, String) {
        let a = self.term.read(c, &mut self.rec, || true, &mut self.line);
        let line = match a {
            ReadAnswer::Line(n) => Some(self.line[..n].iter().map(|&b| b as char).collect()),
            _ => None,
        };
        (a, line, self.rec.take())
    }

    fn typed(&mut self, bytes: &[u8]) -> String {
        for &b in bytes {
            if let Some((c, n)) = self.term.input(b, &mut self.rec, &mut self.line) {
                let l = self.line[..n].iter().map(|&b| b as char).collect();
                self.delivered.push((c, l));
            }
        }
        self.rec.take()
    }
}

/// console's status line `text` as it reaches the terminal: in reverse
/// video, then `\r\n`.
fn status(text: &str) -> String {
    format!("\x1b[7m{text}\x1b[0m\r\n")
}

/// The status line's marks are console's own bytes, around the text.
#[test]
fn a_status_line_is_console_s_own_in_reverse_video() {
    assert_eq!((STATUS_ON, STATUS_OFF), (&b"\x1b[7m"[..], &b"\x1b[0m"[..]));
    let mut t = T::new();
    t.term.attach(2, b"cee");
    assert_eq!(t.term.input(0x14, &mut t.rec, &mut t.line), None);
    assert_eq!(t.term.input(b'3', &mut t.rec, &mut t.line), None);
    assert!(t.rec.0.iter().all(|&(from, _)| from == Source::Console));
    assert_eq!(t.rec.take(), status("[console] focus 3 (cee)"));
}

// The event table.

#[test]
fn a_write_that_completes_lines_sends_them_whole() {
    let mut t = T::new();
    assert_eq!(t.write(0, "hi\nthere\n"), "hi\r\nthere\r\n");
    assert_eq!(t.term.owner(), Owner::None);
    // Held bytes, then the rest of the line, then a held tail.
    assert_eq!(t.write(1, "a1 alpha "), "");
    assert_eq!(t.write(2, "b1 bravo "), "");
    assert_eq!(t.write(1, "one\n"), "a1 alpha one\r\n");
    assert_eq!(t.write(2, "one\nb2 "), "b1 bravo one\r\n");
    assert_eq!(t.term.held(2), b"b2 ");
    // An empty line is a line.
    assert_eq!(t.write(3, "\n"), "\r\n");
}

#[test]
fn a_break_comes_only_after_another_clients_line() {
    let mut t = T::new();
    t.write(1, "abc");
    assert_eq!(t.flush(1), "abc");
    assert_eq!(t.term.owner(), Owner::Output(1));
    // The same client goes on on the same line.
    assert_eq!(t.write(1, "def\n"), "def\r\n");
    t.write(1, "ghi");
    t.flush(1);
    // Another client's line gets a break first.
    assert_eq!(t.write(2, "x\n"), "\r\nx\r\n");
    assert_eq!(t.term.owner(), Owner::None);
}

#[test]
fn a_write_restores_the_focused_clients_input_line() {
    let mut t = T::new();
    t.write(0, "> ");
    assert_eq!(t.read(0), (ReadAnswer::Saved, None, "> ".into()));
    assert_eq!(t.term.owner(), Owner::Input(0));
    assert_eq!(t.typed(b"ab"), "ab");
    // Another client's line: a break, the line, the input line again.
    assert_eq!(t.write(1, "news\n"), "\r\nnews\r\n> ab");
    assert_eq!(t.term.owner(), Owner::Input(0));
    // An unfocused client with typed bytes is not restored.
    let mut t = T::new();
    t.write(3, "unfocused\n");
    assert_eq!(t.term.owner(), Owner::None);
}

#[test]
fn held_bytes_go_out_at_512() {
    let mut t = T::new();
    let long: String = (0..700).map(|i| (b'a' + (i % 26) as u8) as char).collect();
    let out = t.write(4, &long);
    assert_eq!(out, long[..512]);
    assert_eq!(t.term.owner(), Owner::Output(4));
    assert_eq!(t.term.held(4), &long.as_bytes()[512..]);
    // Another client then breaks the line.
    assert_eq!(t.write(5, "z\n"), "\r\nz\r\n");
    // 512 exactly, then a newline: the newline alone completes nothing
    // but an empty line after the piece, which is the same client's.
    let mut t = T::new();
    let mut s: String = "y".repeat(512);
    s.push('\n');
    assert_eq!(t.write(0, &s), format!("{}\r\n", "y".repeat(512)));
}

#[test]
fn a_clients_control_bytes_are_shown_not_sent() {
    let mut t = T::new();
    // Tab and printable ASCII pass; C0, DEL and everything from 0x80 up
    // are shown.
    assert_eq!(
        t.write(0, "a\tb\x1b[2Jc\rd\x08e\x7f\x00\x1f\n"),
        "a\tb^[[2Jc^Md^He^?^@^_\r\n"
    );
    t.term.write(0, b"\x80\x9b\xc3\xa9\xff\n", &mut t.rec);
    assert_eq!(t.rec.take(), "\\x80\\x9b\\xc3\\xa9\\xff\r\n");
    // Held bytes flushed, and 512 of them at once.
    t.write(1, "\x1b[H");
    assert_eq!(t.flush(1), "^[[H");
    assert_eq!(
        t.write(2, &"\x01".repeat(512)),
        format!("\r\n{}", "^A".repeat(512))
    );
    // A prompt, when its Read shows it.
    t.write(0, "\x1b[1A> ");
    assert_eq!(t.read(0), (ReadAnswer::Saved, None, "\r\n^[[1A> ".into()));
    // A name, in a status line.
    t.term.attach(3, b"\x1b[2Kx\x9b");
    assert_eq!(
        t.typed(b"\x144"),
        format!("\r\n{}", status("[console] focus 4 (^[[2Kx\\x9b)"))
    );
    // Every byte's form.
    for b in 0..=255u8 {
        let (e, n) = shown(b);
        let want = match b {
            0x00..=0x1F | 0x7F => format!("^{}", char::from(b ^ 0x40)),
            _ => format!("\\x{b:02x}"),
        };
        if !passes(b) {
            assert_eq!(&e[..n], want.as_bytes(), "{b:#x}");
            assert!(e[..n].iter().all(|&c| passes(c) && c != b'\t'));
        }
        assert_eq!(passes(b), b == b'\t' || (0x20..=0x7E).contains(&b));
    }
}

#[test]
fn flush_sends_held_bytes_after_a_break() {
    let mut t = T::new();
    assert_eq!(t.flush(2), "", "nothing held");
    t.write(3, "partial");
    assert_eq!(t.flush(2), "");
    t.write(2, "mine");
    assert_eq!(t.flush(3), "partial");
    assert_eq!(t.flush(2), "\r\nmine");
    assert_eq!(t.term.owner(), Owner::Output(2));
}

#[test]
fn a_read_with_a_line_waiting_flushes_and_answers_at_once() {
    let mut t = T::new();
    assert_eq!(t.typed(b"first\rsecond\r"), "first\r\nsecond\r\n");
    t.write(0, "p> ");
    assert_eq!(
        t.read(0),
        (ReadAnswer::Line(5), Some("first".into()), "p> ".into())
    );
    assert_eq!(t.term.owner(), Owner::Output(0));
    assert_eq!(
        t.read(0),
        (ReadAnswer::Line(6), Some("second".into()), "".into())
    );
    assert!(!t.term.reading(0));
    // None left: saved.
    assert_eq!(t.read(0).0, ReadAnswer::Saved);
}

#[test]
fn a_read_with_none_makes_the_held_bytes_its_prompt() {
    let mut t = T::new();
    t.write(1, "b> ");
    // Not focused: nothing shows.
    assert_eq!(t.read(1), (ReadAnswer::Saved, None, "".into()));
    assert!(t.term.held(1).is_empty());
    assert!(t.term.reading(1));
    // A second Read: the slot is full.
    let a = t.term.read(1, &mut t.rec, || false, &mut t.line);
    assert_eq!(a, ReadAnswer::Busy);
    assert_eq!(t.rec.take(), "");
    // Focused: the input line shows, after a break if needed.
    let mut t = T::new();
    t.write(0, "x");
    t.flush(0);
    t.write(0, "a> ");
    assert_eq!(t.read(0), (ReadAnswer::Saved, None, "\r\na> ".into()));
    assert_eq!(t.term.owner(), Owner::Input(0));
}

#[test]
fn a_typed_byte_shows_the_input_line_first() {
    let mut t = T::new();
    t.write(0, "q");
    t.flush(0);
    // The owner is client 0's output: a break, the (empty) prompt, echo.
    assert_eq!(t.typed(b"k"), "\r\nk");
    assert_eq!(t.term.owner(), Owner::Input(0));
    assert_eq!(t.typed(b"j"), "j", "already the last thing on the terminal");
    assert_eq!(t.term.edit(0), b"kj");
}

#[test]
fn enter_answers_the_saved_read_or_joins_the_waiting_lines() {
    let mut t = T::new();
    t.write(0, "> ");
    t.read(0);
    assert_eq!(t.typed(b"go\r"), "go\r\n");
    assert_eq!(t.delivered, [(0, "go".into())]);
    assert_eq!(t.term.owner(), Owner::None);
    assert!(!t.term.reading(0));
    // No Read: the line waits.
    assert_eq!(t.typed(b"later\r"), "later\r\n");
    assert_eq!(t.delivered.len(), 1);
    assert_eq!(t.read(0).1.as_deref(), Some("later"));
}

#[test]
fn ctrl_t_and_a_digit_moves_the_focus() {
    let mut t = T::new();
    t.term.attach(1, b"bee");
    assert_eq!(t.typed(b"\x142"), status("[console] focus 2 (bee)"));
    assert_eq!(t.term.focus(), 1);
    // Before it has attached; from the middle of an input line.
    t.typed(b"half");
    assert_eq!(
        t.typed(b"\x147"),
        format!("\r\n{}", status("[console] focus 7 (client 7)"))
    );
    // Back: the half-typed line is where it was, and is restored.
    assert_eq!(
        t.typed(b"\x142"),
        format!("{}half", status("[console] focus 2 (bee)"))
    );
    assert_eq!(t.term.owner(), Owner::Input(1));
    // A reading client's prompt comes back with its line.
    t.write(5, "six> ");
    t.read(5);
    assert_eq!(
        t.typed(b"\x146"),
        format!("\r\n{}six> ", status("[console] focus 6 (client 6)"))
    );
}

// The input table.

#[test]
fn printable_bytes_are_appended_up_to_255() {
    let mut t = T::new();
    let full = vec![b'x'; EDIT];
    assert_eq!(t.typed(&full).len(), EDIT);
    assert_eq!(t.typed(b"y"), "\x07");
    assert_eq!(t.term.edit(0).len(), EDIT);
}

#[test]
fn backspace_and_delete_remove_the_last_byte() {
    let mut t = T::new();
    assert_eq!(t.typed(b"\x08"), "", "nothing to remove");
    assert_eq!(t.term.owner(), Owner::Input(0), "but the line shows");
    assert_eq!(t.typed(b"abc\x08"), "abc\x08 \x08");
    assert_eq!(t.typed(b"\x7f"), "\x08 \x08");
    assert_eq!(t.term.edit(0), b"a");
}

#[test]
fn ctrl_u_empties_the_buffer() {
    let mut t = T::new();
    assert_eq!(t.typed(b"abc\x15"), "abc\x08 \x08\x08 \x08\x08 \x08");
    assert!(t.term.edit(0).is_empty());
    assert_eq!(t.typed(b"\x15"), "");
}

#[test]
fn cr_lf_and_crlf_each_end_one_line() {
    let mut t = T::new();
    t.typed(b"one\rtwo\nthree\r\nfour\n\r");
    assert_eq!(
        (0..5).map(|_| t.read(0).1).collect::<Vec<_>>(),
        [
            Some("one".into()),
            Some("two".into()),
            Some("three".into()),
            Some("four".into()),
            Some("".into())
        ]
    );
    // LF right after CR is dropped; after anything else it is Enter.
    let mut t = T::new();
    assert_eq!(t.typed(b"\r\n"), "\r\n");
    assert_eq!(t.typed(b"\n"), "\r\n");
}

#[test]
fn ctrl_t_with_anything_but_a_digit_drops_both() {
    let mut t = T::new();
    for seq in [&b"\x140"[..], b"\x149", b"\x14a", b"\x14\x14", b"\x14\x1b"] {
        assert_eq!(t.typed(seq), "", "{seq:?}");
        assert_eq!(t.term.focus(), 0);
    }
    assert!(t.term.edit(0).is_empty());
}

#[test]
fn escape_sequences_are_skipped() {
    let mut t = T::new();
    // CSI with parameters, CSI without, a two-byte escape.
    assert_eq!(t.typed(b"a\x1b[1;5Ab\x1b[Cc\x1bOd"), "abcd");
    assert_eq!(t.term.edit(0), b"abcd");
}

#[test]
fn other_bytes_are_dropped() {
    let mut t = T::new();
    assert_eq!(t.typed(b"\x00\x01\x07\x09\x1f\x80\xff"), "");
    assert!(t.term.edit(0).is_empty());
}

#[test]
fn enter_without_room_rings_and_keeps_the_line() {
    let mut t = T::new();
    let line = vec![b'w'; EDIT];
    let mut typed = line.clone();
    typed.push(b'\r');
    t.typed(&typed);
    t.typed(&typed);
    // 2 x 256 bytes wait: no room for a third.
    t.typed(&line);
    assert_eq!(t.typed(b"\r"), "\x07");
    assert_eq!(t.term.edit(0).len(), EDIT);
    assert_eq!(t.term.owner(), Owner::Input(0));
    // A Read makes room.
    assert_eq!(t.read(0).0, ReadAnswer::Line(EDIT));
    assert_eq!(t.typed(b"\r"), "\r\n");
}

/// The `console` scenario's input part (`docs/design.md`, "Scenarios"),
/// with the clients' Reads before the input, and after it.
#[test]
fn the_scenarios_input_reaches_the_right_clients() {
    let input: &[&[u8]] = &[b"\x143to b\r", b"\x142hellp\x7fo\x15hi a\r"];
    for reads_first in [true, false] {
        let mut t = T::new();
        t.term.attach(0, b"root");
        t.term.attach(1, b"a");
        t.term.attach(2, b"b");
        t.write(0, "console: input next\n");
        let mut answers = Vec::new();
        if reads_first {
            for (c, p) in [(1, "a> "), (2, "b> ")] {
                t.write(c, p);
                assert_eq!(t.read(c), (ReadAnswer::Saved, None, "".into()));
            }
        }
        let shown: Vec<String> = input.iter().map(|i| t.typed(i)).collect();
        if reads_first {
            assert_eq!(
                shown,
                [
                    format!("{}b> to b\r\n", status("[console] focus 3 (b)")),
                    format!(
                        "{}a> hellp\x08 \x08o{}hi a\r\n",
                        status("[console] focus 2 (a)"),
                        "\x08 \x08".repeat(5)
                    ),
                ]
            );
            answers = t.delivered.clone();
            answers.sort();
        } else {
            assert_eq!(
                shown,
                [
                    format!("{}to b\r\n", status("[console] focus 3 (b)")),
                    format!(
                        "{}hellp\x08 \x08o{}hi a\r\n",
                        status("[console] focus 2 (a)"),
                        "\x08 \x08".repeat(5)
                    ),
                ]
            );
            assert!(t.delivered.is_empty());
            for (c, p) in [(1, "a> "), (2, "b> ")] {
                t.write(c, p);
                let (a, line, out) = t.read(c);
                assert!(matches!(a, ReadAnswer::Line(_)));
                assert!(out.ends_with(p), "the prompt, flushed: {out:?}");
                answers.push((c, line.unwrap()));
            }
        }
        assert_eq!(answers, [(1, "hi a".into()), (2, "to b".into())]);
    }
}

#[test]
fn requests_check_label_then_badge_then_length() {
    let mut buf = [0; MAX_BYTES];
    let words = [2u64, u64::from_le_bytes(*b"hi\0\0\0\0\0\0")];
    let w = |i: usize| words[i];
    // 0x125 is ReadRaw from M8 (`raw`): client 4's only.
    assert_eq!(decode(0x125, 1, 2, w, &mut buf), Err(Refusal::BadBadge));
    assert_eq!(decode(0x127, 1, 2, w, &mut buf), Err(Refusal::BadLabel));
    assert_eq!(decode(0x110, 1, 2, w, &mut buf), Err(Refusal::BadLabel));
    assert_eq!(decode(0x126, 1, 2, w, &mut buf), Err(Refusal::BadLabel));
    for badge in [0, 9, 1 << 32] {
        assert_eq!(
            decode(label::CONSOLE_WRITE, badge, 7, w, &mut buf),
            Err(Refusal::BadBadge)
        );
        assert_eq!(
            decode(label::CONSOLE_SYNC, badge, 0, w, &mut buf),
            Err(Refusal::BadBadge)
        );
    }
    assert_eq!(
        decode(label::CONSOLE_WRITE, 1, 3, w, &mut buf),
        Err(Refusal::BadLength)
    );
    assert_eq!(
        decode(label::CONSOLE_WRITE, 8, 2, w, &mut buf),
        Ok((7, Request::Write(b"hi")))
    );
    assert_eq!(
        decode(label::CONSOLE_ATTACH, 3, 2, w, &mut buf),
        Ok((2, Request::Attach(b"hi")))
    );
    let long = |i: usize| if i == 0 { 17 } else { 0 };
    assert_eq!(
        decode(label::CONSOLE_ATTACH, 1, 4, long, &mut buf),
        Err(Refusal::BadLength)
    );
    let sixteen = |i: usize| if i == 0 { 16 } else { 0 };
    assert!(decode(label::CONSOLE_ATTACH, 1, 3, sixteen, &mut buf).is_ok());
    assert_eq!(
        decode(label::CONSOLE_FLUSH, 2, 5, w, &mut buf),
        Ok((1, Request::Flush))
    );
    assert_eq!(
        decode(label::CONSOLE_READ, 2, 0, w, &mut buf),
        Ok((1, Request::Read))
    );
    assert_eq!(
        decode(label::CONSOLE_SYNC, 2, 0, w, &mut buf),
        Ok((1, Request::Sync))
    );
    assert_eq!(slot::saved_read(1), 8);
    assert_eq!(slot::saved_read(8), 15);
}

#[test]
fn output_goes_to_uart_in_writes_of_952() {
    let mut sent = Vec::new();
    {
        let mut c = Chunks::new(|b: &[u8]| sent.push(b.to_vec()));
        c.put(Source::Console, &[1; 1000]);
        c.put(Source::Console, &[2; 1000]);
        c.flush();
        c.flush();
    }
    assert_eq!(
        sent.iter().map(Vec::len).collect::<Vec<_>>(),
        [952, 952, 96]
    );
    assert_eq!(sent.concat(), [vec![1; 1000], vec![2; 1000]].concat());
}

// The proptest.

#[derive(Clone, Debug)]
enum Op {
    Write(usize, Vec<u8>),
    Flush(usize),
    Read(usize),
    /// Client 4's `ReadRaw`.
    ReadRaw,
    /// The bytes of one uart `Read`.
    Type(Vec<u8>),
}

fn op() -> impl Strategy<Value = Op> {
    let client = 0..CLIENTS;
    let out_byte = prop_oneof![
        8 => b'a'..=b'z',
        2 => Just(b' '),
        3 => Just(b'\n'),
        1 => Just(b'\r'),
        1 => Just(b'\t'),
        1 => Just(0x1Bu8),
        1 => Just(0x08u8),
        1 => Just(0x7Fu8),
        1 => any::<u8>(),
    ];
    let typed_byte = prop_oneof![
        10 => b'a'..=b'z',
        2 => Just(b'\r'),
        1 => Just(b'\n'),
        1 => Just(0x08u8),
        1 => Just(0x7Fu8),
        1 => Just(0x15u8),
        2 => Just(0x14u8),
        3 => b'0'..=b'9',
        1 => Just(0x1Bu8),
        1 => Just(b'['),
        1 => Just(0x01u8),
        1 => any::<u8>(),
    ];
    // Ctrl-T and a digit first, often 4, so that client 4 has focus for a
    // good share of the typing.
    let focus = prop_oneof![
        3 => Just(None),
        2 => Just(Some(b'4')),
        1 => (b'1'..=b'8').prop_map(Some),
    ];
    let typed = |len: core::ops::Range<usize>| {
        (
            focus.clone(),
            prop::collection::vec(typed_byte.clone(), len),
        )
            .prop_map(|(f, mut b)| {
                if let Some(d) = f {
                    b.splice(0..0, [0x14, d]);
                }
                Op::Type(b)
            })
    };
    prop_oneof![
        5 => (client.clone(), prop::collection::vec(out_byte.clone(), 0..40)).prop_map(|(c, b)| Op::Write(c, b)),
        1 => (client.clone(), prop::collection::vec(out_byte, 400..700)).prop_map(|(c, b)| Op::Write(c, b)),
        1 => client.clone().prop_map(Op::Flush),
        // Client 4 has no lines: its Read is refused before the terminal,
        // so it reads raw.
        2 => client.prop_map(|c| if c == RAW { Op::ReadRaw } else { Op::Read(c) }),
        1 => Just(Op::ReadRaw),
        3 => typed(1..30),
        // Long enough to fill the raw queue, but under Miri.
        1 => typed(if cfg!(miri) { 30..60 } else { 300..700 }),
    ]
}

/// How the terminal must show a client's bytes: tab and printable ASCII
/// as they are, C0 controls and DEL in caret notation, the rest as `\xNN`.
fn shown_model(bytes: &[u8]) -> Vec<u8> {
    bytes
        .iter()
        .flat_map(|&b| match b {
            b'\t' | b' '..=b'~' => vec![b],
            0..=0x1F | 0x7F => vec![b'^', b ^ 0x40],
            _ => format!("\\x{b:02x}").into_bytes(),
        })
        .collect()
}

/// The model: what each client's output must be, which of its lines must
/// reach the terminal whole, and where each typed line goes.
#[derive(Default)]
struct Model {
    /// Per client: bytes written since its output last went out.
    held: [Vec<u8>; CLIENTS],
    /// Whether those bytes are a clean line start: nothing of the line
    /// went out early.
    clean: [bool; CLIENTS],
    /// Per client: its output as the terminal must show it, `\n` as
    /// `\r\n` and other bytes as [`shown_model`] says, and the ranges of
    /// that which are whole lines.
    shown: [Vec<u8>; CLIENTS],
    whole: [Vec<(usize, usize)>; CLIENTS],
    // The editor.
    focus: usize,
    edit: [Vec<u8>; CLIENTS],
    waiting: [VecDeque<Vec<u8>>; CLIENTS],
    reading: [bool; CLIENTS],
    after_cr: bool,
    ctrl_t: bool,
    esc: u8,
    // The raw client.
    raw: Vec<u8>,
    /// Every byte that reached the raw queue, in order.
    raw_all: Vec<u8>,
    /// A byte reached the queue in this Read, and BEL rang in it.
    raw_added: bool,
    raw_rang: bool,
}

/// What a typed byte did, beyond any line it ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Typed {
    /// An editor's byte, or a focus key.
    Other,
    /// In the raw queue, with nothing on the terminal.
    Queued,
    /// Dropped from a full raw queue: BEL on the terminal if it was the
    /// first in its Read, else nothing.
    Dropped { bel: bool },
}

impl Model {
    fn new() -> Model {
        Model {
            clean: [true; CLIENTS],
            ..Model::default()
        }
    }

    fn emit(&mut self, c: usize, newline: bool) {
        let start = self.shown[c].len();
        let held = shown_model(&self.held[c]);
        self.shown[c].extend_from_slice(&held);
        if newline {
            self.shown[c].extend_from_slice(b"\r\n");
            if self.clean[c] {
                self.whole[c].push((start, self.shown[c].len()));
            }
        }
        self.held[c].clear();
        self.clean[c] = newline;
    }

    fn write(&mut self, c: usize, bytes: &[u8]) {
        for &b in bytes {
            if b == b'\n' {
                self.emit(c, true);
            } else {
                self.held[c].push(b);
                if self.held[c].len() == LINE {
                    self.emit(c, false);
                }
            }
        }
    }

    fn flush(&mut self, c: usize) {
        if !self.held[c].is_empty() {
            self.emit(c, false);
        }
    }

    /// The answer the terminal must give: `Some(line)`, `None` for saved,
    /// and the error for Busy.
    fn read(&mut self, c: usize) -> Result<Option<Vec<u8>>, ()> {
        if let Some(l) = self.waiting[c].pop_front() {
            self.flush(c);
            return Ok(Some(l));
        }
        if self.reading[c] {
            return Err(());
        }
        // The held bytes become the prompt: never the client's output.
        self.held[c].clear();
        self.clean[c] = true;
        self.reading[c] = true;
        Ok(None)
    }

    fn raw_push(&mut self, b: u8) -> Typed {
        if self.raw.len() < RAW_QUEUE {
            self.raw.push(b);
            self.raw_all.push(b);
            self.raw_added = true;
            Typed::Queued
        } else {
            let bel = !self.raw_rang;
            self.raw_rang = true;
            Typed::Dropped { bel }
        }
    }

    fn end_of_read(&mut self) -> bool {
        self.raw_rang = false;
        core::mem::replace(&mut self.raw_added, false)
    }

    fn typed(&mut self, b: u8) -> (Option<(usize, Vec<u8>)>, Typed) {
        let after_cr = core::mem::replace(&mut self.after_cr, false);
        // Escapes are skipped only for a client with an input line; raw
        // bytes never start one.
        if self.focus == RAW && self.esc == 0 {
            if self.ctrl_t {
                self.ctrl_t = false;
                return match b {
                    b'1'..=b'8' => {
                        self.focus = usize::from(b - b'1');
                        (None, Typed::Other)
                    }
                    0x14 => (None, self.raw_push(b)),
                    _ => (None, Typed::Other),
                };
            }
            if b == 0x14 {
                self.ctrl_t = true;
                return (None, Typed::Other);
            }
            return (None, self.raw_push(b));
        }
        (self.edited(b, after_cr), Typed::Other)
    }

    /// A byte for a client with an input line, as in M7.
    fn edited(&mut self, b: u8, after_cr: bool) -> Option<(usize, Vec<u8>)> {
        match self.esc {
            1 => {
                self.esc = if b == b'[' { 2 } else { 0 };
                return None;
            }
            2 => {
                if (0x40..=0x7E).contains(&b) {
                    self.esc = 0;
                }
                return None;
            }
            _ => {}
        }
        if self.ctrl_t {
            self.ctrl_t = false;
            if (b'1'..=b'8').contains(&b) {
                self.focus = usize::from(b - b'1');
            }
            return None;
        }
        let f = self.focus;
        match b {
            0x20..=0x7E => {
                if self.edit[f].len() < EDIT {
                    self.edit[f].push(b);
                }
            }
            0x08 | 0x7F => {
                self.edit[f].pop();
            }
            0x15 => self.edit[f].clear(),
            b'\r' | b'\n' if b == b'\r' || !after_cr => {
                self.after_cr = b == b'\r';
                let line = self.edit[f].clone();
                if self.reading[f] {
                    self.reading[f] = false;
                    self.edit[f].clear();
                    return Some((f, line));
                }
                let used: usize = self.waiting[f].iter().map(|l| l.len() + 1).sum();
                if used + line.len() < WAITING {
                    self.waiting[f].push_back(line);
                    self.edit[f].clear();
                }
            }
            0x14 => self.ctrl_t = true,
            0x1B => self.esc = 1,
            _ => {}
        }
        None
    }
}

/// Operations per case; few under Miri, which interprets every byte.
const MAX_OPS: usize = if cfg!(miri) { 12 } else { 120 };

fn check(ops: &[Op]) -> Result<(), TestCaseError> {
    let mut term = Terminal::new();
    let mut model = Model::new();
    let mut rec = Rec::default();
    let mut line = [0; EDIT];
    let mut raw_read = Vec::new();
    let mut raw = [0; RAW_QUEUE];
    for op in ops {
        match op {
            Op::Write(c, b) => {
                term.write(*c, b, &mut rec);
                model.write(*c, b);
            }
            Op::Flush(c) => {
                term.flush(*c, &mut rec);
                model.flush(*c);
            }
            Op::Read(c) => {
                // The slot is full while a Read is saved.
                let full = term.reading(*c);
                let got = term.read(*c, &mut rec, || !full, &mut line);
                let want = model.read(*c);
                match (got, want) {
                    (ReadAnswer::Line(n), Ok(Some(l))) => prop_assert_eq!(&line[..n], &l[..]),
                    (ReadAnswer::Saved, Ok(None)) | (ReadAnswer::Busy, Err(())) => {}
                    (g, w) => prop_assert!(false, "Read by {}: {:?}, the model {:?}", c, g, w),
                }
            }
            Op::ReadRaw => {
                let n = term.read_raw(&mut raw);
                prop_assert_eq!(&raw[..n], &model.raw[..]);
                raw_read.extend_from_slice(&raw[..n]);
                model.raw.clear();
            }
            Op::Type(bytes) => {
                for &b in bytes {
                    let before = rec.0.len();
                    let got = term
                        .input(b, &mut rec, &mut line)
                        .map(|(c, n)| (c, line[..n].to_vec()));
                    let (want, typed) = model.typed(b);
                    prop_assert_eq!(got, want, "typed {:#x}", b);
                    // Unechoed: a raw byte shows nothing, a dropped one at
                    // most the Read's one BEL.
                    let shown: Vec<u8> = rec.0[before..].iter().map(|e| e.1).collect();
                    match typed {
                        Typed::Queued | Typed::Dropped { bel: false } => {
                            prop_assert!(shown.is_empty(), "raw {:#x} showed {:?}", b, shown)
                        }
                        Typed::Dropped { bel: true } => prop_assert_eq!(&shown[..], b"\x07"),
                        Typed::Other => {}
                    }
                }
                prop_assert_eq!(term.raw(), &model.raw[..]);
                prop_assert_eq!(term.end_of_read(), model.end_of_read(), "the signal");
            }
        }
    }
    // Client 4's typed bytes reached the raw queue once each, in order,
    // as typed: everything ReadRaw returned, then what is left.
    raw_read.extend_from_slice(term.raw());
    prop_assert_eq!(&raw_read, &model.raw_all);
    // Raw mode is input only: nothing ever showed client 4's input line.
    prop_assert!(term.owner() != Owner::Input(RAW));
    // No client's byte, in its output or its prompt, reaches the terminal
    // as a control byte: only tab, and the CR LF console ends its lines
    // with.
    for (i, &(from, b)) in rec.0.iter().enumerate() {
        if let Source::Client(_) | Source::Prompt(_) = from {
            let line_end = (b == b'\r' && rec.0.get(i + 1) == Some(&(from, b'\n')))
                || (b == b'\n' && i > 0 && rec.0[i - 1] == (from, b'\r'));
            prop_assert!(
                b == b'\t'
                    || (0x20..=0x7E).contains(&b)
                    || (line_end && matches!(from, Source::Client(_))),
                "{:?} sent {:#x}",
                from,
                b
            );
        }
    }
    // Each client's bytes once and in order, `\n` as `\r\n`.
    for c in 0..CLIENTS {
        let mine: Vec<usize> = rec
            .0
            .iter()
            .enumerate()
            .filter(|(_, e)| e.0 == Source::Client(c))
            .map(|(i, _)| i)
            .collect();
        let bytes: Vec<u8> = mine.iter().map(|&i| rec.0[i].1).collect();
        prop_assert_eq!(&bytes, &model.shown[c], "client {}'s output", c);
        prop_assert_eq!(term.held(c), &model.held[c][..]);
        // Whole lines: their bytes are consecutive on the terminal.
        for &(s, e) in &model.whole[c] {
            prop_assert_eq!(
                mine[e - 1] - mine[s],
                e - 1 - s,
                "client {}'s line at {}",
                c,
                s
            );
        }
    }
    Ok(())
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn eight_clients_against_a_model_of_their_lines(ops in prop::collection::vec(op(), 1..MAX_OPS)) {
        check(&ops)?;
    }
}
