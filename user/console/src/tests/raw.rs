//! The raw client's rules (`docs/design.md`, "Input and the term
//! protocol"): client 4's typed bytes go to its raw queue unedited and
//! unechoed, ESC and what follows included, but for the focus keys
//! (Ctrl-T and a digit, Ctrl-T Ctrl-T, Ctrl-T and anything else); a full
//! queue drops the byte and rings BEL once per uart `Read`; `ReadRaw`
//! takes the queue at once and only from client 4, whose `Read` is
//! refused; client 4 has no input line; its output is shown as every
//! client's.

use std::format;
use std::vec::Vec;

use libsys::proto::{MAX_BYTES, Refusal, label};

use super::{T, status};
use crate::{Owner, RAW, RAW_QUEUE, ReadAnswer, Request, decode};

impl T {
    /// One uart Read's bytes: the transcript, and whether console would
    /// signal term.
    fn read_from_uart(&mut self, bytes: &[u8]) -> (std::string::String, bool) {
        let shown = self.typed(bytes);
        (shown, self.term.end_of_read())
    }

    fn read_raw(&mut self) -> Vec<u8> {
        let mut out = [0; RAW_QUEUE];
        let n = self.term.read_raw(&mut out);
        out[..n].to_vec()
    }

    /// The terminal with client 4 attached as term and focused, as in the
    /// `tui` scenario once Ctrl-T 4 is typed.
    fn focused_on_term() -> T {
        let mut t = T::new();
        t.term.attach(RAW, b"term");
        assert_eq!(t.typed(b"\x144"), status("[console] focus 4 (term)"));
        assert_eq!(t.term.focus(), RAW);
        assert!(!t.term.end_of_read(), "focus keys queue nothing");
        t
    }
}

#[test]
fn client_4_s_bytes_go_to_the_raw_queue_unedited_and_unechoed() {
    let mut t = T::focused_on_term();
    // Printable bytes, the editing keys, Enter both ways, controls and
    // bytes from 0x80: nothing echoes, nothing is edited away.
    let typed = b"ab\x08\x7f\x15c\r\n\r\x00\x07\x1f\x80\xff q";
    assert_eq!(t.read_from_uart(typed), ("".into(), true));
    assert_eq!(t.term.raw(), typed);
    assert!(t.delivered.is_empty(), "no line for anyone");
    assert_eq!(t.term.owner(), Owner::None);
    assert!(t.term.edit(RAW).is_empty());
    // The tui scenario's keys: Down, Down, Enter, q.
    let mut t = T::focused_on_term();
    assert_eq!(t.read_from_uart(b"\x1b[B\x1b[B\r"), ("".into(), true));
    assert_eq!(t.read_from_uart(b"q"), ("".into(), true));
    assert_eq!(t.read_raw(), b"\x1b[B\x1b[B\rq");
}

#[test]
fn escape_sequences_pass_whole() {
    let mut t = T::focused_on_term();
    // CSI with parameters, SS3, a lone ESC, ESC ESC, and an ESC with
    // Ctrl-T and a digit right after: the focus key still acts.
    let seqs: &[&[u8]] = &[
        b"\x1b[1;5A",
        b"\x1bOP",
        b"\x1b",
        b"\x1b\x1b[C",
        b"\x1b[200~x\x1b[201~",
    ];
    let mut want = Vec::new();
    for s in seqs {
        assert_eq!(t.read_from_uart(s), ("".into(), true));
        want.extend_from_slice(s);
    }
    assert_eq!(t.term.raw(), &want[..]);
    assert_eq!(
        t.read_from_uart(b"\x1b\x141"),
        (status("[console] focus 1 (client 1)"), true)
    );
    want.push(0x1b);
    assert_eq!(t.term.raw(), &want[..]);
    // Back on client 1, ESC sequences are skipped as in M7.
    assert_eq!(t.typed(b"\x1b[Ax"), "x");
    assert_eq!(t.term.edit(0), b"x");
}

#[test]
fn ctrl_t_and_a_digit_moves_the_focus_from_client_4() {
    let mut t = T::focused_on_term();
    t.term.attach(1, b"tui");
    assert_eq!(
        t.read_from_uart(b"ab\x142cd"),
        (format!("{}cd", status("[console] focus 2 (tui)")), true)
    );
    assert_eq!(t.term.raw(), b"ab");
    assert_eq!(t.term.edit(1), b"cd", "client 2 edits as before");
    // Back to 4: the half-typed line stays with client 2, and no input
    // line of client 4's is shown.
    assert_eq!(
        t.read_from_uart(b"\x144e"),
        (format!("\r\n{}", status("[console] focus 4 (term)")), true)
    );
    assert_eq!(t.term.raw(), b"abe");
    assert_eq!(t.term.owner(), Owner::None);
}

#[test]
fn ctrl_t_ctrl_t_queues_one_ctrl_t() {
    let mut t = T::focused_on_term();
    assert_eq!(t.read_from_uart(b"\x14\x14"), ("".into(), true));
    assert_eq!(t.term.raw(), b"\x14");
    // Three: one queued, the third starts a focus key.
    assert_eq!(t.read_from_uart(b"\x14\x14\x14"), ("".into(), true));
    assert_eq!(t.term.raw(), b"\x14\x14");
    assert_eq!(
        t.read_from_uart(b"3"),
        (status("[console] focus 3 (client 3)"), false)
    );
    // Four: two.
    let mut t = T::focused_on_term();
    t.read_from_uart(b"x\x14\x14\x14\x14y");
    assert_eq!(t.term.raw(), b"x\x14\x14y");
    // Only client 4 gets one: elsewhere Ctrl-T Ctrl-T drops both, as in M7.
    let mut t = T::new();
    assert_eq!(t.typed(b"\x14\x14z"), "z");
    assert!(t.term.raw().is_empty());
}

#[test]
fn ctrl_t_and_anything_else_drops_both() {
    let mut t = T::focused_on_term();
    for seq in [
        &b"\x140"[..],
        b"\x149",
        b"\x14a",
        b"\x14\x1b",
        b"\x14\r",
        b"\x14\xff",
    ] {
        assert_eq!(t.read_from_uart(seq), ("".into(), false), "{seq:?}");
        assert_eq!(t.term.focus(), RAW);
    }
    assert!(t.term.raw().is_empty());
    // A Ctrl-T at the end of one Read pairs with the next Read's byte.
    assert_eq!(t.read_from_uart(b"k\x14"), ("".into(), true));
    assert_eq!(t.read_from_uart(b"\x14"), ("".into(), true));
    assert_eq!(t.term.raw(), b"k\x14");
}

#[test]
fn a_full_queue_drops_and_rings_bel_once_per_read() {
    let mut t = T::focused_on_term();
    let fill: Vec<u8> = (0..RAW_QUEUE).map(|i| b'a' + (i % 26) as u8).collect();
    assert_eq!(t.read_from_uart(&fill), ("".into(), true));
    assert_eq!(t.term.raw().len(), RAW_QUEUE);
    // Every byte past it is dropped; one BEL for the Read, and no signal,
    // since nothing was queued.
    assert_eq!(t.read_from_uart(b"xyz"), ("\x07".into(), false));
    assert_eq!(t.read_from_uart(b"w"), ("\x07".into(), false));
    // A Read that fills the queue and drops the rest rings once too.
    let mut t = T::focused_on_term();
    let mut over = fill.clone();
    over.extend_from_slice(b"0123456789");
    assert_eq!(t.read_from_uart(&over), ("\x07".into(), true));
    assert_eq!(t.term.raw(), &fill[..]);
    // The focus keys still act on a full queue; Ctrl-T Ctrl-T's Ctrl-T is
    // dropped like any byte.
    assert_eq!(
        t.read_from_uart(b"\x14\x14\x141"),
        (
            format!("\x07{}", status("[console] focus 1 (client 1)")),
            false
        )
    );
    // ReadRaw makes room.
    assert_eq!(t.read_raw(), fill);
    assert_eq!(
        t.read_from_uart(b"\x144q"),
        (status("[console] focus 4 (term)"), true)
    );
    assert_eq!(t.term.raw(), b"q");
}

#[test]
fn read_raw_takes_everything_at_once_possibly_nothing() {
    let mut t = T::focused_on_term();
    assert_eq!(t.read_raw(), b"", "an empty queue answers at once");
    t.read_from_uart(b"one");
    t.read_from_uart(b"two");
    assert_eq!(t.read_raw(), b"onetwo");
    assert_eq!(t.read_raw(), b"");
    // Bytes typed for client 4 with nothing reading wait, as in `nofb`:
    // Ctrl-T 4, then `abc` and Up, then Ctrl-T 1 and a line for root.
    let mut t = T::new();
    t.term.attach(0, b"root");
    t.write(0, "nofb: type a line\n");
    t.write(0, "> ");
    assert_eq!(t.read(0).0, ReadAnswer::Saved);
    t.read_from_uart(b"\x144abc\x1b[A\x141hi\r");
    assert_eq!(t.term.raw(), b"abc\x1b[A");
    assert_eq!(t.delivered, [(0, "hi".into())]);
}

#[test]
fn only_client_4_reads_raw_and_it_never_reads_lines() {
    let mut buf = [0; MAX_BYTES];
    let none = |_: usize| 0;
    let words = |i: usize| [5u64, 0][i.min(1)];
    assert_eq!(
        decode(label::CONSOLE_READ_RAW, 4, 0, none, &mut buf),
        Ok((RAW, Request::ReadRaw))
    );
    // Words sent with it are ignored, whatever their length.
    assert_eq!(
        decode(label::CONSOLE_READ_RAW, 4, 2, words, &mut buf),
        Ok((RAW, Request::ReadRaw))
    );
    for badge in [0, 1, 2, 3, 5, 6, 7, 8, 9, 1 << 32] {
        assert_eq!(
            decode(label::CONSOLE_READ_RAW, badge, 0, none, &mut buf),
            Err(Refusal::BadBadge),
            "badge {badge}"
        );
    }
    assert_eq!(
        decode(label::CONSOLE_READ, 4, 0, none, &mut buf),
        Err(Refusal::BadBadge)
    );
    for badge in [1, 2, 3, 5, 8] {
        assert_eq!(
            decode(label::CONSOLE_READ, badge, 0, none, &mut buf),
            Ok((badge as usize - 1, Request::Read))
        );
    }
    // The label first, then the badge.
    assert_eq!(decode(0x126, 4, 0, none, &mut buf), Err(Refusal::BadLabel));
    // Client 4's other requests work as any client's.
    let name = |i: usize| [4u64, u64::from_le_bytes(*b"term\0\0\0\0")][i];
    assert_eq!(
        decode(label::CONSOLE_ATTACH, 4, 2, name, &mut buf),
        Ok((RAW, Request::Attach(b"term")))
    );
    assert_eq!(
        decode(label::CONSOLE_WRITE, 4, 2, name, &mut buf),
        Ok((RAW, Request::Write(b"term")))
    );
    for (l, r) in [
        (label::CONSOLE_FLUSH, Request::Flush),
        (label::CONSOLE_SYNC, Request::Sync),
    ] {
        assert_eq!(decode(l, 4, 0, none, &mut buf), Ok((RAW, r)));
    }
}

#[test]
fn client_4_has_no_input_line_and_its_output_is_shown() {
    let mut t = T::focused_on_term();
    t.read_from_uart(b"typed");
    // Another client's line: no input line of client 4's comes back after
    // it, though bytes wait in its queue.
    assert_eq!(t.write(0, "root: hello\n"), "root: hello\r\n");
    assert_eq!(t.term.owner(), Owner::None);
    // Its own output: shown, not obeyed, as M7's red team required.
    assert_eq!(
        t.write(RAW, "term: \x1b[2Jcleared\n"),
        "term: ^[[2Jcleared\r\n"
    );
    t.write(RAW, "\x1b[H");
    assert_eq!(t.flush(RAW), "^[[H");
    // A focus change to client 4 restores nothing.
    let mut t = T::new();
    t.write(0, "> ");
    t.read(0);
    t.typed(b"half");
    assert_eq!(
        t.typed(b"\x144"),
        format!("\r\n{}", status("[console] focus 4 (client 4)"))
    );
    assert_eq!(t.term.owner(), Owner::None);
    // And back: client 1's line is restored as in M7.
    assert_eq!(
        t.typed(b"\x141"),
        format!("{}> half", status("[console] focus 1 (client 1)"))
    );
}
