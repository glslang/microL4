//! The M8 fresh review's tests (reviewer T). One finding: a DSR or DA reply
//! queued between two `ReadRaw`s that each bring part of one key landed
//! inside that key, so the client read keys nobody typed even though the
//! reply was queued whole. The red team's fix for
//! `docs/redteam/m8-reply-cut-short.md` (queue a reply whole or not at
//! all) does not cover it. The M8 fix round puts a reply before an
//! unfinished key the input queue ends in, so the case where term holds
//! both parts passes; the case where the client has already read the
//! first part is a limit, kept as a test of how it behaves.

use std::string::String;
use std::vec;
use std::vec::Vec;

use fb::{Format, Geometry};

use crate::STATE_WORDS;
use crate::server::{Answer, INPUT, Request, Server};
use crate::session::Session;

/// A host session's server, as `term::run` makes it.
fn with_server<R>(f: impl FnOnce(&mut Server<'_>) -> R) -> R {
    let g = Geometry::new(84, 50, 90, Format::Bgr).unwrap();
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

/// console hands term what its raw queue holds at each `ReadRaw`, so a key
/// whose bytes reached uart in two `Read`s (a FIFO's trigger level, a slow
/// line; tui's decoder waits for the rest for this reason) can come in two
/// `ReadRaw`s. A `Write` that asked DSR or DA between them queued its
/// reply, whole, between the key's two parts: F5 (`ESC [ 1 5 ~`) reached
/// the client as `ESC [ 1`, `ESC [ 0 n`, `5 ~`, which tui's decoder (and
/// any that drops a sequence another ESC cuts short) reads as an unknown
/// key and the keys `5` and `~`, and `5` opens tui's Keys panel; Up (`ESC
/// [ A`) split after its ESC became the keys `[` and `A`. The guarantee,
/// while term holds both parts: the client reads each escape sequence's
/// bytes together, with each reply whole before or after them (a UTF-8
/// character is not covered: `tests/recheck.rs`). It failed before the
/// fix round, `#[ignore]`d.
#[test]
fn a_reply_never_lands_inside_a_key_that_came_in_two_read_raws() {
    for (first, ask, reply, rest, key) in [
        (
            &b"\x1b[1"[..],
            &b"\x1b[5n"[..],
            &b"\x1b[0n"[..],
            &b"5~"[..],
            "F5",
        ),
        (b"\x1b", b"\x1b[c", b"\x1b[?1;2c", b"[A", "Up"),
    ] {
        let stream = with_server(|s| {
            let mut out = [0u8; INPUT];
            // One ReadRaw brings the start of the key.
            s.keys(first);
            // The client asks for a report.
            s.request(Request::Write(ask), || unreachable!(), &mut out);
            // The next ReadRaw brings the rest of the key.
            s.keys(rest);
            read_all(s)
        });
        let typed = [first, rest].concat();
        let before = [reply, &typed[..]].concat();
        let after = [&typed[..], reply].concat();
        assert!(
            stream == before || stream == after,
            "{key}: the client reads {:?}: the reply inside the key",
            String::from_utf8_lossy(&stream)
        );
    }
}

/// The limit of the fix: once the client has read a key's first part,
/// those bytes are gone from term's queue, and term has no timer to hold a
/// reply back until the key ends, so a reply queued before the rest
/// arrives still lands inside the key. That is the case whenever the
/// client already waits in `Read` when the first part comes, since term
/// releases it at once; tui never asks DSR or DA. Recorded as it behaves:
/// F5 becomes `ESC [ 1`, then `ESC [ 0 n 5 ~`; Up split after its ESC
/// becomes ESC, then `ESC [ ? 1 ; 2 c [ A`.
#[test]
fn a_reply_lands_inside_a_key_whose_first_part_the_client_has_read() {
    for (first, ask, rest, reads) in [
        (
            &b"\x1b[1"[..],
            &b"\x1b[5n"[..],
            &b"5~"[..],
            [&b"\x1b[1"[..], &b"\x1b[0n5~"[..]],
        ),
        (b"\x1b", b"\x1b[c", b"[A", [b"\x1b", b"\x1b[?1;2c[A"]),
    ] {
        let got = with_server(|s| {
            let mut out = [0u8; INPUT];
            s.keys(first);
            // The client reads the key's first part.
            let one = read_all(s);
            s.request(Request::Write(ask), || unreachable!(), &mut out);
            s.keys(rest);
            [one, read_all(s)]
        });
        assert_eq!(got, reads.map(<[u8]>::to_vec));
    }
}
