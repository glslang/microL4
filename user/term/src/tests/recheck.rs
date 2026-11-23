//! The M8 fix round's fresh re-check. Each test is `#[ignore]`d so the
//! default run passes; `cargo test -p term --lib recheck -- --ignored`
//! runs them. The first asserts a guarantee the fix round's tests state
//! and fails; the other two record how the input queue behaves, and pass.

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

/// `tests/review.rs` states the guarantee "while term holds both parts:
/// the client reads each key's bytes together, with each reply whole
/// before or after them". A key typed as a UTF-8 character is several
/// bytes too, and console can bring them in two `ReadRaw`s as it can an
/// escape sequence's; `server::unfinished` looks only for ESC, so a reply
/// queued between them goes inside the character: `é` (C3 A9) reaches the
/// client as C3, `ESC [ 0 n`, A9.
#[test]
#[ignore = "recheck: a reply still lands inside a UTF-8 key that came in two ReadRaws; unfinished() finds only ESC sequences"]
fn a_reply_never_lands_inside_a_utf8_key_that_came_in_two_read_raws() {
    let got = with_server(|s| {
        let mut out = [0u8; INPUT];
        s.keys(b"\xc3");
        s.request(Request::Write(b"\x1b[5n"), || unreachable!(), &mut out);
        s.keys(b"\xa9");
        read_all(s)
    });
    assert!(
        got == b"\x1b[0n\xc3\xa9" || got == b"\xc3\xa9\x1b[0n",
        "the client reads \"{}\"",
        got.escape_ascii()
    );
}

/// Escape, then a reply, then `x`, all before the client reads: the reply
/// goes before the lone ESC, so the client reads the reply, then ESC and
/// `x` together, which is what Alt-x sends; in arrival order the reply's
/// own ESC would have stood between them. `docs/design.md` states the
/// rule ("the reply goes before it too") but not this consequence.
#[test]
#[ignore = "recheck: records that Escape, a reply, then x reads as the reply, then ESC x (passes)"]
fn escape_then_a_reply_then_a_key_reads_as_the_reply_then_esc_and_the_key() {
    let got = with_server(|s| {
        let mut out = [0u8; INPUT];
        s.keys(b"\x1b");
        s.request(Request::Write(b"\x1b[5n"), || unreachable!(), &mut out);
        s.keys(b"x");
        read_all(s)
    });
    assert_eq!(got, b"\x1b[0n\x1bx", "\"{}\"", got.escape_ascii());
}

/// The red team's finding for a key rather than a reply: keys are still
/// queued as far as they fit, so with 510 bytes unread F5 (`ESC [ 1 5 ~`)
/// keeps `ESC [`, and the next byte typed, `A`, completes Up, which nobody
/// typed. The design keeps the per-byte rule for keys ("console splits
/// keys anyway"), and console's own full queue can cut a key the same
/// way; recorded as it behaves.
#[test]
#[ignore = "recheck: records that a key cut by the full queue and the next key typed read as Up (passes)"]
fn a_key_cut_by_the_full_queue_and_the_next_key_read_as_another_key() {
    let got = with_server(|s| {
        s.keys(&[b'x'; INPUT - 2]);
        s.keys(b"\x1b[15~");
        let mut read = read_all(s);
        s.keys(b"A");
        read.extend(read_all(s));
        (read, s.stats().dropped)
    });
    assert_eq!(got.1, 3);
    assert_eq!(&got.0[INPUT - 2..], b"\x1b[A");
}
