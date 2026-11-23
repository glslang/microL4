//! The proptest of random byte streams (`docs/design.md`, "Golden tests"
//! and "Invariants"): streams weighted toward ESC, `[`, digits, `;`, finals
//! and UTF-8 lead and continuation bytes, with real sequences mixed in. For
//! each: nothing panics; after every write the cursor is in the grid, the
//! pending wrap only in the last column, the region inside the screen and
//! at least two rows unless it is the whole screen, the cursor inside it
//! under DECOM, and every cell a graphic character; no write lands outside
//! the grid; the ways of writing agree; and the frames drawn after every
//! write equal a full render.

use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use proptest::sample::select;

use super::golden::{Snapshot, glyph};
use crate::Terminal;
use crate::look::{Drawn, Look};

/// Sequences term acts on, and some it must ignore, to reach deep states.
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
    b"\x1b[?25l",
    b"\x1b[?5h",
    b"\x1b[2;4r",
    b"\x1b[3;9r",
    b"\x1b[r",
    b"\x1b[4h",
    b"\x1b[4l",
    b"\x1b[20h",
    b"\x1b[20l",
    b"\x1b7",
    b"\x1b8",
    b"\x1b[s",
    b"\x1b[u",
    b"\x1bc",
    b"\x1b#8",
    b"\x1b(0",
    b"\x1b(B",
    b"\x1b)0",
    b"\x0e",
    b"\x0f",
    b"\x1b[3L",
    b"\x1b[2M",
    b"\x1b[5@",
    b"\x1b[3P",
    b"\x1b[4X",
    b"\x1b[2S",
    b"\x1b[2T",
    b"\x1bD",
    b"\x1bM",
    b"\x1bE",
    b"\x1bH",
    b"\x1b[3g",
    b"\x1b[g",
    b"\x1b[2I",
    b"\x1b[2Z",
    b"\x1b[6n",
    b"\x1b[5n",
    b"\x1b[c",
    b"\x1b[3b",
    b"\x1b[65535b",
    b"\x1b[38;2;10;200;30m",
    b"\x1b[48;5;123m",
    b"\x1b[1;2;3;4;5;7;8;9m",
    b"\x1b[38;5;300m",
    b"\x1b]0;title\x07",
    b"\x1b]2;t\x1b\\",
    b"\x1bP1$qm\x1b\\",
    b"\x1bXsos\x1b\\",
    b"\x1b[10;20H",
    b"\x1b[99;99H",
    b"\x1b[65535A",
    b"\x1b[65535B",
    b"\x1b[65535C",
    b"\x1b[65535L",
    b"\x1b[J",
    b"\x1b[1J",
    b"\x1b[2K",
    b"\x1b[3 q",
    b"\x1b[5 q",
    b"\xc3\xa9",
    b"\xe2\x82\xac",
    b"\xf0\x9f\x98\x80",
    b"\r\n",
    b"\t",
    b"999999",
];

fn token() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        5 => Just(vec![0x1B]),
        4 => Just(vec![b'[']),
        4 => (b'0'..=b'9').prop_map(|b| vec![b]),
        3 => Just(vec![b';']),
        4 => (0x40u8..=0x7E).prop_map(|b| vec![b]),
        1 => (0x20u8..=0x2F).prop_map(|b| vec![b]),
        1 => (0x3Au8..=0x3F).prop_map(|b| vec![b]),
        2 => (0x00u8..=0x1F).prop_map(|b| vec![b]),
        3 => (0xC2u8..=0xF4).prop_map(|b| vec![b]),
        3 => (0x80u8..=0xBF).prop_map(|b| vec![b]),
        1 => prop_oneof![Just(0xC0u8), Just(0xC1), 0xF5u8..=0xFF].prop_map(|b| vec![b]),
        4 => (0x20u8..=0x7E).prop_map(|b| vec![b]),
        1 => Just(vec![0x7F]),
        5 => select(SEQUENCES).prop_map(<[u8]>::to_vec),
        1 => any::<u8>().prop_map(|b| vec![b]),
    ]
}

const MAX_TOKENS: usize = if cfg!(miri) { 24 } else { 1600 };
const MAX_BYTES: usize = if cfg!(miri) { 96 } else { 4096 };

fn stream() -> impl Strategy<Value = Vec<u8>> {
    prop::collection::vec(token(), 0..MAX_TOKENS).prop_map(|t| {
        let mut s = t.concat();
        s.truncate(MAX_BYTES);
        s
    })
}

/// A word no screen writes: its code point is not one.
const CANARY: u64 = 0xDEAD_BEEF_00FF_FFFF;
const SPARE: usize = 16;

/// The invariants that hold after every write.
fn check(t: &Terminal<'_>) -> Result<(), String> {
    let s = t.screen();
    let (cols, rows) = (s.cols(), s.rows());
    let c = s.cursor();
    if c.row >= rows || c.col >= cols {
        return Err(format!("cursor {},{} outside {cols}x{rows}", c.row, c.col));
    }
    if c.pending_wrap && c.col != cols - 1 {
        return Err(format!("pending wrap in column {}", c.col));
    }
    let (top, bottom) = s.region();
    if top > bottom || bottom >= rows {
        return Err(format!("region {top}..={bottom} in {rows} rows"));
    }
    if (top, bottom) != (0, rows - 1) && top >= bottom {
        return Err(format!("a region of one row, {top}"));
    }
    if s.modes().origin && !(top..=bottom).contains(&c.row) {
        return Err(format!(
            "DECOM with the cursor in row {} outside {top}..={bottom}",
            c.row
        ));
    }
    if s.title().len() > crate::screen::TITLE_MAX {
        return Err("title too long".into());
    }
    for r in 0..rows {
        for col in 0..cols {
            let ch = s.cell(r, col).ch as u32;
            if ch < 0x20 || (0x7F..=0x9F).contains(&ch) || ch > 0x10_FFFF {
                return Err(format!("cell {r},{col} holds U+{ch:04X}"));
            }
        }
    }
    Ok(())
}

/// Runs `writes`, checking the invariants after each and drawing a frame;
/// the final state, and whether the drawn looks equal a full render.
fn run_checked(cols: usize, rows: usize, writes: &[&[u8]]) -> Result<(Snapshot, bool), String> {
    let n = cols * rows;
    let mut main = vec![CANARY; n + SPARE];
    let mut alt = vec![CANARY; n + SPARE];
    let mut drawn_words = vec![0u64; n];
    let snap;
    let damage_ok;
    {
        let mut t = Terminal::new(cols, rows, &mut main, &mut alt);
        let mut drawn = Drawn::new(cols, rows, &mut drawn_words, Look::blank(glyph(' ')));
        let mut reply = Vec::new();
        check(&t)?;
        drawn.frame(t.screen(), glyph, |_, _, _| {});
        for w in writes {
            t.write(w, |r| reply.extend_from_slice(r));
            check(&t)?;
            drawn.frame(t.screen(), glyph, |_, _, _| {});
        }
        damage_ok =
            (0..rows).all(|r| (0..cols).all(|c| drawn.get(r, c) == t.screen().look(r, c, glyph)));
        snap = Snapshot::of(&t, reply);
    }
    if main[n..].iter().chain(&alt[n..]).any(|&w| w != CANARY) {
        return Err("a write landed past the grid".into());
    }
    Ok((snap, damage_ok))
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_streams_keep_the_invariants_however_they_are_split(
        cols in 1usize..=24,
        rows in 1usize..=9,
        bytes in stream(),
        splits in prop::collection::vec(1usize..=48, 1..64),
    ) {
        // Whole, byte by byte, and in chunks of the sizes drawn, cycled.
        let whole: Vec<&[u8]> = vec![&bytes];
        let single: Vec<&[u8]> = bytes.chunks(1).collect();
        let mut chunks: Vec<&[u8]> = Vec::new();
        let mut i = 0;
        let mut k = 0;
        while i < bytes.len() {
            let end = (i + splits[k % splits.len()]).min(bytes.len());
            chunks.push(&bytes[i..end]);
            i = end;
            k += 1;
        }
        let mut first: Option<Snapshot> = None;
        for (way, writes) in [("whole", whole), ("byte by byte", single), ("chunks", chunks)] {
            let (snap, damage_ok) = run_checked(cols, rows, &writes)
                .map_err(|e| TestCaseError::fail(format!("{way}: {e}")))?;
            prop_assert!(damage_ok, "{way}: the frames drawn differ from a full render");
            match &first {
                None => first = Some(snap),
                Some(f) => prop_assert_eq!(f, &snap, "{} differs from writing it whole", way),
            }
        }
    }
}

/// The state after `writes` on a fresh terminal.
fn snapshot(cols: usize, rows: usize, writes: &[&[u8]]) -> Snapshot {
    let mut main = vec![0u64; cols * rows];
    let mut alt = vec![0u64; cols * rows];
    let mut t = Terminal::new(cols, rows, &mut main, &mut alt);
    let mut reply = Vec::new();
    for w in writes {
        t.write(w, |r| reply.extend_from_slice(r));
    }
    Snapshot::of(&t, reply)
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    /// REP n leaves the state n prints would, past the count where its
    /// prints cycle too, from any state a random stream leaves (IRM,
    /// DECAWM, regions and DECOM among them).
    #[test]
    fn rep_acts_as_its_count_of_prints(
        cols in 1usize..=6,
        rows in 1usize..=4,
        prefix in prop::collection::vec(token(), 0..if cfg!(miri) { 8 } else { 64 }),
        c in select(&b"xq ~"[..]),
        n in 0usize..if cfg!(miri) { 120 } else { 400 },
    ) {
        // CAN ends whatever sequence the prefix left unfinished.
        let mut start = prefix.concat();
        start.extend_from_slice(&[0x18, c]);
        let rep = format!("\x1b[{n}b");
        let prints = vec![c; n.max(1)];
        prop_assert_eq!(
            snapshot(cols, rows, &[&start, rep.as_bytes()]),
            snapshot(cols, rows, &[&start, &prints])
        );
    }
}
