//! The parser's table test: every state and every byte `0x00` to `0xFF`,
//! one at a time, against a transcription of the note's state table
//! (`docs/design.md`, "`term`: the parser") written here from the note, not
//! taken from the parser.

use std::vec::Vec;
use std::{format, vec};

use crate::parser::{Actions, Parser, State};

/// What an action the test can see did.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Act {
    Print(char),
    Execute(u8),
    Esc(u8),
    Csi(u8),
    Osc,
    Ignored,
}

/// Records the parser's actions.
#[derive(Default)]
pub struct Rec(pub Vec<Act>);

impl Actions for Rec {
    fn print(&mut self, c: char) {
        self.0.push(Act::Print(c));
    }
    fn execute(&mut self, byte: u8) {
        self.0.push(Act::Execute(byte));
    }
    fn esc_dispatch(&mut self, _: &[u8], final_byte: u8) {
        self.0.push(Act::Esc(final_byte));
    }
    fn csi_dispatch(&mut self, _: &[u16], _: &[u8], final_byte: u8) {
        self.0.push(Act::Csi(final_byte));
    }
    fn osc_dispatch(&mut self, _: &[u8]) {
        self.0.push(Act::Osc);
    }
    fn ignored(&mut self) {
        self.0.push(Act::Ignored);
    }
}

/// C0 as the note counts it: `0x00` to `0x17`, `0x19` and `0x1C` to `0x1F`.
fn c0(b: u8) -> bool {
    matches!(b, 0x00..=0x17 | 0x19 | 0x1C..=0x1F)
}

/// The note's table: the actions `b` causes in state `s` and the state it
/// leaves the parser in, and whether a UTF-8 code point is then in
/// progress.
fn expected(s: State, b: u8) -> (Vec<Act>, State, bool) {
    use State::*;
    // Leaving a string runs its exit action: OSC end, or the string
    // counted as ignored.
    let exit = match s {
        OscString => vec![Act::Osc],
        DcsEntry | DcsParam | DcsIntermediate | DcsPassthrough | DcsIgnore | SosPmApcString => {
            vec![Act::Ignored]
        }
        _ => vec![],
    };
    // Every state: CAN and SUB execute and go to ground, ESC goes to
    // escape, DEL is ignored.
    match b {
        0x18 | 0x1A => {
            let mut a = exit;
            a.push(Act::Execute(b));
            return (a, Ground, false);
        }
        0x1B => return (exit, Escape, false),
        0x7F => return (vec![], s, false),
        _ => {}
    }
    let stay = (vec![], s, false);
    let to = |t: State| (vec![], t, false);
    let execute = (vec![Act::Execute(b)], s, false);
    let high = b >= 0x80;
    match s {
        Ground => match b {
            _ if c0(b) => execute,
            0x20..=0x7E => (vec![Act::Print(char::from(b))], Ground, false),
            0xC2..=0xF4 => (vec![], Ground, true),
            _ => (vec![Act::Print('\u{FFFD}')], Ground, false),
        },
        Escape => match b {
            _ if c0(b) => execute,
            _ if high => stay,
            0x20..=0x2F => to(EscapeIntermediate),
            b'[' => to(CsiEntry),
            b']' => to(OscString),
            b'P' => to(DcsEntry),
            b'X' | b'^' | b'_' => to(SosPmApcString),
            _ => (vec![Act::Esc(b)], Ground, false),
        },
        EscapeIntermediate => match b {
            _ if c0(b) => execute,
            _ if high => stay,
            0x20..=0x2F => stay,
            _ => (vec![Act::Esc(b)], Ground, false),
        },
        CsiEntry => match b {
            _ if c0(b) => execute,
            _ if high => stay,
            0x20..=0x2F => to(CsiIntermediate),
            b'0'..=b'9' | b';' => to(CsiParam),
            b':' => to(CsiIgnore),
            b'<'..=b'?' => to(CsiParam),
            _ => (vec![Act::Csi(b)], Ground, false),
        },
        CsiParam => match b {
            _ if c0(b) => execute,
            _ if high => stay,
            b'0'..=b'9' | b';' => stay,
            b':' | b'<'..=b'?' => to(CsiIgnore),
            0x20..=0x2F => to(CsiIntermediate),
            _ => (vec![Act::Csi(b)], Ground, false),
        },
        CsiIntermediate => match b {
            _ if c0(b) => execute,
            _ if high => stay,
            0x20..=0x2F => stay,
            0x30..=0x3F => to(CsiIgnore),
            _ => (vec![Act::Csi(b)], Ground, false),
        },
        CsiIgnore => match b {
            _ if c0(b) => execute,
            _ if high => stay,
            0x20..=0x3F => stay,
            _ => (vec![Act::Ignored], Ground, false),
        },
        DcsEntry => match b {
            _ if c0(b) || high => stay,
            0x20..=0x2F => to(DcsIntermediate),
            b'0'..=b'9' | b';' => to(DcsParam),
            b':' => to(DcsIgnore),
            b'<'..=b'?' => to(DcsParam),
            _ => to(DcsPassthrough),
        },
        DcsParam => match b {
            _ if c0(b) || high => stay,
            b'0'..=b'9' | b';' => stay,
            b':' | b'<'..=b'?' => to(DcsIgnore),
            0x20..=0x2F => to(DcsIntermediate),
            _ => to(DcsPassthrough),
        },
        DcsIntermediate => match b {
            _ if c0(b) || high => stay,
            0x20..=0x2F => stay,
            0x30..=0x3F => to(DcsIgnore),
            _ => to(DcsPassthrough),
        },
        DcsPassthrough | DcsIgnore | SosPmApcString => stay,
        OscString => match b {
            0x07 => (vec![Act::Osc], Ground, false),
            _ => stay,
        },
    }
}

#[test]
fn every_state_and_byte_follows_the_table() {
    let mut wrong = Vec::new();
    for s in State::ALL {
        for b in 0..=255u8 {
            let mut p = Parser::new();
            p.enter(s);
            let mut rec = Rec::default();
            p.advance(&mut rec, b);
            let got = (rec.0, p.state(), p.in_utf8());
            let want = expected(s, b);
            if got != want {
                wrong.push(format!("{s:?} {b:#04x}: got {got:?}, want {want:?}"));
            }
        }
    }
    assert!(
        wrong.is_empty(),
        "{} transitions differ:\n{}",
        wrong.len(),
        wrong.join("\n")
    );
}

/// A byte that leaves ground mid-code-point first prints U+FFFD for what
/// came before, then acts as it would in ground, in every case the table
/// gives.
#[test]
fn a_code_point_cut_short_prints_a_replacement_then_the_byte_acts() {
    for b in 0..=255u8 {
        // After the lead E2, only 80 to BF continue it.
        let mut p = Parser::new();
        let mut rec = Rec::default();
        p.advance(&mut rec, 0xE2);
        assert!(p.in_utf8());
        p.advance(&mut rec, b);
        if (0x80..=0xBF).contains(&b) {
            assert!(rec.0.is_empty() && p.in_utf8(), "{b:#04x} continues it");
            continue;
        }
        let (mut want, state, utf8) = expected(State::Ground, b);
        want.insert(0, Act::Print('\u{FFFD}'));
        assert_eq!(
            (rec.0, p.state(), p.in_utf8()),
            (want, state, utf8),
            "{b:#04x}"
        );
    }
}
