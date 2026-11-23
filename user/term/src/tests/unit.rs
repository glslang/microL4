//! Unit tests: the palette and the true-colour mapping, the cell and look
//! words, the renderer's look steps (one per row of its table) and the
//! damage, and the parser's limits.

use std::vec;
use std::vec::Vec;

use super::golden::glyph;
use super::table::{Act, Rec};
use crate::Terminal;
use crate::look::{Drawn, Look};
use crate::palette::{self, DEFAULT_BG, DEFAULT_FG, nearest, rgb};
use crate::parser::{Actions, MAX_OSC, Parser};
use crate::screen::{Attrs, Cell, Color, Pen};

#[test]
fn the_palette_is_vga_then_xterms_cube_and_ramp() {
    assert_eq!(rgb(0), 0x000000);
    assert_eq!(rgb(3), 0xAA5500);
    assert_eq!(rgb(7), 0xAAAAAA);
    assert_eq!(rgb(8), 0x555555);
    assert_eq!(rgb(15), 0xFFFFFF);
    assert_eq!(rgb(16), 0x000000);
    assert_eq!(rgb(17), 0x00005F);
    assert_eq!(rgb(16 + 36 + 6 * 2 + 3), 0x5F87AF);
    assert_eq!(rgb(231), 0xFFFFFF);
    assert_eq!(rgb(232), 0x080808);
    assert_eq!(rgb(244), 0x808080);
    assert_eq!(rgb(255), 0xEEEEEE);
    assert_eq!((DEFAULT_FG, DEFAULT_BG), (rgb(7), rgb(0)));
}

#[test]
fn a_true_colour_maps_to_the_nearest_entry_from_16() {
    // Every cube colour and every grey maps to itself: no grey of the ramp
    // is one of the cube's.
    for i in 16..=255u8 {
        let c = rgb(i);
        let (r, g, b) = ((c >> 16) as u8, (c >> 8) as u8, c as u8);
        assert_eq!(nearest(r, g, b), i, "colour {i}");
    }
    // Per channel the nearest level: 0x2F is 47 from 0x00 and 48 from 0x5F,
    // 0x30 the other way round.
    assert_eq!(nearest(0x2F, 0xFF, 0xFF), 16 + 6 * 5 + 5);
    assert_eq!(nearest(0x30, 0xFF, 0xFF), 16 + 36 + 6 * 5 + 5);
    // 0x73 is halfway between 0x5F and 0x87: the lower.
    assert_eq!(nearest(0x73, 0x73, 0xFF), 16 + 36 + 6 + 5);
    assert_eq!(nearest(0x73, 0, 0), 16 + 36);
    // A grey off the cube's levels goes to the ramp: 0x80 is 7 from 0x87
    // per channel (147 squared) and the ramp's 0x80 exactly.
    assert_eq!(nearest(0x80, 0x80, 0x80), 244);
    // 13 is halfway between greys 8 and 18: the lower.
    assert_eq!(nearest(13, 13, 13), 232);
    assert_eq!(nearest(14, 14, 14), 233);
    // Near black: the cube's black and grey 8 are both 3 × 4² from 4: the
    // cube on a tie.
    assert_eq!(nearest(4, 4, 4), 16);
    assert_eq!(nearest(5, 5, 5), 232);
    // A dark red is nearer a grey than the cube's black or 0x5F red.
    assert_eq!(nearest(0x30, 0, 0), 233);
    // Pure red is the cube's.
    assert_eq!(nearest(255, 0, 0), 196);
    // Beyond the ramp's top: 0xFA is the cube's white (5 away) before the
    // ramp's 0xEE (12 away).
    assert_eq!(nearest(0xFA, 0xFA, 0xFA), 231);
    assert_eq!(palette::LEVELS.len(), 6);
}

#[test]
fn a_cell_word_round_trips() {
    let pens = [
        Pen::default(),
        Pen {
            fg: Color::Index(0),
            bg: Color::Index(255),
            attrs: Attrs(0xFF),
        },
        Pen {
            fg: Color::Index(196),
            bg: Color::Default,
            attrs: Attrs::BOLD,
        },
    ];
    for ch in [' ', 'a', '\u{A0}', '\u{FFFD}', '\u{10FFFF}', '\u{1F600}'] {
        for pen in pens {
            let c = Cell { ch, pen };
            assert_eq!(Cell::from_word(c.word()), c);
        }
    }
    // A blank is not word 0, and a word with no code point reads as U+FFFD.
    assert_ne!(Cell::blank(Color::Default).word(), 0);
    assert_eq!(Cell::from_word(0x1F_FFFF).ch, '\u{FFFD}');
    assert_eq!(Cell::from_word(0xD800).ch, '\u{FFFD}');
}

#[test]
fn a_look_word_round_trips() {
    let l = Look {
        glyph: Look::GLYPHS - 1,
        fg: 0xFF_FFFF,
        bg: 0x12_3456,
        flags: 0x1F,
    };
    assert_eq!(Look::from_word(l.word()), l);
    let b = Look::blank(7);
    assert_eq!(Look::from_word(b.word()), b);
    assert_ne!(b.word(), l.word());
}

/// The look at (0, 0) after `input` on a 4 × 2 screen.
fn look_after(input: &[u8], row: usize, col: usize) -> Look {
    let mut main = [0u64; 8];
    let mut alt = [0u64; 8];
    let mut t = Terminal::new(4, 2, &mut main, &mut alt);
    t.write(input, |_| {});
    t.screen().look(row, col, glyph)
}

#[test]
fn the_look_resolves_defaults_and_swaps_for_inverse_and_decscnm() {
    // The cursor sits in column 2, away from the cell looked at.
    let l = look_after(b"x", 0, 0);
    assert_eq!(
        (l.fg, l.bg, l.flags, l.glyph),
        (DEFAULT_FG, DEFAULT_BG, 0, glyph('x'))
    );
    let l = look_after(b"\x1b[31;44mx", 0, 0);
    assert_eq!((l.fg, l.bg), (rgb(1), rgb(4)));
    let l = look_after(b"\x1b[7mx", 0, 0);
    assert_eq!((l.fg, l.bg), (DEFAULT_BG, DEFAULT_FG));
    let l = look_after(b"\x1b[?5hx", 0, 0);
    assert_eq!((l.fg, l.bg), (DEFAULT_BG, DEFAULT_FG));
    // Inverse under DECSCNM swaps twice.
    let l = look_after(b"\x1b[?5h\x1b[7;32mx", 0, 0);
    assert_eq!((l.fg, l.bg), (rgb(2), DEFAULT_BG));
}

#[test]
fn conceal_draws_a_space_and_no_line() {
    let l = look_after(b"\x1b[8;4;9mx", 0, 0);
    assert_eq!((l.glyph, l.flags), (glyph(' '), 0));
}

#[test]
fn faint_is_the_mean_of_the_two_colours_rounded_down() {
    let l = look_after(b"\x1b[2;97;41mx", 0, 0);
    // (FF + AA) / 2 = D4 (rounded down from D4.8), (FF + 00) / 2 = 7F.
    assert_eq!((l.fg, l.bg), (0xD47F7F, rgb(1)));
}

#[test]
fn bold_underline_and_strike_are_flags() {
    let l = look_after(b"\x1b[1mx", 0, 0);
    assert_eq!(l.flags, Look::BOLD);
    let l = look_after(b"\x1b[4mx", 0, 0);
    assert_eq!(l.flags, Look::UNDERLINE);
    let l = look_after(b"\x1b[9mx", 0, 0);
    assert_eq!(l.flags, Look::STRIKE);
    // Italic and blink are drawn upright and steady.
    let l = look_after(b"\x1b[3;5mx", 0, 0);
    assert_eq!(l, look_after(b"x", 0, 0));
}

#[test]
fn the_cursor_swaps_the_colours_or_sets_a_flag_unless_hidden() {
    // A block cursor on a blank swaps its colours.
    let l = look_after(b"", 0, 0);
    assert_eq!((l.fg, l.bg, l.flags), (DEFAULT_BG, DEFAULT_FG, 0));
    let l = look_after(b"\x1b[4 q", 0, 0);
    assert_eq!(
        (l.fg, l.bg, l.flags),
        (DEFAULT_FG, DEFAULT_BG, Look::CURSOR_UNDERLINE)
    );
    let l = look_after(b"\x1b[6 q", 0, 0);
    assert_eq!(l.flags, Look::CURSOR_BAR);
    let l = look_after(b"\x1b[?25l", 0, 0);
    assert_eq!(l, Look::blank(glyph(' ')));
    // With the pending wrap the cursor is in the last column.
    let l = look_after(b"abcd", 0, 3);
    assert_eq!((l.fg, l.bg, l.glyph), (DEFAULT_BG, DEFAULT_FG, glyph('d')));
    // After faint: the block swaps the faint foreground into the background.
    let l = look_after(b"\x1b[2;37;44m \x1b[D", 0, 0);
    assert_eq!((l.fg, l.bg), (rgb(4), 0x5555AA));
}

#[test]
fn a_frame_draws_exactly_the_cells_whose_look_changed() {
    let mut main = [0u64; 12];
    let mut alt = [0u64; 12];
    let mut words = [0u64; 12];
    let mut t = Terminal::new(4, 3, &mut main, &mut alt);
    let mut d = Drawn::new(4, 3, &mut words, Look::blank(glyph(' ')));
    let mut cells = Vec::new();
    // The first frame shows only the cursor at home.
    assert_eq!(d.frame(t.screen(), glyph, |r, c, _| cells.push((r, c))), 1);
    assert_eq!(cells, [(0, 0)]);
    cells.clear();
    // A print draws its cell and the cursor's new one.
    t.write(b"a", |_| {});
    d.frame(t.screen(), glyph, |r, c, _| cells.push((r, c)));
    assert_eq!(cells, [(0, 0), (0, 1)]);
    cells.clear();
    // Overwriting a cell with what it holds draws nothing but the cursor.
    t.write(b"\r", |_| {});
    d.frame(t.screen(), glyph, |r, c, _| cells.push((r, c)));
    cells.clear();
    t.write(b"a\x1b[D", |_| {});
    assert_eq!(d.frame(t.screen(), glyph, |r, c, _| cells.push((r, c))), 0);
    // A scroll redraws the cells whose looks moved.
    t.write(b"\x1b[S", |_| {});
    d.frame(t.screen(), glyph, |r, c, _| cells.push((r, c)));
    assert_eq!(cells, [(0, 0)]);
    assert_eq!(d.get(0, 0), t.screen().look(0, 0, glyph));
}

#[test]
fn the_state_window_holds_a_full_size_terminal() {
    // Three grids of 240 × 75 words in the note's 106 pages.
    const { assert!(crate::STATE_WORDS * 8 == 432_000 && 432_000 <= 106 * 4096) };
    let mut state = vec![0u64; crate::STATE_WORDS];
    let (main, alt, words) = crate::split_state(&mut state);
    let mut t = Terminal::new(crate::MAX_COLS, crate::MAX_ROWS, main, alt);
    let mut d = Drawn::new(
        crate::MAX_COLS,
        crate::MAX_ROWS,
        words,
        Look::blank(glyph(' ')),
    );
    assert_eq!(d.frame(t.screen(), glyph, |_, _, _| {}), 1);
    let mut reply = Vec::new();
    t.write(b"\x1b[99;999Hx\x1b[6n", |r| reply.extend_from_slice(r));
    assert_eq!(reply, b"\x1b[75;240R");
    // Home loses the cursor; the last cell gets the x and the cursor.
    let mut cells = Vec::new();
    d.frame(t.screen(), glyph, |r, c, _| cells.push((r, c)));
    assert_eq!(cells, [(0, 0), (74, 239)]);
}

/// Records CSI parameters, intermediates and OSC strings.
#[derive(Default)]
struct Seq {
    csi: Vec<(Vec<u16>, Vec<u8>, u8)>,
    esc: Vec<(Vec<u8>, u8)>,
    osc: Vec<Vec<u8>>,
    ignored: usize,
}

impl Actions for Seq {
    fn print(&mut self, _: char) {}
    fn execute(&mut self, _: u8) {}
    fn esc_dispatch(&mut self, i: &[u8], f: u8) {
        self.esc.push((i.to_vec(), f));
    }
    fn csi_dispatch(&mut self, p: &[u16], i: &[u8], f: u8) {
        self.csi.push((p.to_vec(), i.to_vec(), f));
    }
    fn osc_dispatch(&mut self, s: &[u8]) {
        self.osc.push(s.to_vec());
    }
    fn ignored(&mut self) {
        self.ignored += 1;
    }
}

fn parse(bytes: &[u8]) -> Seq {
    let mut p = Parser::new();
    let mut s = Seq::default();
    p.feed(&mut s, bytes);
    s
}

#[test]
fn parameters_saturate_and_stop_at_sixteen() {
    let s = parse(b"\x1b[m\x1b[;m\x1b[1;;3m\x1b[99999;65536;65535m");
    assert_eq!(s.csi[0].0, Vec::<u16>::new());
    assert_eq!(s.csi[1].0, [0, 0]);
    assert_eq!(s.csi[2].0, [1, 0, 3]);
    assert_eq!(s.csi[3].0, [65535, 65535, 65535]);
    let s = parse(b"\x1b[1;2;3;4;5;6;7;8;9;10;11;12;13;14;15;16;17;18m");
    assert_eq!(s.csi[0].0, (1..=16).collect::<Vec<u16>>());
    let s = parse(b"\x1b[;;;;;;;;;;;;;;;;;;;;5m");
    assert_eq!(s.csi[0].0, vec![0; 16]);
}

#[test]
fn two_intermediates_pass_and_a_third_is_ignored() {
    let s = parse(b"\x1b[?1$p\x1b[? $p\x1b(B\x1b(%B\x1b(%%B");
    assert_eq!(s.csi, [(vec![1], b"?$".to_vec(), b'p')]);
    assert_eq!(s.esc, [(b"(".to_vec(), b'B'), (b"(%".to_vec(), b'B')]);
    assert_eq!(s.ignored, 2);
}

#[test]
fn an_osc_string_keeps_its_first_64_bytes_however_it_ends() {
    let mut long = b"\x1b]2;".to_vec();
    long.extend(core::iter::repeat_n(b'x', 100));
    long.push(0x07);
    let s = parse(&long);
    let mut want = b"2;".to_vec();
    want.extend(vec![b'x'; MAX_OSC - 2]);
    assert_eq!(s.osc, [want]);
    // Ended by ST, BEL, CAN, SUB and ESC; C0 and DEL are not kept.
    let s = parse(b"\x1b]0;a\x1b\\\x1b]x\r;a\x07\x1b]1;\xc3\xa9\x18\x1b]\x7f\x1a\x1b]2;b\x1bD");
    assert_eq!(
        s.osc,
        [
            b"0;a".to_vec(),
            b"x;a".to_vec(),
            b"1;\xc3\xa9".to_vec(),
            vec![],
            b"2;b".to_vec(),
        ]
    );
}

#[test]
fn utf8_decodes_one_to_four_bytes_and_drops_c1() {
    let mut p = Parser::new();
    let mut r = Rec::default();
    p.feed(&mut r, "aé€😀".as_bytes());
    p.feed(&mut r, b"\xc2\x85\xc2\xa0");
    assert_eq!(
        r.0,
        [
            Act::Print('a'),
            Act::Print('é'),
            Act::Print('€'),
            Act::Print('😀'),
            Act::Print('\u{A0}'),
        ]
    );
}
