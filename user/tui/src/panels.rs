//! What each panel shows (`docs/design.md`, "`tui`", the panel table):
//! line `i` of a panel's inner area, from 0, written into a [`Line`] as
//! wide as that area. Lines past a panel's content are blank. Nothing here
//! depends on anything but the size, so every frame is the same for the
//! same keys.

use crate::Panel;
use crate::draw::Line;

/// Line `i` of `panel`'s content on a `cols` x `rows` terminal.
pub fn line(panel: Panel, i: usize, l: &mut Line<'_, '_>, cols: u16, rows: u16) {
    match panel {
        Panel::Overview => overview(i, l, cols, rows),
        Panel::Attributes => attributes(i, l),
        Panel::Colours => colours(i, l),
        Panel::Boxes => boxes(i, l),
        Panel::Keys => keys(i, l),
    }
}

fn overview(i: usize, l: &mut Line<'_, '_>, cols: u16, rows: u16) {
    let text = match i {
        1 => " A terminal emulator drawing on the GOP framebuffer, and this app inside it:",
        2 => " tui writes escape sequences, term parses them into its screen model and",
        3 => " draws each cell that changed with an 8x16 font.",
        5 => " Threads, by priority:",
        6 => "   root     255   builds every server, then waits for their reports",
        7 => "   watch    255   ends the run if a server faults",
        8 => "   uart     200   the COM1 driver",
        9 => "   console  150   clients' lines, the focus, and client 4's raw keys",
        10 => "   term     125   the terminal, the only thread that maps the framebuffer",
        11 => "   tui      100   this app, term's one client",
        13 => {
            l.tf(format_args!(
                " Terminal: {cols} x {rows} cells of 8 x 16 pixels, no scrollback"
            ));
            return;
        }
        15 => " Keys: COM1, uart, console (client 4 is raw), term, tui.",
        16 => " Ctrl-T 4 gives term the keyboard; Ctrl-T 1 gives it back to root.",
        18 => {
            l.t(" Styles: ");
            for (on, word, off) in [
                ("\x1b[1m", "bold", "\x1b[22m"),
                ("\x1b[2m", "faint", "\x1b[22m"),
                ("\x1b[4m", "underline", "\x1b[24m"),
                ("\x1b[7m", "inverse", "\x1b[27m"),
                ("\x1b[96m", "colour", "\x1b[39m"),
            ] {
                l.e(on);
                l.t(word);
                l.e(off);
                l.t(" ");
            }
            return;
        }
        _ => return,
    };
    l.t(text);
}

fn attributes(i: usize, l: &mut Line<'_, '_>) {
    // SGR on, the sample, SGR off, and its words.
    const ROWS: [(&str, &str, &str, &str); 8] = [
        ("1", "bold", "22", ""),
        ("2", "faint", "22", ""),
        ("3", "italic", "23", "  (drawn upright: no italic font)"),
        ("4", "underline", "24", ""),
        ("5", "blink", "25", "  (drawn steady: nothing blinks)"),
        ("7", "inverse", "27", ""),
        ("8", "conceal", "28", "  (hidden between the brackets)"),
        ("9", "strike", "29", ""),
    ];
    const COMBINATIONS: [(&str, &str); 6] = [
        ("1;4", "bold and underline"),
        ("2;7", "faint and inverse"),
        ("1;9;91", "bold and struck in bright red"),
        ("4;7;94", "underlined and inverse in bright blue"),
        ("1;2;3;4", "bold, faint, italic and underlined"),
        ("7;8", "inverse and concealed: a block of blanks"),
    ];
    match i {
        1 => l.t(" Each SGR attribute on, then off again:"),
        3 => {
            l.e("\x1b[1m");
            l.t("   on  sample                off  after it");
        }
        4..=11 => {
            let (on, word, off, note) = ROWS[i - 4];
            l.tf(format_args!("   {on:<3} "));
            if on == "8" {
                l.t("[");
            }
            l.ef(format_args!("\x1b[{on}m"));
            l.t(word);
            l.ef(format_args!("\x1b[{off}m"));
            if on == "8" {
                l.t("]");
            }
            l.to(30);
            l.tf(format_args!("{off}   normal again{note}"));
        }
        13 => l.t(" Combinations, and SGR 0 to end each:"),
        15..=20 => {
            let (on, words) = COMBINATIONS[i - 15];
            l.tf(format_args!("   {on:<9} "));
            l.ef(format_args!("\x1b[{on}m"));
            l.t(words);
            l.e("\x1b[0m");
        }
        _ => {}
    }
}

fn colours(i: usize, l: &mut Line<'_, '_>) {
    match i {
        1 => l.t(" The 16 colours as backgrounds, SGR 40 to 47 and 100 to 107:"),
        2 | 3 => {
            l.t(" ");
            let first = if i == 2 { 0 } else { 8 };
            for n in first..first + 8u8 {
                // A light label on the dark colours, a dark one on the rest.
                let fg = if matches!(n, 0 | 1 | 4 | 5 | 8) {
                    97
                } else {
                    30
                };
                let bg = if n < 8 {
                    40 + u16::from(n)
                } else {
                    100 + u16::from(n - 8)
                };
                l.ef(format_args!("\x1b[{bg};{fg}m"));
                l.tf(format_args!(" {n:>3}  "));
            }
            l.e("\x1b[0m");
        }
        4 => {
            l.t(" As text, SGR 30 to 37 and 90 to 97: ");
            for n in 0..16u8 {
                let fg = if n < 8 { 30 + n } else { 90 + n - 8 };
                l.ef(format_args!("\x1b[{fg}m"));
                l.tf(format_args!("{n} "));
            }
            l.e("\x1b[39m");
        }
        6 => l.t(" The 6 x 6 x 6 cube, SGR 48;5 from 16 to 231:"),
        7..=12 => {
            let r = (i - 7) as u16;
            l.t(" ");
            for gb in 0..36 {
                l.ef(format_args!("\x1b[48;5;{}m", 16 + 36 * r + gb));
                l.t(" ");
            }
            l.e("\x1b[49m");
        }
        14 => l.t(" The 24 greys, 232 to 255:"),
        15 => {
            l.t(" ");
            for n in 232..=255u16 {
                l.ef(format_args!("\x1b[48;5;{n}m"));
                l.t("  ");
            }
            l.e("\x1b[49m");
        }
        17 => l.t(" 24 true colours from red to blue, SGR 48;2, as term maps them:"),
        18 => {
            l.t(" ");
            for n in 0..24u16 {
                let b = 255 * n / 23;
                l.ef(format_args!("\x1b[48;2;{};0;{b}m", 255 - b));
                l.t("  ");
            }
            l.e("\x1b[49m");
        }
        20 => {
            l.t(" Text in 256 and true colours: ");
            l.e("\x1b[38;5;208m");
            l.t("38;5;208");
            l.e("\x1b[39m");
            l.t("  ");
            l.e("\x1b[38;2;255;0;255m");
            l.t("38;2;255;0;255");
            l.e("\x1b[39m");
            l.t("  ");
            l.e("\x1b[38;5;16;48;5;229m");
            l.t("38;5;16 on 48;5;229");
            l.e("\x1b[39;49m");
        }
        _ => {}
    }
}

fn boxes(i: usize, l: &mut Line<'_, '_>) {
    const BOXES: [&str; 5] = [
        "  ┌───┬───┐   ┏━━━┳━━━┓   ╔═══╦═══╗   ╭───────╮",
        "  │   │   │   ┃   ┃   ┃   ║   ║   ║   │       │",
        "  ├───┼───┤   ┣━━━╋━━━┫   ╠═══╬═══╣   │       │",
        "  │   │   │   ┃   ┃   ┃   ║   ║   ║   │       │",
        "  └───┴───┘   ┗━━━┻━━━┛   ╚═══╩═══╝   ╰───────╯",
    ];
    const MIXED: [&str; 3] = [
        "  ╒═╤═╕  ╓─╥─╖  ┍━┯━┑  ┎─┰─┒  ┌─┲━┓  ╭─╮",
        "  ╞═╪═╡  ╟─╫─╢  ┝━┿━┥  ┠─╂─┨  ┢━╅─┦  ╰─╯",
        "  ╘═╧═╛  ╙─╨─╜  ┕━┷━┙  ┖─┸─┚  ┗━┹─┘  ╱╲╳",
    ];
    // DEC Special Graphics, as a VT100 draws a box.
    const DEC: [&str; 5] = [
        "lqqqwqqqk",
        "x   x   x",
        "tqqqnqqqu",
        "x   x   x",
        "mqqqvqqqj",
    ];
    match i {
        1 => l.t(" Light, heavy, double and rounded, with their junctions:"),
        3..=7 => l.t(BOXES[i - 3]),
        9 => l.t(" Mixed weights, double with single, and the diagonals:"),
        11..=13 => l.t(MIXED[i - 11]),
        15 => l.t(" Dashes: ┄ ┅ ┆ ┇ ┈ ┉ ┊ ┋ ╌ ╍ ╎ ╏"),
        17 => l.t(" Blocks: ▁▂▃▄▅▆▇█ ▉▊▋▌▍▎▏ ▔▕ ▀▐ ▖▗▘▙▚▛▜▝▞▟"),
        18 => l.t(" Shades: ░░░ ▒▒▒ ▓▓▓ ███"),
        20 => l.t(" DEC Special Graphics, ESC ( 0 to ESC ( B:"),
        22..=26 => {
            l.t("  ");
            l.e("\x1b(0");
            l.t(DEC[i - 22]);
            l.e("\x1b(B");
        }
        28 => {
            l.t("  ");
            l.e("\x1b(0");
            l.t("` a f g ~ o p q r s");
            l.e("\x1b(B");
            l.t("   diamond, shade, degree, plus-minus, dot, scan lines 1 to 9");
        }
        _ => {}
    }
}

fn keys(i: usize, l: &mut Line<'_, '_>) {
    const TABLE: [&str; 6] = [
        " ESC [ A, ESC O A, k    Up      the selection moves up, stopping at item 1",
        " ESC [ B, ESC O B, j    Down    the selection moves down, stopping at item 6",
        " CR, LF                 Enter   opens the selected panel; on Quit, quits",
        " 1 to 6                         selects that item and opens it",
        " q                              quits",
        " any other                      logged as an unknown key",
    ];
    match i {
        1 => {
            l.e("\x1b[1m");
            l.t(" Bytes                  Key     Effect");
        }
        2..=7 => l.t(TABLE[i - 2]),
        9 => l.t(" Keys reach tui through console, where client 4 is raw: Ctrl-T 4 gives"),
        10 => l.t(" them to term, Ctrl-T Ctrl-T sends one Ctrl-T, and Ctrl-T 1 gives them"),
        11 => l.t(" back to root. term passes them on as typed, VT sequences and all."),
        _ => {}
    }
}
