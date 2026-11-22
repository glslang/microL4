//! The M7 red team's attack on the terminal
//! (`docs/redteam/m7-console-escapes.md`): a client's output reached the
//! wire byte for byte, control bytes and escape sequences included, so on a
//! VT100-compatible terminal one client could move the cursor into lines
//! console showed for others, erase them and forge console's own status
//! line. console now shows a client's control bytes as visible escapes
//! ([`crate::shown`]); these tests run the attack against it over a small
//! VT100 screen model.

use std::format;
use std::string::String;
use std::vec::Vec;

use super::T;

/// The screen a VT100-compatible terminal shows for `bytes`: printable
/// bytes, CR, LF, BS, and the CSI sequences `n A` (cursor up), `2 K`
/// (erase the line) and `K` (erase to its end); anything else is dropped.
fn screen(bytes: &str) -> Vec<String> {
    let mut rows: Vec<Vec<char>> = std::vec![Vec::new()];
    let (mut row, mut col) = (0usize, 0usize);
    let mut it = bytes.chars().peekable();
    while let Some(c) = it.next() {
        match c {
            '\r' => col = 0,
            '\n' => {
                row += 1;
                if rows.len() <= row {
                    rows.push(Vec::new());
                }
            }
            '\x08' => col = col.saturating_sub(1),
            '\x1b' if it.peek() == Some(&'[') => {
                it.next();
                let mut param = String::new();
                let mut fin = ' ';
                for d in it.by_ref() {
                    if ('\x40'..='\x7e').contains(&d) {
                        fin = d;
                        break;
                    }
                    param.push(d);
                }
                let n: usize = param.parse().unwrap_or(0);
                match fin {
                    'A' => row = row.saturating_sub(n.max(1)),
                    'K' if n == 2 => rows[row].clear(),
                    'K' => rows[row].truncate(col),
                    _ => {}
                }
            }
            ' '..='~' => {
                let r = &mut rows[row];
                if r.len() <= col {
                    r.resize(col + 1, ' ');
                }
                r[col] = c;
                col += 1;
            }
            _ => {}
        }
    }
    rows.into_iter()
        .map(|r| r.into_iter().collect::<String>().trim_end().into())
        .collect()
}

/// The screen model itself.
#[test]
fn the_screen_model_moves_up_and_erases() {
    assert_eq!(screen("ab\r\ncd\x1b[1A\x1b[2K\rxy\r\n"), ["xy", "cd"]);
}

/// The attack: client 2 ("evil") has focus, as console's status line
/// says; it tries to move up over that line, erase it and write a forged
/// one naming client 1 ("root"), then reads with root's prompt. Its escape
/// sequences reach the terminal as visible text, the real status line
/// stays, and the forgery is plainly client 2's line, escapes and all.
#[test]
fn a_client_s_escape_sequences_are_shown_not_obeyed() {
    let mut t = T::new();
    let mut wire = String::new();
    t.term.attach(0, b"root");
    t.term.attach(1, b"evil");
    wire += &t.write(0, "root: ready\n");
    wire += &t.typed(b"\x142");
    assert_eq!(t.term.focus(), 1);
    let out = t.write(1, "\x1b[1A\x1b[2K[console] focus 1 (root)\nroot# ");
    assert_eq!(out, "^[[1A^[[2K[console] focus 1 (root)\r\n");
    wire += &out;
    wire += &t.read(1).2;
    wire += &t.typed(b"hunter2\r");
    assert_eq!(
        screen(&wire),
        [
            "root: ready",
            "[console] focus 2 (evil)",
            "^[[1A^[[2K[console] focus 1 (root)",
            "root# hunter2",
            ""
        ]
    );
    assert_eq!(t.delivered, [(1, "hunter2".into())]);
}

/// Every other way a client's bytes reach the terminal: its prompt, its
/// held bytes flushed or at 512, and its name in a status line. Each
/// tries to erase the line above; none can.
#[test]
fn no_client_byte_moves_the_cursor_up() {
    let up = "\x1b[1A\x1b[2K\rX";
    let mut t = T::new();
    let mut wire = String::new();
    t.term.attach(1, format!("{up}evil").as_bytes());
    wire += &t.write(0, "keep me\n");
    wire += &t.typed(b"\x142");
    wire += &t.write(1, up);
    wire += &t.read(1).2;
    wire += &t.write(2, up);
    wire += &t.flush(2);
    wire += &t.write(3, &up.repeat(80));
    let rows = screen(&wire);
    assert_eq!(
        rows[..2],
        ["keep me", "[console] focus 2 (^[[1A^[[2K^MXevil)"]
    );
    assert!(rows[2].starts_with("^[[1A^[[2K^MX"), "{rows:?}");
    assert!(!wire.contains('\x1b'), "{wire:?}");
}

/// The guarantee: console's own status line, once shown, stays on the
/// screen; no client's output can erase or forge it.
#[test]
fn a_client_cannot_rewrite_console_s_status_line() {
    let mut t = T::new();
    let mut wire = String::new();
    t.term.attach(0, b"root");
    t.term.attach(1, b"evil");
    wire += &t.typed(b"\x142");
    wire += &t.write(1, "\x1b[1A\x1b[2K[console] focus 1 (root)\nroot# ");
    wire += &t.read(1).2;
    let rows = screen(&wire);
    assert!(
        rows.iter().any(|r| r == "[console] focus 2 (evil)"),
        "the screen shows {rows:?}"
    );
}
