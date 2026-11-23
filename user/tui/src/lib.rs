//! `tui`: the terminal demo app (`docs/design.md`, "`tui`" under
//! "Framebuffer, terminal and TUI").
//!
//! [`App`] is pure and host-tested: it turns the terminal's size and each
//! key into the bytes of a frame. [`run`], its loop, exists only on the
//! user target, where the root task starts it in a VSpace and CSpace of
//! its own with the capabilities [`slot`] lists. Every byte `run` writes
//! to term comes from `App`, the banner and the goodbye included, so a
//! host test that feeds term `App`'s output renders exactly what the
//! guest's term was sent.
//!
//! The screen: a title bar, a menu of six items, the open panel, a
//! scrolling log in DECSTBM's region, a prompt with a visible block
//! cursor, and a status line, on the alternate buffer. Each key draws a
//! frame: everything but the log whole, and the log a line longer, so the
//! region's scrolling runs on the machine too. Nothing on screen moves
//! with the build or the run: no address, slot count or time, only the
//! size and the keys typed. tui uses only sequences term acts on, so
//! term's ignored count stays 0.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod draw;
mod keys;
mod panels;
#[cfg(target_os = "none")]
mod run;
#[cfg(test)]
mod tests;

use core::fmt;

use draw::{D, Line, digits};

pub use keys::{Decoder, Key, SHOWN, Unknown, escaped};
#[cfg(target_os = "none")]
pub use run::run;

/// tui's CSpace: a 16-slot CNode with guard 0 of size 60, so `CPtr` `n`
/// is slot `n` (`docs/design.md`, "Capabilities" under "Where it runs").
pub mod slot {
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, as every server's; tui does not use it.
    pub const CNODE: u64 = 1;
    /// Endpoint T, with Write, GrantReply and badge 1: term's client.
    pub const TERM: u64 = 2;
    /// Endpoint C, with Write, GrantReply and badge 5: its log lines.
    pub const CONSOLE: u64 = 3;
    /// Endpoint D, with Write, GrantReply and badge 5: its report to root,
    /// and its fault endpoint.
    pub const REPORT: u64 = 4;
}

/// Where a frame's bytes go: to term, through `Write`s of at most 952
/// bytes, on the target; to a buffer in host tests.
pub trait Out {
    fn put(&mut self, bytes: &[u8]);
}

/// The smallest terminal the layout fits, which `fb` guarantees, and the
/// largest term makes.
pub const MIN_COLS: u64 = 80;
pub const MIN_ROWS: u64 = 24;
pub const MAX_COLS: u64 = 240;
pub const MAX_ROWS: u64 = 75;
/// The most bytes read from term that the report to root carries.
pub const REPORT: usize = 255;

/// The menu's items, 1 to 6.
pub const ITEMS: [&str; 6] = ["Overview", "Attributes", "Colours", "Boxes", "Keys", "Quit"];

/// The status line's keys.
const HELP: &str = " Up/Down j/k: move  Enter: open  1-6: jump  q: quit";

/// A panel: items 1 to 5.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Panel {
    Overview = 1,
    Attributes,
    Colours,
    Boxes,
    Keys,
}

impl Panel {
    /// The panel item `n` opens; `None` for 6, Quit, and anything else.
    pub const fn from_item(n: u8) -> Option<Panel> {
        Some(match n {
            1 => Panel::Overview,
            2 => Panel::Attributes,
            3 => Panel::Colours,
            4 => Panel::Boxes,
            5 => Panel::Keys,
            _ => return None,
        })
    }

    pub const fn item(self) -> u8 {
        self as u8
    }

    pub const fn name(self) -> &'static str {
        ITEMS[self as usize - 1]
    }
}

impl fmt::Display for Panel {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// What a key did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// A frame went out.
    Drawn(Drawn),
    /// tui quit: the goodbye went out.
    Quit(Quit),
}

/// A frame drawn; its `Display` is the console line `run` prints once term
/// has answered the frame's last `Write`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Drawn {
    /// From 1, the first frame.
    pub frame: u32,
    /// The open panel.
    pub panel: Panel,
    /// The selected item, 1 to 6.
    pub item: u8,
}

impl fmt::Display for Drawn {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "tui: frame {} drawn: {}, item {}",
            self.frame, self.panel, self.item
        )
    }
}

/// tui quit after this many keys, the one that quit included; its
/// `Display` is the console line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Quit {
    pub keys: u32,
}

impl fmt::Display for Quit {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tui: quit after {} keys", self.keys)
    }
}

/// The console line tui prints first: `tui: <cols>x<rows> terminal`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Size {
    pub cols: u16,
    pub rows: u16,
}

impl fmt::Display for Size {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tui: {}x{} terminal", self.cols, self.rows)
    }
}

/// The app: the size, the selection, the open panel, the counts and the
/// key decoder.
#[derive(Clone, Debug)]
pub struct App {
    cols: u16,
    rows: u16,
    /// 1 to 6.
    selected: u8,
    open: Panel,
    frames: u32,
    keys: u32,
    decoder: Decoder,
    report: [u8; REPORT],
    report_len: usize,
    quit: bool,
}

impl App {
    /// The app for a terminal of `cols` x `rows` cells, from term's
    /// `Size`; `None` outside 80 x 24 to 240 x 75.
    pub fn new(cols: u64, rows: u64) -> Option<App> {
        let fits = (MIN_COLS..=MAX_COLS).contains(&cols) && (MIN_ROWS..=MAX_ROWS).contains(&rows);
        fits.then_some(App {
            cols: cols as u16,
            rows: rows as u16,
            selected: 1,
            open: Panel::Overview,
            frames: 0,
            keys: 0,
            decoder: Decoder::new(),
            report: [0; REPORT],
            report_len: 0,
            quit: false,
        })
    }

    pub fn size(&self) -> Size {
        Size {
            cols: self.cols,
            rows: self.rows,
        }
    }

    /// The start: `tui: starting on a <cols>x<rows> terminal` and CR LF on
    /// the main screen, the alternate buffer (`CSI ? 1049 h`), cleared, the
    /// block cursor and the log's region, then the first frame.
    pub fn start(&mut self, out: &mut dyn Out) -> Drawn {
        let mut d = D(out);
        d.f(format_args!(
            "tui: starting on a {}x{} terminal\r\n",
            self.cols, self.rows
        ));
        d.s("\x1b[?1049h\x1b[2J\x1b[2 q");
        let (top, bottom) = self.log_region();
        d.f(format_args!("\x1b[{top};{bottom}r"));
        self.frame(None, &mut d)
    }

    /// Bytes `Read` from term: the first [`REPORT`] of them go in the
    /// report. Decode them with [`decode`](Self::decode).
    pub fn received(&mut self, bytes: &[u8]) {
        let n = bytes.len().min(REPORT - self.report_len);
        self.report[self.report_len..self.report_len + n].copy_from_slice(&bytes[..n]);
        self.report_len += n;
    }

    /// The next byte read; the key it completes, if any.
    pub fn decode(&mut self, b: u8) -> Option<Key> {
        self.decoder.push(b)
    }

    /// A key: a frame, or the goodbye; `None` once tui has quit.
    pub fn key(&mut self, key: Key, out: &mut dyn Out) -> Option<Step> {
        if self.quit {
            return None;
        }
        self.keys += 1;
        match key {
            Key::Up => self.selected = self.selected.saturating_sub(1).max(1),
            Key::Down => self.selected = (self.selected + 1).min(ITEMS.len() as u8),
            Key::Enter | Key::Item(_) => {
                if let Key::Item(n) = key {
                    self.selected = n;
                }
                match Panel::from_item(self.selected) {
                    Some(p) => self.open = p,
                    None => return Some(Step::Quit(self.bye(out))),
                }
            }
            Key::Quit => return Some(Step::Quit(self.bye(out))),
            Key::Unknown(_) => {}
        }
        let mut d = D(out);
        Some(Step::Drawn(self.frame(Some(key), &mut d)))
    }

    /// The first bytes read from term, for the report to root.
    pub fn report(&self) -> &[u8] {
        &self.report[..self.report_len]
    }

    /// Keys so far.
    pub fn keys(&self) -> u32 {
        self.keys
    }

    pub fn quit(&self) -> bool {
        self.quit
    }

    /// The log's region: the rows above the prompt, below the rule.
    fn log_region(&self) -> (u16, u16) {
        (self.rows - 9, self.rows - 2)
    }

    /// The goodbye: the whole screen as the region again, which the
    /// buffers share, then the main buffer and its cursor, then a line
    /// below the banner.
    fn bye(&mut self, out: &mut dyn Out) -> Quit {
        self.quit = true;
        let mut d = D(out);
        d.s("\x1b[r\x1b[?1049l");
        d.f(format_args!("tui: bye after {} keys\r\n", self.keys));
        Quit { keys: self.keys }
    }

    /// A frame, with the cursor hidden while it is drawn: every row but
    /// the log's whole, then `logged`'s line in the log.
    fn frame(&mut self, logged: Option<Key>, d: &mut D<'_>) -> Drawn {
        self.frames += 1;
        d.s("\x1b[?25l\x1b[0m");
        self.title(d);
        // Row 2 is blank; rows 3 to `rows` - 11 hold the menu and the
        // panel, each row drawn from its first column to its last.
        d.cup(2, 1);
        d.s("\x1b[K");
        for row in 3..=self.rows - 11 {
            d.cup(row, 1);
            d.s(" ");
            self.menu(row, d);
            d.s(" ");
            self.panel(row, d);
            d.s("\x1b[K");
        }
        self.rule(d);
        if let Some(k) = logged {
            self.log(d, k);
        }
        self.status(d);
        Drawn {
            frame: self.frames,
            panel: self.open,
            item: self.selected,
        }
    }

    /// Row 1: the title, bold bright white on blue, the rest of the row
    /// blue through EL, and the size right-aligned.
    fn title(&self, d: &mut D<'_>) {
        d.cup(1, 1);
        d.s("\x1b[1;97;44m microL4 terminal demo\x1b[K");
        let size = digits(self.cols.into()) + 1 + digits(self.rows.into());
        d.cup(1, self.cols - size as u16);
        d.f(format_args!("{}x{}\x1b[0m", self.cols, self.rows));
    }

    /// Columns 2 to 25 of `row`: on rows 3 to 10 a light box with rounded
    /// corners, ` Menu ` in bold, the items on rows 4 to 9, the selected
    /// one with `> `, in reverse video; blanks below it.
    fn menu(&self, row: u16, d: &mut D<'_>) {
        const INNER: usize = 22;
        match row {
            3 => {
                d.s("╭─\x1b[1m Menu \x1b[22m");
                d.rep("─", INNER - 7);
                d.s("╮");
            }
            4..=9 => {
                let n = (row - 3) as u8;
                let name = ITEMS[usize::from(n) - 1];
                d.s("│");
                let mut l = Line::new(d, INNER);
                if n == self.selected {
                    l.e("\x1b[7m");
                    l.tf(format_args!(" > {n} {name}"));
                    l.to(INNER);
                } else {
                    l.tf(format_args!("   {n} {name}"));
                }
                l.finish();
                d.s("│");
            }
            10 => {
                d.s("╰");
                d.rep("─", INNER);
                d.s("╯");
            }
            _ => d.blanks(INNER + 2),
        }
    }

    /// Columns 27 to `cols` - 1 of `row`, on rows 3 to `rows` - 11: a
    /// double-line box, the panel's name in bold, its content inside.
    fn panel(&self, row: u16, d: &mut D<'_>) {
        let (top, bottom) = (3, self.rows - 11);
        let inner = usize::from(self.cols) - 29;
        if row == top {
            let name = self.open.name();
            d.s("╔═\x1b[1m ");
            d.s(name);
            d.s(" \x1b[22m");
            d.rep("═", inner - 3 - name.len());
            d.s("╗");
        } else if row == bottom {
            d.s("╚");
            d.rep("═", inner);
            d.s("╝");
        } else {
            d.s("║");
            let mut l = Line::new(d, inner);
            panels::line(
                self.open,
                usize::from(row - top - 1),
                &mut l,
                self.cols,
                self.rows,
            );
            l.finish();
            d.s("║");
        }
    }

    /// Row `rows` - 10: a heavy rule with ` Log ` in faint.
    fn rule(&self, d: &mut D<'_>) {
        d.cup(self.rows - 10, 1);
        d.s("━━\x1b[2m Log \x1b[22m");
        d.rep("━", usize::from(self.cols) - 7);
    }

    /// The log: LF on the region's bottom row scrolls it up one, and the
    /// new bottom row takes `key <n>: <name>`, short of the last column.
    fn log(&self, d: &mut D<'_>, key: Key) {
        let (_, bottom) = self.log_region();
        d.cup(bottom, 1);
        d.s("\n");
        let mut l = Line::new(d, usize::from(self.cols) - 1);
        l.tf(format_args!("key {}: ", self.keys));
        match key {
            Key::Up => l.t("Up"),
            Key::Down => l.t("Down"),
            Key::Enter => l.t("Enter"),
            Key::Item(n) => l.tf(format_args!("{n}")),
            Key::Quit => l.t("q"),
            Key::Unknown(u) => l.tf(format_args!("unknown {u}")),
        }
    }

    /// Row `rows` - 1: the prompt; row `rows`: the status line in reverse
    /// video, `frame <n>` right-aligned; then the cursor, a visible block,
    /// after the prompt.
    fn status(&self, d: &mut D<'_>) {
        d.cup(self.rows - 1, 1);
        d.s("> \x1b[K");
        d.cup(self.rows, 1);
        let width = usize::from(self.cols);
        let mut l = Line::new(d, width);
        l.e("\x1b[7m");
        l.t(HELP);
        l.to(width - 7 - digits(self.frames.into()));
        l.tf(format_args!("frame {}", self.frames));
        l.to(width);
        l.finish();
        d.cup(self.rows - 1, 3);
        d.s("\x1b[?25h");
    }
}
