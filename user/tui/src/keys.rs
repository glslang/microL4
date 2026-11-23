//! The key decoder (`docs/design.md`, "`tui`"): a function of the byte
//! stream, one byte at a time, so a sequence split across term's `Read`s
//! decodes as it would whole.
//!
//! ESC followed by `[` or `O` and a final byte (`0x40` to `0x7E`), with any
//! parameter and intermediate bytes (`0x20` to `0x3F`) between, is one key:
//! `ESC [ A` and `ESC O A` are Up, `ESC [ B` and `ESC O B` Down, any other
//! an unknown key. ESC followed by anything else is dropped and the byte
//! after it decoded afresh; so is an unfinished sequence that meets any
//! other byte (a control, DEL, or a byte from `0x80`), which is how a
//! second ESC starts a new sequence. CR and LF are Enter, each of them;
//! `k` and `j` are Up and Down, `1` to `6` the menu's items, `q` quits,
//! and every other byte is an unknown key of its own.

use core::fmt;

const ESC: u8 = 0x1B;

/// The bytes of an unknown key kept for its log line; a longer sequence
/// shows its first ones and `...`.
pub const SHOWN: usize = 8;

/// A decoded key.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Key {
    Up,
    Down,
    Enter,
    /// `1` to `6`: select that item and open it.
    Item(u8),
    /// `q`.
    Quit,
    Unknown(Unknown),
}

/// An unknown key's bytes, as the log shows them.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Unknown {
    bytes: [u8; SHOWN],
    len: u8,
    /// More bytes than [`SHOWN`].
    cut: bool,
}

impl Unknown {
    fn one(b: u8) -> Unknown {
        let mut u = Unknown {
            bytes: [0; SHOWN],
            len: 0,
            cut: false,
        };
        u.push(b);
        u
    }

    fn push(&mut self, b: u8) {
        if usize::from(self.len) < SHOWN {
            self.bytes[usize::from(self.len)] = b;
            self.len += 1;
        } else {
            self.cut = true;
        }
    }

    /// The bytes kept.
    pub fn bytes(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }
}

impl fmt::Debug for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "Unknown({self})")
    }
}

/// The bytes escaped as the harness's `send:` writes them: `\e`, `\r`,
/// `\n`, `\t`, `\\`, `\xHH` for any other byte outside printable ASCII,
/// and `...` after a cut sequence. Only printable ASCII comes out.
impl fmt::Display for Unknown {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        escaped(self.bytes(), f)?;
        if self.cut {
            f.write_str("...")?;
        }
        Ok(())
    }
}

/// `bytes` as the harness's `send:` escapes them.
pub fn escaped(bytes: &[u8], f: &mut impl fmt::Write) -> fmt::Result {
    for &b in bytes {
        match b {
            ESC => f.write_str("\\e")?,
            b'\r' => f.write_str("\\r")?,
            b'\n' => f.write_str("\\n")?,
            b'\t' => f.write_str("\\t")?,
            b'\\' => f.write_str("\\\\")?,
            0x20..=0x7E => f.write_char(char::from(b))?,
            _ => write!(f, "\\x{b:02x}")?,
        }
    }
    Ok(())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum State {
    Ground,
    /// After ESC.
    Escape,
    /// After ESC `[` or ESC `O`: the sequence so far.
    Sequence(Unknown),
}

/// The decoder's state, which survives the end of a `Read`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Decoder {
    state: State,
}

impl Default for Decoder {
    fn default() -> Self {
        Self::new()
    }
}

impl Decoder {
    pub const fn new() -> Decoder {
        Decoder {
            state: State::Ground,
        }
    }

    /// Whether a sequence is unfinished: bytes wait for the next `Read`.
    pub fn pending(&self) -> bool {
        self.state != State::Ground
    }

    /// The next byte; the key it completes, if any.
    pub fn push(&mut self, b: u8) -> Option<Key> {
        match self.state {
            State::Ground => self.ground(b),
            State::Escape => {
                if b == b'[' || b == b'O' {
                    let mut seq = Unknown::one(ESC);
                    seq.push(b);
                    self.state = State::Sequence(seq);
                    None
                } else {
                    // The ESC is dropped; this byte starts afresh.
                    self.state = State::Ground;
                    self.ground(b)
                }
            }
            State::Sequence(mut seq) => match b {
                0x20..=0x3F => {
                    seq.push(b);
                    self.state = State::Sequence(seq);
                    None
                }
                0x40..=0x7E => {
                    self.state = State::Ground;
                    Some(match (seq.bytes(), b) {
                        ([ESC, _], b'A') => Key::Up,
                        ([ESC, _], b'B') => Key::Down,
                        _ => {
                            seq.push(b);
                            Key::Unknown(seq)
                        }
                    })
                }
                _ => {
                    // Cut short: dropped, and this byte starts afresh.
                    self.state = State::Ground;
                    self.ground(b)
                }
            },
        }
    }

    fn ground(&mut self, b: u8) -> Option<Key> {
        Some(match b {
            ESC => {
                self.state = State::Escape;
                return None;
            }
            b'\r' | b'\n' => Key::Enter,
            b'k' => Key::Up,
            b'j' => Key::Down,
            b'1'..=b'6' => Key::Item(b - b'0'),
            b'q' => Key::Quit,
            _ => Key::Unknown(Unknown::one(b)),
        })
    }
}
