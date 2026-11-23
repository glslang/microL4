//! The parser: Paul Williams' state machine for DEC's ANSI-compatible
//! terminals, as `docs/design.md` adapts it ("`term`: the parser"): bytes
//! from `0x80` are UTF-8, never C1 controls; BEL ends an OSC string as ST
//! does; DEL is ignored everywhere; parameters, intermediates and the OSC
//! string have fixed limits.
//!
//! It is fed one byte at a time and keeps its state between calls, so a
//! sequence split across writes acts as it would whole. Its actions go to
//! an [`Actions`]; it never allocates and does a bounded amount of work per
//! byte.

/// Parameters a dispatch passes; more are dropped.
pub const MAX_PARAMS: usize = 16;
/// A parameter's value saturates here.
pub const MAX_PARAM: u16 = 65_535;
/// Intermediates (a private marker counts as one) a dispatch passes; a
/// sequence with more is ignored.
pub const MAX_INTERMEDIATES: usize = 2;
/// The bytes of an OSC string kept; the rest are dropped.
pub const MAX_OSC: usize = 64;

const CAN: u8 = 0x18;
const SUB: u8 = 0x1A;
const ESC: u8 = 0x1B;
const DEL: u8 = 0x7F;
const BEL: u8 = 0x07;

/// What the parser asks of the screen model.
pub trait Actions {
    /// A graphic character: printable ASCII or a decoded code point (never
    /// a C0 or C1 control, DEL or a surrogate).
    fn print(&mut self, c: char);
    /// A C0 control, CAN and SUB included.
    fn execute(&mut self, byte: u8);
    /// `ESC` with up to [`MAX_INTERMEDIATES`] intermediates and a final byte
    /// from `0x30` to `0x7E`.
    fn esc_dispatch(&mut self, intermediates: &[u8], final_byte: u8);
    /// A control sequence: up to [`MAX_PARAMS`] parameters, an empty one
    /// read as 0; up to [`MAX_INTERMEDIATES`] intermediates, a private
    /// marker (`<` to `?`) first if there is one; the final byte.
    fn csi_dispatch(&mut self, params: &[u16], intermediates: &[u8], final_byte: u8);
    /// An OSC string has ended, however it ended: its first [`MAX_OSC`]
    /// bytes, as they came.
    fn osc_dispatch(&mut self, string: &[u8]);
    /// A sequence the parser itself drops: a CSI ignored for a `:` or a
    /// misplaced private marker, a sequence with too many intermediates,
    /// and every DCS and SOS, PM or APC string, counted once when it ends.
    fn ignored(&mut self);
}

/// The parser's states, Williams' names.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum State {
    Ground,
    Escape,
    EscapeIntermediate,
    CsiEntry,
    CsiParam,
    CsiIntermediate,
    CsiIgnore,
    DcsEntry,
    DcsParam,
    DcsIntermediate,
    DcsPassthrough,
    DcsIgnore,
    OscString,
    SosPmApcString,
}

impl State {
    /// Every state, for the table test.
    pub const ALL: [State; 14] = [
        State::Ground,
        State::Escape,
        State::EscapeIntermediate,
        State::CsiEntry,
        State::CsiParam,
        State::CsiIntermediate,
        State::CsiIgnore,
        State::DcsEntry,
        State::DcsParam,
        State::DcsIntermediate,
        State::DcsPassthrough,
        State::DcsIgnore,
        State::OscString,
        State::SosPmApcString,
    ];

    fn is_dcs(self) -> bool {
        matches!(
            self,
            State::DcsEntry
                | State::DcsParam
                | State::DcsIntermediate
                | State::DcsPassthrough
                | State::DcsIgnore
        )
    }
}

/// The UTF-8 decoder: what the code point has so far, how many continuation
/// bytes it still needs, and the range the next one must fall in.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
struct Utf8 {
    need: u8,
    code: u32,
    lo: u8,
    hi: u8,
}

impl Utf8 {
    const IDLE: Utf8 = Utf8 {
        need: 0,
        code: 0,
        lo: 0x80,
        hi: 0xBF,
    };
}

/// The state machine. [`Parser::new`] starts it in ground.
#[derive(Clone, Debug)]
pub struct Parser {
    state: State,
    params: [u16; MAX_PARAMS],
    /// Parameters started, 0 to `MAX_PARAMS + 1` (one past: the rest are
    /// dropped).
    nparams: u8,
    intermediates: [u8; MAX_INTERMEDIATES],
    /// Intermediates collected, 0 to `MAX_INTERMEDIATES + 1` (one past:
    /// too many).
    nintermediates: u8,
    osc: [u8; MAX_OSC],
    osc_len: u8,
    utf8: Utf8,
}

impl Default for Parser {
    fn default() -> Self {
        Self::new()
    }
}

impl Parser {
    pub const fn new() -> Parser {
        Parser {
            state: State::Ground,
            params: [0; MAX_PARAMS],
            nparams: 0,
            intermediates: [0; MAX_INTERMEDIATES],
            nintermediates: 0,
            osc: [0; MAX_OSC],
            osc_len: 0,
            utf8: Utf8::IDLE,
        }
    }

    /// The state the next byte meets.
    pub fn state(&self) -> State {
        self.state
    }

    /// Whether the UTF-8 decoder holds part of a code point.
    pub fn in_utf8(&self) -> bool {
        self.utf8.need != 0
    }

    /// Puts the parser in `state` as its entry would, for the table test.
    #[cfg(test)]
    pub(crate) fn enter(&mut self, state: State) {
        match state {
            State::Escape | State::CsiEntry | State::DcsEntry => self.clear(),
            State::OscString => self.osc_start(),
            _ => {}
        }
        self.state = state;
    }

    /// Feeds every byte of `bytes`.
    pub fn feed<A: Actions>(&mut self, actions: &mut A, bytes: &[u8]) {
        for &b in bytes {
            self.advance(actions, b);
        }
    }

    /// Feeds one byte.
    pub fn advance<A: Actions>(&mut self, actions: &mut A, byte: u8) {
        if self.utf8.need != 0 {
            // Only ground decodes, and only a byte below 0x80 leaves it, so
            // a code point in progress means ground.
            if (self.utf8.lo..=self.utf8.hi).contains(&byte) {
                self.continue_utf8(actions, byte);
                return;
            }
            // A maximal ill-formed subpart: one U+FFFD, then the byte that
            // ended it afresh.
            self.utf8 = Utf8::IDLE;
            actions.print(char::REPLACEMENT_CHARACTER);
        }
        match byte {
            CAN | SUB => {
                self.leave(actions);
                actions.execute(byte);
                self.state = State::Ground;
                return;
            }
            ESC => {
                self.leave(actions);
                self.clear();
                self.state = State::Escape;
                return;
            }
            DEL => return,
            _ => {}
        }
        let c0 = byte < 0x20;
        let high = byte >= 0x80;
        match self.state {
            State::Ground => {
                if c0 {
                    actions.execute(byte);
                } else if high {
                    self.start_utf8(actions, byte);
                } else {
                    actions.print(char::from(byte));
                }
            }
            State::Escape => match byte {
                _ if c0 => actions.execute(byte),
                _ if high => {}
                0x20..=0x2F => {
                    self.collect(byte);
                    self.state = State::EscapeIntermediate;
                }
                b'[' => {
                    self.clear();
                    self.state = State::CsiEntry;
                }
                b']' => {
                    self.osc_start();
                    self.state = State::OscString;
                }
                b'P' => {
                    self.clear();
                    self.state = State::DcsEntry;
                }
                b'X' | b'^' | b'_' => self.state = State::SosPmApcString,
                _ => self.esc_dispatch(actions, byte),
            },
            State::EscapeIntermediate => match byte {
                _ if c0 => actions.execute(byte),
                _ if high => {}
                0x20..=0x2F => self.collect(byte),
                _ => self.esc_dispatch(actions, byte),
            },
            State::CsiEntry => match byte {
                _ if c0 => actions.execute(byte),
                _ if high => {}
                0x20..=0x2F => {
                    self.collect(byte);
                    self.state = State::CsiIntermediate;
                }
                b'0'..=b'9' | b';' => {
                    self.param(byte);
                    self.state = State::CsiParam;
                }
                b':' => self.state = State::CsiIgnore,
                b'<'..=b'?' => {
                    self.collect(byte);
                    self.state = State::CsiParam;
                }
                _ => self.csi_dispatch(actions, byte),
            },
            State::CsiParam => match byte {
                _ if c0 => actions.execute(byte),
                _ if high => {}
                b'0'..=b'9' | b';' => self.param(byte),
                b':' | b'<'..=b'?' => self.state = State::CsiIgnore,
                0x20..=0x2F => {
                    self.collect(byte);
                    self.state = State::CsiIntermediate;
                }
                _ => self.csi_dispatch(actions, byte),
            },
            State::CsiIntermediate => match byte {
                _ if c0 => actions.execute(byte),
                _ if high => {}
                0x20..=0x2F => self.collect(byte),
                0x30..=0x3F => self.state = State::CsiIgnore,
                _ => self.csi_dispatch(actions, byte),
            },
            State::CsiIgnore => match byte {
                _ if c0 => actions.execute(byte),
                _ if high => {}
                0x20..=0x3F => {}
                _ => {
                    actions.ignored();
                    self.state = State::Ground;
                }
            },
            State::DcsEntry => match byte {
                _ if c0 || high => {}
                0x20..=0x2F => {
                    self.collect(byte);
                    self.state = State::DcsIntermediate;
                }
                b'0'..=b'9' | b';' => {
                    self.param(byte);
                    self.state = State::DcsParam;
                }
                b':' => self.state = State::DcsIgnore,
                b'<'..=b'?' => {
                    self.collect(byte);
                    self.state = State::DcsParam;
                }
                _ => self.state = State::DcsPassthrough,
            },
            State::DcsParam => match byte {
                _ if c0 || high => {}
                b'0'..=b'9' | b';' => self.param(byte),
                b':' | b'<'..=b'?' => self.state = State::DcsIgnore,
                0x20..=0x2F => {
                    self.collect(byte);
                    self.state = State::DcsIntermediate;
                }
                _ => self.state = State::DcsPassthrough,
            },
            State::DcsIntermediate => match byte {
                _ if c0 || high => {}
                0x20..=0x2F => self.collect(byte),
                0x30..=0x3F => self.state = State::DcsIgnore,
                _ => self.state = State::DcsPassthrough,
            },
            // Put: term acts on no DCS, so what is put goes nowhere.
            State::DcsPassthrough | State::DcsIgnore | State::SosPmApcString => {}
            State::OscString => {
                if byte == BEL {
                    self.osc_end(actions);
                    self.state = State::Ground;
                } else if !c0 {
                    self.osc_put(byte);
                }
            }
        }
    }

    /// The exit action of the state being left by CAN, SUB or ESC.
    fn leave<A: Actions>(&mut self, actions: &mut A) {
        match self.state {
            State::OscString => self.osc_end(actions),
            State::SosPmApcString => actions.ignored(),
            s if s.is_dcs() => actions.ignored(),
            _ => {}
        }
    }

    fn clear(&mut self) {
        self.params = [0; MAX_PARAMS];
        self.nparams = 0;
        self.intermediates = [0; MAX_INTERMEDIATES];
        self.nintermediates = 0;
    }

    fn collect(&mut self, byte: u8) {
        let n = usize::from(self.nintermediates);
        if n < MAX_INTERMEDIATES {
            self.intermediates[n] = byte;
        }
        if n <= MAX_INTERMEDIATES {
            self.nintermediates += 1;
        }
    }

    fn param(&mut self, byte: u8) {
        if self.nparams == 0 {
            self.nparams = 1;
        }
        if byte == b';' {
            if usize::from(self.nparams) <= MAX_PARAMS {
                self.nparams += 1;
            }
            return;
        }
        let n = usize::from(self.nparams);
        if n <= MAX_PARAMS {
            let p = &mut self.params[n - 1];
            let v = u32::from(*p) * 10 + u32::from(byte - b'0');
            *p = v.min(u32::from(MAX_PARAM)) as u16;
        }
    }

    fn intermediates(&self) -> Option<&[u8]> {
        let n = usize::from(self.nintermediates);
        (n <= MAX_INTERMEDIATES).then(|| &self.intermediates[..n])
    }

    fn esc_dispatch<A: Actions>(&mut self, actions: &mut A, byte: u8) {
        match self.intermediates() {
            Some(i) => actions.esc_dispatch(i, byte),
            None => actions.ignored(),
        }
        self.state = State::Ground;
    }

    fn csi_dispatch<A: Actions>(&mut self, actions: &mut A, byte: u8) {
        let n = usize::from(self.nparams).min(MAX_PARAMS);
        match self.intermediates() {
            Some(i) => actions.csi_dispatch(&self.params[..n], i, byte),
            None => actions.ignored(),
        }
        self.state = State::Ground;
    }

    fn osc_start(&mut self) {
        self.osc_len = 0;
    }

    fn osc_put(&mut self, byte: u8) {
        let n = usize::from(self.osc_len);
        if n < MAX_OSC {
            self.osc[n] = byte;
            self.osc_len += 1;
        }
    }

    fn osc_end<A: Actions>(&mut self, actions: &mut A) {
        actions.osc_dispatch(&self.osc[..usize::from(self.osc_len)]);
    }

    fn start_utf8<A: Actions>(&mut self, actions: &mut A, byte: u8) {
        // The Unicode standard's table of well-formed byte sequences: the
        // number of continuation bytes, and the range of the first.
        let (need, lo, hi, bits) = match byte {
            0xC2..=0xDF => (1, 0x80, 0xBF, byte & 0x1F),
            0xE0 => (2, 0xA0, 0xBF, byte & 0x0F),
            0xE1..=0xEC | 0xEE..=0xEF => (2, 0x80, 0xBF, byte & 0x0F),
            0xED => (2, 0x80, 0x9F, byte & 0x0F),
            0xF0 => (3, 0x90, 0xBF, byte & 0x07),
            0xF1..=0xF3 => (3, 0x80, 0xBF, byte & 0x07),
            0xF4 => (3, 0x80, 0x8F, byte & 0x07),
            // A lone continuation byte, an overlong lead (C0, C1) or one
            // past U+10FFFF (F5 to FF).
            _ => {
                actions.print(char::REPLACEMENT_CHARACTER);
                return;
            }
        };
        self.utf8 = Utf8 {
            need,
            code: u32::from(bits),
            lo,
            hi,
        };
    }

    fn continue_utf8<A: Actions>(&mut self, actions: &mut A, byte: u8) {
        let code = (self.utf8.code << 6) | u32::from(byte & 0x3F);
        let need = self.utf8.need - 1;
        if need != 0 {
            self.utf8 = Utf8 {
                need,
                code,
                lo: 0x80,
                hi: 0xBF,
            };
            return;
        }
        self.utf8 = Utf8::IDLE;
        // The ranges above admit only scalar values; C1's code points are
        // dropped.
        if let Some(c) = char::from_u32(code)
            && !(0x80..=0x9F).contains(&code)
        {
            actions.print(c);
        }
    }
}
