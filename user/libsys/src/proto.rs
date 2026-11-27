//! The `uart`, `console` and `term` protocols (`docs/design.md`, "The
//! uart protocol", "Protocols" and "Input and the term protocol"): request
//! labels, the byte-string encoding, the error labels, `uart`'s and
//! `term`'s `Stats`, `term`'s `Size`, and the notification badges. Both
//! ends are built into one root image, so this module is the protocols'
//! only definition; it is not part of `docs/abi.md`.
//!
//! A byte string travels as MR0 = its length `n` and MR1 to MR⌈`n`/8⌉ =
//! its bytes, eight per word, little-endian: byte `i` is bits 8(`i` mod 8)
//! to 8(`i` mod 8) + 7 of MR(1 + ⌊`i`/8⌋). `length` is 1 + ⌈`n`/8⌉, at most
//! 120, so `n` is at most [`MAX_BYTES`]. Up to 24 bytes travel in
//! registers; more need IPC buffers on both sides.
//!
//! A reply's label is 0 on success; a refusal has one of the [`Refusal`]
//! labels and `length` 0. Request labels lie above every kernel invocation
//! label (`0x01` to `0x8F`) and error labels above every kernel error code
//! (1 to 10), so a client tells a server's refusal from the kernel's.

use core::fmt;

use l4core::ipc::MSG_MAX_LENGTH;

/// The most bytes one message carries.
pub const MAX_BYTES: usize = 8 * (MSG_MAX_LENGTH - 1);
/// The most words a byte string takes, MR0 included.
pub const MAX_WORDS: usize = MSG_MAX_LENGTH;
/// The most bytes a message carries without IPC buffers: MR1 to MR3.
pub const MAX_REGISTER_BYTES: usize = 24;

const _: () = assert!(MAX_BYTES == 952);

/// Request labels.
pub mod label {
    /// `uart`: queue a byte string for transmit.
    pub const UART_WRITE: u64 = 0x110;
    /// `uart`: everything the receive ring holds.
    pub const UART_READ: u64 = 0x111;
    /// `uart`: answered once the queue and the FIFO are empty.
    pub const UART_DRAIN: u64 = 0x112;
    /// `uart`: the counters ([`super::UartStats`]).
    pub const UART_STATS: u64 = 0x113;

    /// `console`: name the client in status lines.
    pub const CONSOLE_ATTACH: u64 = 0x120;
    /// `console`: a byte string of output.
    pub const CONSOLE_WRITE: u64 = 0x121;
    /// `console`: emit the client's unfinished line.
    pub const CONSOLE_FLUSH: u64 = 0x122;
    /// `console`: the next line typed for the client.
    pub const CONSOLE_READ: u64 = 0x123;
    /// `console`: answered once everything emitted has left the UART.
    pub const CONSOLE_SYNC: u64 = 0x124;
    /// `console`: everything in client 4's raw queue, possibly nothing, at
    /// once; never saved. `BadBadge` for any badge but 4 (M8).
    pub const CONSOLE_READ_RAW: u64 = 0x125;

    /// tui's report to root on endpoint D: a byte string, the first 255
    /// bytes it read from term. Root never answers it.
    pub const TUI_REPORT: u64 = 0x131;

    /// `term`: a byte string of at most 952 bytes for the parser; answered
    /// with MR0 its length once every byte is applied and the frame drawn.
    pub const TERM_WRITE: u64 = 0x140;
    /// `term`: its input queue, all of it (at most 512 bytes), at once if
    /// it holds anything, else once bytes arrive.
    pub const TERM_READ: u64 = 0x141;
    /// `term`: MR0 columns, MR1 rows, MR2 width and MR3 height in pixels
    /// ([`super::TermSize`]).
    pub const TERM_SIZE: u64 = 0x142;
    /// `term`: the counters ([`super::TermStats`]); any badge.
    pub const TERM_STATS: u64 = 0x143;
}

/// A server's refusal: the reply's label, with `length` 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u64)]
pub enum Refusal {
    /// A label the server does not know, including a reserved one.
    BadLabel = 0x101,
    /// A byte string longer than the server takes, or a `length` that
    /// does not match its `n`.
    BadLength = 0x102,
    /// The server already holds the one request of this kind it can.
    Busy = 0x103,
    /// A badge outside the requests' range.
    BadBadge = 0x104,
}

impl Refusal {
    /// The refusal a reply label names, if any.
    pub const fn from_label(label: u64) -> Option<Refusal> {
        match label {
            0x101 => Some(Refusal::BadLabel),
            0x102 => Some(Refusal::BadLength),
            0x103 => Some(Refusal::Busy),
            0x104 => Some(Refusal::BadBadge),
            _ => None,
        }
    }

    /// The reply label.
    pub const fn label(self) -> u64 {
        self as u64
    }
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Refusal::BadLabel => "BadLabel",
            Refusal::BadLength => "BadLength",
            Refusal::Busy => "Busy",
            Refusal::BadBadge => "BadBadge",
        })
    }
}

/// The badge of a notification signal `uart` sends `console` when input
/// waits, and of the signal IRQ 4 sends `uart`: bit 32, above every
/// endpoint badge either server's requests carry, so
/// `libsys::Event::classify` tells them from messages.
pub const RX_READY: u64 = 1 << 32;
/// The badge of the IRQ 4 handler's notification capability.
pub const IRQ: u64 = 1 << 32;
/// The badge of console's capability to term's notification NT, which it
/// signals once per uart `Read` that put bytes in its raw queue: bit 32,
/// above term's client badges, as [`RX_READY`] is above console's.
pub const KEYS: u64 = 1 << 32;
/// console's raw client: client 4, term.
pub const CONSOLE_RAW_CLIENT: u64 = 4;
/// The badge of term's one client; `Write`, `Read` and `Size` need it.
pub const TERM_CLIENT: u64 = 1;

/// The words a byte string of `n` bytes takes, MR0 included.
pub const fn words_for(n: usize) -> usize {
    1 + n.div_ceil(8)
}

/// Encodes `bytes` as MR0 and up into `words`, and returns the message's
/// `length`. Panics past [`MAX_BYTES`].
pub fn encode(bytes: &[u8], words: &mut [u64; MAX_WORDS]) -> usize {
    assert!(
        bytes.len() <= MAX_BYTES,
        "{} bytes in one message",
        bytes.len()
    );
    words[0] = bytes.len() as u64;
    for (w, chunk) in words[1..].iter_mut().zip(bytes.chunks(8)) {
        let mut b = [0; 8];
        b[..chunk.len()].copy_from_slice(chunk);
        *w = u64::from_le_bytes(b);
    }
    words_for(bytes.len())
}

/// Decodes the byte string in a message of `length` words, read one at a
/// time with `word` (MR0 first), into `out`; returns its `n`. `BadLength`
/// if `length` is 0, `n` is over `limit` or `out`'s length, or `length`
/// is not 1 + ⌈`n`/8⌉. The unused bytes of the last word are ignored.
pub fn decode(
    length: usize,
    mut word: impl FnMut(usize) -> u64,
    limit: usize,
    out: &mut [u8],
) -> Result<usize, Refusal> {
    if length == 0 {
        return Err(Refusal::BadLength);
    }
    let n = word(0);
    let limit = limit.min(out.len()).min(MAX_BYTES) as u64;
    if n > limit || length != words_for(n as usize) {
        return Err(Refusal::BadLength);
    }
    let n = n as usize;
    for (i, chunk) in out[..n].chunks_mut(8).enumerate() {
        let b = word(1 + i).to_le_bytes();
        chunk.copy_from_slice(&b[..chunk.len()]);
    }
    Ok(n)
}

/// `uart`'s counters, the reply to `Stats` as MR0 to MR9.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct UartStats {
    /// MR0: interrupt signals handled.
    pub signals: u64,
    /// MR1: bytes moved from the receiver into the receive ring.
    pub received: u64,
    /// MR2: bytes written to the transmitter.
    pub sent: u64,
    /// MR3: bursts written for a THRE cause in the service routine, not
    /// those a request wrote.
    pub thre_bursts: u64,
    /// MR4: overruns (LSR.OE seen).
    pub overruns: u64,
    /// MR5: line errors (LSR.PE, FE or BI seen).
    pub line_errors: u64,
    /// MR6: Writes held for room in the queue.
    pub writes_held: u64,
    /// MR7: service routines cut short by the limit of 64 reads that move
    /// no byte.
    pub cut_short: u64,
    /// MR8 (M8): the transmit burst setup chose, 15 with working FIFOs
    /// and 1 without, for the Hyper-V check of its 16550.
    pub burst: u64,
    /// MR9 (M8): THRE interrupts found stale, IIR naming THRE while LSR
    /// said the FIFO still held bytes, which uart then ignores; for the
    /// Hyper-V check, where one cost 6 bytes before uart checked LSR.
    pub stale_thre: u64,
}

impl UartStats {
    /// The reply's words.
    pub const WORDS: usize = 10;

    pub const fn to_words(&self) -> [u64; Self::WORDS] {
        [
            self.signals,
            self.received,
            self.sent,
            self.thre_bursts,
            self.overruns,
            self.line_errors,
            self.writes_held,
            self.cut_short,
            self.burst,
            self.stale_thre,
        ]
    }

    pub const fn from_words(w: [u64; Self::WORDS]) -> UartStats {
        UartStats {
            signals: w[0],
            received: w[1],
            sent: w[2],
            thre_bursts: w[3],
            overruns: w[4],
            line_errors: w[5],
            writes_held: w[6],
            cut_short: w[7],
            burst: w[8],
            stale_thre: w[9],
        }
    }
}

/// What root's uart lines show; `release` expects `, burst 15` (working
/// FIFOs) near their end.
impl fmt::Display for UartStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} signals, {} bytes received, {} sent, {} THRE bursts, {} overruns, {} line errors, {} Writes held, {} routines cut short, burst {}, {} stale THREs",
            self.signals,
            self.received,
            self.sent,
            self.thre_bursts,
            self.overruns,
            self.line_errors,
            self.writes_held,
            self.cut_short,
            self.burst,
            self.stale_thre
        )
    }
}

/// `term`'s `Size` reply, MR0 to MR3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TermSize {
    /// MR0, MR1: the screen in cells.
    pub cols: u64,
    pub rows: u64,
    /// MR2, MR3: the framebuffer in pixels.
    pub width: u64,
    pub height: u64,
}

impl TermSize {
    /// The reply's words.
    pub const WORDS: usize = 4;

    pub const fn to_words(&self) -> [u64; Self::WORDS] {
        [self.cols, self.rows, self.width, self.height]
    }

    pub const fn from_words(w: [u64; Self::WORDS]) -> TermSize {
        TermSize {
            cols: w[0],
            rows: w[1],
            width: w[2],
            height: w[3],
        }
    }
}

/// `term`'s counters, the reply to `Stats` as MR0 to MR6.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct TermStats {
    /// MR0: bytes its client wrote.
    pub written: u64,
    /// MR1: frames drawn, one after each `Write` and the first.
    pub frames: u64,
    /// MR2: cells drawn.
    pub cells: u64,
    /// MR3: sequences the parser or the screen model ignored.
    pub ignored: u64,
    /// MR4: bytes `ReadRaw` brought from console.
    pub from_console: u64,
    /// MR5: bytes dropped because its input queue was full.
    pub dropped: u64,
    /// MR6: bytes of DSR and DA replies queued as input.
    pub replies: u64,
}

impl TermStats {
    /// The reply's words.
    pub const WORDS: usize = 7;

    pub const fn to_words(&self) -> [u64; Self::WORDS] {
        [
            self.written,
            self.frames,
            self.cells,
            self.ignored,
            self.from_console,
            self.dropped,
            self.replies,
        ]
    }

    pub const fn from_words(w: [u64; Self::WORDS]) -> TermStats {
        TermStats {
            written: w[0],
            frames: w[1],
            cells: w[2],
            ignored: w[3],
            from_console: w[4],
            dropped: w[5],
            replies: w[6],
        }
    }
}

/// What root's `term: stats:` line shows: `, <n> ignored,` and `, <n>
/// dropped` are what the `tui` scenario matches.
impl fmt::Display for TermStats {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} bytes written, {} frames drawn, {} cells drawn, {} ignored, {} bytes from console, {} dropped, {} reply bytes queued",
            self.written,
            self.frames,
            self.cells,
            self.ignored,
            self.from_console,
            self.dropped,
            self.replies
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pattern(n: usize) -> std::vec::Vec<u8> {
        (0..n).map(|i| (i * 7 + 3) as u8).collect()
    }

    /// Every `n`, or under Miri those around word and register limits.
    fn lengths() -> impl Iterator<Item = usize> {
        const FEW: [usize; 11] = [0, 1, 7, 8, 9, 23, 24, 25, 500, 951, 952];
        (0..=MAX_BYTES).filter(|n| !cfg!(miri) || FEW.contains(n))
    }

    #[test]
    fn every_length_round_trips() {
        let mut out = [0; MAX_BYTES];
        for n in lengths() {
            let bytes = pattern(n);
            let mut words = [0; MAX_WORDS];
            let length = encode(&bytes, &mut words);
            assert_eq!(length, words_for(n));
            assert!(length <= MAX_WORDS);
            assert_eq!(words[0], n as u64);
            out.fill(0xEE);
            assert_eq!(decode(length, |i| words[i], MAX_BYTES, &mut out), Ok(n));
            assert_eq!(&out[..n], &bytes[..], "n = {n}");
            // Bytes past n are untouched.
            assert!(out[n..].iter().all(|&b| b == 0xEE));
        }
    }

    #[test]
    fn bytes_are_little_endian_eight_to_a_word() {
        let mut words = [0; MAX_WORDS];
        assert_eq!(encode(b"abcdefghij", &mut words), 3);
        assert_eq!(words[0], 10);
        assert_eq!(words[1], u64::from_le_bytes(*b"abcdefgh"));
        assert_eq!(words[2], u64::from(b'i') | u64::from(b'j') << 8);
        // Three words of bytes fit in registers with MR0.
        assert_eq!(words_for(MAX_REGISTER_BYTES), 4);
        assert_eq!(words_for(MAX_REGISTER_BYTES + 1), 5);
        assert_eq!(words_for(0), 1);
        assert_eq!(words_for(MAX_BYTES), MAX_WORDS);
    }

    #[test]
    fn the_unused_bytes_of_the_last_word_are_ignored() {
        let mut out = [0; 16];
        let words = [3, 0xFFFF_FFFF_FF63_6261];
        assert_eq!(decode(2, |i| words[i], 16, &mut out), Ok(3));
        assert_eq!(&out[..3], b"abc");
        assert_eq!(out[3], 0);
    }

    #[test]
    fn a_length_that_does_not_match_n_is_bad() {
        let mut out = [0; MAX_BYTES];
        for n in [0usize, 1, 8, 9, 24, 25, 100, 951, 952] {
            let good = words_for(n);
            for length in
                (0..=127usize).filter(|&l| !cfg!(miri) || l % 16 < 2 || l.abs_diff(good) < 2)
            {
                let words = |i: usize| {
                    if i == 0 {
                        n as u64
                    } else {
                        0x4141_4141_4141_4141
                    }
                };
                let r = decode(length, words, MAX_BYTES, &mut out);
                if length == good {
                    assert_eq!(r, Ok(n));
                } else {
                    assert_eq!(r, Err(Refusal::BadLength), "n {n}, length {length}");
                }
            }
        }
    }

    #[test]
    fn n_over_the_limit_is_bad() {
        let mut out = [0; MAX_BYTES];
        let mut big = [0u8; 64];
        // Over the server's limit, over the buffer, over 952, huge.
        for (n, limit, buf) in [
            (17usize, 16usize, MAX_BYTES),
            (65, MAX_BYTES, 64),
            (953, MAX_BYTES, MAX_BYTES),
        ] {
            let words = |i: usize| if i == 0 { n as u64 } else { 0 };
            let r = if buf == 64 {
                decode(words_for(n), words, limit, &mut big)
            } else {
                decode(words_for(n), words, limit, &mut out)
            };
            assert_eq!(r, Err(Refusal::BadLength), "n {n}");
        }
        let words = |i: usize| if i == 0 { u64::MAX } else { 0 };
        assert_eq!(
            decode(120, words, MAX_BYTES, &mut out),
            Err(Refusal::BadLength)
        );
        // At the limit is fine.
        let words = |i: usize| if i == 0 { 16 } else { 0 };
        assert_eq!(decode(3, words, 16, &mut out), Ok(16));
    }

    #[test]
    fn labels_lie_above_the_kernels() {
        let all = [
            label::UART_WRITE,
            label::UART_READ,
            label::UART_DRAIN,
            label::UART_STATS,
            label::CONSOLE_ATTACH,
            label::CONSOLE_WRITE,
            label::CONSOLE_FLUSH,
            label::CONSOLE_READ,
            label::CONSOLE_SYNC,
            label::CONSOLE_READ_RAW,
            label::TUI_REPORT,
            label::TERM_WRITE,
            label::TERM_READ,
            label::TERM_SIZE,
            label::TERM_STATS,
        ];
        assert!(all.iter().all(|&l| l > 0x8F));
        // Distinct, and none an error label.
        for (i, a) in all.iter().enumerate() {
            assert!(all[i + 1..].iter().all(|b| b != a), "{a:#x}");
            assert_eq!(Refusal::from_label(*a), None);
        }
        for r in [
            Refusal::BadLabel,
            Refusal::BadLength,
            Refusal::Busy,
            Refusal::BadBadge,
        ] {
            assert!(r.label() > 10);
            assert_eq!(Refusal::from_label(r.label()), Some(r));
        }
        assert_eq!(Refusal::from_label(0), None);
        assert_eq!(Refusal::from_label(0x105), None);
        assert_eq!(RX_READY & 0xFFFF_FFFF, 0);
        // term's notification bit lies above every badge its endpoint's
        // capabilities carry (its client 1, root's Stats 2).
        assert_eq!(KEYS & 0xFFFF_FFFF, 0);
        assert_eq!(TERM_CLIENT & !0xFFFF_FFFF, 0);
        assert_eq!(CONSOLE_RAW_CLIENT, 4);
    }

    #[test]
    #[should_panic(expected = "953 bytes")]
    fn encoding_past_the_limit_panics() {
        let mut words = [0; MAX_WORDS];
        encode(&[0; 953], &mut words);
    }

    #[test]
    fn stats_round_trip() {
        let s = UartStats {
            signals: 1,
            received: 2,
            sent: 3,
            thre_bursts: 4,
            overruns: 5,
            line_errors: 6,
            writes_held: 7,
            cut_short: 8,
            burst: 15,
            stale_thre: 9,
        };
        assert_eq!(s.to_words(), [1, 2, 3, 4, 5, 6, 7, 8, 15, 9]);
        assert_eq!(UartStats::from_words(s.to_words()), s);
        assert_eq!(
            std::format!("{s}"),
            "1 signals, 2 bytes received, 3 sent, 4 THRE bursts, 5 overruns, 6 line errors, 7 Writes held, 8 routines cut short, burst 15, 9 stale THREs"
        );
        let t = TermStats {
            written: 1,
            frames: 2,
            cells: 3,
            ignored: 4,
            from_console: 5,
            dropped: 6,
            replies: 7,
        };
        assert_eq!(t.to_words(), [1, 2, 3, 4, 5, 6, 7]);
        assert_eq!(TermStats::from_words(t.to_words()), t);
        let z = TermSize {
            cols: 160,
            rows: 50,
            width: 1280,
            height: 800,
        };
        assert_eq!(TermSize::from_words(z.to_words()), z);
    }

    /// The `tui` scenario expects `, 0 ignored,` and `, 0 dropped` on
    /// root's `term: stats:` line.
    #[test]
    fn term_stats_show_what_the_scenario_matches() {
        let t = TermStats {
            written: 9000,
            frames: 12,
            cells: 8000,
            from_console: 8,
            ..TermStats::default()
        };
        let s = std::format!("term: stats: {t}");
        assert_eq!(
            s,
            "term: stats: 9000 bytes written, 12 frames drawn, 8000 cells drawn, 0 ignored, 8 bytes from console, 0 dropped, 0 reply bytes queued"
        );
        assert!(s.contains(", 0 ignored,") && s.contains(", 0 dropped"));
    }
}
