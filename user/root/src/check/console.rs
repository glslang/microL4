//! The verdicts of `test=console` and `test=release` (`docs/design.md`,
//! "Scenarios" under "User-level drivers and console"): the script the
//! two clients follow, their reports, the lines each must receive, uart's
//! totals, and the release probe's faults.

use core::fmt;

use libsys::fault_label::UNKNOWN_SYSCALL;
use libsys::proto::{self, UartStats};

/// The label of a client's report on endpoint D: above every fault type,
/// so root tells a report from a fault by the label.
pub const REPORT: u64 = 0x130;
/// The step a client's first report names: it has attached.
pub const STARTED: u64 = u64::MAX;

/// Client numbers, which are their badges on endpoints C and D; root is
/// client 1.
pub const ROOT: u64 = 1;
pub const A: u64 = 2;
pub const B: u64 = 3;

/// The name of client `badge`.
pub const fn name(badge: u64) -> &'static str {
    match badge {
        ROOT => "root",
        A => "a",
        B => "b",
        _ => "?",
    }
}

/// What a step has its client do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// One console Write.
    Write(&'static [u8]),
    /// One Write of the 100-byte piece `n` of the 300-byte `b2` line.
    B2(usize),
    /// [`BURST_LINES`] Writes of a [`BURST_LEN`]-byte line each.
    Burst,
    /// Write the prompt, then Read a line and report it.
    Input(&'static str),
}

/// One step: a client and what it does.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Step {
    pub client: u64,
    pub action: Action,
}

const fn step(client: u64, action: Action) -> Step {
    Step { client, action }
}

/// The script. Root runs the steps before [`INPUT_STEPS`] one at a time,
/// so every write boundary is fixed; then it starts both input steps and
/// waits for both reports.
pub const SCRIPT: [Step; 14] = [
    // Interleaved lines.
    step(A, Action::Write(b"a1 alpha ")),
    step(B, Action::Write(b"b1 bravo ")),
    step(A, Action::Write(b"one\n")),
    step(B, Action::Write(b"one\n")),
    step(B, Action::B2(0)),
    step(A, Action::Write(b"a2 short\n")),
    step(B, Action::B2(1)),
    step(B, Action::B2(2)),
    step(A, Action::Write(b"a3 x\na4 y\na5 ")),
    step(B, Action::Write(b"b3 z\n")),
    step(A, Action::Write(b"end\n")),
    // Burst.
    step(B, Action::Burst),
    // Input.
    step(A, Action::Input("a> ")),
    step(B, Action::Input("b> ")),
];

/// The interleaved lines the transcript shows, but the 300-byte one, in
/// order: `a1 alpha one`, `b1 bravo one`, `a2 short`, the `b2` line, then
/// the rest.
pub const INTERLEAVED_LINES: [&str; 7] = [
    "a1 alpha one",
    "b1 bravo one",
    "a2 short",
    "a3 x",
    "a4 y",
    "b3 z",
    "a5 end",
];

/// The first step of the input part.
pub const INPUT_STEPS: usize = 12;
/// The last step of the interleaved lines.
pub const INTERLEAVED_STEPS: usize = 10;

/// The `b2` line: `b2 `, digits, ` end` and its newline, 300 bytes.
pub const B2_LEN: usize = 300;
/// Twelve lines of 200 bytes each, newline included.
pub const BURST_LINES: usize = 12;
pub const BURST_LEN: usize = 200;

/// The `b2` line.
pub fn b2_line() -> [u8; B2_LEN] {
    let mut l = [0; B2_LEN];
    l[..3].copy_from_slice(b"b2 ");
    for (i, b) in l[3..B2_LEN - 5].iter_mut().enumerate() {
        *b = b'0' + (i % 10) as u8;
    }
    l[B2_LEN - 5..].copy_from_slice(b" end\n");
    l
}

/// Burst line `n`, from 1: `b burst NN `, letters, ` NN` and its newline.
pub fn burst_line(n: usize) -> [u8; BURST_LEN] {
    let mut l = [0; BURST_LEN];
    let tens = b'0' + (n / 10) as u8;
    let ones = b'0' + (n % 10) as u8;
    l[..11].copy_from_slice(b"b burst 00 ");
    l[8] = tens;
    l[9] = ones;
    for (i, b) in l[11..BURST_LEN - 4].iter_mut().enumerate() {
        *b = b'a' + (i % 26) as u8;
    }
    l[BURST_LEN - 4..].copy_from_slice(&[b' ', tens, ones, b'\n']);
    l
}

/// The lines each client must read: `a` exactly `hi a`, `b` exactly
/// `to b`.
pub const READS: [(u64, &str); 2] = [(A, "hi a"), (B, "to b")];
/// The bytes the harness sends in `test=console`: `\x143to b\r` and
/// `\x142hellp\x7fo\x15hi a\r`.
pub const CONSOLE_INPUT_BYTES: u64 = 7 + 15;
/// The line the harness types in `test=release`, and its bytes with the
/// CR.
pub const RELEASE_LINE: &str = "release input";
pub const RELEASE_INPUT_BYTES: u64 = RELEASE_LINE.len() as u64 + 1;

/// A client's report: the step it did, its status (0, or the error that
/// stopped it), and for an input step the line it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Report {
    pub step: u64,
    pub status: u64,
    pub line: [u8; 255],
    pub len: usize,
}

impl Report {
    /// The report's words: MR0 the step, MR1 the status, MR2 and up the
    /// line as a byte string. Returns the length.
    pub fn encode(step: u64, status: u64, line: &[u8], words: &mut [u64; 120]) -> usize {
        let mut s = [0; proto::MAX_WORDS];
        let n = proto::encode(line, &mut s);
        words[0] = step;
        words[1] = status;
        words[2..2 + n].copy_from_slice(&s[..n]);
        2 + n
    }

    /// Decodes a report of `length` words, read with `word`.
    pub fn decode(length: usize, mut word: impl FnMut(usize) -> u64) -> Option<Report> {
        if length < 3 {
            return None;
        }
        let mut line = [0; 255];
        let len = proto::decode(length - 2, |i| word(i + 2), 255, &mut line).ok()?;
        Some(Report {
            step: word(0),
            status: word(1),
            line,
            len,
        })
    }

    pub fn line(&self) -> &[u8] {
        &self.line[..self.len]
    }
}

/// Why `test=console` or `test=release` fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// Client `client` read `got`, not the line it must.
    WrongLine { client: u64 },
    /// A read reported by a client that must read nothing.
    UnexpectedRead { client: u64 },
    /// A client that must read reported no line.
    MissingRead { client: u64 },
    /// uart's totals.
    Stats(&'static str),
    /// The probe's fault `i` is not an UnknownSyscall for its number.
    Probe { i: usize },
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Failure::WrongLine { client } => {
                write!(f, "client {} read the wrong line", name(client))
            }
            Failure::UnexpectedRead { client } => {
                write!(f, "client {} read a line it was not sent", name(client))
            }
            Failure::MissingRead { client } => write!(f, "client {} read no line", name(client)),
            Failure::Stats(what) => write!(f, "uart's Stats: {what}"),
            Failure::Probe { i } => write!(
                f,
                "the probe's fault {i} is not UnknownSyscall with number {} in MR18",
                PROBE_NUMBERS[i]
            ),
        }
    }
}

/// Checks the lines the clients read: each of [`READS`] exactly once, and
/// nothing else reached any client.
pub fn reads(got: &[(u64, &[u8])]) -> Result<(), Failure> {
    for &(client, line) in got {
        match READS.iter().find(|r| r.0 == client) {
            None => return Err(Failure::UnexpectedRead { client }),
            Some(r) if r.1.as_bytes() != line => return Err(Failure::WrongLine { client }),
            Some(_) => {}
        }
    }
    for r in READS {
        match got.iter().filter(|g| g.0 == r.0).count() {
            0 => return Err(Failure::MissingRead { client: r.0 }),
            1 => {}
            _ => return Err(Failure::UnexpectedRead { client: r.0 }),
        }
    }
    Ok(())
}

/// Checks uart's totals: signals and THRE bursts above 0, exactly the
/// bytes the harness sent, and no overruns or line errors.
pub fn stats(s: &UartStats, input_bytes: u64) -> Result<(), Failure> {
    if s.signals == 0 {
        return Err(Failure::Stats("no interrupt signals"));
    }
    if s.thre_bursts == 0 {
        return Err(Failure::Stats("no THRE bursts"));
    }
    if s.received != input_bytes {
        return Err(Failure::Stats("not the bytes the harness sent"));
    }
    if s.overruns != 0 || s.line_errors != 0 {
        return Err(Failure::Stats("overruns or line errors"));
    }
    Ok(())
}

/// The system calls the release probe makes, each an `UnknownSyscall` in
/// a kernel without `debug`: `DebugPutChar`, `DebugHalt`,
/// `DebugDumpScheduler` and the reserved 19 and 31.
pub const PROBE_NUMBERS: [u64; 5] = [16, 17, 18, 19, 31];
/// Words of an UnknownSyscall fault message, and of the reply that sets
/// the registers: MR0 to MR17.
pub const UNKNOWN_SYSCALL_WORDS: usize = 19;
pub const REPLY_WORDS: usize = 18;
/// MR15, `ip`; MR18, the number.
const IP: usize = 15;
const NUMBER: usize = 18;

/// Checks the probe's fault `i` and returns the reply's words: its
/// registers as the fault gave them, with `ip` 2 past the `syscall`.
pub fn probe_fault(
    i: usize,
    label: u64,
    words: &[u64; UNKNOWN_SYSCALL_WORDS],
    length: u64,
) -> Result<[u64; REPLY_WORDS], Failure> {
    if label != UNKNOWN_SYSCALL
        || length != UNKNOWN_SYSCALL_WORDS as u64
        || words[NUMBER] != PROBE_NUMBERS[i]
    {
        return Err(Failure::Probe { i });
    }
    let mut reply = [0; REPLY_WORDS];
    reply.copy_from_slice(&words[..REPLY_WORDS]);
    reply[IP] += 2;
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_scripts_lines() {
        let b2 = b2_line();
        assert_eq!(b2.len(), 300);
        assert!(b2.starts_with(b"b2 0123456789"));
        assert!(b2.ends_with(b"901 end\n"));
        assert_eq!(b2.iter().filter(|&&b| b == b'\n').count(), 1);
        let l = burst_line(7);
        assert!(l.starts_with(b"b burst 07 abc"));
        assert!(l.ends_with(b" 07\n"));
        assert_eq!(burst_line(12)[..11], *b"b burst 12 ");
        // Every line the transcript must show is distinct and in none of
        // the others, so a piece console put inside another line would be
        // missing from its own.
        let b2 = std::string::String::from_utf8(b2_line()[..B2_LEN - 1].to_vec()).unwrap();
        let mut lines: std::vec::Vec<std::string::String> = INTERLEAVED_LINES
            .iter()
            .map(std::string::ToString::to_string)
            .collect();
        lines.push(b2);
        for n in 1..=BURST_LINES {
            lines.push(
                std::string::String::from_utf8(burst_line(n)[..BURST_LEN - 1].to_vec()).unwrap(),
            );
        }
        for (i, a) in lines.iter().enumerate() {
            for (j, b) in lines.iter().enumerate() {
                assert!(i == j || !b.contains(a.as_str()), "{a:?} in {b:?}");
            }
        }
        // Steps 0 to 10 write the interleaved lines, 11 is the burst, and
        // root prints its line after the last interleaved step.
        assert!(
            SCRIPT[..=INTERLEAVED_STEPS]
                .iter()
                .all(|s| matches!(s.action, Action::Write(_) | Action::B2(_)))
        );
        assert_eq!(SCRIPT[INTERLEAVED_STEPS + 1].action, Action::Burst);
        assert_eq!(INTERLEAVED_STEPS + 2, INPUT_STEPS);
        assert_eq!(SCRIPT[INPUT_STEPS].action, Action::Input("a> "));
        assert_eq!(SCRIPT.len(), INPUT_STEPS + 2);
        assert_eq!(CONSOLE_INPUT_BYTES, 22);
        assert_eq!(RELEASE_INPUT_BYTES, 14);
    }

    #[test]
    fn reports_round_trip() {
        let mut words = [0; 120];
        let n = Report::encode(13, 0, b"to b", &mut words);
        assert_eq!(n, 4);
        let r = Report::decode(n, |i| words[i]).unwrap();
        assert_eq!((r.step, r.status, r.line()), (13, 0, &b"to b"[..]));
        let line = [b'x'; 255];
        let n = Report::encode(STARTED, 7, &line, &mut words);
        assert_eq!(n, 2 + 1 + 32);
        let r = Report::decode(n, |i| words[i]).unwrap();
        assert_eq!((r.step, r.status, r.line()), (STARTED, 7, &line[..]));
        // Too short, or a byte string that does not match its length.
        assert_eq!(Report::decode(2, |i| words[i]), None);
        assert_eq!(Report::decode(n - 1, |i| words[i]), None);
    }

    #[test]
    fn each_client_reads_its_line_and_nothing_else() {
        assert_eq!(reads(&[(B, b"to b"), (A, b"hi a")]), Ok(()));
        assert_eq!(
            reads(&[(A, b"hi a")]),
            Err(Failure::MissingRead { client: B })
        );
        assert_eq!(
            reads(&[(A, b"hi a"), (B, b"to a")]),
            Err(Failure::WrongLine { client: B })
        );
        assert_eq!(
            reads(&[(A, b"hello"), (B, b"to b")]),
            Err(Failure::WrongLine { client: A })
        );
        assert_eq!(
            reads(&[(A, b"hi a"), (B, b"to b"), (ROOT, b"x")]),
            Err(Failure::UnexpectedRead { client: ROOT })
        );
        assert_eq!(
            reads(&[(A, b"hi a"), (B, b"to b"), (A, b"hi a")]),
            Err(Failure::UnexpectedRead { client: A })
        );
    }

    #[test]
    fn uarts_totals() {
        let good = UartStats {
            signals: 30,
            received: 22,
            sent: 4000,
            thre_bursts: 200,
            writes_held: 1,
            ..UartStats::default()
        };
        assert_eq!(stats(&good, 22), Ok(()));
        assert!(stats(&good, 14).is_err());
        assert!(stats(&UartStats { signals: 0, ..good }, 22).is_err());
        assert!(
            stats(
                &UartStats {
                    thre_bursts: 0,
                    ..good
                },
                22
            )
            .is_err()
        );
        assert!(
            stats(
                &UartStats {
                    overruns: 1,
                    ..good
                },
                22
            )
            .is_err()
        );
        assert!(
            stats(
                &UartStats {
                    line_errors: 1,
                    ..good
                },
                22
            )
            .is_err()
        );
    }

    #[test]
    fn the_probes_faults_are_answered_two_bytes_on() {
        let mut words = [0; UNKNOWN_SYSCALL_WORDS];
        for (j, w) in words.iter_mut().enumerate() {
            *w = 100 + j as u64;
        }
        for (i, &n) in PROBE_NUMBERS.iter().enumerate() {
            words[18] = n;
            let reply = probe_fault(i, UNKNOWN_SYSCALL, &words, 19).unwrap();
            assert_eq!(reply[15], 115 + 2);
            assert_eq!(reply[..15], words[..15]);
            assert_eq!(reply[16..], words[16..18]);
            // The wrong number, label or length.
            assert!(probe_fault((i + 1) % 5, UNKNOWN_SYSCALL, &words, 19).is_err());
            assert!(probe_fault(i, 5, &words, 19).is_err());
            assert!(probe_fault(i, UNKNOWN_SYSCALL, &words, 4).is_err());
        }
    }
}
