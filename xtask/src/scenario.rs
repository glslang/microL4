//! QEMU boot scenarios: `tests/qemu/*.scenario`.
//!
//! A scenario boots the image with a given kernel command line, reads COM1,
//! and passes when every `expect:` line appears in order and the guest exits
//! through `isa-debug-exit` with the expected status, all within the timeout.
//! Each runs in `target/xtask/scenarios/<name>/`: the COM1 log stays there,
//! and so does the 64 MiB `disk.img` if the scenario fails; a pass deletes
//! the image.
//!
//! ```text
//! # Comments start with '#'.
//! cmdline: test=hello
//! kernel: selftest         # or: release, the kernel built without features
//! exit: success            # or: failure, or timeout
//! timeout: 60              # seconds; optional, at most 60
//! qemu_args: -cpu qemu64   # optional; appended to the QEMU command line
//! expect: microL4 kernel   # a substring of one serial line
//! next: root: microL4      # the very next line must start with this
//! send: hello\r            # written to COM1's input once the expects above
//!                          # it have matched
//! expect: TEST PASS
//! forbid: KERNEL PANIC     # no serial line may contain this
//! ```
//!
//! A `next:` follows an `expect:` or another `next:`: the serial line right
//! after the one the step above it matched must begin with its text, so
//! nothing was printed between them; any other line there fails the
//! scenario, and ends the boot at once rather than at the timeout. The
//! release scenarios use it to show the kernel printed
//! nothing between the loader's last line and the root task's first.
//! `exit: timeout` means the guest must still be running when the
//! scenario's `timeout:`, which it then needs, ends the boot: the only end a
//! release kernel without a user-level exit has. A `send:` value takes the
//! escapes `\r`, `\n`, `\t`, `\e` (ESC), `\\` and `\xHH`; as for every
//! value, its ends are trimmed and ` #` starts a comment, so a space or `#`
//! there is `\x20` or `\x23` (`docs/design.md`, "The harness").

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};
use std::{fs, thread};

use crate::compile::{Artifacts, Kernel};
use crate::{Result, image, qemu, rel};

/// Every boot gets at most this long.
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// The cloud box has two vCPUs and no KVM; more instances only slow each other.
const MAX_PARALLEL: usize = 2;
/// Serial lines shown when a scenario fails.
const TAIL_LINES: usize = 40;
/// Serial lines kept in the log; a guest stuck in a print loop cannot fill
/// the disk.
const MAX_LOG_LINES: usize = 100_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Success,
    Failure,
    /// Still running when the timeout ends the boot.
    Timeout,
}

impl Exit {
    /// QEMU's exit status when the guest ends the run this way.
    fn status(self) -> Option<i32> {
        match self {
            Exit::Success => Some(qemu::GUEST_SUCCESS),
            Exit::Failure => Some(qemu::GUEST_FAILURE),
            Exit::Timeout => None,
        }
    }
}

/// The most input one scenario may send, in bytes after unescaping.
const MAX_SEND_BYTES: usize = 4096;

/// One `expect:` or `send:`, in file order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Text a serial line must contain, after the previous step's.
    Expect(String),
    /// Bytes written to COM1's input once every `expect:` before it matched.
    Send(Vec<u8>),
    /// Text the serial line right after the previous step's must start
    /// with: no line may fall between them.
    Next(String),
}

#[derive(Debug, PartialEq, Eq)]
pub struct Scenario {
    pub name: String,
    pub cmdline: String,
    /// The kernel the image boots.
    pub kernel: Kernel,
    /// Extra QEMU arguments, split on whitespace.
    pub qemu_args: Vec<String>,
    pub exit: Exit,
    pub timeout: Duration,
    pub steps: Vec<Step>,
    /// Text no serial line may contain.
    pub forbid: Vec<String>,
}

pub fn parse(name: &str, text: &str) -> Result<Scenario> {
    let mut cmdline = String::new();
    let mut kernel = Kernel::Selftest;
    let mut qemu_args = Vec::new();
    let mut exit = None;
    let mut timeout = None;
    let mut steps = Vec::new();
    let mut forbid = Vec::new();
    for (n, raw) in text.lines().enumerate() {
        let err = |msg: &str| format!("{name}.scenario:{}: {msg}", n + 1);
        // A '#' starts a comment, except inside `expect:` text, where it may
        // be part of what the guest prints; there only " #" does.
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let (key, value) = line
            .split_once(':')
            .ok_or_else(|| err("expected `key: value`"))?;
        let value = match value.find(" #") {
            Some(i) => &value[..i],
            None => value,
        }
        .trim();
        match key.trim() {
            "cmdline" => cmdline = value.to_string(),
            "kernel" => {
                kernel = Kernel::parse(value)
                    .ok_or_else(|| err("kernel must be `selftest` or `release`"))?
            }
            "qemu_args" => qemu_args.extend(value.split_whitespace().map(String::from)),
            "qemu" => {
                return Err(err("unknown key \"qemu\"; QEMU arguments go in `qemu_args:`").into());
            }
            "exit" => {
                exit = Some(match value {
                    "success" => Exit::Success,
                    "failure" => Exit::Failure,
                    "timeout" => Exit::Timeout,
                    _ => {
                        return Err(err("exit must be `success`, `failure` or `timeout`").into());
                    }
                })
            }
            "timeout" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|_| err("timeout must be whole seconds"))?;
                let t = Duration::from_secs(secs);
                if t.is_zero() || t > MAX_TIMEOUT {
                    return Err(err("timeout must be between 1 and 60 seconds").into());
                }
                timeout = Some(t);
            }
            "expect" if value.is_empty() => return Err(err("empty expect line").into()),
            "expect" => steps.push(Step::Expect(value.to_string())),
            "next" if value.is_empty() => return Err(err("empty next line").into()),
            "next" => {
                if !matches!(steps.last(), Some(Step::Expect(_) | Step::Next(_))) {
                    return Err(
                        err("a `next:` needs an `expect:` or `next:` right above it").into(),
                    );
                }
                steps.push(Step::Next(value.to_string()));
            }
            "send" if value.is_empty() => return Err(err("empty send line").into()),
            "send" => {
                // Until the guest's uart has started, OVMF reads COM1, and
                // uart's FIFO reset drops whatever arrived before it.
                if !steps.iter().any(|s| matches!(s, Step::Expect(_))) {
                    return Err(err("a `send:` needs an `expect:` above it").into());
                }
                steps.push(Step::Send(unescape(value).map_err(|e| err(&e))?));
            }
            "forbid" if value.is_empty() => return Err(err("empty forbid line").into()),
            "forbid" => forbid.push(value.to_string()),
            other => return Err(err(&format!("unknown key {other:?}")).into()),
        }
    }
    let exit = exit.ok_or_else(|| format!("{name}.scenario: missing `exit:`"))?;
    if !steps.iter().any(|s| matches!(s, Step::Expect(_))) {
        return Err(format!("{name}.scenario: needs at least one `expect:`").into());
    }
    if exit == Exit::Timeout && timeout.is_none() {
        return Err(format!("{name}.scenario: `exit: timeout` needs a `timeout:`").into());
    }
    // The runner writes sends to QEMU's stdin with a blocking write on the
    // thread that also enforces the timeout. Keeping every scenario's input
    // far below a pipe's buffer (64 KiB on Linux) means that write never
    // waits on a guest that has stopped reading.
    let sent: usize = steps
        .iter()
        .map(|s| match s {
            Step::Send(bytes) => bytes.len(),
            Step::Expect(_) | Step::Next(_) => 0,
        })
        .sum();
    if sent > MAX_SEND_BYTES {
        return Err(format!(
            "{name}.scenario: its `send:` lines total {sent} bytes, more than {MAX_SEND_BYTES}"
        )
        .into());
    }
    Ok(Scenario {
        name: name.to_string(),
        cmdline,
        kernel,
        qemu_args,
        exit,
        timeout: timeout.unwrap_or(MAX_TIMEOUT),
        steps,
        forbid,
    })
}

/// Decodes a `send:` value: `\r`, `\n`, `\t`, `\e` (ESC), `\\` and `\xHH`
/// stand for their bytes, a `\` before anything else is an error, and every
/// other character stands for its UTF-8 bytes.
pub fn unescape(text: &str) -> std::result::Result<Vec<u8>, String> {
    let mut out = Vec::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.extend_from_slice(c.encode_utf8(&mut [0; 4]).as_bytes());
            continue;
        }
        out.push(match chars.next() {
            Some('r') => b'\r',
            Some('n') => b'\n',
            Some('t') => b'\t',
            Some('e') => 0x1B,
            Some('\\') => b'\\',
            Some('x') => {
                let digit = |c: Option<char>| c.and_then(|c| c.to_digit(16));
                match (digit(chars.next()), digit(chars.next())) {
                    (Some(hi), Some(lo)) => (hi << 4 | lo) as u8,
                    _ => return Err(r"`\x` needs two hex digits".into()),
                }
            }
            Some(c) => return Err(format!("unknown escape `\\{c}`")),
            None => return Err(r"a `\` ends the text".into()),
        });
    }
    Ok(out)
}

/// Loads every `*.scenario` in `dir`, sorted by name.
pub fn load_dir(dir: &Path) -> Result<Vec<Scenario>> {
    let mut paths: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| format!("{}: {e}", dir.display()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "scenario"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy();
            parse(&name, &fs::read_to_string(p)?)
        })
        .collect()
}

/// Strips terminal escape sequences, carriage returns and other control
/// characters that OVMF's console output is full of.
pub fn clean(raw: &[u8]) -> String {
    let text = String::from_utf8_lossy(raw);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        match c {
            '\x1b' => {
                if chars.peek() == Some(&'[') {
                    chars.next();
                    // CSI: parameters, then one final byte in '@'..='~'.
                    for c in chars.by_ref() {
                        if ('@'..='~').contains(&c) {
                            break;
                        }
                    }
                } else {
                    // Other escapes: intermediates in ' '..='/', then a final
                    // byte, as in ESC ( B.
                    while chars.next_if(|c| (' '..='/').contains(c)).is_some() {}
                    chars.next();
                }
            }
            '\t' => out.push(c),
            c if c.is_control() => {}
            c => out.push(c),
        }
    }
    out
}

/// Tracks how far through the steps the output has got. Each expectation
/// must appear after the previous one: on a later line, or further along
/// the same line. A send is released as soon as every expectation before
/// it has matched, and the expectations after it match only from the next
/// line on: the rest of the line that released it was printed before the
/// guest could have read the text. A `next:` must match at the start of the
/// line after its step's; when it does not, the matcher is broken and
/// matches nothing more.
pub struct Matcher<'a> {
    steps: &'a [Step],
    next: usize,
    broken: Option<String>,
}

impl<'a> Matcher<'a> {
    pub fn new(steps: &'a [Step]) -> Self {
        Self {
            steps,
            next: 0,
            broken: None,
        }
    }

    /// Feeds one serial line. Returns the text of each send it released,
    /// in order.
    pub fn feed(&mut self, line: &str) -> Vec<&'a [u8]> {
        let mut rest = line;
        let mut sends = Vec::new();
        // Whether a step matched on this line.
        let mut matched = false;
        while self.broken.is_none()
            && let Some(step) = self.steps.get(self.next)
        {
            match step {
                Step::Expect(_) if !sends.is_empty() => break,
                Step::Expect(e) => {
                    let Some(at) = rest.find(e.as_str()) else {
                        break;
                    };
                    rest = &rest[at + e.len()..];
                    matched = true;
                }
                // Its line is the next one. The parser put an `expect:` or
                // `next:` right above it, so the line before matched that.
                Step::Next(_) if matched => break,
                Step::Next(t) => {
                    let Some(r) = line.strip_prefix(t.as_str()) else {
                        let above = match &self.steps[self.next - 1] {
                            Step::Expect(a) | Step::Next(a) => a.as_str(),
                            Step::Send(_) => "",
                        };
                        self.broken = Some(format!(
                            "printed {line:?} right after the line with {above:?}, \
                             where a line starting {t:?} must come"
                        ));
                        break;
                    };
                    rest = r;
                    matched = true;
                }
                Step::Send(text) => sends.push(text.as_slice()),
            }
            self.next += 1;
        }
        sends
    }

    /// Why a `next:` failed, if one did.
    pub fn broken(&self) -> Option<&str> {
        self.broken.as_deref()
    }

    pub fn done(&self) -> bool {
        self.next == self.steps.len()
    }

    pub fn waiting_for(&self) -> Option<&'a str> {
        self.steps[self.next..].iter().find_map(|s| match s {
            Step::Expect(e) | Step::Next(e) => Some(e.as_str()),
            Step::Send(_) => None,
        })
    }
}

pub struct Outcome {
    pub name: String,
    pub passed: bool,
}

/// Runs `scenarios`, at most [`MAX_PARALLEL`] at a time, printing a report
/// for each as it finishes.
pub fn run_all(scenarios: &[Scenario], art: &Artifacts, dir: &Path) -> Vec<Outcome> {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::new());
    thread::scope(|s| {
        for _ in 0..MAX_PARALLEL.min(scenarios.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(sc) = scenarios.get(i) else { break };
                    let (passed, report) = match run_one(sc, art, &dir.join(&sc.name)) {
                        Ok(r) => r,
                        Err(e) => (false, format!("FAIL {}: {e}\n", sc.name)),
                    };
                    print!("{report}");
                    results.lock().unwrap().push((
                        i,
                        Outcome {
                            name: sc.name.clone(),
                            passed,
                        },
                    ));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|(i, _)| *i);
    results.into_iter().map(|(_, o)| o).collect()
}

/// Boots one scenario. Returns whether it passed and a printable report.
fn run_one(sc: &Scenario, art: &Artifacts, dir: &Path) -> Result<(bool, String)> {
    let cmdline = (!sc.cmdline.is_empty()).then_some(sc.cmdline.as_str());
    let disk = image::build_disk(dir, art, sc.kernel, cmdline)?;
    // COM1's input is QEMU's stdin: a pipe for a scenario that sends, and
    // otherwise nothing.
    let sends = sc.steps.iter().any(|s| matches!(s, Step::Send(_)));
    let start = Instant::now();
    let mut child = qemu::base_command(&disk)?
        .args(["-display", "none", "-serial", "stdio", "-monitor", "none"])
        .args(&sc.qemu_args)
        .stdin(if sends { Stdio::piped() } else { Stdio::null() })
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;
    let mut stdin = child.stdin.take();

    let (tx, rx) = mpsc::channel();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    thread::spawn(move || {
        let mut buf = Vec::new();
        while matches!(stdout.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
            if tx.send(clean(&buf)).is_err() {
                break;
            }
            buf.clear();
        }
    });
    let mut stderr = child.stderr.take().unwrap();
    let stderr = thread::spawn(move || {
        let mut s = String::new();
        let _ = stderr.read_to_string(&mut s);
        s
    });

    let mut matcher = Matcher::new(&sc.steps);
    let mut transcript = Vec::new();
    let mut record = |line: String| {
        if transcript.len() < MAX_LOG_LINES {
            transcript.push(line);
        }
    };
    // The first serial line with forbidden text, and the text.
    let mut forbidden: Option<(&str, String)> = None;
    let mut send_error = None;
    let deadline = start + sc.timeout;
    let mut timed_out = false;
    loop {
        // Checked on every line, so a guest that never stops printing still
        // hits the limit.
        let left = deadline.saturating_duration_since(Instant::now());
        let line = if left.is_zero() {
            Err(RecvTimeoutError::Timeout)
        } else {
            rx.recv_timeout(left)
        };
        match line {
            Ok(line) => {
                if forbidden.is_none()
                    && let Some(f) = sc.forbid.iter().find(|f| line.contains(f.as_str()))
                {
                    forbidden = Some((f.as_str(), line.clone()));
                }
                let released = matcher.feed(&line);
                record(line);
                for text in released {
                    // `sends` made the pipe for every scenario with a send.
                    let pipe = stdin.as_mut().unwrap();
                    if let Err(e) = pipe.write_all(text).and_then(|()| pipe.flush()) {
                        send_error.get_or_insert(format!(
                            "could not send \"{}\": {e}",
                            text.escape_ascii()
                        ));
                    }
                    record(format!("xtask: sent \"{}\"", text.escape_ascii()));
                }
                // A failed `next:` is the scenario's failure, and no later
                // line can mend it: end the boot now.
                if matcher.broken().is_some() {
                    let _ = child.kill();
                    break;
                }
            }
            Err(RecvTimeoutError::Timeout) => {
                timed_out = true;
                let _ = child.kill();
                break;
            }
            Err(RecvTimeoutError::Disconnected) => break,
        }
    }
    let status = child.wait()?;
    drop(stdin);
    let elapsed = start.elapsed().as_secs_f32();
    let stderr = stderr.join().unwrap_or_default();

    let log = dir.join("serial.log");
    fs::write(&log, transcript.join("\n") + "\n")?;

    let mut why = Vec::new();
    if let Some((text, line)) = &forbidden {
        why.push(format!("printed forbidden {text:?} in {line:?}"));
    }
    why.extend(send_error);
    why.extend(matcher.broken().map(String::from));
    let secs = sc.timeout.as_secs();
    let waiting = matcher
        .waiting_for()
        .map(|w| format!(" waiting for {w:?}"))
        .unwrap_or_default();
    match (sc.exit.status(), timed_out) {
        // Its steps stopped there; that is the failure.
        _ if matcher.broken().is_some() => {}
        (None, true) if matcher.done() => {}
        (None, true) => why.push(format!("ran until the {secs} s timeout{waiting}")),
        (None, false) => why.push(format!(
            "expected the guest to run until the {secs} s timeout, but {}",
            qemu::describe_exit(status.code())
        )),
        (Some(_), true) => why.push(format!("timed out after {secs} s{waiting}")),
        (Some(_), false) if !matcher.done() => why.push(format!(
            "never printed {:?}; {}",
            matcher.waiting_for().unwrap_or_default(),
            qemu::describe_exit(status.code())
        )),
        (Some(expected), false) if status.code() != Some(expected) => why.push(format!(
            "expected exit {:?}, but {}",
            sc.exit,
            qemu::describe_exit(status.code())
        )),
        (Some(_), false) => {}
    }

    let mut report = String::new();
    if why.is_empty() {
        // 64 MiB per scenario adds up to gigabytes per run; a failure
        // keeps its image beside the log, to boot again by hand.
        fs::remove_file(&disk)?;
        writeln!(report, "PASS {} ({elapsed:.1} s)", sc.name)?
    } else {
        writeln!(
            report,
            "FAIL {} ({elapsed:.1} s): {}",
            sc.name,
            why.join("; ")
        )?;
        writeln!(report, "  last serial lines (full log: {}):", rel(&log))?;
        for line in &transcript[transcript.len().saturating_sub(TAIL_LINES)..] {
            writeln!(report, "  | {line}")?;
        }
        for line in stderr.lines() {
            writeln!(report, "  qemu: {line}")?;
        }
    }
    Ok((why.is_empty(), report))
}

#[cfg(test)]
mod tests {
    use super::*;

    const HELLO: &str = "\
# Boots and says hello.
cmdline: test=hello
exit: success
expect: microL4 kernel
expect: TEST PASS   # the kernel's success marker
";

    fn expect(e: &str) -> Step {
        Step::Expect(e.into())
    }

    fn send(s: &[u8]) -> Step {
        Step::Send(s.into())
    }

    fn next(n: &str) -> Step {
        Step::Next(n.into())
    }

    #[test]
    fn parses_a_scenario() {
        let s = parse("hello", HELLO).unwrap();
        assert_eq!(
            s,
            Scenario {
                name: "hello".into(),
                cmdline: "test=hello".into(),
                kernel: Kernel::Selftest,
                qemu_args: vec![],
                exit: Exit::Success,
                timeout: MAX_TIMEOUT,
                steps: vec![expect("microL4 kernel"), expect("TEST PASS")],
                forbid: vec![],
            }
        );
    }

    #[test]
    fn hash_inside_expect_text_is_kept() {
        let s = parse("x", "exit: failure\nexpect: issue#12 seen\ntimeout: 5\n").unwrap();
        assert_eq!(s.steps, vec![expect("issue#12 seen")]);
        assert_eq!(s.timeout, Duration::from_secs(5));
        assert_eq!(s.cmdline, "");
    }

    #[test]
    fn qemu_args_split_and_accumulate() {
        let s = parse(
            "x",
            "exit: failure\nqemu_args: -cpu qemu64  # old CPU\nqemu_args: -global ioapic.version=0x11\nexpect: x\n",
        )
        .unwrap();
        assert_eq!(
            s.qemu_args,
            ["-cpu", "qemu64", "-global", "ioapic.version=0x11"]
        );
    }

    #[test]
    fn parses_the_m7_directives() {
        let s = parse(
            "release",
            "\
kernel: release
cmdline: test=release
exit: success
expect: release: type a line
send: release input\\r   # 14 bytes
send: \\x20#\\x23
expect: release: read \"release input\"
forbid: microL4 kernel
forbid: KERNEL PANIC     # what a debug kernel would print
",
        )
        .unwrap();
        assert_eq!(s.kernel, Kernel::Release);
        assert_eq!(
            s.steps,
            vec![
                expect("release: type a line"),
                send(b"release input\r"),
                send(b" ##"),
                expect("release: read \"release input\""),
            ]
        );
        assert_eq!(s.forbid, ["microL4 kernel", "KERNEL PANIC"]);
        assert_eq!(
            parse("x", "kernel: selftest\nexit: success\nexpect: x\n")
                .unwrap()
                .kernel,
            Kernel::Selftest
        );
    }

    #[test]
    fn parses_next_lines() {
        let s = parse(
            "release",
            "\
exit: success
expect: entering kernel
forbid: microL4 kernel
next: root: microL4 root task   # nothing between
next: root: image
expect: TEST PASS
",
        )
        .unwrap();
        assert_eq!(
            s.steps,
            vec![
                expect("entering kernel"),
                next("root: microL4 root task"),
                next("root: image"),
                expect("TEST PASS"),
            ]
        );
        for (text, why) in [
            (
                "exit: success\nnext: x\n",
                "2: a `next:` needs an `expect:`",
            ),
            (
                "exit: success\nnext: x\nexpect: y\n",
                "needs an `expect:` or `next:`",
            ),
            (
                "exit: success\nexpect: x\nsend: y\nnext: z\n",
                "needs an `expect:` or `next:`",
            ),
            (
                "exit: success\nexpect: x\nnext:   # nothing\n",
                "empty next",
            ),
        ] {
            let e = parse("t", text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?} gave {e:?}, wanted {why:?}");
        }
    }

    #[test]
    fn exit_timeout_needs_a_timeout() {
        let s = parse("x", "exit: timeout\ntimeout: 20\nexpect: x\n").unwrap();
        assert_eq!(
            (s.exit, s.timeout),
            (Exit::Timeout, Duration::from_secs(20))
        );
        let e = parse("x", "exit: timeout\nexpect: x\n").unwrap_err();
        assert!(e.to_string().contains("needs a `timeout:`"), "{e}");
    }

    #[test]
    fn decodes_send_escapes() {
        for (text, bytes) in [
            ("plain", &b"plain"[..]),
            (r"\r\n\t\e\\", b"\r\n\t\x1b\\"),
            (r"\x143to b\r", b"\x143to b\r"),
            (r"\x142hellp\x7fo\x15hi a\r", b"\x142hellp\x7fo\x15hi a\r"),
            (r"\x00\xff\xAb", b"\x00\xff\xab"),
            ("é", "é".as_bytes()),
            ("", b""),
        ] {
            assert_eq!(unescape(text).unwrap(), bytes, "{text:?}");
        }
        for (text, why) in [
            (r"\q", r"unknown escape `\q`"),
            (r#"\""#, r#"unknown escape `\"`"#),
            (r"\é", r"unknown escape `\é`"),
            (r"\x1", "two hex digits"),
            (r"\x1g", "two hex digits"),
            (r"\xé0", "two hex digits"),
            (r"ab\", r"a `\` ends the text"),
        ] {
            let e = unescape(text).unwrap_err();
            assert!(e.contains(why), "{text:?} gave {e:?}, wanted {why:?}");
        }
    }

    #[test]
    fn rejects_bad_scenarios() {
        for (text, why) in [
            ("expect: x\n", "missing `exit:`"),
            ("exit: success\n", "at least one `expect:`"),
            ("exit: maybe\nexpect: x\n", "exit must be"),
            (
                "exit: success\nexpect: x\ntimeout: 61\n",
                "between 1 and 60",
            ),
            ("exit: success\nexpect: x\ntimeout: 0\n", "between 1 and 60"),
            ("exit: success\nexpect: x\ntimeout: soon\n", "whole seconds"),
            ("exit: success\nexpect:\n", "empty expect"),
            ("exit: success\nexpect: x\nretries: 3\n", "unknown key"),
            (
                &format!("exit: success\nexpect: x\nsend: {}\n", "a".repeat(4097)),
                "more than 4096",
            ),
            ("exit: success\nno colon here\n", "key: value"),
            (
                "exit: success\nsend: x\nexpect: x\n",
                "needs an `expect:` above",
            ),
            (
                "exit: success\nforbid: x\nsend: x\n",
                "needs an `expect:` above",
            ),
            (
                "exit: success\nexpect: x\nsend:   # nothing\n",
                "empty send",
            ),
            ("exit: success\nexpect: x\nsend: \\q\n", "3: unknown escape"),
            ("exit: success\nexpect: x\nforbid:\n", "empty forbid"),
            (
                "kernel: debug\nexit: success\nexpect: x\n",
                "kernel must be",
            ),
            ("exit: success\nexpect: x\nqemu: -s\n", "go in `qemu_args:`"),
        ] {
            let e = parse("t", text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?} gave {e:?}, wanted {why:?}");
        }
    }

    #[test]
    fn matcher_needs_lines_in_order() {
        let steps = vec![expect("one"), expect("two")];
        let mut m = Matcher::new(&steps);
        assert!(m.feed("two").is_empty());
        assert_eq!(m.waiting_for(), Some("one"));
        m.feed("this is one");
        m.feed("noise");
        assert!(!m.done());
        m.feed("two!");
        assert!(m.done());
        assert_eq!(m.waiting_for(), None);
    }

    #[test]
    fn matcher_consumes_each_match() {
        let steps = vec![expect("a"), expect("a")];
        let mut m = Matcher::new(&steps);
        m.feed("a");
        assert!(!m.done());
        m.feed("a");
        assert!(m.done());
    }

    #[test]
    fn matcher_finds_several_in_order_on_one_line() {
        let steps = vec![expect("PANIC at"), expect("deliberate")];
        let mut m = Matcher::new(&steps);
        m.feed("KERNEL PANIC at main.rs:54: deliberate panic");
        assert!(m.done());

        let mut m = Matcher::new(&steps);
        m.feed("deliberate, then PANIC at");
        assert_eq!(m.waiting_for(), Some("deliberate"));
    }

    #[test]
    fn matcher_releases_each_send_after_the_expects_above_it() {
        let steps = vec![
            expect("console: input next"),
            send(b"\x143to b\r"),
            expect("focus 3 (b)"),
            expect("b: read \"to b\""),
            send(b"\x142"),
            send(b"hi a\r"),
            expect("a: read \"hi a\""),
        ];
        let mut m = Matcher::new(&steps);
        assert!(m.feed("root: starting").is_empty());
        assert!(m.feed("focus 3 (b)").is_empty(), "too early");
        assert_eq!(m.waiting_for(), Some("console: input next"));
        assert_eq!(m.feed("console: input next"), [b"\x143to b\r"]);
        assert_eq!(m.waiting_for(), Some("focus 3 (b)"));
        assert!(m.feed("[console] focus 3 (b)").is_empty());
        // Consecutive sends go together, in order.
        assert_eq!(m.feed("b: read \"to b\""), [&b"\x142"[..], b"hi a\r"]);
        assert!(!m.done());
        assert!(m.feed("a: read \"hi a\"").is_empty());
        assert!(m.done());
        assert!(m.feed("console: input next").is_empty(), "sent once");
    }

    #[test]
    fn matcher_matches_after_a_send_only_from_the_next_line() {
        let steps = vec![expect("prompt"), send(b"x\r"), expect("got")];
        let mut m = Matcher::new(&steps);
        // "got" was printed before the text was written.
        assert_eq!(m.feed("prompt; got nothing yet"), [b"x\r"]);
        assert_eq!(m.waiting_for(), Some("got"));
        m.feed("got x");
        assert!(m.done());
    }

    #[test]
    fn matcher_releases_trailing_sends_with_the_last_expect() {
        let steps = vec![expect("ready"), send(b"bye\r")];
        let mut m = Matcher::new(&steps);
        assert_eq!(m.feed("ready"), [b"bye\r"]);
        assert!(m.done());
        assert_eq!(m.waiting_for(), None);
    }

    #[test]
    fn matcher_takes_next_only_from_the_start_of_the_next_line() {
        let steps = vec![
            expect("entering kernel"),
            next("root: microL4"),
            next("root: image"),
            expect("ok"),
        ];
        let lines = [
            "loader: entering kernel",
            "root: microL4 root task",
            "root: image ok",
        ];
        let mut m = Matcher::new(&steps);
        assert!(m.feed("loader: microL4 loader").is_empty());
        for l in lines {
            m.feed(l);
        }
        // An `expect:` after it matches on the rest of its line.
        assert!(m.done(), "{:?}", m.waiting_for());
        assert_eq!(m.broken(), None);
        // A line between, a line that has the text but does not start
        // with it, or the text further along the same line.
        for (between, after) in [
            (Some("microL4 kernel"), "root: microL4 root task"),
            (None, "Xroot: microL4 root task"),
            (None, " root: microL4 root task"),
        ] {
            let mut m = Matcher::new(&steps);
            m.feed(lines[0]);
            if let Some(b) = between {
                m.feed(b);
            }
            m.feed(after);
            let why = m.broken().expect("broken");
            assert!(
                why.contains("right after the line with \"entering kernel\"")
                    && why.contains("starting \"root: microL4\""),
                "{why}"
            );
            // Broken for good: nothing more matches.
            m.feed("root: microL4 root task");
            m.feed("root: image ok");
            assert!(!m.done());
        }
        let mut m = Matcher::new(&steps);
        m.feed("loader: entering kernel root: microL4");
        assert_eq!(m.broken(), None);
        assert_eq!(m.waiting_for(), Some("root: microL4"));
        m.feed("ok");
        assert!(m.broken().unwrap().starts_with("printed \"ok\""));
        // A `next:` after a `next:` is the line after that one's.
        let mut m = Matcher::new(&steps);
        m.feed(lines[0]);
        m.feed(lines[1]);
        m.feed("noise");
        assert!(
            m.broken()
                .unwrap()
                .contains("after the line with \"root: microL4\"")
        );
    }

    #[test]
    fn clean_strips_terminal_noise() {
        assert_eq!(clean(b"\x1b[2J\x1b[01;01Hloader: hi\r\n"), "loader: hi");
        assert_eq!(
            clean(b"\x1b[0m\x1b[37m\x1b[40mBdsDxe: loading\r\n"),
            "BdsDxe: loading"
        );
        assert_eq!(clean(b"a\x1b(Bb\tc\x07"), "ab\tc");
        assert_eq!(clean(b"bad \xff byte"), "bad \u{fffd} byte");
    }

    #[test]
    fn repo_scenarios_parse() {
        let all = load_dir(&crate::root().join("tests/qemu")).unwrap();
        assert!(all.iter().any(|s| s.name == "hello"));
        assert!(all.iter().any(|s| s.name == "panic"));
    }
}
