//! QEMU boot scenarios: `tests/qemu/*.scenario`.
//!
//! A scenario boots the image with a given kernel command line, reads COM1,
//! and passes when every `expect:` line appears in order and the guest exits
//! through `isa-debug-exit` with the expected status, all within the timeout.
//!
//! ```text
//! # Comments start with '#'.
//! cmdline: test=hello
//! exit: success            # or: failure
//! timeout: 60              # seconds; optional, at most 60
//! expect: microL4 kernel   # a substring of one serial line
//! expect: TEST PASS
//! ```

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};
use std::{fs, thread};

use crate::compile::Artifacts;
use crate::{Result, image, qemu, rel};

/// Every boot gets at most this long.
const MAX_TIMEOUT: Duration = Duration::from_secs(60);
/// The cloud box has two vCPUs and no KVM; more instances only slow each other.
const MAX_PARALLEL: usize = 2;
/// Serial lines shown when a scenario fails.
const TAIL_LINES: usize = 40;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Exit {
    Success,
    Failure,
}

impl Exit {
    fn status(self) -> i32 {
        match self {
            Exit::Success => qemu::GUEST_SUCCESS,
            Exit::Failure => qemu::GUEST_FAILURE,
        }
    }
}

#[derive(Debug, PartialEq, Eq)]
pub struct Scenario {
    pub name: String,
    pub cmdline: String,
    pub exit: Exit,
    pub timeout: Duration,
    pub expect: Vec<String>,
}

pub fn parse(name: &str, text: &str) -> Result<Scenario> {
    let mut cmdline = String::new();
    let mut exit = None;
    let mut timeout = MAX_TIMEOUT;
    let mut expect = Vec::new();
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
            "exit" => {
                exit = Some(match value {
                    "success" => Exit::Success,
                    "failure" => Exit::Failure,
                    _ => return Err(err("exit must be `success` or `failure`").into()),
                })
            }
            "timeout" => {
                let secs: u64 = value
                    .parse()
                    .map_err(|_| err("timeout must be whole seconds"))?;
                timeout = Duration::from_secs(secs);
                if timeout.is_zero() || timeout > MAX_TIMEOUT {
                    return Err(err("timeout must be between 1 and 60 seconds").into());
                }
            }
            "expect" if value.is_empty() => return Err(err("empty expect line").into()),
            "expect" => expect.push(value.to_string()),
            other => return Err(err(&format!("unknown key {other:?}")).into()),
        }
    }
    let exit = exit.ok_or_else(|| format!("{name}.scenario: missing `exit:`"))?;
    if expect.is_empty() {
        return Err(format!("{name}.scenario: needs at least one `expect:`").into());
    }
    Ok(Scenario {
        name: name.to_string(),
        cmdline,
        exit,
        timeout,
        expect,
    })
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

/// Tracks how far through the expected text the output has got. Each
/// expectation must appear after the previous one: on a later line, or
/// further along the same line.
pub struct Matcher<'a> {
    expect: &'a [String],
    next: usize,
}

impl<'a> Matcher<'a> {
    pub fn new(expect: &'a [String]) -> Self {
        Self { expect, next: 0 }
    }

    /// Feeds one serial line.
    pub fn feed(&mut self, line: &str) {
        let mut rest = line;
        while let Some(e) = self.expect.get(self.next) {
            let Some(at) = rest.find(e.as_str()) else {
                break;
            };
            rest = &rest[at + e.len()..];
            self.next += 1;
        }
    }

    pub fn done(&self) -> bool {
        self.next == self.expect.len()
    }

    pub fn waiting_for(&self) -> Option<&'a str> {
        self.expect.get(self.next).map(String::as_str)
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
    let disk = image::build_disk(dir, art, cmdline)?;
    let start = Instant::now();
    let mut child = qemu::base_command(&disk)?
        .args(["-display", "none", "-serial", "stdio", "-monitor", "none"])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()?;

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

    let mut matcher = Matcher::new(&sc.expect);
    let mut transcript = Vec::new();
    let deadline = start + sc.timeout;
    let mut timed_out = false;
    loop {
        match rx.recv_timeout(deadline.saturating_duration_since(Instant::now())) {
            Ok(line) => {
                matcher.feed(&line);
                transcript.push(line);
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
    let elapsed = start.elapsed().as_secs_f32();
    let stderr = stderr.join().unwrap_or_default();

    let log = dir.join("serial.log");
    fs::write(&log, transcript.join("\n") + "\n")?;

    let failure = if timed_out {
        Some(format!(
            "timed out after {} s{}",
            sc.timeout.as_secs(),
            matcher
                .waiting_for()
                .map(|w| format!(" waiting for {w:?}"))
                .unwrap_or_default()
        ))
    } else if !matcher.done() {
        let missing = matcher.waiting_for().unwrap_or_default();
        Some(format!(
            "never printed {missing:?}; {}",
            qemu::describe_exit(status.code())
        ))
    } else if status.code() != Some(sc.exit.status()) {
        Some(format!(
            "expected exit {:?}, but {}",
            sc.exit,
            qemu::describe_exit(status.code())
        ))
    } else {
        None
    };

    let mut report = String::new();
    match &failure {
        None => writeln!(report, "PASS {} ({elapsed:.1} s)", sc.name)?,
        Some(why) => {
            writeln!(report, "FAIL {} ({elapsed:.1} s): {why}", sc.name)?;
            writeln!(report, "  last serial lines (full log: {}):", rel(&log))?;
            for line in &transcript[transcript.len().saturating_sub(TAIL_LINES)..] {
                writeln!(report, "  | {line}")?;
            }
            for line in stderr.lines() {
                writeln!(report, "  qemu: {line}")?;
            }
        }
    }
    Ok((failure.is_none(), report))
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

    #[test]
    fn parses_a_scenario() {
        let s = parse("hello", HELLO).unwrap();
        assert_eq!(
            s,
            Scenario {
                name: "hello".into(),
                cmdline: "test=hello".into(),
                exit: Exit::Success,
                timeout: MAX_TIMEOUT,
                expect: vec!["microL4 kernel".into(), "TEST PASS".into()],
            }
        );
    }

    #[test]
    fn hash_inside_expect_text_is_kept() {
        let s = parse("x", "exit: failure\nexpect: issue#12 seen\ntimeout: 5\n").unwrap();
        assert_eq!(s.expect, vec!["issue#12 seen"]);
        assert_eq!(s.timeout, Duration::from_secs(5));
        assert_eq!(s.cmdline, "");
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
            ("exit: success\nno colon here\n", "key: value"),
        ] {
            let e = parse("t", text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?} gave {e:?}, wanted {why:?}");
        }
    }

    #[test]
    fn matcher_needs_lines_in_order() {
        let expect = vec!["one".to_string(), "two".to_string()];
        let mut m = Matcher::new(&expect);
        m.feed("two");
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
        let expect = vec!["a".to_string(), "a".to_string()];
        let mut m = Matcher::new(&expect);
        m.feed("a");
        assert!(!m.done());
        m.feed("a");
        assert!(m.done());
    }

    #[test]
    fn matcher_finds_several_in_order_on_one_line() {
        let expect = vec!["PANIC at".to_string(), "deliberate".to_string()];
        let mut m = Matcher::new(&expect);
        m.feed("KERNEL PANIC at main.rs:54: deliberate panic");
        assert!(m.done());

        let mut m = Matcher::new(&expect);
        m.feed("deliberate, then PANIC at");
        assert_eq!(m.waiting_for(), Some("deliberate"));
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
