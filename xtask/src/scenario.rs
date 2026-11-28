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
//! expect: tui: drawn
//! screendump: tui          # the screen, once the line above has matched,
//!                          # must equal tests/qemu/golden/tui.png
//! send: hello\r            # written to COM1's input once the expects above
//!                          # it have matched
//! expect: TEST PASS
//! forbid: KERNEL PANIC     # no serial line may contain this
//! nic: virtio-net          # (M9) a NIC, with a forwarded UDP port
//! expect: echo: listening on UDP port 7
//! udp_echo: 100            # 100 datagrams through it, each echoed once
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
//!
//! A `screendump:` follows an `expect:` or a `next:`. Once that step has
//! matched, xtask takes the screen through QEMU's QMP monitor
//! ([`qemu::Qmp`]) before any later step, and when the boot has ended
//! compares it, pixel for pixel, with `tests/qemu/golden/<name>.png`
//! ([`screen`]). The screen stays beside the log as `<name>.png`, and a
//! mismatch leaves `<name>.diff.png` there too. `cargo xtask test --bless`
//! writes each screen that differs from its golden, or has none, as the
//! golden, if its scenario passed everything else, but never replaces one
//! the host drew (the `tui` scenario's, from `hostrender.rs`, whose
//! `Source` is [`screen::HOST_RENDER`]): it says so, and the scenario
//! fails. The guest must keep the
//! screen still from the line the screendump follows until it is taken:
//! say, by waiting for a `send:` after it.
//!
//! From M9, `nic: virtio-net` gives the machine a virtio-net device on
//! QEMU's user networking ([`qemu::nic_args`]), with a free loopback UDP
//! port forwarded to the guest's port 7, and `udp_echo: <count>`, which
//! follows an `expect:` or a `next:` in a scenario with `nic:`, sends
//! `count` datagrams through that port once the step above it has matched
//! and before any later step, and fails the scenario unless each comes
//! back once, unaltered ([`udp::exchange`]). Like a `send:`, it changes
//! what the guest does, so the steps after it match from the next line
//! on; the lines that arrive while it runs are matched when it ends. The
//! log records the port and each exchange as `xtask:` lines.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{Ipv4Addr, SocketAddr};
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};
use std::{fs, thread};

use crate::compile::{Artifacts, Kernel};
use crate::qemu::Nic;
use crate::{Result, image, qemu, rel, screen, udp};

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

/// One `expect:`, `next:`, `send:`, `screendump:` or `udp_echo:`, in file
/// order.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Step {
    /// Text a serial line must contain, after the previous step's.
    Expect(String),
    /// Bytes written to COM1's input once every `expect:` before it matched.
    Send(Vec<u8>),
    /// Text the serial line right after the previous step's must start
    /// with: no line may fall between them.
    Next(String),
    /// The screen, captured once the step right above it matched and
    /// compared with `tests/qemu/golden/<name>.png`.
    Screendump(String),
    /// (M9) This many datagrams through the forwarded port, once the step
    /// right above it matched, each to come back once, unaltered.
    UdpEcho(u32),
}

/// What the runner does when the matcher reaches a `send:`, a
/// `screendump:` or a `udp_echo:`, in step order.
#[derive(Debug, PartialEq, Eq)]
pub enum Action<'a> {
    Send(&'a [u8]),
    Screendump(&'a str),
    UdpEcho(u32),
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
    /// (M9) The network device, if any.
    pub nic: Option<Nic>,
}

pub fn parse(name: &str, text: &str) -> Result<Scenario> {
    let mut cmdline = String::new();
    let mut kernel = Kernel::Selftest;
    let mut qemu_args = Vec::new();
    let mut exit = None;
    let mut timeout = None;
    let mut steps = Vec::new();
    let mut forbid = Vec::new();
    let mut nic = None;
    // The first `udp_echo:`'s line, which needs a `nic:`.
    let mut udp_echo_line = None;
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
            "screendump" if value.is_empty() => return Err(err("empty screendump line").into()),
            "screendump" => {
                // The screen is the one the line above announced. Right
                // after a `send:` it would race the guest's answer to it.
                if !matches!(steps.last(), Some(Step::Expect(_) | Step::Next(_))) {
                    return Err(err(
                        "a `screendump:` needs an `expect:` or `next:` right above it",
                    )
                    .into());
                }
                // It names a file in tests/qemu/golden/.
                if !value
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"-_".contains(&b))
                {
                    return Err(err(
                        "a screendump's name is lowercase letters, digits, `-` and `_`",
                    )
                    .into());
                }
                if steps
                    .iter()
                    .any(|s| matches!(s, Step::Screendump(n) if n == value))
                {
                    return Err(err(&format!("a second screendump named {value:?}")).into());
                }
                steps.push(Step::Screendump(value.to_string()));
            }
            "nic" if nic.is_some() => return Err(err("a second `nic:`").into()),
            "nic" => {
                nic = Some(Nic::parse(value).ok_or_else(|| err("nic must be `virtio-net`"))?);
            }
            "udp_echo" => {
                // The exchange is the guest's answer to what the line above
                // announced, as a screendump's screen is.
                if !matches!(steps.last(), Some(Step::Expect(_) | Step::Next(_))) {
                    return Err(
                        err("a `udp_echo:` needs an `expect:` or `next:` right above it").into(),
                    );
                }
                let count = Some(value)
                    .filter(|v| !v.is_empty() && v.bytes().all(|b| b.is_ascii_digit()))
                    .and_then(|v| v.parse().ok())
                    .filter(|n| (1..=udp::MAX_COUNT).contains(n))
                    .ok_or_else(|| {
                        err(&format!(
                            "udp_echo's count must be a number from 1 to {}",
                            udp::MAX_COUNT
                        ))
                    })?;
                steps.push(Step::UdpEcho(count));
                udp_echo_line.get_or_insert(n + 1);
            }
            other => return Err(err(&format!("unknown key {other:?}")).into()),
        }
    }
    if let Some(line) = udp_echo_line
        && nic.is_none()
    {
        return Err(format!(
            "{name}.scenario:{line}: a `udp_echo:` needs `nic: virtio-net`, its forwarded port"
        )
        .into());
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
            Step::Expect(_) | Step::Next(_) | Step::Screendump(_) | Step::UdpEcho(_) => 0,
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
        nic,
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
    let scenarios = paths
        .iter()
        .map(|p| {
            let name = p.file_stem().unwrap().to_string_lossy();
            parse(&name, &fs::read_to_string(p)?)
        })
        .collect::<Result<Vec<_>>>()?;
    check_screendump_names(&scenarios)?;
    Ok(scenarios)
}

/// Every scenario's screendumps share `tests/qemu/golden/`, so no two may
/// have one name: scenarios run two at a time, and `--bless` would have
/// both write one file.
fn check_screendump_names(scenarios: &[Scenario]) -> Result<()> {
    let mut seen: Vec<(&str, &str)> = Vec::new();
    for sc in scenarios {
        for name in sc.screendumps() {
            if let Some((_, other)) = seen.iter().find(|(n, _)| *n == name) {
                return Err(format!(
                    "{}.scenario and {other}.scenario both have a screendump named {name:?}",
                    sc.name
                )
                .into());
            }
            seen.push((name, &sc.name));
        }
    }
    Ok(())
}

impl Scenario {
    /// The names of its `screendump:` steps, in order.
    pub fn screendumps(&self) -> impl Iterator<Item = &str> {
        self.steps.iter().filter_map(|s| match s {
            Step::Screendump(name) => Some(name.as_str()),
            _ => None,
        })
    }
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
/// guest could have read the text. A screendump is released like a send,
/// but changes nothing in the guest, so matching goes on along its line;
/// a `udp_echo:` is released like a send, and changes what the guest does
/// as a send does. A `next:` must match at the start of the line after its
/// step's; when it does not, the matcher is broken and matches nothing
/// more.
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

    /// Feeds one serial line. Returns each send and screendump it released,
    /// in order.
    pub fn feed(&mut self, line: &str) -> Vec<Action<'a>> {
        let mut rest = line;
        let mut actions = Vec::new();
        // Whether a send was released, or a step matched, on this line.
        let mut sent = false;
        let mut matched = false;
        while self.broken.is_none()
            && let Some(step) = self.steps.get(self.next)
        {
            match step {
                Step::Expect(_) if sent => break,
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
                            Step::Send(_) | Step::Screendump(_) | Step::UdpEcho(_) => "",
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
                Step::Send(text) => {
                    sent = true;
                    actions.push(Action::Send(text));
                }
                Step::Screendump(name) => actions.push(Action::Screendump(name)),
                Step::UdpEcho(count) => {
                    sent = true;
                    actions.push(Action::UdpEcho(*count));
                }
            }
            self.next += 1;
        }
        actions
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
            Step::Send(_) | Step::Screendump(_) | Step::UdpEcho(_) => None,
        })
    }
}

pub struct Outcome {
    pub name: String,
    pub passed: bool,
}

/// Where `screendump:` goldens live, and what a run does with them.
pub struct Goldens {
    /// `tests/qemu/golden/`.
    pub dir: PathBuf,
    /// `--bless`: a screen that differs from its golden, or has none,
    /// becomes the golden, if its scenario passes otherwise, unless the
    /// golden is the host render's.
    pub bless: bool,
    /// QEMU's version line, kept in each image's `Source` text, so a
    /// mismatch can say when the golden came from another QEMU.
    pub qemu: String,
}

/// Runs `scenarios`, at most [`MAX_PARALLEL`] at a time, printing a report
/// for each as it finishes.
pub fn run_all(
    scenarios: &[Scenario],
    art: &Artifacts,
    dir: &Path,
    goldens: &Goldens,
) -> Vec<Outcome> {
    let next = AtomicUsize::new(0);
    let results = Mutex::new(Vec::new());
    thread::scope(|s| {
        for _ in 0..MAX_PARALLEL.min(scenarios.len()) {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(sc) = scenarios.get(i) else { break };
                    let (passed, report) = match run_one(sc, art, &dir.join(&sc.name), goldens) {
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
fn run_one(
    sc: &Scenario,
    art: &Artifacts,
    dir: &Path,
    goldens: &Goldens,
) -> Result<(bool, String)> {
    let cmdline = (!sc.cmdline.is_empty()).then_some(sc.cmdline.as_str());
    let disk = image::build_disk(dir, art, sc.kernel, cmdline)?;
    // An earlier run's screens must not pass for this one's.
    for name in sc.screendumps() {
        for file in screen_files(dir, name) {
            let _ = fs::remove_file(file);
        }
    }
    // COM1's input is QEMU's stdin: a pipe for a scenario that sends, and
    // otherwise nothing. A scenario with a screendump gets a QMP monitor,
    // and no parallel port: QEMU dumps its first console, which is the
    // display's, but the parallel port's text console if the machine has no
    // display device, and this way it fails instead.
    let sends = sc.steps.iter().any(|s| matches!(s, Step::Send(_)));
    let (mut qmp, qmp_args) = match sc.screendumps().next() {
        Some(_) => {
            let (qmp, args) = qemu::Qmp::listen()?;
            let mut args = args.to_vec();
            args.extend(["-parallel".into(), "none".into()]);
            (Some(qmp), args)
        }
        None => (None, Vec::new()),
    };
    // A NIC's forwarded port, found free: two scenarios may run at once.
    let nic = match sc.nic {
        Some(nic) => Some((nic, qemu::free_udp_port()?)),
        None => None,
    };
    let nic_args = nic.map_or_else(Vec::new, |(nic, port)| qemu::nic_args(nic, port));
    let start = Instant::now();
    let mut child = qemu::base_command(&disk)?
        .args(["-display", "none", "-serial", "stdio", "-monitor", "none"])
        .args(&qmp_args)
        .args(&nic_args)
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
    if let Some((nic, port)) = nic {
        record(format!(
            "xtask: nic {nic}, udp 127.0.0.1:{port} to the guest's port {}",
            qemu::GUEST_ECHO_PORT
        ));
    }
    // Why the `udp_echo:` exchanges failed, if any did.
    let mut udp_errors = Vec::new();
    // The first serial line with forbidden text, and the text.
    let mut forbidden: Option<(&str, String)> = None;
    let mut send_error = None;
    // The screendumps taken, each with QEMU's PPM, and any that failed.
    let mut screens: Vec<(&str, PathBuf)> = Vec::new();
    let mut screendump_errors = Vec::new();
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
                for action in released {
                    match action {
                        Action::Send(text) => {
                            // `sends` made the pipe for every scenario with
                            // a send.
                            let pipe = stdin.as_mut().unwrap();
                            if let Err(e) = pipe.write_all(text).and_then(|()| pipe.flush()) {
                                send_error.get_or_insert(format!(
                                    "could not send \"{}\": {e}",
                                    text.escape_ascii()
                                ));
                            }
                            record(format!("xtask: sent \"{}\"", text.escape_ascii()));
                        }
                        Action::Screendump(name) => {
                            // Every scenario with a screendump has a monitor.
                            // QEMU answers once the file is written, before
                            // any later step's text reaches the guest.
                            let ppm = screen_files(dir, name)[0].clone();
                            match qmp.as_mut().unwrap().screendump(&ppm, deadline) {
                                Ok(()) => {
                                    record(format!("xtask: screendump \"{name}\""));
                                    screens.push((name, ppm));
                                }
                                Err(e) => {
                                    record(format!("xtask: screendump \"{name}\" failed"));
                                    screendump_errors.push(format!("screendump {name:?}: {e}"));
                                }
                            }
                        }
                        Action::UdpEcho(count) => {
                            // The parser gave every scenario with a
                            // `udp_echo:` a NIC. The serial lines that
                            // arrive meanwhile wait in the channel.
                            let (_, port) = nic.unwrap();
                            let to = SocketAddr::from((Ipv4Addr::LOCALHOST, port));
                            match udp::exchange(to, count, udp::Limits::SCENARIO, deadline) {
                                Ok(report) => {
                                    record(format!("xtask: {}", report.line()));
                                    for p in report.problems() {
                                        record(format!("xtask: udp_echo: {p}"));
                                    }
                                    udp_errors.extend(report.failure());
                                }
                                Err(e) => {
                                    record(format!("xtask: udp_echo {count} to {to} failed: {e}"));
                                    udp_errors.push(format!("udp_echo {count}: {e}"));
                                }
                            }
                        }
                    }
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
    why.extend(udp_errors);
    why.extend(screendump_errors);
    let notes = check_screens(sc, &screens, goldens, &mut why);

    let mut report = String::new();
    if why.is_empty() {
        // 64 MiB per scenario adds up to gigabytes per run; a failure
        // keeps its image beside the log, to boot again by hand.
        fs::remove_file(&disk)?;
        writeln!(report, "PASS {} ({elapsed:.1} s)", sc.name)?;
        for note in notes {
            writeln!(report, "  {note}")?;
        }
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

/// Checks a run's screens, each a screendump's name and its PPM, against
/// their goldens, once `why` holds every other reason the run failed; adds
/// the screens' failures to `why` and returns their notes. Only a run that
/// passed everything else may bless its screens: a failed one may show a
/// panic, or the wrong moment.
fn check_screens(
    sc: &Scenario,
    screens: &[(&str, PathBuf)],
    goldens: &Goldens,
    why: &mut Vec<String>,
) -> Vec<String> {
    let bless = goldens.bless && why.is_empty();
    if goldens.bless && !bless && !screens.is_empty() {
        why.push("--bless wrote no golden, since the scenario failed".into());
    }
    let mut notes = Vec::new();
    for (name, ppm) in screens {
        match check_screen(sc, name, ppm, goldens, bless) {
            Ok(note) => notes.extend(note),
            Err(e) => why.push(e),
        }
    }
    notes
}

/// A screendump's files beside its scenario's log: QEMU's PPM, deleted once
/// read; the screen as PNG, kept; and the difference from the golden, made
/// only when they differ.
fn screen_files(dir: &Path, name: &str) -> [PathBuf; 3] {
    ["ppm", "png", "diff.png"].map(|ext| dir.join(format!("{name}.{ext}")))
}

/// Turns the screendump `name`'s PPM into a PNG beside it and compares it
/// with its golden, pixel for pixel. A missing or different golden fails
/// the check, unless `bless`, which writes the screen as the golden and
/// returns a note saying so; but `bless` leaves a golden the host drew
/// (its `Source` is [`screen::HOST_RENDER`]) as it is, and the check fails,
/// so the guest's screen is compared with an image QEMU never wrote.
fn check_screen(
    sc: &Scenario,
    name: &str,
    ppm: &Path,
    goldens: &Goldens,
    bless: bool,
) -> std::result::Result<Option<String>, String> {
    let fail = |e: String| format!("screendump {name:?}: {e}");
    let [_, png, diff] = screen_files(ppm.parent().unwrap(), name);
    let bytes = fs::read(ppm).map_err(|e| fail(format!("{}: {e}", rel(ppm))))?;
    let screen = screen::read_ppm(&bytes).map_err(|e| fail(format!("{}: {e}", rel(ppm))))?;
    let _ = fs::remove_file(ppm);
    let encoded = screen::encode_png(&screen, &[("Source", &goldens.qemu)]);
    fs::write(&png, &encoded).map_err(|e| fail(format!("{}: {e}", rel(&png))))?;

    let path = goldens.dir.join(format!("{name}.png"));
    let golden = match fs::read(&path) {
        Ok(bytes) => screen::decode_png(&bytes).map(Some),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.to_string()),
    };
    let difference = match &golden {
        Ok(Some(g)) => screen::compare(&screen, &g.image),
        _ => None,
    };
    if matches!(golden, Ok(Some(_))) && difference.is_none() {
        return Ok(None);
    }
    let host = matches!(&golden, Ok(Some(g)) if source(g) == Some(screen::HOST_RENDER));
    let bless_hint = format!("`cargo xtask test {} --bless` makes it the golden", sc.name);
    if bless && !host {
        fs::create_dir_all(&goldens.dir).map_err(|e| fail(e.to_string()))?;
        fs::write(&path, &encoded).map_err(|e| fail(format!("{}: {e}", rel(&path))))?;
        let was = match (&golden, &difference) {
            (Ok(None), _) => "new".to_string(),
            (Err(e), _) => format!("the old one was unreadable: {e}"),
            (_, Some(d)) => format!("{d}"),
            (Ok(Some(_)), None) => unreachable!("returned above"),
        };
        return Ok(Some(format!(
            "blessed {} ({was}), {} bytes",
            rel(&path),
            encoded.len()
        )));
    }
    let golden = match golden {
        Ok(Some(g)) => g,
        Ok(None) => {
            return Err(fail(format!(
                "no golden {}; the screen is in {}, and {bless_hint}",
                rel(&path),
                rel(&png)
            )));
        }
        Err(e) => {
            return Err(fail(format!(
                "golden {}: {e}; the screen is in {}, and {bless_hint}",
                rel(&path),
                rel(&png)
            )));
        }
    };
    let difference = difference.unwrap();
    let shown = match difference {
        screen::Difference::Pixels { .. } => {
            let image = screen::difference_image(&screen, &golden.image);
            let encoded = screen::encode_png(&image, &[]);
            fs::write(&diff, encoded).map_err(|e| fail(format!("{}: {e}", rel(&diff))))?;
            format!(", where they differ in magenta in {}", rel(&diff))
        }
        screen::Difference::Size(..) => String::new(),
    };
    if host {
        let left = if bless {
            "`--bless` left the golden as it is: it"
        } else {
            "the golden"
        };
        return Err(fail(format!(
            "differs from {}: {difference}; the screen is in {}{shown}; {left} is the host \
             render (Source {:?}), which only `tui_screendumps_are_the_host_render` \
             (xtask/src/hostrender.rs) writes, from term's renderer and the same bytes, so \
             the guest drew something else",
            rel(&path),
            rel(&png),
            screen::HOST_RENDER
        )));
    }
    // `Source` names QEMU, but OVMF draws on the screen too (`ovmf` is all
    // OVMF's), so an OVMF update can change a golden with QEMU the same.
    let qemu = source(&golden)
        .filter(|v| *v != goldens.qemu)
        .map(|v| format!("; the golden came from {v:?}, this is {:?}", goldens.qemu))
        .unwrap_or_default();
    Err(fail(format!(
        "differs from {}: {difference}{qemu}; a golden QEMU drew also depends on the OVMF \
         build, which its Source does not record; the screen is in {}{shown}; if it is \
         right, {bless_hint}",
        rel(&path),
        rel(&png)
    )))
}

/// A golden's `Source` text: QEMU's version, or [`screen::HOST_RENDER`].
fn source(png: &screen::Png) -> Option<&str> {
    png.text
        .iter()
        .find(|(k, _)| k == "Source")
        .map(|(_, v)| v.as_str())
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

    fn screendump(n: &str) -> Step {
        Step::Screendump(n.into())
    }

    fn udp_echo(count: u32) -> Step {
        Step::UdpEcho(count)
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
                nic: None,
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
        assert_eq!(
            m.feed("console: input next"),
            [Action::Send(b"\x143to b\r")]
        );
        assert_eq!(m.waiting_for(), Some("focus 3 (b)"));
        assert!(m.feed("[console] focus 3 (b)").is_empty());
        // Consecutive sends go together, in order.
        assert_eq!(
            m.feed("b: read \"to b\""),
            [Action::Send(b"\x142"), Action::Send(b"hi a\r")]
        );
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
        assert_eq!(m.feed("prompt; got nothing yet"), [Action::Send(b"x\r")]);
        assert_eq!(m.waiting_for(), Some("got"));
        m.feed("got x");
        assert!(m.done());
    }

    #[test]
    fn matcher_releases_trailing_sends_with_the_last_expect() {
        let steps = vec![expect("ready"), send(b"bye\r")];
        let mut m = Matcher::new(&steps);
        assert_eq!(m.feed("ready"), [Action::Send(b"bye\r")]);
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

    #[test]
    fn parses_screendumps() {
        let s = parse(
            "tui",
            "\
exit: success
expect: tui: drawn
screendump: tui-main   # tests/qemu/golden/tui-main.png
send: q
expect: entering kernel
next: root: microL4
screendump: tui_2
expect: TEST PASS
",
        )
        .unwrap();
        assert_eq!(
            s.steps,
            vec![
                expect("tui: drawn"),
                screendump("tui-main"),
                send(b"q"),
                expect("entering kernel"),
                next("root: microL4"),
                screendump("tui_2"),
                expect("TEST PASS"),
            ]
        );
        assert_eq!(s.screendumps().collect::<Vec<_>>(), ["tui-main", "tui_2"]);
        for (text, why) in [
            (
                "exit: success\nscreendump: a\nexpect: x\n",
                "2: a `screendump:` needs",
            ),
            (
                "exit: success\nexpect: x\nsend: y\nscreendump: a\n",
                "needs an `expect:` or `next:` right above it",
            ),
            (
                "exit: success\nexpect: x\nscreendump: a\nscreendump: b\n",
                "needs an `expect:` or `next:` right above it",
            ),
            (
                "exit: success\nexpect: x\nscreendump: a\nnext: y\n",
                "a `next:` needs an `expect:` or `next:`",
            ),
            (
                "exit: success\nexpect: x\nscreendump:   # none\n",
                "empty screendump",
            ),
            (
                "exit: success\nexpect: x\nscreendump: a\nexpect: y\nscreendump: a\n",
                "5: a second screendump named \"a\"",
            ),
        ] {
            let e = parse("t", text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?} gave {e:?}, wanted {why:?}");
        }
        // The name becomes a file name in tests/qemu/golden/.
        for name in ["Tui", "../tui", "tui.png", "a b", "tui/x", "é"] {
            let e = parse(
                "t",
                &format!("exit: success\nexpect: x\nscreendump: {name}\n"),
            )
            .unwrap_err()
            .to_string();
            assert!(
                e.contains("lowercase letters, digits"),
                "{name:?} gave {e:?}"
            );
        }
    }

    #[test]
    fn parses_nic_and_udp_echo() {
        let s = parse(
            "net",
            "\
cmdline: test=net
exit: success
nic: virtio-net                    # QEMU's user networking
expect: echo: listening on UDP port 7
udp_echo: 100                      # the done-when
send: \\r
expect: , 100 datagrams echoed,
next: TEST PASS
udp_echo: 0100
expect: x
udp_echo: 1000
",
        )
        .unwrap();
        assert_eq!(s.nic, Some(Nic::VirtioNet));
        assert_eq!(
            s.steps,
            vec![
                expect("echo: listening on UDP port 7"),
                udp_echo(100),
                send(b"\r"),
                expect(", 100 datagrams echoed,"),
                next("TEST PASS"),
                udp_echo(100),
                expect("x"),
                udp_echo(1000),
            ]
        );
        assert_eq!(parse("x", "exit: success\nexpect: x\n").unwrap().nic, None);
        // A `nic:` alone, anywhere, is enough; a `udp_echo:` needs one.
        let s = parse("x", "exit: success\nexpect: x\nnic: virtio-net\n").unwrap();
        assert_eq!((s.nic, s.steps.len()), (Some(Nic::VirtioNet), 1));
        let nic = "nic: virtio-net\nexit: success\n";
        for (text, why) in [
            (
                "exit: success\nexpect: x\nudp_echo: 5\nexpect: y\nudp_echo: 1\n".to_string(),
                "t.scenario:3: a `udp_echo:` needs `nic: virtio-net`",
            ),
            (
                format!("{nic}udp_echo: 5\nexpect: x\n"),
                "3: a `udp_echo:` needs an `expect:` or `next:` right above it",
            ),
            (
                format!("{nic}expect: x\nsend: y\nudp_echo: 5\n"),
                "right above it",
            ),
            (
                format!("{nic}expect: x\nscreendump: s\nudp_echo: 5\n"),
                "right above it",
            ),
            (
                format!("{nic}expect: x\nudp_echo: 5\nudp_echo: 5\n"),
                "5: a `udp_echo:` needs an `expect:` or `next:`",
            ),
            (
                format!("{nic}expect: x\nudp_echo: 5\nnext: y\n"),
                "5: a `next:` needs",
            ),
            (
                format!("{nic}expect: x\nudp_echo: 5\nscreendump: s\n"),
                "5: a `screendump:` needs",
            ),
            (
                "nic: e1000e\nexit: success\nexpect: x\n".into(),
                "1: nic must be `virtio-net`",
            ),
            (
                "nic:   # none\nexit: success\nexpect: x\n".into(),
                "nic must be `virtio-net`",
            ),
            (
                format!("{nic}nic: virtio-net\nexpect: x\n"),
                "3: a second `nic:`",
            ),
        ] {
            let e = parse("t", &text).unwrap_err().to_string();
            assert!(e.contains(why), "{text:?} gave {e:?}, wanted {why:?}");
        }
        for count in [
            "0",
            "00",
            "1001",
            "-1",
            "+5",
            "1e2",
            "0x10",
            "1,000",
            "100 datagrams",
            "4294967296",
            "  # none",
        ] {
            let e = parse("t", &format!("{nic}expect: x\nudp_echo: {count}\n"))
                .unwrap_err()
                .to_string();
            assert!(
                e.contains("4: udp_echo's count must be a number from 1 to 1000"),
                "{count:?} gave {e:?}"
            );
        }
    }

    #[test]
    fn matcher_releases_udp_echo_like_a_send() {
        let steps = vec![
            expect("listening"),
            udp_echo(100),
            send(b"\r"),
            expect("echoed"),
            expect("PASS"),
        ];
        let mut m = Matcher::new(&steps);
        assert!(m.feed("not yet").is_empty());
        // Released with the send after it, in order; the rest of the line
        // was printed before the exchange.
        assert_eq!(
            m.feed("listening; echoed"),
            [Action::UdpEcho(100), Action::Send(b"\r")]
        );
        assert_eq!(m.waiting_for(), Some("echoed"));
        assert!(m.feed("100 echoed, PASS").is_empty());
        assert!(m.done());
        // Alone, it still ends its line's matching.
        let steps = vec![expect("a"), udp_echo(3), expect("b")];
        let mut m = Matcher::new(&steps);
        assert_eq!(m.feed("a b"), [Action::UdpEcho(3)]);
        assert_eq!(m.waiting_for(), Some("b"));
        assert!(m.feed("b").is_empty());
        assert!(m.done());
        assert!(m.feed("a").is_empty(), "released once");
    }

    /// `Test-L4Vhdx.ps1 -Scenario` follows the Hyper-V checks' scenarios,
    /// which are in this format: each must parse here, so a typo shows on
    /// the host. The script ignores QEMU's `kernel:`, `exit:`, `timeout:`,
    /// `qemu_args:` and `nic:`, and reads `cmdline:` only for the guest's
    /// `net.ip=`, which a `udp_echo:` sends to.
    #[test]
    fn hyperv_scenarios_parse() {
        let all = load_dir(&crate::root().join("tools/hyperv")).unwrap();
        assert!(all.iter().any(|s| s.name == "m8-release"));
    }

    /// The lines root's `release.flood=<n>` prints (`root::flood`), from
    /// the design rather than root's code: `release: flood <i>/<n> `, `i`
    /// zero-padded to `n`'s width, then `0`-`9`, `a`-`z`, `A`-`P` rotated
    /// left by `i`.
    fn flood(n: usize) -> Vec<String> {
        let alphabet: Vec<char> = ('0'..='9').chain('a'..='z').chain('A'..='P').collect();
        assert_eq!(alphabet.len(), 52);
        let width = n.to_string().len();
        (1..=n)
            .map(|i| {
                let rotated: String = (0..52).map(|j| alphabet[(i + j) % 52]).collect();
                format!("release: flood {i:0width$}/{n} {rotated}")
            })
            .collect()
    }

    /// The M9 COM1 runs, `release_burst1` and `release_burst15` on QEMU and
    /// `m9-release-burst1` and `-burst15` on Hyper-V, which boot the same
    /// command lines, are `release`'s and `m8-release`'s steps with the cap
    /// and the flood: the command line and its `root: cmdline` line; the 32
    /// flood lines after `root: empty: slots`, the first an `expect:` and
    /// the rest `next:`; release's own line `next:` after them; the burst
    /// in uart's line; and root's line for an ignored word forbidden. On
    /// QEMU root's line for the cap is `next:` after its command line; on
    /// Hyper-V it is not expected, so a byte lost there leaves the run
    /// going.
    #[test]
    fn the_com1_runs_are_release_with_the_cap_and_the_flood() {
        let load = |dir: &str, name: &str| {
            let path = crate::root().join(dir).join(format!("{name}.scenario"));
            parse(name, &fs::read_to_string(path).unwrap()).unwrap()
        };
        let lines = flood(32);
        assert_eq!(
            lines[0],
            "release: flood 01/32 123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOP0"
        );
        let bytes: usize = lines.iter().map(|l| l.len() + 2).sum();
        assert_eq!(bytes, 2400, "with console's CR LF");
        let flood: Vec<Step> = lines
            .into_iter()
            .enumerate()
            .map(|(i, l)| if i == 0 { expect(&l) } else { next(&l) })
            .collect();
        for (dir, base, prefix, base_burst) in [
            ("tests/qemu", "release", "release_burst", ", burst 15"),
            (
                "tools/hyperv",
                "m8-release",
                "m9-release-burst",
                ", burst 1",
            ),
        ] {
            let qemu = dir == "tests/qemu";
            let base = load(dir, base);
            for cap in [1, 15] {
                let name = format!("{prefix}{cap}");
                let sc = load(dir, &name);
                let cmdline = format!("test=release uart.burst={cap} release.flood=32");
                assert_eq!(
                    (sc.cmdline.as_str(), sc.kernel, sc.exit, sc.timeout, sc.nic),
                    (
                        cmdline.as_str(),
                        Kernel::Release,
                        base.exit,
                        base.timeout,
                        None
                    ),
                    "{name}"
                );
                assert!(sc.qemu_args.is_empty() && base.qemu_args.is_empty());
                let mut want = Vec::new();
                let mut changes = 0;
                for s in &base.steps {
                    let Step::Expect(t) = s else {
                        want.push(s.clone());
                        continue;
                    };
                    changes += 1;
                    match t.as_str() {
                        "root: cmdline \"test=release\"" => {
                            want.push(expect(&format!("root: cmdline {cmdline:?}")));
                            if qemu {
                                want.push(next(&format!(
                                    "root: uart.burst={cap}: uart's burst capped at {cap}"
                                )));
                            }
                        }
                        "root: empty: slots" => {
                            want.push(s.clone());
                            want.extend(flood.iter().cloned());
                        }
                        t if t.starts_with("release: watch (priority 255), ") => want.push(next(t)),
                        t if t == base_burst => want.push(expect(&match qemu {
                            true => format!(", burst {cap}, 0 stale THREs"),
                            false => format!(", burst {cap},"),
                        })),
                        _ => {
                            changes -= 1;
                            want.push(s.clone());
                        }
                    }
                }
                assert_eq!(changes, 4, "{name}: each change found its step");
                assert_eq!(sc.steps, want, "{name}");
                let mut forbid = base.forbid.clone();
                forbid.push("ignored: not a number".into());
                assert_eq!(sc.forbid, forbid, "{name}");
            }
        }
        // CI builds the Hyper-V images with the scenarios' command lines
        // and puts the scenarios beside them.
        let ci = fs::read_to_string(crate::root().join(".github/workflows/ci.yml")).unwrap();
        for text in [
            "for burst in 1 15; do",
            "--kernel release --cmdline \"test=release uart.burst=$burst release.flood=32\"",
            "target/xtask/m9-com1/release-burst$burst/disk.vhdx",
            "cp tools/hyperv/m9-release-burst1.scenario tools/hyperv/m9-release-burst15.scenario target/xtask/m9-com1/",
            "name: microl4-vhdx-m9-com1",
        ] {
            assert!(ci.contains(text), "ci.yml has no {text:?}");
        }
    }

    /// The M9 Hyper-V check's network runs, `m9-net` and `m9-net-mnf`, are
    /// QEMU's `net` on Hyper-V: `test=net` on the selftest kernel with the
    /// note's addresses, the mnf run differing only in `netvsc.mnf=1` and
    /// the line that says how netvsc signals the host; `nic:`, so that
    /// `udp_echo:` parses; one exchange of QEMU's count followed by root's
    /// Enter, released once echo listens; the lines naming the addresses
    /// agree with the command line's `net.ip=` and `net.gw=`; QEMU's
    /// checks of net's Stats, with the script's 4 pings answered, before
    /// `TEST PASS`; and CI builds the images with these command lines and
    /// puts the scenarios beside them.
    #[test]
    fn the_network_runs_are_net_on_hyperv() {
        let load = |dir: &str, name: &str| {
            let path = crate::root().join(dir).join(format!("{name}.scenario"));
            parse(name, &fs::read_to_string(path).unwrap()).unwrap()
        };
        let qemu = load("tests/qemu", "net");
        let net = load("tools/hyperv", "m9-net");
        let mnf = load("tools/hyperv", "m9-net-mnf");
        let addresses = "net.ip=192.168.77.2/24 net.gw=192.168.77.1";
        assert_eq!(net.cmdline, format!("test=net {addresses}"));
        assert_eq!(mnf.cmdline, format!("test=net {addresses} netvsc.mnf=1"));
        let exchange = |sc: &Scenario| {
            let at: Vec<usize> = (0..sc.steps.len())
                .filter(|&i| matches!(sc.steps[i], Step::UdpEcho(_)))
                .collect();
            assert_eq!(at.len(), 1, "{}: one udp_echo:", sc.name);
            at[0]
        };
        let q = exchange(&qemu);
        // Each step of `want` among `steps`, in this order.
        let in_order = |name: &str, steps: &[Step], want: &[Step]| {
            let mut rest = steps.iter();
            for w in want {
                assert!(rest.any(|s| s == w), "{name}: no {w:?} in order");
            }
        };
        for sc in [&net, &mnf] {
            let name = sc.name.as_str();
            assert_eq!(
                (sc.kernel, sc.exit, sc.nic),
                (Kernel::Selftest, qemu.exit, qemu.nic),
                "{name}"
            );
            assert!(sc.qemu_args.is_empty(), "{name}");
            let word = |key: &str| {
                sc.cmdline
                    .split_whitespace()
                    .find_map(|w| w.strip_prefix(key))
                    .unwrap()
            };
            let (ip, gw) = (word("net.ip="), word("net.gw="));
            let i = exchange(sc);
            assert_eq!(
                sc.steps[i..i + 2],
                qemu.steps[q..q + 2],
                "{name}: QEMU's exchange and Enter"
            );
            assert_eq!(
                sc.steps[i - 1],
                expect("echo: listening on UDP port 7"),
                "{name}"
            );
            let before = [
                expect("cpu: hypervisor Hyper-V"),
                expect(&format!("root: cmdline {:?}", sc.cmdline)),
                expect("servers: vmbus (priority 145, SINT 2 IRQ"),
                expect("), netvsc (priority 140), net (priority 130); root CNode"),
                expect("vmbus: version"),
                expect(": netvsc, connection"),
                expect("netvsc: up: NVSP"),
                expect(&format!("net: up: {ip} via {gw}, MAC 00:15:5d:")),
            ];
            in_order(name, &sc.steps[..i], &before);
            // After the exchange: the gateway, which net prints only after
            // echo's line, then the Stats and the verdict.
            in_order(
                name,
                &sc.steps[i..],
                &[
                    Step::UdpEcho(100),
                    expect(&format!("net: gateway {gw} is at")),
                    expect("vmbus: stats: version"),
                    expect("netvsc: stats: NVSP"),
                    expect(", 0 broken packets,"),
                    expect("net: stats:"),
                    expect(", 4 ICMP echo requests answered,"),
                    expect(", 100 datagrams echoed,"),
                    expect(", 0 frames dropped, 0 bad entries,"),
                    expect("TEST PASS"),
                ],
            );
            // QEMU's checks of net's Stats, in QEMU's order.
            let nets: Vec<Step> = qemu.steps[q..]
                .iter()
                .skip_while(|s| **s != expect("net: stats:"))
                .filter(|s| !matches!(s, Step::Expect(t) if t.starts_with("DEBUG HALT")))
                .cloned()
                .collect();
            assert_eq!(nets.len(), 4, "net: stats: to TEST PASS on QEMU");
            in_order(name, &sc.steps[i..], &nets);
            let mut forbid = qemu.forbid.clone();
            forbid.push("USER PANIC".into());
            assert_eq!(sc.forbid, forbid, "{name}");
        }
        // The two differ in the command line's line and the signalling
        // line alone.
        assert_eq!(net.steps.len(), mnf.steps.len());
        let differ: Vec<(&Step, &Step)> = net
            .steps
            .iter()
            .zip(&mnf.steps)
            .filter(|(a, b)| a != b)
            .collect();
        assert_eq!(
            differ,
            [
                (
                    &expect(&format!("root: cmdline {:?}", net.cmdline)),
                    &expect(&format!("root: cmdline {:?}", mnf.cmdline))
                ),
                (
                    &expect("; netvsc signals the host with SignalEvent"),
                    &expect(
                        "; netvsc signals the host through monitor page 2 and the event flags (netvsc.mnf=1)"
                    )
                ),
            ]
        );
        // CI builds the images with the scenarios' command lines and puts
        // the scenarios beside them.
        let ci = fs::read_to_string(crate::root().join(".github/workflows/ci.yml")).unwrap();
        for text in [
            format!("cargo xtask image --cmdline \"{}\"", net.cmdline),
            "mv target/xtask/image/disk.vhdx target/xtask/m9-check/net/disk.vhdx".into(),
            format!("cargo xtask image --cmdline \"{}\"", mnf.cmdline),
            "mv target/xtask/image/disk.vhdx target/xtask/m9-check/net-mnf/disk.vhdx".into(),
            "cp tools/hyperv/m9-net.scenario tools/hyperv/m9-net-mnf.scenario target/xtask/m9-check/"
                .into(),
            "name: microl4-vhdx-m9-check".into(),
        ] {
            assert!(ci.contains(&text), "ci.yml has no {text:?}");
        }
        // The README runs each with its scenario.
        let readme = fs::read_to_string(crate::root().join("tools/hyperv/README.md")).unwrap();
        for text in [
            "microl4-vhdx-m9-check",
            "m9-check\\net\\disk.vhdx",
            "m9-check\\net-mnf\\disk.vhdx",
            "m9-check\\m9-net.scenario",
            "m9-check\\m9-net-mnf.scenario",
        ] {
            assert!(readme.contains(text), "README.md has no {text:?}");
        }
    }

    #[test]
    fn screendump_names_are_unique_across_scenarios() {
        let a = parse("a", "exit: success\nexpect: x\nscreendump: one\n").unwrap();
        let b = parse("b", "exit: success\nexpect: x\nscreendump: two\n").unwrap();
        let c = parse("c", "exit: success\nexpect: x\nscreendump: one\n").unwrap();
        let mut all = vec![a, b];
        check_screendump_names(&all).unwrap();
        all.push(c);
        let e = check_screendump_names(&all).unwrap_err().to_string();
        assert_eq!(
            e,
            "c.scenario and a.scenario both have a screendump named \"one\""
        );
    }

    #[test]
    fn matcher_releases_screendumps_in_step_order() {
        let steps = vec![
            expect("drawn"),
            screendump("a"),
            send(b"q"),
            expect("redrawn"),
            screendump("b"),
            expect("more"),
            expect("end"),
        ];
        let mut m = Matcher::new(&steps);
        assert!(m.feed("not yet").is_empty());
        // The screendump comes before the send it precedes.
        assert_eq!(
            m.feed("drawn; redrawn"),
            [Action::Screendump("a"), Action::Send(b"q")]
        );
        assert_eq!(m.waiting_for(), Some("redrawn"));
        // Matching goes on along the line after a screendump, unlike after
        // a send.
        assert_eq!(m.feed("redrawn more"), [Action::Screendump("b")]);
        assert_eq!(m.waiting_for(), Some("end"));
        assert!(m.feed("end").is_empty());
        assert!(m.done());
    }

    /// A directory of its own under target/xtask/unit/ for a test's files.
    fn unit_dir(name: &str) -> PathBuf {
        let dir = crate::xtask_dir().join("unit").join(name);
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// QEMU's PPM of `img`, written where its screendump would be.
    fn write_ppm(dir: &Path, name: &str, img: &screen::Image) -> PathBuf {
        let ppm = screen_files(dir, name)[0].clone();
        let mut bytes = format!("P6\n{} {}\n255\n", img.width, img.height).into_bytes();
        bytes.extend_from_slice(&img.rgb);
        fs::write(&ppm, bytes).unwrap();
        ppm
    }

    #[test]
    fn checks_screens_against_goldens() {
        let dir = unit_dir("checks_screens_against_goldens");
        let sc = parse("tui", "exit: success\nexpect: x\nscreendump: s\n").unwrap();
        let mut goldens = Goldens {
            dir: dir.join("golden"),
            bless: false,
            qemu: "QEMU emulator version 8.2.2".into(),
        };
        let golden = goldens.dir.join("s.png");
        let [_, png, diff] = screen_files(&dir, "s");
        let img = screen::Image::new(4, 3, (0..36).map(|i| i * 7).collect()).unwrap();
        let check = |goldens: &Goldens, img: &screen::Image| {
            let ppm = write_ppm(&dir, "s", img);
            let result = check_screen(&sc, "s", &ppm, goldens, goldens.bless);
            assert!(!ppm.exists(), "the PPM is deleted");
            assert_eq!(
                screen::decode_png(&fs::read(&png).unwrap()).unwrap().image,
                *img
            );
            result
        };

        // No golden: the screen is kept, and the message says how to bless it.
        let e = check(&goldens, &img).unwrap_err();
        assert!(e.starts_with("screendump \"s\": no golden "), "{e}");
        assert!(
            e.contains("unit/checks_screens_against_goldens/s.png, and `cargo xtask test tui --bless` makes it the golden"),
            "{e}"
        );
        assert!(!golden.exists());

        goldens.bless = true;
        let note = check(&goldens, &img).unwrap().unwrap();
        assert!(
            note.starts_with("blessed ") && note.contains("golden/s.png (new), "),
            "{note}"
        );
        let blessed = screen::decode_png(&fs::read(&golden).unwrap()).unwrap();
        assert_eq!(blessed.image, img);
        assert_eq!(blessed.text, [("Source".into(), goldens.qemu.clone())]);

        // The same screen matches, with or without --bless, and leaves the
        // golden alone.
        let before = fs::metadata(&golden).unwrap().modified().unwrap();
        assert_eq!(check(&goldens, &img), Ok(None));
        goldens.bless = false;
        assert_eq!(check(&goldens, &img), Ok(None));
        assert_eq!(fs::metadata(&golden).unwrap().modified().unwrap(), before);
        assert!(!diff.exists());

        // One pixel off, from the same QEMU: OVMF may have changed, which
        // Source does not record.
        let mut off = img.clone();
        off.rgb[3 * 5] ^= 1;
        let ovmf =
            "a golden QEMU drew also depends on the OVMF build, which its Source does not record";
        let e = check(&goldens, &off).unwrap_err();
        assert!(e.contains(ovmf) && !e.contains("came from"), "{e}");
        fs::remove_file(&diff).unwrap();

        // From another QEMU: a difference image beside it.
        goldens.qemu = "QEMU emulator version 9.0.0".into();
        let e = check(&goldens, &off).unwrap_err();
        assert!(
            e.contains("golden/s.png: 1 pixel differs, in x 1-1, y 1-1"),
            "{e}"
        );
        assert!(
            e.contains("the golden came from \"QEMU emulator version 8.2.2\", this is \"QEMU emulator version 9.0.0\"; ")
                && e.contains(ovmf),
            "{e}"
        );
        assert!(e.contains("where they differ in magenta in "), "{e}");
        let d = screen::decode_png(&fs::read(&diff).unwrap()).unwrap().image;
        assert_eq!(d, screen::difference_image(&off, &img));

        // Another size: no difference image.
        fs::remove_file(&diff).unwrap();
        let small = screen::Image::new(4, 2, img.rgb[..24].to_vec()).unwrap();
        let e = check(&goldens, &small).unwrap_err();
        assert!(e.contains("the screen is 4x2, the golden 4x3"), "{e}");
        assert!(!e.contains("magenta"), "{e}");
        assert!(!diff.exists());

        // --bless takes the new screen, and replaces a golden it cannot read.
        goldens.bless = true;
        let note = check(&goldens, &off).unwrap().unwrap();
        assert!(
            note.contains("(1 pixel differs, in x 1-1, y 1-1)"),
            "{note}"
        );
        assert_eq!(
            screen::decode_png(&fs::read(&golden).unwrap())
                .unwrap()
                .image,
            off
        );
        fs::write(&golden, b"not a PNG").unwrap();
        let note = check(&goldens, &img).unwrap().unwrap();
        assert!(
            note.contains("(the old one was unreadable: PNG: no PNG signature)"),
            "{note}"
        );
        goldens.bless = false;
        fs::write(&golden, b"not a PNG").unwrap();
        let e = check(&goldens, &img).unwrap_err();
        assert!(
            e.contains("golden/s.png: PNG: no PNG signature; the screen is in"),
            "{e}"
        );

        // A PPM QEMU never wrote, or a bad one.
        let ppm = screen_files(&dir, "s")[0].clone();
        let e = check_screen(&sc, "s", &ppm, &goldens, false).unwrap_err();
        assert!(
            e.starts_with("screendump \"s\": ") && e.contains("s.ppm: "),
            "{e}"
        );
        fs::write(&ppm, b"P5\n1 1\n255\n\0").unwrap();
        let e = check_screen(&sc, "s", &ppm, &goldens, false).unwrap_err();
        assert!(e.contains("not a binary PPM"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }

    /// `--bless` leaves a golden the host drew as it is, and says why;
    /// one from QEMU it still replaces.
    #[test]
    fn bless_leaves_a_host_render_golden_as_it_is() {
        let dir = unit_dir("bless_leaves_a_host_render_golden_as_it_is");
        let sc = parse("tui", "exit: success\nexpect: x\nscreendump: s\n").unwrap();
        let goldens = Goldens {
            dir: dir.join("golden"),
            bless: true,
            qemu: "QEMU emulator version 8.2.2".into(),
        };
        fs::create_dir_all(&goldens.dir).unwrap();
        let golden = goldens.dir.join("s.png");
        let [_, png, diff] = screen_files(&dir, "s");
        let img = screen::Image::new(4, 3, (0..36).map(|i| i * 7).collect()).unwrap();
        let mut off = img.clone();
        off.rgb[0] ^= 0x80;
        let host = screen::encode_png(&img, &[("Source", screen::HOST_RENDER)]);
        fs::write(&golden, &host).unwrap();
        let check = |img: &screen::Image, bless: bool| {
            check_screen(&sc, "s", &write_ppm(&dir, "s", img), &goldens, bless)
        };

        // The same screen passes, with or without --bless.
        assert_eq!(check(&img, true), Ok(None));
        assert_eq!(check(&img, false), Ok(None));

        // Another screen fails, --bless or not, and the golden stays.
        for bless in [true, false] {
            let _ = fs::remove_file(&diff);
            let e = check(&off, bless).unwrap_err();
            assert!(
                e.contains("golden/s.png: 1 pixel differs, in x 0-0, y 0-0"),
                "{e}"
            );
            assert!(
                e.contains("is the host render (Source \"microL4 host render\"), which only `tui_screendumps_are_the_host_render`"),
                "{e}"
            );
            assert_eq!(
                e.contains("`--bless` left the golden as it is"),
                bless,
                "{e}"
            );
            // It neither offers --bless nor names a QEMU version or OVMF.
            assert!(
                !e.contains("makes it the golden")
                    && !e.contains("came from")
                    && !e.contains("OVMF"),
                "{e}"
            );
            assert!(diff.exists() && png.exists(), "{e}");
            assert_eq!(fs::read(&golden).unwrap(), host);
        }

        // A golden from QEMU, such as `screendump`'s `ovmf`, still blesses.
        fs::write(
            &golden,
            screen::encode_png(&img, &[("Source", &goldens.qemu)]),
        )
        .unwrap();
        let note = check(&off, true).unwrap().unwrap();
        assert!(note.starts_with("blessed "), "{note}");
        let blessed = screen::decode_png(&fs::read(&golden).unwrap()).unwrap();
        assert_eq!(blessed.image, off);
        assert_eq!(blessed.text, [("Source".into(), goldens.qemu.clone())]);
        fs::remove_dir_all(&dir).unwrap();
    }

    /// Only a run that passed everything else blesses its screens: with
    /// another failure, `--bless` writes no golden and leaves one that
    /// differs as it is, says so, and the screen fails its check as
    /// without `--bless`; with none, it blesses.
    #[test]
    fn a_failed_run_never_blesses() {
        let dir = unit_dir("a_failed_run_never_blesses");
        let sc = parse("tui", "exit: success\nexpect: x\nscreendump: s\n").unwrap();
        let goldens = Goldens {
            dir: dir.join("golden"),
            bless: true,
            qemu: "QEMU emulator version 8.2.2".into(),
        };
        let golden = goldens.dir.join("s.png");
        let img = screen::Image::new(4, 3, (0..36).map(|i| i * 7).collect()).unwrap();
        let mut off = img.clone();
        off.rgb[0] ^= 0x80;
        let failed = "timed out after 60 s waiting for \"x\"";
        let run = |why: &mut Vec<String>| {
            check_screens(&sc, &[("s", write_ppm(&dir, "s", &img))], &goldens, why)
        };

        // No golden: none is written.
        let mut why = vec![failed.to_string()];
        assert_eq!(run(&mut why), Vec::<String>::new());
        assert!(!golden.exists());
        assert_eq!(why.len(), 3, "{why:?}");
        assert_eq!(
            why[..2],
            [failed, "--bless wrote no golden, since the scenario failed"]
        );
        assert!(
            why[2].starts_with("screendump \"s\": no golden "),
            "{why:?}"
        );

        // A golden that differs stays as it is.
        fs::create_dir_all(&goldens.dir).unwrap();
        let old = screen::encode_png(&off, &[("Source", &goldens.qemu)]);
        fs::write(&golden, &old).unwrap();
        let mut why = vec![failed.to_string()];
        assert_eq!(run(&mut why), Vec::<String>::new());
        assert_eq!(fs::read(&golden).unwrap(), old);
        assert!(
            why.len() == 3 && why[2].contains("1 pixel differs"),
            "{why:?}"
        );

        // The same run with nothing else failed blesses it.
        let mut why = Vec::new();
        let notes = run(&mut why);
        assert!(why.is_empty(), "{why:?}");
        assert!(
            notes.len() == 1 && notes[0].starts_with("blessed "),
            "{notes:?}"
        );
        let blessed = screen::decode_png(&fs::read(&golden).unwrap()).unwrap();
        assert_eq!(blessed.image, img);

        // A failed run with no screens says nothing of --bless.
        let mut why = vec![failed.to_string()];
        assert_eq!(
            check_screens(&sc, &[], &goldens, &mut why),
            Vec::<String>::new()
        );
        assert_eq!(why, [failed]);
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn repo_goldens_are_used_and_read() {
        // Each golden is a PNG xtask reads, named by a scenario's
        // screendump: one no scenario takes is stale. The host render's
        // (`hostrender.rs`) are the `tui` scenario's, as
        // `the_moments_are_the_scenarios_screendumps` checks; a golden with
        // the host render's Source is one of them, since only that test
        // writes one.
        let all = load_dir(&crate::root().join("tests/qemu")).unwrap();
        let names: Vec<&str> = all.iter().flat_map(|s| s.screendumps()).collect();
        let moments: Vec<&str> = crate::hostrender::MOMENTS.iter().map(|m| m.0).collect();
        let dir = crate::root().join("tests/qemu/golden");
        for entry in fs::read_dir(&dir).into_iter().flatten().flatten() {
            let path = entry.path();
            let file = path.file_name().unwrap().to_string_lossy();
            let name = file.strip_suffix(".png").unwrap_or_else(|| {
                panic!("{file}: tests/qemu/golden/ holds only screendump goldens, *.png")
            });
            assert!(
                names.contains(&name),
                "no scenario takes screendump {name:?}"
            );
            let png = screen::decode_png(&fs::read(&path).unwrap()).unwrap();
            if source(&png) == Some(screen::HOST_RENDER) {
                assert!(
                    moments.contains(&name),
                    "{file}: the host render draws no screendump {name:?}"
                );
            }
        }
    }
}
