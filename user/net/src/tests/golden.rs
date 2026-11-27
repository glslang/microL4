//! The golden frames (`docs/design.md`, "`net`", "Tests"): every case
//! under `user/net/golden/<group>/*.golden` runs on a fresh stack, and
//! each step must send exactly its `out:` frames, in order, and print its
//! `event:` lines, and the case must end with its `stats:` line.
//! `MICROL4_BLESS=1` rewrites each failing case from the stack's output,
//! keeping its comments, `config:` and steps as written.
//!
//! A case is a `config:` line, `<ip>/<n> via <gw>, MAC <mac>`, then
//! steps: `start:` runs `Stack::start`, `in: <hex>` gives the stack one
//! frame, `tx: <n>` leaves `n` transmit buffers free from there on (`tx:
//! any` for no limit, the default). After `start:` and each `in:` come the
//! `out: <hex>` frames sent and the `event: <line>` lines printed, and the
//! case ends with `stats:`, every counter that is not 0 as `name=value`
//! in the counters' order. Hex is pairs of digits with spaces anywhere
//! between pairs; a line that starts with a space continues the frame
//! above; `#` starts a comment to the end of the line.

use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::string::{String, ToString};
use std::vec::Vec;
use std::{format, fs, println};

use super::Wire;
use super::wire::{describe, layout, unhex};
use crate::{Config, Ip, Mac, Stack, Stats};

/// The note's groups and the cases each must have at least.
pub const GROUPS: &[(&str, usize)] = &[
    ("ethernet", 10),
    ("arp", 20),
    ("ipv4", 20),
    ("icmp", 14),
    ("udp", 12),
    ("echo", 16),
    ("checksum", 6),
    ("held", 8),
];

#[derive(Clone, Debug, PartialEq, Eq)]
enum Action {
    Start,
    In(Vec<u8>),
    Tx(Option<usize>),
}

/// A step and what it must do.
#[derive(Clone, Debug)]
struct Step {
    /// Its lines as written, comments before it included.
    head: Vec<String>,
    action: Action,
    outs: Vec<Vec<u8>>,
    events: Vec<String>,
}

/// A case as read from its file.
struct Case {
    path: PathBuf,
    name: String,
    /// The comments and the `config:` line before the first step.
    head: Vec<String>,
    config: Config,
    mac: Mac,
    steps: Vec<Step>,
    /// Comments after the last step.
    tail: Vec<String>,
    /// `None` for a case not yet blessed.
    stats: Option<String>,
}

/// What a case's run gave: each step's frames and lines, and the stats.
struct Run {
    outs: Vec<Vec<Vec<u8>>>,
    events: Vec<Vec<String>>,
    stats: String,
}

/// The value of a line, its comment stripped.
fn value(line: &str) -> &str {
    line.split('#').next().unwrap_or("").trim()
}

fn parse_config(v: &str) -> Result<(Config, Mac), String> {
    let bad = || format!("`config: {v}` is not `<ip>/<n> via <gw>, MAC <mac>`");
    let (net, mac) = v.split_once(", MAC ").ok_or_else(bad)?;
    let (ip, gw) = net.split_once(" via ").ok_or_else(bad)?;
    let cmdline = format!("net.ip={ip} net.gw={gw}");
    let config = Config::parse(&cmdline, None).map_err(|e| format!("{v}: {e}"))?;
    let bytes = unhex(&mac.replace(':', ""))?;
    let mac: [u8; 6] = bytes.try_into().map_err(|_| bad())?;
    Ok((config, Mac(mac)))
}

/// The lines of the file as logical lines: a line that starts with a
/// space or a tab joins the one above, each kept as written.
fn logical(text: &str) -> Result<Vec<Vec<&str>>, String> {
    let mut out: Vec<Vec<&str>> = Vec::new();
    for (n, line) in text.lines().enumerate() {
        if line.starts_with([' ', '\t']) && !line.trim().is_empty() {
            let Some(last) = out.last_mut() else {
                return Err(format!("line {}: a continuation with nothing above", n + 1));
            };
            last.push(line);
        } else {
            out.push(vec_of(line));
        }
    }
    Ok(out)
}

fn vec_of(line: &str) -> Vec<&str> {
    let mut v = Vec::with_capacity(4);
    v.push(line);
    v
}

/// The hex of a logical line: its first line's value after `key:` and
/// each continuation's value.
fn joined(lines: &[&str], key: &str) -> Result<Vec<u8>, String> {
    let mut text = String::from(value(&lines[0][key.len()..]));
    for l in &lines[1..] {
        text.push(' ');
        text.push_str(value(l));
    }
    unhex(&text)
}

fn parse(path: &Path, name: &str, text: &str) -> Result<Case, String> {
    let mut head = Vec::new();
    let mut pending: Vec<String> = Vec::new();
    let mut config = None;
    let mut steps: Vec<Step> = Vec::new();
    let mut stats = None;
    for lines in logical(text)? {
        let first = lines[0];
        let v = value(first);
        let raw = || lines.iter().map(|l| l.to_string()).collect::<Vec<_>>();
        if v.is_empty() {
            pending.extend(raw());
            continue;
        }
        if stats.is_some() {
            return Err(format!("`{first}` after `stats:`"));
        }
        let step = |action, pending: &mut Vec<String>| {
            let mut head = core::mem::take(pending);
            head.extend(raw());
            Step {
                head,
                action,
                outs: Vec::new(),
                events: Vec::new(),
            }
        };
        if let Some(c) = v.strip_prefix("config:") {
            if config.is_some() || !steps.is_empty() {
                return Err("`config:` must come once, before the steps".into());
            }
            config = Some(parse_config(c.trim())?);
            head.append(&mut pending);
            head.extend(raw());
        } else if v == "start:" {
            steps.push(step(Action::Start, &mut pending));
        } else if v.starts_with("in:") {
            let frame = joined(&lines, "in:")?;
            steps.push(step(Action::In(frame), &mut pending));
        } else if let Some(n) = v.strip_prefix("tx:") {
            let n = match n.trim() {
                "any" => None,
                n => Some(n.parse().map_err(|_| format!("`tx: {n}` is not a count"))?),
            };
            steps.push(step(Action::Tx(n), &mut pending));
        } else if v.starts_with("out:") {
            let frame = joined(&lines, "out:")?;
            let s = steps
                .last_mut()
                .filter(|s| !matches!(s.action, Action::Tx(_)))
                .ok_or("`out:` must follow `start:` or `in:`")?;
            s.outs.push(frame);
        } else if let Some(e) = v.strip_prefix("event:") {
            let s = steps
                .last_mut()
                .filter(|s| !matches!(s.action, Action::Tx(_)))
                .ok_or("`event:` must follow `start:` or `in:`")?;
            s.events.push(e.trim().to_string());
        } else if let Some(s) = v.strip_prefix("stats:") {
            stats = Some(s.trim().to_string());
        } else {
            return Err(format!("unknown line `{first}`"));
        }
    }
    let (config, mac) = config.ok_or("no `config:`")?;
    Ok(Case {
        path: path.to_path_buf(),
        name: name.to_string(),
        head,
        config,
        mac,
        steps,
        tail: pending,
        stats,
    })
}

/// The `stats:` value: every counter that is not 0.
pub fn stats_line(s: &Stats) -> String {
    let words = s.to_words();
    let parts: Vec<String> = Stats::NAMES
        .iter()
        .zip(words)
        .filter(|(_, n)| *n != 0)
        .map(|(name, n)| format!("{name}={n}"))
        .collect();
    parts.join(" ")
}

fn run(case: &Case) -> Run {
    let mut stack = Stack::new(case.config, case.mac);
    let mut wire = Wire::new();
    let mut outs = Vec::new();
    let mut events = Vec::new();
    for step in &case.steps {
        match &step.action {
            Action::Start => stack.start(&mut wire),
            Action::In(frame) => stack.input(frame, &mut wire),
            Action::Tx(n) => wire.free = *n,
        }
        outs.push(wire.take());
        let mut lines = Vec::new();
        while let Some(e) = stack.event() {
            lines.push(e.to_string());
        }
        events.push(lines);
    }
    Run {
        outs,
        events,
        stats: stats_line(stack.stats()),
    }
}

/// A frame's `out:` lines.
pub fn out_lines(frame: &[u8]) -> Vec<String> {
    let mut lines = layout(frame);
    lines[0] = format!("out: {}  # {}", lines[0], describe(frame));
    for l in &mut lines[1..] {
        *l = format!("     {l}");
    }
    lines
}

/// Rewrites `case`'s file from `result`.
fn bless(case: &Case, result: &Run) {
    let mut text = String::new();
    let mut push = |l: &str| {
        text.push_str(l);
        text.push('\n');
    };
    for l in &case.head {
        push(l);
    }
    for (i, step) in case.steps.iter().enumerate() {
        for l in &step.head {
            push(l);
        }
        for f in &result.outs[i] {
            for l in out_lines(f) {
                push(&l);
            }
        }
        for e in &result.events[i] {
            push(&format!("event: {e}"));
        }
    }
    for l in &case.tail {
        push(l);
    }
    push(&format!("stats: {}", result.stats));
    fs::write(&case.path, text).unwrap();
    println!("blessed {}", case.name);
}

/// Where a run differs from the case; empty when it passes.
fn compare(case: &Case, result: &Run) -> String {
    let mut report = String::new();
    for (i, step) in case.steps.iter().enumerate() {
        let what = step
            .head
            .iter()
            .find(|l| !value(l).is_empty())
            .map_or("", String::as_str)
            .trim();
        if step.outs != result.outs[i] {
            let _ = writeln!(report, "  step {} `{what}`: frames differ", i + 1);
            let _ = writeln!(report, "    expected:");
            for f in &step.outs {
                let _ = writeln!(report, "      {}", describe(f));
            }
            let _ = writeln!(report, "    sent:");
            for f in &result.outs[i] {
                for l in out_lines(f) {
                    let _ = writeln!(report, "      {l}");
                }
            }
        }
        if step.events != result.events[i] {
            let _ = writeln!(
                report,
                "  step {} `{what}`: events {:?}, expected {:?}",
                i + 1,
                result.events[i],
                step.events
            );
        }
    }
    match &case.stats {
        Some(s) if *s == result.stats => {}
        Some(s) => {
            let _ = writeln!(report, "  stats: {}\n  expected: {s}", result.stats);
        }
        None => {
            let _ = writeln!(report, "  no `stats:`: not yet blessed");
        }
    }
    report
}

fn load_group(group: &str) -> Vec<Result<Case, String>> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("golden")
        .join(group);
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap_or_else(|e| panic!("{}: {e}", dir.display()))
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "golden"))
        .collect();
    paths.sort();
    paths
        .iter()
        .map(|p| {
            let name = format!("{group}/{}", p.file_name().unwrap().to_string_lossy());
            let text = fs::read_to_string(p).map_err(|e| format!("{name}: {e}"))?;
            parse(p, &name, &text).map_err(|e| format!("{name}: {e}"))
        })
        .collect()
}

/// Runs every case of `group`; panics listing each failure.
fn check_group(group: &str) {
    let bless_on = std::env::var_os("MICROL4_BLESS").is_some_and(|v| v == "1");
    let min = GROUPS
        .iter()
        .find(|(g, _)| *g == group)
        .map_or(0, |&(_, n)| n);
    let mut failures = Vec::new();
    let mut blessed = 0;
    let cases = load_group(group);
    let count = cases.len();
    for case in cases {
        let case = match case {
            Ok(c) => c,
            Err(e) => {
                failures.push(e);
                continue;
            }
        };
        let result = run(&case);
        let report = compare(&case, &result);
        if report.is_empty() {
            continue;
        }
        if bless_on {
            bless(&case, &result);
            blessed += 1;
        } else {
            failures.push(format!("{}:\n{report}", case.name));
        }
    }
    if count < min {
        failures.push(format!(
            "group {group} has {count} cases; it needs at least {min}"
        ));
    }
    if blessed > 0 {
        println!("{group}: blessed {blessed} cases; review each diff");
    }
    assert!(
        failures.is_empty(),
        "{} of {count} cases in {group} fail:\n\n{}",
        failures.len(),
        failures.join("\n")
    );
}

/// Every directory under `golden/` is a group a test runs.
#[test]
#[cfg_attr(miri, ignore = "Miri cannot read files")]
fn every_group_directory_is_tested() {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("golden");
    for e in fs::read_dir(&dir).unwrap().flatten() {
        let name = e.file_name().to_string_lossy().to_string();
        assert!(
            GROUPS.iter().any(|(g, _)| *g == name),
            "golden/{name} is not a group the tests run"
        );
    }
}

/// The layout reads back as the frame it wrote, for frames of every kind
/// and some cut short.
#[test]
fn the_layout_reads_back() {
    use super::wire::{V4, arp, eth, icmp_echo, udp};
    let us = [10, 0, 2, 15];
    let gw = [10, 0, 2, 2];
    let m = [0x52, 0x54, 0, 0x12, 0x34, 0x56];
    let frames = [
        eth([0xFF; 6], m, 0x0806, &arp(1, m, us, [0; 6], gw)),
        eth(
            m,
            m,
            0x0800,
            &V4::new(gw, us, 17).packet(&udp(gw, us, 1, 7, b"abc", true)),
        ),
        eth(
            m,
            m,
            0x0800,
            &V4::new(gw, us, 1).packet(&icmp_echo(8, 1, 2, &[7; 40])),
        ),
        eth(m, m, 0x86DD, &[1, 2, 3]),
        std::vec![1, 2, 3],
        std::vec![],
    ];
    for f in &frames {
        for cut in 0..=f.len() {
            let lines = out_lines(&f[..cut]);
            let mut text = String::new();
            for l in &lines {
                text.push_str(value(l.strip_prefix("out:").unwrap_or(l)));
                text.push(' ');
            }
            assert_eq!(unhex(&text).unwrap(), &f[..cut], "{lines:?}");
        }
    }
}

macro_rules! groups {
    ($($name:ident),* $(,)?) => {
        $(
            #[test]
            #[cfg_attr(miri, ignore = "Miri cannot read files")]
            fn $name() {
                check_group(stringify!($name));
            }
        )*
    };
}

groups!(ethernet, arp, ipv4, icmp, udp, echo, checksum, held);

#[test]
fn a_config_line_reads() {
    let (c, m) = parse_config("10.0.2.15/24 via 10.0.2.2, MAC 52:54:00:12:34:56").unwrap();
    assert_eq!(c, Config::QEMU);
    assert_eq!(m, Mac([0x52, 0x54, 0, 0x12, 0x34, 0x56]));
    assert_eq!(c.address(), Ip::new(10, 0, 2, 15));
    assert!(parse_config("10.0.2.15/24 via 10.0.2.2").is_err());
}
