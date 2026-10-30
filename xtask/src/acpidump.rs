//! `cargo xtask acpidump`: ACPI tables for the parser's host tests.
//!
//! The loader prints every ACPI table it can reach to COM1 when the kernel
//! command line has the word `acpidump` (`l4core::acpi::dump`). This command
//! boots QEMU with `acpidump test=hello`, or reads a COM1 log someone made
//! elsewhere (`--from-log`, the owner's Hyper-V run), checks the dump is
//! whole, runs the parser on it, and writes the dump lines to a file for
//! `core/tests/acpi/`.

use std::fmt::Write as _;
use std::io::{BufRead, BufReader};
use std::path::{Path, PathBuf};
use std::process::{ExitCode, Stdio};
use std::sync::mpsc::{self, RecvTimeoutError};
use std::time::{Duration, Instant};
use std::{fs, thread};

use l4core::acpi::dump::{DumpMemory, MARKER};
use l4core::acpi::{self, Platform};

use crate::{Result, compile, image, qemu, rel, scenario, xtask_dir};

/// The command line the dump boot uses.
const CMDLINE: &str = "acpidump test=hello";
/// The boot limit every QEMU run has.
const TIMEOUT: Duration = Duration::from_secs(60);

/// Runs the command: the dump from `from_log`, or from a QEMU boot with
/// `qemu_args` added, written to `out` (default
/// `target/xtask/acpidump/acpi.dump`).
pub fn run(
    profile: compile::Profile,
    from_log: Option<&Path>,
    out: Option<&Path>,
    qemu_args: &[String],
) -> Result<ExitCode> {
    let (log, source) = match from_log {
        Some(path) => {
            if !qemu_args.is_empty() {
                return Err("--from-log takes no QEMU arguments".into());
            }
            let bytes = fs::read(path).map_err(|e| format!("{}: {e}", path.display()))?;
            (
                String::from_utf8_lossy(&bytes).into_owned(),
                format!("a COM1 log, {}", file_name(path)),
            )
        }
        None => boot(profile, qemu_args)?,
    };
    let mem = DumpMemory::parse(&log)?;
    mem.check()
        .map_err(|e| format!("the dump is not whole: {e}"))?;
    let rsdp = mem.rsdp().unwrap_or(0);
    let parsed = acpi::parse(&mem, rsdp);

    let out = out.map_or_else(default_out, Path::to_path_buf);
    if let Some(dir) = out.parent() {
        fs::create_dir_all(dir)?;
    }
    let mut text = String::new();
    writeln!(
        text,
        "# ACPI tables dumped by the microL4 loader from {source}."
    )?;
    writeln!(
        text,
        "# Made by `cargo xtask acpidump`; core/src/acpi/tests.rs reads it."
    )?;
    for line in mem.lines() {
        writeln!(text, "{line}")?;
    }
    fs::write(&out, text)?;
    println!(
        "{}: {} tables, {} bytes, RSDP at {rsdp:#x}",
        rel(&out),
        mem.tables().len(),
        mem.bytes()
    );
    match parsed {
        Ok(p) => {
            print_platform(&p);
            Ok(ExitCode::SUCCESS)
        }
        Err(e) => {
            // Still written: a dump the parser rejects is what a test needs.
            println!("the parser rejects it: {e}");
            Ok(ExitCode::FAILURE)
        }
    }
}

/// `--from-log`'s file name, without the directory it happens to be in.
fn file_name(path: &Path) -> String {
    path.file_name().map_or_else(
        || path.display().to_string(),
        |n| n.to_string_lossy().into(),
    )
}

/// Boots QEMU with the dump command line and returns COM1 up to the dump's
/// `end` line, and a description of the machine.
fn boot(profile: compile::Profile, qemu_args: &[String]) -> Result<(String, String)> {
    let art = compile::build(profile)?;
    let dir = xtask_dir().join("acpidump");
    let disk = image::build_disk(&dir, &art, Some(CMDLINE))?;
    let version = qemu::version()?;
    let mut child = qemu::base_command(&disk)?
        .args(["-display", "none", "-serial", "stdio", "-monitor", "none"])
        .args(qemu_args)
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;
    let (tx, rx) = mpsc::channel();
    let mut stdout = BufReader::new(child.stdout.take().unwrap());
    thread::spawn(move || {
        let mut buf = Vec::new();
        while matches!(stdout.read_until(b'\n', &mut buf), Ok(n) if n > 0) {
            if tx.send(scenario::clean(&buf)).is_err() {
                break;
            }
            buf.clear();
        }
    });

    let deadline = Instant::now() + TIMEOUT;
    let mut log = String::new();
    let mut done = false;
    while !done {
        let left = deadline.saturating_duration_since(Instant::now());
        match rx.recv_timeout(left) {
            Ok(line) => {
                done = line.contains(&format!("{MARKER}end "));
                log.push_str(&line);
                log.push('\n');
            }
            Err(RecvTimeoutError::Timeout | RecvTimeoutError::Disconnected) => break,
        }
    }
    // The dump is all that is wanted; the kernel need not finish.
    let _ = child.kill();
    let _ = child.wait();
    let serial = dir.join("serial.log");
    fs::write(&serial, &log)?;
    if !done {
        return Err(format!(
            "no complete dump within {} s; COM1 is in {}",
            TIMEOUT.as_secs(),
            rel(&serial)
        )
        .into());
    }
    let args = if qemu_args.is_empty() {
        String::new()
    } else {
        format!(" {}", qemu_args.join(" "))
    };
    Ok((
        log,
        format!("{version}: xtask's machine (q35, OVMF, -cpu max,la57=off, 256 MiB){args}"),
    ))
}

/// What the parser makes of the dump, as the kernel's boot log will say it.
fn print_platform(p: &Platform) {
    println!(
        "{} at {:#x}, RSDP revision {}",
        p.root.signature, p.root.address, p.revision
    );
    for t in p.tables.iter() {
        println!("  {} at {:#x}, {} bytes", t.signature, t.address, t.length);
    }
    println!(
        "MADT flags {:#x}, LAPIC {:#x}, {} processors",
        p.madt.flags, p.madt.lapic, p.madt.processors
    );
    for (i, io) in p.ioapics.iter().enumerate() {
        println!(
            "I/O APIC {i}: ID {} at {:#x}, GSI base {}",
            io.id, io.address, io.gsi_base
        );
    }
    for irq in 0..16 {
        match p.isa_route(irq) {
            Some(r) => println!("ISA IRQ {irq} -> {r}"),
            None => println!("ISA IRQ {irq}: no route"),
        }
    }
    match p.hpet {
        Some(h) => println!("HPET at {:#x}", h.base),
        None => println!("no HPET"),
    }
    for e in p.ecam.iter() {
        println!(
            "ECAM segment {}, buses {}-{}, at {:#x}",
            e.segment, e.start_bus, e.end_bus, e.base
        );
    }
    for w in p.warnings.iter() {
        println!("warning: {w}");
    }
}

/// Where the dump goes without `--out`.
fn default_out() -> PathBuf {
    xtask_dir().join("acpidump/acpi.dump")
}
