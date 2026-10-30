//! Booting the disk image under QEMU and OVMF.

use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};

use crate::{Result, output, rel};

/// What QEMU exits with when the guest writes `ExitCode::Success` (0x10) or
/// `ExitCode::Failure` (0x11) to `isa-debug-exit`: `(value << 1) | 1`.
pub const GUEST_SUCCESS: i32 = 0x10 << 1 | 1;
pub const GUEST_FAILURE: i32 = 0x11 << 1 | 1;

const QEMU: &str = "qemu-system-x86_64";
const OVMF_CANDIDATES: &[&str] = &[
    "/usr/share/ovmf/OVMF.fd",
    "/usr/share/OVMF/OVMF.fd",
    "/usr/share/qemu/OVMF.fd",
];

pub fn version() -> Result<String> {
    let out = output(Command::new(QEMU).arg("--version"))?;
    Ok(out.lines().next().unwrap_or("").to_string())
}

/// OVMF firmware: `$OVMF_FD` if set, else the first distribution path that
/// exists.
fn ovmf() -> Result<PathBuf> {
    if let Some(p) = std::env::var_os("OVMF_FD") {
        return Ok(p.into());
    }
    OVMF_CANDIDATES
        .iter()
        .map(PathBuf::from)
        .find(|p| p.is_file())
        .ok_or_else(|| "OVMF.fd not found; install ovmf, run tools/setup.sh, or set OVMF_FD".into())
}

/// The machine every boot uses: q35, 256 MiB, OVMF, the disk, and the
/// isa-debug-exit device the kernel's test exits rely on. Display, serial and
/// monitor are left to the caller.
///
/// The CPU is `max` without LA57: QEMU's default `qemu64` lacks SMEP, SMAP
/// and XSAVE, which the kernel requires (`docs/design.md`, CPU features),
/// and the loader refuses 5-level paging. A later `-cpu` argument, such as a
/// scenario's `qemu_args:`, overrides it.
pub fn base_command(disk: &Path) -> Result<Command> {
    let mut cmd = Command::new(QEMU);
    cmd.args(["-machine", "q35", "-cpu", "max,la57=off", "-m", "256M"])
        .arg("-no-reboot")
        .arg("-bios")
        .arg(ovmf()?)
        .arg("-drive")
        .arg(format!("format=raw,file={}", disk.display()))
        .args(["-device", "isa-debug-exit,iobase=0xf4,iosize=0x04"]);
    Ok(cmd)
}

/// Describes how the guest ended, from QEMU's exit status.
pub fn describe_exit(code: Option<i32>) -> String {
    match code {
        Some(GUEST_SUCCESS) => "guest reported success".into(),
        Some(GUEST_FAILURE) => "guest reported failure".into(),
        Some(0) => "QEMU exited without a guest report (shutdown, or a triple fault)".into(),
        Some(c) => format!("QEMU exited with status {c}"),
        None => "QEMU was killed by a signal".into(),
    }
}

/// `cargo xtask run`: COM1 and the QEMU monitor share the terminal.
pub fn run_interactive(disk: &Path, extra: &[String]) -> Result<ExitCode> {
    println!("booting {}; Ctrl-A X quits QEMU", rel(disk));
    let status = base_command(disk)?.arg("-nographic").args(extra).status()?;
    println!("\n{}", describe_exit(status.code()));
    Ok(if status.code() == Some(GUEST_SUCCESS) {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// `cargo xtask gdb`: QEMU waits for GDB on port 1234 before the firmware
/// runs; COM1 goes to a log file so GDB keeps the terminal.
pub fn run_gdb(disk: &Path, kernel: &Path, dir: &Path) -> Result<ExitCode> {
    let serial_log = dir.join("serial.log");
    let mut qemu = base_command(disk)?
        .args(["-s", "-S", "-display", "none", "-monitor", "none"])
        .arg("-serial")
        .arg(format!("file:{}", serial_log.display()))
        .stdin(Stdio::null())
        .spawn()?;
    println!("COM1 is logged to {}", rel(&serial_log));
    println!("the kernel runs at its link address; try `hbreak kernel::kmain` then `continue`");
    let status = Command::new("gdb")
        .arg("-q")
        .arg(kernel)
        .args(["-ex", "target remote localhost:1234"])
        .status();
    let _ = qemu.kill();
    let _ = qemu.wait();
    status?;
    Ok(ExitCode::SUCCESS)
}
