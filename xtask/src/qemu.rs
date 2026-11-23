//! Booting the disk image under QEMU and OVMF, and QEMU's QMP monitor.

use std::io::{BufRead, BufReader, ErrorKind, Write};
use std::net::{Ipv4Addr, TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::time::{Duration, Instant};

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

/// A QMP connection to one QEMU, for the scenario harness's `screendump:`.
///
/// xtask listens on a loopback port the OS picks, and QEMU connects to it as
/// a client (`-qmp tcp:127.0.0.1:<port>`) while it starts, before the guest
/// runs; QEMU does not start if it cannot. A port, not a Unix socket in the
/// scenario's directory, since a socket's path is limited to 107 bytes,
/// which a worktree's `target/` can pass. The connection is accepted, and
/// the QMP handshake done, at the first command.
pub struct Qmp {
    listener: TcpListener,
    stream: Option<BufReader<TcpStream>>,
}

impl Qmp {
    /// Listens for QEMU. Returns the monitor and the QEMU arguments that
    /// connect QEMU to it.
    pub fn listen() -> Result<(Qmp, [String; 2])> {
        let listener = TcpListener::bind((Ipv4Addr::LOCALHOST, 0))?;
        let port = listener.local_addr()?.port();
        listener.set_nonblocking(true)?;
        let qmp = Qmp {
            listener,
            stream: None,
        };
        Ok((qmp, ["-qmp".into(), format!("tcp:127.0.0.1:{port}")]))
    }

    /// Writes the guest's display to `file` as a binary PPM (P6) through
    /// QMP's `screendump`, which answers once the file is written. Fails if
    /// QEMU has not answered by `deadline`.
    pub fn screendump(&mut self, file: &Path, deadline: Instant) -> Result<()> {
        let file = file
            .to_str()
            .ok_or_else(|| format!("{}: not UTF-8", file.display()))?;
        self.command(
            &format!(
                r#"{{"execute": "screendump", "arguments": {{"filename": "{}"}}}}"#,
                json_escape(file)
            ),
            deadline,
        )
    }

    /// Sends one command and waits for its answer, skipping events.
    fn command(&mut self, json: &str, deadline: Instant) -> Result<()> {
        if self.stream.is_none() {
            self.connect(deadline)?;
        }
        let stream = self.stream.as_mut().unwrap();
        stream
            .get_mut()
            .write_all(format!("{json}\n").as_bytes())
            .map_err(closed)?;
        loop {
            let line = read_line(stream, deadline)?;
            if line.starts_with(r#"{"return""#) {
                return Ok(());
            }
            if line.starts_with(r#"{"error""#) {
                // {"error": {"class": "GenericError", "desc": "..."}}
                let desc = line
                    .split_once(r#""desc": ""#)
                    .and_then(|(_, d)| d.rsplit_once(r#""}"#))
                    .map_or(line.trim(), |(d, _)| d);
                let command = json.split('"').nth(3).unwrap_or(json);
                return Err(format!("QMP {command}: {desc}").into());
            }
            // An event, such as RESET: nothing else comes unasked.
        }
    }

    /// Accepts QEMU's connection, reads its greeting and leaves capability
    /// negotiation.
    fn connect(&mut self, deadline: Instant) -> Result<()> {
        let stream = loop {
            match self.listener.accept() {
                Ok((stream, _)) => break stream,
                Err(e) if e.kind() == ErrorKind::WouldBlock && Instant::now() < deadline => {
                    std::thread::sleep(Duration::from_millis(10));
                }
                Err(e) if e.kind() == ErrorKind::WouldBlock => {
                    return Err("QEMU never connected to its QMP monitor".into());
                }
                Err(e) => return Err(e.into()),
            }
        };
        stream.set_nonblocking(false)?;
        let mut stream = BufReader::new(stream);
        let greeting = read_line(&mut stream, deadline)?;
        if !greeting.starts_with(r#"{"QMP""#) {
            return Err(format!("QMP: unexpected greeting {:?}", greeting.trim()).into());
        }
        self.stream = Some(stream);
        self.command(r#"{"execute": "qmp_capabilities"}"#, deadline)
    }
}

/// Reads one line from QMP, failing at `deadline` or once QEMU has closed
/// the connection.
fn read_line(stream: &mut BufReader<TcpStream>, deadline: Instant) -> Result<String> {
    let left = deadline.saturating_duration_since(Instant::now());
    if left.is_zero() {
        return Err("QMP: no answer before the timeout".into());
    }
    stream.get_ref().set_read_timeout(Some(left))?;
    let mut line = String::new();
    match stream.read_line(&mut line) {
        Ok(0) => Err(CLOSED.into()),
        Ok(_) => Ok(line),
        Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
            Err("QMP: no answer before the timeout".into())
        }
        Err(e) => Err(closed(e)),
    }
}

const CLOSED: &str = "QEMU closed its QMP monitor: the guest has probably exited";

/// An I/O error on the monitor, saying so plainly if QEMU has gone.
fn closed(e: std::io::Error) -> Box<dyn std::error::Error> {
    match e.kind() {
        ErrorKind::ConnectionReset | ErrorKind::ConnectionAborted | ErrorKind::BrokenPipe => {
            CLOSED.into()
        }
        _ => e.into(),
    }
}

/// `text` as the inside of a JSON string.
fn json_escape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    for c in text.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            c if u32::from(c) < 0x20 => out.push_str(&format!("\\u{:04x}", u32::from(c))),
            c => out.push(c),
        }
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::thread::{self, JoinHandle};

    const OK: &str = "{\"return\": {}}\r\n";

    /// Plays QEMU on the monitor `args` name: connects, sends `greeting`,
    /// then answers each line it reads with the next of `replies` and
    /// returns the lines, closing the connection once out of replies.
    fn fake_qemu(args: &[String; 2], greeting: &str, replies: &[&str]) -> JoinHandle<Vec<String>> {
        assert_eq!(args[0], "-qmp");
        let addr = args[1].strip_prefix("tcp:").unwrap().to_string();
        let greeting = greeting.to_string();
        let replies: Vec<String> = replies.iter().map(|r| r.to_string()).collect();
        thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(greeting.as_bytes()).unwrap();
            let mut reader = BufReader::new(stream.try_clone().unwrap());
            let mut lines = Vec::new();
            for reply in replies {
                let mut line = String::new();
                if reader.read_line(&mut line).unwrap() == 0 {
                    break;
                }
                lines.push(line);
                stream.write_all(reply.as_bytes()).unwrap();
            }
            lines
        })
    }

    const GREETING: &str = "{\"QMP\": {\"version\": {\"qemu\": {\"micro\": 2, \"minor\": 2, \"major\": 8}}, \"capabilities\": [\"oob\"]}}\r\n";

    fn soon() -> Instant {
        Instant::now() + Duration::from_secs(20)
    }

    #[test]
    fn qmp_takes_screendumps() {
        let (mut qmp, args) = Qmp::listen().unwrap();
        let event =
            "{\"timestamp\": {\"seconds\": 1, \"microseconds\": 2}, \"event\": \"RESET\"}\r\n";
        let qemu = fake_qemu(&args, GREETING, &[OK, &format!("{event}{OK}"), OK]);
        qmp.screendump(Path::new("/s/a \"b\".ppm"), soon()).unwrap();
        // The second goes over the same connection.
        qmp.screendump(Path::new("c.ppm"), soon()).unwrap();
        assert_eq!(
            qemu.join().unwrap(),
            [
                "{\"execute\": \"qmp_capabilities\"}\n",
                "{\"execute\": \"screendump\", \"arguments\": {\"filename\": \"/s/a \\\"b\\\".ppm\"}}\n",
                "{\"execute\": \"screendump\", \"arguments\": {\"filename\": \"c.ppm\"}}\n",
            ]
        );
    }

    #[test]
    fn qmp_reports_errors() {
        let (mut qmp, args) = Qmp::listen().unwrap();
        let error = "{\"error\": {\"class\": \"GenericError\", \"desc\": \"There is no console to take a screendump from\"}}\r\n";
        let qemu = fake_qemu(&args, GREETING, &[OK, error]);
        let e = qmp.screendump(Path::new("x.ppm"), soon()).unwrap_err();
        assert_eq!(
            e.to_string(),
            "QMP screendump: There is no console to take a screendump from"
        );
        qemu.join().unwrap();

        // QEMU exits: the connection closes.
        let (mut qmp, args) = Qmp::listen().unwrap();
        let qemu = fake_qemu(&args, GREETING, &[OK]);
        let e = qmp.screendump(Path::new("x.ppm"), soon()).unwrap_err();
        assert_eq!(e.to_string(), CLOSED);
        qemu.join().unwrap();

        let (mut qmp, args) = Qmp::listen().unwrap();
        let qemu = fake_qemu(&args, "hello\r\n", &[]);
        let e = qmp.screendump(Path::new("x.ppm"), soon()).unwrap_err();
        assert!(
            e.to_string().contains("unexpected greeting \"hello\""),
            "{e}"
        );
        qemu.join().unwrap();
    }

    #[test]
    fn qmp_gives_up_at_the_deadline() {
        // Nothing connects.
        let (mut qmp, _) = Qmp::listen().unwrap();
        let deadline = Instant::now() + Duration::from_millis(50);
        let e = qmp.screendump(Path::new("x.ppm"), deadline).unwrap_err();
        assert_eq!(e.to_string(), "QEMU never connected to its QMP monitor");

        // QEMU connects but never answers the screendump.
        let (mut qmp, args) = Qmp::listen().unwrap();
        let addr = args[1].strip_prefix("tcp:").unwrap().to_string();
        let (done, wait) = std::sync::mpsc::channel::<()>();
        let qemu = thread::spawn(move || {
            let mut stream = TcpStream::connect(addr).unwrap();
            stream.write_all(GREETING.as_bytes()).unwrap();
            stream.write_all(OK.as_bytes()).unwrap();
            // Holds the connection open until the test is done.
            let _ = wait.recv();
        });
        let deadline = Instant::now() + Duration::from_millis(300);
        let e = qmp.screendump(Path::new("x.ppm"), deadline).unwrap_err();
        assert_eq!(e.to_string(), "QMP: no answer before the timeout");
        assert!(Instant::now() < deadline + Duration::from_secs(5));
        done.send(()).unwrap();
        qemu.join().unwrap();
    }

    #[test]
    fn escapes_json_strings() {
        assert_eq!(json_escape("/a/b c.ppm"), "/a/b c.ppm");
        assert_eq!(
            json_escape("a\"b\\c\nd\x01é"),
            "a\\\"b\\\\c\\u000ad\\u0001é"
        );
    }
}
