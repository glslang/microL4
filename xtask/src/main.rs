//! `cargo xtask`: the only supported way to build, boot and test microL4.
//!
//! Run `cargo xtask help` for the commands.

mod acpidump;
mod compile;
mod image;
mod qemu;
mod scenario;
mod source;

use std::error::Error;
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode};

pub type Result<T> = std::result::Result<T, Box<dyn Error>>;

const USAGE: &str = "\
usage: cargo xtask <command> [options]

commands:
  build             build the kernel and the loader
  image             build target/xtask/image/disk.img and disk.vhdx
  run               boot the image under OVMF, COM1 on stdio (Ctrl-A X quits)
  test [names...]   host tests, kernel source checks, then every QEMU
                    scenario in tests/qemu/ (or only the named ones)
  clippy            clippy with -D warnings on every crate and target
  gdb               boot under QEMU paused, with GDB attached
  acpidump [-- <qemu args>]
                    boot QEMU with `acpidump test=hello` and write the ACPI
                    tables the loader dumps (default
                    target/xtask/acpidump/acpi.dump); with --from-log, read
                    them from a COM1 log instead
  help              this text

options:
  --release         use the release profile
  --cmdline <text>  kernel command line for image, run and gdb
                    (image defaults to test=hello, run and gdb to none)
  --out <file>      where acpidump writes the dump
  --from-log <file> the COM1 log acpidump reads instead of booting QEMU
";

struct Options {
    command: String,
    release: bool,
    cmdline: Option<String>,
    out: Option<PathBuf>,
    from_log: Option<PathBuf>,
    rest: Vec<String>,
}

fn parse_args() -> Result<Options> {
    let mut args = std::env::args().skip(1);
    let mut opts = Options {
        command: args.next().unwrap_or_else(|| "help".into()),
        release: false,
        cmdline: None,
        out: None,
        from_log: None,
        rest: Vec::new(),
    };
    while let Some(a) = args.next() {
        match a.as_str() {
            "--release" => opts.release = true,
            "--cmdline" => opts.cmdline = Some(args.next().ok_or("--cmdline needs a value")?),
            "--out" => opts.out = Some(args.next().ok_or("--out needs a file")?.into()),
            "--from-log" => {
                opts.from_log = Some(args.next().ok_or("--from-log needs a file")?.into())
            }
            "--" => opts.rest.extend(args.by_ref()),
            s if s.starts_with("--") => return Err(format!("unknown option {s}").into()),
            _ => opts.rest.push(a),
        }
    }
    Ok(opts)
}

fn main() -> ExitCode {
    match parse_args().and_then(|opts| dispatch(&opts)) {
        Ok(code) => code,
        Err(e) => {
            eprintln!("xtask: error: {e}");
            ExitCode::FAILURE
        }
    }
}

fn dispatch(opts: &Options) -> Result<ExitCode> {
    let profile = if opts.release {
        compile::Profile::Release
    } else {
        compile::Profile::Dev
    };
    match opts.command.as_str() {
        "build" => {
            let art = compile::build(profile)?;
            println!("kernel: {}\nloader: {}", rel(&art.kernel), rel(&art.loader));
        }
        "image" => {
            let art = compile::build(profile)?;
            let dir = xtask_dir().join("image");
            let cmdline = opts.cmdline.as_deref().unwrap_or("test=hello");
            let disk = image::build_disk(&dir, &art, Some(cmdline))?;
            let vhdx = image::to_vhdx(&disk)?;
            println!(
                "disk: {}\nvhdx: {}\ncmdline: {cmdline:?}",
                rel(&disk),
                rel(&vhdx)
            );
        }
        "run" => {
            let art = compile::build(profile)?;
            let disk = image::build_disk(&xtask_dir().join("run"), &art, opts.cmdline.as_deref())?;
            return qemu::run_interactive(&disk, &opts.rest);
        }
        "gdb" => {
            let art = compile::build(profile)?;
            let disk = image::build_disk(&xtask_dir().join("gdb"), &art, opts.cmdline.as_deref())?;
            return qemu::run_gdb(&disk, &art.kernel, &xtask_dir().join("gdb"));
        }
        "test" => return test(profile, &opts.rest),
        "acpidump" => {
            return acpidump::run(
                profile,
                opts.from_log.as_deref(),
                opts.out.as_deref(),
                &opts.rest,
            );
        }
        "clippy" => compile::clippy()?,
        "help" | "-h" | "--help" => print!("{USAGE}"),
        other => return Err(format!("unknown command {other:?}\n\n{USAGE}").into()),
    }
    Ok(ExitCode::SUCCESS)
}

fn test(profile: compile::Profile, only: &[String]) -> Result<ExitCode> {
    // Host tests first: they are fast and catch most mistakes.
    run(Command::new(cargo()).arg("test").current_dir(root()))?;
    source::check_kernel(&root().join("kernel"))?;

    let mut scenarios = scenario::load_dir(&root().join("tests/qemu"))?;
    if !only.is_empty() {
        for name in only {
            if !scenarios.iter().any(|s| &s.name == name) {
                return Err(format!("no scenario named {name:?} in tests/qemu").into());
            }
        }
        scenarios.retain(|s| only.contains(&s.name));
    }
    let art = compile::build(profile)?;
    println!("{}", qemu::version()?);
    let results = scenario::run_all(&scenarios, &art, &xtask_dir().join("scenarios"));
    let failed: Vec<&str> = results
        .iter()
        .filter(|r| !r.passed)
        .map(|r| r.name.as_str())
        .collect();
    println!(
        "\nscenarios: {} passed, {} failed",
        results.len() - failed.len(),
        failed.len()
    );
    if !failed.is_empty() {
        println!("failed: {}", failed.join(", "));
    }
    Ok(if failed.is_empty() {
        ExitCode::SUCCESS
    } else {
        ExitCode::FAILURE
    })
}

/// The workspace root.
pub fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .unwrap()
        .to_path_buf()
}

/// Cargo's target directory.
pub fn target_dir() -> PathBuf {
    std::env::var_os("CARGO_TARGET_DIR")
        .map(PathBuf::from)
        .unwrap_or_else(|| root().join("target"))
}

/// Where xtask keeps images, scenario runs and logs.
pub fn xtask_dir() -> PathBuf {
    target_dir().join("xtask")
}

/// The cargo that invoked us, so every build uses the same toolchain.
pub fn cargo() -> String {
    std::env::var("CARGO").unwrap_or_else(|_| "cargo".into())
}

/// `path` relative to the workspace root, for messages.
pub fn rel(path: &Path) -> String {
    path.strip_prefix(root())
        .unwrap_or(path)
        .display()
        .to_string()
}

/// Runs a command to completion, failing if it does not exit 0.
pub fn run(cmd: &mut Command) -> Result<()> {
    let status = cmd
        .status()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    if !status.success() {
        return Err(format!("{:?} failed: {status}", cmd.get_program()).into());
    }
    Ok(())
}

/// Runs a command and returns its stdout, including stderr in the error if
/// it fails.
pub fn output(cmd: &mut Command) -> Result<String> {
    let out = cmd
        .output()
        .map_err(|e| format!("cannot run {:?}: {e}", cmd.get_program()))?;
    if !out.status.success() {
        return Err(format!(
            "{:?} failed: {}\n{}{}",
            cmd.get_program(),
            out.status,
            String::from_utf8_lossy(&out.stdout),
            String::from_utf8_lossy(&out.stderr)
        )
        .into());
    }
    Ok(String::from_utf8_lossy(&out.stdout).into_owned())
}
