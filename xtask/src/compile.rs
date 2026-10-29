//! Building the kernel and the loader for their bare-metal targets.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::{Result, cargo, root, run, target_dir};

/// The only target the kernel may be built for. It keeps the compiler off
/// SSE registers; the kernel's own `compile_error!` checks back this up.
pub const KERNEL_TARGET: &str = "x86_64-unknown-none";
pub const LOADER_TARGET: &str = "x86_64-unknown-uefi";

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Profile {
    Dev,
    Release,
}

impl Profile {
    fn dir(self) -> &'static str {
        match self {
            Profile::Dev => "debug",
            Profile::Release => "release",
        }
    }
}

pub struct Artifacts {
    pub kernel: PathBuf,
    pub loader: PathBuf,
}

pub fn build(profile: Profile) -> Result<Artifacts> {
    // M5 adds the user crates here, packed into the boot image the kernel
    // embeds, before the kernel itself is built.
    cargo_for("build", KERNEL_TARGET, "kernel", profile, &[])?;
    cargo_for("build", LOADER_TARGET, "loader", profile, &[])?;
    let out = |target: &str, file: &str| target_dir().join(target).join(profile.dir()).join(file);
    Ok(Artifacts {
        kernel: out(KERNEL_TARGET, "kernel"),
        loader: out(LOADER_TARGET, "loader.efi"),
    })
}

pub fn clippy() -> Result<()> {
    run(Command::new(cargo())
        .args([
            "clippy",
            "--package",
            "l4core",
            "--package",
            "xtask",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ])
        .current_dir(root()))?;
    cargo_for(
        "clippy",
        KERNEL_TARGET,
        "kernel",
        Profile::Dev,
        &["--", "-D", "warnings"],
    )?;
    cargo_for(
        "clippy",
        LOADER_TARGET,
        "loader",
        Profile::Dev,
        &["--", "-D", "warnings"],
    )
}

/// Runs a cargo subcommand for one package on a bare-metal target.
fn cargo_for(
    subcommand: &str,
    target: &str,
    package: &str,
    profile: Profile,
    extra: &[&str],
) -> Result<()> {
    if package == "kernel" && target != KERNEL_TARGET {
        return Err(format!(
            "refusing to build the kernel for {target}; it must be {KERNEL_TARGET}"
        )
        .into());
    }
    let mut cmd = Command::new(cargo());
    cmd.current_dir(root());
    if !has_prebuilt_std(target)? {
        // Fall back to building core from source; see .cargo/build-std.toml.
        cmd.arg("--config")
            .arg(root().join(".cargo/build-std.toml"));
        cmd.env("RUSTC_BOOTSTRAP", "1");
    }
    cmd.args([subcommand, "--package", package, "--target", target]);
    if profile == Profile::Release {
        cmd.arg("--release");
    }
    cmd.args(extra);
    run(&mut cmd)
}

/// Whether rustup installed the standard library for `target`.
/// `XTASK_FORCE_BUILD_STD=1` pretends it did not, to test the fallback.
fn has_prebuilt_std(target: &str) -> Result<bool> {
    if std::env::var_os("XTASK_FORCE_BUILD_STD").is_some_and(|v| v == "1") {
        return Ok(false);
    }
    let sysroot = crate::output(Command::new("rustc").args(["--print", "sysroot"]))?;
    let lib = Path::new(sysroot.trim())
        .join("lib/rustlib")
        .join(target)
        .join("lib");
    let Ok(entries) = std::fs::read_dir(&lib) else {
        return Ok(false);
    };
    Ok(entries
        .flatten()
        .any(|e| e.file_name().to_string_lossy().starts_with("libcore-")))
}
