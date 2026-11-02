//! Building the user crates, the kernel and the loader for their bare-metal
//! targets.
//!
//! The user crates come first: `user/root` is built, stripped and checked
//! into `target/xtask/rootimage/<profile>/root.elf` (`rootimage`), and the
//! kernel embeds that file in `.rootimage` through `include_bytes!` of the
//! path in `MICROL4_ROOT_IMAGE`. Then the kernel, whose image xtask checks
//! against `KERNEL_IMAGE_MAX`, and the loader.

use std::ffi::OsString;
use std::path::{Path, PathBuf};
use std::process::Command;

use l4core::elf::Elf;
use l4core::vspace::KERNEL_IMAGE_MAX;

use crate::rootimage::{self, Packed};
use crate::{Result, cargo, root, run, target_dir, xtask_dir};

/// The only target the kernel may be built for. It keeps the compiler off
/// SSE registers; the kernel's own `compile_error!` checks back this up.
pub const KERNEL_TARGET: &str = "x86_64-unknown-none";
pub const LOADER_TARGET: &str = "x86_64-unknown-uefi";
/// User programs build for the kernel's target, so they use no SSE either
/// (`docs/design.md`, "The kernel never touches SSE; the user target").
pub const USER_TARGET: &str = "x86_64-unknown-none";
/// The kernel features every image is built with: the self-tests, which
/// scenarios pick with `test=`, and with them `debug` (ADR 0021). M7 adds a
/// build without `debug`.
pub const KERNEL_FEATURES: &str = "selftest";
/// The user crates, linted by `cargo xtask clippy`.
pub const USER_CRATES: &[&str] = &["libsys", "root"];
/// The variable whose path the kernel's `include_bytes!` embeds.
pub const ROOT_IMAGE_ENV: &str = "MICROL4_ROOT_IMAGE";
/// Flags for the user crates, in place of `.cargo/config.toml`'s for the
/// target: static, not position-independent, and the small code model
/// instead of the target's default `kernel`, since they are linked at
/// `0x40_0000` (`user/link.ld`), not in the top 2 GiB.
const USER_RUSTFLAGS: &[&str] = &["-C", "relocation-model=static", "-C", "code-model=small"];

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
    /// The root task as linked, with symbols, for a debugger.
    pub root: PathBuf,
    /// The stripped root ELF the kernel embeds.
    pub root_image: PathBuf,
    /// What the embedded image holds.
    pub packed: Packed,
}

pub fn build(profile: Profile) -> Result<Artifacts> {
    let (root, root_image, packed) = build_root(profile)?;
    let mut kernel = cargo_for("build", KERNEL_TARGET, &["kernel"], profile)?;
    kernel
        .args(["--features", KERNEL_FEATURES])
        .env(ROOT_IMAGE_ENV, &root_image);
    run(&mut kernel)?;
    run(&mut cargo_for(
        "build",
        LOADER_TARGET,
        &["loader"],
        profile,
    )?)?;
    let out = |target: &str, file: &str| target_dir().join(target).join(profile.dir()).join(file);
    let kernel = out(KERNEL_TARGET, "kernel");
    check_kernel_size(&kernel, &packed)?;
    Ok(Artifacts {
        kernel,
        loader: out(LOADER_TARGET, "loader.efi"),
        root,
        root_image,
        packed,
    })
}

/// Builds the user crates and packs `root`: its ELF as linked, the image
/// the kernel embeds, and what that image holds.
fn build_root(profile: Profile) -> Result<(PathBuf, PathBuf, Packed)> {
    run(&mut user_cargo("build", &["root"], profile)?)?;
    let elf = user_target_dir()
        .join(USER_TARGET)
        .join(profile.dir())
        .join("root");
    let image = xtask_dir()
        .join("rootimage")
        .join(profile.dir())
        .join("root.elf");
    let packed = rootimage::pack(&elf, &image)?;
    Ok((elf, image, packed))
}

/// Refuses a kernel whose image, `.rootimage` included, is over
/// `KERNEL_IMAGE_MAX`. The linker script asserts the same; this says why.
fn check_kernel_size(kernel: &Path, root: &Packed) -> Result<()> {
    let file = std::fs::read(kernel)?;
    let elf = Elf::parse(&file).map_err(|e| format!("{}: {e}", kernel.display()))?;
    let (start, end) = elf.bounds();
    if end - start > KERNEL_IMAGE_MAX {
        return Err(format!(
            "the kernel image is {} KiB with a {} KiB root image, over KERNEL_IMAGE_MAX ({} MiB)",
            (end - start) >> 10,
            root.bytes >> 10,
            KERNEL_IMAGE_MAX >> 20
        )
        .into());
    }
    Ok(())
}

pub fn clippy() -> Result<()> {
    run(Command::new(cargo())
        .args([
            "clippy",
            "--package",
            "l4core",
            "--package",
            "l4model",
            "--package",
            "xtask",
            "--all-targets",
            "--",
            "-D",
            "warnings",
        ])
        .current_dir(root()))?;
    // The user crates' libraries and their tests on the host, where those
    // tests run (`cargo xtask test`).
    run(Command::new(cargo())
        .args([
            "clippy",
            "--package",
            "libsys",
            "--package",
            "root",
            "--lib",
            "--tests",
            "--",
            "-D",
            "warnings",
        ])
        .current_dir(root()))?;
    // The user crates for their target, then root's image, which the kernel
    // needs to compile.
    run(user_cargo("clippy", USER_CRATES, Profile::Dev)?.args(["--", "-D", "warnings"]))?;
    let (_, root_image, _) = build_root(Profile::Dev)?;
    // The kernel twice, so that every `cfg` compiles both ways: as images
    // are built, and with no features at all.
    for features in [
        &["--features", KERNEL_FEATURES][..],
        &["--no-default-features"],
    ] {
        run(
            cargo_for("clippy", KERNEL_TARGET, &["kernel"], Profile::Dev)?
                .args(features)
                .args(["--", "-D", "warnings"])
                .env(ROOT_IMAGE_ENV, &root_image),
        )?;
    }
    run(
        cargo_for("clippy", LOADER_TARGET, &["loader"], Profile::Dev)?
            .args(["--", "-D", "warnings"]),
    )
}

/// The user crates' own target directory: their flags differ from the
/// kernel's for the same target, so they do not share build output.
fn user_target_dir() -> PathBuf {
    target_dir().join("user")
}

/// A cargo command for user crates: their target, target directory and
/// flags.
fn user_cargo(subcommand: &str, packages: &[&str], profile: Profile) -> Result<Command> {
    let mut cmd = cargo_for(subcommand, USER_TARGET, packages, profile)?;
    cmd.arg("--target-dir").arg(user_target_dir());
    let flags: OsString = USER_RUSTFLAGS.join("\x1f").into();
    cmd.env("CARGO_ENCODED_RUSTFLAGS", flags);
    Ok(cmd)
}

/// A cargo subcommand for packages on a bare-metal target.
fn cargo_for(
    subcommand: &str,
    target: &str,
    packages: &[&str],
    profile: Profile,
) -> Result<Command> {
    if packages.contains(&"kernel") && target != KERNEL_TARGET {
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
    cmd.args([subcommand, "--target", target]);
    for p in packages {
        cmd.args(["--package", p]);
    }
    if profile == Profile::Release {
        cmd.arg("--release");
    }
    Ok(cmd)
}

/// Whether rustup installed the standard library for `target`.
/// `XTASK_FORCE_BUILD_STD=1` pretends it did not, to test the fallback.
fn has_prebuilt_std(target: &str) -> Result<bool> {
    if std::env::var_os("XTASK_FORCE_BUILD_STD").is_some_and(|v| v == "1") {
        return Ok(false);
    }
    // Ask the compiler cargo will use: `$RUSTC` if set, else the rustup
    // proxy, which honours the toolchain cargo was invoked with.
    let rustc = std::env::var_os("RUSTC").unwrap_or_else(|| "rustc".into());
    let sysroot = crate::output(Command::new(rustc).args(["--print", "sysroot"]))?;
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
