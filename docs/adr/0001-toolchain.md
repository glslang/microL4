# 0001: Stable Rust with prebuilt targets, build-std as the fallback

Status: accepted, M0 (2026-10-29)

## Context

The plan was written when the cloud proxy blocked `static.rust-lang.org`, so
`rustup target add` failed and every build had to use `build-std` with library
source from GitHub and `RUSTC_BOOTSTRAP=1`. In this session `rustup target
add x86_64-unknown-none x86_64-unknown-uefi` worked. Either can happen in a
future session, and CI on GitHub's runners can always install targets.

## Decision

- Use the stable toolchain that is installed; do not pin a version in
  `rust-toolchain.toml`, because a pin would need a download that may be
  blocked.
- `tools/setup.sh` tries `rustup target add`. If that fails, it clones the
  library source for the installed `rustc` version from GitHub, as the plan
  describes.
- `cargo xtask` checks the sysroot for each target. If its prebuilt `core` is
  missing, it passes `--config .cargo/build-std.toml` and sets
  `RUSTC_BOOTSTRAP=1` for that build only. That file holds every unstable flag.
- `XTASK_FORCE_BUILD_STD=1` forces the fallback, to test it. It was tested on
  2026-10-29 with rustc 1.97.0: both scenarios pass.
- The workspace uses edition 2024.

## Consequences

- Normal builds need no unstable features. The kernel uses only stable
  `global_asm!` with `sym` and `const` operands.
- Miri needs nightly. CI installs it for the Miri job only; sessions without
  nightly skip Miri locally.
- If a future `rustc` changes the `build-std` flags, only
  `.cargo/build-std.toml` changes.
