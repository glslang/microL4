# microL4

A small L4-family microkernel written from scratch in Rust. It boots under
QEMU's q35 machine with OVMF in cloud sessions, and as a Hyper-V Generation 2
guest on the owner's machine.

## Rules

- Read `PLAN.md` and `STATUS.md` first. `STATUS.md` is the only memory between
  sessions.
- Run `tools/setup.sh` once at the start of every session.
- Run QEMU only through `cargo xtask`, never by hand.
- Keep `unsafe` inside `kernel/src/arch/`, each block with a `SAFETY:`
  comment. The kernel's `#![deny(unsafe_code)]` and
  `clippy::undocumented_unsafe_blocks` enforce this.
- Record any decision that changes `docs/abi.md` (until M1, the handoff in
  `docs/boot.md`) as a new ADR in `docs/adr/`.
- Never tick a milestone without a fresh reviewer's sign-off.
- Update `STATUS.md` before ending the session.

## Commands

| Command | Does |
| --- | --- |
| `cargo xtask test` | host tests, then every QEMU scenario in `tests/qemu/` (`cargo xtask test hello` runs one) |
| `cargo xtask clippy` | clippy with `-D warnings` on every crate, each for its own target |
| `cargo fmt --all` | format; CI runs `cargo fmt --all --check` |
| `cargo xtask build` | build the kernel and the loader |
| `cargo xtask image` | build `target/xtask/image/disk.img` and `disk.vhdx`, with `test=hello` |
| `cargo xtask run [--cmdline "..."]` | boot under OVMF with COM1 on the terminal; Ctrl-A X quits |
| `cargo xtask gdb` | boot paused with GDB attached |

Plain `cargo test` and `cargo build` cover only the host crates (`core`,
`xtask`); the kernel and loader need their own targets, which xtask passes.

## Layout

| Path | What |
| --- | --- |
| `core/` | crate `l4core`: `no_std`, `#![forbid(unsafe_code)]`, host-tested logic shared by the loader and the kernel (handoff ABI, ELF parser, command line; from M2 the capability core) |
| `kernel/` | the kernel, `x86_64-unknown-none`, linked at `0xFFFF_FFFF_8000_0000` by `kernel/linker.ld` |
| `loader/` | the UEFI loader, `x86_64-unknown-uefi`, with its own minimal UEFI bindings |
| `xtask/` | build, image, QEMU runner and scenario harness |
| `tests/qemu/` | boot scenarios, one `*.scenario` file each |
| `tools/` | `setup.sh`, and `hyperv/` scripts for the owner's host |
| `docs/` | design notes (`boot.md`), ADRs in `adr/` |

## Conventions

- Put logic that can run on the host in `core/` and test it there; it also
  runs under Miri in CI. Add a QEMU scenario only for what needs the machine.
- A scenario picks a kernel test with `cmdline: test=<name>`, which the kernel
  reads from `\cmdline.txt` on the ESP. A passing test prints `TEST PASS` and
  exits with `ExitCode::Success`; every boot has a 60-second limit.
- When a scenario fails, xtask prints the tail of COM1 and keeps the full log
  in `target/xtask/scenarios/<name>/serial.log`.
- Unstable cargo flags live only in `.cargo/build-std.toml`, which xtask uses
  when rustup cannot install a target (see `docs/adr/0001-toolchain.md`).
