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
- Record any decision that changes `docs/abi.md` as a new ADR in `docs/adr/`.
- Never tick a milestone without a fresh reviewer's sign-off.
- Update `STATUS.md` before ending the session.

## Commands

| Command | Does |
| --- | --- |
| `cargo xtask test` | host tests (the host crates, then the user crates' libraries), the kernel source check, the release kernel's disassembly check (no UART code; `llvm-objdump` from the `llvm-tools` that `tools/setup.sh` adds), then every QEMU scenario in `tests/qemu/` (`cargo xtask test hello` runs one, after the same checks) |
| `cargo xtask clippy` | clippy with `-D warnings` on every crate, each for its own target, the kernel three ways (`selftest`, no features, `debug` alone); the user crates also on the host, with their tests |
| `cargo fmt --all` | format; CI runs `cargo fmt --all --check` |
| `cargo xtask build` | build the user crates, the root image, both kernels (selftest and release) and the loader |
| `cargo xtask image [--kernel release]` | build `target/xtask/image/disk.img` and `disk.vhdx`, with `test=hello` |
| `cargo xtask run [--cmdline "..."] [--kernel release]` | boot under OVMF with COM1 on the terminal; Ctrl-A X quits |
| `cargo xtask gdb [--kernel release]` | boot paused with GDB attached |
| `cargo xtask acpidump [--from-log <file>] [--out <file>]` | dump the ACPI tables the loader reads, from a QEMU boot or a COM1 log (the Hyper-V check), for `core/tests/acpi/` |

Plain `cargo test` and `cargo build` cover only the host crates (`core`,
`model`, `xtask`); the kernel, the loader and the user crates need their own
targets and flags, which xtask passes. `--kernel release` boots the kernel
built without features (no `debug`, so no kernel output, UART code or debug
system calls); without it every command boots the selftest kernel.

## Layout

| Path | What |
| --- | --- |
| `core/` | crate `l4core`: `no_std`, `#![forbid(unsafe_code)]`, host-tested logic shared by the loader, the kernel and the user crates (handoff ABI, ELF parser, command line; from M2 the capability core; from M3 the CPU feature check, ACPI parser, page-table builder, trap decoding, APIC, HPET, Hyper-V and timer arithmetic; from M4 BootInfo, the boot plan and untyped with checks of their invariants, the Untyped and CNode invocation decoder, and the memory kernel objects may occupy; from M5 the system-call numbers and dispatch, kernel entry and exit, x87 and SSE state, registers and faults, TCBs and their invocations, the scheduler, the paging objects with their back-references and invocations, endpoint IPC with reply capabilities and fault delivery, and the root image's checks and VSpace; from M6 notifications and binding, capability transfer, `CNode_SaveCaller` and badged-send cancellation; from M7 the IRQ table with its routes, delivery and I/O APIC actions, the IRQControl, IRQHandler, IOPortControl and IOPort invocations, and the port bitmap) |
| `model/` | crate `l4model`, host only: slow, obviously correct reference models written from the design, each run beside `l4core` by a harness that compares them after every step: M2's capability model (`model.rs`, `harness.rs`; `tests/random.rs`, `tests/scenarios.rs`) and M6's IPC model (`ipc.rs`, `ipc_harness.rs`; `tests/ipc_random.rs`, `tests/ipc_scenarios.rs`) |
| `kernel/` | the kernel, `x86_64-unknown-none`, linked at `0xFFFF_FFFF_8000_0000` by `kernel/linker.ld`; xtask builds it twice, the selftest kernel (`selftest`, which implies `debug`) and the release kernel (no features), copied to `target/xtask/release-kernel/<profile>/kernel.elf` |
| `loader/` | the UEFI loader, `x86_64-unknown-uefi`, with its own minimal UEFI bindings |
| `user/` | user programs, built for `x86_64-unknown-none` by xtask and linked at `0x40_0000` by `user/link.ld`: `libsys` (`_start`, system calls, kernel invocations, capability transfer, notifications, slot and untyped allocation; from M7 the IRQ and I/O port invocations (`device`), the `uart` and `console` protocols and their clients, `print!`'s output and `exit`, and the mapping calls and segment bounds for building a VSpace); `uart` (the COM1 driver) and `console` (the console server, with line editing and focus), host-tested libraries linked into `root`, which runs each in a CSpace and VSpace of its own; and `root`, the root task the kernel embeds in `.rootimage` |
| `xtask/` | build (both kernels), image, QEMU runner, scenario harness and the release kernel's disassembly check (`disasm.rs`) |
| `tests/qemu/` | boot scenarios, one `*.scenario` file each |
| `tools/` | `setup.sh` (QEMU, OVMF, image tools, Rust targets, clippy, rustfmt and `llvm-tools`), and `hyperv/` scripts for the owner's host |
| `docs/` | `design.md` (kernel design), `abi.md` (the ABI every milestone codes against), `boot.md` (the loader), ADRs in `adr/` |

## Conventions

- Put logic that can run on the host in `core/` and test it there; it also
  runs under Miri in CI. Add a QEMU scenario only for what needs the machine.
- A scenario picks a kernel test with `cmdline: test=<name>`, which the kernel
  reads from `\cmdline.txt` on the ESP. Kernel test code builds only with the
  kernel's `selftest` feature, which xtask enables for every scenario but one
  that says `kernel: release`; a `test=` the kernel does not know, or any
  `test=` in a kernel without `selftest`, goes to the root task, which runs
  its own tests (`user/root/`). A passing test prints `TEST PASS` and exits
  with `ExitCode::Success` (a root-task test through `libsys::exit(0)`:
  `DebugHalt`, or on the release kernel `isa-debug-exit` through an IOPort);
  every boot has a 60-second limit. Besides `cmdline:`, `exit:`, `timeout:`,
  `qemu_args:` and `expect:`, a scenario can `send:` input to COM1 once the
  `expect:` lines above it match, `forbid:` text, pick `kernel: release`, and
  ask for `exit: timeout` (`docs/design.md`, "The harness").
- When a scenario fails, xtask prints the tail of COM1 and keeps the full log
  in `target/xtask/scenarios/<name>/serial.log`, beside its `disk.img`; a
  scenario that passes keeps its log but not its 64 MiB disk image.
- Unstable cargo flags live only in `.cargo/build-std.toml`, which xtask uses
  when rustup cannot install a target (see `docs/adr/0001-toolchain.md`).
