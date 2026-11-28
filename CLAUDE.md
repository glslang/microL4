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
| `cargo xtask test <scenario> --bless` | as above, and a screendump that differs from its golden in `tests/qemu/golden/`, or has none, becomes the golden if its scenario passed otherwise; a golden the host drew (`Source` `microL4 host render`) is left as it is and the scenario fails |
| `MICROL4_BLESS=1 cargo xtask test` | as `cargo xtask test`, and the host tests rewrite each failing golden from the result: term's and tui's text goldens (`user/term/golden/`, `user/tui/golden/`), net's golden frames (`user/net/golden/`, from M9) and the `tui` scenario's host-rendered screendumps (`tui_screendumps_are_the_host_render`, in `tests/qemu/golden/` and `tools/hyperv/golden/`); review the diff |
| `cargo xtask clippy` | clippy with `-D warnings` on every crate, each for its own target, the kernel three ways (`selftest`, no features, `debug` alone); the user crates also on the host, with their tests (`hvmock`, host only, on the host alone) |
| `cargo fmt --all` | format; CI runs `cargo fmt --all --check` |
| `cargo xtask build` | build the user crates, the root image, both kernels (selftest and release) and the loader |
| `cargo xtask image [--kernel release]` | build `target/xtask/image/disk.img` and `disk.vhdx`, with `test=hello` and Spleen's licence as `\licenses\spleen.txt` |
| `cargo xtask run [--cmdline "..."] [--kernel release] [--nic]` | boot under OVMF with COM1 on the terminal; Ctrl-A X quits. `--nic` (M9; `run` only) adds a `virtio-net-pci` on QEMU's user networking with UDP `127.0.0.1:5555` forwarded to the guest's port 7, for `nc -u 127.0.0.1 5555` against `--cmdline "test=net"` |
| `cargo xtask gdb [--kernel release]` | boot paused with GDB attached |
| `cargo xtask acpidump [--from-log <file>] [--out <file>]` | dump the ACPI tables the loader reads, from a QEMU boot or a COM1 log (the Hyper-V check), for `core/tests/acpi/` |

Plain `cargo test` and `cargo build` cover only the host crates (`core`,
`model`, `xtask`; xtask's tests also build `fb`, `term` and `tui` for the
host, for the host render); the kernel, the loader and the user crates need
their own targets and flags, which xtask passes. `--kernel release` boots the kernel
built without features (no `debug`, so no kernel output, UART code or debug
system calls); without it every command boots the selftest kernel.

## Layout

| Path | What |
| --- | --- |
| `core/` | crate `l4core`: `no_std`, `#![forbid(unsafe_code)]`, host-tested logic shared by the loader, the kernel and the user crates (handoff ABI, ELF parser, command line; from M2 the capability core; from M3 the CPU feature check, ACPI parser, page-table builder, trap decoding, APIC, HPET, Hyper-V and timer arithmetic; from M4 BootInfo, the boot plan and untyped with checks of their invariants, the Untyped and CNode invocation decoder, and the memory kernel objects may occupy; from M5 the system-call numbers and dispatch, kernel entry and exit, x87 and SSE state, registers and faults, TCBs and their invocations, the scheduler, the paging objects with their back-references and invocations, endpoint IPC with reply capabilities and fault delivery, and the root image's checks and VSpace; from M6 notifications and binding, capability transfer, `CNode_SaveCaller` and badged-send cancellation; from M7 the IRQ table with its routes, delivery and I/O APIC actions, the IRQControl, IRQHandler, IOPortControl and IOPort invocations, and the port bitmap; from M9 the guest OS ID, the hypercall MSR's set-up and read-back, the SynIC's MSR values, the hypercall input values and the `PostMessage` block, the Hypervisor capability with its four invocations and Mint's narrowing (`hyperv::invocation`), MSI and SINT sources with `GetMSI` and `GetSint`, `Frame_GetAddress`, and the HPET's FSB route) |
| `model/` | crate `l4model`, host only: slow, obviously correct reference models written from the design, each run beside `l4core` by a harness that compares them after every step: M2's capability model (`model.rs`, `harness.rs`; `tests/random.rs`, `tests/scenarios.rs`) and M6's IPC model (`ipc.rs`, `ipc_harness.rs`; `tests/ipc_random.rs`, `tests/ipc_scenarios.rs`) |
| `kernel/` | the kernel, `x86_64-unknown-none`, linked at `0xFFFF_FFFF_8000_0000` by `kernel/linker.ld`; xtask builds it twice, the selftest kernel (`selftest`, which implies `debug`) and the release kernel (no features), copied to `target/xtask/release-kernel/<profile>/kernel.elf` |
| `loader/` | the UEFI loader, `x86_64-unknown-uefi`, with its own minimal UEFI bindings |
| `user/` | user programs, built for `x86_64-unknown-none` by xtask and linked at `0x40_0000` by `user/link.ld`: `libsys` (`_start`, system calls, kernel invocations, capability transfer, notifications, slot and untyped allocation; from M7 the IRQ and I/O port invocations (`device`), the `uart` and `console` protocols and their clients, `print!`'s output and `exit`, and the mapping calls and segment bounds for building a VSpace; from M8 the `term` protocol and its client, console's `ReadRaw`, `store_fence`, the uncached and write-combining attributes, `unmap_table` and retyping a named untyped); `uart` (the COM1 driver), `console` (the console server, with line editing and focus, and from M8 its raw client 4), `fb` (from M8: the GOP framebuffer's geometry, pixel formats, frame plan and write-only surface; a library, not a server), `term` (from M8: the terminal emulator, a VT parser after Paul Williams, the screen model, Spleen's and generated 8×16 glyphs, the damage renderer and the term server; golden screens in `user/term/golden/`) and `tui` (from M8: the demo app; goldens in `user/tui/golden/`), host-tested libraries linked into `root`, which runs `uart`, `console`, `term` and `tui` each in a CSpace and VSpace of its own, the framebuffer mapped write-combining in term's alone; from M9 libsys's `mem` (device windows and shared memory: `Mmio`, `Shared`, the `Regs` and `Memory` traits, the host's `Ram`), `frames` (the frame queues a network driver shares with `net`), `hyperv` (the Hypervisor invocations), `objects::Carver` (device frames at chosen addresses, by splitting device untyped), `irq_control_get_msi`, `irq_control_get_sint`, `frame_get_address` and `proto`'s M9 labels and stats; and the crates `pci` (enumeration through ECAM, BAR sizing, MSI-X and the virtio-net plan), `virtio-net` (the QEMU driver, with a model device and network in its tests), `vmbus` (VMBus contact, offers, GPADLs and netvsc's channel), `netvsc` (NVSP and RNDIS over the channel), `net` (the stack and the UDP echo service; golden frames in `user/net/golden/`; its `src/tests/{peer,preempt,owners}.rs`, the end-to-end tests' scripted peer, preemption points and owners' check, which `virtio-net`'s and `netvsc`'s tests include by path, `net` a dev-dependency of both) and `hvmock` (host only: the mock VMBus host and its netvsc device, a dev-dependency of `vmbus` and `netvsc`), host-tested libraries too, of which root runs `virtio-net` and `net` on QEMU, with ECAM, MSI-X and the BARs set up itself, and `vmbus`, `netvsc` and `net` on Hyper-V, with SINT 2, the SynIC frames and slot 12's Hypervisor capability (root's image carries all four drivers on both); and `root`, the root task the kernel embeds in `.rootimage` |
| `xtask/` | build (both kernels), image (with the licences the image carries), QEMU runner (with QMP for screendumps and, from M9, the `virtio-net-pci` NIC on a free forwarded UDP port), scenario harness, `udp_echo:`'s datagram exchange (`udp.rs`, M9), screen images (`screen.rs`: QEMU's PPM, PNG goldens, the exact comparison), the screendump goldens' host render (`hostrender.rs`, a test) and the release kernel's disassembly check (`disasm.rs`, with M9's hypercall-page rule) |
| `tests/qemu/` | boot scenarios, one `*.scenario` file each, and `golden/`, the screendump goldens |
| `tools/` | `setup.sh` (QEMU, OVMF, image tools, Rust targets, clippy, rustfmt and `llvm-tools`), `spleen.py` (regenerates term's Spleen glyphs, `user/term/src/font/spleen.rs`, and `LICENSE-spleen` from a pinned tag), `net-goldens/` (from M9: the independent model that writes `user/net/golden/`, `gen.py` then `extra.py`), and `hyperv/` scripts for the owner's host, with the M8 check's scenarios (`m8-*.scenario`, which `Test-L4Vhdx.ps1 -Scenario` follows) and its 1024x768 goldens (`golden/`), and from M9 the COM1 runs' scenarios (`m9-release-burst1.scenario`, `m9-release-burst15.scenario`) and the network runs' (`m9-net.scenario`, `m9-net-mnf.scenario`), the raw COM1 reader (`Read-L4Com1.ps1 -Raw`), the network scripts (`New-L4Switch.ps1`, the internal switch; `Send-L4Udp.ps1`, the host's pings and datagrams; `Set-L4Cmdline.ps1`, a VHDX's command line) and `Test-L4Vhdx.ps1`'s `udp_echo:` |
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
  `expect:` lines above it match, `forbid:` text, require with `next:` that
  the line right after an `expect:`'s starts with a text, pick `kernel:
  release`, ask for `exit: timeout`, and take a `screendump:` of the screen
  once the line above it matches, which must equal
  `tests/qemu/golden/<name>.png` pixel for pixel; a mismatch keeps the
  screen and a difference image beside the log (`docs/design.md`, "The
  harness"). From M9 `nic: virtio-net` gives the machine a
  `virtio-net-pci` with a free loopback UDP port forwarded to the guest's
  port 7, and `udp_echo: <n>`, right after an `expect:` or `next:`, sends
  `n` datagrams through it once that line matches and fails the scenario
  unless each comes back once, unaltered (`docs/design.md`, "The harness:
  `nic:` and `udp_echo:`"). `cargo xtask test <scenario> --bless` writes a golden only QEMU
  can draw, such as `screendump`'s `ovmf`. The `tui` scenario's goldens are
  the host's render of the same bytes, which only the xtask host test
  `tui_screendumps_are_the_host_render` writes (`MICROL4_BLESS=1 cargo test
  -p xtask tui_screendumps`), and `--bless` refuses them, so the guest is
  never compared with its own capture.
- When a scenario fails, xtask prints the tail of COM1 and keeps the full log
  in `target/xtask/scenarios/<name>/serial.log`, beside its `disk.img`; a
  scenario that passes keeps its log but not its 64 MiB disk image.
- Unstable cargo flags live only in `.cargo/build-std.toml`, which xtask uses
  when rustup cannot install a target (see `docs/adr/0001-toolchain.md`).
