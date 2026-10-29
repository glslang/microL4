# microL4

A small L4-family microkernel written from scratch in Rust. It boots on QEMU's
x86_64 q35 machine under OVMF and as a Hyper-V Generation 2 guest. The kernel
API is shaped like seL4's (capabilities over untyped memory, synchronous IPC,
notifications), but it is not seL4-compatible.

[`PLAN.md`](PLAN.md) is the project plan, with eleven milestones.
[`STATUS.md`](STATUS.md) says where things stand.

## Quick start

On Ubuntu 24.04:

```bash
tools/setup.sh
```

```bash
cargo xtask test
```

`tools/setup.sh` installs QEMU, OVMF and the disk-image tools, and adds the
`x86_64-unknown-none` and `x86_64-unknown-uefi` targets. `cargo xtask test`
runs the host tests, then boots each scenario in `tests/qemu/` and checks its
serial output. To boot the kernel interactively:

```bash
cargo xtask run
```

`cargo xtask help` lists every command.

## Layout

- `loader/` is a UEFI application that loads `kernel.elf`, builds the first
  page tables and hands over to the kernel ([`docs/boot.md`](docs/boot.md);
  the handoff itself is in [`docs/abi.md`](docs/abi.md)).
- `kernel/` is the kernel, running in ring 0 in the upper half.
- `core/` holds logic shared by both and tested on the host.
- `xtask/` builds disk images, runs QEMU and checks scenarios.
- `tools/hyperv/` boots a CI-built VHDX on Hyper-V.

## Licence

MIT; see [`LICENSE`](LICENSE).
