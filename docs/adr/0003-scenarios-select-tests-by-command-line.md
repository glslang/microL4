# 0003: Scenarios select kernel tests through a command line on the ESP

Status: accepted, M0 (2026-10-29)

## Context

The `hello` and deliberate-panic scenarios need the same kernel to behave
differently. The options were a Cargo feature per scenario, which builds a
kernel per scenario, or a run-time switch.

## Decision

The loader passes `\cmdline.txt` from the EFI system partition to the kernel
in the handoff. A scenario file names a command line such as `test=panic`, and
xtask writes it into that scenario's disk image. One kernel binary serves every
scenario, and `cargo xtask image` uses `test=hello`, so the Hyper-V check runs
exactly the QEMU `hello` scenario.

## Consequences

- A disk image is built per scenario. It takes well under a second.
- From M5 the root task will read the same command line from BootInfo to pick
  user-space tests.
- Test-only code paths ship in every kernel. They are small, and in-kernel
  self-tests from M4 go behind a feature flag as the plan says.
