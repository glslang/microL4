# 0021: All UART code and the debug system calls exist only with the kernel's `debug` feature, and `DebugHalt` takes an exit status

Status: accepted, M1 (2026-10-29); M7 status note at the end

## Context

PLAN.md's Debug row asks for `putchar` to COM1, a TCB dump and a halt system
call, "compiled in only with a `debug` feature", and M7's done-when says the
release kernel contains no UART code. M0's kernel prints through `kprintln!`
unconditionally, and scenarios rely on its `KERNEL PANIC` and `TEST PASS`
lines. seL4 splits its debug calls between `CONFIG_PRINTING` and
`CONFIG_DEBUG_BUILD`, and its `DebugHalt` takes no argument
(`libsel4/include/api/syscall.xml`, `handleUnknownSyscall` in
`src/api/syscall.c`). From M5, tests run in user space and need to end a QEMU
run with a pass or fail status.

## Decision

- One Cargo feature, `debug`, gates `arch/x86_64/serial.rs`, `kprintln!`'s
  writer, the panic message, the boot summary, the report of an unhandled
  fault, the TCB debug list and system calls 16 to 18. Without it
  `kprintln!` type-checks its arguments and emits no code, and a panic exits
  with failure silently.
- `DebugPutChar` (16) writes the low byte of `rdi`; `DebugHalt` (17) takes a
  status in `rdi` and ends the run through `arch::exit`, success for 0;
  `DebugDumpScheduler` (18) prints every TCB. None takes a capability.
- Numbers 19 to 31 stay reserved, with no `DebugNameThread`; the debug TCB
  list's two link words live in the TCB's debug-only tail.
- xtask builds with `debug` for scenarios, `run`, `gdb` and `image`. From M7
  `cargo xtask test` also builds without it, disassembles that kernel and
  fails on any `in` or `out` outside the IOPort path in `io.rs`, any
  immediate in `0x3F8` to `0x3FF` moved into `dx`, `edx` or `rdx`, and any
  `serial` symbol, and boots it in a
  scenario whose output comes from the `uart` server.

## Consequences

- A release kernel touches COM1 only in IOPort invocations by `uart`, and
  numbers 16 to 31 raise `UnknownSyscall` there exactly as any unknown number
  does.
- In a debug kernel any thread can print and stop the machine; debug kernels
  make no security claim.
- A release kernel's panic is silent; the harness sees only the failure exit
  status.
- A release-kernel test ends the run through an IOPort capability for
  `isa-debug-exit`, which the root task makes from IOPortControl.
- The TCB keeps one size in both builds: the debug list lives in its
  debug-only tail.

## M7 status (2026-11-22)

M7 built the release kernel and its check as decided, with two points made
precise:

- "Outside the IOPort path in `io.rs`" means outside `io.rs`'s functions: the
  check fails on any `in` or `out` whose address lies outside the symbols of
  `kernel/src/arch/x86_64/io.rs`. Those six functions (`inb`, `inw`, `inl`,
  `outb`, `outw`, `outl`) are `#[inline(never)]` and take the port as their
  first argument, so every `in` and `out` sits under one of them; the IOPort
  invocations, `pic::init` and `arch::exit` call them.
- A fourth rule: the check also fails on a `call` or jump to one of `io.rs`'s
  functions when the straight-line code before it moved an immediate in
  `0x3F8` to `0x3FF` into `dil`, `di`, `edi` or `rdi`, the port argument.
  Since those functions move the port into `dx` themselves, that is how
  release code would name COM1 without the second rule's `mov` into `dx`.

The release kernel is built without features and copied to
`target/xtask/release-kernel/<profile>/kernel.elf`; `cargo xtask test`
disassembles it with `llvm-objdump` from rustup's `llvm-tools`
(`xtask/src/disasm.rs`) before the scenarios, and the `release` scenario
boots it (`docs/design.md`, "A release kernel without UART code").
