# 0014: Eager XSAVE of x87 and SSE state only, with XSAVE required

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's FP and SIMD row builds the kernel for `x86_64-unknown-none`, which
keeps the compiler off SSE, and saves user state with XSAVE eagerly on every
switch. The row does not say which state components are enabled, what happens
on a CPU without XSAVE, or how the area size relates to the fixed TCB size.
The XSAVE area grows with the enabled features: 576 bytes for x87 and SSE, 832
with AVX, about 2.7 KiB with AVX-512, and more with AMX. QEMU 8.2 under TCG and
the owner's Hyper-V host offer different features. QEMU's default `qemu64`
model has no XSAVE at all (from memory; check in M5). seL4 defaults to plain
XSAVE with x87 and SSE and a 576-byte area (`XSAVE_FEATURE_SET` 3,
`XSAVE_SIZE` 576 in `src/arch/x86/config.cmake`), and since its owner
tracking (`lazyFPURestore` in `include/machine/fpu.h`) it switches state in
`switchToThread` without trapping.

## Decision

- The kernel requires XSAVE (CPUID.1:ECX bit 26) and panics without it.
- XCR0 is `0x3`: x87 and SSE. Every other component stays disabled, so AVX and
  later instructions raise #UD in user code.
- At boot the kernel checks that CPUID.(EAX=0xD, ECX=0).EBX fits the TCB's
  1024-byte reserve; for x87 and SSE it is 576. `TCB_BITS` is 11.
- CR0.TS is never set. When the kernel returns to a user thread that does not
  own the FP registers, it saves the owner's state with XSAVE64 and restores
  the thread's with XRSTOR64. The idle thread never takes ownership, and
  deleting the owner drops ownership without saving.
- A new thread's state is a template built from constants: FCW `0x037F`,
  MXCSR `0x1F80`, all registers zero.
- User crates build for `x86_64-unknown-none` through M10. No per-thread FPU
  disable flag.
- From M3, xtask's `base_command()` passes `-cpu max,la57=off`; a scenario
  boots `-cpu qemu64` through the `qemu_args:` key and expects the kernel's
  refusal line, which from M5 names XSAVE ([ADR
  0004](0004-privilege-features.md)).

## Consequences

- Every machine gives the same TCB layout and the same user-visible FP
  behaviour, whatever AVX, AVX-512, PKRU or AMX support the host has.
- One save and one restore per switch between two different user threads,
  even for threads that never touch FP. Under TCG this cost does not matter.
- No #NM handler, so no lazy-switching races to reason about.
- Enabling AVX later needs no change to `TCB_BITS` (832 bytes fits the
  reserve). AVX-512 would need 4 KiB TCBs.
- A CPU or hypervisor configuration without XSAVE cannot boot microL4. The
  owner's VM runs with processor compatibility mode off
  (`tools/hyperv/New-L4Vm.ps1`, [ADR 0004](0004-privilege-features.md)), and
  the boot summary prints the required CPUID features, XCR0 and the XSAVE
  size, so the M5 Hyper-V check confirms XSAVE.
