# 0015: CR4.FSGSBASE stays off; the kernel sets and switches user FS and GS bases, always in the lower half

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Syscall ABI row enters the kernel with `syscall` and `swapgs`. After
`swapgs`, the kernel finds its own data through GS. If the entry path ever
skips or doubles a `swapgs` (on an exception or NMI taken at the wrong moment,
a classic bug class that red-team brief 5 targets), the kernel runs with the
user's GS base. With CR4.FSGSBASE set, which seL4 on x86_64 does by default
(`KernelFSGSBase` in `src/arch/x86/config.cmake`, `src/arch/x86/64/head.S`), a
user can put any address in GS base with WRGSBASE (from memory; check in
M5). That includes the direct-map alias of a frame the user fills, so such a
bug becomes a privilege escalation. Threads also need FS base for TLS.

## Decision

- CR4.FSGSBASE stays clear, so ring 3 cannot run RDFSBASE, WRFSBASE, RDGSBASE
  or WRGSBASE.
- FS base is set with `TCB_SetTLSBase`, which, unlike `TCB_WriteRegisters`,
  also works on the caller, or with `TCB_WriteRegisters` word 18. GS base is
  set with word 19.
- The register sanitiser replaces any FS or GS base, `rip` or `rsp` at or above
  `0x0000_8000_0000_0000` with 0.
- On a switch away from a thread, the kernel saves IA32_FS_BASE and
  IA32_KERNEL_GS_BASE (which holds the user GS base while the kernel runs)
  into the TCB. On a switch to a thread, it writes them back.

## Consequences

- A user GS base is always 0 or a lower-half address. A `swapgs` mistake then
  makes the kernel access a user address, which SMAP refuses, so the result is
  a kernel panic rather than a kernel reading attacker-chosen data.
- Setting TLS costs a system call, and each thread switch costs two RDMSR and
  two WRMSR.
- The entry path ([ADR 0008](0008-kernel-entry-and-exit.md)) must agree. User
  code can still reset either base to 0 by loading a segment selector, so the
  kernel reads the bases back from the MSRs when it switches away instead of
  trusting the TCB copy.
