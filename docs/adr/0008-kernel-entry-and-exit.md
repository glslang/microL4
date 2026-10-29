# 0008: Kernel entry builds one trap frame on the kernel stack, IST stacks serve only fatal and debug vectors, and `sysretq` returns only below 2^47

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Syscall ABI row says "`syscall` and `sysret`, with `swapgs` on
entry", and `docs/abi.md`, [System calls](../abi.md#system-calls), adds
`iretq` "when the return state cannot be expressed by `sysretq`". The row does
not say where the user's registers are saved, which vectors use IST stacks,
what happens to an NMI in the instructions before `swapgs`, or which check
stops the Intel `sysretq` #GP on a non-canonical RCX, which M10's brief 5
attacks. seL4's uniprocessor x86_64 build has no `swapgs`, pushes the user
context straight into the TCB, runs every vector on one small IST stack, and
relies on register sanitising for RCX (`src/arch/x86/64/traps.S`,
`src/arch/x86/64/c_traps.c`, `src/arch/x86/64/machine/registerset.c`).

## Decision

- `IA32_STAR` = `0x0013_0008_0000_0000`, for the GDT null, kernel code
  `0x08`, kernel data `0x10`, user data `0x1B`, user code `0x23`, TSS
  `0x28`; `IA32_FMASK` = `0x0025_7FD5`, seL4's mask, which clears
  IF, TF, DF, AC, NT, IOPL and the rest; `IA32_SYSENTER_CS` = 0;
  `IA32_CSTAR` points at a stub that switches stacks and panics.
- Every entry from ring 3 runs `swapgs` once, builds a 22-word trap frame at
  the top of the single kernel stack (from RSP0, or from `PerCpu` for
  `syscall`), and Rust copies it into the TCB. Exits rebuild the frame from
  the TCB and run `swapgs` once. Every exception and interrupt stub runs
  `clac` and `cld` first ([ADR 0004](0004-privilege-features.md)).
- IST1 #DF, IST2 NMI, IST3 #MC, IST4 #DB, each 8 KiB above an unmapped guard
  page, as is the kernel stack ([ADR 0004](0004-privilege-features.md)). NMI,
  #DF and #MC are fatal from any ring; #DB from ring 0 returns only when the
  saved RIP is exactly `syscall_entry`, and otherwise panics. None of them
  reads GS.
- Only vector 3 has DPL 3. Vectors that cannot occur here (9, 15, 17,
  20 to 31) panic from either ring; 17, 21, 29 and 30 use the
  no-error-code stub so an injected MSI cannot make the kernel misread a
  frame.
- The kernel runs with interrupts off except in `idle_loop`, and preemption
  points poll the local APIC's IRR; a ring-0 interrupt anywhere else,
  and every ring-0 exception, panics.
- `l4core::entry::exit_frame` replaces a RIP or RSP at or above 2^47 by 0,
  masks RFLAGS to what ring 3 can set itself plus IF, and fixes CS and
  SS. `sysretq` is used only when the thread's last entry was `syscall` and
  no register write followed; otherwise `iretq`.

## Consequences

- The check against the `sysretq` #GP holds even if a register writer forgets
  to sanitise, and `exit_frame` is a pure function host tests and proptest
  can cover at every boundary.
- Every entry costs a 22-word copy; the stubs stay short and all decisions
  are in Rust.
- `swapgs` brings one invariant, that GS is read only outside the two windows
  around it and never by IST handlers; in return the stubs are ready for the
  multi-core stretch goal.
- Any NMI or machine check, and any vector that cannot occur, stops the
  machine, also in user mode, where seL4 would deliver it to the thread as a
  user exception. A driver that can program MSI can therefore stop the
  machine.
- An `sti` window in the kernel would need a nested-interrupt path; polling
  the IRR at preemption points avoids one.
