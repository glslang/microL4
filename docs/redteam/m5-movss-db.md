# M5 red team: a deferred single step reaches ring 0 outside `syscall_entry`

**Severity:** high, a denial of service. Any thread can panic the kernel.
It cannot run code in ring 0 or read kernel memory.

**Where:** on hardware and on Hyper-V. QEMU 8.2 TCG does not reproduce it.

**Status:** fixed for `int3` in the M5 fix round ([The fix](#the-fix)):
the kernel returns from a ring-0 `#DB` on the first instruction of the
`#BP` stub. Not proven on a real CPU either way: the test passes on QEMU
before and after the fix. The `int n` and `int1` variants below are
judged not real and stay unfixed; the M5 Hyper-V check settles all three
([What stays to be confirmed on Hyper-V](#what-stays-to-be-confirmed-on-hyper-v)).

## What breaks

`docs/design.md` (NMI, double fault, machine check and debug) says the only
ring-0 `#DB` is the single step that a `syscall` executed with TF set may
raise at `syscall_entry`. `trap_from_kernel`
(`kernel/src/arch/x86_64/trap.rs`) returns from that one case
(`l4core::entry::single_step_into_syscall_entry`) and panics on every other
ring-0 `#DB`.

A ring-3 thread can raise another one:

```
pushfq
or qword ptr [rsp], 0x100   ; TF
popfq
mov ss, eax                 ; eax = 0x1B, the thread's own SS
int3                        ; or int 0x80, or any int n, or a faulting instruction
```

`popfq` sets TF, so the single-step trap fires after the next instruction,
`mov ss`. A load of SS blocks debug traps until the instruction after it has
finished (SDM vol. 3A, 6.8.3, "Masking Exceptions and Interrupts When
Switching Stacks"). That instruction is `int3`, which enters the `#BP` gate
and clears TF in the handler's RFLAGS. The deferred `#DB` is then delivered
on the first instruction of `trap_vector_03`, in ring 0, with the kernel's
CS and with GS still the user's.

This is the mechanism of CVE-2018-8897, here with TF in place of a data
breakpoint. The thread can set TF itself, so DR7 being kept at `0x400` does
not stop it.

`trap_common_entry` sees a ring-0 CS and correctly runs no `swapgs`.
`trap_from_kernel` then finds a `#DB` whose RIP is not `syscall_entry`, so
`l4core::trap::kernel_trap` returns `Fatal`, and the kernel panics with
`fatal trap`. With `int 0x80`, or any `int n` whose gate has DPL 0, the
`#DB` arrives in the `#GP` stub instead. Any `int n` (a DPL-0 gate gives
`#GP`) or `int3` works (the `int n` case is contested; see
[Proposed fix (red team)](#proposed-fix-red-team)).

`mov ss; int1` (ICEBP) with TF set adds a second problem. The ICEBP `#DB`
from ring 3 enters `trap_vector_01` on IST4, and a deferred single step
there, if the CPU delivers it separately rather than merging it into the
same `#DB`, also runs on IST4. Its frame overwrites the outer frame, so the
fix below must not simply return from it.

## The test

`test=redteam-movss` (`tests/qemu/redteam-movss.scenario`;
`user/root/src/redteam/probes.rs`, `MOV_SS`) runs five probes: `mov ss`
with TF set, followed by `syscall` (Yield), `int3`, `int 0x80`, `int1` and
`ud2`. The root task is the thread's fault handler.

- **On QEMU 8.2 TCG:** the scenario passes. QEMU raises the `#DB` in ring 3
  right after `mov ss`, at the next instruction, with nothing deferred. The
  log shows `label 3, 0x1/0x0` for every probe.
- **On Hyper-V or bare metal, before the fix:** expected to stop at probe
  1 with `panic: ... fatal trap: ... vector 1 ...`, RIP on
  `trap_vector_03`. Probe 0, the `syscall` case, should be the one ring-0
  `#DB` the kernel already returns from, if the CPU defers it to
  `syscall_entry`.
- **After the fix:** see
  [What stays to be confirmed on Hyper-V](#what-stays-to-be-confirmed-on-hyper-v).

To run it on Hyper-V, boot the `redteam-movss` VHDX of CI's
`microl4-vhdx-m5-check` artifact with `tools/hyperv/Test-L4Vhdx.ps1`
(`tools/hyperv/README.md`, "At the M5 check").

## How sure

Medium to high. The SDM documents the deferral for MOV SS and POP SS, and
the CVE-2018-8897 advisories describe a `#DB` delivered in the first
instruction of an `int3` or `int n` handler. They demonstrate it with data
breakpoints. Whether a TF single step is deferred the same way, rather than
dropped, comes from that text and from memory: Linux's
`tools/testing/selftests/x86/mov_ss_trap.c` single-steps
`MOV SS; SYSENTER`. Running the test on Hyper-V would settle it.

## Proposed fix (red team)

The red team proposed accepting a ring-0 `#DB` on the first instruction of
every IDT stub but vector 1's, and settling `int1` on Hyper-V. The M5
kernel reviewer agreed with the `int3` case only: `#BP` is the only gate
with DPL 3, `int n` on a DPL-0 gate raises `#GP`, which drops the pending
single step, and `mov ss; int1` gives one `#DB` (the notes in Linux's
`mov_ss_trap.c`; moderate confidence). Accepting a `#DB` on stubs no
instruction can reach would widen the rule for nothing, so the fix below
accepts only the `#BP` stub.

## The fix

M5 fix round, in `kernel/src/arch/x86_64/trap.rs` and `core/src/entry.rs`:

- `trap_from_kernel` returns from a ring-0 `#DB` whose saved RIP is
  `syscall_entry` (as before) or the first instruction of the `#BP` stub,
  `trap::stubs()[3]` (`l4core::entry::single_step_into_breakpoint_stub`).
  As at `syscall_entry`, it `iretq`s at once through
  `entry::return_to_kernel`, with the saved state unchanged: the single
  step is dropped. The `#BP` stub then runs as if nothing had happened: the
  `#BP` frame the CPU pushed is at the top of the kernel stack (RSP0, not
  IST4, so the `#DB` overwrote nothing), and its saved CS says ring 3, so
  the stub's `swapgs` is right. The thread gets UserException 3, with
  `rip` past its `int3`.
- Every other ring-0 `#DB` panics as before: on the `#GP` stub, and on the
  `#DB` stub's own first instruction above all, whose IST4 frame a nested
  `#DB` would have overwritten.
- Host test `single_step_into_breakpoint_stub_needs_db_ring_0_and_vector_3s_stub`
  beside `single_step_into_syscall_entry`'s: a ring-0 `#DB` on each of the
  256 stubs is accepted only on vector 3's, never on a neighbouring
  address, another vector, or from ring 3.
- `docs/design.md` ("NMI, double fault, machine check and debug", Faults,
  the vector map, Invariants, Open questions) and ADR 0008 state the rule.
- Not done: adding `mov ss` with TF before each kernel entry to M10's
  entry-and-exit red-team brief, `PLAN.md` M10 item 5, is left to the lead.

## What stays to be confirmed on Hyper-V

QEMU cannot show any of this: it raises the `#DB` in ring 3 after
`mov ss`. The M5 Hyper-V check boots `test=redteam-movss`, which must
reach `TEST PASS` without a panic. Each probe line reads
`label 3, <vector>/<error code>`:

- Probe 0 (`syscall`): `0x1`. If the CPU defers the step to
  `syscall_entry`, the kernel returns from it, and `sysretq` restores TF.
- Probe 1 (`int3`): `0x3` if the CPU defers the step past `int3`, as the
  finding says: the fix's path, which confirms it. `0x1` if it does not.
  A `fatal trap` at `trap_vector_03` would mean the fix is not in place.
- Probe 2 (`int 0x80`): `0x1` or `0xd`. A `fatal trap` with RIP on
  `trap_vector_0d` would mean `#GP` keeps the pending step after all, and
  the `#GP` stub must be accepted as well.
- Probe 3 (`int1`): `0x1`. A `fatal trap` with RIP on `trap_vector_01`
  would mean the CPU raises a second `#DB` over the first one's IST4
  frame; that needs a design change (no IST for `#DB`, or a stack switch
  the nested `#DB` cannot overwrite), not a wider rule.
- Probe 4 (`ud2`): `0x1` or `0x6`.

## What held (M5 red team)

Every test below passes on QEMU and stays as an ordinary scenario.

- **`test=redteam-exceptions`:** 80 ring-3 probes. Each ended in the
  thread's own fault with IOPL 0, and the kernel never panicked.
  - `int n` on the NMI, `#DF`, `#MC`, timer, device and spurious vectors.
  - `int1`, `int3`, `sysenter`, `sysexit` and `sysretq` in ring 3.
  - `hlt`, `cli`, `in` and `out`.
  - CR, DR and MSR access, `swapgs`, `lgdt`, `ltr`, `invlpg`, `xsetbv`
    and `xrstors`.
  - `retfq` and `iretq` to every GDT selector, including the TSS and its
    upper half, past the limit, and with NT set.
  - IOPL 3 asked for by `popfq` and by `iretq`.
  - Jumps to and accesses of kernel text, the direct map, the device
    window, non-canonical addresses and the last page below 2^47.
  - TF and AC across `syscall`.
  - An x87 `#MF` left pending across a kernel entry and FP switch.
  - Bad XSAVE headers.
  - A `syscall` with a non-canonical or kernel-half RSP, which returns
    with RSP 0.
  - Unknown system-call numbers.
- **`test=redteam-tlb`:** after each operation that takes a mapping away,
  a thread in the same VSpace faulted at the address. That covers
  `Frame_Unmap`, `Frame_Remap` to read-only, `CNode_Delete` and
  `CNode_Revoke` of the frame, unmapping the page table, page directory or
  PDPT, deleting the page table, and revoking and reusing the frame's
  untyped. 4 KiB and 2 MiB frames were both tested. No CR3 write happened
  in between. `Frame_Map` was refused at `USER_TOP`, at 2^47, at page 0 and
  in the kernel half.
- **`test=redteam-selfdelete`:** a thread deleted the last capability to
  its own TCB, which held the last capability to the PML4 in CR3. A second
  thread revoked the untyped holding its own TCB, VSpace and IPC buffer. In
  both cases the kernel finished the call and never ran the thread again. A
  TCB retyped at the dead one's address started with FS base 0 and clean
  XMM0, so `thread::forget` and `fpu::forget` worked.

## QEMU 8.2 TCG deviations seen (not kernel bugs)

- `retfq` and `iretq` executed in ring 3 pop the user stack with a
  supervisor access, which SMAP faults (`#PF`, error code 1). User code
  cannot use them under this kernel on QEMU 8.2.
- A non-canonical data address or RIP gives `#PF`, where hardware gives
  `#GP` or `#SS`.
- `int1` (ICEBP) gives `#UD` in ring 3 as well as in ring 0.
  `docs/abi.md`'s "`int1` gives 1" holds only on hardware.
- `ldmxcsr`, `fxrstor` and `xrstor` accept reserved MXCSR bits. Unmasked
  SSE exceptions raise no `#XM`.
