# M5 red team: a deferred single step reaches ring 0 outside `syscall_entry`

**Severity:** high, a denial of service. Any thread can panic the kernel.
It cannot run code in ring 0 or read kernel memory.

**Where:** on hardware and on Hyper-V. QEMU 8.2 TCG does not reproduce it.

**Status:** not proven. The test passes on QEMU. It needs the Hyper-V run
below.

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
`#GP`) or `int3` works.

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
- **On Hyper-V or bare metal:** expected to stop at probe 1 with
  `panic: ... fatal trap: ... vector 1 ...`, RIP on `trap_vector_03`. Probe
  0, the `syscall` case, should be the one ring-0 `#DB` the kernel already
  returns from, if the CPU defers it to `syscall_entry`.

To run it on Hyper-V, build the image with `cargo xtask image`, set
`\cmdline.txt` to `test=redteam-movss`, or use CI's VHDX check with that
`test=`, and boot it with `tools/hyperv/`.

## How sure

Medium to high. The SDM documents the deferral for MOV SS and POP SS, and
the CVE-2018-8897 advisories describe a `#DB` delivered in the first
instruction of an `int3` or `int n` handler. They demonstrate it with data
breakpoints. Whether a TF single step is deferred the same way, rather than
dropped, comes from that text and from memory: Linux's
`tools/testing/selftests/x86/mov_ss_trap.c` single-steps
`MOV SS; SYSENTER`. Running the test on Hyper-V would settle it.

## Proposed fix

A ring-0 `#DB` with DR7 at its reset value can only be a single step
deferred from ring 3. Treat it as such wherever it lands:

1. In `trap_from_kernel`, accept a ring-0 `#DB` whose saved RIP is
   `syscall_entry`, or the first instruction of any IDT stub other than
   vector 1's (`trap::stubs()[v]` for `v != 1`). Clear DR6 and return
   through `entry::return_to_kernel`, as for `syscall_entry` today. The
   interrupted stub then runs as if nothing had happened: its own frame is
   on RSP0, and its saved CS still says ring 3, so its `swapgs` is right.
   Generalise `l4core::entry::single_step_into_syscall_entry` to take the
   set of entry addresses, and host-test it.
2. For vector 1's own stub, a nested `#DB` on IST4 may have overwritten the
   outer frame. Either:
   - Move ring-3 `#DB`s off IST4 before anything else runs. This is not
     possible here, because the nested `#DB` fires on the stub's first
     instruction.
   - Or confirm, in the same Hyper-V run, that the CPU merges ICEBP's `#DB`
     with the pending single step into one `#DB` (DR6.BS set alongside it),
     as the SDM's description of pending debug exceptions suggests. Then
     only the first point is needed.
3. Record the rule in `docs/design.md` (NMI, double fault, machine check
   and debug, and Invariants), and add `mov ss; int3` to the M10
   entry/exit brief.

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
