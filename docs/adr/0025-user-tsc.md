# 0025: User code may read the time-stamp counter

Status: accepted, M5 (2026-11-02)

## Context

BootInfo carries `tsc_hz`, the TSC frequency the kernel measures in M3,
but `docs/abi.md` never said whether user code may execute `rdtsc`. The
kernel has never set CR4.TSD, so it can. M5's `test=threads` root test
measures its busy loops with the TSC to make sure the 10 ms timer preempts
them, and later servers (the terminal's cursor blink, `net`'s timeouts)
will want a cheap clock without a system call. seL4 on x86 leaves CR4.TSD
clear as well, and offers no time system call outside MCS.

## Decision

- The kernel keeps CR4.TSD clear: `rdtsc` and `rdtscp` work in ring 3 on
  every thread, and BootInfo's `tsc_hz` converts their ticks to time.
- `rdtscp` also returns `IA32_TSC_AUX` in ECX, as `rdpid` does. When CPUID
  reports either instruction, the kernel writes the MSR to 0 in boot step 3
  (`entry::init`, which prints it), so every thread reads 0 there, not
  whatever the firmware left (added in the M5 fix round, after the M5
  kernel review found the MSR never written).
- The ABI promises nothing about the TSC beyond that: it is not
  synchronised across cores (there is one), and an invariant TSC is not
  checked.

## Consequences

- User code has a clock without a system call, at the cost of a timing
  side channel every thread already has through any busy loop.
- Setting CR4.TSD later, to remove that channel, would be an ABI change
  and a new ADR.
