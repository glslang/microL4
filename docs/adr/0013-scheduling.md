# 0013: Fixed-priority round-robin with MCP, one 10 ms tick per slice, and woken threads at the queue tail

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Scheduling row asks for 256 fixed priorities, round-robin within a
priority and a 10 ms timeslice from the local APIC timer, following seL4's
classic scheduler. The row does not say who may set priorities, how the
timeslice is counted, or where a thread that becomes runnable is placed in its
queue. seL4's non-MCS kernel uses a 2 ms tick with a 5-tick slice
(`config.cmake`), an MCP checked against an authority TCB (`checkPrio` in
`src/object/tcb.c`), and usually prepends a woken thread that cannot run at
once to its queue (`tcbSchedEnqueue` from `possibleSwitchTo`, `schedule` and
`restart` in `src/kernel/thread.c`).

## Decision

- Priorities 0 to 255, 255 highest; the highest-priority runnable thread runs.
- Each thread has an MCP. SetPriority, SetMCPriority and SetSchedParams name
  an authority TCB, and no new value may exceed the authority's MCP. The root
  task starts at priority 255 with MCP 255; new TCBs at 0 and 0.
- The local APIC timer ticks at 100 Hz and a slice is one tick
  (`TIME_SLICE_TICKS` = 1). At the end of its slice, or on Yield, the current
  thread goes to the tail of its queue.
- A thread preempted by a higher-priority thread goes back to the head of its
  queue.
- A thread made runnable (IPC wake-up, Resume, SetPriority) runs at once if
  its priority is above every other runnable thread's, the current one
  included, or equal to the highest when the current thread has just blocked
  (the direct switch for Call and ReplyRecv). Otherwise it is appended to its
  queue, not prepended.
- The idle thread is a static kernel context, not a TCB object. It runs on
  the kernel's own page tables, which have no lower-half entries after M3.
- The queue logic lives in `l4core::sched` and is proptested against a model.

## Consequences

- Equal-priority threads share the CPU in strict turn: a thread that blocks
  often cannot jump the queue, at no cost to IPC latency on Call and ReplyRecv.
- Slices are charged in whole ticks, so a thread that blocks just before every
  tick is never charged. seL4 has the same weakness at 2 ms. Red-team brief 9
  tests it; re-arming a one-shot timer with the remaining slice on each switch
  would fix it if needed.
- A thread can raise priorities only up to the highest MCP among the TCBs it
  holds capabilities to, so the root task must not hand out its own TCB
  capability.
- There is no priority inheritance. As in seL4, servers must run at a priority
  at least as high as their clients'.
