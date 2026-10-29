# 0018: IPC does no priority inheritance; endpoint and notification queues are FIFO

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Scheduling row gives 256 fixed priorities with round-robin within
a priority, and M10's scheduler brief lists priority inversion and
"bypassing the priority ceiling". The IPC row says nothing about
priorities. Classic seL4 queues endpoint and notification waiters in
arrival order (`src/object/tcb.c`, `tcbEPAppend`) and does no priority
inheritance; a server runs at its own priority, and systems avoid inversion
by giving servers a priority at least that of their clients. MCS adds
scheduling-context donation, which PLAN.md leaves as a stretch goal.

## Decision

- Endpoint and notification queues are strictly FIFO.
- IPC never reads or changes a priority or a timeslice, and there is no
  donation. A thread woken by IPC is passed to the scheduler's
  `make_runnable`. IPC never switches threads itself; the scheduler's tie rule
  ([ADR 0013](0013-scheduling.md)) runs a `Call` or `ReplyRecv` partner at
  once.
- Avoiding inversion is a configuration rule: `root` gives each server a
  priority at least that of every client (an immediate priority ceiling), and
  the maximum controlled priority of [ADR 0013](0013-scheduling.md) keeps a
  client from raising itself above the ceiling.

## Consequences

- A high-priority client waits behind lower-priority clients queued earlier
  on the same endpoint, for at most the length of the queue.
- A misconfigured system, with a server below one of its clients, shows
  priority inversion under load. The kernel does not detect it.
- `IpcEnv` in `l4core::ipc` has no method that touches priorities, so the
  property is checked by the type from M5, and M10 brief 9 tests that no
  IPC path raises a thread above its ceiling.
- Cancelling a queue is not preemptible either: deleting an endpoint or
  notification, or cancelling a badge, wakes every matching queued thread in
  one kernel entry. The queue holds at most the TCBs that exist; M10
  brief 9 measures the worst case.
- MCS-style donation, if the stretch goal is taken, changes this decision and
  needs a new ADR.
