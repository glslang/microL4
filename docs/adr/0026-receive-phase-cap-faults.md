# 0026: A receive phase that cannot use its capability reports MissingCapability with 0 bits left

Status: accepted, M6 (2026-11-22)

## Context

A receive phase (`Recv`, `NBRecv`, the second half of `ReplyRecv`) whose
`CPtr` resolves but names a slot it cannot use raises a CapFault: the slot
is empty, holds neither an endpoint nor a notification, holds one without
Read, or, from M6, holds a notification bound to another thread
(`docs/design.md`, [Fault types and
sources](../design.md#fault-types-and-sources)). `docs/abi.md` said the
CapFault carries "the lookup-failure description" but not which one, and
defined bits left as the `CPtr` bits not yet resolved where the lookup
stopped. A capability lookup ignores its leftover bits, so by that
definition such a fault could carry any bits left. seL4 reports
`lookup_fault_missing_capability_new(0)` for every one of these cases
(`src/api/syscall.c`, `handleRecv`), and M5's `l4core::syscall` already
does the same for the cases it has. The M6 spec check found the gap while
checking the bound-notification rule.

## Decision

- A receive-phase CapFault on a slot the lookup reached is
  `MissingCapability` with 0 bits left, whatever bits the lookup left
  unresolved: `in_recv_phase` 1, length 5. This covers an empty slot, a
  capability of another type, an endpoint or notification capability
  without Read, and a notification bound to another thread.
- A receive-phase `CPtr` that does not resolve keeps the failure its
  lookup produced, as before.
- `docs/abi.md`, [CapFault](../abi.md#capfault-1) and [Lookup failure
  description](../abi.md#lookup-failure-description), say so.

## Consequences

- A fault handler cannot tell these four cases apart from the message; it
  can read the thread's capability with its own CSpace authority if it
  needs to know. This is seL4's behaviour.
- No code changes: M5 already reports this for the first three cases, and
  M6's dispatcher check for a bound notification reuses the same fault.
- The host tests that check receive-phase faults pin the 0, and M6 adds
  one for a notification bound to another thread.
