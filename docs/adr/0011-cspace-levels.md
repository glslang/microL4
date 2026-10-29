# 0011: CSpaces are seL4's guarded radix trees, with no limit on levels

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Capability addressing row proposes CNodes of `2^n` slots with
guards, looked up by a capability pointer, "at most two levels to start".
seL4 resolves a `CPtr` through any number of CNodes, each consuming its guard
and radix bits from the most significant end, stopping at a slot that does
not hold a CNode capability (`resolveAddressBits` in `src/kernel/cspace.c`;
manual `cspace.tex`, "CSpace Addressing").

## Decision

- Lookup is seL4's `resolveAddressBits`, with no level limit. Every CNode
  has radix at least 1, so a 64-bit lookup ends within 64 levels.
- Capability lookups use 64 bits and ignore bits left when they reach a
  non-CNode slot. Slot arguments of CNode and Untyped invocations resolve
  exactly `depth` bits, 1 to 64, and fail with `DepthMismatch` otherwise;
  `Untyped_Retype`'s `node_depth` may also be 0, naming the root itself.
- Lookup failures and their detail words are seL4's, except that "bits
  left" is always the number of unresolved bits (0 after an exact lookup).
- "At most two levels" becomes a convention for the root task's initial
  CSpace, which `docs/design.md`, [Initial CSpace and
  BootInfo](../design.md#initial-cspace-and-bootinfo), sets, not a kernel
  rule.

## Consequences

- The lookup loop is bounded by the word size, so a level limit would add a
  check and remove nothing; dropping it costs no complexity.
- seL4 CSpace layouts and the manual's addressing examples apply unchanged.
- M2 must proptest lookups with random guards, radixes and `CPtr`s,
  including `guard_size` 0 with 64 bits left, where a naive shift overflows.
