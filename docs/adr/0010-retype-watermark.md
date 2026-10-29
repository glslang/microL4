# 0010: Retype allocates at the watermark while an untyped has children, and resets it only when it has none

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Memory row says retype is the only allocator and revoking an
untyped reclaims everything made from it. Its M2 milestone adds a proptest
check that "an untyped with children cannot be retyped". Read literally,
each untyped could be retyped once, into one type of object, before it is
revoked: the root task would have to split all memory up front, and a 4 KiB
untyped would hold one 16-byte endpoint and waste the rest.

seL4 keeps a watermark in each untyped capability. While the untyped has
children, retype allocates at the watermark, aligned up to the object size;
once it has none, the next retype resets it, clearing the used memory and
setting the watermark to 0 (`src/object/untyped.c`; manual `objects.tex`,
"Reusing Memory"). Copying an untyped needs it to have no children, and the
source is then marked full (`setUntypedCapAsFull`, `ensureNoChildren`).

## Decision

- microL4 follows seL4: retype allocates at the aligned watermark while the
  untyped has children, and resets it only when it has none. An untyped with
  children cannot be reset or copied.
- Memory at or above the watermark is zero in RAM untyped. Boot creates
  every untyped with its watermark at its size, so the first retype clears
  it. A reset clears from the top down in 4 KiB chunks with a preemption
  point after each, lowering the watermark as it goes.
- Device untyped yields only Frames and device untyped and is never
  cleared.
- M2's invariant becomes: an untyped with children is never reset or
  copied, every retype lands at or above the watermark, and no two live
  objects overlap.

## Consequences

- Untyped memory can be shared among object types without pre-splitting,
  and "retype never overlaps a live object" rests on two facts M2 can test:
  the watermark only rises while children exist, and every object in an
  untyped's region is its descendant.
- Objects are zeroed lazily, at reset, not at creation; `init_object` writes
  only non-zero fields.
- A partly used untyped cannot reuse memory freed below its watermark until
  all its children are gone, as in seL4.
- PLAN.md's M2 bullet must be reworded when this ADR is accepted.
