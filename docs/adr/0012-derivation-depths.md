# 0012: The derivation list stores a depth and a low-water depth in every slot

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Derivation tracking row proposes "a derivation-ordered list with
depths, so revoke can find every descendant", built and model-tested in
`core/` first. It does not say what happens when a capability that has
children is deleted, which is where a plain depth list breaks: in
`U(0) A(1) X(1) C(2)`, deleting `X` leaves `C` right after its former uncle
`A` and one level deeper, so `C` reads as `A`'s child and revoking `A` would
delete it. Lifting `X`'s subtree by one level fixes that but costs time
proportional to the subtree, cannot be preempted without exposing wrong
parent relations, and makes a single delete unbounded.

seL4's mapping database avoids depths: a slot has `prev`, `next`,
`mdbRevocable` and `mdbFirstBadged`, and `isMDBParentOf` decides parenthood
by comparing the two capabilities (`sameRegionAs`, badges), with
`mdbFirstBadged` propagated on delete to keep badge groups apart
(`src/object/cnode.c`, `include/object/structures_64.bf`). It is proven
correct, but revoke then depends on type-specific comparisons, and a model
built from plain parent maps must reproduce them.

## Decision

- Each derivation tree is a doubly linked list of slots in preorder. The
  16-byte node in each 32-byte slot holds `prev`, `next` (slot physical
  addresses), `original`, `depth` (12 bits) and `low` (12 bits).
- `low` is the smallest depth among the slot and any deleted slots that
  stood between it and its predecessor. A slot's descendants are the run of
  following slots whose `low` exceeds its depth. Deleting `m` sets
  `low(next) = min(low(next), low(m))`, in constant time, so a deleted
  capability's children pass to its nearest surviving ancestor, as in seL4.
- Every derived capability goes right after its source, as seL4's `cteInsert`
  puts it: one level deeper if the source is original (a child), at the
  source's depth if it is a plain copy (a sibling). Either way the new slot's
  `low` is its depth and no neighbour changes. Which capabilities are original
  follows seL4's `isCapRevocable`, `insertNewCap` and `setupReplyMaster`, plus
  a Hypervisor capability narrowed by Mint ([ADR
  0020](0020-hypervisor-capability.md)). Boot capabilities and each TCB's
  Reply master are roots at depth 0 ([ADR 0016](0016-reply-capability.md)).
- The maximum depth is 4095. One child-insert function in
  `l4core::cdt` enforces it. Every path that installs a derived copy reports
  a refusal as `IllegalOperation`: `CNode_Copy`, `CNode_Mint`,
  `Untyped_Retype`, `TCB_Configure`, `TCB_SetSpace`, `TCB_SetIPCBuffer` and
  `IRQHandler_SetNotification`; IPC transfer skips the capability.

## Consequences

- Revoke, "has children" and delete are type-agnostic, and M2's `model/`
  can be a plain parent map: proptest compares parent relations directly.
- Badge groups need no special case: `low` does what `mdbFirstBadged` does,
  at every level.
- Finality still compares capabilities (`sameObjectAs`) with the two list
  neighbours, as seL4 does.
- The node needs 24 more bits than seL4's. They fit because a link is a
  32-byte-aligned physical address below `2^52`, which leaves 17 bits of each
  word free. No kernel object lies at physical address 0 ([ADR
  0007](0007-boot-region-and-bootinfo.md)), because a zero link means none.
- Honest trees are a few dozen levels deep, but `depth` also counts deleted
  ancestors, so a ring-3 task that copies an untyped and deletes the source
  over and over reaches 4095 in about 8,190 calls. Only derivations below
  that task's own capabilities then fail, and the holder of any ancestor can
  still revoke. Kernel-internal child inserts with no error path never meet
  the limit: a `Call`'s reply capability is a child of a depth-0 master, and
  an issued IRQHandler or IOPort a child of a depth-0 control capability.
  M2 must test the limit on every path and red-team brief 1 should try it.
