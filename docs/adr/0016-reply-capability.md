# 0016: The reply capability is a one-shot capability in the receiver's TCB, made from a master in the caller's TCB

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's IPC row says "the reply capability lives in the caller's TCB", with
classic seL4 reply capabilities rather than MCS reply objects as the
reference. Classic seL4 actually splits the reply state over two TCBs: each
thread's `tcbReply` slot holds a master reply capability to itself, and `Call`
puts a reply capability derived from the caller's master into the receiver's
`tcbCaller` slot (`src/object/tcb.c`, `setupCallerCap`;
`include/object/structures.h`). `Reply` invokes that slot and receiving on an
endpoint deletes it (`src/api/syscall.c`, `handleReply`, `handleRecv`);
`CNode_SaveCaller` moves it into the CSpace (`src/object/cnode.c`). The shared
label numbering ([ADR 0022](0022-abi-v0-numbering.md)) reserves CNode label
`0x18` for `CNode_SaveCaller` if it is kept.

Two seL4 details are awkward: `Call` through a capability with neither Grant
nor GrantReply delivers the message and then leaves the caller `Inactive`
(`src/object/endpoint.c`), and `CNode_SaveCaller` with nothing to save
reports success (`src/object/cnode.c`).

## Decision

- Each TCB has two slots no `CPtr` reaches, slots 3 and 4 of the five at
  the start of the TCB (offsets 96 and 128): `reply`, holding the thread's
  master reply capability from the moment the TCB is retyped, and `caller`.
  The master is a derivation root at depth 0, as seL4's `setupReplyMaster`
  makes it (`src/object/cnode.c`), so no revoke can delete it; it dies only
  when its TCB is finalised. It is the one stated exception to "every
  capability to an object in an untyped's region is its descendant".
- When a `Call` or a fault meets a receiver, the kernel puts a reply
  capability to the caller into the receiver's `caller` slot, derived from
  the caller's master at depth 1, so the derivation depth limit never stops
  a `Call`. Its Grant is the Grant of the capability the receiver received
  on.
- The reply capability is used once, by `Reply`, by `ReplyRecv`, or by
  `Send`, `NBSend` or `Call` once saved. It cannot be copied, minted or sent
  by IPC; it can be moved.
- It is deleted unused, while in the holder's `caller` slot, when its holder
  receives on an endpoint; in any slot, when that slot is deleted; when the caller is suspended, restarted or deleted (by deleting
  the one capability derived from the caller's master), and when the holder's
  TCB is deleted. The caller then stays `BlockedOnReply` until it is itself
  suspended, restarted or deleted; the kernel never invents a reply.
- `CNode_SaveCaller` exists, label `0x18`, and returns `IllegalOperation`
  when the caller slot is empty.
- `Call` on an endpoint capability needs Write and Grant or GrantReply,
  checked before anything is sent; without them it returns
  `InvalidCapability`.

## Consequences

- The PLAN.md wording is read as: the reply state belongs to the caller (its
  master capability, its `BlockedOnReply` state), while the usable
  capability sits with whoever must answer. `docs/design.md`, [Reply
  capabilities](../design.md#reply-capabilities), is the reference.
- The TCB layout gives the two slots fixed places among its five. The
  capability core gains a `Reply` capability type (target TCB, master flag,
  Grant) that is never derivable and a kernel-only insert under a master;
  M2 reserves it, M5 uses it for fault delivery and `Call`, and M6 adds
  `CNode_SaveCaller`.
- Cleanup reuses the derivation list: cancelling a caller deletes the one
  capability derived from its master wherever it has been moved, with no
  reply-specific back pointer.
- Servers that must defer replies (`console`, `term`, `net`) can save them;
  nested `Call`s work without saving, because `Call` leaves the caller's own
  caller slot alone.
- A server that never replies holds its client forever, as in seL4. A client
  that needs a timeout uses another thread that suspends it.
- Misusing `Call` surfaces as an error instead of a silently suspended
  thread; no seL4 protocol relies on the old behaviour.
