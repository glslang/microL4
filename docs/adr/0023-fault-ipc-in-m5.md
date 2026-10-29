# 0023: M5 builds the IPC that fault delivery needs

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md puts endpoints, the IPC system calls and "fault delivery as IPC" in
M6, but M5's done-when test has a user page fault reach its fault-handler
thread, which prints it and kills the faulting thread. That test needs an
Endpoint, a blocking receive, a fault sent with `Call` semantics, a reply
capability, and the cancellation that runs when a thread blocked waiting
for a reply is killed. The IPC and threads designers both raised this.

## Decision

M5 builds, in `l4core::ipc` and the kernel:

- Endpoint objects and `Send`, `NBSend`, `Call`, `Recv`, `NBRecv`, `Reply`
  and `ReplyRecv`, without capability transfer;
- reply capabilities (the master in each TCB and the one-shot capability in
  the receiver's `caller` slot);
- fault delivery and fault replies;
- `cancel_ipc` and `cancel_all_ipc`.

M6 adds capability transfer and unwrapping, badge tests, notifications and
binding, `CNode_SaveCaller`, `cancel_badged_sends`, `cancel_all_signals`,
and the IPC state machine proptest. M6's done-when test is unchanged.

## Consequences

- M5 is larger than PLAN.md's M5 list, and M6 smaller. The budget split in
  PLAN.md is not changed; STATUS.md records the move.
- Every invariant in `docs/design.md` names its milestone under this split.
- The M6 proptest also covers the M5 paths, so they get model checking one
  milestone after they land.
