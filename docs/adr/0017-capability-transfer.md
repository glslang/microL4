# 0017: IPC names up to three capabilities, copies at most one, and unwraps capabilities to the sending endpoint

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's IPC row allows "one transferred capability per message". The shared
ABI ([ADR 0022](0022-abi-v0-numbering.md)) gives `MessageInfo` a two-bit
`extra_caps` (up to three capability pointers, which kernel invocations need)
and a `caps_unwrapped` field, and leaves open whether v0 unwraps. In seL4 a
receiver offers one slot, a sender may name up to three capabilities, and a
capability to the endpoint the message travels through is unwrapped: its badge
goes to the receiver and the capability itself is not copied (`ipc.tex`,
"Capability Transfer"; `src/kernel/thread.c`, `transferCaps`).

## Decision

- A message names up to three capabilities in `caps_or_badges`. They are
  looked up when the send starts, which can fault, and again when the
  message is delivered.
- The receiver names one receive slot through `receive_cnode`,
  `receive_index` and `receive_depth`. At most one capability is copied per
  message, into that slot, with the same rights and badge. The copy is made
  by the capability core's `derive` and `insert_derived`, the functions
  `CNode_Copy` uses, so it is derived from the sender's capability as seL4's
  `cteInsert` places it: a child of an original, a sibling of a copy. A
  copy that `insert_derived` refuses at `MAX_DERIVATION_DEPTH` is not
  transferred, like any capability that cannot be derived.
- An endpoint capability to the endpoint carrying the message is unwrapped
  into `caps_or_badges[i]` and bit `i` of `caps_unwrapped`, at any position
  the transfer reaches, and does not use the slot.
- Transfer needs Grant on the sender's capability, a readable IPC buffer
  for the sender and a writable one for the receiver. It stops at the first
  capability that can be neither unwrapped nor copied; nothing is reported
  except the received `extra_caps`.

## Consequences

- This matches seL4, so nothing is lost against the reference, except that
  a copy at the derivation depth limit, which seL4 does not have, is not
  transferred.
- M6 builds it; M5's IPC moves no capabilities.
- Unwrapping costs one comparison per capability in the `core/` transfer
  loop and lets a client prove to a server that it holds a badged capability
  to the same endpoint, for example to name a session in a request.
- A server that needs several capabilities from one client takes them over
  several messages.
- Failures are silent by design, as in seL4: the receive phase cannot return
  an error that would be confused with a message, so protocols check
  `extra_caps`.
