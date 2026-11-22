//! A slow, obviously correct reference model of `l4core`'s capability core,
//! and the harness that runs the two side by side (`PLAN.md`, M2); and the
//! same for IPC (`PLAN.md`, M6).
//!
//! [`model::Model`] is written from the specification, not from the
//! implementation: `docs/design.md`, "Kernel objects" to "Derivation
//! tracking", and `docs/abi.md`, "Capabilities" and "Errors", with seL4 where
//! they leave a choice open. It keeps slots in a map and the derivation
//! forest as explicit parent and child lists, and applies every operation
//! atomically.
//!
//! [`harness::World`] holds an `l4core` kernel over fake memory and a model
//! of the same boot state, applies each action to both (restarting the
//! kernel's preempted operations), and compares them after every step:
//! every slot, every derivation link, finality, the hooks, and the
//! invariants of `docs/design.md`.
//!
//! [`ipc::Model`] models threads, endpoints, notifications and binding,
//! reply capabilities, capability transfer, `CNode_SaveCaller`,
//! `CNode_CancelBadgedSends`, fault delivery and the scheduler's part in
//! them from `docs/design.md`, "IPC", "Notifications", "Faults" and
//! "Scheduling", and `docs/abi.md`, "IPC and notifications";
//! [`ipc_harness::World`] runs it beside `l4core`'s system-call dispatch
//! and compares thread states, registers, IPC buffers, queues,
//! notification words, bindings, reply capabilities, CSpace slots and the
//! scheduler after every system call.

pub mod harness;
pub mod ipc;
pub mod ipc_harness;
pub mod model;
