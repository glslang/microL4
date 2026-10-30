//! A slow, obviously correct reference model of `l4core`'s capability core,
//! and the harness that runs the two side by side (`PLAN.md`, M2).
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

pub mod harness;
pub mod model;
