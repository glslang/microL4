//! The hooks `core/` calls into the rest of the kernel.
//!
//! `core/` does every slot write itself; [`Kernel`] adds what only the kernel
//! can do: finalise objects of other subsystems, rewrite paging
//! back-references when a capability moves, clear and initialise memory, and
//! check for a pending interrupt (`docs/design.md`, "How `core/` reaches
//! kernel memory"). Hooks may change other slots, so `core/` re-reads every
//! slot it needs after calling one.

use crate::cap::Cap;
use crate::slot::{SlotAddr, SlotMemory};

/// A preemption point found an interrupt pending. The operation has left
/// every object consistent; the system call restarts later from the thread's
/// saved registers and continues.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Preempted;

/// The kernel side of the capability core.
pub trait Kernel: SlotMemory {
    /// A capability other than a CNode or Zombie is being deleted; `last`
    /// says whether it is the last capability to its object. Called before
    /// the slot empties. A TCB's hook suspends and unbinds the thread; a
    /// Frame's unmaps on every deletion; an Endpoint's releases its queue.
    /// Returns a capability to pass to [`Kernel::after_delete`] once the slot
    /// is empty, as seL4's `cleanupInfo`. A TCB's hook returns `None`, as
    /// seL4's thread finalisation does: its last capability becomes a Zombie,
    /// and its slot empties only steps later.
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap>;

    /// The slot that held a finalised capability is now empty.
    fn after_delete(&mut self, cleanup: Cap);

    /// `cap` moved from slot `from` to slot `to`, by Move, Mutate, Rotate, a
    /// swap or a Zombie swap. The paging code rewrites the back-reference of
    /// a mapped capability.
    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr);

    /// Writes zeros to `len` bytes of RAM at `paddr`.
    fn zero(&mut self, paddr: u64, len: u64);

    /// A new object's memory is zero; writes its non-zero fields.
    fn init_object(&mut self, cap: Cap);

    /// A preemption point: `Err` if an interrupt is pending.
    fn preempt(&mut self) -> Result<(), Preempted>;
}
