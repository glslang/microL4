//! Slot operations: copy, mint, move, mutate, rotate, delete and revoke
//! (`docs/design.md`, "Slot operations" and "Deletion and finalisation").
//!
//! Callers have resolved every slot argument; these functions check what the
//! slots hold and change them. Delete and revoke are sequences of
//! single-capability steps with a preemption point after each: a preempted
//! call leaves every object consistent and continues when restarted.

use crate::cap::{Cap, CapType, Rights, TCB_BITS, TCB_SLOTS, cnode_data};
use crate::cdt;
use crate::error::{LookupFailure, SyscallError};
use crate::kernel::{Kernel, Preempted};
use crate::slot::{SlotAddr, SlotMemory};

/// The error for an empty source or pivot slot.
const EMPTY_SOURCE: SyscallError = SyscallError::FailedLookup {
    source: true,
    failure: LookupFailure::MissingCapability { bits_left: 0 },
};

/// The capability a copy of the one in `src` starts as, as seL4's
/// `deriveCap`. Refuses capabilities that cannot be copied (Null, Zombie,
/// Reply, the two control capabilities and the move-only paging
/// structures) and an untyped with children. A Frame copy is unmapped.
pub fn derive<M: SlotMemory + ?Sized>(mem: &M, src: SlotAddr) -> Result<Cap, SyscallError> {
    let cap = mem.load(src).cap;
    match cap.cap_type() {
        CapType::Null
        | CapType::Zombie
        | CapType::Reply
        | CapType::IrqControl
        | CapType::IoPortControl
        | CapType::Pdpt
        | CapType::PageDirectory
        | CapType::PageTable => Err(SyscallError::IllegalOperation),
        CapType::Untyped if cdt::has_children(mem, src) => Err(SyscallError::RevokeFirst),
        CapType::Frame => Ok(cap.with_data(0)),
        _ => Ok(cap),
    }
}

/// `CNode_Copy`: puts a copy of the capability in `src` in the empty slot
/// `dst`, its rights reduced to `rights`.
pub fn copy<K: Kernel + ?Sized>(
    k: &mut K,
    src: SlotAddr,
    dst: SlotAddr,
    rights: u64,
) -> Result<(), SyscallError> {
    let cap = derived_copy(k, src, dst, rights)?;
    let original = cap.cap_type() == CapType::Untyped;
    insert_copy(k, src, dst, cap, original)
}

/// `CNode_Mint`: as [`copy`], plus the capability data word
/// (`docs/abi.md`, "Capability data"). A new badge makes the copy original.
pub fn mint<K: Kernel + ?Sized>(
    k: &mut K,
    src: SlotAddr,
    dst: SlotAddr,
    rights: u64,
    data: u64,
) -> Result<(), SyscallError> {
    let cap = derived_copy(k, src, dst, rights)?;
    let (cap, original) = mint_data(cap, data)?;
    insert_copy(k, src, dst, cap, original)
}

/// `CNode_Move`: moves the capability in `src`, unchanged, with its place in
/// the derivation tree, to the empty slot `dst`.
pub fn move_cap<K: Kernel + ?Sized>(
    k: &mut K,
    src: SlotAddr,
    dst: SlotAddr,
) -> Result<(), SyscallError> {
    let cap = move_source(k, src, dst)?;
    cdt::move_slot(k, cap, src, dst);
    Ok(())
}

/// `CNode_Mutate`: as [`move_cap`], applying `data` to the capability.
pub fn mutate<K: Kernel + ?Sized>(
    k: &mut K,
    src: SlotAddr,
    dst: SlotAddr,
    data: u64,
) -> Result<(), SyscallError> {
    let cap = move_source(k, src, dst)?;
    let cap = mutate_data(cap, data)?;
    cdt::move_slot(k, cap, src, dst);
    Ok(())
}

/// `CNode_Rotate`: moves the pivot's capability to `dst` with `dst_data`
/// applied, and the source's to the pivot with `pivot_data` applied, at
/// once. If `dst` is `src`, the two capabilities swap.
pub fn rotate<K: Kernel + ?Sized>(
    k: &mut K,
    dst: SlotAddr,
    dst_data: u64,
    pivot: SlotAddr,
    pivot_data: u64,
    src: SlotAddr,
) -> Result<(), SyscallError> {
    if pivot == src || pivot == dst {
        return Err(SyscallError::IllegalOperation);
    }
    if dst != src && !k.load(dst).cap.is_null() {
        return Err(SyscallError::DeleteFirst);
    }
    let src_cap = k.load(src).cap;
    if src_cap.is_null() {
        return Err(EMPTY_SOURCE);
    }
    let pivot_cap = k.load(pivot).cap;
    if pivot_cap.is_null() {
        return Err(EMPTY_SOURCE);
    }
    let to_dst = mutate_data(pivot_cap, dst_data)?;
    let to_pivot = mutate_data(src_cap, pivot_data)?;
    if dst == src {
        cdt::swap_slots(k, to_pivot, src, to_dst, pivot);
    } else {
        cdt::move_slot(k, to_dst, pivot, dst);
        cdt::move_slot(k, to_pivot, src, pivot);
    }
    Ok(())
}

/// `CNode_Delete`: deletes the capability in `slot`, finalising its object
/// if it is the last capability to it. An empty slot is left as it is.
pub fn delete<K: Kernel + ?Sized>(k: &mut K, slot: SlotAddr) -> Result<(), Preempted> {
    delete_slot(k, slot, true)
}

/// `CNode_Revoke`: deletes every capability derived, directly or not, from
/// the one in `slot`, which stays. Re-reads `slot` at every step, so it stops
/// cleanly if a step deletes the CNode holding `slot`.
pub fn revoke<K: Kernel + ?Sized>(k: &mut K, slot: SlotAddr) -> Result<(), Preempted> {
    while let Some(child) = cdt::first_child(k, slot) {
        delete_slot(k, child, true)?;
        k.preempt()?;
    }
    Ok(())
}

/// The checks Copy and Mint share, then the derived capability with its
/// rights reduced.
fn derived_copy<M: SlotMemory + ?Sized>(
    mem: &M,
    src: SlotAddr,
    dst: SlotAddr,
    rights: u64,
) -> Result<Cap, SyscallError> {
    if !mem.load(dst).cap.is_null() {
        return Err(SyscallError::DeleteFirst);
    }
    if mem.load(src).cap.is_null() {
        return Err(EMPTY_SOURCE);
    }
    let cap = derive(mem, src)?;
    Ok(cap.with_rights(cap.rights().intersect(Rights::from_word(rights))))
}

/// Inserts a derived capability next to its source. A copied untyped keeps
/// the source's watermark, and the source's goes to its size, so only the
/// copy allocates (seL4 `setUntypedCapAsFull`).
fn insert_copy<K: Kernel + ?Sized>(
    k: &mut K,
    src: SlotAddr,
    dst: SlotAddr,
    cap: Cap,
    original: bool,
) -> Result<(), SyscallError> {
    cdt::insert_derived(k, src, dst, cap, original).map_err(|_| SyscallError::IllegalOperation)?;
    if cap.cap_type() == CapType::Untyped {
        let mut s = k.load(src);
        s.cap = s.cap.with_data(1 << s.cap.size_bits());
        k.store(src, s);
    }
    Ok(())
}

/// The checks Move and Mutate share; returns the source capability.
fn move_source<M: SlotMemory + ?Sized>(
    mem: &M,
    src: SlotAddr,
    dst: SlotAddr,
) -> Result<Cap, SyscallError> {
    if !mem.load(dst).cap.is_null() {
        return Err(SyscallError::DeleteFirst);
    }
    let cap = mem.load(src).cap;
    if cap.is_null() {
        return Err(EMPTY_SOURCE);
    }
    Ok(cap)
}

/// Applies a Mint data word; returns the capability and whether it is
/// original.
fn mint_data(cap: Cap, data: u64) -> Result<(Cap, bool), SyscallError> {
    match cap.cap_type() {
        CapType::Endpoint | CapType::Notification => {
            if cap.badge() != 0 {
                Err(SyscallError::IllegalOperation)
            } else if data == 0 {
                Ok((cap, false))
            } else {
                Ok((cap.with_data(data), true))
            }
        }
        CapType::CNode => Ok((with_guard(cap, data)?, false)),
        // Narrowing a Hypervisor capability arrives with it, in M9.
        CapType::Hypervisor if data != 0 => Err(SyscallError::IllegalOperation),
        CapType::Untyped => Ok((cap, true)),
        _ => Ok((cap, false)),
    }
}

/// Applies a Mutate or Rotate data word.
fn mutate_data(cap: Cap, data: u64) -> Result<Cap, SyscallError> {
    match cap.cap_type() {
        CapType::Endpoint | CapType::Notification => Err(SyscallError::IllegalOperation),
        CapType::CNode => with_guard(cap, data),
        CapType::Hypervisor if data != 0 => Err(SyscallError::IllegalOperation),
        _ => Ok(cap),
    }
}

/// A CNode capability with the guard a data word gives, if it fits:
/// `guard_size + radix <= 64`.
fn with_guard(cap: Cap, data: u64) -> Result<Cap, SyscallError> {
    let guard_size = (data & 0x3F) as u32;
    if guard_size + cap.radix() > 64 {
        return Err(SyscallError::IllegalOperation);
    }
    Ok(cap.with_data(cnode_data(guard_size, data >> 6)))
}

/// Deletes the capability in `slot`: seL4's `cteDelete`. An `exposed`
/// deletion (one a user asked for) clears a dying container completely; a
/// nested one, of a capability inside a container being cleared, only moves
/// the dying container's Zombie into its own slot 0 and carries on with
/// what was there, so recursion is at most two levels deep. seL4 empties
/// the slot if `exposed || done`; here an exposed deletion is not done only
/// when a cycle of containers left another container's Zombie in `slot`
/// (see [`reduce_zombie`]), which stays.
fn delete_slot<K: Kernel + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    exposed: bool,
) -> Result<(), Preempted> {
    let (done, cleanup) = finalise_slot(k, slot, exposed)?;
    if done {
        empty_slot(k, slot, cleanup);
    }
    Ok(())
}

/// Finalises the capability in `slot` until the slot can be emptied:
/// seL4's `finaliseSlot`. Returns whether it can, and the cleanup to pass
/// on. `false` for a nested deletion that leaves a Zombie in its own
/// container's slot 0, and for a deletion that a cycle of containers left
/// holding another container's Zombie (see [`reduce_zombie`]).
fn finalise_slot<K: Kernel + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    immediate: bool,
) -> Result<(bool, Option<Cap>), Preempted> {
    loop {
        let cap = k.load(slot).cap;
        if cap.is_null() {
            return Ok((true, None));
        }
        let last = cdt::is_final(k, slot);
        let (remainder, cleanup) = finalise_cap(k, cap, last);
        if removable(remainder, slot) {
            return Ok((true, cleanup));
        }
        let mut s = k.load(slot);
        s.cap = remainder;
        k.store(slot, s);
        // seL4's `capCyclicZombie`. Without overlapping objects no nested
        // deletion reaches a Zombie in its own slot 0; kept as seL4 has it.
        if !immediate && remainder.object() == slot.get() {
            return Ok((false, cleanup));
        }
        if !reduce_zombie(k, slot, immediate)? {
            return Ok((false, None));
        }
        k.preempt()?;
    }
}

/// What deleting `cap` leaves in its slot: Null, or a Zombie for the last
/// capability to a CNode or TCB. Calls the kernel's finalise hook for every
/// type but CNode and Zombie.
fn finalise_cap<K: Kernel + ?Sized>(k: &mut K, cap: Cap, last: bool) -> (Cap, Option<Cap>) {
    match cap.cap_type() {
        CapType::Null => (Cap::NULL, None),
        CapType::Zombie => (cap, None),
        CapType::CNode if last => (
            Cap::zombie(cap.object(), cap.size_bits(), 1 << cap.radix(), false),
            None,
        ),
        CapType::CNode => (Cap::NULL, None),
        CapType::Tcb => {
            let cleanup = k.finalise(cap, last);
            debug_assert!(cleanup.is_none(), "a TCB's finalisation has no cleanup");
            if last {
                (Cap::zombie(cap.object(), TCB_BITS, TCB_SLOTS, true), None)
            } else {
                (Cap::NULL, None)
            }
        }
        _ => (Cap::NULL, k.finalise(cap, last)),
    }
}

/// Whether a finalise remainder lets the slot empty: Null, or a Zombie with
/// nothing left to clear, or only itself in its own container's slot 0.
fn removable(remainder: Cap, slot: SlotAddr) -> bool {
    match remainder.cap_type() {
        CapType::Zombie => {
            let n = remainder.zombie_slots();
            n == 0 || (n == 1 && remainder.object() == slot.get())
        }
        _ => true,
    }
}

/// One step of clearing the container of the Zombie in `slot`: seL4's
/// `reduceZombie`. Exposed: deletes the highest slot left and counts it.
/// Nested: swaps the Zombie into the container's slot 0, so the caller goes
/// on with the capability that was there.
///
/// Returns `false` if the step left another container's Zombie in `slot`;
/// the deletion then ends without emptying `slot`. Only a cycle does that:
/// `slot` is slot 0 of a container `D` whose last capability lies in the
/// container being cleared, so the nested deletion of that capability swaps
/// `D`'s Zombie, with `D`'s derivation node, into `slot` (seL4's "Expected
/// new Zombie to be self-referential"). seL4 then clears `D` in this
/// deletion, but a restarted call could not resume that. No user can name
/// `slot`, so only a revoke gets here, and a restarted revoke finds its work
/// only among the revoked capability's descendants, which `D`'s Zombie need
/// not be: a preemption point while clearing `D` would leave it half
/// cleared, and the outcome would depend on where the interrupt fell.
/// Instead `D` always stays, detached in its own slot 0, as every nested
/// deletion leaves a container, until a deletion that reaches its Zombie
/// clears it (`docs/design.md`, "Deletion and finalisation", step 3).
fn reduce_zombie<K: Kernel + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    immediate: bool,
) -> Result<bool, Preempted> {
    let zombie = k.load(slot).cap;
    let container = zombie.object();
    let n = zombie.zombie_slots();
    debug_assert!(zombie.cap_type() == CapType::Zombie && n > 0);
    let base = SlotAddr::new(container).expect("a Zombie names a slot address");
    if immediate {
        let end = base.offset(n - 1);
        delete_slot(k, end, false)?;
        let now = k.load(slot).cap;
        match now.cap_type() {
            CapType::Null => {}
            CapType::Zombie
                if now.object() == container
                    && now.zombie_slots() == n
                    && now.zombie_is_tcb() == zombie.zombie_is_tcb() =>
            {
                debug_assert!(k.load(end).cap.is_null());
                let mut s = k.load(slot);
                s.cap = now.with_zombie_slots(n - 1);
                k.store(slot, s);
            }
            CapType::Zombie => {
                // The nested deletion swapped a self-referential Zombie here.
                debug_assert!(now.object() == slot.get() && container != slot.get());
                return Ok(false);
            }
            _ => unreachable!("clearing a container left a non-Zombie in its slot"),
        }
    } else {
        debug_assert!(container != slot.get());
        let first = k.load(base).cap;
        cdt::swap_slots(k, first, base, zombie, slot);
    }
    Ok(true)
}

/// Empties `slot` and unlinks it, then passes on the cleanup: seL4's
/// `emptySlot`.
fn empty_slot<K: Kernel + ?Sized>(k: &mut K, slot: SlotAddr, cleanup: Option<Cap>) {
    if k.load(slot).cap.is_null() {
        return;
    }
    cdt::unlink_and_clear(k, slot);
    if let Some(c) = cleanup {
        k.after_delete(c);
    }
}
