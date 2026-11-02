//! Decoding and performing kernel invocations: `Untyped_Retype` and the
//! CNode methods (`docs/abi.md`, "Untyped invocations", "CNode invocations",
//! "Error detail words" and "Invocation label index"; `docs/design.md`,
//! "System-call dispatch").
//!
//! The caller has looked up the invoked capability's slot and each extra
//! capability, as a thread's `syscall` does. [`invoke`] checks the label and
//! the message length, resolves every slot argument and performs the call
//! through [`crate::cnode`] and [`crate::untyped`], which check what the
//! slots hold. Errors come in the order `docs/abi.md` lists them, and an
//! attempt that returns one has changed nothing.
//!
//! Revoke, Delete and a retype's reset are preemptible. [`Preempted`] means
//! the work done so far is kept and consistent; the caller restarts the call
//! later from the same arguments, looking up the invoked and extra
//! capabilities again and decoding the message again, as a thread's
//! restarted `syscall` does. The restarted call goes on where the last one
//! stopped, unless its work destroyed a CNode on the path that named its slot
//! (`docs/design.md`, "Slot operations"): its lookup then fails, and it
//! returns that failure.
//!
//! # Orders the ABI leaves open
//!
//! - An empty or Zombie invoked slot is `InvalidCapability` 0 whatever the
//!   label, as in seL4: the label means nothing without a type.
//! - The label comes before the message length (`IllegalOperation` before
//!   `TruncatedMessage`), as in seL4. Labels marked for a later milestone
//!   (`CNode_CancelBadgedSends`, `CNode_SaveCaller`) are `IllegalOperation`
//!   at once, like the reserved ones, without a length check or a lookup.
//! - `Untyped_Retype` with `node_depth` 0 and a `root` that is not a CNode
//!   is `FailedLookup` 0, `InvalidRoot`, the row `docs/abi.md` lists first,
//!   whatever the depth. seL4 skips the root check at depth 0 and reports
//!   `MissingCapability` with 0 bits left, the next row.
//! - In Copy, Mint, Move and Mutate the source's `depth` range check is part
//!   of the source lookup, so it comes after `DeleteFirst` and after an
//!   `InvalidRoot` `src_root`, as `docs/abi.md` places the source lookup.
//! - Rotate looks up the destination, then the source, then the pivot, each
//!   with its own root and `depth` checks: seL4's order.
//! - Within one `IllegalOperation` row, and between the rows that give the
//!   same error (an empty source and an empty pivot; a capability that
//!   cannot be copied, a bad data word and the depth limit), which cause wins
//!   cannot be seen.

use crate::cap::{Cap, CapType};
use crate::cnode;
use crate::cspace;
use crate::error::{LookupFailure, SyscallError};
use crate::kernel::{Kernel, Preempted};
use crate::slot::{SlotAddr, SlotMemory};
use crate::untyped::{self, RetypeArgs, RetypeError};
use crate::vspace::{self, PagingStore};

/// Invocation labels decoded here (`docs/abi.md`, "Invocation label index").
/// Untyped's are `0x01` to `0x0F`, CNode's `0x10` to `0x1F`; any label the
/// invoked type does not decode is `IllegalOperation`.
pub mod label {
    pub const UNTYPED_RETYPE: u64 = 0x01;
    pub const CNODE_REVOKE: u64 = 0x10;
    pub const CNODE_DELETE: u64 = 0x11;
    /// M6; `IllegalOperation` until then.
    pub const CNODE_CANCEL_BADGED_SENDS: u64 = 0x12;
    pub const CNODE_COPY: u64 = 0x13;
    pub const CNODE_MINT: u64 = 0x14;
    pub const CNODE_MOVE: u64 = 0x15;
    pub const CNODE_MUTATE: u64 = 0x16;
    pub const CNODE_ROTATE: u64 = 0x17;
    /// M6; `IllegalOperation` until then.
    pub const CNODE_SAVE_CALLER: u64 = 0x18;
}

/// An extra capability of a message, as the caller's capability lookup of
/// `caps_or_badges[i]` found it: the capability and its slot. The slot may
/// be empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ExtraCap {
    pub cap: Cap,
    pub slot: SlotAddr,
}

impl ExtraCap {
    /// The capability in `slot` now.
    pub fn load<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr) -> ExtraCap {
        ExtraCap {
            cap: mem.load(slot).cap,
            slot,
        }
    }
}

/// A decoded message: the `MessageInfo` label, the message registers
/// (`mrs.len()` is the message length, MR0 first) and the extra
/// capabilities (`extra_caps.len()` is `extra_caps`).
#[derive(Clone, Copy, Debug)]
pub struct Message<'a> {
    pub label: u64,
    pub mrs: &'a [u64],
    pub extra_caps: &'a [ExtraCap],
}

impl Message<'_> {
    /// MR0 to MR`N - 1`, if the message has them and at least `caps` extra
    /// capabilities: each method's one length check, before any lookup.
    fn args<const N: usize>(&self, caps: usize) -> Result<[u64; N], SyscallError> {
        match self.mrs.first_chunk::<N>() {
            Some(words) if self.extra_caps.len() >= caps => Ok(*words),
            _ => Err(SyscallError::TruncatedMessage),
        }
    }

    /// Extra capability `i`'s capability; [`Message::args`] checked that it
    /// is there.
    fn cap(&self, i: usize) -> Cap {
        self.extra_caps[i].cap
    }
}

/// The kernel's reply to a successful invocation: label 0 and `length`
/// result words in MR0 and up. No M4 invocation has results; M5's
/// (`TCB_ReadRegisters`, for example) add the words.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Reply {
    pub length: usize,
}

impl Reply {
    /// No results.
    pub const EMPTY: Reply = Reply { length: 0 };
}

/// Why an invocation did not complete.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum InvokeError {
    /// It failed and changed nothing; the kernel replies with the error's
    /// code and detail words ([`SyscallError::code`],
    /// [`SyscallError::detail`]).
    Error(SyscallError),
    /// A preemption point found an interrupt pending. The work so far is
    /// kept; restart the call from the same arguments.
    Preempted,
}

impl From<SyscallError> for InvokeError {
    fn from(e: SyscallError) -> InvokeError {
        InvokeError::Error(e)
    }
}

impl From<Preempted> for InvokeError {
    fn from(_: Preempted) -> InvokeError {
        InvokeError::Preempted
    }
}

impl From<RetypeError> for InvokeError {
    fn from(e: RetypeError) -> InvokeError {
        match e {
            RetypeError::Error(e) => InvokeError::Error(e),
            RetypeError::Preempted => InvokeError::Preempted,
        }
    }
}

/// Decodes and performs the invocation `msg` of the capability in `slot`.
///
/// An empty slot or a Zombie is `InvalidCapability` 0. An Untyped decodes
/// `Untyped_Retype`, a CNode its methods, a TCB its methods
/// ([`crate::tcb::invoke`]), a Frame or a PDPT, page directory or page
/// table its map and unmap methods ([`vspace::invoke`]); any other label,
/// and every other capability type until its milestone, is
/// `IllegalOperation`.
pub fn invoke<K: Kernel + PagingStore + crate::tcb::Threads + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    let cap = k.load(slot).cap;
    match cap.cap_type() {
        CapType::Null | CapType::Zombie => Err(SyscallError::InvalidCapability(0).into()),
        CapType::Untyped => untyped_invocation(k, slot, msg),
        CapType::CNode => cnode_invocation(k, cap, msg),
        CapType::Tcb => crate::tcb::invoke(k, slot, msg),
        CapType::Frame | CapType::PageTable | CapType::PageDirectory | CapType::Pdpt => {
            vspace::invoke(k, slot, msg)
        }
        _ => Err(SyscallError::IllegalOperation.into()),
    }
}

/// `Untyped_Retype` (`docs/abi.md`): MR0 `type`, MR1 `size_bits`, MR2
/// `node_index`, MR3 `node_depth`, MR4 `node_offset`, MR5 `num_objects`;
/// extra capability 0 `root`.
fn untyped_invocation<K: Kernel + ?Sized>(
    k: &mut K,
    untyped: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    if msg.label != label::UNTYPED_RETYPE {
        return Err(SyscallError::IllegalOperation.into());
    }
    let [
        object_type,
        size_bits,
        node_index,
        node_depth,
        node_offset,
        num_objects,
    ] = msg.args(1)?;
    let root = msg.cap(0);
    untyped::check_object(object_type, size_bits)?;
    // `node_depth` is checked before the root, unlike a CNode method's
    // `depth` (`docs/design.md`, "Memory and retype", Compared with seL4).
    if node_depth > 64 {
        return Err(SyscallError::RangeError { min: 0, max: 64 }.into());
    }
    if root.cap_type() != CapType::CNode {
        return Err(SyscallError::FailedLookup {
            source: false,
            failure: LookupFailure::InvalidRoot,
        }
        .into());
    }
    let dest = if node_depth == 0 {
        root
    } else {
        let at = cspace::lookup_slot(k, root, node_index, node_depth, false)?;
        k.load(at).cap
    };
    let args = RetypeArgs {
        object_type,
        size_bits,
        node_offset,
        num_objects,
    };
    untyped::retype(k, untyped, dest, args)?;
    Ok(Reply::EMPTY)
}

/// The CNode methods. The invoked CNode capability is the root of the first
/// slot argument, MR0 and MR1.
fn cnode_invocation<K: Kernel + ?Sized>(
    k: &mut K,
    cnode: Cap,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    match msg.label {
        label::CNODE_REVOKE => {
            let [index, depth] = msg.args(0)?;
            let at = cspace::lookup_slot(k, cnode, index, depth, false)?;
            cnode::revoke(k, at)?;
        }
        label::CNODE_DELETE => {
            let [index, depth] = msg.args(0)?;
            let at = cspace::lookup_slot(k, cnode, index, depth, false)?;
            cnode::delete(k, at)?;
        }
        label::CNODE_COPY => {
            let [dest_index, dest_depth, src_index, src_depth, rights] = msg.args(1)?;
            let (src, dst) = slots_for_copy(
                k,
                cnode,
                (dest_index, dest_depth),
                msg.cap(0),
                (src_index, src_depth),
            )?;
            cnode::copy(k, src, dst, rights)?;
        }
        label::CNODE_MINT => {
            let [dest_index, dest_depth, src_index, src_depth, rights, data] = msg.args(1)?;
            let (src, dst) = slots_for_copy(
                k,
                cnode,
                (dest_index, dest_depth),
                msg.cap(0),
                (src_index, src_depth),
            )?;
            cnode::mint(k, src, dst, rights, data)?;
        }
        label::CNODE_MOVE => {
            let [dest_index, dest_depth, src_index, src_depth] = msg.args(1)?;
            let (src, dst) = slots_for_copy(
                k,
                cnode,
                (dest_index, dest_depth),
                msg.cap(0),
                (src_index, src_depth),
            )?;
            cnode::move_cap(k, src, dst)?;
        }
        label::CNODE_MUTATE => {
            let [dest_index, dest_depth, src_index, src_depth, data] = msg.args(1)?;
            let (src, dst) = slots_for_copy(
                k,
                cnode,
                (dest_index, dest_depth),
                msg.cap(0),
                (src_index, src_depth),
            )?;
            cnode::mutate(k, src, dst, data)?;
        }
        label::CNODE_ROTATE => {
            let [
                dest_index,
                dest_depth,
                dest_data,
                pivot_index,
                pivot_depth,
                pivot_data,
                src_index,
                src_depth,
            ] = msg.args(2)?;
            let dst = cspace::lookup_slot(k, cnode, dest_index, dest_depth, false)?;
            let src = cspace::lookup_slot(k, msg.cap(1), src_index, src_depth, true)?;
            let pivot = cspace::lookup_slot(k, msg.cap(0), pivot_index, pivot_depth, true)?;
            cnode::rotate(k, dst, dest_data, pivot, pivot_data, src)?;
        }
        // Other labels, `CNode_CancelBadgedSends` and `CNode_SaveCaller`
        // until M6 included.
        _ => return Err(SyscallError::IllegalOperation.into()),
    }
    Ok(Reply::EMPTY)
}

/// The slot lookups Copy, Mint, Move and Mutate share, in the order
/// `docs/abi.md` lists their errors: the destination from the invoked
/// CNode, `DeleteFirst` if it is not empty, then the source from
/// `src_root`. Returns `(src, dst)`.
fn slots_for_copy<M: SlotMemory + ?Sized>(
    mem: &M,
    cnode: Cap,
    (dest_index, dest_depth): (u64, u64),
    src_root: Cap,
    (src_index, src_depth): (u64, u64),
) -> Result<(SlotAddr, SlotAddr), SyscallError> {
    let dst = cspace::lookup_slot(mem, cnode, dest_index, dest_depth, false)?;
    if !mem.load(dst).cap.is_null() {
        return Err(SyscallError::DeleteFirst);
    }
    let src = cspace::lookup_slot(mem, src_root, src_index, src_depth, true)?;
    Ok((src, dst))
}

#[cfg(test)]
mod redteam;
#[cfg(test)]
mod tests;
