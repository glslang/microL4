//! Capability transfer (`docs/design.md`, "Capability transfer";
//! `docs/abi.md`, "Capability transfer"; ADR 0017): the capabilities a
//! message names in `caps_or_badges`, unwrapped to badges or copied into
//! the receiver's one receive slot.
//!
//! Capabilities move only if the sender's capability has Grant (for a
//! reply, the reply capability's), the sender has a readable IPC buffer and
//! names at least one, and the receiver has a writable IPC buffer. Then,
//! as seL4's `doNormalTransfer` and `transferCaps` do:
//!
//! 1. Every pointer is looked up again in the sender's CSpace, with all 64
//!    bits. If one fails, nothing moves, not even those named before it. A
//!    pointer that reaches an empty slot has not failed.
//! 2. The receive slot is found once: `receive_cnode` resolved in the
//!    receiver's CSpace must be a CNode capability, `receive_index` with
//!    `receive_depth` bits must name a slot from it, and the slot must be
//!    empty. Otherwise there is none.
//! 3. In order, a capability to the endpoint the message goes through
//!    (never for a reply) is unwrapped, whatever its rights: its badge goes
//!    to the receiver's `caps_or_badges[i]` and bit `i` of
//!    `caps_unwrapped` is set. Any other is copied into the receive slot as
//!    `CNode_Copy` copies, with its rights and badge, if the slot is still
//!    free and the copy is allowed ([`cnode::copy`]: `derive` and the
//!    depth limit). The first that can be neither ends the loop.
//! 4. The receiver's `extra_caps` counts the capabilities processed before
//!    the end.
//!
//! Neither side is told about a failure. Nothing here can fail, block or
//! preempt; the work is bounded by three lookups, one receive-slot lookup
//! and one copy.

use crate::cap::{Rights, TCB_SLOT_CSPACE};
use crate::cnode;
use crate::cspace;
use crate::slot::SlotAddr;
use crate::tcb::{self, EpRef, TcbRef};

use super::endpoint::{EndpointCap, IpcEnv};
use super::message::{MSG_MAX_EXTRA_CAPS, MessageInfo, word};

/// What a transfer delivered: the receiver's `extra_caps` and
/// `caps_unwrapped`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct Moved {
    pub extra_caps: u64,
    pub caps_unwrapped: u64,
}

impl Moved {
    /// Nothing processed: no capability moved or was unwrapped.
    pub const NONE: Moved = Moved {
        extra_caps: 0,
        caps_unwrapped: 0,
    };
}

/// A copy keeps every right of its source.
const KEEP_RIGHTS: u64 = Rights::ALL.0 as u64;

/// Moves the capabilities `s`'s message names to `r` (steps 1 to 4 of the
/// module docs). `info` is `s`'s `MessageInfo`, `grant` the Grant of the
/// capability `s` sent with (a queued sender's as it recorded it, a
/// reply's from its reply capability), and `ep` the endpoint the message
/// goes through, `None` for a reply. `s` holds no fault: fault messages and
/// fault replies move no capabilities. Returns what `r`'s `MessageInfo`
/// reports; `r`'s registers are its caller's to write.
pub(super) fn transfer_caps<E: IpcEnv + ?Sized>(
    e: &mut E,
    s: TcbRef,
    r: TcbRef,
    info: MessageInfo,
    grant: bool,
    ep: Option<EpRef>,
) -> Moved {
    debug_assert!(e.fault(s).is_none(), "a fault message moves no capability");
    let n = info.extra_caps() as usize;
    if !grant
        || n == 0
        || tcb::buffer_word(e, s, 0, false).is_none()
        || tcb::buffer_word(e, r, 0, true).is_none()
    {
        return Moved::NONE;
    }
    let Some(sources) = lookup_extra_caps(e, s, n) else {
        return Moved::NONE;
    };
    let mut dest = receive_slot(e, r);
    let mut moved = Moved::NONE;
    for (i, &src) in sources[..n].iter().enumerate() {
        let src = src.expect("every pointer up to extra_caps was looked up");
        let cap = e.load(src).cap;
        match EndpointCap::from_cap(&cap) {
            Some(c) if Some(c.ep) == ep => {
                let at = tcb::buffer_word(e, r, word::CAPS_OR_BADGES + i, true)
                    .expect("a writable buffer");
                e.write_buffer_word(at, c.badge);
                moved.caps_unwrapped |= 1 << i;
            }
            // One copy at most: the slot is used once taken.
            _ => {
                let Some(d) = dest.take() else { break };
                if cnode::copy(e, src, d, KEEP_RIGHTS).is_err() {
                    break;
                }
            }
        }
        moved.extra_caps += 1;
    }
    moved
}

/// Step 1: the slots `s`'s first `n` pointers in `caps_or_badges` reach
/// now, from its CSpace root with all 64 bits; `None` if any does not
/// resolve. `s` has a readable IPC buffer.
fn lookup_extra_caps<E: IpcEnv + ?Sized>(
    e: &E,
    s: TcbRef,
    n: usize,
) -> Option<[Option<SlotAddr>; MSG_MAX_EXTRA_CAPS]> {
    let root = e.load(s.slot(TCB_SLOT_CSPACE)).cap;
    let mut slots = [None; MSG_MAX_EXTRA_CAPS];
    for (i, slot) in slots[..n].iter_mut().enumerate() {
        let at =
            tcb::buffer_word(e, s, word::CAPS_OR_BADGES + i, false).expect("a readable buffer");
        *slot = Some(cspace::lookup_cap(e, root, e.read_buffer_word(at)).ok()?);
    }
    Some(slots)
}

/// Step 2: `r`'s receive slot, if its `receive_cnode`, `receive_index` and
/// `receive_depth` name an empty one (seL4 `getReceiveSlots`). `r` has a
/// writable, and so readable, IPC buffer.
fn receive_slot<E: IpcEnv + ?Sized>(e: &E, r: TcbRef) -> Option<SlotAddr> {
    let read = |w: usize| {
        let at = tcb::buffer_word(e, r, w, false).expect("a readable buffer");
        e.read_buffer_word(at)
    };
    let root = e.load(r.slot(TCB_SLOT_CSPACE)).cap;
    let at = cspace::lookup_cap(e, root, read(word::RECEIVE_CNODE)).ok()?;
    // `lookup_slot` refuses a root that is not a CNode capability.
    let cnode = e.load(at).cap;
    let slot = cspace::lookup_slot(
        e,
        cnode,
        read(word::RECEIVE_INDEX),
        read(word::RECEIVE_DEPTH),
        false,
    )
    .ok()?;
    e.load(slot).cap.is_null().then_some(slot)
}

#[cfg(test)]
mod tests;
