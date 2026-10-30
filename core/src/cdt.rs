//! The derivation list (`docs/design.md`, "Derivation tracking";
//! ADR 0012).
//!
//! Each derivation tree is a doubly linked list of slots in preorder. A slot
//! records its tree `depth`, whether it is `original` (may have children),
//! and `low`, the smallest depth among itself and the deleted slots that
//! stood between it and its predecessor. The descendants of `a` are the run
//! of slots after `a` whose `low` exceeds `a`'s depth, so nothing here looks
//! at capability types except [`is_final`].

use crate::cap::{Cap, MAX_DERIVATION_DEPTH};
use crate::kernel::Kernel;
use crate::slot::{Node, Slot, SlotAddr, SlotMemory};

/// A child would be deeper than [`MAX_DERIVATION_DEPTH`].
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DepthExceeded;

/// Puts `cap` in the empty slot `at` as the root of a list of its own:
/// depth 0, original. Boot capabilities and reply masters are roots.
pub fn insert_root<M: SlotMemory + ?Sized>(mem: &mut M, at: SlotAddr, cap: Cap) {
    debug_assert!(mem.load(at).cap.is_null());
    mem.store(
        at,
        Slot {
            cap,
            node: Node::new(true, 0, 0),
        },
    );
}

/// Puts `cap`, derived from the capability in `src`, in the empty slot `dst`,
/// right after `src`. It is a child of `src` if `src` is original, otherwise
/// a sibling sharing `src`'s parent. `original` says whether the new
/// capability may have children. This is the one function that makes a
/// child, so it alone checks [`MAX_DERIVATION_DEPTH`].
pub fn insert_derived<M: SlotMemory + ?Sized>(
    mem: &mut M,
    src: SlotAddr,
    dst: SlotAddr,
    cap: Cap,
    original: bool,
) -> Result<(), DepthExceeded> {
    debug_assert!(src != dst && mem.load(dst).cap.is_null());
    let s = mem.load(src);
    debug_assert!(!s.cap.is_null());
    let depth = if s.node.original() {
        s.node.depth() + 1
    } else {
        s.node.depth()
    };
    if depth > MAX_DERIVATION_DEPTH {
        return Err(DepthExceeded);
    }
    let next = s.node.next();
    let node = Node::new(original, depth, depth)
        .with_prev(Some(src))
        .with_next(next);
    mem.store(dst, Slot { cap, node });
    mem.store(
        src,
        Slot {
            cap: s.cap,
            node: s.node.with_next(Some(dst)),
        },
    );
    if let Some(n) = next {
        set_prev(mem, n, Some(dst));
    }
    Ok(())
}

/// Whether a child of the capability in `slot` would exceed
/// [`MAX_DERIVATION_DEPTH`]. Siblings never do.
pub fn child_too_deep<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr) -> bool {
    let n = mem.load(slot).node;
    n.original() && n.depth() >= MAX_DERIVATION_DEPTH
}

/// Whether the capability in `slot` has children.
pub fn has_children<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr) -> bool {
    let s = mem.load(slot);
    match s.node.next() {
        Some(n) => mem.load(n).node.low() > s.node.depth(),
        None => false,
    }
}

/// The first descendant of the capability in `slot`, if any: the next slot,
/// when its `low` exceeds `slot`'s depth.
pub fn first_child<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr) -> Option<SlotAddr> {
    let s = mem.load(slot);
    let n = s.node.next()?;
    (mem.load(n).node.low() > s.node.depth()).then_some(n)
}

/// Whether the capability in `slot` is the last one to its object. Every
/// derivation lands next to its source, so all capabilities to one object
/// are adjacent and only the two list neighbours need checking.
pub fn is_final<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr) -> bool {
    let s = mem.load(slot);
    [s.node.prev(), s.node.next()]
        .into_iter()
        .flatten()
        .all(|a| !mem.load(a).cap.same_object(&s.cap))
}

/// The nearest ancestor of the capability in `slot`: the closest earlier
/// slot whose depth is below the `low` of every slot from it to `slot`.
/// Linear in the distance; for tests and debugging.
pub fn parent<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr) -> Option<SlotAddr> {
    let s = mem.load(slot);
    let mut low = s.node.low();
    let mut cur = s.node.prev();
    while let Some(p) = cur {
        let ps = mem.load(p);
        if ps.node.depth() < low {
            return Some(p);
        }
        low = low.min(ps.node.low());
        cur = ps.node.prev();
    }
    None
}

/// Checks one slot's list invariants: an empty slot has no node; otherwise
/// `low <= depth <= MAX_DERIVATION_DEPTH` and both neighbours link back.
pub fn check_slot<M: SlotMemory + ?Sized>(mem: &M, slot: SlotAddr) -> Result<(), &'static str> {
    let s = mem.load(slot);
    if s.cap.is_null() {
        return if s.node == Node::EMPTY {
            Ok(())
        } else {
            Err("empty slot with a derivation node")
        };
    }
    if s.node.low() > s.node.depth() || s.node.depth() > MAX_DERIVATION_DEPTH {
        return Err("low or depth out of range");
    }
    if let Some(p) = s.node.prev() {
        if mem.load(p).node.next() != Some(slot) {
            return Err("prev does not link back");
        }
    }
    if let Some(n) = s.node.next() {
        if mem.load(n).node.prev() != Some(slot) {
            return Err("next does not link back");
        }
    }
    Ok(())
}

/// Removes the slot from its list and empties it. Its `low` passes to the
/// next slot, so the deleted capability's children fall to its nearest
/// surviving ancestor.
pub(crate) fn unlink_and_clear<M: SlotMemory + ?Sized>(mem: &mut M, slot: SlotAddr) {
    let node = mem.load(slot).node;
    if let Some(p) = node.prev() {
        set_next(mem, p, node.next());
    }
    if let Some(n) = node.next() {
        let mut ns = mem.load(n);
        let low = ns.node.low().min(node.low());
        ns.node = ns.node.with_prev(node.prev()).with_low(low);
        mem.store(n, ns);
    }
    mem.store(slot, Slot::EMPTY);
}

/// Moves the capability in `src` to the empty slot `dst` as `cap` (the same
/// capability, or it with new data), with its node and place in the list.
/// `src` is left empty. Calls [`Kernel::moved`].
pub fn move_slot<K: Kernel + ?Sized>(k: &mut K, cap: Cap, src: SlotAddr, dst: SlotAddr) {
    debug_assert!(src != dst && k.load(dst).cap.is_null());
    let node = k.load(src).node;
    k.store(dst, Slot { cap, node });
    k.store(src, Slot::EMPTY);
    if let Some(p) = node.prev() {
        set_next(k, p, Some(dst));
    }
    if let Some(n) = node.next() {
        set_prev(k, n, Some(dst));
    }
    k.moved(cap, src, dst);
}

/// Swaps two slots: `cap1`, the capability from `slot1`, goes to `slot2`
/// and `cap2` to `slot1`, each with its node, so the list order is
/// unchanged. Either slot may be empty. A port of seL4's `cteSwap`, which is
/// correct when the slots are list neighbours. Calls [`Kernel::moved`] for
/// each capability that moves.
pub fn swap_slots<K: Kernel + ?Sized>(
    k: &mut K,
    cap1: Cap,
    slot1: SlotAddr,
    cap2: Cap,
    slot2: SlotAddr,
) {
    debug_assert!(slot1 != slot2);
    let n1 = k.load(slot1).node;
    let s2 = k.load(slot2);
    k.store(
        slot1,
        Slot {
            cap: cap2,
            node: n1,
        },
    );
    k.store(
        slot2,
        Slot {
            cap: cap1,
            node: s2.node,
        },
    );
    if let Some(p) = n1.prev() {
        set_next(k, p, Some(slot2));
    }
    if let Some(n) = n1.next() {
        set_prev(k, n, Some(slot2));
    }
    let n2 = k.load(slot2).node;
    k.store(
        slot1,
        Slot {
            cap: cap2,
            node: n2,
        },
    );
    k.store(
        slot2,
        Slot {
            cap: cap1,
            node: n1,
        },
    );
    if let Some(p) = n2.prev() {
        set_next(k, p, Some(slot1));
    }
    if let Some(n) = n2.next() {
        set_prev(k, n, Some(slot1));
    }
    if !cap1.is_null() {
        k.moved(cap1, slot1, slot2);
    }
    if !cap2.is_null() {
        k.moved(cap2, slot2, slot1);
    }
}

fn set_next<M: SlotMemory + ?Sized>(mem: &mut M, at: SlotAddr, next: Option<SlotAddr>) {
    let mut s = mem.load(at);
    s.node = s.node.with_next(next);
    mem.store(at, s);
}

fn set_prev<M: SlotMemory + ?Sized>(mem: &mut M, at: SlotAddr, prev: Option<SlotAddr>) {
    let mut s = mem.load(at);
    s.node = s.node.with_prev(prev);
    mem.store(at, s);
}
