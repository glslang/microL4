//! Capability slots and how `core/` reaches them.
//!
//! A slot is 32 bytes: a [`Cap`] and its derivation [`Node`]
//! (`docs/design.md`, "Slots"). `core/` never dereferences an address: it
//! loads and stores whole slots by value through [`SlotMemory`], which the
//! kernel implements over the direct map and the host tests over fake memory.

use core::num::NonZeroU64;

use crate::cap::{Cap, MAX_DERIVATION_DEPTH, SLOT_SIZE};

/// Physical addresses a slot link can hold: bits 5 to 51.
const LINK_MASK: u64 = ((1 << 52) - 1) & !(SLOT_SIZE - 1);

/// The physical address of a slot: non-zero, 32-byte aligned, below `2^52`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SlotAddr(NonZeroU64);

impl SlotAddr {
    /// The slot at `paddr`, if it is a valid slot address.
    pub const fn new(paddr: u64) -> Option<SlotAddr> {
        if paddr & !LINK_MASK != 0 {
            return None;
        }
        match NonZeroU64::new(paddr) {
            Some(a) => Some(SlotAddr(a)),
            None => None,
        }
    }

    /// The physical address.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The slot `index` slots after this one. Panics if the result is not a
    /// slot address, which the callers' bounds rule out.
    pub fn offset(self, index: u64) -> SlotAddr {
        index
            .checked_mul(SLOT_SIZE)
            .and_then(|off| self.get().checked_add(off))
            .and_then(SlotAddr::new)
            .expect("slot address out of range")
    }
}

/// A slot's place in its derivation list.
///
/// | Word | Bits | Field |
/// | --- | --- | --- |
/// | 0 | 0 | `original`: the capability may have children |
/// | 0 | 5 to 51 | `prev` |
/// | 0 | 52 to 63 | `depth` |
/// | 1 | 5 to 51 | `next` |
/// | 1 | 52 to 63 | `low` |
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct Node {
    w0: u64,
    w1: u64,
}

impl Node {
    /// The node of an empty slot: no links, depth 0.
    pub const EMPTY: Node = Node { w0: 0, w1: 0 };

    /// A node with no links.
    pub const fn new(original: bool, depth: u32, low: u32) -> Node {
        debug_assert!(depth <= MAX_DERIVATION_DEPTH && low <= depth);
        Node {
            w0: (original as u64) | ((depth as u64) << 52),
            w1: (low as u64) << 52,
        }
    }

    /// Whether the capability may have children.
    pub const fn original(&self) -> bool {
        self.w0 & 1 == 1
    }

    /// The previous slot in the list.
    pub const fn prev(&self) -> Option<SlotAddr> {
        SlotAddr::new(self.w0 & LINK_MASK)
    }

    /// The next slot in the list.
    pub const fn next(&self) -> Option<SlotAddr> {
        SlotAddr::new(self.w1 & LINK_MASK)
    }

    /// The slot's depth in its derivation tree, counting deleted ancestors.
    pub const fn depth(&self) -> u32 {
        (self.w0 >> 52) as u32
    }

    /// The smallest depth among this slot and the deleted slots between it
    /// and its predecessor.
    pub const fn low(&self) -> u32 {
        (self.w1 >> 52) as u32
    }

    /// This node with `prev` replaced.
    pub const fn with_prev(self, prev: Option<SlotAddr>) -> Node {
        Node {
            w0: (self.w0 & !LINK_MASK) | link(prev),
            w1: self.w1,
        }
    }

    /// This node with `next` replaced.
    pub const fn with_next(self, next: Option<SlotAddr>) -> Node {
        Node {
            w0: self.w0,
            w1: (self.w1 & !LINK_MASK) | link(next),
        }
    }

    /// This node with `low` replaced; `low` must not exceed the depth.
    pub const fn with_low(self, low: u32) -> Node {
        debug_assert!(low <= self.depth());
        Node {
            w0: self.w0,
            w1: (self.w1 & LINK_MASK) | ((low as u64) << 52),
        }
    }
}

const fn link(a: Option<SlotAddr>) -> u64 {
    match a {
        Some(a) => a.get(),
        None => 0,
    }
}

/// A capability slot, 32 bytes. The all-zero slot is empty.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Default)]
#[repr(C)]
pub struct Slot {
    pub cap: Cap,
    pub node: Node,
}

const _: () = assert!(core::mem::size_of::<Slot>() == SLOT_SIZE as usize);

impl Slot {
    /// An empty slot.
    pub const EMPTY: Slot = Slot {
        cap: Cap::NULL,
        node: Node::EMPTY,
    };

    /// The four words as they lie in memory.
    pub const fn to_words(self) -> [u64; 4] {
        [self.cap.data, self.cap.header, self.node.w0, self.node.w1]
    }

    /// A slot from the four words in memory.
    pub const fn from_words(w: [u64; 4]) -> Slot {
        Slot {
            cap: Cap {
                data: w[0],
                header: w[1],
            },
            node: Node { w0: w[2], w1: w[3] },
        }
    }
}

/// Loads and stores slots by value. The kernel implements it in `arch` over
/// the direct map; host tests over fake memory.
pub trait SlotMemory {
    /// The slot at `at`.
    fn load(&self, at: SlotAddr) -> Slot;
    /// Overwrites the slot at `at`.
    fn store(&mut self, at: SlotAddr, slot: Slot);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn slot_addresses() {
        assert_eq!(SlotAddr::new(0), None);
        assert_eq!(SlotAddr::new(0x10), None);
        assert_eq!(SlotAddr::new(1 << 52), None);
        let a = SlotAddr::new(0x1000).unwrap();
        assert_eq!(a.offset(3).get(), 0x1060);
    }

    #[test]
    fn node_fields() {
        let a = SlotAddr::new(0x1000);
        let b = SlotAddr::new(0x000F_FFFF_FFFF_FFE0);
        let n = Node::new(true, 4095, 7).with_prev(a).with_next(b);
        assert!(n.original());
        assert_eq!(n.depth(), 4095);
        assert_eq!(n.low(), 7);
        assert_eq!(n.prev(), a);
        assert_eq!(n.next(), b);
        let n = n.with_low(3).with_prev(None);
        assert_eq!((n.low(), n.depth(), n.prev(), n.next()), (3, 4095, None, b));
    }

    #[test]
    fn words_round_trip() {
        let s = Slot {
            cap: Cap { data: 1, header: 2 },
            node: Node::new(false, 2, 1).with_next(SlotAddr::new(0x40)),
        };
        assert_eq!(Slot::from_words(s.to_words()), s);
        assert_eq!(Slot::from_words([0; 4]), Slot::EMPTY);
    }
}
