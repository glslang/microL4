//! Slots and untyped memory for the root task's objects: a slot allocator
//! over BootInfo's `empty` region, an untyped picker over `untyped`, and
//! [`ObjectAlloc`], which retypes objects into fresh slots with both.
//!
//! The root task's CNode is single-level (`docs/abi.md`, "Initial
//! CSpace"), so `CPtr` `n` is slot `n`, and a retype names the CNode itself
//! as its destination (`node_depth` 0) and the slot as `node_offset`.
//!
//! The picker keeps a model of each untyped's watermark (ADR 0010): the
//! first retype of an untyped with no children starts at 0, and every later
//! one at the watermark aligned up to the object size, while nothing is
//! deleted. The first retype of an untyped clears all of it, so the picker
//! fills untyped it has used before, and otherwise takes the smallest RAM
//! untyped that fits. A root task that deletes or revokes what it retyped
//! must not keep using the same `UntypedAlloc`.

use core::fmt;

use l4core::bootinfo::{BootInfo, CAP_INIT_CNODE, MAX_UNTYPED, SlotRegion, UntypedDesc};
use l4core::cap::{
    MAX_CNODE_RADIX, MAX_UNTYPED_BITS, MIN_CNODE_RADIX, MIN_UNTYPED_BITS, ObjectType,
};

use crate::error::Error;
use crate::invoke::{Slot, untyped_retype};
use crate::syscall::{CPtr, Ipc};

/// Hands out the slots of one region in order, never twice.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct SlotAlloc {
    next: u64,
    end: u64,
}

impl SlotAlloc {
    /// The slots of `region`.
    pub const fn new(region: SlotRegion) -> SlotAlloc {
        SlotAlloc {
            next: region.start,
            end: if region.end > region.start {
                region.end
            } else {
                region.start
            },
        }
    }

    /// `n` consecutive free slots, by the first one's `CPtr`; `None` if
    /// fewer are left or `n` is 0.
    pub fn alloc(&mut self, n: u64) -> Option<CPtr> {
        if n == 0 || n > self.remaining() {
            return None;
        }
        let first = self.next;
        self.next += n;
        Some(first)
    }

    /// Slots left.
    pub const fn remaining(&self) -> u64 {
        self.end - self.next
    }
}

/// Where a retype goes: the untyped's slot, and the offset in it the
/// kernel puts the first object at.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Placement {
    pub untyped: CPtr,
    pub offset: u64,
}

/// Picks the untyped each retype draws from, with a model of their
/// watermarks (module docs).
#[derive(Clone, Debug)]
pub struct UntypedAlloc<'a> {
    /// The slot of `list[0]`.
    first: CPtr,
    list: &'a [UntypedDesc],
    /// Bytes below each untyped's modelled watermark; 0 for one not used.
    used: [u64; MAX_UNTYPED],
}

impl<'a> UntypedAlloc<'a> {
    /// The untyped BootInfo lists.
    pub fn new(bi: &'a BootInfo) -> UntypedAlloc<'a> {
        UntypedAlloc::from_list(bi.untyped.start, bi.untyped())
    }

    /// The untyped `list` describes, the first in slot `first`; at most
    /// [`MAX_UNTYPED`] of them are used.
    pub fn from_list(first: CPtr, list: &'a [UntypedDesc]) -> UntypedAlloc<'a> {
        UntypedAlloc {
            first,
            list: &list[..list.len().min(MAX_UNTYPED)],
            used: [0; MAX_UNTYPED],
        }
    }

    /// Where `count` objects of `2^bits` bytes would go: in the first used
    /// RAM untyped with room above its aligned watermark, else at the start
    /// of the smallest unused RAM untyped big enough (the first of equals).
    /// Records nothing; [`UntypedAlloc::record`] does.
    pub fn choose(&self, bits: u32, count: u64) -> Option<Placement> {
        let bytes = count.checked_mul(1u64.checked_shl(bits)?)?;
        let ram = self.list.iter().enumerate().filter(|(_, d)| !d.device());
        let used = ram.clone().find_map(|(i, d)| {
            let used = self.used[i];
            let start = align_up(used, bits)?;
            (used > 0 && start.checked_add(bytes)? <= d.size()).then_some((i, start))
        });
        let (i, offset) = used.or_else(|| {
            ram.filter(|&(i, d)| self.used[i] == 0 && bytes <= d.size())
                .min_by_key(|&(i, d)| (d.size_bits, i))
                .map(|(i, _)| (i, 0))
        })?;
        Some(Placement {
            untyped: self.first + i as u64,
            offset,
        })
    }

    /// Records that `count` objects of `2^bits` bytes went where
    /// [`UntypedAlloc::choose`] said.
    pub fn record(&mut self, at: Placement, bits: u32, count: u64) {
        let i = (at.untyped - self.first) as usize;
        self.used[i] = at.offset + (count << bits);
    }

    /// Bytes below the modelled watermark of the untyped in slot `untyped`.
    pub fn used(&self, untyped: CPtr) -> Option<u64> {
        let i = usize::try_from(untyped.checked_sub(self.first)?).ok()?;
        self.list.get(i).map(|_| self.used[i])
    }
}

fn align_up(v: u64, bits: u32) -> Option<u64> {
    let mask = 1u64.checked_shl(bits)? - 1;
    Some(v.checked_add(mask)? & !mask)
}

/// Why [`ObjectAlloc::retype`] made nothing.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AllocError {
    /// `size_bits` is out of range for the type, or `count` is 0.
    BadRequest,
    /// Fewer free slots than objects.
    NoSlots,
    /// No RAM untyped has room.
    NoUntyped,
    /// `Untyped_Retype` failed.
    Kernel(Error),
}

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllocError::BadRequest => f.write_str("bad size or count"),
            AllocError::NoSlots => f.write_str("no free slots left"),
            AllocError::NoUntyped => f.write_str("no RAM untyped has room"),
            AllocError::Kernel(e) => write!(f, "Untyped_Retype: {e}"),
        }
    }
}

/// Retypes objects into fresh slots of the root task's CNode.
#[derive(Clone, Debug)]
pub struct ObjectAlloc<'a> {
    pub slots: SlotAlloc,
    pub untyped: UntypedAlloc<'a>,
}

impl<'a> ObjectAlloc<'a> {
    /// BootInfo's empty slots and untyped.
    pub fn new(bi: &'a BootInfo) -> ObjectAlloc<'a> {
        ObjectAlloc {
            slots: SlotAlloc::new(bi.empty),
            untyped: UntypedAlloc::new(bi),
        }
    }

    /// `count` objects of type `ty` (`size_bits` for an Untyped or a CNode,
    /// ignored otherwise), each with its capability in one of `count`
    /// consecutive fresh slots, by the first one's `CPtr`. On an error
    /// nothing is recorded, though the slots stay taken.
    pub fn retype(
        &mut self,
        ipc: Ipc,
        ty: ObjectType,
        size_bits: u64,
        count: u64,
    ) -> Result<CPtr, AllocError> {
        let bits = object_bits(ty, size_bits).ok_or(AllocError::BadRequest)?;
        if count == 0 {
            return Err(AllocError::BadRequest);
        }
        let at = self
            .untyped
            .choose(bits, count)
            .ok_or(AllocError::NoUntyped)?;
        let first = self.slots.alloc(count).ok_or(AllocError::NoSlots)?;
        untyped_retype(
            ipc,
            at.untyped,
            ty,
            size_bits,
            Slot::cnode_itself(CAP_INIT_CNODE),
            first,
            count,
        )
        .map_err(AllocError::Kernel)?;
        self.untyped.record(at, bits, count);
        Ok(first)
    }
}

/// log2 of the size of an object of type `ty`, if `size_bits` is in range
/// for an Untyped or a CNode.
pub fn object_bits(ty: ObjectType, size_bits: u64) -> Option<u32> {
    let size_bits = u32::try_from(size_bits).ok();
    let ok = match ty {
        ObjectType::Untyped => (MIN_UNTYPED_BITS..=MAX_UNTYPED_BITS).contains(&size_bits?),
        ObjectType::CNode => (MIN_CNODE_RADIX..=MAX_CNODE_RADIX).contains(&size_bits?),
        _ => true,
    };
    ok.then(|| ty.object_bits(size_bits.unwrap_or(0)))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    fn ram(paddr: u64, bits: u32) -> UntypedDesc {
        UntypedDesc::new(paddr, bits, false)
    }

    fn device(paddr: u64, bits: u32) -> UntypedDesc {
        UntypedDesc::new(paddr, bits, true)
    }

    #[test]
    fn slots_come_in_order_and_run_out() {
        let mut s = SlotAlloc::new(SlotRegion {
            start: 100,
            end: 110,
        });
        assert_eq!(s.remaining(), 10);
        assert_eq!(s.alloc(0), None);
        assert_eq!(s.alloc(1), Some(100));
        assert_eq!(s.alloc(4), Some(101));
        assert_eq!(s.alloc(6), None, "five are left");
        assert_eq!(s.alloc(5), Some(105));
        assert_eq!(s.remaining(), 0);
        assert_eq!(s.alloc(1), None);
        // An empty region, and one written backwards, have no slots.
        for (start, end) in [(7, 7), (9, 3)] {
            assert_eq!(SlotAlloc::new(SlotRegion { start, end }).alloc(1), None);
        }
    }

    #[test]
    fn the_smallest_ram_untyped_that_fits_comes_first() {
        let list = [
            device(0x10_0000, 12),
            ram(0x20_0000, 20),
            ram(0x30_0000, 13),
            ram(0x40_0000, 16),
            ram(0x50_0000, 13),
        ];
        let u = UntypedAlloc::from_list(40, &list);
        // One TCB fits all four RAM untyped: the first 8 KiB one.
        assert_eq!(
            u.choose(11, 1),
            Some(Placement {
                untyped: 42,
                offset: 0
            })
        );
        // Five TCBs need 16 KiB: the 64 KiB one.
        assert_eq!(u.choose(11, 5).map(|p| p.untyped), Some(43));
        // 128 KiB: only the 1 MiB one; the device untyped never.
        assert_eq!(u.choose(17, 1).map(|p| p.untyped), Some(41));
        assert_eq!(u.choose(21, 1), None);
        assert_eq!(
            UntypedAlloc::from_list(0, &[device(0, 30)]).choose(4, 1),
            None
        );
    }

    #[test]
    fn a_used_untyped_fills_at_its_aligned_watermark() {
        let list = [ram(0x10_0000, 14), ram(0x20_0000, 13)];
        let mut u = UntypedAlloc::from_list(16, &list);
        let mut take = |bits, count| {
            let p = u.choose(bits, count)?;
            u.record(p, bits, count);
            Some((p.untyped, p.offset))
        };
        // The 8 KiB untyped first, then the used one while it has room.
        assert_eq!(take(5, 1), Some((17, 0)));
        assert_eq!(take(11, 2), Some((17, 0x800)), "aligned up from 0x20");
        assert_eq!(take(5, 3), Some((17, 0x1800)));
        // 2 KiB more does not fit above 0x1860 in 8 KiB: the 16 KiB one.
        assert_eq!(take(11, 1), Some((16, 0)));
        assert_eq!(
            take(5, 1),
            Some((16, 0x800)),
            "the first used one with room"
        );
        assert_eq!(take(12, 3), Some((16, 0x1000)));
        assert_eq!(take(12, 1), None);
        assert_eq!(take(5, 4), Some((17, 0x1860)));
        assert_eq!(u.used(16), Some(0x4000));
        assert_eq!(u.used(17), Some(0x18E0));
        assert_eq!(u.used(18), None);
        assert_eq!(u.used(3), None);
    }

    #[test]
    fn huge_requests_do_not_overflow() {
        let list = [ram(0, 47)];
        let u = UntypedAlloc::from_list(16, &list);
        assert_eq!(u.choose(47, 1).map(|p| p.offset), Some(0));
        assert_eq!(u.choose(47, 2), None);
        assert_eq!(u.choose(63, 2), None);
        assert_eq!(u.choose(64, 1), None);
        assert_eq!(u.choose(5, u64::MAX), None);
    }

    #[test]
    fn at_most_max_untyped_are_considered() {
        let list: Vec<UntypedDesc> = (0..MAX_UNTYPED as u64 + 1)
            .map(|i| ram(i << 20, if i == MAX_UNTYPED as u64 { 12 } else { 20 }))
            .collect();
        let u = UntypedAlloc::from_list(16, &list);
        // The 4 KiB one past the limit would be the smallest.
        assert_eq!(u.choose(12, 1).map(|p| p.untyped), Some(16));
    }

    #[test]
    fn object_sizes() {
        assert_eq!(object_bits(ObjectType::Tcb, 99), Some(11));
        assert_eq!(object_bits(ObjectType::Endpoint, 0), Some(5));
        assert_eq!(object_bits(ObjectType::Frame4K, 0), Some(12));
        assert_eq!(object_bits(ObjectType::CNode, 4), Some(9));
        assert_eq!(object_bits(ObjectType::CNode, 0), None);
        assert_eq!(object_bits(ObjectType::CNode, 43), None);
        assert_eq!(object_bits(ObjectType::Untyped, 3), None);
        assert_eq!(object_bits(ObjectType::Untyped, 47), Some(47));
        assert_eq!(object_bits(ObjectType::Untyped, 1 << 32), None);
    }
}
