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
//!
//! From M9, [`Carver`] makes device frames at chosen physical addresses,
//! ECAM's and a device's BAR pages, by splitting device untyped
//! (`docs/design.md`, "PCI on QEMU", "Carving").

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

    /// Where `count` objects of `2^bits` bytes would go in the untyped in
    /// slot `untyped`, named rather than chosen, device untyped included:
    /// at its modelled watermark aligned up to the object size, as the
    /// kernel places them. `None` if BootInfo lists no such untyped or they
    /// do not fit. Records nothing; [`UntypedAlloc::record`] does.
    pub fn place(&self, untyped: CPtr, bits: u32, count: u64) -> Option<Placement> {
        let i = usize::try_from(untyped.checked_sub(self.first)?).ok()?;
        let d = self.list.get(i)?;
        let bytes = count.checked_mul(1u64.checked_shl(bits)?)?;
        let offset = align_up(self.used[i], bits)?;
        (offset.checked_add(bytes)? <= d.size()).then_some(Placement { untyped, offset })
    }

    /// Records that `count` objects of `2^bits` bytes went where
    /// [`UntypedAlloc::choose`] or [`UntypedAlloc::place`] said.
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
    /// The named untyped is not one BootInfo lists, or has no room.
    NoRoom,
    /// `Untyped_Retype` failed.
    Kernel(Error),
}

impl fmt::Display for AllocError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AllocError::BadRequest => f.write_str("bad size or count"),
            AllocError::NoSlots => f.write_str("no free slots left"),
            AllocError::NoUntyped => f.write_str("no RAM untyped has room"),
            AllocError::NoRoom => f.write_str("the named untyped is not BootInfo's or has no room"),
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
        self.retype_at(ipc, at, ty, size_bits, bits, count)
    }

    /// As [`retype`](Self::retype), from the untyped in slot `untyped`,
    /// named rather than picked: a device untyped, which the picker never
    /// takes, into frames (the framebuffer's, `ty` `Frame4K` or
    /// `Frame2M`), or a RAM untyped the caller chose. The objects go at its
    /// watermark aligned up to their size, which the picker's model
    /// records, so later picks of a RAM untyped stay right.
    pub fn retype_from(
        &mut self,
        ipc: Ipc,
        untyped: CPtr,
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
            .place(untyped, bits, count)
            .ok_or(AllocError::NoRoom)?;
        self.retype_at(ipc, at, ty, size_bits, bits, count)
    }

    fn retype_at(
        &mut self,
        ipc: Ipc,
        at: Placement,
        ty: ObjectType,
        size_bits: u64,
        bits: u32,
        count: u64,
    ) -> Result<CPtr, AllocError> {
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

/// The most free halves a [`Carver`] keeps: a carve adds at most one a
/// level, 35 from a 128 TiB untyped down to a page.
pub const MAX_HALVES: usize = 256;

/// Device frames at chosen physical addresses, carved out of device
/// untyped by splitting, as seL4's allocators find a device frame at a
/// fixed address (`docs/design.md`, "PCI on QEMU", "Carving"). The
/// untyped that holds the frame is retyped into two Untyped of half its
/// size (one `Untyped_Retype`, two slots), the half that holds the frame
/// is split again, and so on down to the frame's size, which is retyped
/// into the frame. The other halves stay free with an empty watermark, so
/// a later frame, at a lower or a higher address, costs only the levels
/// left: 2 slots a level and 1 for the frame.
///
/// The carver models each untyped as used or free: BootInfo's device
/// untyped start free, but for the framebuffer's (`fb`'s) and any the
/// [`UntypedAlloc`] it starts from has used; RAM untyped are never free.
/// It refuses a frame that no single free device untyped holds, so it
/// never retypes an untyped twice, and it changes nothing when it
/// refuses. An Untyped retyped from device untyped is itself device
/// memory, so the frames it ends in are device frames, which map only
/// uncached or write-combining (`docs/abi.md`, `Untyped_Retype`).
#[derive(Clone, Debug)]
pub struct Carver<'a> {
    /// The slot of `list[0]`.
    first: CPtr,
    list: &'a [UntypedDesc],
    /// A bit for each of BootInfo's untyped that is not free: RAM, the
    /// framebuffer's, those used before, and those split or carved.
    taken: [u64; MAX_UNTYPED.div_ceil(64)],
    /// The free halves splitting has made.
    halves: [Free; MAX_HALVES],
    count: usize,
}

/// A free device untyped: one of BootInfo's (`boot`, its index), or a half
/// a split made.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Free {
    slot: CPtr,
    paddr: u64,
    bits: u32,
    boot: Option<usize>,
}

impl Free {
    /// Whether all `2^bits` bytes at `paddr` lie in it.
    fn holds(&self, paddr: u64, bits: u32) -> bool {
        let end = paddr.checked_add(1 << bits);
        self.bits >= bits
            && self.paddr <= paddr
            && end.is_some_and(|end| end <= self.paddr + (1 << self.bits))
    }
}

/// One `Untyped_Retype` a carve makes: `count` objects of type `ty`
/// (`size_bits` for an Untyped, else 0) from the untyped in slot
/// `untyped`, into the root task's slots from `first` on. A split is two
/// Untyped of half the untyped's size; the last is the frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retype {
    pub untyped: CPtr,
    pub ty: ObjectType,
    pub size_bits: u64,
    pub first: CPtr,
    pub count: u64,
}

/// Why [`Carver::carve`] made no frame. Only `Kernel` leaves slots
/// taken, and the halves the splits before the failed retype made.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CarveError {
    /// `ty` is not `Frame4K` or `Frame2M`, or `paddr` is not aligned to
    /// its size.
    BadRequest,
    /// No free device untyped holds all `2^bits` bytes at `paddr`: they
    /// are RAM, in no untyped, in the framebuffer's, or overlap a frame
    /// carved before.
    NotHeld { paddr: u64, bits: u32 },
    /// The carve needs `need` slots and `left` remain.
    NoSlots { need: u64, left: u64 },
    /// It would leave more than [`MAX_HALVES`] free halves.
    TooManyHalves,
    /// `Untyped_Retype` failed.
    Kernel(Error),
}

impl fmt::Display for CarveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            CarveError::BadRequest => {
                f.write_str("not a frame type, or an address not aligned to its size")
            }
            CarveError::NotHeld { paddr, bits } => write!(
                f,
                "no free device untyped holds the {} KiB at {paddr:#x}",
                (1u64 << bits) >> 10
            ),
            CarveError::NoSlots { need, left } => {
                write!(f, "carving needs {need} slots, {left} are left")
            }
            CarveError::TooManyHalves => write!(f, "more than {MAX_HALVES} free halves"),
            CarveError::Kernel(e) => write!(f, "Untyped_Retype: {e}"),
        }
    }
}

impl<'a> Carver<'a> {
    /// BootInfo's device untyped, but for the framebuffer's and any that
    /// `used` has retyped from.
    pub fn new(bi: &'a BootInfo, used: &UntypedAlloc<'_>) -> Carver<'a> {
        let mut c = Carver::from_list(bi.untyped.start, bi.untyped(), bi.framebuffer_untyped);
        for i in 0..c.list.len() {
            if used.used(c.first + i as u64).is_none_or(|u| u != 0) {
                c.take(i);
            }
        }
        c
    }

    /// The untyped `list` describes, the first in slot `first`, but for
    /// RAM untyped and the slots of `framebuffer`; at most [`MAX_UNTYPED`]
    /// of them are used.
    pub fn from_list(first: CPtr, list: &'a [UntypedDesc], framebuffer: SlotRegion) -> Carver<'a> {
        let mut c = Carver {
            first,
            list: &list[..list.len().min(MAX_UNTYPED)],
            taken: [0; MAX_UNTYPED.div_ceil(64)],
            halves: [Free::default(); MAX_HALVES],
            count: 0,
        };
        for i in 0..c.list.len() {
            if !c.list[i].device() || framebuffer.contains(first + i as u64) {
                c.take(i);
            }
        }
        c
    }

    fn take(&mut self, i: usize) {
        self.taken[i / 64] |= 1 << (i % 64);
    }

    fn is_taken(&self, i: usize) -> bool {
        self.taken[i / 64] & (1 << (i % 64)) != 0
    }

    /// Every free device untyped in the model: BootInfo's still whole,
    /// then the halves.
    fn frees(&self) -> impl Iterator<Item = Free> + '_ {
        let boot = self.list.iter().enumerate();
        boot.filter(|&(i, _)| !self.is_taken(i))
            .map(|(i, d)| Free {
                slot: self.first + i as u64,
                paddr: d.paddr,
                bits: d.size_bits.into(),
                boot: Some(i),
            })
            .chain(self.halves[..self.count].iter().copied())
    }

    /// The free untyped that holds all `2^bits` bytes at `paddr`: free
    /// untyped never overlap, so at most one does.
    fn holder(&self, paddr: u64, bits: u32) -> Option<Free> {
        self.frees().find(|u| u.holds(paddr, bits))
    }

    /// The free device untyped in the model, as `(slot, paddr,
    /// size_bits)`: BootInfo's still whole, then the halves.
    pub fn free(&self) -> impl Iterator<Item = (CPtr, u64, u32)> + '_ {
        self.frees().map(|u| (u.slot, u.paddr, u.bits))
    }

    /// The slots a frame of type `ty` at `paddr` would cost now: 2 for
    /// each split and 1 for the frame. Records nothing.
    pub fn cost(&self, paddr: u64, ty: ObjectType) -> Result<u64, CarveError> {
        let bits = frame_bits(ty, paddr)?;
        let holder = self
            .holder(paddr, bits)
            .ok_or(CarveError::NotHeld { paddr, bits })?;
        Ok(2 * u64::from(holder.bits - bits) + 1)
    }

    /// Carves the frame of type `ty` (`Frame4K` or `Frame2M`) at `paddr`,
    /// aligned to its size, with `retype` performing each
    /// `Untyped_Retype` in order, the slots taken from `slots`; returns the
    /// frame's slot. It checks first that a free device untyped holds the
    /// frame, that enough slots are left and that the halves fit, and
    /// otherwise refuses with nothing changed. If a retype fails, the
    /// untyped it named stays free, the halves made before it stay free,
    /// and the slots taken stay taken.
    pub fn carve(
        &mut self,
        paddr: u64,
        ty: ObjectType,
        slots: &mut SlotAlloc,
        mut retype: impl FnMut(&Retype) -> Result<(), Error>,
    ) -> Result<CPtr, CarveError> {
        let bits = frame_bits(ty, paddr)?;
        let holder = self
            .holder(paddr, bits)
            .ok_or(CarveError::NotHeld { paddr, bits })?;
        let levels = holder.bits - bits;
        let need = 2 * u64::from(levels) + 1;
        let left = slots.remaining();
        if left < need {
            return Err(CarveError::NoSlots { need, left });
        }
        let from_half = usize::from(holder.boot.is_none());
        if self.count - from_half + levels as usize > MAX_HALVES {
            return Err(CarveError::TooManyHalves);
        }
        self.remove(holder);
        let mut at = holder;
        while at.bits > bits {
            let half = at.bits - 1;
            let first = slots.alloc(2).ok_or(CarveError::NoSlots { need, left })?;
            let split = Retype {
                untyped: at.slot,
                ty: ObjectType::Untyped,
                size_bits: half.into(),
                first,
                count: 2,
            };
            if let Err(e) = retype(&split) {
                self.restore(at);
                return Err(CarveError::Kernel(e));
            }
            let lower = Free {
                slot: first,
                paddr: at.paddr,
                bits: half,
                boot: None,
            };
            let upper = Free {
                slot: first + 1,
                paddr: at.paddr + (1 << half),
                ..lower
            };
            let (next, other) = if paddr < upper.paddr {
                (lower, upper)
            } else {
                (upper, lower)
            };
            self.halves[self.count] = other;
            self.count += 1;
            at = next;
        }
        let frame = slots.alloc(1).ok_or(CarveError::NoSlots { need, left })?;
        let last = Retype {
            untyped: at.slot,
            ty,
            size_bits: 0,
            first: frame,
            count: 1,
        };
        if let Err(e) = retype(&last) {
            self.restore(at);
            return Err(CarveError::Kernel(e));
        }
        Ok(frame)
    }

    /// Takes `u` out of the free model.
    fn remove(&mut self, u: Free) {
        match u.boot {
            Some(i) => self.take(i),
            None => {
                if let Some(k) = self.halves[..self.count].iter().position(|h| *h == u) {
                    self.count -= 1;
                    self.halves[k] = self.halves[self.count];
                }
            }
        }
    }

    /// Puts `u`, which a failed retype left as it was, back in the model.
    fn restore(&mut self, u: Free) {
        match u.boot {
            Some(i) => self.taken[i / 64] &= !(1 << (i % 64)),
            None => {
                self.halves[self.count] = u;
                self.count += 1;
            }
        }
    }

    /// As [`carve`](Carver::carve), on the target: each retype an
    /// `Untyped_Retype` into the root task's CNode, the slots from
    /// `objects`, whose model then counts each of BootInfo's untyped the
    /// carver retyped as full, so that `retype_from` never names it.
    pub fn carve_frame(
        &mut self,
        ipc: Ipc,
        objects: &mut ObjectAlloc<'_>,
        paddr: u64,
        ty: ObjectType,
    ) -> Result<CPtr, CarveError> {
        let boot = SlotRegion {
            start: self.first,
            end: self.first + self.list.len() as u64,
        };
        let ObjectAlloc { slots, untyped } = objects;
        self.carve(paddr, ty, slots, |r| {
            untyped_retype(
                ipc,
                r.untyped,
                r.ty,
                r.size_bits,
                Slot::cnode_itself(CAP_INIT_CNODE),
                r.first,
                r.count,
            )?;
            let bits = object_bits(r.ty, r.size_bits);
            if let Some(bits) = bits.filter(|_| boot.contains(r.untyped)) {
                let at = Placement {
                    untyped: r.untyped,
                    offset: 0,
                };
                untyped.record(at, bits, r.count);
            }
            Ok(())
        })
    }
}

/// log2 of a frame of type `ty`, if it is one and `paddr` is aligned to
/// it.
fn frame_bits(ty: ObjectType, paddr: u64) -> Result<u32, CarveError> {
    let bits = match ty {
        ObjectType::Frame4K => 12,
        ObjectType::Frame2M => 21,
        _ => return Err(CarveError::BadRequest),
    };
    if paddr & ((1 << bits) - 1) != 0 {
        return Err(CarveError::BadRequest);
    }
    Ok(bits)
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

    /// QEMU's framebuffer untyped lead the list: a 2 MiB one, then smaller
    /// ones, each retyped by name into frames from its start.
    #[test]
    fn a_named_untyped_device_or_ram_places_at_its_watermark() {
        let list = [
            device(0x8000_0000, 21),
            device(0x8020_0000, 20),
            ram(0x10_0000, 14),
        ];
        let mut u = UntypedAlloc::from_list(16, &list);
        let mut take = |slot, bits, count| {
            let p = u.place(slot, bits, count)?;
            u.record(p, bits, count);
            Some(p.offset)
        };
        assert_eq!(take(16, 21, 1), Some(0));
        assert_eq!(take(16, 12, 1), None, "the 2 MiB untyped is full");
        assert_eq!(take(17, 12, 256), Some(0));
        assert_eq!(take(17, 12, 1), None);
        // A RAM untyped named fills on from its watermark, aligned up, and
        // the picker sees it used.
        assert_eq!(take(18, 5, 1), Some(0));
        assert_eq!(take(18, 11, 2), Some(0x800));
        assert_eq!(u.used(18), Some(0x1800));
        assert_eq!(
            u.choose(12, 1).map(|p| (p.untyped, p.offset)),
            Some((18, 0x2000))
        );
        // Slots BootInfo does not list.
        assert_eq!(u.place(15, 12, 1), None);
        assert_eq!(u.place(19, 12, 1), None);
        assert_eq!(
            u.place(18, 12, 0),
            Some(Placement {
                untyped: 18,
                offset: 0x2000
            })
        );
        assert_eq!(u.place(18, 64, 1), None);
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

    // The carver (`docs/design.md`, "Code and tests", the Carving row):
    // against a model kernel, fixed cases, then random untyped lists and
    // address sets in any order.

    use std::boxed::Box;
    use std::collections::BTreeMap;
    use std::format;
    use std::string::ToString;

    use l4core::error::SyscallError;

    /// A model kernel for the carver: each capability by slot. It fails a
    /// test that retypes an untyped twice, a RAM untyped, into a slot
    /// already full, or into objects that do not exactly fill the untyped,
    /// and places objects as a fresh untyped's first retype does, from its
    /// start. `fail_at` makes that retype fail, changing nothing.
    #[derive(Debug, Default)]
    struct Kernel {
        caps: BTreeMap<CPtr, Obj>,
        retypes: usize,
        fail_at: Option<usize>,
    }

    #[derive(Clone, Copy, Debug, PartialEq, Eq)]
    enum Obj {
        Untyped {
            paddr: u64,
            bits: u32,
            device: bool,
            retyped: bool,
        },
        Frame {
            paddr: u64,
            bits: u32,
            device: bool,
        },
    }

    impl Kernel {
        fn boot(first: CPtr, list: &[UntypedDesc]) -> Kernel {
            let caps = list
                .iter()
                .enumerate()
                .map(|(i, d)| {
                    let u = Obj::Untyped {
                        paddr: d.paddr,
                        bits: d.size_bits.into(),
                        device: d.device(),
                        retyped: false,
                    };
                    (first + i as u64, u)
                })
                .collect();
            Kernel {
                caps,
                ..Kernel::default()
            }
        }

        fn retype(&mut self, r: &Retype) -> Result<(), Error> {
            self.retypes += 1;
            if self.fail_at == Some(self.retypes) {
                return Err(Error::Kernel(SyscallError::NotEnoughMemory(0)));
            }
            let Some(Obj::Untyped {
                paddr,
                bits,
                device,
                retyped,
            }) = self.caps.get_mut(&r.untyped)
            else {
                panic!("slot {} holds no untyped", r.untyped);
            };
            assert!(!*retyped, "the untyped in slot {} retyped twice", r.untyped);
            assert!(*device, "the RAM untyped in slot {} retyped", r.untyped);
            let ob = match r.ty {
                ObjectType::Untyped => r.size_bits as u32,
                ObjectType::Frame4K => 12,
                ObjectType::Frame2M => 21,
                t => panic!("a carve retyped {t:?}"),
            };
            assert_eq!(r.count << ob, 1u64 << *bits, "{r:?} fills its untyped");
            *retyped = true;
            let (paddr, device) = (*paddr, *device);
            for i in 0..r.count {
                let obj = match r.ty {
                    ObjectType::Untyped => Obj::Untyped {
                        paddr: paddr + (i << ob),
                        bits: ob,
                        device,
                        retyped: false,
                    },
                    _ => Obj::Frame {
                        paddr: paddr + (i << ob),
                        bits: ob,
                        device,
                    },
                };
                assert!(
                    self.caps.insert(r.first + i, obj).is_none(),
                    "slot {} full",
                    r.first + i
                );
            }
            Ok(())
        }
    }

    const FIRST: CPtr = 100;
    const NO_FB: SlotRegion = SlotRegion { start: 0, end: 0 };

    fn carve(
        c: &mut Carver<'_>,
        k: &mut Kernel,
        slots: &mut SlotAlloc,
        paddr: u64,
        ty: ObjectType,
    ) -> Result<CPtr, CarveError> {
        c.carve(paddr, ty, slots, |r| k.retype(r))
    }

    fn many_slots() -> SlotAlloc {
        SlotAlloc::new(SlotRegion {
            start: 1000,
            end: 100_000,
        })
    }

    #[test]
    fn a_frame_is_carved_by_halving_down_to_it_and_later_ones_cost_less() {
        let list = [device(0x8000_0000, 30), ram(0x10_0000, 20)];
        let mut c = Carver::from_list(FIRST, &list, NO_FB);
        let mut k = Kernel::boot(FIRST, &list);
        let mut s = many_slots();
        let mut take = |c: &mut Carver<'_>, paddr, ty| {
            let cost = c.cost(paddr, ty).unwrap();
            let before = s.remaining();
            let slot = carve(c, &mut k, &mut s, paddr, ty).unwrap();
            assert_eq!(before - s.remaining(), cost, "{paddr:#x}");
            let bits = if ty == ObjectType::Frame2M { 21 } else { 12 };
            assert_eq!(
                k.caps[&slot],
                Obj::Frame {
                    paddr,
                    bits,
                    device: true
                }
            );
            cost
        };
        // 18 halvings from 1 GiB to 4 KiB, then the frame.
        assert_eq!(take(&mut c, 0x8000_3000, ObjectType::Frame4K), 37);
        // Below it: its 4 KiB buddy, then the 8 KiB half below that.
        assert_eq!(take(&mut c, 0x8000_2000, ObjectType::Frame4K), 1);
        assert_eq!(take(&mut c, 0x8000_0000, ObjectType::Frame4K), 3);
        // A 2 MiB frame at the top: from the upper 512 MiB half.
        assert_eq!(take(&mut c, 0xBFE0_0000, ObjectType::Frame2M), 17);
        // And one in the first 2 MiB's buddy.
        assert_eq!(take(&mut c, 0x8020_0000, ObjectType::Frame2M), 1);
        // Halves left: one at each level, less those taken.
        let free: std::vec::Vec<_> = c.free().collect();
        assert!(free.iter().all(|&(_, p, b)| p % (1 << b) == 0));
        let bytes: u64 = free.iter().map(|&(_, _, b)| 1u64 << b).sum();
        assert_eq!(bytes, (1 << 30) - 3 * 4096 - 2 * (2 << 20));
    }

    #[test]
    fn a_whole_untyped_of_the_frames_size_is_retyped_at_once() {
        let list = [device(0x9000_0000, 12), device(0x9020_0000, 21)];
        let mut c = Carver::from_list(FIRST, &list, NO_FB);
        let mut k = Kernel::boot(FIRST, &list);
        let mut s = many_slots();
        assert_eq!(c.cost(0x9000_0000, ObjectType::Frame4K), Ok(1));
        assert_eq!(
            carve(&mut c, &mut k, &mut s, 0x9000_0000, ObjectType::Frame4K),
            Ok(1000)
        );
        assert_eq!(
            carve(&mut c, &mut k, &mut s, 0x9020_0000, ObjectType::Frame2M),
            Ok(1001)
        );
        assert_eq!(c.free().count(), 0);
    }

    #[test]
    fn frames_no_free_device_untyped_holds_are_refused_with_nothing_changed() {
        let list = [
            device(0xE000_0000, 21),
            device(0x8000_0000, 22),
            ram(0x20_0000, 21),
            device(0xC000_0000, 13),
            device(0xC000_2000, 13),
        ];
        let fb = SlotRegion {
            start: FIRST,
            end: FIRST + 1,
        };
        let mut c = Carver::from_list(FIRST, &list, fb);
        let mut k = Kernel::boot(FIRST, &list);
        let mut s = many_slots();
        let not_held = |paddr, bits| Err(CarveError::NotHeld { paddr, bits });
        macro_rules! try_ {
            ($paddr:expr, $ty:expr) => {
                carve(&mut c, &mut k, &mut s, $paddr, $ty)
            };
        }
        // The framebuffer's, RAM, a gap, past the end of everything.
        assert_eq!(
            try_!(0xE000_0000, ObjectType::Frame4K),
            not_held(0xE000_0000, 12)
        );
        assert_eq!(
            try_!(0x20_1000, ObjectType::Frame4K),
            not_held(0x20_1000, 12)
        );
        assert_eq!(
            try_!(0x7FFF_F000, ObjectType::Frame4K),
            not_held(0x7FFF_F000, 12)
        );
        assert_eq!(
            try_!(0xFFFF_FFFF_FFFF_F000, ObjectType::Frame4K),
            not_held(0xFFFF_FFFF_FFFF_F000, 12)
        );
        // 2 MiB over two 8 KiB untyped, and over the untyped's end.
        assert_eq!(
            try_!(0xC000_0000, ObjectType::Frame2M),
            not_held(0xC000_0000, 21)
        );
        // Misaligned, or not a frame.
        assert_eq!(
            try_!(0x8000_0800, ObjectType::Frame4K),
            Err(CarveError::BadRequest)
        );
        assert_eq!(
            try_!(0x8010_0000, ObjectType::Frame2M),
            Err(CarveError::BadRequest)
        );
        assert_eq!(
            try_!(0x8000_0000, ObjectType::PageTable),
            Err(CarveError::BadRequest)
        );
        assert_eq!(k.retypes, 0);
        assert_eq!(s.remaining(), 99_000);
        // Carved once, never again, nor a 2 MiB frame over it.
        assert!(try_!(0x8000_1000, ObjectType::Frame4K).is_ok());
        assert_eq!(
            try_!(0x8000_1000, ObjectType::Frame4K),
            not_held(0x8000_1000, 12)
        );
        assert_eq!(
            try_!(0x8000_0000, ObjectType::Frame2M),
            not_held(0x8000_0000, 21)
        );
        assert!(try_!(0x8020_0000, ObjectType::Frame2M).is_ok());
        assert_eq!(
            CarveError::NotHeld {
                paddr: 0x8000_1000,
                bits: 12
            }
            .to_string(),
            "no free device untyped holds the 4 KiB at 0x80001000"
        );
    }

    #[test]
    fn too_few_slots_or_halves_refuse_with_nothing_changed() {
        let list = [device(0x1_0000_0000, 32)];
        let mut c = Carver::from_list(FIRST, &list, NO_FB);
        let mut k = Kernel::boot(FIRST, &list);
        let mut s = SlotAlloc::new(SlotRegion {
            start: 1000,
            end: 1000 + 40,
        });
        let r = carve(&mut c, &mut k, &mut s, 0x1_0000_0000, ObjectType::Frame4K);
        assert_eq!(r, Err(CarveError::NoSlots { need: 41, left: 40 }));
        assert_eq!((k.retypes, s.remaining()), (0, 40));
        assert_eq!(c.cost(0x1_0000_0000, ObjectType::Frame4K), Ok(41));
        assert!(carve(&mut c, &mut k, &mut s, 0x1_0000_0000, ObjectType::Frame2M).is_ok());

        // Ten 1 TiB untyped: nine pages carved leave 9 x 28 halves; a tenth
        // would pass 256.
        let list: std::vec::Vec<_> = (1..=10).map(|i| device(i << 40, 40)).collect();
        let mut c = Carver::from_list(FIRST, &list, NO_FB);
        let mut k = Kernel::boot(FIRST, &list);
        let mut s = many_slots();
        for i in 1..=9 {
            assert!(carve(&mut c, &mut k, &mut s, i << 40, ObjectType::Frame4K).is_ok());
        }
        let before = (k.retypes, s.remaining());
        let r = carve(&mut c, &mut k, &mut s, 10 << 40, ObjectType::Frame4K);
        assert_eq!(r, Err(CarveError::TooManyHalves));
        assert_eq!((k.retypes, s.remaining()), before);
        // A frame that is a free half already adds none.
        assert_eq!(c.free().count(), 9 * 28 + 1);
        let r = carve(
            &mut c,
            &mut k,
            &mut s,
            (1 << 40) + (2 << 20),
            ObjectType::Frame2M,
        );
        assert!(r.is_ok());
        assert_eq!(c.free().count(), 9 * 28);
    }

    #[test]
    fn a_failed_retype_leaves_the_model_right() {
        let list = [device(0x8000_0000, 24)];
        for fail in 1..=13 {
            let mut c = Carver::from_list(FIRST, &list, NO_FB);
            let mut k = Kernel::boot(FIRST, &list);
            k.fail_at = Some(fail);
            let mut s = many_slots();
            let r = carve(&mut c, &mut k, &mut s, 0x80F0_0000, ObjectType::Frame4K);
            assert!(matches!(r, Err(CarveError::Kernel(_))), "{fail}: {r:?}");
            // The splits before it stand; the retype that failed changed
            // nothing, so the same carve goes on from there.
            let cost = c.cost(0x80F0_0000, ObjectType::Frame4K).unwrap();
            assert_eq!(cost, 2 * (13 - (fail as u64 - 1)) - 1, "{fail}");
            k.fail_at = None;
            let slot = carve(&mut c, &mut k, &mut s, 0x80F0_0000, ObjectType::Frame4K).unwrap();
            assert!(matches!(
                k.caps[&slot],
                Obj::Frame {
                    paddr: 0x80F0_0000,
                    ..
                }
            ));
            assert!(carve(&mut c, &mut k, &mut s, 0x8000_0000, ObjectType::Frame2M).is_ok());
        }
    }

    #[test]
    fn new_leaves_out_the_framebuffer_ram_and_what_the_picker_used() {
        let mut bi = Box::new(BootInfo::ZERO);
        let list = [
            device(0x8000_0000, 24),
            device(0x9000_0000, 24),
            ram(0x10_0000, 20),
            device(0xA000_0000, 24),
        ];
        bi.untyped = SlotRegion {
            start: FIRST,
            end: FIRST + 4,
        };
        bi.untyped_list[..4].copy_from_slice(&list);
        bi.framebuffer_untyped = SlotRegion {
            start: FIRST,
            end: FIRST + 1,
        };
        let mut used = UntypedAlloc::new(&bi);
        let at = used.place(FIRST + 3, 12, 1).unwrap();
        used.record(at, 12, 1);
        let c = Carver::new(&bi, &used);
        let free: std::vec::Vec<_> = c.free().collect();
        assert_eq!(free, [(FIRST + 1, 0x9000_0000, 24)]);
    }

    /// A xorshift generator: Miri-cheap and repeatable.
    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, n: u64) -> u64 {
            self.next() % n
        }
    }

    /// The kernel's chunks of `[start, end)`: at each address the largest
    /// aligned power of two that fits, at most 2^47.
    fn chunks(start: u64, end: u64, device: bool, out: &mut std::vec::Vec<UntypedDesc>) {
        let mut at = start;
        while at < end {
            let bits = (end - at).ilog2().min(at.trailing_zeros()).min(47);
            out.push(UntypedDesc::new(at, bits, device));
            at += 1 << bits;
        }
    }

    /// A random physical map below 2^40 in pages and 2 MiB stretches:
    /// RAM, device memory and gaps, with the framebuffer's device untyped
    /// first, as BootInfo lists them.
    fn random_list(rng: &mut Rng) -> (std::vec::Vec<UntypedDesc>, SlotRegion) {
        let mut runs = std::vec::Vec::new();
        let mut at = 1 << 20;
        while at < 1 << 40 {
            let len = match rng.below(4) {
                0 => (1 + rng.below(16)) << 12,
                1 => (1 + rng.below(64)) << 21,
                2 => (1 + rng.below(8)) << 30,
                _ => 1 << (32 + rng.below(8)),
            };
            let end = (at + len).min(1 << 40);
            runs.push((at, end, rng.below(3)));
            at = end;
        }
        let fb = rng.below(runs.len() as u64) as usize;
        let mut list = std::vec::Vec::new();
        let (s, e, _) = runs[fb];
        chunks(s, e, true, &mut list);
        let fb_slots = SlotRegion {
            start: FIRST,
            end: FIRST + list.len() as u64,
        };
        for (i, &(s, e, kind)) in runs.iter().enumerate() {
            if i != fb && kind != 2 {
                chunks(s, e, kind == 1, &mut list);
            }
        }
        list.truncate(MAX_UNTYPED);
        (list, fb_slots)
    }

    /// What a carve should do, from the list and the frames carved so far
    /// alone: the slots it costs, or why not.
    fn oracle(
        list: &[UntypedDesc],
        fb: SlotRegion,
        carved: &[(u64, u32)],
        paddr: u64,
        bits: u32,
    ) -> Result<u64, CarveError> {
        if paddr % (1 << bits) != 0 {
            return Err(CarveError::BadRequest);
        }
        let not_held = Err(CarveError::NotHeld { paddr, bits });
        let end = paddr + (1 << bits);
        let Some((i, u)) = list
            .iter()
            .enumerate()
            .find(|(_, u)| u.paddr <= paddr && end <= u.paddr + u.size())
        else {
            return not_held;
        };
        if !u.device() || fb.contains(FIRST + i as u64) {
            return not_held;
        }
        let overlaps = |s: u64, b: u32| {
            carved
                .iter()
                .any(|&(p, cb)| p < s + (1 << b) && s < p + (1 << cb))
        };
        if overlaps(paddr, bits) {
            return not_held;
        }
        // The largest aligned block around the frame, in the untyped, that
        // holds no carved frame: what the free halves leave there.
        let top = (bits..=u32::from(u.size_bits))
            .rev()
            .find(|&b| !overlaps(paddr & !((1 << b) - 1), b))
            .unwrap();
        Ok(2 * u64::from(top - bits) + 1)
    }

    #[test]
    fn random_lists_and_addresses_carve_as_the_oracle_says() {
        let cases = if cfg!(miri) { 3 } else { 200 };
        // Carved, refused as not held, misaligned, for want of slots, for
        // want of halves.
        let mut outcomes = [0; 5];
        for seed in 1..=cases {
            let mut rng = Rng(0x9E37_79B9_7F4A_7C15 ^ seed);
            let (list, fb) = random_list(&mut rng);
            let mut c = Carver::from_list(FIRST, &list, fb);
            let mut k = Kernel::boot(FIRST, &list);
            let mut s = SlotAlloc::new(SlotRegion {
                start: 1000,
                end: 1000 + 100 + rng.below(1000),
            });
            let mut carved = std::vec::Vec::new();
            for step in 0..(if cfg!(miri) { 8 } else { 60 }) {
                let u = list[rng.below(list.len() as u64) as usize];
                let huge = rng.below(3) == 0;
                let (ty, bits) = if huge {
                    (ObjectType::Frame2M, 21)
                } else {
                    (ObjectType::Frame4K, 12)
                };
                let paddr = match rng.below(6) {
                    // Inside an untyped, aligned.
                    0..=2 => (u.paddr + rng.below(u.size())) & !((1 << bits) - 1),
                    // Near a frame carved before.
                    3 if !carved.is_empty() => {
                        let (p, _): (u64, u32) = carved[rng.below(carved.len() as u64) as usize];
                        (p & !((1 << bits) - 1)).wrapping_add(rng.below(3) << 12)
                    }
                    // Misaligned, or anywhere.
                    4 => u.paddr + 0x800,
                    _ => rng.next() & ((1 << 41) - 1) & !0xFFF,
                };
                let want = oracle(&list, fb, &carved, paddr, bits);
                let before = s.remaining();
                let got = carve(&mut c, &mut k, &mut s, paddr, ty);
                let ctx = format!("seed {seed} step {step}: {paddr:#x} {ty:?}");
                outcomes[match got {
                    Ok(_) => 0,
                    Err(CarveError::NotHeld { .. }) => 1,
                    Err(CarveError::BadRequest) => 2,
                    Err(CarveError::NoSlots { .. }) => 3,
                    Err(_) => 4,
                }] += 1;
                match (want, got) {
                    (Ok(cost), Ok(slot)) => {
                        assert_eq!(before - s.remaining(), cost, "{ctx}");
                        assert_eq!(
                            k.caps[&slot],
                            Obj::Frame {
                                paddr,
                                bits,
                                device: true
                            },
                            "{ctx}"
                        );
                        carved.push((paddr, bits));
                    }
                    (Ok(cost), Err(CarveError::NoSlots { need, left })) => {
                        assert_eq!((need, left, s.remaining()), (cost, before, before), "{ctx}");
                    }
                    (Ok(_), Err(CarveError::TooManyHalves)) => {
                        assert_eq!(s.remaining(), before, "{ctx}");
                    }
                    (want, got) => assert_eq!(want.map(|_| 0), got.map(|_| 0), "{ctx}"),
                }
                // The free model tiles each device untyped but the
                // framebuffer's, less what was carved, with aligned blocks.
                let free: u64 = c
                    .free()
                    .map(|(_, p, b)| {
                        assert_eq!(p % (1 << b), 0, "{ctx}");
                        1u64 << b
                    })
                    .sum();
                let device: u64 = list
                    .iter()
                    .enumerate()
                    .filter(|&(i, u)| u.device() && !fb.contains(FIRST + i as u64))
                    .map(|(_, u)| u.size())
                    .sum();
                let taken: u64 = carved.iter().map(|&(_, b)| 1u64 << b).sum();
                assert_eq!(free, device - taken, "{ctx}");
            }
        }
        std::println!("carved, not held, misaligned, no slots, no halves: {outcomes:?}");
        if !cfg!(miri) {
            assert!(outcomes.iter().all(|&n| n > 0), "{outcomes:?}");
        }
    }
}
