//! `Untyped_Retype`: the only allocator (`docs/design.md`, "Memory and
//! retype"; ADR 0010).
//!
//! An untyped allocates at its watermark, aligned up to each object's size,
//! while it has children, and is reset (cleared from the top down, watermark
//! 0) only when it has none. RAM at or above a watermark is always zero, so
//! new objects start zeroed.

use crate::cap::{
    Cap, CapType, MAX_CNODE_RADIX, MAX_UNTYPED_BITS, MIN_CNODE_RADIX, MIN_UNTYPED_BITS, ObjectType,
    RETYPE_FAN_OUT_LIMIT, TCB_SLOT_REPLY,
};
use crate::cdt;
use crate::error::{LookupFailure, SyscallError};
use crate::kernel::{Kernel, Preempted};
use crate::slot::SlotAddr;

/// Bytes a reset clears between preemption points.
pub const RESET_CHUNK: u64 = 4096;

/// The arguments of `Untyped_Retype` once its slot arguments are resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RetypeArgs {
    /// MR0, an object type number.
    pub object_type: u64,
    /// MR1: an untyped's size or a CNode's radix; ignored for other types.
    pub size_bits: u64,
    /// MR4, the first destination slot.
    pub node_offset: u64,
    /// MR5, how many objects to make.
    pub num_objects: u64,
}

/// Why a retype stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetypeError {
    /// It failed; nothing changed.
    Error(SyscallError),
    /// A preemption point stopped the reset; restart the call.
    Preempted,
}

impl From<SyscallError> for RetypeError {
    fn from(e: SyscallError) -> RetypeError {
        RetypeError::Error(e)
    }
}

impl From<Preempted> for RetypeError {
    fn from(_: Preempted) -> RetypeError {
        RetypeError::Preempted
    }
}

/// Retypes part of the untyped in `untyped` into `num_objects` objects and
/// puts their capabilities in consecutive slots of the CNode `dest`, from
/// `node_offset`. Checks run in the order `docs/abi.md` lists; nothing
/// changes unless all pass, except a reset a preemption interrupts, which
/// leaves a consistent untyped that the restarted call finishes.
pub fn retype<K: Kernel + ?Sized>(
    k: &mut K,
    untyped: SlotAddr,
    dest: Cap,
    args: RetypeArgs,
) -> Result<(), RetypeError> {
    let ut = k.load(untyped).cap;
    debug_assert!(ut.cap_type() == CapType::Untyped);
    let ty = ObjectType::from_number(args.object_type).ok_or(SyscallError::InvalidArgument(0))?;
    let size_bits = match ty {
        ObjectType::Untyped => in_range(args.size_bits, MIN_UNTYPED_BITS, MAX_UNTYPED_BITS)?,
        ObjectType::CNode => in_range(args.size_bits, MIN_CNODE_RADIX, MAX_CNODE_RADIX)?,
        _ => 0,
    };
    if dest.cap_type() != CapType::CNode {
        return Err(SyscallError::FailedLookup {
            source: false,
            failure: LookupFailure::MissingCapability { bits_left: 0 },
        }
        .into());
    }
    let slots = 1u64 << dest.radix();
    if args.node_offset >= slots {
        return Err(SyscallError::RangeError {
            min: 0,
            max: slots - 1,
        }
        .into());
    }
    if args.num_objects == 0 || args.num_objects > RETYPE_FAN_OUT_LIMIT {
        return Err(SyscallError::RangeError {
            min: 1,
            max: RETYPE_FAN_OUT_LIMIT,
        }
        .into());
    }
    if args.num_objects > slots - args.node_offset {
        return Err(SyscallError::RangeError {
            min: 1,
            max: slots - args.node_offset,
        }
        .into());
    }
    let first = SlotAddr::new(dest.object()).expect("a CNode capability names a slot address");
    for i in 0..args.num_objects {
        if !k.load(first.offset(args.node_offset + i)).cap.is_null() {
            return Err(SyscallError::DeleteFirst.into());
        }
    }
    let object_bits = ty.object_bits(size_bits);
    let has_children = cdt::has_children(k, untyped);
    let start = if has_children { ut.watermark() } else { 0 };
    let free = (1u64 << ut.size_bits()) - start;
    if free >> object_bits < args.num_objects {
        return Err(SyscallError::NotEnoughMemory(free).into());
    }
    if ut.is_device()
        && !matches!(
            ty,
            ObjectType::Untyped | ObjectType::Frame4K | ObjectType::Frame2M
        )
    {
        return Err(SyscallError::InvalidArgument(0).into());
    }
    if cdt::child_too_deep(k, untyped) {
        return Err(SyscallError::IllegalOperation.into());
    }

    if !has_children {
        reset(k, untyped)?;
    }
    let aligned = align_up(start, object_bits);
    let mut s = k.load(untyped);
    s.cap = s.cap.with_data(aligned + (args.num_objects << object_bits));
    k.store(untyped, s);
    for i in 0..args.num_objects {
        let paddr = ut.object() + aligned + (i << object_bits);
        let cap = new_object_cap(ty, paddr, object_bits, ut.is_device());
        k.init_object(cap);
        let dst = first.offset(args.node_offset + i);
        cdt::insert_derived(k, untyped, dst, cap, true)
            .expect("the depth limit was checked before the reset");
        if ty == ObjectType::Tcb {
            let reply = SlotAddr::new(paddr)
                .expect("a TCB is a slot address")
                .offset(TCB_SLOT_REPLY);
            cdt::insert_root(k, reply, Cap::reply(paddr, true, true));
        }
    }
    Ok(())
}

/// Clears the untyped in `untyped` below its watermark, from the top down in
/// [`RESET_CHUNK`]s, lowering the watermark after each and passing a
/// preemption point while any is left. A device untyped only has its
/// watermark set to 0 (seL4 `resetUntypedCap`).
fn reset<K: Kernel + ?Sized>(k: &mut K, untyped: SlotAddr) -> Result<(), Preempted> {
    let ut = k.load(untyped).cap;
    if ut.is_device() {
        set_watermark(k, untyped, 0);
        return Ok(());
    }
    let mut watermark = ut.watermark();
    while watermark > 0 {
        let low = (watermark - 1) & !(RESET_CHUNK - 1);
        k.zero(ut.object() + low, watermark - low);
        watermark = low;
        set_watermark(k, untyped, watermark);
        if watermark > 0 {
            k.preempt()?;
        }
    }
    Ok(())
}

fn set_watermark<K: Kernel + ?Sized>(k: &mut K, untyped: SlotAddr, watermark: u64) {
    let mut s = k.load(untyped);
    s.cap = s.cap.with_data(watermark);
    k.store(untyped, s);
}

/// The capability retype makes for a new object: every right its type uses.
fn new_object_cap(ty: ObjectType, paddr: u64, object_bits: u32, device: bool) -> Cap {
    match ty {
        ObjectType::Untyped => Cap::untyped(paddr, object_bits, device, 0),
        ObjectType::CNode => Cap::cnode(paddr, object_bits - crate::cap::SLOT_BITS, 0, 0),
        _ => Cap::new(
            ty.cap_type(),
            paddr,
            object_bits,
            ty.full_rights(),
            device,
            0,
        ),
    }
}

fn in_range(v: u64, min: u32, max: u32) -> Result<u32, SyscallError> {
    if v < min as u64 || v > max as u64 {
        Err(SyscallError::RangeError {
            min: min as u64,
            max: max as u64,
        })
    } else {
        Ok(v as u32)
    }
}

fn align_up(v: u64, bits: u32) -> u64 {
    let mask = (1u64 << bits) - 1;
    (v + mask) & !mask
}
