//! Capability addressing: resolving a `CPtr` through guarded CNodes
//! (`docs/design.md`, "Capability addressing").

use crate::cap::{Cap, CapType, low_mask};
use crate::error::{LookupFailure, SyscallError};
use crate::slot::{SlotAddr, SlotMemory};

/// Resolves the low `bits` bits of `cptr`, starting at the CNode `root`, as
/// seL4's `resolveAddressBits` does. Returns the slot reached and the bits
/// left there: the lookup stops early at a slot that does not hold a CNode
/// capability. `bits` is at most 64.
pub fn resolve<M: SlotMemory + ?Sized>(
    mem: &M,
    root: Cap,
    cptr: u64,
    bits: u32,
) -> Result<(SlotAddr, u32), LookupFailure> {
    debug_assert!(bits <= 64);
    if root.cap_type() != CapType::CNode {
        return Err(LookupFailure::InvalidRoot);
    }
    let mut node = root;
    let mut left = bits;
    loop {
        let guard_size = node.guard_size();
        let radix = node.radix();
        let guard = node.guard();
        if guard_size > left || bits_below(cptr, left, guard_size) != guard {
            return Err(LookupFailure::GuardMismatch {
                bits_left: left,
                guard,
                guard_size,
            });
        }
        if radix + guard_size > left {
            return Err(LookupFailure::DepthMismatch {
                bits_left: left,
                bits_found: radix + guard_size,
            });
        }
        let index = bits_below(cptr, left - guard_size, radix);
        left -= radix + guard_size;
        let slot = SlotAddr::new(node.object())
            .expect("a CNode capability names a slot address")
            .offset(index);
        if left == 0 {
            return Ok((slot, 0));
        }
        let cap = mem.load(slot).cap;
        if cap.cap_type() != CapType::CNode {
            return Ok((slot, left));
        }
        node = cap;
    }
}

/// The `width` bits of `cptr` just below bit `top`: bits `top - width` to
/// `top - 1`. `width <= top <= 64`.
fn bits_below(cptr: u64, top: u32, width: u32) -> u64 {
    cptr.checked_shr(top - width).unwrap_or(0) & low_mask(width)
}

/// A capability lookup: the invoked capability, an extra capability, a fault
/// endpoint. Resolves up to 64 bits from the thread's CSpace root and ignores
/// the bits left. The slot may be empty; the caller decides what that means.
pub fn lookup_cap<M: SlotMemory + ?Sized>(
    mem: &M,
    root: Cap,
    cptr: u64,
) -> Result<SlotAddr, LookupFailure> {
    resolve(mem, root, cptr, 64).map(|(slot, _)| slot)
}

/// A slot argument (root, index, depth) of a CNode or Untyped invocation:
/// resolves exactly `depth` bits. `depth` must be 1 to 64.
pub fn lookup_slot<M: SlotMemory + ?Sized>(
    mem: &M,
    root: Cap,
    index: u64,
    depth: u64,
    source: bool,
) -> Result<SlotAddr, SyscallError> {
    if root.cap_type() != CapType::CNode {
        return Err(SyscallError::FailedLookup {
            source,
            failure: LookupFailure::InvalidRoot,
        });
    }
    if depth == 0 || depth > 64 {
        return Err(SyscallError::RangeError { min: 1, max: 64 });
    }
    match resolve(mem, root, index, depth as u32) {
        Ok((slot, 0)) => Ok(slot),
        Ok((_, left)) => Err(SyscallError::FailedLookup {
            source,
            failure: LookupFailure::DepthMismatch {
                bits_left: left,
                bits_found: 0,
            },
        }),
        Err(failure) => Err(SyscallError::FailedLookup { source, failure }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testing::FakeMemory;

    const ROOT: u64 = 0x1000;
    const CHILD: u64 = 0x2000;

    /// A root CNode of 16 slots with a 4-bit guard 0b1010, whose slot 3 holds
    /// a CNode of 4 slots with no guard, whose slot 2 holds an endpoint.
    fn setup() -> (FakeMemory, Cap) {
        let mut mem = FakeMemory::new(0, 0x4000);
        let root = Cap::cnode(ROOT, 4, 4, 0b1010);
        let child = Cap::cnode(CHILD, 2, 0, 0);
        let ep = Cap::new(
            CapType::Endpoint,
            0x3000,
            5,
            crate::cap::Rights::ALL,
            false,
            0,
        );
        let mut s = mem.load(SlotAddr::new(ROOT + 3 * 32).unwrap());
        s.cap = child;
        mem.store(SlotAddr::new(ROOT + 3 * 32).unwrap(), s);
        let mut s = mem.load(SlotAddr::new(CHILD + 2 * 32).unwrap());
        s.cap = ep;
        mem.store(SlotAddr::new(CHILD + 2 * 32).unwrap(), s);
        (mem, root)
    }

    #[test]
    fn resolves_through_two_levels() {
        let (mem, root) = setup();
        // guard 1010, index 0011, then index 10: 10 bits.
        let cptr = 0b10_1000_1110;
        assert_eq!(
            resolve(&mem, root, cptr, 10),
            Ok((SlotAddr::new(CHILD + 2 * 32).unwrap(), 0))
        );
        // A capability lookup stops at the endpoint and ignores the rest.
        let cptr64 = cptr << 54 | 0x1234;
        assert_eq!(
            lookup_cap(&mem, root, cptr64),
            Ok(SlotAddr::new(CHILD + 2 * 32).unwrap())
        );
    }

    #[test]
    fn stops_at_a_non_cnode_with_bits_left() {
        let (mem, root) = setup();
        let cptr = 0b10_1001_0101;
        assert_eq!(
            resolve(&mem, root, cptr, 10),
            Ok((SlotAddr::new(ROOT + 5 * 32).unwrap(), 2))
        );
        assert_eq!(
            lookup_slot(&mem, root, cptr, 10, false),
            Err(SyscallError::FailedLookup {
                source: false,
                failure: LookupFailure::DepthMismatch {
                    bits_left: 2,
                    bits_found: 0
                }
            })
        );
    }

    #[test]
    fn guard_and_depth_failures() {
        let (mem, root) = setup();
        assert_eq!(
            resolve(&mem, root, 0b1110_0011, 8),
            Err(LookupFailure::GuardMismatch {
                bits_left: 8,
                guard: 0b1010,
                guard_size: 4
            })
        );
        assert_eq!(
            resolve(&mem, root, 0b101, 3),
            Err(LookupFailure::GuardMismatch {
                bits_left: 3,
                guard: 0b1010,
                guard_size: 4
            })
        );
        assert_eq!(
            resolve(&mem, root, 0b101_0001, 7),
            Err(LookupFailure::DepthMismatch {
                bits_left: 7,
                bits_found: 8
            })
        );
        // The child CNode needs 2 more bits than the 1 left.
        assert_eq!(
            resolve(&mem, root, 0b1_0100_0111, 9),
            Err(LookupFailure::DepthMismatch {
                bits_left: 1,
                bits_found: 2
            })
        );
    }

    #[test]
    fn roots_and_depth_ranges() {
        let (mem, root) = setup();
        assert_eq!(
            resolve(&mem, Cap::NULL, 0, 64),
            Err(LookupFailure::InvalidRoot)
        );
        assert_eq!(
            lookup_slot(&mem, root, 0, 0, true),
            Err(SyscallError::RangeError { min: 1, max: 64 })
        );
        assert_eq!(
            lookup_slot(&mem, root, 0, 65, true),
            Err(SyscallError::RangeError { min: 1, max: 64 })
        );
        assert_eq!(
            lookup_slot(&mem, Cap::NULL, 0, 0, true),
            Err(SyscallError::FailedLookup {
                source: true,
                failure: LookupFailure::InvalidRoot
            })
        );
    }

    #[test]
    fn full_width_guards_and_shifts() {
        // A 64-bit lookup through a radix-4 CNode with a 60-bit guard.
        let mut mem = FakeMemory::new(0, 0x2000);
        let guard = 0x0123_4567_89AB_CDEF & low_mask(60);
        let root = Cap::cnode(ROOT, 4, 60, guard);
        let _ = &mut mem;
        let cptr = (guard << 4) | 0x7;
        assert_eq!(
            resolve(&mem, root, cptr, 64),
            Ok((SlotAddr::new(ROOT + 7 * 32).unwrap(), 0))
        );
        // A radix-1 CNode without a guard consumes one bit; 64 bits stop at
        // its empty slot with 63 left.
        let tiny = Cap::cnode(ROOT, 1, 0, 0);
        assert_eq!(
            resolve(&mem, tiny, u64::MAX, 64),
            Ok((SlotAddr::new(ROOT + 32).unwrap(), 63))
        );
    }
}
