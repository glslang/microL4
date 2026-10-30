//! Scenario tests of the capability core over fake memory. The random
//! sequences against a reference model live in `model/`.

use std::format;
use std::vec;
use std::vec::Vec;

use crate::cap::{
    Cap, CapType, MAX_DERIVATION_DEPTH, ObjectType, Rights, TCB_BITS, TCB_SLOT_REPLY, cnode_data,
};
use crate::cdt;
use crate::cnode;
use crate::error::{LookupFailure, SyscallError};
use crate::kernel::Preempted;
use crate::slot::{SlotAddr, SlotMemory};
use crate::testing::{DIRT, Event, TestKernel};
use crate::untyped::{RetypeArgs, RetypeError, retype};

/// The root CNode: 64 slots at 0x1000.
const ROOT: u64 = 0x1000;
const ROOT_RADIX: u32 = 6;
/// A 64 KiB boot untyped at 64 KiB, in root slot 1. Small, so Miri runs
/// these tests in reasonable time.
const UT: u64 = 0x1_0000;
const UT_BITS: u32 = 16;
/// A 64 KiB device untyped above it.
const DEV: u64 = 0x2_0000;

struct World {
    k: TestKernel,
}

impl World {
    /// Fake memory for the root CNode and the untyped, with the untyped as
    /// a boot root in slot 1 and its watermark at its size, as boot leaves it.
    fn new() -> World {
        let mut k = TestKernel::new(0, 0x3_0000);
        cdt::insert_root(
            &mut k,
            slot(ROOT, 1),
            Cap::untyped(UT, UT_BITS, false, 1 << UT_BITS),
        );
        World { k }
    }

    fn root() -> Cap {
        Cap::cnode(ROOT, ROOT_RADIX, 64 - ROOT_RADIX, 0)
    }

    fn cap(&self, s: SlotAddr) -> Cap {
        self.k.load(s).cap
    }

    /// Retypes `n` objects from the untyped in root slot `ut` into `dest`
    /// from `offset`, with no preemption.
    fn retype(&mut self, ut: u64, ty: ObjectType, size_bits: u64, dest: Cap, offset: u64, n: u64) {
        retype(
            &mut self.k,
            slot(ROOT, ut),
            dest,
            RetypeArgs {
                object_type: ty as u64,
                size_bits,
                node_offset: offset,
                num_objects: n,
            },
        )
        .unwrap();
    }

    /// Runs `op` until it is not preempted, preempting at the `every`-th
    /// point each time; returns how many times it was preempted.
    fn until_done(
        &mut self,
        every: u64,
        op: impl Fn(&mut TestKernel) -> Result<(), Preempted>,
    ) -> u32 {
        let mut n = 0;
        loop {
            self.k.preempt_in = Some(every);
            match op(&mut self.k) {
                Ok(()) => {
                    self.k.preempt_in = None;
                    return n;
                }
                Err(Preempted) => {
                    n += 1;
                    self.check(ROOT, 1 << ROOT_RADIX);
                }
            }
        }
    }

    /// Checks the list invariants of `count` slots from `base`.
    fn check(&self, base: u64, count: u64) {
        for i in 0..count {
            cdt::check_slot(&self.k, slot(base, i)).unwrap();
        }
    }

    fn finalised_last(&self) -> Vec<Cap> {
        self.k
            .events
            .iter()
            .filter_map(|e| match e {
                Event::Finalise { cap, last: true } => Some(*cap),
                _ => None,
            })
            .collect()
    }
}

fn slot(base: u64, i: u64) -> SlotAddr {
    SlotAddr::new(base).unwrap().offset(i)
}

fn ep(object: u64) -> Cap {
    Cap::new(CapType::Endpoint, object, 5, Rights::ALL, false, 0)
}

#[test]
fn retype_places_aligned_objects_as_children() {
    let mut w = World::new();
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 10, 3);
    // The first retype resets the boot untyped, then allocates from 0.
    assert!(w.k.events.contains(&Event::Zero {
        paddr: UT + (1 << UT_BITS) - 4096,
        len: 4096
    }));
    for i in 0..3 {
        let c = w.cap(slot(ROOT, 10 + i));
        assert_eq!(c, ep(UT + 32 * i));
        assert_eq!(cdt::parent(&w.k, slot(ROOT, 10 + i)), Some(slot(ROOT, 1)));
        assert!(cdt::is_final(&w.k, slot(ROOT, 10 + i)));
    }
    assert_eq!(w.cap(slot(ROOT, 1)).watermark(), 96);
    // A CNode needs 2^(radix + 5) alignment: radix 4 is 512 bytes.
    w.retype(1, ObjectType::CNode, 4, World::root(), 20, 1);
    assert_eq!(w.cap(slot(ROOT, 20)), Cap::cnode(UT + 512, 4, 0, 0));
    assert_eq!(w.cap(slot(ROOT, 1)).watermark(), 1024);
    w.check(ROOT, 64);
}

#[test]
fn retype_errors_in_order() {
    let mut w = World::new();
    let args = |ty: ObjectType, size_bits, off, n| RetypeArgs {
        object_type: ty as u64,
        size_bits,
        node_offset: off,
        num_objects: n,
    };
    let ut = slot(ROOT, 1);
    let e = |w: &mut World, a: RetypeArgs, dest: Cap| retype(&mut w.k, ut, dest, a);
    let err = |s| Err(RetypeError::Error(s));
    let root = World::root();
    assert_eq!(
        e(
            &mut w,
            RetypeArgs {
                object_type: 11,
                ..args(ObjectType::Tcb, 0, 0, 1)
            },
            root
        ),
        err(SyscallError::InvalidArgument(0))
    );
    assert_eq!(
        e(&mut w, args(ObjectType::Untyped, 3, 0, 1), root),
        err(SyscallError::RangeError { min: 4, max: 47 })
    );
    assert_eq!(
        e(&mut w, args(ObjectType::CNode, 43, 0, 1), root),
        err(SyscallError::RangeError { min: 1, max: 42 })
    );
    assert_eq!(
        e(&mut w, args(ObjectType::Tcb, 0, 64, 1), root),
        err(SyscallError::RangeError { min: 0, max: 63 })
    );
    assert_eq!(
        e(&mut w, args(ObjectType::Tcb, 0, 0, 257), root),
        err(SyscallError::RangeError { min: 1, max: 256 })
    );
    assert_eq!(
        e(&mut w, args(ObjectType::Tcb, 0, 60, 5), root),
        err(SyscallError::RangeError { min: 1, max: 4 })
    );
    assert_eq!(
        e(&mut w, args(ObjectType::Tcb, 0, 0, 2), root),
        err(SyscallError::DeleteFirst)
    );
    assert_eq!(
        e(
            &mut w,
            args(ObjectType::Untyped, UT_BITS as u64 + 1, 2, 1),
            root
        ),
        err(SyscallError::NotEnoughMemory(1 << UT_BITS))
    );
    // Nothing above changed the untyped or wrote memory.
    assert_eq!(w.cap(ut).watermark(), 1 << UT_BITS);
    assert!(w.k.events.is_empty());
}

#[test]
fn has_children_allocates_at_the_watermark_and_never_resets() {
    let mut w = World::new();
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 10, 1);
    w.retype(1, ObjectType::Frame4K, 0, World::root(), 11, 1);
    // The frame is aligned up past the endpoint.
    assert_eq!(w.cap(slot(ROOT, 11)).object(), UT + 4096);
    let zeros =
        w.k.events
            .iter()
            .filter(|e| matches!(e, Event::Zero { .. }))
            .count();
    assert_eq!(zeros, 1 << (UT_BITS - 12), "only the first retype resets");
    // Revoking frees the untyped; the next retype resets it and reuses the
    // same addresses, clearing what init_object wrote.
    assert_eq!(w.k.mem.read(UT), DIRT);
    cnode::revoke(&mut w.k, slot(ROOT, 1)).unwrap();
    assert!(!cdt::has_children(&w.k, slot(ROOT, 1)));
    w.retype(1, ObjectType::CNode, 1, World::root(), 12, 1);
    assert_eq!(w.cap(slot(ROOT, 12)).object(), UT);
    // The new CNode's slots are empty and everything else is zero again.
    assert!(w.k.mem.is_zero(UT, 1 << UT_BITS));
}

#[test]
fn preempted_reset_restarts_and_completes() {
    let mut w = World::new();
    let dest = World::root();
    let mut preempted = 0;
    loop {
        w.k.preempt_in = Some(3);
        let r = retype(
            &mut w.k,
            slot(ROOT, 1),
            dest,
            RetypeArgs {
                object_type: ObjectType::Frame4K as u64,
                size_bits: 0,
                node_offset: 5,
                num_objects: 2,
            },
        );
        match r {
            Ok(()) => break,
            Err(RetypeError::Preempted) => {
                preempted += 1;
                // Zero from the watermark up at every interruption.
                let wm = w.cap(slot(ROOT, 1)).watermark();
                assert!(w.k.mem.is_zero(UT + wm, (1 << UT_BITS) - wm));
                assert!(w.cap(slot(ROOT, 5)).is_null());
            }
            Err(e) => panic!("{e:?}"),
        }
    }
    // Four chunks between preemption points, the last one free.
    assert_eq!(preempted, (1 << (UT_BITS - 12)) / 4 - 1);
    assert_eq!(w.cap(slot(ROOT, 1)).watermark(), 8192);
    assert_eq!(w.cap(slot(ROOT, 6)).object(), UT + 4096);
}

#[test]
fn device_untyped_makes_only_frames_and_is_never_cleared() {
    let mut w = World::new();
    cdt::insert_root(
        &mut w.k,
        slot(ROOT, 2),
        Cap::untyped(DEV, 16, true, 1 << 16),
    );
    let r = retype(
        &mut w.k,
        slot(ROOT, 2),
        World::root(),
        RetypeArgs {
            object_type: ObjectType::Endpoint as u64,
            size_bits: 0,
            node_offset: 3,
            num_objects: 1,
        },
    );
    assert_eq!(r, Err(RetypeError::Error(SyscallError::InvalidArgument(0))));
    w.retype(2, ObjectType::Frame4K, 0, World::root(), 3, 1);
    let f = w.cap(slot(ROOT, 3));
    assert!(f.is_device() && f.cap_type() == CapType::Frame);
    assert!(!w.k.events.iter().any(|e| matches!(e, Event::Zero { .. })));
}

#[test]
fn tcb_retype_makes_a_reply_master_root() {
    let mut w = World::new();
    w.retype(1, ObjectType::Tcb, 0, World::root(), 4, 1);
    let tcb = w.cap(slot(ROOT, 4));
    assert_eq!((tcb.cap_type(), tcb.size_bits()), (CapType::Tcb, TCB_BITS));
    let master = slot(tcb.object(), TCB_SLOT_REPLY);
    let s = w.k.load(master);
    assert_eq!(s.cap, Cap::reply(tcb.object(), true, true));
    assert_eq!(
        (s.node.depth(), s.node.original(), s.node.prev()),
        (0, true, None)
    );
    // Deleting the TCB clears its slots, the master included.
    cnode::delete(&mut w.k, slot(ROOT, 4)).unwrap();
    assert!(w.k.load(master).cap.is_null());
    assert!(w.cap(slot(ROOT, 4)).is_null());
    assert_eq!(
        w.finalised_last(),
        [tcb, Cap::reply(tcb.object(), true, true)]
    );
}

#[test]
fn copies_are_children_of_originals_and_siblings_of_copies() {
    let mut w = World::new();
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 10, 1);
    cnode::copy(
        &mut w.k,
        slot(ROOT, 10),
        slot(ROOT, 11),
        Rights::READ.0 as u64 | 1,
    )
    .unwrap();
    cnode::copy(
        &mut w.k,
        slot(ROOT, 11),
        slot(ROOT, 12),
        Rights::ALL.0 as u64,
    )
    .unwrap();
    let c11 = w.k.load(slot(ROOT, 11));
    let c12 = w.k.load(slot(ROOT, 12));
    // Rights only shrink: the copy of the copy keeps Write and Read.
    assert_eq!(c11.cap.rights(), Rights(3));
    assert_eq!(c12.cap.rights(), Rights(3));
    assert_eq!((c11.node.depth(), c11.node.original()), (2, false));
    assert_eq!((c12.node.depth(), c12.node.original()), (2, false));
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 12)), Some(slot(ROOT, 10)));
    assert!(!cdt::has_children(&w.k, slot(ROOT, 11)));
    assert!(cdt::has_children(&w.k, slot(ROOT, 10)));
    // Three capabilities to one endpoint: none is final until two go.
    assert!(!cdt::is_final(&w.k, slot(ROOT, 10)));
    cnode::delete(&mut w.k, slot(ROOT, 11)).unwrap();
    cnode::delete(&mut w.k, slot(ROOT, 12)).unwrap();
    assert!(cdt::is_final(&w.k, slot(ROOT, 10)));
    assert!(w.finalised_last().is_empty());
    w.check(ROOT, 64);
}

#[test]
fn mint_badges_and_guards() {
    let mut w = World::new();
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 10, 1);
    w.retype(1, ObjectType::CNode, 2, World::root(), 20, 1);
    cnode::mint(&mut w.k, slot(ROOT, 10), slot(ROOT, 11), 0xF, 7).unwrap();
    let badged = w.k.load(slot(ROOT, 11));
    assert_eq!(badged.cap.badge(), 7);
    assert!(badged.node.original());
    // A badged capability cannot be minted again, even with badge 0.
    assert_eq!(
        cnode::mint(&mut w.k, slot(ROOT, 11), slot(ROOT, 12), 0xF, 0),
        Err(SyscallError::IllegalOperation)
    );
    // Its copies are its children; revoking it leaves the original.
    cnode::copy(&mut w.k, slot(ROOT, 11), slot(ROOT, 12), 0xF).unwrap();
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 12)), Some(slot(ROOT, 11)));
    cnode::revoke(&mut w.k, slot(ROOT, 11)).unwrap();
    assert!(w.cap(slot(ROOT, 12)).is_null());
    assert_eq!(w.cap(slot(ROOT, 10)).badge(), 0);
    // Guards must fit with the radix.
    assert_eq!(
        cnode::mint(
            &mut w.k,
            slot(ROOT, 20),
            slot(ROOT, 21),
            0,
            cnode_data(63, 0)
        ),
        Err(SyscallError::IllegalOperation)
    );
    cnode::mint(
        &mut w.k,
        slot(ROOT, 20),
        slot(ROOT, 21),
        0,
        cnode_data(62, 5),
    )
    .unwrap();
    assert_eq!(
        (
            w.cap(slot(ROOT, 21)).guard_size(),
            w.cap(slot(ROOT, 21)).guard()
        ),
        (62, 5)
    );
    assert_eq!(
        cnode::mutate(&mut w.k, slot(ROOT, 10), slot(ROOT, 30), 1),
        Err(SyscallError::IllegalOperation)
    );
}

#[test]
fn derive_refusals() {
    let mut w = World::new();
    w.retype(1, ObjectType::PageTable, 0, World::root(), 10, 1);
    w.retype(1, ObjectType::Frame4K, 0, World::root(), 11, 1);
    w.retype(1, ObjectType::Untyped, 12, World::root(), 12, 1);
    assert_eq!(
        cnode::copy(&mut w.k, slot(ROOT, 10), slot(ROOT, 20), 0xF),
        Err(SyscallError::IllegalOperation)
    );
    // A mapped frame's copy is unmapped.
    let mut s = w.k.load(slot(ROOT, 11));
    s.cap = s.cap.with_data(0xABC);
    w.k.store(slot(ROOT, 11), s);
    cnode::copy(&mut w.k, slot(ROOT, 11), slot(ROOT, 21), 0xF).unwrap();
    assert_eq!(w.cap(slot(ROOT, 21)).data, 0);
    // The boot untyped has children now.
    assert_eq!(
        cnode::copy(&mut w.k, slot(ROOT, 1), slot(ROOT, 22), 0xF),
        Err(SyscallError::RevokeFirst)
    );
    // A childless untyped copies: the copy keeps the watermark, the source
    // becomes full.
    w.retype(12, ObjectType::Endpoint, 0, World::root(), 23, 1);
    cnode::delete(&mut w.k, slot(ROOT, 23)).unwrap();
    let wm = w.cap(slot(ROOT, 12)).watermark();
    cnode::copy(&mut w.k, slot(ROOT, 12), slot(ROOT, 24), 0).unwrap();
    assert_eq!(w.cap(slot(ROOT, 24)).watermark(), wm);
    assert_eq!(w.cap(slot(ROOT, 12)).watermark(), 1 << 12);
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 24)), Some(slot(ROOT, 12)));
    assert_eq!(
        cnode::copy(&mut w.k, slot(ROOT, 25), slot(ROOT, 26), 0),
        Err(SyscallError::FailedLookup {
            source: true,
            failure: LookupFailure::MissingCapability { bits_left: 0 }
        })
    );
    assert_eq!(
        cnode::copy(&mut w.k, slot(ROOT, 12), slot(ROOT, 1), 0),
        Err(SyscallError::DeleteFirst)
    );
}

#[test]
fn deleting_from_the_middle_passes_children_to_the_nearest_ancestor() {
    // The design's example: U(0) A(1) X(1) C(2); delete X, then revoke A
    // keeps C and revoke U takes it. Each retype puts its child first, so
    // retype X, then A.
    let mut w = World::new();
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 11, 1); // X
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 10, 1); // A
    cnode::copy(&mut w.k, slot(ROOT, 11), slot(ROOT, 12), 0xF).unwrap(); // C
    let order = |w: &World, s: u64| w.k.load(slot(ROOT, s)).node.next();
    assert_eq!(order(&w, 1), Some(slot(ROOT, 10)));
    assert_eq!(order(&w, 10), Some(slot(ROOT, 11)));
    assert_eq!(order(&w, 11), Some(slot(ROOT, 12)));
    cnode::delete(&mut w.k, slot(ROOT, 11)).unwrap();
    assert_eq!(order(&w, 10), Some(slot(ROOT, 12)));
    assert_eq!(w.k.load(slot(ROOT, 12)).node.low(), 1);
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 12)), Some(slot(ROOT, 1)));
    assert!(!cdt::has_children(&w.k, slot(ROOT, 10)));
    cnode::revoke(&mut w.k, slot(ROOT, 10)).unwrap();
    assert!(!w.cap(slot(ROOT, 12)).is_null());
    cnode::revoke(&mut w.k, slot(ROOT, 1)).unwrap();
    assert!(w.cap(slot(ROOT, 12)).is_null() && w.cap(slot(ROOT, 10)).is_null());
    w.check(ROOT, 64);
}

#[test]
fn move_and_rotate_keep_the_list() {
    let mut w = World::new();
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 10, 3);
    cnode::move_cap(&mut w.k, slot(ROOT, 11), slot(ROOT, 40)).unwrap();
    assert!(w.cap(slot(ROOT, 11)).is_null());
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 40)), Some(slot(ROOT, 1)));
    // Rotate: 12 -> 41, 40 -> 12.
    cnode::rotate(
        &mut w.k,
        slot(ROOT, 41),
        0,
        slot(ROOT, 12),
        0,
        slot(ROOT, 40),
    )
    .unwrap_err();
    let e12 = w.cap(slot(ROOT, 12));
    let e40 = w.cap(slot(ROOT, 40));
    // Endpoint data words are refused by Rotate as by Mutate, so rotate
    // two CNodes instead.
    w.retype(1, ObjectType::CNode, 1, World::root(), 50, 2);
    let c50 = w.cap(slot(ROOT, 50));
    let c51 = w.cap(slot(ROOT, 51));
    cnode::rotate(
        &mut w.k,
        slot(ROOT, 52),
        cnode_data(3, 1),
        slot(ROOT, 51),
        cnode_data(2, 2),
        slot(ROOT, 50),
    )
    .unwrap();
    assert_eq!(w.cap(slot(ROOT, 52)), c51.with_data(cnode_data(3, 1)));
    assert_eq!(w.cap(slot(ROOT, 51)), c50.with_data(cnode_data(2, 2)));
    assert!(w.cap(slot(ROOT, 50)).is_null());
    // As a swap: destination is the source.
    cnode::rotate(
        &mut w.k,
        slot(ROOT, 52),
        0,
        slot(ROOT, 51),
        0,
        slot(ROOT, 52),
    )
    .unwrap();
    assert_eq!(w.cap(slot(ROOT, 52)), c50);
    assert_eq!(w.cap(slot(ROOT, 51)), c51);
    assert_eq!((e12, e40), (w.cap(slot(ROOT, 12)), w.cap(slot(ROOT, 40))));
    assert_eq!(
        cnode::rotate(
            &mut w.k,
            slot(ROOT, 52),
            0,
            slot(ROOT, 52),
            0,
            slot(ROOT, 51)
        ),
        Err(SyscallError::IllegalOperation)
    );
    w.check(ROOT, 64);
    let moves =
        w.k.events
            .iter()
            .filter(|e| matches!(e, Event::Moved { .. }))
            .count();
    assert_eq!(moves, 5);
}

#[test]
fn deleting_a_cnode_clears_it_preemptibly() {
    let mut w = World::new();
    w.retype(1, ObjectType::CNode, 4, World::root(), 20, 1);
    let c = w.cap(slot(ROOT, 20));
    // Fill it with endpoints.
    w.retype(1, ObjectType::Endpoint, 0, c, 0, 16);
    let n = w.until_done(2, |k| cnode::delete(k, slot(ROOT, 20)));
    assert!(n >= 5, "preempted {n} times");
    assert!(w.cap(slot(ROOT, 20)).is_null());
    for i in 0..16 {
        assert!(w.k.load(slot(c.object(), i)).cap.is_null());
    }
    assert_eq!(w.finalised_last().len(), 16);
    assert!(!cdt::has_children(&w.k, slot(ROOT, 1)));
    w.check(c.object(), 16);
}

#[test]
fn nested_deletion_detaches_the_inner_cnode() {
    let mut w = World::new();
    w.retype(1, ObjectType::CNode, 2, World::root(), 20, 2);
    let a = w.cap(slot(ROOT, 20));
    let b = w.cap(slot(ROOT, 21));
    // B holds two endpoints; A holds the only capability to B in slot 1.
    w.retype(1, ObjectType::Endpoint, 0, b, 0, 2);
    cnode::move_cap(&mut w.k, slot(ROOT, 21), slot(a.object(), 1)).unwrap();
    cnode::delete(&mut w.k, slot(ROOT, 20)).unwrap();
    assert!(w.cap(slot(ROOT, 20)).is_null());
    // B's slot 0 capability was deleted and B's Zombie sits there, its
    // count untouched; B's slot 1 is unreachable but alive.
    let z = w.k.load(slot(b.object(), 0)).cap;
    assert_eq!(z, Cap::zombie(b.object(), b.size_bits(), 4, false));
    assert!(!w.k.load(slot(b.object(), 1)).cap.is_null());
    // Revoking the untyped reaches the Zombie and clears B.
    w.check(b.object(), 4);
    cnode::revoke(&mut w.k, slot(ROOT, 1)).unwrap();
    for i in 0..4 {
        assert!(w.k.load(slot(b.object(), i)).cap.is_null());
    }
    assert!(!cdt::has_children(&w.k, slot(ROOT, 1)));
}

#[test]
fn a_cnode_holding_its_only_capability_is_cleared_by_revoke() {
    let mut w = World::new();
    w.retype(1, ObjectType::CNode, 1, World::root(), 20, 1);
    let c = w.cap(slot(ROOT, 20));
    w.retype(1, ObjectType::Endpoint, 0, c, 1, 1);
    cnode::move_cap(&mut w.k, slot(ROOT, 20), slot(c.object(), 0)).unwrap();
    let n = w.until_done(1, |k| cnode::revoke(k, slot(ROOT, 1)));
    assert!(n > 0);
    assert!(w.k.load(slot(c.object(), 0)).cap.is_null());
    assert!(w.k.load(slot(c.object(), 1)).cap.is_null());
    assert!(!cdt::has_children(&w.k, slot(ROOT, 1)));
    assert!(w.finalised_last().contains(&ep(c.object() + 64)));
}

/// Runs `op` on worlds from `setup`, preempted once at each preemption
/// point in turn and then at every point, restarting it until it
/// completes; each run must end with the memory and hook calls of `whole`,
/// the unpreempted run, and the `(base, count)` slot ranges of `slots` must
/// pass `check` at every preemption. Returns how many points there are.
fn ends_the_same_preempted_or_not(
    whole: &World,
    setup: impl Fn() -> World,
    op: impl Fn(&mut TestKernel) -> Result<(), Preempted>,
    slots: &[(u64, u64)],
) -> u64 {
    let mut points = 0;
    loop {
        let mut w = setup();
        w.k.preempt_in = Some(points);
        let mut preempted = false;
        while op(&mut w.k) == Err(Preempted) {
            preempted = true;
            for &(base, count) in slots {
                w.check(base, count);
            }
        }
        assert!(w.k.mem == whole.k.mem, "preempted at point {points}");
        assert_eq!(w.k.events, whole.k.events, "preempted at point {points}");
        if !preempted {
            break;
        }
        points += 1;
    }
    let mut w = setup();
    w.until_done(0, &op);
    assert!(w.k.mem == whole.k.mem, "preempted at every point");
    assert_eq!(w.k.events, whole.k.events, "preempted at every point");
    points
}

/// CNodes C and D, from different untyped, hold each other's only
/// capabilities: C's in D's slot 0, D's in C's slot 0. Revoking C's untyped
/// deletes C's capability in D's slot 0; clearing C meets D's last
/// capability, and the nested deletion swaps D's Zombie into the slot being
/// deleted. A restarted revoke finds its work only among the untyped's
/// descendants, which D's Zombie is not, so the deletion ends there: D stays
/// detached in its own slot 0, as after any nested deletion, and the revoke
/// ends in the same state wherever it is preempted. (seL4 goes on to clear
/// D, and abandons it half-cleared if preempted while doing so.)
#[test]
fn revoke_through_a_cycle_of_cnodes_ends_the_same_preempted_or_not() {
    let setup = || {
        let mut w = World::new();
        cdt::insert_root(
            &mut w.k,
            slot(ROOT, 2),
            Cap::untyped(DEV, UT_BITS, false, 1 << UT_BITS),
        );
        w.retype(1, ObjectType::CNode, 1, World::root(), 20, 1);
        w.retype(2, ObjectType::CNode, 2, World::root(), 21, 1);
        let (c, d) = (w.cap(slot(ROOT, 20)), w.cap(slot(ROOT, 21)));
        w.retype(2, ObjectType::Endpoint, 0, d, 1, 1);
        cnode::move_cap(&mut w.k, slot(ROOT, 20), slot(d.object(), 0)).unwrap();
        cnode::move_cap(&mut w.k, slot(ROOT, 21), slot(c.object(), 0)).unwrap();
        w.k.events.clear();
        (w, c, d)
    };

    let (mut whole, c, d) = setup();
    cnode::revoke(&mut whole.k, slot(ROOT, 1)).unwrap();
    let detached = Cap::zombie(d.object(), d.size_bits(), 4, false);
    assert_eq!(whole.cap(slot(d.object(), 0)), detached);
    assert_eq!(whole.cap(slot(d.object(), 1)), ep(d.object() + 128));
    assert!(whole.cap(slot(c.object(), 0)).is_null());
    assert!(!cdt::has_children(&whole.k, slot(ROOT, 1)));
    assert_eq!(
        cdt::parent(&whole.k, slot(d.object(), 0)),
        Some(slot(ROOT, 2))
    );
    assert!(whole.finalised_last().is_empty());
    whole.check(c.object(), 2);
    whole.check(d.object(), 4);

    let points = ends_the_same_preempted_or_not(
        &whole,
        || setup().0,
        |k| cnode::revoke(k, slot(ROOT, 1)),
        &[(c.object(), 2), (d.object(), 4)],
    );
    assert!(points >= 2, "only {points} preemption points");

    // A revoke of D's untyped reaches the Zombie and clears D.
    cnode::revoke(&mut whole.k, slot(ROOT, 2)).unwrap();
    assert!((0..4).all(|i| whole.cap(slot(d.object(), i)).is_null()));
    assert_eq!(whole.finalised_last(), [ep(d.object() + 128)]);
    assert!(!cdt::has_children(&whole.k, slot(ROOT, 2)));
}

/// The root CNode with no guard, as a thread's CSpace root: a 6-bit `CPtr`
/// names a root slot, and 6 more bits than a CNode's radix name a slot of a
/// CNode whose capability lies in a root slot.
fn user_root() -> Cap {
    Cap::cnode(ROOT, ROOT_RADIX, 0, 0)
}

/// The `CPtr` and depth that name slot `i` of the CNode `c`, through its
/// capability in root slot `at`, from [`user_root`].
fn path(at: u64, c: Cap, i: u64) -> (u64, u64) {
    ((at << c.radix()) | i, u64::from(ROOT_RADIX + c.radix()))
}

/// A slot operation `op` as the kernel runs it (`docs/design.md`,
/// "System-call dispatch"): looks the slot `named` names up from
/// [`user_root`] and runs `op` on it, and on a preemption does both again.
/// Attempt `k` is preempted after `schedule[k]` preemption points, and past
/// the end of `schedule` not at all. Returns what the call returns: `Ok`,
/// or the failed lookup of a restart.
fn call(
    w: &mut World,
    named: (u64, u64),
    schedule: &[u64],
    op: fn(&mut TestKernel, SlotAddr) -> Result<(), Preempted>,
) -> Result<(), SyscallError> {
    let mut attempt = 0;
    loop {
        let at = crate::cspace::lookup_slot(&w.k, user_root(), named.0, named.1, false)?;
        w.k.preempt_in = schedule.get(attempt).copied();
        let r = op(&mut w.k, at);
        w.k.preempt_in = None;
        if r.is_ok() {
            return Ok(());
        }
        w.check(ROOT, 1 << ROOT_RADIX);
        attempt += 1;
    }
}

/// `CNode_Revoke` as the kernel runs it: see [`call`].
fn revoke_call(w: &mut World, named: (u64, u64), schedule: &[u64]) -> Result<(), SyscallError> {
    call(w, named, schedule, cnode::revoke)
}

/// Every capability finalised as the last one, in a fixed order.
fn finalised_last_sorted(w: &World) -> Vec<Cap> {
    let mut v = w.finalised_last();
    v.sort_by_key(|c| (c.header, c.data));
    v
}

/// The boot untyped's child U, revoked from a slot of a CNode C made from
/// it, named through the root's capability to C, while C's last capability
/// lies in C itself: the shape of the random failure behind 2c60870. The
/// revoke deletes the root's capability, ending its slot's lookup path,
/// then C's last one, whose clearing deletes U's slot: a partial revoke
/// (`docs/design.md`, "Slot operations"). Unpreempted, it ends as seL4's
/// does. Preempted at any point, its restart fails its lookup and the call
/// returns, leaving work in C, which no lookup reaches: sometimes no Zombie
/// at all, U and C's last capability still in C, sometimes C's Zombie
/// part-cleared, sometimes U moved by a nested deletion that never
/// finished. Every slot stays consistent, and a revoke of the boot untyped,
/// U's parent, finishes the work: memory ends as after the unpreempted
/// revoke and the same revoke of the boot untyped, with the same
/// capabilities finalised once each.
///
/// - C's last capability in slot 3, U in slot 1.
/// - The same with U in slot 2 and, in slot 1, an endpoint from another
///   untyped.
/// - C of two slots, its last capability in slot 1, U in slot 0.
#[test]
fn a_revoke_that_destroys_its_own_slot_is_finished_by_an_ancestor_revoke() {
    let shapes = [(2, 3, 1, None), (2, 3, 2, Some(1)), (1, 1, 0, None)];
    for (radix, last, u, endpoint) in shapes {
        let setup = || {
            let mut w = World::new();
            cdt::insert_root(
                &mut w.k,
                slot(ROOT, 2),
                Cap::untyped(DEV, UT_BITS, false, 1 << UT_BITS),
            );
            w.retype(1, ObjectType::Untyped, 12, World::root(), 30, 1);
            w.retype(30, ObjectType::CNode, radix, World::root(), 20, 1);
            let c = w.cap(slot(ROOT, 20));
            if let Some(i) = endpoint {
                w.retype(2, ObjectType::Endpoint, 0, c, i, 1);
            }
            cnode::copy(&mut w.k, slot(ROOT, 20), slot(c.object(), last), 0xF).unwrap();
            cnode::move_cap(&mut w.k, slot(ROOT, 30), slot(c.object(), u)).unwrap();
            w.k.events.clear();
            (w, c)
        };
        let finish = |w: &mut World| {
            cnode::revoke(&mut w.k, slot(ROOT, 1)).unwrap();
            assert!(!cdt::has_children(&w.k, slot(ROOT, 1)));
        };
        let (mut whole, c) = setup();
        let (named, n) = (path(20, c, u), 1 << radix);
        assert_eq!(revoke_call(&mut whole, named, &[]), Ok(()));
        assert!(whole.cap(slot(ROOT, 20)).is_null());
        whole.check(c.object(), n);
        finish(&mut whole);
        assert!((0..n).all(|i| whole.cap(slot(c.object(), i)).is_null()));

        let mut cut = 0;
        for p in 0.. {
            let (mut w, _) = setup();
            let r = revoke_call(&mut w, named, &[p]);
            if r == Ok(()) {
                break;
            }
            let what = format!("U in slot {u}, cut short at point {p}");
            assert!(
                matches!(r, Err(SyscallError::FailedLookup { .. })),
                "{what}: {r:?}"
            );
            w.check(c.object(), n);
            finish(&mut w);
            assert!(w.k.mem == whole.k.mem, "{what}");
            assert_eq!(finalised_last_sorted(&w), finalised_last_sorted(&whole));
            cut += 1;
        }
        assert!(cut >= 4, "U in slot {u}: cut short at {cut} points");
    }
}

/// Review of 2c60870: the cycle of the test above, where D's Zombie,
/// swapped into the slot being deleted, has one slot left. A partial revoke
/// cut short leaves such a Zombie: RA, D's untyped, revoked from D's slot 1
/// through D's capability in root slot 21, deletes that capability, then
/// turns D's last one, a copy in C's slot 1, into D's Zombie and deletes RA,
/// and is preempted there, so its restart fails its lookup. C's only
/// capability, from U, lies in D's slot 0.
///
/// Revoking U deletes C's capability in D's slot 0. Clearing C deletes C's
/// slot 1 in a nested deletion, which swaps D's Zombie into D's slot 0 and
/// C's Zombie, with C's node, into C's slot 1, then passes a preemption
/// point before it swaps C's Zombie on into C's slot 0. Unpreempted, seL4's
/// deletion would then find D's Zombie in its slot removable (one slot
/// left, in its own slot 0) and empty the slot, destroying D, which is not
/// U's descendant. Preempted at that point, the restarted revoke finds C's
/// Zombie in C's slot 1 and never touches D's slot 0, so D's Zombie stays.
/// The cycle stop ends the deletion before the removable check, as
/// 5211e83's did, so D's Zombie stays either way.
#[test]
fn a_revoke_through_a_cycle_leaves_a_removable_zombie_the_same_preempted_or_not() {
    let setup = || {
        let mut w = World::new();
        cdt::insert_root(
            &mut w.k,
            slot(ROOT, 2),
            Cap::untyped(DEV, UT_BITS, false, 1 << UT_BITS),
        );
        w.retype(1, ObjectType::CNode, 1, World::root(), 20, 1);
        w.retype(2, ObjectType::CNode, 1, World::root(), 21, 1);
        let (c, d) = (w.cap(slot(ROOT, 20)), w.cap(slot(ROOT, 21)));
        cnode::copy(&mut w.k, slot(ROOT, 21), slot(c.object(), 1), 0xF).unwrap();
        cnode::move_cap(&mut w.k, slot(ROOT, 20), slot(d.object(), 0)).unwrap();
        cnode::move_cap(&mut w.k, slot(ROOT, 2), slot(d.object(), 1)).unwrap();
        // The partial revoke, cut short after it deleted RA.
        let r = revoke_call(&mut w, path(21, d, 1), &[1]);
        assert!(matches!(r, Err(SyscallError::FailedLookup { .. })), "{r:?}");
        assert_eq!(
            w.cap(slot(c.object(), 1)),
            Cap::zombie(d.object(), d.size_bits(), 1, false)
        );
        assert_eq!(w.cap(slot(d.object(), 0)), c);
        assert!(w.cap(slot(d.object(), 1)).is_null());
        w.k.events.clear();
        (w, c, d)
    };

    let (mut whole, c, d) = setup();
    cnode::revoke(&mut whole.k, slot(ROOT, 1)).unwrap();
    assert!((0..2).all(|i| whole.cap(slot(c.object(), i)).is_null()));
    assert!(!cdt::has_children(&whole.k, slot(ROOT, 1)));
    whole.check(c.object(), 2);
    whole.check(d.object(), 2);
    // `docs/design.md`, "Deletion and finalisation", step 3: D's Zombie
    // stays in D's slot 0, and the revoke's deletion ends without emptying
    // it.
    assert_eq!(
        whole.cap(slot(d.object(), 0)),
        Cap::zombie(d.object(), d.size_bits(), 1, false),
        "the unpreempted revoke destroyed D"
    );

    ends_the_same_preempted_or_not(
        &whole,
        || setup().0,
        |k| cnode::revoke(k, slot(ROOT, 1)),
        &[(c.object(), 2), (d.object(), 2)],
    );
}

/// Review of 2c60870: the kernel restarts a preempted system call by
/// executing it again with the same arguments, so a restarted revoke looks
/// its slot up again (`docs/design.md`, "System-call dispatch" and "Slot
/// operations"). Revoking U from C's slot 4, named through C's only
/// capability in root slot 10, turns that capability into C's Zombie in its
/// first step, so from then on the lookup stops at the Zombie: a partial
/// revoke. Unpreempted, it goes on as seL4's does, deleting U and
/// destroying C. Preempted at any point, its restart fails its lookup and
/// the call returns that failure with the work left undone: at the first
/// point, after C's slot 7, U survives and C's Zombie counts 7. Every slot
/// stays consistent, and a Delete of C's Zombie, in a slot the user can
/// name, finishes the work: memory and hook calls end as without
/// preemption.
#[test]
fn a_revoke_restarted_by_looking_its_slot_up_again_is_cut_short() {
    let setup = || {
        let mut w = World::new();
        w.retype(1, ObjectType::CNode, 3, World::root(), 10, 1);
        let c = w.cap(slot(ROOT, 10));
        cnode::move_cap(&mut w.k, slot(ROOT, 1), slot(c.object(), 4)).unwrap();
        w.k.events.clear();
        (w, c)
    };
    let (mut whole, c) = setup();
    let ut = whole.cap(slot(c.object(), 4));
    let named = path(10, c, 4);
    assert_eq!(revoke_call(&mut whole, named, &[]), Ok(()));
    assert!(whole.cap(slot(ROOT, 10)).is_null());
    assert!((0..8).all(|i| whole.cap(slot(c.object(), i)).is_null()));
    assert_eq!(whole.finalised_last(), [ut]);

    let mut cut = 0;
    for p in 0.. {
        let (mut w, _) = setup();
        let r = revoke_call(&mut w, named, &[p]);
        if r == Ok(()) {
            break;
        }
        assert!(
            matches!(r, Err(SyscallError::FailedLookup { .. })),
            "cut short at point {p}: {r:?}"
        );
        w.check(c.object(), 8);
        let left = w.cap(slot(ROOT, 10));
        if p == 0 {
            assert_eq!(left, Cap::zombie(c.object(), c.size_bits(), 7, false));
            assert_eq!(w.cap(slot(c.object(), 4)), ut, "U survives");
        }
        if left.cap_type() == CapType::Zombie {
            cnode::delete(&mut w.k, slot(ROOT, 10)).unwrap();
        }
        assert!(w.k.mem == whole.k.mem, "cut short at point {p}");
        assert_eq!(w.k.events, whole.k.events, "cut short at point {p}");
        cut += 1;
    }
    assert!(cut >= 8, "cut short at {cut} points");
}

/// Re-review of 7462b41: a revoke cut short leaves "the rest of the work
/// undone" (`docs/design.md`, "Slot operations"), so its memory must be
/// what the unpreempted revoke had at one of its preemption points, however
/// many restarts succeeded before the one whose lookup failed. That is the
/// exact check `World::finish_partial_revoke` makes, with the hook calls
/// too; this shows it holds for the shapes above, under every schedule of
/// up to three preemptions.
#[test]
fn a_revoke_cut_short_stops_where_the_unpreempted_revoke_passed() {
    let shapes = [(2, 3, 1, None), (2, 3, 2, Some(1)), (1, 1, 0, None)];
    for (radix, last, u, endpoint) in shapes {
        let setup = || {
            let mut w = World::new();
            cdt::insert_root(
                &mut w.k,
                slot(ROOT, 2),
                Cap::untyped(DEV, UT_BITS, false, 1 << UT_BITS),
            );
            w.retype(1, ObjectType::Untyped, 12, World::root(), 30, 1);
            w.retype(30, ObjectType::CNode, radix, World::root(), 20, 1);
            let c = w.cap(slot(ROOT, 20));
            if let Some(i) = endpoint {
                w.retype(2, ObjectType::Endpoint, 0, c, i, 1);
            }
            cnode::copy(&mut w.k, slot(ROOT, 20), slot(c.object(), last), 0xF).unwrap();
            // Two endpoints from U come first among its children, so the
            // first restarts look the slot up again and go on.
            w.retype(30, ObjectType::Endpoint, 0, World::root(), 40, 2);
            cnode::move_cap(&mut w.k, slot(ROOT, 30), slot(c.object(), u)).unwrap();
            w.k.events.clear();
            (w, c)
        };
        let (w, c) = setup();
        let named = path(20, c, u);
        let at = crate::cspace::lookup_slot(&w.k, user_root(), named.0, named.1, false).unwrap();
        // The unpreempted revoke's memory at each of its points.
        let mut passed = Vec::new();
        for p in 0.. {
            let (mut w, _) = setup();
            w.k.preempt_in = Some(p);
            if cnode::revoke(&mut w.k, at).is_ok() {
                break;
            }
            passed.push(w.k.mem.clone());
        }
        let n = passed.len() as u64 + 1;
        // Every schedule of up to three preemptions natively; under Miri,
        // which is slow, one preemption, or one restart and then a second.
        let mut schedules: Vec<Vec<u64>> = Vec::new();
        for a in 0..n {
            schedules.push(vec![a]);
            for b in 0..n {
                if cfg!(miri) && a != 0 {
                    continue;
                }
                schedules.push(vec![a, b]);
                if cfg!(miri) {
                    continue;
                }
                for c in 0..n {
                    schedules.push(vec![a, b, c]);
                }
            }
        }
        let mut restarted_then_cut = 0;
        for schedule in schedules {
            let (mut w, _) = setup();
            if revoke_call(&mut w, named, &schedule).is_ok() {
                continue;
            }
            if schedule.len() > 1 && schedule[0] == 0 {
                restarted_then_cut += 1;
            }
            assert!(
                passed.contains(&w.k.mem),
                "U in slot {u}, schedule {schedule:?}: cut short where the unpreempted revoke never was"
            );
        }
        assert!(restarted_then_cut > 0, "U in slot {u}");
    }
}

/// A Delete is cut short the same way only if the path that names its slot
/// runs through that slot itself. Y's slot 0 holds X's only capability, and
/// X's slot 1 a copy of Y's, so the path root slot 10, Y's slot 0, X's slot
/// 1, Y's slot 0 names Y's slot 0 through itself. Deleting it turns X's
/// capability into X's Zombie, which ends that path: preempted at its first
/// point, the restart fails its lookup. What it leaves is X's Zombie in Y's
/// slot 0, which a Delete through the short path, root slot 10 then Y's slot
/// 0, finishes. Through the short path the Delete is never cut short.
#[test]
fn a_delete_named_through_its_own_slot_can_be_cut_short() {
    let setup = || {
        let mut w = World::new();
        w.retype(1, ObjectType::CNode, 1, World::root(), 10, 2);
        let (y, x) = (w.cap(slot(ROOT, 10)), w.cap(slot(ROOT, 11)));
        cnode::copy(&mut w.k, slot(ROOT, 10), slot(x.object(), 1), 0xF).unwrap();
        cnode::move_cap(&mut w.k, slot(ROOT, 11), slot(y.object(), 0)).unwrap();
        w.k.events.clear();
        (w, y, x)
    };
    let (mut whole, y, x) = setup();
    let short = path(10, y, 0);
    // Root slot 10, then Y's slot 0, X's slot 1 and Y's slot 0, a bit each.
    let through = ((10 << 3) | 0b010, u64::from(ROOT_RADIX) + 3);
    let at = crate::cspace::lookup_slot(&whole.k, user_root(), through.0, through.1, false);
    assert_eq!(at, Ok(slot(y.object(), 0)));
    assert_eq!(call(&mut whole, through, &[], cnode::delete), Ok(()));
    assert!(whole.cap(slot(y.object(), 0)).is_null());
    assert!(whole.cap(slot(x.object(), 1)).is_null());

    let (mut w, ..) = setup();
    let r = call(&mut w, through, &[0], cnode::delete);
    assert!(matches!(r, Err(SyscallError::FailedLookup { .. })), "{r:?}");
    let zombie = Cap::zombie(x.object(), x.size_bits(), 1, false);
    assert_eq!(w.cap(slot(y.object(), 0)), zombie);
    w.check(x.object(), 2);
    w.check(y.object(), 2);
    assert_eq!(call(&mut w, short, &[0], cnode::delete), Ok(()));
    assert!(w.k.mem == whole.k.mem);
    assert_eq!(w.k.events, whole.k.events);

    let (mut w, ..) = setup();
    assert_eq!(call(&mut w, short, &[0, 0, 0, 0], cnode::delete), Ok(()));
    assert!(w.k.mem == whole.k.mem);
}

#[test]
#[cfg_attr(miri, ignore = "4,094 copy-and-delete steps are too slow under Miri")]
fn depth_limit_is_reachable_and_refused() {
    let mut w = World::new();
    w.retype(1, ObjectType::Untyped, 12, World::root(), 10, 1);
    // Copy the untyped and delete the source, over and over: each copy is a
    // child one level deeper.
    let (mut from, mut to) = (10, 11);
    for _ in 1..MAX_DERIVATION_DEPTH {
        cnode::copy(&mut w.k, slot(ROOT, from), slot(ROOT, to), 0).unwrap();
        cnode::delete(&mut w.k, slot(ROOT, from)).unwrap();
        core::mem::swap(&mut from, &mut to);
    }
    assert_eq!(
        w.k.load(slot(ROOT, from)).node.depth(),
        MAX_DERIVATION_DEPTH
    );
    assert_eq!(
        cnode::copy(&mut w.k, slot(ROOT, from), slot(ROOT, to), 0),
        Err(SyscallError::IllegalOperation)
    );
    let r = retype(
        &mut w.k,
        slot(ROOT, from),
        World::root(),
        RetypeArgs {
            object_type: ObjectType::Endpoint as u64,
            size_bits: 0,
            node_offset: to,
            num_objects: 1,
        },
    );
    assert_eq!(r, Err(RetypeError::Error(SyscallError::IllegalOperation)));
    // The holder of the boot untyped can still revoke it.
    cnode::revoke(&mut w.k, slot(ROOT, 1)).unwrap();
    assert!(w.cap(slot(ROOT, from)).is_null());
}

#[test]
fn swap_of_list_neighbours_in_both_orders() {
    let mut w = World::new();
    w.retype(1, ObjectType::Endpoint, 0, World::root(), 10, 1);
    cnode::copy(&mut w.k, slot(ROOT, 10), slot(ROOT, 11), 0xF).unwrap();
    // 10 then 11 in the list; swap them through Rotate's swap form.
    let (a, b) = (w.cap(slot(ROOT, 10)), w.cap(slot(ROOT, 11)));
    crate::cdt::swap_slots(&mut w.k, a, slot(ROOT, 10), b, slot(ROOT, 11));
    w.check(ROOT, 64);
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 10)), Some(slot(ROOT, 11)));
    crate::cdt::swap_slots(&mut w.k, b, slot(ROOT, 10), a, slot(ROOT, 11));
    w.check(ROOT, 64);
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 11)), Some(slot(ROOT, 10)));
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 10)), Some(slot(ROOT, 1)));
}

#[test]
fn a_revoke_that_destroys_its_own_slot_leaves_a_zombie_the_user_can_finish() {
    let mut w = World::new();
    // A second RAM untyped, so C holds capabilities the revoke does not reach.
    cdt::insert_root(
        &mut w.k,
        slot(ROOT, 2),
        Cap::untyped(DEV, UT_BITS, false, 1 << UT_BITS),
    );
    w.retype(1, ObjectType::CNode, 3, World::root(), 10, 1);
    let c = w.cap(slot(ROOT, 10));
    w.retype(2, ObjectType::Endpoint, 0, c, 0, 2);
    cnode::move_cap(&mut w.k, slot(ROOT, 1), slot(c.object(), 4)).unwrap();
    // Revoking the untyped in C slot 4 destroys C, and with it that slot.
    // Preempted at every point and restarted by the slot's address, the
    // revoke stops once the slot is gone (seL4's partial revoke; the
    // kernel's restart fails its lookup through C's Zombie already after the
    // first step). C's Zombie stays where C's capability was.
    let n = w.until_done(0, |k| cnode::revoke(k, slot(c.object(), 4)));
    assert_eq!(n, 4);
    let zombie = Cap::zombie(c.object(), c.size_bits(), 4, false);
    assert_eq!(w.cap(slot(ROOT, 10)), zombie);
    assert_eq!(cdt::parent(&w.k, slot(ROOT, 10)), None);
    assert!(w.cap(slot(c.object(), 0)).cap_type() == CapType::Endpoint);
    w.check(ROOT, 64);
    w.check(c.object(), 8);
    // A Zombie cannot be copied or minted, but it can be moved.
    let illegal = Err(SyscallError::IllegalOperation);
    assert_eq!(
        cnode::copy(&mut w.k, slot(ROOT, 10), slot(ROOT, 20), 0xF),
        illegal
    );
    assert_eq!(
        cnode::mint(&mut w.k, slot(ROOT, 10), slot(ROOT, 20), 0xF, 5),
        illegal
    );
    w.k.events.clear();
    cnode::mutate(&mut w.k, slot(ROOT, 10), slot(ROOT, 21), 0x1234).unwrap();
    cnode::move_cap(&mut w.k, slot(ROOT, 21), slot(ROOT, 22)).unwrap();
    assert_eq!(w.cap(slot(ROOT, 22)), zombie);
    assert_eq!(
        w.k.events,
        [
            Event::Moved {
                cap: zombie,
                from: slot(ROOT, 10),
                to: slot(ROOT, 21)
            },
            Event::Moved {
                cap: zombie,
                from: slot(ROOT, 21),
                to: slot(ROOT, 22)
            },
        ]
    );
    // Revoke finds no children; Delete resumes the clearing.
    cnode::revoke(&mut w.k, slot(ROOT, 22)).unwrap();
    assert_eq!(w.cap(slot(ROOT, 22)), zombie);
    w.until_done(0, |k| cnode::delete(k, slot(ROOT, 22)));
    assert!(w.cap(slot(ROOT, 22)).is_null());
    for i in 0..8 {
        assert!(w.cap(slot(c.object(), i)).is_null());
    }
    assert_eq!(
        w.finalised_last(),
        [ep(DEV + 32), ep(DEV)],
        "C's endpoints, highest slot first"
    );
    assert!(!cdt::has_children(&w.k, slot(ROOT, 2)));
    w.check(ROOT, 64);
}
