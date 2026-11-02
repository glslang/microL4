//! Host tests of the invocation decoder over fake memory and the recording
//! kernel: each method's success path, every error row of `docs/abi.md` and
//! the pairs whose order decides which error wins, the derivation limit,
//! calls preempted and restarted by decoding the same message again, and
//! random messages.
//!
//! The CSpace has two levels with guards. The root CNode (64 slots, a 2-bit
//! guard `0b01`) holds its own capability in slot 2, as the root task's
//! does, a second CNode `L2` (8 slots, a 3-bit guard `0b101`) in slot 3, a
//! 16 KiB RAM untyped in slot 16 and a 4 KiB device untyped in slot 17. A
//! root slot is named in 8 bits, an `L2` slot in 14.

use std::collections::BTreeSet;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use proptest::strategy::ValueTree;

use super::*;
use crate::cap::{
    MAX_DERIVATION_DEPTH, ObjectType, Rights, SLOT_BITS, SLOT_SIZE, TCB_SLOT_REPLY, TCB_SLOTS,
    cnode_data,
};
use crate::cdt;
use crate::slot::Node;
use crate::testing::{DIRT, Event, TestKernel};

// Fake memory is small, 24 KiB, because Miri's cost for each access grows
// with it.
const UT: u64 = 0x4000;
const UT_BITS: u32 = 14;
const ROOT: u64 = 0x8000;
const ROOT_RADIX: u32 = 6;
const ROOT_GUARD: u64 = 0b01;
const L2: u64 = 0x8800;
const L2_RADIX: u32 = 3;
const L2_GUARD: u64 = 0b101;
const DEV: u64 = 0x9000;
const DEV_BITS: u32 = 12;
const MEM_END: u64 = 0xA000;

/// Root slots of the boot capabilities.
const S_ROOT: u64 = 2;
const S_L2: u64 = 3;
const S_UT: u64 = 16;
const S_DEV: u64 = 17;

const RETYPE: u64 = label::UNTYPED_RETYPE;
const REVOKE: u64 = label::CNODE_REVOKE;
const DELETE: u64 = label::CNODE_DELETE;
const COPY: u64 = label::CNODE_COPY;
const MINT: u64 = label::CNODE_MINT;
const MOVE: u64 = label::CNODE_MOVE;
const MUTATE: u64 = label::CNODE_MUTATE;
const ROTATE: u64 = label::CNODE_ROTATE;

/// `node_index` and `node_depth` 0: `Untyped_Retype` puts the objects in
/// `root` itself.
const SELF: (u64, u64) = (0, 0);

const TRUNCATED: SyscallError = SyscallError::TruncatedMessage;
const ILLEGAL: SyscallError = SyscallError::IllegalOperation;
const DELETE_FIRST: SyscallError = SyscallError::DeleteFirst;
const REVOKE_FIRST: SyscallError = SyscallError::RevokeFirst;
const EMPTY_SOURCE: SyscallError = failed(true, LookupFailure::MissingCapability { bits_left: 0 });
const NOT_A_CNODE: SyscallError = failed(false, LookupFailure::MissingCapability { bits_left: 0 });

const fn failed(source: bool, failure: LookupFailure) -> SyscallError {
    SyscallError::FailedLookup { source, failure }
}

const fn range(min: u64, max: u64) -> SyscallError {
    SyscallError::RangeError { min, max }
}

fn sa(a: u64) -> SlotAddr {
    SlotAddr::new(a).unwrap()
}

/// Root slot `i`.
fn rs(i: u64) -> SlotAddr {
    sa(ROOT + i * SLOT_SIZE)
}

/// `L2` slot `j`.
fn ls(j: u64) -> SlotAddr {
    sa(L2 + j * SLOT_SIZE)
}

/// The name (index, depth) of root slot `i`.
fn r(i: u64) -> (u64, u64) {
    ((ROOT_GUARD << ROOT_RADIX) | i, 8)
}

/// The name of `L2` slot `j`, through root slot 3.
fn l2(j: u64) -> (u64, u64) {
    ((r(S_L2).0 << 6) | (L2_GUARD << L2_RADIX) | j, 14)
}

/// The name of slot `j` of the CNode whose capability (radix `radix`, no
/// guard) is in root slot `i`.
fn inside(i: u64, radix: u32, j: u64) -> (u64, u64) {
    ((r(i).0 << radix) | j, 8 + u64::from(radix))
}

fn root_cap() -> Cap {
    Cap::cnode(ROOT, ROOT_RADIX, 2, ROOT_GUARD)
}

fn rt(ty: ObjectType, size_bits: u64, node: (u64, u64), offset: u64, n: u64) -> Vec<u64> {
    vec![ty as u64, size_bits, node.0, node.1, offset, n]
}

fn at(s: (u64, u64)) -> Vec<u64> {
    vec![s.0, s.1]
}

fn copy(dst: (u64, u64), src: (u64, u64), rights: u64) -> Vec<u64> {
    vec![dst.0, dst.1, src.0, src.1, rights]
}

fn mint(dst: (u64, u64), src: (u64, u64), rights: u64, data: u64) -> Vec<u64> {
    vec![dst.0, dst.1, src.0, src.1, rights, data]
}

fn mv(dst: (u64, u64), src: (u64, u64)) -> Vec<u64> {
    vec![dst.0, dst.1, src.0, src.1]
}

fn mutate(dst: (u64, u64), src: (u64, u64), data: u64) -> Vec<u64> {
    vec![dst.0, dst.1, src.0, src.1, data]
}

fn rotate(
    dst: (u64, u64),
    dst_data: u64,
    pivot: (u64, u64),
    pivot_data: u64,
    src: (u64, u64),
) -> Vec<u64> {
    vec![
        dst.0, dst.1, dst_data, pivot.0, pivot.1, pivot_data, src.0, src.1,
    ]
}

/// The slots of the container a capability names, if it names one.
fn container(cap: Cap) -> Option<(u64, u64)> {
    match cap.cap_type() {
        CapType::CNode => Some((cap.object(), 1 << cap.radix())),
        CapType::Tcb => Some((cap.object(), TCB_SLOTS)),
        CapType::Zombie if cap.zombie_is_tcb() => Some((cap.object(), TCB_SLOTS)),
        CapType::Zombie => Some((cap.object(), 1 << (cap.size_bits() - SLOT_BITS))),
        _ => None,
    }
}

#[derive(Clone)]
struct World {
    k: TestKernel,
}

impl World {
    /// The boot CSpace above, the untyped with their watermarks at their
    /// sizes, as boot leaves them.
    fn new() -> World {
        let mut k = TestKernel::new(UT, MEM_END - UT);
        cdt::insert_root(&mut k, rs(S_ROOT), root_cap());
        cdt::insert_root(&mut k, rs(S_L2), Cap::cnode(L2, L2_RADIX, 3, L2_GUARD));
        cdt::insert_root(
            &mut k,
            rs(S_UT),
            Cap::untyped(UT, UT_BITS, false, 1 << UT_BITS),
        );
        cdt::insert_root(
            &mut k,
            rs(S_DEV),
            Cap::untyped(DEV, DEV_BITS, true, 1 << DEV_BITS),
        );
        World { k }
    }

    fn cap(&self, s: SlotAddr) -> Cap {
        self.k.load(s).cap
    }

    fn node(&self, s: SlotAddr) -> Node {
        self.k.load(s).node
    }

    /// One attempt at a call: the capability in `invoked`, with the extra
    /// capabilities in `extra` as a lookup finds them now.
    fn call(
        &mut self,
        invoked: SlotAddr,
        label: u64,
        mrs: &[u64],
        extra: &[SlotAddr],
    ) -> Result<Reply, InvokeError> {
        let extra: Vec<ExtraCap> = extra.iter().map(|s| ExtraCap::load(&self.k, *s)).collect();
        let msg = Message {
            label,
            mrs,
            extra_caps: &extra,
        };
        invoke(&mut self.k, invoked, &msg)
    }

    /// `Untyped_Retype` of the untyped in root slot `ut`, with the root
    /// CNode as `root`, which must succeed.
    fn make(
        &mut self,
        ut: u64,
        ty: ObjectType,
        size_bits: u64,
        node: (u64, u64),
        offset: u64,
        n: u64,
    ) {
        let mrs = rt(ty, size_bits, node, offset, n);
        self.ok(rs(ut), RETYPE, &mrs, &[rs(S_ROOT)]);
    }

    /// A call that must succeed without a preemption point reporting.
    fn ok(&mut self, invoked: SlotAddr, label: u64, mrs: &[u64], extra: &[SlotAddr]) {
        assert_eq!(self.call(invoked, label, mrs, extra), Ok(Reply::EMPTY));
        self.check_step();
    }

    /// A call as the kernel runs it: every attempt is preempted at its
    /// `every`-th preemption point (from 0), and restarted from the same
    /// arguments, extra capabilities looked up again, until one is not.
    /// Returns its result and how many attempts were preempted.
    fn run(
        &mut self,
        every: u64,
        invoked: SlotAddr,
        label: u64,
        mrs: &[u64],
        extra: &[SlotAddr],
    ) -> (Result<Reply, SyscallError>, u32) {
        let mut preempted = 0;
        loop {
            self.k.preempt_in = Some(every);
            let r = self.call(invoked, label, mrs, extra);
            self.k.preempt_in = None;
            self.check_step();
            match r {
                Ok(reply) => {
                    self.check();
                    return (Ok(reply), preempted);
                }
                Err(InvokeError::Error(e)) => {
                    self.check();
                    return (Err(e), preempted);
                }
                Err(InvokeError::Preempted) => preempted += 1,
            }
            assert!(preempted < 100_000, "a restarted call made no progress");
        }
    }

    /// [`World::check`] after a step: natively after every call and every
    /// preempted attempt, under Miri, where one check takes tens of
    /// milliseconds, only where a test asks. `l4core` has no `unsafe`, so the
    /// checks gain nothing from Miri.
    fn check_step(&self) {
        if !cfg!(miri) {
            self.check();
        }
    }

    /// Checks the derivation-list invariants of every slot of the root
    /// CNode, `L2`, and every container a capability in a checked slot
    /// names.
    fn check(&self) {
        let mut todo = vec![(ROOT, 1 << ROOT_RADIX), (L2, 1 << L2_RADIX)];
        let mut seen = BTreeSet::new();
        while let Some((base, n)) = todo.pop() {
            if !seen.insert(base) {
                continue;
            }
            for i in 0..n {
                let s = sa(base + i * SLOT_SIZE);
                if let Err(e) = cdt::check_slot(&self.k, s) {
                    panic!("slot {:#x}: {e}", s.get());
                }
                if let Some(c) = container(self.cap(s)) {
                    todo.push(c);
                }
            }
        }
    }
}

/// The world most error tests start from, after these calls:
///
/// | Root slot | Capability |
/// | --- | --- |
/// | 20, 21 | endpoints, unbadged originals |
/// | 22 | a CNode, radix 2 |
/// | 23 | an untyped, 256 bytes, with a child endpoint in 24 |
/// | 25 | 20 minted with badge 7 |
/// | 26 | a PageTable |
/// | 27 | IRQControl, a boot root |
/// | 29 | a Hypervisor capability, a boot root |
/// | 28 | a Zombie: a CNode whose deletion was preempted |
///
/// `L2` slot 1 holds an endpoint. The RAM untyped is full.
fn stocked() -> World {
    let mut w = World::new();
    let root = [rs(S_ROOT)];
    w.make(S_UT, ObjectType::Endpoint, 0, SELF, 20, 2);
    w.make(S_UT, ObjectType::CNode, 2, SELF, 22, 1);
    w.make(S_UT, ObjectType::Untyped, 8, SELF, 23, 1);
    w.make(23, ObjectType::Endpoint, 0, SELF, 24, 1);
    w.ok(rs(S_ROOT), MINT, &mint(r(25), r(20), 0xF, 7), &root);
    let irq_control = Cap::new(CapType::IrqControl, 0, 0, Rights::NONE, false, 0);
    cdt::insert_root(&mut w.k, rs(27), irq_control);
    let hypervisor = Cap::new(CapType::Hypervisor, 0, 0, Rights::NONE, false, 0);
    cdt::insert_root(&mut w.k, rs(29), hypervisor);
    w.make(S_UT, ObjectType::CNode, 1, SELF, 28, 1);
    w.k.preempt_in = Some(0);
    assert_eq!(
        w.call(rs(S_ROOT), DELETE, &at(r(28)), &[]),
        Err(InvokeError::Preempted)
    );
    w.k.preempt_in = None;
    assert_eq!(w.cap(rs(28)).cap_type(), CapType::Zombie);
    w.make(S_UT, ObjectType::Endpoint, 0, r(S_L2), 1, 1);
    // Last, as it fills the untyped: 8 KiB aligned to 8 KiB.
    w.make(S_UT, ObjectType::PageTable, 0, SELF, 26, 1);
    assert_eq!(w.cap(rs(S_UT)).watermark(), 1 << UT_BITS);
    w.check();
    w
}

/// An error case: the call, and the error it must return without changing
/// anything.
struct Case {
    what: &'static str,
    invoked: SlotAddr,
    label: u64,
    mrs: Vec<u64>,
    extra: Vec<SlotAddr>,
    want: SyscallError,
}

/// `Untyped_Retype` of the RAM untyped.
fn retype_case(what: &'static str, mrs: Vec<u64>, extra: &[SlotAddr], want: SyscallError) -> Case {
    Case {
        what,
        invoked: rs(S_UT),
        label: RETYPE,
        mrs,
        extra: extra.to_vec(),
        want,
    }
}

/// A method of the root CNode, through its capability in its slot 2.
fn cnode_case(
    what: &'static str,
    label: u64,
    mrs: Vec<u64>,
    extra: &[SlotAddr],
    want: SyscallError,
) -> Case {
    Case {
        what,
        invoked: rs(S_ROOT),
        label,
        mrs,
        extra: extra.to_vec(),
        want,
    }
}

/// Runs each case on a copy of `w`.
fn expect_errors(w: &World, cases: &[Case]) {
    for c in cases {
        let mut t = w.clone();
        assert_eq!(
            t.call(c.invoked, c.label, &c.mrs, &c.extra),
            Err(InvokeError::Error(c.want)),
            "{}",
            c.what
        );
        assert!(t.k.mem == w.k.mem, "{}: memory changed", c.what);
        assert_eq!(t.k.events, w.k.events, "{}: a hook was called", c.what);
    }
}

/// Names that fail to resolve from the root CNode, and how.
fn bad_names() -> [((u64, u64), LookupFailure); 5] {
    [
        (
            ((0b10 << ROOT_RADIX) | 20, 8),
            LookupFailure::GuardMismatch {
                bits_left: 8,
                guard: ROOT_GUARD,
                guard_size: 2,
            },
        ),
        (
            (r(20).0 >> 1, 7),
            LookupFailure::DepthMismatch {
                bits_left: 7,
                bits_found: 8,
            },
        ),
        // Slot 20 holds an endpoint and one bit is left.
        (
            (r(20).0 << 1, 9),
            LookupFailure::DepthMismatch {
                bits_left: 1,
                bits_found: 0,
            },
        ),
        (
            ((r(S_L2).0 << 6) | (0b111 << L2_RADIX), 14),
            LookupFailure::GuardMismatch {
                bits_left: 6,
                guard: L2_GUARD,
                guard_size: 3,
            },
        ),
        (
            ((r(S_L2).0 << 5) | (L2_GUARD << 2), 13),
            LookupFailure::DepthMismatch {
                bits_left: 5,
                bits_found: 6,
            },
        ),
    ]
}

// ---------------------------------------------------------------------
// Dispatch.

#[test]
fn an_empty_slot_or_a_zombie_is_invalid_capability_0_whatever_the_label() {
    let mut w = stocked();
    let full = rotate(r(40), 0, r(41), 0, r(42));
    for invoked in [rs(40), rs(28), ls(5)] {
        for label in [
            0,
            RETYPE,
            0x02,
            REVOKE,
            DELETE,
            COPY,
            ROTATE,
            0x77,
            u64::MAX,
        ] {
            for (mrs, extra) in [
                (&full[..], &[rs(S_ROOT), rs(S_ROOT)][..]),
                (&[][..], &[][..]),
            ] {
                assert_eq!(
                    w.call(invoked, label, mrs, extra),
                    Err(InvokeError::Error(SyscallError::InvalidCapability(0)))
                );
            }
        }
    }
    // The Zombie's deletion goes on when it is restarted.
    assert_eq!(
        w.run(0, rs(S_ROOT), DELETE, &at(r(28)), &[]).0,
        Ok(Reply::EMPTY)
    );
    assert!(w.cap(rs(28)).is_null());
}

#[test]
fn a_label_outside_the_type_or_unassigned_is_illegal_before_the_length() {
    let mut w = stocked();
    let full = rotate(r(40), 0, r(41), 0, r(42));
    let two = [rs(S_ROOT), rs(S_ROOT)];
    let mut check = |invoked: SlotAddr, labels: &[u64]| {
        for &label in labels {
            for (mrs, extra) in [(&full[..], &two[..]), (&[][..], &[][..])] {
                assert_eq!(
                    w.call(invoked, label, mrs, extra),
                    Err(InvokeError::Error(ILLEGAL)),
                    "label {label:#x} on {:#x}",
                    invoked.get()
                );
            }
        }
    };
    let cnode_labels = [0x10, 0x11, 0x13, 0x14, 0x15, 0x16, 0x17];
    let unassigned = [
        0,
        0x02,
        0x0F,
        0x12,
        0x18,
        0x19,
        0x1F,
        0x20,
        0x40,
        0x50,
        0x60,
        1 << 51,
        u64::MAX,
    ];
    check(rs(S_UT), &cnode_labels);
    check(rs(S_UT), &unassigned);
    check(rs(S_ROOT), &[RETYPE]);
    check(rs(S_ROOT), &unassigned);
    // Every other type, for now: an endpoint, a PageTable, IRQControl.
    for s in [rs(20), rs(25), rs(26), rs(27), ls(1)] {
        check(s, &[RETYPE]);
        check(s, &cnode_labels);
        check(s, &unassigned);
    }
}

#[test]
fn errors_convert_from_the_slot_operations() {
    let e = SyscallError::InvalidCapability(0);
    assert_eq!((e.code(), e.detail()), (2, ([0, 0, 0, 0, 0], 1)));
    assert_eq!(
        InvokeError::from(RetypeError::Error(TRUNCATED)),
        InvokeError::Error(TRUNCATED)
    );
    assert_eq!(
        InvokeError::from(RetypeError::Preempted),
        InvokeError::Preempted
    );
    assert_eq!(InvokeError::from(Preempted), InvokeError::Preempted);
}

// ---------------------------------------------------------------------
// Untyped_Retype.

#[test]
fn retype_makes_each_type_with_full_rights_as_original_children() {
    let mut w = World::new();
    let types = [
        (ObjectType::Untyped, 6),
        (ObjectType::Tcb, 0),
        (ObjectType::Endpoint, 0),
        (ObjectType::Notification, 0),
        (ObjectType::CNode, 3),
        (ObjectType::Frame4K, 0),
        (ObjectType::PageTable, 0),
        (ObjectType::PageDirectory, 0),
        (ObjectType::Pdpt, 0),
        (ObjectType::Pml4, 0),
    ];
    for (ty, size_bits) in types {
        // Each time after a revoke: the same object at the same address.
        w.make(S_UT, ty, size_bits, SELF, 20, 1);
        let c = w.cap(rs(20));
        let bits = ty.object_bits(size_bits as u32);
        assert_eq!(
            (c.cap_type(), c.object(), c.size_bits()),
            (ty.cap_type(), UT, bits),
            "{ty:?}"
        );
        assert_eq!(c.rights(), ty.full_rights());
        assert!(!c.is_device());
        assert_eq!(cdt::parent(&w.k, rs(20)), Some(rs(S_UT)));
        assert!(w.node(rs(20)).original());
        assert_eq!(w.node(rs(20)).depth(), 1);
        assert_eq!(w.cap(rs(S_UT)).watermark(), 1 << bits);
        if ty == ObjectType::Tcb {
            let master = sa(UT).offset(TCB_SLOT_REPLY);
            assert_eq!(w.cap(master), Cap::reply(UT, true, true));
            assert_eq!(w.node(master), Node::new(true, 0, 0));
        }
        if let Some(off) = TestKernel::dirt_offset(&c) {
            assert_eq!(w.k.mem.read(UT + off), DIRT);
        }
        w.ok(rs(S_ROOT), REVOKE, &at(r(S_UT)), &[]);
        assert!(w.cap(rs(20)).is_null());
    }
    // The next retype resets what the last one dirtied.
    w.make(S_UT, ObjectType::Endpoint, 0, SELF, 20, 1);
    assert!(w.k.mem.is_zero(UT + 32, (1 << UT_BITS) - 32));
    w.check();
}

#[test]
fn retype_places_consecutive_objects_where_the_destination_names() {
    let mut w = World::new();
    // node_depth 0: the root itself; size_bits is ignored for a fixed size.
    w.make(S_UT, ObjectType::Notification, u64::MAX, SELF, 61, 3);
    for i in 0..3 {
        let c = w.cap(rs(61 + i));
        assert_eq!((c.object(), c.size_bits()), (UT + 64 * i, 6));
        assert!(cdt::is_final(&w.k, rs(61 + i)));
    }
    // The root's own capability in its slot 2, named in 8 bits.
    w.make(S_UT, ObjectType::Endpoint, 0, r(S_ROOT), 30, 1);
    assert_eq!(w.cap(rs(30)).object(), UT + 192);
    // L2 through root slot 3, then a CNode made in L2, named in 14 bits.
    w.make(S_UT, ObjectType::CNode, 2, r(S_L2), 7, 1);
    assert_eq!(w.cap(ls(7)), Cap::cnode(UT + 256, 2, 0, 0));
    w.make(S_UT, ObjectType::Endpoint, 0, l2(7), 3, 1);
    let deep = sa(UT + 256).offset(3);
    assert_eq!(w.cap(deep).object(), UT + 384);
    assert_eq!(cdt::parent(&w.k, deep), Some(rs(S_UT)));
    // The root named through L2's capability as `root`, node_depth 0.
    w.ok(
        rs(S_UT),
        RETYPE,
        &rt(ObjectType::Endpoint, 0, SELF, 0, 1),
        &[rs(S_L2)],
    );
    assert_eq!(w.cap(ls(0)).cap_type(), CapType::Endpoint);
    // A device untyped makes device frames and untyped; a new untyped
    // starts with its watermark at 0.
    w.make(S_DEV, ObjectType::Untyped, 10, SELF, 40, 2);
    assert_eq!(w.cap(rs(41)), Cap::untyped(DEV + 1024, 10, true, 0));
    w.ok(rs(S_ROOT), REVOKE, &at(r(S_DEV)), &[]);
    w.make(S_DEV, ObjectType::Frame4K, 0, SELF, 42, 1);
    let f = w.cap(rs(42));
    assert!(f.is_device() && f.object() == DEV && f.rights() == Rights(0b11));
    // The device untyped is never cleared.
    assert!(
        !w.k.events
            .iter()
            .any(|e| matches!(e, Event::Zero { paddr, .. } if (DEV..DEV + 4096).contains(paddr)))
    );
    w.check();
}

#[test]
fn retype_errors_one_per_row() {
    let w = stocked();
    let root = [rs(S_ROOT)];
    let ep = |node, off, n| rt(ObjectType::Endpoint, 0, node, off, n);
    let free = (1 << UT_BITS) - w.cap(rs(S_UT)).watermark();
    let mut cases = vec![
        retype_case(
            "5 registers",
            ep(SELF, 40, 1)[..5].to_vec(),
            &root,
            TRUNCATED,
        ),
        retype_case("no root", ep(SELF, 40, 1), &[], TRUNCATED),
        retype_case("nothing", vec![], &[], TRUNCATED),
        retype_case(
            "type 11",
            vec![11, 0, 0, 0, 40, 1],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        retype_case(
            "type 2^64 - 1",
            vec![u64::MAX, 0, 0, 0, 40, 1],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        retype_case(
            "untyped of 8 bytes",
            rt(ObjectType::Untyped, 3, SELF, 40, 1),
            &root,
            range(4, 47),
        ),
        retype_case(
            "untyped of 2^48 bytes",
            rt(ObjectType::Untyped, 48, SELF, 40, 1),
            &root,
            range(4, 47),
        ),
        retype_case(
            "CNode radix 0",
            rt(ObjectType::CNode, 0, SELF, 40, 1),
            &root,
            range(1, 42),
        ),
        retype_case(
            "CNode radix 43",
            rt(ObjectType::CNode, 43, SELF, 40, 1),
            &root,
            range(1, 42),
        ),
        retype_case("node_depth 65", ep((0, 65), 40, 1), &root, range(0, 64)),
        retype_case(
            "node_depth 2^64 - 1",
            ep((0, u64::MAX), 40, 1),
            &root,
            range(0, 64),
        ),
        retype_case(
            "root an endpoint",
            ep(r(S_L2), 40, 1),
            &[rs(20)],
            failed(false, LookupFailure::InvalidRoot),
        ),
        retype_case(
            "root empty, node_depth 0",
            ep(SELF, 40, 1),
            &[rs(40)],
            failed(false, LookupFailure::InvalidRoot),
        ),
        retype_case(
            "root a Zombie, node_depth 0",
            ep(SELF, 40, 1),
            &[rs(28)],
            failed(false, LookupFailure::InvalidRoot),
        ),
        retype_case("node an endpoint", ep(r(20), 0, 1), &root, NOT_A_CNODE),
        retype_case("node empty", ep(r(40), 0, 1), &root, NOT_A_CNODE),
        retype_case("node a Zombie", ep(r(28), 0, 1), &root, NOT_A_CNODE),
        retype_case("node_offset 64", ep(SELF, 64, 1), &root, range(0, 63)),
        retype_case(
            "node_offset 2^64 - 1",
            ep(SELF, u64::MAX, 1),
            &root,
            range(0, 63),
        ),
        retype_case("L2 node_offset 8", ep(r(S_L2), 8, 1), &root, range(0, 7)),
        retype_case("0 objects", ep(SELF, 40, 0), &root, range(1, 256)),
        retype_case("257 objects", ep(SELF, 40, 257), &root, range(1, 256)),
        retype_case(
            "2^64 - 1 objects",
            ep(SELF, 40, u64::MAX),
            &root,
            range(1, 256),
        ),
        retype_case("past the root's end", ep(SELF, 60, 5), &root, range(1, 4)),
        retype_case("past L2's end", ep(r(S_L2), 6, 3), &root, range(1, 2)),
        retype_case("a full slot", ep(SELF, 19, 2), &root, DELETE_FIRST),
        retype_case("a full L2 slot", ep(r(S_L2), 0, 2), &root, DELETE_FIRST),
        retype_case(
            "four frames",
            rt(ObjectType::Frame4K, 0, SELF, 40, 4),
            &root,
            SyscallError::NotEnoughMemory(free),
        ),
        Case {
            what: "the child untyped's 256 bytes, from its watermark",
            invoked: rs(23),
            ..retype_case(
                "",
                rt(ObjectType::Untyped, 8, SELF, 40, 1),
                &root,
                SyscallError::NotEnoughMemory(256 - 32),
            )
        },
        Case {
            what: "an endpoint from device memory",
            invoked: rs(S_DEV),
            ..retype_case("", ep(SELF, 40, 1), &root, SyscallError::InvalidArgument(0))
        },
        Case {
            what: "a CNode from device memory",
            invoked: rs(S_DEV),
            ..retype_case(
                "",
                rt(ObjectType::CNode, 1, SELF, 40, 1),
                &root,
                SyscallError::InvalidArgument(0),
            )
        },
    ];
    for (name, failure) in bad_names() {
        cases.push(retype_case(
            "node_index does not resolve",
            ep(name, 0, 1),
            &root,
            failed(false, failure),
        ));
    }
    expect_errors(&w, &cases);
}

#[test]
fn retype_errors_that_occur_together_in_abi_order() {
    let w = stocked();
    let root = [rs(S_ROOT)];
    let ep = |node, off, n| rt(ObjectType::Endpoint, 0, node, off, n);
    let (bad, failure) = bad_names()[0];
    let cases = vec![
        retype_case(
            "truncated, type 11",
            vec![11, 0, 0, 0, 40],
            &root,
            TRUNCATED,
        ),
        retype_case("no root, type 11", vec![11, 0, 0, 0, 40, 1], &[], TRUNCATED),
        retype_case(
            "type 11, node_depth 65",
            vec![11, 0, 0, 65, 40, 1],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        retype_case(
            "untyped of 8 bytes, node_depth 65",
            rt(ObjectType::Untyped, 3, (0, 65), 40, 1),
            &root,
            range(4, 47),
        ),
        retype_case(
            "CNode radix 43, root an endpoint",
            rt(ObjectType::CNode, 43, SELF, 40, 1),
            &[rs(20)],
            range(1, 42),
        ),
        // Unlike a CNode method's depth, node_depth before the root.
        retype_case(
            "node_depth 65, root an endpoint",
            ep((0, 65), 40, 1),
            &[rs(20)],
            range(0, 64),
        ),
        retype_case(
            "root empty, node_offset 1000",
            ep(SELF, 1000, 0),
            &[rs(40)],
            failed(false, LookupFailure::InvalidRoot),
        ),
        retype_case(
            "unresolved node, node_offset 1000",
            ep(bad, 1000, 0),
            &root,
            failed(false, failure),
        ),
        retype_case(
            "node an endpoint, node_offset 1000",
            ep(r(20), 1000, 0),
            &root,
            NOT_A_CNODE,
        ),
        retype_case(
            "node_offset 64, 0 objects",
            ep(SELF, 64, 0),
            &root,
            range(0, 63),
        ),
        retype_case(
            "257 objects, past the end",
            ep(SELF, 60, 257),
            &root,
            range(1, 256),
        ),
        retype_case(
            "past the end, over a full slot",
            ep(SELF, 19, 46),
            &root,
            range(1, 45),
        ),
        retype_case(
            "a full slot, not enough memory",
            rt(ObjectType::Frame2M, 0, SELF, 19, 2),
            &root,
            DELETE_FIRST,
        ),
        Case {
            what: "device: not enough memory for TCBs",
            invoked: rs(S_DEV),
            ..retype_case(
                "",
                rt(ObjectType::Tcb, 0, SELF, 40, 3),
                &root,
                SyscallError::NotEnoughMemory(4096),
            )
        },
    ];
    expect_errors(&w, &cases);
}

// ---------------------------------------------------------------------
// CNode methods: success.

#[test]
fn copy_and_mint_derive_with_rights_badges_and_guards() {
    let mut w = stocked();
    let root = [rs(S_ROOT)];
    // A copy of an original is its child, its rights reduced.
    w.ok(rs(S_ROOT), COPY, &copy(r(30), r(20), 0b0011), &root);
    assert_eq!(w.cap(rs(30)), w.cap(rs(20)).with_rights(Rights(0b0011)));
    assert_eq!(cdt::parent(&w.k, rs(30)), Some(rs(20)));
    assert_eq!(
        (w.node(rs(30)).depth(), w.node(rs(30)).original()),
        (2, false)
    );
    // A copy of a plain copy is a sibling; rights never grow; bits 4 to 63
    // of the rights word are ignored.
    w.ok(rs(S_ROOT), COPY, &copy(r(31), r(30), !0b1000), &root);
    assert_eq!(w.cap(rs(31)).rights(), Rights(0b0011));
    assert_eq!(cdt::parent(&w.k, rs(31)), Some(rs(20)));
    assert_eq!(w.node(rs(31)).depth(), 2);
    // Into L2 through two levels, then out of it with L2 as src_root.
    w.ok(rs(S_ROOT), COPY, &copy(l2(2), r(20), 0xF), &root);
    assert_eq!(cdt::parent(&w.k, ls(2)), Some(rs(20)));
    let in_l2 = ((L2_GUARD << L2_RADIX) | 2, 6);
    w.ok(rs(S_ROOT), COPY, &copy(r(32), in_l2, 0xF), &[rs(S_L2)]);
    assert_eq!(w.cap(rs(32)), w.cap(rs(20)));
    // Mint: a badge makes an original child; badge 0 is a Copy.
    w.ok(rs(S_ROOT), MINT, &mint(r(33), r(21), 0b0101, 0xBAD), &root);
    assert_eq!(w.cap(rs(33)).badge(), 0xBAD);
    assert_eq!(w.cap(rs(33)).rights(), Rights(0b0101));
    assert_eq!(cdt::parent(&w.k, rs(33)), Some(rs(21)));
    assert!(w.node(rs(33)).original());
    w.ok(rs(S_ROOT), MINT, &mint(r(34), r(21), 0xF, 0), &root);
    assert_eq!(w.cap(rs(34)), w.cap(rs(21)));
    assert!(!w.node(rs(34)).original());
    // A copy of a badged original is its child and keeps the badge.
    w.ok(rs(S_ROOT), COPY, &copy(r(35), r(33), 0xF), &root);
    assert_eq!(w.cap(rs(35)).badge(), 0xBAD);
    assert_eq!(cdt::parent(&w.k, rs(35)), Some(rs(33)));
    // Mint of a CNode sets the guard; the rights word means nothing to it.
    w.ok(
        rs(S_ROOT),
        MINT,
        &mint(r(36), r(22), 0, cnode_data(3, 0b110)),
        &root,
    );
    let c = w.cap(rs(36));
    assert_eq!(
        (c.object(), c.radix(), c.guard_size(), c.guard()),
        (w.cap(rs(22)).object(), 2, 3, 0b110)
    );
    // The guard names the copy's slots: guard 110, then 2 bits.
    w.ok(
        rs(S_ROOT),
        COPY,
        &copy(((r(36).0 << 5) | (0b110 << 2) | 1, 13), r(20), 0xF),
        &root,
    );
    assert_eq!(w.cap(sa(c.object()).offset(1)), w.cap(rs(20)));
    // An untyped without children: the copy is an original child keeping
    // the watermark, and the source's goes to its size.
    w.make(23, ObjectType::Untyped, 6, SELF, 37, 1);
    w.make(37, ObjectType::Endpoint, 0, SELF, 38, 1);
    w.ok(rs(S_ROOT), DELETE, &at(r(38)), &root);
    w.ok(rs(S_ROOT), COPY, &copy(r(39), r(37), 0), &root);
    assert_eq!(w.cap(rs(39)).watermark(), 32);
    assert_eq!(w.cap(rs(37)).watermark(), 64);
    assert!(w.node(rs(39)).original());
    assert_eq!(cdt::parent(&w.k, rs(39)), Some(rs(37)));
    // Mint of an untyped ignores the data word.
    w.ok(rs(S_ROOT), DELETE, &at(r(39)), &root);
    w.ok(rs(S_ROOT), MINT, &mint(r(39), r(37), 0, u64::MAX), &root);
    assert_eq!(
        w.cap(rs(39)),
        Cap::untyped(w.cap(rs(37)).object(), 6, false, 64)
    );
    // A Hypervisor capability: Mint with word 0 is a Copy, a plain copy of
    // a boot root; Mutate with word 0 moves it.
    w.ok(rs(S_ROOT), MINT, &mint(r(40), r(29), 0xF, 0), &root);
    assert_eq!(w.cap(rs(40)), w.cap(rs(29)));
    assert!(!w.node(rs(40)).original());
    assert_eq!(cdt::parent(&w.k, rs(40)), Some(rs(29)));
    w.ok(rs(S_ROOT), MUTATE, &mutate(r(41), r(40), 0), &root);
    assert!(w.cap(rs(40)).is_null());
    assert_eq!(cdt::parent(&w.k, rs(41)), Some(rs(29)));
    w.check();
}

#[test]
fn move_mutate_and_rotate_keep_each_capability_in_its_place() {
    let mut w = stocked();
    let root = [rs(S_ROOT)];
    let two = [rs(S_ROOT), rs(S_ROOT)];
    // Move: unchanged, with its node; the source is emptied; `moved` runs.
    let (cap, node) = (w.cap(rs(25)), w.node(rs(25)));
    w.ok(rs(S_ROOT), MOVE, &mv(r(40), r(25)), &root);
    assert_eq!((w.cap(rs(40)), w.node(rs(40)).depth()), (cap, node.depth()));
    assert!(w.node(rs(40)).original());
    assert!(w.cap(rs(25)).is_null());
    assert_eq!(cdt::parent(&w.k, rs(40)), Some(rs(20)));
    assert_eq!(
        w.k.events.last(),
        Some(&Event::Moved {
            cap,
            from: rs(25),
            to: rs(40)
        })
    );
    // Any capability moves: a Zombie, IRQControl, a PageTable; into L2.
    w.ok(rs(S_ROOT), MOVE, &mv(r(41), r(28)), &root);
    assert_eq!(w.cap(rs(41)).cap_type(), CapType::Zombie);
    w.ok(rs(S_ROOT), MOVE, &mv(l2(4), r(27)), &root);
    assert_eq!(w.cap(ls(4)).cap_type(), CapType::IrqControl);
    // Mutate: a new guard on a CNode, which stays an original child.
    w.ok(
        rs(S_ROOT),
        MUTATE,
        &mutate(r(42), r(22), cnode_data(4, 0b1001)),
        &root,
    );
    let c = w.cap(rs(42));
    assert_eq!((c.guard_size(), c.guard(), c.radix()), (4, 0b1001, 2));
    assert!(w.node(rs(42)).original());
    assert_eq!(cdt::parent(&w.k, rs(42)), Some(rs(S_UT)));
    // Mutate ignores the data word of a PageTable.
    w.ok(rs(S_ROOT), MUTATE, &mutate(r(43), r(26), u64::MAX), &root);
    let pt = w.cap(rs(43));
    assert_eq!(pt.cap_type(), CapType::PageTable);
    // Rotate: the pivot's capability to the destination with dest_data,
    // the source's to the pivot with pivot_data (meaningless to a
    // PageTable).
    w.ok(
        rs(S_ROOT),
        ROTATE,
        &rotate(r(44), cnode_data(7, 0b101), r(42), u64::MAX, r(43)),
        &two,
    );
    assert_eq!(w.cap(rs(44)), c.with_data(cnode_data(7, 0b101)));
    assert_eq!(w.cap(rs(42)), pt);
    assert!(w.cap(rs(43)).is_null());
    assert!(w.node(rs(44)).original());
    // Rotate as a swap, the destination the source, guards applied.
    w.ok(
        rs(S_ROOT),
        ROTATE,
        &rotate(r(44), 0, r(42), cnode_data(2, 0b11), r(44)),
        &two,
    );
    assert_eq!(w.cap(rs(44)), pt);
    assert_eq!(w.cap(rs(42)).guard(), 0b11);
    assert_eq!(cdt::parent(&w.k, rs(42)), Some(rs(S_UT)));
    assert_eq!(cdt::parent(&w.k, rs(44)), Some(rs(S_UT)));
    // The pivot named from another root: L2's capability.
    w.ok(rs(S_ROOT), MOVE, &mv(l2(5), r(42)), &root);
    let pivot = ((L2_GUARD << L2_RADIX) | 5, 6);
    w.ok(
        rs(S_ROOT),
        ROTATE,
        &rotate(r(45), cnode_data(0, 0), pivot, 0, r(44)),
        &[rs(S_L2), rs(S_ROOT)],
    );
    assert_eq!(w.cap(rs(45)).guard_size(), 0);
    assert_eq!(w.cap(ls(5)), pt);
    w.check();
}

#[test]
fn revoke_and_delete_and_their_no_change_cases() {
    let mut w = stocked();
    let root = [rs(S_ROOT)];
    w.ok(rs(S_ROOT), COPY, &copy(r(30), r(20), 0xF), &root);
    w.ok(rs(S_ROOT), COPY, &copy(r(31), r(25), 0xF), &root);
    let ep = w.cap(rs(20));
    // Revoke 20: its copy, its badged child 25 and that one's copy go.
    w.ok(rs(S_ROOT), REVOKE, &at(r(20)), &[]);
    assert_eq!(w.cap(rs(20)), ep);
    for s in [25, 30, 31] {
        assert!(w.cap(rs(s)).is_null(), "{s}");
    }
    assert!(!w.k.events.contains(&Event::Finalise {
        cap: ep,
        last: true
    }));
    // A slot without children, an empty one, and an empty one to delete:
    // nothing changes and no hook runs.
    let before = w.clone();
    w.ok(rs(S_ROOT), REVOKE, &at(r(20)), &[]);
    w.ok(rs(S_ROOT), REVOKE, &at(r(50)), &[]);
    w.ok(rs(S_ROOT), DELETE, &at(r(50)), &[]);
    w.ok(rs(S_ROOT), DELETE, &at(l2(6)), &[]);
    assert!(w.k.mem == before.k.mem && w.k.events == before.k.events);
    // The last capability to an endpoint is finalised as the last.
    let ep = w.cap(rs(21));
    w.ok(rs(S_ROOT), DELETE, &at(r(21)), &[]);
    assert!(w.k.events.contains(&Event::Finalise {
        cap: ep,
        last: true
    }));
    assert!(w.cap(rs(21)).is_null());
    // The invoked CNode is the root of the slot argument: L2's capability
    // names L2's slots in 6 bits.
    w.ok(rs(S_L2), DELETE, &at(((L2_GUARD << L2_RADIX) | 1, 6)), &[]);
    assert!(w.cap(ls(1)).is_null());
    // Extra registers and capabilities are ignored.
    w.ok(rs(S_ROOT), REVOKE, &[r(S_UT).0, r(S_UT).1, 5, 6], &[rs(20)]);
    assert!(!cdt::has_children(&w.k, rs(S_UT)));
    w.check();
}

// ---------------------------------------------------------------------
// CNode methods: errors.

#[test]
fn cnode_errors_one_per_row() {
    let w = stocked();
    let root = [rs(S_ROOT)];
    let two = [rs(S_ROOT), rs(S_ROOT)];
    let mut cases = vec![
        // TruncatedMessage: one length check per method.
        cnode_case(
            "revoke, 1 register",
            REVOKE,
            vec![r(20).0],
            &root,
            TRUNCATED,
        ),
        cnode_case(
            "delete, 1 register",
            DELETE,
            vec![r(20).0],
            &root,
            TRUNCATED,
        ),
        cnode_case(
            "copy, 4 registers",
            COPY,
            copy(r(40), r(20), 0xF)[..4].to_vec(),
            &root,
            TRUNCATED,
        ),
        cnode_case(
            "copy, no src_root",
            COPY,
            copy(r(40), r(20), 0xF),
            &[],
            TRUNCATED,
        ),
        cnode_case(
            "mint, 5 registers",
            MINT,
            mint(r(40), r(20), 0xF, 1)[..5].to_vec(),
            &root,
            TRUNCATED,
        ),
        cnode_case(
            "mint, no src_root",
            MINT,
            mint(r(40), r(20), 0xF, 1),
            &[],
            TRUNCATED,
        ),
        cnode_case(
            "move, 3 registers",
            MOVE,
            mv(r(40), r(20))[..3].to_vec(),
            &root,
            TRUNCATED,
        ),
        cnode_case("move, no src_root", MOVE, mv(r(40), r(20)), &[], TRUNCATED),
        cnode_case(
            "mutate, 4 registers",
            MUTATE,
            mutate(r(40), r(22), 0)[..4].to_vec(),
            &root,
            TRUNCATED,
        ),
        cnode_case(
            "mutate, no src_root",
            MUTATE,
            mutate(r(40), r(22), 0),
            &[],
            TRUNCATED,
        ),
        cnode_case(
            "rotate, 7 registers",
            ROTATE,
            rotate(r(40), 0, r(22), 0, r(26))[..7].to_vec(),
            &two,
            TRUNCATED,
        ),
        cnode_case(
            "rotate, 1 extra capability",
            ROTATE,
            rotate(r(40), 0, r(22), 0, r(26)),
            &root,
            TRUNCATED,
        ),
        // The destination's depth.
        cnode_case(
            "revoke, depth 0",
            REVOKE,
            at((r(20).0, 0)),
            &[],
            range(1, 64),
        ),
        cnode_case(
            "delete, depth 65",
            DELETE,
            at((r(20).0, 65)),
            &[],
            range(1, 64),
        ),
        cnode_case(
            "copy, dest_depth 2^64 - 1",
            COPY,
            copy((0, u64::MAX), r(20), 0xF),
            &root,
            range(1, 64),
        ),
        cnode_case(
            "mint, dest_depth 0",
            MINT,
            mint((0, 0), r(20), 0xF, 1),
            &root,
            range(1, 64),
        ),
        cnode_case(
            "move, dest_depth 0",
            MOVE,
            mv((0, 0), r(20)),
            &root,
            range(1, 64),
        ),
        cnode_case(
            "mutate, dest_depth 65",
            MUTATE,
            mutate((0, 65), r(22), 0),
            &root,
            range(1, 64),
        ),
        cnode_case(
            "rotate, dest_depth 0",
            ROTATE,
            rotate((0, 0), 0, r(22), 0, r(26)),
            &two,
            range(1, 64),
        ),
        // Copy, Mint, Move and Mutate: the destination is full.
        cnode_case(
            "copy into 21",
            COPY,
            copy(r(21), r(20), 0xF),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "mint into 21",
            MINT,
            mint(r(21), r(20), 0xF, 1),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "move into L2 1",
            MOVE,
            mv(l2(1), r(20)),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "mutate into the Zombie",
            MUTATE,
            mutate(r(28), r(22), 0),
            &root,
            DELETE_FIRST,
        ),
        // The source does not resolve.
        cnode_case(
            "copy, src_root an endpoint",
            COPY,
            copy(r(40), r(20), 0xF),
            &[rs(20)],
            failed(true, LookupFailure::InvalidRoot),
        ),
        cnode_case(
            "mint, src_root empty",
            MINT,
            mint(r(40), r(20), 0xF, 0),
            &[rs(40)],
            failed(true, LookupFailure::InvalidRoot),
        ),
        cnode_case(
            "move, src_root a Zombie",
            MOVE,
            mv(r(40), r(20)),
            &[rs(28)],
            failed(true, LookupFailure::InvalidRoot),
        ),
        cnode_case(
            "mutate, src_root IRQControl",
            MUTATE,
            mutate(r(40), r(22), 0),
            &[rs(27)],
            failed(true, LookupFailure::InvalidRoot),
        ),
        cnode_case(
            "copy, src_depth 0",
            COPY,
            copy(r(40), (r(20).0, 0), 0xF),
            &root,
            range(1, 64),
        ),
        cnode_case(
            "move, src_depth 65",
            MOVE,
            mv(r(40), (r(20).0, 65)),
            &root,
            range(1, 64),
        ),
        // The source is empty.
        cnode_case(
            "copy from 40",
            COPY,
            copy(r(41), r(40), 0xF),
            &root,
            EMPTY_SOURCE,
        ),
        cnode_case(
            "mint from L2 6",
            MINT,
            mint(r(41), l2(6), 0xF, 1),
            &root,
            EMPTY_SOURCE,
        ),
        cnode_case("move from 40", MOVE, mv(r(41), r(40)), &root, EMPTY_SOURCE),
        cnode_case(
            "mutate from 40",
            MUTATE,
            mutate(r(41), r(40), 0),
            &root,
            EMPTY_SOURCE,
        ),
        // An untyped with children.
        cnode_case(
            "copy the untyped 23",
            COPY,
            copy(r(40), r(23), 0xF),
            &root,
            REVOKE_FIRST,
        ),
        cnode_case(
            "mint the untyped 23",
            MINT,
            mint(r(40), r(23), 0xF, 0),
            &root,
            REVOKE_FIRST,
        ),
        cnode_case(
            "copy the boot untyped",
            COPY,
            copy(r(40), r(S_UT), 0xF),
            &root,
            REVOKE_FIRST,
        ),
        // Cannot be copied.
        cnode_case(
            "copy a PageTable",
            COPY,
            copy(r(40), r(26), 0xF),
            &root,
            ILLEGAL,
        ),
        cnode_case(
            "copy IRQControl",
            COPY,
            copy(r(40), r(27), 0xF),
            &root,
            ILLEGAL,
        ),
        cnode_case(
            "copy a Zombie",
            COPY,
            copy(r(40), r(28), 0xF),
            &root,
            ILLEGAL,
        ),
        cnode_case(
            "mint a PageTable",
            MINT,
            mint(r(40), r(26), 0xF, 0),
            &root,
            ILLEGAL,
        ),
        // Mint's data word.
        cnode_case(
            "mint a badged endpoint",
            MINT,
            mint(r(40), r(25), 0xF, 0),
            &root,
            ILLEGAL,
        ),
        cnode_case(
            "mint a badged endpoint again",
            MINT,
            mint(r(40), r(25), 0xF, 9),
            &root,
            ILLEGAL,
        ),
        cnode_case(
            "mint a guard of 63 bits on radix 2",
            MINT,
            mint(r(40), r(22), 0xF, 63),
            &root,
            ILLEGAL,
        ),
        // Mutate's data word.
        cnode_case(
            "mutate an endpoint, word 0",
            MUTATE,
            mutate(r(40), r(20), 0),
            &root,
            ILLEGAL,
        ),
        cnode_case(
            "mutate a guard of 63 bits",
            MUTATE,
            mutate(r(40), r(22), 63),
            &root,
            ILLEGAL,
        ),
        // A Hypervisor capability takes only word 0 until M9's narrowing.
        cnode_case(
            "mint a Hypervisor capability, word 1",
            MINT,
            mint(r(40), r(29), 0xF, 1),
            &root,
            ILLEGAL,
        ),
        cnode_case(
            "mutate a Hypervisor capability, word 1",
            MUTATE,
            mutate(r(40), r(29), 1),
            &root,
            ILLEGAL,
        ),
        // Rotate: the source, then the pivot, does not resolve.
        cnode_case(
            "rotate, src_root an endpoint",
            ROTATE,
            rotate(r(40), 0, r(22), 0, r(26)),
            &[rs(S_ROOT), rs(20)],
            failed(true, LookupFailure::InvalidRoot),
        ),
        cnode_case(
            "rotate, src_depth 0",
            ROTATE,
            rotate(r(40), 0, r(22), 0, (0, 0)),
            &two,
            range(1, 64),
        ),
        cnode_case(
            "rotate, pivot_root empty",
            ROTATE,
            rotate(r(40), 0, r(22), 0, r(26)),
            &[rs(40), rs(S_ROOT)],
            failed(true, LookupFailure::InvalidRoot),
        ),
        cnode_case(
            "rotate, pivot_depth 65",
            ROTATE,
            rotate(r(40), 0, (0, 65), 0, r(26)),
            &two,
            range(1, 64),
        ),
        // Rotate: the pivot is the source or the destination.
        cnode_case(
            "rotate, pivot = source",
            ROTATE,
            rotate(r(40), 0, r(26), 0, r(26)),
            &two,
            ILLEGAL,
        ),
        cnode_case(
            "rotate, pivot = destination",
            ROTATE,
            rotate(r(40), 0, r(40), 0, r(26)),
            &two,
            ILLEGAL,
        ),
        // Rotate: the destination is neither the source nor empty.
        cnode_case(
            "rotate into 20",
            ROTATE,
            rotate(r(20), 0, r(22), 0, r(26)),
            &two,
            DELETE_FIRST,
        ),
        // Rotate: the source, then the pivot, is empty.
        cnode_case(
            "rotate from 41",
            ROTATE,
            rotate(r(40), 0, r(22), 0, r(41)),
            &two,
            EMPTY_SOURCE,
        ),
        cnode_case(
            "rotate, pivot 41",
            ROTATE,
            rotate(r(40), 0, r(41), 0, r(26)),
            &two,
            EMPTY_SOURCE,
        ),
        // Rotate: a data word.
        cnode_case(
            "rotate an endpoint to the pivot",
            ROTATE,
            rotate(r(40), 0, r(22), 0, r(20)),
            &two,
            ILLEGAL,
        ),
        cnode_case(
            "rotate an endpoint to the destination",
            ROTATE,
            rotate(r(40), 0, r(20), 0, r(26)),
            &two,
            ILLEGAL,
        ),
        cnode_case(
            "rotate a 63-bit guard to the destination",
            ROTATE,
            rotate(r(40), 63, r(22), 0, r(26)),
            &two,
            ILLEGAL,
        ),
        cnode_case(
            "rotate a 63-bit guard to the pivot",
            ROTATE,
            rotate(r(40), 0, r(26), 63, r(22)),
            &two,
            ILLEGAL,
        ),
        cnode_case(
            "rotate a Hypervisor capability with a word",
            ROTATE,
            rotate(r(40), 1, r(29), 0, r(26)),
            &two,
            ILLEGAL,
        ),
    ];
    // The destination, and each source, does not resolve.
    for (name, failure) in bad_names() {
        cases.push(cnode_case(
            "revoke",
            REVOKE,
            at(name),
            &[],
            failed(false, failure),
        ));
        cases.push(cnode_case(
            "delete",
            DELETE,
            at(name),
            &[],
            failed(false, failure),
        ));
        cases.push(cnode_case(
            "copy to",
            COPY,
            copy(name, r(20), 0xF),
            &root,
            failed(false, failure),
        ));
        cases.push(cnode_case(
            "copy from",
            COPY,
            copy(r(40), name, 0xF),
            &root,
            failed(true, failure),
        ));
        cases.push(cnode_case(
            "mint from",
            MINT,
            mint(r(40), name, 0xF, 1),
            &root,
            failed(true, failure),
        ));
        cases.push(cnode_case(
            "move from",
            MOVE,
            mv(r(40), name),
            &root,
            failed(true, failure),
        ));
        cases.push(cnode_case(
            "mutate from",
            MUTATE,
            mutate(r(40), name, 0),
            &root,
            failed(true, failure),
        ));
        cases.push(cnode_case(
            "rotate to",
            ROTATE,
            rotate(name, 0, r(22), 0, r(26)),
            &two,
            failed(false, failure),
        ));
        cases.push(cnode_case(
            "rotate from",
            ROTATE,
            rotate(r(40), 0, r(22), 0, name),
            &two,
            failed(true, failure),
        ));
        cases.push(cnode_case(
            "rotate pivot",
            ROTATE,
            rotate(r(40), 0, name, 0, r(26)),
            &two,
            failed(true, failure),
        ));
    }
    expect_errors(&w, &cases);
}

#[test]
fn cnode_errors_that_occur_together_in_abi_order() {
    let w = stocked();
    let root = [rs(S_ROOT)];
    let two = [rs(S_ROOT), rs(S_ROOT)];
    let ep_root = [rs(20)];
    let invalid_root = failed(true, LookupFailure::InvalidRoot);
    let (bad, failure) = bad_names()[0];
    let (bad2, failure2) = bad_names()[3];
    let cases = vec![
        cnode_case(
            "truncated, depth 0",
            COPY,
            copy((0, 0), r(20), 0)[..4].to_vec(),
            &root,
            TRUNCATED,
        ),
        cnode_case(
            "truncated rotate, pivot = source",
            ROTATE,
            rotate(r(40), 0, r(26), 0, r(26)),
            &root,
            TRUNCATED,
        ),
        cnode_case("revoke truncated, depth 0", REVOKE, vec![0], &[], TRUNCATED),
        // The destination before the source, whatever the source's failure.
        cnode_case(
            "dest_depth 0, src_root an endpoint",
            COPY,
            copy((0, 0), r(20), 0),
            &ep_root,
            range(1, 64),
        ),
        cnode_case(
            "dest unresolved, src_root an endpoint",
            MOVE,
            mv(bad, r(20)),
            &ep_root,
            failed(false, failure),
        ),
        cnode_case(
            "dest unresolved, src_depth 0",
            MINT,
            mint(bad, (0, 0), 0, 0),
            &root,
            failed(false, failure),
        ),
        cnode_case(
            "rotate: dest_depth 0, src_root an endpoint",
            ROTATE,
            rotate((0, 0), 0, r(22), 0, r(26)),
            &[rs(20), rs(20)],
            range(1, 64),
        ),
        cnode_case(
            "rotate: dest unresolved, src unresolved",
            ROTATE,
            rotate(bad, 0, r(22), 0, bad2),
            &two,
            failed(false, failure),
        ),
        // DeleteFirst before the source lookup, its root check included.
        cnode_case(
            "full, src_root an endpoint",
            COPY,
            copy(r(21), r(20), 0),
            &ep_root,
            DELETE_FIRST,
        ),
        cnode_case(
            "full, src_depth 0",
            MOVE,
            mv(r(21), (0, 0)),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "full, source unresolved",
            MUTATE,
            mutate(r(21), bad, 0),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "full, source empty",
            COPY,
            copy(r(21), r(40), 0),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "full, an untyped with children",
            COPY,
            copy(r(21), r(23), 0),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "full, a PageTable",
            COPY,
            copy(r(21), r(26), 0),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "full, a badged source",
            MINT,
            mint(r(21), r(25), 0, 0),
            &root,
            DELETE_FIRST,
        ),
        cnode_case(
            "full, an endpoint to mutate",
            MUTATE,
            mutate(r(21), r(20), 0),
            &root,
            DELETE_FIRST,
        ),
        // A root that is not a CNode before the depth, as seL4.
        cnode_case(
            "src_root an endpoint, src_depth 0",
            COPY,
            copy(r(40), (0, 0), 0),
            &ep_root,
            invalid_root,
        ),
        cnode_case(
            "rotate: src_root an endpoint, src_depth 65",
            ROTATE,
            rotate(r(40), 0, r(22), 0, (0, 65)),
            &[rs(S_ROOT), rs(20)],
            invalid_root,
        ),
        // An untyped with children: RevokeFirst whatever the Mint word.
        cnode_case(
            "mint the untyped 23 with a word",
            MINT,
            mint(r(40), r(23), 0, u64::MAX),
            &root,
            REVOKE_FIRST,
        ),
        // Rotate: the source before the pivot.
        cnode_case(
            "rotate: source and pivot unresolved",
            ROTATE,
            rotate(r(40), 0, bad2, 0, bad),
            &two,
            failed(true, failure),
        ),
        cnode_case(
            "rotate: src_root an endpoint, pivot_depth 0",
            ROTATE,
            rotate(r(40), 0, (0, 0), 0, r(26)),
            &[rs(S_ROOT), rs(20)],
            invalid_root,
        ),
        cnode_case(
            "rotate: src_depth 0, pivot_root an endpoint",
            ROTATE,
            rotate(r(40), 0, r(22), 0, (0, 0)),
            &[rs(20), rs(S_ROOT)],
            range(1, 64),
        ),
        cnode_case(
            "rotate: source unresolved, pivot_depth 0",
            ROTATE,
            rotate(r(40), 0, (0, 0), 0, bad),
            &two,
            failed(true, failure),
        ),
        cnode_case(
            "rotate: pivot unresolved, destination full",
            ROTATE,
            rotate(r(20), 0, bad2, 0, r(26)),
            &two,
            failed(true, failure2),
        ),
        cnode_case(
            "rotate: pivot unresolved, source empty",
            ROTATE,
            rotate(r(40), 0, bad2, 0, r(41)),
            &two,
            failed(true, failure2),
        ),
        cnode_case(
            "rotate: pivot = source, destination full",
            ROTATE,
            rotate(r(20), 0, r(26), 0, r(26)),
            &two,
            ILLEGAL,
        ),
        cnode_case(
            "rotate: destination full, source empty",
            ROTATE,
            rotate(r(20), 0, r(22), 0, r(41)),
            &two,
            DELETE_FIRST,
        ),
        cnode_case(
            "rotate: destination full, an endpoint",
            ROTATE,
            rotate(r(21), 0, r(22), 0, r(20)),
            &two,
            DELETE_FIRST,
        ),
        cnode_case(
            "rotate: source empty, pivot empty",
            ROTATE,
            rotate(r(40), 0, r(42), 0, r(41)),
            &two,
            EMPTY_SOURCE,
        ),
        cnode_case(
            "rotate: source empty, an endpoint pivot",
            ROTATE,
            rotate(r(40), 0, r(20), 0, r(41)),
            &two,
            EMPTY_SOURCE,
        ),
        cnode_case(
            "rotate: pivot empty, an endpoint source",
            ROTATE,
            rotate(r(40), 0, r(41), 0, r(20)),
            &two,
            EMPTY_SOURCE,
        ),
        // A swap whose pivot is the destination: pivot = source too.
        cnode_case(
            "rotate: swap with itself",
            ROTATE,
            rotate(r(20), 0, r(20), 0, r(20)),
            &two,
            ILLEGAL,
        ),
    ];
    expect_errors(&w, &cases);
}

// ---------------------------------------------------------------------
// The derivation limit.

/// The world with the RAM untyped's slot at `depth`, as a chain of copies
/// whose sources were deleted leaves it: original, `low` 0.
fn at_depth(depth: u32) -> World {
    let mut w = World::new();
    let mut s = w.k.load(rs(S_UT));
    s.node = Node::new(true, depth, 0);
    w.k.store(rs(S_UT), s);
    let mut s = w.k.load(rs(S_DEV));
    s.node = Node::new(true, depth, 0);
    w.k.store(rs(S_DEV), s);
    w.check();
    w
}

#[test]
fn the_derivation_limit_through_the_decoder() {
    let root = [rs(S_ROOT)];
    let ep = rt(ObjectType::Endpoint, 0, SELF, 40, 1);
    // An untyped at 4095 makes no child: Retype, Copy and Mint refuse, and
    // change nothing. Earlier errors still win: memory, device type.
    let w = at_depth(MAX_DERIVATION_DEPTH);
    expect_errors(
        &w,
        &[
            retype_case("retype at 4095", ep.clone(), &root, ILLEGAL),
            retype_case(
                "retype too much at 4095",
                rt(ObjectType::Frame4K, 0, SELF, 40, 9),
                &root,
                SyscallError::NotEnoughMemory(1 << UT_BITS),
            ),
            Case {
                what: "device frame at 4095",
                invoked: rs(S_DEV),
                ..retype_case("", rt(ObjectType::Frame4K, 0, SELF, 40, 1), &root, ILLEGAL)
            },
            Case {
                what: "device endpoint at 4095",
                invoked: rs(S_DEV),
                ..retype_case("", ep.clone(), &root, SyscallError::InvalidArgument(0))
            },
            cnode_case(
                "copy at 4095",
                COPY,
                copy(r(40), r(S_UT), 0xF),
                &root,
                ILLEGAL,
            ),
            cnode_case(
                "mint at 4095",
                MINT,
                mint(r(40), r(S_UT), 0xF, 0),
                &root,
                ILLEGAL,
            ),
        ],
    );
    // Moving it derives nothing.
    let mut m = w.clone();
    m.ok(rs(S_ROOT), MOVE, &mv(r(40), r(S_UT)), &root);
    assert_eq!(m.node(rs(40)).depth(), MAX_DERIVATION_DEPTH);

    // One level up, the children are at 4095: an original endpoint and a
    // copy of the device untyped there make no child.
    let mut w = at_depth(MAX_DERIVATION_DEPTH - 1);
    w.ok(rs(S_UT), RETYPE, &ep, &root);
    w.ok(rs(S_ROOT), COPY, &copy(r(41), r(S_DEV), 0), &root);
    assert_eq!(w.node(rs(40)).depth(), MAX_DERIVATION_DEPTH);
    assert_eq!(w.node(rs(41)).depth(), MAX_DERIVATION_DEPTH);
    expect_errors(
        &w,
        &[
            cnode_case(
                "copy an original endpoint at 4095",
                COPY,
                copy(r(42), r(40), 0xF),
                &root,
                ILLEGAL,
            ),
            cnode_case(
                "mint a badge at 4095",
                MINT,
                mint(r(42), r(40), 0xF, 9),
                &root,
                ILLEGAL,
            ),
            cnode_case(
                "mint badge 0 at 4095",
                MINT,
                mint(r(42), r(40), 0xF, 0),
                &root,
                ILLEGAL,
            ),
            cnode_case(
                "copy the untyped copy",
                COPY,
                copy(r(42), r(41), 0),
                &root,
                ILLEGAL,
            ),
            Case {
                what: "retype the untyped copy",
                invoked: rs(41),
                ..retype_case("", rt(ObjectType::Frame4K, 0, SELF, 42, 1), &root, ILLEGAL)
            },
        ],
    );

    // Two levels up: a plain copy at 4095 still makes siblings, a badged
    // one among them, but that badged original makes no child.
    let mut w = at_depth(MAX_DERIVATION_DEPTH - 2);
    w.ok(rs(S_UT), RETYPE, &ep, &root);
    w.ok(rs(S_ROOT), COPY, &copy(r(41), r(40), 0xF), &root);
    w.ok(rs(S_ROOT), COPY, &copy(r(42), r(41), 0xF), &root);
    w.ok(rs(S_ROOT), MINT, &mint(r(43), r(41), 0xF, 5), &root);
    for s in [41, 42, 43] {
        assert_eq!(w.node(rs(s)).depth(), MAX_DERIVATION_DEPTH);
        assert_eq!(cdt::parent(&w.k, rs(s)), Some(rs(40)));
    }
    assert!(w.node(rs(43)).original());
    expect_errors(
        &w,
        &[cnode_case(
            "copy the badged original at 4095",
            COPY,
            copy(r(44), r(43), 0xF),
            &root,
            ILLEGAL,
        )],
    );
}

/// The limit reached as a ring-3 task would reach it: copying an untyped
/// and deleting the source, over and over, all through the decoder.
#[test]
#[cfg_attr(miri, ignore = "8,188 decoded calls are too slow under Miri")]
fn the_derivation_limit_reached_by_copy_and_delete() {
    let mut w = World::new();
    let root = [rs(S_ROOT)];
    w.make(S_UT, ObjectType::Untyped, 12, SELF, 40, 1);
    let (mut from, mut to) = (40, 41);
    for _ in 1..MAX_DERIVATION_DEPTH {
        assert_eq!(
            w.call(rs(S_ROOT), COPY, &copy(r(to), r(from), 0), &root),
            Ok(Reply::EMPTY)
        );
        assert_eq!(
            w.call(rs(S_ROOT), DELETE, &at(r(from)), &[]),
            Ok(Reply::EMPTY)
        );
        core::mem::swap(&mut from, &mut to);
    }
    w.check();
    assert_eq!(w.node(rs(from)).depth(), MAX_DERIVATION_DEPTH);
    expect_errors(
        &w,
        &[
            cnode_case("copy", COPY, copy(r(to), r(from), 0), &root, ILLEGAL),
            cnode_case("mint", MINT, mint(r(to), r(from), 0, 0), &root, ILLEGAL),
            Case {
                what: "retype",
                invoked: rs(from),
                ..retype_case("", rt(ObjectType::Endpoint, 0, SELF, to, 1), &root, ILLEGAL)
            },
        ],
    );
    // The holder of the boot untyped can still revoke it all.
    w.ok(rs(S_ROOT), REVOKE, &at(r(S_UT)), &[]);
    assert!(w.cap(rs(from)).is_null());
}

// ---------------------------------------------------------------------
// Preempted calls, restarted by decoding the same message again.

/// Runs the call from `start` unpreempted, then preempted at the `every`-th
/// point of each attempt for each `every` in `schedules`: each ends as the
/// unpreempted call does, in memory and in every hook call. Returns the
/// unpreempted end and the preemption counts.
fn same_end_when_restarted(
    start: &World,
    schedules: &[u64],
    invoked: SlotAddr,
    label: u64,
    mrs: &[u64],
    extra: &[SlotAddr],
) -> (World, Vec<u32>) {
    let mut whole = start.clone();
    assert_eq!(whole.call(invoked, label, mrs, extra), Ok(Reply::EMPTY));
    whole.check();
    let mut counts = Vec::new();
    for &every in schedules {
        let mut w = start.clone();
        let (r, n) = w.run(every, invoked, label, mrs, extra);
        assert_eq!(r, Ok(Reply::EMPTY), "every {every}");
        assert!(w.k.mem == whole.k.mem, "every {every}: memory differs");
        assert_eq!(w.k.events, whole.k.events, "every {every}");
        counts.push(n);
    }
    (whole, counts)
}

#[test]
fn a_retype_preempted_in_its_reset_restarts_to_the_same_end() {
    let mut w = World::new();
    let root = [rs(S_ROOT)];
    // Dirty 16 KiB, then revoke it all: the next retype resets 16 KiB in
    // four chunks, with three preemption points.
    w.make(S_UT, ObjectType::Endpoint, 0, SELF, 20, 2);
    w.make(S_UT, ObjectType::Frame4K, 0, SELF, 22, 3);
    assert_eq!(w.cap(rs(S_UT)).watermark(), 0x4000);
    w.ok(rs(S_ROOT), REVOKE, &at(r(S_UT)), &[]);
    assert!(!w.k.mem.is_zero(UT + 0x3000, 0x1000));
    let msg = rt(ObjectType::Tcb, 0, r(S_L2), 2, 2);
    let (whole, counts) = same_end_when_restarted(&w, &[0, 1, 2, 3], rs(S_UT), RETYPE, &msg, &root);
    assert_eq!(counts, [3, 1, 1, 0]);
    assert_eq!(whole.cap(ls(3)).object(), UT + 2048);
    assert_eq!(
        whole.cap(sa(UT + 2048).offset(TCB_SLOT_REPLY)),
        Cap::reply(UT + 2048, true, true)
    );
    assert!(whole.k.mem.is_zero(UT + 0x1000, 0x3000));

    // Step by step: each attempt lowers the watermark by a chunk, leaves
    // zeros above it and puts nothing in L2 until the last.
    let mut w = w.clone();
    for left in [0x3000, 0x2000, 0x1000] {
        w.k.preempt_in = Some(0);
        assert_eq!(
            w.call(rs(S_UT), RETYPE, &msg, &root),
            Err(InvokeError::Preempted)
        );
        w.check();
        assert_eq!(w.cap(rs(S_UT)).watermark(), left);
        assert!(w.k.mem.is_zero(UT + left, (1 << UT_BITS) - left));
        assert!(w.cap(ls(2)).is_null() && w.cap(ls(3)).is_null());
        assert!(!cdt::has_children(&w.k, rs(S_UT)));
    }
    w.ok(rs(S_UT), RETYPE, &msg, &root);
    assert!(w.k.mem == whole.k.mem);
}

#[test]
fn a_revoke_preempted_anywhere_restarts_to_the_same_end() {
    let mut w = World::new();
    let root = [rs(S_ROOT)];
    w.make(S_UT, ObjectType::Endpoint, 0, SELF, 20, 2);
    w.ok(rs(S_ROOT), COPY, &copy(r(30), r(20), 0xF), &root);
    w.ok(rs(S_ROOT), MINT, &mint(r(31), r(20), 0xF, 5), &root);
    w.ok(rs(S_ROOT), COPY, &copy(r(32), r(31), 0xF), &root);
    // A CNode holding a copy of an endpoint and another CNode's last
    // capability, which holds a third CNode's.
    w.make(S_UT, ObjectType::CNode, 2, SELF, 22, 1);
    w.make(S_UT, ObjectType::CNode, 1, SELF, 23, 2);
    w.ok(rs(S_ROOT), COPY, &copy(inside(22, 2, 1), r(21), 0xF), &root);
    w.ok(rs(S_ROOT), MOVE, &mv(inside(23, 1, 0), r(24)), &root);
    w.ok(rs(S_ROOT), MOVE, &mv(inside(22, 2, 3), r(23)), &root);
    // A TCB, whose deletion clears its reply master, and an untyped with a
    // child.
    w.make(S_UT, ObjectType::Tcb, 0, SELF, 25, 1);
    w.make(S_UT, ObjectType::Untyped, 10, SELF, 26, 1);
    w.make(26, ObjectType::Notification, 0, SELF, 27, 3);
    let schedules: &[u64] = if cfg!(miri) { &[0] } else { &[0, 1, 2, 5] };
    let (whole, counts) =
        same_end_when_restarted(&w, schedules, rs(S_ROOT), REVOKE, &at(r(S_UT)), &[]);
    assert!(counts[0] > 10, "{counts:?}");
    for s in 20..33 {
        assert!(whole.cap(rs(s)).is_null(), "{s}");
    }
    assert!(!cdt::has_children(&whole.k, rs(S_UT)));
}

#[test]
fn a_delete_preempted_anywhere_restarts_to_the_same_end() {
    let mut w = World::new();
    let root = [rs(S_ROOT)];
    // C (radix 2) in 22 holds an endpoint copy and the last capability to
    // D (radix 1), which holds another.
    w.make(S_UT, ObjectType::CNode, 2, SELF, 22, 1);
    w.make(S_UT, ObjectType::CNode, 1, SELF, 23, 1);
    w.make(S_UT, ObjectType::Endpoint, 0, SELF, 24, 1);
    w.ok(rs(S_ROOT), COPY, &copy(inside(22, 2, 1), r(24), 0xF), &root);
    w.ok(rs(S_ROOT), COPY, &copy(inside(23, 1, 1), r(24), 0xF), &root);
    w.ok(rs(S_ROOT), MOVE, &mv(inside(22, 2, 3), r(23)), &root);
    let (whole, counts) =
        same_end_when_restarted(&w, &[0, 1, 2], rs(S_ROOT), DELETE, &at(r(22)), &[]);
    assert!(counts[0] >= 4, "{counts:?}");
    assert!(whole.cap(rs(22)).is_null());
    // D stays, detached, its Zombie in its own slot 0 and the endpoint copy
    // in its slot 1, until a revoke of the untyped reaches it.
    let d = UT + 128;
    assert_eq!(whole.cap(sa(d)).cap_type(), CapType::Zombie);
    assert_eq!(whole.cap(sa(d).offset(1)), whole.cap(rs(24)));

    // Between attempts the slot holds a Zombie, which cannot be invoked.
    let mut w = w.clone();
    w.k.preempt_in = Some(0);
    assert_eq!(
        w.call(rs(S_ROOT), DELETE, &at(r(22)), &[]),
        Err(InvokeError::Preempted)
    );
    assert_eq!(w.cap(rs(22)).cap_type(), CapType::Zombie);
    assert_eq!(
        w.call(rs(22), REVOKE, &at(r(20)), &[]),
        Err(InvokeError::Error(SyscallError::InvalidCapability(0)))
    );
    assert_eq!(
        w.run(0, rs(S_ROOT), DELETE, &at(r(22)), &[]).0,
        Ok(Reply::EMPTY)
    );
    assert!(w.k.mem == whole.k.mem);
}

// ---------------------------------------------------------------------
// Random messages.
//
// A random call is mostly built against the state it runs in, so that most
// calls do something: a destination is an empty slot, a source a full one,
// the invoked capability one of the label's type. Each argument can instead
// be raw: a word near a boundary, or a name with a wrong depth.

/// What an argument is for, which decides how a natural one is chosen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Role {
    /// The slot Revoke or Delete acts on: a full one.
    Target,
    /// A destination: an empty slot, sometimes a full one.
    Dest,
    /// A source or a pivot: a full slot.
    Source,
    /// `Untyped_Retype`'s destination CNode.
    Node,
    Type,
    SizeBits,
    Offset,
    Count,
    Rights,
    Data,
    Raw,
}

#[derive(Clone, Copy, Debug)]
enum Arg {
    /// Two registers, index and depth.
    Name(Role),
    Word(Role),
}

/// Where each method reads its arguments, as `docs/abi.md` lays them out.
fn layout(label: u64) -> &'static [Arg] {
    use Arg::{Name, Word};
    match label {
        RETYPE => &[
            Word(Role::Type),
            Word(Role::SizeBits),
            Name(Role::Node),
            Word(Role::Offset),
            Word(Role::Count),
        ],
        REVOKE | DELETE => &[Name(Role::Target)],
        COPY => &[Name(Role::Dest), Name(Role::Source), Word(Role::Rights)],
        MINT => &[
            Name(Role::Dest),
            Name(Role::Source),
            Word(Role::Rights),
            Word(Role::Data),
        ],
        MOVE => &[Name(Role::Dest), Name(Role::Source)],
        MUTATE => &[Name(Role::Dest), Name(Role::Source), Word(Role::Data)],
        ROTATE => &[
            Name(Role::Dest),
            Word(Role::Data),
            Name(Role::Source),
            Word(Role::Data),
            Name(Role::Source),
        ],
        _ => &[
            Word(Role::Raw),
            Word(Role::Raw),
            Word(Role::Raw),
            Word(Role::Raw),
            Name(Role::Raw),
            Word(Role::Raw),
        ],
    }
}

/// The extra capabilities each method takes.
fn extra_caps_taken(label: u64) -> usize {
    match label {
        REVOKE | DELETE => 0,
        ROTATE => 2,
        _ => 1,
    }
}

/// One random choice: natural (chosen by `k` from what fits its role
/// now) or raw.
#[derive(Clone, Copy, Debug)]
struct Atom {
    natural: bool,
    k: u64,
    raw: u64,
    depth: u64,
}

#[derive(Clone, Debug)]
struct RandomCall {
    label: u64,
    invoked: Atom,
    args: [Atom; 6],
    /// `None`: the extra capabilities the method takes, each natural.
    extra: Option<Vec<Atom>>,
    /// `None`: the method's length plus one register.
    len: Option<usize>,
    preempt: Option<u64>,
}

/// A slot a random call can name, its name, and what it holds.
#[derive(Clone, Copy)]
struct Named {
    slot: SlotAddr,
    name: (u64, u64),
    cap: Cap,
}

/// Every slot a random call names, the root's then L2's, read once per
/// call: each read of fake memory is slow under Miri.
fn snapshot(w: &World) -> Vec<Named> {
    let root = (0..1 << ROOT_RADIX).map(|i| (rs(i), r(i)));
    root.chain((0..1 << L2_RADIX).map(|j| (ls(j), l2(j))))
        .map(|(slot, name)| Named {
            slot,
            name,
            cap: w.cap(slot),
        })
        .collect()
}

/// The `k`-th of `all` whose capability passes `f`, if any.
fn kth(all: &[Named], k: u64, f: impl Fn(Cap) -> bool) -> Option<Named> {
    let v: Vec<&Named> = all.iter().filter(|n| f(n.cap)).collect();
    (!v.is_empty()).then(|| *v[(k % v.len() as u64) as usize])
}

/// As [`kth`], leaving the root's and L2's capabilities alone but one time
/// in 32, so that most names keep resolving.
fn kth_spared(all: &[Named], k: u64, f: impl Fn(Cap) -> bool) -> Option<Named> {
    let spared = [root_cap(), all[S_L2 as usize].cap];
    if k.is_multiple_of(32) {
        kth(all, k / 32, f)
    } else {
        kth(all, k, |c| f(c) && !spared.contains(&c))
    }
}

/// The `k`-th slot holding a CNode capability.
fn kth_cnode(all: &[Named], k: u64) -> Option<SlotAddr> {
    kth(all, k, |c| c.cap_type() == CapType::CNode).map(|n| n.slot)
}

/// A slot holding the root CNode's capability as boot made it, which the
/// names are relative to: slot 2 while it is there.
fn root_slot(all: &[Named]) -> SlotAddr {
    kth(all, 0, |c| c == root_cap()).map_or(rs(S_ROOT), |n| n.slot)
}

impl RandomCall {
    fn raw_name(a: &Atom) -> (u64, u64) {
        if a.raw.is_multiple_of(2) {
            (r(a.k % 64).0, a.depth)
        } else {
            (a.raw, a.depth)
        }
    }

    /// The name for `role`, and for a Node the CNode it names.
    fn name(all: &[Named], role: Role, a: &Atom) -> ((u64, u64), Option<Cap>) {
        if !a.natural {
            return (Self::raw_name(a), None);
        }
        let k = a.k;
        let full = |c: Cap| !c.is_null();
        let found = match role {
            Role::Target | Role::Source => kth_spared(all, k, full),
            Role::Dest if k.is_multiple_of(6) => kth_spared(all, k / 6, full),
            Role::Dest => kth(all, k, |c| c.is_null()),
            Role::Node => {
                return match k % 4 {
                    0 => (SELF, Some(root_cap())),
                    1 => (r(S_ROOT), Some(all[S_ROOT as usize].cap)),
                    2 => (r(S_L2), Some(all[S_L2 as usize].cap)),
                    _ => match kth(all, k / 4, |c| c.cap_type() == CapType::CNode) {
                        Some(n) => (n.name, Some(n.cap)),
                        None => (SELF, None),
                    },
                };
            }
            _ => None,
        };
        (found.map_or(Self::raw_name(a), |n| n.name), None)
    }

    /// The word for `role`. `ty` is the retype's type, `dest` its CNode.
    fn word(w: &World, role: Role, a: &Atom, ty: u64, dest: Option<Cap>) -> u64 {
        if !a.natural {
            return a.raw;
        }
        let k = a.k;
        match role {
            Role::Type => k % 11,
            Role::SizeBits if ty == ObjectType::Untyped as u64 => 4 + k % 9,
            Role::SizeBits if ty == ObjectType::CNode as u64 => 1 + k % 4,
            Role::Offset => match dest.filter(|c| c.cap_type() == CapType::CNode) {
                Some(c) => {
                    let empty: Vec<u64> = (0..1u64 << c.radix().min(6))
                        .filter(|&i| w.cap(sa(c.object()).offset(i)).is_null())
                        .collect();
                    if empty.is_empty() {
                        k
                    } else {
                        empty[(k % empty.len() as u64) as usize]
                    }
                }
                None => k % 8,
            },
            Role::Count => 1 + k % 3,
            Role::Rights => k % 16,
            Role::Data => match k % 4 {
                0 => 0,
                1 => k,
                2 => cnode_data((k % 7) as u32, k >> 3),
                _ => cnode_data(0, 0),
            },
            _ => k,
        }
    }

    /// The call against the state of `w`: the invoked slot, the message
    /// registers and the extra capabilities' slots. A restart reuses them.
    fn build(&self, w: &World) -> (SlotAddr, Vec<u64>, Vec<SlotAddr>) {
        let all = snapshot(w);
        let any = |a: &Atom| all[(a.raw % all.len() as u64) as usize].slot;
        let invoked = if !self.invoked.natural {
            any(&self.invoked)
        } else if self.label == RETYPE {
            kth(&all, self.invoked.k, |c| c.cap_type() == CapType::Untyped)
                .map_or(rs(S_UT), |n| n.slot)
        } else if self.invoked.k.is_multiple_of(6) {
            kth_cnode(&all, self.invoked.k / 6).unwrap_or(rs(S_ROOT))
        } else {
            root_slot(&all)
        };
        let mut mrs = Vec::new();
        let (mut ty, mut dest) = (0, None);
        for (arg, a) in layout(self.label).iter().zip(&self.args) {
            match *arg {
                Arg::Name(role) => {
                    let ((index, depth), node) = Self::name(&all, role, a);
                    mrs.extend([index, depth]);
                    dest = dest.or(node);
                }
                Arg::Word(role) => {
                    let v = Self::word(w, role, a, ty, dest);
                    if role == Role::Type {
                        ty = v;
                    }
                    mrs.push(v);
                }
            }
        }
        mrs.push(self.args[5].raw);
        if let Some(len) = self.len {
            mrs.truncate(len);
        }
        let extra = match &self.extra {
            Some(v) => v.iter().map(any).collect(),
            None => self
                .args
                .iter()
                .take(extra_caps_taken(self.label))
                .map(|a| match a.k % 6 {
                    0 => kth_cnode(&all, a.k / 6).unwrap_or(rs(S_ROOT)),
                    _ => root_slot(&all),
                })
                .collect(),
        };
        (invoked, mrs, extra)
    }
}

fn atom() -> impl Strategy<Value = Atom> {
    let raw = prop_oneof![
        4 => 0u64..70,
        1 => prop::sample::select(vec![127, 255, 256, 257, 4095, 4096, 1 << 32, u64::MAX - 1, u64::MAX]),
        1 => any::<u64>(),
    ];
    let depth = prop::sample::select(vec![0u64, 1, 6, 7, 8, 9, 13, 14, 15, 63, 64, 65, u64::MAX]);
    (prop::bool::weighted(0.85), 0u64..256, raw, depth).prop_map(|(natural, k, raw, depth)| Atom {
        natural,
        k,
        raw,
        depth,
    })
}

fn random_call() -> impl Strategy<Value = RandomCall> {
    let label = prop_oneof![
        10 => prop::sample::select(vec![RETYPE, REVOKE, DELETE, COPY, MINT, MOVE, MUTATE, ROTATE]),
        1 => 0u64..0x30,
        1 => any::<u64>(),
    ];
    (
        label,
        atom(),
        [atom(), atom(), atom(), atom(), atom(), atom()],
        prop_oneof![8 => Just(None), 1 => prop::collection::vec(atom(), 0..=3).prop_map(Some)],
        prop_oneof![12 => Just(None), 1 => (0usize..9).prop_map(Some)],
        prop_oneof![3 => Just(None), 1 => (0u64..4).prop_map(Some)],
    )
        .prop_map(|(label, invoked, args, extra, len, preempt)| RandomCall {
            label,
            invoked,
            args,
            extra,
            len,
            preempt,
        })
}

/// Runs a random call as the kernel would, restarting it from the same
/// arguments while it is preempted. Every slot stays consistent after every
/// attempt, and an attempt that returns an error changes nothing (under
/// Miri, both are checked once the call ends). Returns the result.
fn run_random(w: &mut World, c: &RandomCall) -> Result<Reply, SyscallError> {
    let (invoked, mrs, extra) = c.build(w);
    w.k.events.clear();
    for _ in 0..100_000 {
        let before = (!cfg!(miri)).then(|| w.clone());
        w.k.preempt_in = c.preempt;
        let r = w.call(invoked, c.label, &mrs, &extra);
        w.k.preempt_in = None;
        w.check_step();
        let r = match r {
            Ok(reply) => {
                assert_eq!(reply, Reply::EMPTY);
                Ok(reply)
            }
            Err(InvokeError::Error(e)) => {
                if let Some(before) = before {
                    assert!(w.k.mem == before.k.mem, "{e:?} changed memory");
                    assert_eq!(w.k.events, before.k.events, "{e:?} called a hook");
                }
                Err(e)
            }
            Err(InvokeError::Preempted) => continue,
        };
        if cfg!(miri) {
            w.check();
        }
        return r;
    }
    panic!("a restarted call made no progress");
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

fn calls() -> impl Strategy<Value = Vec<RandomCall>> {
    prop::collection::vec(random_call(), 1..if cfg!(miri) { 10 } else { 80 })
}

/// The world a random sequence starts from: the boot CSpace, two
/// endpoints, a CNode, and an untyped in L2.
fn random_start() -> World {
    let mut w = World::new();
    w.make(S_UT, ObjectType::Endpoint, 0, SELF, 20, 2);
    w.make(S_UT, ObjectType::CNode, 1, SELF, 22, 1);
    w.make(S_UT, ObjectType::Untyped, 10, r(S_L2), 0, 1);
    w
}

/// After a revoke of the boot untyped, no slot the CSpace reaches, but the
/// boot untyped's own, holds a capability to memory inside it.
fn assert_nothing_names_the_untyped(w: &World) {
    let mut todo = vec![(ROOT, 1u64 << ROOT_RADIX), (L2, 1 << L2_RADIX)];
    let mut seen = BTreeSet::new();
    while let Some((base, n)) = todo.pop() {
        if !seen.insert(base) {
            continue;
        }
        for i in 0..n {
            let s = sa(base + i * SLOT_SIZE);
            let c = w.cap(s);
            let names_memory = !matches!(
                c.cap_type(),
                CapType::Null
                    | CapType::IrqControl
                    | CapType::IrqHandler
                    | CapType::IoPortControl
                    | CapType::IoPort
                    | CapType::Hypervisor
            );
            if s != rs(S_UT) && names_memory {
                assert!(
                    !(UT..UT + (1 << UT_BITS)).contains(&c.object()),
                    "slot {:#x} still holds {c:?}",
                    s.get()
                );
            }
            if let Some(cn) = container(c) {
                todo.push(cn);
            }
        }
    }
}

proptest! {
    #![proptest_config(config())]

    /// Random messages never panic and keep every slot consistent; a
    /// revoke of the boot untyped then removes every capability to its
    /// memory from the slots the CSpace reaches.
    #[test]
    fn random_messages_keep_every_slot_consistent(calls in calls()) {
        let mut w = random_start();
        for c in &calls {
            let _ = run_random(&mut w, c);
        }
        let ut = w.cap(rs(S_UT));
        if ut.cap_type() == CapType::Untyped && ut.object() == UT && w.node(rs(S_UT)).depth() == 0 {
            crate::cnode::revoke(&mut w.k, rs(S_UT)).unwrap();
            w.check();
            prop_assert!(!cdt::has_children(&w.k, rs(S_UT)));
            assert_nothing_names_the_untyped(&w);
        }
    }
}

/// Many random calls do something: at least a quarter succeed, and each
/// method succeeds in some, so the random test reaches past the argument
/// checks. (About 29% succeed; the rest spread over every error.)
#[test]
#[cfg_attr(miri, ignore = "a statistic over many random calls")]
fn random_messages_mostly_succeed() {
    let mut runner = proptest::test_runner::TestRunner::deterministic();
    let (mut total, mut succeeded) = (0u32, 0u32);
    let mut by_label = std::collections::BTreeMap::new();
    for _ in 0..64 {
        let calls = calls().new_tree(&mut runner).unwrap().current();
        let mut w = random_start();
        for c in &calls {
            total += 1;
            if run_random(&mut w, c).is_ok() {
                succeeded += 1;
                *by_label.entry(c.label).or_insert(0u32) += 1;
            }
        }
    }
    assert!(4 * succeeded >= total, "{succeeded} of {total}");
    for label in [RETYPE, REVOKE, DELETE, COPY, MINT, MOVE, MUTATE, ROTATE] {
        assert!(
            by_label.get(&label).copied().unwrap_or(0) >= 20,
            "{label:#x}: {by_label:?}"
        );
    }
}
