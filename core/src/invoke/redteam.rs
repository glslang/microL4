//! M4 red team: attacks on the invocation decoder and the capability core
//! behind it, as a ring-3 root task would make them from M5 on. The M4 pass
//! found no way to break a guarantee, so these are regression tests.
//!
//! The world is a boot-like CSpace over fake memory, and every call goes
//! through [`invoke`]. After every attempt, preempted or not, [`World::audit`]
//! scans every 32-byte slot of fake memory, not only the slots a CSpace
//! reaches, and checks the guarantees `docs/design.md` states:
//!
//! - every slot keeps the derivation-list invariants, and `is_final` agrees
//!   with a scan for other capabilities to the same object;
//! - capabilities to different objects never overlap;
//! - RAM at or above a RAM untyped's watermark is zero;
//! - every object and smaller untyped inside a live untyped is its
//!   descendant, and an untyped with no children has nothing live in its
//!   region, so its next retype may reset it;
//! - no capability carries a right its type never has;
//! - a reset never zeroes memory a live object occupied when the attempt
//!   began, and an attempt that fails changes no memory.
//!
//! Planting a bug in `retype`'s children check, in `derive`'s untyped check
//! or in the rights mask makes the random tests fail within a few hundred
//! calls. `REDTEAM_SEEDS` runs more sequences than the default 40.

use std::collections::BTreeSet;
use std::format;
use std::string::String;
use std::vec;
use std::vec::Vec;

use super::*;
use crate::cap::{MAX_DERIVATION_DEPTH, ObjectType, Rights, SLOT_SIZE, cnode_data};
use crate::cdt;
use crate::testing::{Event, TestKernel};

const BASE: u64 = 0x1_0000;
/// A 32 KiB RAM untyped.
const UT: u64 = 0x1_0000;
const UT_BITS: u32 = 15;
/// A 4 KiB RAM untyped.
const UT2: u64 = 0x1_8000;
const UT2_BITS: u32 = 12;
const ROOT: u64 = 0x1_A000;
const ROOT_RADIX: u32 = 6;
const ROOT_GUARD: u64 = 0b01;
const L2: u64 = 0x1_A800;
const L2_RADIX: u32 = 3;
const L2_GUARD: u64 = 0b101;
/// A 4 KiB device untyped.
const DEV: u64 = 0x1_B000;
const DEV_BITS: u32 = 12;
const MEM_END: u64 = 0x1_C000;

const S_ROOT: u64 = 2;
const S_L2: u64 = 3;
const S_UT: u64 = 16;
const S_UT2: u64 = 17;
const S_DEV: u64 = 18;

const RETYPE: u64 = label::UNTYPED_RETYPE;
const REVOKE: u64 = label::CNODE_REVOKE;
const DELETE: u64 = label::CNODE_DELETE;
const COPY: u64 = label::CNODE_COPY;
const MINT: u64 = label::CNODE_MINT;
const MOVE: u64 = label::CNODE_MOVE;
const MUTATE: u64 = label::CNODE_MUTATE;
const ROTATE: u64 = label::CNODE_ROTATE;

/// Words near every boundary a register has.
const BOUNDARY: [u64; 18] = [
    0,
    1,
    2,
    4,
    42,
    47,
    63,
    64,
    65,
    255,
    256,
    257,
    4095,
    1 << 32,
    1 << 63,
    (1 << 63) + 1,
    u64::MAX - 1,
    u64::MAX,
];

fn sa(a: u64) -> SlotAddr {
    SlotAddr::new(a).unwrap()
}

fn rs(i: u64) -> SlotAddr {
    sa(ROOT + i * SLOT_SIZE)
}

/// The name of root slot `i`.
fn r(i: u64) -> (u64, u64) {
    ((ROOT_GUARD << ROOT_RADIX) | i, 8)
}

/// The name of slot `j` of the CNode `cap` whose capability is in the slot
/// named `at`, through `cap`'s guard; `None` if it needs over 64 bits.
fn through(at: (u64, u64), cap: Cap, j: u64) -> Option<(u64, u64)> {
    let bits = at.1 + u64::from(cap.guard_size()) + u64::from(cap.radix());
    if bits > 64 {
        return None;
    }
    let index = (at.0 << cap.guard_size() | cap.guard()) << cap.radix() | j;
    // Shifts past 64 bits drop the high bits, which the lookup ignores.
    let index = if bits == 64 {
        index
    } else {
        index & ((1 << bits) - 1)
    };
    Some((index, bits))
}

fn root_cap() -> Cap {
    Cap::cnode(ROOT, ROOT_RADIX, 2, ROOT_GUARD)
}

fn l2_cap() -> Cap {
    Cap::cnode(L2, L2_RADIX, 3, L2_GUARD)
}

/// The memory a capability names as an object, if any: Reply capabilities
/// name a TCB from inside it, and Untyped are checked separately.
fn object_range(c: Cap) -> Option<(u64, u64)> {
    match c.cap_type() {
        CapType::Null
        | CapType::Untyped
        | CapType::Reply
        | CapType::IrqControl
        | CapType::IrqHandler
        | CapType::IoPortControl
        | CapType::IoPort
        | CapType::Hypervisor => None,
        _ => Some((c.object(), c.object() + (1u64 << c.size_bits()))),
    }
}

fn overlap(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.1 && b.0 < a.1
}

/// The rights each type may carry at most.
fn max_rights(t: CapType) -> Rights {
    match t {
        CapType::Endpoint => Rights::ALL,
        CapType::Notification | CapType::Frame => Rights(Rights::READ.0 | Rights::WRITE.0),
        CapType::Reply => Rights::GRANT,
        _ => Rights::NONE,
    }
}

#[derive(Clone)]
struct World {
    k: TestKernel,
}

impl World {
    fn new() -> World {
        let mut k = TestKernel::new(BASE, MEM_END - BASE);
        cdt::insert_root(&mut k, rs(S_ROOT), root_cap());
        cdt::insert_root(&mut k, rs(S_L2), l2_cap());
        cdt::insert_root(
            &mut k,
            rs(S_UT),
            Cap::untyped(UT, UT_BITS, false, 1 << UT_BITS),
        );
        cdt::insert_root(
            &mut k,
            rs(S_UT2),
            Cap::untyped(UT2, UT2_BITS, false, 1 << UT2_BITS),
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

    /// A call through the root CNode's capability in its slot 2, with that
    /// capability as every extra capability.
    fn root_call(&mut self, label: u64, mrs: &[u64]) -> Result<Reply, InvokeError> {
        self.call(rs(S_ROOT), label, mrs, &[rs(S_ROOT), rs(S_ROOT)])
    }

    /// Every slot of fake memory holding a capability.
    fn full_slots(&self) -> Vec<(SlotAddr, Cap)> {
        (BASE..MEM_END)
            .step_by(SLOT_SIZE as usize)
            .map(sa)
            .map(|s| (s, self.cap(s)))
            .filter(|(_, c)| !c.is_null())
            .collect()
    }

    /// The live objects: each memory range some capability names.
    fn objects(&self) -> Vec<(u64, u64)> {
        self.full_slots()
            .into_iter()
            .filter_map(|(_, c)| object_range(c))
            .collect()
    }

    /// The descendants of the capability in `s`.
    fn run_of(&self, s: SlotAddr) -> BTreeSet<SlotAddr> {
        let depth = self.k.load(s).node.depth();
        let mut out = BTreeSet::new();
        let mut at = self.k.load(s).node.next();
        while let Some(n) = at {
            let node = self.k.load(n).node;
            if node.low() <= depth || !out.insert(n) {
                break;
            }
            at = node.next();
        }
        out
    }

    /// Checks every guarantee in the module comment but the last; returns
    /// the first broken one.
    fn audit(&self) -> Result<(), String> {
        for s in (BASE..MEM_END).step_by(SLOT_SIZE as usize).map(sa) {
            cdt::check_slot(&self.k, s).map_err(|e| format!("slot {:#x}: {e}", s.get()))?;
        }
        let full = self.full_slots();
        for (i, &(s, c)) in full.iter().enumerate() {
            let n = self.k.load(s).node;
            if n.depth() > MAX_DERIVATION_DEPTH {
                return Err(format!("slot {:#x} deeper than the limit", s.get()));
            }
            if !max_rights(c.cap_type()).contains(c.rights()) {
                return Err(format!(
                    "slot {:#x}: {c:?} has rights it never has",
                    s.get()
                ));
            }
            let others = full
                .iter()
                .enumerate()
                .any(|(j, (_, d))| j != i && d.same_object(&c));
            if cdt::is_final(&self.k, s) == others {
                return Err(format!(
                    "slot {:#x}: is_final {} but another capability to {c:?} exists: {others}",
                    s.get(),
                    !others
                ));
            }
            if let Some(a) = object_range(c) {
                for &(t, d) in &full[i + 1..] {
                    if let Some(b) = object_range(d)
                        && overlap(a, b)
                        && !d.same_object(&c)
                    {
                        return Err(format!(
                            "{c:?} in {:#x} overlaps {d:?} in {:#x}",
                            s.get(),
                            t.get()
                        ));
                    }
                }
            }
            if c.cap_type() == CapType::Untyped {
                let region = (c.object(), c.object() + (1u64 << c.size_bits()));
                if c.watermark() > region.1 - region.0 {
                    return Err(format!("{c:?} in {:#x}: watermark past its end", s.get()));
                }
                // Regions outside fake memory are never touched.
                if !c.is_device() && BASE <= region.0 && region.1 <= MEM_END {
                    let w = region.0 + c.watermark();
                    if !self.k.mem.is_zero(w, region.1 - w) {
                        return Err(format!(
                            "{c:?} in {:#x}: RAM above the watermark is not zero",
                            s.get()
                        ));
                    }
                }
                // Every object inside it, and every smaller untyped, is its
                // descendant: in the run of slots after it whose `low`
                // exceeds its depth.
                let run = self.run_of(s);
                for &(t, d) in &full {
                    let b = match d.cap_type() {
                        CapType::Untyped => {
                            let b = (d.object(), d.object() + (1u64 << d.size_bits()));
                            (b.1 - b.0 < region.1 - region.0).then_some(b)
                        }
                        _ => object_range(d),
                    };
                    if let Some(b) = b
                        && overlap(region, b)
                        && !run.contains(&t)
                    {
                        return Err(format!(
                            "{d:?} in {:#x} lives in {c:?} in {:#x} but is not its descendant",
                            t.get(),
                            s.get()
                        ));
                    }
                }
                if !cdt::has_children(&self.k, s) {
                    for &(t, d) in &full {
                        let inside = match d.cap_type() {
                            // Another untyped inside it, or across its edge;
                            // its parents and copies cover all of it.
                            CapType::Untyped => {
                                let b = (d.object(), d.object() + (1u64 << d.size_bits()));
                                overlap(region, b) && !(b.0 <= region.0 && region.1 <= b.1)
                            }
                            _ => object_range(d).is_some_and(|b| overlap(region, b)),
                        };
                        if inside {
                            return Err(format!(
                                "{c:?} in {:#x} has no children, but {d:?} in {:#x} lives in it",
                                s.get(),
                                t.get()
                            ));
                        }
                    }
                }
            }
        }
        Ok(())
    }

    /// One attempt, audited, with the zeroing it did checked against the
    /// objects live before it.
    fn attempt(
        &mut self,
        invoked: SlotAddr,
        label: u64,
        mrs: &[u64],
        extra: &[SlotAddr],
        preempt: Option<u64>,
    ) -> Result<Reply, InvokeError> {
        let live = self.objects();
        let before = self.k.mem.clone();
        self.k.events.clear();
        self.k.preempt_in = preempt;
        let r = self.call(invoked, label, mrs, extra);
        self.k.preempt_in = None;
        for e in &self.k.events {
            if let Event::Zero { paddr, len } = *e
                && let Some(o) = live.iter().find(|o| overlap(**o, (paddr, paddr + len)))
            {
                panic!("a reset zeroed {paddr:#x}+{len:#x}, inside the live object {o:x?}");
            }
        }
        if let Err(InvokeError::Error(e)) = r {
            assert!(self.k.mem == before, "{e:?} changed memory");
        }
        if let Err(e) = self.audit() {
            panic!("after {label:#x} {mrs:x?}: {e}");
        }
        r
    }
}

/// `Untyped_Retype` registers.
fn rt(ty: ObjectType, size_bits: u64, node: (u64, u64), offset: u64, n: u64) -> Vec<u64> {
    vec![ty as u64, size_bits, node.0, node.1, offset, n]
}

const SELF: (u64, u64) = (0, 0);

/// Retypes from the untyped in root slot `ut` into the root CNode; must
/// succeed.
fn make(w: &mut World, ut: u64, ty: ObjectType, size_bits: u64, offset: u64, n: u64) {
    let mrs = rt(ty, size_bits, SELF, offset, n);
    assert_eq!(
        w.attempt(rs(ut), RETYPE, &mrs, &[rs(S_ROOT)], None),
        Ok(Reply::EMPTY),
        "retype {ty:?} into {offset}"
    );
}

/// Runs a call to completion, restarting it while it is preempted at its
/// `every`-th point; returns the result and the restarts.
fn run(
    w: &mut World,
    every: u64,
    invoked: SlotAddr,
    label: u64,
    mrs: &[u64],
    extra: &[SlotAddr],
) -> (Result<Reply, InvokeError>, u32) {
    let mut n = 0;
    loop {
        match w.attempt(invoked, label, mrs, extra, Some(every)) {
            Err(InvokeError::Preempted) => n += 1,
            r => return (r, n),
        }
        assert!(n < 100_000, "no progress");
    }
}

// ---------------------------------------------------------------------
// Targeted attacks.

/// Every register of `Untyped_Retype` at every boundary word, alone and
/// with `node_offset + num_objects` at and past the destination's end.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn retype_registers_at_every_boundary() {
    let mut start = World::new();
    make(&mut start, S_UT, ObjectType::CNode, 4, 20, 1);
    let base = [
        rt(ObjectType::Endpoint, 0, SELF, 30, 2),
        rt(ObjectType::Untyped, 4, SELF, 30, 1),
        rt(ObjectType::CNode, 1, r(20), 15, 1),
        rt(ObjectType::Frame4K, 0, r(20), 14, 2),
    ];
    for mrs in &base {
        for reg in 0..mrs.len() {
            for &v in BOUNDARY.iter().chain(&[3, 5, 11, 14, 15, 16, 17, 48]) {
                for ut in [S_UT, S_UT2, S_DEV] {
                    let mut w = start.clone();
                    let mut m = mrs.clone();
                    m[reg] = v;
                    let _ = w.attempt(rs(ut), RETYPE, &m, &[rs(S_ROOT)], None);
                }
            }
        }
    }
    // The end of a 16-slot CNode: offsets 0 to 15, counts up to the end.
    for offset in [0u64, 1, 14, 15, 16, 1 << 63, u64::MAX] {
        for n in [1u64, 2, 15, 16, 17, 256, 257, u64::MAX - offset, u64::MAX] {
            let mut w = start.clone();
            let mrs = rt(ObjectType::Untyped, 4, r(20), offset, n);
            let res = w.attempt(rs(S_UT2), RETYPE, &mrs, &[rs(S_ROOT)], None);
            let fits = offset < 16 && n >= 1 && n <= 16 - offset;
            assert_eq!(res.is_ok(), fits, "offset {offset} count {n}: {res:?}");
        }
    }
    // The largest sizes: 256 untyped of 2^47 bytes, 256 CNodes of radix 42.
    let mut w = start.clone();
    for (ty, bits) in [(ObjectType::Untyped, 47), (ObjectType::CNode, 42)] {
        let mrs = rt(ty, bits, SELF, 30, 34);
        let res = w.attempt(rs(S_UT), RETYPE, &mrs, &[rs(S_ROOT)], None);
        assert!(matches!(
            res,
            Err(InvokeError::Error(SyscallError::NotEnoughMemory(_)))
        ));
        let mrs = rt(ty, bits, r(20), 0, 16);
        let res = w.attempt(rs(S_UT), RETYPE, &mrs, &[rs(S_ROOT)], None);
        assert!(matches!(
            res,
            Err(InvokeError::Error(SyscallError::NotEnoughMemory(_)))
        ));
    }
}

/// A 2^47 untyped at the top of the 52-bit physical address space, filled
/// exactly by 256 untyped of 2^39, the last of which ends at 2^52; then
/// alignment from a 16-byte object up to 2^38 in that last one. The region
/// lies outside fake memory: nothing here touches it.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn the_largest_untyped_at_the_top_of_physical_memory() {
    const TOP: u64 = (1 << 52) - (1 << 47);
    let mut w = World::new();
    make(&mut w, S_UT, ObjectType::CNode, 8, 20, 1);
    make(&mut w, S_UT, ObjectType::CNode, 8, 21, 1);
    // Watermark 0, as a new untyped starts: no reset touches the region.
    cdt::insert_root(&mut w.k, rs(40), Cap::untyped(TOP, 47, false, 0));
    let big = rt(ObjectType::Untyped, 39, r(20), 0, 256);
    assert_eq!(
        w.attempt(rs(40), RETYPE, &big, &[rs(S_ROOT)], None),
        Ok(Reply::EMPTY)
    );
    assert_eq!(w.cap(rs(40)).watermark(), 1 << 47);
    let c20 = w.cap(rs(20));
    let last = sa(c20.object() + 255 * SLOT_SIZE);
    assert_eq!(w.cap(last).object() + (1 << 39), 1 << 52);
    let one_more = rt(ObjectType::Untyped, 4, SELF, 50, 1);
    assert_eq!(
        w.attempt(rs(40), RETYPE, &one_more, &[rs(S_ROOT)], None),
        Err(SyscallError::NotEnoughMemory(0).into())
    );
    // Move the last one out, then 16 bytes, then 2^38 aligned up to 2^38,
    // which ends at 2^52 too, then nothing fits.
    w.root_call(MOVE, &[r(41).0, 8, (r(20).0 << 8) | 255, 16])
        .unwrap();
    for (bits, slot) in [(4u64, 42u64), (38, 43)] {
        let mrs = rt(ObjectType::Untyped, bits, SELF, slot, 1);
        assert_eq!(
            w.attempt(rs(41), RETYPE, &mrs, &[rs(S_ROOT)], None),
            Ok(Reply::EMPTY)
        );
    }
    assert_eq!(w.cap(rs(43)).object(), (1 << 52) - (1 << 38));
    assert_eq!(w.cap(rs(41)).watermark(), 1 << 39);
    let mrs = rt(ObjectType::Untyped, 4, SELF, 44, 1);
    assert_eq!(
        w.attempt(rs(41), RETYPE, &mrs, &[rs(S_ROOT)], None),
        Err(SyscallError::NotEnoughMemory(0).into())
    );
    // 256 CNodes of radix 25 fill the 2^38 untyped exactly, the last ending
    // at 2^52; then not even the smallest CNode fits.
    let cn = rt(ObjectType::CNode, 25, r(21), 0, 256);
    assert_eq!(
        w.attempt(rs(43), RETYPE, &cn, &[rs(S_ROOT)], None),
        Ok(Reply::EMPTY)
    );
    assert_eq!(w.cap(rs(43)).watermark(), 1 << 38);
    let c21 = w.cap(rs(21));
    let top = w.cap(sa(c21.object() + 255 * SLOT_SIZE));
    assert_eq!(
        (top.object() + (1 << top.size_bits()), top.radix()),
        (1 << 52, 25)
    );
    let cn = rt(ObjectType::CNode, 1, SELF, 45, 1);
    assert_eq!(
        w.attempt(rs(43), RETYPE, &cn, &[rs(S_ROOT)], None),
        Err(SyscallError::NotEnoughMemory(0).into())
    );
}

/// Guards whose size plus the radix is exactly 64, and one bit more; a
/// lookup of 64 bits through them, and `CPtr` bits above the depth.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn guards_filling_all_64_bits() {
    let mut w = World::new();
    make(&mut w, S_UT, ObjectType::CNode, 2, 20, 1);
    make(&mut w, S_UT, ObjectType::Endpoint, 0, 21, 1);
    // Guard size 54 under the root's 8 bits: 8 + 54 + 2 = 64.
    let guard = 0x2A_AAAA_AAAA_AAAA & ((1 << 54) - 1);
    assert_eq!(
        w.root_call(MUTATE, &[r(22).0, 8, r(20).0, 8, cnode_data(54, guard)]),
        Ok(Reply::EMPTY)
    );
    let c = w.cap(rs(22));
    assert_eq!((c.guard_size(), c.guard()), (54, guard));
    let slot3 = through(r(22), c, 3).unwrap();
    assert_eq!(slot3.1, 64);
    assert_eq!(
        w.root_call(COPY, &[slot3.0, slot3.1, r(21).0, 8, 0xF]),
        Ok(Reply::EMPTY)
    );
    // Bits above the depth are ignored: the same slot named with garbage.
    for junk in [1u64 << 63, u64::MAX << 9] {
        let r8 = (r(21).0 | junk, 8);
        assert_eq!(
            w.root_call(COPY, &[slot3.0 ^ 1, 64, r8.0, r8.1, 0xF]),
            Ok(Reply::EMPTY)
        );
        w.root_call(DELETE, &[slot3.0 ^ 1, 64]).unwrap();
    }
    // Guard size 62 on a radix-2 CNode: the CNode alone resolves 64 bits.
    for g in [62u64, 63] {
        let res = w.root_call(MUTATE, &[r(23).0, 8, r(22).0, 8, g | (u64::MAX << 6)]);
        if g + 2 > 64 {
            assert_eq!(res, Err(SyscallError::IllegalOperation.into()));
        } else {
            assert_eq!(res, Ok(Reply::EMPTY));
            let c = w.cap(rs(23));
            // A guard over 58 bits keeps only the stored 58.
            assert_eq!(c.guard(), u64::MAX >> 6);
            let root = [rs(23)];
            let full = (c.guard() << 2) | 3;
            assert_eq!(w.call(rs(23), DELETE, &[full, 64], &root), Ok(Reply::EMPTY));
            assert!(w.cap(sa(c.object() + 3 * SLOT_SIZE)).is_null());
            // Depth 63 cannot hold guard and radix.
            assert!(w.call(rs(23), DELETE, &[full, 63], &root).is_err());
            w.root_call(MOVE, &[r(22).0, 8, r(23).0, 8]).unwrap();
        }
    }
}

/// A CNode whose slot 0 holds its own capability: lookups 64 levels deep,
/// and Delete, Revoke and Rotate of the capabilities that name it.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn a_cnode_that_names_itself() {
    for every in 0..12 {
        let mut w = World::new();
        make(&mut w, S_UT, ObjectType::CNode, 1, 20, 1);
        let c = w.cap(rs(20));
        // A copy into its own slot 0, then 56 levels of self-lookup reach
        // slot 1.
        let s0 = through(r(20), c, 0).unwrap();
        assert_eq!(
            w.root_call(COPY, &[s0.0, s0.1, r(20).0, 8, 0]),
            Ok(Reply::EMPTY)
        );
        let deep = (r(20).0 << 56) | 1;
        assert_eq!(
            w.root_call(COPY, &[deep, 64, r(S_UT2).0, 8, 0]),
            Ok(Reply::EMPTY)
        );
        assert_eq!(
            w.cap(sa(c.object() + SLOT_SIZE)).cap_type(),
            CapType::Untyped
        );
        // Rotate the self-copy with the untyped copy and back, as a swap.
        let s1 = through(r(20), c, 1).unwrap();
        let rot = [s1.0, s1.1, 0, s0.0, s0.1, 0, s1.0, s1.1];
        assert_eq!(w.root_call(ROTATE, &rot), Ok(Reply::EMPTY));
        assert_eq!(w.root_call(ROTATE, &rot), Ok(Reply::EMPTY));
        // Delete the outer capability: the inner one is the last.
        let _ = run(&mut w, every, rs(S_ROOT), DELETE, &[r(20).0, 8], &[]);
        // Revoke the untyped: the CNode goes, with the copy inside it.
        let (res, _) = run(&mut w, every, rs(S_ROOT), REVOKE, &[r(S_UT).0, 8], &[]);
        assert_eq!(res, Ok(Reply::EMPTY));
        assert!(!cdt::has_children(&w.k, rs(S_UT)));
        assert!(!cdt::has_children(&w.k, rs(S_UT2)));
    }
}

/// Rotate with every aliasing of its three slots, between list neighbours
/// and not.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn rotate_with_aliased_slots() {
    let mut start = World::new();
    make(&mut start, S_UT, ObjectType::Endpoint, 0, 20, 1);
    make(&mut start, S_UT, ObjectType::CNode, 1, 21, 1);
    // 22 is 21's child, list neighbours; 23 an untyped, a root.
    start.root_call(COPY, &[r(22).0, 8, r(21).0, 8, 0]).unwrap();
    let full = [20u64, 21, 22, S_UT2, 30];
    for &d in &full {
        for &p in &full {
            for &s in &full {
                for data in [0, cnode_data(3, 5), cnode_data(63, 1), u64::MAX] {
                    let mut w = start.clone();
                    let mrs = [r(d).0, 8, data, r(p).0, 8, data, r(s).0, 8];
                    let _ = w.root_call(ROTATE, &mrs);
                    w.audit().unwrap();
                    // And back, if it moved anything.
                    let _ = w.root_call(ROTATE, &mrs);
                }
            }
        }
    }
}

/// Zombies at every count: Delete, Revoke, Move, Mutate, Rotate and Copy of
/// them, then a revoke of the untyped clears everything.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn revoke_and_delete_on_zombies() {
    for stop in 0..6 {
        for op in 0..6 {
            let mut w = World::new();
            make(&mut w, S_UT, ObjectType::CNode, 2, 20, 1);
            make(&mut w, S_UT, ObjectType::Endpoint, 0, 21, 1);
            make(&mut w, S_UT, ObjectType::Tcb, 0, 25, 1);
            let c = w.cap(rs(20));
            for j in 0..4 {
                let s = through(r(20), c, j).unwrap();
                w.root_call(COPY, &[s.0, s.1, r(21).0, 8, 0xF]).unwrap();
            }
            // A preempted Delete of the CNode's and the TCB's last
            // capabilities leaves Zombies.
            for slot in [20u64, 25] {
                let r0 = w.attempt(rs(S_ROOT), DELETE, &[r(slot).0, 8], &[], Some(stop));
                if r0 == Err(InvokeError::Preempted) {
                    assert_eq!(w.cap(rs(slot)).cap_type(), CapType::Zombie);
                }
            }
            for slot in [20u64, 25] {
                let mrs: Vec<u64> = match op {
                    0 => vec![r(slot).0, 8],
                    1 => vec![r(slot).0, 8],
                    2 => vec![r(40).0, 8, r(slot).0, 8],
                    3 => vec![r(40).0, 8, r(slot).0, 8, u64::MAX],
                    4 => vec![r(slot).0, 8, 0, r(S_DEV).0, 8, 0, r(slot).0, 8],
                    _ => vec![r(42).0, 8, r(slot).0, 8, 0xF],
                };
                let label = [DELETE, REVOKE, MOVE, MUTATE, ROTATE, COPY][op];
                let _ = run(
                    &mut w,
                    stop,
                    rs(S_ROOT),
                    label,
                    &mrs,
                    &[rs(S_ROOT), rs(S_ROOT)],
                );
                // Delete what is left, wherever it went.
                for t in [slot, 40, 41] {
                    let _ = run(&mut w, stop, rs(S_ROOT), DELETE, &[r(t).0, 8], &[]);
                }
            }
            let (res, _) = run(&mut w, stop, rs(S_ROOT), REVOKE, &[r(S_UT).0, 8], &[]);
            assert_eq!(res, Ok(Reply::EMPTY));
            assert!(!cdt::has_children(&w.k, rs(S_UT)));
            // The whole region can be retyped again.
            make(&mut w, S_UT, ObjectType::Untyped, u64::from(UT_BITS), 50, 1);
        }
    }
}

/// An untyped with children moved, then moved into a CNode it made, then
/// revoked from there and preempted at every point; and a retype whose
/// reset is preempted, followed by other calls on the half-reset untyped.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn moved_untyped_and_interrupted_resets() {
    for every in 0..10 {
        let mut w = World::new();
        make(&mut w, S_UT, ObjectType::Untyped, 14, 20, 1);
        // Dirty the sub-untyped, then free it: its next retype resets it in
        // four chunks.
        let fill = rt(ObjectType::Frame4K, 0, SELF, 30, 4);
        assert_eq!(
            w.attempt(rs(20), RETYPE, &fill, &[rs(S_ROOT)], None),
            Ok(Reply::EMPTY)
        );
        for i in 30..34 {
            w.root_call(DELETE, &[r(i).0, 8]).unwrap();
        }
        make(&mut w, S_UT, ObjectType::CNode, 2, 21, 1);
        let c = w.cap(rs(21));
        // Move the boot untyped, which has children, into the CNode it made.
        let inner = through(r(21), c, 1).unwrap();
        w.root_call(MOVE, &[inner.0, inner.1, r(S_UT).0, 8])
            .unwrap();
        // A reset of the sub-untyped preempted at `every`, then a copy of it
        // and a retype of the copy.
        let ep = rt(ObjectType::Endpoint, 0, SELF, 31, 1);
        let r1 = w.attempt(rs(20), RETYPE, &ep, &[rs(S_ROOT)], Some(every));
        if r1 == Err(InvokeError::Preempted) {
            w.root_call(COPY, &[r(34).0, 8, r(20).0, 8, 0]).unwrap();
            let r2 = rt(ObjectType::Tcb, 0, SELF, 35, 1);
            let _ = run(&mut w, every, rs(34), RETYPE, &r2, &[rs(S_ROOT)]);
            let _ = run(&mut w, every, rs(20), RETYPE, &ep, &[rs(S_ROOT)]);
        }
        // Revoke the boot untyped through the CNode it made: a partial
        // revoke, which deletes the boot untyped's capability with the CNode
        // and leaves the sub-untyped's subtree without a parent.
        let _ = run(&mut w, every, rs(S_ROOT), REVOKE, &[inner.0, inner.1], &[]);
        // Everything left can still be deleted.
        for i in [20u64, 21, 34, 35, 31] {
            let _ = run(&mut w, every, rs(S_ROOT), DELETE, &[r(i).0, 8], &[]);
        }
    }
}

/// A revoke of the boot untyped stopped at each of its preemption points,
/// then a different call instead of the restart: a copy, a retype, a move
/// or a delete of the untyped, a revoke or delete of what it still covers,
/// or the revoke named through another slot. Each is audited; then the
/// revoke runs to the end and the whole region retypes again.
#[test]
#[cfg_attr(
    miri,
    ignore = "audits all fake memory after every call; l4core has no unsafe"
)]
fn revoke_stopped_anywhere_then_a_different_call() {
    let mut start = World::new();
    make(&mut start, S_UT, ObjectType::Endpoint, 0, 20, 1);
    make(&mut start, S_UT, ObjectType::CNode, 2, 21, 1);
    make(&mut start, S_UT, ObjectType::CNode, 1, 22, 1);
    make(&mut start, S_UT, ObjectType::Tcb, 0, 23, 1);
    make(&mut start, S_UT, ObjectType::Untyped, 12, 24, 1);
    let sub = rt(ObjectType::Notification, 0, SELF, 25, 2);
    assert_eq!(
        start.attempt(rs(24), RETYPE, &sub, &[rs(S_ROOT)], None),
        Ok(Reply::EMPTY)
    );
    // 21 holds a copy of the endpoint, a badged one, and 22's last
    // capability, which holds a copy of the TCB.
    let c21 = start.cap(rs(21));
    let c22 = start.cap(rs(22));
    let at21 = |j| through(r(21), c21, j).unwrap();
    let at22 = |j| through(r(22), c22, j).unwrap();
    start
        .root_call(COPY, &[at21(0).0, at21(0).1, r(20).0, 8, 0xF])
        .unwrap();
    start
        .root_call(MINT, &[at21(1).0, at21(1).1, r(20).0, 8, 0x5, 77])
        .unwrap();
    start
        .root_call(COPY, &[at22(1).0, at22(1).1, r(23).0, 8, 0])
        .unwrap();
    start
        .root_call(MOVE, &[at21(3).0, at21(3).1, r(22).0, 8])
        .unwrap();
    let revoke = [r(S_UT).0, 8];
    let mut points = 0;
    loop {
        let mut w = start.clone();
        let res = w.attempt(rs(S_ROOT), REVOKE, &revoke, &[], Some(points));
        if res != Err(InvokeError::Preempted) {
            assert_eq!(res, Ok(Reply::EMPTY));
            break;
        }
        let follow: [(SlotAddr, u64, Vec<u64>); 10] = [
            (rs(S_ROOT), COPY, vec![r(50).0, 8, r(S_UT).0, 8, 0]),
            (rs(S_UT), RETYPE, rt(ObjectType::Endpoint, 0, SELF, 51, 1)),
            (rs(S_ROOT), MOVE, vec![r(52).0, 8, r(S_UT).0, 8]),
            (rs(S_ROOT), DELETE, revoke.to_vec()),
            (rs(S_ROOT), REVOKE, vec![r(20).0, 8]),
            (rs(S_ROOT), DELETE, vec![r(21).0, 8]),
            (rs(S_ROOT), REVOKE, vec![r(24).0, 8]),
            (rs(S_ROOT), MINT, vec![r(53).0, 8, r(20).0, 8, 0xF, 77]),
            (
                rs(S_ROOT),
                ROTATE,
                vec![r(54).0, 8, 0, r(S_UT).0, 8, 0, r(24).0, 8],
            ),
            (rs(S_UT), RETYPE, rt(ObjectType::Untyped, 15, SELF, 55, 1)),
        ];
        for (invoked, label, mrs) in &follow {
            for every in [0, 1, u64::MAX] {
                let mut t = w.clone();
                let _ = run(
                    &mut t,
                    every,
                    *invoked,
                    *label,
                    mrs,
                    &[rs(S_ROOT), rs(S_ROOT)],
                );
                // Finish: revoke the boot untyped wherever it went.
                let held = [S_UT, 52, 54]
                    .into_iter()
                    .find(|&i| t.cap(rs(i)) == start.cap(rs(S_UT)).with_data(t.cap(rs(i)).data));
                if let Some(i) = held {
                    let (res, _) = run(&mut t, every, rs(S_ROOT), REVOKE, &[r(i).0, 8], &[]);
                    assert_eq!(res, Ok(Reply::EMPTY));
                    assert!(!cdt::has_children(&t.k, rs(i)));
                    make(&mut t, i, ObjectType::Untyped, u64::from(UT_BITS), 60, 1);
                }
            }
        }
        points += 1;
    }
    assert!(points > 5, "only {points} preemption points");
}

// ---------------------------------------------------------------------
// Random calls with boundary words, audited after every attempt.

/// A small deterministic generator (SplitMix64).
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    fn chance(&mut self, num: u64, den: u64) -> bool {
        self.below(den) < num
    }

    fn pick<T: Copy>(&mut self, v: &[T]) -> T {
        v[self.below(v.len() as u64) as usize]
    }

    fn boundary(&mut self) -> u64 {
        if self.chance(1, 4) {
            self.next()
        } else {
            self.pick(&BOUNDARY)
        }
    }
}

/// A slot the generator can name from the root CNode, and its capability.
#[derive(Clone, Copy)]
struct Named {
    slot: SlotAddr,
    name: (u64, u64),
    cap: Cap,
}

/// The root's slots, then the slots of every CNode a root slot holds,
/// through its guard, and one level further.
fn nameable(w: &World) -> Vec<Named> {
    let mut out = Vec::new();
    let mut todo: Vec<((u64, u64), Cap)> = vec![((0, 0), root_cap())];
    let mut levels = 0;
    while let Some((at, c)) = todo.pop() {
        levels += 1;
        if levels > 40 {
            break;
        }
        let n = 1u64 << c.radix().min(6);
        for j in 0..n {
            let name = if at.1 == 0 {
                Some(((ROOT_GUARD << ROOT_RADIX) | j, 8))
            } else {
                through(at, c, j)
            };
            let Some(name) = name else { continue };
            let slot = sa(c.object() + j * SLOT_SIZE);
            let cap = w.cap(slot);
            out.push(Named { slot, name, cap });
            if cap.cap_type() == CapType::CNode && name.1 < 40 && cap.object() != c.object() {
                todo.push((name, cap));
            }
        }
    }
    out
}

struct Gen<'a> {
    rng: &'a mut Rng,
    all: Vec<Named>,
}

impl Gen<'_> {
    fn spare(n: &Named) -> bool {
        n.slot == rs(S_ROOT) || n.slot == rs(S_L2)
    }

    fn slot_where(&mut self, f: impl Fn(&Named) -> bool) -> Option<Named> {
        let spare_ok = self.rng.chance(1, 40);
        let v: Vec<Named> = self
            .all
            .iter()
            .filter(|n| f(n) && (spare_ok || !Self::spare(n)))
            .copied()
            .collect();
        (!v.is_empty()).then(|| self.rng.pick(&v))
    }

    fn name(&mut self, full: bool) -> (u64, u64) {
        if self.rng.chance(1, 12) {
            let depth = self.rng.pick(&[0u64, 1, 7, 8, 9, 63, 64, 65, u64::MAX]);
            return (self.rng.boundary(), depth);
        }
        let f = |n: &Named| n.cap.is_null() != full;
        match self.slot_where(f) {
            Some(n) => n.name,
            None => (self.rng.next(), 8),
        }
    }

    fn data(&mut self) -> u64 {
        match self.rng.below(6) {
            0 => 0,
            1 => 1 + self.rng.below(9),
            2 => {
                let g = self.rng.pick(&[0u64, 1, 3, 54, 56, 58, 59, 61, 62, 63]);
                cnode_data(g as u32, self.rng.next())
            }
            3 => cnode_data(0, 0),
            _ => self.rng.boundary(),
        }
    }

    fn word(&mut self, natural: impl FnOnce(&mut Rng) -> u64) -> u64 {
        if self.rng.chance(1, 10) {
            self.rng.boundary()
        } else {
            natural(self.rng)
        }
    }

    /// A root slot holding the boot root CNode's capability.
    fn root_slot(&mut self) -> SlotAddr {
        if self.rng.chance(1, 20)
            && let Some(n) = self.slot_where(|n| n.cap.cap_type() == CapType::CNode)
        {
            return n.slot;
        }
        self.all
            .iter()
            .find(|n| n.cap == root_cap())
            .map_or(rs(S_ROOT), |n| n.slot)
    }

    /// A call: invoked slot, label, registers, extra capability slots.
    fn call(&mut self) -> (SlotAddr, u64, Vec<u64>, Vec<SlotAddr>) {
        let label = if self.rng.chance(1, 40) {
            self.rng.boundary()
        } else {
            self.rng.pick(&[
                RETYPE, RETYPE, REVOKE, DELETE, COPY, MINT, MOVE, MUTATE, ROTATE,
            ])
        };
        let mut mrs = Vec::new();
        let invoked;
        let extra = if label == RETYPE {
            invoked = self
                .slot_where(|n| n.cap.cap_type() == CapType::Untyped)
                .map_or(rs(S_UT), |n| n.slot);
            let ty = self.word(|r| r.below(11));
            let size = self.word(|r| match ty {
                0 => 4 + r.below(10),
                4 => 1 + r.below(4),
                _ => r.below(3),
            });
            // The destination CNode: the root itself, or one it holds.
            let node = if self.rng.chance(1, 3) {
                (0, 0)
            } else {
                match self.slot_where(|n| n.cap.cap_type() == CapType::CNode) {
                    Some(n) => n.name,
                    None => (0, 0),
                }
            };
            let dest = if node == (0, 0) {
                Some(root_cap())
            } else {
                self.all.iter().find(|n| n.name == node).map(|n| n.cap)
            };
            let slots = dest.map_or(64, |c| 1u64 << c.radix().min(6));
            let offset = self.word(|r| {
                if r.chance(1, 3) {
                    slots - 1 - r.below(2.min(slots))
                } else {
                    r.below(slots)
                }
            });
            let count = self.word(|r| 1 + r.below(3));
            let node = if self.rng.chance(1, 12) {
                (self.rng.boundary(), self.rng.pick(&[0u64, 1, 8, 64, 65]))
            } else {
                node
            };
            mrs.extend([ty, size, node.0, node.1, offset, count]);
            vec![self.root_slot()]
        } else {
            invoked = self.root_slot();
            match label {
                REVOKE | DELETE => {
                    let t = self.name(true);
                    mrs.extend([t.0, t.1]);
                }
                COPY | MINT | MOVE | MUTATE => {
                    let d = self.name(false);
                    let s = self.name(true);
                    mrs.extend([d.0, d.1, s.0, s.1]);
                    if label == COPY || label == MINT {
                        let rights = self.word(|r| r.below(16));
                        mrs.push(rights);
                    }
                    if label != MOVE && label != COPY {
                        let data = self.data();
                        mrs.push(data);
                    }
                }
                _ => {
                    let swap = self.rng.chance(1, 3);
                    let s = self.name(true);
                    let d = if swap { s } else { self.name(false) };
                    let p = self.name(true);
                    let (dd, pd) = (self.data(), self.data());
                    mrs.extend([d.0, d.1, dd, p.0, p.1, pd, s.0, s.1]);
                }
            }
            vec![self.root_slot(), self.root_slot()]
        };
        if self.rng.chance(1, 30) {
            let n = self.rng.below(mrs.len() as u64 + 1) as usize;
            mrs.truncate(n);
        }
        (invoked, label, mrs, extra)
    }
}

/// The world a random sequence starts from: a few of each kind of object,
/// a CNode with a 54-bit guard filling 64 bits, a sub-untyped and a copied
/// untyped.
fn random_start(depth: u32) -> World {
    let mut w = World::new();
    // The boot untyped as a chain of copies whose sources were deleted
    // leaves them.
    for ut in [S_UT, S_UT2, S_DEV] {
        let mut s = w.k.load(rs(ut));
        s.node = crate::slot::Node::new(true, depth, 0);
        w.k.store(rs(ut), s);
    }
    make(&mut w, S_UT, ObjectType::Endpoint, 0, 20, 2);
    make(&mut w, S_UT, ObjectType::CNode, 2, 22, 1);
    make(&mut w, S_UT, ObjectType::CNode, 1, 23, 1);
    make(&mut w, S_UT, ObjectType::Untyped, 11, 24, 1);
    make(&mut w, S_UT, ObjectType::Tcb, 0, 25, 1);
    w.root_call(MUTATE, &[r(26).0, 8, r(22).0, 8, cnode_data(54, 0x15)])
        .unwrap();
    w.root_call(COPY, &[r(27).0, 8, r(S_UT2).0, 8, 0]).unwrap();
    w.audit().unwrap();
    w
}

fn random_sequence(seed: u64, steps: u32, depth: u32) {
    let mut rng = Rng(seed);
    let mut w = random_start(depth);
    for step in 0..steps {
        let all = nameable(&w);
        let mut g = Gen { rng: &mut rng, all };
        let (invoked, label, mrs, extra) = g.call();
        let preempt = rng.chance(1, 3).then(|| rng.below(6));
        let retries = if rng.chance(1, 2) { 1000 } else { 0 };
        let attempt = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
            let mut w2 = w.clone();
            let mut n = 0;
            loop {
                match w2.attempt(invoked, label, &mrs, &extra, preempt) {
                    Err(InvokeError::Preempted) if n < retries => n += 1,
                    _ => return w2,
                }
            }
        }));
        match attempt {
            Ok(w2) => w = w2,
            Err(e) => {
                let msg = e
                    .downcast_ref::<String>()
                    .cloned()
                    .or_else(|| e.downcast_ref::<&str>().map(|s| String::from(*s)))
                    .unwrap_or_default();
                panic!(
                    "seed {seed:#x} step {step}: {:#x} on {:#x} {mrs:x?} extra {:x?} \
                     preempt {preempt:?}: {msg}",
                    label,
                    invoked.get(),
                    extra.iter().map(|s| s.get()).collect::<Vec<_>>()
                );
            }
        }
    }
    // A revoke of every boot untyped still held clears it.
    for ut in [S_UT, S_UT2, S_DEV] {
        let c = w.cap(rs(ut));
        if c.cap_type() == CapType::Untyped && w.k.load(rs(ut)).node.depth() == depth {
            crate::cnode::revoke(&mut w.k, rs(ut)).unwrap();
            w.audit().unwrap();
            assert!(!cdt::has_children(&w.k, rs(ut)));
        }
    }
}

/// Random calls never panic and keep every guarantee after every attempt.
/// `REDTEAM_SEEDS` sets how many sequences run.
#[test]
#[cfg_attr(miri, ignore = "a long random search")]
fn random_calls_keep_every_guarantee() {
    let seeds: u64 = std::env::var("REDTEAM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    let first: u64 = std::env::var("REDTEAM_FIRST")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    for seed in first..first + seeds {
        random_sequence(seed, 150, 0);
    }
}

/// The same from untyped at depth 4092, so that sequences reach the
/// derivation limit.
#[test]
#[cfg_attr(miri, ignore = "a long random search")]
fn random_calls_at_the_depth_limit_keep_every_guarantee() {
    let seeds: u64 = std::env::var("REDTEAM_SEEDS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(40);
    for seed in 0..seeds {
        random_sequence(seed ^ 0xDEE9, 150, MAX_DERIVATION_DEPTH - 3);
    }
}

/// The random generator reaches past the argument checks.
#[test]
#[cfg_attr(miri, ignore = "a statistic over many random calls")]
fn random_calls_mostly_do_something() {
    let mut rng = Rng(7);
    let mut w = random_start(0);
    let (mut ok, mut total) = (0, 0);
    let mut seen = BTreeSet::new();
    for _ in 0..400 {
        let all = nameable(&w);
        let (invoked, label, mrs, extra) = Gen { rng: &mut rng, all }.call();
        total += 1;
        let (res, _) = run(&mut w, u64::MAX, invoked, label, &mrs, &extra);
        if res.is_ok() {
            ok += 1;
            seen.insert(label);
        }
    }
    assert!(4 * ok >= total, "{ok} of {total}");
    assert!(seen.len() >= 7, "{seen:x?}");
}
