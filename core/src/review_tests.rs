//! A fresh reviewer's attempts to break the capability core (M2 review
//! brief): hand-written sequences of capability operations, each run on a
//! checking [`Kernel`] that follows every capability through every slot
//! write and `moved` call, keeps a plain parent map as the model, and checks
//! the invariants of `docs/design.md`, `docs/abi.md` and ADRs 0009 to 0012
//! at every hook call and after every call. Every test here names the
//! invariant it attacks; those that pass are regression tests.

use std::collections::{BTreeMap, BTreeSet};
use std::format;
use std::string::{String, ToString};
use std::vec;
use std::vec::Vec;

use crate::cap::{
    Cap, CapType, MAX_DERIVATION_DEPTH, ObjectType, Rights, SLOT_SIZE, TCB_SLOT_REPLY, TCB_SLOTS,
    cnode_data, low_mask,
};
use crate::cdt;
use crate::cnode;
use crate::cspace;
use crate::error::{LookupFailure, SyscallError};
use crate::kernel::{Kernel, Preempted};
use crate::slot::{Slot, SlotAddr, SlotMemory};
use crate::testing::{DIRT, FakeMemory};
use crate::untyped::{RetypeArgs, RetypeError, retype};

/// The root CNode: 64 slots at 0x1000, outside every untyped (a boot-region
/// object). Its capability is not in any slot.
const ROOT: u64 = 0x1000;
const ROOT_RADIX: u32 = 6;
/// A 64 KiB boot untyped at 64 KiB, in root slot 1.
const UT: u64 = 0x1_0000;
const UT_BITS: u32 = 16;
/// Fake memory: 0 to 192 KiB.
const MEM: u64 = 0x3_0000;

const EMPTY_SOURCE: SyscallError = SyscallError::FailedLookup {
    source: true,
    failure: LookupFailure::MissingCapability { bits_left: 0 },
};

fn sa(a: u64) -> SlotAddr {
    SlotAddr::new(a).unwrap()
}

fn slot(base: u64, i: u64) -> u64 {
    base + i * SLOT_SIZE
}

fn root_cap() -> Cap {
    Cap::cnode(ROOT, ROOT_RADIX, 64 - ROOT_RADIX, 0)
}

type Key = (u8, u64, u32);

fn key(c: &Cap) -> Key {
    (c.cap_type() as u8, c.object(), c.size_bits())
}

/// Types whose last deletion calls `finalise(cap, true)`.
fn finalisable(t: CapType) -> bool {
    matches!(
        t,
        CapType::Tcb
            | CapType::Endpoint
            | CapType::Notification
            | CapType::Frame
            | CapType::PageTable
            | CapType::PageDirectory
            | CapType::Pdpt
            | CapType::Pml4
    )
}

/// The memory a capability names: `(base, len)`.
fn region(c: &Cap) -> Option<(u64, u64)> {
    match c.cap_type() {
        CapType::Null
        | CapType::IrqControl
        | CapType::IrqHandler
        | CapType::IoPortControl
        | CapType::IoPort
        | CapType::Hypervisor
        | CapType::Reply => None,
        _ => Some((c.object(), 1u64 << c.size_bits())),
    }
}

fn overlaps(a: (u64, u64), b: (u64, u64)) -> bool {
    a.0 < b.0 + b.1 && b.0 < a.0 + a.1
}

fn inside(a: (u64, u64), b: (u64, u64)) -> bool {
    b.0 <= a.0 && a.0 + a.1 <= b.0 + b.1
}

/// A [`Kernel`] over fake memory that gives every capability an identity,
/// follows it through stores and `moved` calls, and checks invariants in
/// every hook.
struct Ck {
    mem: FakeMemory,
    preempt_in: Option<u64>,
    preempt_points: u64,
    /// Return a cleanup capability from every `finalise` call but a TCB's,
    /// which the `Kernel::finalise` contract keeps at `None`, and check that
    /// each reaches `after_delete`.
    cleanup_all: bool,
    /// Act as the kernel's TCB finalisation (M5): deleting the last
    /// capability to a TCB first deletes the reply capability its master
    /// has outstanding (`docs/design.md`, Deletion and finalisation).
    reply_hook: bool,
    /// Slots the reply hook emptied during this call.
    hook_deleted: Vec<u64>,
    cleanups: Vec<Cap>,
    next_id: u64,
    id_at: BTreeMap<u64, u64>,
    pending_removed: Vec<(u64, u64)>,
    pending_inserted: BTreeSet<u64>,
    skip: Option<(u64, u64)>,
    parent: BTreeMap<u64, Option<u64>>,
    original: BTreeMap<u64, bool>,
    finalised: BTreeSet<Key>,
    finalise_calls: Vec<(Cap, bool)>,
    /// Finalisable objects made by retype whose memory has not been reused.
    created: Vec<Cap>,
    /// Regions of containers whose last capability became a Zombie.
    containers: Vec<(u64, u64)>,
    /// End of the untyped regions scanned: one boot untyped, or two.
    scan_end: u64,
    stores: u64,
    hooks: u64,
    errors: Vec<String>,
}

impl Ck {
    fn new() -> Ck {
        Ck {
            mem: FakeMemory::new(0, MEM),
            preempt_in: None,
            preempt_points: 0,
            cleanup_all: false,
            reply_hook: false,
            hook_deleted: Vec::new(),
            cleanups: Vec::new(),
            next_id: 1,
            id_at: BTreeMap::new(),
            pending_removed: Vec::new(),
            pending_inserted: BTreeSet::new(),
            skip: None,
            parent: BTreeMap::new(),
            original: BTreeMap::new(),
            finalised: BTreeSet::new(),
            finalise_calls: Vec::new(),
            created: Vec::new(),
            containers: Vec::new(),
            scan_end: UT + (1 << UT_BITS),
            stores: 0,
            hooks: 0,
            errors: Vec::new(),
        }
    }

    fn err(&mut self, s: String) {
        self.errors.push(s);
    }

    /// Every slot that can hold a capability: the root CNode and the
    /// untyped regions.
    fn all_slots(&self) -> impl Iterator<Item = u64> + use<> {
        (0..(1u64 << ROOT_RADIX))
            .map(|i| slot(ROOT, i))
            .chain((0..(self.scan_end - UT) / SLOT_SIZE).map(|i| slot(UT, i)))
    }

    fn caps(&self) -> Vec<(u64, Cap)> {
        self.all_slots()
            .map(|a| (a, self.mem.load(sa(a)).cap))
            .filter(|(_, c)| !c.is_null())
            .collect()
    }

    fn cap(&self, a: u64) -> Cap {
        self.mem.load(sa(a)).cap
    }

    fn node(&self, a: u64) -> crate::slot::Node {
        self.mem.load(sa(a)).node
    }

    fn model_children(&self, id: u64) -> Vec<u64> {
        self.parent
            .iter()
            .filter(|(_, p)| **p == Some(id))
            .map(|(c, _)| *c)
            .collect()
    }

    fn model_descendants(&self, id: u64) -> BTreeSet<u64> {
        let mut out = BTreeSet::new();
        let mut todo = vec![id];
        while let Some(x) = todo.pop() {
            for c in self.model_children(x) {
                if out.insert(c) {
                    todo.push(c);
                }
            }
        }
        out
    }

    fn is_model_ancestor(&self, anc: u64, mut id: u64) -> bool {
        while let Some(Some(p)) = self.parent.get(&id) {
            if *p == anc {
                return true;
            }
            id = *p;
        }
        false
    }

    /// Settles this call's slot writes: pending insertions become new
    /// capabilities, with the parent and `original` flag `rule` gives them,
    /// and pending removals become deletions whose children pass to the
    /// deleted capability's parent. Returns the deleted ids and the slots
    /// they were last in.
    fn settle(&mut self, rule: ParentRule) -> Vec<(u64, u64)> {
        let inserted = core::mem::take(&mut self.pending_inserted);
        let removed = core::mem::take(&mut self.pending_removed);
        for a in inserted {
            let c = self.cap(a);
            if c.is_null() {
                self.err(format!("slot {a:#x} filled and emptied untracked"));
                continue;
            }
            let (p, orig) = rule.parent(self, a, c);
            let id = self.next_id;
            self.next_id += 1;
            self.id_at.insert(a, id);
            self.parent.insert(id, p);
            self.original.insert(id, orig);
        }
        for &(_, id) in &removed {
            let p = self.parent.remove(&id).flatten();
            self.original.remove(&id);
            for v in self.parent.values_mut() {
                if *v == Some(id) {
                    *v = p;
                }
            }
        }
        if !self.cleanups.is_empty() {
            let c = core::mem::take(&mut self.cleanups);
            self.err(format!("cleanups never passed to after_delete: {c:?}"));
        }
        self.skip = None;
        removed
    }

    /// Checks every invariant that holds between system calls.
    fn verify(&mut self) {
        let caps = self.caps();
        let mut errs = Vec::new();
        // The list itself.
        for a in self.all_slots() {
            if let Err(e) = cdt::check_slot(self, sa(a)) {
                errs.push(format!("check_slot({a:#x}): {e}"));
            }
            let n = self.node(a);
            if !self.cap(a).is_null() && n.depth() > MAX_DERIVATION_DEPTH {
                errs.push(format!("depth over the limit at {a:#x}"));
            }
        }
        // Tracking agrees with memory.
        for (a, _) in &caps {
            if !self.id_at.contains_key(a) {
                errs.push(format!("untracked capability at {a:#x}"));
            }
        }
        let mut slot_of = BTreeMap::new();
        for (&a, &id) in &self.id_at {
            if self.cap(a).is_null() {
                errs.push(format!("tracked capability {id} missing at {a:#x}"));
            }
            slot_of.insert(id, a);
        }
        // Parents, original flags, has_children and is_final against the
        // model and against a scan of all memory.
        for (a, c) in &caps {
            let Some(&id) = self.id_at.get(a) else {
                continue;
            };
            let model = self
                .parent
                .get(&id)
                .copied()
                .flatten()
                .and_then(|p| slot_of.get(&p).copied());
            let got = cdt::parent(self, sa(*a)).map(|s| s.get());
            if model != got {
                errs.push(format!(
                    "parent of {a:#x} ({c:?}): model {model:x?}, list {got:x?}"
                ));
            }
            if self.original.get(&id).copied() != Some(self.node(*a).original()) {
                errs.push(format!("original flag of {a:#x} differs from the model"));
            }
            let mc = !self.model_children(id).is_empty();
            if mc != cdt::has_children(self, sa(*a)) {
                errs.push(format!("has_children({a:#x}) = {}, model {mc}", !mc));
            }
            let others = caps
                .iter()
                .filter(|(b, d)| b != a && d.same_object(c))
                .count();
            if cdt::is_final(self, sa(*a)) != (others == 0) {
                errs.push(format!(
                    "is_final({a:#x}) wrong: {others} other capabilities to {c:?}"
                ));
            }
        }
        // Objects: aligned, inside the untyped, disjoint, below every
        // covering untyped's watermark and descended from it.
        let ut_region = (UT, self.scan_end - UT);
        let objs: Vec<(u64, Cap)> = caps
            .iter()
            .filter(|(_, c)| region(c).is_some())
            .copied()
            .collect();
        for (a, c) in &objs {
            let r = region(c).unwrap();
            if !r.0.is_multiple_of(r.1) {
                errs.push(format!("{c:?} at {a:#x} is not aligned to its size"));
            }
            if !inside(r, ut_region) {
                errs.push(format!("{c:?} at {a:#x} lies outside the untyped"));
            }
        }
        for (i, (a, c)) in objs.iter().enumerate() {
            for (b, d) in &objs[i + 1..] {
                let (rc, rd) = (region(c).unwrap(), region(d).unwrap());
                if !overlaps(rc, rd) {
                    continue;
                }
                let cu = c.cap_type() == CapType::Untyped;
                let du = d.cap_type() == CapType::Untyped;
                if !cu && !du {
                    if key(c) != key(d) {
                        errs.push(format!(
                            "objects overlap: {c:?} at {a:#x} and {d:?} at {b:#x}"
                        ));
                    }
                    continue;
                }
                // One is an untyped; the other must be inside it, below its
                // watermark and its descendant (or, for two untypeds, one
                // descends from the other).
                let (u, ua, x, xa) = if cu && (!du || inside(rd, rc)) {
                    (c, *a, d, *b)
                } else {
                    (d, *b, c, *a)
                };
                let ru = region(u).unwrap();
                let rx = region(x).unwrap();
                let (uid, xid) = (self.id_at.get(&ua), self.id_at.get(&xa));
                let (Some(&uid), Some(&xid)) = (uid, xid) else {
                    continue;
                };
                if !inside(rx, ru) {
                    errs.push(format!("{x:?} at {xa:#x} straddles untyped {u:?}"));
                    continue;
                }
                if x.cap_type() == CapType::Untyped && rx == ru && self.is_model_ancestor(xid, uid)
                {
                    continue;
                }
                if !self.is_model_ancestor(uid, xid) {
                    errs.push(format!(
                        "{x:?} at {xa:#x} lies in untyped {u:?} at {ua:#x} but is not its descendant"
                    ));
                }
                if rx.0 + rx.1 > ru.0 + u.watermark() {
                    errs.push(format!(
                        "{x:?} at {xa:#x} lies at or above the watermark of {u:?} at {ua:#x}"
                    ));
                }
            }
        }
        // RAM at or above a watermark is zero.
        for (a, c) in &caps {
            if c.cap_type() == CapType::Untyped && !c.is_device() {
                let size = 1u64 << c.size_bits();
                let wm = c.watermark();
                if wm > size {
                    errs.push(format!("watermark past the end at {a:#x}"));
                } else if !self.mem.is_zero(c.object() + wm, size - wm) {
                    errs.push(format!(
                        "non-zero memory above the watermark of {c:?} at {a:#x}"
                    ));
                }
            }
        }
        // Every non-empty slot lies in the root CNode or in the slots of a
        // live container; every reply capability names a live TCB.
        let containers: Vec<(u64, u64, bool)> = caps
            .iter()
            .filter_map(|(_, c)| match c.cap_type() {
                CapType::CNode => Some((c.object(), 1u64 << c.size_bits(), false)),
                CapType::Tcb => Some((c.object(), TCB_SLOTS * SLOT_SIZE, true)),
                CapType::Zombie if c.zombie_is_tcb() => {
                    Some((c.object(), TCB_SLOTS * SLOT_SIZE, true))
                }
                CapType::Zombie => Some((c.object(), 1u64 << c.size_bits(), false)),
                _ => None,
            })
            .collect();
        for (a, c) in &caps {
            if *a < UT {
                continue;
            }
            if !containers.iter().any(|&(b, l, _)| b <= *a && *a < b + l) {
                errs.push(format!("{c:?} at {a:#x} is in no live CNode or TCB"));
            }
            if c.cap_type() == CapType::Reply
                && !caps.iter().any(|(_, t)| {
                    t.object() == c.object()
                        && (t.cap_type() == CapType::Tcb
                            || (t.cap_type() == CapType::Zombie && t.zombie_is_tcb()))
                })
            {
                errs.push(format!("reply capability {c:?} at {a:#x} outlives its TCB"));
            }
            if finalisable(c.cap_type()) && self.finalised.contains(&key(c)) {
                errs.push(format!("{c:?} at {a:#x} names a finalised object"));
            }
        }
        self.errors.extend(errs);
    }

    /// Checks before memory is cleared or a new object made in `r`.
    fn check_reuse(&mut self, r: (u64, u64), what: &str) {
        let mut errs = Vec::new();
        for (a, c) in self.caps() {
            if r.0 <= a && a < r.0 + r.1 {
                errs.push(format!(
                    "{what} {r:x?} over a live slot {a:#x} holding {c:?}"
                ));
            }
            let Some(rc) = region(&c) else {
                if c.cap_type() == CapType::Reply && r.0 <= c.object() && c.object() < r.0 + r.1 {
                    errs.push(format!("{what} {r:x?} under reply capability {c:?}"));
                }
                continue;
            };
            if !overlaps(r, rc) {
                continue;
            }
            if c.cap_type() == CapType::Untyped {
                if !inside(r, rc) {
                    errs.push(format!("{what} {r:x?} over untyped {c:?} at {a:#x}"));
                }
            } else {
                errs.push(format!("{what} {r:x?} under live {c:?} at {a:#x}"));
            }
        }
        let mut keep = Vec::new();
        for o in core::mem::take(&mut self.created) {
            if overlaps(region(&o).unwrap(), r) {
                if !self.finalised.contains(&key(&o)) {
                    errs.push(format!("{what} {r:x?} reuses {o:?}, never finalised"));
                }
            } else {
                keep.push(o);
            }
        }
        self.created = keep;
        self.errors.extend(errs);
    }
}

impl SlotMemory for Ck {
    fn load(&self, at: SlotAddr) -> Slot {
        self.mem.load(at)
    }

    fn store(&mut self, at: SlotAddr, s: Slot) {
        let a = at.get();
        let old = self.mem.load(at);
        self.mem.store(at, s);
        self.stores += 1;
        let (was, now) = (!old.cap.is_null(), !s.cap.is_null());
        if was && !now {
            match self.id_at.remove(&a) {
                Some(id) => self.pending_removed.push((a, id)),
                None => {
                    if !self.pending_inserted.remove(&a) {
                        self.err(format!("emptied untracked slot {a:#x}"));
                    }
                }
            }
        } else if !was && now {
            self.pending_inserted.insert(a);
        }
        if s.cap.cap_type() == CapType::Zombie
            && matches!(old.cap.cap_type(), CapType::CNode | CapType::Tcb)
            && s.cap.object() == old.cap.object()
        {
            let r = region(&s.cap).unwrap();
            self.containers.push(r);
            let others = self
                .caps()
                .into_iter()
                .filter(|(x, c)| *x != a && c.same_object(&old.cap))
                .count();
            if others > 0 {
                self.err(format!(
                    "{:?} became a Zombie while {others} capabilities to it remain",
                    old.cap
                ));
            }
        }
    }
}

impl Kernel for Ck {
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
        self.hooks += 1;
        self.finalise_calls.push((cap, last));
        if self.reply_hook && last && cap.cap_type() == CapType::Tcb {
            let master = sa(cap.object()).offset(TCB_SLOT_REPLY);
            if let Some(child) = cdt::first_child(self, master) {
                self.hook_deleted.push(child.get());
                cnode::delete(self, child).expect("deleting a reply capability never preempts");
            }
        }
        let t = cap.cap_type();
        if finalisable(t) || t == CapType::Reply {
            let n = self
                .caps()
                .iter()
                .filter(|(_, c)| c.same_object(&cap))
                .count();
            if last && n != 1 {
                self.err(format!(
                    "finalise({cap:?}, last) with {n} capabilities to it"
                ));
            }
            if !last && n < 2 {
                self.err(format!(
                    "finalise({cap:?}, not last) with {n} capabilities to it"
                ));
            }
        }
        if finalisable(t) {
            if last && !self.finalised.insert(key(&cap)) {
                self.err(format!("{cap:?} finalised twice"));
            }
            if !last && self.finalised.contains(&key(&cap)) {
                self.err(format!("{cap:?} deleted after its last capability"));
            }
        }
        if self.cleanup_all && t != CapType::Tcb {
            self.cleanups.push(cap);
            Some(cap)
        } else {
            None
        }
    }

    fn after_delete(&mut self, cleanup: Cap) {
        self.hooks += 1;
        match self.cleanups.iter().position(|c| *c == cleanup) {
            Some(i) => {
                self.cleanups.remove(i);
            }
            None => self.err(format!(
                "after_delete({cleanup:?}) never returned by finalise"
            )),
        }
    }

    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        self.hooks += 1;
        let (f, t) = (from.get(), to.get());
        if self.cap(t) != cap {
            self.err(format!("moved({cap:?}) but {t:#x} holds {:?}", self.cap(t)));
        }
        if self.skip == Some((f, t)) {
            self.skip = None;
            return;
        }
        if self.cap(f).is_null() {
            match self.pending_removed.iter().rposition(|(s, _)| *s == f) {
                Some(i) => {
                    let (_, id) = self.pending_removed.remove(i);
                    self.pending_inserted.remove(&t);
                    self.id_at.insert(t, id);
                }
                None => self.err(format!("moved from {f:#x}, which held nothing tracked")),
            }
        } else {
            let x = self.id_at.remove(&f);
            let y = self.id_at.remove(&t);
            if let Some(x) = x {
                self.id_at.insert(t, x);
            }
            if let Some(y) = y {
                self.id_at.insert(f, y);
            }
            self.skip = Some((t, f));
        }
    }

    fn zero(&mut self, paddr: u64, len: u64) {
        self.hooks += 1;
        self.check_reuse((paddr, len), "zero");
        self.mem.zero(paddr, len);
    }

    fn init_object(&mut self, cap: Cap) {
        self.hooks += 1;
        let r = region(&cap).unwrap();
        if !self.mem.is_zero(r.0, r.1) {
            self.err(format!("new object {cap:?} is not zero"));
        }
        self.check_reuse(r, "init_object");
        self.finalised.remove(&key(&cap));
        if finalisable(cap.cap_type()) {
            self.created.push(cap);
        }
        let off = match cap.cap_type() {
            CapType::Endpoint | CapType::Notification | CapType::Frame => Some(0),
            CapType::Tcb => Some(1024),
            _ => None,
        };
        if let Some(off) = off {
            self.mem.write(cap.object() + off, DIRT);
        }
    }

    fn preempt(&mut self) -> Result<(), Preempted> {
        self.preempt_points += 1;
        match self.preempt_in {
            Some(0) => {
                self.preempt_in = None;
                Err(Preempted)
            }
            Some(n) => {
                self.preempt_in = Some(n - 1);
                Ok(())
            }
            None => Ok(()),
        }
    }
}

/// A sequence of calls, each with its first preemption point.
type Calls = Vec<(Op, Option<u64>)>;

/// One user operation on resolved slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    Retype {
        ut: u64,
        ty: u64,
        size_bits: u64,
        /// The slot holding the destination CNode capability; `None` for
        /// the root CNode.
        dest: Option<u64>,
        offset: u64,
        n: u64,
    },
    Copy {
        src: u64,
        dst: u64,
        rights: u64,
    },
    Mint {
        src: u64,
        dst: u64,
        rights: u64,
        data: u64,
    },
    Move {
        src: u64,
        dst: u64,
    },
    Mutate {
        src: u64,
        dst: u64,
        data: u64,
    },
    Rotate {
        dst: u64,
        dst_data: u64,
        pivot: u64,
        pivot_data: u64,
        src: u64,
    },
    Delete {
        slot: u64,
    },
    Revoke {
        slot: u64,
    },
    /// Kernel side (M5): the TCB at `caller` calls the one at `callee`,
    /// which gets a reply capability in its caller slot.
    Call {
        caller: u64,
        callee: u64,
    },
}

/// What one call did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Outcome {
    Done,
    Failed(SyscallError),
    Preempted,
}

/// A world: the checking kernel, the root CNode and the boot untyped.
struct World {
    k: Ck,
    log: Vec<(Op, Option<u64>, Outcome)>,
    /// Preempted calls waiting to restart.
    pending: Vec<Op>,
    /// Let the explorer make kernel-side calls too (TCB installs, `Call`,
    /// `CNode_SaveCaller`).
    kernel_ops: bool,
}

impl World {
    fn new() -> World {
        let mut k = Ck::new();
        cdt::insert_root(
            &mut k,
            sa(slot(ROOT, 1)),
            Cap::untyped(UT, UT_BITS, false, 1 << UT_BITS),
        );
        k.settle(ParentRule::Root);
        World {
            k,
            log: Vec::new(),
            pending: Vec::new(),
            kernel_ops: false,
        }
    }

    fn cap(&self, a: u64) -> Cap {
        self.k.cap(a)
    }

    fn assert_clean(&self) {
        assert!(
            self.k.errors.is_empty(),
            "invariants broken:\n{}\nafter:\n{:#?}",
            self.k.errors.join("\n"),
            self.log
        );
    }

    /// Slots reachable from the root CNode through CNode capabilities.
    fn reachable(&self) -> Vec<u64> {
        let mut out = Vec::new();
        let mut seen = BTreeSet::new();
        let mut todo = vec![(ROOT, ROOT_RADIX)];
        seen.insert(ROOT);
        while let Some((base, radix)) = todo.pop() {
            for i in 0..(1u64 << radix) {
                let a = slot(base, i);
                out.push(a);
                let c = self.cap(a);
                if c.cap_type() == CapType::CNode && seen.insert(c.object()) {
                    todo.push((c.object(), c.radix()));
                }
            }
        }
        out
    }

    fn id(&self, a: u64) -> Option<u64> {
        self.k.id_at.get(&a).copied()
    }

    fn model_has_children(&self, a: u64) -> bool {
        self.id(a)
            .is_some_and(|id| !self.k.model_children(id).is_empty())
    }

    /// The model's result for Copy and Mint (`docs/abi.md`, `CNode_Copy`
    /// and `CNode_Mint`): the new capability and whether it is original.
    fn expect_copy(
        &self,
        src: u64,
        dst: u64,
        rights: u64,
        data: Option<u64>,
    ) -> Result<(Cap, bool), SyscallError> {
        if !self.cap(dst).is_null() {
            return Err(SyscallError::DeleteFirst);
        }
        let c = self.cap(src);
        if c.is_null() {
            return Err(EMPTY_SOURCE);
        }
        let t = c.cap_type();
        if matches!(
            t,
            CapType::Zombie
                | CapType::Reply
                | CapType::IrqControl
                | CapType::IoPortControl
                | CapType::Pdpt
                | CapType::PageDirectory
                | CapType::PageTable
        ) {
            return Err(SyscallError::IllegalOperation);
        }
        if t == CapType::Untyped && self.model_has_children(src) {
            return Err(SyscallError::RevokeFirst);
        }
        let mut n = c.with_rights(c.rights().intersect(Rights::from_word(rights)));
        if t == CapType::Frame {
            n = n.with_data(0);
        }
        let mut original = t == CapType::Untyped;
        if let Some(data) = data {
            match t {
                CapType::Endpoint | CapType::Notification => {
                    if c.badge() != 0 {
                        return Err(SyscallError::IllegalOperation);
                    }
                    if data != 0 {
                        n = n.with_data(data);
                        original = true;
                    }
                }
                CapType::CNode => {
                    let gs = (data & 0x3F) as u32;
                    if gs + c.radix() > 64 {
                        return Err(SyscallError::IllegalOperation);
                    }
                    n = n.with_data(cnode_data(gs, data >> 6));
                }
                CapType::Hypervisor if data != 0 => return Err(SyscallError::IllegalOperation),
                _ => {}
            }
        }
        let node = self.k.node(src);
        if node.original() && node.depth() >= MAX_DERIVATION_DEPTH {
            return Err(SyscallError::IllegalOperation);
        }
        Ok((n, original))
    }

    /// The model's Mutate data rule.
    fn expect_mutate(c: Cap, data: u64) -> Result<Cap, SyscallError> {
        match c.cap_type() {
            CapType::Endpoint | CapType::Notification => Err(SyscallError::IllegalOperation),
            CapType::CNode => {
                let gs = (data & 0x3F) as u32;
                if gs + c.radix() > 64 {
                    Err(SyscallError::IllegalOperation)
                } else {
                    Ok(c.with_data(cnode_data(gs, data >> 6)))
                }
            }
            CapType::Hypervisor if data != 0 => Err(SyscallError::IllegalOperation),
            _ => Ok(c),
        }
    }

    /// The model's Untyped_Retype checks, in `docs/abi.md`'s order, given a
    /// resolved untyped and destination capability.
    fn expect_retype(
        &self,
        ut: u64,
        dest: Cap,
        ty: u64,
        size_bits: u64,
        offset: u64,
        n: u64,
    ) -> Result<(), SyscallError> {
        let u = self.cap(ut);
        let Some(t) = ObjectType::from_number(ty) else {
            return Err(SyscallError::InvalidArgument(0));
        };
        if t == ObjectType::Untyped && !(4..=47).contains(&size_bits) {
            return Err(SyscallError::RangeError { min: 4, max: 47 });
        }
        if t == ObjectType::CNode && !(1..=42).contains(&size_bits) {
            return Err(SyscallError::RangeError { min: 1, max: 42 });
        }
        if dest.cap_type() != CapType::CNode {
            return Err(SyscallError::FailedLookup {
                source: false,
                failure: LookupFailure::MissingCapability { bits_left: 0 },
            });
        }
        let slots = 1u64 << dest.radix();
        if offset >= slots {
            return Err(SyscallError::RangeError {
                min: 0,
                max: slots - 1,
            });
        }
        if n == 0 || n > 256 {
            return Err(SyscallError::RangeError { min: 1, max: 256 });
        }
        if n > slots - offset {
            return Err(SyscallError::RangeError {
                min: 1,
                max: slots - offset,
            });
        }
        for i in 0..n {
            if !self.cap(slot(dest.object(), offset + i)).is_null() {
                return Err(SyscallError::DeleteFirst);
            }
        }
        let bits = t.object_bits(size_bits as u32);
        let start = if self.model_has_children(ut) {
            u.watermark()
        } else {
            0
        };
        let free = (1u64 << u.size_bits()) - start;
        let aligned = (start + low_mask(bits)) & !low_mask(bits);
        if aligned + (n << bits) > 1u64 << u.size_bits() || bits > u.size_bits() {
            return Err(SyscallError::NotEnoughMemory(free));
        }
        if u.is_device()
            && !matches!(
                t,
                ObjectType::Untyped | ObjectType::Frame4K | ObjectType::Frame2M
            )
        {
            return Err(SyscallError::InvalidArgument(0));
        }
        let node = self.k.node(ut);
        if node.depth() >= MAX_DERIVATION_DEPTH {
            return Err(SyscallError::IllegalOperation);
        }
        Ok(())
    }

    /// Runs one call with preemption after `preempt` points, checks its
    /// result against the model and every invariant after it.
    fn run(&mut self, op: Op, preempt: Option<u64>) -> Outcome {
        let before = self.k.mem.clone();
        self.k.stores = 0;
        self.k.hooks = 0;
        self.k.preempt_in = preempt;
        let target = match op {
            Op::Delete { slot: s } | Op::Revoke { slot: s } => self.id(s).map(|id| (s, id)),
            _ => None,
        };
        let desc = match (op, target) {
            (Op::Revoke { .. }, Some((_, id))) => self.k.model_descendants(id),
            _ => BTreeSet::new(),
        };
        let (outcome, expect, parent_rule): (
            Outcome,
            Option<Result<(), SyscallError>>,
            ParentRule,
        ) = match op {
            Op::Copy { src, dst, rights }
            | Op::Mint {
                src, dst, rights, ..
            } => {
                let data = match op {
                    Op::Mint { data, .. } => Some(data),
                    _ => None,
                };
                let e = self.expect_copy(src, dst, rights, data);
                let src_id = self.id(src);
                let old = self.cap(src);
                let r = match data {
                    Some(d) => cnode::mint(&mut self.k, sa(src), sa(dst), rights, d),
                    None => cnode::copy(&mut self.k, sa(src), sa(dst), rights),
                };
                let out = match r {
                    Ok(()) => Outcome::Done,
                    Err(e) => Outcome::Failed(e),
                };
                if let (Ok(()), Ok((cap, _))) = (&r, &e) {
                    if self.cap(dst) != *cap {
                        self.k
                            .err(format!("{op:?} made {:?}, expected {cap:?}", self.cap(dst)));
                    }
                    let want_src = if old.cap_type() == CapType::Untyped {
                        old.with_data(1 << old.size_bits())
                    } else {
                        old
                    };
                    if self.cap(src) != want_src {
                        self.k
                            .err(format!("{op:?} left the source {:?}", self.cap(src)));
                    }
                }
                let orig = e.map(|(_, o)| o).unwrap_or(false);
                (
                    out,
                    Some(e.map(|_| ())),
                    ParentRule::Copy {
                        src_id,
                        original: orig,
                    },
                )
            }
            Op::Move { src, dst } | Op::Mutate { src, dst, .. } => {
                let data = match op {
                    Op::Mutate { data, .. } => Some(data),
                    _ => None,
                };
                let c = self.cap(src);
                let e = if !self.cap(dst).is_null() {
                    Err(SyscallError::DeleteFirst)
                } else if c.is_null() {
                    Err(EMPTY_SOURCE)
                } else {
                    match data {
                        Some(d) => World::expect_mutate(c, d),
                        None => Ok(c),
                    }
                };
                let r = match data {
                    Some(d) => cnode::mutate(&mut self.k, sa(src), sa(dst), d),
                    None => cnode::move_cap(&mut self.k, sa(src), sa(dst)),
                };
                if let (Ok(()), Ok(want)) = (&r, &e)
                    && (self.cap(dst) != *want || !self.cap(src).is_null())
                {
                    self.k.err(format!("{op:?}: wrong result"));
                }
                (
                    match r {
                        Ok(()) => Outcome::Done,
                        Err(e) => Outcome::Failed(e),
                    },
                    Some(e.map(|_| ())),
                    ParentRule::None,
                )
            }
            Op::Rotate {
                dst,
                dst_data,
                pivot,
                pivot_data,
                src,
            } => {
                let (sc, pc) = (self.cap(src), self.cap(pivot));
                let e = if pivot == src || pivot == dst {
                    Err(SyscallError::IllegalOperation)
                } else if dst != src && !self.cap(dst).is_null() {
                    Err(SyscallError::DeleteFirst)
                } else if sc.is_null() || pc.is_null() {
                    Err(EMPTY_SOURCE)
                } else {
                    World::expect_mutate(pc, dst_data)
                        .and_then(|d| World::expect_mutate(sc, pivot_data).map(|p| (d, p)))
                        .map(|_| ())
                };
                let r = cnode::rotate(
                    &mut self.k,
                    sa(dst),
                    dst_data,
                    sa(pivot),
                    pivot_data,
                    sa(src),
                );
                if r.is_ok() && e.is_ok() {
                    let want_dst = World::expect_mutate(pc, dst_data).unwrap();
                    let want_pivot = World::expect_mutate(sc, pivot_data).unwrap();
                    if self.cap(dst) != want_dst
                        || self.cap(pivot) != want_pivot
                        || (dst != src && !self.cap(src).is_null())
                    {
                        self.k.err(format!("{op:?}: wrong result"));
                    }
                }
                (
                    match r {
                        Ok(()) => Outcome::Done,
                        Err(e) => Outcome::Failed(e),
                    },
                    Some(e),
                    ParentRule::None,
                )
            }
            Op::Delete { slot: s } => {
                let r = cnode::delete(&mut self.k, sa(s));
                (
                    match r {
                        Ok(()) => Outcome::Done,
                        Err(Preempted) => Outcome::Preempted,
                    },
                    None,
                    ParentRule::None,
                )
            }
            Op::Call { caller, callee } => {
                let master = slot(caller, TCB_SLOT_REPLY);
                let to = slot(callee, 4);
                let ok = caller != callee
                    && self.cap(master).is_reply_master()
                    && self.cap(to).is_null()
                    && cdt::first_child(&self.k, sa(master)).is_none();
                if ok {
                    let reply = Cap::reply(caller, false, true);
                    cdt::insert_derived(&mut self.k, sa(master), sa(to), reply, false).unwrap();
                }
                (
                    if ok {
                        Outcome::Done
                    } else {
                        Outcome::Failed(SyscallError::IllegalOperation)
                    },
                    None,
                    ParentRule::Copy {
                        src_id: self.id(master),
                        original: false,
                    },
                )
            }
            Op::Revoke { slot: s } => {
                let r = cnode::revoke(&mut self.k, sa(s));
                (
                    match r {
                        Ok(()) => Outcome::Done,
                        Err(Preempted) => Outcome::Preempted,
                    },
                    None,
                    ParentRule::None,
                )
            }
            Op::Retype {
                ut,
                ty,
                size_bits,
                dest,
                offset,
                n,
            } => {
                let dcap = match dest {
                    None => root_cap(),
                    Some(d) => self.cap(d),
                };
                let e = self.expect_retype(ut, dcap, ty, size_bits, offset, n);
                let had_children = self.model_has_children(ut);
                let old = self.cap(ut);
                let r = retype(
                    &mut self.k,
                    sa(ut),
                    dcap,
                    RetypeArgs {
                        object_type: ty,
                        size_bits,
                        node_offset: offset,
                        num_objects: n,
                    },
                );
                if r.is_ok() && e.is_ok() {
                    let t = ObjectType::from_number(ty).unwrap();
                    let bits = t.object_bits(size_bits as u32);
                    let start = if had_children { old.watermark() } else { 0 };
                    let aligned = (start + low_mask(bits)) & !low_mask(bits);
                    for i in 0..n {
                        let c = self.cap(slot(dcap.object(), offset + i));
                        if c.cap_type() != t.cap_type()
                            || c.object() != old.object() + aligned + (i << bits)
                            || c.size_bits() != bits
                            || c.rights() != t.full_rights()
                            || c.is_device() != old.is_device()
                        {
                            self.k.err(format!("{op:?}: object {i} is {c:?}"));
                        }
                    }
                    if self.cap(ut).watermark() != aligned + (n << bits) {
                        self.k
                            .err(format!("{op:?}: watermark {:#x}", self.cap(ut).watermark()));
                    }
                }
                (
                    match r {
                        Ok(()) => Outcome::Done,
                        Err(RetypeError::Error(e)) => Outcome::Failed(e),
                        Err(RetypeError::Preempted) => Outcome::Preempted,
                    },
                    Some(e),
                    ParentRule::Retype { ut_id: self.id(ut) },
                )
            }
        };
        // Errors match the model and change nothing.
        if let Some(e) = expect {
            match (outcome, e) {
                (Outcome::Failed(got), Err(want)) if got != want => self
                    .k
                    .err(format!("{op:?} failed with {got:?}, expected {want:?}")),
                (Outcome::Failed(got), Ok(())) => self
                    .k
                    .err(format!("{op:?} failed with {got:?}, expected success")),
                (Outcome::Done | Outcome::Preempted, Err(want)) => {
                    self.k.err(format!("{op:?} succeeded, expected {want:?}"))
                }
                _ => {}
            }
        }
        if let Outcome::Failed(_) = outcome
            && (self.k.mem != before || self.k.hooks != 0)
        {
            self.k.err(format!("failed {op:?} changed something"));
        }
        // Who may be deleted: the target of a delete, the descendants of a
        // revoke's target, and what lay in a container destroyed meanwhile.
        let removed = self.k.settle(parent_rule);
        let containers = self.k.containers.clone();
        for (a, id) in removed {
            let ok_target = matches!(op, Op::Delete { .. }) && target.map(|t| t.1) == Some(id);
            let in_container = containers.iter().any(|&(b, l)| b <= a && a < b + l);
            let by_hook = self.k.hook_deleted.contains(&a);
            if !(ok_target || desc.contains(&id) || in_container || by_hook) {
                self.k.err(format!(
                    "{op:?} deleted {id} at {a:#x}, neither its target, a descendant nor in a destroyed container"
                ));
            }
        }
        self.k.hook_deleted.clear();
        if let (Op::Revoke { slot: s }, Outcome::Done, Some((_, id))) = (op, outcome, target)
            && self.id(s) == Some(id)
            && !self.k.model_children(id).is_empty()
        {
            self.k
                .err(format!("{op:?} completed but {s:#x} still has children"));
        }
        if let (Op::Delete { slot: s }, Outcome::Done) = (op, outcome)
            && !self.cap(s).is_null()
        {
            self.k.err(format!(
                "{op:?} completed but {s:#x} still holds {:?}",
                self.cap(s)
            ));
        }
        self.k.verify();
        self.log.push((op, preempt, outcome));
        if outcome == Outcome::Preempted {
            self.pending.push(op);
        }
        outcome
    }

    /// Runs a kernel-side action `f` (a TCB install, a `Call`'s reply
    /// capability) and checks every invariant after it.
    fn kernel(&mut self, rule: ParentRule, f: impl FnOnce(&mut Ck)) {
        f(&mut self.k);
        self.k.settle(rule);
        self.k.verify();
        self.assert_clean();
    }

    fn ok(&mut self, op: Op) {
        let r = self.run(op, None);
        assert_eq!(r, Outcome::Done, "{op:?}");
        self.assert_clean();
    }

    fn retype(
        &mut self,
        ut: u64,
        ty: ObjectType,
        size_bits: u64,
        dest: Option<u64>,
        offset: u64,
        n: u64,
    ) {
        self.ok(Op::Retype {
            ut,
            ty: ty as u64,
            size_bits,
            dest,
            offset,
            n,
        });
    }
}

/// How a call's new capabilities get their model parent.
#[derive(Clone, Copy)]
enum ParentRule {
    None,
    /// Boot capabilities: roots.
    Root,
    Copy {
        src_id: Option<u64>,
        original: bool,
    },
    Retype {
        ut_id: Option<u64>,
    },
}

impl ParentRule {
    fn parent(&self, k: &Ck, _a: u64, c: Cap) -> (Option<u64>, bool) {
        match *self {
            ParentRule::None => (None, false),
            ParentRule::Root => (None, true),
            ParentRule::Copy { src_id, original } => {
                let src = src_id.unwrap();
                let p = if k.original[&src] {
                    Some(src)
                } else {
                    k.parent[&src]
                };
                (p, original)
            }
            ParentRule::Retype { ut_id } => {
                if c.cap_type() == CapType::Reply {
                    (None, true)
                } else {
                    (ut_id, true)
                }
            }
        }
    }
}

fn r(i: u64) -> u64 {
    slot(ROOT, i)
}

/// A small deterministic generator for the explorer.
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

    fn pick(&mut self, v: &[u64]) -> Option<u64> {
        if v.is_empty() {
            None
        } else {
            Some(v[self.below(v.len() as u64) as usize])
        }
    }
}

impl World {
    /// A random user operation on reachable slots.
    fn random_op(&self, g: &mut Rng) -> Option<Op> {
        let reach = self.reachable();
        let full: Vec<u64> = reach
            .iter()
            .copied()
            .filter(|a| !self.cap(*a).is_null())
            .collect();
        let empty: Vec<u64> = reach
            .iter()
            .copied()
            .filter(|a| self.cap(*a).is_null())
            .collect();
        let any = |g: &mut Rng| g.pick(&reach);
        let src = |g: &mut Rng| {
            if g.below(10) < 9 {
                g.pick(&full)
            } else {
                any(g)
            }
        };
        let dst = |g: &mut Rng| {
            if g.below(10) < 8 {
                g.pick(&empty)
            } else {
                any(g)
            }
        };
        let data = |g: &mut Rng| match g.below(4) {
            0 => 0,
            1 => g.below(4) + 1,
            2 => cnode_data(g.below(8) as u32, g.below(4)),
            _ => cnode_data(60 + g.below(4) as u32, 0),
        };
        let op = match g.below(24) {
            0..=5 => {
                let uts: Vec<u64> = full
                    .iter()
                    .copied()
                    .filter(|a| self.cap(*a).cap_type() == CapType::Untyped)
                    .collect();
                let ut = g.pick(&uts)?;
                let cnodes: Vec<u64> = full
                    .iter()
                    .copied()
                    .filter(|a| self.cap(*a).cap_type() == CapType::CNode)
                    .collect();
                let dest = if g.below(2) == 0 {
                    None
                } else {
                    g.pick(&cnodes)
                };
                let radix = match dest {
                    None => ROOT_RADIX,
                    Some(d) => self.cap(d).radix(),
                };
                let (ty, size_bits) = match g.below(12) {
                    0 | 1 => (ObjectType::Endpoint, 0),
                    2 => (ObjectType::Notification, 0),
                    3..=6 => (ObjectType::CNode, 1 + g.below(3)),
                    7 | 8 => (ObjectType::Tcb, 0),
                    9 | 10 => (ObjectType::Untyped, 6 + g.below(7)),
                    _ => (ObjectType::Frame4K, 0),
                };
                Op::Retype {
                    ut,
                    ty: ty as u64,
                    size_bits,
                    dest,
                    offset: g.below(1 << radix),
                    n: 1 + g.below(3),
                }
            }
            6..=8 => Op::Copy {
                src: src(g)?,
                dst: dst(g)?,
                rights: g.below(16),
            },
            9..=10 => Op::Mint {
                src: src(g)?,
                dst: dst(g)?,
                rights: g.below(16),
                data: data(g),
            },
            11..=14 => Op::Move {
                src: src(g)?,
                dst: dst(g)?,
            },
            15 => Op::Mutate {
                src: src(g)?,
                dst: dst(g)?,
                data: data(g),
            },
            16..=17 => {
                let s = src(g)?;
                Op::Rotate {
                    dst: if g.below(2) == 0 { s } else { dst(g)? },
                    dst_data: data(g),
                    pivot: src(g)?,
                    pivot_data: data(g),
                    src: s,
                }
            }
            18..=20 => Op::Delete { slot: src(g)? },
            _ => Op::Revoke { slot: src(g)? },
        };
        let tcbs = self.tcbs();
        let op = if self.kernel_ops && !tcbs.is_empty() && g.below(4) == 0 {
            let t = g.pick(&tcbs)?;
            match g.below(4) {
                0 => Op::Copy {
                    src: src(g)?,
                    dst: slot(t, g.below(3)),
                    rights: g.below(16),
                },
                1 => Op::Delete {
                    slot: slot(t, g.below(3)),
                },
                2 => Op::Call {
                    caller: t,
                    callee: g.pick(&tcbs)?,
                },
                _ => Op::Move {
                    src: slot(t, 4),
                    dst: dst(g)?,
                },
            }
        } else {
            op
        };
        // Keep the boot untyped in place most of the time, so the world
        // does not starve.
        let touches_boot = match op {
            Op::Move { src, .. } | Op::Mutate { src, .. } | Op::Delete { slot: src } => src == r(1),
            Op::Rotate { src, pivot, .. } => src == r(1) || pivot == r(1),
            Op::Revoke { slot } => slot == r(1),
            _ => false,
        };
        if touches_boot && g.below(20) != 0 {
            return None;
        }
        Some(op)
    }

    /// Whether a preempted call can restart: every slot it names is still
    /// reachable, and a retype's untyped and destination are still there.
    fn can_restart(&self, op: &Op) -> bool {
        let reach: BTreeSet<u64> = self.reachable().into_iter().collect();
        match *op {
            Op::Delete { slot } => reach.contains(&slot) || self.install_slots().contains(&slot),
            Op::Revoke { slot } => reach.contains(&slot),
            Op::Retype { ut, dest, .. } => {
                reach.contains(&ut)
                    && self.cap(ut).cap_type() == CapType::Untyped
                    && dest.is_none_or(|d| {
                        reach.contains(&d) && self.cap(d).cap_type() == CapType::CNode
                    })
            }
            _ => false,
        }
    }
}

/// The explorer's world for `seed`. Odd seeds start with three untypeds and
/// two CNodes made from the boot untyped; seeds 2 and 3 modulo 4 add the
/// kernel-side calls (TCB installs, `Call`, `CNode_SaveCaller`, with the
/// kernel's TCB finalisation), and 3 modulo 4 has every `finalise` return a
/// cleanup capability. `REVIEW_KERNEL` and `REVIEW_CLEANUP` force those on.
fn explorer_world(seed: u64) -> World {
    let mut w = World::new();
    w.kernel_ops = seed % 4 >= 2 || std::env::var("REVIEW_KERNEL").is_ok();
    w.k.reply_hook = w.kernel_ops;
    w.k.cleanup_all = seed % 4 == 3 || std::env::var("REVIEW_CLEANUP").is_ok();
    if seed % 2 == 1 {
        w.retype(r(1), ObjectType::Untyped, 13, None, 2, 3);
        w.retype(r(1), ObjectType::CNode, 3, None, 5, 2);
    }
    w
}

/// Runs `steps` random calls from `seed`, with random preemption and the
/// preempted calls restarted at random later, checking everything after
/// each. On a broken invariant returns it with the calls made.
fn explore(seed: u64, steps: usize) -> Result<(), (String, Calls)> {
    let mut w = explorer_world(seed);
    let mut g = Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1);
    let mut calls = Vec::new();
    let r = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| {
        for _ in 0..steps {
            let op = if !w.pending.is_empty() && g.below(3) == 0 {
                let i = g.below(w.pending.len() as u64) as usize;
                let op = w.pending.remove(i);
                if !w.can_restart(&op) {
                    continue;
                }
                op
            } else {
                match w.random_op(&mut g) {
                    Some(op) => op,
                    None => continue,
                }
            };
            let pre = if g.below(3) == 0 {
                Some(g.below(6))
            } else {
                None
            };
            calls.push((op, pre));
            w.run(op, pre);
            if !w.k.errors.is_empty() {
                return Err(w.k.errors.join("\n"));
            }
        }
        Ok(())
    }));
    match r {
        Ok(Ok(())) => Ok(()),
        Ok(Err(e)) => Err((e, calls)),
        Err(p) => Err((panic_message(p), calls)),
    }
}

fn panic_message(p: std::boxed::Box<dyn core::any::Any + Send>) -> String {
    p.downcast_ref::<String>()
        .cloned()
        .or_else(|| p.downcast_ref::<&str>().map(|s| s.to_string()))
        .unwrap_or_default()
}

/// Every invariant, after every call of random sequences: copies, mints,
/// moves, mutates, rotates (and swaps), deletes, revokes and retypes on
/// every reachable slot, with random preemption and restarts, plus the
/// kernel-side calls. `REVIEW_SEEDS` and `REVIEW_STEPS` scale it up; the
/// review ran 7,000 seeds of 1,500 to 2,500 calls across the three modes.
#[test]
#[cfg_attr(miri, ignore = "the random explorer is too slow under Miri")]
fn explorer_finds_no_broken_invariant() {
    let var = |name, default| {
        std::env::var(name)
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(default)
    };
    let (seeds, steps) = (var("REVIEW_SEEDS", 24), var("REVIEW_STEPS", 400));
    for seed in 0..seeds as u64 {
        if let Err((e, calls)) = explore(seed, steps) {
            panic!("seed {seed}: {e}\nafter {} calls: {calls:x?}", calls.len());
        }
    }
}

/// Replays `calls` on the explorer's world for `seed`, skipping calls
/// whose slots are no longer reachable; returns the first broken invariant
/// or panic.
fn replay(seed: u64, calls: &[(Op, Option<u64>)]) -> Option<String> {
    let calls = calls.to_vec();
    let r = std::panic::catch_unwind(move || {
        let mut w = explorer_world(seed);
        for (op, pre) in calls {
            if !w.valid(&op) {
                continue;
            }
            w.run(op, pre);
            if !w.k.errors.is_empty() {
                return Some(w.k.errors.join("\n"));
            }
        }
        None
    });
    r.unwrap_or_else(|p| Some(panic_message(p)))
}

/// Delta debugging: a small subsequence of `calls` whose replay still
/// fails with a message containing `pat`.
fn minimize(seed: u64, calls: Vec<(Op, Option<u64>)>, pat: &str) -> Vec<(Op, Option<u64>)> {
    let fails = |v: &[(Op, Option<u64>)]| replay(seed, v).is_some_and(|m| m.contains(pat));
    assert!(fails(&calls), "the sequence does not fail with {pat:?}");
    let mut cur = calls;
    let mut n = 2usize;
    while cur.len() >= 2 {
        let chunk = cur.len().div_ceil(n);
        let mut reduced = false;
        let mut i = 0;
        while i < cur.len() {
            let mut cand = cur[..i].to_vec();
            cand.extend_from_slice(&cur[(i + chunk).min(cur.len())..]);
            if !cand.is_empty() && fails(&cand) {
                cur = cand;
                reduced = true;
                n = (n - 1).max(2);
                break;
            }
            i += chunk;
        }
        if !reduced {
            if chunk == 1 {
                break;
            }
            n = (n * 2).min(cur.len());
        }
    }
    for i in 0..cur.len() {
        if cur[i].1.is_some() {
            let mut cand = cur.clone();
            cand[i].1 = None;
            if fails(&cand) {
                cur = cand;
            }
        }
    }
    cur
}

/// A tool, not a test: shrinks the explorer's failing sequence for
/// `REVIEW_MIN_SEED` (with `REVIEW_STEPS` calls) to the calls that still
/// break an invariant whose message contains `REVIEW_MIN_PAT`, and prints
/// them with the slots after each.
#[test]
#[ignore = "a tool: REVIEW_MIN_SEED, REVIEW_STEPS, REVIEW_MIN_PAT"]
fn minimize_explorer_failure() {
    let seed: u64 = std::env::var("REVIEW_MIN_SEED").unwrap().parse().unwrap();
    let steps: usize = std::env::var("REVIEW_STEPS").unwrap().parse().unwrap();
    let pat = std::env::var("REVIEW_MIN_PAT").unwrap_or_default();
    let (_, calls) = explore(seed, steps).expect_err("no failure");
    let min = minimize(seed, calls, &pat);
    let mut w = explorer_world(seed);
    for (op, pre) in &min {
        if !w.valid(op) {
            std::eprintln!("{op:x?}: skipped, not reachable");
            continue;
        }
        let out = w.run(*op, *pre);
        std::eprintln!("{op:x?} preempt {pre:?}: {out:?}");
        w.dump();
    }
    std::eprintln!("{}", w.k.errors.join("\n"));
}

impl World {
    /// Prints every non-empty slot with its node.
    fn dump(&self) {
        for (a, c) in self.k.caps() {
            let n = self.k.node(a);
            std::eprintln!(
                "   {a:#x}: {:?} {:#x}/{} data {:#x} | depth {} low {} original {} prev {:x?} next {:x?}",
                c.cap_type(),
                c.object(),
                c.size_bits(),
                c.data,
                n.depth(),
                n.low(),
                n.original(),
                n.prev().map(|s| s.get()),
                n.next().map(|s| s.get())
            );
        }
    }
}

impl World {
    /// Whether every slot `op` names is reachable, as a user's call needs.
    fn valid(&self, op: &Op) -> bool {
        let reach: BTreeSet<u64> = self.reachable().into_iter().collect();
        match *op {
            Op::Retype { ut, dest, .. } => {
                reach.contains(&ut)
                    && self.cap(ut).cap_type() == CapType::Untyped
                    && dest.is_none_or(|d| {
                        reach.contains(&d) && self.cap(d).cap_type() == CapType::CNode
                    })
            }
            Op::Copy { src, dst, .. } => {
                reach.contains(&src)
                    && (reach.contains(&dst) || self.install_slots().contains(&dst))
            }
            Op::Move { src, dst } => {
                (reach.contains(&src) || self.tcbs().iter().any(|t| slot(*t, 4) == src))
                    && reach.contains(&dst)
            }
            Op::Mint { src, dst, .. } | Op::Mutate { src, dst, .. } => {
                reach.contains(&src) && reach.contains(&dst)
            }
            Op::Rotate {
                dst, pivot, src, ..
            } => reach.contains(&src) && reach.contains(&dst) && reach.contains(&pivot),
            Op::Delete { slot } => reach.contains(&slot) || self.install_slots().contains(&slot),
            Op::Revoke { slot } => reach.contains(&slot),
            Op::Call { caller, callee } => {
                let t = self.tcbs();
                t.contains(&caller) && t.contains(&callee)
            }
        }
    }

    /// TCBs named by a reachable TCB capability.
    fn tcbs(&self) -> Vec<u64> {
        let mut v: Vec<u64> = self
            .reachable()
            .into_iter()
            .map(|a| self.cap(a))
            .filter(|c| c.cap_type() == CapType::Tcb)
            .map(|c| c.object())
            .collect();
        v.sort();
        v.dedup();
        v
    }

    /// The CSpace, VSpace and IPC-buffer slots of those TCBs, which the
    /// TCB invocations (M5) fill and empty.
    fn install_slots(&self) -> BTreeSet<u64> {
        self.tcbs()
            .into_iter()
            .flat_map(|t| (0..3).map(move |i| slot(t, i)))
            .collect()
    }
}

/// `docs/design.md`, "Resolution", written out with 128-bit arithmetic so
/// no shift can overflow.
fn ref_resolve(
    mem: &FakeMemory,
    root: Cap,
    cptr: u64,
    n: u32,
) -> Result<(u64, u32), LookupFailure> {
    if root.cap_type() != CapType::CNode {
        return Err(LookupFailure::InvalidRoot);
    }
    let bits = |top: u32, width: u32| -> u64 {
        (((cptr as u128) >> (top - width)) & ((1u128 << width) - 1)) as u64
    };
    let mut node = root;
    let mut left = n;
    loop {
        let (g, r, guard) = (node.guard_size(), node.radix(), node.guard());
        if g > left || bits(left, g) != guard {
            return Err(LookupFailure::GuardMismatch {
                bits_left: left,
                guard,
                guard_size: g,
            });
        }
        if r + g > left {
            return Err(LookupFailure::DepthMismatch {
                bits_left: left,
                bits_found: r + g,
            });
        }
        let index = bits(left - g, r);
        left -= r + g;
        let s = node.object() + index * SLOT_SIZE;
        if left == 0 {
            return Ok((s, 0));
        }
        let c = mem.load(sa(s)).cap;
        if c.cap_type() != CapType::CNode {
            return Ok((s, left));
        }
        node = c;
    }
}

/// CSpace addressing (ADR 0011): guard and radix edges, guard size 0 with
/// 64 bits left, guards wider than 58 bits, CNodes that hold capabilities to
/// themselves or to each other, against the reference above.
#[test]
#[cfg_attr(miri, ignore = "many random lookups")]
fn lookups_match_the_reference_resolution() {
    let mut g = Rng(0x1234_5678_9ABC_DEF1);
    let mut kinds = [0u32; 6];
    for round in 0..300 {
        // Four CNodes of radix 1 to 4 at 0x1000, 0x2000, 0x3000, 0x4000.
        let mut mem = FakeMemory::new(0, 0x6000);
        let mut caps = Vec::new();
        for i in 0..4u64 {
            let radix = 1 + g.below(4) as u32;
            let gs = match g.below(5) {
                0 => 0,
                1 => 64 - radix,
                2 => 58 - radix.min(58) + g.below(3) as u32,
                _ => g.below(9) as u32,
            }
            .min(64 - radix);
            let guard = g.next() & low_mask(gs);
            caps.push(Cap::cnode(0x1000 * (i + 1), radix, gs, guard));
        }
        // Scatter CNode capabilities, cycles included, and endpoints.
        for _ in 0..12 {
            let c = caps[g.below(4) as usize];
            let into = caps[g.below(4) as usize];
            let at = slot(into.object(), g.below(1 << into.radix()));
            let what = if g.below(4) == 0 {
                Cap::new(CapType::Endpoint, 0x5000, 5, Rights::ALL, false, 0)
            } else {
                c
            };
            mem.store(
                sa(at),
                Slot {
                    cap: what,
                    node: crate::slot::Node::EMPTY,
                },
            );
        }
        for _ in 0..200 {
            let root = if g.below(30) == 0 {
                Cap::NULL
            } else {
                caps[g.below(4) as usize]
            };
            // Build a CPtr that follows guards most of the time.
            let mut cptr: u128 = 0;
            let mut used = 0u32;
            let mut node = root;
            while node.cap_type() == CapType::CNode && used < 64 {
                let (gs, r) = (node.guard_size(), node.radix());
                if used + gs + r > 64 {
                    break;
                }
                let guard = if g.below(8) == 0 {
                    g.next() & low_mask(gs)
                } else {
                    node.guard()
                };
                let index = g.below(1 << r);
                cptr = (cptr << (gs + r)) | ((guard as u128) << r) | index as u128;
                used += gs + r;
                node = mem.load(sa(slot(node.object(), index))).cap;
                if g.below(4) == 0 {
                    break;
                }
            }
            let pad = g.below(65 - used as u64) as u32;
            cptr = (cptr << pad) | (g.next() as u128 & ((1u128 << pad) - 1));
            let n = if g.below(3) == 0 {
                1 + g.below(64) as u32
            } else {
                used + pad
            };
            let n = n.clamp(1, 64);
            let cptr = if g.below(10) == 0 {
                u64::MAX
            } else {
                cptr as u64
            };
            let want = ref_resolve(&mem, root, cptr, n);
            kinds[match want {
                Ok((_, 0)) => 0,
                Ok(_) => 1,
                Err(LookupFailure::InvalidRoot) => 2,
                Err(LookupFailure::GuardMismatch { .. }) => 3,
                Err(LookupFailure::DepthMismatch { .. }) => 4,
                Err(LookupFailure::MissingCapability { .. }) => 5,
            }] += 1;
            let got = cspace::resolve(&mem, root, cptr, n).map(|(s, l)| (s.get(), l));
            assert_eq!(
                got, want,
                "round {round}: resolve({root:?}, {cptr:#x}, {n})"
            );
            let want_slot = match want {
                Ok((s, 0)) => Ok(s),
                Ok((_, left)) => Err(SyscallError::FailedLookup {
                    source: true,
                    failure: LookupFailure::DepthMismatch {
                        bits_left: left,
                        bits_found: 0,
                    },
                }),
                Err(failure) => Err(SyscallError::FailedLookup {
                    source: true,
                    failure,
                }),
            };
            assert_eq!(
                cspace::lookup_slot(&mem, root, cptr, n as u64, true).map(|s| s.get()),
                want_slot
            );
            assert_eq!(
                cspace::lookup_cap(&mem, root, cptr).map(|s| s.get()),
                ref_resolve(&mem, root, cptr, 64).map(|(s, _)| s)
            );
        }
    }
    assert!(kinds[..5].iter().all(|k| *k > 100), "outcomes {kinds:?}");
}

// Hand-written attacks. Each builds a world through the same calls a root
// task would make (plus kernel-side TCB installs and reply capabilities,
// as M5 will make them), then runs the call under attack with preemption
// at every point, other calls between the restarts, and finally reclaims
// all memory so that the reset and `init_object` checks see any capability
// or slot left behind.

/// A second 64 KiB boot untyped, in root slot 63, for calls between the
/// restarts that must not add descendants of the target.
const UT2: u64 = 0x2_0000;
const SPARE: u64 = 63;

impl World {
    /// A world with the second boot untyped too.
    fn with_spare() -> World {
        let mut w = World::new();
        w.k.scan_end = UT2 + (1 << UT_BITS);
        w.kernel(ParentRule::Root, |k| {
            cdt::insert_root(
                k,
                sa(r(SPARE)),
                Cap::untyped(UT2, UT_BITS, false, 1 << UT_BITS),
            );
        });
        w
    }

    /// The first empty root slot from 40.
    fn free_root(&self) -> Option<u64> {
        (40..SPARE).map(r).find(|a| self.cap(*a).is_null())
    }

    /// Calls between restarts: an endpoint from the spare untyped, a copy
    /// of it, and a delete of the copy.
    fn busy(&mut self) {
        let Some(a) = self.free_root() else { return };
        if self.cap(r(SPARE)).cap_type() != CapType::Untyped {
            return;
        }
        let off = (a - ROOT) / SLOT_SIZE;
        self.retype(r(SPARE), ObjectType::Endpoint, 0, None, off, 1);
        if let Some(b) = self.free_root() {
            self.ok(Op::Copy {
                src: a,
                dst: b,
                rights: 3,
            });
            self.ok(Op::Delete { slot: b });
        }
    }

    /// Revokes the boot untyped and retypes all of it as one untyped, which
    /// resets every byte: the checks in `zero` and `init_object` then see
    /// any capability, slot or unfinalised object left in its region.
    fn reclaim_all(&mut self) {
        if self.cap(r(1)).cap_type() != CapType::Untyped {
            return;
        }
        self.ok(Op::Revoke { slot: r(1) });
        let Some(a) = self.free_root() else { return };
        let off = (a - ROOT) / SLOT_SIZE;
        self.retype(r(1), ObjectType::Untyped, UT_BITS as u64, None, off, 1);
        self.assert_clean();
    }
}

/// Runs `op` on a fresh world from `setup` with the first preemption at
/// point `k`, for every `k` until a run completes unpreempted; between the
/// restarts runs `between`, and at the end reclaims all memory. Every
/// invariant is checked after every call.
fn at_every_point(setup: impl Fn() -> World, op: Op, between: impl Fn(&mut World)) -> u64 {
    for k in 0.. {
        let mut w = setup();
        let mut first = true;
        let mut restarts = 0;
        loop {
            if !w.valid(&op) {
                break;
            }
            let pre = if first { Some(k) } else { Some(restarts % 3) };
            first = false;
            let out = w.run(op, pre);
            w.assert_clean();
            if out != Outcome::Preempted {
                break;
            }
            w.pending.pop();
            restarts += 1;
            assert!(restarts < 10_000, "{op:?} makes no progress");
            between(&mut w);
            w.assert_clean();
        }
        w.reclaim_all();
        if restarts == 0 && k > 0 {
            return k;
        }
    }
    unreachable!()
}

/// No dangling capabilities, CNodes cleared before reuse, deletion
/// terminates: a CNode whose only capability sits in its own last slot,
/// so clearing it deletes the Zombie's own slot first (`end` is the slot).
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn cnode_holding_its_only_capability_in_its_last_slot() {
    let setup = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::CNode, 2, None, 20, 1);
        w.retype(r(1), ObjectType::Endpoint, 0, Some(r(20)), 0, 3);
        let c = w.cap(r(20));
        w.ok(Op::Move {
            src: r(20),
            dst: slot(c.object(), 3),
        });
        w
    };
    let points = at_every_point(setup, Op::Revoke { slot: r(1) }, World::busy);
    assert!(points > 3);
}

/// The same, deleting through a second capability: the root's copy is
/// deleted (not final), then revoke reaches the copy inside.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn deleting_the_slot_that_holds_the_cnode_deleted_through() {
    let setup = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::CNode, 2, None, 20, 1);
        w.retype(r(1), ObjectType::CNode, 1, None, 21, 1);
        let (c, d) = (w.cap(r(20)), w.cap(r(21)));
        w.retype(r(1), ObjectType::Endpoint, 0, Some(r(20)), 0, 2);
        // C[2] holds a copy of C, C[3] the only capability to D, D[0] an
        // endpoint copy, D[1] a copy of C.
        w.ok(Op::Copy {
            src: r(20),
            dst: slot(c.object(), 2),
            rights: 0,
        });
        w.ok(Op::Move {
            src: r(21),
            dst: slot(c.object(), 3),
        });
        w.ok(Op::Copy {
            src: slot(c.object(), 0),
            dst: slot(d.object(), 0),
            rights: 1,
        });
        w.ok(Op::Copy {
            src: r(20),
            dst: slot(d.object(), 1),
            rights: 0,
        });
        w
    };
    // Delete C's root capability, then the copy in C[2] through... nothing:
    // C stays reachable only through D[1], inside C. Revoke reclaims.
    let points = at_every_point(
        || {
            let mut w = setup();
            w.ok(Op::Delete { slot: r(20) });
            w
        },
        Op::Revoke { slot: r(1) },
        World::busy,
    );
    assert!(points > 3);
    // And deleting the root capability of C last, at every point, after
    // C[2] (a copy of C, in C) is gone.
    at_every_point(
        || {
            let mut w = setup();
            let c = w.cap(r(20));
            w.ok(Op::Delete {
                slot: slot(c.object(), 2),
            });
            w
        },
        Op::Delete { slot: r(20) },
        World::busy,
    );
}

/// CNodes in each other's slot 0: each holds the only capability to the
/// other, so clearing one meets the other's last capability in its own
/// slot 0 (seL4's "Expected new Zombie to be self-referential").
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn two_cnodes_in_each_others_slot_0() {
    let setup = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::CNode, 1, None, 20, 2);
        let (a, b) = (w.cap(r(20)), w.cap(r(21)));
        w.retype(r(1), ObjectType::Endpoint, 0, Some(r(20)), 1, 1);
        w.retype(r(1), ObjectType::Endpoint, 0, Some(r(21)), 1, 1);
        w.ok(Op::Move {
            src: r(20),
            dst: slot(b.object(), 0),
        });
        w.ok(Op::Move {
            src: r(21),
            dst: slot(a.object(), 0),
        });
        w
    };
    at_every_point(setup, Op::Revoke { slot: r(1) }, World::busy);
    // The same with A reachable: delete A's last capability, which lives in
    // B[0] while A[0] holds B's: A's Zombie lands in B[0] = D[0] of the
    // nested container.
    let setup2 = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::CNode, 1, None, 20, 2);
        let b = w.cap(r(21));
        w.retype(r(1), ObjectType::Endpoint, 0, Some(r(20)), 1, 1);
        w.retype(r(1), ObjectType::Endpoint, 0, Some(r(21)), 1, 1);
        // Root 20 holds A; A[0] holds B; B[0] holds a copy of A.
        let a = w.cap(r(20));
        w.ok(Op::Move {
            src: r(21),
            dst: slot(a.object(), 0),
        });
        w.ok(Op::Copy {
            src: r(20),
            dst: slot(b.object(), 0),
            rights: 0,
        });
        w
    };
    at_every_point(setup2, Op::Delete { slot: r(20) }, World::busy);
}

/// A TCB and a CNode holding each other's only capability, the TCB's
/// through its CSpace slot (a kernel install, as `TCB_SetSpace` makes it):
/// the TCB's Zombie lands in its own slot 0 and its reply master must
/// still go before the memory is reused.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn tcb_and_cnode_holding_each_other() {
    let setup = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::Tcb, 0, None, 10, 1);
        w.retype(r(1), ObjectType::CNode, 2, None, 20, 1);
        let (t, c) = (w.cap(r(10)), w.cap(r(20)));
        w.retype(r(1), ObjectType::Endpoint, 0, Some(r(20)), 1, 1);
        // Install C as T's CSpace root, then put T in C[3] and drop the
        // root's capability to C.
        w.ok(Op::Copy {
            src: r(20),
            dst: t.object(),
            rights: 0,
        });
        w.ok(Op::Move {
            src: r(10),
            dst: slot(c.object(), 3),
        });
        w.ok(Op::Delete { slot: r(20) });
        w
    };
    at_every_point(setup, Op::Revoke { slot: r(1) }, World::busy);
}

/// Revoke removes every descendant and stops cleanly when a step deletes
/// the CNode holding the revoked slot: an untyped revoked from inside a
/// CNode made from it.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn revoking_an_untyped_from_inside_a_cnode_made_from_it() {
    let setup = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::Untyped, 13, None, 2, 1);
        w.retype(r(2), ObjectType::CNode, 2, None, 20, 1);
        let c = w.cap(r(20));
        w.retype(r(2), ObjectType::Endpoint, 0, Some(r(20)), 1, 2);
        w.retype(r(2), ObjectType::Tcb, 0, None, 21, 1);
        w.ok(Op::Move {
            src: r(2),
            dst: slot(c.object(), 0),
        });
        w
    };
    let c = setup().cap(r(20));
    at_every_point(
        setup,
        Op::Revoke {
            slot: slot(c.object(), 0),
        },
        World::busy,
    );
    // Without preemption: the untyped is gone, and whatever survived (the
    // TCB, retyped last, so revoked first, or not) belongs to the boot
    // untyped now.
    let mut w = setup();
    w.ok(Op::Revoke {
        slot: slot(c.object(), 0),
    });
    assert!(w.cap(r(20)).is_null());
    assert!(w.cap(slot(c.object(), 0)).is_null());
}

/// An untyped whose descendants hold copies of it: revoke the source while
/// its copy, inside a CNode the copy made, has children of its own.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn revoking_an_untyped_whose_copy_lives_in_its_own_descendant() {
    let setup = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::Untyped, 13, None, 2, 1);
        w.ok(Op::Copy {
            src: r(2),
            dst: r(3),
            rights: 0,
        });
        w.retype(r(3), ObjectType::CNode, 2, None, 20, 1);
        let c = w.cap(r(20));
        w.retype(r(3), ObjectType::Endpoint, 0, Some(r(20)), 1, 3);
        w.ok(Op::Move {
            src: r(3),
            dst: slot(c.object(), 0),
        });
        w
    };
    at_every_point(setup, Op::Revoke { slot: r(2) }, World::busy);
    let mut w = setup();
    w.ok(Op::Revoke { slot: r(2) });
    // The copy is gone and the source resets in full.
    assert!(!cdt::has_children(&w.k, sa(r(2))));
    w.retype(r(2), ObjectType::Frame4K, 0, None, 30, 2);
    assert_eq!(w.cap(r(30)).object(), w.cap(r(2)).object());
}

/// Watermarks of copies of copies: memory a source handed out is reset
/// before anything is made there again, and only the newest copy
/// allocates.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn untyped_copies_of_copies_and_their_watermarks() {
    let mut w = World::with_spare();
    w.retype(r(1), ObjectType::Untyped, 12, None, 2, 1);
    w.retype(r(2), ObjectType::Endpoint, 0, None, 10, 1);
    w.ok(Op::Delete { slot: r(10) });
    assert_eq!(w.cap(r(2)).watermark(), 32);
    w.ok(Op::Copy {
        src: r(2),
        dst: r(3),
        rights: 0,
    });
    w.ok(Op::Copy {
        src: r(3),
        dst: r(4),
        rights: 0,
    });
    assert_eq!(
        (
            w.cap(r(2)).watermark(),
            w.cap(r(3)).watermark(),
            w.cap(r(4)).watermark()
        ),
        (4096, 4096, 32)
    );
    // r(2) and r(3) have children, so neither can be copied or allocate.
    assert_eq!(
        w.run(
            Op::Copy {
                src: r(2),
                dst: r(5),
                rights: 0
            },
            None
        ),
        Outcome::Failed(SyscallError::RevokeFirst)
    );
    let full = Op::Retype {
        ut: r(3),
        ty: ObjectType::Endpoint as u64,
        size_bits: 0,
        dest: None,
        offset: 11,
        n: 1,
    };
    assert_eq!(
        w.run(full, None),
        Outcome::Failed(SyscallError::NotEnoughMemory(0))
    );
    // The newest copy resets its stale 32 bytes and allocates from 0.
    w.retype(r(4), ObjectType::Notification, 0, None, 11, 2);
    assert_eq!(w.cap(r(11)).object(), w.cap(r(2)).object());
    // Mint and Move of untyped follow the same rules.
    w.ok(Op::Delete { slot: r(11) });
    w.ok(Op::Delete { slot: r(12) });
    w.ok(Op::Mint {
        src: r(4),
        dst: r(5),
        rights: 0,
        data: 77,
    });
    assert_eq!(w.cap(r(5)).watermark(), 128);
    w.ok(Op::Move {
        src: r(5),
        dst: r(6),
    });
    w.retype(r(6), ObjectType::Endpoint, 0, None, 13, 1);
    // Deleting the middle copy hands the grandchild to the source.
    w.ok(Op::Delete { slot: r(3) });
    assert_eq!(cdt::parent(&w.k, sa(r(4))).map(|s| s.get()), Some(r(2)));
    w.reclaim_all();
}

/// A preempted reset keeps "zero at and above the watermark", and other
/// calls before the restart (copying the half-reset untyped, retyping from
/// the copy, moving it back) cannot make the restart overlap a live object.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn preempted_reset_with_calls_before_the_restart() {
    let op = Op::Retype {
        ut: r(2),
        ty: ObjectType::Frame4K as u64,
        size_bits: 0,
        dest: None,
        offset: 10,
        n: 2,
    };
    let setup = || {
        let mut w = World::with_spare();
        w.retype(r(1), ObjectType::Untyped, 15, None, 2, 1);
        // Dirty all of it, then free it again.
        w.retype(r(2), ObjectType::Frame4K, 0, None, 20, 8);
        for i in 0..8 {
            w.ok(Op::Delete { slot: r(20 + i) });
        }
        w
    };
    let interleavings: [fn(&mut World); 3] = [
        |w| {
            // Copy the half-reset untyped and allocate from the copy.
            if w.cap(r(3)).is_null() && !cdt::has_children(&w.k, sa(r(2))) {
                w.ok(Op::Copy {
                    src: r(2),
                    dst: r(3),
                    rights: 0,
                });
                w.retype(r(3), ObjectType::Endpoint, 0, None, 30, 1);
            }
        },
        |w| {
            // Move it away and back.
            w.ok(Op::Move {
                src: r(2),
                dst: r(4),
            });
            w.ok(Op::Move {
                src: r(4),
                dst: r(2),
            });
            w.busy();
        },
        |w| {
            // A second retype from it, itself preempted once.
            let other = Op::Retype {
                ut: r(2),
                ty: ObjectType::Endpoint as u64,
                size_bits: 0,
                dest: None,
                offset: 31,
                n: 1,
            };
            if w.cap(r(31)).is_null() {
                let _ = w.run(other, Some(0));
                w.pending.clear();
            }
        },
    ];
    for f in interleavings {
        at_every_point(setup, op, f);
    }
}

/// Depth-limit edges (ADR 0012): at depth 4095 an original cannot have a
/// child by any path, a plain copy can still have siblings, a badge minted
/// from a plain copy at 4095 is an original sibling, and retype's checks
/// before the depth check still win.
#[test]
#[cfg_attr(miri, ignore = "8,000 copy-and-delete steps are too slow under Miri")]
fn depth_limit_edges() {
    let mut w = World::new();
    w.retype(r(1), ObjectType::Untyped, 12, None, 10, 1);
    // Chain to depth 4093 by copy and delete, without checking each step.
    let (mut from, mut to) = (r(10), r(11));
    for _ in 1..MAX_DERIVATION_DEPTH - 2 {
        let src_id = w.id(from);
        cnode::copy(&mut w.k, sa(from), sa(to), 0).unwrap();
        cnode::delete(&mut w.k, sa(from)).unwrap();
        w.k.settle(ParentRule::Copy {
            src_id,
            original: true,
        });
        core::mem::swap(&mut from, &mut to);
    }
    w.k.verify();
    w.assert_clean();
    assert_eq!(w.k.node(from).depth(), MAX_DERIVATION_DEPTH - 2);
    // 4094: an untyped child; 4095: its endpoint, an original.
    w.retype(from, ObjectType::Untyped, 8, None, 20, 1);
    w.retype(r(20), ObjectType::Endpoint, 0, None, 21, 1);
    assert_eq!(w.k.node(r(21)).depth(), MAX_DERIVATION_DEPTH);
    let refused = Outcome::Failed(SyscallError::IllegalOperation);
    assert_eq!(
        w.run(
            Op::Copy {
                src: r(21),
                dst: r(22),
                rights: 15
            },
            None
        ),
        refused
    );
    assert_eq!(
        w.run(
            Op::Mint {
                src: r(21),
                dst: r(22),
                rights: 15,
                data: 9
            },
            None
        ),
        refused
    );
    // An untyped at 4095 cannot retype, but DeleteFirst and NotEnoughMemory
    // come first.
    w.retype(r(20), ObjectType::Untyped, 4, None, 23, 1);
    let at = |off, n, ty: ObjectType| Op::Retype {
        ut: r(23),
        ty: ty as u64,
        size_bits: 0,
        dest: None,
        offset: off,
        n,
    };
    assert_eq!(
        w.run(at(21, 1, ObjectType::Endpoint), None),
        Outcome::Failed(SyscallError::DeleteFirst)
    );
    assert_eq!(
        w.run(at(24, 1, ObjectType::Notification), None),
        Outcome::Failed(SyscallError::NotEnoughMemory(16))
    );
    assert_eq!(
        w.run(at(24, 1, ObjectType::Endpoint), None),
        Outcome::Failed(SyscallError::NotEnoughMemory(16))
    );
    let untyped = Op::Retype {
        ut: r(23),
        ty: ObjectType::Untyped as u64,
        size_bits: 4,
        dest: None,
        offset: 24,
        n: 1,
    };
    assert_eq!(w.run(untyped, None), refused);
    // A plain copy at 4095 (from the 4094 endpoint) has siblings, and a
    // badge minted from it is an original sibling that cannot have
    // children.
    w.retype(from, ObjectType::Endpoint, 0, None, 30, 1);
    assert_eq!(w.k.node(r(30)).depth(), MAX_DERIVATION_DEPTH - 1);
    w.ok(Op::Copy {
        src: r(30),
        dst: r(31),
        rights: 15,
    });
    w.ok(Op::Copy {
        src: r(31),
        dst: r(32),
        rights: 3,
    });
    w.ok(Op::Mint {
        src: r(32),
        dst: r(33),
        rights: 15,
        data: 5,
    });
    assert_eq!(cdt::parent(&w.k, sa(r(33))).map(|s| s.get()), Some(r(30)));
    assert_eq!(w.cap(r(33)).rights(), Rights(3));
    assert_eq!(
        w.run(
            Op::Copy {
                src: r(33),
                dst: r(34),
                rights: 15
            },
            None
        ),
        refused
    );
    // The holder of the boot untyped revokes it all.
    w.reclaim_all();
}

/// Reply capabilities never outlive their TCB (with the kernel's TCB
/// finalisation, which deletes the outstanding reply capability): a
/// `Call`'s reply capability, saved into a CNode next to the caller's only
/// capability, at every preemption point of the CNode's deletion.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn reply_capabilities_with_the_kernels_tcb_finalisation() {
    let setup = |order: bool| {
        let mut w = World::with_spare();
        w.k.reply_hook = true;
        w.retype(r(1), ObjectType::Tcb, 0, None, 10, 2);
        w.retype(r(1), ObjectType::CNode, 2, None, 20, 1);
        let (t1, t2, c) = (w.cap(r(10)), w.cap(r(11)), w.cap(r(20)));
        // T1 calls T2: a reply capability, child of T1's master, in T2's
        // caller slot; T2 saves it (CNode_SaveCaller is a move).
        let master = slot(t1.object(), TCB_SLOT_REPLY);
        let caller = slot(t2.object(), 4);
        let master_id = w.id(master);
        w.kernel(
            ParentRule::Copy {
                src_id: master_id,
                original: false,
            },
            |k| {
                cdt::insert_derived(
                    k,
                    sa(master),
                    sa(caller),
                    Cap::reply(t1.object(), false, true),
                    false,
                )
                .unwrap();
            },
        );
        let (a, b) = if order { (2, 3) } else { (3, 2) };
        w.ok(Op::Move {
            src: caller,
            dst: slot(c.object(), a),
        });
        w.ok(Op::Move {
            src: r(10),
            dst: slot(c.object(), b),
        });
        w
    };
    for order in [false, true] {
        at_every_point(|| setup(order), Op::Delete { slot: r(20) }, World::busy);
        at_every_point(|| setup(order), Op::Revoke { slot: r(1) }, World::busy);
    }
}

/// Error results and their order (`docs/abi.md`, the CNode and Untyped
/// tables), where several apply at once.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn errors_in_the_order_the_abi_lists() {
    let mut w = World::new();
    w.retype(r(1), ObjectType::Endpoint, 0, None, 10, 2);
    w.retype(r(1), ObjectType::CNode, 2, None, 12, 1);
    w.retype(r(1), ObjectType::Untyped, 8, None, 13, 1);
    w.retype(r(13), ObjectType::Endpoint, 0, None, 14, 1);
    let fail = |e| Outcome::Failed(e);
    // Copy: a full destination wins over an empty source.
    assert_eq!(
        w.run(
            Op::Copy {
                src: r(30),
                dst: r(10),
                rights: 0
            },
            None
        ),
        fail(SyscallError::DeleteFirst)
    );
    assert_eq!(
        w.run(
            Op::Copy {
                src: r(30),
                dst: r(31),
                rights: 0
            },
            None
        ),
        fail(EMPTY_SOURCE)
    );
    assert_eq!(
        w.run(
            Op::Copy {
                src: r(13),
                dst: r(31),
                rights: 0
            },
            None
        ),
        fail(SyscallError::RevokeFirst)
    );
    // Mint: a guard that does not fit; a badged source.
    assert_eq!(
        w.run(
            Op::Mint {
                src: r(12),
                dst: r(31),
                rights: 0,
                data: 63
            },
            None
        ),
        fail(SyscallError::IllegalOperation)
    );
    w.ok(Op::Mint {
        src: r(12),
        dst: r(31),
        rights: 0,
        data: 62 | (u64::MAX << 6),
    });
    assert_eq!(w.cap(r(31)).guard(), low_mask(58));
    w.ok(Op::Mint {
        src: r(10),
        dst: r(32),
        rights: 0xF,
        data: 1 << 63,
    });
    assert_eq!(
        w.run(
            Op::Mint {
                src: r(32),
                dst: r(33),
                rights: 0xF,
                data: 0
            },
            None
        ),
        fail(SyscallError::IllegalOperation)
    );
    // Rotate: pivot = source beats a full destination, which beats an
    // empty source, which beats a bad data word.
    let rot = |dst, pivot, src, d| Op::Rotate {
        dst,
        dst_data: d,
        pivot,
        pivot_data: d,
        src,
    };
    assert_eq!(
        w.run(rot(r(10), r(30), r(30), 0), None),
        fail(SyscallError::IllegalOperation)
    );
    assert_eq!(
        w.run(rot(r(10), r(11), r(30), 0), None),
        fail(SyscallError::DeleteFirst)
    );
    assert_eq!(w.run(rot(r(40), r(10), r(30), 0), None), fail(EMPTY_SOURCE));
    assert_eq!(w.run(rot(r(40), r(30), r(10), 0), None), fail(EMPTY_SOURCE));
    assert_eq!(
        w.run(rot(r(40), r(10), r(11), 0), None),
        fail(SyscallError::IllegalOperation)
    );
    // Rotate as a swap of two CNodes, guards applied to each half.
    w.ok(rot(r(12), r(31), r(12), cnode_data(5, 3)));
    assert_eq!(
        (w.cap(r(12)).guard_size(), w.cap(r(31)).guard_size()),
        (5, 5)
    );
    // Mutate: an Endpoint whatever the word, after the slot checks.
    assert_eq!(
        w.run(
            Op::Mutate {
                src: r(10),
                dst: r(11),
                data: 0
            },
            None
        ),
        fail(SyscallError::DeleteFirst)
    );
    assert_eq!(
        w.run(
            Op::Mutate {
                src: r(10),
                dst: r(40),
                data: 0
            },
            None
        ),
        fail(SyscallError::IllegalOperation)
    );
    // Retype from the small untyped: DeleteFirst, then NotEnoughMemory
    // with the bytes free from the watermark, then the device check.
    let rt = |ty: ObjectType, size_bits, off, n| Op::Retype {
        ut: r(13),
        ty: ty as u64,
        size_bits,
        dest: None,
        offset: off,
        n,
    };
    assert_eq!(
        w.run(rt(ObjectType::Frame4K, 0, 14, 1), None),
        fail(SyscallError::DeleteFirst)
    );
    assert_eq!(
        w.run(rt(ObjectType::Frame4K, 0, 40, 1), None),
        fail(SyscallError::NotEnoughMemory(256 - 32))
    );
    assert_eq!(
        w.run(rt(ObjectType::Notification, 0, 40, 4), None),
        fail(SyscallError::NotEnoughMemory(256 - 32))
    );
    w.ok(rt(ObjectType::Notification, 0, 40, 3));
    assert_eq!(w.cap(r(13)).watermark(), 256);
    assert_eq!(
        w.run(rt(ObjectType::Untyped, 3, 50, 1), None),
        fail(SyscallError::RangeError { min: 4, max: 47 })
    );
    assert_eq!(
        w.run(rt(ObjectType::Untyped, 48, 50, 1), None),
        fail(SyscallError::RangeError { min: 4, max: 47 })
    );
    // Fixed-size types ignore size_bits, even 64 and up.
    w.ok(Op::Delete { slot: r(40) });
    w.ok(Op::Delete { slot: r(41) });
    w.ok(Op::Delete { slot: r(42) });
    w.ok(Op::Delete { slot: r(14) });
    w.ok(rt(ObjectType::Endpoint, u64::MAX, 40, 1));
    // A device untyped refuses kernel objects only after the memory check.
    let mut d = World::new();
    d.ok(Op::Delete { slot: r(1) });
    d.kernel(ParentRule::Root, |k| {
        cdt::insert_root(k, sa(r(2)), Cap::untyped(0x1_8000, 8, true, 0));
    });
    let dev = |ty: ObjectType, n| Op::Retype {
        ut: r(2),
        ty: ty as u64,
        size_bits: 0,
        dest: None,
        offset: 20,
        n,
    };
    assert_eq!(
        d.run(dev(ObjectType::Tcb, 1), None),
        fail(SyscallError::NotEnoughMemory(256))
    );
    assert_eq!(
        d.run(dev(ObjectType::Endpoint, 1), None),
        fail(SyscallError::InvalidArgument(0))
    );
}

/// "No capability survives a completed revoke of an ancestor" against
/// "revoke stops cleanly if it deletes the CNode holding its own slot": an
/// untyped revoked from inside a CNode made from it, whose first child is
/// that CNode, deletes itself in the first step, and its other children
/// pass to its parent and survive the revoke, which reports success. The
/// design accepts this (seL4's partial-revoke cases); every other invariant
/// holds.
#[test]
#[cfg_attr(miri, ignore = "the checking kernel scans all memory after every call")]
fn a_revoke_that_deletes_its_own_slot_leaves_later_children() {
    let mut w = World::with_spare();
    w.retype(r(1), ObjectType::Untyped, 13, None, 2, 1);
    w.retype(r(2), ObjectType::Tcb, 0, None, 21, 1);
    w.retype(r(2), ObjectType::Endpoint, 0, None, 22, 2);
    // The CNode last, so it is the untyped's first child.
    w.retype(r(2), ObjectType::CNode, 2, None, 20, 1);
    let c = w.cap(r(20));
    w.ok(Op::Move {
        src: r(22),
        dst: slot(c.object(), 1),
    });
    w.ok(Op::Move {
        src: r(2),
        dst: slot(c.object(), 0),
    });
    w.ok(Op::Revoke {
        slot: slot(c.object(), 0),
    });
    // The untyped and its CNode are gone, with the endpoint inside it; the
    // TCB and the other endpoint survive as children of the boot untyped.
    assert!(w.cap(slot(c.object(), 0)).is_null() && w.cap(r(20)).is_null());
    assert_eq!(w.cap(r(21)).cap_type(), CapType::Tcb);
    assert_eq!(cdt::parent(&w.k, sa(r(21))).map(|s| s.get()), Some(r(1)));
    assert_eq!(cdt::parent(&w.k, sa(r(23))).map(|s| s.get()), Some(r(1)));
    w.reclaim_all();
}
