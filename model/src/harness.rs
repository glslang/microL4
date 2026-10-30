//! The world both implementations live in, and the comparison of the two.
//!
//! A [`World`] is an `l4core` kernel ([`Tracked`], a
//! [`TestKernel`](l4core::testing::TestKernel) over a few MiB of fake memory
//! that also notes which pages were written) and a [`Model`] of the same boot
//! state. [`World::apply`] runs one [`Action`] on both: the model atomically,
//! the kernel with preemption injected and the operation restarted until it
//! completes, checking the invariants at every preemption point. It then
//! compares everything visible and checks the invariants again. Any
//! difference comes back as an `Err` describing it.
//!
//! The boot state:
//!
//! | Address | What |
//! | --- | --- |
//! | `0x10_0000` | a holder of 4 slots, reachable by no `CPtr`; slot 0 holds the root CNode capability, a derivation root |
//! | `0x10_0400` | the root CNode, 32 slots; its capability, with the configured guard, is the root of every user lookup |
//! | `0x11_0000` | a 64 KiB untyped, RAM or device |
//! | `0x20_0000` | a 2 MiB RAM untyped |
//!
//! Both untyped start with their watermark at their size over memory full of
//! garbage, as boot leaves them, so the first retype must clear them. The
//! root CNode holds, in slots 1 to 8: the two untyped, a copy of its own
//! capability, IRQControl and an IRQHandler issued from it, IOPortControl and
//! an IOPort issued from it, and a Hypervisor capability.

use std::collections::{BTreeMap, BTreeSet, VecDeque};

use l4core::cap::{Cap, CapType, Rights, SLOT_SIZE, TCB_BITS};
use l4core::cdt;
use l4core::cnode;
use l4core::cspace;
use l4core::error::{LookupFailure, SyscallError};
use l4core::kernel::{Kernel, Preempted};
use l4core::slot::{Slot, SlotAddr, SlotMemory};
use l4core::testing::{Event, TestKernel};
use l4core::untyped::{self, RetypeArgs, RetypeError};

use crate::model::{Model, ObjId, slot_at};

/// The first byte of fake memory.
pub const MEM_BASE: u64 = 0x10_0000;
/// The first byte past fake memory.
pub const MEM_END: u64 = 0x40_0000;
/// The holder of the root CNode capability: 4 slots no lookup reaches.
pub const HOLDER: u64 = 0x10_0000;
const HOLDER_SLOTS: u64 = 4;
/// The root CNode.
pub const ROOT: u64 = 0x10_0400;
pub const ROOT_RADIX: u32 = 5;
/// The small boot untyped, 64 KiB, RAM or device.
pub const SMALL_UNTYPED: u64 = 0x11_0000;
pub const SMALL_UNTYPED_BITS: u32 = 16;
/// The large boot untyped, 2 MiB of RAM.
pub const BIG_UNTYPED: u64 = 0x20_0000;
pub const BIG_UNTYPED_BITS: u32 = 21;

/// Root CNode slots of the boot capabilities.
pub mod boot {
    pub const SMALL_UNTYPED: u64 = 1;
    pub const BIG_UNTYPED: u64 = 2;
    pub const ROOT_COPY: u64 = 3;
    pub const IRQ_CONTROL: u64 = 4;
    pub const IRQ_HANDLER: u64 = 5;
    pub const IO_PORT_CONTROL: u64 = 6;
    pub const IO_PORT: u64 = 7;
    pub const HYPERVISOR: u64 = 8;
}

const PAGE_BITS: u32 = 12;
const PAGE: u64 = 1 << PAGE_BITS;

/// [`TestKernel`] plus two things it does not record:
///
/// - the pages every write touched, so the harness can keep an exact set of
///   the pages that are not all zero without scanning megabytes after every
///   step;
/// - the back-reference each mapped capability (a Frame or paging structure
///   with a mapping record) would have, kept from `moved` and `finalise` as
///   the paging code will keep it (ADR 0005). `moved` must name the slot the
///   capability was in, and `finalise` must find it still in its slot, before
///   the slot empties; the harness checks the rest at every preemption point.
#[derive(Clone, Debug)]
pub struct Tracked {
    pub k: TestKernel,
    dirty: BTreeSet<u64>,
    backrefs: BTreeMap<(u64, u64), SlotAddr>,
    /// Hook calls that broke the back-reference rules.
    violations: Vec<String>,
}

impl Tracked {
    fn mark(&mut self, paddr: u64, len: u64) {
        if len == 0 {
            return;
        }
        for page in (paddr >> PAGE_BITS)..=((paddr + len - 1) >> PAGE_BITS) {
            self.dirty.insert(page);
        }
    }

    /// Every back-reference names a slot holding its capability, and no hook
    /// broke the rules.
    fn check_backrefs(&mut self) -> Result<(), String> {
        if let Some(v) = self.violations.pop() {
            return Err(v);
        }
        for (&(header, data), &at) in &self.backrefs {
            let held = self.k.load(at).cap;
            ensure(held == Cap { data, header }, || {
                format!(
                    "the back-reference of {:?} names {at:?}, which holds {held:?}",
                    Cap { data, header }
                )
            })?;
        }
        Ok(())
    }
}

impl SlotMemory for Tracked {
    fn load(&self, at: SlotAddr) -> Slot {
        self.k.load(at)
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        self.mark(at.get(), SLOT_SIZE);
        self.k.store(at, slot)
    }
}

impl Kernel for Tracked {
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
        // A mapped capability is unmapped when deleted, while its slot still
        // holds it.
        if let Some(at) = self.backrefs.remove(&(cap.header, cap.data)) {
            let held = self.k.load(at).cap;
            if held != cap {
                self.violations.push(format!(
                    "finalise({cap:?}) with its back-reference slot {at:?} holding {held:?}"
                ));
            }
        }
        self.k.finalise(cap, last)
    }

    fn after_delete(&mut self, cleanup: Cap) {
        self.k.after_delete(cleanup)
    }

    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        if let Some(at) = self.backrefs.get_mut(&(cap.header, cap.data)) {
            if *at != from {
                self.violations.push(format!(
                    "moved({cap:?}, {from:?}, {to:?}) but its back-reference names {at:?}"
                ));
            }
            *at = to;
        }
        self.k.moved(cap, from, to)
    }

    fn zero(&mut self, paddr: u64, len: u64) {
        self.mark(paddr, len);
        self.k.zero(paddr, len)
    }

    fn init_object(&mut self, cap: Cap) {
        if let Some(off) = TestKernel::dirt_offset(&cap) {
            self.mark(cap.object() + off, 8);
        }
        self.k.init_object(cap)
    }

    fn preempt(&mut self) -> Result<(), Preempted> {
        self.k.preempt()
    }
}

/// One operation, with every slot argument already resolved.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    Copy {
        src: SlotAddr,
        dst: SlotAddr,
        rights: u64,
    },
    Mint {
        src: SlotAddr,
        dst: SlotAddr,
        rights: u64,
        data: u64,
    },
    Move {
        src: SlotAddr,
        dst: SlotAddr,
    },
    Mutate {
        src: SlotAddr,
        dst: SlotAddr,
        data: u64,
    },
    Rotate {
        dst: SlotAddr,
        dst_data: u64,
        pivot: SlotAddr,
        pivot_data: u64,
        src: SlotAddr,
    },
    Delete {
        slot: SlotAddr,
    },
    Revoke {
        slot: SlotAddr,
    },
    /// `dest` is the capability the destination lookup found.
    Retype {
        untyped: SlotAddr,
        dest: Cap,
        args: RetypeArgs,
    },
    /// A derived, plain copy of a non-untyped capability into an empty TCB
    /// slot, as `TCB_Configure` will install one (M5): `cnode::derive`, then
    /// `cdt::insert_derived`.
    DeriveInto {
        src: SlotAddr,
        dst: SlotAddr,
    },
    /// Writes the mapping record of a Frame or paging structure, as
    /// `l4core::vspace` will (M5), so that derivation, moves and Mint can be
    /// seen to clear or keep it.
    SetMapping {
        slot: SlotAddr,
        record: u64,
    },
    /// `resolve` (when `depth <= 64`), `lookup_cap` and `lookup_slot`.
    Lookup {
        root: Cap,
        cptr: u64,
        depth: u64,
        source: bool,
    },
}

/// What an action returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Done(Result<(), SyscallError>),
    Lookup {
        resolve: Option<Result<(SlotAddr, u32), LookupFailure>>,
        cap: Result<SlotAddr, LookupFailure>,
        slot: Result<SlotAddr, SyscallError>,
    },
}

/// The boot choices a world can vary.
#[derive(Clone, Copy, Debug)]
pub struct Config {
    /// The guard of the root CNode capability every lookup starts from.
    pub root_guard_size: u32,
    pub root_guard: u64,
    /// Whether the 64 KiB untyped is device memory.
    pub small_device: bool,
    /// Seeds the garbage boot leaves in untyped memory.
    pub seed: u64,
}

impl Default for Config {
    fn default() -> Config {
        Config {
            root_guard_size: 0,
            root_guard: 0,
            small_device: false,
            seed: 1,
        }
    }
}

/// An `l4core` kernel and the model, side by side.
pub struct World {
    pub k: Tracked,
    pub m: Model,
    /// The root CNode capability, held in the holder's slot 0.
    pub root: Cap,
    /// Pages of fake memory that are not all zero.
    nz: BTreeSet<u64>,
    /// Preemptions the last action met.
    pub preemptions: u64,
    /// The hook calls of the last action, in the kernel's order.
    pub last_events: Vec<Event>,
    /// Actions applied.
    pub steps: u64,
    /// Revokes that destroyed their own slot and stopped (see
    /// `check_partial_revoke`).
    pub partial_revokes: u64,
    /// If set, counts each action kind with its result, for coverage
    /// reports.
    pub tally: Option<BTreeMap<String, u64>>,
}

/// An action's kind and the gist of its result, for [`World::tally`].
fn tally_key(action: &Action, outcome: &Outcome) -> String {
    let kind = format!("{action:?}");
    let kind = kind.split([' ', '{']).next().unwrap_or("");
    let result = match outcome {
        Outcome::Done(Ok(())) => "ok".to_string(),
        Outcome::Done(Err(SyscallError::FailedLookup { failure, .. })) => {
            format!("FailedLookup {failure:?}")
        }
        Outcome::Done(Err(e)) => format!("{e:?}"),
        Outcome::Lookup { slot: Ok(_), .. } => "ok".to_string(),
        Outcome::Lookup { slot: Err(e), .. } => format!("{e:?}"),
    };
    let result: String = result
        .split(['(', '{'])
        .next()
        .unwrap_or("")
        .trim()
        .to_string();
    format!("{kind:<10} {result}")
}

/// The slot `index` of the CNode `cnode` names.
pub fn cnode_slot(cnode: Cap, index: u64) -> SlotAddr {
    slot_at(cnode.object(), index)
}

/// The root CNode's slot `index`.
pub fn root_slot(index: u64) -> SlotAddr {
    slot_at(ROOT, index)
}

fn ensure(ok: bool, what: impl FnOnce() -> String) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what()) }
}

/// Every slot of the containers, each once.
fn all_slots(containers: &BTreeSet<(SlotAddr, u64)>) -> BTreeSet<SlotAddr> {
    containers
        .iter()
        .flat_map(|&(base, n)| (0..n).map(move |i| base.offset(i)))
        .collect()
}

/// A sort key for hook events, which have no order of their own.
fn event_key(e: &Event) -> (u8, u64, u64, u64, u64) {
    match *e {
        Event::Finalise { cap, last } => (0, cap.header, cap.data, last as u64, 0),
        Event::AfterDelete(cap) => (1, cap.header, cap.data, 0, 0),
        Event::Moved { cap, from, to } => (2, cap.header, cap.data, from.get(), to.get()),
        Event::Zero { paddr, len } => (3, paddr, len, 0, 0),
        Event::InitObject(cap) => (4, cap.header, cap.data, 0, 0),
    }
}

/// The object a capability with memory names, as (type, address, size):
/// a Zombie names its container and a reply capability its TCB.
fn named_object(cap: &Cap) -> Option<(CapType, u64, u32)> {
    match cap.cap_type() {
        CapType::Null
        | CapType::IrqControl
        | CapType::IrqHandler
        | CapType::IoPortControl
        | CapType::IoPort
        | CapType::Hypervisor => None,
        CapType::Zombie => {
            let ty = if cap.zombie_is_tcb() {
                CapType::Tcb
            } else {
                CapType::CNode
            };
            Some((ty, cap.object(), cap.size_bits()))
        }
        CapType::Reply => Some((CapType::Tcb, cap.object(), TCB_BITS)),
        ty => Some((ty, cap.object(), cap.size_bits())),
    }
}

impl World {
    /// The boot state described in the module documentation, in both.
    pub fn new(cfg: &Config) -> World {
        let mut k = Tracked {
            k: TestKernel::new(MEM_BASE, MEM_END - MEM_BASE),
            dirty: BTreeSet::new(),
            backrefs: BTreeMap::new(),
            violations: Vec::new(),
        };
        // Boot leaves untyped memory full of garbage.
        let mut x = cfg.seed | 1;
        for (base, bits) in [
            (SMALL_UNTYPED, SMALL_UNTYPED_BITS),
            (BIG_UNTYPED, BIG_UNTYPED_BITS),
        ] {
            for page in (base..base + (1 << bits)).step_by(PAGE as usize) {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                for off in [0, 8 * (x % 512), PAGE - 8] {
                    k.k.mem.write(page + off, x | 1);
                }
            }
        }
        let mut m = Model::new();
        let root = Cap::cnode(ROOT, ROOT_RADIX, cfg.root_guard_size, cfg.root_guard);
        let root_obj = m.add_object(CapType::CNode, ROOT, root.size_bits(), false, None);
        let small = Cap::untyped(
            SMALL_UNTYPED,
            SMALL_UNTYPED_BITS,
            cfg.small_device,
            1 << SMALL_UNTYPED_BITS,
        );
        let small_obj = m.add_object(
            CapType::Untyped,
            SMALL_UNTYPED,
            SMALL_UNTYPED_BITS,
            cfg.small_device,
            None,
        );
        let big = Cap::untyped(BIG_UNTYPED, BIG_UNTYPED_BITS, false, 1 << BIG_UNTYPED_BITS);
        let big_obj = m.add_object(CapType::Untyped, BIG_UNTYPED, BIG_UNTYPED_BITS, false, None);
        let holder0 = slot_at(HOLDER, 0);
        let none = |ty, data| Cap::new(ty, 0, 0, Rights::NONE, false, data);

        cdt::insert_root(&mut k, holder0, root);
        m.insert_root(holder0, root, Some(root_obj));
        for (slot, cap, obj) in [
            (boot::SMALL_UNTYPED, small, Some(small_obj)),
            (boot::BIG_UNTYPED, big, Some(big_obj)),
            (boot::IRQ_CONTROL, none(CapType::IrqControl, 0), None),
            (boot::IO_PORT_CONTROL, none(CapType::IoPortControl, 0), None),
            (boot::HYPERVISOR, none(CapType::Hypervisor, 0), None),
        ] {
            cdt::insert_root(&mut k, root_slot(slot), cap);
            m.insert_root(root_slot(slot), cap, obj);
        }
        for (src, dst, cap, original, obj) in [
            (
                holder0,
                root_slot(boot::ROOT_COPY),
                root,
                false,
                Some(root_obj),
            ),
            (
                root_slot(boot::IRQ_CONTROL),
                root_slot(boot::IRQ_HANDLER),
                none(CapType::IrqHandler, 7),
                true,
                None,
            ),
            (
                root_slot(boot::IO_PORT_CONTROL),
                root_slot(boot::IO_PORT),
                none(CapType::IoPort, 0x3F8 | (8 << 16)),
                true,
                None,
            ),
        ] {
            cdt::insert_derived(&mut k, src, dst, cap, original).unwrap();
            m.insert_derived(src, dst, cap, original, obj).unwrap();
        }
        k.k.events.clear();
        let mut w = World {
            k,
            m,
            root,
            nz: BTreeSet::new(),
            preemptions: 0,
            last_events: Vec::new(),
            steps: 0,
            partial_revokes: 0,
            tally: None,
        };
        for page in (MEM_BASE >> PAGE_BITS)..(MEM_END >> PAGE_BITS) {
            w.k.dirty.insert(page);
        }
        w.refresh_nz();
        w
    }

    /// Recomputes, for every page written since the last call, whether it is
    /// all zero.
    fn refresh_nz(&mut self) {
        for page in std::mem::take(&mut self.k.dirty) {
            if self.k.k.mem.is_zero(page << PAGE_BITS, PAGE) {
                self.nz.remove(&page);
            } else {
                self.nz.insert(page);
            }
        }
    }

    /// The kernel's slot, read only if its page is not all zero.
    fn impl_slot(&self, at: SlotAddr) -> Slot {
        if self.nz.contains(&(at.get() >> PAGE_BITS)) {
            self.k.load(at)
        } else {
            Slot::EMPTY
        }
    }

    /// Every slot a user can name: each slot of each CNode reachable from
    /// the root through CNode capabilities, in address order.
    pub fn reachable(&self) -> Vec<SlotAddr> {
        self.paths(self.root).into_keys().collect()
    }

    /// Every slot reachable from the CNode capability `root`, with the
    /// `CPtr` bits and depth of a lookup from `root` that ends there, if it
    /// fits in 64 bits (the first path found, breadth first).
    pub fn paths(&self, root: Cap) -> BTreeMap<SlotAddr, Option<(u64, u32)>> {
        let mut out = BTreeMap::new();
        if root.cap_type() != CapType::CNode {
            return out;
        }
        let mut seen = BTreeSet::new();
        let mut queue = VecDeque::from([(root, Some((0u64, 0u32)))]);
        while let Some((cnode, path)) = queue.pop_front() {
            if !seen.insert(cnode.object()) {
                continue;
            }
            let (gs, radix) = (cnode.guard_size(), cnode.radix());
            for i in 0..(1u64 << radix) {
                let slot = cnode_slot(cnode, i);
                let here = path.and_then(|(bits, n)| {
                    let n2 = n + gs + radix;
                    (n2 <= 64).then(|| {
                        let wide = ((bits as u128) << (gs + radix))
                            | ((cnode.guard() as u128) << radix)
                            | i as u128;
                        (wide as u64, n2)
                    })
                });
                out.entry(slot).or_insert(here);
                let cap = self.m.cap(slot);
                if cap.cap_type() == CapType::CNode && !seen.contains(&cap.object()) {
                    queue.push_back((cap, here));
                }
            }
        }
        out
    }

    /// Every container slot range to compare: live CNodes and TCBs, and the
    /// holder.
    fn containers(&self) -> BTreeSet<(SlotAddr, u64)> {
        let mut c: BTreeSet<_> = self.m.containers().into_iter().collect();
        c.insert((slot_at(HOLDER, 0), HOLDER_SLOTS));
        c
    }

    /// The (type, address, size) of every live object.
    fn live_keys(&self) -> BTreeSet<(CapType, u64, u32)> {
        let objs = self.m.objects();
        self.m
            .referenced()
            .into_iter()
            .map(|id| (objs[id].ty, objs[id].paddr, objs[id].size_bits))
            .collect()
    }

    fn untyped_values(&self, containers: &BTreeSet<(SlotAddr, u64)>) -> BTreeSet<(u64, u64)> {
        all_slots(containers)
            .into_iter()
            .map(|at| self.impl_slot(at).cap)
            .filter(|cap| cap.cap_type() == CapType::Untyped)
            .map(|cap| (cap.header, cap.data))
            .collect()
    }

    /// Runs `action` on both and compares them. `schedule` drives
    /// preemption: before the first attempt the kernel preempts after
    /// `schedule[0]` preemption points, before the `k`-th restart after
    /// `schedule[k]`; past its end, never.
    pub fn apply(&mut self, action: &Action, schedule: &[u8]) -> Result<Outcome, String> {
        self.steps += 1;
        let step = self.steps;
        let ctx = |e: String| format!("step {step} {action:?}: {e}");
        let pre_containers = self.containers();
        let pre_live = self.m.referenced();
        let pre_keys = self.live_keys();
        let pre_untyped = self.untyped_values(&pre_containers);
        let pre_watch: BTreeMap<u64, (u64, bool)> = self
            .m
            .entries()
            .iter()
            .filter(|(_, e)| e.cap.cap_type() == CapType::Untyped)
            .map(|(&s, e)| (e.uid, (e.cap.watermark(), self.m.has_children(s))))
            .collect();
        let retyped = match *action {
            Action::Retype { untyped, .. } => {
                Some((untyped, self.m.cap(untyped), self.m.has_children(untyped)))
            }
            _ => None,
        };
        let revoked = match *action {
            Action::Revoke { slot } => self.m.cap(slot),
            _ => Cap::NULL,
        };
        let pre_stray = self.stray_zombies(&pre_containers).len();

        // The model, atomically.
        let expected = self.run_model(action);
        let model_events = self.m.take_events();

        // The kernel, restarted until it completes. Midway, only what existed
        // before can be live: deletion only destroys, and retype creates its
        // objects after the last preemption point.
        self.k.k.events.clear();
        self.k.k.preempt_in = schedule.first().map(|&n| n as u64);
        self.preemptions = 0;
        let got = loop {
            match self.run_impl(action) {
                Ok(outcome) => break outcome,
                Err(Preempted) => {
                    self.preemptions += 1;
                    self.refresh_nz();
                    self.check_impl(&pre_containers, &pre_keys)
                        .map_err(|e| ctx(format!("at preemption {}: {e}", self.preemptions)))?;
                    self.check_untyped_midway(action, retyped, &pre_containers, &pre_untyped)
                        .map_err(|e| ctx(format!("at preemption {}: {e}", self.preemptions)))?;
                    self.k
                        .check_backrefs()
                        .map_err(|e| ctx(format!("at preemption {}: {e}", self.preemptions)))?;
                    self.k.k.preempt_in =
                        schedule.get(self.preemptions as usize).map(|&n| n as u64);
                }
            }
        };
        self.k.k.preempt_in = None;
        self.refresh_nz();
        let mut containers = pre_containers;
        containers.extend(self.containers());
        self.check_partial_revoke(action, revoked, pre_stray, &containers)
            .map_err(ctx)?;

        ensure(got == expected, || {
            format!("kernel returned {got:?}, model {expected:?}")
        })
        .map_err(ctx)?;
        if let Some(t) = &mut self.tally {
            *t.entry(tally_key(action, &got)).or_default() += 1;
        }
        self.last_events = std::mem::take(&mut self.k.k.events);
        self.compare_events(retyped, self.last_events.clone(), model_events)
            .map_err(ctx)?;
        if let Action::Revoke { slot } = *action {
            let left =
                self.k.load(slot).cap.header == revoked.header && cdt::has_children(&self.k, slot);
            ensure(!left, || "revoke left descendants".to_string()).map_err(ctx)?;
        }
        self.k.check_backrefs().map_err(ctx)?;
        if !matches!(action, Action::Lookup { .. }) {
            self.compare_state(&containers).map_err(ctx)?;
            self.check_impl(&containers, &self.live_keys())
                .map_err(ctx)?;
            self.check_model(&pre_live, &pre_watch).map_err(ctx)?;
        }
        Ok(got)
    }

    /// A Revoke whose step deletes its own slot, with the CNode holding it,
    /// or swaps a Zombie into it, stops after that step, preempted or not
    /// (`docs/design.md`, "Slot operations"): seL4's partial revoke
    /// (`cspace.tex`, "Deletion and Revocation"), except that seL4 finishes
    /// the step's container unless a preemption point intervenes. Here the
    /// container keeps what it still holds, its Zombie where the deletion
    /// left it, perhaps outside its own slot 0 in a slot a user can name,
    /// and the model stops the same way, so `compare_state` checks the
    /// result. This counts such revokes, and checks that nothing else adds
    /// a Zombie outside its own container's slot 0.
    fn check_partial_revoke(
        &mut self,
        action: &Action,
        revoked: Cap,
        before: usize,
        containers: &BTreeSet<(SlotAddr, u64)>,
    ) -> Result<(), String> {
        let partial =
            matches!(*action, Action::Revoke { slot } if self.k.load(slot).cap != revoked);
        if partial {
            self.partial_revokes += 1;
        }
        let stray = self.stray_zombies(containers);
        ensure(partial || stray.len() <= before, || {
            format!("{before} Zombies outside their container's slot 0 became {stray:?}")
        })
    }

    /// The slots of `containers` that hold a Zombie outside its own
    /// container's slot 0, with the Zombie.
    fn stray_zombies(&self, containers: &BTreeSet<(SlotAddr, u64)>) -> Vec<(SlotAddr, Cap)> {
        all_slots(containers)
            .into_iter()
            .map(|at| (at, self.impl_slot(at).cap))
            .filter(|(at, cap)| cap.cap_type() == CapType::Zombie && cap.object() != at.get())
            .collect()
    }

    fn run_model(&mut self, action: &Action) -> Outcome {
        let m = &mut self.m;
        Outcome::Done(match *action {
            Action::Copy { src, dst, rights } => m.copy(src, dst, rights),
            Action::Mint {
                src,
                dst,
                rights,
                data,
            } => m.mint(src, dst, rights, data),
            Action::Move { src, dst } => m.move_cap(src, dst),
            Action::Mutate { src, dst, data } => m.mutate(src, dst, data),
            Action::Rotate {
                dst,
                dst_data,
                pivot,
                pivot_data,
                src,
            } => m.rotate(dst, dst_data, pivot, pivot_data, src),
            Action::Delete { slot } => {
                m.delete(slot);
                Ok(())
            }
            Action::Revoke { slot } => {
                m.revoke(slot);
                Ok(())
            }
            Action::Retype {
                untyped,
                dest,
                args,
            } => m.retype(untyped, dest, args),
            Action::DeriveInto { src, dst } => m.derive_into(src, dst),
            Action::SetMapping { slot, record } => {
                m.set_mapping(slot, record);
                Ok(())
            }
            Action::Lookup {
                root,
                cptr,
                depth,
                source,
            } => {
                return Outcome::Lookup {
                    resolve: (depth <= 64).then(|| m.resolve(root, cptr, depth as u32)),
                    cap: m.lookup_cap(root, cptr),
                    slot: m.lookup_slot(root, cptr, depth, source),
                };
            }
        })
    }

    fn run_impl(&mut self, action: &Action) -> Result<Outcome, Preempted> {
        let k = &mut self.k;
        Ok(Outcome::Done(match *action {
            Action::Copy { src, dst, rights } => cnode::copy(k, src, dst, rights),
            Action::Mint {
                src,
                dst,
                rights,
                data,
            } => cnode::mint(k, src, dst, rights, data),
            Action::Move { src, dst } => cnode::move_cap(k, src, dst),
            Action::Mutate { src, dst, data } => cnode::mutate(k, src, dst, data),
            Action::Rotate {
                dst,
                dst_data,
                pivot,
                pivot_data,
                src,
            } => cnode::rotate(k, dst, dst_data, pivot, pivot_data, src),
            Action::Delete { slot } => cnode::delete(k, slot).map(|()| Ok(()))?,
            Action::Revoke { slot } => cnode::revoke(k, slot).map(|()| Ok(()))?,
            Action::Retype {
                untyped,
                dest,
                args,
            } => match untyped::retype(k, untyped, dest, args) {
                Ok(()) => Ok(()),
                Err(RetypeError::Error(e)) => Err(e),
                Err(RetypeError::Preempted) => return Err(Preempted),
            },
            Action::DeriveInto { src, dst } => cnode::derive(&*k, src).and_then(|cap| {
                cdt::insert_derived(k, src, dst, cap, false)
                    .map_err(|_| SyscallError::IllegalOperation)
            }),
            Action::SetMapping { slot, record } => {
                let mut s = k.load(slot);
                k.backrefs.remove(&(s.cap.header, s.cap.data));
                s.cap = s.cap.with_data(record);
                k.store(slot, s);
                let fresh = k
                    .backrefs
                    .insert((s.cap.header, s.cap.data), slot)
                    .is_none();
                assert!(
                    fresh,
                    "two mapped capabilities with one value; give each a new record"
                );
                Ok(())
            }
            Action::Lookup {
                root,
                cptr,
                depth,
                source,
            } => {
                return Ok(Outcome::Lookup {
                    resolve: (depth <= 64).then(|| cspace::resolve(&*k, root, cptr, depth as u32)),
                    cap: cspace::lookup_cap(&*k, root, cptr),
                    slot: cspace::lookup_slot(&*k, root, cptr, depth, source),
                });
            }
        }))
    }

    /// The hooks: `finalise`, `after_delete`, `moved` and `init_object` as
    /// multisets equal to the model's; every `zero` inside the untyped a
    /// retype resets, and only when it is RAM without children.
    fn compare_events(
        &self,
        retyped: Option<(SlotAddr, Cap, bool)>,
        events: Vec<Event>,
        mut expected: Vec<Event>,
    ) -> Result<(), String> {
        let (zeros, mut got): (Vec<Event>, Vec<Event>) = events
            .into_iter()
            .partition(|e| matches!(e, Event::Zero { .. }));
        for z in &zeros {
            let Event::Zero { paddr, len } = *z else {
                unreachable!()
            };
            let Some((_, ut, had_children)) = retyped else {
                return Err(format!("{z:?} outside a retype"));
            };
            ensure(!ut.is_device() && !had_children, || {
                format!("{z:?} resets {ut:?}, which is device memory or has children")
            })?;
            let end = ut.object() + (1u64 << ut.size_bits());
            ensure(paddr >= ut.object() && paddr + len <= end, || {
                format!("{z:?} outside the untyped {ut:?}")
            })?;
        }
        got.sort_by_key(event_key);
        expected.sort_by_key(event_key);
        ensure(got == expected, || {
            format!("hooks differ:\n  kernel {got:?}\n  model  {expected:?}")
        })
    }

    /// Every slot of every container, with its derivation node, against the
    /// model.
    fn compare_state(&self, containers: &BTreeSet<(SlotAddr, u64)>) -> Result<(), String> {
        let mut neighbours: BTreeMap<SlotAddr, (Option<SlotAddr>, Option<SlotAddr>)> =
            BTreeMap::new();
        for list in self.m.lists() {
            for (i, &s) in list.iter().enumerate() {
                let prev = i.checked_sub(1).map(|j| list[j]);
                neighbours.insert(s, (prev, list.get(i + 1).copied()));
            }
        }
        let finality = self.finality();
        let mut seen = 0usize;
        for at in all_slots(containers) {
            let slot = self.impl_slot(at);
            let want = self.m.cap(at);
            ensure(slot.cap == want, || {
                format!("slot {at:?} holds {:?}, model {want:?}", slot.cap)
            })?;
            let Some(e) = self.m.entry(at) else {
                ensure(slot == Slot::EMPTY, || {
                    format!("empty slot {at:?} has a node {:?}", slot.node)
                })?;
                continue;
            };
            seen += 1;
            let what = |field: &str, got: String, want: String| {
                format!("slot {at:?} ({:?}): {field} is {got}, model {want}", e.cap)
            };
            ensure(slot.node.original() == e.original, || {
                what(
                    "original",
                    slot.node.original().to_string(),
                    e.original.to_string(),
                )
            })?;
            ensure(slot.node.depth() == e.depth, || {
                what("depth", slot.node.depth().to_string(), e.depth.to_string())
            })?;
            let parent = cdt::parent(&self.k, at);
            ensure(parent == self.m.parent(at), || {
                what(
                    "parent",
                    format!("{parent:?}"),
                    format!("{:?}", self.m.parent(at)),
                )
            })?;
            let fin = cdt::is_final(&self.k, at);
            let want_fin = finality[&at];
            ensure(fin == want_fin, || {
                what("is_final", fin.to_string(), want_fin.to_string())
            })?;
            let kids = cdt::has_children(&self.k, at);
            ensure(kids == !e.children.is_empty(), || {
                what(
                    "has_children",
                    kids.to_string(),
                    (!e.children.is_empty()).to_string(),
                )
            })?;
            let (prev, next) = neighbours[&at];
            ensure(slot.node.prev() == prev && slot.node.next() == next, || {
                what(
                    "list neighbours",
                    format!("{:?}/{:?}", slot.node.prev(), slot.node.next()),
                    format!("{prev:?}/{next:?}"),
                )
            })?;
        }
        ensure(seen == self.m.entries().len(), || {
            "the model has capabilities outside every live container".to_string()
        })
    }

    /// [`Model::is_final`] for every slot at once. Capabilities that name the
    /// same object have the same type and address, so only those are
    /// compared; `Cap::same_object` still decides.
    fn finality(&self) -> BTreeMap<SlotAddr, bool> {
        let mut buckets: BTreeMap<(CapType, u64), Vec<(SlotAddr, Cap)>> = BTreeMap::new();
        for (&s, e) in self.m.entries() {
            buckets
                .entry((e.cap.cap_type(), e.cap.object()))
                .or_default()
                .push((s, e.cap));
        }
        let mut out = BTreeMap::new();
        for bucket in buckets.values() {
            for &(s, c) in bucket {
                out.insert(
                    s,
                    !bucket.iter().any(|&(s2, c2)| s2 != s && c2.same_object(&c)),
                );
            }
        }
        out
    }

    /// Invariants of the kernel's state, at every preemption point and after
    /// every step: the list invariants of every slot, zero memory above every
    /// RAM untyped's watermark, rights that only shrink down the tree, and no
    /// capability to an object that is not live.
    fn check_impl(
        &self,
        containers: &BTreeSet<(SlotAddr, u64)>,
        live: &BTreeSet<(CapType, u64, u32)>,
    ) -> Result<(), String> {
        let mut untyped = BTreeSet::new();
        for at in all_slots(containers) {
            let slot = self.impl_slot(at);
            if slot == Slot::EMPTY {
                continue;
            }
            cdt::check_slot(&self.k, at).map_err(|e| format!("check_slot({at:?}): {e}"))?;
            let cap = slot.cap;
            if let Some(key) = named_object(&cap) {
                ensure(live.contains(&key), || {
                    format!("slot {at:?} holds {cap:?}, naming no live object")
                })?;
            }
            if cap.cap_type() == CapType::Untyped && !cap.is_device() {
                untyped.insert((cap.object(), cap.size_bits(), cap.watermark()));
            }
            if let Some(p) = cdt::parent(&self.k, at) {
                let pc = self.k.load(p).cap;
                ensure(
                    pc.cap_type() != cap.cap_type() || pc.rights().contains(cap.rights()),
                    || format!("slot {at:?} holds {cap:?} with more rights than its parent {pc:?}"),
                )?;
            }
        }
        for (base, bits, wm) in untyped {
            let size = 1u64 << bits;
            ensure(wm <= size, || {
                format!("untyped {base:#x} has watermark {wm:#x} past its size")
            })?;
            self.check_zero(base + wm, base + size).map_err(|e| {
                format!("untyped {base:#x}/{bits} above its watermark {wm:#x}: {e}")
            })?;
        }
        Ok(())
    }

    /// Whether `[from, to)` is all zero: words in partial pages, the
    /// not-all-zero page set for whole ones.
    fn check_zero(&self, from: u64, to: u64) -> Result<(), String> {
        let first_full = from.div_ceil(PAGE);
        let last_full = to / PAGE;
        if first_full >= last_full {
            return self.check_zero_words(from, to);
        }
        self.check_zero_words(from, first_full * PAGE)?;
        if let Some(page) = self.nz.range(first_full..last_full).next() {
            return Err(format!("page {:#x} is not zero", page * PAGE));
        }
        self.check_zero_words(last_full * PAGE, to)
    }

    /// Whether `[from, to)`, inside one page, is all zero.
    fn check_zero_words(&self, from: u64, to: u64) -> Result<(), String> {
        if from >= to || !self.nz.contains(&(from >> PAGE_BITS)) {
            return Ok(());
        }
        let mem = &self.k.k.mem;
        ensure(mem.is_zero(from, to - from), || {
            format!("[{from:#x}, {to:#x}) is not zero")
        })
    }

    /// At a preemption point: Delete and Revoke change no watermark, so every
    /// untyped capability is one that existed before; a retype lowers only
    /// its own untyped's watermark, and only while it has no children.
    fn check_untyped_midway(
        &self,
        action: &Action,
        retyped: Option<(SlotAddr, Cap, bool)>,
        containers: &BTreeSet<(SlotAddr, u64)>,
        before: &BTreeSet<(u64, u64)>,
    ) -> Result<(), String> {
        if let Some((slot, ut, had_children)) = retyped {
            let now = self.k.load(slot).cap;
            ensure(now.header == ut.header, || {
                format!("retype changed its untyped to {now:?}")
            })?;
            if now.watermark() < ut.watermark() {
                ensure(!had_children && !cdt::has_children(&self.k, slot), || {
                    format!("{now:?} lowered its watermark with children")
                })?;
            }
        }
        for at in all_slots(containers) {
            let cap = self.impl_slot(at).cap;
            let own = matches!(*action, Action::Retype { untyped, .. } if untyped == at);
            if cap.cap_type() == CapType::Untyped && !own {
                ensure(before.contains(&(cap.header, cap.data)), || {
                    format!("slot {at:?} holds {cap:?}, not an untyped capability from before")
                })?;
            }
        }
        Ok(())
    }

    /// Invariants of the model's state after a step, which equals the
    /// kernel's: live objects pairwise disjoint (but for an untyped and what
    /// was made from it), aligned to their size and inside their untyped;
    /// every capability naming its object; every object finalised exactly
    /// once as its last capability goes; no watermark lowered while its
    /// untyped has children.
    fn check_model(
        &self,
        pre_live: &BTreeSet<ObjId>,
        pre_watch: &BTreeMap<u64, (u64, bool)>,
    ) -> Result<(), String> {
        let objs = self.m.objects();
        let live = self.m.referenced();

        // Each capability names its object.
        for (at, e) in self.m.entries() {
            let key = named_object(&e.cap);
            let obj = e
                .obj
                .map(|id| (objs[id].ty, objs[id].paddr, objs[id].size_bits));
            ensure(key == obj, || {
                format!("model slot {at:?} holds {:?} but names {obj:?}", e.cap)
            })?;
        }

        // Disjoint, aligned, inside the untyped they came from.
        let ancestor = |a: ObjId, mut b: ObjId| loop {
            match objs[b].from {
                Some(p) if p == a => return true,
                Some(p) => b = p,
                None => return false,
            }
        };
        let mut order: Vec<ObjId> = live.iter().copied().collect();
        order.sort_by_key(|&id| (objs[id].paddr, std::cmp::Reverse(objs[id].size_bits), id));
        let mut stack: Vec<ObjId> = Vec::new();
        for &id in &order {
            let o = &objs[id];
            ensure(o.paddr.is_multiple_of(1u64 << o.size_bits), || {
                format!("{o:?} is not aligned to its size")
            })?;
            if let Some(f) = o.from {
                ensure(objs[f].paddr <= o.paddr && o.end() <= objs[f].end(), || {
                    format!("{o:?} lies outside its untyped {:?}", objs[f])
                })?;
            }
            while stack.last().is_some_and(|&t| objs[t].end() <= o.paddr) {
                stack.pop();
            }
            if let Some(&t) = stack.last() {
                ensure(o.end() <= objs[t].end() && ancestor(t, id), || {
                    format!("{o:?} overlaps {:?}", objs[t])
                })?;
            }
            stack.push(id);
        }
        ensure(
            objs.iter()
                .all(|o| o.end() <= MEM_END && o.paddr >= MEM_BASE),
            || "an object lies outside the untyped memory".to_string(),
        )?;

        // Finalised exactly once, before the object goes.
        let hooked = |ty| {
            matches!(
                ty,
                CapType::Tcb
                    | CapType::Endpoint
                    | CapType::Notification
                    | CapType::Frame
                    | CapType::PageTable
                    | CapType::PageDirectory
                    | CapType::Pdpt
                    | CapType::Pml4
            )
        };
        for (id, o) in objs.iter().enumerate() {
            let n = self.m.finalised(id, o.ty);
            ensure(n <= 1, || format!("{o:?} finalised {n} times"))?;
            if pre_live.contains(&id) && !live.contains(&id) && hooked(o.ty) {
                ensure(n == 1, || format!("{o:?} died without being finalised"))?;
                if o.ty == CapType::Tcb {
                    let r = self.m.finalised(id, CapType::Reply);
                    ensure(r == 1, || {
                        format!("{o:?} died with its reply master finalised {r} times")
                    })?;
                }
            }
            if n == 1 && live.contains(&id) {
                // Only a TCB outlives its finalisation, as a Zombie.
                let held_by_zombie = self
                    .m
                    .entries()
                    .values()
                    .any(|e| e.obj == Some(id) && e.cap.cap_type() == CapType::Zombie);
                ensure(o.ty == CapType::Tcb && held_by_zombie, || {
                    format!("{o:?} finalised but still has capabilities")
                })?;
            }
        }

        // An untyped with children keeps its watermark or raises it.
        for e in self.m.entries().values() {
            if let Some(&(wm, had_children)) = pre_watch.get(&e.uid)
                && e.cap.cap_type() == CapType::Untyped
            {
                ensure(!had_children || e.cap.watermark() >= wm, || {
                    format!(
                        "{:?} lowered its watermark from {wm:#x} while it had children",
                        e.cap
                    )
                })?;
            }
        }
        Ok(())
    }
}

/// The harness must notice when the kernel's state drifts from the model's;
/// these tests corrupt the kernel side behind the model's back.
#[cfg(test)]
mod tests {
    use super::*;

    fn retype_endpoint(w: &mut World, slot: u64) {
        let a = Action::Retype {
            untyped: root_slot(boot::BIG_UNTYPED),
            dest: w.root,
            args: RetypeArgs {
                object_type: 2,
                size_bits: 0,
                node_offset: slot,
                num_objects: 1,
            },
        };
        assert_eq!(w.apply(&a, &[]).unwrap(), Outcome::Done(Ok(())));
    }

    fn noop(w: &mut World) -> Result<Outcome, String> {
        w.apply(
            &Action::Delete {
                slot: root_slot(30),
            },
            &[],
        )
    }

    #[test]
    fn a_clean_world_matches() {
        let mut w = World::new(&Config::default());
        retype_endpoint(&mut w, 10);
        noop(&mut w).unwrap();
    }

    #[test]
    fn notices_a_stray_capability() {
        let mut w = World::new(&Config::default());
        let ep = Cap::new(CapType::Endpoint, BIG_UNTYPED, 5, Rights::ALL, false, 0);
        w.k.store(
            root_slot(20),
            Slot {
                cap: ep,
                node: l4core::slot::Node::EMPTY,
            },
        );
        assert!(noop(&mut w).unwrap_err().contains("model Cap"));
    }

    #[test]
    fn notices_a_wrong_parent_or_depth() {
        let mut w = World::new(&Config::default());
        retype_endpoint(&mut w, 10);
        let mut s = w.k.load(root_slot(10));
        s.node = l4core::slot::Node::new(true, 2, 1)
            .with_prev(s.node.prev())
            .with_next(s.node.next());
        w.k.store(root_slot(10), s);
        assert!(noop(&mut w).unwrap_err().contains("depth"));
    }

    #[test]
    fn notices_dirt_above_a_watermark() {
        let mut w = World::new(&Config::default());
        retype_endpoint(&mut w, 10);
        w.k.k.mem.write(BIG_UNTYPED + 0x1_0000, 1);
        w.k.mark(BIG_UNTYPED + 0x1_0000, 8);
        assert!(noop(&mut w).unwrap_err().contains("not zero"));
    }

    #[test]
    fn notices_a_relocation_without_moved() {
        let mut w = World::new(&Config::default());
        let a = Action::Retype {
            untyped: root_slot(boot::BIG_UNTYPED),
            dest: w.root,
            args: RetypeArgs {
                object_type: 5,
                size_bits: 0,
                node_offset: 10,
                num_objects: 1,
            },
        };
        w.apply(&a, &[]).unwrap();
        let map = Action::SetMapping {
            slot: root_slot(10),
            record: 0x11,
        };
        w.apply(&map, &[]).unwrap();
        // Move the frame behind the hooks' back.
        let s = w.k.load(root_slot(10));
        w.k.store(root_slot(11), s);
        w.k.store(root_slot(10), Slot::EMPTY);
        assert!(w.k.check_backrefs().unwrap_err().contains("back-reference"));
    }

    #[test]
    fn notices_a_hook_the_model_did_not_call() {
        let mut w = World::new(&Config::default());
        retype_endpoint(&mut w, 10);
        let ep = w.m.cap(root_slot(10));
        // Pre-arm a spurious event: apply clears the log first, so add it
        // through a deletion the model does not see.
        w.k.k.finalise(ep, true);
        let events = std::mem::take(&mut w.k.k.events);
        assert_eq!(events.len(), 1);
        assert!(w.compare_events(None, events, Vec::new()).is_err());
    }
}
