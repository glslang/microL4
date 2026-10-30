//! The world both implementations live in, and the comparison of the two.
//!
//! A [`World`] is an `l4core` kernel ([`Tracked`], a
//! [`TestKernel`](l4core::testing::TestKernel) over a few MiB of fake memory
//! that also notes which pages were written) and a [`Model`] of the same boot
//! state. [`World::apply`] runs one [`Action`] on both: the model atomically,
//! the kernel with preemption injected and the operation restarted until it
//! completes, checking the invariants at every preemption point. A restart
//! of Delete or Revoke first looks its slot up again, as the kernel's does.
//! It then compares everything visible and checks the invariants again. Any
//! difference comes back as an `Err` describing it. The one exception is a
//! revoke whose restart cannot look its slot up again, which may leave the
//! kernel where the atomic model never is; `World::finish_partial_revoke`
//! checks that it stopped where the same revoke run without preemption
//! passed, and goes on from that run's end.
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
///
/// While a revoke runs it also logs every word it overwrites, so that
/// [`World::finish_partial_revoke`] can rebuild the world from before it.
#[derive(Clone, Debug)]
pub struct Tracked {
    pub k: TestKernel,
    dirty: BTreeSet<u64>,
    backrefs: BTreeMap<(u64, u64), SlotAddr>,
    /// Hook calls that broke the back-reference rules.
    violations: Vec<String>,
    /// If set, each word written and what it held before, in order.
    undo: Option<Vec<(u64, u64)>>,
}

impl Tracked {
    /// Before every write: logs the words `len` bytes from `paddr` hold, if
    /// the undo log is on, and marks their pages.
    fn writing(&mut self, paddr: u64, len: u64) {
        if let Some(log) = &mut self.undo {
            let mem = &self.k.mem;
            log.extend((paddr..paddr + len).step_by(8).map(|a| (a, mem.read(a))));
        }
        self.mark(paddr, len);
    }

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
        self.writing(at.get(), SLOT_SIZE);
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
        self.writing(paddr, len);
        self.k.zero(paddr, len)
    }

    fn init_object(&mut self, cap: Cap) {
        if let Some(off) = TestKernel::dirt_offset(&cap) {
            self.writing(cap.object() + off, 8);
        }
        self.k.init_object(cap)
    }

    fn preempt(&mut self) -> Result<(), Preempted> {
        self.k.preempt()
    }
}

/// A [`Tracked`] kernel that never preempts, for the run a revoke cut short
/// is checked against (see [`World::finish_partial_revoke`]). At each
/// preemption point it notes how many hook calls had been made and whether
/// the kernel's memory and back-references then equalled `target`'s, rather
/// than keep megabytes of memory per point.
struct Unpreempted<'a> {
    k: &'a mut Tracked,
    target: &'a Tracked,
    /// For each preemption point passed, in order: the hook calls made so
    /// far, and whether the state equalled `target`'s.
    points: Vec<(usize, bool)>,
}

impl SlotMemory for Unpreempted<'_> {
    fn load(&self, at: SlotAddr) -> Slot {
        self.k.load(at)
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        self.k.store(at, slot)
    }
}

impl Kernel for Unpreempted<'_> {
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
        self.k.finalise(cap, last)
    }

    fn after_delete(&mut self, cleanup: Cap) {
        self.k.after_delete(cleanup)
    }

    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        self.k.moved(cap, from, to)
    }

    fn zero(&mut self, paddr: u64, len: u64) {
        self.k.zero(paddr, len)
    }

    fn init_object(&mut self, cap: Cap) {
        self.k.init_object(cap)
    }

    fn preempt(&mut self) -> Result<(), Preempted> {
        let same = self.k.k.mem == self.target.k.mem && self.k.backrefs == self.target.backrefs;
        self.points.push((self.k.k.events.len(), same));
        Ok(())
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
    /// Revokes whose work destroyed their slot's lookup path: seL4's partial
    /// revokes (`docs/design.md`, "Slot operations").
    pub partial_revokes: u64,
    /// Of those, the ones a restart could not look up again, so the kernel
    /// left them unfinished (see [`World::finish_partial_revoke`]).
    pub cut_short: u64,
    /// What the last revoke cut short left and returned.
    pub last_partial: Option<PartialRevoke>,
    /// If set, counts each action kind with its result, for coverage
    /// reports.
    pub tally: Option<BTreeMap<String, u64>>,
}

/// A revoke cut short: preempted after its work destroyed its slot's lookup
/// path, so the restarted call failed its lookup and returned.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PartialRevoke {
    /// What the restarted call returned.
    pub error: SyscallError,
    /// The preemption points of the unpreempted revoke, counted from 0, at
    /// which its state and hook calls were what this one left: several when
    /// the steps between them changed nothing.
    pub stops: Vec<u64>,
    /// How many preemption points the unpreempted revoke passed.
    pub points: u64,
    /// Each Zombie it left where the model's end state holds something else,
    /// with its slot, in slot order.
    pub zombies: Vec<(SlotAddr, Cap)>,
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
            undo: None,
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
            cut_short: 0,
            last_partial: None,
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

    /// Plants, in both, what a revoke cut short can leave in the kernel and
    /// the atomic model never has: the last capability to a CNode, in `at`,
    /// turned in place into the CNode's Zombie with `slots_left` slots left
    /// to clear ([`Model::leave_zombie`]). For scenarios that start from such
    /// a leftover; their next action must move that Zombie into its own
    /// CNode's slot 0 or delete it, or `check_model` objects.
    pub fn leave_zombie(&mut self, at: SlotAddr, slots_left: u64) {
        self.m.leave_zombie(at, slots_left);
        let mut s = self.k.load(at);
        s.cap = self.m.cap(at);
        self.k.store(at, s);
        self.refresh_nz();
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
        let named = self.named_slot(action).map_err(ctx)?;
        // A revoke may be cut short, and then rebuilt from before (see
        // `finish_partial_revoke`).
        let saved = matches!(action, Action::Revoke { .. }).then(|| {
            self.k.undo = Some(Vec::new());
            (self.k.backrefs.clone(), self.k.violations.clone())
        });

        // The model, atomically.
        let expected = self.run_model(action);
        let model_events = self.m.take_events();

        // The kernel, restarted until it completes. Midway, only what existed
        // before can be live: deletion only destroys, and retype creates its
        // objects after the last preemption point.
        self.k.k.events.clear();
        self.k.k.preempt_in = schedule.first().map(|&n| n as u64);
        self.preemptions = 0;
        let mut lost = None;
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
                    // The restart looks the slot up again; a failure ends
                    // the call, which returns it.
                    if let Some(e) = self.lookup_again(action, named).map_err(ctx)? {
                        lost = Some(e);
                        break Outcome::Done(Err(e));
                    }
                    self.k.k.preempt_in =
                        schedule.get(self.preemptions as usize).map(|&n| n as u64);
                }
            }
        };
        self.k.k.preempt_in = None;
        self.refresh_nz();
        let mut containers = pre_containers;
        containers.extend(self.containers());
        if let Action::Revoke { .. } = *action
            && (lost.is_some() || self.lookup_again(action, named) != Ok(None))
        {
            self.partial_revokes += 1;
        }
        match (lost, saved, *action) {
            (Some(error), Some(saved), Action::Revoke { slot }) => self
                .finish_partial_revoke(slot, error, expected, &containers, &pre_keys, saved)
                .map_err(ctx)?,
            _ => ensure(got == expected, || {
                format!("kernel returned {got:?}, model {expected:?}")
            })
            .map_err(ctx)?,
        }
        self.k.undo = None;
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

    /// The `CPtr` and depth that name the slot of a Delete or Revoke from the
    /// root, as a user's call names it: the first path [`World::paths`]
    /// finds. A Revoke must have one; a Delete without one, of a slot the
    /// scenario reaches some other way, restarts by its address.
    fn named_slot(&self, action: &Action) -> Result<Option<(u64, u64)>, String> {
        let (Action::Delete { slot } | Action::Revoke { slot }) = *action else {
            return Ok(None);
        };
        let path = self
            .paths(self.root)
            .get(&slot)
            .copied()
            .flatten()
            .map(|(cptr, depth)| (cptr, u64::from(depth)));
        ensure(
            path.is_some() || matches!(action, Action::Delete { .. }),
            || format!("no CPtr names the revoked slot {slot:?}"),
        )?;
        Ok(path)
    }

    /// Looks the slot of a preempted Delete or Revoke up again, through the
    /// path that named it, as the kernel does when it restarts the call
    /// (`docs/design.md`, "System-call dispatch"). `Some` with the lookup's
    /// error if a revoke's work destroyed the path; a Delete's never does.
    fn lookup_again(
        &self,
        action: &Action,
        named: Option<(u64, u64)>,
    ) -> Result<Option<SyscallError>, String> {
        let (Action::Delete { slot } | Action::Revoke { slot }) = *action else {
            return Ok(None);
        };
        let Some((cptr, depth)) = named else {
            return Ok(None);
        };
        match cspace::lookup_slot(&self.k, self.root, cptr, depth, false) {
            Ok(at) if at == slot => Ok(None),
            Ok(at) => Err(format!("the restart looked up {at:?}, not {slot:?}")),
            Err(e) if matches!(action, Action::Revoke { .. }) => Ok(Some(e)),
            Err(e) => Err(format!("a restarted Delete failed its lookup: {e:?}")),
        }
    }

    /// A revoke cut short: preempted after its work destroyed a CNode on its
    /// slot's lookup path, so the restart failed its lookup and the call
    /// returned that error, with work left undone (seL4's partial revoke;
    /// `docs/design.md`, "Slot operations"). This is the one place where the
    /// kernel may end where the atomic model does not. It must have stopped
    /// exactly where the same revoke, run without preemption, passed one of
    /// its preemption points, however many restarts went on before the one
    /// whose lookup failed (`l4core`'s test
    /// `a_revoke_cut_short_stops_where_the_unpreempted_revoke_passed`). So:
    ///
    /// 1. **Safe:** what it left passes `check_impl`'s list and liveness
    ///    invariants, the back-references are exact, and `check_covered`
    ///    finds no capability that could outlive its object.
    /// 2. **Where the unpreempted revoke passed:** the harness rebuilds the
    ///    world from before the call through the undo log, runs the revoke on
    ///    it without preemption, and finds a preemption point of that run
    ///    where the memory and back-references equalled what the revoke cut
    ///    short left, and the hook calls made so far were, in order, the ones
    ///    the revoke cut short made.
    ///
    /// The unpreempted run must return what the model did, and later steps
    /// go on from where it ended, which `apply` compares with the model as
    /// after every other step.
    fn finish_partial_revoke(
        &mut self,
        slot: SlotAddr,
        error: SyscallError,
        expected: Outcome,
        containers: &BTreeSet<(SlotAddr, u64)>,
        live: &BTreeSet<(CapType, u64, u32)>,
        saved: (BTreeMap<(u64, u64), SlotAddr>, Vec<String>),
    ) -> Result<(), String> {
        self.cut_short += 1;
        let left = format!("the revoke cut short with {error:?}");
        self.refresh_nz();
        self.check_impl(containers, live)
            .and_then(|()| self.k.check_backrefs())
            .and_then(|()| self.check_covered(containers))
            .map_err(|e| format!("{left}: {e}"))?;
        let zombies: Vec<(SlotAddr, Cap)> = all_slots(containers)
            .into_iter()
            .map(|at| (at, self.impl_slot(at).cap))
            .filter(|&(at, cap)| cap.cap_type() == CapType::Zombie && self.m.cap(at) != cap)
            .collect();

        let undo = self.k.undo.take().unwrap_or_default();
        let mut whole = self.k.clone();
        for (paddr, old) in undo.into_iter().rev() {
            whole.k.mem.write(paddr, old);
            whole.mark(paddr, 8);
        }
        (whole.backrefs, whole.violations) = saved;
        whole.k.events.clear();
        let mut run = Unpreempted {
            k: &mut whole,
            target: &self.k,
            points: Vec::new(),
        };
        cnode::revoke(&mut run, slot).map_err(|_| "preempted with preemption off")?;
        let points = run.points;
        let again = Outcome::Done(Ok(()));
        ensure(again == expected, || {
            format!("run unpreempted, the kernel returned {again:?}, model {expected:?}")
        })?;

        let (hooks, all) = (&self.k.k.events, &whole.k.events);
        let same: Vec<usize> = (0..points.len()).filter(|&i| points[i].1).collect();
        let Some(&first) = same.first() else {
            return Err(format!(
                "{left} left memory or back-references that the unpreempted revoke had at none \
                 of its {} preemption points",
                points.len()
            ));
        };
        let stops: Vec<u64> = same
            .into_iter()
            .filter(|&i| all[..points[i].0] == hooks[..])
            .map(|i| i as u64)
            .collect();
        ensure(!stops.is_empty(), || {
            format!(
                "{left} left the state the unpreempted revoke had at its preemption point \
                 {first}, but its hook calls differ:\n  cut short   {hooks:?}\n  unpreempted {:?}",
                &all[..points[first].0]
            )
        })?;
        self.k = whole;
        self.refresh_nz();
        self.last_partial = Some(PartialRevoke {
            error,
            stops,
            points: points.len() as u64,
            zombies,
        });
        Ok(())
    }

    /// No capability can outlive its object: every capability naming memory
    /// inside an untyped is that untyped's descendant, so the untyped, which
    /// is reset only when it has none, cannot hand out memory a capability
    /// still names (`docs/design.md`, "Deletion and finalisation",
    /// Invariants). Exempt are reply capabilities, which name a TCB but are
    /// derivation roots, and the untyped capabilities whose memory contains
    /// the untyped's: its ancestors, and the one it was copied from.
    fn check_covered(&self, containers: &BTreeSet<(SlotAddr, u64)>) -> Result<(), String> {
        let held: Vec<(SlotAddr, Slot)> = all_slots(containers)
            .into_iter()
            .map(|at| (at, self.impl_slot(at)))
            .filter(|(_, s)| !s.cap.is_null())
            .collect();
        for &(at, ut) in &held {
            if ut.cap.cap_type() != CapType::Untyped {
                continue;
            }
            let (base, end) = (
                ut.cap.object(),
                ut.cap.object() + (1u64 << ut.cap.size_bits()),
            );
            let mut descendants = BTreeSet::new();
            let mut next = ut.node.next();
            while let Some(n) = next {
                let node = self.k.load(n).node;
                if node.low() <= ut.node.depth() {
                    break;
                }
                descendants.insert(n);
                next = node.next();
            }
            for &(t, s) in &held {
                let Some((_, from, bits)) = named_object(&s.cap) else {
                    continue;
                };
                let to = from + (1u64 << bits);
                let inside = base <= from && to <= end;
                let covers = s.cap.cap_type() == CapType::Untyped && from <= base && end <= to;
                if t == at || s.cap.cap_type() == CapType::Reply || !inside || covers {
                    continue;
                }
                ensure(descendants.contains(&t), || {
                    format!(
                        "{:?} in {t:?} names memory of {:?} in {at:?} but is not its descendant",
                        s.cap, ut.cap
                    )
                })?;
            }
        }
        Ok(())
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

        // Each capability names its object. Every Zombie lies in its own
        // container's slot 0: an atomic deletion either empties its slot or
        // leaves a container detached there, and only a revoke cut short
        // leaves one elsewhere, in the kernel.
        for (at, e) in self.m.entries() {
            let key = named_object(&e.cap);
            let obj = e
                .obj
                .map(|id| (objs[id].ty, objs[id].paddr, objs[id].size_bits));
            ensure(key == obj, || {
                format!("model slot {at:?} holds {:?} but names {obj:?}", e.cap)
            })?;
            ensure(
                e.cap.cap_type() != CapType::Zombie || e.cap.object() == at.get(),
                || format!("model slot {at:?} holds {:?}", e.cap),
            )?;
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
    fn notices_a_capability_outside_its_untyped() {
        let mut w = World::new(&Config::default());
        retype_endpoint(&mut w, 10);
        let containers = w.containers();
        w.check_covered(&containers).unwrap();
        // An endpoint in the big untyped's memory that is not its descendant.
        let ep = Cap::new(
            CapType::Endpoint,
            BIG_UNTYPED + 0x100,
            5,
            Rights::ALL,
            false,
            0,
        );
        cdt::insert_root(&mut w.k, root_slot(20), ep);
        w.refresh_nz();
        let e = w.check_covered(&containers).unwrap_err();
        assert!(e.contains("not its descendant"), "{e}");
    }

    #[test]
    fn a_revoke_needs_a_cptr_that_names_its_slot() {
        let mut w = World::new(&Config::default());
        let e = w
            .apply(
                &Action::Revoke {
                    slot: slot_at(HOLDER, 0),
                },
                &[],
            )
            .unwrap_err();
        assert!(e.contains("no CPtr names"), "{e}");
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

    /// The shape of the scenario
    /// `partial_revoke_of_an_untyped_inside_a_cnode_made_from_it`: the small
    /// untyped in slot 4 of a CNode C made from it, which also made two
    /// endpoints, with C's only capability in root slot 10. Revokes the
    /// untyped, preempted at its first point, and hands what `tamper` makes
    /// of that to `finish_partial_revoke`.
    fn cut_short_revoke(tamper: impl FnOnce(&mut Tracked)) -> (World, Result<(), String>) {
        let mut w = World::new(&Config::default());
        let small = root_slot(boot::SMALL_UNTYPED);
        for (object_type, size_bits, node_offset, num_objects) in [(4, 3, 10, 1), (2, 0, 11, 2)] {
            let args = RetypeArgs {
                object_type,
                size_bits,
                node_offset,
                num_objects,
            };
            let a = Action::Retype {
                untyped: small,
                dest: w.root,
                args,
            };
            w.apply(&a, &[]).unwrap();
        }
        let slot = cnode_slot(w.m.cap(root_slot(10)), 4);
        let moved = Action::Move {
            src: small,
            dst: slot,
        };
        w.apply(&moved, &[]).unwrap();

        let (mut containers, live) = (w.containers(), w.live_keys());
        let expected = w.run_model(&Action::Revoke { slot });
        containers.extend(w.containers());
        let saved = (w.k.backrefs.clone(), w.k.violations.clone());
        w.k.undo = Some(Vec::new());
        w.k.k.preempt_in = Some(0);
        assert_eq!(cnode::revoke(&mut w.k, slot), Err(Preempted));
        tamper(&mut w.k);
        let error = SyscallError::IllegalOperation;
        let r = w.finish_partial_revoke(slot, error, expected, &containers, &live, saved);
        (w, r)
    }

    #[test]
    fn a_revoke_cut_short_is_where_the_unpreempted_one_passed() {
        let (w, r) = cut_short_revoke(|_| {});
        r.unwrap();
        assert_eq!(w.last_partial.unwrap().stops, [0]);
    }

    #[test]
    fn notices_a_revoke_cut_short_where_the_unpreempted_one_never_was() {
        // A stray write outside every container, which no invariant covers.
        let stray = SlotAddr::new(BIG_UNTYPED).unwrap();
        let (_, r) = cut_short_revoke(|k| k.store(stray, Slot::EMPTY));
        let e = r.unwrap_err();
        assert!(e.contains("had at none"), "{e}");
    }

    #[test]
    fn notices_a_revoke_cut_short_with_a_hook_call_too_many() {
        let (_, r) = cut_short_revoke(|k| k.k.events.push(Event::AfterDelete(Cap::NULL)));
        let e = r.unwrap_err();
        assert!(e.contains("hook calls differ"), "{e}");
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
