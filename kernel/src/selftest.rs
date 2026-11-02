//! The kernel's own self-tests from M4, built only with `selftest` and
//! picked by `test=` on the command line (ADR 0003). M3's trap, paging and
//! timer tests live in `arch`, next to what they test. Each test ends the
//! run with `TEST PASS`, or `TEST FAIL` and a failure status.
//!
//! - `test=bootinfo` checks what boot steps 6, 7 and 9 made.
//! - `test=retype` is M4's done-when test: it retypes, revokes and retypes
//!   again through `l4core::invoke`, as the root task will, and gets the
//!   same result both times.
//!
//! A call that returns `Preempted` idles; the pending interrupt is taken,
//! and the resume hook the idle path calls restarts the call from its
//! unchanged arguments, looking its capabilities up and decoding it again,
//! as a thread's restarted `syscall` will from M5. If no interrupt is
//! pending, because the preemption was injected, the next timer tick
//! resumes it.

use core::fmt;
use core::ops::Range;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};

use l4core::boot::check::{check_bootinfo, check_plan, check_root_cnode, check_untyped};
use l4core::boot::{LOW_MEMORY_END, MSI_WINDOW};
use l4core::bootinfo::{
    BootInfo, CAP_BOOTINFO_FRAME, CAP_INIT_CNODE, CAP_INIT_IPC_BUFFER, CAP_INIT_VSPACE,
    ROOT_CNODE_SLOTS, UntypedDesc,
};
use l4core::cap::{self, Cap, CapType, ObjectType, Rights, SLOT_SIZE, TCB_SLOTS};
use l4core::cdt;
use l4core::cspace;
use l4core::error::SyscallError;
use l4core::invoke::{self, ExtraCap, InvokeError, Message, label};
use l4core::regs::{RFLAGS_INITIAL, Regs};
use l4core::slot::{Node, Slot, SlotAddr, SlotMemory};
use l4core::tcb;
use l4core::vspace::{BACKREFS, CacheType};

use crate::arch::{self, BootFacts, Objects, StaticCell};
use crate::boot::{BootState, RootSpace};

/// Ends the run with `TEST FAIL` and `why`.
fn fail(why: fmt::Arguments<'_>) -> ! {
    kprintln!("TEST FAIL: {why}");
    arch::exit(arch::ExitCode::Failure)
}

/// Nanoseconds, shown as microseconds with three decimals.
struct Micros(u64);

impl fmt::Display for Micros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:03}", self.0 / 1000, self.0 % 1000)
    }
}

/// `[start, end)` in hex.
struct Hex<'a>(&'a Range<u64>);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:#x}-{:#x}", self.0.start, self.0.end)
    }
}

fn overlaps(a: &Range<u64>, b: &Range<u64>) -> bool {
    a.start < b.end && b.start < a.end
}

// ---------------------------------------------------------------------------
// test=bootinfo
// ---------------------------------------------------------------------------

/// `test=bootinfo`: runs `l4core::boot::check`'s checks on the plan, the
/// untyped, BootInfo and the root CNode as boot made them, then checks
/// every untyped descriptor against kernel memory as `arch` sees it
/// (`arch::kernel_memory`): the kernel image, which must hold the stacks,
/// the descriptor tables, the page tables and `BootState`; the pages the
/// device window maps; the boot region `arch` zeroed; the MSI window and
/// `[0, 1 MiB)`. Every RAM untyped must also be memory `arch` lets kernel
/// objects occupy. Last, it walks the live direct map over every untyped:
/// RAM untyped must be mapped write-back, and no device untyped may lie in
/// a write-back page. `.rootimage`, which boot step 8 reclaimed, is the one
/// part of the kernel image untyped cover.
pub fn bootinfo(boot: &BootState, facts: &BootFacts, root: &RootSpace, bi: &BootInfo) -> ! {
    let plan = &root.plan;
    let k = Objects::begin();
    let checks = [
        ("check_plan", check_plan(plan)),
        (
            "check_untyped",
            check_untyped(plan, bi.untyped(), bi.framebuffer_untyped.len() as usize),
        ),
        ("check_bootinfo", check_bootinfo(plan, bi)),
        ("check_root_cnode", check_root_cnode(&k, plan, bi)),
    ];
    for (name, result) in checks {
        match result {
            Ok(()) => kprintln!("bootinfo: {name}: ok"),
            Err(v) => fail(format_args!("bootinfo: {name}: {v}")),
        }
    }

    let image = facts.kernel_image.clone();
    kprintln!("bootinfo: the kernel image is {}", Hex(&image));
    let mut avoid = [const { None }; 24];
    let mut n = 0;
    let mut add = |name: &'static str, r: Range<u64>| {
        avoid[n] = Some((name, r));
        n += 1;
    };
    // The kernel image but `.rootimage`.
    let ri = root.rootimage.start..root.rootimage.end;
    kprintln!("bootinfo: .rootimage {} was reclaimed from it", Hex(&ri));
    add("the kernel image", image.start..ri.start);
    add("the kernel image", ri.end..image.end);
    let (mut parts, mut window_pages) = (0, 0);
    for (name, r) in arch::kernel_memory(boot).into_iter().flatten() {
        if name == "a device-window page" {
            window_pages += 1;
        } else {
            if r.start < image.start || r.end > image.end {
                fail(format_args!(
                    "bootinfo: {name} at {} is outside the kernel image",
                    Hex(&r)
                ))
            }
            kprintln!("bootinfo: {name} at {} lies in the kernel image", Hex(&r));
            parts += 1;
        }
        add(name, r);
    }
    let region = plan.layout.region;
    add("the boot region", region.start..region.end);
    add("the MSI window", MSI_WINDOW.start..MSI_WINDOW.end);
    add("[0, 1 MiB)", 0..LOW_MEMORY_END);
    let avoid = &avoid[..n];

    let (mut ram, mut device) = (0u64, 0u64);
    for (i, d) in bi.untyped().iter().enumerate() {
        let r = d.paddr..d.end();
        for (name, z) in avoid.iter().flatten() {
            if overlaps(&r, z) {
                fail(format_args!(
                    "bootinfo: untyped {i} at {} overlaps {name} at {}",
                    Hex(&r),
                    Hex(z)
                ))
            }
        }
        if d.device() {
            device += 1;
        } else {
            if !k.is_object_memory(d.paddr, d.size()) {
                fail(format_args!(
                    "bootinfo: RAM untyped {i} at {} is not RAM the kernel hands out",
                    Hex(&r)
                ))
            }
            ram += 1;
        }
    }
    kprintln!(
        "bootinfo: {} untyped ({ram} RAM, {device} device) are clear of the kernel image, its {parts} parts above, {window_pages} device-window pages, the boot region, the MSI window and [0, 1 MiB)",
        ram + device
    );
    kprintln!("bootinfo: every RAM untyped is RAM the kernel hands out");

    // The direct map's cache types, from the live tables rather than the
    // rule the planner applied: every RAM untyped is mapped write-back, and
    // no device untyped lies in a write-back page (ADR 0004).
    let end = boot.handoff.direct_map_end();
    let mut pages = 0u64;
    for (i, d) in bi.untyped().iter().enumerate() {
        let mut a = d.paddr;
        while a < d.end().min(end) {
            let mapped = arch::direct_map_page(boot, a);
            let wb = matches!(mapped, Some((CacheType::WriteBack, _)));
            if d.device() == wb || mapped.is_none() {
                fail(format_args!(
                    "bootinfo: {} untyped {i} at {}: the direct map maps {a:#x} as {mapped:?}",
                    if d.device() { "device" } else { "RAM" },
                    Hex(&(d.paddr..d.end()))
                ))
            }
            let size = mapped.map_or(4096, |(_, size)| size);
            a = (a | (size - 1)) + 1;
            pages += 1;
        }
    }
    kprintln!(
        "bootinfo: the live direct map maps every RAM untyped write-back and no device untyped write-back ({pages} pages walked)"
    );
    kprintln!("TEST PASS");
    arch::exit(arch::ExitCode::Success)
}

// ---------------------------------------------------------------------------
// test=retype
// ---------------------------------------------------------------------------

/// The root CNode's CPtr in the root CSpace.
const ROOT: u64 = CAP_INIT_CNODE;
/// Every right.
const ALL: u64 = Rights::ALL.0 as u64;
/// Read and Write.
const RW: u64 = (Rights::READ.0 | Rights::WRITE.0) as u64;
/// The radix of the CNode the test makes.
const CN_RADIX: u64 = 4;
/// Guard data words for that CNode: guard 5, then guard 3, each 60 bits
/// long, so that the CNode resolves all 64 bits of a CPtr.
const GUARD_5: u64 = (5 << 6) | 60;
const GUARD_3: u64 = (3 << 6) | 60;
/// The badge the test mints.
const BADGE: u64 = 0x42;
/// The slots of C that hold a copy of the BootInfo frame and a mint of the
/// root CNode capability: boot capabilities, not from U.
const C_BOOTINFO_COPY: u64 = 8;
const C_ROOT_COPY: u64 = 9;
/// The boot capabilities the test copies into C.
const COPIED_BOOT_SLOTS: [u64; 2] = [CAP_BOOTINFO_FRAME, CAP_INIT_CNODE];
/// What objects without slots are filled with after the first run.
const PATTERN: u8 = 0xC3;
/// The least size of `U`: it holds a 1 MiB untyped, a 2 MiB frame and
/// the rest.
const MIN_U_BITS: u8 = 23;
/// How long the test waits with interrupts off for the 100 Hz timer before
/// run 1: five periods.
const WAIT_NS: u64 = 50_000_000;

/// A CPtr into a guarded copy of the test's CNode: guard `guard`, then
/// slot `slot`.
const fn guarded(guard: u64, slot: u64) -> u64 {
    (guard << CN_RADIX) | slot
}

/// One invocation, as the root task would make it: the invoked
/// capability's CPtr, the label, the message registers and the extra
/// capabilities' CPtrs, all in the root CSpace; and the error it must
/// give, if any.
#[derive(Clone, Copy)]
struct Call {
    what: &'static str,
    invoked: u64,
    label: u64,
    mrs: [u64; 8],
    len: usize,
    extra: [u64; 2],
    n_extra: usize,
    expect: Option<SyscallError>,
}

impl Call {
    fn new(what: &'static str, invoked: u64, label: u64, mrs: &[u64], extra: &[u64]) -> Call {
        let mut c = Call {
            what,
            invoked,
            label,
            mrs: [0; 8],
            len: mrs.len(),
            extra: [0; 2],
            n_extra: extra.len(),
            expect: None,
        };
        c.mrs[..mrs.len()].copy_from_slice(mrs);
        c.extra[..extra.len()].copy_from_slice(extra);
        c
    }

    fn fails(self, e: SyscallError) -> Call {
        Call {
            expect: Some(e),
            ..self
        }
    }
}

/// `Untyped_Retype` of the untyped at `ut` into `n` objects at slot
/// `offset` of the CNode `(node_index, node_depth)` names from the root
/// CNode (depth 0: the root CNode itself).
fn retype_call(
    what: &'static str,
    ut: u64,
    ty: ObjectType,
    size_bits: u64,
    (node_index, node_depth): (u64, u64),
    offset: u64,
    n: u64,
) -> Call {
    let mrs = [ty as u64, size_bits, node_index, node_depth, offset, n];
    Call::new(what, ut, label::UNTYPED_RETYPE, &mrs, &[ROOT])
}

/// The test's slots and the untyped it retypes.
struct Ctx {
    root: &'static RootSpace,
    /// The root CNode slot of `U`, the largest RAM untyped.
    u: u64,
    /// The first free root CNode slot; the test uses slots from here.
    e: u64,
    /// U's memory.
    u_mem: Range<u64>,
}

impl Ctx {
    /// The sequence each run makes: every object type `U` can make, the
    /// CNode methods between the root CNode and the test's CNode `C`
    /// (through its own capability and two guarded copies), copies into
    /// `C` of boot capabilities that do not come from `U`, a retype of the
    /// untyped made from `U`, and three calls that must fail.
    fn calls(&self) -> [Call; 27] {
        let (u, e) = (self.u, self.e);
        let ut = e; // The 1 MiB untyped made from U.
        let cn = e + 1; // C, radix 4.
        let ep = e + 2; // Two endpoints.
        let nt = e + 4; // Two notifications.
        let tcb = e + 6;
        let f4k = e + 7; // Two 4 KiB frames.
        let f2m = e + 9;
        let (pt, pd, pdpt, pml4) = (e + 10, e + 11, e + 12, e + 13);
        let cn_g5 = e + 14; // C minted with guard 5.
        let cn_g3 = e + 15; // That copy mutated to guard 3.
        let rot = e + 16;
        let cf = e + 17; // Two 4 KiB frames from `ut`.
        let ep_copy = e + 19;
        let spare = e + 20;
        let here = (0, 0);
        let rc = |what, ty, bits, offset, n| retype_call(what, u, ty, bits, here, offset, n);
        [
            rc("U into a 1 MiB untyped", ObjectType::Untyped, 20, ut, 1),
            rc("U into a CNode", ObjectType::CNode, CN_RADIX, cn, 1),
            rc("U into two endpoints", ObjectType::Endpoint, 0, ep, 2),
            rc(
                "U into two notifications",
                ObjectType::Notification,
                0,
                nt,
                2,
            ),
            rc("U into a TCB", ObjectType::Tcb, 0, tcb, 1),
            rc("U into two 4 KiB frames", ObjectType::Frame4K, 0, f4k, 2),
            rc("U into a 2 MiB frame", ObjectType::Frame2M, 0, f2m, 1),
            rc("U into a page table", ObjectType::PageTable, 0, pt, 1),
            rc(
                "U into a page directory",
                ObjectType::PageDirectory,
                0,
                pd,
                1,
            ),
            rc("U into a PDPT", ObjectType::Pdpt, 0, pdpt, 1),
            rc("U into a PML4", ObjectType::Pml4, 0, pml4, 1),
            rc("U into a taken slot", ObjectType::Endpoint, 0, ep, 1)
                .fails(SyscallError::DeleteFirst),
            Call::new(
                "copy an endpoint into C",
                cn,
                label::CNODE_COPY,
                &[0, CN_RADIX, ep, 64, ALL],
                &[ROOT],
            ),
            Call::new(
                "mint a badged endpoint into C",
                cn,
                label::CNODE_MINT,
                &[1, CN_RADIX, ep + 1, 64, RW, BADGE],
                &[ROOT],
            ),
            Call::new(
                "mint C with guard 5",
                ROOT,
                label::CNODE_MINT,
                &[cn_g5, 64, cn, 64, ALL, GUARD_5],
                &[ROOT],
            ),
            Call::new(
                "move a notification into C through guard 5",
                cn_g5,
                label::CNODE_MOVE,
                &[guarded(5, 2), 64, nt, 64],
                &[ROOT],
            ),
            // Two capabilities in C that do not come from U: only C's
            // Zombie clearing can delete them when U is revoked.
            Call::new(
                "copy the BootInfo frame into C",
                cn,
                label::CNODE_COPY,
                &[C_BOOTINFO_COPY, CN_RADIX, CAP_BOOTINFO_FRAME, 64, ALL],
                &[ROOT],
            ),
            Call::new(
                "mint the root CNode into C",
                cn,
                label::CNODE_MINT,
                &[C_ROOT_COPY, CN_RADIX, ROOT, 64, ALL, 0],
                &[ROOT],
            ),
            Call::new(
                "mutate an endpoint",
                ROOT,
                label::CNODE_MUTATE,
                &[spare, 64, ep + 1, 64, 0],
                &[ROOT],
            )
            .fails(SyscallError::IllegalOperation),
            Call::new(
                "mutate C's guard to 3",
                ROOT,
                label::CNODE_MUTATE,
                &[cn_g3, 64, cn_g5, 64, GUARD_3],
                &[ROOT],
            ),
            Call::new(
                "mutate a frame into C through guard 3",
                cn_g3,
                label::CNODE_MUTATE,
                &[guarded(3, 3), 64, f4k, 64, 0],
                &[ROOT],
            ),
            Call::new(
                "rotate frames between C and the root CNode",
                ROOT,
                label::CNODE_ROTATE,
                &[rot, 64, 0, guarded(3, 3), 64, 0, f4k + 1, 64],
                &[cn_g3, ROOT],
            ),
            Call::new(
                "copy U, which has children",
                ROOT,
                label::CNODE_COPY,
                &[spare, 64, u, 64, ALL],
                &[ROOT],
            )
            .fails(SyscallError::RevokeFirst),
            retype_call(
                "the 1 MiB untyped into four endpoints in C",
                ut,
                ObjectType::Endpoint,
                0,
                (cn, 64),
                4,
                4,
            ),
            retype_call(
                "the 1 MiB untyped into two 4 KiB frames",
                ut,
                ObjectType::Frame4K,
                0,
                here,
                cf,
                2,
            ),
            Call::new(
                "delete C's copy of an endpoint",
                cn,
                label::CNODE_DELETE,
                &[0, CN_RADIX],
                &[],
            ),
            Call::new(
                "copy the badged endpoint out of C through guard 3",
                ROOT,
                label::CNODE_COPY,
                &[ep_copy, 64, guarded(3, 1), 64, ALL],
                &[cn_g3],
            ),
        ]
    }

    /// `CNode_Revoke` of `U`.
    fn revoke(&self) -> Call {
        Call::new("revoke U", ROOT, label::CNODE_REVOKE, &[self.u, 64], &[])
    }

    /// The slot a CNode or TCB capability in root slot `slot` names, and
    /// how many slots it has; `None` if `slot` holds neither.
    fn container(&self, k: &Objects, slot: u64) -> Option<(SlotAddr, u64)> {
        let cap = k.load(self.root.plan.layout.slot(slot)).cap;
        let base = SlotAddr::new(cap.object())?;
        match cap.cap_type() {
            CapType::CNode => Some((base, 1 << cap.radix())),
            CapType::Tcb => Some((base, TCB_SLOTS)),
            _ => None,
        }
    }

    /// Every slot the record covers: the root CNode's, then the test
    /// CNode's and the TCB's, if they exist.
    fn for_each_slot(&self, k: &Objects, mut f: impl FnMut(SlotAddr)) {
        let layout = &self.root.plan.layout;
        for slot in 0..ROOT_CNODE_SLOTS {
            f(layout.slot(slot));
        }
        // C, from root slot e + 1, and the TCB, from root slot e + 6.
        for root_slot in [self.e + 1, self.e + 6] {
            if let Some((base, n)) = self.container(k, root_slot) {
                for i in 0..n {
                    f(base.offset(i));
                }
            }
        }
    }
}

static CTX: StaticCell<Ctx> = StaticCell::new();

/// One recorded slot: its address, its four words (capability and
/// derivation node: type, object, size, rights, badge or guard, depth,
/// original, links) and its parent's address, or 0.
type Entry = [u64; 6];

/// The most slots a record holds: the root CNode's non-empty slots (16
/// fixed, 448 untyped, the test's), the test CNode's and the TCB's.
const MAX_RECORD: usize = 640;

/// The first run's record.
static RECORD: [[AtomicU64; 6]; MAX_RECORD] =
    [const { [const { AtomicU64::new(0) }; 6] }; MAX_RECORD];
static RECORD_LEN: AtomicUsize = AtomicUsize::new(0);

fn entry(k: &Objects, at: SlotAddr) -> Option<Entry> {
    let s = k.load(at);
    if s.cap.is_null() {
        return None;
    }
    let [w0, w1, w2, w3] = s.to_words();
    let parent = cdt::parent(k, at).map_or(0, SlotAddr::get);
    Some([at.get(), w0, w1, w2, w3, parent])
}

/// The memory a recorded capability's object holds inside `u`, U's
/// memory, that holds no slot and that nothing reads until a reset clears
/// it: a frame; a TCB's registers and XSAVE area; a PML4's
/// back-references for its kernel half, which no walk reads. (Endpoints,
/// notifications, lower paging structures and the rest of a TCB or PML4
/// are read when their capabilities are deleted.) Boot's frames,
/// BootInfo's and the IPC buffer's, lie outside `u`.
fn object_memory(e: &Entry, u: &Range<u64>) -> [Option<Range<u64>>; 2] {
    let cap = Slot::from_words([e[1], e[2], e[3], e[4]]).cap;
    let (base, size) = (cap.object(), 1u64 << cap.size_bits());
    if base < u.start || base + size > u.end {
        return [None, None];
    }
    match cap.cap_type() {
        CapType::Frame => [Some(base..base + size), None],
        CapType::Tcb => [
            Some(base + tcb::REGS_OFFSET..base + tcb::SCALARS_OFFSET),
            Some(base + tcb::XSAVE_OFFSET..base + size),
        ],
        CapType::Pml4 => [Some(base + BACKREFS + 256 * 8..base + size), None],
        _ => [None, None],
    }
}

/// What word `at` of a recorded object reads once it is made again: what
/// `init_object` writes (a TCB's RFLAGS and initial FP state), else 0.
fn fresh_word(e: &Entry, at: u64) -> u64 {
    let cap = Slot::from_words([e[1], e[2], e[3], e[4]]).cap;
    if cap.cap_type() != CapType::Tcb {
        return 0;
    }
    let off = at - cap.object();
    if off == tcb::REGS_OFFSET + core::mem::offset_of!(Regs, rflags) as u64 {
        return RFLAGS_INITIAL;
    }
    let template = l4core::fpu::initial_state();
    let x = off.wrapping_sub(tcb::XSAVE_OFFSET) as usize;
    if x < template.len() {
        return u64::from_le_bytes(template[x..x + 8].try_into().expect("8 bytes"));
    }
    0
}

/// Where the test is: each run's calls, then a revoke of `U`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
#[repr(u64)]
enum Phase {
    Run1 = 0,
    Revoke1 = 1,
    Run2 = 2,
    Revoke2 = 3,
    Done = 4,
}

impl Phase {
    const ALL: [Phase; 5] = [
        Phase::Run1,
        Phase::Revoke1,
        Phase::Run2,
        Phase::Revoke2,
        Phase::Done,
    ];

    fn name(self) -> &'static str {
        match self {
            Phase::Run1 => "run 1",
            Phase::Revoke1 => "revoke 1",
            Phase::Run2 => "run 2",
            Phase::Revoke2 => "revoke 2",
            Phase::Done => "done",
        }
    }

    /// The poll, counted from the start of attempt `attempt` of call
    /// `step`, that an injected preemption hits, if any, while the phase
    /// has had fewer than its target: the reset of U in each run (the
    /// first run's also takes the timer's preemptions) and each revoke. An
    /// interrupt that comes first, as one pending since the last phase's
    /// output may at the first poll, only defers it to the next attempt.
    fn injection(self, step: u64, attempt: u64, injected: u64) -> Option<u64> {
        let (target, at) = match self {
            Phase::Run1 => (1, 300),
            Phase::Revoke1 => (2, 2 + attempt),
            Phase::Run2 => (2, if attempt == 0 { 1 } else { 100 }),
            Phase::Revoke2 => (1, 3),
            Phase::Done => return None,
        };
        (step == 0 && injected < target).then_some(at)
    }
}

static PHASE: AtomicU64 = AtomicU64::new(0);
/// The call of the current run, and its attempts so far.
static STEP: AtomicU64 = AtomicU64::new(0);
static ATTEMPT: AtomicU64 = AtomicU64::new(0);
/// A preempted call waits for the idle path to restart it.
static WAITING: AtomicBool = AtomicBool::new(false);
/// Restarts from the idle path.
static RESTARTS: AtomicU64 = AtomicU64::new(0);
/// Preemptions by an interrupt and injected ones, per phase.
static BY_INTERRUPT: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
static INJECTED: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
/// Each phase's longest stretch between two polls, in nanoseconds.
static LONGEST_NS: [AtomicU64; 4] = [const { AtomicU64::new(0) }; 4];
/// Preemptions of each run's first call, the reset of U, by an interrupt.
static RESET_BY_INTERRUPT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// The poll statistics at the last preemption, to name its cause.
static SEEN_INTERRUPTED: AtomicU64 = AtomicU64::new(0);
static SEEN_INJECTED: AtomicU64 = AtomicU64::new(0);

/// `test=retype`, M4's done-when test: retypes the largest RAM untyped
/// `U` into every object type, works the CNode methods on the results,
/// records every slot, fills the objects' memory, revokes `U`, and runs the
/// same calls again. The second run must give the same record and objects
/// that read zero. Every call goes through `l4core::invoke` with its
/// capabilities looked up from the root CNode, and is restarted from the
/// idle path whenever it is preempted: by the timer during the first
/// run's reset of `U`, and by injected preemptions in both runs and both
/// revokes.
pub fn retype(root: &'static RootSpace, bi: &BootInfo) -> ! {
    let Some((i, d)) = bi
        .untyped()
        .iter()
        .enumerate()
        .rev()
        .filter(|(_, d)| !d.device())
        .max_by_key(|(_, d)| d.size_bits)
    else {
        fail(format_args!("retype: no RAM untyped"))
    };
    if d.size_bits < MIN_U_BITS {
        fail(format_args!(
            "retype: the largest RAM untyped has only 2^{} bytes",
            d.size_bits
        ))
    }
    let ctx = CTX.init(Ctx {
        root,
        u: bi.untyped.start + i as u64,
        e: bi.empty.start,
        u_mem: d.paddr..d.end(),
    });
    let UntypedDesc {
        paddr, size_bits, ..
    } = *d;
    kprintln!(
        "retype: U is root slot {}: {} MiB of RAM at {paddr:#x}, its watermark at its size; the test's slots start at {}",
        ctx.u,
        (1u64 << size_bits) >> 20,
        ctx.e
    );
    arch::set_resume_hook(resume);
    // Run 1's first call resets U. Waiting here, with interrupts off, for
    // the timer makes its first poll find an interrupt pending on any host,
    // however fast the reset would be.
    if !arch::wait_interrupt_pending(WAIT_NS) {
        fail(format_args!(
            "retype: no interrupt became pending within {} ms",
            WAIT_NS / 1_000_000
        ))
    }
    kprintln!(
        "retype: an interrupt is pending, so run 1's reset of U is preempted by it at its first poll"
    );
    drive()
}

/// The resume hook, on the idle path after every interrupt: restarts the
/// preempted call if there is one, else idles again.
fn resume() -> ! {
    if !WAITING.swap(false, Ordering::Relaxed) {
        arch::idle()
    }
    RESTARTS.fetch_add(1, Ordering::Relaxed);
    drive()
}

fn phase() -> Phase {
    Phase::ALL[PHASE.load(Ordering::Relaxed) as usize]
}

/// Runs the test's calls from where it is, restarting the current one
/// from the start, until the test ends or a call is preempted.
fn drive() -> ! {
    let Some(ctx) = CTX.get() else {
        fail(format_args!("retype: no context"))
    };
    loop {
        let phase = phase();
        let step = STEP.load(Ordering::Relaxed);
        let call = match phase {
            Phase::Run1 | Phase::Run2 => match ctx.calls().get(step as usize) {
                Some(call) => *call,
                None => {
                    end_run(ctx, phase);
                    next_phase();
                    continue;
                }
            },
            Phase::Revoke1 | Phase::Revoke2 => ctx.revoke(),
            Phase::Done => finish(),
        };
        let attempt = ATTEMPT.load(Ordering::Relaxed);
        let injected = INJECTED
            .get(phase as usize)
            .map_or(0, |c| c.load(Ordering::Relaxed));
        arch::inject_preemption(phase.injection(step, attempt, injected).unwrap_or(0));
        let mut k = Objects::begin();
        match execute(&mut k, ctx, &call) {
            Err(InvokeError::Preempted) => preempted(phase, step, &call),
            Err(InvokeError::Error(e)) if call.expect == Some(e) => {}
            Ok(_) if call.expect.is_none() => {}
            other => fail(format_args!(
                "retype: {}: {} gave {other:?}, not {:?}",
                phase.name(),
                call.what,
                call.expect
            )),
        }
        ATTEMPT.store(0, Ordering::Relaxed);
        match phase {
            Phase::Revoke1 | Phase::Revoke2 => {
                after_revoke(ctx, &k, phase);
                next_phase();
            }
            _ => {
                STEP.fetch_add(1, Ordering::Relaxed);
            }
        }
    }
}

/// The phase is over: reports its preemptions and the stretches between
/// its polls, then starts the next.
fn next_phase() {
    let p = phase();
    let i = p as usize;
    let s = arch::poll_stats();
    let (b, f) = (&s.between, &s.first);
    kprintln!(
        "retype: {}: preempted {} times by an interrupt, {} by injection; {} stretches between two polls, the longest {} us (poll {}), the mean {} us; from a call's start to its first poll the longest {} us",
        p.name(),
        BY_INTERRUPT[i].load(Ordering::Relaxed),
        INJECTED[i].load(Ordering::Relaxed),
        b.count,
        Micros(b.longest_ns),
        b.longest_at,
        Micros(b.mean_ns),
        Micros(f.longest_ns)
    );
    LONGEST_NS[i].store(b.longest_ns, Ordering::Relaxed);
    arch::reset_stretches();
    PHASE.fetch_add(1, Ordering::Relaxed);
    STEP.store(0, Ordering::Relaxed);
}

/// Looks the call's capabilities up from the root CNode, as a thread's
/// `syscall` does with its CSpace root, and invokes it.
fn execute(k: &mut Objects, ctx: &Ctx, c: &Call) -> Result<invoke::Reply, InvokeError> {
    let layout = &ctx.root.plan.layout;
    let root = k.load(layout.slot(CAP_INIT_CNODE)).cap;
    let lookup = |k: &Objects, cptr: u64| match cspace::lookup_cap(k, root, cptr) {
        Ok(slot) => slot,
        Err(f) => fail(format_args!(
            "retype: CPtr {cptr:#x} does not resolve: {f:?}"
        )),
    };
    let slot = lookup(k, c.invoked);
    let mut extra = [ExtraCap {
        cap: Cap::NULL,
        slot,
    }; 2];
    for (x, &cptr) in extra.iter_mut().zip(&c.extra[..c.n_extra]) {
        *x = ExtraCap::load(k, lookup(k, cptr));
    }
    let msg = Message {
        label: c.label,
        mrs: &c.mrs[..c.len],
        extra_caps: &extra[..c.n_extra],
    };
    invoke::invoke(k, slot, &msg)
}

/// The call was preempted: names the cause and idles until the idle path
/// restarts it.
fn preempted(phase: Phase, step: u64, call: &Call) -> ! {
    let s = arch::poll_stats();
    let p = phase as usize;
    let cause = if s.interrupted != SEEN_INTERRUPTED.load(Ordering::Relaxed) {
        BY_INTERRUPT[p].fetch_add(1, Ordering::Relaxed);
        if step == 0 && matches!(phase, Phase::Run1 | Phase::Run2) {
            RESET_BY_INTERRUPT[p / 2].fetch_add(1, Ordering::Relaxed);
        }
        "an interrupt"
    } else if s.injected != SEEN_INJECTED.load(Ordering::Relaxed) {
        INJECTED[p].fetch_add(1, Ordering::Relaxed);
        "an injected preemption"
    } else {
        fail(format_args!("retype: preempted, but no poll says why"))
    };
    SEEN_INTERRUPTED.store(s.interrupted, Ordering::Relaxed);
    SEEN_INJECTED.store(s.injected, Ordering::Relaxed);
    let attempt = ATTEMPT.fetch_add(1, Ordering::Relaxed) + 1;
    kprintln!(
        "retype: {}: {} preempted by {cause} at poll {} (attempt {attempt}); restarting from the idle path",
        phase.name(),
        call.what,
        s.polls
    );
    WAITING.store(true, Ordering::Relaxed);
    arch::idle()
}

/// U's watermark now.
fn watermark(ctx: &Ctx, k: &Objects) -> u64 {
    k.load(ctx.root.plan.layout.slot(ctx.u)).cap.watermark()
}

/// A run's calls are done. After the first: record every slot and fill the
/// objects' memory with [`PATTERN`]. After the second: compare with the
/// record, and check the reset cleared the pattern.
fn end_run(ctx: &Ctx, phase: Phase) {
    let mut k = Objects::begin();
    let mut n = 0;
    let mut filled = 0u64;
    if phase == Phase::Run1 {
        ctx.for_each_slot(&k, |at| {
            if let Some(e) = entry(&k, at) {
                if n == MAX_RECORD {
                    fail(format_args!("retype: more than {MAX_RECORD} slots"))
                }
                for (w, v) in RECORD[n].iter().zip(e) {
                    w.store(v, Ordering::Relaxed);
                }
                n += 1;
            }
        });
        RECORD_LEN.store(n, Ordering::Relaxed);
        for e in &RECORD[..n] {
            let e = e.each_ref().map(|w| w.load(Ordering::Relaxed));
            for r in object_memory(&e, &ctx.u_mem).into_iter().flatten() {
                k.fill(r.start, r.end - r.start, PATTERN);
                filled += r.end - r.start;
            }
        }
        kprintln!(
            "retype: run 1 done: {n} slots recorded, U's watermark {:#x}; {} KiB of objects filled with {PATTERN:#04x}",
            watermark(ctx, &k),
            filled >> 10
        );
    } else {
        let len = RECORD_LEN.load(Ordering::Relaxed);
        let mut zeroed = 0u64;
        ctx.for_each_slot(&k, |at| {
            let Some(e) = entry(&k, at) else { return };
            let Some(old) = RECORD.get(n).filter(|_| n < len) else {
                fail(format_args!(
                    "retype: run 2 has more slots than run 1's {len}"
                ))
            };
            let old = old.each_ref().map(|w| w.load(Ordering::Relaxed));
            if e != old {
                fail(format_args!(
                    "retype: run 2's slot {:#x} holds {e:x?}, run 1's {old:x?}",
                    at.get()
                ))
            }
            for r in object_memory(&e, &ctx.u_mem).into_iter().flatten() {
                if let Some(a) = k.first_unlike(r.start, r.end - r.start, |at| fresh_word(&e, at)) {
                    fail(format_args!(
                        "retype: word {a:#x} of an object at {} is not as retype makes it",
                        Hex(&r)
                    ))
                }
                zeroed += r.end - r.start;
            }
            n += 1;
        });
        if n != len {
            fail(format_args!("retype: run 2 has {n} slots, run 1 had {len}"))
        }
        kprintln!(
            "retype: run 2 done: the same {n} slots as run 1, U's watermark {:#x}; its objects' {} KiB read zero, or as retype makes them",
            watermark(ctx, &k),
            zeroed >> 10
        );
    }
}

/// `U` was revoked. Every slot the test filled is empty, C's copies of boot
/// capabilities included, which only C's Zombie clearing deletes. Every
/// boot capability, `U` among them, holds what it held after run 1 (`U`'s
/// watermark where the run left it) and is again a derivation root with
/// no links: no children, so the boot capabilities copied into C have
/// none left. Every recorded slot and every root CNode slot passes
/// `cdt::check_slot`.
fn after_revoke(ctx: &Ctx, k: &Objects, phase: Phase) {
    let layout = &ctx.root.plan.layout;
    let boot_slots = layout.slot(0)..layout.slot(ctx.e);
    let len = RECORD_LEN.load(Ordering::Relaxed);
    let check = |at: SlotAddr| {
        if let Err(why) = cdt::check_slot(k, at) {
            fail(format_args!(
                "retype: {}: slot {:#x}: {why}",
                phase.name(),
                at.get()
            ))
        }
    };
    let mut emptied = 0;
    for e in &RECORD[..len] {
        let e = e.each_ref().map(|w| w.load(Ordering::Relaxed));
        let at = SlotAddr::new(e[0]).expect("a recorded slot address");
        check(at);
        let now = k.load(at);
        if boot_slots.contains(&at) {
            let recorded = Slot::from_words([e[1], e[2], e[3], e[4]]).cap;
            // A root without links, but for the root TCB's copies of the
            // root CNode, its PML4 and the IPC buffer.
            let tcb_copy = match (at.get() - layout.slot(0).get()) / SLOT_SIZE {
                CAP_INIT_CNODE => Some(cap::TCB_SLOT_CSPACE),
                CAP_INIT_VSPACE => Some(cap::TCB_SLOT_VSPACE),
                CAP_INIT_IPC_BUFFER => Some(cap::TCB_SLOT_IPC_BUFFER),
                _ => None,
            };
            let node = Node::new(true, 0, 0).with_next(tcb_copy.map(|n| ctx.root.tcb.slot(n)));
            if now.cap != recorded || now.node != node {
                fail(format_args!(
                    "retype: {}: boot slot {:#x} holds {:x?}, not run 1's capability as a root without links",
                    phase.name(),
                    at.get(),
                    now
                ))
            }
        } else if now != Slot::EMPTY {
            fail(format_args!(
                "retype: {}: slot {:#x} is not empty",
                phase.name(),
                at.get()
            ))
        } else {
            emptied += 1;
        }
    }
    for slot in 0..ROOT_CNODE_SLOTS {
        let at = layout.slot(slot);
        check(at);
        if slot >= ctx.e && k.load(at) != Slot::EMPTY {
            fail(format_args!(
                "retype: {}: root slot {slot} is not empty",
                phase.name()
            ))
        }
    }
    for slot in COPIED_BOOT_SLOTS {
        // No children, but for the root TCB's copy of the root CNode.
        let at = layout.slot(slot);
        let left = match slot {
            CAP_INIT_CNODE => {
                let copy = ctx.root.tcb.slot(cap::TCB_SLOT_CSPACE);
                cdt::first_child(k, at) != Some(copy) || k.load(copy).node.next().is_some()
            }
            _ => cdt::has_children(k, at),
        };
        if left {
            fail(format_args!(
                "retype: {}: root slot {slot}, copied into C, still has children",
                phase.name()
            ))
        }
    }
    kprintln!(
        "retype: {} done: the {emptied} slots the test filled are empty, C's copies of root slots {} and {} included; U and the boot capabilities are as run 1 left them, roots without links but the root TCB's copies",
        phase.name(),
        COPIED_BOOT_SLOTS[0],
        COPIED_BOOT_SLOTS[1]
    );
}

/// Both runs gave the same result: reports the preemptions and the polls.
fn finish() -> ! {
    let count = |a: &[AtomicU64; 4]| a.each_ref().map(|c| c.load(Ordering::Relaxed));
    let (by_interrupt, injected) = (count(&BY_INTERRUPT), count(&INJECTED));
    let restarts = RESTARTS.load(Ordering::Relaxed);
    let total: u64 = by_interrupt.iter().chain(&injected).sum();
    let longest = count(&LONGEST_NS);
    let s = arch::poll_stats();
    kprintln!(
        "retype: {restarts} restarts from the idle path after {} preemptions by an interrupt and {} injected; {} polls",
        by_interrupt.iter().sum::<u64>(),
        injected.iter().sum::<u64>(),
        s.polls
    );
    kprintln!(
        "retype: the longest stretch between two polls: {} us in run 1, {} us in revoke 1, {} us in run 2, {} us in revoke 2",
        Micros(longest[0]),
        Micros(longest[1]),
        Micros(longest[2]),
        Micros(longest[3])
    );
    if restarts != total {
        fail(format_args!(
            "retype: {restarts} restarts for {total} preemptions"
        ))
    }
    if RESET_BY_INTERRUPT[0].load(Ordering::Relaxed) == 0 {
        fail(format_args!(
            "retype: no interrupt preempted run 1's reset of U"
        ))
    }
    if let Some(p) = Phase::ALL[..4].iter().find(|p| injected[**p as usize] == 0) {
        fail(format_args!("retype: {}: no injected preemption", p.name()))
    }
    kprintln!("TEST PASS");
    arch::exit(arch::ExitCode::Success)
}
