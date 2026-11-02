//! The kernel's boot steps outside `arch` (`docs/design.md`, "Boot
//! sequence"):
//!
//! - Step 2 (M3): what the kernel keeps from the loader. The handoff and
//!   its memory map are copied into kernel memory, so that no code reads
//!   `LOADER` memory afterwards except the kernel image itself, and M4 can
//!   hand that memory out.
//! - Steps 6 to 9 (M4, M5): the boot region, the root CNode, the root
//!   task's VSpace, image and TCB, the untyped and BootInfo, built by
//!   `l4core::boot` from what steps 2 to 5 found and the root ELF in
//!   `.rootimage`.
//! - Step 10 (M5): the root task runs.

use l4core::boot::image::{RootImage, RootMapping, root_mappings};
use l4core::boot::{self as l4boot, BootInput, BootPlan, FramebufferStatus, UntypedSummary};
use l4core::bootinfo::{
    BootInfo, CAP_INIT_CNODE, CAP_INIT_IPC_BUFFER, CAP_INIT_TCB, CAP_INIT_VSPACE, InterruptInfo,
};
use l4core::cap::{TCB_SLOT_CSPACE, TCB_SLOT_IPC_BUFFER, TCB_SLOT_VSPACE};
use l4core::handoff::{Handoff, MemoryRegion};
use l4core::kernel::Kernel;
use l4core::sched;
use l4core::slot::SlotMemory;
use l4core::tcb::{self, TcbRef, Tcbs};
use l4core::vspace::{Span, paging};
use l4core::{cdt, cnode};

use crate::arch::{self, BootFacts, Objects, StaticCell};

/// The most memory-map entries the kernel copies; more is a panic.
pub const MAX_REGIONS: usize = 256;

/// The handoff and memory map, copied out of loader memory.
pub struct BootState {
    /// The handoff. Its `memory_map` field still names loader memory, which
    /// nothing reads after the copy; use [`BootState::memory_map`].
    pub handoff: Handoff,
    regions: [MemoryRegion; MAX_REGIONS],
    len: usize,
}

impl BootState {
    /// The memory map, sorted and merged by the loader.
    pub fn memory_map(&self) -> &[MemoryRegion] {
        &self.regions[..self.len]
    }

    /// The kernel command line.
    pub fn cmdline(&self) -> &str {
        self.handoff.cmdline()
    }
}

static BOOT: StaticCell<BootState> = StaticCell::new();

/// Validates the handoff at `handoff_phys`, checks that the kernel image, the
/// handoff and the memory map lie inside the kernel's direct map (ADR 0006),
/// and copies them. Runs once, on the loader's page tables.
pub fn take_handoff(handoff_phys: u64) -> &'static BootState {
    let handoff = arch::read_handoff(handoff_phys);
    if let Err(e) = handoff
        .validate()
        .and_then(|()| handoff.check_kernel_bounds(handoff_phys, MAX_REGIONS))
    {
        panic!("bad handoff: {e}");
    }
    let len = handoff.memory_map_len as usize;
    let mut regions = [MemoryRegion::default(); MAX_REGIONS];
    arch::read_memory_map(&handoff, &mut regions[..len]);
    BOOT.init(BootState {
        handoff,
        regions,
        len,
    })
}

// ---------------------------------------------------------------------------
// Steps 6 to 9 (M4, M5)
// ---------------------------------------------------------------------------

/// What boot steps 6 to 9 made: the boot plan, the untyped, the slot
/// regions and the root task, whose objects lie in the boot region. The
/// kernel keeps no reference to BootInfo: the root task can write its
/// frames.
pub struct RootSpace {
    /// The plan, over [`BootState`]'s memory map, with the root task's
    /// needs and `.rootimage` reclaimed.
    pub plan: BootPlan<'static>,
    /// What the untyped came to.
    pub untyped: UntypedSummary,
    /// The root task's TCB, ready to run.
    pub tcb: TcbRef,
    /// Its entry point and image, `[user_image_start, user_image_end)`.
    pub entry: u64,
    pub user_image: Span,
    /// `.rootimage`'s physical pages, unmapped in step 8 and now covered by
    /// RAM untyped.
    pub rootimage: Span,
    /// What step 8 meant the image frames to hold, for `test=rootimage`,
    /// which can no longer read the ELF: [`page_hash`] over each image
    /// page by ascending address, and how many there are.
    #[cfg_attr(
        not(feature = "selftest"),
        expect(dead_code, reason = "only test=rootimage reads them")
    )]
    pub image_hash: u64,
    #[cfg_attr(
        not(feature = "selftest"),
        expect(dead_code, reason = "only test=rootimage reads them")
    )]
    pub image_pages: u64,
}

/// FNV-1a, 64 bits, over `bytes`, from `hash`.
pub fn fnv1a(hash: u64, bytes: &[u8]) -> u64 {
    bytes.iter().fold(hash, |h, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0000_0100_0000_01B3)
    })
}

/// FNV-1a's offset basis.
pub const FNV_BASIS: u64 = 0xCBF2_9CE4_8422_2325;

/// Adds one mapped image page to `hash`: its address, whether it is
/// writable and executable, and its 4096 bytes, `word` giving each 8.
pub fn page_hash(
    hash: u64,
    vaddr: u64,
    write: bool,
    execute: bool,
    word: impl Fn(usize) -> u64,
) -> u64 {
    let mut h = fnv1a(hash, &vaddr.to_le_bytes());
    h = fnv1a(h, &[u8::from(write), u8::from(execute)]);
    (0..512).fold(h, |h, i| fnv1a(h, &word(i).to_le_bytes()))
}

static ROOT: StaticCell<RootSpace> = StaticCell::new();

/// Boot steps 6 to 9 (`docs/design.md`, "Boot sequence"):
///
/// 6. checks the root ELF in `.rootimage`, plans the boot region for its
///    needs, with `.rootimage` reclaimed, and zeroes it;
/// 9. computes the untyped and writes BootInfo into its frames (before
///    step 7, whose CNode holds step 9's untyped);
/// 7. writes every boot capability into the root CNode;
/// 8. gives the root PML4 the kernel's half, maps the paging structures,
///    the image frames, the IPC buffer and BootInfo in `root_mappings`'
///    order, copies the image's file bytes, unmaps `.rootimage` from the
///    kernel window with a CR4.PGE toggle, and makes the root TCB:
///    `Running` at the entry with BootInfo in `rdi`, priority and MCP 255,
///    the root CNode, PML4 and IPC buffer frame copied into its slots.
///
/// No untyped can be used before the root task runs, so making them before
/// step 8 unmaps `.rootimage` is safe. Returns what was made and BootInfo,
/// which the caller must not keep once the root task can run. Runs once,
/// after `arch::init`; panics with the reason if the root image or the
/// plan is refused.
pub fn make_root_space(
    boot: &'static BootState,
    facts: &'static BootFacts,
) -> (&'static RootSpace, &'static BootInfo) {
    let h = &boot.handoff;
    let section = arch::take_rootimage();
    let rootimage = section.phys(h.kernel_phys_base);
    let mut k = Objects::begin();
    let (plan, bi, untyped, entry, bootinfo_va, ipc_buffer_va, user_image, hash) = {
        let image = match RootImage::check(section.bytes()) {
            Ok(image) => image,
            Err(e) => panic!("the root image: {e}"),
        };
        let input = BootInput {
            memory_map: boot.memory_map(),
            kernel_image: Span {
                start: facts.kernel_image.start,
                end: facts.kernel_image.end,
            },
            rootimage: Some(rootimage),
            direct_map_end: h.direct_map_end(),
            phys_addr_bits: facts.phys_addr_bits,
            window: facts.device_window,
            locked_hypercall_page: facts.locked_hypercall_page,
            framebuffer: h.framebuffer,
            // M9 adds the Hypervisor capability on Hyper-V.
            root: image.needs(),
        };
        // Step 6.
        let plan = match l4boot::plan(input) {
            Ok(p) => p,
            Err(e) => panic!("boot plan: {e}"),
        };
        let l = plan.layout;
        k.zero(l.region.start, l.region.end - l.region.start);
        // Step 9: the untyped, the slot regions and BootInfo.
        let bi = arch::bootinfo_frames(l.bootinfo);
        let bi_facts = l4boot::BootFacts {
            ipc_buffer: image.ipc_buffer(),
            user_image: image.image(),
            rsdp: h.rsdp,
            tsc_hz: facts.tsc_hz,
            hypervisor_vendor: facts.hypervisor_vendor,
            // The bytes unchanged, valid UTF-8 or not.
            cmdline: &h.cmdline[..(h.cmdline_len as usize).min(h.cmdline.len())],
            interrupts: InterruptInfo::from_platform(facts.platform, &facts.ioapic_pins),
        };
        let (untyped, slots) = match l4boot::write_bootinfo(bi, &plan, &bi_facts) {
            Ok(r) => r,
            Err(e) => panic!("BootInfo: {e}"),
        };
        let bi: &'static BootInfo = bi;
        // Step 7.
        l4boot::write_root_cnode(&mut k, &plan, &slots, bi.untyped());
        // Step 8: the VSpace, then the image's bytes.
        let vspace = l.slot(CAP_INIT_VSPACE);
        let pml4 = k.load(vspace).cap;
        k.init_object(pml4);
        let tables = root_mappings(&image, &l, &slots).filter_map(|m| match m {
            RootMapping::Table { slot, .. } => Some(l.slot(slot)),
            RootMapping::Frame { .. } => None,
        });
        paging::map_boot_tables(&mut k, vspace, image.mapped(), tables);
        let mut hash = (FNV_BASIS, 0);
        for m in root_mappings(&image, &l, &slots) {
            if let RootMapping::Frame {
                slot,
                paddr,
                vaddr,
                access,
                offset,
                bytes,
            } = m
            {
                paging::map_boot_frame(&mut k, l.slot(slot), vspace, vaddr, access);
                k.copy_into_frame(paddr + offset as u64, bytes);
                if slots.user_image_frames.contains(slot) {
                    // The page as the ELF makes it: zeros, then the bytes.
                    let byte = |i: usize| {
                        i.checked_sub(offset)
                            .and_then(|j| bytes.get(j))
                            .copied()
                            .unwrap_or(0)
                    };
                    let word =
                        |w: usize| u64::from_le_bytes(core::array::from_fn(|b| byte(8 * w + b)));
                    hash.0 = page_hash(hash.0, vaddr, access.write, access.execute, word);
                    hash.1 += 1;
                }
            }
        }
        (
            plan,
            bi,
            untyped,
            image.entry(),
            image.bootinfo(),
            image.ipc_buffer(),
            image.image(),
            hash,
        )
    };
    // The image is copied: `.rootimage` leaves the kernel window, and its
    // pages may hold objects once the root task retypes their untyped.
    let reclaimed = section.unmap(h.kernel_phys_base);
    debug_assert_eq!(reclaimed, rootimage);

    // Step 8: the root TCB.
    let l = plan.layout;
    let tcb_cap = k.load(l.slot(CAP_INIT_TCB)).cap;
    let t = TcbRef::from_cap(&tcb_cap).expect("the plan has a root TCB");
    k.init_object(tcb_cap);
    tcb::init_root(&mut k, t, entry, bootinfo_va);
    for (from, to) in [
        (CAP_INIT_CNODE, TCB_SLOT_CSPACE),
        (CAP_INIT_VSPACE, TCB_SLOT_VSPACE),
        (CAP_INIT_IPC_BUFFER, TCB_SLOT_IPC_BUFFER),
    ] {
        let src = l.slot(from);
        let copied = cnode::derive(&k, src)
            .map_err(|_| "underivable")
            .and_then(|cap| {
                cdt::insert_derived(&mut k, src, t.slot(to), cap, false).map_err(|_| "too deep")
            });
        if let Err(e) = copied {
            panic!("root TCB slot {to}: root slot {from} is {e}");
        }
    }
    k.set_ipc_buffer(t, ipc_buffer_va);
    let root = ROOT.init(RootSpace {
        plan,
        untyped,
        tcb: t,
        entry,
        user_image,
        rootimage: reclaimed,
        image_hash: hash.0,
        image_pages: hash.1,
    });
    (root, bi)
}

/// The BootInfo summary: the boot region, the untyped, the framebuffer's
/// untyped and the slot regions; then the root task.
pub fn print_root_space(root: &RootSpace, bi: &BootInfo) {
    let l = &root.plan.layout;
    let r = l.region;
    kprintln!(
        "bootinfo: boot region {:#x}-{:#x}, {} KiB: root CNode at {:#x}, IPC buffer at {:#x}, BootInfo at {:#x}",
        r.start,
        r.end,
        (r.end - r.start) >> 10,
        l.cnode,
        l.ipc_buffer,
        l.bootinfo
    );
    let u = &root.untyped;
    kprintln!(
        "bootinfo: {} untyped: {} KiB of RAM, {} MiB of device memory, below 2^{}",
        u.count,
        u.ram_bytes >> 10,
        u.device_bytes >> 20,
        bi.phys_addr_bits
    );
    match root.plan.framebuffer {
        FramebufferStatus::Absent => kprintln!("bootinfo: no framebuffer"),
        FramebufferStatus::Untyped(s) => kprintln!(
            "bootinfo: framebuffer {:#x}-{:#x}: {} device untyped, listed first",
            s.start,
            s.end,
            u.framebuffer
        ),
        FramebufferStatus::Rejected { span, reason } => kprintln!(
            "bootinfo: warning: framebuffer {:#x}-{:#x} gets no untyped: {reason}",
            span.start,
            span.end
        ),
    }
    let regions = [
        ("extra_bootinfo_frames", bi.extra_bootinfo_frames),
        ("user_image_paging", bi.user_image_paging),
        ("user_image_frames", bi.user_image_frames),
        ("untyped", bi.untyped),
        ("framebuffer_untyped", bi.framebuffer_untyped),
        ("empty", bi.empty),
    ];
    for (name, s) in regions.into_iter().filter(|(_, s)| !s.is_empty()) {
        kprintln!(
            "bootinfo: slots {}-{}: {name}, {} slot{}",
            s.start,
            s.end - 1,
            s.len(),
            if s.len() == 1 { "" } else { "s" }
        );
    }
    let n = root.plan.input.root;
    kprintln!(
        "boot: root task: image {:#x}-{:#x}, entry {:#x}; TCB at {:#x}, PML4 at {:#x}, {} PDPT, {} PD, {} PT, {} image frames",
        root.user_image.start,
        root.user_image.end,
        root.entry,
        root.tcb.get(),
        l.pml4.unwrap_or(0),
        n.pdpts,
        n.pds,
        n.pts,
        n.image_frames
    );
    kprintln!(
        "boot: .rootimage {:#x}-{:#x} unmapped from the kernel window and reclaimed as RAM untyped",
        root.rootimage.start,
        root.rootimage.end
    );
}

/// Step 10: the root task runs. Hands its TCB to the scheduler and leaves
/// the kernel for it by `iretq`, with its FS and GS bases (0), its VSpace
/// and the initial FP state loaded on the way out. Whatever the caller held
/// on the kernel stack, BootInfo's reference included, is abandoned.
pub fn start_root_task(root: &RootSpace) -> ! {
    kprintln!(
        "boot: entering the root task at {:#x} in ring 3",
        root.entry
    );
    {
        let mut k = Objects::begin();
        sched::make_runnable(&mut k, root.tcb);
    }
    arch::exit_to_scheduled()
}
