//! The kernel's boot steps outside `arch` (`docs/design.md`, "Boot
//! sequence"):
//!
//! - Step 2 (M3): what the kernel keeps from the loader. The handoff and
//!   its memory map are copied into kernel memory, so that no code reads
//!   `LOADER` memory afterwards except the kernel image itself, and M4 can
//!   hand that memory out.
//! - Steps 6, 7 and 9 (M4): the boot region, the root CNode and BootInfo,
//!   built by `l4core::boot` from what steps 2 to 5 found. M4 has no root
//!   task, so steps 8 and 10 are M5's.

use l4core::boot::{
    self as l4boot, BootInput, BootPlan, FramebufferStatus, RootNeeds, UntypedSummary,
};
use l4core::bootinfo::{BootInfo, InterruptInfo};
use l4core::handoff::{Handoff, MemoryRegion};
use l4core::kernel::Kernel;
use l4core::vspace::Span;

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
// Steps 6, 7 and 9 (M4)
// ---------------------------------------------------------------------------

/// What boot steps 6, 7 and 9 made: the boot plan, the untyped and
/// BootInfo, whose slot regions say where the root CNode
/// (`plan.layout.cnode`) holds what.
pub struct RootSpace {
    /// The plan, over [`BootState`]'s memory map.
    pub plan: BootPlan<'static>,
    /// What the untyped came to.
    pub untyped: UntypedSummary,
    /// BootInfo, in its two frames in the boot region. Only boot writes it;
    /// once the root task can write those frames (M5), the kernel must stop
    /// reading them through this reference.
    pub bootinfo: &'static BootInfo,
}

static ROOT: StaticCell<RootSpace> = StaticCell::new();

/// Boot steps 6, 7 and 9: plans the boot region, zeroes it, writes BootInfo
/// into its frames and the boot capabilities into the root CNode. Runs once,
/// after `arch::init`; panics with the reason if the plan cannot be made.
pub fn make_root_space(boot: &'static BootState, facts: &'static BootFacts) -> &'static RootSpace {
    let h = &boot.handoff;
    let input = BootInput {
        memory_map: boot.memory_map(),
        kernel_image: Span {
            start: facts.kernel_image.start,
            end: facts.kernel_image.end,
        },
        // M5 reclaims `.rootimage` in step 8.
        rootimage: None,
        direct_map_end: h.direct_map_end(),
        phys_addr_bits: facts.phys_addr_bits,
        window: facts.device_window,
        locked_hypercall_page: facts.locked_hypercall_page,
        framebuffer: h.framebuffer,
        // M4 has no root task: no TCB, VSpace, image frames or Hypervisor
        // capability.
        root: RootNeeds::default(),
    };
    // Step 6.
    let plan = match l4boot::plan(input) {
        Ok(p) => p,
        Err(e) => panic!("boot plan: {e}"),
    };
    let region = plan.layout.region;
    let mut k = Objects::begin();
    k.zero(region.start, region.end - region.start);
    // Step 9's BootInfo, then the capabilities of steps 7 and 9.
    let bi = arch::bootinfo_frames(plan.layout.bootinfo);
    let bi_facts = l4boot::BootFacts {
        // M5 maps the IPC buffer and the root image.
        ipc_buffer: 0,
        user_image: Span { start: 0, end: 0 },
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
    let bootinfo: &'static BootInfo = bi;
    l4boot::write_root_cnode(&mut k, &plan, &slots, bootinfo.untyped());
    ROOT.init(RootSpace {
        plan,
        untyped,
        bootinfo,
    })
}

/// The BootInfo summary: the boot region, the untyped, the framebuffer's
/// untyped and the slot regions.
pub fn print_root_space(root: &RootSpace) {
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
        root.bootinfo.phys_addr_bits
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
    let bi = root.bootinfo;
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
}
