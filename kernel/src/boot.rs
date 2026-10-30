//! What the kernel keeps from the loader: step 2 of the M3 boot sequence
//! (`docs/design.md`, "Boot sequence").
//!
//! The handoff and its memory map are copied into kernel memory, so that no
//! code reads `LOADER` memory afterwards except the kernel image itself, and
//! M4 can hand that memory out.

use l4core::handoff::{Handoff, MemoryRegion};

use crate::arch::{self, StaticCell};

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
