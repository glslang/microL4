//! The kernel side of the capability core (`docs/design.md`, "How `core/`
//! reaches kernel memory", "Deletion and finalisation", "Reset and
//! preemption"): [`Objects`] implements `l4core::slot::SlotMemory` and
//! `l4core::kernel::Kernel` over the direct map.
//!
//! - Slots are loaded and stored by value through raw pointers at
//!   `PHYS_MAP_BASE + addr`, and `zero` writes through one the same way; no
//!   Rust reference into slot or untyped memory is ever made.
//! - Debug builds check every slot address and every range `zero` clears
//!   against [`ObjectMemory`], computed once at the end of step 5: RAM the
//!   kernel hands out, inside the direct map, outside the kernel image.
//! - The hooks into other subsystems do nothing yet: before M5 no
//!   capability names an object that holds kernel state to undo or set up.
//! - The preemption point polls the local APIC's IRR and never enables
//!   interrupts. With `selftest` it also counts polls, times the longest
//!   stretch between two, and can be told to report a preemption with no
//!   interrupt pending.

use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use l4core::bootinfo::{BOOTINFO_SIZE, BootInfo};
use l4core::cap::{Cap, CapType, SLOT_SIZE};
use l4core::kernel::{Kernel, Preempted};
use l4core::objmem::ObjectMemory;
use l4core::slot::{Slot, SlotAddr, SlotMemory};

use super::{BootFacts, StaticCell, apic, phys_to_virt};
use crate::boot::BootState;

#[cfg(feature = "selftest")]
pub use self::polls::{inject_preemption, poll_stats, reset_stretches};

/// The memory kernel objects may occupy, for the debug checks.
static MEMORY: StaticCell<ObjectMemory> = StaticCell::new();

/// Computes the memory kernel objects may occupy: the `USABLE`, `LOADER`
/// and `ACPI_RECLAIMABLE` memory of the map from 1 MiB to the direct map's
/// end, without the kernel image and a hypercall page the firmware locked.
/// Called once, at the end of step 5, when that memory is free.
pub fn init(boot: &BootState, facts: &BootFacts) {
    let image = facts.kernel_image.clone();
    let memory = match facts.locked_hypercall_page {
        Some(page) => {
            let holes = [image, page..page + 4096];
            ObjectMemory::new(boot.memory_map(), boot.handoff.direct_map_end(), &holes)
        }
        None => ObjectMemory::new(boot.memory_map(), boot.handoff.direct_map_end(), &[image]),
    };
    MEMORY.init(memory);
}

/// Boot step 9: BootInfo's two frames at physical `paddr`, in the boot
/// region step 6 zeroed, as one `BootInfo` for boot to fill. The first call
/// only gets them; any later one panics.
///
/// Checked here: `paddr` is page-aligned, both frames are RAM kernel
/// objects may occupy (inside the direct map, outside the kernel image and
/// a locked hypercall page), and they read zero. The caller's word: they
/// are BootInfo's frames in the boot region, which no untyped covers and
/// nothing but boot touches; `l4core::boot::plan` placed them there, and
/// boot passes that address.
pub fn bootinfo_frames(paddr: u64) -> &'static mut BootInfo {
    static TAKEN: AtomicBool = AtomicBool::new(false);
    assert!(
        !TAKEN.swap(true, Ordering::Relaxed),
        "BootInfo's frames taken twice"
    );
    let memory = MEMORY
        .get()
        .expect("kernel objects exist only after arch::init");
    let len = BOOTINFO_SIZE as u64;
    assert!(
        paddr.is_multiple_of(4096) && memory.contains(paddr, len),
        "BootInfo's frames at {paddr:#x} are not page-aligned RAM for kernel objects"
    );
    let zero = (paddr..paddr + len).step_by(8).all(|a| {
        // SAFETY: as in `Objects::load`: a word of RAM below the direct
        // map's end, checked above, read by value; any bits are a `u64`.
        unsafe { ptr::read(phys_to_virt(a) as *const u64) == 0 }
    });
    assert!(zero, "BootInfo's frames at {paddr:#x} are not zeroed");
    // SAFETY: the frames are page-aligned RAM below the direct map's end,
    // mapped RW at `PHYS_MAP_BASE + paddr` (write-back, as the boot region
    // touches no 2 MiB page the direct map maps uncached; a plain access
    // would be correct uncached too), outside the kernel image: checked
    // above. That they are BootInfo's frames in the boot region, which no
    // untyped covers and nothing but boot touches, is the caller's word, so
    // no slot or other kernel data lies there and no other reference to
    // them exists; `TAKEN` hands this one out once. Every field of
    // `BootInfo` is a plain integer, so any contents, here zeros, are a
    // valid value.
    unsafe { &mut *(phys_to_virt(paddr) as *mut BootInfo) }
}

/// The kernel's [`SlotMemory`] and [`Kernel`]: `l4core`'s view of kernel
/// memory and its hooks into the rest of the kernel. Make one with
/// [`Objects::begin`] at the start of each kernel operation (a system call,
/// a boot step, a self-test's call), and drop it when the operation ends or
/// is preempted. There is one core, so two never run at once.
pub struct Objects {
    memory: &'static ObjectMemory,
}

impl Objects {
    /// The view for one kernel operation, from the end of step 5 on. With
    /// `selftest`, the stretch the preemption statistics time starts here.
    /// Panics before `arch::init` has finished.
    pub fn begin() -> Objects {
        let memory = MEMORY
            .get()
            .expect("kernel objects exist only after arch::init");
        #[cfg(feature = "selftest")]
        polls::begin();
        Objects { memory }
    }

    /// Debug builds: `len` bytes at `paddr` are memory kernel objects may
    /// occupy.
    fn check(&self, paddr: u64, len: u64, what: &str) {
        debug_assert!(
            self.memory.contains(paddr, len),
            "{what} {paddr:#x}+{len:#x} is not RAM for kernel objects: outside the direct map, \
             outside USABLE, LOADER and ACPI_RECLAIMABLE memory above 1 MiB, or in the kernel image"
        );
    }
}

impl SlotMemory for Objects {
    fn load(&self, at: SlotAddr) -> Slot {
        self.check(at.get(), SLOT_SIZE, "slot");
        // SAFETY: core's invariants make every `SlotAddr` a slot of a CNode
        // or TCB whose memory has not been reset (from M7 also an IRQ-node
        // slot): 32-byte aligned, in a RAM untyped or the boot region below
        // the direct map's end, so mapped RW at `PHYS_MAP_BASE + addr`. It
        // is write-back there, as no RAM untyped and no boot region lies in
        // a 2 MiB page the direct map maps uncached; a plain access would be
        // correct uncached too. Debug builds check the memory map, not the
        // cache type. Slot memory is plain words, so any contents are a
        // valid `[u64; 4]`, and no Rust reference to it exists: only this
        // type reads and writes it, by value.
        let words = unsafe { ptr::read(phys_to_virt(at.get()) as *const [u64; 4]) };
        Slot::from_words(words)
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        self.check(at.get(), SLOT_SIZE, "slot");
        // SAFETY: as in `load`. The slot is outside the kernel image, so the
        // write changes no kernel code or static data, and nothing holds a
        // reference to it.
        unsafe { ptr::write(phys_to_virt(at.get()) as *mut [u64; 4], slot.to_words()) };
    }
}

/// Whether a Frame or paging-structure capability is mapped: its mapping
/// record, the data word, is non-zero only from M5's Map on.
fn mapped(cap: &Cap) -> bool {
    match cap.cap_type() {
        CapType::Frame | CapType::PageTable | CapType::PageDirectory | CapType::Pdpt => {
            cap.data != 0
        }
        _ => false,
    }
}

impl Kernel for Objects {
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
        let _ = last;
        match cap.cap_type() {
            // Nothing, ever: an object's memory returns when its untyped is
            // reset, and the control capabilities and the Hypervisor
            // capability own no kernel state. core calls this with `last`
            // set for every deletion of these.
            CapType::Untyped
            | CapType::IrqControl
            | CapType::IoPortControl
            | CapType::Hypervisor => {}
            // M5: suspend and unbind the thread (off every queue, IPC
            // cancelled; M6 unbinds its notification). A TCB's finalisation
            // has no cleanup.
            CapType::Tcb => {}
            // M5: on the last capability, every queued thread is released
            // and restarts its system call.
            CapType::Endpoint => {}
            // M6: on the last capability, unbound from its TCB and every
            // waiter released.
            CapType::Notification => {}
            // M5: a reply capability's caller is released; a master goes
            // only with its TCB.
            CapType::Reply => {}
            // M5: a Frame unmaps on every deletion, a paging structure on
            // its only one. Nothing is mapped before M5.
            CapType::Frame | CapType::PageTable | CapType::PageDirectory | CapType::Pdpt => {
                debug_assert!(!mapped(&cap), "a mapped {cap:?} before M5");
            }
            // M5: on the last capability, the VSpace is torn down.
            CapType::Pml4 => {}
            // M7: an IRQHandler is masked and unbound, and returns itself as
            // the cleanup, so that `after_delete` frees the IRQ once its slot
            // is empty; an IOPort's range is freed the same way. Neither
            // exists before M7.
            CapType::IrqHandler | CapType::IoPort => {}
            // core turns these into Zombies or nothing itself.
            CapType::Null | CapType::CNode | CapType::Zombie => {
                unreachable!("core finalises no {:?} capability", cap.cap_type())
            }
        }
        None
    }

    fn after_delete(&mut self, cleanup: Cap) {
        // M7: frees the IRQ of an IRQHandler, or the range of an IOPort,
        // whose slot is now empty. `finalise` returns no cleanup before M7.
        let _ = cleanup;
    }

    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        // M5: rewrites the back-reference of a mapped Frame or paging
        // structure from `from` to `to`. Nothing is mapped before M5.
        debug_assert!(!mapped(&cap), "a mapped {cap:?} moved before M5");
        let _ = (from, to);
    }

    fn zero(&mut self, paddr: u64, len: u64) {
        self.check(paddr, len, "zeroed range");
        // SAFETY: core zeroes only RAM untyped below the watermark during a
        // reset (and boot step 6 zeroes the boot region the same way): no
        // live object lies there, so nothing refers to it, and it lies
        // below the direct map's end, mapped RW (write-back, as in `load`;
        // plain stores would be correct uncached too). Debug builds check
        // the memory map and that the range is outside the kernel image,
        // not the cache type.
        unsafe { ptr::write_bytes(phys_to_virt(paddr) as *mut u8, 0, len as usize) };
    }

    fn init_object(&mut self, cap: Cap) {
        match cap.cap_type() {
            // M5: a TCB's non-zero fields (state, priorities, the FP
            // template) and a PML4's kernel half, PML4 entries 256 to 511.
            CapType::Tcb | CapType::Pml4 => {}
            // A new Untyped, Endpoint, Notification, CNode, Frame or lower
            // paging structure is all zeros, which is its initial state.
            _ => {}
        }
    }

    fn preempt(&mut self) -> Result<(), Preempted> {
        let pending = apic::interrupt_pending();
        #[cfg(feature = "selftest")]
        let pending = polls::poll(pending);
        if pending { Err(Preempted) } else { Ok(()) }
    }
}

/// Preemption-point statistics and injected preemptions, for the
/// self-tests. They answer `docs/design.md`'s open question "Is 4 KiB the
/// right chunk?" with the longest stretch between two polls.
#[cfg(feature = "selftest")]
mod polls {
    use core::sync::atomic::{AtomicU64, Ordering};

    use super::super::FACTS;
    use super::super::cpu::rdtsc;

    /// Polls so far.
    static POLLS: AtomicU64 = AtomicU64::new(0);
    /// Polls that found an interrupt pending.
    static INTERRUPTED: AtomicU64 = AtomicU64::new(0);
    /// Polls that reported an injected preemption, with nothing pending.
    static INJECTED: AtomicU64 = AtomicU64::new(0);
    /// 0, or how many polls from now one reports a preemption.
    static INJECT_IN: AtomicU64 = AtomicU64::new(0);
    /// The TSC at the last poll of the current operation, or 0 before its
    /// first; and at the operation's start ([`super::Objects::begin`]).
    static LAST_POLL: AtomicU64 = AtomicU64::new(0);
    static BEGIN: AtomicU64 = AtomicU64::new(0);
    /// Stretches between two polls of one operation.
    static BETWEEN: Stretches = Stretches::new();
    /// Stretches from an operation's start to its first poll. Under TCG the
    /// first of these also translates the code the operation runs.
    static FIRST: Stretches = Stretches::new();

    /// Non-preemptible stretches of one kind: how many, their sum and the
    /// longest, in TSC ticks, and the poll that ended the longest.
    struct Stretches {
        count: AtomicU64,
        total: AtomicU64,
        longest: AtomicU64,
        longest_at: AtomicU64,
    }

    impl Stretches {
        const fn new() -> Self {
            Stretches {
                count: AtomicU64::new(0),
                total: AtomicU64::new(0),
                longest: AtomicU64::new(0),
                longest_at: AtomicU64::new(0),
            }
        }

        fn reset(&self) {
            for c in [&self.count, &self.total, &self.longest, &self.longest_at] {
                c.store(0, Ordering::Relaxed);
            }
        }

        fn record(&self, tsc: u64, poll: u64) {
            self.count.fetch_add(1, Ordering::Relaxed);
            self.total.fetch_add(tsc, Ordering::Relaxed);
            if tsc > self.longest.load(Ordering::Relaxed) {
                self.longest.store(tsc, Ordering::Relaxed);
                self.longest_at.store(poll, Ordering::Relaxed);
            }
        }

        fn stats(&self, tsc_hz: u64) -> StretchStats {
            let ns = |tsc: u64| {
                (u128::from(tsc) * 1_000_000_000)
                    .checked_div(u128::from(tsc_hz))
                    .map_or(0, |ns| ns as u64)
            };
            let count = self.count.load(Ordering::Relaxed);
            let total = self.total.load(Ordering::Relaxed);
            StretchStats {
                count,
                longest_ns: ns(self.longest.load(Ordering::Relaxed)),
                longest_at: self.longest_at.load(Ordering::Relaxed),
                mean_ns: ns(total.checked_div(count).unwrap_or(0)),
            }
        }
    }

    pub fn begin() {
        LAST_POLL.store(0, Ordering::Relaxed);
        BEGIN.store(rdtsc(), Ordering::Relaxed);
    }

    /// Records one poll that found `pending`; returns whether it reports a
    /// preemption. An injected one that falls on a poll with an interrupt
    /// pending counts as interrupted.
    pub fn poll(pending: bool) -> bool {
        let now = rdtsc();
        let n = POLLS.fetch_add(1, Ordering::Relaxed) + 1;
        match LAST_POLL.swap(now, Ordering::Relaxed) {
            0 => FIRST.record(now.wrapping_sub(BEGIN.load(Ordering::Relaxed)), n),
            last => BETWEEN.record(now.wrapping_sub(last), n),
        }
        let injected = match INJECT_IN.load(Ordering::Relaxed) {
            0 => false,
            n => {
                INJECT_IN.store(n - 1, Ordering::Relaxed);
                n == 1
            }
        };
        if pending {
            INTERRUPTED.fetch_add(1, Ordering::Relaxed);
        } else if injected {
            INJECTED.fetch_add(1, Ordering::Relaxed);
        }
        pending || injected
    }

    /// Forgets the stretches measured so far, so that [`poll_stats`] times
    /// only what follows; the poll and preemption counts go on.
    pub fn reset_stretches() {
        BETWEEN.reset();
        FIRST.reset();
    }

    /// Makes the `n`th preemption point from now (1: the next) report a
    /// preemption even with no interrupt pending. 0 cancels.
    pub fn inject_preemption(n: u64) {
        INJECT_IN.store(n, Ordering::Relaxed);
    }

    /// The preemption points passed since boot.
    #[derive(Clone, Copy, Debug)]
    pub struct PollStats {
        /// Polls.
        pub polls: u64,
        /// Polls that found an interrupt pending, and so preempted.
        pub interrupted: u64,
        /// Polls that preempted because of [`inject_preemption`], with no
        /// interrupt pending.
        pub injected: u64,
        /// The stretches between two polls of one operation.
        pub between: StretchStats,
        /// The stretches from an operation's start to its first poll.
        pub first: StretchStats,
    }

    /// Stretches of kernel work with no preemption point.
    #[derive(Clone, Copy, Debug)]
    pub struct StretchStats {
        /// How many.
        pub count: u64,
        /// The longest, in nanoseconds at the calibrated TSC rate, and the
        /// poll that ended it, counting from 1 at boot.
        pub longest_ns: u64,
        pub longest_at: u64,
        /// The mean, in nanoseconds.
        pub mean_ns: u64,
    }

    pub fn poll_stats() -> PollStats {
        let tsc_hz = FACTS.get().map_or(0, |f| f.tsc_hz);
        PollStats {
            polls: POLLS.load(Ordering::Relaxed),
            interrupted: INTERRUPTED.load(Ordering::Relaxed),
            injected: INJECTED.load(Ordering::Relaxed),
            between: BETWEEN.stats(tsc_hz),
            first: FIRST.stats(tsc_hz),
        }
    }
}

/// Self-test helpers over memory kernel objects may occupy.
#[cfg(feature = "selftest")]
impl Objects {
    /// Fills `len` bytes at `paddr` with `byte`. The self-tests call it only
    /// on objects that hold no slots and whose memory the kernel does not
    /// read before M5 (endpoints, notifications, frames, paging structures,
    /// a TCB past its slots).
    pub fn fill(&mut self, paddr: u64, len: u64, byte: u8) {
        assert!(self.memory.contains(paddr, len), "fill outside object RAM");
        // SAFETY: the range is RAM below the direct map's end, outside the
        // kernel image (checked above), mapped RW. No Rust reference to it
        // exists: only this type reaches object memory, by value. That it
        // holds no slot, so that `core`'s state stays sound, is the
        // caller's word (above).
        unsafe { ptr::write_bytes(phys_to_virt(paddr) as *mut u8, byte, len as usize) };
    }

    /// Whether `len` bytes at `paddr` are RAM kernel objects may occupy.
    pub fn is_object_memory(&self, paddr: u64, len: u64) -> bool {
        self.memory.contains(paddr, len)
    }

    /// The first non-zero byte in `len` bytes at `paddr`, if any.
    pub fn first_non_zero(&self, paddr: u64, len: u64) -> Option<u64> {
        assert!(
            paddr.is_multiple_of(8) && len.is_multiple_of(8),
            "unaligned"
        );
        assert!(self.memory.contains(paddr, len), "read outside object RAM");
        (paddr..paddr + len).step_by(8).find_map(|a| {
            // SAFETY: as in `load`: the range is RAM below the direct map's
            // end, read by value; any bits are a valid `u64`.
            let w = unsafe { ptr::read(phys_to_virt(a) as *const u64) };
            (w != 0).then(|| a + u64::from(w.trailing_zeros() / 8))
        })
    }
}
