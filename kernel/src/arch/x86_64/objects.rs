//! The kernel side of the capability core and of threads (`docs/design.md`,
//! "How `core/` reaches kernel memory", "Deletion and finalisation", "Reset
//! and preemption", "Threads and TCBs", "Scheduling"): [`Objects`]
//! implements `l4core`'s `SlotMemory`, `Kernel`, `PagingStore` (in
//! [`super::paging`]), `Tcbs`, `Scheduling`, `Threads` and `IpcEnv` over
//! the direct map.
//!
//! - Slots, TCB fields, endpoint words and IPC buffer words are loaded and
//!   stored by value through raw pointers at `PHYS_MAP_BASE + addr`, and
//!   `zero` writes
//!   through one the same way; no Rust reference into object memory is
//!   ever made.
//! - Debug builds check every slot address, TCB and range `zero` clears
//!   against [`ObjectMemory`], computed once at the end of step 5: RAM the
//!   kernel hands out, inside the direct map, outside the kernel image; and
//!   from boot step 8 `.rootimage`'s reclaimed pages ([`reclaim`]).
//! - The scheduler's queues live in a static that only `Objects` reaches.
//! - The hooks: a new TCB gets its initial fields, the initial FP state and
//!   a place in the debug list, a new PML4 the kernel's half; a TCB's last
//!   capability suspends it and drops its FP and FS/GS-base ownership; a
//!   Frame or paging structure unmaps; a mapped one that moves takes its
//!   back-reference along; an endpoint's last capability releases its
//!   queue (`l4core::ipc::finalise`).
//! - The preemption point polls the local APIC's IRR and never enables
//!   interrupts. With `selftest` it also counts polls, times the longest
//!   stretch between two, and can be told to report a preemption with no
//!   interrupt pending.

use core::cell::UnsafeCell;
use core::ops::Range;
use core::ptr;
use core::sync::atomic::{AtomicBool, Ordering};

use l4core::bootinfo::{BOOTINFO_SIZE, BootInfo};
use l4core::cap::{Cap, CapType, ENDPOINT_BITS, SLOT_SIZE, TCB_BITS};
use l4core::ipc::{self, IpcEnv};
use l4core::kernel::{Kernel, Preempted};
use l4core::objmem::ObjectMemory;
use l4core::sched::{Scheduler, Scheduling};
use l4core::slot::{Slot, SlotAddr, SlotMemory};
use l4core::syscall;
use l4core::tcb::{self, EpRef, REGS_OFFSET, TcbRef, Tcbs, Threads, XSAVE_OFFSET};

use super::{BootFacts, StaticCell, apic, entry, fpu, paging, phys_to_virt, thread};
use crate::boot::BootState;

#[cfg(feature = "debug")]
pub use self::debug_tcbs::for_each_tcb;

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

/// `.rootimage`'s physical pages, once boot step 8 has unmapped them from
/// the kernel window: RAM untyped cover them, so kernel objects may lie
/// there although they are inside the kernel image.
static RECLAIMED: StaticCell<Range<u64>> = StaticCell::new();

/// Records `.rootimage`'s pages as object memory, after step 8 unmapped
/// them. Once.
pub fn reclaim(span: Range<u64>) {
    RECLAIMED.init(span);
}

/// Whether `len` bytes at `paddr` are memory kernel objects may occupy.
fn object_memory(memory: &ObjectMemory, paddr: u64, len: u64) -> bool {
    memory.contains(paddr, len)
        || RECLAIMED.get().is_some_and(|r| {
            paddr >= r.start && paddr.checked_add(len).is_some_and(|end| end <= r.end)
        })
}

/// The ready queues, the scheduler action and the current thread.
struct SchedulerCell(UnsafeCell<Scheduler>);

// SAFETY: one core, and kernel code runs with interrupts off, so nothing
// runs concurrently; `Objects`' `Scheduling` methods are the only way to
// the scheduler, and each reference they give lives no longer than the
// borrow of the `Objects` it came through.
unsafe impl Sync for SchedulerCell {}

static SCHEDULER: SchedulerCell = SchedulerCell(UnsafeCell::new(Scheduler::new()));

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
            object_memory(self.memory, paddr, len),
            "{what} {paddr:#x}+{len:#x} is not RAM for kernel objects: outside the direct map, \
             outside USABLE, LOADER and ACPI_RECLAIMABLE memory above 1 MiB, or in the kernel image"
        );
    }

    /// The physical address of field `offset` of TCB `t`, as [`Tcbs`]
    /// allows it: a multiple of 8 between the slots and the XSAVE area.
    fn tcb_field(&self, t: TcbRef, offset: u64) -> u64 {
        assert!(
            (REGS_OFFSET..XSAVE_OFFSET).contains(&offset) && offset.is_multiple_of(8),
            "TCB field offset {offset:#x}"
        );
        self.check(t.get(), 1 << TCB_BITS, "TCB");
        t.get() + offset
    }

    /// The physical address of word `offset` of endpoint `ep`: one of its
    /// four.
    fn endpoint_field(&self, ep: EpRef, offset: u64) -> u64 {
        assert!(
            offset < 1 << ENDPOINT_BITS && offset.is_multiple_of(8),
            "endpoint field offset {offset:#x}"
        );
        self.check(ep.get(), 1 << ENDPOINT_BITS, "endpoint");
        ep.get() + offset
    }

    /// Boot step 8: copies root-image `bytes` to `paddr`, inside one image
    /// frame of the boot region, which step 6 zeroed.
    pub fn copy_into_frame(&mut self, paddr: u64, bytes: &[u8]) {
        if bytes.is_empty() {
            return;
        }
        let len = bytes.len() as u64;
        assert!(
            paddr % 4096 + len <= 4096 && object_memory(self.memory, paddr, len),
            "a copy of {len} bytes to {paddr:#x} is not inside one frame of object memory"
        );
        // SAFETY: the destination is inside one 4 KiB frame of RAM kernel
        // objects may occupy (checked above), below the direct map's end and
        // mapped RW there; boot step 8 passes an image frame of the boot
        // region, which holds no slot or kernel data and which nothing else
        // refers to. The source is `.rootimage`, inside the kernel image,
        // which the boot region never overlaps, so the two do not overlap.
        unsafe {
            ptr::copy_nonoverlapping(bytes.as_ptr(), phys_to_virt(paddr) as *mut u8, bytes.len())
        };
    }

    /// The word at `paddr`, which `tcb::buffer_word` found in an IPC
    /// buffer: inside a non-device frame a TCB's buffer slot holds.
    pub fn buffer_word(&self, paddr: u64) -> u64 {
        assert!(paddr.is_multiple_of(8), "unaligned IPC buffer word");
        self.check(paddr, 8, "IPC buffer word");
        // SAFETY: a word of a RAM frame a capability names, which lies in a
        // RAM untyped or the boot region below the direct map's end, so it
        // is mapped RW at `PHYS_MAP_BASE + paddr`; read by value, and any
        // bits are a `u64`. The frame's user may write it at any time from
        // ring 3, but not while the kernel runs: one core.
        unsafe { ptr::read(phys_to_virt(paddr) as *const u64) }
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

/// TCB fields through the direct map.
impl Tcbs for Objects {
    fn tcb_word(&self, t: TcbRef, offset: u64) -> u64 {
        let at = self.tcb_field(t, offset);
        // SAFETY: a `TcbRef` names a live TCB (it comes only from a TCB
        // capability or a link the kernel keeps), 2 KiB aligned in RAM
        // below the direct map's end, so mapped RW and write-back; the word
        // lies between its slots and its XSAVE area, which only this type
        // reaches, by value. Any bits are a `u64`.
        unsafe { ptr::read(phys_to_virt(at) as *const u64) }
    }

    fn set_tcb_word(&mut self, t: TcbRef, offset: u64, value: u64) {
        let at = self.tcb_field(t, offset);
        // SAFETY: as in `tcb_word`; the write changes one field of the TCB
        // and no slot, kernel code or static data.
        unsafe { ptr::write(phys_to_virt(at) as *mut u64, value) };
    }
}

impl Scheduling for Objects {
    fn scheduler(&self) -> &Scheduler {
        // SAFETY: see `SchedulerCell`: the reference is tied to this
        // borrow of `self`, and no `&mut` from `scheduler_mut` can be live
        // while it is, since that needs `&mut self`. The kernel uses one
        // `Objects` at a time for scheduler calls, so no other `Objects`
        // holds one either.
        unsafe { &*SCHEDULER.0.get() }
    }

    fn scheduler_mut(&mut self) -> &mut Scheduler {
        // SAFETY: as in `scheduler`; `&mut self` makes this the only
        // reference through this `Objects`.
        unsafe { &mut *SCHEDULER.0.get() }
    }
}

impl Threads for Objects {
    /// IPC's `cancel_ipc`: a blocked thread leaves its endpoint queue, or
    /// loses the reply capability to it, and becomes `Inactive`; its fault
    /// is cleared in any state.
    fn cancel_ipc(&mut self, t: TcbRef) {
        ipc::cancel_ipc(self, t);
    }

    /// The current thread's `rdx` is `Call`'s number: every system call
    /// preserves `rdx`, so it says how the invocation being performed came;
    /// false with no current thread (a self-test's invocation).
    fn invoked_by_call(&self) -> bool {
        syscall::invoked_by_call(self)
    }

    /// No SynIC page is recorded before M9.
    fn synic_pages(&self) -> [u64; 2] {
        [0; 2]
    }

    fn set_current_fs_base(&mut self, value: u64) {
        entry::set_fs_base(value);
    }

    fn write_buffer_word(&mut self, paddr: u64, value: u64) {
        assert!(paddr.is_multiple_of(8), "unaligned IPC buffer word");
        self.check(paddr, 8, "IPC buffer word");
        // SAFETY: as in `buffer_word`; the word is in a RAM frame the
        // thread's buffer slot holds with Read and Write, which holds no
        // slot or kernel data.
        unsafe { ptr::write(phys_to_virt(paddr) as *mut u64, value) };
    }
}

/// Endpoint words and IPC buffer reads through the direct map, for
/// `l4core::ipc`.
impl IpcEnv for Objects {
    fn endpoint_word(&self, ep: EpRef, offset: u64) -> u64 {
        let at = self.endpoint_field(ep, offset);
        // SAFETY: an `EpRef` names a live endpoint (it comes only from an
        // Endpoint capability or a blocked thread's state, which IPC keeps
        // in step with the endpoint's queue, and finalisation empties that
        // queue before the memory can be reset): 32-byte aligned in RAM
        // below the direct map's end, so mapped RW and write-back. The word
        // is one of its four, which only this type reaches, by value; any
        // bits are a `u64`.
        unsafe { ptr::read(phys_to_virt(at) as *const u64) }
    }

    fn set_endpoint_word(&mut self, ep: EpRef, offset: u64, value: u64) {
        let at = self.endpoint_field(ep, offset);
        // SAFETY: as in `endpoint_word`; the write changes one word of the
        // endpoint and no slot, kernel code or static data.
        unsafe { ptr::write(phys_to_virt(at) as *mut u64, value) };
    }

    fn read_buffer_word(&self, paddr: u64) -> u64 {
        self.buffer_word(paddr)
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
            // The last capability suspends the thread (off its ready queue,
            // IPC cancelled; M6 unbinds its notification), drops its FP and
            // FS and GS base ownership without saving, and takes it off the
            // debug list. No cleanup.
            CapType::Tcb => {
                if last {
                    let t = TcbRef::from_cap(&cap).expect("a TCB capability names a TCB");
                    tcb::suspend(self, t);
                    fpu::forget(t);
                    thread::forget(t);
                    #[cfg(feature = "debug")]
                    debug_tcbs::remove(self, t);
                }
            }
            // The last capability to an endpoint releases its queue: every
            // queued thread restarts its system call. A reply capability
            // needs nothing: deleted unused, it leaves its caller
            // `BlockedOnReply`, and a master goes only with its TCB, after
            // `cancel_ipc` deleted the one derived from it.
            CapType::Endpoint | CapType::Reply => ipc::finalise(self, cap, last),
            // M6: on the last capability, unbound from its TCB and every
            // waiter released.
            CapType::Notification => {}
            // A Frame unmaps on every deletion, a paging structure on its
            // only one, and a PML4's last capability empties its user half
            // (loading the kernel PML4 first if it is in CR3).
            CapType::Frame
            | CapType::PageTable
            | CapType::PageDirectory
            | CapType::Pdpt
            | CapType::Pml4 => paging::finalise(self, cap, last),
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
        // A mapped Frame or paging structure's back-reference follows its
        // capability from `from` to `to`.
        if matches!(
            cap.cap_type(),
            CapType::Frame
                | CapType::PageTable
                | CapType::PageDirectory
                | CapType::Pdpt
                | CapType::Pml4
        ) {
            paging::moved(self, cap, from, to);
        }
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
            // A TCB's non-zero fields (a full slice, RFLAGS 0x202), the
            // initial FP state, and its place in the debug list.
            CapType::Tcb => {
                let t = TcbRef::from_cap(&cap).expect("a TCB capability names a TCB");
                tcb::init(self, t);
                fpu::init_area(t);
                #[cfg(feature = "debug")]
                debug_tcbs::append(self, t);
            }
            // A PML4's kernel half, its entries 256 to 511.
            CapType::Pml4 => paging::init_object(self, cap),
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

/// The list of every TCB `DebugDumpScheduler` walks (`docs/design.md`,
/// "Debug"; seL4 `ksDebugTCBs`): a TCB joins at retype and leaves when its
/// last capability goes. Its two links are the TCB's debug-only words at
/// `DEBUG_OFFSET`: the previous and next TCB's address, 0 for none.
#[cfg(feature = "debug")]
mod debug_tcbs {
    use core::sync::atomic::{AtomicU64, Ordering};

    use l4core::tcb::{DEBUG_OFFSET, TcbRef, Tcbs};

    use super::Objects;

    const PREV: u64 = DEBUG_OFFSET;
    const NEXT: u64 = DEBUG_OFFSET + 8;

    /// The first TCB's address, or 0.
    static HEAD: AtomicU64 = AtomicU64::new(0);

    /// Puts the new TCB `t`, whose links retype zeroed, first.
    pub fn append(k: &mut Objects, t: TcbRef) {
        let head = HEAD.load(Ordering::Relaxed);
        debug_assert!(head != t.get(), "TCB {:#x} listed twice", t.get());
        k.set_tcb_word(t, PREV, 0);
        k.set_tcb_word(t, NEXT, head);
        if let Some(h) = TcbRef::new(head) {
            k.set_tcb_word(h, PREV, t.get());
        }
        HEAD.store(t.get(), Ordering::Relaxed);
    }

    /// Takes `t` off the list.
    pub fn remove(k: &mut Objects, t: TcbRef) {
        let (prev, next) = (k.tcb_word(t, PREV), k.tcb_word(t, NEXT));
        match TcbRef::new(prev) {
            Some(p) => k.set_tcb_word(p, NEXT, next),
            None => {
                debug_assert_eq!(HEAD.load(Ordering::Relaxed), t.get(), "an unlisted TCB");
                HEAD.store(next, Ordering::Relaxed);
            }
        }
        if let Some(n) = TcbRef::new(next) {
            k.set_tcb_word(n, PREV, prev);
        }
        k.set_tcb_word(t, PREV, 0);
        k.set_tcb_word(t, NEXT, 0);
    }

    /// Calls `f` with every TCB, newest first.
    pub fn for_each_tcb(k: &Objects, mut f: impl FnMut(TcbRef)) {
        let mut at = TcbRef::new(HEAD.load(Ordering::Relaxed));
        while let Some(t) = at {
            f(t);
            at = TcbRef::new(k.tcb_word(t, NEXT));
        }
    }
}

/// Self-test helpers over memory kernel objects may occupy.
#[cfg(feature = "selftest")]
impl Objects {
    /// Fills `len` bytes at `paddr` with `byte`. The self-tests call it only
    /// on object memory that holds no slots and that nothing reads before
    /// the object is reset: frames, a TCB's registers and XSAVE area, a
    /// PML4's kernel-half back-references.
    pub fn fill(&mut self, paddr: u64, len: u64, byte: u8) {
        assert!(
            object_memory(self.memory, paddr, len),
            "fill outside object RAM"
        );
        // SAFETY: the range is RAM below the direct map's end, outside the
        // kernel image (checked above), mapped RW. No Rust reference to it
        // exists: only this type reaches object memory, by value. That it
        // holds no slot, so that `core`'s state stays sound, is the
        // caller's word (above).
        unsafe { ptr::write_bytes(phys_to_virt(paddr) as *mut u8, byte, len as usize) };
    }

    /// Whether `len` bytes at `paddr` are RAM kernel objects may occupy.
    pub fn is_object_memory(&self, paddr: u64, len: u64) -> bool {
        object_memory(self.memory, paddr, len)
    }

    /// The address of the first word in `len` bytes at `paddr` that is not
    /// `expected(address)`, if any.
    pub fn first_unlike(&self, paddr: u64, len: u64, expected: impl Fn(u64) -> u64) -> Option<u64> {
        assert!(
            paddr.is_multiple_of(8) && len.is_multiple_of(8),
            "unaligned"
        );
        assert!(
            object_memory(self.memory, paddr, len),
            "read outside object RAM"
        );
        (paddr..paddr + len).step_by(8).find(|&a| {
            // SAFETY: as in `load`: the range is RAM below the direct map's
            // end, read by value; any bits are a valid `u64`.
            let w = unsafe { ptr::read(phys_to_virt(a) as *const u64) };
            w != expected(a)
        })
    }
}
