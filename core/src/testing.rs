//! Fake physical memory and a recording [`Kernel`] for host tests.
//!
//! Built for `cargo test` and with the `testing` feature, which `model/`
//! uses. The kernel never enables it.

use alloc::vec;
use alloc::vec::Vec;

use crate::cap::{Cap, CapType};
use crate::kernel::{Kernel, Preempted};
use crate::sched::{Scheduler, Scheduling};
use crate::slot::{Slot, SlotAddr, SlotMemory};
use crate::tcb::{REGS_OFFSET, TcbRef, Tcbs, ThreadState, Threads, XSAVE_OFFSET};

/// A range of fake physical memory: `len` bytes from `base`, as words.
/// Every access outside it, or not 8-byte aligned, panics, so a stray slot
/// address shows up at once.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeMemory {
    base: u64,
    words: Vec<u64>,
}

impl FakeMemory {
    /// `len` bytes of zeros from `base`; both multiples of 8.
    pub fn new(base: u64, len: u64) -> FakeMemory {
        assert!(base.is_multiple_of(8) && len.is_multiple_of(8));
        FakeMemory {
            base,
            words: vec![0; (len / 8) as usize],
        }
    }

    /// The first byte.
    pub fn base(&self) -> u64 {
        self.base
    }

    /// The size in bytes.
    pub fn len(&self) -> u64 {
        self.words.len() as u64 * 8
    }

    /// Whether the memory is empty.
    pub fn is_empty(&self) -> bool {
        self.words.is_empty()
    }

    fn index(&self, paddr: u64) -> usize {
        assert!(paddr.is_multiple_of(8), "unaligned access at {paddr:#x}");
        let off = paddr
            .checked_sub(self.base)
            .filter(|off| *off < self.len())
            .unwrap_or_else(|| panic!("access outside fake memory at {paddr:#x}"));
        (off / 8) as usize
    }

    /// The word at `paddr`.
    pub fn read(&self, paddr: u64) -> u64 {
        self.words[self.index(paddr)]
    }

    /// Overwrites the word at `paddr`.
    pub fn write(&mut self, paddr: u64, value: u64) {
        let i = self.index(paddr);
        self.words[i] = value;
    }

    /// Writes zeros to `len` bytes from `paddr`.
    pub fn zero(&mut self, paddr: u64, len: u64) {
        assert!(len.is_multiple_of(8));
        if len == 0 {
            return;
        }
        let first = self.index(paddr);
        let last = self.index(paddr + len - 8);
        self.words[first..=last].fill(0);
    }

    /// Whether `len` bytes from `paddr` are all zero.
    pub fn is_zero(&self, paddr: u64, len: u64) -> bool {
        assert!(len.is_multiple_of(8));
        if len == 0 {
            return true;
        }
        let first = self.index(paddr);
        let last = self.index(paddr + len - 8);
        self.words[first..=last].iter().all(|w| *w == 0)
    }
}

impl SlotMemory for FakeMemory {
    fn load(&self, at: SlotAddr) -> Slot {
        let a = at.get();
        Slot::from_words([
            self.read(a),
            self.read(a + 8),
            self.read(a + 16),
            self.read(a + 24),
        ])
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        let a = at.get();
        for (i, w) in slot.to_words().into_iter().enumerate() {
            self.write(a + 8 * i as u64, w);
        }
    }
}

/// TCB fields in fake memory, at the TCB's physical address, as the kernel
/// keeps them in the direct map. Panics on an offset [`Tcbs`] does not
/// allow.
impl Tcbs for FakeMemory {
    fn tcb_word(&self, t: TcbRef, offset: u64) -> u64 {
        self.read(tcb_field(t, offset))
    }

    fn set_tcb_word(&mut self, t: TcbRef, offset: u64, value: u64) {
        self.write(tcb_field(t, offset), value);
    }
}

fn tcb_field(t: TcbRef, offset: u64) -> u64 {
    assert!(
        (REGS_OFFSET..XSAVE_OFFSET).contains(&offset) && offset.is_multiple_of(8),
        "TCB field offset {offset:#x}"
    );
    t.get() + offset
}

/// A hook call [`TestKernel`] recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    Finalise {
        cap: Cap,
        last: bool,
    },
    AfterDelete(Cap),
    Moved {
        cap: Cap,
        from: SlotAddr,
        to: SlotAddr,
    },
    Zero {
        paddr: u64,
        len: u64,
    },
    InitObject(Cap),
}

/// A [`Threads`] hook call [`TestKernel`] recorded, kept apart from the
/// [`Event`]s so that the capability core's records stay as they were.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ThreadEvent {
    CancelIpc(TcbRef),
    SetCurrentFsBase(u64),
    WriteBufferWord { paddr: u64, value: u64 },
}

/// The word [`TestKernel::init_object`] writes into objects that hold data,
/// so tests can see that a reset clears them.
pub const DIRT: u64 = 0xD1D1_D1D1_D1D1_D1D1;

/// A [`Kernel`] over [`FakeMemory`] that records every hook call and can
/// preempt at a chosen preemption point.
#[derive(Clone, Debug)]
pub struct TestKernel {
    pub mem: FakeMemory,
    pub events: Vec<Event>,
    /// If `Some(n)`, the preemption point after the next `n` passes reports
    /// an interrupt, once; then this becomes `None`.
    pub preempt_in: Option<u64>,
    /// Preemption points passed so far.
    pub preempt_points: u64,
    /// The scheduler: the current thread and the ready queues.
    pub sched: Scheduler,
    /// [`Threads`] hook calls.
    pub thread_events: Vec<ThreadEvent>,
    /// What [`Threads::invoked_by_call`] answers.
    pub by_call: bool,
    /// What [`Threads::synic_pages`] answers.
    pub synic: [u64; 2],
}

impl TestKernel {
    /// A kernel over `len` bytes of fake memory from `base`.
    pub fn new(base: u64, len: u64) -> TestKernel {
        TestKernel {
            mem: FakeMemory::new(base, len),
            events: Vec::new(),
            preempt_in: None,
            preempt_points: 0,
            sched: Scheduler::new(),
            thread_events: Vec::new(),
            by_call: true,
            synic: [0; 2],
        }
    }

    /// Where `init_object` writes [`DIRT`] in an object of this capability,
    /// if anywhere: never in slots, which must start empty.
    pub fn dirt_offset(cap: &Cap) -> Option<u64> {
        match cap.cap_type() {
            CapType::Endpoint
            | CapType::Notification
            | CapType::Frame
            | CapType::PageTable
            | CapType::PageDirectory
            | CapType::Pdpt
            | CapType::Pml4 => Some(0),
            CapType::Tcb => Some(1024),
            _ => None,
        }
    }
}

impl SlotMemory for TestKernel {
    fn load(&self, at: SlotAddr) -> Slot {
        self.mem.load(at)
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        self.mem.store(at, slot)
    }
}

impl Kernel for TestKernel {
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
        self.events.push(Event::Finalise { cap, last });
        (last && cap.cap_type() == CapType::IrqHandler).then_some(cap)
    }

    fn after_delete(&mut self, cleanup: Cap) {
        self.events.push(Event::AfterDelete(cleanup));
    }

    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        self.events.push(Event::Moved { cap, from, to });
    }

    fn zero(&mut self, paddr: u64, len: u64) {
        self.events.push(Event::Zero { paddr, len });
        self.mem.zero(paddr, len);
    }

    fn init_object(&mut self, cap: Cap) {
        self.events.push(Event::InitObject(cap));
        if let Some(off) = TestKernel::dirt_offset(&cap) {
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

impl Tcbs for TestKernel {
    fn tcb_word(&self, t: TcbRef, offset: u64) -> u64 {
        self.mem.tcb_word(t, offset)
    }

    fn set_tcb_word(&mut self, t: TcbRef, offset: u64, value: u64) {
        self.mem.set_tcb_word(t, offset, value);
    }
}

impl Scheduling for TestKernel {
    fn scheduler(&self) -> &Scheduler {
        &self.sched
    }

    fn scheduler_mut(&mut self) -> &mut Scheduler {
        &mut self.sched
    }
}

impl Threads for TestKernel {
    /// Records the call and does what IPC's `cancel_ipc` does to the thread
    /// itself: a blocked thread becomes `Inactive`, and the fault is
    /// cleared. There are no endpoint queues or reply capabilities to undo.
    fn cancel_ipc(&mut self, t: TcbRef) {
        self.thread_events.push(ThreadEvent::CancelIpc(t));
        if self.state(t).is_blocked() {
            self.set_state(t, ThreadState::Inactive);
        }
        self.set_fault(t, None);
    }

    fn invoked_by_call(&self) -> bool {
        self.by_call
    }

    fn synic_pages(&self) -> [u64; 2] {
        self.synic
    }

    fn set_current_fs_base(&mut self, value: u64) {
        self.thread_events
            .push(ThreadEvent::SetCurrentFsBase(value));
    }

    fn write_buffer_word(&mut self, paddr: u64, value: u64) {
        self.thread_events
            .push(ThreadEvent::WriteBufferWord { paddr, value });
        self.mem.write(paddr, value);
    }
}
