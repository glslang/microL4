//! Fake physical memory and a recording [`Kernel`] for host tests.
//!
//! Built for `cargo test` and with the `testing` feature, which `model/`
//! uses. The kernel never enables it.

use alloc::boxed::Box;
use alloc::collections::{BTreeMap, BTreeSet};
use alloc::vec;
use alloc::vec::Vec;

use crate::acpi::IsaRoute;
use crate::apic;
use crate::cap::{Cap, CapType, ENDPOINT_BITS, NOTIFICATION_BITS, SLOT_SIZE};
use crate::hyperv::{BLOCK_WORDS, Hypercalls, PostMessage, SignalEvent};
use crate::ioport::{self, IoPorts, PortBitmap, Width};
use crate::ipc::IpcEnv;
use crate::irq::{
    self, Action, IRQS, Interrupts, IoApicDesc, IrqTable, Routing, RteWrite, SintAction,
};
use crate::kernel::{Kernel, Preempted};
use crate::sched::{Scheduler, Scheduling};
use crate::slot::{Slot, SlotAddr, SlotMemory};
use crate::tcb::{EpRef, NtfnRef, REGS_OFFSET, TcbRef, Tcbs, ThreadState, Threads, XSAVE_OFFSET};

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
    CancelBadgedSends { ep: EpRef, badge: u64 },
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
    /// The IRQ table, the IRQ node, the port bitmap and models of the
    /// I/O APICs and the local APIC, for [`Interrupts`] and [`IoPorts`].
    /// No I/O APIC unless a test adds them ([`FakeDevices::q35`]).
    pub dev: FakeDevices,
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
            dev: FakeDevices::new(),
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

/// Slots of fake memory, and of the IRQ node at [`IRQ_NODE_BASE`].
impl SlotMemory for TestKernel {
    fn load(&self, at: SlotAddr) -> Slot {
        if FakeDevices::in_node(at) {
            self.dev.node.load(at)
        } else {
            self.mem.load(at)
        }
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        if FakeDevices::in_node(at) {
            self.dev.node.store(at, slot)
        } else {
            self.mem.store(at, slot)
        }
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

    /// Records the call: there are no endpoint queues to cancel.
    fn cancel_badged_sends(&mut self, ep: EpRef, badge: u64) {
        self.thread_events
            .push(ThreadEvent::CancelBadgedSends { ep, badge });
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

    fn notification_word(&self, n: NtfnRef, offset: u64) -> u64 {
        self.mem.read(notification_field(n, offset))
    }

    fn set_notification_word(&mut self, n: NtfnRef, offset: u64, value: u64) {
        self.mem.write(notification_field(n, offset), value)
    }
}

/// Notification words in fake memory, at the notification's physical
/// address.
fn notification_field(n: NtfnRef, offset: u64) -> u64 {
    assert!(
        offset < 1 << NOTIFICATION_BITS && offset.is_multiple_of(8),
        "notification field offset {offset:#x}"
    );
    n.get() + offset
}

/// Endpoint words in fake memory, at the endpoint's physical address.
fn endpoint_field(ep: EpRef, offset: u64) -> u64 {
    assert!(
        offset < 1 << ENDPOINT_BITS && offset.is_multiple_of(8),
        "endpoint field offset {offset:#x}"
    );
    ep.get() + offset
}

/// A [`TestKernel`] whose hooks do what the kernel's do for threads, IPC,
/// interrupts and I/O ports, for tests of [`crate::ipc`],
/// [`crate::syscall`], [`crate::irq`] and [`crate::ioport`]:
///
/// - [`Threads::cancel_ipc`] is [`crate::ipc::cancel_ipc`], and
///   [`Threads::cancel_badged_sends`] [`crate::ipc::cancel_badged_sends`],
///   each after recording the call as [`TestKernel`] does;
/// - [`Kernel::finalise`] unbinds and suspends a TCB when its last
///   capability goes ([`crate::tcb::finalise`]), releases an endpoint's
///   or a notification's queue ([`crate::ipc::finalise`]), and finalises
///   an IRQHandler ([`crate::irq::finalise`]) or an IOPort
///   ([`crate::ioport::finalise`]), after recording the call as
///   [`TestKernel`] does; [`Kernel::after_delete`] frees their IRQ or
///   range;
/// - [`Threads::invoked_by_call`] is [`crate::syscall::invoked_by_call`];
/// - [`IpcEnv`] reads and writes fake memory.
///
/// Every other hook is [`TestKernel`]'s, which the fields reach through
/// `Deref`.
#[derive(Clone, Debug)]
pub struct IpcTestKernel(pub TestKernel);

impl IpcTestKernel {
    /// A kernel over `len` bytes of fake memory from `base`.
    pub fn new(base: u64, len: u64) -> IpcTestKernel {
        IpcTestKernel(TestKernel::new(base, len))
    }
}

impl core::ops::Deref for IpcTestKernel {
    type Target = TestKernel;

    fn deref(&self) -> &TestKernel {
        &self.0
    }
}

impl core::ops::DerefMut for IpcTestKernel {
    fn deref_mut(&mut self) -> &mut TestKernel {
        &mut self.0
    }
}

impl SlotMemory for IpcTestKernel {
    fn load(&self, at: SlotAddr) -> Slot {
        self.0.load(at)
    }

    fn store(&mut self, at: SlotAddr, slot: Slot) {
        self.0.store(at, slot)
    }
}

impl Kernel for IpcTestKernel {
    fn finalise(&mut self, cap: Cap, last: bool) -> Option<Cap> {
        let cleanup = self.0.finalise(cap, last);
        if let (Some(t), true) = (TcbRef::from_cap(&cap), last) {
            crate::tcb::finalise(self, t);
        }
        crate::ipc::finalise(self, cap, last);
        match cap.cap_type() {
            CapType::IrqHandler => irq::finalise(self, cap, last),
            CapType::IoPort => ioport::finalise(cap, last),
            _ => cleanup,
        }
    }

    fn after_delete(&mut self, cleanup: Cap) {
        self.0.after_delete(cleanup);
        match cleanup.cap_type() {
            CapType::IrqHandler => irq::after_delete(self, cleanup),
            CapType::IoPort => ioport::after_delete(self, cleanup),
            _ => {}
        }
    }

    fn moved(&mut self, cap: Cap, from: SlotAddr, to: SlotAddr) {
        self.0.moved(cap, from, to)
    }

    fn zero(&mut self, paddr: u64, len: u64) {
        self.0.zero(paddr, len)
    }

    fn init_object(&mut self, cap: Cap) {
        self.0.init_object(cap)
    }

    fn preempt(&mut self) -> Result<(), Preempted> {
        self.0.preempt()
    }
}

impl Tcbs for IpcTestKernel {
    fn tcb_word(&self, t: TcbRef, offset: u64) -> u64 {
        self.0.tcb_word(t, offset)
    }

    fn set_tcb_word(&mut self, t: TcbRef, offset: u64, value: u64) {
        self.0.set_tcb_word(t, offset, value)
    }
}

impl Scheduling for IpcTestKernel {
    fn scheduler(&self) -> &Scheduler {
        &self.0.sched
    }

    fn scheduler_mut(&mut self) -> &mut Scheduler {
        &mut self.0.sched
    }
}

impl Threads for IpcTestKernel {
    fn cancel_ipc(&mut self, t: TcbRef) {
        self.0.thread_events.push(ThreadEvent::CancelIpc(t));
        crate::ipc::cancel_ipc(self, t);
    }

    fn cancel_badged_sends(&mut self, ep: EpRef, badge: u64) {
        self.0
            .thread_events
            .push(ThreadEvent::CancelBadgedSends { ep, badge });
        crate::ipc::cancel_badged_sends(self, ep, badge);
    }

    fn invoked_by_call(&self) -> bool {
        crate::syscall::invoked_by_call(self)
    }

    fn synic_pages(&self) -> [u64; 2] {
        self.0.synic_pages()
    }

    fn set_current_fs_base(&mut self, value: u64) {
        self.0.set_current_fs_base(value)
    }

    fn write_buffer_word(&mut self, paddr: u64, value: u64) {
        self.0.write_buffer_word(paddr, value)
    }

    fn notification_word(&self, n: NtfnRef, offset: u64) -> u64 {
        self.0.notification_word(n, offset)
    }

    fn set_notification_word(&mut self, n: NtfnRef, offset: u64, value: u64) {
        self.0.set_notification_word(n, offset, value)
    }
}

/// Paging structures in fake memory, as [`TestKernel`] keeps them.
impl crate::vspace::PagingStore for IpcTestKernel {
    fn entry(&self, table: u64, i: usize) -> u64 {
        self.0.entry(table, i)
    }

    fn set_entry(&mut self, table: u64, i: usize, entry: u64) {
        self.0.set_entry(table, i, entry)
    }

    fn backref(&self, table: u64, i: usize) -> u64 {
        self.0.backref(table, i)
    }

    fn set_backref(&mut self, table: u64, i: usize, backref: u64) {
        self.0.set_backref(table, i, backref)
    }

    fn flush(&mut self, flush: crate::vspace::Flush) {
        self.0.flush(flush)
    }
}

impl IpcEnv for IpcTestKernel {
    fn endpoint_word(&self, ep: EpRef, offset: u64) -> u64 {
        self.0.mem.read(endpoint_field(ep, offset))
    }

    fn set_endpoint_word(&mut self, ep: EpRef, offset: u64, value: u64) {
        self.0.mem.write(endpoint_field(ep, offset), value)
    }

    fn read_buffer_word(&self, paddr: u64) -> u64 {
        self.0.mem.read(paddr)
    }
}

// ---------------------------------------------------------------------------
// Interrupts and I/O ports
// ---------------------------------------------------------------------------

/// Where the test kernels keep the IRQ node: far above every test's fake
/// memory, in memory of its own.
pub const IRQ_NODE_BASE: u64 = 0xF000_0000;

/// The read-only bits of a redirection entry's low word: delivery status
/// and Remote IRR.
const RTE_READ_ONLY: u32 = 1 << 12 | apic::REDIRECTION_REMOTE_IRR;

/// A model of an I/O APIC, as QEMU 8.2's `hw/intc/ioapic.c` behaves (from
/// memory): its redirection entries, its input lines and its latched edge
/// requests.
///
/// - A level pin sends its vector while its line is high, it is unmasked
///   and Remote IRR is clear, and sets Remote IRR; an EOI for the vector,
///   broadcast by the local APIC or written to the EOI register (version
///   `0x20` only), clears Remote IRR in level entries with that vector.
/// - An edge pin latches a request each time its line is raised while it
///   is unmasked, as QEMU does whether or not the line was already high,
///   and drops one raised while it is masked (the 82093AA's rule); a
///   latched request is sent once.
/// - Writing an entry keeps its read-only bits, and an entry written
///   edge-triggered loses Remote IRR (`ioapic_fix_edge_remote_irr`).
/// - With `stuck_remote_irr`, no write and no EOI clears Remote IRR: the
///   hardware ADR 0027's paths would fail on.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeIoApic {
    pub version: u8,
    /// Each pin's entry: low and high word.
    pub entries: Vec<(u32, u32)>,
    /// Each pin's input line.
    pub line: Vec<bool>,
    /// Each edge pin's latched request.
    latched: Vec<bool>,
    pub stuck_remote_irr: bool,
    /// Edge requests dropped because the pin was masked.
    pub dropped_edges: u64,
    /// Writes that unmasked a level entry with Remote IRR set, which the
    /// kernel must never make.
    pub unmasked_with_remote_irr: u64,
}

impl FakeIoApic {
    /// `pins` pins, each masked, edge-triggered and with vector 0, its line
    /// low.
    pub fn new(version: u8, pins: u16) -> FakeIoApic {
        let n = usize::from(pins);
        FakeIoApic {
            version,
            entries: vec![(apic::REDIRECTION_MASKED, 0); n],
            line: vec![false; n],
            latched: vec![false; n],
            stuck_remote_irr: false,
            dropped_edges: 0,
            unmasked_with_remote_irr: 0,
        }
    }

    /// Pin `pin`'s entry's low word.
    pub fn low(&self, pin: u16) -> u32 {
        self.entries[usize::from(pin)].0
    }

    fn level(low: u32) -> bool {
        low & apic::REDIRECTION_LEVEL != 0
    }

    fn masked(low: u32) -> bool {
        low & apic::REDIRECTION_MASKED != 0
    }

    /// Writes pin `pin`'s low word, keeping its read-only bits; returns
    /// the vector it then sends, if any.
    pub fn write_low(&mut self, pin: u16, value: u32) -> Option<u8> {
        let i = usize::from(pin);
        let old = self.entries[i].0;
        let mut new = (value & !RTE_READ_ONLY) | (old & RTE_READ_ONLY);
        if !Self::level(new) && !self.stuck_remote_irr {
            new &= !apic::REDIRECTION_REMOTE_IRR;
        }
        if Self::masked(old) && !Self::masked(new) && Self::level(new) && apic::remote_irr(new) {
            self.unmasked_with_remote_irr += 1;
        }
        self.entries[i].0 = new;
        self.service(pin)
    }

    /// Writes pin `pin`'s high word.
    pub fn write_high(&mut self, pin: u16, value: u32) {
        self.entries[usize::from(pin)].1 = value;
    }

    /// An EOI for `vector`: Remote IRR clears in every level entry with
    /// it, which then sends again if its line is still high. Returns the
    /// vectors sent.
    pub fn eoi(&mut self, vector: u8) -> Vec<u8> {
        let mut sent = Vec::new();
        for pin in 0..self.entries.len() as u16 {
            let low = self.low(pin);
            if low & apic::REDIRECTION_VECTOR == u32::from(vector)
                && Self::level(low)
                && apic::remote_irr(low)
                && !self.stuck_remote_irr
            {
                self.entries[usize::from(pin)].0 = low & !apic::REDIRECTION_REMOTE_IRR;
                sent.extend(self.service(pin));
            }
        }
        sent
    }

    /// A write of `vector` to the EOI register, which only version `0x20`
    /// and later have.
    pub fn eoi_register(&mut self, vector: u8) -> Vec<u8> {
        if self.version >= apic::IOAPIC_EOI_VERSION {
            self.eoi(vector)
        } else {
            Vec::new()
        }
    }

    /// Drives pin `pin`'s line: raising it requests an interrupt (dropped
    /// on a masked edge pin). Returns the vector sent, if any.
    pub fn set_line(&mut self, pin: u16, high: bool) -> Option<u8> {
        let i = usize::from(pin);
        self.line[i] = high;
        let low = self.low(pin);
        if !high {
            return None;
        }
        if Self::level(low) {
            return self.service(pin);
        }
        if Self::masked(low) {
            self.dropped_edges += 1;
            return None;
        }
        self.latched[i] = true;
        self.service(pin)
    }

    /// Leaves pin `pin` as a delivery whose EOI never came does: level,
    /// masked, `vector`, Remote IRR set.
    pub fn strand(&mut self, pin: u16, vector: u8) {
        self.entries[usize::from(pin)].0 = u32::from(vector)
            | apic::REDIRECTION_LEVEL
            | apic::REDIRECTION_MASKED
            | apic::REDIRECTION_REMOTE_IRR;
    }

    /// Sends pin `pin`'s vector if the pin may.
    fn service(&mut self, pin: u16) -> Option<u8> {
        let i = usize::from(pin);
        let low = self.low(pin);
        if Self::masked(low) {
            return None;
        }
        let vector = (low & apic::REDIRECTION_VECTOR) as u8;
        if Self::level(low) {
            if !self.line[i] || apic::remote_irr(low) {
                return None;
            }
            self.entries[i].0 = low | apic::REDIRECTION_REMOTE_IRR;
        } else {
            if !self.latched[i] {
                return None;
            }
            self.latched[i] = false;
        }
        Some(vector)
    }
}

/// An I/O port access [`FakeDevices`] recorded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PortRecord {
    pub port: u16,
    pub width: Width,
    /// `None` for a read; the value written for a write.
    pub written: Option<u32>,
}

/// A hypercall, EOM write or VP index read the kernel made, as
/// [`FakeDevices`] records it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Hypercall {
    /// `HvCallPostMessage`: the input value and the whole input block.
    Post {
        input: u64,
        block: Box<[u64; BLOCK_WORDS]>,
    },
    /// `HvCallSignalEvent`: the input value and the fast input.
    Signal {
        input: u64,
        rdx: u64,
    },
    Eom,
    VpIndex,
}

/// A model of the boot CPU's SynIC (M9), as far as the kernel reaches it:
/// the 16 SINT registers, each write to them, and the hypervisor's side of
/// a SINT: a message or event edge reaches the local APIC as the SINT's
/// vector only while the SINT is unmasked, and is lost otherwise (TLFS).
/// With `enabled` false there is no SynIC, as under QEMU's TCG.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct FakeSynic {
    pub enabled: bool,
    /// SINT0 to SINT15, as the kernel left them at boot: masked, the
    /// firmware's reserved bits kept.
    pub sints: [u64; 16],
    /// Every SINT write: the SINT and the value.
    pub writes: Vec<(u8, u64)>,
    /// Edges raised on a masked SINT, and so lost.
    pub lost_edges: u64,
}

impl FakeSynic {
    /// Reserved bits the model's SINTs start with, so tests see them kept.
    pub const RESERVED: u64 = 0xA5A5_0000_0000_5A00;

    /// A SynIC with every SINT masked, or none.
    pub fn new(enabled: bool) -> FakeSynic {
        FakeSynic {
            enabled,
            sints: [Self::RESERVED | crate::hyperv::SINT_MASKED; 16],
            writes: Vec::new(),
            lost_edges: 0,
        }
    }

    /// The hypervisor raises an edge on SINT `n`: its vector, if unmasked.
    pub fn raise(&mut self, n: u8) -> Option<u8> {
        let v = self.sints[usize::from(n)];
        if v & crate::hyperv::SINT_MASKED != 0 {
            self.lost_edges += 1;
            None
        } else {
            Some((v & crate::hyperv::SINT_VECTOR) as u8)
        }
    }
}

/// The interrupt and port state of a test kernel, and models of its
/// devices: the IRQ table, the routes, the IRQ node, the I/O APICs
/// ([`FakeIoApic`]), the local APIC's IRR, the port bitmap and the ports;
/// from M9 the SynIC ([`FakeSynic`]) and the hypercalls made.
#[derive(Clone, Debug)]
pub struct FakeDevices {
    pub table: IrqTable,
    pub routing: Routing,
    pub ioapics: Vec<FakeIoApic>,
    /// The local APIC's IRR: vectors the I/O APICs sent and the CPU has
    /// not taken.
    pub lapic_irr: BTreeSet<u8>,
    /// The boot CPU's local APIC ID, for the destination words.
    pub apic_id: u8,
    /// Every action performed, in order.
    pub actions: Vec<Action>,
    /// The IRQ node's slots, at [`IRQ_NODE_BASE`].
    pub node: FakeMemory,
    pub ports: PortBitmap,
    /// Every port access, in order.
    pub port_log: Vec<PortRecord>,
    /// What a read of a port returns: the last value written to it, else
    /// [`FakeDevices::FLOATING`].
    pub port_values: BTreeMap<u16, u32>,
    pub synic: FakeSynic,
    /// Every hypercall, EOM and VP index read, in order.
    pub hypercalls: Vec<Hypercall>,
    /// What the next hypercalls return.
    pub hv_status: u16,
    /// What `VpIndex` reads.
    pub vp_index: u64,
}

impl FakeDevices {
    /// What a port no test wrote reads as, wider than any width, so tests
    /// see the zero-extension.
    pub const FLOATING: u32 = 0xDEAD_BEEF;

    /// No I/O APIC, no route, nothing issued, no SynIC.
    pub fn new() -> FakeDevices {
        FakeDevices {
            table: IrqTable::new(),
            routing: Routing::NONE,
            ioapics: Vec::new(),
            lapic_irr: BTreeSet::new(),
            apic_id: 0,
            actions: Vec::new(),
            node: FakeMemory::new(IRQ_NODE_BASE, IRQS as u64 * SLOT_SIZE),
            ports: PortBitmap::new(),
            port_log: Vec::new(),
            port_values: BTreeMap::new(),
            synic: FakeSynic::new(false),
            hypercalls: Vec::new(),
            hv_status: 0,
            vp_index: 0,
        }
    }

    /// Performs a SINT action as the kernel's `hyperv.rs` does: reads the
    /// SINT, writes [`SintAction::value`].
    pub fn sint_action(&mut self, action: SintAction) {
        assert!(self.synic.enabled, "a SINT touched without a SynIC");
        let n = action.sint();
        let value = action.value(self.synic.sints[usize::from(n)]);
        self.synic.sints[usize::from(n)] = value;
        self.synic.writes.push((n, value));
    }

    /// The hypervisor raises an edge on SINT `n`.
    pub fn raise_sint(&mut self, n: u8) {
        let sent = self.synic.raise(n);
        self.lapic_irr.extend(sent);
    }

    /// A device writes MSI `data` to the local APIC: its vector, bits 7:0,
    /// becomes pending (an edge; a second one merges into the IRR bit).
    pub fn msi(&mut self, data: u64) {
        self.lapic_irr.insert(data as u8);
    }

    /// QEMU's q35 with one I/O APIC of `version` and 24 pins, GSI 0 to 23,
    /// and its MADT's overrides: ISA IRQ 0 to GSI 2 (so IRQ 2 has no
    /// route), and IRQs 5, 9, 10 and 11 level-triggered, active high
    /// (`docs/design.md`, "Local APIC, PIC and I/O APIC (M3)").
    pub fn q35(version: u8) -> FakeDevices {
        let mut d = FakeDevices::new();
        d.ioapics.push(FakeIoApic::new(version, 24));
        d.routing.ioapics[0] = Some(IoApicDesc {
            gsi_base: 0,
            pins: 24,
            version,
        });
        for (n, route) in d.routing.isa.iter_mut().enumerate() {
            let n = n as u32;
            *route = match n {
                0 => Some(IsaRoute {
                    gsi: 2,
                    level: false,
                    active_low: false,
                }),
                2 => None,
                _ => Some(IsaRoute {
                    gsi: n,
                    level: matches!(n, 5 | 9 | 10 | 11),
                    active_low: false,
                }),
            };
        }
        d
    }

    /// Whether `at` is a slot of the IRQ node.
    pub fn in_node(at: SlotAddr) -> bool {
        (IRQ_NODE_BASE..IRQ_NODE_BASE + IRQS as u64 * SLOT_SIZE).contains(&at.get())
    }

    /// Performs `action` on its pin's model I/O APIC, as the kernel's
    /// `ioapic.rs` does: reads the entry, then makes [`Action::writes`].
    pub fn perform(&mut self, action: Action) -> bool {
        self.actions.push(action);
        let pin = action.pin();
        let apic_id = self.apic_id;
        let io = &mut self.ioapics[usize::from(pin.ioapic)];
        let low = io.low(pin.pin);
        if let Action::CheckRemoteIrr(_) = action {
            return apic::remote_irr(low);
        }
        let mut sent = Vec::new();
        for w in action.writes(low, apic_id).into_iter().flatten() {
            match w {
                RteWrite::Low(v) => sent.extend(io.write_low(pin.pin, v)),
                RteWrite::High(v) => io.write_high(pin.pin, v),
                RteWrite::Eoi(v) => sent.extend(io.eoi_register(v as u8)),
            }
        }
        self.lapic_irr.extend(sent);
        false
    }

    /// Drives the line of the pin that serves `gsi`, which must exist.
    pub fn set_line(&mut self, gsi: u32, high: bool) {
        let (pin, _) = self
            .routing
            .pin(u64::from(gsi))
            .expect("a GSI an I/O APIC serves");
        let sent = self.ioapics[usize::from(pin.ioapic)].set_line(pin.pin, high);
        self.lapic_irr.extend(sent);
    }

    /// The model I/O APIC and the pin on it that serve `gsi`.
    pub fn pin(&self, gsi: u32) -> (&FakeIoApic, u16) {
        let (pin, _) = self
            .routing
            .pin(u64::from(gsi))
            .expect("a GSI an I/O APIC serves");
        (&self.ioapics[usize::from(pin.ioapic)], pin.pin)
    }

    /// The model I/O APIC and the pin on it that serve `gsi`, to change.
    pub fn pin_mut(&mut self, gsi: u32) -> (&mut FakeIoApic, u16) {
        let (pin, _) = self
            .routing
            .pin(u64::from(gsi))
            .expect("a GSI an I/O APIC serves");
        (&mut self.ioapics[usize::from(pin.ioapic)], pin.pin)
    }

    /// The CPU takes the highest vector the local APIC holds, if any.
    pub fn take(&mut self) -> Option<u8> {
        self.lapic_irr.pop_last()
    }

    /// The kernel's EOI for `vector`, broadcast to every I/O APIC.
    pub fn eoi(&mut self, vector: u8) {
        let mut sent = Vec::new();
        for io in &mut self.ioapics {
            sent.extend(io.eoi(vector));
        }
        self.lapic_irr.extend(sent);
    }

    fn port_in(&mut self, access: ioport::PortAccess) -> u32 {
        let port = access.port();
        self.port_log.push(PortRecord {
            port,
            width: access.width(),
            written: None,
        });
        *self.port_values.get(&port).unwrap_or(&Self::FLOATING)
    }

    fn port_out(&mut self, access: ioport::PortAccess, value: u32) {
        let port = access.port();
        self.port_log.push(PortRecord {
            port,
            width: access.width(),
            written: Some(value),
        });
        self.port_values.insert(port, value);
    }
}

impl Default for FakeDevices {
    fn default() -> FakeDevices {
        FakeDevices::new()
    }
}

impl Interrupts for TestKernel {
    fn irq_table(&self) -> &IrqTable {
        &self.dev.table
    }

    fn irq_table_mut(&mut self) -> &mut IrqTable {
        &mut self.dev.table
    }

    fn routing(&self) -> &Routing {
        &self.dev.routing
    }

    fn irq_node(&self) -> SlotAddr {
        SlotAddr::new(IRQ_NODE_BASE).expect("a slot address")
    }

    fn irq_action(&mut self, action: Action) -> bool {
        self.dev.perform(action)
    }

    fn apic_id(&self) -> u8 {
        self.dev.apic_id
    }

    fn synic(&self) -> bool {
        self.dev.synic.enabled
    }

    fn sint_action(&mut self, action: SintAction) {
        self.dev.sint_action(action)
    }
}

/// The hypercalls, recorded, each answering [`FakeDevices::hv_status`].
impl Hypercalls for TestKernel {
    fn post_message(&mut self, call: PostMessage) -> u16 {
        self.dev.hypercalls.push(Hypercall::Post {
            input: call.input_value(),
            block: Box::new(*call.block()),
        });
        self.dev.hv_status
    }

    fn signal_event(&mut self, call: SignalEvent) -> u16 {
        self.dev.hypercalls.push(Hypercall::Signal {
            input: call.input_value(),
            rdx: call.input(),
        });
        self.dev.hv_status
    }

    fn eom(&mut self) {
        self.dev.hypercalls.push(Hypercall::Eom);
    }

    fn vp_index(&mut self) -> u64 {
        self.dev.hypercalls.push(Hypercall::VpIndex);
        self.dev.vp_index
    }
}

impl IoPorts for TestKernel {
    fn port_bitmap(&self) -> &PortBitmap {
        &self.dev.ports
    }

    fn port_bitmap_mut(&mut self) -> &mut PortBitmap {
        &mut self.dev.ports
    }

    fn port_in(&mut self, access: ioport::PortAccess) -> u32 {
        self.dev.port_in(access)
    }

    fn port_out(&mut self, access: ioport::PortAccess, value: u32) {
        self.dev.port_out(access, value)
    }
}

impl Interrupts for IpcTestKernel {
    fn irq_table(&self) -> &IrqTable {
        self.0.irq_table()
    }

    fn irq_table_mut(&mut self) -> &mut IrqTable {
        self.0.irq_table_mut()
    }

    fn routing(&self) -> &Routing {
        self.0.routing()
    }

    fn irq_node(&self) -> SlotAddr {
        self.0.irq_node()
    }

    fn irq_action(&mut self, action: Action) -> bool {
        self.0.irq_action(action)
    }

    fn apic_id(&self) -> u8 {
        self.0.apic_id()
    }

    fn synic(&self) -> bool {
        self.0.synic()
    }

    fn sint_action(&mut self, action: SintAction) {
        self.0.sint_action(action)
    }
}

impl Hypercalls for IpcTestKernel {
    fn post_message(&mut self, call: PostMessage) -> u16 {
        self.0.post_message(call)
    }

    fn signal_event(&mut self, call: SignalEvent) -> u16 {
        self.0.signal_event(call)
    }

    fn eom(&mut self) {
        self.0.eom()
    }

    fn vp_index(&mut self) -> u64 {
        self.0.vp_index()
    }
}

impl IoPorts for IpcTestKernel {
    fn port_bitmap(&self) -> &PortBitmap {
        self.0.port_bitmap()
    }

    fn port_bitmap_mut(&mut self) -> &mut PortBitmap {
        self.0.port_bitmap_mut()
    }

    fn port_in(&mut self, access: ioport::PortAccess) -> u32 {
        self.0.port_in(access)
    }

    fn port_out(&mut self, access: ioport::PortAccess, value: u32) {
        self.0.port_out(access, value)
    }
}
