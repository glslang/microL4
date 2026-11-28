//! The guest's memory and its SynIC: one [`Ram`] that stands for guest
//! physical memory from 0, the SIM and SIEF pages in it, SINT 2's
//! interrupt line, and windows over it behind `libsys::mem`'s [`Memory`].
//!
//! Every window is a [`Page`] (or a [`View`] of a GPADL's pages), so a
//! driver under test reaches guest memory through the same trait as on
//! the target, and the host reaches it directly. The machine is shared by
//! reference between the host, the driver and the test; its own state is
//! in [`Cell`]s.

use core::cell::Cell;
use core::sync::atomic::{Ordering, fence};

use libsys::mem::{Memory, Part, Ram, Width};

/// A page.
pub const PAGE: u64 = 4096;
/// The standard machine's layout, by guest physical address. The SynIC
/// pages, as the kernel's boot region would hold them.
pub const SIM: u64 = 0x1000;
pub const SIEF: u64 = 0x2000;
/// The two monitor pages and the event-flags page, consecutive, as root
/// retypes them (`docs/design.md`, "Arguments").
pub const MONITOR: u64 = 0x4000;
pub const EVENT_FLAGS: u64 = 0x6000;
/// netvsc's channel frame: 2 MiB, 2 MiB-aligned.
pub const CHANNEL: u64 = 0x20_0000;
pub const CHANNEL_SIZE: u64 = 0x20_0000;
/// The guest's memory: 4 MiB.
pub const RAM: u64 = 0x40_0000;

/// SINT 2's slot in either SynIC page.
pub const SLOT: usize = 512;
/// `MessageFlags`' `MessagePending`, at byte 5 of the slot.
pub const PENDING: u8 = 1;
const FLAGS: usize = 5;

/// The guest's memory and SynIC.
pub struct Machine {
    ram: Ram,
    /// SINT 2's edge, raised and not yet taken.
    interrupt: Cell<bool>,
    /// Edges raised.
    interrupts: Cell<u64>,
    /// Messages the hypervisor holds for SINT 2, behind the slot.
    queued: Cell<usize>,
    /// Sets `MessagePending` only when the guest empties the slot.
    late: Cell<bool>,
    /// How often that set it.
    late_sets: Cell<u64>,
}

impl Default for Machine {
    fn default() -> Machine {
        Machine::new()
    }
}

impl Machine {
    /// The standard machine: [`RAM`] bytes, zeroed.
    pub fn new() -> Machine {
        Machine {
            ram: Ram::new(RAM as usize),
            interrupt: Cell::new(false),
            interrupts: Cell::new(0),
            queued: Cell::new(0),
            late: Cell::new(false),
            late_sets: Cell::new(0),
        }
    }

    /// Guest physical memory, from 0.
    pub fn ram(&self) -> &Ram {
        &self.ram
    }

    /// The SIM page, as the driver maps it: a store that empties slot 2
    /// may set `MessagePending` ([`Machine::set_late_pending`]).
    pub fn sim(&self) -> Page<'_> {
        Page {
            m: self,
            base: SIM as usize,
            len: PAGE as usize,
            hook: true,
        }
    }

    /// The SIEF page, as the driver maps it.
    pub fn sief(&self) -> Page<'_> {
        self.window(SIEF, PAGE)
    }

    /// `len` bytes of guest memory from `gpa`, as a driver maps them.
    pub fn window(&self, gpa: u64, len: u64) -> Page<'_> {
        assert!(
            gpa.checked_add(len).is_some_and(|end| end <= RAM),
            "hvmock: a window of {len:#x} bytes at {gpa:#x} outside guest memory"
        );
        Page {
            m: self,
            base: gpa as usize,
            len: len as usize,
            hook: false,
        }
    }

    /// The pages `pages` as one window, in order: what a GPADL gives the
    /// host.
    pub fn view<'a>(&'a self, pages: &'a [u64]) -> View<'a> {
        for &p in pages {
            assert!(p < RAM / PAGE, "hvmock: page {p:#x} outside guest memory");
        }
        View { m: self, pages }
    }

    /// Takes SINT 2's edge: true if one was raised since the last take,
    /// as a bound notification's signal would be.
    pub fn take_interrupt(&self) -> bool {
        self.interrupt.replace(false)
    }

    /// Whether an edge is raised and not taken.
    pub fn interrupt_pending(&self) -> bool {
        self.interrupt.get()
    }

    /// Edges raised so far.
    pub fn interrupts(&self) -> u64 {
        self.interrupts.get()
    }

    /// Raises SINT 2's edge.
    pub fn raise(&self) {
        self.interrupt.set(true);
        self.interrupts.set(self.interrupts.get() + 1);
    }

    /// Sets `MessagePending` never at delivery, and only when the guest's
    /// store empties the slot while a message waits: the latest the TLFS
    /// allows ("upon message delivery or at any time afterwards"), so a
    /// guest that trusts its copy of the flags misses the `Eom`.
    pub fn set_late_pending(&self, late: bool) {
        self.late.set(late);
    }

    pub fn late_pending(&self) -> bool {
        self.late.get()
    }

    /// How often the late flag was set.
    pub fn late_sets(&self) -> u64 {
        self.late_sets.get()
    }

    pub(crate) fn set_queued(&self, n: usize) {
        self.queued.set(n);
    }

    /// The guest wrote into slot 2's `MessageType`.
    fn slot_written(&self) {
        let slot = SIM as usize + SLOT;
        if self.late.get()
            && self.queued.get() != 0
            && self.ram.load32(slot, Ordering::Relaxed) == 0
        {
            self.ram
                .or(slot + FLAGS, Width::Byte, PENDING.into(), Ordering::SeqCst);
            self.late_sets.set(self.late_sets.get() + 1);
        }
    }
}

/// A window of guest memory: what a driver maps.
#[derive(Clone, Copy)]
pub struct Page<'m> {
    m: &'m Machine,
    base: usize,
    len: usize,
    hook: bool,
}

impl Page<'_> {
    fn part(&self) -> Part<&Ram> {
        Part::memory(&self.m.ram, self.base, self.len)
    }

    /// The window's guest physical address.
    pub fn gpa(&self) -> u64 {
        self.base as u64
    }

    fn after(&self, offset: usize, len: usize) {
        if self.hook && offset < SLOT + 4 && offset + len > SLOT {
            self.m.slot_written();
        }
    }
}

impl Memory for Page<'_> {
    fn len(&self) -> usize {
        self.len
    }
    fn load(&self, offset: usize, width: Width, order: Ordering) -> u64 {
        self.part().load(offset, width, order)
    }
    fn store(&self, offset: usize, width: Width, value: u64, order: Ordering) {
        self.part().store(offset, width, value, order);
        self.after(offset, width.bytes());
    }
    fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64 {
        let old = self.part().swap(offset, width, value, order);
        self.after(offset, width.bytes());
        old
    }
    fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64 {
        let old = self.part().or(offset, width, bits, order);
        self.after(offset, width.bytes());
        old
    }
    fn read(&self, offset: usize, out: &mut [u8]) {
        self.part().read(offset, out)
    }
    fn write(&self, offset: usize, bytes: &[u8]) {
        self.part().write(offset, bytes);
        self.after(offset, bytes.len());
    }
    fn fence(&self, order: Ordering) {
        fence(order);
    }
}

/// Pages of guest memory, in a GPADL's order, as one window: byte `i` is
/// byte `i mod 4096` of page `pages[i / 4096]`. An atomic access, aligned
/// to its width, never crosses a page; a byte copy may.
#[derive(Clone, Copy)]
pub struct View<'a> {
    m: &'a Machine,
    pages: &'a [u64],
}

impl View<'_> {
    /// The guest physical address of byte `offset`; panics past the end.
    pub fn gpa(&self, offset: usize) -> u64 {
        let page = self
            .pages
            .get(offset / PAGE as usize)
            .unwrap_or_else(|| panic!("hvmock: byte {offset:#x} past a view of {:#x}", self.len()));
        page * PAGE + (offset as u64 % PAGE)
    }

    pub fn pages(&self) -> &[u64] {
        self.pages
    }

    fn check(&self, offset: usize, len: usize) {
        assert!(
            offset.checked_add(len).is_some_and(|end| end <= self.len()),
            "hvmock: {len} bytes at {offset:#x} outside a view of {:#x}",
            self.len()
        );
    }

    /// Calls `f` with each piece of `offset..offset + len` that lies in
    /// one page: its guest address, and its offset in the run.
    fn pieces(&self, offset: usize, len: usize, mut f: impl FnMut(usize, usize, usize)) {
        self.check(offset, len);
        let mut done = 0;
        while done < len {
            let at = offset + done;
            let n = (PAGE as usize - at % PAGE as usize).min(len - done);
            f(self.gpa(at) as usize, done, n);
            done += n;
        }
    }

    fn atomic(&self, offset: usize, width: Width) -> usize {
        self.check(offset, width.bytes());
        self.gpa(offset) as usize
    }
}

impl Memory for View<'_> {
    fn len(&self) -> usize {
        self.pages.len() * PAGE as usize
    }
    fn load(&self, offset: usize, width: Width, order: Ordering) -> u64 {
        self.m.ram.load(self.atomic(offset, width), width, order)
    }
    fn store(&self, offset: usize, width: Width, value: u64, order: Ordering) {
        self.m
            .ram
            .store(self.atomic(offset, width), width, value, order)
    }
    fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64 {
        self.m
            .ram
            .swap(self.atomic(offset, width), width, value, order)
    }
    fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64 {
        self.m
            .ram
            .or(self.atomic(offset, width), width, bits, order)
    }
    fn read(&self, offset: usize, out: &mut [u8]) {
        self.pieces(offset, out.len(), |gpa, at, n| {
            self.m.ram.read(gpa, &mut out[at..at + n])
        });
    }
    fn write(&self, offset: usize, bytes: &[u8]) {
        self.pieces(offset, bytes.len(), |gpa, at, n| {
            self.m.ram.write(gpa, &bytes[at..at + n])
        });
    }
    fn fence(&self, order: Ordering) {
        fence(order);
    }
}
