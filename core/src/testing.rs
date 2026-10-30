//! Fake physical memory and a recording [`Kernel`] for host tests.
//!
//! Built for `cargo test` and with the `testing` feature, which `model/`
//! uses. The kernel never enables it.

use alloc::vec;
use alloc::vec::Vec;

use crate::cap::{Cap, CapType};
use crate::kernel::{Kernel, Preempted};
use crate::slot::{Slot, SlotAddr, SlotMemory};

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
        assert!(base % 8 == 0 && len % 8 == 0);
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
        assert!(paddr % 8 == 0, "unaligned access at {paddr:#x}");
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
        assert!(len % 8 == 0);
        if len == 0 {
            return;
        }
        let first = self.index(paddr);
        let last = self.index(paddr + len - 8);
        self.words[first..=last].fill(0);
    }

    /// Whether `len` bytes from `paddr` are all zero.
    pub fn is_zero(&self, paddr: u64, len: u64) -> bool {
        assert!(len % 8 == 0);
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
}

impl TestKernel {
    /// A kernel over `len` bytes of fake memory from `base`.
    pub fn new(base: u64, len: u64) -> TestKernel {
        TestKernel {
            mem: FakeMemory::new(base, len),
            events: Vec::new(),
            preempt_in: None,
            preempt_points: 0,
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
