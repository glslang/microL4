//! A split virtqueue of 64 entries, the driver's side (virtio 1.2, 2.7,
//! read in the specification's `split-ring.tex`, fetched 2026-11-27), in
//! the DMA frame at [`layout::ring`].
//!
//! Each descriptor `i` names buffer `i` of its queue ([`layout::buffer`]),
//! written once by [`Virtq::init`], so no other physical address ever
//! reaches a ring. The driver keeps its own copy of every index it writes
//! and a map of the descriptors the device holds ([`Virtq::posted`]), and
//! reads the device's used ring without trusting it: an element is taken
//! only if its `id` names a descriptor the device holds, which then is the
//! driver's again; any other is counted as bad and passed, and a used
//! index more than 64 ahead of the driver's is taken as no elements and
//! counted. So the device can make the driver neither read outside the
//! ring nor post a descriptor twice, whatever it writes.
//!
//! Ring indices are 16-bit and free-running; entry `k` lives at `k mod
//! 64`. The driver writes descriptors and available entries, then the
//! available index with release order ([`Virtq::publish`]); it reads a used
//! index with acquire order ([`Virtq::poll`]).

use core::sync::atomic::Ordering::{Acquire, Relaxed, Release, SeqCst};

use libsys::mem::Memory;

use crate::layout::{self, AVAIL, DESC, DESC_SIZE, QUEUE_SIZE, USED};

/// `VIRTQ_DESC_F_NEXT`: the buffer continues in `next`.
pub const DESC_F_NEXT: u16 = 1;
/// `VIRTQ_DESC_F_WRITE`: the device writes the buffer.
pub const DESC_F_WRITE: u16 = 2;
/// `VIRTQ_DESC_F_INDIRECT`: the buffer is a table of descriptors.
pub const DESC_F_INDIRECT: u16 = 4;
/// `VIRTQ_AVAIL_F_NO_INTERRUPT`: the driver needs no used-buffer
/// notification.
pub const AVAIL_F_NO_INTERRUPT: u16 = 1;
/// `VIRTQ_USED_F_NO_NOTIFY`: the device needs no available-buffer
/// notification.
pub const USED_F_NO_NOTIFY: u16 = 1;

/// Offsets in a ring, from its start.
pub mod off {
    use super::{AVAIL, DESC, DESC_SIZE, QUEUE_SIZE, USED};

    /// Descriptor `i`'s `addr` (le64), `len` (le32), `flags` and `next`
    /// (le16 each).
    pub const fn desc(i: u16) -> usize {
        DESC + DESC_SIZE * i as usize
    }
    pub const DESC_ADDR: usize = 0;
    pub const DESC_LEN: usize = 8;
    pub const DESC_FLAGS: usize = 12;
    pub const DESC_NEXT: usize = 14;

    pub const AVAIL_FLAGS: usize = AVAIL;
    pub const AVAIL_IDX: usize = AVAIL + 2;
    /// Available entry `k` (le16), `k` free-running.
    pub const fn avail_entry(k: u16) -> usize {
        AVAIL + 4 + 2 * (k % QUEUE_SIZE) as usize
    }

    pub const USED_FLAGS: usize = USED;
    pub const USED_IDX: usize = USED + 2;
    /// Used element `k`'s `id` (le32), `k` free-running; its `len` (le32)
    /// follows.
    pub const fn used_elem(k: u16) -> usize {
        USED + 4 + 8 * (k % QUEUE_SIZE) as usize
    }
    pub const USED_ID: usize = 0;
    pub const USED_LEN: usize = 4;
}

/// A used element the driver took: the descriptor the device gave back
/// and the bytes it says it wrote into it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Used {
    pub id: u16,
    pub len: u32,
}

/// The driver's side of one queue.
#[derive(Clone, Copy, Debug)]
pub struct Virtq {
    index: u16,
    /// Where the ring starts in the DMA frame.
    ring: usize,
    /// The next available index the driver writes an entry at.
    avail: u16,
    /// The available index as the ring last showed it.
    published: u16,
    /// The next used index the driver reads.
    used: u16,
    /// Used elements [`Virtq::poll`] found and [`Virtq::take`] has not
    /// taken.
    ready: u16,
    /// Bit `i`: descriptor `i` is the device's, posted and not yet given
    /// back.
    posted: u64,
    /// Whether `VIRTQ_AVAIL_F_NO_INTERRUPT` is clear.
    interrupts: bool,
    /// Where its notifications go in the notify region.
    notify: usize,
}

const ALL: u64 = if QUEUE_SIZE as u32 == u64::BITS {
    u64::MAX
} else {
    (1 << QUEUE_SIZE) - 1
};

impl Virtq {
    /// Queue `index`, with nothing posted and used-buffer notifications
    /// on, as zeroed memory has them.
    pub const fn new(index: u16) -> Virtq {
        Virtq {
            index,
            ring: layout::ring(index),
            avail: 0,
            published: 0,
            used: 0,
            ready: 0,
            posted: 0,
            interrupts: true,
            notify: 0,
        }
    }

    pub const fn index(&self) -> u16 {
        self.index
    }

    /// Where the ring starts in the DMA frame.
    pub const fn ring(&self) -> usize {
        self.ring
    }

    /// The offsets of its descriptor table, available ring and used ring
    /// in the DMA frame, which the driver gives the device as `base` plus
    /// each.
    pub const fn parts(&self) -> [usize; 3] {
        [self.ring + DESC, self.ring + AVAIL, self.ring + USED]
    }

    /// Zeroes the ring and writes every descriptor: its own buffer's
    /// physical address, `base` + [`layout::buffer`], and `flags`
    /// ([`DESC_F_WRITE`] for a queue the device writes, else 0), length 0
    /// until posted.
    pub fn init(&mut self, mem: &impl Memory, base: u64, flags: u16) {
        mem.fill(self.ring, layout::RING_STRIDE, 0);
        for i in 0..QUEUE_SIZE {
            let d = self.ring + off::desc(i);
            let addr = base + layout::buffer(self.index, i) as u64;
            mem.store64(d + off::DESC_ADDR, addr, Relaxed);
            mem.store32(d + off::DESC_LEN, 0, Relaxed);
            mem.store16(d + off::DESC_FLAGS, flags, Relaxed);
            mem.store16(d + off::DESC_NEXT, 0, Relaxed);
        }
        *self = Virtq {
            notify: self.notify,
            ..Virtq::new(self.index)
        };
    }

    /// Where its notifications go in the notify region:
    /// `queue_notify_off × notify_off_multiplier`.
    pub fn set_notify(&mut self, offset: usize) {
        self.notify = offset;
    }

    pub const fn notify(&self) -> usize {
        self.notify
    }

    /// The descriptors the device holds: posted and not yet given back.
    pub const fn posted(&self) -> u64 {
        self.posted
    }

    /// The lowest descriptor the device does not hold.
    pub const fn free(&self) -> Option<u16> {
        let free = !self.posted & ALL;
        if free == 0 {
            None
        } else {
            Some(free.trailing_zeros() as u16)
        }
    }

    /// Whether used-buffer notifications are on.
    pub const fn interrupts(&self) -> bool {
        self.interrupts
    }

    /// Posts descriptor `id` with `len` bytes: writes its length and the
    /// next available entry; [`Virtq::publish`] shows it to the device.
    /// Panics if the device holds it, which only a bug in the driver
    /// causes, since only [`Virtq::take`] gives one back.
    #[track_caller]
    pub fn post(&mut self, mem: &impl Memory, id: u16, len: u32) {
        assert!(
            id < QUEUE_SIZE && self.posted & 1 << id == 0,
            "virtio-net: queue {} descriptor {id} posted twice",
            self.index
        );
        let d = self.ring + off::desc(id);
        mem.store32(d + off::DESC_LEN, len, Relaxed);
        mem.store16(self.ring + off::avail_entry(self.avail), id, Relaxed);
        self.avail = self.avail.wrapping_add(1);
        self.posted |= 1 << id;
    }

    /// Writes the available index if anything was posted since the last
    /// time, with release order, so that the descriptors, the entries and
    /// the buffers they name are written first; whether it did.
    pub fn publish(&mut self, mem: &impl Memory) -> bool {
        if self.avail == self.published {
            return false;
        }
        mem.store16(self.ring + off::AVAIL_IDX, self.avail, Release);
        self.published = self.avail;
        true
    }

    /// Whether to notify the device after [`Virtq::publish`]: a
    /// sequentially consistent fence, so that the available index is
    /// visible before the device's flag is read, then whether the used
    /// ring's `VIRTQ_USED_F_NO_NOTIFY` is clear (2.7.10: the driver MUST
    /// notify when it is 0, and SHOULD NOT when it is 1).
    pub fn wants_notify(&self, mem: &impl Memory) -> bool {
        mem.fence(SeqCst);
        mem.load16(self.ring + off::USED_FLAGS, Relaxed) & USED_F_NO_NOTIFY == 0
    }

    /// Turns used-buffer notifications on or off through
    /// `VIRTQ_AVAIL_F_NO_INTERRUPT`, if that changes them. Turning them on
    /// ends with a sequentially consistent fence, so that a
    /// [`Virtq::poll`] after it sees every element the device used without
    /// a notification.
    pub fn set_interrupts(&mut self, mem: &impl Memory, on: bool) {
        if on == self.interrupts {
            return;
        }
        let flags = if on { 0 } else { AVAIL_F_NO_INTERRUPT };
        mem.store16(self.ring + off::AVAIL_FLAGS, flags, Relaxed);
        self.interrupts = on;
        if on {
            mem.fence(SeqCst);
        }
    }

    /// Reads the used index (acquire, so that the elements it covers are
    /// read after it) and makes the elements the device added since the
    /// last look ready for [`Virtq::take`]; returns how many. An index
    /// more than 64 ahead of the driver's, or behind it, which no honest
    /// device writes, is counted in `bad` and taken as none.
    pub fn poll(&mut self, mem: &impl Memory, bad: &mut u64) -> u16 {
        let idx = mem.load16(self.ring + off::USED_IDX, Acquire);
        let n = idx.wrapping_sub(self.used);
        self.ready = if n > QUEUE_SIZE {
            *bad += 1;
            0
        } else {
            n
        };
        self.ready
    }

    /// Takes the next element [`Virtq::poll`] made ready, whatever it
    /// holds, and returns it if its `id` names a descriptor the device
    /// holds, which is then the driver's again; any other element is
    /// counted in `bad` and passed. `None` too once none is ready.
    pub fn take(&mut self, mem: &impl Memory, bad: &mut u64) -> Option<Used> {
        while self.ready > 0 {
            let e = self.ring + off::used_elem(self.used);
            let id = mem.load32(e + off::USED_ID, Relaxed);
            let len = mem.load32(e + off::USED_LEN, Relaxed);
            self.used = self.used.wrapping_add(1);
            self.ready -= 1;
            if id < u32::from(QUEUE_SIZE) && self.posted & 1 << id != 0 {
                self.posted &= !(1 << id);
                return Some(Used { id: id as u16, len });
            }
            *bad += 1;
        }
        None
    }
}
