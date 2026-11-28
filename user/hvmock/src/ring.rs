//! A VMBus ring buffer (FreeBSD's `vmbus_bufring`, `vmbus_br.c`, read
//! 2026-11-27), over any window of its pages: a control page, then the
//! data. The format is the same in both directions; the host writes the
//! inbound ring and reads the outbound one, and a test can play the guest
//! with the same code.
//!
//! | Control page offset | Field |
//! | --- | --- |
//! | 0 | `br_windex`: the write index, a byte offset into the data |
//! | 4 | `br_rindex`: the read index |
//! | 8 | `br_imask`: 1 while the reader wants no signal |
//! | 12 | `br_pending_snd_sz`: the writer waits for this much free space |
//! | 64 | `br_feature_bits`: bit 0, the writer of this field uses the pending send size |
//!
//! Equal indices mean empty, so a write must leave free space: it needs
//! more free bytes than the packet and its 8 trailing bytes. A packet is
//! a 16-byte header (`vmbus_chanpkt_hdr`: type, header length and total
//! length in 8-byte units, flags, transaction ID), its body padded to 8
//! bytes, then 8 bytes holding the write index before it, shifted up 32
//! bits. Bytes wrap at the data's end.

use core::sync::atomic::Ordering::{Acquire, Relaxed, Release, SeqCst};

use libsys::mem::Memory;

/// The control page.
pub const CONTROL: usize = 4096;
/// Its fields.
pub const WRITE_INDEX: usize = 0;
pub const READ_INDEX: usize = 4;
pub const INTERRUPT_MASK: usize = 8;
pub const PENDING_SEND_SIZE: usize = 12;
pub const FEATURES: usize = 64;
/// `feat_pending_snd_sz`.
pub const FEATURE_PENDING_SEND_SIZE: u32 = 1;
/// A packet's header.
pub const HEADER: usize = 16;
/// The trailing index.
pub const TRAILER: usize = 8;

/// The packet types (`VMBUS_CHANPKT_TYPE_*`).
pub mod kind {
    pub const INBAND: u16 = 6;
    pub const RXBUF: u16 = 7;
    pub const GPA: u16 = 9;
    pub const COMP: u16 = 11;
}
/// `VMBUS_CHANPKT_FLAG_RC`: the sender asks for a completion.
pub const FLAG_COMPLETION: u16 = 1;

/// A packet as read: its header's fields and every byte of it, header
/// included, `total` bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Packet {
    pub kind: u16,
    /// The header's length in bytes, 16 or more.
    pub header_len: usize,
    pub flags: u16,
    pub xid: u64,
    /// The packet, header and padding included.
    pub bytes: Vec<u8>,
    /// The trailing word: the write index before it, shifted up 32 bits.
    pub trailer: u64,
}

impl Packet {
    /// What follows the header.
    pub fn body(&self) -> &[u8] {
        &self.bytes[self.header_len..]
    }
}

/// Why a ring cannot be read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    /// An index outside the data or not a multiple of 8.
    Index { read: u32, write: u32 },
    /// A header whose lengths are under 16 bytes, a header longer than its
    /// packet, or a packet longer than the ring holds.
    Header {
        header: usize,
        total: usize,
        held: usize,
    },
}

/// No room: the ring holds `free` bytes and the packet needs more than
/// `need`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Full {
    pub need: usize,
    pub free: usize,
}

/// What a write did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Written {
    /// The write index before it.
    pub old: u32,
    /// The ring was empty before it: FreeBSD's writer signals only then
    /// (`vmbus_txbr_need_signal`), if the reader's mask is 0.
    pub was_empty: bool,
}

/// A ring over its pages.
#[derive(Clone, Copy)]
pub struct Ring<M> {
    mem: M,
}

impl<M: Memory> Ring<M> {
    /// The ring in `mem`; panics unless it is whole pages, at least two.
    pub fn new(mem: M) -> Ring<M> {
        assert!(
            mem.len() >= 2 * CONTROL && mem.len().is_multiple_of(CONTROL),
            "hvmock: a ring of {:#x} bytes",
            mem.len()
        );
        Ring { mem }
    }

    pub fn memory(&self) -> &M {
        &self.mem
    }

    /// The data's size in bytes.
    pub fn size(&self) -> usize {
        self.mem.len() - CONTROL
    }

    pub fn write_index(&self) -> u32 {
        self.mem.load32(WRITE_INDEX, Acquire)
    }
    pub fn read_index(&self) -> u32 {
        self.mem.load32(READ_INDEX, Acquire)
    }
    pub fn interrupt_mask(&self) -> u32 {
        self.mem.load32(INTERRUPT_MASK, Acquire)
    }
    pub fn pending_send_size(&self) -> u32 {
        self.mem.load32(PENDING_SEND_SIZE, Acquire)
    }
    pub fn features(&self) -> u32 {
        self.mem.load32(FEATURES, Acquire)
    }
    pub fn set_write_index(&self, v: u32) {
        self.mem.store32(WRITE_INDEX, v, Release)
    }
    pub fn set_read_index(&self, v: u32) {
        self.mem.store32(READ_INDEX, v, Release)
    }
    pub fn set_interrupt_mask(&self, v: u32) {
        self.mem.store32(INTERRUPT_MASK, v, Release)
    }
    pub fn set_pending_send_size(&self, v: u32) {
        self.mem.store32(PENDING_SEND_SIZE, v, Release)
    }
    pub fn set_features(&self, v: u32) {
        self.mem.store32(FEATURES, v, Release)
    }

    fn indices(&self) -> Result<(usize, usize), Broken> {
        let (read, write) = (self.read_index(), self.write_index());
        let ok = |i: u32| (i as usize) < self.size() && i.is_multiple_of(8);
        if ok(read) && ok(write) {
            Ok((read as usize, write as usize))
        } else {
            Err(Broken::Index { read, write })
        }
    }

    /// Bytes written and not yet read.
    pub fn held(&self) -> Result<usize, Broken> {
        let (r, w) = self.indices()?;
        Ok((w + self.size() - r) % self.size())
    }

    /// Bytes a write may use: the free space, of which one byte must stay
    /// free.
    pub fn free(&self) -> Result<usize, Broken> {
        Ok(self.size() - self.held()?)
    }

    /// Copies `out.len()` bytes, a multiple of 8, from data offset `at`,
    /// a multiple of 8, wrapping at the end: a 64-bit load a word, which
    /// is also quicker under Miri than a byte at a time.
    fn copy_out(&self, at: usize, out: &mut [u8]) {
        for (i, w) in out.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            let off = (at + 8 * i) % self.size();
            *w = self.mem.load64(CONTROL + off, Relaxed).to_le_bytes();
        }
    }

    /// Copies `bytes`, a multiple of 8, to data offset `at`, wrapping;
    /// returns the offset after them.
    fn copy_in(&self, at: usize, bytes: &[u8]) -> usize {
        for (i, w) in bytes.as_chunks::<8>().0.iter().enumerate() {
            let off = (at + 8 * i) % self.size();
            self.mem
                .store64(CONTROL + off, u64::from_le_bytes(*w), Relaxed);
        }
        (at + bytes.len()) % self.size()
    }

    /// Writes one packet: the header, `body` padded to 8 bytes, the
    /// trailing index, then a fence and the write index with release
    /// order. `Full` if the free space does not exceed the packet and its
    /// trailer.
    pub fn write(&self, kind: u16, flags: u16, xid: u64, body: &[u8]) -> Result<Written, Full> {
        self.write_ext(kind, flags, xid, &[], body)
    }

    /// As [`Ring::write`], with `ext` after the 16 bytes and inside the
    /// header's length: a receive-buffer packet's ID, count and ranges
    /// (`vmbus_chanpkt_rxbuf`), or a GPA packet's (`vmbus_chanpkt_sglist`).
    /// Panics unless `ext` is a multiple of 8 bytes.
    pub fn write_ext(
        &self,
        kind: u16,
        flags: u16,
        xid: u64,
        ext: &[u8],
        body: &[u8],
    ) -> Result<Written, Full> {
        assert!(
            ext.len().is_multiple_of(8),
            "hvmock: a header extension of {} bytes",
            ext.len()
        );
        let header = HEADER + ext.len();
        let padded = body.len().div_ceil(8) * 8;
        let total = header + padded;
        let need = total + TRAILER;
        let free = self.free().map_err(|_| Full { need, free: 0 })?;
        let tlen = u16::try_from(total / 8).map_err(|_| Full { need, free })?;
        if free <= need {
            return Err(Full { need, free });
        }
        let old = self.write_index();
        let was_empty = old == self.read_index();
        let mut p = Vec::with_capacity(need);
        p.extend_from_slice(&kind.to_le_bytes());
        p.extend_from_slice(&((header / 8) as u16).to_le_bytes());
        p.extend_from_slice(&tlen.to_le_bytes());
        p.extend_from_slice(&flags.to_le_bytes());
        p.extend_from_slice(&xid.to_le_bytes());
        p.extend_from_slice(ext);
        p.extend_from_slice(body);
        p.resize(total, 0);
        p.extend_from_slice(&(u64::from(old) << 32).to_le_bytes());
        let next = self.copy_in(old as usize, &p);
        self.mem.fence(SeqCst);
        self.set_write_index(next as u32);
        Ok(Written { old, was_empty })
    }

    /// Reads the next packet, if any, and moves the read index past it
    /// with release order. A header whose lengths do not fit is `Broken`,
    /// and the read index stays.
    pub fn read(&self) -> Result<Option<Packet>, Broken> {
        let (r, _) = self.indices()?;
        let held = self.held()?;
        if held == 0 {
            return Ok(None);
        }
        let mut h = [0u8; HEADER];
        if held < HEADER + TRAILER {
            return Err(Broken::Header {
                header: 0,
                total: 0,
                held,
            });
        }
        self.copy_out(r, &mut h);
        let word = |at: usize| u16::from_le_bytes([h[at], h[at + 1]]);
        let header = usize::from(word(2)) * 8;
        let total = usize::from(word(4)) * 8;
        if header < HEADER || header > total || total + TRAILER > held {
            return Err(Broken::Header {
                header,
                total,
                held,
            });
        }
        let mut bytes = vec![0u8; total];
        self.copy_out(r, &mut bytes);
        let mut t = [0u8; TRAILER];
        self.copy_out((r + total) % self.size(), &mut t);
        self.set_read_index(((r + total + TRAILER) % self.size()) as u32);
        Ok(Some(Packet {
            kind: word(0),
            header_len: header,
            flags: word(6),
            xid: u64::from_le_bytes(h[8..16].try_into().expect("8 bytes")),
            bytes,
            trailer: u64::from_le_bytes(t),
        }))
    }

    /// Reads every packet the ring holds.
    pub fn read_all(&self) -> Result<Vec<Packet>, Broken> {
        let mut v = Vec::new();
        while let Some(p) = self.read()? {
            v.push(p);
        }
        Ok(v)
    }

    /// Whether a reader that has just read `bytes` should signal the
    /// writer: the writer uses the pending send size (its feature bit),
    /// set a size, had less free space than it before the read and has
    /// at least it now (FreeBSD's `vmbus_rxbr_need_signal`).
    pub fn reader_should_signal(&self, bytes: usize) -> bool {
        let want = self.pending_send_size() as usize;
        if self.features() & FEATURE_PENDING_SEND_SIZE == 0 || want == 0 {
            return false;
        }
        let Ok(free) = self.free() else {
            return false;
        };
        free > want && free - bytes.min(free) <= want
    }

    /// Fills the data with `byte`, to show what a reader copies.
    pub fn poison(&self, byte: u8) {
        self.mem.fill(CONTROL, self.size(), byte);
    }
}
