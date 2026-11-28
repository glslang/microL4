//! The channel's two rings in the channel frame (`docs/design.md`,
//! "Rings"): FreeBSD's `vmbus_bufring` (`vmbus_reg.h`, `vmbus_br.c`, read
//! 2026-11-27), each a control page and 60 KiB of data, packets, and the
//! transaction IDs that pair a request with its completion.
//!
//! | Control page offset | Field |
//! | --- | --- |
//! | 0 | `br_windex`: the write index, a byte offset into the data |
//! | 4 | `br_rindex`: the read index |
//! | 8 | `br_imask`: 1 while the reader wants no signal |
//! | 12 | `br_pending_snd_sz`: the writer waits for this much free space |
//! | 64 | `br_feature_bits`: bit 0, the writer uses the pending send size |
//!
//! A packet is a 16-byte header (`vmbus_chanpkt_hdr`: type, header length
//! and total length in 8-byte units, flags, transaction ID), its body
//! padded to 8 bytes, then 8 bytes holding the write index before it,
//! shifted up 32 bits. Bytes wrap at the data's end; equal indices mean
//! empty, so a write needs more free bytes than the packet and its
//! trailer.
//!
//! Each side keeps its own copy of the index it writes, read once from the
//! zeroed page at start and never read back, so the host can move only
//! its own index; an index of the host's outside the data or not a
//! multiple of 8, or a header whose lengths do not fit, breaks the ring,
//! which is then neither read nor written again. Every access is a 64-bit
//! load or store of a word, or a 32-bit one of a control field, through
//! [`Memory`].

use core::fmt;
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
/// `feat_pending_snd_sz`: this ring's writer sets the pending send size
/// when it waits for room, so the reader signals it once there is.
pub const FEATURE_PENDING_SEND_SIZE: u32 = 1;
/// A packet's header.
pub const HEADER: usize = 16;
/// The trailing index.
pub const TRAILER: usize = 8;
/// The longest packet netvsc reads: longer ones are skipped and counted.
pub const MAX_PACKET: usize = 4096;
/// The longest packet netvsc writes: a GPA packet naming one page, with
/// its 40-byte NVS body (80 bytes), rounded up.
pub const MAX_WRITE: usize = 128;

/// The packet types (`VMBUS_CHANPKT_TYPE_*`).
pub mod kind {
    /// Data in the packet itself: NVS messages.
    pub const INBAND: u16 = 6;
    /// Ranges of the receive buffer (`vmbus_chanpkt_rxbuf`).
    pub const RXBUF: u16 = 7;
    /// Pages named by guest page number (`vmbus_chanpkt_sglist`).
    pub const GPA: u16 = 9;
    /// A completion of a packet that asked for one.
    pub const COMP: u16 = 11;
}

/// `VMBUS_CHANPKT_FLAG_RC`: the sender asks for a completion.
pub const FLAG_COMPLETION: u16 = 1;

/// Transaction IDs: what a completion names to say which packet it
/// completes. netvsc's control requests (NVS requests and RNDIS control
/// packets) count up from 1, below 2^32; a data packet in send section
/// `s` is 2^32 + `s`. The host's receive-buffer packets carry its own,
/// which netvsc's acknowledgement repeats.
pub mod xid {
    /// The first data packet's.
    pub const SEND: u64 = 1 << 32;

    /// A data packet's in section `section`.
    pub const fn send(section: u32) -> u64 {
        SEND + section as u64
    }

    /// The section a data packet's ID names, if it is one.
    pub const fn section(xid: u64) -> Option<u32> {
        if xid >= SEND && xid - SEND <= u32::MAX as u64 {
            Some((xid - SEND) as u32)
        } else {
            None
        }
    }
}

/// A packet's header, as read.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    pub kind: u16,
    /// The header's length in bytes.
    pub header_len: usize,
    /// The packet's length in bytes, header and padding included.
    pub total: usize,
    pub flags: u16,
    pub xid: u64,
}

impl Header {
    /// The header in `b`'s 16 bytes, lengths in bytes.
    pub fn parse(b: &[u8; HEADER]) -> Header {
        let word = |at: usize| u16::from_le_bytes([b[at], b[at + 1]]);
        Header {
            kind: word(0),
            header_len: usize::from(word(2)) * 8,
            total: usize::from(word(4)) * 8,
            flags: word(6),
            xid: u64::from_le_bytes([b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15]]),
        }
    }
}

/// Why a ring is broken: what the host wrote that cannot be followed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Broken {
    /// The host's index is outside the data or not a multiple of 8.
    Index(u32),
    /// A header whose lengths give under 16 bytes, a header longer than
    /// its packet, or a packet and trailer longer than the ring holds.
    Header {
        header: usize,
        total: usize,
        held: usize,
    },
}

impl fmt::Display for Broken {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Broken::Index(i) => write!(f, "the host's index {i:#x}"),
            Broken::Header {
                header,
                total,
                held,
            } => write!(
                f,
                "a packet of {total} bytes with a {header}-byte header, {held} bytes held"
            ),
        }
    }
}

/// Why a write did not happen.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WriteError {
    /// No room: the packet and its trailer need more than `free` bytes;
    /// the writer may ask for `need` with [`Outbound::ask_room`].
    Full { need: usize, free: usize },
    /// The ring is broken, now or before.
    Broken(Broken),
}

/// Bytes of data in a ring of `mem`'s length.
fn data_size(mem: &impl Memory) -> usize {
    mem.len() - CONTROL
}

/// Whether `i` is an index into `size` bytes of data.
fn valid(i: u32, size: usize) -> bool {
    (i as usize) < size && i.is_multiple_of(8)
}

/// The outbound ring: netvsc writes, the host reads.
#[derive(Clone, Copy, Debug)]
pub struct Outbound {
    write: u32,
    asked: bool,
    broken: Option<Broken>,
}

impl Outbound {
    /// The ring in `mem` (its pages, at least two): its write index read
    /// once, as root's zeroed frame or vmbus's open left it. Sets the
    /// pending-send-size feature, as FreeBSD's `vmbus_txbr_setup` does.
    pub fn new(mem: &impl Memory) -> Outbound {
        let write = mem.load32(WRITE_INDEX, Relaxed);
        let broken = (!valid(write, data_size(mem))).then_some(Broken::Index(write));
        mem.store32(FEATURES, FEATURE_PENDING_SEND_SIZE, Release);
        Outbound {
            write,
            asked: false,
            broken,
        }
    }

    pub fn broken(&self) -> Option<Broken> {
        self.broken
    }

    /// The write index, as netvsc keeps it.
    pub fn write_index(&self) -> u32 {
        self.write
    }

    /// Free bytes, by the host's read index (acquire: its reads of the
    /// data come first); breaks the ring if that index is bad.
    pub fn free(&mut self, mem: &impl Memory) -> Result<usize, Broken> {
        if let Some(b) = self.broken {
            return Err(b);
        }
        let size = data_size(mem);
        let read = mem.load32(READ_INDEX, Acquire);
        if !valid(read, size) {
            self.broken = Some(Broken::Index(read));
            return Err(Broken::Index(read));
        }
        let held = (self.write as usize + size - read as usize) % size;
        Ok(size - held)
    }

    /// Writes one packet: the 16-byte header and `ext`, which the header's
    /// length covers (a GPA packet's ranges; a multiple of 8 bytes), then
    /// `body` padded to 8 bytes, the trailing index; then a full fence and
    /// the write index with release order; then, after another full
    /// fence, reads the host's interrupt mask. Returns whether to signal
    /// the host: its mask is 0. Panics past [`MAX_WRITE`] bytes, which
    /// netvsc never writes.
    pub fn write(
        &mut self,
        mem: &impl Memory,
        kind: u16,
        flags: u16,
        xid: u64,
        ext: &[u8],
        body: &[u8],
    ) -> Result<bool, WriteError> {
        assert!(
            ext.len().is_multiple_of(8),
            "netvsc: a header of {} bytes",
            ext.len()
        );
        let header = HEADER + ext.len();
        let total = header + body.len().div_ceil(8) * 8;
        let need = total + TRAILER;
        assert!(
            need <= MAX_WRITE,
            "netvsc: a packet of {total} bytes to write"
        );
        let free = self.free(mem).map_err(WriteError::Broken)?;
        if free <= need {
            return Err(WriteError::Full { need, free });
        }
        let mut p = [0u8; MAX_WRITE];
        p[0..2].copy_from_slice(&kind.to_le_bytes());
        p[2..4].copy_from_slice(&((header / 8) as u16).to_le_bytes());
        p[4..6].copy_from_slice(&((total / 8) as u16).to_le_bytes());
        p[6..8].copy_from_slice(&flags.to_le_bytes());
        p[8..16].copy_from_slice(&xid.to_le_bytes());
        p[HEADER..header].copy_from_slice(ext);
        p[header..header + body.len()].copy_from_slice(body);
        p[total..need].copy_from_slice(&(u64::from(self.write) << 32).to_le_bytes());
        let size = data_size(mem);
        for (i, w) in p[..need].as_chunks::<8>().0.iter().enumerate() {
            let off = (self.write as usize + 8 * i) % size;
            mem.store64(CONTROL + off, u64::from_le_bytes(*w), Relaxed);
        }
        self.write = ((self.write as usize + need) % size) as u32;
        mem.fence(SeqCst);
        mem.store32(WRITE_INDEX, self.write, Release);
        if self.asked {
            mem.store32(PENDING_SEND_SIZE, 0, Release);
            self.asked = false;
        }
        mem.fence(SeqCst);
        Ok(mem.load32(INTERRUPT_MASK, Acquire) == 0)
    }

    /// Asks the host to signal once more than `need` bytes are free: the
    /// pending send size, which the next write clears. Then, after a full
    /// fence, reads the room again: a host that read the ring after the
    /// writer found it full but before it saw the request has made room
    /// and will not signal for it, so true means write now rather than
    /// wait (Linux's `hv_ringbuffer` and FreeBSD's `vmbus_txbr` check
    /// again too). Breaks the ring if the host's read index is bad.
    pub fn ask_room(&mut self, mem: &impl Memory, need: usize) -> Result<bool, Broken> {
        mem.store32(PENDING_SEND_SIZE, need as u32, Release);
        self.asked = true;
        mem.fence(SeqCst);
        Ok(self.free(mem)? > need)
    }
}

/// What [`Inbound::next`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Read {
    /// A packet, its `total` bytes copied to the start of the buffer.
    Packet(Header),
    /// A packet over [`MAX_PACKET`] bytes, passed unread but its header.
    Skipped(Header),
}

/// The inbound ring: the host writes, netvsc reads. Its interrupt mask
/// stays 0, so the host may always signal.
#[derive(Clone, Copy, Debug)]
pub struct Inbound {
    /// The read index the host sees.
    read: u32,
    /// The next packet's offset, past what this batch read.
    pos: u32,
    broken: Option<Broken>,
}

impl Inbound {
    /// The ring in `mem` (its pages, at least two): its read index read
    /// once.
    pub fn new(mem: &impl Memory) -> Inbound {
        let read = mem.load32(READ_INDEX, Relaxed);
        let broken = (!valid(read, data_size(mem))).then_some(Broken::Index(read));
        Inbound {
            read,
            pos: read,
            broken,
        }
    }

    pub fn broken(&self) -> Option<Broken> {
        self.broken
    }

    /// The host's write index (acquire: its writes of the data come
    /// first), checked.
    fn write_index(&mut self, mem: &impl Memory) -> Result<usize, Broken> {
        if let Some(b) = self.broken {
            return Err(b);
        }
        let w = mem.load32(WRITE_INDEX, Acquire);
        if !valid(w, data_size(mem)) {
            self.broken = Some(Broken::Index(w));
            return Err(Broken::Index(w));
        }
        Ok(w as usize)
    }

    /// Bytes the host wrote past this batch's position.
    pub fn held(&mut self, mem: &impl Memory) -> Result<usize, Broken> {
        let size = data_size(mem);
        let w = self.write_index(mem)?;
        Ok((w + size - self.pos as usize) % size)
    }

    /// Copies `out.len()` bytes, a multiple of 8, from data offset `at`, a
    /// multiple of 8, wrapping: a 64-bit load a word.
    fn copy_out(mem: &impl Memory, at: usize, out: &mut [u8]) {
        let size = data_size(mem);
        for (i, w) in out.as_chunks_mut::<8>().0.iter_mut().enumerate() {
            let off = (at + 8 * i) % size;
            *w = mem.load64(CONTROL + off, Relaxed).to_le_bytes();
        }
    }

    /// Reads the next packet, if any, into `buf`, and moves past it; the
    /// host sees the move at [`Inbound::finish`]. A header whose lengths
    /// do not fit breaks the ring.
    pub fn next(
        &mut self,
        mem: &impl Memory,
        buf: &mut [u8; MAX_PACKET],
    ) -> Result<Option<Read>, Broken> {
        let held = self.held(mem)?;
        if held == 0 {
            return Ok(None);
        }
        let size = data_size(mem);
        let pos = self.pos as usize;
        let mut h = [0u8; HEADER];
        if held >= HEADER + TRAILER {
            Self::copy_out(mem, pos, &mut h);
        }
        let header = Header::parse(&h);
        if held < HEADER + TRAILER
            || header.header_len < HEADER
            || header.header_len > header.total
            || header.total + TRAILER > held
        {
            let b = Broken::Header {
                header: header.header_len,
                total: header.total,
                held,
            };
            self.broken = Some(b);
            return Err(b);
        }
        self.pos = ((pos + header.total + TRAILER) % size) as u32;
        if header.total > MAX_PACKET {
            return Ok(Some(Read::Skipped(header)));
        }
        Self::copy_out(mem, pos, &mut buf[..header.total]);
        Ok(Some(Read::Packet(header)))
    }

    /// Ends a batch: the read index with release order, if it moved; then,
    /// after a full fence, whether to signal the host: it waits for room
    /// (its pending send size is not 0) and the free space now reaches
    /// it. Signals at most once a batch that read something.
    pub fn finish(&mut self, mem: &impl Memory) -> bool {
        if self.pos == self.read {
            return false;
        }
        self.read = self.pos;
        mem.store32(READ_INDEX, self.read, Release);
        mem.fence(SeqCst);
        let want = mem.load32(PENDING_SEND_SIZE, Acquire) as usize;
        let Ok(held) = self.held(mem) else {
            return false;
        };
        want != 0 && data_size(mem) - held >= want
    }

    /// Whether the host wrote more since this batch's position: the write
    /// index read again.
    pub fn more(&mut self, mem: &impl Memory) -> bool {
        self.held(mem).is_ok_and(|h| h != 0)
    }
}
