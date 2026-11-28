//! RNDIS, the Remote NDIS protocol inside NVSP's RNDIS messages
//! (FreeBSD's `sys/net/rndis.h` and `hn_rndis.c`, and `if_hn.c`'s
//! receive checks, read 2026-11-28): the control requests netvsc writes in
//! its request page, the data packets it writes in send sections, and the
//! messages the host puts in the receive buffer, which netvsc reads
//! through [`Memory`] and checks field by field before it uses one.
//!
//! Every message starts with its type and length (`rndis_msghdr`). The
//! offsets in a packet message, a query's completion and a status
//! indication count from byte 8, the field after the length.

use core::fmt;

use libsys::frames::{MAX_FRAME, MIN_FRAME};
use libsys::mem::Memory;

/// The message types (`REMOTE_NDIS_*_MSG` and `_CMPLT`).
pub mod kind {
    pub const PACKET: u32 = 0x0000_0001;
    pub const INITIALIZE: u32 = 0x0000_0002;
    pub const HALT: u32 = 0x0000_0003;
    pub const QUERY: u32 = 0x0000_0004;
    pub const SET: u32 = 0x0000_0005;
    pub const RESET: u32 = 0x0000_0006;
    pub const INDICATE_STATUS: u32 = 0x0000_0007;
    pub const KEEPALIVE: u32 = 0x0000_0008;
    pub const INITIALIZE_CMPLT: u32 = 0x8000_0002;
    pub const QUERY_CMPLT: u32 = 0x8000_0004;
    pub const SET_CMPLT: u32 = 0x8000_0005;
    pub const RESET_CMPLT: u32 = 0x8000_0006;
    pub const KEEPALIVE_CMPLT: u32 = 0x8000_0008;
}

/// `RNDIS_STATUS_SUCCESS`; and the status indications netvsc acts on.
pub const STATUS_SUCCESS: u32 = 0;
pub const STATUS_MEDIA_CONNECT: u32 = 0x4001_000B;
pub const STATUS_MEDIA_DISCONNECT: u32 = 0x4001_000C;

/// The objects netvsc queries and sets.
pub mod oid {
    /// The adapter's MAC, 6 bytes.
    pub const PERMANENT_ADDRESS: u32 = 0x0101_0101;
    /// The link, 4 bytes: 0 connected (`NdisMediaStateConnected`).
    pub const MEDIA_CONNECT_STATUS: u32 = 0x0001_0114;
    /// The packet filter, 4 bytes.
    pub const CURRENT_PACKET_FILTER: u32 = 0x0001_010E;
}

/// The packet filter netvsc sets: directed and broadcast frames
/// (`NDIS_PACKET_TYPE_DIRECTED | NDIS_PACKET_TYPE_BROADCAST`).
pub const FILTER: u32 = 0x9;

/// RNDIS 1.0, with transfers of at most 2,048 bytes
/// (`HN_RNDIS_XFER_SIZE`).
pub const VERSION_MAJOR: u32 = 1;
pub const VERSION_MINOR: u32 = 0;
pub const MAX_TRANSFER: u32 = 2048;

/// A control request's ID: FreeBSD's `hn_rndis_rid` numbers requests from
/// 1 and uses the upper 16 bits.
pub const fn request_id(n: u32) -> u32 {
    n << 16
}

/// Where a request's information buffer starts, counted from byte 8:
/// right after the 28-byte query or set (`RNDIS_QUERY_REQ_INFOBUFOFFSET`).
/// Hyper-V refuses a query without it, though RNDIS asks for 0 with no
/// input (FreeBSD's note in `hn_rndis_query2`).
pub const INFOBUF_OFFSET: u32 = 20;
/// The bytes of each request.
pub const INITIALIZE_LEN: usize = 24;
pub const QUERY_LEN: usize = 28;
pub const SET_LEN: usize = QUERY_LEN + 4;

/// `REMOTE_NDIS_PACKET_MSG`'s header (`rndis_packet_msg`), 44 bytes.
pub const PACKET_HEADER: usize = 44;
/// Offsets in a message count from this byte.
pub const OFFSET_BASE: usize = 8;
/// The smallest data, out-of-band and per-packet offset, which is also
/// where netvsc's frames start: right after the header
/// (`RNDIS_PACKET_MSG_OFFSET_MIN`).
pub const DATA_OFFSET: u32 = (PACKET_HEADER - OFFSET_BASE) as u32;
/// A per-packet information element's header (`rndis_pktinfo`): size,
/// type, offset of its data.
pub const PKTINFO_HEADER: usize = 12;
/// The most per-packet information elements netvsc walks in one packet;
/// a packet with more is refused. Hyper-V sends a handful.
pub const MAX_PKTINFO: usize = 16;

/// `INITIALIZE` (`rndis_init_req`).
pub fn initialize(rid: u32) -> [u8; INITIALIZE_LEN] {
    words([
        kind::INITIALIZE,
        INITIALIZE_LEN as u32,
        rid,
        VERSION_MAJOR,
        VERSION_MINOR,
        MAX_TRANSFER,
    ])
}

/// `QUERY` of `oid` with no input (`rndis_query_req`).
pub fn query(rid: u32, oid: u32) -> [u8; QUERY_LEN] {
    words([
        kind::QUERY,
        QUERY_LEN as u32,
        rid,
        oid,
        0,
        INFOBUF_OFFSET,
        0,
    ])
}

/// `SET` of `oid` to the 4-byte `value` (`rndis_set_req` and its data).
pub fn set(rid: u32, oid: u32, value: u32) -> [u8; SET_LEN] {
    words([
        kind::SET,
        SET_LEN as u32,
        rid,
        oid,
        4,
        INFOBUF_OFFSET,
        0,
        value,
    ])
}

/// The header of a data packet carrying a frame of `len` bytes right after
/// it: no out-of-band data and no per-packet information (its offset
/// points past the header, as FreeBSD and Linux leave it, its length 0).
pub fn packet_header(len: usize) -> [u8; PACKET_HEADER] {
    words([
        kind::PACKET,
        (PACKET_HEADER + len) as u32,
        DATA_OFFSET,
        len as u32,
        0,
        0,
        0,
        DATA_OFFSET,
        0,
        0,
        0,
    ])
}

fn words<const W: usize, const B: usize>(w: [u32; W]) -> [u8; B] {
    const { assert!(B == 4 * W) };
    let mut b = [0u8; B];
    for (chunk, v) in b.as_chunks_mut::<4>().0.iter_mut().zip(w) {
        *chunk = v.to_le_bytes();
    }
    b
}

/// The little-endian u32 at byte `at` of a message, read as bytes: the
/// host picks where a message starts in the receive buffer, so its fields
/// need not be aligned for an atomic load.
fn u32_at(msg: &impl Memory, at: usize) -> u32 {
    let mut b = [0u8; 4];
    msg.read(at, &mut b);
    u32::from_le_bytes(b)
}

/// The `N` little-endian u32s at the start of a message, read as bytes.
fn read_words<const N: usize>(msg: &impl Memory) -> [u32; N] {
    core::array::from_fn(|i| u32_at(msg, 4 * i))
}

/// Why a message was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// Its range holds fewer bytes than its type's fields: the range's
    /// length.
    Short(usize),
    /// Its own length is under its type's, or past its range.
    Length(u32),
    /// A status other than success.
    Status(u32),
    /// A query's answer is not as long as its object.
    InfoLength(u32),
    /// A query's answer lies outside the message.
    InfoOffset(u32),
    /// A packet's data, out-of-band data and per-packet information add
    /// up past its length.
    Lengths,
    /// A packet with no data.
    NoData,
    /// A data offset under 36.
    DataOffset(u32),
    /// An out-of-band offset under 36 or unaligned, or out-of-band data
    /// outside the message or over the data or the per-packet information.
    Oob(u32),
    /// A per-packet offset under 36 or unaligned, information outside the
    /// message or over the data, or an element whose size does not fit.
    Pktinfo(u32),
    /// Data outside the message.
    Data(u32),
    /// A frame shorter than 14 bytes or longer than 1,514.
    Frame(u32),
}

impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Bad::Short(n) => write!(f, "a message of {n} bytes"),
            Bad::Length(n) => write!(f, "a message length of {n}"),
            Bad::Status(s) => write!(f, "status {s:#010x}"),
            Bad::InfoLength(n) => write!(f, "an answer of {n} bytes"),
            Bad::InfoOffset(o) => write!(f, "an answer at offset {o}"),
            Bad::Lengths => f.write_str("lengths past the message"),
            Bad::NoData => f.write_str("no data"),
            Bad::DataOffset(o) => write!(f, "data offset {o}"),
            Bad::Oob(o) => write!(f, "out-of-band data at {o}"),
            Bad::Pktinfo(o) => write!(f, "per-packet information at {o}"),
            Bad::Data(o) => write!(f, "data at {o} past the message"),
            Bad::Frame(n) => write!(f, "a frame of {n} bytes"),
        }
    }
}

/// A message's type, if its range holds a header.
pub fn kind_of(msg: &impl Memory) -> Option<u32> {
    (msg.len() >= OFFSET_BASE).then(|| u32_at(msg, 0))
}

/// A completion's common header (`rndis_comp_hdr`): type, length, request
/// ID and status.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Completion {
    pub kind: u32,
    pub len: u32,
    pub rid: u32,
    pub status: u32,
}

/// The completion header of `msg`, if its range holds one.
pub fn completion(msg: &impl Memory) -> Option<Completion> {
    (msg.len() >= 16).then(|| {
        let [kind, len, rid, status] = read_words(msg);
        Completion {
            kind,
            len,
            rid,
            status,
        }
    })
}

/// The bytes a completion may use: its range, and its own length if that
/// is shorter; at least `min`, else [`Bad::Short`] or [`Bad::Length`].
fn bound(msg: &impl Memory, c: &Completion, min: usize) -> Result<usize, Bad> {
    if msg.len() < min {
        return Err(Bad::Short(msg.len()));
    }
    if (c.len as usize) < min {
        return Err(Bad::Length(c.len));
    }
    Ok(msg.len().min(c.len as usize))
}

/// `INITIALIZE_CMPLT` (`rndis_init_comp`): at least 48 bytes, status
/// success. Returns the packet alignment the host asks, `1 << rm_align`,
/// never below 4, as FreeBSD's `hn_rndis_init` fixes it up.
pub fn initialize_cmplt(msg: &impl Memory, c: &Completion) -> Result<u32, Bad> {
    bound(msg, c, 48)?;
    if c.status != STATUS_SUCCESS {
        return Err(Bad::Status(c.status));
    }
    let shift = u32_at(msg, 40);
    Ok(1u32.checked_shl(shift).unwrap_or(1 << 31).max(4))
}

/// `QUERY_CMPLT` (`rndis_query_comp`) of an object of `want` bytes: status
/// success, an information buffer of exactly `want` bytes inside the
/// message, after its 24-byte header. Returns the buffer's offset in the
/// message.
pub fn query_cmplt(msg: &impl Memory, c: &Completion, want: usize) -> Result<usize, Bad> {
    let end = bound(msg, c, 24)?;
    if c.status != STATUS_SUCCESS {
        return Err(Bad::Status(c.status));
    }
    let len = u32_at(msg, 16);
    let offset = u32_at(msg, 20);
    if len as usize != want {
        return Err(Bad::InfoLength(len));
    }
    let at = OFFSET_BASE as u64 + u64::from(offset);
    if at < 24 || at + u64::from(len) > end as u64 {
        return Err(Bad::InfoOffset(offset));
    }
    Ok(at as usize)
}

/// `SET_CMPLT` (`rndis_set_comp`): 16 bytes, status success.
pub fn set_cmplt(msg: &impl Memory, c: &Completion) -> Result<(), Bad> {
    bound(msg, c, 16)?;
    if c.status != STATUS_SUCCESS {
        return Err(Bad::Status(c.status));
    }
    Ok(())
}

/// `INDICATE_STATUS` (`rndis_status_msg`, 20 bytes): its status.
pub fn indicate_status(msg: &impl Memory) -> Result<u32, Bad> {
    if msg.len() < 20 {
        return Err(Bad::Short(msg.len()));
    }
    Ok(u32_at(msg, 8))
}

/// Where a packet's frame lies in its message.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Data {
    /// Its offset from the message's start.
    pub offset: usize,
    pub len: usize,
}

/// Whether `[a, a + alen)` and `[b, b + blen)` overlap, as FreeBSD's
/// `hn_rndis_check_overlap` decides: regions that start together always
/// do.
fn overlap(a: u64, alen: u64, b: u64, blen: u64) -> bool {
    if a < b {
        a + alen > b
    } else if a > b {
        b + blen > a
    } else {
        true
    }
}

/// An offset that is either absent (0) or at least 36 and aligned to 4.
fn offset_ok(o: u32) -> bool {
    o == 0 || (o >= DATA_OFFSET && o.is_multiple_of(4))
}

/// `REMOTE_NDIS_PACKET_MSG`, checked as FreeBSD's `hn_rndis_rx_data`
/// checks it: the message's length within its range and at least the
/// header; data, out-of-band data and per-packet information adding up
/// within it; some data, at offset 36 or more; the out-of-band data and
/// the per-packet information, when present, at aligned offsets of 36 or
/// more, inside the message and not over the data or each other; each
/// per-packet element whole, at most [`MAX_PKTINFO`] of them (FreeBSD's
/// `hn_rndis_rxinfo`); the data inside the message; and then a frame of 14
/// to 1,514 bytes. Returns where the frame lies.
pub fn packet(msg: &impl Memory) -> Result<Data, Bad> {
    if msg.len() < PACKET_HEADER {
        return Err(Bad::Short(msg.len()));
    }
    let [
        _,
        len,
        data_off,
        data_len,
        oob_off,
        oob_len,
        _,
        pi_off,
        pi_len,
        _,
        _,
    ] = read_words::<11>(msg);
    if len as usize > msg.len() || (len as usize) < PACKET_HEADER {
        return Err(Bad::Length(len));
    }
    let (len64, data_len64, oob_len64, pi_len64) = (
        u64::from(len),
        u64::from(data_len),
        u64::from(oob_len),
        u64::from(pi_len),
    );
    if len64 < data_len64 + oob_len64 + pi_len64 {
        return Err(Bad::Lengths);
    }
    if data_len == 0 {
        return Err(Bad::NoData);
    }
    if data_off < DATA_OFFSET {
        return Err(Bad::DataOffset(data_off));
    }
    if !offset_ok(oob_off) || (oob_len != 0 && oob_off == 0) {
        return Err(Bad::Oob(oob_off));
    }
    if !offset_ok(pi_off) || (pi_len != 0 && pi_off == 0) {
        return Err(Bad::Pktinfo(pi_off));
    }
    let base = OFFSET_BASE as u64;
    let (data_at, oob_at, pi_at) = (
        base + u64::from(data_off),
        base + u64::from(oob_off),
        base + u64::from(pi_off),
    );
    if oob_len != 0
        && (oob_at + oob_len64 > len64
            || overlap(oob_at, oob_len64, data_at, data_len64)
            || (pi_len != 0 && overlap(oob_at, oob_len64, pi_at, pi_len64)))
    {
        return Err(Bad::Oob(oob_off));
    }
    if pi_len != 0 {
        if pi_at + pi_len64 > len64 || overlap(pi_at, pi_len64, data_at, data_len64) {
            return Err(Bad::Pktinfo(pi_off));
        }
        pktinfo(msg, pi_at as usize, pi_len as usize).map_err(|()| Bad::Pktinfo(pi_off))?;
    }
    if data_at + data_len64 > len64 {
        return Err(Bad::Data(data_off));
    }
    if !(MIN_FRAME..=MAX_FRAME).contains(&(data_len as usize)) {
        return Err(Bad::Frame(data_len));
    }
    Ok(Data {
        offset: data_at as usize,
        len: data_len as usize,
    })
}

/// Walks the per-packet information at `at`, `len` bytes inside the
/// message: each element at least its 12-byte header, its size within
/// what is left and a multiple of 4, and its data's offset within it. Its
/// contents netvsc does not use: no offload is negotiated.
fn pktinfo(msg: &impl Memory, mut at: usize, len: usize) -> Result<(), ()> {
    let mut left = len;
    for _ in 0..MAX_PKTINFO {
        if left == 0 {
            return Ok(());
        }
        if left < PKTINFO_HEADER {
            return Err(());
        }
        let size = u32_at(msg, at) as usize;
        let offset = u32_at(msg, at + 8) as usize;
        if size < PKTINFO_HEADER || size > left || !size.is_multiple_of(4) || offset > size {
            return Err(());
        }
        left -= size;
        at += size;
    }
    if left == 0 { Ok(()) } else { Err(()) }
}
