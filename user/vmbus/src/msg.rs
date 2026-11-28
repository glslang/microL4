//! The VMBus channel messages vmbus sends and takes (FreeBSD's
//! `vmbus_reg.h`, "Channel messages", read 2026-11-27), each encoded and
//! decoded with every length checked.
//!
//! A channel message travels as a SynIC message of type 1
//! ([`MESSAGE_TYPE`], `HYPERV_MSGTYPE_CHANNEL`): vmbus posts requests on
//! connection 1 ([`CONNECTION`], `VMBUS_CONNID_MESSAGE`) with
//! `Hypervisor_PostMessage`, and the host's answers and notes arrive in
//! the SIM's slot 2 ([`crate::synic`]). Every message starts with an
//! 8-byte header, its type (`chm_type`) and a reserved word; the fields
//! follow, packed and little-endian. A message may be longer than its
//! type's size, never shorter.
//!
//! | Type | Message | Bytes | Sent by |
//! | --- | --- | --- | --- |
//! | 1 | `CHOFFER` | 196 | host |
//! | 2 | `CHRESCIND` | 12 | host |
//! | 3 | `CHREQUEST` | 8 | guest |
//! | 4 | `CHOFFER_DONE` | 8 | host |
//! | 5 | `CHOPEN` | 148 | guest |
//! | 6 | `CHOPEN_RESP` | 20 | host |
//! | 7 | `CHCLOSE` | 12 | guest |
//! | 8 | `GPADL_CONN` | 28 + 8 per page, 26 pages at most | guest |
//! | 9 | `GPADL_SUBCONN` | 16 + 8 per page, 28 pages at most | guest |
//! | 10 | `GPADL_CONNRESP` | 20 | host |
//! | 11 | `GPADL_DISCONN` | 16 | guest |
//! | 12 | `GPADL_DISCONNRESP` | 12 | host |
//! | 14 | `CONNECT` | 40 | guest |
//! | 15 | `CONNECT_RESP` | 9 | host |
//!
//! FreeBSD names no structure for `GPADL_DISCONNRESP`, whose answer it
//! discards; its layout here, the header and the GPADL handle, is from
//! memory of Linux's `vmbus_channel_gpadl_torndown`.

use core::fmt;

use crate::offer::{Guid, Offer};

/// The SynIC message type of every channel message.
pub const MESSAGE_TYPE: u32 = 1;
/// The connection vmbus posts its requests on.
pub const CONNECTION: u32 = 1;
/// The header: type and a reserved word.
pub const HEADER: usize = 8;
/// The largest message: a SynIC message's payload.
pub const MAX: usize = 240;
/// Pages in a `GPADL_CONN` (`VMBUS_CHANMSG_GPADL_CONN_PGMAX`).
pub const CONN_PAGES: usize = 26;
/// Pages in a `GPADL_SUBCONN` (`VMBUS_CHANMSG_GPADL_SUBCONN_PGMAX`).
pub const SUBCONN_PAGES: usize = 28;
/// Where a `GPADL_CONN`'s page numbers start.
pub const CONN_PAGE_OFFSET: usize = 28;
/// Where a `GPADL_SUBCONN`'s page numbers start.
pub const SUBCONN_PAGE_OFFSET: usize = 16;
/// `CHOPEN`'s user data, which vmbus leaves 0.
pub const OPEN_USER_DATA: usize = 120;

/// The message types (`VMBUS_CHANMSG_TYPE_*`).
pub mod kind {
    pub const CHOFFER: u32 = 1;
    pub const CHRESCIND: u32 = 2;
    pub const CHREQUEST: u32 = 3;
    pub const CHOFFER_DONE: u32 = 4;
    pub const CHOPEN: u32 = 5;
    pub const CHOPEN_RESP: u32 = 6;
    pub const CHCLOSE: u32 = 7;
    pub const GPADL_CONN: u32 = 8;
    pub const GPADL_SUBCONN: u32 = 9;
    pub const GPADL_CONNRESP: u32 = 10;
    pub const GPADL_DISCONN: u32 = 11;
    pub const GPADL_DISCONNRESP: u32 = 12;
    /// `CHFREE`: vmbus never sends it.
    pub const CHFREE: u32 = 13;
    pub const CONNECT: u32 = 14;
    pub const CONNECT_RESP: u32 = 15;
    /// `DISCONNECT`, Linux's UNLOAD: vmbus never sends it.
    pub const DISCONNECT: u32 = 16;
}

/// A message type's size, the fewest bytes a message of it may have;
/// `None` for a type vmbus neither sends nor takes. A GPADL message's is
/// its size with one page.
pub const fn size(kind: u32) -> Option<usize> {
    Some(match kind {
        kind::CHOFFER => 196,
        kind::CHRESCIND | kind::CHCLOSE | kind::GPADL_DISCONNRESP => 12,
        kind::CHREQUEST | kind::CHOFFER_DONE => 8,
        kind::CHOPEN => 28 + OPEN_USER_DATA,
        kind::CHOPEN_RESP | kind::GPADL_CONNRESP => 20,
        kind::GPADL_CONN => CONN_PAGE_OFFSET + 8,
        kind::GPADL_SUBCONN => SUBCONN_PAGE_OFFSET + 8,
        kind::GPADL_DISCONN => 16,
        kind::CONNECT => 40,
        kind::CONNECT_RESP => 9,
        _ => return None,
    })
}

/// Up to 28 page numbers: a GPADL message's.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct PageList {
    len: u8,
    page: [u64; SUBCONN_PAGES],
}

impl PageList {
    /// `pages`, or `None` for more than 28.
    pub fn new(pages: &[u64]) -> Option<PageList> {
        let mut l = PageList {
            len: u8::try_from(pages.len()).ok()?,
            page: [0; SUBCONN_PAGES],
        };
        l.page.get_mut(..pages.len())?.copy_from_slice(pages);
        Some(l)
    }

    /// `count` consecutive pages from `first`; `None` for more than 28.
    pub fn run(first: u64, count: usize) -> Option<PageList> {
        let mut l = PageList::new(&[])?;
        if count > SUBCONN_PAGES {
            return None;
        }
        for (i, p) in l.page.iter_mut().take(count).enumerate() {
            *p = first + i as u64;
        }
        l.len = count as u8;
        Some(l)
    }

    pub fn as_slice(&self) -> &[u64] {
        &self.page[..usize::from(self.len)]
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }
}

impl fmt::Debug for PageList {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.as_slice()).finish()
    }
}

/// A channel message, with the fields vmbus reads or writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Msg {
    /// The host offers a channel.
    ChOffer(Offer),
    /// The host takes an offered channel back.
    ChRescind { channel: u32 },
    /// The guest asks for the offers.
    ChRequest,
    /// The host has sent every offer.
    ChOfferDone,
    /// The guest opens a channel on the ring's GPADL, the outbound ring
    /// in its first `outbound_pages`, its messages to VP `vp`. User data
    /// 0.
    ChOpen {
        channel: u32,
        open_id: u32,
        gpadl: u32,
        vp: u32,
        outbound_pages: u32,
    },
    /// The host's answer to `ChOpen`: status 0 is open.
    ChOpenResp {
        channel: u32,
        open_id: u32,
        status: u32,
    },
    /// The guest closes a channel; no answer.
    ChClose { channel: u32 },
    /// A GPADL's first message: one range (`range_count` 1) of
    /// `byte_len` bytes from `byte_offset` in its first page, described by
    /// `range_len` bytes of range (8 plus 8 per page), and its first
    /// pages.
    GpadlConn {
        channel: u32,
        gpadl: u32,
        range_len: u16,
        range_count: u16,
        byte_len: u32,
        byte_offset: u32,
        pages: PageList,
    },
    /// More of the GPADL's pages; `number` is 0, as FreeBSD leaves it.
    GpadlSubconn {
        number: u32,
        gpadl: u32,
        pages: PageList,
    },
    /// The host's answer to a GPADL: status 0 is made.
    GpadlConnResp {
        channel: u32,
        gpadl: u32,
        status: u32,
    },
    /// The guest tears a GPADL down.
    GpadlDisconn { channel: u32, gpadl: u32 },
    /// The host has torn it down.
    GpadlDisconnResp { gpadl: u32 },
    /// The guest's contact: the version, and the physical addresses of
    /// the event-flags page and the two monitor pages.
    Connect {
        version: u32,
        event_flags: u64,
        monitor1: u64,
        monitor2: u64,
    },
    /// The host's answer: whether it takes the version (`chm_done`).
    ConnectResp { done: bool },
}

/// Why a message's bytes are not a message vmbus takes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// Shorter than the header.
    Short(usize),
    /// A type vmbus neither sends nor takes.
    Kind(u32),
    /// Shorter than its type's size, or a GPADL message whose length is
    /// not its header and 1 to 26 (or 28) whole page numbers.
    Size { kind: u32, len: usize },
}

impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Bad::Short(n) => write!(f, "{n} bytes, under a channel message's header"),
            Bad::Kind(k) => write!(f, "channel message type {k}"),
            Bad::Size { kind, len } => write!(f, "{len} bytes for channel message type {kind}"),
        }
    }
}

fn u16_at(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes([b[at], b[at + 1]])
}

fn u32_at(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes([b[at], b[at + 1], b[at + 2], b[at + 3]])
}

fn u64_at(b: &[u8], at: usize) -> u64 {
    u64::from(u32_at(b, at)) | u64::from(u32_at(b, at + 4)) << 32
}

fn guid_at(b: &[u8], at: usize) -> Guid {
    let mut g = [0; 16];
    g.copy_from_slice(&b[at..at + 16]);
    Guid(g)
}

/// A little-endian writer over a message buffer.
struct Out<'a> {
    b: &'a mut [u8; MAX],
    len: usize,
}

impl Out<'_> {
    fn bytes(&mut self, v: &[u8]) -> &mut Self {
        self.b[self.len..self.len + v.len()].copy_from_slice(v);
        self.len += v.len();
        self
    }
    fn u8(&mut self, v: u8) -> &mut Self {
        self.bytes(&[v])
    }
    fn u16(&mut self, v: u16) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }
    fn u32(&mut self, v: u32) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }
    fn u64(&mut self, v: u64) -> &mut Self {
        self.bytes(&v.to_le_bytes())
    }
    fn zeros(&mut self, n: usize) -> &mut Self {
        self.b[self.len..self.len + n].fill(0);
        self.len += n;
        self
    }
    fn pages(&mut self, p: &PageList) -> &mut Self {
        for &page in p.as_slice() {
            self.u64(page);
        }
        self
    }
}

impl Msg {
    /// Its type.
    pub const fn kind(&self) -> u32 {
        match self {
            Msg::ChOffer(_) => kind::CHOFFER,
            Msg::ChRescind { .. } => kind::CHRESCIND,
            Msg::ChRequest => kind::CHREQUEST,
            Msg::ChOfferDone => kind::CHOFFER_DONE,
            Msg::ChOpen { .. } => kind::CHOPEN,
            Msg::ChOpenResp { .. } => kind::CHOPEN_RESP,
            Msg::ChClose { .. } => kind::CHCLOSE,
            Msg::GpadlConn { .. } => kind::GPADL_CONN,
            Msg::GpadlSubconn { .. } => kind::GPADL_SUBCONN,
            Msg::GpadlConnResp { .. } => kind::GPADL_CONNRESP,
            Msg::GpadlDisconn { .. } => kind::GPADL_DISCONN,
            Msg::GpadlDisconnResp { .. } => kind::GPADL_DISCONNRESP,
            Msg::Connect { .. } => kind::CONNECT,
            Msg::ConnectResp { .. } => kind::CONNECT_RESP,
        }
    }

    /// FreeBSD's name for its type, for panics.
    pub const fn name(&self) -> &'static str {
        match self {
            Msg::ChOffer(_) => "CHOFFER",
            Msg::ChRescind { .. } => "CHRESCIND",
            Msg::ChRequest => "CHREQUEST",
            Msg::ChOfferDone => "CHOFFER_DONE",
            Msg::ChOpen { .. } => "CHOPEN",
            Msg::ChOpenResp { .. } => "CHOPEN_RESP",
            Msg::ChClose { .. } => "CHCLOSE",
            Msg::GpadlConn { .. } => "GPADL_CONN",
            Msg::GpadlSubconn { .. } => "GPADL_SUBCONN",
            Msg::GpadlConnResp { .. } => "GPADL_CONNRESP",
            Msg::GpadlDisconn { .. } => "GPADL_DISCONN",
            Msg::GpadlDisconnResp { .. } => "GPADL_DISCONNRESP",
            Msg::Connect { .. } => "CONNECT",
            Msg::ConnectResp { .. } => "CONNECT_RESP",
        }
    }

    /// Writes it into `out`; returns its length, at most 240. A GPADL
    /// message's length follows its page count.
    pub fn encode(&self, out: &mut [u8; MAX]) -> usize {
        let mut o = Out { b: out, len: 0 };
        o.u32(self.kind()).u32(0);
        match *self {
            Msg::ChOffer(ref of) => {
                o.bytes(&of.kind.0).bytes(&of.instance.0);
                // chm_chlat, chm_chrev, chm_svrctx_sz, chm_chflags,
                // chm_mmio_sz and the user data: 0.
                o.zeros(8 + 4 + 4 + 2 + 2 + 120);
                o.u16(of.subchannel).u16(0).u32(of.channel);
                o.u8(of.montrig).u8(of.flags1).u16(of.flags2);
                o.u32(of.connection);
            }
            Msg::ChRescind { channel } | Msg::ChClose { channel } => {
                o.u32(channel);
            }
            Msg::ChRequest | Msg::ChOfferDone => {}
            Msg::ChOpen {
                channel,
                open_id,
                gpadl,
                vp,
                outbound_pages,
            } => {
                o.u32(channel).u32(open_id).u32(gpadl).u32(vp);
                o.u32(outbound_pages).zeros(OPEN_USER_DATA);
            }
            Msg::ChOpenResp {
                channel,
                open_id: a,
                status,
            }
            | Msg::GpadlConnResp {
                channel,
                gpadl: a,
                status,
            } => {
                o.u32(channel).u32(a).u32(status);
            }
            Msg::GpadlConn {
                channel,
                gpadl,
                range_len,
                range_count,
                byte_len,
                byte_offset,
                ref pages,
            } => {
                o.u32(channel).u32(gpadl).u16(range_len).u16(range_count);
                o.u32(byte_len).u32(byte_offset).pages(pages);
            }
            Msg::GpadlSubconn {
                number,
                gpadl,
                ref pages,
            } => {
                o.u32(number).u32(gpadl).pages(pages);
            }
            Msg::GpadlDisconn { channel, gpadl } => {
                o.u32(channel).u32(gpadl);
            }
            Msg::GpadlDisconnResp { gpadl } => {
                o.u32(gpadl);
            }
            Msg::Connect {
                version,
                event_flags,
                monitor1,
                monitor2,
            } => {
                o.u32(version)
                    .u32(0)
                    .u64(event_flags)
                    .u64(monitor1)
                    .u64(monitor2);
            }
            Msg::ConnectResp { done } => {
                o.u8(done.into());
            }
        }
        o.len
    }

    /// The message in `b`, a SynIC message's payload: its header, then at
    /// least its type's size, or for a GPADL message exactly its pages.
    pub fn decode(b: &[u8]) -> Result<Msg, Bad> {
        if b.len() < HEADER {
            return Err(Bad::Short(b.len()));
        }
        let k = u32_at(b, 0);
        let need = size(k).ok_or(Bad::Kind(k))?;
        let bad = Bad::Size {
            kind: k,
            len: b.len(),
        };
        if b.len() < need || b.len() > MAX {
            return Err(bad);
        }
        // A GPADL message's pages: what follows its header, whole page
        // numbers, no more than its type carries.
        let pages = |at: usize, max: usize| {
            let rest = b.len() - at;
            if !rest.is_multiple_of(8) || rest / 8 > max {
                return Err(bad);
            }
            let mut l = PageList::new(&[]).ok_or(bad)?;
            l.len = (rest / 8) as u8;
            for (i, p) in l.page.iter_mut().take(rest / 8).enumerate() {
                *p = u64_at(b, at + 8 * i);
            }
            Ok(l)
        };
        let w = |at| u32_at(b, at);
        Ok(match k {
            kind::CHOFFER => Msg::ChOffer(Offer {
                kind: guid_at(b, 8),
                instance: guid_at(b, 24),
                subchannel: u16_at(b, 180),
                channel: w(184),
                montrig: b[188],
                flags1: b[189],
                flags2: u16_at(b, 190),
                connection: w(192),
            }),
            kind::CHRESCIND => Msg::ChRescind { channel: w(8) },
            kind::CHREQUEST => Msg::ChRequest,
            kind::CHOFFER_DONE => Msg::ChOfferDone,
            kind::CHOPEN => Msg::ChOpen {
                channel: w(8),
                open_id: w(12),
                gpadl: w(16),
                vp: w(20),
                outbound_pages: w(24),
            },
            kind::CHOPEN_RESP => Msg::ChOpenResp {
                channel: w(8),
                open_id: w(12),
                status: w(16),
            },
            kind::CHCLOSE => Msg::ChClose { channel: w(8) },
            kind::GPADL_CONN => Msg::GpadlConn {
                channel: w(8),
                gpadl: w(12),
                range_len: u16_at(b, 16),
                range_count: u16_at(b, 18),
                byte_len: w(20),
                byte_offset: w(24),
                pages: pages(CONN_PAGE_OFFSET, CONN_PAGES)?,
            },
            kind::GPADL_SUBCONN => Msg::GpadlSubconn {
                number: w(8),
                gpadl: w(12),
                pages: pages(SUBCONN_PAGE_OFFSET, SUBCONN_PAGES)?,
            },
            kind::GPADL_CONNRESP => Msg::GpadlConnResp {
                channel: w(8),
                gpadl: w(12),
                status: w(16),
            },
            kind::GPADL_DISCONN => Msg::GpadlDisconn {
                channel: w(8),
                gpadl: w(12),
            },
            kind::GPADL_DISCONNRESP => Msg::GpadlDisconnResp { gpadl: w(8) },
            kind::CONNECT => Msg::Connect {
                version: w(8),
                event_flags: u64_at(b, 16),
                monitor1: u64_at(b, 24),
                monitor2: u64_at(b, 32),
            },
            kind::CONNECT_RESP => Msg::ConnectResp { done: b[8] != 0 },
            _ => return Err(Bad::Kind(k)),
        })
    }
}
