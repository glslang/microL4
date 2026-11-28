//! The VMBus channel messages as the host reads and writes them, written
//! from FreeBSD's `vmbus_reg.h` (read 2026-11-27) on their own, not
//! shared with `vmbus::msg`, so that a layout mistake on either side
//! shows as a test failure rather than agreeing with itself.
//!
//! Every message is an 8-byte header (`chm_type`, a reserved word) and
//! packed little-endian fields; the guest's requests are parsed with every
//! length checked, the host's answers and notes built.

use std::fmt::Write as _;

use crate::host::OfferSpec;

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
    pub const CHFREE: u32 = 13;
    pub const CONNECT: u32 = 14;
    pub const CONNECT_RESP: u32 = 15;
    pub const DISCONNECT: u32 = 16;
}

/// The SynIC message type of a channel message (`HYPERV_MSGTYPE_CHANNEL`).
pub const CHANNEL_MESSAGE: u32 = 1;
/// The message connection (`VMBUS_CONNID_MESSAGE`).
pub const MESSAGE_CONNECTION: u32 = 1;
/// A SynIC message's payload.
pub const MAX: usize = 240;
/// Pages in `GPADL_CONN` and `GPADL_SUBCONN`.
pub const CONN_PAGES: usize = 26;
pub const SUBCONN_PAGES: usize = 28;

/// A request the guest posted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Connect {
        version: u32,
        event_flags: u64,
        monitor1: u64,
        monitor2: u64,
    },
    ChRequest,
    GpadlConn {
        channel: u32,
        gpadl: u32,
        range_len: u16,
        range_count: u16,
        byte_len: u32,
        byte_offset: u32,
        pages: Vec<u64>,
    },
    GpadlSubconn {
        number: u32,
        gpadl: u32,
        pages: Vec<u64>,
    },
    ChOpen {
        channel: u32,
        open_id: u32,
        gpadl: u32,
        vp: u32,
        outbound_pages: u32,
        user_data_zero: bool,
    },
    ChClose {
        channel: u32,
    },
    GpadlDisconn {
        channel: u32,
        gpadl: u32,
    },
    ChFree {
        channel: u32,
    },
    Disconnect,
    /// A type no guest sends.
    Other(u32),
}

fn le32(b: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(b[at..at + 4].try_into().expect("4 bytes"))
}

fn le64(b: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(b[at..at + 8].try_into().expect("8 bytes"))
}

fn le16(b: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(b[at..at + 2].try_into().expect("2 bytes"))
}

fn page_list(b: &[u8], from: usize, max: usize, what: &str) -> Result<Vec<u64>, String> {
    let rest = b.len() - from;
    if rest == 0 || !rest.is_multiple_of(8) || rest / 8 > max {
        return Err(format!(
            "{what} of {} bytes: not 1 to {max} page numbers",
            b.len()
        ));
    }
    Ok((0..rest / 8).map(|i| le64(b, from + 8 * i)).collect())
}

/// Parses a request. `Err` names what is wrong; a real host would ignore
/// or refuse it.
pub fn parse(b: &[u8]) -> Result<Request, String> {
    if b.len() < 8 || b.len() > MAX {
        return Err(format!("a channel message of {} bytes", b.len()));
    }
    let k = le32(b, 0);
    let need = |n: usize, what: &str| {
        if b.len() < n {
            Err(format!("{what} of {} bytes, under {n}", b.len()))
        } else {
            Ok(())
        }
    };
    Ok(match k {
        kind::CONNECT => {
            need(40, "CONNECT")?;
            Request::Connect {
                version: le32(b, 8),
                event_flags: le64(b, 16),
                monitor1: le64(b, 24),
                monitor2: le64(b, 32),
            }
        }
        kind::CHREQUEST => Request::ChRequest,
        kind::GPADL_CONN => {
            need(28 + 8, "GPADL_CONN")?;
            Request::GpadlConn {
                channel: le32(b, 8),
                gpadl: le32(b, 12),
                range_len: le16(b, 16),
                range_count: le16(b, 18),
                byte_len: le32(b, 20),
                byte_offset: le32(b, 24),
                pages: page_list(b, 28, CONN_PAGES, "GPADL_CONN")?,
            }
        }
        kind::GPADL_SUBCONN => {
            need(16 + 8, "GPADL_SUBCONN")?;
            Request::GpadlSubconn {
                number: le32(b, 8),
                gpadl: le32(b, 12),
                pages: page_list(b, 16, SUBCONN_PAGES, "GPADL_SUBCONN")?,
            }
        }
        kind::CHOPEN => {
            need(148, "CHOPEN")?;
            Request::ChOpen {
                channel: le32(b, 8),
                open_id: le32(b, 12),
                gpadl: le32(b, 16),
                vp: le32(b, 20),
                outbound_pages: le32(b, 24),
                user_data_zero: b[28..148].iter().all(|&x| x == 0),
            }
        }
        kind::CHCLOSE => {
            need(12, "CHCLOSE")?;
            Request::ChClose {
                channel: le32(b, 8),
            }
        }
        kind::GPADL_DISCONN => {
            need(16, "GPADL_DISCONN")?;
            Request::GpadlDisconn {
                channel: le32(b, 8),
                gpadl: le32(b, 12),
            }
        }
        kind::CHFREE => {
            need(12, "CHFREE")?;
            Request::ChFree {
                channel: le32(b, 8),
            }
        }
        kind::DISCONNECT => Request::Disconnect,
        other => Request::Other(other),
    })
}

/// A message's bytes as it is built.
struct Msg(Vec<u8>);

impl Msg {
    fn new(kind: u32) -> Msg {
        let mut v = Vec::with_capacity(MAX);
        v.extend_from_slice(&kind.to_le_bytes());
        v.extend_from_slice(&0u32.to_le_bytes());
        Msg(v)
    }
    fn u8(mut self, x: u8) -> Msg {
        self.0.push(x);
        self
    }
    fn u16(mut self, x: u16) -> Msg {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn u32(mut self, x: u32) -> Msg {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn u64(mut self, x: u64) -> Msg {
        self.0.extend_from_slice(&x.to_le_bytes());
        self
    }
    fn bytes(mut self, x: &[u8]) -> Msg {
        self.0.extend_from_slice(x);
        self
    }
}

/// `CHOFFER`, 196 bytes (`vmbus_chanmsg_choffer`).
pub fn offer(o: &OfferSpec) -> Vec<u8> {
    let m = Msg::new(kind::CHOFFER)
        .bytes(&o.kind)
        .bytes(&o.instance)
        // chm_chlat, chm_chrev, chm_svrctx_sz, chm_chflags, chm_mmio_sz.
        .u64(0)
        .u32(0)
        .u32(0)
        .u16(0)
        .u16(0)
        .bytes(&[0; 120])
        .u16(o.subchannel)
        .u16(0)
        .u32(o.channel)
        .u8(o.montrig)
        .u8(o.flags1)
        .u16(o.flags2)
        .u32(o.connection);
    debug_assert_eq!(m.0.len(), 196);
    m.0
}

/// `CONNECT_RESP`: `chm_done` at byte 8, as FreeBSD reads it, in the 16
/// bytes of Linux's `vmbus_channel_version_response` (from memory: the
/// state byte, padding and the message connection, all 0 here).
pub fn connect_resp(done: bool) -> Vec<u8> {
    Msg::new(kind::CONNECT_RESP)
        .u8(done.into())
        .u8(0)
        .u16(0)
        .u32(0)
        .0
}

pub fn offers_done() -> Vec<u8> {
    Msg::new(kind::CHOFFER_DONE).0
}

pub fn rescind(channel: u32) -> Vec<u8> {
    Msg::new(kind::CHRESCIND).u32(channel).0
}

pub fn gpadl_connresp(channel: u32, gpadl: u32, status: u32) -> Vec<u8> {
    Msg::new(kind::GPADL_CONNRESP)
        .u32(channel)
        .u32(gpadl)
        .u32(status)
        .0
}

pub fn chopen_resp(channel: u32, open_id: u32, status: u32) -> Vec<u8> {
    Msg::new(kind::CHOPEN_RESP)
        .u32(channel)
        .u32(open_id)
        .u32(status)
        .0
}

/// `GPADL_DISCONNRESP`: the header and the handle (Linux's
/// `vmbus_channel_gpadl_torndown`, from memory; FreeBSD discards it).
pub fn gpadl_disconnresp(gpadl: u32) -> Vec<u8> {
    Msg::new(kind::GPADL_DISCONNRESP).u32(gpadl).0
}

/// A GUID's text, as FreeBSD's `hyperv_guid2str` prints it.
pub fn guid_text(g: &[u8; 16]) -> String {
    let mut s = String::new();
    for (i, w) in [3, 2, 1, 0, 5, 4, 7, 6, 8, 9, 10, 11, 12, 13, 14, 15]
        .into_iter()
        .enumerate()
    {
        if matches!(i, 4 | 6 | 8 | 10) {
            s.push('-');
        }
        let _ = write!(s, "{:02x}", g[w]);
    }
    s
}
