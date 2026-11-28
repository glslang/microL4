//! NVSP, the Network Virtualization Service protocol (FreeBSD's
//! `if_hnreg.h`, `hn_nvs.c` and `hn_nvs.h`, read 2026-11-28): the
//! messages netvsc sends in inband packets and the host's answers in
//! completions, each field little-endian at a fixed offset.
//!
//! Every request is 40 bytes: FreeBSD's structures are at least
//! `HN_NVS_REQSIZE_MIN` (32) bytes, "if only 12B data were sent,
//! Hypervisor would never reply", plus 8 bytes of pad. The answers are
//! checked for length, type and status before any field is used.

use core::fmt;

use crate::layout;

/// The length of every request.
pub const MESSAGE: usize = 40;

/// The message types (`HN_NVS_TYPE_*`).
pub mod kind {
    pub const INIT: u32 = 1;
    pub const INIT_RESP: u32 = 2;
    pub const NDIS_INIT: u32 = 100;
    pub const RXBUF_CONN: u32 = 101;
    pub const RXBUF_CONNRESP: u32 = 102;
    pub const CHIM_CONN: u32 = 104;
    pub const CHIM_CONNRESP: u32 = 105;
    pub const RNDIS: u32 = 107;
    pub const RNDIS_ACK: u32 = 108;
    pub const NDIS_CONF: u32 = 125;
    /// Host notes, counted and ignored.
    pub const VFASSOC_NOTE: u32 = 128;
    pub const TXTBL_NOTE: u32 = 134;
}

/// `HN_NVS_STATUS_OK`; anything else, `HN_NVS_STATUS_FAILED` (2) among
/// them, is a refusal.
pub const STATUS_OK: u32 = 1;
pub const STATUS_FAILED: u32 = 2;

/// The NVSP versions netvsc offers, best first: 5, 4 and 2
/// (`HN_NVS_VERSION_5`, `_4`, `_2`). FreeBSD also tries 6.1, 6 and 1.
pub const VERSIONS: [u32; 3] = [0x5_0000, 0x4_0000, 0x3_0002];

/// NDIS 6.30 and 6.1 (`HN_NDIS_VERSION_6_30`, `_6_1`).
pub const NDIS_6_30: u32 = 0x0006_001E;
pub const NDIS_6_1: u32 = 0x0006_0001;

/// The NDIS version netvsc sends with NVSP `nvsp`: 6.30 from version 5,
/// else 6.1, as FreeBSD's `hn_nvs_init` chooses.
pub const fn ndis_for(nvsp: u32) -> u32 {
    if nvsp >= VERSIONS[0] {
        NDIS_6_30
    } else {
        NDIS_6_1
    }
}

/// The MTU NDIS_CONF gives: a 1,500-byte packet and its Ethernet header,
/// as FreeBSD's `hn_nvs_conf_ndis` (`mtu + ETHER_HDR_LEN`).
pub const NDIS_MTU: u32 = 1514;
/// `HN_NVS_NDIS_CONF_VLAN`, the one capability FreeBSD gives below NVSP
/// 5; netvsc gives it with every version.
pub const CONF_VLAN: u64 = 0x8;

/// The receive buffer's and the send buffer's signatures.
pub const RXBUF_SIG: u16 = 0xCAFE;
pub const CHIM_SIG: u16 = 0xFACE;
/// A control RNDIS message uses no send section.
pub const CHIM_NONE: u32 = 0xFFFF_FFFF;
/// `nvs_rndis_mtype`: data (0) or control (1).
pub const MTYPE_DATA: u32 = 0;
pub const MTYPE_CONTROL: u32 = 1;

/// The smallest send section netvsc takes: an RNDIS packet message's
/// header and a whole frame.
pub const MIN_SECTION: u32 = (crate::rndis::PACKET_HEADER + libsys::frames::MAX_FRAME) as u32;
/// The most send sections netvsc uses.
pub const MAX_SECTIONS: u32 = 128;

fn message(kind: u32, fields: &[(usize, &[u8])]) -> [u8; MESSAGE] {
    let mut m = [0u8; MESSAGE];
    m[..4].copy_from_slice(&kind.to_le_bytes());
    for &(at, bytes) in fields {
        m[at..at + bytes.len()].copy_from_slice(bytes);
    }
    m
}

/// INIT (`hn_nvs_init`): `nvs_ver_min` and `nvs_ver_max` both `version`.
pub fn init(version: u32) -> [u8; MESSAGE] {
    message(
        kind::INIT,
        &[(4, &version.to_le_bytes()), (8, &version.to_le_bytes())],
    )
}

/// NDIS_CONF (`hn_nvs_ndis_conf`): the MTU at 4, the capabilities (u64)
/// at 12. No completion.
pub fn ndis_conf() -> [u8; MESSAGE] {
    message(
        kind::NDIS_CONF,
        &[(4, &NDIS_MTU.to_le_bytes()), (12, &CONF_VLAN.to_le_bytes())],
    )
}

/// NDIS_INIT (`hn_nvs_ndis_init`): the major version at 4, the minor at
/// 8. No completion.
pub fn ndis_init(ndis: u32) -> [u8; MESSAGE] {
    message(
        kind::NDIS_INIT,
        &[
            (4, &(ndis >> 16).to_le_bytes()),
            (8, &(ndis & 0xFFFF).to_le_bytes()),
        ],
    )
}

/// RXBUF_CONN (`hn_nvs_rxbuf_conn`): the GPADL at 4, the signature (u16)
/// at 8.
pub fn rxbuf_conn(gpadl: u32) -> [u8; MESSAGE] {
    message(
        kind::RXBUF_CONN,
        &[(4, &gpadl.to_le_bytes()), (8, &RXBUF_SIG.to_le_bytes())],
    )
}

/// CHIM_CONN (`hn_nvs_chim_conn`): the same, with the send buffer's.
pub fn chim_conn(gpadl: u32) -> [u8; MESSAGE] {
    message(
        kind::CHIM_CONN,
        &[(4, &gpadl.to_le_bytes()), (8, &CHIM_SIG.to_le_bytes())],
    )
}

/// RNDIS (`hn_nvs_rndis`): the message type at 4, the send section at 8
/// and the message's size in it at 12; a control message uses none
/// ([`CHIM_NONE`], size 0).
pub fn rndis(mtype: u32, section: u32, size: u32) -> [u8; MESSAGE] {
    message(
        kind::RNDIS,
        &[
            (4, &mtype.to_le_bytes()),
            (8, &section.to_le_bytes()),
            (12, &size.to_le_bytes()),
        ],
    )
}

/// RNDIS_ACK (`hn_nvs_rndis_ack`): the status at 4. netvsc's
/// acknowledgement of a receive-buffer packet carries [`STATUS_OK`], as
/// FreeBSD's `hn_nvs_ack_rxbuf` does.
pub fn rndis_ack(status: u32) -> [u8; MESSAGE] {
    message(kind::RNDIS_ACK, &[(4, &status.to_le_bytes())])
}

/// The little-endian u32 at `at` of `b`, if it is there.
pub(crate) fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    let w = b.get(at..at.checked_add(4)?)?;
    Some(u32::from_le_bytes([w[0], w[1], w[2], w[3]]))
}

/// The NVS message type of a body, its first 4 bytes.
pub fn kind_of(body: &[u8]) -> Option<u32> {
    u32_at(body, 0)
}

/// Why an answer was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Bad {
    /// Shorter than its type's fields: its length.
    Short(usize),
    /// Another message type.
    Kind(u32),
    /// A status other than [`STATUS_OK`].
    Status(u32),
    /// RXBUF_CONNRESP: no section, or more than its length holds.
    Sections(u32),
    /// RXBUF_CONNRESP: section `n`, as the host laid it out, is not
    /// inside the receive buffer ([`RxSection::outside`] says why).
    Section(u32, RxSection),
    /// CHIM_CONNRESP: a section size netvsc cannot use.
    SectionSize(u32),
}

impl fmt::Display for Bad {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Bad::Short(n) => write!(f, "an answer of {n} bytes"),
            Bad::Kind(k) => write!(f, "an answer of type {k}"),
            Bad::Status(s) => write!(f, "status {s:#x}"),
            Bad::Sections(n) => write!(f, "{n} sections"),
            Bad::Section(i, s) => {
                write!(
                    f,
                    "section {i} (start {:#x}, end {:#x}, {} slots of {} bytes)",
                    s.start, s.end, s.slots, s.slot_size
                )?;
                let size = layout::RECEIVE_SIZE;
                match s.outside() {
                    Some(Outside::StartPastEnd) => f.write_str(": it starts after it ends"),
                    Some(Outside::EndPastBuffer) => {
                        write!(f, ": it ends past the {size:#x}-byte receive buffer")
                    }
                    Some(Outside::SlotsPastBuffer) => write!(
                        f,
                        ": its slots reach {:#x}, past the {size:#x}-byte receive buffer",
                        s.slots_end()
                    ),
                    None => f.write_str(" outside the receive buffer"),
                }
            }
            Bad::SectionSize(s) => write!(f, "a section size of {s} bytes"),
        }
    }
}

/// Checks an answer's length, type and status (at 4, or for INIT_RESP at
/// 12).
fn check(body: &[u8], kind: u32, len: usize, status_at: usize) -> Result<(), Bad> {
    let k = kind_of(body).ok_or(Bad::Short(body.len()))?;
    if k != kind {
        return Err(Bad::Kind(k));
    }
    if body.len() < len {
        return Err(Bad::Short(body.len()));
    }
    let s = u32_at(body, status_at).ok_or(Bad::Short(body.len()))?;
    if s != STATUS_OK {
        return Err(Bad::Status(s));
    }
    Ok(())
}

/// INIT_RESP (`hn_nvs_init_resp`): 16 bytes, the status at 12.
pub fn init_resp(body: &[u8]) -> Result<(), Bad> {
    check(body, kind::INIT_RESP, 16, 12)
}

/// A receive buffer section (`hn_nvs_rxbuf_sect`): where it starts and
/// ends in the buffer, and its slots.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct RxSection {
    pub start: u32,
    pub slot_size: u32,
    pub slots: u32,
    pub end: u32,
}

/// Why a section is not inside the receive buffer: the first of
/// [`RxSection::outside`]'s checks it fails, which a refusal's line names,
/// so that one run on a real host shows which field the check refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outside {
    /// Its start is past its end.
    StartPastEnd,
    /// Its end is past the 1 MiB buffer.
    EndPastBuffer,
    /// Its slots, from its start, reach past the buffer.
    SlotsPastBuffer,
}

impl RxSection {
    /// Where its slots end: its start plus the slots' bytes.
    pub const fn slots_end(&self) -> u64 {
        self.start as u64 + self.slot_size as u64 * self.slots as u64
    }

    /// Why it is not inside the receive buffer, or `None` if it is: its
    /// start at or before its end, its end and its slots within the
    /// buffer.
    pub const fn outside(&self) -> Option<Outside> {
        let size = layout::RECEIVE_SIZE as u64;
        if self.start > self.end {
            Some(Outside::StartPastEnd)
        } else if self.end as u64 > size {
            Some(Outside::EndPastBuffer)
        } else if self.slots_end() > size {
            Some(Outside::SlotsPastBuffer)
        } else {
            None
        }
    }
}

/// RXBUF_CONNRESP (`hn_nvs_rxbuf_connresp`): the status at 4, the section
/// count at 8, then 16 bytes a section. At least one section, every one
/// the body holds, each inside the 1 MiB buffer: its start at or before
/// its end, both within it, and its slots too. Returns the first section.
pub fn rxbuf_connresp(body: &[u8]) -> Result<RxSection, Bad> {
    check(body, kind::RXBUF_CONNRESP, 12, 4)?;
    let n = u32_at(body, 8).ok_or(Bad::Short(body.len()))?;
    if n == 0 || 12 + 16 * u64::from(n) > body.len() as u64 {
        return Err(Bad::Sections(n));
    }
    let mut first = None;
    for i in 0..n {
        let at = 12 + 16 * i as usize;
        let f = |k: usize| u32_at(body, at + 4 * k).expect("inside the body");
        let s = RxSection {
            start: f(0),
            slot_size: f(1),
            slots: f(2),
            end: f(3),
        };
        if s.outside().is_some() {
            return Err(Bad::Section(i, s));
        }
        first.get_or_insert(s);
    }
    Ok(first.expect("one section at least"))
}

/// CHIM_CONNRESP (`hn_nvs_chim_connresp`): the status at 4, the section
/// size at 8, which must be a multiple of 4 and hold a whole frame's
/// RNDIS message. Returns the size and the sections netvsc uses: as many
/// as the 768 KiB buffer holds, at most 128.
pub fn chim_connresp(body: &[u8]) -> Result<(u32, u32), Bad> {
    check(body, kind::CHIM_CONNRESP, 12, 4)?;
    let size = u32_at(body, 8).ok_or(Bad::Short(body.len()))?;
    if !size.is_multiple_of(4) || size < MIN_SECTION || size as usize > layout::SEND_SIZE {
        return Err(Bad::SectionSize(size));
    }
    let sections = (layout::SEND_SIZE as u32 / size).min(MAX_SECTIONS);
    Ok((size, sections))
}

/// A send completion's body: RNDIS_ACK with its status at 4, or `None`
/// for anything else.
pub fn ack_status(body: &[u8]) -> Option<u32> {
    (kind_of(body)? == kind::RNDIS_ACK).then(|| u32_at(body, 4))?
}
