//! Ethernet II: the 14-byte header and the MAC address. Frames carry no
//! FCS, no VLAN tag and no offload; `net` takes 14 to 1,514 bytes and
//! pads what it sends to 60.

use core::fmt;

/// The header: destination, source, EtherType.
pub const HEADER: usize = 14;
/// The shortest frame on the wire without its FCS: the stack pads shorter
/// frames it sends with zeros, as a NIC would.
pub const MIN_PADDED: usize = 60;
/// EtherType IPv4.
pub const IPV4: u16 = 0x0800;
/// EtherType ARP.
pub const ARP: u16 = 0x0806;

/// A MAC address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Mac(pub [u8; 6]);

impl Mac {
    /// `ff:ff:ff:ff:ff:ff`.
    pub const BROADCAST: Mac = Mac([0xFF; 6]);
    /// `00:00:00:00:00:00`.
    pub const ZERO: Mac = Mac([0; 6]);

    /// Whether the group bit is set: multicast, broadcast among them.
    pub const fn is_multicast(self) -> bool {
        self.0[0] & 1 != 0
    }

    /// Whether this is one station's address: neither 0 nor a group's.
    pub fn is_unicast(self) -> bool {
        !self.is_multicast() && self != Mac::ZERO
    }

    /// The six bytes at the start of `bytes`, which holds at least six.
    pub fn read(bytes: &[u8]) -> Mac {
        let mut m = [0; 6];
        m.copy_from_slice(&bytes[..6]);
        Mac(m)
    }
}

/// `52:54:00:12:34:56`, lower case.
impl fmt::Display for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let m = &self.0;
        write!(
            f,
            "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
            m[0], m[1], m[2], m[3], m[4], m[5]
        )
    }
}

impl fmt::Debug for Mac {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// A frame's header.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    pub dst: Mac,
    pub src: Mac,
    pub ethertype: u16,
}

impl Header {
    /// The header and the payload after it, padding included; `None` for
    /// a frame shorter than the header.
    pub fn parse(frame: &[u8]) -> Option<(Header, &[u8])> {
        if frame.len() < HEADER {
            return None;
        }
        let h = Header {
            dst: Mac::read(&frame[0..6]),
            src: Mac::read(&frame[6..12]),
            ethertype: u16::from_be_bytes([frame[12], frame[13]]),
        };
        Some((h, &frame[HEADER..]))
    }

    /// Writes the header at the start of `buf`.
    pub fn write(&self, buf: &mut [u8]) {
        buf[0..6].copy_from_slice(&self.dst.0);
        buf[6..12].copy_from_slice(&self.src.0);
        buf[12..14].copy_from_slice(&self.ethertype.to_be_bytes());
    }
}

/// The length to send for a frame of `len` bytes built at the start of
/// `buf`: `len`, or 60 with the bytes between zeroed.
pub fn pad(buf: &mut [u8], len: usize) -> usize {
    if len < MIN_PADDED {
        buf[len..MIN_PADDED].fill(0);
        MIN_PADDED
    } else {
        len
    }
}
