//! Ethernet II: the 14-byte header and the MAC address. Frames carry no
//! FCS, no VLAN tag and no offload; `net` takes 14 to 1,514 bytes and
//! pads what it sends to 60.

/// The header: destination, source, EtherType.
pub const HEADER: usize = 14;
/// The shortest frame on the wire without its FCS: the stack pads shorter
/// frames it sends with zeros, as a NIC would.
pub const MIN_PADDED: usize = 60;
/// EtherType IPv4.
pub const IPV4: u16 = 0x0800;
/// EtherType ARP.
pub const ARP: u16 = 0x0806;

/// A MAC address: the frame queues' own, whose link block gives the
/// stack its MAC.
pub use libsys::frames::Mac;

/// The MAC in the six bytes at the start of `bytes`, which holds at least
/// six.
pub fn mac_at(bytes: &[u8]) -> Mac {
    let mut m = [0; 6];
    m.copy_from_slice(&bytes[..6]);
    Mac(m)
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
            dst: mac_at(&frame[0..6]),
            src: mac_at(&frame[6..12]),
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
