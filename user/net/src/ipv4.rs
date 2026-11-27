//! IPv4: the address, and the header `net` checks and writes.
//!
//! A packet is taken with version 4, IHL 5 to 15 (options skipped
//! unread), a total length from 4 × IHL to what the frame carries (the
//! rest is padding), and a header checksum that verifies; fragments are
//! refused, since nothing reassembles. A packet sent has version 4, IHL 5,
//! TOS 0, the stack's next identification, DF, TTL 64 and its checksum.

use core::fmt;

use crate::checksum::Sum;

/// A header without options.
pub const HEADER: usize = 20;
/// The largest packet: Ethernet's MTU.
pub const MAX_PACKET: usize = 1500;
/// Protocol ICMP.
pub const ICMP: u8 = 1;
/// Protocol UDP.
pub const UDP: u8 = 17;
/// The TTL of every packet sent.
pub const TTL: u8 = 64;
/// Don't Fragment, in the flags and fragment offset word.
pub const DF: u16 = 0x4000;
/// More Fragments.
pub const MF: u16 = 0x2000;
/// The fragment offset's bits.
pub const OFFSET: u16 = 0x1FFF;

/// An IPv4 address.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash, Default)]
pub struct Ip(pub [u8; 4]);

impl Ip {
    /// `0.0.0.0`.
    pub const UNSPECIFIED: Ip = Ip([0; 4]);
    /// `255.255.255.255`, the limited broadcast.
    pub const BROADCAST: Ip = Ip([255; 4]);

    pub const fn new(a: u8, b: u8, c: u8, d: u8) -> Ip {
        Ip([a, b, c, d])
    }

    /// The address as a number, `a.b.c.d` as `0xaabbccdd`.
    pub const fn to_u32(self) -> u32 {
        u32::from_be_bytes(self.0)
    }

    pub const fn from_u32(n: u32) -> Ip {
        Ip(n.to_be_bytes())
    }

    /// In `224.0.0.0/4`.
    pub const fn is_multicast(self) -> bool {
        self.0[0] >> 4 == 0xE
    }

    /// The four bytes at the start of `bytes`, which holds at least four.
    pub fn read(bytes: &[u8]) -> Ip {
        Ip([bytes[0], bytes[1], bytes[2], bytes[3]])
    }

    /// `a.b.c.d`, each part a decimal from 0 to 255 without a leading
    /// zero (so `010` is refused, not read as octal or as ten).
    pub fn parse(text: &str) -> Option<Ip> {
        let mut out = [0u8; 4];
        let mut parts = text.split('.');
        for o in &mut out {
            let p = parts.next()?;
            let ok = !p.is_empty()
                && p.len() <= 3
                && p.bytes().all(|b| b.is_ascii_digit())
                && (p == "0" || !p.starts_with('0'));
            if !ok {
                return None;
            }
            *o = p.parse().ok()?;
        }
        parts.next().is_none().then_some(Ip(out))
    }
}

impl fmt::Display for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let [a, b, c, d] = self.0;
        write!(f, "{a}.{b}.{c}.{d}")
    }
}

impl fmt::Debug for Ip {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Display::fmt(self, f)
    }
}

/// What a header that parsed says.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Header {
    /// 4 × IHL: where the payload starts.
    pub header_len: usize,
    /// The total length: where the payload ends.
    pub total_len: usize,
    pub ident: u16,
    /// The flags and the fragment offset.
    pub fragment: u16,
    pub ttl: u8,
    pub protocol: u8,
    pub src: Ip,
    pub dst: Ip,
}

/// Why a packet was refused, in the order the checks run.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bad {
    /// Shorter than a header, a version but 4, an IHL under 5 or past
    /// the packet, or a total length under the header or past the frame.
    Malformed,
    /// A header checksum that does not verify.
    Checksum,
    /// MF set or a non-zero offset.
    Fragment,
}

impl Header {
    /// Checks the header at the start of `packet` (an Ethernet payload,
    /// padding included) and returns it with the payload, which ends at
    /// the total length.
    pub fn parse(packet: &[u8]) -> Result<(Header, &[u8]), Bad> {
        if packet.len() < HEADER || packet[0] >> 4 != 4 {
            return Err(Bad::Malformed);
        }
        let header_len = usize::from(packet[0] & 0xF) * 4;
        let total_len = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
        if header_len < HEADER
            || header_len > packet.len()
            || total_len < header_len
            || total_len > packet.len()
        {
            return Err(Bad::Malformed);
        }
        if !Sum::new().add(&packet[..header_len]).verifies() {
            return Err(Bad::Checksum);
        }
        let fragment = u16::from_be_bytes([packet[6], packet[7]]);
        if fragment & (MF | OFFSET) != 0 {
            return Err(Bad::Fragment);
        }
        let h = Header {
            header_len,
            total_len,
            ident: u16::from_be_bytes([packet[4], packet[5]]),
            fragment,
            ttl: packet[8],
            protocol: packet[9],
            src: Ip::read(&packet[12..16]),
            dst: Ip::read(&packet[16..20]),
        };
        Ok((h, &packet[header_len..total_len]))
    }
}

/// Writes a 20-byte header at the start of `buf` for a packet of
/// `payload_len` bytes after it: version 4, IHL 5, TOS 0, `ident`, DF,
/// TTL 64, `protocol`, the checksum.
pub fn write(buf: &mut [u8], ident: u16, protocol: u8, src: Ip, dst: Ip, payload_len: usize) {
    let total = (HEADER + payload_len) as u16;
    let h = &mut buf[..HEADER];
    h[0] = 0x45;
    h[1] = 0;
    h[2..4].copy_from_slice(&total.to_be_bytes());
    h[4..6].copy_from_slice(&ident.to_be_bytes());
    h[6..8].copy_from_slice(&DF.to_be_bytes());
    h[8] = TTL;
    h[9] = protocol;
    h[10..12].fill(0);
    h[12..16].copy_from_slice(&src.0);
    h[16..20].copy_from_slice(&dst.0);
    let c = Sum::new().add(h).checksum();
    h[10..12].copy_from_slice(&c.to_be_bytes());
}

/// The pseudo-header's sum, which UDP's checksum starts from.
pub fn pseudo(src: Ip, dst: Ip, protocol: u8, len: usize) -> Sum {
    let mut s = Sum::new();
    s.add(&src.0)
        .add(&dst.0)
        .add(&[0, protocol])
        .add_u16(len as u16);
    s
}
