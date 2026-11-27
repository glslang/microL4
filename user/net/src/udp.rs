//! UDP: the datagram `net` checks and writes, and the service the stack
//! hands datagrams to (`docs/design.md`, "`net`").
//!
//! A datagram is taken with a length from 8 to its IP payload (bytes past
//! it are ignored) and a checksum of 0 (none, which IPv4 allows) or one
//! that verifies with the pseudo-header. One sent always carries its
//! checksum, a result of 0 sent as `0xFFFF`.

use crate::ipv4::{self, Ip};

/// The header: source port, destination port, length, checksum.
pub const HEADER: usize = 8;
/// The largest payload that fits a 1,500-byte packet unfragmented.
pub const MAX_PAYLOAD: usize = ipv4::MAX_PACKET - ipv4::HEADER - HEADER;

const _: () = assert!(MAX_PAYLOAD == 1472);

/// An address and a port.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Endpoint {
    pub ip: Ip,
    pub port: u16,
}

/// A datagram that parsed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub struct Datagram<'a> {
    pub src_port: u16,
    pub dst_port: u16,
    /// Whether it carried a checksum.
    pub checksummed: bool,
    pub payload: &'a [u8],
}

/// Why a datagram was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bad {
    /// Shorter than its header, or a length under 8 or past the IP
    /// payload.
    Length,
    /// A non-zero checksum that does not verify.
    Checksum,
}

impl<'a> Datagram<'a> {
    /// Checks `data`, the IP payload of a packet from `src` to `dst`.
    pub fn parse(src: Ip, dst: Ip, data: &'a [u8]) -> Result<Datagram<'a>, Bad> {
        if data.len() < HEADER {
            return Err(Bad::Length);
        }
        let len = usize::from(u16::from_be_bytes([data[4], data[5]]));
        if len < HEADER || len > data.len() {
            return Err(Bad::Length);
        }
        let d = &data[..len];
        let checksummed = d[6..8] != [0, 0];
        if checksummed && !ipv4::pseudo(src, dst, ipv4::UDP, len).add(d).verifies() {
            return Err(Bad::Checksum);
        }
        Ok(Datagram {
            src_port: u16::from_be_bytes([d[0], d[1]]),
            dst_port: u16::from_be_bytes([d[2], d[3]]),
            checksummed,
            payload: &d[HEADER..],
        })
    }
}

/// Writes a datagram from `src` to `dst` carrying `payload` at the start
/// of `buf`, with its checksum, and returns its length.
pub fn write(buf: &mut [u8], src: Endpoint, dst: Endpoint, payload: &[u8]) -> usize {
    let len = HEADER + payload.len();
    let d = &mut buf[..len];
    d[0..2].copy_from_slice(&src.port.to_be_bytes());
    d[2..4].copy_from_slice(&dst.port.to_be_bytes());
    d[4..6].copy_from_slice(&(len as u16).to_be_bytes());
    d[6..8].fill(0);
    d[HEADER..].copy_from_slice(payload);
    let mut c = ipv4::pseudo(src.ip, dst.ip, ipv4::UDP, len)
        .add(d)
        .checksum();
    if c == 0 {
        c = 0xFFFF;
    }
    d[6..8].copy_from_slice(&c.to_be_bytes());
    len
}

/// A UDP service on one port: the stack calls it for each datagram to
/// [`Service::PORT`] that passed every check, from any port but 0 and
/// its own, to the stack's unicast address.
pub trait Service {
    /// The port it serves.
    const PORT: u16;

    /// One datagram, borrowed for the call: `payload` lies in the receive
    /// buffer. The service may send one datagram back with `reply`.
    fn datagram<'p>(&mut self, from: Endpoint, payload: &'p [u8], reply: &mut Reply<'p>);
}

/// The one datagram a service may send back, from its port to the
/// datagram's source. The stack writes it straight into a transmit
/// buffer, so a payload is copied once, from the receive buffer.
#[derive(Debug, Default)]
pub struct Reply<'p> {
    payload: Option<&'p [u8]>,
}

impl<'p> Reply<'p> {
    pub(crate) const fn new() -> Reply<'p> {
        Reply { payload: None }
    }

    /// Sends `payload` back. Returns `false`, sending nothing more, for a
    /// second reply or a payload over [`MAX_PAYLOAD`] bytes.
    pub fn send(&mut self, payload: &'p [u8]) -> bool {
        if self.payload.is_some() || payload.len() > MAX_PAYLOAD {
            return false;
        }
        self.payload = Some(payload);
        true
    }

    /// What the service sent.
    pub(crate) fn take(self) -> Option<&'p [u8]> {
        self.payload
    }
}
