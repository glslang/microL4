//! ICMP echo: the request the stack answers, the reply it builds, and its
//! one request to the gateway (`docs/design.md`, "`net`").
//!
//! A message is checked for its 8-byte header and a checksum over the
//! whole message; then only echo requests (type 8, code 0) and echo
//! replies (type 0, code 0) mean anything.

use crate::checksum::Sum;

/// The header: type, code, checksum, identifier, sequence.
pub const HEADER: usize = 8;
/// Type echo reply.
pub const ECHO_REPLY: u8 = 0;
/// Type echo request.
pub const ECHO_REQUEST: u8 = 8;
/// The identifier of the stack's one echo request: `L4`.
pub const PING_IDENT: u16 = 0x4C34;
/// Its sequence number.
pub const PING_SEQ: u16 = 1;
/// Its data's length, as ping's.
pub const PING_DATA: usize = 56;

/// Byte `i` of the stack's echo request's data.
pub const fn ping_byte(i: usize) -> u8 {
    i as u8
}

/// A message that parsed.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Message<'a> {
    /// Type 8, code 0.
    EchoRequest {
        ident: u16,
        seq: u16,
        data: &'a [u8],
    },
    /// Type 0, code 0.
    EchoReply {
        ident: u16,
        seq: u16,
        data: &'a [u8],
    },
    /// Any other type or code.
    Other { kind: u8, code: u8 },
}

/// Why a message was refused.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum Bad {
    /// Shorter than its header.
    Short,
    /// A checksum that does not verify.
    Checksum,
}

impl<'a> Message<'a> {
    /// Checks `msg`, an IPv4 payload.
    pub fn parse(msg: &'a [u8]) -> Result<Message<'a>, Bad> {
        if msg.len() < HEADER {
            return Err(Bad::Short);
        }
        if !Sum::new().add(msg).verifies() {
            return Err(Bad::Checksum);
        }
        let ident = u16::from_be_bytes([msg[4], msg[5]]);
        let seq = u16::from_be_bytes([msg[6], msg[7]]);
        let data = &msg[HEADER..];
        Ok(match (msg[0], msg[1]) {
            (ECHO_REQUEST, 0) => Message::EchoRequest { ident, seq, data },
            (ECHO_REPLY, 0) => Message::EchoReply { ident, seq, data },
            (kind, code) => Message::Other { kind, code },
        })
    }
}

/// Writes an echo message of type `kind` at the start of `buf`, with the
/// checksum over the whole message, and returns its length.
pub fn write_echo(buf: &mut [u8], kind: u8, ident: u16, seq: u16, data: &[u8]) -> usize {
    let len = HEADER + data.len();
    let m = &mut buf[..len];
    m[0] = kind;
    m[1] = 0;
    m[2..4].fill(0);
    m[4..6].copy_from_slice(&ident.to_be_bytes());
    m[6..8].copy_from_slice(&seq.to_be_bytes());
    m[HEADER..].copy_from_slice(data);
    let c = Sum::new().add(m).checksum();
    m[2..4].copy_from_slice(&c.to_be_bytes());
    len
}

/// Writes the stack's echo request at the start of `buf` and returns its
/// length.
pub fn write_ping(buf: &mut [u8]) -> usize {
    let mut data = [0u8; PING_DATA];
    for (i, b) in data.iter_mut().enumerate() {
        *b = ping_byte(i);
    }
    write_echo(buf, ECHO_REQUEST, PING_IDENT, PING_SEQ, &data)
}
