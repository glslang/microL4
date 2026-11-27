//! Frames built and read by the tests, with checksum code of their own:
//! nothing here calls the stack's builders, parsers or `net::checksum`,
//! so the tests compare the stack with a second implementation. Also the
//! goldens' hex layout and the comments that describe a frame.

use std::fmt::Write as _;
use std::string::String;
use std::vec::Vec;
use std::{format, vec};

/// The ones' complement sum, the obvious way: each 16-bit word added
/// with its carry wrapped round at once, an odd last byte padded with 0.
pub fn ones_sum(data: &[u8]) -> u16 {
    let mut s: u16 = 0;
    for i in (0..data.len()).step_by(2) {
        let hi = data[i];
        let lo = if i + 1 < data.len() { data[i + 1] } else { 0 };
        let w = u16::from(hi) << 8 | u16::from(lo);
        let (r, carry) = s.overflowing_add(w);
        s = r + u16::from(carry);
    }
    s
}

/// The checksum a header or message carries.
pub fn csum(data: &[u8]) -> u16 {
    !ones_sum(data)
}

pub fn put16(b: &mut [u8], at: usize, v: u16) {
    b[at] = (v >> 8) as u8;
    b[at + 1] = v as u8;
}

pub fn get16(b: &[u8], at: usize) -> u16 {
    u16::from(b[at]) << 8 | u16::from(b[at + 1])
}

/// An Ethernet frame.
pub fn eth(dst: [u8; 6], src: [u8; 6], ethertype: u16, payload: &[u8]) -> Vec<u8> {
    let mut f = Vec::with_capacity(14 + payload.len());
    f.extend_from_slice(&dst);
    f.extend_from_slice(&src);
    f.extend_from_slice(&ethertype.to_be_bytes());
    f.extend_from_slice(payload);
    f
}

/// An ARP body for Ethernet and IPv4.
pub fn arp(op: u16, sha: [u8; 6], spa: [u8; 4], tha: [u8; 6], tpa: [u8; 4]) -> Vec<u8> {
    let mut b = vec![0, 1, 8, 0, 6, 4];
    b.extend_from_slice(&op.to_be_bytes());
    b.extend_from_slice(&sha);
    b.extend_from_slice(&spa);
    b.extend_from_slice(&tha);
    b.extend_from_slice(&tpa);
    b
}

/// An IPv4 header's fields.
#[derive(Clone, Debug)]
pub struct V4 {
    pub src: [u8; 4],
    pub dst: [u8; 4],
    pub protocol: u8,
    pub ident: u16,
    pub flags: u16,
    pub ttl: u8,
    pub tos: u8,
    /// Options, a multiple of 4 bytes, at most 40.
    pub options: Vec<u8>,
}

impl V4 {
    pub fn new(src: [u8; 4], dst: [u8; 4], protocol: u8) -> V4 {
        V4 {
            src,
            dst,
            protocol,
            ident: 0x1234,
            flags: 0x4000,
            ttl: 64,
            tos: 0,
            options: Vec::new(),
        }
    }

    /// The packet, with its header checksum.
    pub fn packet(&self, payload: &[u8]) -> Vec<u8> {
        assert!(self.options.len() % 4 == 0 && self.options.len() <= 40);
        let hl = 20 + self.options.len();
        let mut p = vec![0u8; hl];
        p[0] = 0x40 | (hl / 4) as u8;
        p[1] = self.tos;
        put16(&mut p, 2, (hl + payload.len()) as u16);
        put16(&mut p, 4, self.ident);
        put16(&mut p, 6, self.flags);
        p[8] = self.ttl;
        p[9] = self.protocol;
        p[12..16].copy_from_slice(&self.src);
        p[16..20].copy_from_slice(&self.dst);
        p[20..].copy_from_slice(&self.options);
        let c = csum(&p);
        put16(&mut p, 10, c);
        p.extend_from_slice(payload);
        p
    }
}

/// A UDP datagram from `src`:`sport` to `dst`:`dport`, with its checksum
/// (0 sent as `0xFFFF`) or none.
pub fn udp(
    src: [u8; 4],
    dst: [u8; 4],
    sport: u16,
    dport: u16,
    payload: &[u8],
    checksum: bool,
) -> Vec<u8> {
    let len = 8 + payload.len();
    let mut d = vec![0u8; 8];
    put16(&mut d, 0, sport);
    put16(&mut d, 2, dport);
    put16(&mut d, 4, len as u16);
    d.extend_from_slice(payload);
    if checksum {
        let c = udp_checksum(src, dst, &d);
        put16(&mut d, 6, c);
    }
    d
}

/// The checksum of datagram `d` (its checksum field 0) from `src` to
/// `dst`, 0 given as `0xFFFF`.
pub fn udp_checksum(src: [u8; 4], dst: [u8; 4], d: &[u8]) -> u16 {
    let mut pseudo = Vec::with_capacity(12 + d.len());
    pseudo.extend_from_slice(&src);
    pseudo.extend_from_slice(&dst);
    pseudo.extend_from_slice(&[0, 17]);
    pseudo.extend_from_slice(&(d.len() as u16).to_be_bytes());
    pseudo.extend_from_slice(&d[..6]);
    pseudo.extend_from_slice(&[0, 0]);
    pseudo.extend_from_slice(&d[8..]);
    match csum(&pseudo) {
        0 => 0xFFFF,
        c => c,
    }
}

/// An ICMP echo message of type `kind`.
pub fn icmp_echo(kind: u8, ident: u16, seq: u16, data: &[u8]) -> Vec<u8> {
    let mut m = vec![kind, 0, 0, 0];
    m.extend_from_slice(&ident.to_be_bytes());
    m.extend_from_slice(&seq.to_be_bytes());
    m.extend_from_slice(data);
    let c = csum(&m);
    put16(&mut m, 2, c);
    m
}

/// `frame` padded with zeros to 60 bytes, as the stack sends it.
pub fn padded(mut frame: Vec<u8>) -> Vec<u8> {
    if frame.len() < 60 {
        frame.resize(60, 0);
    }
    frame
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(2 * bytes.len());
    for b in bytes {
        let _ = write!(s, "{b:02x}");
    }
    s
}

/// `bytes` split at `widths`, each group in hex, groups joined by spaces;
/// what the widths do not cover follows in groups of 4.
fn fields(bytes: &[u8], widths: &[usize]) -> String {
    let mut out = Vec::new();
    let mut at = 0;
    for &w in widths {
        if at + w > bytes.len() {
            break;
        }
        out.push(hex(&bytes[at..at + w]));
        at += w;
    }
    for c in bytes[at..].chunks(4) {
        out.push(hex(c));
    }
    out.join(" ")
}

fn ip4(b: &[u8]) -> String {
    format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3])
}

fn mac(b: &[u8]) -> String {
    let parts: Vec<String> = b[..6].iter().map(|x| format!("{x:02x}")).collect();
    parts.join(":")
}

/// A frame as the goldens write it: the Ethernet header on the first
/// line, then each header on a line of its own with its fields split,
/// then the payload 16 bytes a line, then any padding the same way; a
/// layer the frame cuts short goes 16 bytes a line. Lines but the first
/// start with five spaces.
pub fn layout(frame: &[u8]) -> Vec<String> {
    let mut lines = Vec::new();
    let rest = |bytes: &[u8], lines: &mut Vec<String>| {
        for c in bytes.chunks(16) {
            lines.push(fields(c, &[]));
        }
    };
    if frame.len() < 14 {
        rest(frame, &mut lines);
        if lines.is_empty() {
            lines.push(String::new());
        }
        return lines;
    }
    lines.push(fields(&frame[..14], &[6, 6, 2]));
    let body = &frame[14..];
    match get16(frame, 12) {
        0x0806 if body.len() >= 28 => {
            lines.push(fields(&body[..28], &[2, 2, 1, 1, 2, 6, 4, 6, 4]));
            rest(&body[28..], &mut lines);
        }
        0x0800 if body.len() >= 20 => {
            let hl = usize::from(body[0] & 0xF) * 4;
            let total = usize::from(get16(body, 2));
            if hl < 20 || hl > body.len() {
                rest(body, &mut lines);
                return lines;
            }
            lines.push(fields(&body[..hl], &[1, 1, 2, 2, 2, 1, 1, 2, 4, 4]));
            let end = total.clamp(hl, body.len());
            let l4 = &body[hl..end];
            let at = match body[9] {
                17 if l4.len() >= 8 => {
                    lines.push(fields(&l4[..8], &[2, 2, 2, 2]));
                    8
                }
                1 if l4.len() >= 8 => {
                    lines.push(fields(&l4[..8], &[1, 1, 2, 2, 2]));
                    8
                }
                _ => 0,
            };
            rest(&l4[at..], &mut lines);
            rest(&body[end..], &mut lines);
        }
        _ => rest(body, &mut lines),
    }
    lines
}

/// What a frame is, for the comment after its first line.
pub fn describe(frame: &[u8]) -> String {
    if frame.len() < 14 {
        return format!("{} bytes", frame.len());
    }
    let body = &frame[14..];
    let mut s = match get16(frame, 12) {
        0x0806 if body.len() >= 28 => match get16(body, 6) {
            1 => format!(
                "ARP request: who has {}? tell {}",
                ip4(&body[24..]),
                ip4(&body[14..])
            ),
            2 => format!(
                "ARP reply: {} is at {}, to {}",
                ip4(&body[14..]),
                mac(&body[8..]),
                ip4(&body[24..])
            ),
            op => format!("ARP op {op}"),
        },
        0x0800 if body.len() >= 20 => {
            let hl = usize::from(body[0] & 0xF) * 4;
            let total = usize::from(get16(body, 2));
            let mut s = format!(
                "{} > {}, id {}",
                ip4(&body[12..]),
                ip4(&body[16..]),
                get16(body, 4)
            );
            if hl >= 20 && hl <= total && total <= body.len() {
                let l4 = &body[hl..total];
                match body[9] {
                    1 if l4.len() >= 8 => {
                        let what = match (l4[0], l4[1]) {
                            (0, 0) => String::from("echo reply"),
                            (8, 0) => String::from("echo request"),
                            (t, c) => format!("type {t} code {c}"),
                        };
                        let _ = write!(
                            s,
                            ": ICMP {what}, id {:#06x} seq {}, {} bytes",
                            get16(l4, 4),
                            get16(l4, 6),
                            l4.len() - 8
                        );
                    }
                    17 if l4.len() >= 8 => {
                        let _ = write!(
                            s,
                            ": UDP {} > {}, {} bytes",
                            get16(l4, 0),
                            get16(l4, 2),
                            l4.len() - 8
                        );
                    }
                    p => {
                        let _ = write!(s, ": protocol {p}");
                    }
                }
            }
            s
        }
        t => format!("EtherType {t:#06x}"),
    };
    let _ = write!(s, "; {} bytes", frame.len());
    s
}

/// Reads a golden's hex: pairs of hex digits, spaces anywhere between
/// pairs.
pub fn unhex(text: &str) -> Result<Vec<u8>, String> {
    let digits: Vec<u8> = text.bytes().filter(|b| !b.is_ascii_whitespace()).collect();
    if digits.len() % 2 != 0 {
        return Err(format!("an odd number of hex digits in {text:?}"));
    }
    let mut out = Vec::with_capacity(digits.len() / 2);
    for p in digits.chunks(2) {
        let d = |c: u8| {
            (c as char)
                .to_digit(16)
                .ok_or_else(|| format!("{:?} is not a hex digit", c as char))
        };
        out.push((d(p[0])? << 4 | d(p[1])?) as u8);
    }
    Ok(out)
}
