//! The netvsc device: the host's half of NVSP and RNDIS on netvsc's
//! channel (`docs/design.md`, "The mock VMBus host"), plugged in with
//! `Host::attach(channel, Box::new(nic.clone()))`.
//!
//! It is written from FreeBSD's `hn(4)` (`sys/dev/hyperv/netvsc`:
//! `if_hnreg.h`, `hn_nvs.c`, `hn_nvs.h`, `hn_rndis.c`, `if_hn.c`) and
//! `sys/net/rndis.h`, read 2026-11-28, on its own: it shares no code with
//! `netvsc`, so that a layout mistake on either side shows. Linux's
//! `drivers/net/hyperv` (`hyperv_net.h`, `netvsc.c`) was read for facts
//! only: the receive section of 1,728 bytes (`NETVSC_RECV_SECTION_SIZE`),
//! the send section of 6,144 (`NETVSC_SEND_SECTION_SIZE`), one receive
//! section in RXBUF_CONNRESP, and the packet alignment of 8
//! (`RNDIS_PKT_ALIGN_DEFAULT`). What the host does that neither says is
//! from memory, and says so: the completion bodies' 40 bytes, the
//! completion of a GPA packet before its RNDIS answer, and the
//! receive-buffer packet's completion flag.
//!
//! | Mock | Behaviour |
//! | --- | --- |
//! | INIT | answered by [`Config::versions`]: INIT_RESP with status 1 for one of them, else 2 |
//! | NDIS_CONF, NDIS_INIT | recorded; NDIS_INIT must name the version FreeBSD pairs with the NVSP version taken |
//! | RXBUF_CONN, CHIM_CONN | the GPADL checked (this channel's, 1 MiB or 768 KiB, the signature); answered with [`Config`]'s statuses, receive sections and send section size |
//! | RNDIS control | GPA packets naming only the request page; INITIALIZE, QUERY of the MAC and the link, SET of the packet filter answered in a receive-buffer section, the GPA packet completed before the answer, or after it with [`Config::late_control_completion`] |
//! | sending | each data packet's section read from the send buffer, its RNDIS message checked, the frame kept; completed at once, or held until [`Netvsc::release`], in any order; a section reused before its completion fails the test |
//! | receiving | frames [`Netvsc::deliver`] queues go once the packet filter is set, each a PACKET_MSG in a section of [`Config::receive_section`] bytes, up to [`Config::frames_per_packet`] to a receive-buffer packet, with per-packet information if [`Config::pktinfo`]; a section is reused only after its packet's acknowledgement |
//! | signals | [`Chan::send`]'s rule, FreeBSD's: only when the inbound ring was empty; a packet that finds it full waits for the guest's next signal |
//! | hostility | [`Netvsc::inject`] any packet, [`Netvsc::inject_rndis`] any RNDIS messages in sections, [`Netvsc::inject_rxbuf`] a receive-buffer packet with any ranges |
//!
//! Whatever the guest does that a host would refuse is a fault
//! ([`Netvsc::faults`]): a test of an honest run asserts none, and none
//! left unacknowledged ([`Netvsc::unacked`]).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, VecDeque};
use std::rc::Rc;

use libsys::mem::Memory;

use crate::device::{Chan, Device, read_bytes};
use crate::machine::{self, PAGE};
use crate::ring::{FLAG_COMPLETION, Packet, kind};

/// NVSP's message types and constants (`if_hnreg.h`).
pub mod nvs {
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
    pub const VFASSOC_NOTE: u32 = 128;
    pub const TXTBL_NOTE: u32 = 134;
    pub const OK: u32 = 1;
    pub const FAILED: u32 = 2;
    pub const RXBUF_SIG: u16 = 0xCAFE;
    pub const CHIM_SIG: u16 = 0xFACE;
    pub const CHIM_NONE: u32 = 0xFFFF_FFFF;
    /// NVSP versions, as `HN_NVS_VERSION_*`.
    pub const V1: u32 = 0x0_0002;
    pub const V2: u32 = 0x3_0002;
    pub const V4: u32 = 0x4_0000;
    pub const V5: u32 = 0x5_0000;
    pub const V6: u32 = 0x6_0000;
    pub const V61: u32 = 0x6_0001;
}

/// RNDIS's message types, statuses and objects (`sys/net/rndis.h`).
pub mod rndis {
    pub const PACKET: u32 = 1;
    pub const INITIALIZE: u32 = 2;
    pub const QUERY: u32 = 4;
    pub const SET: u32 = 5;
    pub const INDICATE_STATUS: u32 = 7;
    pub const INITIALIZE_CMPLT: u32 = 0x8000_0002;
    pub const QUERY_CMPLT: u32 = 0x8000_0004;
    pub const SET_CMPLT: u32 = 0x8000_0005;
    pub const SUCCESS: u32 = 0;
    pub const FAILURE: u32 = 0xC000_0001;
    pub const NOT_SUPPORTED: u32 = 0xC000_00BB;
    pub const MEDIA_CONNECT: u32 = 0x4001_000B;
    pub const MEDIA_DISCONNECT: u32 = 0x4001_000C;
    pub const LINK_SPEED_CHANGE: u32 = 0x4001_0013;
    pub const OID_PERMANENT_ADDRESS: u32 = 0x0101_0101;
    pub const OID_MEDIA_CONNECT_STATUS: u32 = 0x0001_0114;
    pub const OID_PACKET_FILTER: u32 = 0x0001_010E;
    pub const FILTER_DIRECTED: u32 = 0x1;
    pub const FILTER_BROADCAST: u32 = 0x8;
}

/// The receive buffer's and the send buffer's sizes, as netvsc's channel
/// frame has them.
pub const RECEIVE_SIZE: usize = 256 * PAGE as usize;
pub const SEND_SIZE: usize = 192 * PAGE as usize;
/// The request page, by its number in the standard machine's channel
/// frame (page 32).
pub const REQUEST_PAGE: u64 = machine::CHANNEL / PAGE + 32;

/// The device's configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// The NVSP versions INIT takes.
    pub versions: Vec<u32>,
    /// RXBUF_CONNRESP's status, and its sections (`start`, slot size,
    /// slots, `end`), or `None` for the one section of
    /// [`Config::receive_section`] slots Linux expects.
    pub rxbuf_status: u32,
    pub rxbuf_sections: Option<Vec<[u32; 4]>>,
    /// CHIM_CONNRESP's status and send section size.
    pub chim_status: u32,
    pub section_size: u32,
    /// The receive buffer's section size, which the host carves it into.
    pub receive_section: usize,
    /// INITIALIZE_CMPLT's status and alignment shift (`rm_align`).
    pub init_status: u32,
    pub align: u32,
    /// The permanent MAC, and the length its query answers with.
    pub mac: [u8; 6],
    pub mac_len: u32,
    /// The query of the link: 0 connected, 1 disconnected.
    pub link: u32,
    /// SET's status.
    pub filter_status: u32,
    /// Frames to a receive-buffer packet, at most.
    pub frames_per_packet: usize,
    /// Per-packet information (checksum and hash value) before each
    /// received frame, as Hyper-V sends it from NVSP 5 (from memory).
    pub pktinfo: bool,
    /// Hold every send completion until [`Netvsc::release`].
    pub hold_completions: bool,
    /// Complete a GPA control packet after its RNDIS answer, not before.
    pub late_control_completion: bool,
    /// The only page a GPA packet may name, or `None` for any.
    pub request_page: Option<u64>,
    /// Rewrites each NVS answer (its request's type, its body) before it
    /// goes: a host that answers wrongly.
    pub tamper_nvs: Option<fn(u32, &mut Vec<u8>)>,
    /// Rewrites each RNDIS answer (its request's type, the message)
    /// before it goes in its section.
    pub tamper_rndis: Option<fn(u32, &mut Vec<u8>)>,
}

impl Default for Config {
    /// NVSP 5 only; one receive section of 1,728-byte slots; send sections
    /// of 6,144 bytes; RNDIS alignment 8; MAC `00:15:5d:4c:34:01`,
    /// connected; one frame a packet, no per-packet information;
    /// completions at once and before the answers; the standard machine's
    /// request page.
    fn default() -> Config {
        Config {
            versions: vec![nvs::V5],
            rxbuf_status: nvs::OK,
            rxbuf_sections: None,
            chim_status: nvs::OK,
            section_size: 6144,
            receive_section: 1728,
            init_status: rndis::SUCCESS,
            align: 3,
            mac: [0x00, 0x15, 0x5d, 0x4c, 0x34, 0x01],
            mac_len: 6,
            link: 0,
            filter_status: rndis::SUCCESS,
            frames_per_packet: 1,
            pktinfo: false,
            hold_completions: false,
            late_control_completion: false,
            request_page: Some(REQUEST_PAGE),
            tamper_nvs: None,
            tamper_rndis: None,
        }
    }
}

/// What the device has seen the guest do.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Seen {
    /// Every request, in order: `INIT 0x50000`, `NDIS_CONF 1514 0x8`,
    /// `NDIS_INIT 6.30`, `RXBUF_CONN`, `CHIM_CONN`, `RNDIS INITIALIZE`,
    /// `RNDIS QUERY 0x1010101`, `RNDIS SET 0x1010e 0x9`.
    pub requests: Vec<String>,
    /// The NVSP version taken, the NDIS version and the packet filter.
    pub nvsp: Option<u32>,
    pub ndis: Option<u32>,
    pub filter: u32,
    /// Data packets taken, completions sent, frames the guest sent.
    pub data: u64,
    pub completions: u64,
    /// Receive-buffer packets sent, and acknowledgements taken.
    pub rxbuf: u64,
    pub acks: u64,
    /// Frames the filter dropped.
    pub filtered: u64,
    /// GPA packets taken.
    pub gpa: u64,
    /// RNDIS answers' request IDs, in order.
    pub rids: Vec<u32>,
}

/// A packet for the guest.
#[derive(Clone, Debug)]
enum Out {
    /// Any packet: kind, flags, transaction ID, header extension, body.
    Packet {
        kind: u16,
        flags: u16,
        xid: u64,
        ext: Vec<u8>,
        body: Vec<u8>,
    },
    /// RNDIS messages, each in a receive section, in one receive-buffer
    /// packet; `control` for an answer (the body's channel type).
    Rx { msgs: Vec<Vec<u8>>, control: bool },
}

struct Inner {
    cfg: Config,
    seen: Seen,
    nvsp: Option<u32>,
    rxbuf: Option<u32>,
    chim: Option<(u32, u32)>,
    rndis_up: bool,
    out: VecDeque<Out>,
    /// The inbound ring was full: wait for the guest's signal.
    blocked: bool,
    /// The host reads nothing of the outbound ring, and remembers the
    /// guest's signals for when it does.
    paused: bool,
    missed: bool,
    frames: VecDeque<Vec<u8>>,
    free: BTreeSet<usize>,
    outstanding: BTreeMap<u64, Vec<usize>>,
    next_xid: u64,
    /// Send sections taken and not yet completed, with their xids.
    sending: BTreeMap<u32, u64>,
    held: Vec<u64>,
    sent: Vec<Vec<u8>>,
    faults: Vec<String>,
}

/// The netvsc device, a handle: clones share it, so a test keeps one and
/// gives the host another.
#[derive(Clone)]
pub struct Netvsc(Rc<RefCell<Inner>>);

fn u16_at(b: &[u8], at: usize) -> Option<u16> {
    Some(u16::from_le_bytes(b.get(at..at + 2)?.try_into().ok()?))
}

fn u32_at(b: &[u8], at: usize) -> Option<u32> {
    Some(u32::from_le_bytes(b.get(at..at + 4)?.try_into().ok()?))
}

fn u64_at(b: &[u8], at: usize) -> Option<u64> {
    Some(u64::from_le_bytes(b.get(at..at + 8)?.try_into().ok()?))
}

/// Little-endian u32s as bytes.
pub fn words(w: &[u32]) -> Vec<u8> {
    w.iter().flat_map(|v| v.to_le_bytes()).collect()
}

/// An NVS message: its words, padded to 40 bytes.
fn nvs_message(w: &[u32]) -> Vec<u8> {
    let mut v = words(w);
    v.resize(v.len().max(40), 0);
    v
}

/// RNDIS_ACK with `status`, as a completion carries it.
pub fn rndis_ack(status: u32) -> Vec<u8> {
    nvs_message(&[nvs::RNDIS_ACK, status])
}

/// A PACKET_MSG carrying `frame`, with per-packet information (a checksum
/// element and a hash value, 16 bytes each) before it if `pktinfo`.
pub fn packet_msg(frame: &[u8], pktinfo: bool) -> Vec<u8> {
    let pi: Vec<u8> = if pktinfo {
        // rndis_pktinfo: size, type (0 checksum, 8 hash value), offset 12,
        // then 4 bytes of data.
        [words(&[16, 0, 12, 0]), words(&[16, 8, 12, 0x1234_5678])].concat()
    } else {
        Vec::new()
    };
    let data_off = 36 + pi.len() as u32;
    let len = 44 + pi.len() + frame.len();
    let (pi_off, pi_len) = if pktinfo {
        (36, pi.len() as u32)
    } else {
        (0, 0)
    };
    let mut m = words(&[
        rndis::PACKET,
        len as u32,
        data_off,
        frame.len() as u32,
        0,
        0,
        0,
        pi_off,
        pi_len,
        0,
        0,
    ]);
    m.extend_from_slice(&pi);
    m.extend_from_slice(frame);
    m
}

/// INDICATE_STATUS of `status`, with no status buffer.
pub fn status_msg(status: u32) -> Vec<u8> {
    words(&[rndis::INDICATE_STATUS, 20, status, 0, 0])
}

impl Netvsc {
    pub fn new(cfg: Config) -> Netvsc {
        let slots = RECEIVE_SIZE / cfg.receive_section;
        Netvsc(Rc::new(RefCell::new(Inner {
            cfg,
            seen: Seen::default(),
            nvsp: None,
            rxbuf: None,
            chim: None,
            rndis_up: false,
            out: VecDeque::new(),
            blocked: false,
            paused: false,
            missed: false,
            frames: VecDeque::new(),
            free: (0..slots).collect(),
            outstanding: BTreeMap::new(),
            next_xid: 0x10_0000,
            sending: BTreeMap::new(),
            held: Vec::new(),
            sent: Vec::new(),
            faults: Vec::new(),
        })))
    }

    pub fn config(&self) -> Config {
        self.0.borrow().cfg.clone()
    }

    /// Changes the configuration, for what the host does from now on.
    pub fn configure(&self, f: impl FnOnce(&mut Config)) {
        f(&mut self.0.borrow_mut().cfg);
    }

    pub fn seen(&self) -> Seen {
        self.0.borrow().seen.clone()
    }

    /// Queues a frame from the network for the guest; it goes once the
    /// packet filter is set, if the filter takes it.
    pub fn deliver(&self, frame: &[u8]) {
        self.0.borrow_mut().frames.push_back(frame.to_vec());
    }

    /// Frames queued and not yet put in a section.
    pub fn waiting(&self) -> usize {
        self.0.borrow().frames.len()
    }

    /// Queues an RNDIS status indication.
    pub fn indicate(&self, status: u32) {
        self.0.borrow_mut().out.push_back(Out::Rx {
            msgs: vec![status_msg(status)],
            control: false,
        });
    }

    /// Queues any packet for the guest.
    pub fn inject(&self, kind: u16, flags: u16, xid: u64, ext: &[u8], body: &[u8]) {
        self.0.borrow_mut().out.push_back(Out::Packet {
            kind,
            flags,
            xid,
            ext: ext.to_vec(),
            body: body.to_vec(),
        });
    }

    /// Queues RNDIS messages, whatever they hold, each in a receive
    /// section, in one receive-buffer packet that must be acknowledged.
    pub fn inject_rndis(&self, msgs: &[&[u8]]) {
        self.0.borrow_mut().out.push_back(Out::Rx {
            msgs: msgs.iter().map(|m| m.to_vec()).collect(),
            control: false,
        });
    }

    /// Queues a receive-buffer packet with ID `id`, `ranges` (length,
    /// offset) whatever they name and `body`; it must be acknowledged.
    /// Returns its transaction ID.
    pub fn inject_rxbuf(&self, id: u16, ranges: &[(u32, u32)], body: &[u8]) -> u64 {
        let mut i = self.0.borrow_mut();
        let xid = i.next_xid;
        i.next_xid += 1;
        let mut ext = Vec::new();
        ext.extend_from_slice(&id.to_le_bytes());
        ext.extend_from_slice(&0u16.to_le_bytes());
        ext.extend_from_slice(&(ranges.len() as u32).to_le_bytes());
        for &(len, ofs) in ranges {
            ext.extend_from_slice(&len.to_le_bytes());
            ext.extend_from_slice(&ofs.to_le_bytes());
        }
        i.outstanding.insert(xid, Vec::new());
        i.out.push_back(Out::Packet {
            kind: kind::RXBUF,
            flags: FLAG_COMPLETION,
            xid,
            ext,
            body: body.to_vec(),
        });
        xid
    }

    /// The send completions held back, in the order they would go.
    pub fn held(&self) -> Vec<u64> {
        self.0.borrow().held.clone()
    }

    /// Sends the held completions, in the order `order` leaves them.
    pub fn release(&self, order: impl FnOnce(&mut Vec<u64>)) {
        let mut i = self.0.borrow_mut();
        let mut held = std::mem::take(&mut i.held);
        order(&mut held);
        for xid in held {
            i.complete_send(xid);
        }
    }

    /// The frames the guest sent, oldest first, taken.
    pub fn take_sent(&self) -> Vec<Vec<u8>> {
        std::mem::take(&mut self.0.borrow_mut().sent)
    }

    /// What the guest did that a host would refuse.
    pub fn faults(&self) -> Vec<String> {
        self.0.borrow().faults.clone()
    }

    /// Receive-buffer packets sent and not acknowledged.
    pub fn unacked(&self) -> usize {
        self.0.borrow().outstanding.len()
    }

    /// Receive sections free.
    pub fn free_sections(&self) -> usize {
        self.0.borrow().free.len()
    }

    /// A host slow to read: from now on it reads nothing of the outbound
    /// ring, so the guest's packets pile up there, until
    /// [`Netvsc::resume_reading`].
    pub fn pause_reading(&self) {
        self.0.borrow_mut().paused = true;
    }

    /// Reads again, at the host's next turn, what the guest signalled
    /// meanwhile.
    pub fn resume_reading(&self) {
        self.0.borrow_mut().paused = false;
    }
}

impl Device for Netvsc {
    fn signalled(&mut self, ch: &Chan<'_>) {
        self.0.borrow_mut().signalled(ch);
    }

    fn poll(&mut self, ch: &Chan<'_>) -> bool {
        self.0.borrow_mut().poll(ch)
    }
}

impl Inner {
    fn fault(&mut self, what: String) {
        self.faults.push(what);
    }

    fn queue(&mut self, kind: u16, flags: u16, xid: u64, body: Vec<u8>) {
        self.out.push_back(Out::Packet {
            kind,
            flags,
            xid,
            ext: Vec::new(),
            body,
        });
    }

    fn complete(&mut self, xid: u64, body: Vec<u8>) {
        self.queue(kind::COMP, 0, xid, body);
    }

    /// An NVS request's answer, as the configuration may rewrite it.
    fn answer(&mut self, request: u32, xid: u64, mut body: Vec<u8>) {
        if let Some(t) = self.cfg.tamper_nvs {
            t(request, &mut body);
        }
        self.complete(xid, body);
    }

    fn complete_send(&mut self, xid: u64) {
        self.sending.retain(|_, x| *x != xid);
        self.seen.completions += 1;
        self.complete(xid, rndis_ack(nvs::OK));
    }

    fn signalled(&mut self, ch: &Chan<'_>) {
        self.blocked = false;
        if self.paused {
            self.missed = true;
            return;
        }
        loop {
            match ch.recv() {
                Ok(Some(p)) => self.packet(ch, &p),
                Ok(None) => break,
                Err(e) => {
                    self.fault(format!("netvsc's outbound ring broken: {e:?}"));
                    break;
                }
            }
        }
    }

    fn packet(&mut self, ch: &Chan<'_>, p: &Packet) {
        match p.kind {
            kind::INBAND => self.nvs(ch, p),
            kind::GPA => self.gpa(ch, p),
            kind::COMP => self.ack(p),
            k => self.fault(format!("a packet of type {k} from the guest")),
        }
    }

    /// An acknowledgement of a receive-buffer packet.
    fn ack(&mut self, p: &Packet) {
        let b = p.body();
        if u32_at(b, 0) != Some(nvs::RNDIS_ACK) || u32_at(b, 4) != Some(nvs::OK) {
            self.fault(format!("an acknowledgement {:02x?}", &b[..b.len().min(8)]));
        }
        match self.outstanding.remove(&p.xid) {
            Some(sections) => {
                self.seen.acks += 1;
                self.free.extend(sections);
            }
            None => self.fault(format!(
                "an acknowledgement of {:#x}, which is not outstanding",
                p.xid
            )),
        }
    }

    fn nvs(&mut self, ch: &Chan<'_>, p: &Packet) {
        let b = p.body();
        let Some(t) = u32_at(b, 0) else {
            self.fault("an empty NVS message".into());
            return;
        };
        if b.len() < 32 {
            // HN_NVS_REQSIZE_MIN: "Hypervisor would never reply".
            self.fault(format!("an NVS message of {} bytes", b.len()));
            return;
        }
        let rc = p.flags & FLAG_COMPLETION != 0;
        let field = |at| u32_at(b, at).expect("32 bytes");
        match t {
            nvs::INIT => {
                let (min, max) = (field(4), field(8));
                self.seen.requests.push(format!("INIT {min:#x}"));
                if min != max || !rc || self.nvsp.is_some() {
                    self.fault(format!("INIT {min:#x} to {max:#x}, completion {rc}"));
                }
                let ok = self.cfg.versions.contains(&min);
                if ok {
                    self.nvsp = Some(min);
                    self.seen.nvsp = Some(min);
                }
                let status = if ok { nvs::OK } else { nvs::FAILED };
                self.answer(t, p.xid, nvs_message(&[nvs::INIT_RESP, 0, 0, status]));
            }
            nvs::NDIS_CONF => {
                let mtu = field(4);
                let caps = u64_at(b, 12).expect("32 bytes");
                self.seen
                    .requests
                    .push(format!("NDIS_CONF {mtu} {caps:#x}"));
                if self.nvsp.is_none() || rc {
                    self.fault("NDIS_CONF before INIT, or asking a completion".into());
                }
            }
            nvs::NDIS_INIT => {
                let (major, minor) = (field(4), field(8));
                self.seen
                    .requests
                    .push(format!("NDIS_INIT {major}.{minor}"));
                let v = major << 16 | minor;
                self.seen.ndis = Some(v);
                // FreeBSD's pairing: 6.30 from NVSP 5, else 6.1.
                let want = match self.nvsp {
                    Some(n) if n >= nvs::V5 => Some(0x0006_001E),
                    Some(_) => Some(0x0006_0001),
                    None => None,
                };
                if want != Some(v) || rc {
                    self.fault(format!(
                        "NDIS_INIT {major}.{minor} with NVSP {:?}",
                        self.nvsp
                    ));
                }
            }
            nvs::RXBUF_CONN => {
                let (gpadl, sig) = (field(4), u16_at(b, 8).expect("32 bytes"));
                self.seen.requests.push("RXBUF_CONN".into());
                let size = ch.gpadl(gpadl).map(|v| v.len());
                let mut status = self.cfg.rxbuf_status;
                if size != Some(RECEIVE_SIZE) || sig != nvs::RXBUF_SIG || !rc {
                    self.fault(format!(
                        "RXBUF_CONN of GPADL {gpadl:#x} ({size:?} bytes), signature {sig:#x}"
                    ));
                    status = nvs::FAILED;
                }
                if status == nvs::OK {
                    self.rxbuf = Some(gpadl);
                }
                let slots = (RECEIVE_SIZE / self.cfg.receive_section) as u32;
                let rs = self.cfg.receive_section as u32;
                let sections = self
                    .cfg
                    .rxbuf_sections
                    .clone()
                    .unwrap_or_else(|| vec![[0, rs, slots, rs * slots]]);
                let mut w = vec![nvs::RXBUF_CONNRESP, status, sections.len() as u32];
                for s in &sections {
                    w.extend_from_slice(s);
                }
                self.answer(t, p.xid, nvs_message(&w));
            }
            nvs::CHIM_CONN => {
                let (gpadl, sig) = (field(4), u16_at(b, 8).expect("32 bytes"));
                self.seen.requests.push("CHIM_CONN".into());
                let size = ch.gpadl(gpadl).map(|v| v.len());
                let mut status = self.cfg.chim_status;
                if size != Some(SEND_SIZE) || sig != nvs::CHIM_SIG || !rc {
                    self.fault(format!(
                        "CHIM_CONN of GPADL {gpadl:#x} ({size:?} bytes), signature {sig:#x}"
                    ));
                    status = nvs::FAILED;
                }
                let s = self.cfg.section_size;
                if status == nvs::OK && s != 0 {
                    self.chim = Some((gpadl, (SEND_SIZE as u32) / s));
                }
                self.answer(t, p.xid, nvs_message(&[nvs::CHIM_CONNRESP, status, s]));
            }
            nvs::RNDIS => self.data(ch, p),
            t => self.fault(format!("an NVS message of type {t}")),
        }
    }

    /// A data packet: the RNDIS message in its send section.
    fn data(&mut self, ch: &Chan<'_>, p: &Packet) {
        let b = p.body();
        let field = |at| u32_at(b, at).expect("32 bytes");
        let (mtype, idx, size) = (field(4), field(8), field(12));
        if mtype != 0 || p.flags & FLAG_COMPLETION == 0 {
            self.fault(format!(
                "an RNDIS packet of channel type {mtype}, flags {}",
                p.flags
            ));
            return;
        }
        let Some((gpadl, sections)) = self.chim else {
            self.fault("a data packet before CHIM_CONN".into());
            return;
        };
        if idx >= sections || size > self.cfg.section_size {
            self.fault(format!("a data packet in section {idx}, {size} bytes"));
            return;
        }
        if let Some(x) = self.sending.insert(idx, p.xid) {
            self.fault(format!(
                "section {idx} sent again ({:#x}) before its completion ({x:#x})",
                p.xid
            ));
        }
        let view = ch.gpadl(gpadl).expect("the send buffer's GPADL");
        let m = read_bytes(&view, (idx * self.cfg.section_size) as usize, size as usize);
        let w = |at| u32_at(&m, at).unwrap_or(0);
        let (t, len, data_off, data_len) = (w(0), w(4), w(8), w(12));
        let (oob_len, pi_len) = (w(20), w(32));
        let at = 8 + data_off as usize;
        let ok = m.len() >= 44
            && t == rndis::PACKET
            && len == size
            && data_off >= 36
            && oob_len == 0
            && pi_len == 0
            && (14..=1514).contains(&data_len)
            && at + data_len as usize <= m.len();
        if !ok {
            self.fault(format!(
                "a data packet's RNDIS message: type {t:#x}, length {len} of {size}, data {data_len} at {data_off}, oob {oob_len}, pktinfo {pi_len}"
            ));
            return;
        }
        self.sent.push(m[at..at + data_len as usize].to_vec());
        self.seen.data += 1;
        if self.cfg.hold_completions {
            self.held.push(p.xid);
        } else {
            self.complete_send(p.xid);
        }
    }

    /// A GPA packet: an RNDIS control message in the page it names.
    fn gpa(&mut self, ch: &Chan<'_>, p: &Packet) {
        self.seen.gpa += 1;
        let h = &p.bytes[..p.header_len];
        let count = u32_at(h, 20).unwrap_or(0);
        let b = p.body();
        let nvs_ok = u32_at(b, 0) == Some(nvs::RNDIS)
            && u32_at(b, 4) == Some(1)
            && u32_at(b, 8) == Some(nvs::CHIM_NONE)
            && u32_at(b, 12) == Some(0)
            && b.len() >= 32;
        if count != 1 || h.len() < 40 || p.flags & FLAG_COMPLETION == 0 || !nvs_ok {
            self.fault(format!(
                "a GPA packet of {count} ranges, a {}-byte header, flags {}, body {:02x?}",
                h.len(),
                p.flags,
                &b[..b.len().min(16)]
            ));
            return;
        }
        let (len, ofs, page) = (
            u32_at(h, 24).expect("40 bytes"),
            u32_at(h, 28).expect("40 bytes"),
            u64_at(h, 32).expect("40 bytes"),
        );
        if self.cfg.request_page.is_some_and(|r| r != page)
            || page >= machine::RAM / PAGE
            || u64::from(ofs) + u64::from(len) > PAGE
            || len < 12
        {
            self.fault(format!(
                "a GPA packet naming {len} bytes at {ofs} of page {page:#x}"
            ));
            return;
        }
        let m = read_bytes(
            ch.machine().ram(),
            (page * PAGE) as usize + ofs as usize,
            len as usize,
        );
        let w = |at| u32_at(&m, at).unwrap_or(0);
        let (t, mlen, rid) = (w(0), w(4), w(8));
        if mlen != len {
            self.fault(format!(
                "an RNDIS request of {mlen} bytes in a range of {len}"
            ));
        }
        let mut answer = match t {
            rndis::INITIALIZE => {
                self.seen.requests.push("RNDIS INITIALIZE".into());
                if (w(12), w(16)) != (1, 0) || self.rndis_up {
                    self.fault(format!("RNDIS INITIALIZE {}.{}", w(12), w(16)));
                }
                self.rndis_up = true;
                words(&[
                    rndis::INITIALIZE_CMPLT,
                    52,
                    rid,
                    self.cfg.init_status,
                    1,
                    0,
                    1,
                    0,
                    8,
                    4096,
                    self.cfg.align,
                    0,
                    0,
                ])
            }
            rndis::QUERY => {
                let (oid, inlen, inoff) = (w(12), w(16), w(20));
                self.seen.requests.push(format!("RNDIS QUERY {oid:#x}"));
                if !self.rndis_up || inlen != 0 {
                    self.fault(format!("RNDIS QUERY {oid:#x} with {inlen} bytes"));
                }
                let data: Option<Vec<u8>> = match oid {
                    rndis::OID_PERMANENT_ADDRESS => {
                        let mut mac = self.cfg.mac.to_vec();
                        mac.resize(self.cfg.mac_len as usize, 0);
                        Some(mac)
                    }
                    rndis::OID_MEDIA_CONNECT_STATUS => Some(self.cfg.link.to_le_bytes().to_vec()),
                    _ => None,
                };
                // Hyper-V answers a query whose information buffer offset
                // is 0 with a failure (FreeBSD's note in hn_rndis_query2).
                let (status, data) = match data {
                    _ if inoff == 0 => (rndis::FAILURE, Vec::new()),
                    Some(d) => (rndis::SUCCESS, d),
                    None => (rndis::NOT_SUPPORTED, Vec::new()),
                };
                let off = if data.is_empty() { 0 } else { 16 };
                let mut a = words(&[
                    rndis::QUERY_CMPLT,
                    24 + data.len() as u32,
                    rid,
                    status,
                    data.len() as u32,
                    off,
                ]);
                a.extend_from_slice(&data);
                a
            }
            rndis::SET => {
                let (oid, inlen, inoff) = (w(12), w(16), w(20));
                let value = u32_at(&m, 8 + inoff as usize);
                self.seen
                    .requests
                    .push(format!("RNDIS SET {oid:#x} {:#x}", value.unwrap_or(0)));
                let status = if oid == rndis::OID_PACKET_FILTER && inlen == 4 && value.is_some() {
                    if self.cfg.filter_status == rndis::SUCCESS {
                        self.seen.filter = value.expect("checked");
                    }
                    self.cfg.filter_status
                } else {
                    self.fault(format!("RNDIS SET {oid:#x} of {inlen} bytes at {inoff}"));
                    rndis::NOT_SUPPORTED
                };
                if !self.rndis_up {
                    self.fault("RNDIS SET before INITIALIZE".into());
                }
                words(&[rndis::SET_CMPLT, 16, rid, status])
            }
            t => {
                self.fault(format!("an RNDIS request of type {t:#x}"));
                return;
            }
        };
        self.seen.rids.push(rid);
        if let Some(f) = self.cfg.tamper_rndis {
            f(t, &mut answer);
        }
        let rx = Out::Rx {
            msgs: vec![answer],
            control: true,
        };
        let comp = Out::Packet {
            kind: kind::COMP,
            flags: 0,
            xid: p.xid,
            ext: Vec::new(),
            body: rndis_ack(nvs::OK),
        };
        if self.cfg.late_control_completion {
            self.out.push_back(rx);
            self.out.push_back(comp);
        } else {
            self.out.push_back(comp);
            self.out.push_back(rx);
        }
    }

    /// Whether the packet filter takes a frame: directed to the MAC, or
    /// broadcast.
    fn takes(&self, frame: &[u8]) -> bool {
        let f = self.seen.filter;
        let dst = &frame[..6.min(frame.len())];
        (f & rndis::FILTER_DIRECTED != 0 && dst == self.cfg.mac)
            || (f & rndis::FILTER_BROADCAST != 0 && dst == [0xFF; 6])
    }

    /// The host's turn: frames go once the filter is set, then whatever
    /// waits, in order, until the inbound ring is full.
    fn poll(&mut self, ch: &Chan<'_>) -> bool {
        let mut did = false;
        if !self.paused && std::mem::take(&mut self.missed) {
            self.signalled(ch);
            did = true;
        }
        if self.blocked {
            return did;
        }
        if self.seen.filter != 0 && self.rxbuf.is_some() {
            while !self.frames.is_empty() {
                let mut msgs = Vec::new();
                while msgs.len() < self.cfg.frames_per_packet.max(1) {
                    let Some(f) = self.frames.pop_front() else {
                        break;
                    };
                    if self.takes(&f) {
                        msgs.push(packet_msg(&f, self.cfg.pktinfo));
                    } else {
                        self.seen.filtered += 1;
                    }
                }
                if !msgs.is_empty() {
                    self.out.push_back(Out::Rx {
                        msgs,
                        control: false,
                    });
                }
            }
        }
        while let Some(o) = self.out.pop_front() {
            if !self.send(ch, &o) {
                self.out.push_front(o);
                break;
            }
            did = true;
        }
        did
    }

    /// Sends one packet; false if it must wait.
    fn send(&mut self, ch: &Chan<'_>, o: &Out) -> bool {
        match o {
            Out::Packet {
                kind,
                flags,
                xid,
                ext,
                body,
            } => {
                if ch.send_ext(*kind, *flags, *xid, ext, body).is_err() {
                    self.blocked = true;
                    return false;
                }
                true
            }
            Out::Rx { msgs, control } => {
                let Some(gpadl) = self.rxbuf else {
                    // No receive buffer: nothing to put it in.
                    return true;
                };
                if self.free.len() < msgs.len() {
                    return false;
                }
                let sections: Vec<usize> = self.free.iter().copied().take(msgs.len()).collect();
                let view = ch.gpadl(gpadl).expect("the receive buffer's GPADL");
                let size = self.cfg.receive_section;
                let mut ext = Vec::new();
                ext.extend_from_slice(&nvs::RXBUF_SIG.to_le_bytes());
                ext.extend_from_slice(&0u16.to_le_bytes());
                ext.extend_from_slice(&(msgs.len() as u32).to_le_bytes());
                for (m, &s) in msgs.iter().zip(&sections) {
                    assert!(
                        m.len() <= size,
                        "hvmock: an RNDIS message of {} bytes",
                        m.len()
                    );
                    view.write(s * size, m);
                    ext.extend_from_slice(&(m.len() as u32).to_le_bytes());
                    ext.extend_from_slice(&((s * size) as u32).to_le_bytes());
                }
                let mtype = u32::from(*control);
                let body = nvs_message(&[nvs::RNDIS, mtype, nvs::CHIM_NONE, 0]);
                let xid = self.next_xid;
                if ch
                    .send_ext(kind::RXBUF, FLAG_COMPLETION, xid, &ext, &body)
                    .is_err()
                {
                    self.blocked = true;
                    return false;
                }
                self.next_xid += 1;
                for s in &sections {
                    self.free.remove(s);
                }
                self.outstanding.insert(xid, sections);
                self.seen.rxbuf += 1;
                true
            }
        }
    }
}
