//! [`Adapter`]: netvsc's setup and its copies, a state machine driven by
//! the signals on its notification (`docs/design.md`, "NVSP and RNDIS
//! setup", "Sending", "Receiving", "The loop").
//!
//! **Setup.** Each request waits for its answer before the next: NVSP INIT
//! with 5, then 4, then 2; NDIS_CONF and NDIS_INIT, which have none; the
//! receive buffer and the send buffer; RNDIS INITIALIZE, the permanent
//! MAC and the link. Then netvsc writes the frame queues' link block,
//! hands `net` the transmit buffers and signals it; at `net`'s first
//! signal, once its receive buffers are in `RX_FREE`, it sets the packet
//! filter, so that no frame the host sends finds no buffer. A host that
//! refuses a step is a [`Failure`], which [`crate::run`] turns into a
//! panic with the reason.
//!
//! **Receiving.** Every receive-buffer packet's ranges are read as RNDIS
//! messages in the receive buffer, each checked, its frame copied into a
//! buffer from `RX_FREE`; then the packet is acknowledged, whatever its
//! ranges held, so the host never loses a section. An acknowledgement
//! that finds the outbound ring full waits, in order, in a queue of
//! [`ACKS`], ahead of any frame; while the queue is full netvsc reads no
//! more of the inbound ring.
//!
//! **Sending.** Each frame in `TX_FILLED` goes into a free send section,
//! behind its RNDIS header, and an inband packet names the section; the
//! queue's buffer goes back at once and the section comes back with its
//! completion. With no free section or no room in the outbound ring the
//! frame waits in `TX_FILLED`: netvsc never drops a frame to send.
//!
//! **Signalling.** After every packet it writes, if the host's interrupt
//! mask on the outbound ring is 0, netvsc signals the host:
//! `SignalEvent` on its connection, or with `netvsc.mnf=1` FreeBSD's
//! `vmbus_chan_signal` (the channel's bit in the event-flags page's
//! guest-to-host half, then its monitor trigger if the offer has one,
//! else `SignalEvent`). After a batch of the inbound ring it signals the
//! host if the host waits for room that it now has.

use core::fmt;
use core::sync::atomic::Ordering::SeqCst;

use libsys::frames::{Driver, Link, Mac, PushError};
use libsys::mem::{self, Memory, Part};
use libsys::proto::{NdisVersion, NetvscStats, NvspVersion, VmbusAttach};

use crate::ring::{self, FLAG_COMPLETION, Header, Inbound, MAX_PACKET, Outbound, Read, kind, xid};
use crate::{FRAMES, Signal, Start, Status, layout, nvs, rndis};

/// Acknowledgements that may wait for room in the outbound ring.
pub const ACKS: usize = 64;
/// Lines that may wait to be printed; more in one signal are dropped.
const NOTES: usize = 8;
/// The bytes a data packet takes in the outbound ring: its header, its
/// 40-byte NVS RNDIS message and the trailer.
const DATA_PACKET: usize = ring::HEADER + nvs::MESSAGE + ring::TRAILER;

/// A step of the setup, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// NVSP INIT with `nvs::VERSIONS[i]`.
    Init(u8),
    /// NDIS_CONF: the MTU and VLAN; no answer.
    NdisConf,
    /// NDIS_INIT: the NDIS version; no answer.
    NdisInit,
    /// RXBUF_CONN.
    ReceiveBuffer,
    /// CHIM_CONN.
    SendBuffer,
    /// RNDIS INITIALIZE.
    Initialize,
    /// RNDIS QUERY of the permanent MAC.
    Mac,
    /// RNDIS QUERY of the link.
    Link,
    /// The link block is written: waiting for `net`'s receive buffers.
    Net,
    /// RNDIS SET of the packet filter.
    Filter,
    /// Set up.
    Up,
}

impl Step {
    /// The transaction ID of the step's request: NVS requests 1 to 5,
    /// RNDIS control packets their request IDs, below 2^32 and apart from
    /// data packets' ([`ring::xid`]).
    const fn xid(self) -> u64 {
        match self {
            Step::Init(i) => 1 + i as u64,
            Step::ReceiveBuffer => 4,
            Step::SendBuffer => 5,
            Step::Initialize | Step::Mac | Step::Link | Step::Filter => {
                rndis::request_id(self.rndis_number()) as u64
            }
            Step::NdisConf | Step::NdisInit | Step::Net | Step::Up => 0,
        }
    }

    /// An RNDIS step's request number, 1 to 4.
    const fn rndis_number(self) -> u32 {
        match self {
            Step::Initialize => 1,
            Step::Mac => 2,
            Step::Link => 3,
            Step::Filter => 4,
            _ => 0,
        }
    }

    const fn what(self) -> &'static str {
        match self {
            Step::Init(_) => "NVSP INIT",
            Step::NdisConf => "NDIS_CONF",
            Step::NdisInit => "NDIS_INIT",
            Step::ReceiveBuffer => "the receive buffer",
            Step::SendBuffer => "the send buffer",
            Step::Initialize => "RNDIS INITIALIZE",
            Step::Mac => "the MAC query",
            Step::Link => "the link query",
            Step::Net => "net's buffers",
            Step::Filter => "the packet filter",
            Step::Up => "nothing",
        }
    }
}

/// Why the host's answer to a step was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Why {
    /// An NVS answer's length, type, status or sections.
    Nvs(nvs::Bad),
    /// An RNDIS answer's length, status or information buffer.
    Rndis(rndis::Bad),
    /// An RNDIS answer with the request's ID but another type.
    Kind(u32),
    /// A MAC that is 0 or a group address.
    Mac(Mac),
}

/// Why netvsc cannot go on: [`crate::run`] panics with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// The host took none of NVSP 5, 4 and 2.
    NoVersion,
    /// The host refused a step.
    Refused(Step, Why),
    /// `SignalEvent` failed: the hypervisor's status.
    Signal { connection: u32, status: Status },
    /// With `netvsc.mnf=1`, an offer's monitor trigger past monitor page
    /// 2's 128, which FreeBSD refuses too.
    Trigger(u8),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Failure::NoVersion => f.write_str("netvsc: the host accepts none of NVSP 5, 4, 2"),
            Failure::Refused(step, Why::Nvs(b)) => {
                write!(f, "netvsc: the host refused {}: {b}", step.what())
            }
            Failure::Refused(step, Why::Rndis(b)) => {
                write!(f, "netvsc: the host refused {}: {b}", step.what())
            }
            Failure::Refused(step, Why::Kind(k)) => write!(
                f,
                "netvsc: the host answered {} with RNDIS message {k:#010x}",
                step.what()
            ),
            Failure::Refused(_, Why::Mac(m)) => {
                write!(f, "netvsc: the host's MAC {m} is not unicast")
            }
            Failure::Signal { connection, status } => {
                write!(
                    f,
                    "netvsc: SignalEvent on connection {connection}: {status}"
                )
            }
            Failure::Trigger(t) => write!(
                f,
                "netvsc: monitor trigger {t} is past monitor page 2's 128"
            ),
        }
    }
}

/// Which ring.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Ring {
    Outbound,
    Inbound,
}

/// A line netvsc prints, through console on the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// `netvsc: up: NVSP 5, NDIS 6.30, MAC 00:15:5d:00:00:01, link up, 128
    /// send sections of 6144 bytes`: the link block is written.
    Up {
        nvsp: u32,
        ndis: u32,
        mac: Mac,
        link: bool,
        sections: u32,
        size: u32,
    },
    /// `netvsc: link up` or `netvsc: link down`: an RNDIS status
    /// indication changed the link once netvsc was up.
    Link(bool),
    /// A ring is broken and no longer used.
    Broken(Ring, ring::Broken),
}

const fn up_down(up: bool) -> &'static str {
    if up { "up" } else { "down" }
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Note::Up {
                nvsp,
                ndis,
                mac,
                link,
                sections,
                size,
            } => write!(
                f,
                "netvsc: up: NVSP {}, NDIS {}, MAC {mac}, link {}, {sections} send sections of {size} bytes",
                NvspVersion(nvsp),
                NdisVersion(ndis),
                up_down(link)
            ),
            Note::Link(up) => write!(f, "netvsc: link {}", up_down(up)),
            Note::Broken(Ring::Inbound, b) => write!(
                f,
                "netvsc: the inbound ring is broken ({b}); it is no longer read"
            ),
            Note::Broken(Ring::Outbound, b) => write!(
                f,
                "netvsc: the outbound ring is broken ({b}); it is no longer written"
            ),
        }
    }
}

/// The receive-buffer packets' transaction IDs waiting to be
/// acknowledged, in order.
#[derive(Clone, Copy, Debug)]
struct Acks {
    xids: [u64; ACKS],
    head: usize,
    len: usize,
}

impl Acks {
    const fn new() -> Acks {
        Acks {
            xids: [0; ACKS],
            head: 0,
            len: 0,
        }
    }

    const fn is_full(&self) -> bool {
        self.len == ACKS
    }

    fn push(&mut self, xid: u64) {
        assert!(!self.is_full(), "netvsc: an acknowledgement past the queue");
        self.xids[(self.head + self.len) % ACKS] = xid;
        self.len += 1;
    }

    fn front(&self) -> Option<u64> {
        (self.len != 0).then(|| self.xids[self.head])
    }

    fn pop(&mut self) {
        self.head = (self.head + 1) % ACKS;
        self.len -= 1;
    }
}

/// netvsc's windows onto the channel frame.
struct Frame<'a, M> {
    channel: &'a M,
    mnf: Option<&'a M>,
}

impl<'a, M: Memory> Frame<'a, M> {
    fn part(&self, offset: usize, len: usize) -> Part<&'a M> {
        Part::memory(self.channel, offset, len)
    }
    fn outbound(&self) -> Part<&'a M> {
        self.part(layout::OUTBOUND, layout::OUTBOUND_PAGES * layout::PAGE)
    }
    fn inbound(&self) -> Part<&'a M> {
        self.part(layout::INBOUND, layout::INBOUND_PAGES * layout::PAGE)
    }
    fn request(&self) -> Part<&'a M> {
        self.part(layout::REQUEST, layout::PAGE)
    }
    fn send(&self) -> Part<&'a M> {
        self.part(layout::SEND, layout::SEND_SIZE)
    }
    fn receive(&self) -> Part<&'a M> {
        self.part(layout::RECEIVE, layout::RECEIVE_SIZE)
    }
}

/// Everything netvsc keeps but its windows.
struct State<Q> {
    start: Start,
    attach: VmbusAttach,
    queues: Driver<Q>,
    out: Outbound,
    inb: Inbound,
    step: Step,
    /// The step's request is written and waits for its answer.
    sent: bool,
    /// RNDIS control packets whose completions have not come: bit `n`
    /// for request number `n`.
    control: u8,
    acks: Acks,
    nvsp: u32,
    ndis: u32,
    section_size: u32,
    sections: u32,
    in_flight: u128,
    align: u32,
    mac: Mac,
    link: bool,
    notes: [Option<Note>; NOTES],
    stats: NetvscStats,
    failure: Option<Failure>,
}

/// netvsc: its channel frame `M`, the monitor window, and the frame
/// queues' driver side over `Q`.
pub struct Adapter<M, Q> {
    channel: M,
    mnf: Option<M>,
    s: State<Q>,
}

impl<M: Memory, Q: Memory> Adapter<M, Q> {
    /// netvsc over its channel frame `channel` (2 MiB, as root maps it at
    /// [`layout::CHANNEL`]), with `start` root's arguments, `attach`
    /// vmbus's answer to `Attach`, `mnf` the monitor window
    /// ([`layout::MNF`]) when `start.mnf`, and `queues` the frame queues'
    /// driver side. Its rings are as vmbus's open left them. Refuses an
    /// offer whose monitor trigger it cannot set; panics on windows of
    /// the wrong size or an `mnf` that does not match `start.mnf`, which
    /// root never passes.
    pub fn new(
        start: Start,
        attach: VmbusAttach,
        channel: M,
        mnf: Option<M>,
        queues: Driver<Q>,
    ) -> Result<Adapter<M, Q>, Failure> {
        assert_eq!(
            channel.len(),
            layout::CHANNEL_SIZE,
            "netvsc: a channel frame of {:#x} bytes",
            channel.len()
        );
        assert_eq!(
            mnf.as_ref().map(|m| m.len()),
            start.mnf.then_some(layout::MNF_SIZE),
            "netvsc: a monitor window that does not match netvsc.mnf"
        );
        if start.mnf && attach.has_mnf() && attach.montrig >= 128 {
            return Err(Failure::Trigger(attach.montrig));
        }
        let f = Frame {
            channel: &channel,
            mnf: None,
        };
        let out = Outbound::new(&f.outbound());
        let inb = Inbound::new(&f.inbound());
        Ok(Adapter {
            s: State {
                start,
                attach,
                queues,
                out,
                inb,
                step: Step::Init(0),
                sent: false,
                control: 0,
                acks: Acks::new(),
                nvsp: 0,
                ndis: 0,
                section_size: 0,
                sections: 0,
                in_flight: 0,
                align: 0,
                mac: Mac::ZERO,
                link: false,
                notes: [None; NOTES],
                stats: NetvscStats::default(),
                failure: None,
            },
            channel,
            mnf,
        })
    }

    /// Starts the setup: writes NVSP INIT with version 5 and signals the
    /// host.
    pub fn start(&mut self, host: &mut impl Signal) -> Result<(), Failure> {
        self.run(0, host).map(|_| ())
    }

    /// One signal's work: `bits` are the notification's (`CHANNEL`,
    /// `FRAMES` or both). Drains the inbound ring, answers what waits and
    /// moves the setup on; takes the receive buffers `net` handed back and
    /// sends what `TX_FILLED` holds. Returns whether to signal `net`. Once
    /// it fails it does nothing more and returns the same failure.
    pub fn on_signal(&mut self, bits: u64, host: &mut impl Signal) -> Result<bool, Failure> {
        self.run(bits, host)
    }

    fn run(&mut self, bits: u64, host: &mut impl Signal) -> Result<bool, Failure> {
        let f = Frame {
            channel: &self.channel,
            mnf: self.mnf.as_ref(),
        };
        self.s.run(&f, bits, host)
    }

    /// The next line to print, oldest first.
    pub fn note(&mut self) -> Option<Note> {
        let n = self.s.notes[0].take();
        self.s.notes.rotate_left(1);
        n
    }

    /// The counters, as `Stats` answers them.
    pub fn stats(&self) -> NetvscStats {
        let s = &self.s;
        NetvscStats {
            acks_waiting: s.acks.len as u64,
            bad_entries: s.queues.counters().bad,
            ..s.stats
        }
    }

    /// The setup's step, [`Step::Up`] once done.
    pub fn step(&self) -> Step {
        self.s.step
    }

    /// The failure netvsc stopped at, if any.
    pub fn failed(&self) -> Option<Failure> {
        self.s.failure
    }

    /// The MAC, once the host gave it.
    pub fn mac(&self) -> Mac {
        self.s.mac
    }

    /// The link, as the host last said.
    pub fn link(&self) -> bool {
        self.s.link
    }

    /// The send sections' size and count, once the host gave them.
    pub fn sections(&self) -> (u32, u32) {
        (self.s.section_size, self.s.sections)
    }

    /// The send sections whose completions have not come, bit `s` for
    /// section `s`.
    pub fn in_flight(&self) -> u128 {
        self.s.in_flight
    }

    /// The packet alignment RNDIS asked, at least 4; netvsc sends one
    /// packet a section, so it uses none.
    pub fn rndis_align(&self) -> u32 {
        self.s.align
    }

    /// The vmbus answer it was made with.
    pub fn attach(&self) -> VmbusAttach {
        self.s.attach
    }

    pub fn queues(&self) -> &Driver<Q> {
        &self.s.queues
    }
}

impl<Q: Memory> State<Q> {
    fn run<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        bits: u64,
        host: &mut impl Signal,
    ) -> Result<bool, Failure> {
        if let Some(e) = self.failure {
            return Err(e);
        }
        let r = self.work(f, bits, host);
        if let Err(e) = r {
            self.failure = Some(e);
        }
        r
    }

    fn work<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        bits: u64,
        host: &mut impl Signal,
    ) -> Result<bool, Failure> {
        // The inbound ring is drained on every signal, not only CHANNEL's:
        // what a full acknowledgement queue left there is read once the
        // queue has room again.
        loop {
            self.drain(f, host)?;
            self.flush_acks(f, host)?;
            let inb = f.inbound();
            if self.acks.is_full() || self.inb.broken().is_some() || !self.inb.more(&inb) {
                break;
            }
        }
        if bits & FRAMES != 0 && self.linked() {
            self.queues.reclaim();
            if self.step == Step::Net {
                self.step = Step::Filter;
            }
        }
        self.advance(f, host)?;
        self.transmit(f, host)?;
        Ok(self.linked() && self.queues.end_batch())
    }

    /// Whether the link block is written: the frame queues are in use.
    fn linked(&self) -> bool {
        matches!(self.step, Step::Net | Step::Filter | Step::Up)
    }

    fn note(&mut self, n: Note) {
        if let Some(slot) = self.notes.iter_mut().find(|n| n.is_none()) {
            *slot = Some(n);
        }
    }

    fn broke(&mut self, which: Ring, b: ring::Broken) {
        self.stats.broken += 1;
        self.note(Note::Broken(which, b));
    }

    // Writing.

    /// Signals the host about the channel.
    fn doorbell<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        host: &mut impl Signal,
    ) -> Result<(), Failure> {
        let a = self.attach;
        if let Some(m) = f.mnf {
            let ch = a.channel as usize;
            m.or64(
                layout::MNF_EVENT_FLAGS + 2048 + 8 * (ch / 64),
                1 << (ch % 64),
                SeqCst,
            );
            if a.has_mnf() {
                let t = usize::from(a.montrig);
                m.or32(
                    layout::MNF_MONITOR + 8 + 8 * (t / 32),
                    1 << (t % 32),
                    SeqCst,
                );
                return Ok(());
            }
        }
        let status = host.signal_event(a.connection);
        if !status.is_success() {
            return Err(Failure::Signal {
                connection: a.connection,
                status,
            });
        }
        Ok(())
    }

    /// Writes one packet to the outbound ring and signals the host if its
    /// mask is 0. False if there is no room (the host is asked to signal
    /// once there is) or the ring is broken (counted once, when it broke).
    #[allow(clippy::too_many_arguments)]
    fn write<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        host: &mut impl Signal,
        kind: u16,
        flags: u16,
        xid: u64,
        ext: &[u8],
        body: &[u8],
    ) -> Result<bool, Failure> {
        let out = f.outbound();
        let was_broken = self.out.broken().is_some();
        match self.out.write(&out, kind, flags, xid, ext, body) {
            Ok(signal) => {
                if signal {
                    self.doorbell(f, host)?;
                }
                Ok(true)
            }
            Err(ring::WriteError::Full { need, .. }) => {
                self.out.ask_room(&out, need);
                Ok(false)
            }
            Err(ring::WriteError::Broken(b)) => {
                if !was_broken {
                    self.broke(Ring::Outbound, b);
                }
                Ok(false)
            }
        }
    }

    /// Writes the waiting acknowledgements, in order, while they fit.
    fn flush_acks<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        host: &mut impl Signal,
    ) -> Result<(), Failure> {
        let ack = nvs::rndis_ack(nvs::STATUS_OK);
        while let Some(x) = self.acks.front() {
            if !self.write(f, host, kind::COMP, 0, x, &[], &ack)? {
                break;
            }
            self.acks.pop();
            self.stats.acks += 1;
        }
        Ok(())
    }

    /// Writes the setup's next requests, as far as they need no answer,
    /// once no acknowledgement waits.
    fn advance<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        host: &mut impl Signal,
    ) -> Result<(), Failure> {
        while !self.sent && self.acks.front().is_none() {
            let a = self.attach;
            let x = self.step.xid();
            let rc = FLAG_COMPLETION;
            let inband = kind::INBAND;
            let written = match self.step {
                Step::Init(i) => {
                    let m = nvs::init(nvs::VERSIONS[usize::from(i)]);
                    self.write(f, host, inband, rc, x, &[], &m)?
                }
                Step::NdisConf => self.write(f, host, inband, 0, x, &[], &nvs::ndis_conf())?,
                Step::NdisInit => {
                    let m = nvs::ndis_init(self.ndis);
                    self.write(f, host, inband, 0, x, &[], &m)?
                }
                Step::ReceiveBuffer => {
                    let m = nvs::rxbuf_conn(a.rx_gpadl);
                    self.write(f, host, inband, rc, x, &[], &m)?
                }
                Step::SendBuffer => {
                    let m = nvs::chim_conn(a.tx_gpadl);
                    self.write(f, host, inband, rc, x, &[], &m)?
                }
                Step::Initialize | Step::Mac | Step::Link | Step::Filter => {
                    self.control(f, host)?
                }
                Step::Net | Step::Up => return Ok(()),
            };
            if !written {
                return Ok(());
            }
            match self.step {
                Step::NdisConf => self.step = Step::NdisInit,
                Step::NdisInit => self.step = Step::ReceiveBuffer,
                _ => self.sent = true,
            }
        }
        Ok(())
    }

    /// Writes the step's RNDIS control request in the request page, then a
    /// GPA packet naming it (`vmbus_chanpkt_sglist`: a reserved word, one
    /// range, the range's length, offset 0 and page number), whose body is
    /// NVS RNDIS with channel type 1 (control), no send section and size
    /// 0, as FreeBSD's `hn_rndis_xact_exec1` sends it. Its transaction ID
    /// is the request's ID.
    fn control<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        host: &mut impl Signal,
    ) -> Result<bool, Failure> {
        let n = self.step.rndis_number();
        let rid = rndis::request_id(n);
        let page = f.request();
        let len = match self.step {
            Step::Initialize => {
                page.write(0, &rndis::initialize(rid));
                rndis::INITIALIZE_LEN
            }
            Step::Mac => {
                page.write(0, &rndis::query(rid, rndis::oid::PERMANENT_ADDRESS));
                rndis::QUERY_LEN
            }
            Step::Link => {
                page.write(0, &rndis::query(rid, rndis::oid::MEDIA_CONNECT_STATUS));
                rndis::QUERY_LEN
            }
            _ => {
                let m = rndis::set(rid, rndis::oid::CURRENT_PACKET_FILTER, rndis::FILTER);
                page.write(0, &m);
                rndis::SET_LEN
            }
        };
        let mut gpa = [0u8; 24];
        gpa[4..8].copy_from_slice(&1u32.to_le_bytes());
        gpa[8..12].copy_from_slice(&(len as u32).to_le_bytes());
        let number = self.start.channel_page(layout::REQUEST_PAGE);
        gpa[16..24].copy_from_slice(&number.to_le_bytes());
        let body = nvs::rndis(nvs::MTYPE_CONTROL, nvs::CHIM_NONE, 0);
        let x = u64::from(rid);
        let written = self.write(f, host, kind::GPA, FLAG_COMPLETION, x, &gpa, &body)?;
        if written {
            self.control |= 1 << n;
        }
        Ok(written)
    }

    /// Sends the frames `TX_FILLED` holds while a send section and room in
    /// the outbound ring are free: once the link block is written, not
    /// before the packet filter's request, and not while an
    /// acknowledgement waits.
    fn transmit<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        host: &mut impl Signal,
    ) -> Result<(), Failure> {
        let ready = match self.step {
            Step::Net | Step::Up => true,
            Step::Filter => self.sent,
            _ => false,
        };
        if !ready || self.acks.front().is_some() {
            return Ok(());
        }
        let mask = if self.sections >= 128 {
            u128::MAX
        } else {
            (1u128 << self.sections) - 1
        };
        while self.queues.peek_tx().is_some() {
            let free = !self.in_flight & mask;
            if free == 0 {
                break;
            }
            let s = free.trailing_zeros();
            let out = f.outbound();
            let was_broken = self.out.broken().is_some();
            match self.out.free(&out) {
                Ok(room) if room > DATA_PACKET => {}
                Ok(_) => {
                    self.out.ask_room(&out, DATA_PACKET);
                    break;
                }
                Err(b) => {
                    if !was_broken {
                        self.broke(Ring::Outbound, b);
                    }
                    break;
                }
            }
            let send = f.send();
            let base = s as usize * self.section_size as usize;
            let Some(n) = self.queues.take_tx_with(|frame| {
                let n = frame.len();
                send.write(base, &rndis::packet_header(n));
                mem::copy(frame, 0, &send, base + rndis::PACKET_HEADER, n);
                n
            }) else {
                break;
            };
            let size = (rndis::PACKET_HEADER + n) as u32;
            let m = nvs::rndis(nvs::MTYPE_DATA, s, size);
            let x = xid::send(s);
            if !self.write(f, host, kind::INBAND, FLAG_COMPLETION, x, &[], &m)? {
                // Only a ring the host broke since the check: the frame
                // goes with it.
                break;
            }
            self.in_flight |= 1 << s;
            self.stats.sent += 1;
            let n = u64::from(self.in_flight.count_ones());
            self.stats.max_in_flight = self.stats.max_in_flight.max(n);
        }
        Ok(())
    }

    // Reading.

    /// Reads the inbound ring in batches until it is empty or broken, or
    /// the acknowledgement queue is full; after each batch, signals the
    /// host if it waits for room it now has.
    fn drain<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        host: &mut impl Signal,
    ) -> Result<(), Failure> {
        let inb = f.inbound();
        let mut buf = [0u8; MAX_PACKET];
        loop {
            while !self.acks.is_full() {
                match self.inb.next(&inb, &mut buf) {
                    Ok(None) => break,
                    Ok(Some(Read::Packet(h))) => self.packet(f, h, &buf[..h.total])?,
                    Ok(Some(Read::Skipped(h))) => {
                        self.stats.skipped += 1;
                        if h.kind == kind::RXBUF {
                            self.stats.rxbuf_packets += 1;
                            self.acks.push(h.xid);
                        }
                    }
                    Err(b) => {
                        self.broke(Ring::Inbound, b);
                        break;
                    }
                }
            }
            if self.inb.finish(&inb) {
                self.doorbell(f, host)?;
            }
            if self.acks.is_full() || self.inb.broken().is_some() || !self.inb.more(&inb) {
                return Ok(());
            }
        }
    }

    /// One inbound packet, `p` its `h.total` bytes.
    fn packet<M: Memory>(&mut self, f: &Frame<'_, M>, h: Header, p: &[u8]) -> Result<(), Failure> {
        match h.kind {
            kind::COMP => self.completion(h.xid, &p[h.header_len..]),
            kind::RXBUF => {
                self.stats.rxbuf_packets += 1;
                self.rxbuf(f, h, p)?;
                self.acks.push(h.xid);
                Ok(())
            }
            // Host notes (TXTBL_NOTE, VFASSOC_NOTE) and anything else.
            _ => {
                self.stats.ignored += 1;
                Ok(())
            }
        }
    }

    /// A completion: of a data packet, by its section; of an RNDIS control
    /// packet, by its request ID; or the answer to the step's NVS request.
    /// Any other is counted and ignored.
    fn completion(&mut self, x: u64, body: &[u8]) -> Result<(), Failure> {
        if let Some(s) = xid::section(x) {
            let bit = 1u128.checked_shl(s).unwrap_or(0);
            if s < self.sections && self.in_flight & bit != 0 {
                self.in_flight &= !bit;
                self.stats.completions += 1;
                if nvs::ack_status(body) != Some(nvs::STATUS_OK) {
                    // The host says it did not send it: counted; the
                    // section is free all the same.
                    self.stats.ignored += 1;
                }
            } else {
                self.stats.ignored += 1;
            }
            return Ok(());
        }
        let n = (x >> 16) as u32;
        if x & 0xFFFF == 0 && (1..=4).contains(&n) && self.control & (1 << n) != 0 {
            self.control &= !(1 << n);
            return Ok(());
        }
        let nvs_step = matches!(
            self.step,
            Step::Init(_) | Step::ReceiveBuffer | Step::SendBuffer
        );
        if !(self.sent && nvs_step && x == self.step.xid()) {
            self.stats.ignored += 1;
            return Ok(());
        }
        self.sent = false;
        let step = self.step;
        let refused = |b| Failure::Refused(step, Why::Nvs(b));
        match step {
            Step::Init(i) => match nvs::init_resp(body) {
                Ok(()) => {
                    self.nvsp = nvs::VERSIONS[usize::from(i)];
                    self.ndis = nvs::ndis_for(self.nvsp);
                    self.stats.nvsp = u64::from(self.nvsp);
                    self.stats.ndis = u64::from(self.ndis);
                    self.step = Step::NdisConf;
                }
                Err(_) if usize::from(i) + 1 < nvs::VERSIONS.len() => {
                    self.step = Step::Init(i + 1);
                }
                Err(_) => return Err(Failure::NoVersion),
            },
            Step::ReceiveBuffer => {
                nvs::rxbuf_connresp(body).map_err(refused)?;
                self.step = Step::SendBuffer;
            }
            _ => {
                let (size, n) = nvs::chim_connresp(body).map_err(refused)?;
                self.section_size = size;
                self.sections = n;
                self.step = Step::Initialize;
            }
        }
        Ok(())
    }

    /// A receive-buffer packet (`vmbus_chanpkt_rxbuf`): ID `0xCAFE`, its
    /// ranges inside its header, an NVS RNDIS body; each range inside the
    /// receive buffer holds one RNDIS message, and one outside it is
    /// skipped and counted (FreeBSD's `hn_nvs_handle_rxbuf`). The caller
    /// acknowledges it whatever it held.
    fn rxbuf<M: Memory>(&mut self, f: &Frame<'_, M>, h: Header, p: &[u8]) -> Result<(), Failure> {
        let fits = h.header_len >= 24;
        let id = if fits {
            u16::from_le_bytes([p[16], p[17]])
        } else {
            0
        };
        let count = if fits {
            nvs::u32_at(p, 20).unwrap_or(0)
        } else {
            0
        };
        let ranges_fit = 24 + 8 * u64::from(count) <= h.header_len as u64;
        let rndis = nvs::kind_of(&p[h.header_len..]) == Some(nvs::kind::RNDIS);
        if !fits || !ranges_fit || id != nvs::RXBUF_SIG || !rndis {
            self.stats.ignored += 1;
            return Ok(());
        }
        for i in 0..count as usize {
            let len = nvs::u32_at(p, 24 + 8 * i).expect("inside the header");
            let ofs = nvs::u32_at(p, 28 + 8 * i).expect("inside the header");
            if u64::from(ofs) + u64::from(len) > layout::RECEIVE_SIZE as u64 {
                self.stats.skipped += 1;
                continue;
            }
            self.message(f, ofs as usize, len as usize)?;
        }
        Ok(())
    }

    /// The RNDIS message at `ofs` in the receive buffer, `len` bytes.
    fn message<M: Memory>(
        &mut self,
        f: &Frame<'_, M>,
        ofs: usize,
        len: usize,
    ) -> Result<(), Failure> {
        let rx = f.receive();
        let msg = Part::memory(&rx, ofs, len);
        match rndis::kind_of(&msg) {
            Some(rndis::kind::PACKET) => self.data(&msg),
            Some(rndis::kind::INDICATE_STATUS) => self.status(&msg),
            Some(
                rndis::kind::INITIALIZE_CMPLT | rndis::kind::QUERY_CMPLT | rndis::kind::SET_CMPLT,
            ) => return self.control_answer(&msg),
            _ => self.stats.ignored += 1,
        }
        Ok(())
    }

    /// A data packet: its frame copied into a buffer from `RX_FREE`, or
    /// dropped and counted with none free.
    fn data(&mut self, msg: &impl Memory) {
        let Ok(d) = rndis::packet(msg) else {
            self.stats.ignored += 1;
            return;
        };
        if !self.linked() {
            // Before the link block, net has handed over no buffer.
            self.stats.dropped += 1;
            return;
        }
        match self
            .queues
            .deliver_with(d.len, |buf| mem::copy(msg, d.offset, buf, 0, d.len))
        {
            Ok(()) => self.stats.received += 1,
            Err(PushError::NoBuffer) => self.stats.dropped += 1,
            // A queue a broken peer left full, which the queues count.
            Err(_) => {}
        }
    }

    /// A status indication: MEDIA_CONNECT and MEDIA_DISCONNECT set the
    /// link, printed once netvsc is up if it changed.
    fn status(&mut self, msg: &impl Memory) {
        let Ok(s) = rndis::indicate_status(msg) else {
            self.stats.ignored += 1;
            return;
        };
        self.stats.status += 1;
        let up = match s {
            rndis::STATUS_MEDIA_CONNECT => true,
            rndis::STATUS_MEDIA_DISCONNECT => false,
            _ => return,
        };
        if up != self.link {
            self.link = up;
            if self.linked() {
                self.note(Note::Link(up));
            }
        }
    }

    /// An RNDIS completion: the answer to the step's control request if it
    /// carries its ID, else counted and ignored.
    fn control_answer(&mut self, msg: &impl Memory) -> Result<(), Failure> {
        let n = self.step.rndis_number();
        let Some(c) = rndis::completion(msg) else {
            self.stats.ignored += 1;
            return Ok(());
        };
        if !self.sent || n == 0 || c.rid != rndis::request_id(n) {
            self.stats.ignored += 1;
            return Ok(());
        }
        let step = self.step;
        let refused = |b| Failure::Refused(step, Why::Rndis(b));
        let want = match step {
            Step::Initialize => rndis::kind::INITIALIZE_CMPLT,
            Step::Mac | Step::Link => rndis::kind::QUERY_CMPLT,
            _ => rndis::kind::SET_CMPLT,
        };
        if c.kind != want {
            return Err(Failure::Refused(step, Why::Kind(c.kind)));
        }
        self.sent = false;
        match step {
            Step::Initialize => {
                self.align = rndis::initialize_cmplt(msg, &c).map_err(refused)?;
                self.step = Step::Mac;
            }
            Step::Mac => {
                let at = rndis::query_cmplt(msg, &c, 6).map_err(refused)?;
                let mut mac = [0u8; 6];
                msg.read(at, &mut mac);
                let mac = Mac(mac);
                if !mac.is_unicast() {
                    return Err(Failure::Refused(step, Why::Mac(mac)));
                }
                self.mac = mac;
                self.step = Step::Link;
            }
            Step::Link => {
                let at = rndis::query_cmplt(msg, &c, 4).map_err(refused)?;
                let mut v = [0u8; 4];
                msg.read(at, &mut v);
                self.link = u32::from_le_bytes(v) == 0;
                self.queues.start(Link::new(self.mac, self.link));
                self.note(Note::Up {
                    nvsp: self.nvsp,
                    ndis: self.ndis,
                    mac: self.mac,
                    link: self.link,
                    sections: self.sections,
                    size: self.section_size,
                });
                self.step = Step::Net;
            }
            _ => {
                rndis::set_cmplt(msg, &c).map_err(refused)?;
                self.step = Step::Up;
            }
        }
        Ok(())
    }
}
