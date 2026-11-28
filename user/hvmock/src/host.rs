//! [`Host`]: the hypervisor's half of the SynIC and the two hypercalls,
//! and the VMBus host's half of the message protocol, written from the
//! TLFS (`inter-partition-communication.md`, `hv_message.md`,
//! `HvCallPostMessage.md`, `HvCallSignalEvent.md`) and FreeBSD's
//! `vmbus.c` and `vmbus_chan.c` (read 2026-11-27).
//!
//! | Mock | Behaviour |
//! | --- | --- |
//! | messages | one message slot for SINT 2: a message waits while the slot is full; delivery raises the SINT; `MessagePending` is set at delivery while more wait, or, with [`Machine::set_late_pending`], only when the guest's store empties the slot |
//! | contact | CONNECT answered by [`Config::versions`]; its pages checked |
//! | offers | CHREQUEST answered by [`Config::offers`] in order, then CHOFFER_DONE; [`Host::offer`] and [`Host::rescind`] later |
//! | GPADLs | reassembled from CONN and SUBCONN, checked page by page against guest memory and [`Config::allowed`]; answered by [`Config::gpadl_status`]; torn down by DISCONN |
//! | channels | CHOPEN checked against the GPADL, the page count and the VP; answered by [`Config::open_status`]; the device attached to the channel then runs on its rings ([`crate::device`]) |
//! | events | `signal_event` per connection, counted; a connection no open channel has fails the test, and so does a restricted capability's signal on another ([`Host::signal_restricted`]); [`Host::signal_guest`] sets the SIEF flag and raises the SINT when it was clear; [`Host::step`] also takes monitor page 2's triggers |
//! | hostility | [`Host::inject`] and [`Host::inject_raw`] queue any message; [`Config::busy_posts`] answers `HV_STATUS_INSUFFICIENT_BUFFERS`; [`Config::unanswered`] never answers some requests, and [`Config::hold_from`] answers late, until [`Host::resume`] |
//!
//! A page the guest names that is outside guest memory or outside
//! [`Config::allowed`] is a panic: the guest must never name it. Anything
//! else a guest does that a host would refuse goes in [`Host::log`], so a
//! test of an honest run asserts the log is empty and a hostile test can
//! let the guest's view and the host's differ.

use std::cell::Cell;
use std::collections::{BTreeMap, VecDeque};
use std::ops::Range;

use core::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release};

use libsys::hyperv::{Restriction, Status};
use libsys::mem::{Memory, Width};

use crate::device::{Chan, Device};
use crate::machine::{self, EVENT_FLAGS, Machine, PAGE, SIEF, SIM, SLOT};
use crate::wire::{self, Request};

/// The status the mock's host answers a request it refuses with.
pub const REFUSED: u32 = 0xC000_0001;

/// A VMBus version word.
pub const fn version(major: u32, minor: u32) -> u32 {
    major << 16 | minor
}

/// Device type GUIDs, in wire order, from FreeBSD's drivers.
pub mod guid {
    /// netvsc, `if_hn.c`'s `hn_guid`: `f8615163-df3e-46c5-913f-f2d2f965ed0e`.
    pub const NETVSC: [u8; 16] = [
        0x63, 0x51, 0x61, 0xf8, 0x3e, 0xdf, 0xc5, 0x46, 0x91, 0x3f, 0xf2, 0xd2, 0xf9, 0x65, 0xed,
        0x0e,
    ];
    /// storvsc, `hv_storvsc_drv_freebsd.c`: `ba6163d9-04a1-4d29-b605-72e2ffb1dc7f`.
    pub const STORVSC: [u8; 16] = [
        0xd9, 0x63, 0x61, 0xba, 0xa1, 0x04, 0x29, 0x4d, 0xb6, 0x05, 0x72, 0xe2, 0xff, 0xb1, 0xdc,
        0x7f,
    ];
    /// heartbeat, `vmbus_heartbeat.c`: `57164f39-9115-4e78-ab55-382f3bd5422d`.
    pub const HEARTBEAT: [u8; 16] = [
        0x39, 0x4f, 0x16, 0x57, 0x15, 0x91, 0x78, 0x4e, 0xab, 0x55, 0x38, 0x2f, 0x3b, 0xd5, 0x42,
        0x2d,
    ];
}

/// An offer the host makes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct OfferSpec {
    pub channel: u32,
    pub kind: [u8; 16],
    pub instance: [u8; 16],
    pub subchannel: u16,
    pub flags1: u8,
    pub montrig: u8,
    pub flags2: u16,
    pub connection: u32,
}

impl OfferSpec {
    /// `chm_flags1`'s `HASMNF`.
    pub const HAS_MNF: u8 = 1;

    /// An offer of device type `kind` on `channel`, signalled on
    /// `connection`, monitored with trigger `channel mod 128`, its
    /// instance GUID made from the channel ID.
    pub fn new(kind: [u8; 16], channel: u32, connection: u32) -> OfferSpec {
        let mut instance = [0u8; 16];
        instance[..4].copy_from_slice(&channel.to_le_bytes());
        instance[15] = 0x1E;
        OfferSpec {
            channel,
            kind,
            instance,
            subchannel: 0,
            flags1: Self::HAS_MNF,
            montrig: (channel % 128) as u8,
            flags2: 0,
            connection,
        }
    }

    pub fn netvsc(channel: u32, connection: u32) -> OfferSpec {
        OfferSpec::new(guid::NETVSC, channel, connection)
    }

    pub fn storvsc(channel: u32, connection: u32) -> OfferSpec {
        OfferSpec::new(guid::STORVSC, channel, connection)
    }

    pub fn heartbeat(channel: u32, connection: u32) -> OfferSpec {
        OfferSpec {
            flags1: 0,
            ..OfferSpec::new(guid::HEARTBEAT, channel, connection)
        }
    }

    /// A device type no driver knows.
    pub fn unknown(channel: u32, connection: u32) -> OfferSpec {
        let mut kind = [0xA5u8; 16];
        kind[0] = channel as u8;
        OfferSpec::new(kind, channel, connection)
    }

    /// The same device's sub-channel `n`: its type and instance.
    pub fn subchannel(self, n: u16, channel: u32, connection: u32) -> OfferSpec {
        OfferSpec {
            subchannel: n,
            channel,
            connection,
            montrig: (channel % 128) as u8,
            ..self
        }
    }

    pub fn has_mnf(&self) -> bool {
        self.flags1 & Self::HAS_MNF != 0
    }
}

/// The host's configuration.
#[derive(Clone, Debug)]
pub struct Config {
    /// The versions CONNECT takes.
    pub versions: Vec<u32>,
    /// The offers CHREQUEST gets, in order.
    pub offers: Vec<OfferSpec>,
    /// The guest's VP index, which CHOPEN must name.
    pub vp_index: u32,
    /// The page numbers the guest may name: root's.
    pub allowed: Vec<Range<u64>>,
    /// `PostMessage`s answered `HV_STATUS_INSUFFICIENT_BUFFERS` before
    /// one is taken.
    pub busy_posts: u32,
    /// The status of each GPADL made, in order; 0 past the list.
    pub gpadl_status: Vec<u32>,
    /// CHOPEN's status.
    pub open_status: u32,
    /// Request types the host takes and never answers: a host that
    /// leaves the guest waiting.
    pub unanswered: Vec<u32>,
    /// From the request with this index on (0 is the first the guest
    /// posts), the host's answers wait until [`Host::resume`], while
    /// [`Host::offer`], [`Host::rescind`] and the injections still go
    /// ahead: a host that answers late.
    pub hold_from: Option<usize>,
}

impl Default for Config {
    /// VMBus 4.0; storvsc on channel 1, heartbeat on 3, netvsc on 14 and
    /// an unknown device on 17, each on the connection of its channel ID;
    /// VP 0; root's pages of the standard machine.
    fn default() -> Config {
        Config {
            versions: vec![version(4, 0)],
            offers: vec![
                OfferSpec::storvsc(1, 1),
                OfferSpec::heartbeat(3, 3),
                OfferSpec::netvsc(14, 14),
                OfferSpec::unknown(17, 17),
            ],
            vp_index: 0,
            allowed: Config::root_pages(),
            busy_posts: 0,
            gpadl_status: Vec::new(),
            open_status: 0,
            unanswered: Vec::new(),
            hold_from: None,
        }
    }
}

impl Config {
    /// The standard machine's pages root gives vmbus to name: the channel
    /// frame, the two monitor pages and the event-flags page.
    pub fn root_pages() -> Vec<Range<u64>> {
        let channel = machine::CHANNEL / PAGE;
        let monitor = machine::MONITOR / PAGE;
        vec![
            channel..channel + machine::CHANNEL_SIZE / PAGE,
            monitor..EVENT_FLAGS / PAGE + 1,
        ]
    }
}

/// What CONNECT named.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Contact {
    pub version: u32,
    pub event_flags: u64,
    pub monitor1: u64,
    pub monitor2: u64,
}

/// A GPADL the host holds.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Gpadl {
    pub channel: u32,
    pub pages: Vec<u64>,
    /// The messages that made it: CONN and SUBCONNs.
    pub messages: usize,
}

/// A GPADL being reassembled.
#[derive(Clone, Debug)]
struct Building {
    channel: u32,
    total: usize,
    pages: Vec<u64>,
    messages: usize,
}

/// An open channel.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Opened {
    pub gpadl: u32,
    pub outbound_pages: u32,
    pub vp: u32,
}

/// A channel the host offered.
#[derive(Debug)]
pub struct ChannelState {
    pub offer: OfferSpec,
    pub rescinded: bool,
    pub open: Option<Opened>,
    /// The guest signalled it since the device last ran.
    pub(crate) signalled: Cell<bool>,
}

/// A request as the guest posted it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Posted {
    pub kind: u32,
    pub payload: Vec<u8>,
}

/// The mock hypervisor and VMBus host.
pub struct Host<'m> {
    m: &'m Machine,
    cfg: Config,
    queue: VecDeque<[u8; 256]>,
    contact: Option<Contact>,
    channels: Vec<ChannelState>,
    gpadls: BTreeMap<u32, Gpadl>,
    building: BTreeMap<u32, Building>,
    devices: BTreeMap<u32, Box<dyn Device + 'm>>,
    posts: Vec<Posted>,
    log: Vec<String>,
    signals: BTreeMap<u32, u64>,
    made: usize,
    busy_left: u32,
    busy: u64,
    eoms: u64,
    delivered: u64,
    monitor_signals: u64,
    /// The request being handled is one the host never answers.
    mute: bool,
    /// Answers held back by [`Config::hold_from`].
    held: VecDeque<[u8; 256]>,
}

impl<'m> Host<'m> {
    pub fn new(m: &'m Machine, cfg: Config) -> Host<'m> {
        Host {
            m,
            busy_left: cfg.busy_posts,
            cfg,
            queue: VecDeque::new(),
            contact: None,
            channels: Vec::new(),
            gpadls: BTreeMap::new(),
            building: BTreeMap::new(),
            devices: BTreeMap::new(),
            posts: Vec::new(),
            log: Vec::new(),
            signals: BTreeMap::new(),
            made: 0,
            busy: 0,
            eoms: 0,
            delivered: 0,
            monitor_signals: 0,
            mute: false,
            held: VecDeque::new(),
        }
    }

    pub fn machine(&self) -> &'m Machine {
        self.m
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn config_mut(&mut self) -> &mut Config {
        &mut self.cfg
    }

    /// Attaches `device` to `channel`'s offer: it runs on the channel's
    /// rings once the guest opens it.
    pub fn attach(&mut self, channel: u32, device: Box<dyn Device + 'm>) {
        self.devices.insert(channel, device);
    }

    /// The device on `channel`.
    pub fn device(&self, channel: u32) -> Option<&(dyn Device + 'm)> {
        self.devices.get(&channel).map(|d| &**d)
    }

    pub fn device_mut(&mut self, channel: u32) -> Option<&mut (dyn Device + 'm)> {
        match self.devices.get_mut(&channel) {
            Some(d) => Some(&mut **d),
            None => None,
        }
    }

    // The hypercalls and Eom, as `vmbus::Hypervisor` and the kernel's
    // checks see them.

    /// `HvCallPostMessage`.
    pub fn post_message(&mut self, connection: u32, message_type: u32, payload: &[u8]) -> Status {
        assert!(
            payload.len() <= wire::MAX && (1..1 << 31).contains(&message_type),
            "hvmock: PostMessage that the kernel refuses: type {message_type:#x}, {} bytes",
            payload.len()
        );
        if connection != wire::MESSAGE_CONNECTION {
            self.note(format!("PostMessage on connection {connection}"));
            return Status::INVALID_CONNECTION_ID;
        }
        if self.busy_left != 0 {
            self.busy_left -= 1;
            self.busy += 1;
            return Status::INSUFFICIENT_BUFFERS;
        }
        if message_type != wire::CHANNEL_MESSAGE {
            self.note(format!("PostMessage of message type {message_type}"));
            return Status::SUCCESS;
        }
        let k = payload
            .get(..4)
            .map_or(0, |b| u32::from_le_bytes(b.try_into().expect("4 bytes")));
        self.posts.push(Posted {
            kind: k,
            payload: payload.to_vec(),
        });
        match wire::parse(payload) {
            Ok(r) => {
                self.mute = self.cfg.unanswered.contains(&k);
                self.request(r);
                self.mute = false;
            }
            Err(e) => self.note(e),
        }
        Status::SUCCESS
    }

    /// `HvCallSignalEvent` on the unrestricted capability. A connection
    /// that no open channel has fails the test.
    pub fn signal_event(&mut self, connection: u32, flag: u16) -> Status {
        *self.signals.entry(connection).or_default() += 1;
        if flag != 0 {
            self.note(format!("SignalEvent of flag {flag}"));
            return Status::INVALID_PARAMETER;
        }
        let Some(c) = self
            .channels
            .iter()
            .find(|c| c.offer.connection == connection && c.open.is_some() && !c.rescinded)
        else {
            panic!("hvmock: SignalEvent on connection {connection}, which no open channel has");
        };
        c.signalled.set(true);
        Status::SUCCESS
    }

    /// `HvCallSignalEvent` on a restricted capability, `cap` its Mint
    /// word's fields ([`Restriction::from_data`] of what vmbus minted):
    /// another connection, or no `signal` right, fails the test, as the
    /// kernel would refuse it with `IllegalOperation`.
    pub fn signal_restricted(&mut self, cap: Restriction, connection: u32, flag: u16) -> Status {
        assert!(
            cap.signal && connection == cap.connection,
            "hvmock: a capability restricted to {cap:?} signalled connection {connection}"
        );
        self.signal_event(connection, flag)
    }

    /// A write to the EOM register: delivers the next message if the slot
    /// is empty.
    pub fn eom(&mut self) {
        self.eoms += 1;
        self.deliver();
    }

    pub fn vp_index(&self) -> u32 {
        self.cfg.vp_index
    }

    // The host's side.

    /// Queues an offer now, as a hot add.
    pub fn offer(&mut self, o: OfferSpec) {
        self.add_channel(o);
        self.push(message(&wire::offer(&o)));
    }

    fn add_channel(&mut self, o: OfferSpec) {
        self.channels.push(ChannelState {
            offer: o,
            rescinded: false,
            open: None,
            signalled: Cell::new(false),
        });
    }

    /// Lets the answers [`Config::hold_from`] held back go, in order.
    pub fn resume(&mut self) {
        self.cfg.hold_from = None;
        let held = std::mem::take(&mut self.held);
        self.queue.extend(held);
        self.deliver();
    }

    /// Answers held back.
    pub fn held(&self) -> usize {
        self.held.len()
    }

    /// Takes `channel` back: queues CHRESCIND; the host stops using it.
    pub fn rescind(&mut self, channel: u32) {
        for c in self
            .channels
            .iter_mut()
            .filter(|c| c.offer.channel == channel)
        {
            c.rescinded = true;
        }
        self.push(message(&wire::rescind(channel)));
    }

    /// Queues `payload` (at most 240 bytes are kept) as a channel
    /// message, whatever it holds.
    pub fn inject(&mut self, payload: &[u8]) {
        self.push(message(payload));
    }

    /// Queues a SynIC message of any type but 0 (none: the hypervisor
    /// never delivers one), `PayloadSize` and bytes, even a size over
    /// 240.
    pub fn inject_raw(&mut self, message_type: u32, size: u8, payload: &[u8]) {
        assert_ne!(message_type, 0, "hvmock: a message of type 0 is no message");
        let mut m = [0u8; 256];
        m[..4].copy_from_slice(&message_type.to_le_bytes());
        m[4] = size;
        let n = payload.len().min(240);
        m[16..16 + n].copy_from_slice(&payload[..n]);
        self.push(m);
    }

    /// Sets `channel`'s event flag in the SIEF's slot 2, and raises SINT
    /// 2 if it was clear, as the host signals a channel.
    pub fn signal_guest(&self, channel: u32) {
        signal_guest(self.m, channel);
    }

    /// The host's turn: scans monitor page 2's triggers for monitored
    /// channels the guest signalled that way, then runs each open
    /// channel's device: `signalled` if the guest signalled it, then
    /// `poll`. Returns whether anything happened.
    pub fn step(&mut self) -> bool {
        let mut did = self.scan_monitor();
        for (&id, dev) in self.devices.iter_mut() {
            let Some(st) = self
                .channels
                .iter()
                .find(|c| c.offer.channel == id && c.open.is_some() && !c.rescinded)
            else {
                continue;
            };
            let ch = Chan::new(self.m, st, &self.gpadls);
            if st.signalled.replace(false) {
                dev.signalled(&ch);
                did = true;
            }
            did |= dev.poll(&ch);
        }
        did
    }

    /// Guest monitor signalling (FreeBSD's `vmbus_chan_signal` with
    /// `HASMNF`): a set bit `t mod 32` of monitor page 2's trigger group
    /// `t / 32` (`mt_pending`, at 8 + 8 × group) signals the open,
    /// monitored channel whose `chm_montrig` is `t`; the bit is cleared,
    /// and so is the channel's flag in the event-flags page's
    /// guest-to-host half (offset 2,048), if set. That the host polls the
    /// page this way is from memory.
    fn scan_monitor(&mut self) -> bool {
        let Some(c) = self.contact else {
            return false;
        };
        let mut did = false;
        for group in 0..4u64 {
            let at = (c.monitor2 + 8 + 8 * group) as usize;
            let mut bits = self.m.ram().swap(at, Width::Dword, 0, AcqRel) as u32;
            while bits != 0 {
                let b = bits.trailing_zeros();
                bits &= bits - 1;
                let trig = (32 * group) as u32 + b;
                let Some(ch) = self.channels.iter().find(|ch| {
                    ch.offer.has_mnf()
                        && u32::from(ch.offer.montrig) == trig
                        && ch.open.is_some()
                        && !ch.rescinded
                }) else {
                    self.log
                        .push(format!("monitor trigger {trig} for no open channel"));
                    continue;
                };
                let flag = c.event_flags as usize + 2048 + ch.offer.channel as usize / 8;
                let byte = self.m.ram().load8(flag, Relaxed);
                self.m
                    .ram()
                    .store8(flag, byte & !(1 << (ch.offer.channel % 8)), Release);
                ch.signalled.set(true);
                self.monitor_signals += 1;
                did = true;
            }
        }
        did
    }

    // What a test asks.

    pub fn contact(&self) -> Option<Contact> {
        self.contact
    }

    pub fn gpadl(&self, handle: u32) -> Option<&Gpadl> {
        self.gpadls.get(&handle)
    }

    pub fn gpadls(&self) -> &BTreeMap<u32, Gpadl> {
        &self.gpadls
    }

    pub fn channel(&self, channel: u32) -> Option<&ChannelState> {
        self.channels.iter().find(|c| c.offer.channel == channel)
    }

    /// A context over `channel`'s rings, as its device gets, if it is
    /// open: for a test that plays the device.
    pub fn chan(&self, channel: u32) -> Option<Chan<'_>> {
        let st = self
            .channels
            .iter()
            .find(|c| c.offer.channel == channel && c.open.is_some())?;
        Some(Chan::new(self.m, st, &self.gpadls))
    }

    /// Every request the guest posted, in order.
    pub fn posts(&self) -> &[Posted] {
        &self.posts
    }

    /// What the guest did that a host would refuse.
    pub fn log(&self) -> &[String] {
        &self.log
    }

    /// `SignalEvent`s on `connection`.
    pub fn signals(&self, connection: u32) -> u64 {
        self.signals.get(&connection).copied().unwrap_or(0)
    }

    pub fn eoms(&self) -> u64 {
        self.eoms
    }

    /// Messages put in the slot.
    pub fn delivered(&self) -> u64 {
        self.delivered
    }

    /// Messages waiting behind the slot.
    pub fn queued(&self) -> usize {
        self.queue.len()
    }

    /// `PostMessage`s answered `HV_STATUS_INSUFFICIENT_BUFFERS`.
    pub fn busy(&self) -> u64 {
        self.busy
    }

    /// Channels signalled through monitor page 2.
    pub fn monitor_signals(&self) -> u64 {
        self.monitor_signals
    }

    fn note(&mut self, what: String) {
        self.log.push(what);
    }

    /// Fails the test unless every page is guest memory and root's.
    fn check_pages(&self, what: &str, pages: &[u64]) {
        for &p in pages {
            let ours = self.cfg.allowed.iter().any(|r| r.contains(&p));
            assert!(
                p < machine::RAM / PAGE && ours,
                "hvmock: the guest named page {p:#x} in {what}, outside the pages root gave it"
            );
        }
    }

    fn request(&mut self, r: Request) {
        if self.contact.is_none() && !matches!(r, Request::Connect { .. }) {
            self.note(format!("{r:?} before contact"));
            return;
        }
        match r {
            Request::Connect {
                version,
                event_flags,
                monitor1,
                monitor2,
            } => self.connect(version, event_flags, monitor1, monitor2),
            Request::ChRequest => {
                let offers = self.cfg.offers.clone();
                for o in offers {
                    self.add_channel(o);
                    self.queue_message(&wire::offer(&o));
                }
                self.queue_message(&wire::offers_done());
            }
            Request::GpadlConn {
                channel,
                gpadl,
                range_len,
                range_count,
                byte_len,
                byte_offset,
                pages,
            } => {
                let total = usize::from(range_len.saturating_sub(8)) / 8;
                let fits = range_count == 1
                    && usize::from(range_len) == 8 + 8 * total
                    && byte_offset == 0
                    && byte_len as usize == total * PAGE as usize
                    && pages.len() <= total
                    && (pages.len() == total || pages.len() == wire::CONN_PAGES);
                if !self.offered(channel) || !fits || self.gpadl_in_use(gpadl) {
                    self.note(format!(
                        "GPADL_CONN {gpadl:#x} on channel {channel}: {range_count} ranges, {range_len} bytes of range, {byte_len} bytes from {byte_offset}, {} pages",
                        pages.len()
                    ));
                    self.queue_message(&wire::gpadl_connresp(channel, gpadl, REFUSED));
                    return;
                }
                self.check_pages("GPADL_CONN", &pages);
                let b = Building {
                    channel,
                    total,
                    pages,
                    messages: 1,
                };
                self.building.insert(gpadl, b);
                self.complete(gpadl);
            }
            Request::GpadlSubconn {
                number,
                gpadl,
                pages,
            } => {
                self.check_pages("GPADL_SUBCONN", &pages);
                let Some(b) = self.building.get_mut(&gpadl) else {
                    self.note(format!(
                        "GPADL_SUBCONN for {gpadl:#x}, which is not being made"
                    ));
                    return;
                };
                if number != 0 {
                    self.log.push(format!("GPADL_SUBCONN number {number}"));
                }
                if b.pages.len() + pages.len() > b.total
                    || (b.pages.len() + pages.len() < b.total && pages.len() != wire::SUBCONN_PAGES)
                {
                    let channel = b.channel;
                    self.building.remove(&gpadl);
                    self.note(format!(
                        "GPADL_SUBCONN for {gpadl:#x}: pages past its range"
                    ));
                    self.queue_message(&wire::gpadl_connresp(channel, gpadl, REFUSED));
                    return;
                }
                b.pages.extend_from_slice(&pages);
                b.messages += 1;
                self.complete(gpadl);
            }
            Request::ChOpen {
                channel,
                open_id,
                gpadl,
                vp,
                outbound_pages,
                user_data_zero,
            } => self.open(channel, open_id, gpadl, vp, outbound_pages, user_data_zero),
            Request::ChClose { channel } => {
                let Some(c) = self
                    .channels
                    .iter_mut()
                    .find(|c| c.offer.channel == channel && c.open.is_some())
                else {
                    self.note(format!("CHCLOSE of channel {channel}, which is not open"));
                    return;
                };
                c.open = None;
            }
            Request::GpadlDisconn { channel, gpadl } => {
                let held = self
                    .gpadls
                    .get(&gpadl)
                    .is_some_and(|g| g.channel == channel);
                let in_use = self
                    .channels
                    .iter()
                    .any(|c| c.open.is_some_and(|o| o.gpadl == gpadl));
                if !held || in_use {
                    self.note(format!(
                        "GPADL_DISCONN of {gpadl:#x} on channel {channel}: held {held}, its ring open {in_use}"
                    ));
                }
                if !in_use {
                    self.gpadls.remove(&gpadl);
                }
                self.queue_message(&wire::gpadl_disconnresp(gpadl));
            }
            Request::ChFree { channel } => self.note(format!("CHFREE of channel {channel}")),
            Request::Disconnect => self.note("DISCONNECT".into()),
            Request::Other(k) => self.note(format!("a request of type {k}")),
        }
    }

    fn connect(&mut self, version: u32, event_flags: u64, monitor1: u64, monitor2: u64) {
        if self.contact.is_some() {
            self.note("CONNECT after contact".into());
            return;
        }
        for (what, a) in [
            ("CONNECT's event-flags page", event_flags),
            ("CONNECT's monitor page 1", monitor1),
            ("CONNECT's monitor page 2", monitor2),
        ] {
            assert!(
                a % PAGE == 0,
                "hvmock: {what} at {a:#x}, not a page's address"
            );
            self.check_pages(what, &[a / PAGE]);
        }
        let done = self.cfg.versions.contains(&version);
        if done {
            self.contact = Some(Contact {
                version,
                event_flags,
                monitor1,
                monitor2,
            });
        }
        self.queue_message(&wire::connect_resp(done));
    }

    fn offered(&self, channel: u32) -> bool {
        self.channels
            .iter()
            .any(|c| c.offer.channel == channel && !c.rescinded)
    }

    fn gpadl_in_use(&self, gpadl: u32) -> bool {
        gpadl == 0 || self.gpadls.contains_key(&gpadl) || self.building.contains_key(&gpadl)
    }

    /// Answers a GPADL whose pages have all come.
    fn complete(&mut self, gpadl: u32) {
        let Some(b) = self.building.get(&gpadl) else {
            return;
        };
        if b.pages.len() < b.total {
            return;
        }
        let b = self.building.remove(&gpadl).expect("being made");
        let status = self.cfg.gpadl_status.get(self.made).copied().unwrap_or(0);
        self.made += 1;
        if status == 0 {
            self.gpadls.insert(
                gpadl,
                Gpadl {
                    channel: b.channel,
                    pages: b.pages,
                    messages: b.messages,
                },
            );
        }
        self.queue_message(&wire::gpadl_connresp(b.channel, gpadl, status));
    }

    fn open(
        &mut self,
        channel: u32,
        open_id: u32,
        gpadl: u32,
        vp: u32,
        outbound_pages: u32,
        user_data_zero: bool,
    ) {
        let pages = self
            .gpadls
            .get(&gpadl)
            .filter(|g| g.channel == channel)
            .map(|g| g.pages.len() as u32);
        let found = self
            .channels
            .iter()
            .position(|c| c.offer.channel == channel && !c.rescinded);
        let ok = match (found, pages) {
            (Some(i), Some(n)) => {
                self.channels[i].open.is_none()
                    && open_id == channel
                    && vp == self.cfg.vp_index
                    && outbound_pages >= 2
                    && n >= outbound_pages + 2
                    && user_data_zero
            }
            _ => false,
        };
        if !ok {
            self.note(format!(
                "CHOPEN of channel {channel} (open ID {open_id}) on GPADL {gpadl:#x} of {pages:?} pages, {outbound_pages} outbound, VP {vp}"
            ));
            self.queue_message(&wire::chopen_resp(channel, open_id, REFUSED));
            return;
        }
        let i = found.expect("found");
        let status = self.cfg.open_status;
        if status == 0 {
            self.channels[i].open = Some(Opened {
                gpadl,
                outbound_pages,
                vp,
            });
            let st = &self.channels[i];
            let ch = Chan::new(self.m, st, &self.gpadls);
            // The host uses the pending send size on its ring.
            ch.inbound()
                .set_features(crate::ring::FEATURE_PENDING_SEND_SIZE);
            if let Some(dev) = self.devices.get_mut(&channel) {
                dev.opened(&ch);
            }
        }
        self.queue_message(&wire::chopen_resp(channel, open_id, status));
    }

    /// Queues a channel message for SINT 2.
    /// The host's answer to the request being handled, unless it is one
    /// the host never answers or answers are held.
    fn queue_message(&mut self, payload: &[u8]) {
        if self.mute {
            return;
        }
        let m = message(payload);
        if self.cfg.hold_from.is_some_and(|n| self.posts.len() > n) {
            self.held.push_back(m);
            return;
        }
        self.push(m);
    }

    /// Queues a message for SINT 2 now.
    fn push(&mut self, m: [u8; 256]) {
        self.queue.push_back(m);
        self.deliver();
    }

    /// Puts the next message in the slot if it is empty, and raises SINT
    /// 2; with the slot full, sets `MessagePending` (unless late).
    fn deliver(&mut self) {
        let ram = self.m.ram();
        let slot = (SIM as usize) + SLOT;
        let late = self.m.late_pending();
        if ram.load32(slot, Acquire) != 0 {
            if !late && !self.queue.is_empty() {
                ram.or(slot + 5, Width::Byte, machine::PENDING.into(), AcqRel);
            }
            self.m.set_queued(self.queue.len());
            return;
        }
        if let Some(mut msg) = self.queue.pop_front() {
            if !late && !self.queue.is_empty() {
                msg[5] |= machine::PENDING;
            }
            // The header and the payload's bytes, as the TLFS lets the
            // hypervisor copy only those: the rest of the slot is stale.
            // A word at a time, which is also quicker under Miri.
            let end = (16 + usize::from(msg[4])).min(256).div_ceil(8) * 8;
            let word = |at: usize| u64::from_le_bytes(msg[at..at + 8].try_into().expect("8 bytes"));
            ram.store32(
                slot + 4,
                u32::from_le_bytes(msg[4..8].try_into().expect("4 bytes")),
                Relaxed,
            );
            for at in (8..end).step_by(8) {
                ram.store64(slot + at, word(at), Relaxed);
            }
            ram.store32(
                slot,
                u32::from_le_bytes(msg[..4].try_into().expect("4 bytes")),
                Release,
            );
            self.delivered += 1;
            self.m.raise();
        }
        self.m.set_queued(self.queue.len());
    }
}

/// A channel message as the slot holds it: type 1, `PayloadSize` its
/// length (at most 240 bytes kept), no flags, origination 0.
fn message(payload: &[u8]) -> [u8; 256] {
    let mut m = [0u8; 256];
    m[..4].copy_from_slice(&wire::CHANNEL_MESSAGE.to_le_bytes());
    let n = payload.len().min(240);
    m[4] = n as u8;
    m[16..16 + n].copy_from_slice(&payload[..n]);
    m
}

/// Sets `channel`'s flag in the SIEF's slot 2; raises SINT 2 if it was
/// clear.
pub(crate) fn signal_guest(m: &Machine, channel: u32) {
    let at = SIEF as usize + SLOT + 8 * (channel as usize / 64);
    let bit = 1u64 << (channel % 64);
    if m.ram().or(at, Width::Qword, bit, AcqRel) & bit == 0 {
        m.raise();
    }
}
