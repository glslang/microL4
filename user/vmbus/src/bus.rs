//! [`Bus`]: contact, offers, netvsc's channel and the vmbus protocol, as
//! a state machine driven by SINT 2's signals and by requests.
//!
//! Each request to the host waits for its answer before the next, as
//! FreeBSD's do: CONNECT for each version until one is taken, CHREQUEST
//! and the offers until CHOFFER_DONE, then for the first primary netvsc
//! offer the ring's GPADL, CHOPEN, the receive buffer's GPADL and the send
//! buffer's, then the Mint of netvsc's capability. An answer is taken
//! only in the step that waits for it and only with that step's IDs;
//! anything else is counted and ignored. With no timer, a host that never
//! answers leaves vmbus waiting, and the last `vmbus:` line says where.
//!
//! A host that refuses a step of netvsc's channel (a non-zero status)
//! stops its setup: vmbus tears down what it built, in FreeBSD's order
//! (the buffers' GPADLs, then CHCLOSE, then the ring's GPADL, each GPADL
//! waiting for its GPADL_DISCONNRESP), and answers `Attach` with
//! `Unavailable`. A CHRESCIND of netvsc's channel revokes the capability
//! vmbus minted and stops it too; nothing more is sent on a rescinded
//! channel.

use core::fmt;

use libsys::hyperv::Restriction;
use libsys::mem::Memory;
use libsys::proto::{Refusal, VMBUS_CLIENT, VmbusAttach, VmbusStats, VmbusVersion, label};

use crate::gpadl::{self, Handles, Pages};
use crate::msg::{self, Msg};
use crate::offer::{Offer, Offers};
use crate::{Hypervisor, MAX_RETRIES, Start, Status, System, VERSIONS, layout, synic};

/// A step of netvsc's channel set-up that waits for the host.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Step {
    /// The ring's GPADL.
    Ring,
    /// CHOPEN.
    Open,
    /// The receive buffer's GPADL.
    Receive,
    /// The send buffer's GPADL.
    Send,
}

impl Step {
    const fn what(self) -> &'static str {
        match self {
            Step::Ring => "the ring's GPADL",
            Step::Open => "the open",
            Step::Receive => "the receive buffer's GPADL",
            Step::Send => "the send buffer's GPADL",
        }
    }
}

/// A line vmbus prints, through console on the target.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Note {
    /// `vmbus: version 4.0`: the host took this version.
    Version(u32),
    /// `vmbus: offer <id>: <name>, connection <c>`: an offer kept.
    Offer(Offer),
    /// `vmbus: netvsc channel <id> rescinded`, or for another channel
    /// `vmbus: offer <id> rescinded`.
    Rescinded { channel: u32, netvsc: bool },
    /// `vmbus: no netvsc offer`: CHOFFER_DONE came with none kept.
    NoNetvsc,
    /// `vmbus: netvsc channel <id> open, connection <c>`.
    Open { channel: u32, connection: u32 },
    /// The host refused a step, and setup stopped.
    Refused {
        channel: u32,
        step: Step,
        status: u32,
    },
    /// What the refused setup built is torn down.
    TornDown { channel: u32 },
}

impl fmt::Display for Note {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Note::Version(v) => write!(f, "vmbus: version {}", VmbusVersion(v)),
            Note::Offer(ref o) => write!(f, "{o}"),
            Note::Rescinded {
                channel,
                netvsc: true,
            } => write!(f, "vmbus: netvsc channel {channel} rescinded"),
            Note::Rescinded {
                channel,
                netvsc: false,
            } => write!(f, "vmbus: offer {channel} rescinded"),
            Note::NoNetvsc => f.write_str("vmbus: no netvsc offer"),
            Note::Open {
                channel,
                connection,
            } => write!(
                f,
                "vmbus: netvsc channel {channel} open, connection {connection}"
            ),
            Note::Refused {
                channel,
                step,
                status,
            } => write!(
                f,
                "vmbus: netvsc channel {channel}: the host refused {} (status {status:#x}); setup stopped",
                step.what()
            ),
            Note::TornDown { channel } => {
                write!(f, "vmbus: netvsc channel {channel}: its GPADLs torn down")
            }
        }
    }
}

/// A request on endpoint VB.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request {
    /// netvsc's, badge 1: its channel, once open.
    Attach,
    /// The counters, any badge.
    Stats,
}

/// Decodes a request: its label, then its badge. Neither takes words, so
/// any sent are ignored.
pub fn decode(label: u64, badge: u64) -> Result<Request, Refusal> {
    match label {
        label::VMBUS_ATTACH if badge == VMBUS_CLIENT => Ok(Request::Attach),
        label::VMBUS_ATTACH => Err(Refusal::BadBadge),
        label::VMBUS_STATS => Ok(Request::Stats),
        _ => Err(Refusal::BadLabel),
    }
}

/// A request's answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Answer {
    /// `Attach`'s eight words; the reply carries slot 8's capability.
    Attach(VmbusAttach),
    /// `Stats`'s nine words.
    Stats(VmbusStats),
    /// A refusal: the label, no words.
    Refused(Refusal),
    /// The `Attach` is saved in slot 7 and [`Bus::release`] answers it.
    Saved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    /// Before [`Bus::start`].
    Idle,
    /// CONNECT posted with `VERSIONS[i]`.
    Contact(usize),
    /// CHREQUEST posted: offers until CHOFFER_DONE.
    Offers,
    /// Waiting for the host's answer to the step.
    Setup(Step),
    /// The channel is open and netvsc's capability minted.
    Up,
    /// Tearing down a refused setup: waiting for the GPADL_DISCONNRESP of
    /// the undo list's head.
    Teardown,
    /// No netvsc offer, or setup stopped.
    Stopped,
}

/// What a refused setup undoes, in order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Undo {
    Gpadl(u32),
    Close,
}

/// netvsc's channel as vmbus sets it up.
#[derive(Clone, Copy, Debug)]
struct Channel {
    offer: Offer,
    ring: u32,
    rx: u32,
    tx: u32,
}

/// vmbus.
pub struct Bus<M> {
    sim: M,
    sief: M,
    start: Start,
    vp: u32,
    phase: Phase,
    offers: Offers,
    chan: Option<Channel>,
    handles: Handles,
    /// The handle the current GPADL step waits for.
    pending: u32,
    /// The channel whose events go to netvsc: from CHOPEN until setup
    /// stops or the channel is rescinded.
    relay: Option<u32>,
    undo: [Undo; 3],
    undo_len: usize,
    undo_at: usize,
    /// An `Attach` is saved in slot 7.
    saved: bool,
    /// Slot 8 holds netvsc's capability.
    minted: bool,
    stats: VmbusStats,
}

impl<M: Memory> Bus<M> {
    /// vmbus over the SIM and SIEF pages, with root's arguments. Panics if
    /// either window is smaller than a page.
    pub fn new(start: Start, sim: M, sief: M) -> Bus<M> {
        assert!(
            sim.len() >= synic::PAGE && sief.len() >= synic::PAGE,
            "vmbus: a SynIC window under a page"
        );
        Bus {
            sim,
            sief,
            start,
            vp: 0,
            phase: Phase::Idle,
            offers: Offers::default(),
            chan: None,
            handles: Handles::default(),
            pending: 0,
            relay: None,
            undo: [Undo::Close; 3],
            undo_len: 0,
            undo_at: 0,
            saved: false,
            minted: false,
            stats: VmbusStats::default(),
        }
    }

    /// Reads the VP index, posts CONNECT with VMBus 4.0, then services the
    /// event flags and the message slot once, as after every signal.
    /// Panics if called twice.
    pub fn start<H: Hypervisor, S: System>(&mut self, hv: &mut H, sys: &mut S) {
        assert_eq!(self.phase, Phase::Idle, "vmbus: started twice");
        self.vp = hv.vp_index();
        self.connect(0, hv, sys);
        self.on_signal(hv, sys);
    }

    /// A SINT 2 signal: relays the event flags, then takes every message
    /// in the slot and handles each.
    pub fn on_signal<H: Hypervisor, S: System>(&mut self, hv: &mut H, sys: &mut S) {
        self.events(sys);
        while let Some(t) = synic::take(&self.sim, hv) {
            self.stats.messages += 1;
            self.stats.eoms += u64::from(t.eom);
            if !self.message(&t.message, hv, sys) {
                self.stats.ignored += 1;
            }
        }
    }

    /// Answers a request; `save` saves the caller's reply capability in
    /// slot 7 (`CNode_SaveCaller`), and says whether it did.
    pub fn request(&mut self, req: Request, save: impl FnOnce() -> bool) -> Answer {
        match req {
            Request::Stats => Answer::Stats(self.stats),
            Request::Attach => match self.phase {
                Phase::Up => Answer::Attach(self.attach_words()),
                Phase::Stopped | Phase::Teardown => Answer::Refused(Refusal::Unavailable),
                _ if self.saved => Answer::Refused(Refusal::Busy),
                _ if save() => {
                    self.saved = true;
                    Answer::Saved
                }
                _ => Answer::Refused(Refusal::Busy),
            },
        }
    }

    /// The saved `Attach`'s answer, once it is due: its words once the
    /// channel is open, `Unavailable` once setup has stopped. The caller
    /// sends it on slot 7.
    pub fn release(&mut self) -> Option<Answer> {
        if !self.saved {
            return None;
        }
        let a = match self.phase {
            Phase::Up => Answer::Attach(self.attach_words()),
            Phase::Stopped | Phase::Teardown => Answer::Refused(Refusal::Unavailable),
            _ => return None,
        };
        self.saved = false;
        Some(a)
    }

    pub fn stats(&self) -> VmbusStats {
        self.stats
    }

    /// The offers kept.
    pub fn offers(&self) -> &Offers {
        &self.offers
    }

    /// `Attach`'s words, once the channel is open.
    pub fn attached(&self) -> Option<VmbusAttach> {
        (self.phase == Phase::Up).then(|| self.attach_words())
    }

    /// Whether setup has stopped: no netvsc offer, a refusal, or a
    /// rescind; `Attach` is `Unavailable`.
    pub fn stopped(&self) -> bool {
        matches!(self.phase, Phase::Stopped | Phase::Teardown)
    }

    /// The Mint data word of netvsc's capability: `connection`, with
    /// `signal` (bit 25) alone (`docs/abi.md`, "Mint data word"). Every
    /// kept offer's connection is below 2^24.
    pub const fn mint_data(connection: u32) -> u64 {
        match Restriction::signal_only(connection).data() {
            Some(w) => w,
            None => panic!("vmbus: a connection of 2^24 or more"),
        }
    }

    fn attach_words(&self) -> VmbusAttach {
        let c = self.chan.expect("an open channel");
        VmbusAttach {
            channel: c.offer.channel,
            connection: c.offer.connection,
            ring_gpadl: c.ring,
            rx_gpadl: c.rx,
            tx_gpadl: c.tx,
            version: low(self.stats.version),
            flags1: c.offer.flags1,
            montrig: c.offer.montrig,
            flags2: c.offer.flags2,
            vp_index: self.vp,
        }
    }

    fn events<S: System>(&mut self, sys: &mut S) {
        let words = synic::words_for(self.offers.max_channel().unwrap_or(0));
        let relay = self.relay;
        let (mut relayed, mut stray) = (0, 0);
        synic::events(&self.sief, words, |id| {
            if Some(id) == relay {
                relayed += 1;
            } else {
                stray += 1;
            }
        });
        self.stats.events += relayed;
        self.stats.stray += stray;
        if relayed != 0 {
            sys.signal_netvsc();
        }
    }

    /// Handles a message copied from the slot; false if it is ignored.
    fn message<H: Hypervisor, S: System>(
        &mut self,
        m: &synic::Message,
        hv: &mut H,
        sys: &mut S,
    ) -> bool {
        if m.kind != msg::MESSAGE_TYPE {
            return false;
        }
        let Some(Ok(msg)) = m.payload().map(Msg::decode) else {
            return false;
        };
        match (self.phase, msg) {
            (Phase::Contact(i), Msg::ConnectResp { done }) => {
                self.contact(i, done, hv, sys);
                true
            }
            // Before contact, nothing but CONNECT_RESP answers anything.
            (Phase::Idle | Phase::Contact(_), _) => false,
            (_, Msg::ChOffer(o)) => self.offer(o, sys),
            (_, Msg::ChRescind { channel }) => self.rescind(channel, sys),
            (Phase::Offers, Msg::ChOfferDone) => {
                self.offers_done(hv, sys);
                true
            }
            (
                Phase::Setup(step @ (Step::Ring | Step::Receive | Step::Send)),
                Msg::GpadlConnResp {
                    channel,
                    gpadl,
                    status,
                },
            ) if self.is_channel(channel) && gpadl == self.pending => {
                self.gpadl_made(step, gpadl, status, hv, sys);
                true
            }
            (
                Phase::Setup(Step::Open),
                Msg::ChOpenResp {
                    channel,
                    open_id,
                    status,
                },
            ) if self.is_channel(channel) && open_id == channel => {
                self.opened(status, hv, sys);
                true
            }
            (Phase::Teardown, Msg::GpadlDisconnResp { gpadl })
                if self.undo.get(self.undo_at) == Some(&Undo::Gpadl(gpadl)) =>
            {
                self.undo_at += 1;
                self.teardown(hv, sys);
                true
            }
            _ => false,
        }
    }

    fn is_channel(&self, channel: u32) -> bool {
        self.chan.is_some_and(|c| c.offer.channel == channel)
    }

    fn connect<H: Hypervisor, S: System>(&mut self, i: usize, hv: &mut H, sys: &mut S) {
        self.phase = Phase::Contact(i);
        let m = Msg::Connect {
            version: VERSIONS[i],
            event_flags: self.start.event_flags,
            monitor1: self.start.monitor,
            monitor2: self.start.monitor2(),
        };
        self.post(&m, hv, sys);
    }

    fn contact<H: Hypervisor, S: System>(&mut self, i: usize, done: bool, hv: &mut H, sys: &mut S) {
        if done {
            self.stats.version = VERSIONS[i].into();
            sys.say(&Note::Version(VERSIONS[i]));
            self.phase = Phase::Offers;
            self.post(&Msg::ChRequest, hv, sys);
        } else if i + 1 < VERSIONS.len() {
            self.connect(i + 1, hv, sys);
        } else {
            panic!("vmbus: the host accepts none of VMBus 4.0, 3.0, 2.4");
        }
    }

    fn offer<S: System>(&mut self, o: Offer, sys: &mut S) -> bool {
        if self.offers.add(o).is_err() {
            return false;
        }
        self.stats.offers = self.offers.len() as u64;
        sys.say(&Note::Offer(o));
        true
    }

    fn rescind<S: System>(&mut self, channel: u32, sys: &mut S) -> bool {
        if self.offers.remove(channel).is_none() {
            return false;
        }
        self.stats.offers = self.offers.len() as u64;
        let netvsc = self.is_channel(channel);
        sys.say(&Note::Rescinded { channel, netvsc });
        if netvsc {
            self.relay = None;
            if self.minted {
                sys.revoke();
                self.minted = false;
            }
            self.chan = None;
            self.stats.netvsc_channel = 0;
            self.phase = Phase::Stopped;
        }
        true
    }

    fn offers_done<H: Hypervisor, S: System>(&mut self, hv: &mut H, sys: &mut S) {
        let Some(&offer) = self.offers.netvsc() else {
            sys.say(&Note::NoNetvsc);
            self.phase = Phase::Stopped;
            return;
        };
        self.chan = Some(Channel {
            offer,
            ring: 0,
            rx: 0,
            tx: 0,
        });
        self.stats.netvsc_channel = offer.channel.into();
        self.make_gpadl(Step::Ring, layout::RING, hv, sys);
    }

    /// Posts a GPADL of `pages` of the channel frame and waits for it.
    fn make_gpadl<H: Hypervisor, S: System>(
        &mut self,
        step: Step,
        pages: Pages,
        hv: &mut H,
        sys: &mut S,
    ) {
        let channel = self.chan.expect("a channel").offer.channel;
        let gpadl = self.handles.take();
        let phys = Pages {
            first: self.start.channel_page(pages.first),
            count: pages.count,
        };
        let messages = gpadl::messages(channel, gpadl, phys).expect("the layout's GPADLs fit");
        self.pending = gpadl;
        self.phase = Phase::Setup(step);
        for m in messages {
            self.post(&m, hv, sys);
        }
    }

    fn gpadl_made<H: Hypervisor, S: System>(
        &mut self,
        step: Step,
        gpadl: u32,
        status: u32,
        hv: &mut H,
        sys: &mut S,
    ) {
        let mut c = self.chan.expect("a channel");
        if status != 0 {
            let undo: &[Undo] = match step {
                Step::Receive => &[Undo::Close, Undo::Gpadl(c.ring)],
                Step::Send => &[Undo::Gpadl(c.rx), Undo::Close, Undo::Gpadl(c.ring)],
                Step::Ring | Step::Open => &[],
            };
            self.refuse(step, status, undo, hv, sys);
            return;
        }
        match step {
            Step::Ring => {
                c.ring = gpadl;
                self.chan = Some(c);
                self.relay = Some(c.offer.channel);
                self.phase = Phase::Setup(Step::Open);
                let m = Msg::ChOpen {
                    channel: c.offer.channel,
                    open_id: c.offer.channel,
                    gpadl,
                    vp: self.vp,
                    outbound_pages: layout::OUTBOUND_PAGES,
                };
                self.post(&m, hv, sys);
            }
            Step::Receive => {
                c.rx = gpadl;
                self.chan = Some(c);
                self.make_gpadl(Step::Send, layout::SEND, hv, sys);
            }
            Step::Send => {
                c.tx = gpadl;
                self.chan = Some(c);
                sys.mint(Self::mint_data(c.offer.connection));
                self.minted = true;
                self.phase = Phase::Up;
                sys.say(&Note::Open {
                    channel: c.offer.channel,
                    connection: c.offer.connection,
                });
            }
            Step::Open => unreachable!("CHOPEN has no GPADL"),
        }
    }

    fn opened<H: Hypervisor, S: System>(&mut self, status: u32, hv: &mut H, sys: &mut S) {
        if status != 0 {
            let ring = self.chan.expect("a channel").ring;
            self.refuse(Step::Open, status, &[Undo::Gpadl(ring)], hv, sys);
            return;
        }
        self.make_gpadl(Step::Receive, layout::RECEIVE, hv, sys);
    }

    /// The host refused `step`: setup stops, and what it built is torn
    /// down.
    fn refuse<H: Hypervisor, S: System>(
        &mut self,
        step: Step,
        status: u32,
        undo: &[Undo],
        hv: &mut H,
        sys: &mut S,
    ) {
        let channel = self.chan.expect("a channel").offer.channel;
        sys.say(&Note::Refused {
            channel,
            step,
            status,
        });
        self.relay = None;
        self.undo[..undo.len()].copy_from_slice(undo);
        self.undo_len = undo.len();
        self.undo_at = 0;
        self.teardown(hv, sys);
    }

    /// Does the undo list from `undo_at`: CHCLOSE at once, a GPADL's
    /// teardown waiting for its answer.
    fn teardown<H: Hypervisor, S: System>(&mut self, hv: &mut H, sys: &mut S) {
        let channel = self.chan.expect("a channel").offer.channel;
        while let Some(&u) = self.undo[..self.undo_len].get(self.undo_at) {
            match u {
                Undo::Close => {
                    self.post(&Msg::ChClose { channel }, hv, sys);
                    self.undo_at += 1;
                }
                Undo::Gpadl(gpadl) => {
                    self.phase = Phase::Teardown;
                    self.post(&Msg::GpadlDisconn { channel, gpadl }, hv, sys);
                    return;
                }
            }
        }
        if self.undo_len != 0 {
            sys.say(&Note::TornDown { channel });
        }
        self.phase = Phase::Stopped;
    }

    /// Posts `m` on connection 1, retrying `HV_STATUS_INSUFFICIENT_BUFFERS`
    /// after a `Yield` up to [`MAX_RETRIES`] times; any other failure, or
    /// the last retry's, is a panic.
    fn post<H: Hypervisor, S: System>(&mut self, m: &Msg, hv: &mut H, sys: &mut S) {
        let mut b = [0u8; msg::MAX];
        let n = m.encode(&mut b);
        let mut retries = 0;
        loop {
            match hv.post_message(msg::CONNECTION, msg::MESSAGE_TYPE, &b[..n]) {
                Status::SUCCESS => return,
                Status::INSUFFICIENT_BUFFERS if retries < MAX_RETRIES => {
                    retries += 1;
                    self.stats.retries += 1;
                    sys.yield_now();
                }
                Status::INSUFFICIENT_BUFFERS => panic!(
                    "vmbus: PostMessage of {}: the host's buffers stayed full for {MAX_RETRIES} retries",
                    m.name()
                ),
                s => panic!("vmbus: PostMessage of {}: {s}", m.name()),
            }
        }
    }
}

/// A word's low 32 bits.
const fn low(w: u64) -> u32 {
    w as u32
}
