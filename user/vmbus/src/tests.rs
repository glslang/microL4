//! vmbus against `hvmock`, the mock VMBus host (`docs/design.md`, "The
//! mock VMBus host"): the messages' encodings against the mock's own,
//! contact and its fallback, offers in any order, GPADLs and their
//! teardown, netvsc's channel and `Attach`, the event scan, the message
//! slot under a late `MessagePending`, post retries, a channel's rings
//! wrapping through the mock's loopback device, and hostile host
//! messages, counted and ignored.

mod channel;
mod codec;
mod hostile;
mod setup;

use std::string::String;
use std::vec::Vec;
use std::{format, vec};

use hvmock::{Config, Host, Machine, Page, machine};

use super::*;

/// The standard machine's arguments.
const START: Start = Start {
    channel: machine::CHANNEL,
    monitor: machine::MONITOR,
    event_flags: machine::EVENT_FLAGS,
    tsc_hz: 2_000_000_000,
};

/// netvsc's channel and connection in the mock's default offers.
const NETVSC: u32 = 14;

impl Hypervisor for Host<'_> {
    fn post_message(&mut self, connection: u32, message_type: u32, payload: &[u8]) -> Status {
        Host::post_message(self, connection, message_type, payload)
    }
    fn signal_event(&mut self, connection: u32, flag: u16) -> Status {
        Host::signal_event(self, connection, flag)
    }
    fn eom(&mut self) {
        Host::eom(self)
    }
    fn vp_index(&mut self) -> u32 {
        Host::vp_index(self)
    }
}

/// What vmbus did to the rest of the system.
#[derive(Default, Debug)]
struct Recorder {
    lines: Vec<String>,
    signals: u64,
    mints: Vec<u64>,
    revokes: u64,
    /// Each `back_off`'s wait, in milliseconds.
    back_offs: Vec<u32>,
}

impl System for Recorder {
    fn say(&mut self, note: &Note) {
        self.lines.push(format!("{note}"));
    }
    fn signal_netvsc(&mut self) {
        self.signals += 1;
    }
    fn mint(&mut self, data: u64) {
        self.mints.push(data);
    }
    fn revoke(&mut self) {
        self.revokes += 1;
    }
    fn back_off(&mut self, ms: u32) {
        self.back_offs.push(ms);
    }
}

/// vmbus, the mock host and a recorder over one machine.
struct Rig<'m> {
    m: &'m Machine,
    host: Host<'m>,
    bus: Bus<Page<'m>>,
    sys: Recorder,
}

impl<'m> Rig<'m> {
    fn new(m: &'m Machine, cfg: Config) -> Rig<'m> {
        Rig {
            m,
            host: Host::new(m, cfg),
            bus: Bus::new(START, m.sim(), m.sief()),
            sys: Recorder::default(),
        }
    }

    /// Starts vmbus and runs until nothing happens.
    fn start(&mut self) {
        self.bus.start(&mut self.host, &mut self.sys);
        self.run();
    }

    /// One turn: vmbus takes SINT 2's signal if one is raised, then the
    /// host runs. Whether anything happened.
    fn turn(&mut self) -> bool {
        let mut did = false;
        if self.m.take_interrupt() {
            self.bus.on_signal(&mut self.host, &mut self.sys);
            did = true;
        }
        did | self.host.step()
    }

    /// Turns until nothing happens; panics after 10,000.
    fn run(&mut self) {
        for _ in 0..10_000 {
            if !self.turn() {
                return;
            }
        }
        panic!("the rig never settled");
    }

    /// The text of what vmbus printed.
    fn lines(&self) -> Vec<&str> {
        self.sys.lines.iter().map(String::as_str).collect()
    }

    /// The type of each request the guest posted.
    fn kinds(&self) -> Vec<u32> {
        self.host.posts().iter().map(|p| p.kind).collect()
    }

    /// Asserts the host saw nothing it would refuse.
    fn honest(&self) {
        assert!(self.host.log().is_empty(), "{:#?}", self.host.log());
    }
}

/// The lines of a bring-up with the mock's default offers.
fn default_lines() -> Vec<String> {
    vec![
        "vmbus: version 4.0".into(),
        "vmbus: offer 1: storvsc, connection 1, monitor trigger 1".into(),
        "vmbus: offer 3: heartbeat, connection 3".into(),
        "vmbus: offer 14: netvsc, connection 14, monitor trigger 14".into(),
        format!(
            "vmbus: offer 17: {}, connection 17, monitor trigger 17",
            hvmock::wire::guid_text(&hvmock::OfferSpec::unknown(17, 17).kind)
        ),
        "vmbus: netvsc channel 14 open, connection 14".into(),
    ]
}

/// xorshift64*: small, deterministic and fast under Miri.
struct Rng(u64);

impl Rng {
    fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}
