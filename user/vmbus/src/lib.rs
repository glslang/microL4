//! `vmbus`: the VMBus driver (`docs/design.md`, "`vmbus`" under
//! "Networking").
//!
//! On Hyper-V, root starts `vmbus` with the SynIC's message and event-flag
//! frames (slots 13 and 14) mapped at [`layout::SYNIC`], an unrestricted
//! copy of the Hypervisor capability, and SINT 2's handler bound to its
//! notification. `vmbus` makes contact (VMBus 4.0, then 3.0, then 2.4, on
//! connection 1), takes the host's channel offers, builds the GPADLs of
//! netvsc's channel frame and opens its channel, then answers netvsc's
//! `Attach` with the channel's IDs and a Hypervisor capability narrowed
//! to signalling its connection, and relays the channel's events to
//! netvsc's notification. The protocol is FreeBSD's
//! (`sys/dev/hyperv/vmbus/vmbus.c`, `vmbus_chan.c`, `vmbus_reg.h`,
//! `vmbus_var.h`, `include/vmbus.h`, read 2026-11-27).
//!
//! Everything that decides is here, generic over `libsys::mem`'s
//! [`Memory`] (the two SynIC pages), [`Hypervisor`] (the four
//! invocations) and [`System`] (console lines, the signal to netvsc, the
//! Mint and its revocation, and `Yield`), and host-tested against
//! `hvmock`, the mock VMBus host; [`run`], the server loop, exists only on
//! the user target.
//!
//! - [`Bus::start`] posts the first CONNECT and services the message slot
//!   and event flags once, since a SINT before binding signalled nothing.
//! - [`Bus::on_signal`] runs for every SINT 2 signal: the event flags
//!   first, then the message slot ([`synic`]), as FreeBSD's
//!   `vmbus_handle_intr1` does.
//! - [`Bus::request`] answers `Attach` and `Stats` ([`decode`] checks the
//!   label and badge first); [`Bus::release`] answers a saved `Attach`
//!   once the channel is open, or setup has stopped.
//!
//! Nothing the host writes is taken on trust: every message's type and
//! size, every offer's channel and connection IDs, and every answer's IDs
//! are checked before use ([`msg`], [`offer`]), and what fails is counted
//! and ignored, never followed. Every page `vmbus` names to the host is
//! computed from root's arguments ([`Start`]) and [`layout`].

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod bus;
pub mod gpadl;
pub mod msg;
pub mod offer;
#[cfg(target_os = "none")]
mod run;
pub mod synic;
#[cfg(test)]
mod tests;

pub use bus::{Answer, Bus, Note, Request, Step, decode};
pub use libsys::hyperv::Status;
pub use libsys::mem::Memory;
#[cfg(target_os = "none")]
pub use run::run;

/// vmbus's CSpace: a 16-slot CNode with guard 0 of size 60, so `CPtr` `n`
/// is slot `n` (`docs/design.md`, "Capabilities" under "Where the network
/// servers run").
pub mod slot {
    /// Slots in vmbus's CNode, and its radix and guard.
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, with the same guard, for `CNode_SaveCaller` and
    /// `CNode_Mint`.
    pub const CNODE: u64 = 1;
    /// Endpoint VB, vmbus's requests, with Read and Grant: its replies
    /// carry netvsc's Hypervisor capability.
    pub const ENDPOINT: u64 = 2;
    /// The Hypervisor capability, a copy of root's slot 12, unrestricted.
    pub const HYPERVISOR: u64 = 3;
    /// netvsc's notification NH, with Write and badge `CHANNEL`.
    pub const NETVSC_NTFN: u64 = 4;
    /// Endpoint F, vmbus's fault endpoint, badge `VMBUS` (5).
    pub const FAULT: u64 = 5;
    /// Endpoint C, console's, badge 6: vmbus's log lines.
    pub const CONSOLE: u64 = 6;
    /// netvsc's saved `Attach`: a reply capability.
    pub const SAVED: u64 = 7;
    /// The Hypervisor capability vmbus mints for netvsc's channel, kept as
    /// the original of every copy netvsc gets.
    pub const MINTED: u64 = 8;
}

/// Where things are: vmbus's SynIC window, and netvsc's channel frame by
/// page, which vmbus names to the host in its GPADLs. `netvsc::layout`
/// maps the same frame and must agree with [`RING`], [`OUTBOUND_PAGES`],
/// [`SEND`] and [`RECEIVE`].
pub mod layout {
    use crate::gpadl::Pages;

    /// A page.
    pub const PAGE: u64 = 4096;
    /// The SynIC window: the SIM frame (slot 13) at [`SIM`] and the SIEF
    /// frame (slot 14) at [`SIEF`], each read-write, write-back.
    pub const SYNIC: u64 = 0x0800_0000;
    pub const SIM: u64 = SYNIC;
    pub const SIEF: u64 = SYNIC + PAGE;
    /// The channel frame: one 2 MiB RAM frame.
    pub const CHANNEL_PAGES: u64 = 512;
    /// The ring's GPADL: the outbound ring (guest to host) in its first
    /// [`OUTBOUND_PAGES`], the inbound ring in the rest, each a control
    /// page and 60 KiB of data.
    pub const RING: Pages = Pages {
        first: 0,
        count: 32,
    };
    /// `chm_txbr_pgcnt`: the outbound ring comes first.
    pub const OUTBOUND_PAGES: u32 = 16;
    /// The send buffer's GPADL (`chimney`), 768 KiB.
    pub const SEND: Pages = Pages {
        first: 64,
        count: 192,
    };
    /// The receive buffer's GPADL, 1 MiB.
    pub const RECEIVE: Pages = Pages {
        first: 256,
        count: 256,
    };
}

/// `Hypervisor_PostMessage`s of one message before vmbus panics, as
/// FreeBSD's `vmbus_msghc_exec` makes them (`HC_RETRY_MAX`,
/// `sys/dev/hyperv/vmbus/vmbus.c`): whatever the status, it posts at most
/// 20 times, waiting 1 ms after the first failure and twice as long after
/// each while the wait is under 2 s, so 1 ms to 2,048 ms, which lets a
/// busy host's buffers drain; about 18 s of waits in all.
pub const MAX_POSTS: u32 = 20;
/// The wait after the first failed post, in milliseconds.
pub const FIRST_BACK_OFF_MS: u32 = 1;
/// A wait under this many milliseconds doubles for the next.
pub const DOUBLE_BELOW_MS: u32 = 2000;

/// The Hypervisor capability's four invocations (`docs/abi.md`,
/// "Hypervisor"), on the unrestricted capability in slot 3. On the target
/// they are `libsys::hyperv`'s; in the tests, the mock host's. A failed
/// invocation is a panic in the implementation, since vmbus's arguments
/// are always in range; a hypercall's refusal is its [`Status`], of which
/// vmbus retries only `HV_STATUS_INSUFFICIENT_BUFFERS`.
pub trait Hypervisor {
    /// `Hypervisor_PostMessage`: `payload`, at most 240 bytes, as a
    /// message of `message_type` on `connection`; the `HV_STATUS`.
    fn post_message(&mut self, connection: u32, message_type: u32, payload: &[u8]) -> Status;
    /// `Hypervisor_SignalEvent`: flag `flag` of `connection`; the
    /// `HV_STATUS`. vmbus itself never signals: netvsc does, on its own
    /// capability.
    fn signal_event(&mut self, connection: u32, flag: u16) -> Status;
    /// `Hypervisor_Eom`: the hypervisor may deliver the next message.
    fn eom(&mut self);
    /// `Hypervisor_VpIndex`: this processor's VP index.
    fn vp_index(&mut self) -> u32;
}

/// What vmbus does to the rest of the system: on the target, `libsys`
/// calls on its slots; in the tests, a recorder.
pub trait System {
    /// One line through console ([`Note`]'s text).
    fn say(&mut self, note: &Note);
    /// Signals netvsc's notification NH with `CHANNEL` (slot 4).
    fn signal_netvsc(&mut self);
    /// `CNode_Mint` of slot 3 into slot 8 with `data`, the narrowing
    /// ([`Bus::mint_data`]).
    fn mint(&mut self, data: u64);
    /// Revokes slot 8 and deletes it: netvsc's copies go too.
    fn revoke(&mut self);
    /// Waits `ms` milliseconds before a `PostMessage` retry.
    fn back_off(&mut self, ms: u32);
}

/// Root's arguments (`docs/design.md`, "Arguments"): the physical bases of
/// netvsc's channel frame, of the two monitor pages and of the event-flags
/// page in `rdi`, `rsi` and `rdx`, and BootInfo's `tsc_hz` in `rcx`, which
/// times the waits between `PostMessage` retries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Start {
    /// The channel frame's physical base, 2 MiB-aligned.
    pub channel: u64,
    /// Monitor page 1's physical address; monitor page 2 follows it.
    pub monitor: u64,
    /// The event-flags page's: the page after monitor page 2, since root
    /// retypes the three in one `Untyped_Retype`.
    pub event_flags: u64,
    /// The time-stamp counter's rate, BootInfo's `tsc_hz`; 0 if the
    /// kernel did not measure it.
    pub tsc_hz: u64,
}

impl Start {
    /// Physical addresses lie below 2^52.
    pub const PHYSICAL: u64 = 1 << 52;
    /// The channel frame's size and alignment.
    pub const CHANNEL_SIZE: u64 = layout::CHANNEL_PAGES * layout::PAGE;

    pub const fn to_words(&self) -> [u64; 4] {
        [self.channel, self.monitor, self.event_flags, self.tsc_hz]
    }

    /// The arguments in `w`, or `None` for words root never passes: a
    /// channel base of 0, not 2 MiB-aligned or whose frame reaches 2^52;
    /// a monitor page of 0, not page-aligned or reaching 2^52; an
    /// event-flags page that is not the page after monitor page 2; any of
    /// those three pages inside the channel frame. Any `tsc_hz` is taken.
    pub fn from_words(w: [u64; 4]) -> Option<Start> {
        let [channel, monitor, event_flags, tsc_hz] = w;
        let page = layout::PAGE;
        let frame_ok = channel != 0
            && channel % Self::CHANNEL_SIZE == 0
            && channel
                .checked_add(Self::CHANNEL_SIZE)
                .is_some_and(|end| end <= Self::PHYSICAL);
        let pages_ok = monitor != 0
            && monitor % page == 0
            && monitor
                .checked_add(3 * page)
                .is_some_and(|end| end <= Self::PHYSICAL)
            && event_flags == monitor + 2 * page;
        // The three pages are consecutive, so they meet the frame only if
        // one of their ends falls inside it.
        let apart = monitor + 3 * page <= channel || monitor >= channel + Self::CHANNEL_SIZE;
        (frame_ok && pages_ok && apart).then_some(Start {
            channel,
            monitor,
            event_flags,
            tsc_hz,
        })
    }

    /// The page number of the channel frame's page `page`.
    pub const fn channel_page(&self, page: u64) -> u64 {
        self.channel / layout::PAGE + page
    }

    /// Monitor page 2's physical address: the guest-to-host page, whose
    /// trigger groups netvsc sets with `netvsc.mnf=1`.
    pub const fn monitor2(&self) -> u64 {
        self.monitor + layout::PAGE
    }
}

/// A VMBus version word as FreeBSD's `VMBUS_VERSION_*` builds it.
pub const fn version(major: u32, minor: u32) -> u32 {
    major << 16 | minor
}

/// The versions vmbus offers, best first: WIN10 (4.0), WIN8_1 (3.0) and
/// WIN8 (2.4). Not WIN7 or WS2008, whose events come through the
/// event-flags page and, for WS2008, all on connection 2, nor WIN10 V5
/// (5.0), which FreeBSD defines but does not offer.
pub const VERSIONS: [u32; 3] = [version(4, 0), version(3, 0), version(2, 4)];
