//! `netvsc`: the driver of Hyper-V's synthetic network adapter
//! (`docs/design.md`, "`netvsc`" under "Networking").
//!
//! On Hyper-V, root starts `netvsc` with its channel frame mapped at
//! [`layout::CHANNEL`] (and, with `netvsc.mnf=1`, the monitor and
//! event-flags pages at [`layout::MNF`]), the frame queues' original at
//! `libsys::frames::WINDOW`, and its notification bound to `vmbus`'s
//! `CHANNEL` and `net`'s `FRAMES` signals. `netvsc` asks `vmbus` for its
//! channel (`Attach`), then speaks NVSP and RNDIS over the channel's rings:
//! NVSP 5, 4 or 2, the NDIS version, the receive and send buffers, RNDIS's
//! initialisation, the permanent MAC, the link and the packet filter. Then
//! it copies every frame between the host's buffers and the frame queues
//! it shares with `net`: received frames out of the receive buffer's
//! sections into `RX_FILLED`, frames to send out of `TX_FILLED` into a
//! section of the send buffer. The protocol is FreeBSD's `hn(4)`
//! (`sys/dev/hyperv/netvsc/if_hnreg.h`, `hn_nvs.c`, `hn_nvs.h`,
//! `hn_rndis.c`, `if_hn.c`, and `sys/net/rndis.h`, read 2026-11-28).
//!
//! Everything that decides is here, generic over `libsys::mem`'s
//! [`Memory`] (the channel frame, the monitor pages and the frame queues)
//! and [`Signal`] (the one hypercall its restricted capability allows),
//! and host-tested against `hvmock`'s netvsc device; [`run`], the server
//! loop, exists only on the user target.
//!
//! - [`ring`]: the channel's two rings in the channel frame, packets,
//!   transaction IDs and completions.
//! - [`nvs`]: NVSP's messages: INIT and its versions, the NDIS version,
//!   the receive and send buffers and their sections, RNDIS packets and
//!   their acknowledgements.
//! - [`rndis`]: RNDIS's messages: initialisation, queries, the packet
//!   filter, data packets with their per-packet information, status
//!   indications.
//! - [`Adapter`]: the setup and the copies, driven by signals.
//!
//! Nothing the host writes is taken on trust: every index, packet length
//! and type, range, section index, offset and transaction ID is checked
//! before use, and what fails is counted and refused, never followed. The
//! only pages `netvsc` names to the host are its request page, in a GPA
//! packet, and its sections, by index.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod adapter;
pub mod nvs;
pub mod ring;
pub mod rndis;
#[cfg(target_os = "none")]
mod run;
#[cfg(test)]
mod tests;

use core::fmt;

pub use adapter::{ACKS, Adapter, Failure, Note, Ring, Step, Why};
pub use libsys::hyperv::Status;
pub use libsys::mem::Memory;
use libsys::proto::{Refusal, VmbusAttach, label};
#[cfg(target_os = "none")]
pub use run::run;

/// The bits `vmbus` and `net` signal netvsc's notification NH with:
/// `CHANNEL` (bit 32) for an event on its channel, `FRAMES` (bit 33) for a
/// batch of the frame queues (`docs/design.md`, "Where the network servers
/// run").
pub use libsys::proto::{CHANNEL, FRAMES};

/// netvsc's CSpace: a 16-slot CNode with guard 0 of size 60, so `CPtr` `n`
/// is slot `n` (`docs/design.md`, "Capabilities" under "Where the network
/// servers run").
pub mod slot {
    /// Slots in netvsc's CNode, and its radix and guard.
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, with the same guard, to name its receive slot.
    pub const CNODE: u64 = 1;
    /// Endpoint NS, netvsc's requests, with Read: root's `Stats`.
    pub const ENDPOINT: u64 = 2;
    /// Endpoint VB, with Write and GrantReply, badge 1: `vmbus`'s client.
    pub const VMBUS: u64 = 3;
    /// net's notification NN, with Write and badge `FRAMES`.
    pub const NET_NTFN: u64 = 4;
    /// Endpoint F, netvsc's fault endpoint, badge `NETVSC` (6).
    pub const FAULT: u64 = 5;
    /// Endpoint C, console's, badge 7: netvsc's log lines.
    pub const CONSOLE: u64 = 6;
    /// Empty at start: receives the restricted Hypervisor capability in
    /// `Attach`'s reply, which may only signal netvsc's connection.
    pub const HYPERVISOR: u64 = 7;
}

/// Where things are: netvsc's windows, and its channel frame by page
/// (`docs/design.md`, "The channel frame"). `vmbus::layout` names the same
/// pages to the host in its GPADLs; a test checks the two agree.
pub mod layout {
    /// A page.
    pub const PAGE: usize = 4096;

    /// The channel frame's window: one 2 MiB RAM frame, read-write,
    /// write-back.
    pub const CHANNEL: u64 = 0x0800_0000;
    pub const CHANNEL_SIZE: usize = 512 * PAGE;

    /// The outbound ring, guest to host: pages 0 to 15, a control page
    /// and 60 KiB of data.
    pub const OUTBOUND: usize = 0;
    pub const OUTBOUND_PAGES: usize = 16;
    /// The inbound ring, host to guest: pages 16 to 31, the same.
    pub const INBOUND: usize = 16 * PAGE;
    pub const INBOUND_PAGES: usize = 16;
    /// The RNDIS control request page, page 32, named by a GPA packet.
    pub const REQUEST_PAGE: u64 = 32;
    pub const REQUEST: usize = REQUEST_PAGE as usize * PAGE;
    /// The send buffer (`chimney`), pages 64 to 255: 768 KiB.
    pub const SEND: usize = 64 * PAGE;
    pub const SEND_SIZE: usize = 192 * PAGE;
    /// The receive buffer, pages 256 to 511: 1 MiB.
    pub const RECEIVE: usize = 256 * PAGE;
    pub const RECEIVE_SIZE: usize = 256 * PAGE;

    /// The monitor window, mapped only with `netvsc.mnf=1`: two pages, in
    /// the order root's one `Untyped_Retype` placed them, monitor page 2
    /// (the guest-to-host one) then the event-flags page.
    pub const MNF: u64 = 0x0A00_0000;
    pub const MNF_SIZE: usize = 2 * PAGE;
    /// Monitor page 2 in the window: trigger group `g`'s `mt_pending` at
    /// `8 + 8 g` (FreeBSD's `struct vmbus_mnf`).
    pub const MNF_MONITOR: usize = 0;
    /// The event-flags page in the window: the guest-to-host half from
    /// byte 2,048, bit `relid` for channel `relid`.
    pub const MNF_EVENT_FLAGS: usize = PAGE;

    const _: () = {
        assert!(INBOUND == OUTBOUND + OUTBOUND_PAGES * PAGE);
        assert!(REQUEST >= INBOUND + INBOUND_PAGES * PAGE);
        assert!(SEND >= REQUEST + PAGE);
        assert!(RECEIVE == SEND + SEND_SIZE);
        assert!(RECEIVE + RECEIVE_SIZE == CHANNEL_SIZE);
    };
}

/// Root's arguments (`docs/design.md`, "Arguments"): `rdi` the channel
/// frame's physical base, `rsi` 1 with `netvsc.mnf=1`, else 0; `rdx` and
/// `rcx` 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Start {
    /// The channel frame's physical base, 2 MiB-aligned: the request
    /// page's number in a GPA packet is computed from it.
    pub channel: u64,
    /// Signal the host through the monitor page and event flags, as
    /// FreeBSD's `vmbus_chan_signal` does, rather than `SignalEvent`.
    pub mnf: bool,
}

impl Start {
    /// Physical addresses lie below 2^52.
    pub const PHYSICAL: u64 = 1 << 52;

    pub const fn to_words(&self) -> [u64; 4] {
        [self.channel, self.mnf as u64, 0, 0]
    }

    /// The arguments in `w`, or `None` for words root never passes: a
    /// channel base of 0, not 2 MiB-aligned or whose frame reaches 2^52;
    /// an `rsi` other than 0 or 1; a non-zero `rdx` or `rcx`.
    pub fn from_words(w: [u64; 4]) -> Option<Start> {
        let [channel, mnf, rdx, rcx] = w;
        let size = layout::CHANNEL_SIZE as u64;
        let frame_ok = channel != 0
            && channel % size == 0
            && channel
                .checked_add(size)
                .is_some_and(|end| end <= Self::PHYSICAL);
        (frame_ok && mnf <= 1 && rdx == 0 && rcx == 0).then_some(Start {
            channel,
            mnf: mnf == 1,
        })
    }

    /// The page number of the channel frame's page `page`.
    pub const fn channel_page(&self, page: u64) -> u64 {
        self.channel / layout::PAGE as u64 + page
    }
}

/// The hypercall netvsc's restricted Hypervisor capability (slot 7)
/// allows: on the target `libsys::hyperv::signal_event`, in the tests the
/// mock host's, which fails a test that signals another connection.
pub trait Signal {
    /// `Hypervisor_SignalEvent(connection, 0)`: the host's status. A
    /// failed invocation is a panic in the implementation, since netvsc
    /// signals only the connection its capability names.
    fn signal_event(&mut self, connection: u32) -> Status;
}

/// A request on endpoint NS: only `Stats` (`0x170`), with no words, from
/// any badge.
pub fn request(label: u64, length: usize) -> Result<(), Refusal> {
    match (label, length) {
        (label::NETVSC_STATS, 0) => Ok(()),
        (label::NETVSC_STATS, _) => Err(Refusal::BadLength),
        _ => Err(Refusal::BadLabel),
    }
}

/// Why `vmbus`'s answer to `Attach` was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AttachError {
    /// vmbus refused: `Unavailable` with no netvsc channel.
    Refused(Refusal),
    /// A reply whose label, length or words vmbus never sends.
    BadReply { label: u64, length: u64 },
    /// The reply carried no capability into slot 7.
    NoCapability,
}

impl fmt::Display for AttachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            AttachError::Refused(Refusal::Unavailable) => {
                f.write_str("vmbus has no netvsc channel (Unavailable)")
            }
            AttachError::Refused(r) => write!(f, "vmbus refused Attach: {r}"),
            AttachError::BadReply { label, length } => write!(
                f,
                "vmbus answered Attach with label {label:#x} and length {length}"
            ),
            AttachError::NoCapability => f.write_str("vmbus's Attach reply carried no capability"),
        }
    }
}

/// Reads `vmbus`'s answer to `Attach`: its label, its words, and whether a
/// capability was copied into slot 7. A success has label 0, eight words
/// that [`VmbusAttach::from_words`] takes, and the capability.
pub fn attach_reply(label: u64, words: &[u64], copied: bool) -> Result<VmbusAttach, AttachError> {
    if let Some(r) = Refusal::from_label(label) {
        return Err(AttachError::Refused(r));
    }
    let bad = AttachError::BadReply {
        label,
        length: words.len() as u64,
    };
    if label != 0 {
        return Err(bad);
    }
    let w: [u64; VmbusAttach::WORDS] = words.try_into().map_err(|_| bad)?;
    let a = VmbusAttach::from_words(w).ok_or(bad)?;
    if !copied {
        return Err(AttachError::NoCapability);
    }
    Ok(a)
}
