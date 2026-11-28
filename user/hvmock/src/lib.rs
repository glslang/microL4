//! `hvmock`: the mock VMBus host (`docs/design.md`, "The mock VMBus
//! host"), host only, for the tests of `vmbus` and `netvsc`; never in the
//! root image.
//!
//! It plays the hypervisor and the host: a guest memory ([`Machine`], a
//! `libsys::mem::Ram` behind the drivers' `Memory` trait) with the SIM and
//! SIEF pages and SINT 2's interrupt line; `post_message`, `signal_event`,
//! `eom` and `vp_index` for `vmbus`'s `Hypervisor` trait; and on the host
//! side the VMBus message protocol ([`Host`]), the channels' ring buffers
//! ([`ring`]) and a pluggable device on each channel ([`device`]).
//!
//! It is written from the published protocol, on its own: the TLFS for the
//! SynIC and the hypercalls (`hv_message.md`, `hv_synic_event_flags.md`,
//! `HvCallPostMessage.md`, `HvCallSignalEvent.md`,
//! `inter-partition-communication.md`), and FreeBSD's BSD-licensed
//! `sys/dev/hyperv/vmbus` (`vmbus_reg.h`, `vmbus.c`, `vmbus_chan.c`,
//! `vmbus_br.c`, `include/vmbus.h`), read on 2026-11-27. What neither
//! says, and the mock assumes from memory of Linux's `drivers/hv`, says so
//! where it is used. It shares no code with `vmbus`, so that a layout
//! mistake on either side shows.
//!
//! A test owns a [`Machine`], makes a [`Host`] over it, and gives the
//! driver the machine's [`Machine::sim`] and [`Machine::sief`] windows
//! and the host behind an adapter for the driver's own trait. Its loop
//! takes SINT 2's edge ([`Machine::take_interrupt`]) as the driver's
//! notification would, and lets the host run ([`Host::step`]) until
//! neither does anything.
//!
//! **netvsc's device** plugs in at [`Device`]: `Host::attach(channel,
//! Box::new(device))` before the guest opens the channel; the host calls
//! [`Device::opened`], then [`Device::signalled`] after each guest signal
//! and [`Device::poll`] on each step, with a [`Chan`] that reads the
//! outbound ring, writes the inbound one by FreeBSD's signal rule, and
//! finds the receive and send buffers' GPADLs. netvsc's restricted
//! capability signals through [`Host::signal_restricted`] with the
//! [`Restriction`] vmbus minted.

#![forbid(unsafe_code)]

pub mod device;
mod host;
pub mod machine;
pub mod ring;
#[cfg(test)]
mod tests;
pub mod wire;

pub use device::{Chan, Device, Loopback};
pub use host::{
    ChannelState, Config, Contact, Gpadl, Host, OfferSpec, Opened, Posted, REFUSED, guid, version,
};
pub use libsys::hyperv::{Restriction, Status};
pub use machine::{Machine, Page, View};
