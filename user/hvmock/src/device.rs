//! The device side of a channel: a [`Device`] attached to an offer runs
//! on the channel's rings once the guest opens it, through a [`Chan`].
//!
//! This is where netvsc's device plugs in: it implements [`Device`],
//! reads what the guest writes in the outbound ring with [`Chan::recv`],
//! answers with [`Chan::send`], finds the receive and send buffers'
//! GPADLs with [`Chan::gpadl`], and reads any guest page a GPA packet
//! names through [`Chan::machine`]. [`Loopback`] is the smallest device:
//! it sends back every packet the guest writes.

use std::collections::VecDeque;

use libsys::mem::Memory;

use crate::host::{ChannelState, Gpadl, OfferSpec, signal_guest};
use crate::machine::{Machine, View};
use crate::ring::{Broken, Full, Packet, Ring};

/// A device on a channel. The host calls it from [`crate::Host::step`]:
/// `signalled` when the guest signalled the channel since the last step,
/// then `poll` on every step.
pub trait Device {
    /// The guest opened the channel: its rings are zero, as the guest left
    /// them.
    fn opened(&mut self, _ch: &Chan<'_>) {}
    /// The guest signalled the channel: drain the outbound ring.
    fn signalled(&mut self, ch: &Chan<'_>);
    /// The host's turn: send what waits. Returns whether it did anything.
    fn poll(&mut self, _ch: &Chan<'_>) -> bool {
        false
    }
    /// What the device has seen go wrong, for a test to assert none.
    fn faults(&self) -> &[String] {
        &[]
    }
}

/// An open channel, as its device reaches it.
pub struct Chan<'a> {
    m: &'a Machine,
    state: &'a ChannelState,
    gpadls: &'a std::collections::BTreeMap<u32, Gpadl>,
    ring_pages: &'a [u64],
    outbound: usize,
}

impl<'a> Chan<'a> {
    pub(crate) fn new(
        m: &'a Machine,
        state: &'a ChannelState,
        gpadls: &'a std::collections::BTreeMap<u32, Gpadl>,
    ) -> Chan<'a> {
        let open = state.open.expect("an open channel");
        let ring_pages = &gpadls.get(&open.gpadl).expect("the ring's GPADL").pages;
        Chan {
            m,
            state,
            gpadls,
            ring_pages,
            outbound: open.outbound_pages as usize,
        }
    }

    pub fn id(&self) -> u32 {
        self.state.offer.channel
    }

    pub fn offer(&self) -> &OfferSpec {
        &self.state.offer
    }

    /// Guest memory, for the pages a GPA packet names.
    pub fn machine(&self) -> &'a Machine {
        self.m
    }

    /// The outbound ring, guest to host: the ring GPADL's first
    /// `chm_txbr_pgcnt` pages.
    pub fn outbound(&self) -> Ring<View<'a>> {
        Ring::new(self.m.view(&self.ring_pages[..self.outbound]))
    }

    /// The inbound ring, host to guest: the rest.
    pub fn inbound(&self) -> Ring<View<'a>> {
        Ring::new(self.m.view(&self.ring_pages[self.outbound..]))
    }

    /// A GPADL the guest made on this channel, as one window of its
    /// pages.
    pub fn gpadl(&self, handle: u32) -> Option<View<'a>> {
        let g = self.gpadls.get(&handle)?;
        (g.channel == self.id()).then(|| self.m.view(&g.pages))
    }

    /// Reads the next packet the guest wrote, moving the read index; then,
    /// if the guest waits for room and now has it, signals the guest.
    pub fn recv(&self) -> Result<Option<Packet>, Broken> {
        let ring = self.outbound();
        let p = ring.read()?;
        if let Some(p) = &p
            && ring.reader_should_signal(p.bytes.len() + crate::ring::TRAILER)
        {
            self.signal_guest();
        }
        Ok(p)
    }

    /// Writes a packet for the guest; signals it by FreeBSD's rule, only
    /// if the ring was empty and the guest's interrupt mask is 0. With no
    /// room, asks the guest for a signal once there is (the pending send
    /// size) and returns `Full`; a later write that fits clears it.
    pub fn send(&self, kind: u16, flags: u16, xid: u64, body: &[u8]) -> Result<(), Full> {
        let ring = self.inbound();
        match ring.write(kind, flags, xid, body) {
            Ok(w) => {
                if ring.pending_send_size() != 0 {
                    ring.set_pending_send_size(0);
                }
                if w.was_empty && ring.interrupt_mask() == 0 {
                    self.signal_guest();
                }
                Ok(())
            }
            Err(full) => {
                ring.set_pending_send_size(full.need as u32 + 1);
                Err(full)
            }
        }
    }

    /// Sets the channel's flag in the SIEF and raises SINT 2 if it was
    /// clear.
    pub fn signal_guest(&self) {
        signal_guest(self.m, self.id());
    }
}

/// A device that sends every packet back: inband, with the packet's
/// transaction ID and body.
#[derive(Debug, Default)]
pub struct Loopback {
    /// Packets taken and sent back.
    pub taken: u64,
    pub sent: u64,
    waiting: VecDeque<Packet>,
    faults: Vec<String>,
}

impl Device for Loopback {
    fn signalled(&mut self, ch: &Chan<'_>) {
        loop {
            match ch.recv() {
                Ok(Some(p)) => {
                    self.taken += 1;
                    self.waiting.push_back(p);
                }
                Ok(None) => break,
                Err(e) => {
                    self.faults.push(format!("outbound ring broken: {e:?}"));
                    break;
                }
            }
        }
    }

    fn poll(&mut self, ch: &Chan<'_>) -> bool {
        let mut did = false;
        while let Some(p) = self.waiting.front() {
            if ch
                .send(crate::ring::kind::INBAND, 0, p.xid, p.body())
                .is_err()
            {
                break;
            }
            self.waiting.pop_front();
            self.sent += 1;
            did = true;
        }
        did
    }

    fn faults(&self) -> &[String] {
        &self.faults
    }
}

/// Reads `len` bytes at `offset` of a window: a convenience for devices.
pub fn read_bytes(w: &impl Memory, offset: usize, len: usize) -> Vec<u8> {
    let mut v = vec![0; len];
    w.read(offset, &mut v);
    v
}
