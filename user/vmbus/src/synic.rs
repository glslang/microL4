//! The SynIC's message slot and event flags for SINT 2 (`docs/abi.md`,
//! "SynIC frames"; TLFS `hv_message.md`, `hv_synic_event_flags.md`,
//! `inter-partition-communication.md`).
//!
//! VMBus sends both its channel messages and its channel events on SINT 2
//! (`VMBUS_SINT_MESSAGE`): a message in the SIM's slot 2, at offset 512,
//! an event as bit `relid` of the SIEF's slot 2, at offset 512, 2,048
//! flags. Both pages are the hypervisor's, which writes them at any time,
//! so they are reached only through [`Memory`]'s atomic accesses and
//! volatile copies, never a reference.

use core::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release, SeqCst};

use libsys::hyperv::synic;
use libsys::mem::Memory;

use crate::Hypervisor;

/// VMBus's SINT (`VMBUS_SINT_MESSAGE`, FreeBSD's "DO NOT CHANGE THIS").
pub const SINT: usize = 2;
/// A slot, in either page.
pub const SLOT_SIZE: usize = synic::SLOT_SIZE;
/// SINT 2's slot, in either page.
pub const SLOT: usize = synic::slot(SINT);
/// A page.
pub const PAGE: usize = 4096;
/// A message's most payload bytes.
pub const MAX_PAYLOAD: usize = synic::MAX_PAYLOAD;
/// 64-bit words of flags in a SIEF slot.
pub const FLAG_WORDS: usize = synic::FLAGS / 64;

/// A copy of the message slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Message {
    /// `MessageType`, never 0.
    pub kind: u32,
    /// `PayloadSize` as the hypervisor wrote it; [`Message::payload`]
    /// refuses one over 240.
    pub size: u8,
    /// `MessageFlags` as copied.
    pub flags: u8,
    pub origination: u64,
    pub bytes: [u8; MAX_PAYLOAD],
}

impl Message {
    /// The payload, or `None` if `PayloadSize` exceeds 240.
    pub fn payload(&self) -> Option<&[u8]> {
        self.bytes.get(..usize::from(self.size))
    }
}

/// What [`take`] did.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Taken {
    pub message: Message,
    /// `MessagePending` read set after the fence, so `Eom` was invoked.
    pub eom: bool,
}

/// Takes the message in slot 2, if there is one: copies it, writes
/// `MessageType` 0, a full fence, then reads `MessageFlags` again and
/// invokes `Hypervisor_Eom` if `MessagePending` is set, since the
/// hypervisor may set it at delivery or at any time after, and the copy's
/// value is not enough (FreeBSD's `vmbus_msg_task`). The hypervisor
/// writes a message only into an empty slot, and `Eom` may already have
/// put the next one there, so the caller loops until this finds the slot
/// empty.
///
/// The copy is the header and the payload's first `PayloadSize` bytes, at
/// most 240, rounded up to whole words, each word one 64-bit atomic load
/// (the TLFS lets the hypervisor copy only the payload's bytes, so the
/// rest of the slot is stale); the bytes past `PayloadSize` read 0.
pub fn take<M: Memory, H: Hypervisor>(sim: &M, hv: &mut H) -> Option<Taken> {
    if sim.load32(SLOT + synic::MESSAGE_TYPE, Acquire) == 0 {
        return None;
    }
    let head = sim.load64(SLOT, Relaxed);
    let size = (head >> 32) as u8;
    let mut bytes = [0u8; MAX_PAYLOAD];
    let words = usize::from(size).min(MAX_PAYLOAD).div_ceil(8);
    for (i, w) in bytes
        .as_chunks_mut::<8>()
        .0
        .iter_mut()
        .take(words)
        .enumerate()
    {
        *w = sim
            .load64(SLOT + synic::PAYLOAD + 8 * i, Relaxed)
            .to_le_bytes();
    }
    if let Some(past) = bytes.get_mut(usize::from(size)..) {
        past.fill(0);
    }
    let message = Message {
        kind: head as u32,
        size,
        flags: (head >> 40) as u8,
        origination: sim.load64(SLOT + synic::ORIGIN, Relaxed),
        bytes,
    };
    sim.store32(SLOT + synic::MESSAGE_TYPE, 0, Release);
    sim.fence(SeqCst);
    let eom = sim.load8(SLOT + synic::MESSAGE_FLAGS, Relaxed) & synic::MESSAGE_PENDING != 0;
    if eom {
        hv.eom();
    }
    Some(Taken { message, eom })
}

/// Clears slot 2's event flags in words `0..words` (at most 32), each
/// with one atomic swap, and calls `f` with the number of each flag that
/// was set, lowest first (FreeBSD's `vmbus_event_flags_proc`). A word
/// that reads 0 is not swapped.
pub fn events<M: Memory>(sief: &M, words: usize, mut f: impl FnMut(u32)) {
    for w in 0..words.min(FLAG_WORDS) {
        let at = SLOT + 8 * w;
        if sief.load64(at, Relaxed) == 0 {
            continue;
        }
        let mut bits = sief.swap64(at, 0, AcqRel);
        while bits != 0 {
            let b = bits.trailing_zeros();
            bits &= bits - 1;
            f(64 * w as u32 + b);
        }
    }
}

/// The words [`events`] scans for channel IDs up to `max`: up to the word
/// of the highest, and at least word 0.
pub const fn words_for(max: u32) -> usize {
    max as usize / 64 + 1
}
