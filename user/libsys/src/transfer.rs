//! Messages with words past MR3 and extra capabilities, and what a receive
//! says about the capabilities it got (`docs/abi.md`, "Messages",
//! "Capability transfer" and "IPC buffer semantics").
//!
//! A send names up to three capabilities by `CPtr` in the IPC buffer's
//! `caps_or_badges` and says how many in `extra_caps`; [`compose`] lays
//! the message and the pointers out. Capabilities move only if the
//! sender's capability has Grant (for a reply, the reply capability's
//! Grant, which is the Grant of the capability the call was received on),
//! the sender has a readable IPC buffer and the receiver a writable one.
//! Each capability to the endpoint the message goes through is unwrapped:
//! its badge lands in the receiver's `caps_or_badges[i]` and bit `i` of
//! `caps_unwrapped` is set. Of the others, at most one is copied, into the
//! receive slot ([`Ipc::set_receive_slot`]) if it is empty; the first that
//! can be neither unwrapped nor copied ends the transfer. Nothing is
//! reported but the received `extra_caps`, which [`ReceivedCaps`] reads
//! with the rest.

use l4core::ipc::{MSG_MAX_EXTRA_CAPS, MSG_MAX_LENGTH, MSG_REG_COUNT, MessageInfo};

use crate::syscall::{CPtr, Ipc, Message};

/// Lays a message out as the kernel reads it: `label`, `words` as MR0 and
/// up (MR0 to MR3 in the returned [`Message`], MR4 and up in `ipc`'s
/// message words) and `caps` in `ipc`'s `caps_or_badges`, with `length`
/// and `extra_caps` to match. `ipc` is the sending thread's IPC buffer; it
/// may be `None` only for at most four `words` and no `caps`. Panics past
/// 120 words or three capabilities, or without a buffer it needs.
pub fn compose(ipc: Option<Ipc>, label: u64, words: &[u64], caps: &[CPtr]) -> Message {
    assert!(
        words.len() <= MSG_MAX_LENGTH,
        "{} message registers",
        words.len()
    );
    assert!(
        caps.len() <= MSG_MAX_EXTRA_CAPS,
        "{} extra caps",
        caps.len()
    );
    let buffer = || ipc.expect("this message needs the sender's IPC buffer");
    let mut mr = [0; MSG_REG_COUNT];
    for (i, &w) in words.iter().enumerate() {
        match mr.get_mut(i) {
            Some(r) => *r = w,
            None => buffer().set_mr(i, w),
        }
    }
    if !caps.is_empty() {
        buffer().set_caps(caps);
    }
    let info = MessageInfo::new(label, 0, caps.len() as u64, words.len() as u64);
    Message::new(info, mr)
}

impl Ipc {
    /// [`compose`] with this buffer.
    pub fn compose(self, label: u64, words: &[u64], caps: &[CPtr]) -> Message {
        compose(Some(self), label, words, caps)
    }

    /// Word `i` of a received message `msg`: MR0 to MR3 from its registers,
    /// the rest from this buffer. Panics past `msg`'s length.
    pub fn received_word(self, msg: &Message, i: usize) -> u64 {
        let length = msg.info.length() as usize;
        assert!(i < length, "word {i} of a {length}-word message");
        match msg.mr.get(i) {
            Some(&w) => w,
            None => self.mr(i),
        }
    }
}

/// How capability `i` of a received message arrived.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Arrival {
    /// It was a capability to the endpoint the message came through; this
    /// is its badge, 0 if it had none.
    Unwrapped(u64),
    /// It was copied into the receive slot.
    Copied,
}

/// What a received message says about its extra capabilities: the
/// received `MessageInfo`'s `extra_caps` (how many the kernel processed
/// before the transfer ended) and `caps_unwrapped`, with the badges of the
/// unwrapped ones from `caps_or_badges`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReceivedCaps {
    processed: usize,
    unwrapped: u64,
    badges: [u64; MSG_MAX_EXTRA_CAPS],
}

impl ReceivedCaps {
    /// From a received `info` and the receiver's `caps_or_badges` as the
    /// receive left them. Bits of `caps_unwrapped` at or above
    /// `extra_caps` are ignored: the kernel never sets them.
    pub fn new(info: MessageInfo, caps_or_badges: [u64; MSG_MAX_EXTRA_CAPS]) -> ReceivedCaps {
        let processed = info.extra_caps() as usize;
        ReceivedCaps {
            processed,
            unwrapped: info.caps_unwrapped() & ((1 << processed) - 1),
            badges: caps_or_badges,
        }
    }

    /// From a received `info` and the receiver's buffer `ipc`. Read it
    /// before the thread composes another message there.
    pub fn read(info: MessageInfo, ipc: Ipc) -> ReceivedCaps {
        ReceivedCaps::new(info, ipc.caps_or_badges())
    }

    /// Capabilities processed, the received `extra_caps`: each was
    /// unwrapped or copied, in order, until the transfer ended.
    pub fn processed(&self) -> usize {
        self.processed
    }

    /// The received `caps_unwrapped`: bit `i` set if capability `i` was
    /// unwrapped.
    pub fn unwrapped(&self) -> u64 {
        self.unwrapped
    }

    /// How capability `i` arrived; `None` if it was not processed.
    pub fn get(&self, i: usize) -> Option<Arrival> {
        if i >= self.processed {
            None
        } else if self.unwrapped & (1 << i) != 0 {
            Some(Arrival::Unwrapped(self.badges[i]))
        } else {
            Some(Arrival::Copied)
        }
    }

    /// The badge of capability `i`, if it was unwrapped.
    pub fn badge(&self, i: usize) -> Option<u64> {
        match self.get(i) {
            Some(Arrival::Unwrapped(b)) => Some(b),
            _ => None,
        }
    }

    /// The index of the capability copied into the receive slot, if one
    /// was: a processed capability that was not unwrapped. There is at
    /// most one, since the slot takes one.
    pub fn copied(&self) -> Option<usize> {
        (0..self.processed).find(|&i| self.get(i) == Some(Arrival::Copied))
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::ptr::NonNull;
    use l4core::ipc::{IpcBuffer, word};
    use std::boxed::Box;

    use crate::invoke::Slot;

    /// A buffer on the heap, freed when dropped. Only the raw pointer is
    /// kept, never the `Box`, so moving this does not invalidate the
    /// pointer the `Ipc` holds (Stacked Borrows retags a moved `Box`).
    struct Buffer(NonNull<IpcBuffer>);

    impl Drop for Buffer {
        fn drop(&mut self) {
            // SAFETY: the pointer came from `Box::into_raw` in `buffer`,
            // and is freed once, here.
            drop(unsafe { Box::from_raw(self.0.as_ptr()) });
        }
    }

    /// A buffer and an `Ipc` over it. The tests read and write the buffer
    /// only through the `Ipc`, and keep the `Buffer` while they use it.
    fn buffer() -> (Buffer, Ipc) {
        let p = NonNull::new(Box::into_raw(Box::new(IpcBuffer::ZERO))).unwrap();
        // SAFETY: the allocation is 1024-byte aligned (the type's
        // alignment), readable and writable, and lives until the `Buffer`
        // the test holds beside the `Ipc` is dropped.
        let ipc = unsafe { Ipc::new(p) };
        (Buffer(p), ipc)
    }

    fn msg(ipc: Ipc, i: usize) -> u64 {
        ipc.word(word::MSG + i)
    }

    #[test]
    fn a_short_message_needs_no_buffer() {
        let m = compose(None, 0x123, &[1, 2, 3], &[]);
        assert_eq!(m.info, MessageInfo::new(0x123, 0, 0, 3));
        assert_eq!(m.mr, [1, 2, 3, 0]);
        assert_eq!(compose(None, 0, &[], &[]), Message::EMPTY);
    }

    #[test]
    fn words_past_mr3_and_caps_go_to_the_buffer() {
        let (_b, ipc) = buffer();
        let words: std::vec::Vec<u64> = (100..106).collect();
        let m = ipc.compose(7, &words, &[40, 41]);
        assert_eq!(m.info, MessageInfo::new(7, 0, 2, 6));
        assert_eq!(m.mr, [100, 101, 102, 103]);
        // MR4 and MR5 are msg[4] and msg[5]; msg[0..4] stay untouched.
        let six: [u64; 6] = core::array::from_fn(|i| msg(ipc, i));
        assert_eq!(six, [0, 0, 0, 0, 104, 105]);
        assert_eq!(ipc.caps_or_badges(), [40, 41, 0]);
        for i in 0..6 {
            assert_eq!(ipc.received_word(&m, i), 100 + i as u64);
        }
        let full: std::vec::Vec<u64> = (0..MSG_MAX_LENGTH as u64).collect();
        let m = ipc.compose(1, &full, &[]);
        assert_eq!(m.info.length(), 120);
        assert_eq!(msg(ipc, 119), 119);
        assert_eq!(ipc.received_word(&m, 119), 119);
        // No caps: caps_or_badges keeps what it held.
        assert_eq!(ipc.caps_or_badges(), [40, 41, 0]);
    }

    #[test]
    #[should_panic(expected = "needs the sender's IPC buffer")]
    fn a_fifth_word_without_a_buffer_panics() {
        compose(None, 0, &[0; 5], &[]);
    }

    #[test]
    #[should_panic(expected = "needs the sender's IPC buffer")]
    fn a_capability_without_a_buffer_panics() {
        compose(None, 0, &[], &[9]);
    }

    #[test]
    #[should_panic(expected = "4 extra caps")]
    fn four_capabilities_panic() {
        let (_b, ipc) = buffer();
        ipc.compose(0, &[], &[1, 2, 3, 4]);
    }

    #[test]
    #[should_panic(expected = "word 4 of a 4-word message")]
    fn a_word_past_the_length_panics() {
        let (_b, ipc) = buffer();
        ipc.received_word(&compose(None, 0, &[1, 2, 3, 4], &[]), 4);
    }

    #[test]
    fn the_receive_slot_words() {
        let (_b, ipc) = buffer();
        let words = |ipc: Ipc| {
            [
                word::RECEIVE_CNODE,
                word::RECEIVE_INDEX,
                word::RECEIVE_DEPTH,
            ]
            .map(|w| ipc.word(w))
        };
        ipc.set_receive_slot(Some(Slot::new(3, 9, 6)));
        assert_eq!(words(ipc), [3, 9, 6]);
        assert_eq!(ipc.receive_slot(), Slot::new(3, 9, 6));
        ipc.set_receive_slot(None);
        assert_eq!(words(ipc), [0, 0, 0]);
    }

    fn info(caps_unwrapped: u64, extra_caps: u64) -> MessageInfo {
        MessageInfo::new(5, caps_unwrapped, extra_caps, 2)
    }

    #[test]
    fn nothing_received() {
        let r = ReceivedCaps::new(info(0, 0), [7, 8, 9]);
        assert_eq!((r.processed(), r.unwrapped()), (0, 0));
        assert_eq!((r.get(0), r.copied(), r.badge(0)), (None, None, None));
    }

    #[test]
    fn unwrapped_and_copied_capabilities() {
        // Capabilities 0 and 1 unwrapped, 2 copied: seL4's order.
        let r = ReceivedCaps::new(info(0b011, 3), [0x5E55, 0, 77]);
        assert_eq!(r.processed(), 3);
        assert_eq!(r.get(0), Some(Arrival::Unwrapped(0x5E55)));
        assert_eq!(r.get(1), Some(Arrival::Unwrapped(0)), "badge 0 is a badge");
        assert_eq!(r.get(2), Some(Arrival::Copied));
        assert_eq!(r.get(3), None);
        assert_eq!(
            (r.badge(0), r.badge(1), r.badge(2)),
            (Some(0x5E55), Some(0), None)
        );
        assert_eq!(r.copied(), Some(2));
        // One copied first, then the slot was used: the transfer ended.
        let r = ReceivedCaps::new(info(0, 1), [1, 2, 3]);
        assert_eq!(
            (r.get(0), r.get(1), r.copied()),
            (Some(Arrival::Copied), None, Some(0))
        );
        // Unwrapped only.
        let r = ReceivedCaps::new(info(0b1, 1), [0xB, 2, 3]);
        assert_eq!((r.badge(0), r.copied()), (Some(0xB), None));
    }

    #[test]
    fn unwrapped_bits_past_extra_caps_are_ignored() {
        let r = ReceivedCaps::new(info(0b110, 1), [1, 2, 3]);
        assert_eq!(r.unwrapped(), 0);
        assert_eq!((r.get(0), r.get(1)), (Some(Arrival::Copied), None));
    }

    #[test]
    fn read_takes_the_badges_from_the_buffer() {
        let (_b, ipc) = buffer();
        ipc.set_caps(&[0xAA, 0xBB, 0xCC]);
        let r = ReceivedCaps::read(info(0b100, 3), ipc);
        assert_eq!(r.badge(2), Some(0xCC));
        assert_eq!(r.copied(), Some(0));
    }
}
