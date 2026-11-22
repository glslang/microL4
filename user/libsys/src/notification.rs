//! Notifications (`docs/abi.md`, "Notification semantics"; `docs/design.md`,
//! "Notifications"): signal, wait and poll, and telling a signal from a
//! message in what an endpoint receive returns to a thread bound to a
//! notification (`TCB_BindNotification`, [`crate::invoke`]).
//!
//! A notification is a word that signals OR their capability's badge into.
//! A wait or poll returns the word in `rdi`, with `rsi` 0, and clears it;
//! signals that arrive before a waiter looks are merged, not counted. A
//! signal through an unbadged capability is remembered but adds no bits, so
//! a protocol that must see who signalled gives every signaller a non-zero
//! badge.

use crate::syscall::{CPtr, Message, Received, nb_recv, recv, send};

/// Signal: `Send` on a notification capability with Write. The word
/// becomes word OR the capability's badge, or the first waiter wakes with
/// the badge, or the bound thread wakes out of an endpoint receive with it.
/// Never blocks. Without Write, or on an empty slot, nothing happens.
pub fn signal(ntfn: CPtr) {
    send(ntfn, &Message::EMPTY);
}

/// Wait: `Recv` on a notification capability with Read. Returns the word
/// and clears it if a signal is pending; otherwise blocks until one
/// arrives. Only the bound thread may wait on a bound notification; any
/// other thread, like one without Read, takes a capability fault.
pub fn wait(ntfn: CPtr) -> u64 {
    recv(ntfn).badge
}

/// Poll: `NBRecv` on a notification capability with Read. Returns the word
/// and clears it if a signal is pending, else 0: an empty poll looks like
/// a signal through unbadged capabilities only.
pub fn poll(ntfn: CPtr) -> u64 {
    nb_recv(ntfn).badge
}

/// What an endpoint receive returned to a thread bound to a notification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Event {
    /// A signal: the notification word, from `rdi`.
    Signal(u64),
    /// A message, a fault message, or an empty `NBRecv`.
    Message(Received),
}

impl Event {
    /// Tells a signal from a message by what the receive returned, as
    /// `docs/design.md`, "Binding", has a server do: a signal leaves the
    /// notification word in `rdi` and 0 in `rsi`, a message the sender's
    /// badge in `rdi` and its label and lengths in `rsi`. Only the
    /// protocol can tell the two `rdi`s apart, so `signal_bits` names the
    /// bits only notification badges use: every notification capability
    /// that signals the bound notification must have a non-zero badge
    /// inside them, and no endpoint capability a badge that touches them.
    /// A receive is a signal if `rsi` is 0 and `rdi` has a bit in
    /// `signal_bits`; a signal through unbadged capabilities, word 0, is
    /// then a `Message` with badge 0 and `MessageInfo` 0.
    pub fn classify(r: Received, signal_bits: u64) -> Event {
        if r.msg.info.word() == 0 && r.badge & signal_bits != 0 {
            Event::Signal(r.badge)
        } else {
            Event::Message(r)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l4core::ipc::MessageInfo;

    const SIGNAL_BITS: u64 = 0xFFFF_FFFF_0000_0000;

    fn received(badge: u64, info: MessageInfo) -> Received {
        Received {
            badge,
            msg: Message::new(info, [1, 2, 3, 4]),
        }
    }

    #[test]
    fn signals_and_messages_are_told_apart() {
        let zero = MessageInfo::from_word(0);
        // Signals, merged or not.
        for word in [1 << 32, 3 << 32, SIGNAL_BITS, (1 << 40) | 7] {
            assert_eq!(
                Event::classify(received(word, zero), SIGNAL_BITS),
                Event::Signal(word)
            );
        }
        // Messages: an endpoint badge outside the signal bits, whatever
        // the MessageInfo, even an empty one.
        for (badge, info) in [
            (1, MessageInfo::new(0x10, 0, 0, 1)),
            (2, zero),
            (0, MessageInfo::new(1, 0, 0, 0)),
            (0xFFFF_FFFF, MessageInfo::new(0, 0, 0, 4)),
        ] {
            let r = received(badge, info);
            assert_eq!(Event::classify(r, SIGNAL_BITS), Event::Message(r));
        }
        // rsi not 0 is never a signal, whatever the badge.
        let r = received(1 << 33, MessageInfo::new(0, 0, 0, 1));
        assert_eq!(Event::classify(r, SIGNAL_BITS), Event::Message(r));
        // An empty NBRecv, or a signal through unbadged capabilities only.
        let r = received(0, zero);
        assert_eq!(Event::classify(r, SIGNAL_BITS), Event::Message(r));
    }
}
