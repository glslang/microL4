//! Endpoint objects, their queues, and [`IpcEnv`], what IPC needs from the
//! kernel (`docs/abi.md`, "Objects"; `docs/design.md`, "Endpoint states and
//! queues" and "Where the code lives").
//!
//! An endpoint is 32 bytes of four words ([`ep_field`]): the head and tail
//! of a FIFO queue of TCBs, linked through their `ep_prev` and `ep_next`
//! fields, and a state that says what the queued threads wait to do. Zeroed
//! memory is the `Idle`, empty endpoint, so retype needs no initialisation.
//!
//! Between kernel entries, and at every point where these functions return,
//! an endpoint is [`EpState::Idle`] exactly when its queue is empty; in
//! `Send` every queued thread is `BlockedOnSend` on it, in `Recv` every one
//! `BlockedOnReceive`; a thread is in at most one queue, with null links
//! when it is in none. [`super::check`] tests all of it.

use crate::cap::{Cap, CapType, Rights};
use crate::tcb::{EpRef, TcbRef, Threads};

/// Byte offsets of an endpoint's words (`docs/abi.md`, "Objects").
pub mod ep_field {
    /// The first queued TCB, 0 for none.
    pub const QUEUE_HEAD: u64 = 0;
    /// The last queued TCB, 0 for none.
    pub const QUEUE_TAIL: u64 = 8;
    /// The [`super::EpState`].
    pub const STATE: u64 = 16;
    /// Reserved, 0.
    pub const RESERVED: u64 = 24;
}

/// What the threads queued on an endpoint wait to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum EpState {
    /// Nobody waits; the queue is empty.
    Idle = 0,
    /// Senders wait for a receiver.
    Send = 1,
    /// Receivers wait for a sender.
    Recv = 2,
}

impl EpState {
    /// The state a [`ep_field::STATE`] word holds. Decoding is total: an
    /// unknown value, which no writer stores, reads as `Idle`.
    pub const fn from_word(w: u64) -> EpState {
        match w {
            1 => EpState::Send,
            2 => EpState::Recv,
            _ => EpState::Idle,
        }
    }
}

/// An endpoint's contents by value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Endpoint {
    pub state: EpState,
    pub head: Option<TcbRef>,
    pub tail: Option<TcbRef>,
}

impl Endpoint {
    /// A new endpoint: `Idle`, nobody queued.
    pub const IDLE: Endpoint = Endpoint {
        state: EpState::Idle,
        head: None,
        tail: None,
    };
}

/// What IPC needs from the kernel besides [`Threads`]: endpoint words and
/// the read side of IPC buffers (`docs/design.md`, "Where the code lives",
/// `IpcEnv`). The kernel implements the three word accessors in `arch` over
/// the direct map, never forming a reference into an endpoint or a buffer;
/// host tests implement them over fake memory ([`crate::testing`]).
///
/// The typed accessors are built on the word accessors. Only
/// [`crate::ipc`] writes endpoints.
pub trait IpcEnv: Threads {
    /// The word at byte `offset` of endpoint `ep`: one of [`ep_field`]'s.
    fn endpoint_word(&self, ep: EpRef, offset: u64) -> u64;

    /// Overwrites the word at byte `offset` of endpoint `ep`.
    fn set_endpoint_word(&mut self, ep: EpRef, offset: u64, value: u64);

    /// The word at `paddr`, which [`crate::tcb::buffer_word`] found in an
    /// IPC buffer the kernel may read: inside a non-device frame that a
    /// TCB's buffer slot holds with Read. The read-side twin of
    /// [`Threads::write_buffer_word`]. Buffers may alias, and a device may
    /// write one, so the kernel reads it as a plain word every time.
    fn read_buffer_word(&self, paddr: u64) -> u64;

    /// The endpoint's state and queue.
    fn endpoint(&self, ep: EpRef) -> Endpoint {
        Endpoint {
            state: EpState::from_word(self.endpoint_word(ep, ep_field::STATE)),
            head: TcbRef::new(self.endpoint_word(ep, ep_field::QUEUE_HEAD)),
            tail: TcbRef::new(self.endpoint_word(ep, ep_field::QUEUE_TAIL)),
        }
    }

    /// Overwrites the endpoint's state and queue.
    fn set_endpoint(&mut self, ep: EpRef, value: &Endpoint) {
        self.set_endpoint_word(ep, ep_field::QUEUE_HEAD, link(value.head));
        self.set_endpoint_word(ep, ep_field::QUEUE_TAIL, link(value.tail));
        self.set_endpoint_word(ep, ep_field::STATE, value.state as u64);
    }
}

fn link(t: Option<TcbRef>) -> u64 {
    t.map_or(0, TcbRef::get)
}

/// What a send or receive takes from the endpoint capability it was given:
/// the endpoint, the badge and the rights. A blocked thread records what it
/// needs of them in its state, so changing or deleting the capability later
/// changes nothing about the message.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct EndpointCap {
    pub ep: EpRef,
    pub badge: u64,
    pub rights: Rights,
}

impl EndpointCap {
    /// The endpoint an Endpoint capability names; `None` for any other.
    pub fn from_cap(cap: &Cap) -> Option<EndpointCap> {
        if cap.cap_type() != CapType::Endpoint {
            return None;
        }
        Some(EndpointCap {
            ep: EpRef::new(cap.object())?,
            badge: cap.badge(),
            rights: cap.rights(),
        })
    }

    /// Write: may send.
    pub const fn can_send(&self) -> bool {
        self.rights.contains(Rights::WRITE)
    }

    /// Read: may receive.
    pub const fn can_receive(&self) -> bool {
        self.rights.contains(Rights::READ)
    }

    /// Grant: capabilities move with the message (M6), and a reply
    /// capability made for a caller received through it may grant.
    pub const fn can_grant(&self) -> bool {
        self.rights.contains(Rights::GRANT)
    }

    /// GrantReply: a `Call` through it may leave a reply capability.
    pub const fn can_grant_reply(&self) -> bool {
        self.rights.contains(Rights::GRANT_REPLY)
    }

    /// What `Call` and a fault endpoint need: Write, and Grant or
    /// GrantReply.
    pub const fn can_call(&self) -> bool {
        self.can_send() && (self.can_grant() || self.can_grant_reply())
    }
}

/// Puts `t` at the tail of `ep`'s queue and sets the endpoint's state:
/// `Send` for a sender, `Recv` for a receiver. `t` is in no queue, and the
/// queue holds only threads waiting for the same thing.
pub(crate) fn append<E: IpcEnv + ?Sized>(e: &mut E, ep: EpRef, t: TcbRef, state: EpState) {
    debug_assert!(state != EpState::Idle);
    debug_assert_eq!(e.ep_links(t), (None, None), "queueing a queued thread");
    let mut q = e.endpoint(ep);
    debug_assert!(q.state == EpState::Idle || q.state == state);
    e.set_ep_prev(t, q.tail);
    e.set_ep_next(t, None);
    match q.tail {
        Some(last) => e.set_ep_next(last, Some(t)),
        None => q.head = Some(t),
    }
    q.tail = Some(t);
    q.state = state;
    e.set_endpoint(ep, &q);
}

/// Takes the head of `ep`'s queue, which the caller found non-empty; the
/// endpoint becomes `Idle` if that empties it.
pub(crate) fn take_head<E: IpcEnv + ?Sized>(e: &mut E, ep: EpRef) -> TcbRef {
    let head = e
        .endpoint(ep)
        .head
        .expect("a Send or Recv endpoint has a queued thread");
    remove(e, ep, head);
    head
}

/// Takes `t` out of `ep`'s queue, wherever it is; the endpoint becomes
/// `Idle` if that empties it.
pub(crate) fn remove<E: IpcEnv + ?Sized>(e: &mut E, ep: EpRef, t: TcbRef) {
    let mut q = e.endpoint(ep);
    debug_assert!(q.state != EpState::Idle, "removing from an idle endpoint");
    let (prev, next) = e.ep_links(t);
    match prev {
        Some(p) => e.set_ep_next(p, next),
        None => {
            debug_assert_eq!(q.head, Some(t));
            q.head = next;
        }
    }
    match next {
        Some(n) => e.set_ep_prev(n, prev),
        None => {
            debug_assert_eq!(q.tail, Some(t));
            q.tail = prev;
        }
    }
    if q.head.is_none() {
        q = Endpoint::IDLE;
    }
    e.set_endpoint(ep, &q);
    e.set_ep_prev(t, None);
    e.set_ep_next(t, None);
}
