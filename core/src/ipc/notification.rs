//! Notifications (`docs/design.md`, "Notifications"; `docs/abi.md`,
//! "Notification semantics", "TCB_BindNotification and
//! TCB_UnbindNotification" and "Objects").
//!
//! A notification is 64 bytes of eight words ([`ntfn_field`]): the pending
//! word that signals OR their badge into, the bound TCB, the head and tail
//! of a FIFO queue of waiting TCBs, linked through their `ep_prev` and
//! `ep_next` fields as endpoint queues are, and a state. Zeroed memory is
//! the `Idle`, empty, unbound notification, so retype needs no
//! initialisation.
//!
//! - [`signal`] ORs a badge in, wakes the first waiter, or wakes the bound
//!   thread out of an endpoint receive; it never blocks or fails.
//! - [`wait`] blocks until a signal is pending or takes the word; a poll
//!   never blocks. Neither touches the caller slot or the message
//!   registers. [`complete_bound_signal`] is step 2 of an endpoint
//!   receive.
//! - [`bind_notification`] and [`unbind_notification`] keep the one-to-one
//!   link between a TCB and a notification; binding delivers a pending
//!   signal to a thread blocked in an endpoint receive.
//! - [`finalise`] unbinds and then runs [`cancel_all_signals`] when the
//!   last capability goes; `cancel_ipc` takes a waiter out through
//!   [`cancel_signal`].
//!
//! Every function is generic over [`Threads`], whose notification words
//! `TCB_BindNotification` needs, except [`signal`], which may cancel an
//! endpoint receive and so needs [`IpcEnv`]. Between kernel entries, and
//! wherever these return, the invariants [`check_notifications`] tests
//! hold.

use crate::cap::{Cap, CapType, Rights};
use crate::sched;
use crate::tcb::{NtfnRef, TcbRef, ThreadState, Threads};

use super::endpoint::IpcEnv;

/// Byte offsets of a notification's words (`docs/abi.md`, "Objects").
pub mod ntfn_field {
    /// The pending badge bits.
    pub const WORD: u64 = 0;
    /// The bound TCB, 0 for none.
    pub const BOUND_TCB: u64 = 8;
    /// The first waiting TCB, 0 for none.
    pub const QUEUE_HEAD: u64 = 16;
    /// The last waiting TCB, 0 for none.
    pub const QUEUE_TAIL: u64 = 24;
    /// The [`super::NtfnState`].
    pub const STATE: u64 = 32;
    /// Reserved, 0: three words, to 64 bytes.
    pub const RESERVED: u64 = 40;
}

/// A notification's state (`docs/design.md`, "States").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum NtfnState {
    /// No signal pending, nobody waits; the word is 0.
    Idle = 0,
    /// Threads wait; the word is 0.
    Waiting = 1,
    /// A signal is pending, nobody waits; the word is the OR of the badges
    /// signalled since the last wait, 0 if only unbadged capabilities
    /// signalled.
    Active = 2,
}

impl NtfnState {
    /// The state a [`ntfn_field::STATE`] word holds. Decoding is total: an
    /// unknown value, which no writer stores, reads as `Idle`.
    pub const fn from_word(w: u64) -> NtfnState {
        match w {
            1 => NtfnState::Waiting,
            2 => NtfnState::Active,
            _ => NtfnState::Idle,
        }
    }
}

/// A notification's contents by value.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Notification {
    pub state: NtfnState,
    /// The pending word.
    pub word: u64,
    /// The bound TCB.
    pub bound: Option<TcbRef>,
    pub head: Option<TcbRef>,
    pub tail: Option<TcbRef>,
}

impl Notification {
    /// A new notification: `Idle`, word 0, unbound, nobody waiting.
    pub const IDLE: Notification = Notification {
        state: NtfnState::Idle,
        word: 0,
        bound: None,
        head: None,
        tail: None,
    };
}

/// Notification `n`'s state, word, binding and queue.
pub fn notification<E: Threads + ?Sized>(e: &E, n: NtfnRef) -> Notification {
    use ntfn_field::*;
    Notification {
        state: NtfnState::from_word(e.notification_word(n, STATE)),
        word: e.notification_word(n, WORD),
        bound: TcbRef::new(e.notification_word(n, BOUND_TCB)),
        head: TcbRef::new(e.notification_word(n, QUEUE_HEAD)),
        tail: TcbRef::new(e.notification_word(n, QUEUE_TAIL)),
    }
}

/// Overwrites notification `n`'s state, word, binding and queue. Only
/// [`crate::ipc`] writes notifications.
pub fn set_notification<E: Threads + ?Sized>(e: &mut E, n: NtfnRef, v: &Notification) {
    use ntfn_field::*;
    e.set_notification_word(n, WORD, v.word);
    e.set_notification_word(n, BOUND_TCB, link(v.bound));
    e.set_notification_word(n, QUEUE_HEAD, link(v.head));
    e.set_notification_word(n, QUEUE_TAIL, link(v.tail));
    e.set_notification_word(n, STATE, v.state as u64);
}

fn link(t: Option<TcbRef>) -> u64 {
    t.map_or(0, TcbRef::get)
}

/// What a signal, wait, poll or bind takes from the notification
/// capability it was given: the notification, the badge and the rights.
/// Only a signal uses the badge; a wait or a bind ignores it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NotificationCap {
    pub ntfn: NtfnRef,
    pub badge: u64,
    pub rights: Rights,
}

impl NotificationCap {
    /// The notification a Notification capability names; `None` for any
    /// other.
    pub fn from_cap(cap: &Cap) -> Option<NotificationCap> {
        if cap.cap_type() != CapType::Notification {
            return None;
        }
        Some(NotificationCap {
            ntfn: NtfnRef::new(cap.object())?,
            badge: cap.badge(),
            rights: cap.rights(),
        })
    }

    /// Write: may signal.
    pub const fn can_signal(&self) -> bool {
        self.rights.contains(Rights::WRITE)
    }

    /// Read: may wait, poll and bind.
    pub const fn can_wait(&self) -> bool {
        self.rights.contains(Rights::READ)
    }
}

// ---------------------------------------------------------------------------
// The queue
// ---------------------------------------------------------------------------

/// Puts `t`, which is in no queue, at the tail of `n`'s queue; `n` becomes
/// `Waiting`. Its word is 0: only an `Idle` or `Waiting` notification
/// takes a waiter.
fn append<E: Threads + ?Sized>(e: &mut E, n: NtfnRef, t: TcbRef) {
    debug_assert_eq!(e.ep_links(t), (None, None), "queueing a queued thread");
    let mut v = notification(e, n);
    debug_assert!(v.state != NtfnState::Active && v.word == 0);
    e.set_ep_prev(t, v.tail);
    e.set_ep_next(t, None);
    match v.tail {
        Some(last) => e.set_ep_next(last, Some(t)),
        None => v.head = Some(t),
    }
    v.tail = Some(t);
    v.state = NtfnState::Waiting;
    set_notification(e, n, &v);
}

/// Takes `t` out of `n`'s queue, wherever it is; `n` becomes `Idle` if
/// that empties it. Its word and binding are kept.
fn remove<E: Threads + ?Sized>(e: &mut E, n: NtfnRef, t: TcbRef) {
    let mut v = notification(e, n);
    debug_assert!(
        v.state == NtfnState::Waiting,
        "removing from a notification nobody waits on"
    );
    let (prev, next) = e.ep_links(t);
    match prev {
        Some(p) => e.set_ep_next(p, next),
        None => {
            debug_assert_eq!(v.head, Some(t));
            v.head = next;
        }
    }
    match next {
        Some(x) => e.set_ep_prev(x, prev),
        None => {
            debug_assert_eq!(v.tail, Some(t));
            v.tail = prev;
        }
    }
    if v.head.is_none() {
        v.state = NtfnState::Idle;
        v.tail = None;
    }
    set_notification(e, n, &v);
    e.set_ep_prev(t, None);
    e.set_ep_next(t, None);
}

// ---------------------------------------------------------------------------
// Signal, wait and poll
// ---------------------------------------------------------------------------

/// `t` gets a signal: `rdi` = `word` and `rsi` = 0; its message registers
/// keep their values.
fn give<E: Threads + ?Sized>(e: &mut E, t: TcbRef, word: u64) {
    let mut regs = e.regs(t);
    regs.rdi = word;
    regs.rsi = 0;
    e.set_regs(t, &regs);
}

/// A thread a signal woke, already out of every queue, gets `word` and
/// becomes `Running`, made runnable.
fn wake<E: Threads + ?Sized>(e: &mut E, t: TcbRef, word: u64) {
    give(e, t, word);
    sched::set_thread_state(e, t, ThreadState::Running);
    sched::make_runnable(e, t);
}

/// `signal(N, b)` of `docs/design.md`: `Send`, `NBSend` and `Call` on a
/// notification capability with Write, whose badge is `badge`, and the
/// kernel's signals for interrupts (M7) and SynIC events (M9). Never blocks
/// and never fails.
///
/// - `Waiting`: the head waiter leaves the queue (`n` becomes `Idle` if
///   that empties it) and becomes `Running` with `rdi` = `badge`, `rsi` =
///   0.
/// - `Idle`, bound to a thread `BlockedOnReceive` on any endpoint: IPC's
///   `cancel_ipc` takes it off that endpoint's queue, and it becomes
///   `Running` with `rdi` = `badge`, `rsi` = 0; `n` stays `Idle`.
/// - `Idle` otherwise: `n` becomes `Active` with word `badge`. A bound
///   thread in any other state is not woken.
/// - `Active`: the word becomes word OR `badge`.
pub fn signal<E: IpcEnv + ?Sized>(e: &mut E, n: NtfnRef, badge: u64) {
    let mut v = notification(e, n);
    match v.state {
        NtfnState::Waiting => {
            let w = v.head.expect("a Waiting notification has a waiter");
            remove(e, n, w);
            wake(e, w, badge);
        }
        NtfnState::Idle => match v.bound {
            Some(t) if matches!(e.state(t), ThreadState::BlockedOnReceive { .. }) => {
                super::cancel_ipc(e, t);
                wake(e, t, badge);
            }
            _ => {
                v.state = NtfnState::Active;
                v.word = badge;
                set_notification(e, n, &v);
            }
        },
        NtfnState::Active => {
            v.word |= badge;
            set_notification(e, n, &v);
        }
    }
}

/// Whether `t` may wait on or poll `n`: `n` is unbound or bound to `t`.
/// Any other thread takes a capability fault in the receive phase
/// (`docs/abi.md`, "Notification semantics").
pub fn may_wait<E: Threads + ?Sized>(e: &E, n: NtfnRef, t: TcbRef) -> bool {
    notification(e, n).bound.is_none_or(|b| b == t)
}

/// `wait(T, N, blocking)` of `docs/design.md`: `Recv` and the receive
/// phase of `ReplyRecv` (`blocking`) and `NBRecv` on a notification
/// capability with Read, by a thread that [`may_wait`]. The badge of that
/// capability plays no part.
///
/// - `Active`: `t` gets `rdi` = the word, `rsi` = 0; `n` becomes `Idle`
///   with word 0.
/// - `Idle` or `Waiting`, blocking: `t` becomes `BlockedOnNotification`
///   at the tail of the queue; `n` becomes `Waiting`.
/// - `Idle` or `Waiting`, a poll: `t` gets `rdi` = 0 and `rsi` = 0.
///
/// Message registers and the caller slot are left alone.
pub fn wait<E: Threads + ?Sized>(e: &mut E, t: TcbRef, n: NtfnRef, blocking: bool) {
    let mut v = notification(e, n);
    match v.state {
        NtfnState::Active => {
            give(e, t, v.word);
            v.state = NtfnState::Idle;
            v.word = 0;
            set_notification(e, n, &v);
        }
        NtfnState::Idle | NtfnState::Waiting => {
            if blocking {
                sched::set_thread_state(e, t, ThreadState::BlockedOnNotification { ntfn: n });
                append(e, n, t);
            } else {
                give(e, t, 0);
            }
        }
    }
}

/// Step 2 of an endpoint receive by `r` (`docs/design.md`, "Receive
/// phase"): if `r` has a bound notification in state `Active`, `r` gets
/// `rdi` = its word and `rsi` = 0, the notification becomes `Idle` with
/// word 0, and the receive is complete (true). Otherwise nothing changes
/// (false).
pub fn complete_bound_signal<E: Threads + ?Sized>(e: &mut E, r: TcbRef) -> bool {
    let Some(n) = e.bound_notification(r) else {
        return false;
    };
    let mut v = notification(e, n);
    if v.state != NtfnState::Active {
        return false;
    }
    give(e, r, v.word);
    v.state = NtfnState::Idle;
    v.word = 0;
    set_notification(e, n, &v);
    true
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

/// `TCB_BindNotification`, decoded: `t` has no bound notification, and
/// `n` is unbound with nobody waiting. Sets both links. If `n` is `Active`
/// and `t` is `BlockedOnReceive`, the signal is delivered at once (the
/// design's change from seL4): IPC's `cancel_ipc`, through
/// [`Threads::cancel_ipc`], takes `t` off its endpoint's queue, `t`
/// becomes `Running` with `rdi` = the word and `rsi` = 0, and `n` becomes
/// `Idle` with word 0. In any other state the signal stays pending.
pub fn bind_notification<E: Threads + ?Sized>(e: &mut E, t: TcbRef, n: NtfnRef) {
    debug_assert!(e.bound_notification(t).is_none(), "binding a bound thread");
    let mut v = notification(e, n);
    debug_assert!(
        v.bound.is_none() && v.head.is_none(),
        "binding a bound or waited-on notification"
    );
    v.bound = Some(t);
    e.set_bound_notification(t, Some(n));
    if v.state == NtfnState::Active && matches!(e.state(t), ThreadState::BlockedOnReceive { .. }) {
        let word = v.word;
        v.state = NtfnState::Idle;
        v.word = 0;
        set_notification(e, n, &v);
        e.cancel_ipc(t);
        wake(e, t, word);
    } else {
        set_notification(e, n, &v);
    }
}

/// `TCB_UnbindNotification`, and the first step of finalising a TCB:
/// clears `t`'s binding and its notification's, if it has one, and
/// nothing else (seL4 `unbindNotification`). The notification keeps its
/// state, word and waiters; `t` stays in whatever it is blocked in.
pub fn unbind_notification<E: Threads + ?Sized>(e: &mut E, t: TcbRef) {
    if let Some(n) = e.bound_notification(t) {
        let mut v = notification(e, n);
        debug_assert_eq!(v.bound, Some(t), "a one-sided binding");
        v.bound = None;
        set_notification(e, n, &v);
        e.set_bound_notification(t, None);
    }
}

// ---------------------------------------------------------------------------
// Cancellation and deletion
// ---------------------------------------------------------------------------

/// The `BlockedOnNotification` arm of IPC's `cancel_ipc` (seL4
/// `cancelSignal`): `t` leaves `n`'s queue (`n` becomes `Idle` if that
/// empties it) and becomes `Inactive`.
pub(crate) fn cancel_signal<E: Threads + ?Sized>(e: &mut E, t: TcbRef, n: NtfnRef) {
    remove(e, n, t);
    sched::set_thread_state(e, t, ThreadState::Inactive);
}

/// `cancel_all_signals(N)`: every waiter leaves, in queue order, with its
/// fault cleared, and becomes `Restart`, made runnable, so its retried
/// `Recv` resolves its `CPtr` afresh: unless it runs at once, it joins the
/// tail of its ready queue, where seL4 puts each at the head, so that its
/// last waiter runs first. The pending word is discarded and `n` becomes
/// `Idle`; its binding is kept. Not preemptible, as in seL4
/// (`cancelAllSignals`): one step per waiter.
pub fn cancel_all_signals<E: Threads + ?Sized>(e: &mut E, n: NtfnRef) {
    let v = notification(e, n);
    set_notification(
        e,
        n,
        &Notification {
            bound: v.bound,
            ..Notification::IDLE
        },
    );
    let mut next = v.head;
    while let Some(t) = next {
        next = e.ep_links(t).1;
        e.set_ep_prev(t, None);
        e.set_ep_next(t, None);
        e.set_fault(t, None);
        sched::set_thread_state(e, t, ThreadState::Restart);
        sched::make_runnable(e, t);
    }
}

/// The last capability to `n` is being deleted (seL4 `finaliseCap`):
/// unbinds its TCB, then [`cancel_all_signals`]. A bound thread in an
/// endpoint receive loses only the link and stays queued there. Afterwards
/// the notification's words are all zero, as retype leaves a new one.
pub fn finalise<E: Threads + ?Sized>(e: &mut E, n: NtfnRef) {
    let mut v = notification(e, n);
    if let Some(t) = v.bound {
        debug_assert_eq!(e.bound_notification(t), Some(n), "a one-sided binding");
        e.set_bound_notification(t, None);
        v.bound = None;
        set_notification(e, n, &v);
    }
    cancel_all_signals(e, n);
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// Checks the notification invariants of `docs/design.md`,
/// "Notifications" ("Invariants"), over the given threads and
/// notifications, as they hold between kernel entries and when any
/// function here returns:
///
/// - each notification is `Waiting` exactly when its queue is non-empty;
///   `Idle` and `Waiting` have word 0, `Active` an empty queue; its links
///   run both ways from head to tail, every queued thread is
///   `BlockedOnNotification` on it, and its reserved words are 0;
/// - a bound notification's queue holds only its bound thread;
/// - binding is symmetric: `T.bound_notification` = `N` exactly when
///   `N.bound_tcb` = `T`;
/// - each thread `BlockedOnNotification` is in that notification's queue;
/// - a bound thread is never `BlockedOnReceive` while its notification is
///   `Active`.
///
/// [`super::check`] checks that a thread blocked on neither an endpoint
/// nor a notification has null queue links. A queue longer than `threads`
/// is reported as a cycle.
pub fn check_notifications<E: Threads + ?Sized>(
    e: &E,
    threads: &[TcbRef],
    ntfns: &[NtfnRef],
) -> Result<(), &'static str> {
    for &n in ntfns {
        check_queue(e, n, threads.len())?;
        if let Some(t) = notification(e, n).bound
            && e.bound_notification(t) != Some(n)
        {
            return Err("a notification is bound to a thread not bound to it");
        }
    }
    for &t in threads {
        let state = e.state(t);
        if let ThreadState::BlockedOnNotification { ntfn } = state {
            check_queue(e, ntfn, threads.len())?;
            if !in_queue(e, ntfn, t, threads.len()) {
                return Err("a waiting thread is not in its notification's queue");
            }
        }
        if let Some(n) = e.bound_notification(t) {
            let v = notification(e, n);
            if v.bound != Some(t) {
                return Err("a thread is bound to a notification not bound to it");
            }
            if v.state == NtfnState::Active && matches!(state, ThreadState::BlockedOnReceive { .. })
            {
                return Err(
                    "a bound thread receives on an endpoint while its notification is Active",
                );
            }
        }
    }
    Ok(())
}

/// The per-notification checks of [`check_notifications`] for `n`.
pub(crate) fn check_queue<E: Threads + ?Sized>(
    e: &E,
    n: NtfnRef,
    limit: usize,
) -> Result<(), &'static str> {
    let v = notification(e, n);
    if v.head.is_none() != v.tail.is_none() {
        return Err("notification queue with a head but no tail");
    }
    if (v.state == NtfnState::Waiting) != v.head.is_some() {
        return Err("notification is Waiting exactly when its queue is non-empty: violated");
    }
    if v.state != NtfnState::Active && v.word != 0 {
        return Err("an Idle or Waiting notification has a non-zero word");
    }
    if (0..3).any(|i| e.notification_word(n, ntfn_field::RESERVED + 8 * i) != 0) {
        return Err("a notification's reserved word is not 0");
    }
    let mut prev = None;
    let mut cur = v.head;
    let mut count = 0;
    while let Some(t) = cur {
        count += 1;
        if count > limit {
            return Err("notification queue longer than the threads: a cycle");
        }
        let (back, next) = e.ep_links(t);
        if back != prev {
            return Err("notification queue link does not point back");
        }
        if e.state(t) != (ThreadState::BlockedOnNotification { ntfn: n }) {
            return Err("a queued thread is not waiting on its notification");
        }
        if v.bound.is_some_and(|b| b != t) {
            return Err("a thread other than the bound one waits on a bound notification");
        }
        prev = Some(t);
        cur = next;
    }
    if v.tail != prev {
        return Err("notification tail is not the last queued thread");
    }
    Ok(())
}

/// Whether `t` is in `n`'s queue, which [`check_queue`] accepted.
pub(crate) fn in_queue<E: Threads + ?Sized>(e: &E, n: NtfnRef, t: TcbRef, limit: usize) -> bool {
    let mut cur = notification(e, n).head;
    for _ in 0..limit {
        match cur {
            Some(x) if x == t => return true,
            Some(x) => cur = e.ep_links(x).1,
            None => return false,
        }
    }
    false
}

#[cfg(test)]
mod tests;
