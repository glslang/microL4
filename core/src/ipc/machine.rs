//! The endpoint state machine (`docs/design.md`, "IPC", "Faults"; ADRs
//! 0016, 0018, 0023): the send, receive and reply phases, message transfer,
//! reply capabilities, cancellation and fault delivery. M6 adds capability
//! transfer, notifications and `CNode_SaveCaller`.
//!
//! Every function runs to completion in one kernel entry with no
//! preemption point, in time bounded by the message, or for
//! [`cancel_all_ipc`] by the queue. None switches threads: a woken thread
//! goes to [`sched::make_runnable`], and the scheduler's tie rule runs a
//! `Call` or `ReplyRecv` partner at once (ADR 0018). Nothing here changes a
//! priority or a time slice; only the scheduler reads them.
//!
//! State changes go through [`sched::set_thread_state`], so a thread that
//! blocks while it is current, or is woken while another runs, leaves the
//! scheduler right. Where seL4's order of effects is visible, it is kept:
//! a sender wakes its receiver before it blocks for the reply
//! (`src/object/endpoint.c`, `sendIPC`), so a `Call` partner of equal
//! priority runs next.

use crate::cap::{Cap, CapType, Rights, TCB_SLOT_CALLER, TCB_SLOT_CSPACE, TCB_SLOT_REPLY};
use crate::cdt;
use crate::cnode;
use crate::cspace;
use crate::error::{LookupFailure, SyscallError};
use crate::regs::{self, Exit, Fault, FaultOutcome, Regs};
use crate::sched;
use crate::slot::SlotAddr;
use crate::tcb::{self, EpRef, TcbRef, ThreadState};

use super::endpoint::{self as queue, EndpointCap, EpState, IpcEnv};
use super::message::{MSG_MAX_LENGTH, MSG_REG_COUNT, MessageInfo, word};

/// The most message registers a fault reply sets: `UnknownSyscall`'s MR0
/// to MR17 (`docs/abi.md`, "Fault replies").
const FAULT_REPLY_MAX: usize = 18;

// ---------------------------------------------------------------------------
// Send, receive and reply phases
// ---------------------------------------------------------------------------

/// The send phase, `send(T, E, badge, g, gr, call, blocking)` of
/// `docs/design.md`: `Send`, `NBSend` and `Call` on an endpoint, and fault
/// delivery. The badge and the rights come from `cap`. The caller checked
/// Write, and for a `Call` Grant or GrantReply.
///
/// - No receiver waits: a blocking `t` becomes `BlockedOnSend` at the tail
///   of the queue, recording the badge, the two grant rights and `call`;
///   otherwise the message is dropped and `t` goes on.
/// - A receiver `R` waits: it leaves the queue, gets the message and
///   becomes `Running`. For a `Call`, `t` then becomes `BlockedOnReply` and
///   `R`'s caller slot gets a reply capability to `t` whose Grant is the
///   Grant `R` received with.
pub fn send<E: IpcEnv + ?Sized>(
    e: &mut E,
    t: TcbRef,
    cap: &EndpointCap,
    call: bool,
    blocking: bool,
) {
    let ep = cap.ep;
    match e.endpoint(ep).state {
        EpState::Idle | EpState::Send => {
            if blocking {
                let state = ThreadState::BlockedOnSend {
                    ep,
                    badge: cap.badge,
                    can_grant: cap.can_grant(),
                    can_grant_reply: cap.can_grant_reply(),
                    is_call: call,
                };
                sched::set_thread_state(e, t, state);
                queue::append(e, ep, t, EpState::Send);
            }
        }
        EpState::Recv => {
            let r = queue::take_head(e, ep);
            let ThreadState::BlockedOnReceive {
                can_grant: reply_grant,
                ..
            } = e.state(r)
            else {
                panic!("a thread in a Recv queue is not receiving");
            };
            transfer(e, t, r, cap.badge);
            sched::set_thread_state(e, r, ThreadState::Running);
            sched::make_runnable(e, r);
            if call {
                debug_assert!(cap.can_grant() || cap.can_grant_reply());
                setup_caller_cap(e, t, r, reply_grant);
            }
        }
    }
}

/// The receive phase, `receive(R, E, g, blocking)` of `docs/design.md`:
/// `Recv` and `NBRecv` on an endpoint, and the receive phase of
/// `ReplyRecv`. The caller checked Read; the Grant of `cap` goes into any
/// reply capability this receive makes.
///
/// 1. Whatever is in `r`'s caller slot is deleted: a server that receives
///    again before replying gives up that reply.
/// 2. A bound notification's pending signal (M6).
/// 3. No sender waits: a blocking `r` becomes `BlockedOnReceive` at the tail
///    of the queue; a non-blocking one gets badge 0 and `MessageInfo` 0.
///    A sender `S` waits: it leaves the queue and `r` gets its message with
///    the badge `S` recorded. A calling `S` (a `Call` or a fault) becomes
///    `BlockedOnReply` with a reply capability in `r`'s caller slot; any
///    other becomes `Running`.
pub fn receive<E: IpcEnv + ?Sized>(e: &mut E, r: TcbRef, cap: &EndpointCap, blocking: bool) {
    delete_one(e, r.slot(TCB_SLOT_CALLER));
    let ep = cap.ep;
    match e.endpoint(ep).state {
        EpState::Idle | EpState::Recv => {
            if blocking {
                let state = ThreadState::BlockedOnReceive {
                    ep,
                    can_grant: cap.can_grant(),
                };
                sched::set_thread_state(e, r, state);
                queue::append(e, ep, r, EpState::Recv);
            } else {
                // seL4's `doNBRecvFailedTransfer` sets only the badge; here
                // `rsi` is defined too.
                let mut regs = e.regs(r);
                regs.rdi = 0;
                regs.rsi = 0;
                e.set_regs(r, &regs);
            }
        }
        EpState::Send => {
            let s = queue::take_head(e, ep);
            let ThreadState::BlockedOnSend {
                badge,
                can_grant,
                can_grant_reply,
                is_call,
                ..
            } = e.state(s)
            else {
                panic!("a thread in a Send queue is not sending");
            };
            transfer(e, s, r, badge);
            if is_call {
                debug_assert!(can_grant || can_grant_reply);
                setup_caller_cap(e, s, r, cap.can_grant());
            } else {
                sched::set_thread_state(e, s, ThreadState::Running);
                sched::make_runnable(e, s);
            }
        }
    }
}

/// The reply phase, `reply(R, slot)` of `docs/design.md`: `Reply` and the
/// reply phase of `ReplyRecv` with `slot` = `r`'s caller slot, and `Send`,
/// `NBSend` or `Call` on a reply capability in a CSpace slot.
///
/// An empty slot does nothing, so a restarted `ReplyRecv` is harmless.
/// Otherwise the reply capability, to a caller `C`, is deleted first; then
/// either `C` gets `r`'s message (badge 0) and becomes `Running`, or, if
/// `C` is waiting for the reply to a fault, the fault-reply rule reads
/// `r`'s message, `C` becomes `Restart` or `Inactive`, and its fault is
/// cleared. A reply never blocks.
pub fn reply<E: IpcEnv + ?Sized>(e: &mut E, r: TcbRef, slot: SlotAddr) {
    let cap = e.load(slot).cap;
    if cap.cap_type() != CapType::Reply || cap.is_reply_master() {
        // A caller slot holds nothing else, and no CPtr reaches a master.
        debug_assert!(cap.is_null(), "replying with {cap:?}");
        return;
    }
    let c = TcbRef::new(cap.object()).expect("a reply capability names a TCB");
    // The capability's Grant decides whether capabilities move with the
    // reply (M6); a reply moves none in M5.
    delete_one(e, slot);
    debug_assert_eq!(e.state(c), ThreadState::BlockedOnReply);
    match e.fault(c) {
        None => {
            transfer(e, r, c, 0);
            sched::set_thread_state(e, c, ThreadState::Running);
            sched::make_runnable(e, c);
        }
        Some(fault) => {
            let rregs = e.regs(r);
            let info = MessageInfo::from_word(rregs.rsi);
            let mut words = [0; FAULT_REPLY_MAX];
            let length = (info.sent_length() as usize).min(FAULT_REPLY_MAX);
            let n = read_message(e, r, &rregs, &mut words[..length]);
            let mut cregs = e.regs(c);
            let outcome = regs::fault_reply(&fault, info.label(), &words[..n], &mut cregs);
            // Whatever the reply set, the thread leaves by `iretq`
            // (`docs/abi.md`, "Fault replies").
            cregs.set_exit(Exit::Iret);
            e.set_regs(c, &cregs);
            e.set_fault(c, None);
            match outcome {
                FaultOutcome::Restart => {
                    sched::set_thread_state(e, c, ThreadState::Restart);
                    sched::make_runnable(e, c);
                }
                FaultOutcome::Inactive => {
                    sched::set_thread_state(e, c, ThreadState::Inactive);
                }
            }
        }
    }
}

/// `sender` waits for the reply that `receiver` now owes it: it becomes
/// `BlockedOnReply`, and `receiver`'s caller slot gets a reply capability
/// to it with Grant `grant`, derived from its master at depth 1 (seL4
/// `setupCallerCap`). The caller slot is empty: a receiver blocked in
/// `Recv` has an empty one, and a receive phase emptied its own.
fn setup_caller_cap<E: IpcEnv + ?Sized>(e: &mut E, sender: TcbRef, receiver: TcbRef, grant: bool) {
    sched::set_thread_state(e, sender, ThreadState::BlockedOnReply);
    let master = sender.slot(TCB_SLOT_REPLY);
    let caller = receiver.slot(TCB_SLOT_CALLER);
    let m = e.load(master).cap;
    let has_master = m.cap_type() == CapType::Reply
        && m.is_reply_master()
        && m.object() == sender.get()
        && !cdt::has_children(e, master);
    let free = e.load(caller).cap.is_null();
    debug_assert!(
        has_master,
        "a calling thread has its master reply capability"
    );
    debug_assert!(free, "the receiver's caller slot is empty");
    if has_master && free {
        let reply = Cap::reply(sender.get(), false, grant);
        let inserted = cdt::insert_derived(e, master, caller, reply, false);
        debug_assert!(inserted.is_ok(), "a master is at depth 0");
    }
}

/// Deletes the capability in `slot`, a caller slot or a reply
/// capability's: never a container, so the deletion has no preemption
/// point.
fn delete_one<E: IpcEnv + ?Sized>(e: &mut E, slot: SlotAddr) {
    debug_assert!(matches!(
        e.load(slot).cap.cap_type(),
        CapType::Null | CapType::Reply
    ));
    let done = cnode::delete(e, slot);
    debug_assert!(done.is_ok(), "deleting a reply capability never preempts");
}

// ---------------------------------------------------------------------------
// Message transfer
// ---------------------------------------------------------------------------

/// `transfer(S, R, badge, g, E)` of `docs/design.md` without capability
/// transfer, which M6 adds: copies one message from `s` to `r`.
///
/// - If `s` has a fault, the fault encoder makes the message; the kernel
///   supplies its words, so only `r`'s buffer matters.
/// - Otherwise the message is `s`'s `MessageInfo` (from `rsi`, a length
///   above 120 counting as 120) and message registers: MR0 to MR3 always,
///   MR4 and up only if `s` has a readable IPC buffer and `r` a writable
///   one.
///
/// `r` gets the badge in `rdi`, the label and the delivered length in
/// `rsi` (`extra_caps` and `caps_unwrapped` 0), and the delivered message
/// registers; its others keep their values.
pub fn transfer<E: IpcEnv + ?Sized>(e: &mut E, s: TcbRef, r: TcbRef, badge: u64) {
    let sregs = e.regs(s);
    match e.fault(s) {
        Some(fault) => {
            let msg = regs::fault_message(&fault, &sregs);
            deliver(e, r, badge, msg.label, msg.mrs());
        }
        None => {
            let info = MessageInfo::from_word(sregs.rsi);
            let mut words = [0; MSG_MAX_LENGTH];
            let n = read_message(e, s, &sregs, &mut words[..info.sent_length() as usize]);
            deliver(e, r, badge, info.label(), &words[..n]);
        }
    }
}

/// Reads `t`'s message registers into `out`, MR0 first: MR0 to MR3 from
/// `regs`, its saved registers, and MR4 and up from its IPC buffer if it
/// has a readable one. Returns how many it read: `out.len()`, or at most 4
/// without a readable buffer.
pub fn read_message<E: IpcEnv + ?Sized>(e: &E, t: TcbRef, regs: &Regs, out: &mut [u64]) -> usize {
    debug_assert!(out.len() <= MSG_MAX_LENGTH);
    let readable = out.len() <= MSG_REG_COUNT || tcb::buffer_word(e, t, 0, false).is_some();
    let n = if readable { out.len() } else { MSG_REG_COUNT };
    for (i, w) in out[..n].iter_mut().enumerate() {
        *w = if i < MSG_REG_COUNT {
            regs.message_register(i)
        } else {
            let at = tcb::buffer_word(e, t, word::MSG + i, false).expect("a readable buffer");
            e.read_buffer_word(at)
        };
    }
    n
}

/// Gives `r` a message: `badge` in `rdi`, `label` and the delivered length
/// in `rsi`, and `words` as MR0 and up, cut to 4 words unless `r` has a
/// writable IPC buffer. Returns the delivered length.
fn deliver<E: IpcEnv + ?Sized>(
    e: &mut E,
    r: TcbRef,
    badge: u64,
    label: u64,
    words: &[u64],
) -> usize {
    let writable = words.len() <= MSG_REG_COUNT || tcb::buffer_word(e, r, 0, true).is_some();
    let n = if writable { words.len() } else { MSG_REG_COUNT };
    let mut regs = e.regs(r);
    for (i, w) in words[..n.min(MSG_REG_COUNT)].iter().enumerate() {
        regs.set_message_register(i, *w);
    }
    regs.rdi = badge;
    regs.rsi = MessageInfo::new(label, 0, 0, n as u64).word();
    e.set_regs(r, &regs);
    for (i, w) in words.iter().enumerate().take(n).skip(MSG_REG_COUNT) {
        let at = tcb::buffer_word(e, r, word::MSG + i, true).expect("a writable buffer");
        e.write_buffer_word(at, *w);
    }
    n
}

/// The kernel's reply to a successful invocation by `Call`: `rdi` 0 and
/// `rsi` = label 0 with `length` result words, which the invocation already
/// wrote as MR0 and up.
pub fn reply_success<E: IpcEnv + ?Sized>(e: &mut E, t: TcbRef, length: usize) {
    let mut regs = e.regs(t);
    regs.rdi = 0;
    regs.rsi = MessageInfo::new(0, 0, 0, length as u64).word();
    e.set_regs(t, &regs);
}

/// The kernel's error reply to an invocation by `Call` (`docs/abi.md`,
/// "Errors"): `rdi` 0, the error code as the label, and the detail words as
/// MR0 and up, cut to 4 without a writable IPC buffer.
pub fn reply_error<E: IpcEnv + ?Sized>(e: &mut E, t: TcbRef, err: SyscallError) {
    let (words, n) = err.detail();
    deliver(e, t, 0, err.code(), &words[..n]);
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

/// `cancel_ipc(T)` (`docs/design.md`, "Deletion and cancellation"), which
/// the kernel's [`crate::tcb::Threads::cancel_ipc`] calls for Suspend,
/// Resume and TCB deletion. A thread blocked on an endpoint leaves its
/// queue; one waiting for a reply loses the one reply capability derived
/// from its master, wherever it is. Either becomes `Inactive`. A thread in
/// any other state keeps it. In every state the pending fault is cleared,
/// so a thread suspended while its fault waits never sends it later.
pub fn cancel_ipc<E: IpcEnv + ?Sized>(e: &mut E, t: TcbRef) {
    match e.state(t) {
        ThreadState::BlockedOnSend { ep, .. } | ThreadState::BlockedOnReceive { ep, .. } => {
            queue::remove(e, ep, t);
            sched::set_thread_state(e, t, ThreadState::Inactive);
        }
        ThreadState::BlockedOnReply => {
            if let Some(reply) = cdt::first_child(e, t.slot(TCB_SLOT_REPLY)) {
                debug_assert!(e.load(reply).cap.object() == t.get());
                delete_one(e, reply);
            }
            sched::set_thread_state(e, t, ThreadState::Inactive);
        }
        // Nothing makes this state before M6's notifications, whose
        // `cancel_signal` goes here.
        ThreadState::BlockedOnNotification { .. } => {
            sched::set_thread_state(e, t, ThreadState::Inactive);
        }
        ThreadState::Inactive | ThreadState::Running | ThreadState::Restart => {}
    }
    e.set_fault(t, None);
}

/// `cancel_all_ipc(E)`: the last capability to `ep` is being deleted.
/// Every queued thread leaves, in queue order, with its fault cleared, and
/// becomes `Restart`, made runnable, so it re-executes its system call or
/// faulting instruction and resolves its `CPtr` afresh; `ep` becomes `Idle`.
/// Not preemptible, as in seL4 (`cancelAllIPC`): one step per queued
/// thread.
pub fn cancel_all_ipc<E: IpcEnv + ?Sized>(e: &mut E, ep: EpRef) {
    let q = e.endpoint(ep);
    if q.state == EpState::Idle {
        return;
    }
    e.set_endpoint(ep, &queue::Endpoint::IDLE);
    let mut next = q.head;
    while let Some(t) = next {
        next = e.ep_links(t).1;
        e.set_ep_prev(t, None);
        e.set_ep_next(t, None);
        e.set_fault(t, None);
        sched::set_thread_state(e, t, ThreadState::Restart);
        sched::make_runnable(e, t);
    }
}

/// The IPC part of the kernel's [`crate::kernel::Kernel::finalise`] hook
/// (`docs/design.md`, "Deletion and finalisation"): the last capability to
/// an endpoint releases its queue with [`cancel_all_ipc`]. A reply
/// capability needs nothing: a one-shot one deleted unused leaves its
/// caller `BlockedOnReply`, and a master is deleted only by its TCB's
/// finalisation, after [`cancel_ipc`] removed the one derived from it. A
/// TCB's hook calls [`crate::tcb::suspend`] itself.
pub fn finalise<E: IpcEnv + ?Sized>(e: &mut E, cap: Cap, last: bool) {
    if last && let Some(ep) = EndpointCap::from_cap(&cap) {
        cancel_all_ipc(e, ep.ep);
    }
}

// ---------------------------------------------------------------------------
// Fault delivery
// ---------------------------------------------------------------------------

/// A fault that could not be delivered: the thread is `Inactive`, and a
/// debug kernel prints both faults and the thread's `rip` (seL4
/// `handleDoubleFault`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct DoubleFault {
    /// The thread, now `Inactive`.
    pub thread: TcbRef,
    /// The fault it raised.
    pub fault: Fault,
    /// The capability fault of its fault endpoint: the `fault_ep` lookup
    /// failed, or found no endpoint with Write and Grant or GrantReply
    /// (`MissingCapability`, 0 bits left, as seL4's `sendFaultIPC`).
    pub handler: Fault,
}

/// Delivers `fault`, which `t` raised (`docs/design.md`, "Delivery"):
/// `t`'s `fault_ep` is resolved in its CSpace now, and must be an endpoint
/// capability with Write and Grant or GrantReply. Then the fault is stored
/// in `t` and sent as a `Call` with that capability's badge and rights, so
/// `t` becomes `BlockedOnSend` until a handler receives it, then
/// `BlockedOnReply`. Otherwise `t` becomes `Inactive` holding no fault, and
/// the error says why.
pub fn deliver_fault<E: IpcEnv + ?Sized>(
    e: &mut E,
    t: TcbRef,
    fault: Fault,
) -> Result<(), DoubleFault> {
    let cptr = e.fault_ep(t);
    let root = e.load(t.slot(TCB_SLOT_CSPACE)).cap;
    let handler = cspace::lookup_cap(e, root, cptr).and_then(|slot| {
        EndpointCap::from_cap(&e.load(slot).cap)
            .filter(EndpointCap::can_call)
            .ok_or(LookupFailure::MissingCapability { bits_left: 0 })
    });
    match handler {
        Ok(ep) => {
            e.set_fault(t, Some(fault));
            send(e, t, &ep, true, true);
            Ok(())
        }
        Err(failure) => {
            sched::set_thread_state(e, t, ThreadState::Inactive);
            Err(DoubleFault {
                thread: t,
                fault,
                handler: Fault::CapFault {
                    addr: cptr,
                    in_recv_phase: false,
                    failure,
                },
            })
        }
    }
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// Checks the IPC invariants of `docs/design.md`, "IPC" ("Invariants"),
/// over the given threads and endpoints, as they hold between kernel
/// entries and when any function here returns:
///
/// - each endpoint is `Idle` exactly when its queue is empty; its links
///   run both ways from head to tail; in `Send` every queued thread is
///   `BlockedOnSend` on it and in `Recv` `BlockedOnReceive`;
/// - each thread blocked on an endpoint is in that endpoint's queue, and a
///   thread blocked on none has null queue links;
/// - a `BlockedOnReceive` thread has an empty caller slot;
/// - a thread holds a fault only while `BlockedOnSend` in a `Call` or
///   `BlockedOnReply`;
/// - each thread's `reply` slot holds its own master reply capability, with
///   Grant, and at most one capability derived from it: a reply capability
///   to it, only while it is `BlockedOnReply`;
/// - each caller slot is empty or holds the one reply capability derived
///   from a `BlockedOnReply` thread's master.
///
/// A queue longer than `threads` is reported as a cycle.
pub fn check<E: IpcEnv + ?Sized>(
    e: &E,
    threads: &[TcbRef],
    endpoints: &[EpRef],
) -> Result<(), &'static str> {
    for &ep in endpoints {
        check_queue(e, ep, threads.len())?;
    }
    for &t in threads {
        match e.state(t) {
            ThreadState::BlockedOnSend { ep, .. } | ThreadState::BlockedOnReceive { ep, .. } => {
                check_queue(e, ep, threads.len())?;
                if !in_queue(e, ep, t, threads.len()) {
                    return Err("a blocked thread is not in its endpoint's queue");
                }
            }
            _ => {
                if e.ep_links(t) != (None, None) {
                    return Err("a thread not blocked on an endpoint has queue links");
                }
            }
        }
        let state = e.state(t);
        if matches!(state, ThreadState::BlockedOnReceive { .. })
            && !e.load(t.slot(TCB_SLOT_CALLER)).cap.is_null()
        {
            return Err("a receiving thread holds a reply capability");
        }
        if e.fault(t).is_some()
            && !matches!(
                state,
                ThreadState::BlockedOnSend { is_call: true, .. } | ThreadState::BlockedOnReply
            )
        {
            return Err("a thread holds a fault outside fault delivery");
        }
        check_reply_caps(e, t)?;
    }
    Ok(())
}

/// The queue checks of [`check`] for one endpoint.
fn check_queue<E: IpcEnv + ?Sized>(e: &E, ep: EpRef, limit: usize) -> Result<(), &'static str> {
    let q = e.endpoint(ep);
    if q.head.is_none() != q.tail.is_none() {
        return Err("endpoint queue with a head but no tail");
    }
    if (q.state == EpState::Idle) != q.head.is_none() {
        return Err("endpoint is Idle exactly when its queue is empty: violated");
    }
    let mut prev = None;
    let mut cur = q.head;
    let mut n = 0;
    while let Some(t) = cur {
        n += 1;
        if n > limit {
            return Err("endpoint queue longer than the threads: a cycle");
        }
        let (back, next) = e.ep_links(t);
        if back != prev {
            return Err("endpoint queue link does not point back");
        }
        let ok = match (q.state, e.state(t)) {
            (EpState::Send, ThreadState::BlockedOnSend { ep: on, .. })
            | (EpState::Recv, ThreadState::BlockedOnReceive { ep: on, .. }) => on == ep,
            _ => false,
        };
        if !ok {
            return Err("queued thread not blocked as its endpoint's state says");
        }
        prev = Some(t);
        cur = next;
    }
    if q.tail != prev {
        return Err("endpoint tail is not the last queued thread");
    }
    Ok(())
}

/// Whether `t` is in `ep`'s queue, which [`check_queue`] accepted.
fn in_queue<E: IpcEnv + ?Sized>(e: &E, ep: EpRef, t: TcbRef, limit: usize) -> bool {
    let mut cur = e.endpoint(ep).head;
    for _ in 0..limit {
        match cur {
            Some(x) if x == t => return true,
            Some(x) => cur = e.ep_links(x).1,
            None => return false,
        }
    }
    false
}

/// The reply capability checks of [`check`] for one thread.
fn check_reply_caps<E: IpcEnv + ?Sized>(e: &E, t: TcbRef) -> Result<(), &'static str> {
    let master = t.slot(TCB_SLOT_REPLY);
    let m = e.load(master);
    if m.cap.cap_type() != CapType::Reply
        || !m.cap.is_reply_master()
        || m.cap.object() != t.get()
        || !m.cap.rights().contains(Rights::GRANT)
        || m.node.depth() != 0
        || !m.node.original()
        || m.node.prev().is_some()
    {
        return Err("a reply slot does not hold its thread's master");
    }
    if let Some(child) = cdt::first_child(e, master) {
        let c = e.load(child);
        if c.cap.cap_type() != CapType::Reply
            || c.cap.is_reply_master()
            || c.cap.object() != t.get()
        {
            return Err("a master has a child that is not a reply capability to its thread");
        }
        if e.state(t) != ThreadState::BlockedOnReply {
            return Err("a reply capability names a thread not waiting for a reply");
        }
        if c.node
            .next()
            .is_some_and(|n| e.load(n).node.low() > m.node.depth())
        {
            return Err("a master has two reply capabilities derived from it");
        }
    }
    let caller = e.load(t.slot(TCB_SLOT_CALLER)).cap;
    if !caller.is_null() {
        let target = (caller.cap_type() == CapType::Reply && !caller.is_reply_master())
            .then(|| TcbRef::new(caller.object()))
            .flatten();
        let Some(target) = target else {
            return Err("a caller slot holds something other than a reply capability");
        };
        if cdt::first_child(e, target.slot(TCB_SLOT_REPLY)) != Some(t.slot(TCB_SLOT_CALLER)) {
            return Err("a caller slot's reply capability is not derived from its target's master");
        }
        if e.state(target) != ThreadState::BlockedOnReply {
            return Err("a caller slot names a thread not waiting for a reply");
        }
    }
    Ok(())
}
