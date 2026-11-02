//! The scheduler (`docs/design.md`, "Scheduling"; ADR 0013): seL4's classic
//! fixed-priority round-robin with 256 priorities, a one-tick slice, and a
//! woken thread that does not run at once appended to its queue.
//!
//! [`Scheduler`] holds the 256 ready queues, intrusive lists through the
//! TCBs' `sched_prev` and `sched_next`, a two-level bitmap of the non-empty
//! ones, the scheduler action and the current thread (`None` for the idle
//! thread, which is the kernel's and never queued). The functions here are
//! generic over [`Scheduling`], a [`Tcbs`] that also holds the scheduler.
//!
//! Between kernel entries, these hold (checked by [`check`] and the
//! proptest in `sched/tests.rs`):
//!
//! - the current thread is runnable, or there is none (idle);
//! - every queued thread is runnable, in exactly the queue of its priority,
//!   and not the current one; bit `p` of the bitmap is set exactly when
//!   queue `p` is non-empty;
//! - no queued thread has a higher priority than the current one;
//! - the action is `ResumeCurrent`.
//!
//! The kernel adds the rule that every runnable thread but the current one
//! is queued: a thread becomes runnable only through [`make_runnable`].

use crate::error::SyscallError;
use crate::tcb::{TcbRef, Tcbs, ThreadState};

/// Priorities: 0 (lowest) to 255.
pub const PRIORITIES: usize = 256;
/// The lowest priority.
pub const MIN_PRIO: u8 = 0;
/// The highest priority.
pub const MAX_PRIO: u8 = 255;
/// Ticks in a time slice: one 10 ms tick of the 100 Hz timer.
pub const TIME_SLICE_TICKS: u64 = 1;

/// What [`schedule`] does at the end of the kernel entry (seL4
/// `ksSchedulerAction`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// The current thread goes on.
    ResumeCurrent,
    /// Choose the highest-priority runnable thread.
    ChooseNew,
    /// A thread woken while the action was `ResumeCurrent`: it runs if
    /// [`schedule`]'s rule lets it, else it joins its queue. It is
    /// runnable, not queued and not the current thread.
    SwitchTo(TcbRef),
}

/// The ready queues, their bitmap, the action and the current thread.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Scheduler {
    heads: [Option<TcbRef>; PRIORITIES],
    tails: [Option<TcbRef>; PRIORITIES],
    /// Bit `i` is set when `l2[i]` is non-zero.
    l1: u64,
    /// Bit `p % 64` of `l2[p / 64]` is set when queue `p` is non-empty.
    l2: [u64; PRIORITIES / 64],
    action: Action,
    current: Option<TcbRef>,
}

impl Default for Scheduler {
    fn default() -> Scheduler {
        Scheduler::new()
    }
}

impl Scheduler {
    /// Empty queues, the idle thread current, `ResumeCurrent`.
    pub const fn new() -> Scheduler {
        Scheduler {
            heads: [None; PRIORITIES],
            tails: [None; PRIORITIES],
            l1: 0,
            l2: [0; PRIORITIES / 64],
            action: Action::ResumeCurrent,
            current: None,
        }
    }

    /// The current thread; `None` while the idle thread runs.
    pub const fn current(&self) -> Option<TcbRef> {
        self.current
    }

    /// Makes `t` the current thread without touching the queues: for host
    /// tests that start from a running thread. `t` must be runnable and not
    /// queued; the kernel's threads become current only through
    /// [`schedule`].
    pub fn set_current(&mut self, t: Option<TcbRef>) {
        self.current = t;
    }

    /// The pending action.
    pub const fn action(&self) -> Action {
        self.action
    }

    /// The first thread of queue `prio`.
    pub const fn head(&self, prio: u8) -> Option<TcbRef> {
        self.heads[prio as usize]
    }

    /// The last thread of queue `prio`.
    pub const fn tail(&self, prio: u8) -> Option<TcbRef> {
        self.tails[prio as usize]
    }

    /// Whether bit `prio` of the bitmap is set.
    pub const fn bit(&self, prio: u8) -> bool {
        self.l2[prio as usize / 64] >> (prio % 64) & 1 == 1
    }

    /// The highest priority with a queued thread: `64 i + 63 − lzcnt(l2[i])`
    /// with `i = 63 − lzcnt(l1)`. `None` if every queue is empty.
    pub const fn highest(&self) -> Option<u8> {
        if self.l1 == 0 {
            return None;
        }
        let i = 63 - self.l1.leading_zeros() as usize;
        let j = 63 - self.l2[i].leading_zeros() as usize;
        Some((64 * i + j) as u8)
    }

    fn mark(&mut self, prio: u8) {
        let i = prio as usize / 64;
        self.l2[i] |= 1 << (prio % 64);
        self.l1 |= 1 << i;
    }

    fn unmark(&mut self, prio: u8) {
        let i = prio as usize / 64;
        self.l2[i] &= !(1 << (prio % 64));
        if self.l2[i] == 0 {
            self.l1 &= !(1 << i);
        }
    }
}

/// [`Tcbs`] plus the scheduler. The kernel implements it on `arch::Objects`
/// over its one [`Scheduler`]; host tests over fake memory.
pub trait Scheduling: Tcbs {
    /// The scheduler.
    fn scheduler(&self) -> &Scheduler;
    /// The scheduler, to change it.
    fn scheduler_mut(&mut self) -> &mut Scheduler;
}

/// Puts `t` at the head of its priority's queue (seL4 `tcbSchedEnqueue`).
/// Nothing happens if it is queued already.
pub fn enqueue<E: Scheduling + ?Sized>(e: &mut E, t: TcbRef) {
    if e.queued(t) {
        return;
    }
    let p = e.priority(t);
    let head = e.scheduler().head(p);
    e.set_sched_prev(t, None);
    e.set_sched_next(t, head);
    match head {
        Some(h) => e.set_sched_prev(h, Some(t)),
        None => {
            let s = e.scheduler_mut();
            s.tails[p as usize] = Some(t);
            s.mark(p);
        }
    }
    e.scheduler_mut().heads[p as usize] = Some(t);
    e.set_queued(t, true);
}

/// Puts `t` at the tail of its priority's queue (seL4 `tcbSchedAppend`).
/// Nothing happens if it is queued already.
pub fn append<E: Scheduling + ?Sized>(e: &mut E, t: TcbRef) {
    if e.queued(t) {
        return;
    }
    let p = e.priority(t);
    let tail = e.scheduler().tail(p);
    e.set_sched_prev(t, tail);
    e.set_sched_next(t, None);
    match tail {
        Some(x) => e.set_sched_next(x, Some(t)),
        None => {
            let s = e.scheduler_mut();
            s.heads[p as usize] = Some(t);
            s.mark(p);
        }
    }
    e.scheduler_mut().tails[p as usize] = Some(t);
    e.set_queued(t, true);
}

/// Takes `t` out of its ready queue (seL4 `tcbSchedDequeue`). Nothing
/// happens if it is not queued. Its priority must be the one it was queued
/// at: [`set_priority`] dequeues before it changes the priority.
pub fn dequeue<E: Scheduling + ?Sized>(e: &mut E, t: TcbRef) {
    if !e.queued(t) {
        return;
    }
    let p = e.priority(t);
    let (prev, next) = e.sched_links(t);
    match prev {
        Some(x) => e.set_sched_next(x, next),
        None => e.scheduler_mut().heads[p as usize] = next,
    }
    match next {
        Some(x) => e.set_sched_prev(x, prev),
        None => e.scheduler_mut().tails[p as usize] = prev,
    }
    if e.scheduler().head(p).is_none() {
        e.scheduler_mut().unmark(p);
    }
    e.set_sched_prev(t, None);
    e.set_sched_next(t, None);
    e.set_queued(t, false);
}

/// seL4 `rescheduleRequired`: a pending `SwitchTo` target joins the tail of
/// its queue, and the action becomes `ChooseNew`.
pub fn reschedule<E: Scheduling + ?Sized>(e: &mut E) {
    if let Action::SwitchTo(t) = e.scheduler().action() {
        append(e, t);
    }
    e.scheduler_mut().action = Action::ChooseNew;
}

/// A thread became runnable (seL4 `possibleSwitchTo`): with the action
/// `ResumeCurrent` it becomes `SwitchTo(t)`; otherwise [`reschedule`] runs
/// and `t` joins the tail of its queue. Nothing happens for the current
/// thread, which [`schedule`] puts back itself, or for a thread already
/// queued or pending. `t` must be runnable.
pub fn make_runnable<E: Scheduling + ?Sized>(e: &mut E, t: TcbRef) {
    debug_assert!(e.state(t).is_runnable(), "making a stopped thread runnable");
    let s = e.scheduler();
    if s.current() == Some(t) || s.action() == Action::SwitchTo(t) || e.queued(t) {
        return;
    }
    if s.action() == Action::ResumeCurrent {
        e.scheduler_mut().action = Action::SwitchTo(t);
    } else {
        reschedule(e);
        append(e, t);
    }
}

/// Sets `t`'s state and keeps the scheduler right (seL4 `setThreadState`
/// with `scheduleTCB`, and the dequeue of `suspend`). A thread that stops
/// being runnable leaves its ready queue, a `SwitchTo` naming it becomes
/// `ChooseNew`, and if it is the current thread with the action
/// `ResumeCurrent`, the action becomes `ChooseNew`. A thread made runnable
/// is not queued here: call [`make_runnable`].
pub fn set_thread_state<E: Scheduling + ?Sized>(e: &mut E, t: TcbRef, state: ThreadState) {
    e.set_state(t, state);
    if state.is_runnable() {
        return;
    }
    dequeue(e, t);
    let s = e.scheduler_mut();
    if s.action == Action::SwitchTo(t)
        || (s.current == Some(t) && s.action == Action::ResumeCurrent)
    {
        s.action = Action::ChooseNew;
    }
}

/// Picks the thread that runs when the kernel entry ends (seL4 `schedule`
/// and `chooseThread`, with ADR 0013's tail rule), makes it current and
/// returns it; `None` means the idle thread. Unless the action is
/// `ResumeCurrent`:
///
/// 1. A runnable, unqueued current thread goes to the head of its queue, so
///    a preempted thread keeps its turn.
/// 2. For `SwitchTo(c)`, with `h` the highest queued priority: `c` runs if
///    its priority is above `h`, or equal to it and the current thread is no
///    longer runnable (the idle thread counts as not runnable). Otherwise
///    `c` joins the tail of its queue.
/// 3. If nothing was picked, the head of the highest non-empty queue runs,
///    or the idle thread.
///
/// The thread picked leaves its queue: the running thread is not queued.
/// `ResumeCurrent` with a current thread that is no longer runnable is
/// treated as `ChooseNew`. The caller switches address space, FS and GS
/// base and FP state if the thread changed, then [`crate::tcb::activate`]s
/// it.
pub fn schedule<E: Scheduling + ?Sized>(e: &mut E) -> Option<TcbRef> {
    let action = e.scheduler().action();
    let current = e.scheduler().current();
    let current_runnable = current.is_some_and(|c| e.state(c).is_runnable());
    if action == Action::ResumeCurrent && (current.is_none() || current_runnable) {
        return current;
    }
    if let Some(c) = current
        && current_runnable
    {
        enqueue(e, c);
    }
    let mut next = None;
    if let Action::SwitchTo(c) = action {
        debug_assert!(e.state(c).is_runnable() && !e.queued(c) && Some(c) != current);
        let p = e.priority(c);
        let wins = match e.scheduler().highest() {
            None => true,
            Some(h) => p > h || (p == h && !current_runnable),
        };
        if wins {
            next = Some(c);
        } else {
            append(e, c);
        }
    }
    if next.is_none() {
        next = e.scheduler().highest().and_then(|p| e.scheduler().head(p));
    }
    if let Some(n) = next {
        dequeue(e, n);
    }
    let s = e.scheduler_mut();
    s.current = next;
    s.action = Action::ResumeCurrent;
    next
}

/// A timer tick (seL4 `timerTick`): the current thread's slice shrinks by
/// one tick; at its end the slice is refilled, the thread joins the tail of
/// its queue and [`reschedule`] runs. Only a runnable current thread is
/// charged: the idle thread has no slice, and a thread that stopped in
/// this entry before the tick (it suspended or deleted itself) must not be
/// queued.
pub fn tick<E: Scheduling + ?Sized>(e: &mut E) {
    let Some(c) = e.scheduler().current() else {
        return;
    };
    if !e.state(c).is_runnable() {
        return;
    }
    let slice = e.time_slice(c);
    if slice > 1 {
        e.set_time_slice(c, slice - 1);
    } else {
        e.set_time_slice(c, TIME_SLICE_TICKS);
        append(e, c);
        reschedule(e);
    }
}

/// `Yield` (system call 7, seL4 `handleYield`): the current thread joins
/// the tail of its queue with the slice it has left, and [`reschedule`]
/// runs, so the highest-priority runnable thread runs next, perhaps the
/// caller again.
pub fn yield_now<E: Scheduling + ?Sized>(e: &mut E) {
    let Some(c) = e.scheduler().current() else {
        return;
    };
    if !e.state(c).is_runnable() {
        return;
    }
    dequeue(e, c);
    append(e, c);
    reschedule(e);
}

/// Changes `t`'s priority (seL4 `setPriority`, non-MCS). A queued thread
/// leaves its queue first. Then a runnable `t` is the current thread, which
/// [`reschedule`]s so that it goes to the head of its new queue and a
/// higher ready thread runs, or another thread, made runnable again as a
/// wake-up is. A blocked thread only changes priority: endpoint queues are
/// FIFO.
pub fn set_priority<E: Scheduling + ?Sized>(e: &mut E, t: TcbRef, priority: u8) {
    dequeue(e, t);
    e.set_priority(t, priority);
    if e.state(t).is_runnable() {
        if e.scheduler().current() == Some(t) {
            reschedule(e);
        } else {
            make_runnable(e, t);
        }
    }
}

/// seL4 `checkPrio`: a new priority or MCP must be at most the authority's
/// MCP. The whole word is compared before it is narrowed, so any value from
/// 256 up fails. Returns it as a `u8`, or `RangeError` 0 to that MCP.
pub fn check_prio<T: Tcbs + ?Sized>(
    e: &T,
    value: u64,
    authority: TcbRef,
) -> Result<u8, SyscallError> {
    let mcp = e.mcp(authority);
    if value > mcp as u64 {
        return Err(SyscallError::RangeError {
            min: MIN_PRIO as u64,
            max: mcp as u64,
        });
    }
    Ok(value as u8)
}

/// Checks the queues against the bitmap and the threads in them, as they
/// hold at any point of a kernel entry: each queue's links run both ways
/// from head to tail; every thread in queue `p` is marked queued, has
/// priority `p` and is runnable; bit `p` is set exactly when queue `p` is
/// non-empty, and `l1` matches `l2`; a `SwitchTo` target is runnable,
/// unqueued and not current. (A tick or a yield queues the current thread
/// until [`schedule`] runs.) Visits each queued thread once, so a cycle
/// shows up as a queue longer than `limit`. Returns the number of queued
/// threads.
pub fn check<E: Scheduling + ?Sized>(e: &E, limit: usize) -> Result<usize, &'static str> {
    let s = e.scheduler();
    // The bitmap the queues call for, then the walk of the non-empty ones.
    let mut l2 = [0u64; PRIORITIES / 64];
    let mut l1 = 0;
    for p in 0..PRIORITIES {
        if s.heads[p].is_some() != s.tails[p].is_some() {
            return Err("queue with a head but no tail");
        }
        if s.heads[p].is_some() {
            l2[p / 64] |= 1 << (p % 64);
            l1 |= 1 << (p / 64);
        }
    }
    if l2 != s.l2 {
        return Err("bitmap bit does not match its queue");
    }
    if l1 != s.l1 {
        return Err("l1 does not match l2");
    }
    let mut total = 0;
    for p in 0..PRIORITIES {
        if l2[p / 64] >> (p % 64) & 1 == 0 {
            continue;
        }
        let p8 = p as u8;
        let mut prev = None;
        let mut cur = s.heads[p];
        while let Some(t) = cur {
            total += 1;
            if total > limit {
                return Err("more queued threads than exist: a cycle");
            }
            let (back, next) = e.sched_links(t);
            if back != prev {
                return Err("queue link does not point back");
            }
            if !e.queued(t) {
                return Err("thread in a queue but not marked queued");
            }
            if e.priority(t) != p8 {
                return Err("thread in the queue of another priority");
            }
            if !e.state(t).is_runnable() {
                return Err("stopped thread in a ready queue");
            }
            prev = Some(t);
            cur = next;
        }
        if s.tails[p] != prev {
            return Err("tail is not the last thread");
        }
    }
    if let Action::SwitchTo(t) = s.action
        && (!e.state(t).is_runnable() || e.queued(t) || s.current == Some(t))
    {
        return Err("SwitchTo names a stopped, queued or current thread");
    }
    Ok(total)
}

/// [`check`], plus what holds when a kernel entry ends: the action is
/// `ResumeCurrent`, the current thread is runnable and not queued, or idle
/// with every queue empty, and no queued thread has a higher priority.
pub fn check_exit<E: Scheduling + ?Sized>(e: &E, limit: usize) -> Result<usize, &'static str> {
    let n = check(e, limit)?;
    let s = e.scheduler();
    if s.action != Action::ResumeCurrent {
        return Err("kernel exit with a pending action");
    }
    if let Some(c) = s.current {
        if !e.state(c).is_runnable() {
            return Err("current thread not runnable at kernel exit");
        }
        if e.queued(c) {
            return Err("current thread queued at kernel exit");
        }
        if s.highest().is_some_and(|h| h > e.priority(c)) {
            return Err("a queued thread has a higher priority than the current one");
        }
    } else if s.highest().is_some() {
        return Err("idle while a thread is queued");
    }
    Ok(n)
}

#[cfg(test)]
mod tests;
