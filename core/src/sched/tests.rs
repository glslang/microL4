//! Host tests of the scheduler: the decision rules one by one, and a
//! proptest of random operation sequences against a model of 256
//! `VecDeque`s, checking the invariants of `docs/design.md`, "Scheduling",
//! after every step.

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;

use super::*;
use crate::cap::TCB_BITS;
use crate::testing::FakeMemory;

/// Threads in a test world.
const N: usize = 8;
/// The first TCB; thread `i` is at `BASE + i * 2 KiB`.
const BASE: u64 = 0x10000;

/// Fake TCBs and a scheduler.
#[derive(Clone, Debug)]
struct World {
    mem: FakeMemory,
    sched: Scheduler,
}

impl Tcbs for World {
    fn tcb_word(&self, t: TcbRef, offset: u64) -> u64 {
        self.mem.tcb_word(t, offset)
    }

    fn set_tcb_word(&mut self, t: TcbRef, offset: u64, value: u64) {
        self.mem.set_tcb_word(t, offset, value);
    }
}

impl Scheduling for World {
    fn scheduler(&self) -> &Scheduler {
        &self.sched
    }

    fn scheduler_mut(&mut self) -> &mut Scheduler {
        &mut self.sched
    }
}

fn tcb(i: usize) -> TcbRef {
    TcbRef::new(BASE + ((i as u64) << TCB_BITS)).unwrap()
}

fn index(t: TcbRef) -> usize {
    ((t.get() - BASE) >> TCB_BITS) as usize
}

impl World {
    /// `N` new threads, `Inactive`, at the given priorities, with a full
    /// slice; the idle thread current.
    fn new(prios: &[u8]) -> World {
        let mut w = World {
            mem: FakeMemory::new(BASE, (N as u64) << TCB_BITS),
            sched: Scheduler::new(),
        };
        for (i, p) in prios.iter().enumerate() {
            crate::tcb::init(&mut w, tcb(i));
            w.set_priority(tcb(i), *p);
        }
        w
    }

    /// Thread `i` becomes runnable, as a Resume or an IPC wake-up does it.
    fn wake(&mut self, i: usize) {
        set_thread_state(self, tcb(i), ThreadState::Restart);
        make_runnable(self, tcb(i));
    }

    /// The thread indices of queue `p`, head first, walking `next`.
    fn queue(&self, p: u8) -> Vec<usize> {
        let mut v = Vec::new();
        let mut cur = self.sched.head(p);
        while let Some(t) = cur {
            v.push(index(t));
            assert!(v.len() <= N, "cycle in queue {p}");
            cur = self.sched_links(t).1;
        }
        v
    }

    fn current(&self) -> Option<usize> {
        self.sched.current().map(index)
    }

    /// Ends the kernel entry: schedules, checks the exit invariants and
    /// activates the thread picked.
    fn exit(&mut self) -> Option<usize> {
        let t = schedule(self);
        check_exit(self, N).unwrap();
        if let Some(t) = t {
            crate::tcb::activate(self, t);
        }
        t.map(index)
    }
}

#[test]
fn highest_reads_the_two_level_bitmap() {
    let mut s = Scheduler::new();
    assert_eq!(s.highest(), None);
    for p in [0u8, 1, 63, 64, 65, 127, 128, 191, 192, 254, 255] {
        let mut t = Scheduler::new();
        t.mark(p);
        assert_eq!(t.highest(), Some(p));
        assert!(t.bit(p));
        s.mark(p);
        assert_eq!(s.highest(), Some(p));
    }
    for p in [255u8, 254, 192, 191, 128, 127, 65, 64, 63, 1] {
        s.unmark(p);
        assert!(!s.bit(p));
        assert!(s.highest().unwrap() < p);
    }
    s.unmark(0);
    assert_eq!((s.highest(), s.l1), (None, 0));
}

#[test]
fn nothing_runnable_is_idle() {
    let mut w = World::new(&[5; N]);
    reschedule(&mut w);
    assert_eq!(w.exit(), None);
    // A tick or a yield with the idle thread current does nothing.
    tick(&mut w);
    yield_now(&mut w);
    assert_eq!(w.sched.action(), Action::ResumeCurrent);
    assert_eq!(w.exit(), None);
}

#[test]
fn equal_priorities_take_turns_one_tick_each() {
    let mut w = World::new(&[7, 7, 7, 3, 0, 0, 0, 0]);
    for i in 0..4 {
        w.wake(i);
    }
    // The first woken runs at once; the others queue behind it in order.
    assert_eq!(w.exit(), Some(0));
    assert_eq!(w.queue(7), [1, 2]);
    assert_eq!(w.queue(3), [3]);
    let mut order = Vec::new();
    for _ in 0..7 {
        tick(&mut w);
        order.push(w.exit().unwrap());
    }
    // Round-robin: each waits exactly one slice per peer; priority 3 never
    // runs while priority 7 is runnable.
    assert_eq!(order, [1, 2, 0, 1, 2, 0, 1]);
}

#[test]
fn a_preempted_thread_keeps_its_turn() {
    let mut w = World::new(&[7, 7, 9, 0, 0, 0, 0, 0]);
    w.wake(0);
    w.wake(1);
    assert_eq!(w.exit(), Some(0));
    // A higher-priority wake-up preempts thread 0, which goes to the head
    // of its queue, ahead of thread 1.
    w.wake(2);
    assert_eq!(w.exit(), Some(2));
    assert_eq!(w.queue(7), [0, 1]);
    set_thread_state(&mut w, tcb(2), ThreadState::BlockedOnReply);
    assert_eq!(w.exit(), Some(0));
}

#[test]
fn a_woken_thread_that_cannot_run_joins_the_tail() {
    let mut w = World::new(&[7, 7, 7, 3, 0, 0, 0, 0]);
    w.wake(0);
    w.wake(1);
    assert_eq!(w.exit(), Some(0));
    // Equal to the current, still runnable thread: appended, not run.
    w.wake(2);
    assert_eq!(w.sched.action(), Action::SwitchTo(tcb(2)));
    assert_eq!(w.exit(), Some(0));
    assert_eq!(w.queue(7), [1, 2]);
    // Lower than the current thread: appended.
    w.wake(3);
    assert_eq!(w.exit(), Some(0));
    assert_eq!(w.queue(3), [3]);
    // Two wake-ups in one entry: the second goes through reschedule, and
    // both join their queues.
    let mut w = World::new(&[7, 9, 9, 0, 0, 0, 0, 0]);
    w.wake(0);
    assert_eq!(w.exit(), Some(0));
    w.wake(1);
    w.wake(2);
    assert_eq!(w.sched.action(), Action::ChooseNew);
    assert_eq!(w.queue(9), [1, 2]);
    assert_eq!(w.exit(), Some(1));
    assert_eq!(w.queue(9), [2]);
    assert_eq!(w.queue(7), [0]);
}

#[test]
fn the_direct_switch_runs_an_equal_partner_when_the_current_blocks() {
    let mut w = World::new(&[7, 7, 7, 0, 0, 0, 0, 0]);
    w.wake(0);
    w.wake(1);
    assert_eq!(w.exit(), Some(0));
    // Thread 0 Calls thread 2, which a receive wakes, and blocks: thread 2
    // runs at once, ahead of thread 1 that was waiting.
    w.wake(2);
    set_thread_state(&mut w, tcb(0), ThreadState::BlockedOnReply);
    assert_eq!(w.sched.action(), Action::SwitchTo(tcb(2)));
    assert_eq!(w.exit(), Some(2));
    assert_eq!(w.queue(7), [1]);
    // But a lower partner does not run ahead of a higher queued thread.
    let mut w = World::new(&[7, 7, 5, 0, 0, 0, 0, 0]);
    w.wake(0);
    w.wake(1);
    assert_eq!(w.exit(), Some(0));
    w.wake(2);
    set_thread_state(&mut w, tcb(0), ThreadState::BlockedOnReply);
    assert_eq!(w.exit(), Some(1));
    assert_eq!(w.queue(5), [2]);
}

#[test]
fn yield_goes_to_the_tail_with_the_slice_left() {
    let mut w = World::new(&[7, 7, 0, 0, 0, 0, 0, 0]);
    w.set_time_slice(tcb(0), 5);
    w.wake(0);
    w.wake(1);
    assert_eq!(w.exit(), Some(0));
    yield_now(&mut w);
    assert_eq!(w.exit(), Some(1));
    assert_eq!(w.queue(7), [0]);
    assert_eq!(w.time_slice(tcb(0)), 5);
    // Alone at its priority, a yield runs the caller again.
    let mut w = World::new(&[7, 3, 0, 0, 0, 0, 0, 0]);
    w.wake(0);
    w.wake(1);
    assert_eq!(w.exit(), Some(0));
    yield_now(&mut w);
    assert_eq!(w.exit(), Some(0));
}

#[test]
fn a_tick_refills_the_slice_only_at_its_end() {
    let mut w = World::new(&[7, 7, 0, 0, 0, 0, 0, 0]);
    w.set_time_slice(tcb(0), 3);
    w.wake(0);
    w.wake(1);
    assert_eq!(w.exit(), Some(0));
    tick(&mut w);
    assert_eq!(w.exit(), Some(0));
    tick(&mut w);
    assert_eq!(w.exit(), Some(0));
    assert_eq!(w.time_slice(tcb(0)), 1);
    tick(&mut w);
    assert_eq!(w.time_slice(tcb(0)), TIME_SLICE_TICKS);
    assert_eq!(w.exit(), Some(1));
    // A current thread that stopped earlier in the entry is not charged
    // and not queued.
    w.set_time_slice(tcb(1), 4);
    set_thread_state(&mut w, tcb(1), ThreadState::Inactive);
    tick(&mut w);
    assert_eq!(w.time_slice(tcb(1)), 4);
    assert!(!w.queued(tcb(1)));
    assert_eq!(w.exit(), Some(0));
}

#[test]
fn set_priority_moves_runnable_threads() {
    let mut w = World::new(&[7, 7, 5, 0, 0, 0, 0, 0]);
    w.wake(0);
    w.wake(1);
    w.wake(2);
    assert_eq!(w.exit(), Some(0));
    // Raising a queued thread above the current one runs it.
    set_priority(&mut w, tcb(2), 8);
    assert_eq!(w.queue(5), []);
    assert_eq!(w.exit(), Some(2));
    assert_eq!(w.queue(7), [0, 1]);
    // Lowering the current thread lets a higher one run; the current goes
    // to the head of its new queue.
    set_priority(&mut w, tcb(2), 7);
    assert_eq!(w.exit(), Some(2));
    assert_eq!(w.queue(7), [0, 1]);
    set_priority(&mut w, tcb(2), 1);
    assert_eq!(w.exit(), Some(0));
    assert_eq!(w.queue(1), [2]);
    // A blocked thread only changes priority.
    set_thread_state(&mut w, tcb(2), ThreadState::BlockedOnReply);
    set_priority(&mut w, tcb(2), 200);
    assert_eq!(w.priority(tcb(2)), 200);
    assert_eq!(w.exit(), Some(0));
    // The pending `SwitchTo` target keeps its place and its new priority
    // decides.
    w.wake(3);
    assert_eq!(w.sched.action(), Action::SwitchTo(tcb(3)));
    set_priority(&mut w, tcb(3), 9);
    assert_eq!(w.sched.action(), Action::SwitchTo(tcb(3)));
    assert_eq!(w.exit(), Some(3));
}

#[test]
fn stopping_a_pending_or_current_thread_chooses_again() {
    let mut w = World::new(&[7, 9, 0, 0, 0, 0, 0, 0]);
    w.wake(0);
    assert_eq!(w.exit(), Some(0));
    w.wake(1);
    assert_eq!(w.sched.action(), Action::SwitchTo(tcb(1)));
    set_thread_state(&mut w, tcb(1), ThreadState::Inactive);
    assert_eq!(w.sched.action(), Action::ChooseNew);
    assert_eq!(w.exit(), Some(0));
    set_thread_state(&mut w, tcb(0), ThreadState::Inactive);
    assert_eq!(w.sched.action(), Action::ChooseNew);
    assert_eq!(w.exit(), None);
}

#[test]
fn check_prio_bounds_by_the_authority_mcp() {
    let mut w = World::new(&[0; N]);
    for mcp in [0u8, 1, 100, 254, 255] {
        w.set_mcp(tcb(1), mcp);
        let err = Err(SyscallError::RangeError {
            min: 0,
            max: mcp as u64,
        });
        assert_eq!(check_prio(&w, 0, tcb(1)), Ok(0));
        assert_eq!(check_prio(&w, mcp as u64, tcb(1)), Ok(mcp));
        assert_eq!(check_prio(&w, mcp as u64 + 1, tcb(1)), err);
        // The whole word is compared before it is narrowed.
        assert_eq!(check_prio(&w, 256, tcb(1)), err);
        assert_eq!(check_prio(&w, 256 + mcp as u64, tcb(1)), err);
        assert_eq!(check_prio(&w, u64::MAX, tcb(1)), err);
    }
}

#[test]
fn check_finds_broken_queues() {
    let mut w = World::new(&[7, 7, 0, 0, 0, 0, 0, 0]);
    w.wake(0);
    w.wake(1);
    w.exit();
    assert_eq!(check(&w, N), Ok(1));
    let good = w.clone();
    w.set_priority(tcb(1), 6);
    assert!(check(&w, N).is_err());
    let mut w = good.clone();
    w.set_state(tcb(1), ThreadState::Inactive);
    assert!(check(&w, N).is_err());
    let mut w = good.clone();
    w.set_sched_next(tcb(1), Some(tcb(1)));
    assert!(check(&w, N).is_err());
    let mut w = good;
    w.sched.unmark(7);
    assert!(check(&w, N).is_err());
}

// ---------------------------------------------------------------------------
// The proptest against a model
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
enum Op {
    /// A stopped thread becomes runnable: Resume, or an IPC wake-up.
    Wake(usize),
    /// The current thread blocks, as a Call or a receive does.
    BlockCurrent,
    /// A thread stops: the scheduler's part of Suspend.
    Stop(usize),
    SetPriority(usize, u8),
    Tick,
    Yield,
    /// The kernel entry ends.
    Schedule,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ModelAction {
    Resume,
    Choose,
    Switch(usize),
}

/// The scheduler as `docs/design.md` describes it, over plain queues.
#[derive(Clone, Debug)]
struct Model {
    queues: Vec<VecDeque<usize>>,
    current: Option<usize>,
    action: ModelAction,
    runnable: [bool; N],
    prio: [u8; N],
    slice: [u64; N],
}

impl Model {
    fn new(prios: &[u8; N]) -> Model {
        Model {
            queues: vec![VecDeque::new(); PRIORITIES],
            current: None,
            action: ModelAction::Resume,
            runnable: [false; N],
            prio: *prios,
            slice: [TIME_SLICE_TICKS; N],
        }
    }

    fn queued(&self, t: usize) -> bool {
        self.queues[self.prio[t] as usize].contains(&t)
    }

    fn push_head(&mut self, t: usize) {
        if !self.queued(t) {
            self.queues[self.prio[t] as usize].push_front(t);
        }
    }

    fn push_tail(&mut self, t: usize) {
        if !self.queued(t) {
            self.queues[self.prio[t] as usize].push_back(t);
        }
    }

    fn remove(&mut self, t: usize) {
        self.queues[self.prio[t] as usize].retain(|x| *x != t);
    }

    fn highest(&self) -> Option<usize> {
        (0..PRIORITIES).rev().find(|p| !self.queues[*p].is_empty())
    }

    fn reschedule(&mut self) {
        if let ModelAction::Switch(t) = self.action {
            self.push_tail(t);
        }
        self.action = ModelAction::Choose;
    }

    fn make_runnable(&mut self, t: usize) {
        if self.current == Some(t) || self.action == ModelAction::Switch(t) || self.queued(t) {
            return;
        }
        if self.action == ModelAction::Resume {
            self.action = ModelAction::Switch(t);
        } else {
            self.reschedule();
            self.push_tail(t);
        }
    }

    fn stop(&mut self, t: usize) {
        self.runnable[t] = false;
        self.remove(t);
        if self.action == ModelAction::Switch(t)
            || (self.current == Some(t) && self.action == ModelAction::Resume)
        {
            self.action = ModelAction::Choose;
        }
    }

    fn current_runnable(&self) -> bool {
        self.current.is_some_and(|c| self.runnable[c])
    }

    fn schedule(&mut self) {
        let cur_runnable = self.current_runnable();
        if self.action == ModelAction::Resume && (self.current.is_none() || cur_runnable) {
            return;
        }
        if let Some(c) = self.current
            && cur_runnable
        {
            self.push_head(c);
        }
        let mut next = None;
        if let ModelAction::Switch(c) = self.action {
            let p = self.prio[c] as usize;
            let wins = match self.highest() {
                None => true,
                Some(h) => p > h || (p == h && !cur_runnable),
            };
            if wins {
                next = Some(c);
            } else {
                self.push_tail(c);
            }
        }
        if next.is_none() {
            next = self.highest().map(|p| self.queues[p][0]);
        }
        if let Some(n) = next {
            self.remove(n);
        }
        self.current = next;
        self.action = ModelAction::Resume;
    }

    /// Applies `op`; false if it does not apply in this state.
    fn apply(&mut self, op: Op) -> bool {
        match op {
            Op::Wake(t) => {
                if self.runnable[t] {
                    return false;
                }
                self.runnable[t] = true;
                self.make_runnable(t);
            }
            Op::BlockCurrent => match self.current {
                Some(c) if self.runnable[c] => self.stop(c),
                _ => return false,
            },
            Op::Stop(t) => self.stop(t),
            Op::SetPriority(t, p) => {
                self.remove(t);
                self.prio[t] = p;
                if self.runnable[t] {
                    if self.current == Some(t) {
                        self.reschedule();
                    } else {
                        self.make_runnable(t);
                    }
                }
            }
            Op::Tick => {
                if let Some(c) = self.current
                    && self.runnable[c]
                {
                    if self.slice[c] > 1 {
                        self.slice[c] -= 1;
                    } else {
                        self.slice[c] = TIME_SLICE_TICKS;
                        self.push_tail(c);
                        self.reschedule();
                    }
                }
            }
            Op::Yield => match self.current {
                Some(c) if self.runnable[c] => {
                    self.remove(c);
                    self.push_tail(c);
                    self.reschedule();
                }
                _ => return false,
            },
            Op::Schedule => self.schedule(),
        }
        true
    }
}

/// Applies `op` to the world, as the kernel would.
fn apply(w: &mut World, op: Op) {
    match op {
        Op::Wake(t) => w.wake(t),
        Op::BlockCurrent => {
            let c = w.sched.current().unwrap();
            set_thread_state(w, c, ThreadState::BlockedOnReply);
        }
        Op::Stop(t) => set_thread_state(w, tcb(t), ThreadState::Inactive),
        Op::SetPriority(t, p) => set_priority(w, tcb(t), p),
        Op::Tick => tick(w),
        Op::Yield => yield_now(w),
        Op::Schedule => {
            if let Some(t) = schedule(w) {
                crate::tcb::activate(w, t);
            }
        }
    }
}

/// The world and the model agree, and the invariants hold.
fn compare(w: &World, m: &Model, exit: bool) -> Result<(), TestCaseError> {
    // `check` walked every queue and matched it to the bitmap; compare the
    // non-empty ones.
    let n = check(w, N).map_err(TestCaseError::fail)?;
    for p in 0..PRIORITIES {
        if m.queues[p].is_empty() && w.sched.head(p as u8).is_none() {
            continue;
        }
        let q: Vec<usize> = m.queues[p].iter().copied().collect();
        prop_assert_eq!(w.queue(p as u8), q, "queue {}", p);
    }
    prop_assert_eq!(n, m.queues.iter().map(VecDeque::len).sum::<usize>());
    prop_assert_eq!(w.current(), m.current);
    let action = match w.sched.action() {
        Action::ResumeCurrent => ModelAction::Resume,
        Action::ChooseNew => ModelAction::Choose,
        Action::SwitchTo(t) => ModelAction::Switch(index(t)),
    };
    prop_assert_eq!(action, m.action);
    for i in 0..N {
        let t = tcb(i);
        prop_assert_eq!(w.state(t).is_runnable(), m.runnable[i], "thread {}", i);
        prop_assert_eq!(w.priority(t), m.prio[i]);
        prop_assert_eq!(w.time_slice(t), m.slice[i]);
        prop_assert_eq!(w.queued(t), m.queued(i));
    }
    if exit {
        check_exit(w, N).map_err(TestCaseError::fail)?;
        // Every runnable thread but the current one is queued, in exactly
        // the queue of its priority (the walk above found it there once).
        for i in 0..N {
            let expect = m.runnable[i] && m.current != Some(i);
            prop_assert_eq!(w.queued(tcb(i)), expect, "thread {}", i);
        }
    }
    Ok(())
}

fn priority() -> impl Strategy<Value = u8> {
    prop::sample::select(vec![0u8, 1, 63, 64, 127, 128, 200, 255, 7, 7, 7])
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        3 => (0..N).prop_map(Op::Wake),
        1 => Just(Op::BlockCurrent),
        1 => (0..N).prop_map(Op::Stop),
        1 => (0..N, priority()).prop_map(|(t, p)| Op::SetPriority(t, p)),
        2 => Just(Op::Tick),
        1 => Just(Op::Yield),
        3 => Just(Op::Schedule),
    ]
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Random wake-ups, blocks, stops, priority changes, ticks, yields and
    /// entry ends against the model: after every step the queues, the
    /// current thread, the action, the states, priorities, slices and
    /// queued flags agree with it and `check` passes; after every entry end
    /// `check_exit` passes too, and the runnable threads but the current
    /// one are exactly the queued ones.
    #[test]
    fn random_operations_match_the_model(
        prios in prop::array::uniform8(priority()),
        ops in prop::collection::vec(op(), 1..if cfg!(miri) { 30 } else { 200 }),
    ) {
        let mut w = World::new(&prios);
        let mut m = Model::new(&prios);
        compare(&w, &m, true)?;
        for op in ops {
            if !m.apply(op) {
                continue;
            }
            apply(&mut w, op);
            compare(&w, &m, matches!(op, Op::Schedule))?;
        }
        m.apply(Op::Schedule);
        apply(&mut w, Op::Schedule);
        compare(&w, &m, true)?;
    }
}
