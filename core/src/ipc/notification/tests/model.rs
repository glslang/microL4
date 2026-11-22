//! A proptest of random signals (by `Send`, `NBSend`, `Call` and the
//! kernel), waits, polls, binds, unbinds, endpoint sends and receives,
//! suspends, resumes, and deletions of notifications and TCBs, by six
//! threads on three notifications and two endpoints, against a model of
//! words, queues and bindings written from `docs/design.md`,
//! "Notifications", and `docs/abi.md`, "Notification semantics".
//!
//! Each step lets one thread that the model says is runnable act, so the
//! model does not depend on the scheduler's choice. Thread A never blocks
//! (its receives poll and its sends do not block) and is never suspended
//! or deleted, so some thread can always act. After every step every live
//! thread's state, binding, `rdi`, `rsi` and MR0 to MR3, every
//! notification's state, word, binding and queue, and every endpoint's
//! queue agree with the model; natively, the scheduler's, IPC's and the
//! notifications' invariants hold at every kernel exit too.

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use super::*;
use crate::cap::TCB_BITS;
use crate::ipc::EpState;

const T: usize = THREADS;
/// Endpoints 0 and 1, through `S_EP0` and `S_EP1`: all rights, unbadged.
const EPN: usize = 2;

/// A thread's state as the model sees it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum St {
    Running,
    Restart,
    Inactive,
    /// Waiting on notification `n`.
    OnNtfn(usize),
    /// Receiving on endpoint `e`.
    OnRecv(usize),
    /// Sending on endpoint `e`.
    OnSend(usize),
    /// Its TCB is deleted.
    Dead,
}

impl St {
    fn runnable(self) -> bool {
        matches!(self, St::Running | St::Restart)
    }
}

/// An action, as intents: thread indices that the model resolves against
/// the world, so that most actions do something.
#[derive(Clone, Copy, Debug)]
enum Op {
    /// `number` is `Call` (1), `Send` (3) or `NBSend` (4).
    Signal {
        t: usize,
        n: usize,
        v: u64,
        number: u64,
    },
    Wait {
        t: usize,
        n: usize,
        v: u64,
        blocking: bool,
    },
    /// An interrupt's signal, made by the kernel.
    KernelSignal {
        n: usize,
        badge: u64,
    },
    /// Unless `exact`, the target and the notification are the first from
    /// those named that could be bound, if any.
    Bind {
        actor: usize,
        target: usize,
        n: usize,
        v: u64,
        exact: bool,
    },
    /// Unless `exact`, the target is the first from the one named that is
    /// bound, if any.
    Unbind {
        actor: usize,
        target: usize,
        exact: bool,
    },
    EpSend {
        t: usize,
        ep: usize,
    },
    EpRecv {
        t: usize,
        ep: usize,
        blocking: bool,
    },
    Suspend {
        actor: usize,
        target: usize,
    },
    Resume {
        actor: usize,
        target: usize,
    },
    DeleteNtfn {
        actor: usize,
        n: usize,
    },
    DeleteTcb {
        actor: usize,
        target: usize,
    },
}

/// The paths of the design a step took, for the coverage test.
#[derive(Clone, Copy, Debug, Default)]
struct Paths {
    woke_waiter: u32,
    woke_bound_receiver: u32,
    bound_receive_took_signal: u32,
    bind_delivered: u32,
    bind_refused: u32,
    waited_on_bound_by_other: u32,
    cancelled_waiters: u32,
    unbound_by_deletion: u32,
}

#[derive(Clone, Debug)]
struct Model {
    state: [St; T],
    /// The notification each thread is bound to.
    bound: [Option<usize>; T],
    /// `rdi` and `rsi`.
    regs: [(u64, u64); T],
    mrs: [[u64; 4]; T],
    /// The word of each `Active` notification; `None` for `Idle` or
    /// `Waiting`.
    word: [Option<u64>; NS],
    waiters: [VecDeque<usize>; NS],
    /// Each endpoint's queue: senders or receivers, as their states say.
    epq: [VecDeque<usize>; EPN],
    paths: Paths,
}

/// Thread `t`'s message for an endpoint send: label `0x10 + t`, length 1,
/// and MR0 to MR3.
fn ep_message(t: usize) -> (u64, [u64; 4]) {
    let t = t as u64;
    (
        info(0x10 + t, 1),
        [0x100 + t, 0x200 + t, 0x300 + t, 0x400 + t],
    )
}

impl Model {
    /// The model of `w`, a fresh world: every thread `Running`, nothing
    /// bound, queued or pending, the registers as the world made them.
    fn new(w: &World) -> Model {
        Model {
            state: [St::Running; T],
            bound: [None; T],
            regs: core::array::from_fn(|t| got(w, t)),
            mrs: core::array::from_fn(|t| w.mrs(t)),
            word: [None; NS],
            waiters: Default::default(),
            epq: Default::default(),
            paths: Paths::default(),
        }
    }

    fn bound_to(&self, n: usize) -> Option<usize> {
        (0..T).find(|&t| self.bound[t] == Some(n))
    }

    /// The first runnable thread from `t` on, cyclically; thread A always
    /// is.
    fn runnable_from(&self, t: usize) -> usize {
        (0..T)
            .map(|i| (t + i) % T)
            .find(|&i| self.state[i].runnable())
            .expect("thread A is always runnable")
    }

    /// `t` leaves whatever queue it is in.
    fn dequeue(&mut self, t: usize) {
        match self.state[t] {
            St::OnNtfn(n) => self.waiters[n].retain(|&x| x != t),
            St::OnRecv(e) | St::OnSend(e) => self.epq[e].retain(|&x| x != t),
            _ => {}
        }
    }

    /// `t`, out of every queue, gets a signal and runs.
    fn wake(&mut self, t: usize, word: u64) {
        self.state[t] = St::Running;
        self.regs[t] = (word, 0);
    }

    fn signal(&mut self, n: usize, badge: u64) {
        if let Some(w) = self.waiters[n].pop_front() {
            self.paths.woke_waiter += 1;
            self.wake(w, badge);
        } else if let Some(word) = &mut self.word[n] {
            *word |= badge;
        } else if let Some(b) = self.bound_to(n)
            && matches!(self.state[b], St::OnRecv(_))
        {
            self.paths.woke_bound_receiver += 1;
            self.dequeue(b);
            self.wake(b, badge);
        } else {
            self.word[n] = Some(badge);
        }
    }

    /// Resolves `op` against the model, which it updates. Returns the
    /// resolved operation, or `None` if it would do nothing worth running.
    fn apply(&mut self, op: Op) -> Option<Op> {
        let op = self.resolve(op)?;
        let actor = match op {
            Op::Signal { t, .. } | Op::Wait { t, .. } | Op::EpSend { t, .. } => Some(t),
            Op::EpRecv { t, .. } => Some(t),
            Op::Bind { actor, .. }
            | Op::Unbind { actor, .. }
            | Op::Suspend { actor, .. }
            | Op::Resume { actor, .. }
            | Op::DeleteNtfn { actor, .. }
            | Op::DeleteTcb { actor, .. } => Some(actor),
            Op::KernelSignal { .. } => None,
        };
        if let Some(a) = actor {
            // Running it activates a restarted thread.
            self.state[a] = St::Running;
        }
        match op {
            Op::Signal { t, n, v, number } => {
                self.regs[t] = (sn(n, v), info(0x33, 1));
                self.mrs[t] = [0x51; 4];
                if !rights_of(v).contains(Rights::WRITE) {
                    if number == 1 {
                        self.regs[t] = (0, info(2, 1));
                        self.mrs[t][0] = 0;
                    }
                } else {
                    self.signal(n, badge_of(n, v));
                    if number == 1 {
                        self.regs[t] = (0, info(0, 0));
                    }
                }
            }
            Op::Wait { t, n, v, blocking } => {
                self.regs[t] = (sn(n, v), 0);
                let other = self.bound_to(n).is_some_and(|b| b != t);
                if other {
                    self.paths.waited_on_bound_by_other += 1;
                }
                if !rights_of(v).contains(Rights::READ) || other {
                    // A capability fault with no handler.
                    self.state[t] = St::Inactive;
                } else if let Some(word) = self.word[n].take() {
                    self.regs[t] = (word, 0);
                } else if blocking {
                    self.state[t] = St::OnNtfn(n);
                    self.waiters[n].push_back(t);
                } else {
                    self.regs[t] = (0, 0);
                }
            }
            Op::KernelSignal { n, badge } => self.signal(n, badge),
            Op::Bind {
                actor,
                target,
                n,
                v,
                ..
            } => {
                let refused = if actor == F {
                    Some(info(7, 0))
                } else if self.bound[target].is_some()
                    || !rights_of(v).contains(Rights::READ)
                    || self.bound_to(n).is_some()
                    || !self.waiters[n].is_empty()
                {
                    Some(info(3, 0))
                } else {
                    None
                };
                if let Some(err) = refused {
                    self.paths.bind_refused += 1;
                    self.regs[actor] = (0, err);
                } else {
                    self.bound[target] = Some(n);
                    if let St::OnRecv(_) = self.state[target]
                        && let Some(word) = self.word[n].take()
                    {
                        self.paths.bind_delivered += 1;
                        self.dequeue(target);
                        self.wake(target, word);
                    }
                    self.regs[actor] = (0, info(0, 0));
                }
            }
            Op::Unbind { actor, target, .. } => {
                self.regs[actor] = if self.bound[target].take().is_some() {
                    (0, info(0, 0))
                } else {
                    (0, info(3, 0))
                };
            }
            Op::EpSend { t, ep } => {
                let (rsi, mrs) = ep_message(t);
                self.regs[t] = (S_EP0 + ep as u64, rsi);
                self.mrs[t] = mrs;
                let receiver = self.epq[ep]
                    .front()
                    .is_some_and(|&r| matches!(self.state[r], St::OnRecv(_)));
                if receiver {
                    let r = self.epq[ep].pop_front().unwrap();
                    self.state[r] = St::Running;
                    self.regs[r] = (0, rsi);
                    self.mrs[r][0] = mrs[0];
                } else if t != A {
                    self.state[t] = St::OnSend(ep);
                    self.epq[ep].push_back(t);
                }
            }
            Op::EpRecv { t, ep, blocking } => {
                self.regs[t] = (S_EP0 + ep as u64, 0);
                let sender = self.epq[ep]
                    .front()
                    .is_some_and(|&s| matches!(self.state[s], St::OnSend(_)));
                if let Some(n) = self.bound[t]
                    && let Some(word) = self.word[n].take()
                {
                    self.paths.bound_receive_took_signal += 1;
                    self.regs[t] = (word, 0);
                } else if sender {
                    let s = self.epq[ep].pop_front().unwrap();
                    self.state[s] = St::Running;
                    self.regs[t] = (0, self.regs[s].1);
                    self.mrs[t][0] = self.mrs[s][0];
                } else if blocking {
                    self.state[t] = St::OnRecv(ep);
                    self.epq[ep].push_back(t);
                } else {
                    self.regs[t] = (0, 0);
                }
            }
            Op::Suspend { actor, target } => {
                // A self-suspend by Call writes this reply first.
                self.regs[actor] = (0, info(0, 0));
                self.dequeue(target);
                self.state[target] = St::Inactive;
            }
            Op::Resume { actor, target } => {
                self.regs[actor] = (0, info(0, 0));
                if !self.state[target].runnable() {
                    self.dequeue(target);
                    self.state[target] = St::Restart;
                }
            }
            Op::DeleteNtfn { actor, n } => {
                self.regs[actor] = (0, info(0, 0));
                self.mrs[actor] = [sn(n, ORIG), 64, 0, 0];
                if let Some(b) = self.bound_to(n) {
                    self.paths.unbound_by_deletion += 1;
                    self.bound[b] = None;
                }
                if !self.waiters[n].is_empty() {
                    self.paths.cancelled_waiters += 1;
                }
                for t in core::mem::take(&mut self.waiters[n]) {
                    self.state[t] = St::Restart;
                }
                self.word[n] = None;
            }
            Op::DeleteTcb { actor, target } => {
                self.regs[actor] = (0, info(0, 0));
                self.mrs[actor] = [S_TCB + target as u64, 64, 0, 0];
                self.dequeue(target);
                self.bound[target] = None;
                self.state[target] = St::Dead;
            }
        }
        Some(op)
    }

    /// Picks the threads an intent names: an actor that can run, targets
    /// that exist; thread A never blocks, takes no capability fault, and
    /// is never suspended or deleted.
    fn resolve(&self, op: Op) -> Option<Op> {
        let live = |t: usize| self.state[t] != St::Dead;
        Some(match op {
            Op::Signal { t, n, v, number } => Op::Signal {
                t: self.runnable_from(t),
                n,
                v,
                number,
            },
            Op::Wait { t, n, v, blocking } => {
                let t = self.runnable_from(t);
                let faults = !rights_of(v).contains(Rights::READ)
                    || self.bound_to(n).is_some_and(|b| b != t);
                if t == A && faults {
                    return None;
                }
                Op::Wait {
                    t,
                    n,
                    v,
                    blocking: blocking && t != A,
                }
            }
            Op::EpSend { t, ep } => Op::EpSend {
                t: self.runnable_from(t),
                ep,
            },
            Op::EpRecv { t, ep, blocking } => {
                let t = self.runnable_from(t);
                Op::EpRecv {
                    t,
                    ep,
                    blocking: blocking && t != A,
                }
            }
            Op::KernelSignal { .. } => op,
            Op::Bind {
                actor,
                target,
                n,
                v,
                exact,
            } if live(target) => {
                let (mut target, mut n) = (target, n);
                if !exact {
                    let free_thread = |t: usize| live(t) && self.bound[t].is_none();
                    let free_ntfn =
                        |n: usize| self.bound_to(n).is_none() && self.waiters[n].is_empty();
                    target = (0..T)
                        .map(|i| (target + i) % T)
                        .find(|&t| free_thread(t))
                        .unwrap_or(target);
                    n = (0..NS)
                        .map(|i| (n + i) % NS)
                        .find(|&n| free_ntfn(n))
                        .unwrap_or(n);
                }
                Op::Bind {
                    actor: self.runnable_from(actor),
                    target,
                    n,
                    v,
                    exact,
                }
            }
            Op::Unbind {
                actor,
                target,
                exact,
            } if live(target) => {
                let bound = |t: usize| live(t) && self.bound[t].is_some();
                let target = match exact {
                    true => target,
                    false => (0..T)
                        .map(|i| (target + i) % T)
                        .find(|&t| bound(t))
                        .unwrap_or(target),
                };
                Op::Unbind {
                    actor: self.runnable_from(actor),
                    target,
                    exact,
                }
            }
            Op::Resume { actor, target } if live(target) => Op::Resume {
                actor: self.runnable_from(actor),
                target,
            },
            Op::Suspend { actor, target } if live(target) && target != A => Op::Suspend {
                actor: self.runnable_from(actor),
                target,
            },
            Op::DeleteNtfn { actor, n } => Op::DeleteNtfn {
                actor: self.runnable_from(actor),
                n,
            },
            Op::DeleteTcb { actor, target }
                if live(target) && target != A && (0..T).filter(|&t| live(t)).count() > 3 =>
            {
                Op::DeleteTcb {
                    actor: self.runnable_from(actor),
                    target,
                }
            }
            _ => return None,
        })
    }
}

/// Runs the resolved `op` in the world, through system calls.
fn run(w: &mut World, op: Op) {
    match op {
        Op::Signal { t, n, v, number } => {
            w.syscall(t, number, sn(n, v), info(0x33, 1), Some([0x51; 4]));
        }
        Op::Wait { t, n, v, blocking } => {
            w.syscall(t, if blocking { 5 } else { 8 }, sn(n, v), 0, None);
        }
        Op::KernelSignal { n, badge } => {
            signal(&mut w.k, ntfn(n), badge);
            w.exit();
        }
        Op::Bind {
            actor,
            target,
            n,
            v,
            ..
        } => {
            bind(w, actor, target, Some(sn(n, v)));
        }
        Op::Unbind { actor, target, .. } => {
            let rsi = info(tcb::label::UNBIND_NOTIFICATION, 0);
            w.syscall(actor, 1, S_TCB + target as u64, rsi, None);
        }
        Op::EpSend { t, ep } => {
            let (rsi, mrs) = ep_message(t);
            let number = if t == A { 4 } else { 3 };
            w.syscall(t, number, S_EP0 + ep as u64, rsi, Some(mrs));
        }
        Op::EpRecv { t, ep, blocking } => {
            w.syscall(t, if blocking { 5 } else { 8 }, S_EP0 + ep as u64, 0, None);
        }
        Op::Suspend { actor, target } | Op::Resume { actor, target } => {
            let l = match op {
                Op::Suspend { .. } => tcb::label::SUSPEND,
                _ => tcb::label::RESUME,
            };
            w.syscall(actor, 1, S_TCB + target as u64, info(l, 0), None);
        }
        Op::DeleteNtfn { actor, n } => {
            delete_ntfn(w, actor, n);
            // Finalisation left the words as retype makes them; give the
            // notification new capabilities, as a retype into the same
            // memory would.
            assert!(w.k.mem.is_zero(ntfn(n).get(), 64), "notification {n}");
            add_ntfn_caps(&mut w.k, n);
        }
        Op::DeleteTcb { actor, target } => {
            w.threads.retain(|t| *t != tcb(target));
            w.call(
                actor,
                S_ROOT,
                CNODE_DELETE,
                2,
                [S_TCB + target as u64, 64, 0, 0],
            );
        }
    }
}

/// The model's view of thread state `s`.
fn kernel_state(s: St) -> ThreadState {
    match s {
        St::Running => ThreadState::Running,
        St::Restart => ThreadState::Restart,
        St::Inactive | St::Dead => ThreadState::Inactive,
        St::OnNtfn(n) => on(n),
        St::OnRecv(e) => on_receive(e),
        St::OnSend(e) => ThreadState::BlockedOnSend {
            ep: ep(e),
            badge: 0,
            can_grant: true,
            can_grant_reply: true,
            is_call: false,
        },
    }
}

fn index(t: TcbRef) -> usize {
    ((t.get() - TCB_BASE) >> TCB_BITS) as usize
}

/// Compares the world with the model, after marking the thread the
/// scheduler activated as `Running` in the model.
fn compare(w: &World, m: &mut Model) -> Result<(), TestCaseError> {
    if let Some(c) = w.current()
        && m.state[index(c)] == St::Restart
    {
        m.state[index(c)] = St::Running;
    }
    for t in 0..T {
        if m.state[t] == St::Dead {
            continue;
        }
        prop_assert_eq!(w.state(t), kernel_state(m.state[t]), "thread {}", t);
        prop_assert_eq!(
            w.k.bound_notification(tcb(t)),
            m.bound[t].map(ntfn),
            "thread {}",
            t
        );
        prop_assert_eq!(got(w, t), m.regs[t], "rdi and rsi of thread {}", t);
        prop_assert_eq!(w.mrs(t), m.mrs[t], "message registers of thread {}", t);
    }
    for n in 0..NS {
        let q = &m.waiters[n];
        let expect = Notification {
            state: if !q.is_empty() {
                NtfnState::Waiting
            } else if m.word[n].is_some() {
                NtfnState::Active
            } else {
                NtfnState::Idle
            },
            word: m.word[n].unwrap_or(0),
            bound: m.bound_to(n).map(tcb),
            head: q.front().map(|&t| tcb(t)),
            tail: q.back().map(|&t| tcb(t)),
        };
        prop_assert_eq!(nt(w, n), expect, "notification {}", n);
        let queued: Vec<TcbRef> = q.iter().map(|&t| tcb(t)).collect();
        prop_assert_eq!(nqueue(w, n), queued, "notification {}", n);
    }
    for e in 0..EPN {
        let q = &m.epq[e];
        let queued: Vec<TcbRef> = q.iter().map(|&t| tcb(t)).collect();
        prop_assert_eq!(w.queue(e), queued, "endpoint {}", e);
        let state = match q.front().map(|&t| m.state[t]) {
            None => EpState::Idle,
            Some(St::OnSend(_)) => EpState::Send,
            Some(_) => EpState::Recv,
        };
        prop_assert_eq!(w.endpoint(e).state, state, "endpoint {}", e);
    }
    Ok(())
}

fn op() -> impl Strategy<Value = Op> {
    let thread = 0..T;
    let n = 0..NS;
    let v = 0..VARIANTS;
    prop_oneof![
        4 => (thread.clone(), n.clone(), v.clone(), prop::sample::select(vec![1u64, 3, 4]))
            .prop_map(|(t, n, v, number)| Op::Signal { t, n, v, number }),
        4 => (thread.clone(), n.clone(), v.clone(), any::<bool>())
            .prop_map(|(t, n, v, blocking)| Op::Wait { t, n, v, blocking }),
        1 => (n.clone(), 0..4usize)
            .prop_map(|(n, b)| Op::KernelSignal { n, badge: [0, 1 << 8, 1 << 9, 1 << 10][b] }),
        3 => (thread.clone(), thread.clone(), n.clone(), v, any::<bool>())
            .prop_map(|(actor, target, n, v, exact)| Op::Bind { actor, target, n, v, exact }),
        1 => (thread.clone(), thread.clone(), any::<bool>())
            .prop_map(|(actor, target, exact)| Op::Unbind { actor, target, exact }),
        3 => (thread.clone(), 0..EPN).prop_map(|(t, ep)| Op::EpSend { t, ep }),
        3 => (thread.clone(), 0..EPN, any::<bool>())
            .prop_map(|(t, ep, blocking)| Op::EpRecv { t, ep, blocking }),
        2 => (thread.clone(), thread.clone())
            .prop_map(|(actor, target)| Op::Suspend { actor, target }),
        2 => (thread.clone(), thread.clone())
            .prop_map(|(actor, target)| Op::Resume { actor, target }),
        1 => (thread.clone(), n).prop_map(|(actor, n)| Op::DeleteNtfn { actor, n }),
        1 => (thread.clone(), thread).prop_map(|(actor, target)| Op::DeleteTcb { actor, target }),
    ]
}

fn ops() -> impl Strategy<Value = Vec<Op>> {
    prop::collection::vec(op(), 1..if cfg!(miri) { 12 } else { 80 })
}

/// Runs `ops` in a fresh world and its model, comparing after every step.
fn run_against_model(ops: &[Op]) -> Result<Paths, TestCaseError> {
    let mut w = world();
    let mut m = Model::new(&w);
    compare(&w, &mut m)?;
    for &op in ops {
        let Some(op) = m.apply(op) else {
            continue;
        };
        run(&mut w, op);
        compare(&w, &mut m).map_err(|e| TestCaseError::fail(std::format!("after {op:?}: {e}")))?;
    }
    Ok(m.paths)
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 1024 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    /// Random notification and endpoint operations agree with the model
    /// after every step.
    #[test]
    fn random_notification_operations_match_the_model(ops in ops()) {
        run_against_model(&ops)?;
    }
}

/// The random sequences reach every path of the design the model knows,
/// so the proptest above tests them all.
#[test]
#[cfg_attr(miri, ignore = "a statistic over many random sequences")]
fn random_sequences_reach_every_path() {
    let mut runner = TestRunner::new_with_rng(
        Config {
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let mut total = Paths::default();
    for _ in 0..256 {
        let ops = ops().new_tree(&mut runner).unwrap().current();
        let p = run_against_model(&ops).unwrap();
        total.woke_waiter += p.woke_waiter;
        total.woke_bound_receiver += p.woke_bound_receiver;
        total.bound_receive_took_signal += p.bound_receive_took_signal;
        total.bind_delivered += p.bind_delivered;
        total.bind_refused += p.bind_refused;
        total.waited_on_bound_by_other += p.waited_on_bound_by_other;
        total.cancelled_waiters += p.cancelled_waiters;
        total.unbound_by_deletion += p.unbound_by_deletion;
    }
    let all = [
        ("a signal woke a waiter", total.woke_waiter),
        ("a signal woke a bound receiver", total.woke_bound_receiver),
        (
            "a bound receive took a pending signal",
            total.bound_receive_took_signal,
        ),
        ("a bind delivered a pending signal", total.bind_delivered),
        ("a bind was refused", total.bind_refused),
        (
            "another thread waited on a bound notification",
            total.waited_on_bound_by_other,
        ),
        ("a deletion restarted waiters", total.cancelled_waiters),
        ("a deletion unbound a thread", total.unbound_by_deletion),
    ];
    for (what, count) in all {
        assert!(count > 0, "never: {what} ({total:?})");
    }
}
