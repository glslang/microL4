//! The IPC differential property test: random system calls, signals,
//! faults, ticks and invocations by a few threads on a few endpoints and
//! notifications, run against `l4core` and the IPC model and compared
//! after every step (`PLAN.md`, M6).
//!
//! Operations are generated as intents ("a thread that holds a reply
//! capability replies", "receive where senders wait", "send a capability
//! to the endpoint the message goes through") and resolved against the
//! world as it is when they run, so most of them do something and
//! shrinking still works. Each lets a thread the scheduler may run act, so
//! the sequence does not depend on the scheduler's choice; when every
//! thread is stopped, a thread outside the world resumes one. Each step
//! carries a preemption schedule, which only a TCB's deletion has the
//! preemption points to use; `World::apply` then checks the invariants at
//! every preemption point and restarts the call until it completes.
//!
//! 20,000 cases of up to 60 steps by default, about 12 seconds natively;
//! `PROPTEST_CASES` overrides the count. Failures persist in
//! `ipc_random.regressions` next to this file, which git ignores: a minimal
//! reproduction worth keeping becomes a named test in `ipc_scenarios.rs`.
//! `cargo test -p l4model --test ipc_random -- --ignored --nocapture`
//! prints what the generated sequences exercise.

use l4core::cap::Rights;
use l4model::ipc::{Dir, Info, MCap, NState, State, label, sysno, word};
use l4model::ipc_harness::{
    Action, BAD_CPTR, Config, Entry, NTFNS, ROOT_SLOTS, THREADS, World, slot,
};
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// Which thread acts: one the scheduler may run now.
#[derive(Clone, Copy, Debug)]
enum Who {
    Current,
    Nth(u8),
    /// One that holds a reply capability, if one may run.
    Holder(u8),
}

/// A `CPtr` to invoke or receive on.
#[derive(Clone, Copy, Debug)]
enum Target {
    /// An endpoint or notification capability with the rights the call
    /// needs, on an object where a partner waits if there is one.
    Partner(u8),
    Endpoint(u8),
    Ntfn(u8),
    /// A saved reply capability.
    Reply(u8),
    /// Any root slot: wrong types, empty slots and missing rights.
    Slot(u8),
    /// A `CPtr` that breaks the root's guard.
    Bad(u64),
}

/// A pointer in `caps_or_badges`.
#[derive(Clone, Copy, Debug)]
enum Extra {
    /// An endpoint capability to the endpoint the message goes through.
    Same(u8),
    /// Any slot but the untyped's, which the model never sends.
    Any(u8),
    Bad(u64),
}

/// What the receiver's `receive_cnode`, `receive_index` and
/// `receive_depth` name.
#[derive(Clone, Copy, Debug)]
enum RecvSlot {
    /// Left as they are.
    Keep,
    /// An empty slot.
    Free(u8),
    /// A full slot.
    Full(u8),
    /// A `receive_cnode` that is no CNode capability.
    NoCNode(u8),
    /// A depth other than 64.
    Depth(u8, u64),
    /// An index that does not resolve.
    Bad(u64),
}

#[derive(Clone, Copy, Debug)]
enum Kind {
    Call,
    Send,
    NBSend,
}

impl Kind {
    fn number(self) -> u64 {
        match self {
            Kind::Call => sysno::CALL,
            Kind::Send => sysno::SEND,
            Kind::NBSend => sysno::NB_SEND,
        }
    }
}

/// The slot a `CNode_Delete` names.
#[derive(Clone, Copy, Debug)]
enum DelSlot {
    Endpoint(u8),
    Ntfn(u8),
    Tcb(u8),
    Reply(u8),
    /// A full slot past the start state's: a received or saved capability.
    Received(u8),
    /// The last capability to an endpoint or notification.
    Final(u8),
    /// Any root slot but the root CNode's own and the frames'.
    Any(u8),
    /// An index that does not resolve.
    Bad(u64),
}

/// The slot a `CNode_CancelBadgedSends` names.
#[derive(Clone, Copy, Debug)]
enum CancelSlot {
    /// An endpoint capability whose badge a queued sender carries.
    Busy(u8),
    Endpoint(u8),
    Any(u8),
}

/// A message: label, length, MR0 to MR3, a seed for the buffer words, and
/// the capabilities it names.
#[derive(Clone, Copy, Debug)]
struct Msg {
    label: u64,
    len: u8,
    mrs: [u64; 4],
    seed: u64,
    extra: u8,
    extras: [Extra; 3],
}

#[derive(Clone, Debug)]
enum Op {
    /// `recv` is the caller's receive slot, for what a reply sends back.
    Send {
        who: Who,
        kind: Kind,
        target: Target,
        msg: Msg,
        recv: RecvSlot,
    },
    /// `rsi` and MR0 to MR3 are ignored on entry: junk, which the receive
    /// must overwrite or keep as the ABI says.
    Recv {
        who: Who,
        nb: bool,
        target: Target,
        rsi: u64,
        mrs: [u64; 4],
        recv: RecvSlot,
    },
    Reply {
        who: Who,
        msg: Msg,
    },
    ReplyRecv {
        who: Who,
        target: Target,
        msg: Msg,
        recv: RecvSlot,
    },
    Yield {
        who: Who,
    },
    Again {
        who: Who,
    },
    Unknown {
        who: Who,
        number: u64,
    },
    Exception {
        who: Who,
        vector: u8,
        error: u64,
        cr2: u64,
    },
    /// `TCB_Suspend`, `TCB_Resume` or an illegal label on a TCB.
    Thread {
        who: Who,
        kind: Kind,
        target: u8,
        label: u64,
    },
    /// `TCB_BindNotification` with `extra` extra capabilities (0 or 1).
    Bind {
        who: Who,
        kind: Kind,
        target: u8,
        ntfn: Target,
        extra: u8,
    },
    Unbind {
        who: Who,
        kind: Kind,
        target: u8,
    },
    Delete {
        who: Who,
        kind: Kind,
        slot: DelSlot,
        len: u8,
        depth: u64,
    },
    SaveCaller {
        who: Who,
        kind: Kind,
        slot: RecvSlot,
        len: u8,
    },
    Cancel {
        who: Who,
        kind: Kind,
        slot: CancelSlot,
        len: u8,
        depth: u64,
    },
    /// An invocation with a label no object performs.
    Invoke {
        who: Who,
        kind: Kind,
        slot: u8,
        label: u64,
    },
    Tick,
    Interrupt {
        n: u8,
        badge: u64,
    },
    /// Another thread rewrites thread `n`'s pointers or receive slot,
    /// preferring a queued sender or receiver.
    Rewrite {
        n: u8,
        extras: [Extra; 3],
        recv: RecvSlot,
    },
}

/// Labels outside every type's performed rows, so every kernel object
/// answers `IllegalOperation`.
const ILLEGAL_LABELS: [u64; 8] = [0, 0x02, 0x19, 0x2E, 0x3F, 0x54, 0x90, 0xABCDE];

/// The user vectors a thread can raise.
const VECTORS: [u8; 11] = [14, 14, 13, 6, 3, 0, 1, 10, 12, 16, 19];

const UNKNOWN_SYSCALLS: [u64; 10] = [0, 9, 15, 16, 17, 18, 31, 32, 1 << 40, u64::MAX];

const SLOTS: u64 = ROOT_SLOTS as u64;

fn pick<T: Copy>(v: &[T], n: u64) -> Option<T> {
    (!v.is_empty()).then(|| v[(n % v.len() as u64) as usize])
}

/// The thread `who` names, if any may run.
fn who(w: &World, who: Who) -> Option<usize> {
    let eligible = w.m.eligible();
    match who {
        Who::Current => eligible.first().copied(),
        Who::Nth(n) => pick(&eligible, n as u64),
        Who::Holder(n) => {
            let holders: Vec<usize> = eligible
                .iter()
                .copied()
                .filter(|&t| w.m.threads[t].caller != MCap::Null)
                .collect();
            pick(&holders, n as u64).or_else(|| pick(&eligible, n as u64))
        }
    }
}

/// The root slots whose capability passes `f`.
fn slots_where(w: &World, f: impl Fn(&MCap) -> bool) -> Vec<u64> {
    (0..SLOTS)
        .filter(|&s| f(&w.m.cap((0, s as usize))))
        .collect()
}

/// Whether thread `t` may send through `cap` as `kind`, and whether a
/// partner waits there.
fn sendable(w: &World, cap: &MCap, kind: Kind) -> (bool, bool) {
    match *cap {
        MCap::Endpoint { ep, rights, .. } => {
            let call = !matches!(kind, Kind::Call)
                || rights.contains(Rights::GRANT)
                || rights.contains(Rights::GRANT_REPLY);
            (
                rights.contains(Rights::WRITE) && call,
                w.m.endpoints[ep].dir == Dir::Recv,
            )
        }
        MCap::Notification { ntfn, rights, .. } => {
            let n = &w.m.ntfns[ntfn];
            let bound_receiving = n
                .bound
                .is_some_and(|b| matches!(w.m.threads[b].state, State::BlockedOnReceive { .. }));
            (
                rights.contains(Rights::WRITE),
                n.state == NState::Waiting || bound_receiving,
            )
        }
        _ => (false, false),
    }
}

/// Whether thread `t` may receive through `cap`, and whether something is
/// pending there.
fn receivable(w: &World, t: usize, cap: &MCap) -> (bool, bool) {
    match *cap {
        MCap::Endpoint { ep, rights, .. } => (
            rights.contains(Rights::READ),
            w.m.endpoints[ep].dir == Dir::Send,
        ),
        MCap::Notification { ntfn, rights, .. } => {
            let n = &w.m.ntfns[ntfn];
            (
                rights.contains(Rights::READ) && n.bound.is_none_or(|b| b == t),
                n.state == NState::Active,
            )
        }
        _ => (false, false),
    }
}

/// The `CPtr` for `target`; `fit` says whether a capability suits the call
/// and whether a partner waits behind it.
fn cptr(w: &World, target: Target, fit: impl Fn(&MCap) -> (bool, bool)) -> u64 {
    let n = |x: u8| x as u64;
    match target {
        Target::Partner(x) => {
            let ok = slots_where(w, |c| fit(c).0);
            let busy = slots_where(w, |c| fit(c) == (true, true));
            pick(&busy, n(x))
                .or_else(|| pick(&ok, n(x)))
                .unwrap_or(n(x) % SLOTS)
        }
        Target::Endpoint(x) => pick(
            &slots_where(w, |c| matches!(c, MCap::Endpoint { .. })),
            n(x),
        )
        .unwrap_or(0),
        Target::Ntfn(x) => pick(
            &slots_where(w, |c| matches!(c, MCap::Notification { .. })),
            n(x),
        )
        .unwrap_or(0),
        Target::Reply(x) => {
            pick(&slots_where(w, |c| matches!(c, MCap::Reply { .. })), n(x)).unwrap_or(n(x) % SLOTS)
        }
        Target::Slot(x) => n(x) % SLOTS,
        Target::Bad(x) => bad(x),
    }
}

fn bad(x: u64) -> u64 {
    if x & 1 == 0 { BAD_CPTR } else { x | 1 << 40 }
}

/// The endpoint `rdi` names for `t`, if it names one.
fn endpoint_of(w: &World, t: usize, rdi: u64) -> Option<usize> {
    match w.m.lookup_cap(t, rdi).map(|s| w.m.cap(s)) {
        Ok(MCap::Endpoint { ep, .. }) => Some(ep),
        _ => None,
    }
}

/// Whether `c` is the only capability to its endpoint or notification.
fn final_ipc_cap(w: &World, c: &MCap) -> bool {
    let same = |x: &MCap| match (*c, *x) {
        (MCap::Endpoint { ep: a, .. }, MCap::Endpoint { ep: b, .. }) => a == b,
        (MCap::Notification { ntfn: a, .. }, MCap::Notification { ntfn: b, .. }) => a == b,
        _ => false,
    };
    matches!(c, MCap::Endpoint { .. } | MCap::Notification { .. })
        && slots_where(w, |x| same(x)).len() == 1
}

/// The pointer for `x`, for a message through endpoint `ep`.
fn extra_cptr(w: &World, x: Extra, ep: Option<usize>) -> u64 {
    match x {
        Extra::Same(n) => {
            let same = slots_where(
                w,
                |c| matches!(*c, MCap::Endpoint { ep: e, .. } if Some(e) == ep),
            );
            let any = slots_where(w, |c| matches!(c, MCap::Endpoint { .. }));
            pick(&same, n as u64)
                .or_else(|| pick(&any, n as u64))
                .unwrap_or(0)
        }
        Extra::Any(n) => match w.m.cap((0, (n as u64 % SLOTS) as usize)) {
            MCap::Untyped => slot::EMPTY,
            _ => n as u64 % SLOTS,
        },
        Extra::Bad(x) => bad(x),
    }
}

/// The `caps_or_badges` words for `extras`.
fn extra_words(w: &World, extras: &[Extra], ep: Option<usize>) -> Vec<(usize, u64)> {
    extras
        .iter()
        .enumerate()
        .map(|(i, &x)| (word::CAPS_OR_BADGES + i, extra_cptr(w, x, ep)))
        .collect()
}

/// The receive-slot words for `r`, or none to keep them.
fn recv_words(w: &World, r: RecvSlot) -> Vec<(usize, u64)> {
    let free = slots_where(w, |c| *c == MCap::Null);
    let full = slots_where(w, |c| *c != MCap::Null);
    let first_free = |n: u8| pick(&free, n as u64).unwrap_or(slot::FREE);
    let (cnode, index, depth) = match r {
        RecvSlot::Keep => return Vec::new(),
        RecvSlot::Free(n) => (slot::ROOT, first_free(n), 64),
        RecvSlot::Full(n) => (slot::ROOT, pick(&full, n as u64).unwrap_or(1), 64),
        RecvSlot::NoCNode(n) => (n as u64 % SLOTS, first_free(n), 64),
        RecvSlot::Depth(n, d) => (slot::ROOT, first_free(n), d),
        RecvSlot::Bad(x) => (slot::ROOT, x | 1 << 40, 64),
    };
    // A `receive_cnode` that names the root CNode's own slot through a
    // copy is as good: received CNode capabilities are copies of it.
    vec![
        (word::RECEIVE_CNODE, cnode),
        (word::RECEIVE_INDEX, index),
        (word::RECEIVE_DEPTH, depth),
    ]
}

/// Buffer words for `msg`: `msg[4..len]`.
fn msg_words(msg: &Msg) -> Vec<(usize, u64)> {
    (4..(msg.len as usize).min(120))
        .map(|i| {
            (
                word::MSG + i,
                msg.seed.wrapping_mul(i as u64 + 1) ^ i as u64,
            )
        })
        .collect()
}

fn sys(
    t: usize,
    number: u64,
    rdi: u64,
    rsi: u64,
    mrs: Option<[u64; 4]>,
    words: Vec<(usize, u64)>,
) -> Action {
    Action::Syscall {
        t,
        entry: Some(Entry {
            number,
            rdi,
            rsi,
            mrs,
        }),
        words,
    }
}

fn rsi(label: u64, len: u8, extra: u8) -> u64 {
    Info {
        label,
        length: len as u64,
        extra_caps: extra as u64,
        caps_unwrapped: 0,
    }
    .word()
}

/// The `rsi` of a CNode invocation with `len` words.
fn invocation(label: u64, len: u8) -> u64 {
    rsi(label, len, 0)
}

/// A message to `rdi` from `t`, with its buffer words.
fn message(w: &World, t: usize, rdi: u64, msg: &Msg, recv: RecvSlot) -> (u64, Vec<(usize, u64)>) {
    let ep = endpoint_of(w, t, rdi);
    let mut words = msg_words(msg);
    words.extend(extra_words(w, &msg.extras[..msg.extra as usize], ep));
    words.extend(recv_words(w, recv));
    // A message to a kernel object is an invocation: keep its label out of
    // the rows objects perform, which the other operations reach with
    // arguments of their own.
    let object = match w.m.lookup_cap(t, rdi) {
        Ok(s) => !matches!(
            w.m.cap(s),
            MCap::Endpoint { .. } | MCap::Notification { .. } | MCap::Reply { .. }
        ),
        Err(_) => false,
    };
    let label = if object && (0x01..0x90).contains(&msg.label) {
        0
    } else {
        msg.label
    };
    (rsi(label, msg.len, msg.extra), words)
}

/// Resolves `op` against the world as it is.
fn resolve(w: &World, op: &Op) -> Action {
    let alive: Vec<usize> = (0..THREADS).filter(|&t| w.m.threads[t].alive).collect();
    let actor = match *op {
        Op::Tick => return Action::Tick,
        Op::Interrupt { n, badge } => {
            return Action::Interrupt {
                n: n as usize % NTFNS,
                badge,
            };
        }
        Op::Rewrite {
            n,
            ref extras,
            recv,
        } => {
            let queued: Vec<usize> = alive
                .iter()
                .copied()
                .filter(|&t| {
                    matches!(
                        w.m.threads[t].state,
                        State::BlockedOnSend { .. } | State::BlockedOnReceive { .. }
                    )
                })
                .collect();
            let Some(t) = pick(&queued, n as u64).or_else(|| pick(&alive, n as u64)) else {
                return Action::Tick;
            };
            let ep = match w.m.threads[t].state {
                State::BlockedOnSend { ep, .. } => Some(ep),
                _ => None,
            };
            let mut words = extra_words(w, extras, ep);
            words.extend(recv_words(w, recv));
            return Action::WriteBuffer { t, words };
        }
        Op::Send { who, .. }
        | Op::Recv { who, .. }
        | Op::Reply { who, .. }
        | Op::ReplyRecv { who, .. }
        | Op::Yield { who }
        | Op::Again { who }
        | Op::Unknown { who, .. }
        | Op::Exception { who, .. }
        | Op::Thread { who, .. }
        | Op::Bind { who, .. }
        | Op::Unbind { who, .. }
        | Op::Delete { who, .. }
        | Op::SaveCaller { who, .. }
        | Op::Cancel { who, .. }
        | Op::Invoke { who, .. } => who,
    };
    let Some(t) = who(w, actor) else {
        // Every thread is stopped: one outside the world resumes one.
        let n = match actor {
            Who::Current => 0,
            Who::Nth(n) | Who::Holder(n) => n,
        };
        return match pick(&alive, n as u64) {
            Some(t) => Action::ExternalResume { t },
            None => Action::Tick,
        };
    };
    match *op {
        Op::Send {
            kind,
            target,
            ref msg,
            recv,
            ..
        } => {
            let rdi = cptr(w, target, |c| sendable(w, c, kind));
            let (rsi, words) = message(w, t, rdi, msg, recv);
            sys(t, kind.number(), rdi, rsi, Some(msg.mrs), words)
        }
        Op::Recv {
            nb,
            target,
            rsi,
            mrs,
            recv,
            ..
        } => {
            let rdi = cptr(w, target, |c| receivable(w, t, c));
            let number = if nb { sysno::NB_RECV } else { sysno::RECV };
            sys(t, number, rdi, rsi, Some(mrs), recv_words(w, recv))
        }
        Op::Reply { ref msg, .. } => {
            let (rsi, words) = message(w, t, slot::EMPTY, msg, RecvSlot::Keep);
            sys(t, sysno::REPLY, 0, rsi, Some(msg.mrs), words)
        }
        Op::ReplyRecv {
            target,
            ref msg,
            recv,
            ..
        } => {
            let rdi = cptr(w, target, |c| receivable(w, t, c));
            let (rsi, words) = message(w, t, slot::EMPTY, msg, recv);
            sys(t, sysno::REPLY_RECV, rdi, rsi, Some(msg.mrs), words)
        }
        Op::Yield { .. } => sys(t, sysno::YIELD, 0, 0, None, Vec::new()),
        Op::Again { .. } => Action::Syscall {
            t,
            entry: None,
            words: Vec::new(),
        },
        Op::Unknown { number, .. } => sys(t, number, 0, 0, None, Vec::new()),
        Op::Exception {
            vector, error, cr2, ..
        } => Action::Exception {
            t,
            vector,
            error,
            cr2,
        },
        Op::Thread {
            kind,
            target,
            label,
            ..
        } => {
            let rdi = slot::TCB + (target as u64 % THREADS as u64);
            sys(
                t,
                kind.number(),
                rdi,
                invocation(label, 0),
                None,
                Vec::new(),
            )
        }
        Op::Bind {
            kind,
            target,
            ntfn,
            extra,
            ..
        } => {
            // Half the time, a thread in an endpoint receive, so that an
            // Active notification's signal reaches it at once.
            let receiving: Vec<usize> = (0..THREADS)
                .filter(|&r| matches!(w.m.threads[r].state, State::BlockedOnReceive { .. }))
                .collect();
            let y = match pick(&receiving, target as u64 / 2) {
                Some(r) if target % 2 == 0 => r,
                _ => target as usize % THREADS,
            };
            let rdi = slot::TCB + y as u64;
            let n = cptr(w, ntfn, |c| match *c {
                MCap::Notification { ntfn, .. } => (true, w.m.ntfns[ntfn].state == NState::Active),
                _ => (false, false),
            });
            let rsi = rsi(label::TCB_BIND_NOTIFICATION, 0, extra);
            sys(
                t,
                kind.number(),
                rdi,
                rsi,
                None,
                vec![(word::CAPS_OR_BADGES, n)],
            )
        }
        Op::Unbind { kind, target, .. } => {
            let rdi = slot::TCB + (target as u64 % THREADS as u64);
            let rsi = invocation(label::TCB_UNBIND_NOTIFICATION, 0);
            sys(t, kind.number(), rdi, rsi, None, Vec::new())
        }
        Op::Delete {
            kind,
            slot: s,
            len,
            depth,
            ..
        } => {
            let of = |f: &dyn Fn(&MCap) -> bool, n: u8| {
                pick(&slots_where(w, f), n as u64).unwrap_or(slot::EMPTY)
            };
            let index = match s {
                DelSlot::Endpoint(n) => of(&|c| matches!(c, MCap::Endpoint { .. }), n),
                DelSlot::Final(n) => of(&|c| final_ipc_cap(w, c), n),
                DelSlot::Ntfn(n) => of(&|c| matches!(c, MCap::Notification { .. }), n),
                DelSlot::Tcb(n) => of(&|c| matches!(c, MCap::Tcb(_)), n),
                DelSlot::Reply(n) => of(&|c| matches!(c, MCap::Reply { .. }), n),
                DelSlot::Received(n) => {
                    let v: Vec<u64> = slots_where(w, |c| *c != MCap::Null)
                        .into_iter()
                        .filter(|&s| s >= slot::FREE)
                        .collect();
                    pick(&v, n as u64).unwrap_or(slot::EMPTY)
                }
                DelSlot::Any(n) => match n as u64 % SLOTS {
                    slot::ROOT | slot::FRAME_RW | slot::FRAME_RO => slot::EMPTY,
                    i => i,
                },
                DelSlot::Bad(x) => x | 1 << 32,
            };
            let rsi = invocation(label::CNODE_DELETE, len);
            sys(
                t,
                kind.number(),
                slot::ROOT,
                rsi,
                Some([index, depth, 0, 0]),
                Vec::new(),
            )
        }
        Op::SaveCaller {
            kind, slot: s, len, ..
        } => {
            // The destination as a receive slot names it, through the root.
            let words = recv_words(w, s);
            let (index, depth) = match &words[..] {
                [_, (_, index), (_, depth)] => (*index, *depth),
                _ => (slot::FREE, 64),
            };
            let rsi = invocation(label::CNODE_SAVE_CALLER, len);
            sys(
                t,
                kind.number(),
                slot::ROOT,
                rsi,
                Some([index, depth, 0, 0]),
                Vec::new(),
            )
        }
        Op::Cancel {
            kind,
            slot: s,
            len,
            depth,
            ..
        } => {
            let index = match s {
                CancelSlot::Busy(n) => {
                    let busy = slots_where(w, |c| {
                        match *c {
                        MCap::Endpoint { ep, badge, .. } => w.m.endpoints[ep].queue.iter().any(|&q| {
                            matches!(w.m.threads[q].state, State::BlockedOnSend { badge: b, .. } if b == badge)
                        }),
                        _ => false,
                    }
                    });
                    let all: Vec<u64> = busy
                        .iter()
                        .copied()
                        .filter(|&s| matches!(w.m.cap((0, s as usize)), MCap::Endpoint { rights, .. } if rights == Rights::ALL))
                        .collect();
                    pick(&all, n as u64)
                        .or_else(|| pick(&busy, n as u64))
                        .unwrap_or(slot::EP0_BADGED)
                }
                CancelSlot::Endpoint(n) => pick(
                    &slots_where(w, |c| matches!(c, MCap::Endpoint { .. })),
                    n as u64,
                )
                .unwrap_or(slot::EMPTY),
                CancelSlot::Any(n) => n as u64 % SLOTS,
            };
            let rsi = invocation(label::CNODE_CANCEL_BADGED_SENDS, len);
            sys(
                t,
                kind.number(),
                slot::ROOT,
                rsi,
                Some([index, depth, 0, 0]),
                Vec::new(),
            )
        }
        Op::Invoke {
            kind,
            slot: s,
            label,
            ..
        } => {
            // On an endpoint, a notification or a reply capability the
            // label is message data.
            let rdi = s as u64 % SLOTS;
            sys(
                t,
                kind.number(),
                rdi,
                invocation(label, 2),
                None,
                Vec::new(),
            )
        }
        Op::Tick | Op::Interrupt { .. } | Op::Rewrite { .. } => unreachable!(),
    }
}

// ---------------------------------------------------------------------------
// Strategies
// ---------------------------------------------------------------------------

fn who_s() -> impl Strategy<Value = Who> {
    prop_oneof![
        3 => Just(Who::Current),
        3 => any::<u8>().prop_map(Who::Nth),
        2 => any::<u8>().prop_map(Who::Holder),
    ]
}

fn holder_s() -> impl Strategy<Value = Who> {
    prop_oneof![1 => Just(Who::Current), 4 => any::<u8>().prop_map(Who::Holder)]
}

fn target_s() -> impl Strategy<Value = Target> {
    prop_oneof![
        10 => any::<u8>().prop_map(Target::Partner),
        2 => any::<u8>().prop_map(Target::Endpoint),
        2 => any::<u8>().prop_map(Target::Ntfn),
        1 => any::<u8>().prop_map(Target::Reply),
        2 => any::<u8>().prop_map(Target::Slot),
        1 => any::<u64>().prop_map(Target::Bad),
    ]
}

fn extra_s() -> impl Strategy<Value = Extra> {
    prop_oneof![
        3 => any::<u8>().prop_map(Extra::Same),
        4 => any::<u8>().prop_map(Extra::Any),
        1 => any::<u64>().prop_map(Extra::Bad),
    ]
}

fn recv_slot_s() -> impl Strategy<Value = RecvSlot> {
    prop_oneof![
        3 => Just(RecvSlot::Keep),
        6 => any::<u8>().prop_map(RecvSlot::Free),
        1 => any::<u8>().prop_map(RecvSlot::Full),
        1 => any::<u8>().prop_map(RecvSlot::NoCNode),
        1 => (any::<u8>(), prop::sample::select(&[0u64, 5, 58, 65][..]))
            .prop_map(|(n, d)| RecvSlot::Depth(n, d)),
        1 => any::<u64>().prop_map(RecvSlot::Bad),
    ]
}

fn kind_s() -> impl Strategy<Value = Kind> {
    prop_oneof![
        3 => Just(Kind::Call),
        2 => Just(Kind::Send),
        1 => Just(Kind::NBSend),
    ]
}

fn word_s() -> impl Strategy<Value = u64> {
    prop_oneof![
        2 => 0..0x100u64,
        1 => 0x40_0000..0x50_0000u64,
        1 => any::<u64>(),
    ]
}

fn badge_s() -> impl Strategy<Value = u64> {
    prop_oneof![1 => Just(0u64), 3 => (0..16u32).prop_map(|b| 1u64 << b), 1 => any::<u64>()]
}

fn msg_s() -> impl Strategy<Value = Msg> {
    (
        prop_oneof![3 => Just(0u64), 2 => 1..8u64, 1 => any::<u64>().prop_map(|x| x >> 12)],
        prop_oneof![4 => 0..=4u8, 3 => 5..=20u8, 1 => 110..=127u8],
        [word_s(), word_s(), word_s(), word_s()],
        any::<u64>(),
        prop_oneof![1 => Just(0u8), 1 => 1..=3u8],
        [extra_s(), extra_s(), extra_s()],
    )
        .prop_map(|(label, len, mrs, seed, extra, extras)| Msg {
            label,
            len,
            mrs,
            seed,
            extra,
            extras,
        })
}

fn len_s() -> impl Strategy<Value = u8> {
    prop_oneof![8 => Just(2u8), 1 => 0..2u8]
}

fn depth_s() -> impl Strategy<Value = u64> {
    prop_oneof![8 => Just(64u64), 1 => Just(0u64), 1 => Just(65u64), 1 => Just(5u64)]
}

fn op() -> impl Strategy<Value = Op> {
    prop_oneof![
        10 => (who_s(), kind_s(), target_s(), msg_s(), recv_slot_s())
            .prop_map(|(who, kind, target, msg, recv)| Op::Send { who, kind, target, msg, recv }),
        8 => (who_s(), prop::bool::weighted(0.2), target_s(), word_s(),
              [word_s(), word_s(), word_s(), word_s()], recv_slot_s())
            .prop_map(|(who, nb, target, rsi, mrs, recv)| Op::Recv { who, nb, target, rsi, mrs, recv }),
        5 => (holder_s(), msg_s()).prop_map(|(who, msg)| Op::Reply { who, msg }),
        5 => (holder_s(), target_s(), msg_s(), recv_slot_s())
            .prop_map(|(who, target, msg, recv)| Op::ReplyRecv { who, target, msg, recv }),
        1 => who_s().prop_map(|who| Op::Yield { who }),
        2 => who_s().prop_map(|who| Op::Again { who }),
        1 => (who_s(), prop::sample::select(&UNKNOWN_SYSCALLS[..]))
            .prop_map(|(who, number)| Op::Unknown { who, number }),
        3 => (who_s(), prop::sample::select(&VECTORS[..]), word_s(), word_s())
            .prop_map(|(who, vector, error, cr2)| Op::Exception { who, vector, error, cr2 }),
        3 => (who_s(), kind_s(), any::<u8>(),
              prop_oneof![3 => Just(label::TCB_SUSPEND), 3 => Just(label::TCB_RESUME),
                          1 => Just(0x2E), 1 => Just(0x11)])
            .prop_map(|(who, kind, target, label)| Op::Thread { who, kind, target, label }),
        3 => (who_s(), kind_s(), any::<u8>(), prop_oneof![5 => any::<u8>().prop_map(Target::Ntfn), 1 => target_s()],
              prop_oneof![6 => Just(1u8), 1 => Just(0u8)])
            .prop_map(|(who, kind, target, ntfn, extra)| Op::Bind { who, kind, target, ntfn, extra }),
        1 => (who_s(), kind_s(), any::<u8>())
            .prop_map(|(who, kind, target)| Op::Unbind { who, kind, target }),
        3 => (who_s(), kind_s(),
              prop_oneof![3 => any::<u8>().prop_map(DelSlot::Endpoint), 2 => any::<u8>().prop_map(DelSlot::Final), 2 => any::<u8>().prop_map(DelSlot::Ntfn),
                          2 => any::<u8>().prop_map(DelSlot::Tcb), 2 => any::<u8>().prop_map(DelSlot::Reply),
                          2 => any::<u8>().prop_map(DelSlot::Received),
                          1 => any::<u8>().prop_map(DelSlot::Any), 1 => any::<u64>().prop_map(DelSlot::Bad)],
              len_s(), depth_s())
            .prop_map(|(who, kind, slot, len, depth)| Op::Delete { who, kind, slot, len, depth }),
        3 => (holder_s(), kind_s(), recv_slot_s(), len_s())
            .prop_map(|(who, kind, slot, len)| Op::SaveCaller { who, kind, slot, len }),
        2 => (who_s(), kind_s(),
              prop_oneof![4 => any::<u8>().prop_map(CancelSlot::Busy), 2 => any::<u8>().prop_map(CancelSlot::Endpoint),
                          1 => any::<u8>().prop_map(CancelSlot::Any)],
              len_s(), depth_s())
            .prop_map(|(who, kind, slot, len, depth)| Op::Cancel { who, kind, slot, len, depth }),
        1 => (who_s(), kind_s(), any::<u8>(), prop::sample::select(&ILLEGAL_LABELS[..]))
            .prop_map(|(who, kind, slot, label)| Op::Invoke { who, kind, slot, label }),
        2 => Just(Op::Tick),
        2 => (any::<u8>(), badge_s()).prop_map(|(n, badge)| Op::Interrupt { n, badge }),
        2 => (any::<u8>(), [extra_s(), extra_s(), extra_s()], recv_slot_s())
            .prop_map(|(n, extras, recv)| Op::Rewrite { n, extras, recv }),
    ]
}

/// A preemption schedule: often none, else a few small counts.
fn schedule() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![
        1 => Just(Vec::new()),
        1 => prop::collection::vec(0..6u8, 1..=4),
    ]
}

/// The fault endpoints a thread may have: endpoint capabilities that can
/// take a fault, ones without the rights, a notification, an empty slot, a
/// TCB and a `CPtr` that does not resolve.
const FAULT_EPS: [u64; 12] = [
    slot::EP3_F0,
    slot::EP3_F1,
    slot::EP,
    slot::EP0_BADGED,
    slot::EP0_WGR_BADGED,
    slot::EP1_WG_BADGED,
    slot::EP0_R,
    slot::EP0_W,
    slot::NTFN,
    slot::EMPTY,
    slot::TCB,
    BAD_CPTR,
];

fn config() -> impl Strategy<Value = Config> {
    prop_oneof![
        1 => Just(Config::default()),
        3 => (
            prop_oneof![
                1 => Just([100u8; THREADS]),
                2 => prop::array::uniform6(prop::sample::select(&[90u8, 100, 110][..])),
            ],
            prop::array::uniform6(prop::sample::select(&FAULT_EPS[..])),
        )
            .prop_map(|(prios, fault_eps)| Config { prios, fault_eps }),
    ]
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(20_000)
}

fn run(w: &mut World, ops: &[(Op, Vec<u8>)]) -> Result<(), String> {
    for (op, schedule) in ops {
        let a = resolve(w, op);
        w.apply(&a, schedule)?;
        w.clear_events();
    }
    Ok(())
}

/// What the generated sequences exercise: each step's kind, with the type
/// it named and the state it left its thread in, and how many
/// capabilities moved. Run with `--ignored --nocapture`.
#[test]
#[ignore]
fn coverage_report() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use std::collections::BTreeMap;

    let mut runner = TestRunner::deterministic();
    let strategy = (config(), prop::collection::vec((op(), schedule()), 1..=60));
    let mut tally: BTreeMap<String, u64> = BTreeMap::new();
    let (mut steps, mut preemptions, mut deaths) = (0, 0, 0);
    let mut stats: BTreeMap<String, u64> = BTreeMap::new();
    let n = cases().min(2000);
    for _ in 0..n {
        let (cfg, ops) = strategy.new_tree(&mut runner).unwrap().current();
        let mut w = World::new(&cfg);
        w.tally = Some(BTreeMap::new());
        run(&mut w, &ops).unwrap();
        steps += w.steps;
        preemptions += w.preemptions;
        deaths += w.m.threads.iter().filter(|t| !t.alive).count();
        for (k, v) in w.tally.take().unwrap() {
            *tally.entry(k).or_default() += v;
        }
        // `Stats` prints as `Stats { name: n, ... }`.
        let s = format!("{:?}", w.m.stats);
        for field in s
            .trim_start_matches("Stats {")
            .trim_end_matches('}')
            .split(',')
        {
            if let Some((k, v)) = field.split_once(':') {
                *stats.entry(k.trim().to_string()).or_default() += v.trim().parse::<u64>().unwrap();
            }
        }
    }
    println!("{n} cases, {steps} steps, {preemptions} preemptions, {deaths} threads deleted");
    for (k, v) in stats {
        println!("{v:>8}  rule: {k}");
    }
    for (k, v) in tally {
        println!("{v:>8}  {k}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: cases(),
        failure_persistence: Some(Box::new(FileFailurePersistence::WithSource("regressions"))),
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_ipc_sequences_match_the_model(
        cfg in config(),
        ops in prop::collection::vec((op(), schedule()), 1..=60),
    ) {
        let mut w = World::new(&cfg);
        run(&mut w, &ops).map_err(TestCaseError::fail)?;
    }
}
