//! The M6 red team's host fuzzer (`docs/redteam/`): random system calls by
//! the six threads of `crate::ipc`'s test world, mixing everything M6
//! added with what M5 had: `Call`, `Send`, `NBSend`, `Recv`, `NBRecv`,
//! `Reply` and `ReplyRecv` on endpoints, notifications and saved reply
//! capabilities, with up to three extra capabilities and a receive slot
//! that may be in the receiver's own root CNode, in a second CNode, full or
//! invalid; `CNode_SaveCaller`, `CNode_CancelBadgedSends`, `CNode_Delete`,
//! `CNode_Revoke`, `CNode_Move`, `CNode_Copy` and `CNode_Mint`;
//! `TCB_Suspend`, `TCB_Resume`, `TCB_BindNotification` and
//! `TCB_UnbindNotification`; and faults delivered to random fault
//! endpoints.
//!
//! After every step the scheduler's, IPC's and the notifications'
//! invariants hold ([`World::check`]), and so do these, which no other
//! test checks over random sequences:
//!
//! - every slot's derivation-list links and depth bounds, and `is_final`
//!   exactly when no other capability names the same object;
//! - every one-shot reply capability, wherever it sits, names a thread
//!   that is `BlockedOnReply`, no thread has two, and it is derived from
//!   that thread's master; no master is outside a TCB's `reply` slot;
//! - no capability anywhere is a reply capability with rights other than
//!   Grant, and none is a Zombie in a CNode slot;
//! - a debug assertion or panic anywhere in `l4core` fails the case.

use std::vec::Vec;

use proptest::prelude::*;

use crate::cap::{Cap, CapType, MAX_DERIVATION_DEPTH, Rights, TCB_SLOT_REPLY, TCB_SLOTS};
use crate::cdt;
use crate::invoke::label;
use crate::slot::{SlotAddr, SlotMemory};
use crate::tcb::{TcbRef, Tcbs, ThreadState};

use super::tests::*;
use super::{MessageInfo, word};

/// Root slots of notification capabilities: notification 0 unbadged with
/// all rights (the original), badged 0x5, Write only; notification 1.
const S_N0: u64 = 20;
const S_N0_BADGED: u64 = 21;
const S_N0_W: u64 = 22;
const S_N1: u64 = 23;
/// Root slots 24 to 31 start empty.
const S_EMPTY0: u64 = 24;

/// TCB invocation labels (`docs/abi.md`, "TCB invocations").
const TCB_SUSPEND: u64 = 0x29;
const TCB_RESUME: u64 = 0x2A;
const TCB_BIND: u64 = 0x2B;
const TCB_UNBIND: u64 = 0x2C;

/// The `CPtr`s a random operation names, weighted towards the endpoints,
/// the notifications and the slots transfers and `CNode_SaveCaller` fill:
/// every root slot, a bad one, 0.
fn cptr(i: u8) -> u64 {
    match i % 64 {
        0..=23 => S_EP0 + u64::from(i % 8),
        24..=35 => S_N0 + u64::from(i % 4),
        36..=45 => S_EMPTY0 + u64::from(i % 8),
        46..=51 => S_ROOT,
        52..=54 => S_CNODE2,
        55..=60 => S_TCB + u64::from(i % 6),
        61 => BAD_CPTR,
        62 => 0,
        _ => u64::from(i / 64) + 16,
    }
}

/// One random system call or fault. Everything is a raw choice, decoded
/// by [`step`].
#[derive(Clone, Debug)]
struct Op {
    thread: u8,
    kind: u8,
    target: u8,
    method: u8,
    args: [u8; 4],
    caps: Vec<u8>,
    recv: u8,
    mr0: u64,
}

fn op() -> impl Strategy<Value = Op> {
    (
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        any::<u8>(),
        any::<[u8; 4]>(),
        proptest::collection::vec(any::<u8>(), 0..=3),
        any::<u8>(),
        any::<u64>(),
    )
        .prop_map(|(thread, kind, target, method, args, caps, recv, mr0)| Op {
            thread,
            kind,
            target,
            method,
            args,
            caps,
            recv,
            mr0,
        })
}

/// The world with the notification capabilities added.
fn world() -> World {
    let mut w = World::new();
    let orig = rs(S_N0);
    cdt::insert_root(&mut w.k, orig, ntfn_cap(0, Rights::ALL, 0));
    cdt::insert_derived(
        &mut w.k,
        orig,
        rs(S_N0_BADGED),
        ntfn_cap(0, Rights::ALL, 5),
        true,
    )
    .unwrap();
    cdt::insert_derived(
        &mut w.k,
        orig,
        rs(S_N0_W),
        ntfn_cap(0, Rights::WRITE, 0),
        false,
    )
    .unwrap();
    cdt::insert_root(&mut w.k, rs(S_N1), ntfn_cap(1, Rights::ALL, 0));
    // Capability faults go to an endpoint, where another thread may take
    // them, rather than stopping the thread.
    for t in 0..THREADS {
        w.set_fault_ep(t, S_EP0 + (t as u64 % 4));
    }
    w
}

/// A receive slot as the three IPC buffer words name it.
fn receive_slot(i: u8) -> (u64, u64, u64) {
    match i % 8 {
        // Free root slots, from the root CNode with all 64 bits.
        0..=2 => (S_ROOT, S_EMPTY0 + u64::from(i % 8), 64),
        // Slots of the second CNode, from its capability.
        3 | 4 => (S_CNODE2, u64::from(i / 8) % 16, 4),
        // A full slot, the CNode capability's own.
        5 => (S_ROOT, S_ROOT, 64),
        // Not a CNode capability.
        6 => (S_EP0, 1, 64),
        _ => (S_ROOT, 1, 0),
    }
}

/// A slot argument (index, depth) of a CNode invocation on `cnode`.
fn slot_arg(cnode: u64, a: u8) -> (u64, u64) {
    if cnode == S_CNODE2 {
        (u64::from(a) % 16, 4)
    } else if a == 0xFF {
        (1, 0)
    } else {
        (u64::from(a) % 32, 64)
    }
}

/// Runs one operation; skips it if its thread cannot run.
fn step(w: &mut World, o: &Op) {
    // The first runnable thread from the one chosen.
    let Some(t) = (0..THREADS)
        .map(|i| (o.thread as usize + i) % THREADS)
        .find(|&t| w.state(t).is_runnable())
    else {
        return;
    };
    // Every buffered thread names a receive slot and its extra caps.
    if t != F {
        let (c, i, d) = receive_slot(o.recv);
        w.set_buf(t, word::RECEIVE_CNODE, c);
        w.set_buf(t, word::RECEIVE_INDEX, i);
        w.set_buf(t, word::RECEIVE_DEPTH, d);
        for (i, &c) in o.caps.iter().enumerate() {
            w.set_buf(t, word::CAPS_OR_BADGES + i, cptr(c));
        }
    }
    let target = cptr(o.target);
    let extra = o.caps.len() as u64;
    let mut mrs = [o.mr0, u64::from(o.args[1]), 0, 0];
    let mut length = 1 + u64::from(o.args[0] % 4);
    let mut lbl = u64::from(o.method);
    // Kernel-object invocations get well-formed arguments most of the time.
    let cap = w.cap(rs(target.min(31)));
    if target < 32 {
        match cap.cap_type() {
            CapType::CNode => {
                let methods = [
                    label::CNODE_SAVE_CALLER,
                    label::CNODE_CANCEL_BADGED_SENDS,
                    label::CNODE_DELETE,
                    label::CNODE_REVOKE,
                    label::CNODE_MOVE,
                    label::CNODE_COPY,
                    label::CNODE_MINT,
                ];
                lbl = methods[o.method as usize % methods.len()];
                let (i0, d0) = slot_arg(target, o.args[1]);
                let (i1, d1) = slot_arg(S_ROOT, o.args[2]);
                // The world's threads live for the whole case: never delete
                // the last capability to a TCB or to the second CNode,
                // which may hold one.
                let at = if target == S_CNODE2 {
                    sa(CNODE2).offset(i0)
                } else {
                    rs(i0 % 32)
                };
                let held = w.cap(at);
                if lbl == label::CNODE_DELETE
                    && matches!(held.cap_type(), CapType::Tcb | CapType::CNode)
                    && cdt::is_final(&w.k, at)
                {
                    return;
                }
                mrs = [i0, d0, i1, d1];
                length = match lbl {
                    label::CNODE_MOVE => 4,
                    label::CNODE_COPY => 5,
                    label::CNODE_MINT => 6,
                    _ => 2,
                };
                if t != F {
                    // Copy's rights, Mint's rights and badge.
                    w.set_buf(t, word::MSG + 4, u64::from(o.args[3]) & 0xF);
                    w.set_buf(t, word::MSG + 5, u64::from(o.args[3] >> 4));
                }
            }
            CapType::Tcb => {
                let methods = [
                    TCB_SUSPEND,
                    TCB_RESUME,
                    TCB_RESUME,
                    TCB_RESUME,
                    TCB_BIND,
                    TCB_BIND,
                    TCB_UNBIND,
                ];
                lbl = methods[o.method as usize % methods.len()];
                length = 0;
            }
            _ => {}
        }
    }
    let rsi = MessageInfo::new(lbl, 0, extra, length).word();
    match o.kind % 16 {
        0..=3 => w.syscall(t, 1, target, rsi, Some(mrs)),
        4 | 5 => w.syscall(t, 3, target, rsi, Some(mrs)),
        6 => w.syscall(t, 4, target, rsi, Some(mrs)),
        7..=9 => w.syscall(t, 5, target, 0, None),
        10 => w.syscall(t, 8, target, 0, None),
        11 => w.syscall(t, 6, 0, rsi, Some(mrs)),
        12 | 13 => w.syscall(t, 2, target, rsi, Some(mrs)),
        14 => {
            // Mostly an endpoint, which may or may not allow a fault.
            let ep = if o.method < 200 {
                S_EP0 + u64::from(o.method % 8)
            } else {
                target
            };
            w.set_fault_ep(t, ep);
            w.exception(t, 14, 4, 0xdead_0000)
        }
        _ => w.syscall(t, 7, 0, 0, None),
    };
}

/// Every slot of the world: the two CNodes' and each thread's TCB slots.
fn all_slots() -> Vec<SlotAddr> {
    let mut v: Vec<SlotAddr> = (0..32).map(rs).collect();
    v.extend((0..16).map(|i| sa(CNODE2).offset(i)));
    for i in 0..THREADS {
        v.extend((0..TCB_SLOTS).map(|s| tcb(i).slot(s)));
    }
    v
}

/// The invariants of the module docs, over every slot.
fn check_slots(w: &World) {
    let slots = all_slots();
    let caps: Vec<(SlotAddr, Cap)> = slots
        .iter()
        .map(|&s| (s, w.cap(s)))
        .filter(|(_, c)| !c.is_null())
        .collect();
    for &s in &slots {
        if let Err(e) = cdt::check_slot(&w.k, s) {
            panic!("slot {:#x}: {e}", s.get());
        }
        let n = w.k.load(s).node;
        for link in [n.prev(), n.next()].into_iter().flatten() {
            assert!(slots.contains(&link), "a link leaves the world");
        }
        assert!(n.depth() <= MAX_DERIVATION_DEPTH);
    }
    for (a, c) in &caps {
        let others = caps
            .iter()
            .filter(|(b, d)| b != a && d.same_object(c))
            .count();
        assert_eq!(
            cdt::is_final(&w.k, *a),
            others == 0,
            "is_final({:#x}) with {others} other capabilities to {c:?}",
            a.get()
        );
    }
    let mut targets = Vec::new();
    for &(s, c) in &caps {
        if c.cap_type() == CapType::Zombie {
            assert!(
                !(0..32).map(rs).any(|r| r == s),
                "a Zombie in root slot {:#x}",
                s.get()
            );
        }
        if c.cap_type() != CapType::Reply {
            continue;
        }
        let to = TcbRef::new(c.object()).expect("a reply capability names a TCB");
        if c.is_reply_master() {
            assert_eq!(
                s,
                to.slot(TCB_SLOT_REPLY),
                "a master outside its reply slot"
            );
            continue;
        }
        assert!(
            Rights::GRANT.contains(c.rights()),
            "a reply capability with {:?}",
            c.rights()
        );
        assert_eq!(
            w.k.state(to),
            ThreadState::BlockedOnReply,
            "a reply capability in {:#x} names a thread not waiting for a reply",
            s.get()
        );
        assert_eq!(
            cdt::first_child(&w.k, to.slot(TCB_SLOT_REPLY)),
            Some(s),
            "a reply capability not derived from its target's master"
        );
        assert!(
            !targets.contains(&to),
            "two reply capabilities to one thread"
        );
        targets.push(to);
    }
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 2 } else { 3000 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

/// Not a check: prints how often the fuzzer reaches each thread state, a
/// binding, a fault, a saved reply capability and a filled free slot, to
/// tune its weights (`cargo test -p l4core --lib ipc::redteam -- --ignored
/// --nocapture`).
#[test]
#[ignore]
fn coverage_stats() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    let mut runner = TestRunner::deterministic();
    let strat = proptest::collection::vec(op(), 60..80);
    let mut stats = std::collections::BTreeMap::<&str, u64>::new();
    for _ in 0..2000 {
        let ops = strat.new_tree(&mut runner).unwrap().current();
        let mut w = world();
        for o in &ops {
            step(&mut w, o);
            for t in 0..THREADS {
                let k = match w.state(t) {
                    ThreadState::BlockedOnReply => "reply",
                    ThreadState::BlockedOnSend { is_call: true, .. } => "send-call",
                    ThreadState::BlockedOnSend { .. } => "send",
                    ThreadState::BlockedOnReceive { .. } => "recv",
                    ThreadState::BlockedOnNotification { .. } => "ntfn",
                    ThreadState::Inactive => "inactive",
                    ThreadState::Restart => "restart",
                    ThreadState::Running => "running",
                };
                *stats.entry(k).or_default() += 1;
                if w.k.bound_notification(tcb(t)).is_some() {
                    *stats.entry("bound").or_default() += 1;
                }
                if w.k.fault(tcb(t)).is_some() {
                    *stats.entry("fault").or_default() += 1;
                }
            }
            for s in (0..32).map(rs).chain((0..16).map(|i| sa(CNODE2).offset(i))) {
                let c = w.cap(s);
                if c.cap_type() == CapType::Reply {
                    *stats.entry("saved reply").or_default() += 1;
                }
                if !c.is_null() && s.get() >= rs(S_EMPTY0).get() {
                    *stats.entry("filled free slot").or_default() += 1;
                }
            }
        }
    }
    std::println!("{stats:#?}");
}

proptest! {
    #![proptest_config(config())]

    // Under Miri its checks of every slot after every step take too long;
    // nothing here is unsafe.
    #[test]
    #[cfg_attr(miri, ignore)]
    fn random_ipc_keeps_every_invariant(ops in proptest::collection::vec(op(), 1..80)) {
        let mut w = world();
        for o in &ops {
            step(&mut w, o);
            w.check();
            check_slots(&w);
        }
    }
}
