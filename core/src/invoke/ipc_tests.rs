//! Host tests of the two CNode methods that act on IPC state,
//! `CNode_SaveCaller` and `CNode_CancelBadgedSends`, decoded by
//! [`super::invoke`] and driven through system calls as threads make them
//! ([`crate::syscall::handle_syscall`]) in the world of `crate::ipc`'s
//! tests: each method's effect, every error row of `docs/abi.md` in its
//! order, and that a failed call changes nothing. The scheduler's and IPC's
//! invariants are checked at every kernel exit ([`World::check`]).

use std::vec::Vec;

use super::label;
use crate::cap::{Cap, CapType, Rights, TCB_SLOT_REPLY};
use crate::cdt;
use crate::error::{LookupFailure, SyscallError};
use crate::ipc::tests::*;
use crate::ipc::{EpState, MessageInfo};
use crate::syscall::Outcome;
use crate::tcb::{self, Tcbs, ThreadState};
use crate::testing::ThreadEvent;

const SAVE: u64 = label::CNODE_SAVE_CALLER;
const CANCEL: u64 = label::CNODE_CANCEL_BADGED_SENDS;

/// Root slot of a client copy of [`S_EP0_BADGED`]: Write only, a child of
/// the badged original.
const S_CLIENT: u64 = 25;
/// Root slot of EP0 minted with badge [`OTHER`] and all rights.
const S_OTHER: u64 = 26;
const OTHER: u64 = 0x99;

/// What thread `t` got back from the kernel: the error code (0 for
/// success) and the detail or result words.
fn kernel_reply(w: &World, t: usize) -> (u64, Vec<u64>) {
    let m = MessageInfo::from_word(w.regs(t).rsi);
    let words = (0..m.length() as usize).map(|i| w.mr(t, i)).collect();
    (m.label(), words)
}

/// The reply an invocation failing with `err` gives.
fn error(err: SyscallError) -> (u64, Vec<u64>) {
    let (words, n) = err.detail();
    (err.code(), words[..n].to_vec())
}

const OK: (u64, Vec<u64>) = (0, Vec::new());

/// `t` calls `method` on the root CNode with `len` message registers from
/// `[index, depth]`.
fn cnode_call(w: &mut World, t: usize, method: u64, len: u64, index: u64, depth: u64) -> Outcome {
    w.call(t, S_ROOT, method, len, [index, depth, 0, 0])
}

/// Every capability in the root CNode and every thread's caller slot.
fn snapshot(w: &World) -> Vec<Cap> {
    let mut v: Vec<Cap> = (0..32).map(|i| w.cap(rs(i))).collect();
    v.extend((0..THREADS).map(|t| w.caller_slot(t)));
    v
}

// ---------------------------------------------------------------------------
// CNode_SaveCaller
// ---------------------------------------------------------------------------

/// B has received A's `Call` and holds the reply capability.
fn serving() -> World {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    w
}

#[test]
fn save_caller_moves_the_reply_capability_below_its_callers_master() {
    let mut w = serving();
    let reply = w.caller_slot(B);
    assert_eq!(cnode_call(&mut w, B, SAVE, 2, S_FREE, 64), Outcome::Done);
    assert_eq!(kernel_reply(&w, B), OK);
    assert!(w.caller_slot(B).is_null());
    assert_eq!(w.cap(rs(S_FREE)), reply);
    assert_eq!(
        cdt::first_child(&w.k, tcb(A).slot(TCB_SLOT_REPLY)),
        Some(rs(S_FREE))
    );
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    w.check();
    // Receiving again leaves a saved reply capability alone, and so does
    // replying with the empty caller slot.
    w.reply_recv(B, S_EP1, 0, 0, [0; 4]);
    assert_eq!(w.cap(rs(S_FREE)), reply);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    // Anyone holding it can reply.
    w.send(C, S_FREE, 3, 1, [33, 0, 0, 0]);
    assert_eq!((w.state(A), w.mrs(A)[0]), (ThreadState::Running, 33));
    assert!(w.cap(rs(S_FREE)).is_null());
    w.check();
}

#[test]
fn save_caller_by_send_saves_and_writes_no_reply() {
    let mut w = serving();
    w.syscall(B, 3, S_ROOT, info(SAVE, 2), Some([S_FREE + 1, 64, 0, 0]));
    assert!(!w.cap(rs(S_FREE + 1)).is_null());
    assert!(w.caller_slot(B).is_null());
    let r = w.regs(B);
    assert_eq!((r.rdi, r.rsi, r.r10), (S_ROOT, info(SAVE, 2), S_FREE + 1));
}

#[test]
fn save_caller_reports_its_errors_in_order_and_changes_nothing() {
    let bad_depth = SyscallError::RangeError { min: 1, max: 64 };
    let guard = SyscallError::FailedLookup {
        source: false,
        failure: BAD_CPTR_FAILURE,
    };
    let guard_63 = SyscallError::FailedLookup {
        source: false,
        failure: LookupFailure::GuardMismatch {
            bits_left: 63,
            guard: 0,
            guard_size: 59,
        },
    };
    let short = SyscallError::FailedLookup {
        source: false,
        failure: LookupFailure::DepthMismatch {
            bits_left: 63,
            bits_found: 64,
        },
    };
    // (holds a reply, length, index, depth, error)
    let rows = [
        (true, 0, S_FREE, 64, SyscallError::TruncatedMessage),
        (true, 1, S_FREE, 64, SyscallError::TruncatedMessage),
        (true, 2, S_FREE, 0, bad_depth),
        (true, 2, S_FREE, 65, bad_depth),
        (true, 2, BAD_CPTR, 64, guard),
        (true, 2, S_FREE, 63, guard_63),
        (true, 2, 5, 63, short),
        (true, 2, S_EP1, 64, SyscallError::DeleteFirst),
        // A full destination comes before an empty caller slot.
        (false, 2, S_EP1, 64, SyscallError::DeleteFirst),
        (false, 2, S_FREE, 64, SyscallError::IllegalOperation),
        // A range error comes before the lookup, the lookup before both.
        (false, 2, BAD_CPTR, 0, bad_depth),
        (false, 2, BAD_CPTR, 64, guard),
    ];
    for (holds, len, index, depth, err) in cases(&rows) {
        let mut w = if holds { serving() } else { World::new() };
        w.run(B);
        let before = snapshot(&w);
        cnode_call(&mut w, B, SAVE, len, index, depth);
        assert_eq!(kernel_reply(&w, B), error(err), "{len} {index:#x} {depth}");
        assert_eq!(snapshot(&w), before, "{err:?}");
        w.check();
    }
}

#[test]
fn a_saved_reply_capability_goes_when_its_caller_is_suspended() {
    let mut w = serving();
    cnode_call(&mut w, B, SAVE, 2, S_FREE, 64);
    assert!(!w.cap(rs(S_FREE)).is_null());
    w.call(C, S_TCB + A as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(kernel_reply(&w, C), OK);
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert!(w.cap(rs(S_FREE)).is_null());
    assert!(!cdt::has_children(&w.k, tcb(A).slot(TCB_SLOT_REPLY)));
    w.check();
}

#[test]
fn save_caller_with_no_invoking_thread_has_nothing_to_save() {
    let mut w = World::new();
    assert_eq!(
        crate::ipc::save_caller(&mut w.k, None, rs(S_FREE)),
        Err(SyscallError::IllegalOperation)
    );
    assert_eq!(
        crate::ipc::save_caller(&mut w.k, None, rs(S_EP1)),
        Err(SyscallError::DeleteFirst)
    );
    w.check();
}

// ---------------------------------------------------------------------------
// CNode_CancelBadgedSends
// ---------------------------------------------------------------------------

/// The world with a client copy of the badged original in [`S_CLIENT`] and
/// a second badge in [`S_OTHER`].
fn badged() -> World {
    let mut w = World::new();
    let client = ep_cap(0, Rights::WRITE, BADGE);
    cdt::insert_derived(&mut w.k, rs(S_EP0_BADGED), rs(S_CLIENT), client, false).unwrap();
    let other = ep_cap(0, Rights::ALL, OTHER);
    cdt::insert_derived(&mut w.k, rs(S_EP0), rs(S_OTHER), other, true).unwrap();
    w.check();
    w
}

/// B sends with [`BADGE`] (through the client copy), C with [`OTHER`], D
/// calls with [`BADGE`] and E sends unbadged: the queue is B, C, D, E.
fn queued() -> World {
    let mut w = badged();
    w.send(B, S_CLIENT, 1, 0, [0; 4]);
    w.send(C, S_OTHER, 2, 0, [0; 4]);
    w.call(D, S_EP0_BADGED, 3, 0, [0; 4]);
    w.send(E, S_EP0, 4, 0, [0; 4]);
    assert_eq!(w.queue(0), [B, C, D, E].map(tcb));
    w
}

#[test]
fn cancel_badged_sends_restarts_exactly_that_badges_senders_in_queue_order() {
    let mut w = queued();
    w.run(A);
    w.k.thread_events.clear();
    assert_eq!(
        cnode_call(&mut w, A, CANCEL, 2, S_EP0_BADGED, 64),
        Outcome::Done
    );
    assert_eq!(kernel_reply(&w, A), OK);
    assert_eq!(
        w.k.thread_events,
        [ThreadEvent::CancelBadgedSends {
            ep: ep(0),
            badge: BADGE
        }]
    );
    // C and E keep their places; the endpoint still holds senders.
    assert_eq!(w.queue(0), [tcb(C), tcb(E)]);
    assert_eq!(w.endpoint(0).state, EpState::Send);
    for t in [B, D] {
        assert_eq!(w.state(t), ThreadState::Restart);
        assert_eq!(w.k.ep_links(tcb(t)), (None, None));
    }
    // They joined the ready queue in queue order, after F.
    let ready = w.ready();
    assert_eq!(ready[ready.len() - 2..], [tcb(B), tcb(D)]);
    // Each re-executes its system call: B's capability survived, so it
    // queues again with its badge, behind the others.
    w.run(B);
    assert_eq!(w.regs(B).next_ip, w.regs(B).fault_ip);
    w.syscall(B, 3, S_CLIENT, w.regs(B).rsi, None);
    assert_eq!(w.queue(0), [tcb(C), tcb(E), tcb(B)]);
}

#[test]
fn revoking_first_retires_the_badge() {
    let mut w = queued();
    w.run(A);
    // The revoke deletes the client copy; B stays queued, since other
    // capabilities to the endpoint remain.
    cnode_call(&mut w, A, label::CNODE_REVOKE, 2, S_EP0_BADGED, 64);
    assert!(w.cap(rs(S_CLIENT)).is_null());
    assert_eq!(w.queue(0), [B, C, D, E].map(tcb));
    cnode_call(&mut w, A, CANCEL, 2, S_EP0_BADGED, 64);
    assert_eq!(w.queue(0), [tcb(C), tcb(E)]);
    // B restarts its Send and finds the slot empty: it goes on.
    w.run(B);
    w.syscall(B, 3, S_CLIENT, w.regs(B).rsi, None);
    assert_eq!(w.state(B), ThreadState::Running);
    assert_eq!(w.queue(0), [tcb(C), tcb(E)]);
    cnode_call(&mut w, A, CANCEL, 2, S_OTHER, 64);
    assert_eq!(w.queue(0), [tcb(E)]);
    // Releasing every sender leaves the endpoint Idle.
    let mut w = badged();
    w.send(B, S_CLIENT, 1, 0, [0; 4]);
    cnode_call(&mut w, A, CANCEL, 2, S_EP0_BADGED, 64);
    assert_eq!(w.endpoint(0).state, EpState::Idle);
    assert!(w.queue(0).is_empty());
}

#[test]
fn an_unbadged_capability_or_a_queue_of_receivers_is_left_alone() {
    // Badge 0: nothing, and the hook is not called.
    let mut w = queued();
    w.run(A);
    w.k.thread_events.clear();
    cnode_call(&mut w, A, CANCEL, 2, S_EP0, 64);
    assert_eq!(kernel_reply(&w, A), OK);
    assert_eq!(w.k.thread_events, []);
    assert_eq!(w.queue(0), [B, C, D, E].map(tcb));
    // Receivers waiting on the endpoint.
    let mut w = badged();
    w.recv(B, S_EP0);
    w.recv(C, S_EP0_BADGED);
    cnode_call(&mut w, A, CANCEL, 2, S_EP0_BADGED, 64);
    assert_eq!(kernel_reply(&w, A), OK);
    assert_eq!(w.queue(0), [tcb(B), tcb(C)]);
    assert_eq!(w.endpoint(0).state, EpState::Recv);
    // An idle endpoint.
    let mut w = badged();
    cnode_call(&mut w, A, CANCEL, 2, S_EP0_BADGED, 64);
    assert_eq!(kernel_reply(&w, A), OK);
    assert_eq!(w.endpoint(0).state, EpState::Idle);
}

#[test]
fn callers_already_received_keep_waiting_and_a_queued_fault_restarts() {
    let mut w = badged();
    // D's Call with the badge was received: D waits for B's reply.
    w.recv(B, S_EP0);
    w.call(D, S_EP0_BADGED, 3, 0, [0; 4]);
    assert_eq!(w.state(D), ThreadState::BlockedOnReply);
    // F faults, its fault endpoint the badged original: its fault is
    // queued with the badge.
    w.set_fault_ep(F, S_EP0_BADGED);
    w.exception(F, 14, 0x4, 0x1000);
    assert!(matches!(
        w.state(F),
        ThreadState::BlockedOnSend {
            badge: BADGE,
            is_call: true,
            ..
        }
    ));
    assert!(w.k.fault(tcb(F)).is_some());
    cnode_call(&mut w, A, CANCEL, 2, S_EP0_BADGED, 64);
    assert_eq!(kernel_reply(&w, A), OK);
    // F restarts its faulting instruction with no fault held.
    assert_eq!(w.state(F), ThreadState::Restart);
    assert_eq!(w.k.fault(tcb(F)), None);
    assert_eq!(w.regs(F).next_ip, w.regs(F).fault_ip);
    // D still waits, and B's reply reaches it.
    assert_eq!(w.state(D), ThreadState::BlockedOnReply);
    assert_eq!(w.caller_slot(B), Cap::reply(tcb(D).get(), false, true));
    w.reply(B, 5, 1, [55, 0, 0, 0]);
    assert_eq!((w.state(D), w.mrs(D)[0]), (ThreadState::Running, 55));
    w.check();
}

#[test]
fn cancel_badged_sends_reports_its_errors_in_order_and_changes_nothing() {
    let illegal = SyscallError::IllegalOperation;
    let bad_depth = SyscallError::RangeError { min: 1, max: 64 };
    let guard = SyscallError::FailedLookup {
        source: false,
        failure: BAD_CPTR_FAILURE,
    };
    let rows = [
        (0, S_EP0_BADGED, 64, SyscallError::TruncatedMessage),
        (1, S_EP0_BADGED, 64, SyscallError::TruncatedMessage),
        (2, S_EP0_BADGED, 0, bad_depth),
        (2, S_EP0_BADGED, 65, bad_depth),
        (2, BAD_CPTR, 64, guard),
        // Not every right, badged or not: the rights come before the badge.
        (2, S_CLIENT, 64, illegal),
        (2, S_EP0_W, 64, illegal),
        (2, S_EP0_R, 64, illegal),
        (2, 27, 64, illegal),
        // Not an endpoint.
        (2, S_FREE, 64, illegal),
        (2, S_FRAME_RW, 64, illegal),
        (2, S_TCB, 64, illegal),
        (2, S_ROOT, 64, illegal),
    ];
    for (len, index, depth, err) in cases(&rows) {
        let mut w = queued();
        // A capability to EP0 with badge BADGE and every right but
        // GrantReply.
        let no_gr = ep_cap(0, Rights(Rights::ALL.0 & !Rights::GRANT_REPLY.0), BADGE);
        cdt::insert_derived(&mut w.k, rs(S_EP0_BADGED), rs(27), no_gr, false).unwrap();
        w.run(A);
        w.k.thread_events.clear();
        let before = snapshot(&w);
        cnode_call(&mut w, A, CANCEL, len, index, depth);
        assert_eq!(kernel_reply(&w, A), error(err), "{len} {index:#x} {depth}");
        assert_eq!(snapshot(&w), before);
        assert_eq!(w.queue(0), [B, C, D, E].map(tcb));
        assert!(
            !w.k.thread_events
                .iter()
                .any(|e| matches!(e, ThreadEvent::CancelBadgedSends { .. }))
        );
        w.check();
    }
}

#[test]
fn a_capability_to_another_type_with_a_badge_is_no_endpoint() {
    // A notification capability with a badge and every right it has.
    let mut w = queued();
    let ntfn = Cap::new(
        CapType::Notification,
        0x7800,
        crate::cap::NOTIFICATION_BITS,
        Rights::ALL,
        false,
        BADGE,
    );
    cdt::insert_root(&mut w.k, rs(28), ntfn);
    w.run(A);
    cnode_call(&mut w, A, CANCEL, 2, 28, 64);
    assert_eq!(kernel_reply(&w, A), error(SyscallError::IllegalOperation));
    assert_eq!(w.queue(0), [B, C, D, E].map(tcb));
}
