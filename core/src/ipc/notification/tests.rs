//! Host tests of notifications, driven through system calls as threads
//! make them ([`crate::syscall::handle_syscall`]) in the world of
//! `crate::ipc`'s tests, with the scheduler run at every kernel exit and
//! the scheduler's, IPC's and the notifications' invariants checked there:
//! signal, wait and poll, binding and the bound receive, cancellation and
//! deletion, and the invariant checker. `model.rs` runs random sequences of
//! them against a model.

use std::vec;
use std::vec::Vec;

use super::*;
use crate::cap::Rights;
use crate::cdt;
use crate::invoke::label::CNODE_DELETE;
use crate::ipc::tests::*;
use crate::ipc::{Endpoint, MessageInfo, word};
use crate::slot::SlotMemory;
use crate::syscall::Outcome;
use crate::tcb::{self, NtfnRef, Tcbs};

mod model;

// ---------------------------------------------------------------------------
// The world's notifications
// ---------------------------------------------------------------------------

/// The notifications the tests give capabilities to: 0 to 2.
const NS: usize = 3;
/// Notification `i`'s capabilities are in root slots `S_NTFN + 4 i` to
/// `S_NTFN + 4 i + 3`, one per variant below.
const S_NTFN: u64 = 20;

/// The original: Read and Write, unbadged.
const ORIG: u64 = 0;
/// Minted with badge `1 << 2i`, Read and Write.
const BADGED: u64 = 1;
/// Minted with badge `1 << (2i + 1)`, Write only.
const BADGED_W: u64 = 2;
/// A copy with Read only, unbadged.
const READ_ONLY: u64 = 3;
const VARIANTS: u64 = 4;

/// The root slot of notification `i`'s capability `v`, which is also its
/// `CPtr`.
fn sn(i: usize, v: u64) -> u64 {
    S_NTFN + VARIANTS * i as u64 + v
}

/// The badge of notification `i`'s capability `v`.
fn badge_of(i: usize, v: u64) -> u64 {
    match v {
        BADGED => 1 << (2 * i),
        BADGED_W => 1 << (2 * i + 1),
        _ => 0,
    }
}

/// The rights of capability `v`.
fn rights_of(v: u64) -> Rights {
    match v {
        BADGED_W => Rights::WRITE,
        READ_ONLY => Rights::READ,
        _ => RW,
    }
}

/// Puts notification `i`'s four capabilities in their slots, as retype and
/// Mint would: the original a root, the badged ones originals derived from
/// it, the read-only one a copy.
fn add_ntfn_caps<M: SlotMemory + ?Sized>(k: &mut M, i: usize) {
    let orig = rs(sn(i, ORIG));
    cdt::insert_root(k, orig, ntfn_cap(i, RW, 0));
    for v in [BADGED, BADGED_W, READ_ONLY] {
        let cap = ntfn_cap(i, rights_of(v), badge_of(i, v));
        cdt::insert_derived(k, orig, rs(sn(i, v)), cap, v != READ_ONLY).unwrap();
    }
}

/// The IPC world with notifications 0 to 2 and their capabilities.
fn world() -> World {
    let mut w = World::new();
    for i in 0..NS {
        add_ntfn_caps(&mut w.k, i);
    }
    w.check();
    w
}

fn nt(w: &World, i: usize) -> Notification {
    notification(&w.k, ntfn(i))
}

/// The threads waiting on notification `i`, head first.
fn nqueue(w: &World, i: usize) -> Vec<TcbRef> {
    let mut v = Vec::new();
    let mut cur = nt(w, i).head;
    while let Some(t) = cur {
        v.push(t);
        cur = w.k.ep_links(t).1;
    }
    v
}

fn active(word: u64) -> Notification {
    Notification {
        state: NtfnState::Active,
        word,
        ..Notification::IDLE
    }
}

fn waiting(head: usize, tail: usize) -> Notification {
    Notification {
        state: NtfnState::Waiting,
        head: Some(tcb(head)),
        tail: Some(tcb(tail)),
        ..Notification::IDLE
    }
}

fn on(i: usize) -> ThreadState {
    ThreadState::BlockedOnNotification { ntfn: ntfn(i) }
}

fn on_receive(i: usize) -> ThreadState {
    ThreadState::BlockedOnReceive {
        ep: ep(i),
        can_grant: true,
    }
}

fn info_caps(label: u64, extra: u64, length: u64) -> u64 {
    MessageInfo::new(label, 0, extra, length).word()
}

/// `rdi` and `rsi` of thread `t`.
fn got(w: &World, t: usize) -> (u64, u64) {
    let r = w.regs(t);
    (r.rdi, r.rsi)
}

/// `actor` calls `TCB_BindNotification` on `target`'s TCB with the
/// capability `cptr` as extra capability 0 (none if `cptr` is `None`).
/// Returns the reply's `rsi`.
fn bind(w: &mut World, actor: usize, target: usize, cptr: Option<u64>) -> u64 {
    let extra = match cptr {
        Some(c) => {
            if actor != F {
                w.set_buf(actor, word::CAPS_OR_BADGES, c);
            }
            1
        }
        None => 0,
    };
    let rsi = info_caps(tcb::label::BIND_NOTIFICATION, extra, 0);
    w.syscall(actor, 1, S_TCB + target as u64, rsi, None);
    w.regs(actor).rsi
}

/// `actor` calls `TCB_UnbindNotification` on `target`'s TCB. Returns the
/// reply's `rsi`.
fn unbind(w: &mut World, actor: usize, target: usize) -> u64 {
    w.call(
        actor,
        S_TCB + target as u64,
        tcb::label::UNBIND_NOTIFICATION,
        0,
        [0; 4],
    );
    w.regs(actor).rsi
}

/// `actor` deletes root slot `slot` with `CNode_Delete`.
fn delete(w: &mut World, actor: usize, slot: u64) {
    w.call(actor, S_ROOT, CNODE_DELETE, 2, [slot, 64, 0, 0]);
    assert_eq!(w.regs(actor).rsi, info(0, 0), "deleting slot {slot}");
}

/// `actor` deletes every capability to notification `i`, the original
/// last, so that its deletion is the final one.
fn delete_ntfn(w: &mut World, actor: usize, i: usize) {
    for v in [READ_ONLY, BADGED_W, BADGED, ORIG] {
        delete(w, actor, sn(i, v));
    }
}

/// D waits on EP1 as `t`'s fault handler.
fn with_handler(w: &mut World, t: usize) {
    w.set_fault_ep(t, S_EP1);
    w.recv(D, S_EP1);
}

/// The message D, the handler, received: label and words.
fn handler_got(w: &World) -> (u64, Vec<u64>) {
    let m = MessageInfo::from_word(w.regs(D).rsi);
    let words = (0..m.length() as usize).map(|i| w.mr(D, i)).collect();
    (m.label(), words)
}

/// The capability fault a receive phase on a slot it cannot use raises:
/// `MissingCapability` with 0 bits left (ADR 0026).
fn recv_cap_fault(ip: u64, cptr: u64) -> (u64, Vec<u64>) {
    (1, vec![ip, cptr, 1, 2, 0])
}

// ---------------------------------------------------------------------------
// Signal
// ---------------------------------------------------------------------------

#[test]
fn signals_with_nobody_waiting_or_their_badges_into_the_word() {
    let mut w = world();
    w.set_mrs(A, [1, 2, 3, 4]);
    let rsi = info(0x42, 2);
    assert_eq!(w.syscall(A, 3, sn(0, BADGED), rsi, None), Outcome::Done);
    assert_eq!(nt(&w, 0), active(1));
    // The signaller goes on with its registers as they were.
    assert_eq!(got(&w, A), (sn(0, BADGED), rsi));
    assert_eq!(w.mrs(A), [1, 2, 3, 4]);
    assert_eq!(w.state(A), ThreadState::Running);
    w.nbsend(A, sn(0, BADGED_W), 0, 0, [0; 4]);
    assert_eq!(nt(&w, 0), active(3));
    // Repeated signals coalesce; an unbadged one adds nothing but is not
    // lost either.
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    w.send(A, sn(0, ORIG), 0, 0, [0; 4]);
    assert_eq!(nt(&w, 0), active(3));
}

#[test]
fn an_unbadged_signal_is_remembered_as_active_with_word_0() {
    let mut w = world();
    w.send(A, sn(1, ORIG), 0, 0, [0; 4]);
    assert_eq!(nt(&w, 1), active(0));
    // A later waiter takes it at once and does not block.
    w.set_mrs(B, [9; 4]);
    assert_eq!(w.recv(B, sn(1, ORIG)), Outcome::Done);
    assert_eq!(w.state(B), ThreadState::Running);
    assert_eq!(got(&w, B), (0, 0));
    assert_eq!(w.mrs(B), [9; 4], "message registers are unchanged");
    assert_eq!(nt(&w, 1), Notification::IDLE);
}

#[test]
fn a_signal_wakes_the_first_waiter_with_its_badge() {
    let mut w = world();
    w.set_mrs(B, [0xB; 4]);
    for t in [B, C] {
        assert_eq!(w.recv(t, sn(0, READ_ONLY)), Outcome::Done);
        assert_eq!(w.state(t), on(0));
    }
    assert_eq!(nt(&w, 0), waiting(B, C));
    assert_eq!(nqueue(&w, 0), [tcb(B), tcb(C)]);
    w.run(A);
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    assert_eq!(w.state(B), ThreadState::Running);
    assert_eq!(got(&w, B), (1, 0));
    assert_eq!(w.mrs(B), [0xB; 4]);
    assert_eq!(nqueue(&w, 0), [tcb(C)]);
    assert_eq!(nt(&w, 0).state, NtfnState::Waiting);
    // The woken waiter joined the tail of its ready queue.
    assert_eq!(*w.ready().last().unwrap(), tcb(B));
    // The word stays 0 while threads wait: the badge went to the waiter.
    w.send(A, sn(0, BADGED_W), 0, 0, [0; 4]);
    assert_eq!(got(&w, C), (2, 0));
    assert_eq!(nt(&w, 0), Notification::IDLE);
}

#[test]
fn call_on_a_notification_signals_then_returns_an_empty_reply() {
    let mut w = world();
    w.recv(B, sn(2, ORIG));
    w.run(A);
    assert_eq!(w.call(A, sn(2, BADGED), 7, 2, [5, 6, 7, 8]), Outcome::Done);
    assert_eq!(got(&w, B), (1 << 4, 0));
    assert_eq!(got(&w, A), (0, info(0, 0)));
    assert_eq!(w.mrs(A), [5, 6, 7, 8], "the reply has no words");
    assert_eq!(w.state(A), ThreadState::Running);
}

#[test]
fn signalling_needs_write() {
    let mut w = world();
    w.recv(B, sn(0, ORIG));
    w.run(A);
    for number in [3, 4] {
        w.syscall(A, number, sn(0, READ_ONLY), info(1, 0), None);
        assert_eq!(got(&w, A), (sn(0, READ_ONLY), info(1, 0)));
    }
    w.call(A, sn(0, READ_ONLY), 1, 0, [9; 4]);
    assert_eq!(got(&w, A), (0, info(2, 1)), "InvalidCapability");
    assert_eq!(w.mrs(A)[0], 0);
    assert_eq!(w.state(B), on(0), "nothing was signalled");
}

#[test]
fn a_signals_extra_capabilities_are_looked_up_but_never_moved() {
    // A pointer that does not resolve: a capability fault for Send and
    // Call, nothing at all for NBSend, and in no case a signal.
    for number in [1, 3, 4] {
        let mut w = world();
        with_handler(&mut w, A);
        w.set_buf(A, word::CAPS_OR_BADGES, BAD_CPTR);
        let ip = w.regs(A).next_ip;
        w.syscall(A, number, sn(0, BADGED), info_caps(0, 1, 0), None);
        assert_eq!(nt(&w, 0), Notification::IDLE, "syscall {number}");
        if number == 4 {
            assert_eq!(w.state(A), ThreadState::Running);
        } else {
            assert_eq!(w.state(A), ThreadState::BlockedOnReply);
            let (label, words) = handler_got(&w);
            assert_eq!((label, &words[..3]), (1, &[ip, BAD_CPTR, 0][..]));
        }
    }
    // One that resolves: the signal happens and the waiter gets no
    // capability, nor any message register.
    // B names slot 0 of the second CNode as its receive slot.
    let mut w = world();
    w.set_buf(B, word::MSG + 4, 0xBB);
    for (i, v) in [S_CNODE2, 0, 4].into_iter().enumerate() {
        w.set_buf(B, 125 + i, v);
    }
    w.recv(B, sn(0, ORIG));
    w.run(A);
    w.set_buf(A, word::CAPS_OR_BADGES, S_EP1);
    w.set_buf(A, word::MSG + 4, 0xAA);
    w.syscall(A, 3, sn(0, BADGED), info_caps(3, 1, 5), Some([1, 2, 3, 4]));
    assert_eq!(got(&w, B), (1, 0));
    assert_eq!(w.mr(B, 4), 0xBB);
    assert!(w.cap(sa(CNODE2)).is_null());
}

#[test]
fn the_kernel_signals_through_the_same_path() {
    let mut w = world();
    signal(&mut w.k, ntfn(0), 0x100);
    w.exit();
    assert_eq!(nt(&w, 0), active(0x100));
    w.recv(B, sn(1, ORIG));
    signal(&mut w.k, ntfn(1), 0x200);
    w.exit();
    assert_eq!(got(&w, B), (0x200, 0));
    assert_eq!(w.state(B), ThreadState::Running);
}

// ---------------------------------------------------------------------------
// Wait and poll
// ---------------------------------------------------------------------------

#[test]
fn a_wait_takes_a_pending_word_and_clears_it_whatever_its_badge() {
    let mut w = world();
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    w.send(A, sn(0, BADGED_W), 0, 0, [0; 4]);
    // The badge of the capability waited on plays no part.
    w.set_mrs(B, [3; 4]);
    w.recv(B, sn(0, BADGED));
    assert_eq!(got(&w, B), (3, 0));
    assert_eq!(w.mrs(B), [3; 4]);
    assert_eq!(nt(&w, 0), Notification::IDLE);
    // Nothing pending now: the next wait blocks.
    w.recv(B, sn(0, BADGED));
    assert_eq!(w.state(B), on(0));
}

#[test]
fn a_poll_never_blocks() {
    let mut w = world();
    w.set_mrs(B, [4; 4]);
    w.nbrecv(B, sn(0, ORIG));
    assert_eq!((w.state(B), got(&w, B)), (ThreadState::Running, (0, 0)));
    assert_eq!(w.mrs(B), [4; 4]);
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    w.nbrecv(B, sn(0, READ_ONLY));
    assert_eq!(got(&w, B), (1, 0));
    assert_eq!(nt(&w, 0), Notification::IDLE);
    // With others waiting, a poll finds nothing and does not queue.
    w.recv(C, sn(0, ORIG));
    w.nbrecv(B, sn(0, ORIG));
    assert_eq!((w.state(B), got(&w, B)), (ThreadState::Running, (0, 0)));
    assert_eq!(nqueue(&w, 0), [tcb(C)]);
}

#[test]
fn an_empty_poll_sets_rdi_and_rsi_to_0_whatever_they_held() {
    // `rsi` is no input of a receive: an empty poll gives 0 and 0 as an
    // empty `NBRecv` on an endpoint does, Idle or with others waiting.
    let mut w = world();
    w.set_mrs(B, [5; 4]);
    w.syscall(B, 8, sn(0, ORIG), info_caps(0x55, 1, 3), None);
    assert_eq!((w.state(B), got(&w, B)), (ThreadState::Running, (0, 0)));
    w.recv(C, sn(0, ORIG));
    w.syscall(B, 8, sn(0, READ_ONLY), u64::MAX, None);
    assert_eq!((w.state(B), got(&w, B)), (ThreadState::Running, (0, 0)));
    assert_eq!(w.mrs(B), [5; 4]);
    assert_eq!(nqueue(&w, 0), [tcb(C)]);
}

#[test]
fn waiting_and_polling_need_read() {
    for number in [5, 8] {
        let mut w = world();
        with_handler(&mut w, A);
        let ip = w.regs(A).next_ip;
        w.syscall(A, number, sn(1, BADGED_W), 0, None);
        assert_eq!(handler_got(&w), recv_cap_fault(ip, sn(1, BADGED_W)));
        assert_eq!(nt(&w, 1), Notification::IDLE);
    }
}

#[test]
fn waiting_leaves_the_caller_slot_alone_and_reply_recv_replies_first() {
    let mut w = world();
    // B holds a reply to A, then waits on a notification.
    w.recv(B, S_EP0);
    w.run(A);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    w.recv(B, sn(0, ORIG));
    assert_eq!(w.state(B), on(0));
    assert!(!w.caller_slot(B).is_null(), "a wait keeps the reply");
    w.run(C);
    w.send(C, sn(0, BADGED), 0, 0, [0; 4]);
    // B still answers A.
    w.run(B);
    w.reply(B, 0x9, 1, [0x99, 0, 0, 0]);
    assert_eq!(
        (w.state(A), w.regs(A).rsi, w.mrs(A)[0]),
        (ThreadState::Running, info(0x9, 1), 0x99)
    );
    // ReplyRecv on a notification replies, then waits.
    w.recv(B, S_EP0);
    w.run(A);
    w.call(A, S_EP0, 2, 0, [0; 4]);
    w.run(B);
    w.reply_recv(B, sn(0, ORIG), 0x7, 0, [0; 4]);
    assert_eq!(
        (w.state(A), w.regs(A).rsi),
        (ThreadState::Running, info(0x7, 0))
    );
    assert_eq!(w.state(B), on(0));
    assert!(w.caller_slot(B).is_null(), "the reply consumed it");
    // A pending signal completes ReplyRecv's wait at once.
    w.run(A);
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    w.call(C, S_EP0, 3, 0, [0; 4]);
    w.run(D);
    w.recv(D, S_EP0);
    w.send(A, sn(0, BADGED_W), 0, 0, [0; 4]);
    w.run(D);
    w.reply_recv(D, sn(0, ORIG), 0, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::Running);
    assert_eq!((w.state(D), got(&w, D)), (ThreadState::Running, (2, 0)));
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

#[test]
fn bind_errors_in_order() {
    let mut w = world();
    let (truncated, illegal) = (info(7, 0), info(3, 0));
    // No extra capability, also when the caller has no buffer to name one.
    assert_eq!(bind(&mut w, A, B, None), truncated);
    assert_eq!(bind(&mut w, F, B, Some(sn(0, ORIG))), truncated);
    // Not a notification, or one without Read.
    assert_eq!(bind(&mut w, A, B, Some(S_EP0)), illegal);
    assert_eq!(bind(&mut w, A, B, Some(sn(0, BADGED_W))), illegal);
    // A notification with waiters, or bound already.
    w.recv(C, sn(0, ORIG));
    assert_eq!(bind(&mut w, A, B, Some(sn(0, ORIG))), illegal);
    assert_eq!(bind(&mut w, A, D, Some(sn(1, READ_ONLY))), info(0, 0));
    assert_eq!(bind(&mut w, A, B, Some(sn(1, ORIG))), illegal);
    // The TCB bound already, even to a notification it could bind.
    assert_eq!(bind(&mut w, A, D, Some(sn(2, ORIG))), illegal);
    // Truncation comes first.
    assert_eq!(bind(&mut w, A, D, None), truncated);
    // Nothing changed.
    assert_eq!(w.k.bound_notification(tcb(B)), None);
    assert_eq!(nt(&w, 2), Notification::IDLE);
    assert_eq!(nqueue(&w, 0), [tcb(C)]);
    // E's buffer is readable, so it can name the capability.
    assert_eq!(bind(&mut w, E, B, Some(sn(2, ORIG))), info(0, 0));
}

#[test]
fn bind_sets_both_links_and_unbind_clears_them() {
    let mut w = world();
    assert_eq!(unbind(&mut w, A, B), info(3, 0), "nothing bound");
    assert_eq!(bind(&mut w, A, B, Some(sn(0, BADGED))), info(0, 0));
    assert_eq!(w.k.bound_notification(tcb(B)), Some(ntfn(0)));
    assert_eq!(nt(&w, 0).bound, Some(tcb(B)));
    assert_eq!(got(&w, A), (0, 0));
    // A thread may bind itself, and F, with no buffer, may unbind.
    w.run(F);
    assert_eq!(unbind(&mut w, F, B), info(0, 0));
    assert_eq!(w.k.bound_notification(tcb(B)), None);
    assert_eq!(nt(&w, 0), Notification::IDLE);
    assert_eq!(bind(&mut w, C, C, Some(sn(0, ORIG))), info(0, 0));
    assert_eq!(nt(&w, 0).bound, Some(tcb(C)));
    assert_eq!(unbind(&mut w, A, B), info(3, 0));
}

#[test]
fn a_bound_thread_receiving_on_an_endpoint_takes_a_pending_signal_first() {
    for number in [5, 8] {
        let mut w = world();
        bind(&mut w, A, B, Some(sn(0, ORIG)));
        // A sender waits on EP0, and B holds a reply to C.
        w.recv(B, S_EP1);
        w.run(C);
        w.call(C, S_EP1, 1, 0, [0; 4]);
        w.send(D, S_EP0, 4, 0, [0; 4]);
        w.run(A);
        w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
        assert_eq!((nt(&w, 0).state, nt(&w, 0).word), (NtfnState::Active, 1));
        w.set_mrs(B, [0xB; 4]);
        assert_eq!(w.syscall(B, number, S_EP0, 0, None), Outcome::Done);
        assert_eq!(w.state(B), ThreadState::Running);
        assert_eq!(got(&w, B), (1, 0));
        assert_eq!(w.mrs(B), [0xB; 4]);
        assert_eq!(nt(&w, 0).state, NtfnState::Idle);
        // The sender still waits, and the receive gave up the reply.
        assert_eq!(w.queue(0), [tcb(D)]);
        assert!(w.caller_slot(B).is_null());
        assert_eq!(w.state(C), ThreadState::BlockedOnReply);
        // With nothing pending, the receive takes the message.
        w.syscall(B, number, S_EP0, 0, None);
        assert_eq!(got(&w, B), (0, info(4, 0)));
    }
}

#[test]
fn a_signal_wakes_a_bound_thread_out_of_an_endpoint_receive() {
    let mut w = world();
    bind(&mut w, A, C, Some(sn(1, ORIG)));
    for t in [B, C, D] {
        w.recv(t, S_EP2);
    }
    assert_eq!(w.queue(2), [tcb(B), tcb(C), tcb(D)]);
    w.run(A);
    w.set_mrs(C, [0xC; 4]);
    w.send(A, sn(1, BADGED), 0, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::Running);
    assert_eq!(got(&w, C), (4, 0));
    assert_eq!(w.mrs(C), [0xC; 4]);
    assert_eq!(w.queue(2), [tcb(B), tcb(D)], "taken out of the middle");
    assert_eq!(
        nt(&w, 1),
        Notification {
            bound: Some(tcb(C)),
            ..Notification::IDLE
        }
    );
    // The last receiver leaving makes the endpoint Idle.
    bind(&mut w, A, D, Some(sn(2, ORIG)));
    w.call(A, S_TCB + B as u64, tcb::label::SUSPEND, 0, [0; 4]);
    w.send(A, sn(2, ORIG), 0, 0, [0; 4]);
    assert_eq!((w.state(D), got(&w, D)), (ThreadState::Running, (0, 0)));
    assert_eq!(w.endpoint(2), Endpoint::IDLE);
}

#[test]
fn a_bound_thread_in_any_other_state_is_not_woken() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    // In a Call, before its message is received and after.
    w.call(B, S_EP1, 1, 0, [0; 4]);
    let call = ThreadState::BlockedOnSend {
        ep: ep(1),
        badge: 0,
        can_grant: true,
        can_grant_reply: true,
        is_call: true,
    };
    assert_eq!(w.state(B), call);
    w.run(A);
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    assert_eq!((w.state(B), nt(&w, 0).state), (call, NtfnState::Active));
    w.run(C);
    w.recv(C, S_EP1);
    assert_eq!(w.state(B), ThreadState::BlockedOnReply);
    w.run(A);
    w.send(A, sn(0, BADGED_W), 0, 0, [0; 4]);
    assert_eq!(w.state(B), ThreadState::BlockedOnReply);
    w.run(C);
    w.reply(C, 0, 0, [0; 4]);
    // Waiting on another notification.
    w.recv(B, sn(1, ORIG));
    w.run(A);
    w.send(A, sn(0, ORIG), 0, 0, [0; 4]);
    assert_eq!(w.state(B), on(1));
    // Stopped.
    w.call(A, S_TCB + B as u64, tcb::label::SUSPEND, 0, [0; 4]);
    w.send(A, sn(0, ORIG), 0, 0, [0; 4]);
    assert_eq!(w.state(B), ThreadState::Inactive);
    assert_eq!(nt(&w, 0).word, 3);
    // The signals wait for its next endpoint receive.
    w.call(A, S_TCB + B as u64, tcb::label::RESUME, 0, [0; 4]);
    w.run(B);
    w.recv(B, S_EP0);
    assert_eq!((w.state(B), got(&w, B)), (ThreadState::Running, (3, 0)));
}

#[test]
fn a_bound_thread_may_wait_on_its_notification_and_no_other_thread_may() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    w.recv(B, sn(0, READ_ONLY));
    assert_eq!(w.state(B), on(0));
    // Another thread waiting or polling takes a capability fault.
    for number in [5, 8] {
        let mut w2 = w.clone_world();
        with_handler(&mut w2, C);
        w2.run(C);
        let ip = w2.regs(C).next_ip;
        w2.syscall(C, number, sn(0, ORIG), 0, None);
        assert_eq!(handler_got(&w2), recv_cap_fault(ip, sn(0, ORIG)));
        assert_eq!(nqueue(&w2, 0), [tcb(B)]);
    }
    w.run(A);
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    assert_eq!((w.state(B), got(&w, B)), (ThreadState::Running, (1, 0)));
    // Unbound again, anyone may wait.
    unbind(&mut w, A, B);
    w.recv(C, sn(0, ORIG));
    assert_eq!(w.state(C), on(0));
}

#[test]
fn binding_delivers_a_pending_signal_to_a_thread_in_an_endpoint_receive() {
    let mut w = world();
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    w.recv(B, S_EP0);
    w.recv(C, S_EP0);
    w.run(A);
    assert_eq!(bind(&mut w, A, B, Some(sn(0, ORIG))), info(0, 0));
    assert_eq!((w.state(B), got(&w, B)), (ThreadState::Running, (1, 0)));
    assert_eq!(w.queue(0), [tcb(C)]);
    assert_eq!(
        nt(&w, 0),
        Notification {
            bound: Some(tcb(B)),
            ..Notification::IDLE
        }
    );
    assert_eq!(got(&w, A), (0, 0));
    // In any other state the signal stays pending.
    w.send(A, sn(1, BADGED), 0, 0, [0; 4]);
    w.run(D);
    w.send(D, S_EP1, 0, 0, [0; 4]);
    w.run(A);
    bind(&mut w, A, D, Some(sn(1, ORIG)));
    assert!(matches!(w.state(D), ThreadState::BlockedOnSend { .. }));
    assert_eq!(nt(&w, 1).state, NtfnState::Active);
}

#[test]
fn a_thread_waiting_on_another_notification_can_be_bound_but_not_to_its_own() {
    let mut w = world();
    w.recv(B, sn(1, ORIG));
    w.run(A);
    assert_eq!(bind(&mut w, A, B, Some(sn(1, ORIG))), info(3, 0));
    assert_eq!(bind(&mut w, A, B, Some(sn(0, ORIG))), info(0, 0));
    assert_eq!(w.state(B), on(1));
    // A signal on its own leaves it waiting there.
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    assert_eq!((w.state(B), nt(&w, 0).state), (on(1), NtfnState::Active));
}

#[test]
fn unbind_changes_nothing_else() {
    let mut w = world();
    // A thread waiting directly on its notification stays queued.
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    w.recv(B, sn(0, ORIG));
    w.run(A);
    unbind(&mut w, A, B);
    assert_eq!((w.state(B), nt(&w, 0)), (on(0), waiting(B, B)));
    // A thread in an endpoint receive stays there, and a pending signal
    // stays pending, delivered to nobody.
    bind(&mut w, A, C, Some(sn(1, ORIG)));
    w.recv(C, S_EP0);
    w.run(A);
    unbind(&mut w, A, C);
    w.send(A, sn(1, BADGED), 0, 0, [0; 4]);
    assert_eq!((w.state(C), nt(&w, 1)), (on_receive(0), active(4)));
}

#[test]
fn suspend_and_resume_keep_a_binding() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    w.recv(B, S_EP0);
    w.run(A);
    w.call(A, S_TCB + B as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.state(B), ThreadState::Inactive);
    assert_eq!(w.k.bound_notification(tcb(B)), Some(ntfn(0)));
    w.call(A, S_TCB + B as u64, tcb::label::RESUME, 0, [0; 4]);
    assert_eq!(w.state(B), ThreadState::Restart);
    assert_eq!(nt(&w, 0).bound, Some(tcb(B)));
}

// ---------------------------------------------------------------------------
// Cancellation and deletion
// ---------------------------------------------------------------------------

#[test]
fn suspend_takes_a_waiter_out_of_the_queue_and_resume_restarts_its_wait() {
    let mut w = world();
    for t in [B, C, D] {
        w.recv(t, sn(0, ORIG));
    }
    w.run(A);
    w.call(A, S_TCB + C as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::Inactive);
    assert_eq!(nqueue(&w, 0), [tcb(B), tcb(D)]);
    w.call(A, S_TCB + C as u64, tcb::label::RESUME, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::Restart);
    // C runs its Recv again, after D.
    w.run(C);
    assert_eq!(w.regs(C).next_ip, w.regs(C).fault_ip);
    w.syscall(C, 5, sn(0, ORIG), 0, None);
    assert_eq!(nqueue(&w, 0), [tcb(B), tcb(D), tcb(C)]);
    for t in [D, B, C] {
        w.call(A, S_TCB + t as u64, tcb::label::SUSPEND, 0, [0; 4]);
    }
    assert_eq!(nt(&w, 0), Notification::IDLE);
}

#[test]
fn deleting_a_notification_restarts_its_waiters_in_order_and_unbinds_it() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    for t in [B, C] {
        w.recv(t, S_EP0);
    }
    for t in [D, E] {
        w.recv(t, sn(1, ORIG));
    }
    w.run(A);
    w.send(A, sn(2, BADGED), 0, 0, [0; 4]);
    assert_eq!(w.ready(), [tcb(F)]);
    // The bound thread in an endpoint receive keeps only its place there.
    delete_ntfn(&mut w, A, 0);
    assert_eq!(w.k.bound_notification(tcb(B)), None);
    assert_eq!(w.state(B), on_receive(0));
    assert_eq!(w.queue(0), [tcb(B), tcb(C)]);
    // The waiters restart in queue order, and the word is discarded.
    delete_ntfn(&mut w, A, 1);
    delete_ntfn(&mut w, A, 2);
    for t in [D, E] {
        assert_eq!(w.state(t), ThreadState::Restart);
        assert_eq!(w.k.ep_links(tcb(t)), (None, None));
    }
    assert_eq!(w.ready(), [F, D, E].map(tcb));
    // Every word is zero again, as retype leaves a new notification.
    for i in 0..NS {
        assert!(w.k.mem.is_zero(ntfn(i).get(), 64), "notification {i}");
    }
    // A restarted Recv on the empty slot is a capability fault; a Send to
    // it does nothing, and a Call gets InvalidCapability.
    w.run(D);
    let out = w.syscall(D, 5, sn(1, ORIG), 0, None);
    assert!(matches!(out, Outcome::Stopped(_)));
    w.run(E);
    w.send(E, sn(1, ORIG), 0, 0, [0; 4]);
    assert_eq!(w.state(E), ThreadState::Running);
    w.call(E, sn(1, ORIG), 0, 0, [0; 4]);
    assert_eq!(w.regs(E).rsi, info(2, 1));
}

#[test]
fn deleting_a_notification_restarts_its_bound_thread_waiting_on_it() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    w.recv(B, sn(0, ORIG));
    w.run(A);
    delete_ntfn(&mut w, A, 0);
    assert_eq!(w.state(B), ThreadState::Restart);
    assert_eq!(w.k.bound_notification(tcb(B)), None);
    assert!(w.k.mem.is_zero(ntfn(0).get(), 64));
}

#[test]
fn only_the_last_capability_finalises_a_notification() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    w.recv(C, sn(1, ORIG));
    w.run(A);
    w.send(A, sn(2, BADGED), 0, 0, [0; 4]);
    for i in 0..NS {
        for v in [READ_ONLY, BADGED_W, BADGED] {
            delete(&mut w, A, sn(i, v));
        }
    }
    assert_eq!(nt(&w, 0).bound, Some(tcb(B)));
    assert_eq!(w.state(C), on(1));
    assert_eq!(nt(&w, 2), active(1 << 4));
}

#[test]
fn deleting_a_bound_tcb_unbinds_its_notification() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    w.recv(B, S_EP0);
    w.run(A);
    w.threads.retain(|t| *t != tcb(B));
    delete(&mut w, A, S_TCB + B as u64);
    assert_eq!(nt(&w, 0), Notification::IDLE);
    assert_eq!(w.endpoint(0), Endpoint::IDLE);
    // The notification can be bound again, and signals reach the new
    // thread only.
    assert_eq!(bind(&mut w, A, C, Some(sn(0, ORIG))), info(0, 0));
    w.recv(C, S_EP0);
    w.run(A);
    w.send(A, sn(0, BADGED), 0, 0, [0; 4]);
    assert_eq!((w.state(C), got(&w, C)), (ThreadState::Running, (1, 0)));
}

#[test]
fn deleting_a_waiting_tcb_takes_it_out_of_the_queue() {
    let mut w = world();
    bind(&mut w, A, C, Some(sn(0, ORIG)));
    w.recv(C, sn(0, ORIG));
    for t in [B, D] {
        w.recv(t, sn(1, ORIG));
    }
    w.run(A);
    for t in [B, C] {
        w.threads.retain(|x| *x != tcb(t));
        delete(&mut w, A, S_TCB + t as u64);
    }
    assert_eq!(nt(&w, 0), Notification::IDLE);
    assert_eq!(nqueue(&w, 1), [tcb(D)]);
    assert_eq!(nt(&w, 1), waiting(D, D));
}

#[test]
fn a_thread_that_deletes_its_own_bound_tcb_leaves_nothing_naming_it() {
    let mut w = world();
    bind(&mut w, A, B, Some(sn(0, ORIG)));
    w.run(B);
    w.threads.retain(|t| *t != tcb(B));
    w.call(B, S_ROOT, CNODE_DELETE, 2, [S_TCB + B as u64, 64, 0, 0]);
    assert_eq!(nt(&w, 0), Notification::IDLE);
    assert_ne!(w.current(), Some(tcb(B)));
    w.check();
}

// ---------------------------------------------------------------------------
// The invariant checker
// ---------------------------------------------------------------------------

/// A test that breaks one invariant: its name and what it does.
type Breakage = (&'static str, fn(&mut World));

fn set_word(w: &mut World, i: usize, offset: u64, value: u64) {
    w.k.set_notification_word(ntfn(i), offset, value);
}

#[test]
fn check_notifications_finds_broken_states() {
    let breakages: [Breakage; 9] = [
        ("Waiting with an empty queue", |w| {
            set_word(w, 0, ntfn_field::STATE, NtfnState::Waiting as u64)
        }),
        ("Idle with a word", |w| set_word(w, 0, ntfn_field::WORD, 1)),
        ("a reserved word", |w| {
            set_word(w, 0, ntfn_field::RESERVED + 16, 1)
        }),
        ("Active with a waiter", |w| {
            w.recv(B, sn(0, ORIG));
            set_word(w, 0, ntfn_field::STATE, NtfnState::Active as u64)
        }),
        ("waiting but not queued", |w| w.k.set_state(tcb(B), on(0))),
        ("bound on one side only", |w| {
            w.k.set_bound_notification(tcb(B), Some(ntfn(0)))
        }),
        ("bound to a thread bound elsewhere", |w| {
            bind(w, A, B, Some(sn(0, ORIG)));
            w.k.set_bound_notification(tcb(B), Some(ntfn(1)));
        }),
        ("another thread waits on a bound notification", |w| {
            w.recv(C, sn(0, ORIG));
            set_word(w, 0, ntfn_field::BOUND_TCB, tcb(B).get());
            w.k.set_bound_notification(tcb(B), Some(ntfn(0)));
        }),
        ("a bound receiver of an Active notification", |w| {
            bind(w, A, B, Some(sn(0, ORIG)));
            w.recv(B, S_EP0);
            set_word(w, 0, ntfn_field::STATE, NtfnState::Active as u64)
        }),
    ];
    for (what, breaks) in breakages {
        let mut w = world();
        breaks(&mut w);
        let found = check_notifications(&w.k, &w.threads, &World::ntfns())
            .and_then(|()| super::super::check(&w.k, &w.threads, &World::eps()));
        assert!(found.is_err(), "{what}");
    }
    // A queue that runs back on itself is a cycle.
    let mut w = world();
    w.recv(B, sn(0, ORIG));
    w.recv(C, sn(0, ORIG));
    w.k.set_ep_next(tcb(C), Some(tcb(B)));
    w.k.set_ep_prev(tcb(B), Some(tcb(C)));
    assert!(check_notifications(&w.k, &w.threads, &World::ntfns()).is_err());
    // `check` alone finds a waiting thread that is not queued too.
    let mut w = world();
    w.k.set_state(tcb(B), on(0));
    assert!(super::super::check(&w.k, &w.threads, &World::eps()).is_err());
}

// ---------------------------------------------------------------------------
// Helpers on the shared world
// ---------------------------------------------------------------------------

trait CloneWorld {
    fn clone_world(&self) -> World;
}

impl CloneWorld for World {
    /// A copy of the world, to try several continuations from one state.
    fn clone_world(&self) -> World {
        World {
            k: self.k.clone(),
            threads: self.threads.clone(),
            prios: self.prios.clone(),
            debug: self.debug,
        }
    }
}

#[test]
fn notification_handles_and_states_decode() {
    assert!(NtfnRef::new(NTFN_BASE + 32).is_none());
    let cap = NotificationCap::from_cap(&ntfn_cap(1, RW, 5)).unwrap();
    assert_eq!(
        (cap.ntfn, cap.badge, cap.can_signal(), cap.can_wait()),
        (ntfn(1), 5, true, true)
    );
    let w_only = NotificationCap::from_cap(&ntfn_cap(1, Rights::WRITE, 0)).unwrap();
    assert_eq!((w_only.can_signal(), w_only.can_wait()), (true, false));
    assert_eq!(NotificationCap::from_cap(&ep_cap(0, RW, 0)), None);
    assert_eq!(NtfnState::from_word(7), NtfnState::Idle);
}
