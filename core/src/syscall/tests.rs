//! Host tests of the dispatch: system-call numbers, capability lookups and
//! their faults or silent drops, kernel invocations with their replies and
//! errors, extra capabilities, preemption and restart, and the calls that
//! stop or delete their own caller. They share the world of
//! `crate::ipc`'s tests.

use std::vec::Vec;

use super::*;
use crate::cap::{CapType, Rights, TCB_SLOTS};
use crate::error::LookupFailure;
use crate::invoke::label;
use crate::ipc::tests::*;
use crate::regs::Fault;
use crate::tcb::Tcbs;

/// A `MessageInfo` with extra capabilities.
fn info_caps(label: u64, extra: u64, length: u64) -> u64 {
    MessageInfo::new(label, 0, extra, length).word()
}

/// D waits on EP1 as A's fault handler.
fn with_handler(w: &mut World) {
    w.set_fault_ep(A, S_EP1);
    w.recv(D, S_EP1);
}

/// The message D, the handler, received: label and words.
fn handler_got(w: &World) -> (u64, Vec<u64>) {
    let m = MessageInfo::from_word(w.regs(D).rsi);
    let words = (0..m.length() as usize).map(|i| w.mr(D, i)).collect();
    (m.label(), words)
}

// ---------------------------------------------------------------------------
// System-call numbers
// ---------------------------------------------------------------------------

#[test]
fn a_number_that_names_no_system_call_is_an_unknown_syscall_fault() {
    let numbers = [
        (0, true),
        (9, true),
        (15, true),
        (19, true),
        (31, true),
        (32, true),
        (1 << 32 | 1, true),
        (u64::MAX, true),
        (16, false),
        (17, false),
        (18, false),
    ];
    for (number, debug) in cases(&numbers) {
        let mut w = World::new();
        w.debug = debug;
        with_handler(&mut w);
        let ip = w.regs(A).next_ip;
        assert_eq!(w.syscall(A, number, 0, 0, None), Outcome::Done);
        let (label, words) = handler_got(&w);
        assert_eq!(label, 2, "rdx {number:#x}");
        assert_eq!(words.len(), 19);
        assert_eq!((words[15], words[18]), (ip, number));
        assert_eq!(w.k.fault(tcb(A)), Some(Fault::UnknownSyscall { number }));
    }
}

#[test]
fn an_unknown_syscall_without_a_handler_stops_the_thread() {
    let mut w = World::new();
    let out = w.syscall(A, 0, 0, 0, None);
    assert_eq!(
        out,
        Outcome::Stopped(DoubleFault {
            thread: tcb(A),
            fault: Fault::UnknownSyscall { number: 0 },
            handler: Fault::CapFault {
                addr: 0,
                in_recv_phase: false,
                failure: LookupFailure::MissingCapability { bits_left: 0 }
            }
        })
    );
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert_ne!(w.current(), Some(tcb(A)));
}

#[test]
fn debug_system_calls_go_back_to_the_kernel() {
    let mut w = World::new();
    let before = w.regs(A);
    assert_eq!(
        w.syscall(A, 16, 0x1_0141, 0x55, None),
        Outcome::Debug(DebugCall::PutChar(0x41))
    );
    assert_eq!(
        w.syscall(A, 17, 3, 0, None),
        Outcome::Debug(DebugCall::Halt(3))
    );
    assert_eq!(
        w.syscall(A, 18, 0, 0, None),
        Outcome::Debug(DebugCall::DumpScheduler)
    );
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!(w.current(), Some(tcb(A)));
    assert_eq!(w.mrs(A), [before.r10, before.r8, before.r9, before.r15]);
}

#[test]
fn yield_goes_to_the_tail() {
    let mut w = World::new();
    assert_eq!(w.syscall(A, 7, 0, 0, None), Outcome::Done);
    assert_eq!(w.current(), Some(tcb(B)));
    assert_eq!(*w.ready().last().unwrap(), tcb(A));
    assert_eq!(w.state(A), ThreadState::Running);
}

#[test]
fn invoked_by_call_reads_the_current_threads_rdx() {
    let mut w = World::new();
    assert!(!invoked_by_call(&w.k));
    let mut regs = w.regs(A);
    regs.rdx = 1;
    w.k.set_regs(tcb(A), &regs);
    assert!(invoked_by_call(&w.k));
    regs.rdx = 3;
    w.k.set_regs(tcb(A), &regs);
    assert!(!invoked_by_call(&w.k));
    regs.rdx = 1;
    w.k.set_regs(tcb(A), &regs);
    w.k.sched.set_current(None);
    assert!(!invoked_by_call(&w.k));
}

// ---------------------------------------------------------------------------
// Lookups
// ---------------------------------------------------------------------------

#[test]
fn a_pointer_that_does_not_resolve_faults_except_for_nbsend() {
    for number in [1, 3] {
        let mut w = World::new();
        with_handler(&mut w);
        let ip = w.regs(A).next_ip;
        w.syscall(A, number, BAD_CPTR, info(0, 0), None);
        assert_eq!(
            handler_got(&w),
            (1, std::vec![ip, BAD_CPTR, 0, 4, 64, 0, 59])
        );
    }
    let mut w = World::new();
    with_handler(&mut w);
    let before = w.regs(A);
    assert_eq!(w.syscall(A, 4, BAD_CPTR, info(1, 1), None), Outcome::Done);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!(w.k.fault(tcb(A)), None);
    assert!(matches!(w.state(D), ThreadState::BlockedOnReceive { .. }));
    assert_eq!(w.regs(A).r10, before.r10);
}

#[test]
fn an_empty_slot_is_invalid_for_call_and_nothing_for_send() {
    let mut w = World::new();
    w.call(A, S_FREE, 1, 1, [5, 6, 7, 8]);
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (0, info(2, 1)));
    assert_eq!(w.mrs(A), [0, 6, 7, 8]);
    for number in [3, 4] {
        w.syscall(A, number, S_FREE, info(1, 1), Some([5, 6, 7, 8]));
        assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (S_FREE, info(1, 1)));
        assert_eq!(w.mrs(A), [5, 6, 7, 8]);
        assert_eq!(w.state(A), ThreadState::Running);
    }
}

#[test]
fn a_receive_on_anything_but_a_readable_endpoint_is_a_cap_fault() {
    let ntfn = Cap::new(CapType::Notification, 0x1900, 6, RW, false, 0);
    let zombie = Cap::zombie(CNODE2, 9, 3, false);
    let mut all = Vec::new();
    for (cap, rdi) in [
        (None, S_FREE),
        (None, S_EP0_W),
        (None, S_TCB + B as u64),
        (Some(ntfn), S_FREE),
        (Some(zombie), S_FREE),
    ] {
        for number in [5, 8] {
            all.push((cap, rdi, number));
        }
    }
    for (cap, rdi, number) in cases(&all) {
        let mut w = World::new();
        if let Some(cap) = cap {
            crate::cdt::insert_root(&mut w.k, rs(S_FREE), cap);
        }
        with_handler(&mut w);
        let ip = w.regs(A).next_ip;
        w.syscall(A, number, rdi, 0, None);
        assert_eq!(
            handler_got(&w),
            (1, std::vec![ip, rdi, 1, 2, 0]),
            "{cap:?} {number}"
        );
    }
}

// ---------------------------------------------------------------------------
// Kernel invocations
// ---------------------------------------------------------------------------

#[test]
fn a_call_gets_the_kernels_reply_with_words_from_the_buffer_and_extra_caps() {
    let mut w = World::new();
    // CNode_Copy: MR4 (rights) is in the buffer, and extra capability 0
    // (the source root) in caps_or_badges.
    w.set_buf(A, word::MSG + 4, Rights::ALL.0 as u64);
    w.set_buf(A, word::CAPS_OR_BADGES, S_ROOT);
    let mrs = [S_FREE, 64, S_EP1, 64];
    let out = w.syscall(A, 1, S_ROOT, info_caps(label::CNODE_COPY, 1, 5), Some(mrs));
    assert_eq!(out, Outcome::Done);
    assert_eq!(w.cap(rs(S_FREE)), ep_cap(1, Rights::ALL, 0));
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (0, info(0, 0)));
    assert_eq!(w.mrs(A), mrs, "no result words");
}

#[test]
fn retype_reads_its_last_two_arguments_from_the_buffer() {
    let mut w = World::new();
    w.set_buf(A, word::MSG + 4, S_FREE);
    w.set_buf(A, word::MSG + 5, 1);
    w.set_buf(A, word::CAPS_OR_BADGES, S_ROOT);
    let out = w.syscall(
        A,
        1,
        S_UNTYPED,
        info_caps(label::UNTYPED_RETYPE, 1, 6),
        Some([2, 0, 0, 0]),
    );
    assert_eq!(out, Outcome::Done);
    assert_eq!(w.regs(A).rsi, info(0, 0));
    let made = w.cap(rs(S_FREE));
    assert_eq!(made.cap_type(), CapType::Endpoint);
    assert_eq!(made.object(), UNTYPED);
    // Without a buffer the message stops at MR3 and has no extra
    // capability.
    w.run(F);
    w.syscall(
        F,
        1,
        S_UNTYPED,
        info_caps(label::UNTYPED_RETYPE, 1, 6),
        Some([2, 0, 0, 0]),
    );
    assert_eq!(w.regs(F).rsi, info(7, 0), "TruncatedMessage");
}

#[test]
fn error_replies_carry_their_detail_words_as_far_as_the_buffer_allows() {
    // FailedLookup has five words: MR4 needs a writable buffer.
    for (t, length) in [(A, 5), (E, 4), (F, 4)] {
        let mut w = World::new();
        w.run(t);
        w.call(t, S_ROOT, label::CNODE_DELETE, 2, [BAD_CPTR, 64, 0, 0]);
        assert_eq!(
            (w.regs(t).rdi, w.regs(t).rsi),
            (0, info(6, length)),
            "thread {t}"
        );
        assert_eq!(w.mrs(t), [0, 4, 64, 0]);
        if t == A {
            assert_eq!(w.mr(A, 4), 59);
        }
    }
    let mut w = World::new();
    w.call(A, S_ROOT, label::CNODE_DELETE, 1, [S_FREE, 64, 0, 0]);
    assert_eq!(w.regs(A).rsi, info(7, 0), "TruncatedMessage");
    w.call(A, S_UNTYPED, 0x50, 0, [0; 4]);
    assert_eq!(w.regs(A).rsi, info(3, 0), "IllegalOperation");
    // A Zombie is an invalid capability, and so, until M6, a notification
    // takes no invocation.
    crate::cdt::insert_root(&mut w.k, rs(S_FREE), Cap::zombie(CNODE2, 9, 3, false));
    w.call(A, S_FREE, 0, 0, [9; 4]);
    assert_eq!((w.regs(A).rsi, w.mrs(A)[0]), (info(2, 1), 0));
    let ntfn = Cap::new(CapType::Notification, 0x1900, 6, RW, false, 0);
    crate::cdt::insert_root(&mut w.k, rs(S_FREE + 1), ntfn);
    w.call(A, S_FREE + 1, 0, 0, [0; 4]);
    assert_eq!(w.regs(A).rsi, info(3, 0));
    w.syscall(A, 3, S_FREE + 1, info(0, 0), None);
    assert_eq!(w.regs(A).rsi, info(0, 0));
}

#[test]
fn send_performs_the_invocation_and_drops_the_reply() {
    let mut w = World::new();
    w.set_buf(A, word::MSG + 4, Rights::ALL.0 as u64);
    w.set_buf(A, word::CAPS_OR_BADGES, S_ROOT);
    let rsi = info_caps(label::CNODE_COPY, 1, 5);
    let mrs = [S_FREE, 64, S_EP1, 64];
    for number in [3, 4] {
        w.syscall(A, number, S_ROOT, rsi, Some(mrs));
        assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (S_ROOT, rsi));
        assert_eq!(w.mrs(A), mrs);
    }
    // The first copied; the second failed with DeleteFirst, unreported.
    assert_eq!(w.cap(rs(S_FREE)), ep_cap(1, Rights::ALL, 0));
    // ReadRegisters by Send writes no results either.
    w.syscall(A, 3, S_TCB + B as u64, info(0x20, 2), Some([0, 20, 7, 7]));
    assert_eq!(w.mrs(A), [0, 20, 7, 7]);
}

#[test]
fn an_extra_capability_that_does_not_resolve_faults_and_nothing_is_done() {
    for (i, number) in [(0, 1), (1, 1), (0, 3)] {
        let mut w = World::new();
        with_handler(&mut w);
        w.set_buf(A, word::MSG + 4, Rights::ALL.0 as u64);
        w.set_buf(A, word::CAPS_OR_BADGES, S_ROOT);
        w.set_buf(A, word::CAPS_OR_BADGES + i, BAD_CPTR);
        let ip = w.regs(A).next_ip;
        let rsi = info_caps(label::CNODE_COPY, 2, 5);
        w.syscall(A, number, S_ROOT, rsi, Some([S_FREE, 64, S_EP1, 64]));
        assert_eq!(
            handler_got(&w),
            (1, std::vec![ip, BAD_CPTR, 0, 4, 64, 0, 59])
        );
        assert!(w.cap(rs(S_FREE)).is_null());
    }
    let mut w = World::new();
    w.set_buf(A, word::CAPS_OR_BADGES, BAD_CPTR);
    let rsi = info_caps(label::CNODE_COPY, 1, 5);
    assert_eq!(
        w.syscall(A, 4, S_ROOT, rsi, Some([S_FREE, 64, S_EP1, 64])),
        Outcome::Done
    );
    assert_eq!(w.state(A), ThreadState::Running);
    assert!(w.cap(rs(S_FREE)).is_null());
    // Without a readable buffer no extra capability is looked up or sent.
    w.run(F);
    let rsi = info_caps(label::CNODE_MOVE, 1, 4);
    w.syscall(F, 1, S_ROOT, rsi, Some([S_FREE, 64, S_EP1, 64]));
    assert_eq!(w.regs(F).rsi, info(7, 0), "TruncatedMessage");
}

#[test]
fn read_registers_returns_as_many_words_as_the_caller_can_take() {
    let mut w = World::new();
    w.call(A, S_TCB + B as u64, 0x20, 2, [0, 20, 0, 0]);
    let b = w.regs(B);
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (0, info(0, 20)));
    assert_eq!(w.mrs(A), [b.next_ip, b.rsp, b.rflags, b.rax]);
    assert_eq!(w.mr(A, 19), b.gs_base);
    w.run(F);
    w.call(F, S_TCB + B as u64, 0x20, 2, [0, 20, 0, 0]);
    assert_eq!(w.regs(F).rsi, info(0, 4));
}

// ---------------------------------------------------------------------------
// Preemption, and calls that stop their caller
// ---------------------------------------------------------------------------

#[test]
fn a_preempted_invocation_restarts_its_syscall_and_finishes() {
    let mut w = World::new();
    w.k.preempt_in = Some(0);
    let rsi = info(label::CNODE_REVOKE, 2);
    let mrs = [S_EP0, 64, 0x33, 0x44];
    assert_eq!(w.enter(A, 1, S_ROOT, rsi, Some(mrs)), Outcome::Preempted);
    assert_eq!(w.state(A), ThreadState::Restart);
    // One child went; the call's registers are untouched.
    assert!(w.cap(rs(S_EP0_R)).is_null());
    assert!(!w.cap(rs(S_EP0_WGR)).is_null());
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi, w.mrs(A)), (S_ROOT, rsi, mrs));
    // The kernel takes the interrupt, then the thread runs its syscall
    // again.
    let ip = w.regs(A).fault_ip;
    assert_eq!(w.exit(), Some(tcb(A)));
    assert_eq!(w.regs(A).next_ip, ip);
    assert_eq!(w.syscall(A, 1, S_ROOT, rsi, None), Outcome::Done);
    assert_eq!(w.regs(A).fault_ip, ip);
    assert_eq!(w.regs(A).rsi, info(0, 0));
    for s in [S_EP0_BADGED, S_EP0_W, S_EP0_WGR, S_EP0_R] {
        assert!(w.cap(rs(s)).is_null());
    }
}

#[test]
fn a_thread_that_suspends_itself_by_call_resumes_after_its_syscall() {
    let mut w = World::new();
    w.call(A, S_TCB + A as u64, crate::tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (0, 0));
    let after = w.regs(A).next_ip;
    w.call(B, S_TCB + A as u64, crate::tcb::label::RESUME, 0, [0; 4]);
    w.run(A);
    assert_eq!(w.regs(A).next_ip, after);
}

#[test]
fn a_thread_that_deletes_its_own_tcb_gets_no_reply() {
    let mut w = World::new();
    w.threads.retain(|t| *t != tcb(A));
    let rsi = info(label::CNODE_DELETE, 2);
    assert_eq!(
        w.syscall(A, 1, S_ROOT, rsi, Some([S_TCB, 64, 0, 0])),
        Outcome::Done
    );
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert_eq!(w.regs(A).rsi, rsi, "no reply");
    assert_ne!(w.current(), Some(tcb(A)));
    for s in 0..TCB_SLOTS {
        assert!(w.cap(tcb(A).slot(s)).is_null());
    }
}

#[test]
fn a_self_delete_preempted_mid_zombie_is_never_restarted() {
    // A deletes its own TCB's last capability: finalisation stops it, and a
    // preemption point after the Zombie clears its first slot cuts the call
    // short. It stays stopped and unqueued: a call that finalises its own
    // caller is never restarted (`docs/design.md`, "Kernel execution
    // model").
    let mut w = World::new();
    w.threads.retain(|t| *t != tcb(A));
    w.k.preempt_in = Some(0);
    let rsi = info(label::CNODE_DELETE, 2);
    assert_eq!(
        w.enter(A, 1, S_ROOT, rsi, Some([S_TCB, 64, 0, 0])),
        Outcome::Preempted
    );
    assert_eq!(w.state(A), ThreadState::Inactive);
    let zombie = w.cap(rs(S_TCB));
    assert_eq!(zombie.cap_type(), CapType::Zombie);
    assert!(zombie.zombie_slots() < TCB_SLOTS);
    assert!(
        !w.cap(tcb(A).slot(0)).is_null(),
        "the deletion was cut short"
    );
    assert_eq!(w.regs(A).rsi, rsi, "no reply");
    let next = w.exit();
    assert_ne!(next, Some(tcb(A)));
    assert!(!w.ready().contains(&tcb(A)));
    // Another thread's Delete of the Zombie finishes the work.
    let b = next.unwrap();
    assert_eq!(b, tcb(B));
    w.call(B, S_ROOT, label::CNODE_DELETE, 2, [S_TCB, 64, 0, 0]);
    assert_eq!(w.regs(B).rsi, info(0, 0));
    assert!(w.cap(rs(S_TCB)).is_null());
    for s in 0..TCB_SLOTS {
        assert!(w.cap(tcb(A).slot(s)).is_null());
    }
    assert_eq!(w.state(A), ThreadState::Inactive);
}

#[test]
fn reply_recv_delivers_its_reply_before_a_receive_phase_fault() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    let out = w.reply_recv(B, BAD_CPTR, 4, 1, [44, 0, 0, 0]);
    assert!(matches!(out, Outcome::Stopped(DoubleFault { thread, .. }) if thread == tcb(B)));
    assert_eq!((w.state(A), w.mrs(A)[0]), (ThreadState::Running, 44));
    assert_eq!(w.state(B), ThreadState::Inactive);
}

#[test]
fn a_fault_handler_can_be_any_thread_receiving_on_the_endpoint() {
    // The handler learns the faulting thread only from its badge; a reply
    // through the reply capability reaches the right thread.
    let mut w = World::new();
    w.set_fault_ep(A, S_EP0_BADGED);
    w.set_fault_ep(B, S_EP0);
    w.exception(A, 14, 6, 0x1000);
    w.exception(B, 14, 6, 0x2000);
    w.recv(C, S_EP0);
    assert_eq!((w.regs(C).rdi, w.mrs(C)[1]), (BADGE, 0x1000));
    w.reply(C, 0, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Restart);
    w.recv(C, S_EP0);
    assert_eq!((w.regs(C).rdi, w.mrs(C)[1]), (0, 0x2000));
    w.reply(C, 1, 0, [0; 4]);
    assert_eq!(w.state(B), ThreadState::Inactive);
}
