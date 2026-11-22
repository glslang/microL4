//! Hand-written IPC sequences, one rule each, run against the kernel and
//! the IPC model at once: every step goes through `World::apply`, which
//! compares the two after it, and the tests then check what the
//! specification says the step must have done.

use l4core::error::LookupFailure;
use l4core::regs::Fault;
use l4core::syscall::Outcome;
use l4model::ipc::{Buffer, Info, MCap, NState, State, sysno, word};
use l4model::ipc_harness::{
    Action, BAD_CPTR, Config, NO_BUFFER_THREAD, RO_THREAD, RW, THREADS, World, info, second, slot,
};

fn world() -> World {
    World::new(&Config::default())
}

#[track_caller]
fn step(w: &mut World, a: Action) -> Outcome {
    step_preempted(w, a, &[])
}

#[track_caller]
fn step_preempted(w: &mut World, a: Action, schedule: &[u8]) -> Outcome {
    let out = w.apply(&a, schedule).unwrap_or_else(|e| panic!("{e}"));
    w.clear_events();
    out
}

fn state(w: &World, t: usize) -> State {
    w.m.threads[t].state
}

fn mrs(w: &World, t: usize) -> [u64; 4] {
    let r = w.m.threads[t].regs;
    [r.r10, r.r8, r.r9, r.r15]
}

const EP0: u64 = slot::EP;
const EP1: u64 = slot::EP + 1;
const EP2: u64 = slot::EP + 2;
const EP3: u64 = slot::EP + 3;

fn blocked_send(ep: usize, badge: u64, call: bool) -> State {
    State::BlockedOnSend {
        ep,
        badge,
        grant: true,
        grant_reply: true,
        call,
    }
}

// ---------------------------------------------------------------------------
// Call and reply
// ---------------------------------------------------------------------------

#[test]
fn call_and_reply() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    assert_eq!(state(&w, 1), State::BlockedOnReceive { ep: 0, grant: true });
    step(
        &mut w,
        Action::call(0, slot::EP0_BADGED, 0x123, 3, [10, 11, 12, 13]),
    );
    assert_eq!(state(&w, 0), State::BlockedOnReply);
    // The receiver runs at once: the tie rule.
    assert_eq!(w.m.current, Some(1));
    let r = w.m.threads[1].regs;
    assert_eq!(
        r.rdi, 0x11,
        "the badge of the capability the caller invoked"
    );
    assert_eq!(r.rsi, info(0x123, 3));
    assert_eq!(mrs(&w, 1)[..3], [10, 11, 12]);
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });

    step(&mut w, Action::reply(1, 0x77, 2, [20, 21, 22, 23]));
    assert_eq!(state(&w, 0), State::Running);
    assert_eq!(
        w.m.threads[1].caller,
        MCap::Null,
        "a reply consumes the capability"
    );
    let r = w.m.threads[0].regs;
    assert_eq!((r.rdi, r.rsi), (0, info(0x77, 2)));
    assert_eq!(
        mrs(&w, 0),
        [20, 21, 12, 13],
        "registers past the length keep the caller's"
    );
    // Reply does not switch: the replier goes on.
    assert_eq!(w.m.current, Some(1));
}

#[test]
fn reply_recv_serves_the_next_caller_and_runs_the_last_one() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 1, 1, [100, 0, 0, 0]));
    assert_eq!(w.m.current, Some(1));
    // Thread 2 calls while the server holds thread 0's reply.
    step(&mut w, Action::call(2, EP0, 2, 1, [200, 0, 0, 0]));
    assert_eq!(state(&w, 2), blocked_send(0, 0, true));
    step(&mut w, Action::reply_recv(1, EP0, 0, 1, [101, 0, 0, 0]));
    // Thread 0 has its answer; the server took thread 2's call at once.
    assert_eq!(state(&w, 0), State::Running);
    assert_eq!(mrs(&w, 0)[0], 101);
    assert_eq!(state(&w, 2), State::BlockedOnReply);
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 2, grant: true });
    assert_eq!(mrs(&w, 1)[0], 200);
    // The server still runs, since it did not block.
    assert_eq!(w.m.current, Some(1));
    step(&mut w, Action::reply_recv(1, EP0, 0, 1, [201, 0, 0, 0]));
    assert_eq!(state(&w, 1), State::BlockedOnReceive { ep: 0, grant: true });
    // The server blocked, so the caller it answered runs at once.
    assert_eq!(w.m.current, Some(2));
    assert_eq!(mrs(&w, 2)[0], 201);
}

#[test]
fn a_restarted_reply_recv_is_harmless() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP2));
    step(&mut w, Action::call(0, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::reply_recv(1, EP2, 5, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::Running);
    assert_eq!(state(&w, 1), State::BlockedOnReceive { ep: 2, grant: true });
    // Deleting the endpoint restarts the server's ReplyRecv, whose reply
    // phase now finds an empty caller slot.
    step(&mut w, Action::delete(0, true, EP2));
    assert_eq!(state(&w, 1), State::Restart);
    step(&mut w, Action::again(1));
    // The receive phase faults, since the slot is empty now, and thread 1
    // waits on its fault endpoint.
    assert_eq!(state(&w, 1), blocked_send(3, 0xF1, true).with_grant(false));
    assert_eq!(
        w.m.threads[1].fault,
        Some(Fault::CapFault {
            addr: EP2,
            in_recv_phase: true,
            failure: LookupFailure::MissingCapability { bits_left: 0 }
        })
    );
    assert_eq!(
        state(&w, 0),
        State::Running,
        "the empty reply phase did nothing"
    );
}

#[test]
fn receiving_again_before_replying_gives_up_the_reply() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
    step(&mut w, Action::nbrecv(1, EP1));
    assert_eq!(w.m.threads[1].caller, MCap::Null);
    assert_eq!(state(&w, 0), State::BlockedOnReply, "the caller waits on");
    // Only suspending or resuming it frees it.
    step(&mut w, Action::resume(1, true, 0));
    assert_eq!(state(&w, 0), State::Restart);
}

#[test]
fn a_reply_with_an_empty_caller_slot_does_nothing() {
    let mut w = world();
    let before = w.m.threads[0].regs;
    step(&mut w, Action::reply(0, 1, 1, [9; 4]));
    let after = w.m.threads[0].regs;
    assert_eq!((after.rdi, after.r15), (before.rdi, 9));
    assert_eq!(state(&w, 0), State::Running);
}

#[test]
fn a_call_leaves_its_own_caller_slot_alone() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    // Server 1 calls server 2 while it holds thread 0's reply.
    step(&mut w, Action::recv(2, EP1));
    step(&mut w, Action::call(1, EP1, 0, 0, [0; 4]));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
    assert_eq!(w.m.threads[2].caller, MCap::Reply { to: 1, grant: true });
    step(&mut w, Action::reply(2, 0, 0, [0; 4]));
    step(&mut w, Action::reply(1, 0, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::Running);
}

// ---------------------------------------------------------------------------
// Queues, badges and rights
// ---------------------------------------------------------------------------

#[test]
fn senders_queue_in_order_and_are_served_in_order() {
    let mut w = world();
    step(&mut w, Action::send(0, EP2, 1, 1, [0xA0; 4]));
    step(&mut w, Action::call(1, EP2, 2, 1, [0xA1; 4]));
    step(&mut w, Action::send(2, EP2, 3, 1, [0xA2; 4]));
    assert_eq!(w.m.endpoints[2].queue, [0, 1, 2]);
    for (t, label) in [(0usize, 1u64), (1, 2), (2, 3)] {
        step(&mut w, Action::recv(3, EP2));
        assert_eq!(w.m.threads[3].regs.rsi, info(label, 1));
        assert_eq!(mrs(&w, 3)[0], 0xA0 + t as u64);
    }
    assert_eq!(state(&w, 0), State::Running);
    assert_eq!(state(&w, 1), State::BlockedOnReply);
    assert_eq!(state(&w, 2), State::Running);
    assert!(w.m.endpoints[2].queue.is_empty());
}

#[test]
fn receivers_queue_in_order_too() {
    let mut w = world();
    for t in [1, 2, 3] {
        step(&mut w, Action::recv(t, EP1));
    }
    for (i, t) in [1usize, 2, 3].into_iter().enumerate() {
        step(&mut w, Action::send(0, EP1, i as u64, 0, [0; 4]));
        assert_eq!(state(&w, t), State::Running);
        assert_eq!(w.m.threads[t].regs.rsi, info(i as u64, 0));
    }
}

#[test]
fn the_badge_is_the_senders_and_never_the_receivers() {
    let mut w = world();
    for (cap, badge) in [
        (slot::EP0_BADGED, 0x11),
        (slot::EP0_WGR_BADGED, 0x22),
        (EP0, 0),
        (slot::EP0_W, 0),
    ] {
        // Receiving through a badged capability changes nothing.
        step(&mut w, Action::recv(1, slot::EP0_BADGED));
        step(&mut w, Action::send(0, cap, 0, 0, [0; 4]));
        assert_eq!(w.m.threads[1].regs.rdi, badge);
    }
    // A queued send keeps the badge it started with, even if its
    // capability goes.
    step(&mut w, Action::send(0, slot::EP0_WGR_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::delete(2, true, slot::EP0_WGR_BADGED));
    step(&mut w, Action::recv(1, EP0));
    assert_eq!(w.m.threads[1].regs.rdi, 0x22);
}

#[test]
fn rights_decide_what_a_call_does() {
    let mut w = world();
    // Call without Grant or GrantReply: InvalidCapability, nothing sent.
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, slot::EP0_W, 0, 0, [7; 4]));
    let r = w.m.threads[0].regs;
    assert_eq!((r.rdi, r.rsi, r.r10), (0, info(2, 1), 0));
    assert_eq!(state(&w, 1), State::BlockedOnReceive { ep: 0, grant: true });
    // Send through it is fine.
    step(&mut w, Action::send(0, slot::EP0_W, 4, 0, [7; 4]));
    assert_eq!(state(&w, 1), State::Running);
    // Without Write: Send does nothing, Call is InvalidCapability.
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::send(0, slot::EP0_R, 0, 0, [0; 4]));
    assert!(matches!(state(&w, 1), State::BlockedOnReceive { .. }));
    step(&mut w, Action::call(0, slot::EP0_R, 0, 0, [0; 4]));
    assert_eq!(w.m.threads[0].regs.rsi, info(2, 1));
    // With Write and GrantReply a call leaves a reply capability without
    // Grant when the receiver's capability has none.
    step(&mut w, Action::call(0, slot::EP0_WGR_BADGED, 0, 0, [0; 4]));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
    step(&mut w, Action::reply(1, 0, 0, [0; 4]));
    step(&mut w, Action::recv(2, slot::EP0_R));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    assert_eq!(
        w.m.threads[2].caller,
        MCap::Reply {
            to: 0,
            grant: false
        }
    );
}

#[test]
fn a_reply_capability_has_the_receivers_grant() {
    // The caller queues first, through a capability with Grant; the
    // receiver's has none.
    let mut w = world();
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::recv(1, slot::EP0_R));
    assert_eq!(
        w.m.threads[1].caller,
        MCap::Reply {
            to: 0,
            grant: false
        }
    );
    // The receiver queues first, with Grant; the caller's has none.
    let mut w = world();
    step(&mut w, Action::recv(1, slot::EP0_RG));
    step(&mut w, Action::call(0, slot::EP0_WGR_BADGED, 0, 0, [0; 4]));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
    // And the same with the roles of the two queued the other way.
    let mut w = world();
    step(&mut w, Action::call(0, slot::EP0_WGR_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::recv(1, slot::EP0_RG));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
}

#[test]
fn receiving_needs_read_and_an_endpoint() {
    let mut w = world();
    for cptr in [slot::EP0_W, slot::EMPTY, slot::TCB, slot::UNTYPED] {
        let mut w2 = world();
        // Thread 2 faults to endpoint 0; thread 1 waits there as its
        // handler.
        step(&mut w2, Action::recv(1, EP0));
        step(&mut w2, Action::recv(2, cptr));
        assert_eq!(state(&w2, 2), State::BlockedOnReply);
        let h = w2.m.threads[1].regs;
        assert_eq!(h.rsi, info(1, 5), "a CapFault, length 5");
        assert_eq!(
            mrs(&w2, 1)[1..],
            [cptr, 1, 2],
            "addr, in_recv_phase, MissingCapability"
        );
        assert_eq!(w2.m.threads[1].words[word::MSG + 4], 0, "0 bits left");
    }
    // A CPtr that does not resolve keeps its failure.
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::recv(2, BAD_CPTR));
    assert_eq!(w.m.threads[1].regs.rsi, info(1, 7));
    assert_eq!(
        w.m.threads[2].fault,
        Some(Fault::CapFault {
            addr: BAD_CPTR,
            in_recv_phase: true,
            failure: LookupFailure::GuardMismatch {
                bits_left: 64,
                guard: 0,
                guard_size: 58
            }
        })
    );
}

// ---------------------------------------------------------------------------
// Non-blocking variants and messages
// ---------------------------------------------------------------------------

#[test]
fn nb_variants_fail_quietly() {
    let mut w = world();
    step(&mut w, Action::nbsend(0, EP1, 3, 2, [1, 2, 3, 4]));
    assert_eq!(state(&w, 0), State::Running);
    assert!(w.m.endpoints[1].queue.is_empty(), "the message is dropped");
    let r = w.m.threads[0].regs;
    assert_eq!(
        (r.rdi, r.rsi),
        (EP1, info(3, 2)),
        "NBSend preserves its registers"
    );
    // NBSend never faults, even on a CPtr that does not resolve.
    step(&mut w, Action::nbsend(0, BAD_CPTR, 0, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::Running);
    // NBRecv with nothing pending: rdi and rsi 0, the message registers
    // kept.
    step(
        &mut w,
        Action::Syscall {
            t: 0,
            entry: Some(l4model::ipc_harness::Entry {
                number: 8,
                rdi: EP1,
                rsi: 0x5555,
                mrs: Some([9, 8, 7, 6]),
            }),
            words: Vec::new(),
        },
    );
    let r = w.m.threads[0].regs;
    assert_eq!((r.rdi, r.rsi), (0, 0));
    assert_eq!(mrs(&w, 0), [9, 8, 7, 6]);
    // NBRecv with a sender waiting receives.
    step(&mut w, Action::send(1, EP1, 4, 1, [44; 4]));
    step(&mut w, Action::nbrecv(0, EP1));
    assert_eq!(w.m.threads[0].regs.rsi, info(4, 1));
}

#[test]
fn long_messages_need_both_buffers() {
    let words: Vec<(usize, u64)> = (4..120)
        .map(|i| (word::MSG + i, 0x1000 + i as u64))
        .collect();
    // Thread 0 to thread 1: both have writable buffers, all 120 words.
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(
        &mut w,
        Action::send(0, EP0, 1, 127, [0, 1, 2, 3]).with_words(words.clone()),
    );
    assert_eq!(w.m.threads[1].regs.rsi, info(1, 120), "127 counts as 120");
    assert_eq!(w.m.threads[1].words[word::MSG + 119], 0x1000 + 119);
    // To the thread with a read-only buffer: 4 words.
    step(&mut w, Action::recv(RO_THREAD, EP0));
    step(
        &mut w,
        Action::send(0, EP0, 1, 50, [0; 4]).with_words(words.clone()),
    );
    assert_eq!(w.m.threads[RO_THREAD].regs.rsi, info(1, 4));
    // From the read-only thread: it can be read, so all of it.
    step(&mut w, Action::recv(2, EP0));
    step(
        &mut w,
        Action::send(RO_THREAD, EP0, 1, 9, [0; 4]).with_words(words.clone()),
    );
    assert_eq!(w.m.threads[2].regs.rsi, info(1, 9));
    assert_eq!(w.m.threads[2].words[word::MSG + 8], 0x1008);
    // From the thread without a buffer: 4.
    step(&mut w, Action::recv(2, EP0));
    step(&mut w, Action::send(NO_BUFFER_THREAD, EP0, 1, 9, [0; 4]));
    assert_eq!(w.m.threads[2].regs.rsi, info(1, 4));
    assert_eq!(w.m.threads[NO_BUFFER_THREAD].buffer, Buffer::None);
}

#[test]
fn extra_capabilities_are_looked_up_at_send_time() {
    let mut w = world();
    let bad = [
        (word::CAPS_OR_BADGES, slot::EP0_W),
        (word::CAPS_OR_BADGES + 1, BAD_CPTR),
    ];
    let sent = Info {
        label: 1,
        length: 0,
        extra_caps: 2,
        caps_unwrapped: 0,
    }
    .word();
    step(&mut w, Action::recv(1, EP0));
    // NBSend: silent.
    step(&mut w, Action::sys(2, 4, EP1, sent, None).with_words(bad));
    assert_eq!(state(&w, 2), State::Running);
    // Send: a capability fault on the pointer that failed; thread 2 faults
    // to endpoint 0, where thread 1 waits.
    step(&mut w, Action::sys(2, 3, EP1, sent, None));
    assert_eq!(state(&w, 2), State::BlockedOnReply);
    assert_eq!(mrs(&w, 1)[1..3], [BAD_CPTR, 0]);
    // Pointers that resolve send: the receiver named no receive slot, so
    // the first, which is not to endpoint 1, ends the transfer at once.
    step(&mut w, Action::reply(1, 1, 0, [0; 4]));
    assert_eq!(
        state(&w, 2),
        State::Inactive,
        "a non-zero fault reply stops it"
    );
    step(&mut w, Action::recv(1, EP1));
    step(
        &mut w,
        Action::sys(0, 3, EP1, sent, None)
            .with_words([(word::CAPS_OR_BADGES, EP2), (word::CAPS_OR_BADGES + 1, EP3)]),
    );
    assert_eq!(w.m.threads[1].regs.rsi, info(1, 0));
}

#[test]
fn kernel_objects_answer_with_errors_only_to_a_call() {
    let mut w = world();
    let sys = |t, number, rdi, label, len, mrs: [u64; 4]| {
        Action::sys(t, number, rdi, info(label, len), Some(mrs))
    };
    // Labels outside each object's rows.
    for (cptr, label) in [
        (slot::ROOT, 0x2E),
        (slot::TCB, 0x19),
        (slot::FRAME_RW, 0x54),
        (slot::UNTYPED, 0x02),
        (slot::TCB, 0),
    ] {
        step(&mut w, sys(0, 1, cptr, label, 0, [5; 4]));
        let r = w.m.threads[0].regs;
        assert_eq!(
            (r.rdi, r.rsi, r.r10),
            (0, info(3, 0), 5),
            "IllegalOperation"
        );
    }
    // An empty slot, whatever the label.
    step(&mut w, sys(0, 1, slot::EMPTY, 0x11, 2, [5; 4]));
    assert_eq!((w.m.threads[0].regs.rsi, mrs(&w, 0)[0]), (info(2, 1), 0));
    // CNode_Delete: too short, a bad depth, a slot that does not resolve.
    step(
        &mut w,
        sys(0, 1, slot::ROOT, 0x11, 1, [slot::EP0_W, 64, 0, 0]),
    );
    assert_eq!(w.m.threads[0].regs.rsi, info(7, 0));
    step(
        &mut w,
        sys(0, 1, slot::ROOT, 0x11, 2, [slot::EP0_W, 65, 0, 0]),
    );
    assert_eq!(w.m.threads[0].regs.rsi, info(4, 2));
    assert_eq!(mrs(&w, 0)[..2], [1, 64]);
    step(&mut w, sys(0, 1, slot::ROOT, 0x11, 2, [1 << 40, 64, 0, 0]));
    assert_eq!(w.m.threads[0].regs.rsi, info(6, 5));
    assert_eq!(mrs(&w, 0), [0, 4, 64, 0]);
    assert_eq!(w.m.threads[0].words[word::MSG + 4], 58, "the guard size");
    // Without a writable buffer the detail is cut to four words.
    for t in [RO_THREAD, NO_BUFFER_THREAD] {
        step(&mut w, sys(t, 1, slot::ROOT, 0x11, 2, [1 << 40, 64, 0, 0]));
        assert_eq!(w.m.threads[t].regs.rsi, info(6, 4));
    }
    // Send and NBSend drop every error and leave the registers alone.
    for number in [3, 4] {
        step(&mut w, sys(1, number, slot::ROOT, 0x11, 1, [7; 4]));
        let r = w.m.threads[1].regs;
        assert_eq!((r.rdi, r.rsi, r.r10), (slot::ROOT, info(0x11, 1), 7));
    }
    assert!(matches!(
        w.m.cap((0, slot::EP0_W as usize)),
        MCap::Endpoint {
            ep: 0,
            badge: 0,
            ..
        }
    ));
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

#[test]
fn a_vm_fault_reaches_its_handler_and_a_reply_restarts_it() {
    let mut w = world();
    step(&mut w, Action::recv(2, EP3));
    let ip = w.m.threads[0].regs.next_ip;
    step(
        &mut w,
        Action::Exception {
            t: 0,
            vector: 14,
            error: 0x14,
            cr2: 0xdead_bee8,
        },
    );
    assert_eq!(state(&w, 0), State::BlockedOnReply);
    let h = w.m.threads[2].regs;
    assert_eq!((h.rdi, h.rsi), (0xF0, info(5, 4)));
    assert_eq!(mrs(&w, 2), [ip, 0xdead_bee8, 1, 0x14]);
    step(&mut w, Action::reply(2, 0, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::Restart);
    assert_eq!(w.m.threads[0].fault, None);
    // It faults again, and this time the handler stops it.
    step(&mut w, Action::recv(2, EP3));
    step(
        &mut w,
        Action::Exception {
            t: 0,
            vector: 14,
            error: 4,
            cr2: 8,
        },
    );
    step(&mut w, Action::reply(2, 3, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::Inactive);
}

#[test]
fn a_fault_waits_for_a_handler_and_suspend_cancels_it() {
    let mut w = world();
    step(
        &mut w,
        Action::Exception {
            t: 1,
            vector: 6,
            error: 0,
            cr2: 0,
        },
    );
    assert_eq!(state(&w, 1), blocked_send(3, 0xF1, true).with_grant(false));
    assert!(w.m.threads[1].fault.is_some());
    step(&mut w, Action::suspend(0, true, 1));
    assert_eq!(state(&w, 1), State::Inactive);
    assert_eq!(w.m.threads[1].fault, None, "suspending clears the fault");
    // A handler that comes later finds nothing.
    step(&mut w, Action::nbrecv(2, EP3));
    assert_eq!(w.m.threads[2].regs.rsi, 0);
}

#[test]
fn an_unknown_syscall_reply_sets_registers_sanitised() {
    let mut w = world();
    step(&mut w, Action::recv(3, EP0));
    step(&mut w, Action::sys(2, 42, 0x1D1, 0x51, Some([1, 2, 3, 4])));
    assert_eq!(state(&w, 2), State::BlockedOnReply);
    assert_eq!(w.m.threads[3].regs.rsi, info(2, 19));
    assert_eq!(
        w.m.threads[3].words[word::MSG + 18],
        42,
        "MR18 is the number"
    );
    // The handler replies with 18 words: rax to r15, rip, rsp, rflags; rip
    // and rsp out of range, rflags with TF.
    let words: Vec<(usize, u64)> = (4..18)
        .map(|i| {
            let v = match i {
                15 => 1 << 63,
                16 => 0x0000_8000_0000_0000,
                17 => 0x100 | 0x1,
                _ => 0x100 + i as u64,
            };
            (word::MSG + i, v)
        })
        .collect();
    step(
        &mut w,
        Action::reply(3, 0, 18, [0xA, 0xB, 0xC, 0xD]).with_words(words),
    );
    assert_eq!(state(&w, 2), State::Restart);
    let r = w.m.threads[2].regs;
    assert_eq!((r.rax, r.rbx, r.rcx, r.rdx), (0xA, 0xB, 0xC, 0xD));
    assert_eq!((r.fault_ip, r.next_ip, r.rsp), (0, 0, 0));
    assert_eq!(r.rflags, 0x203);
    assert_eq!(r.exit, l4model::ipc::EXIT_IRET);
}

#[test]
fn a_user_exception_reply_sets_rip_rsp_and_rflags_only() {
    let mut w = world();
    step(&mut w, Action::recv(3, EP3));
    let before = w.m.threads[0].regs;
    step(
        &mut w,
        Action::Exception {
            t: 0,
            vector: 13,
            error: 0x402,
            cr2: 0,
        },
    );
    assert_eq!(w.m.threads[3].regs.rsi, info(3, 5));
    assert_eq!(mrs(&w, 3), [before.next_ip, before.rsp, before.rflags, 13]);
    assert_eq!(w.m.threads[3].words[word::MSG + 4], 0x402);
    // Five words asked, three set; a label 0 restarts at the new rip.
    step(
        &mut w,
        Action::reply(3, 0, 5, [0x50_0000, 0x7000, 0xFFFF, 0xBAD]),
    );
    let r = w.m.threads[0].regs;
    assert_eq!(state(&w, 0), State::Restart);
    assert_eq!((r.fault_ip, r.rsp, r.rflags), (0x50_0000, 0x7000, 0x0ED7));
    assert_eq!((r.rax, r.r15), (before.rax, before.r15));
}

#[test]
fn a_fault_without_a_handler_stops_the_thread() {
    let mut w = world();
    let out = step(
        &mut w,
        Action::Exception {
            t: 3,
            vector: 0,
            error: 0,
            cr2: 0,
        },
    );
    assert!(matches!(out, Outcome::Stopped(_)), "{out:?}");
    assert_eq!(state(&w, 3), State::Inactive);
    assert_eq!(w.m.threads[3].fault, None);
    let out = step(&mut w, Action::sys(4, 0, 0, 0, None));
    let Outcome::Stopped(d) = out else {
        panic!("{out:?}")
    };
    assert_eq!(
        d.handler,
        Fault::CapFault {
            addr: BAD_CPTR,
            in_recv_phase: false,
            failure: LookupFailure::GuardMismatch {
                bits_left: 64,
                guard: 0,
                guard_size: 58
            }
        }
    );
}

#[test]
fn a_fault_handler_with_write_and_grant_only() {
    let mut w = world();
    step(&mut w, Action::recv(0, EP1));
    step(
        &mut w,
        Action::Exception {
            t: NO_BUFFER_THREAD,
            vector: 3,
            error: 0,
            cr2: 0,
        },
    );
    assert_eq!(w.m.threads[0].regs.rdi, 0x55);
    assert_eq!(
        w.m.threads[0].caller,
        MCap::Reply {
            to: NO_BUFFER_THREAD,
            grant: true
        }
    );
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

#[test]
fn suspend_and_resume_cancel_a_blocked_send() {
    let mut w = world();
    step(&mut w, Action::send(0, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::send(1, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::send(2, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::suspend(3, true, 1));
    assert_eq!(w.m.endpoints[2].queue, [0, 2]);
    assert_eq!(state(&w, 1), State::Inactive);
    step(&mut w, Action::resume(3, true, 1));
    assert_eq!(state(&w, 1), State::Restart);
    step(&mut w, Action::again(1));
    assert_eq!(
        w.m.endpoints[2].queue,
        [0, 2, 1],
        "it sends again, at the tail"
    );
}

#[test]
fn suspending_a_caller_deletes_its_reply_capability() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
    step(&mut w, Action::suspend(1, false, 0));
    assert_eq!(w.m.threads[1].caller, MCap::Null);
    assert_eq!(state(&w, 0), State::Inactive);
    // The server's reply now does nothing.
    step(&mut w, Action::reply(1, 0, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::Inactive);
}

#[test]
fn self_suspend_by_call_writes_its_reply_first() {
    let mut w = world();
    step(&mut w, Action::suspend(0, true, 0));
    assert_eq!(state(&w, 0), State::Inactive);
    let r = w.m.threads[0].regs;
    assert_eq!((r.rdi, r.rsi), (0, 0));
    assert_eq!(r.fault_ip, r.next_ip, "Resume continues after the syscall");
    step(&mut w, Action::resume(1, true, 0));
    assert_eq!(state(&w, 0), State::Restart);
}

#[test]
fn deleting_an_endpoint_restarts_every_queued_thread_in_order() {
    let mut w = world();
    step(&mut w, Action::send(0, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::call(1, EP2, 0, 0, [0; 4]));
    step(
        &mut w,
        Action::Exception {
            t: 2,
            vector: 1,
            error: 0,
            cr2: 0,
        },
    );
    // Thread 2's fault went to endpoint 0 instead; queue three senders on
    // endpoint 2.
    step(&mut w, Action::send(3, EP2, 0, 0, [0; 4]));
    assert_eq!(w.m.endpoints[2].queue, [0, 1, 3]);
    step(&mut w, Action::delete(4, true, EP2));
    assert!(w.m.endpoints[2].queue.is_empty());
    for t in [0, 1, 3] {
        assert_eq!(state(&w, t), State::Restart);
    }
    // Woken in queue order, behind thread 5, which was ready before.
    assert_eq!(w.m.queues[&100], [5, 0, 1, 3]);
    // Restarted, the call finds an empty slot.
    step(&mut w, Action::again(1));
    assert_eq!(w.m.threads[1].regs.rsi, info(2, 1));
}

#[test]
fn deleting_a_server_holding_a_reply_leaves_its_caller_waiting() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::recv(3, EP1));
    for schedule in [&[][..], &[0], &[1, 0], &[2, 2, 2]] {
        let mut w = World::new(&Config::default());
        step(&mut w, Action::recv(1, EP0));
        step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
        step(&mut w, Action::recv(3, EP1));
        step_preempted(&mut w, Action::delete(2, true, slot::TCB + 1), schedule);
        assert!(!w.m.threads[1].alive);
        assert_eq!(state(&w, 0), State::BlockedOnReply);
        assert_eq!(w.m.threads[2].regs.rsi, 0, "the deleter's reply");
    }
}

#[test]
fn a_thread_deleting_its_own_tcb_gets_no_reply() {
    for schedule in [&[][..], &[0], &[1], &[0, 0, 0, 0, 0, 0]] {
        let mut w = world();
        step(&mut w, Action::recv(1, EP0));
        step(&mut w, Action::call(2, EP0, 0, 0, [0; 4]));
        // Thread 1 holds thread 2's reply and deletes itself.
        step_preempted(&mut w, Action::delete(1, true, slot::TCB + 1), schedule);
        assert!(!w.m.threads[1].alive);
        assert_eq!(state(&w, 2), State::BlockedOnReply);
        assert_ne!(w.m.current, Some(1));
    }
}

#[test]
fn deleting_a_queued_thread_takes_it_out_of_the_queue() {
    let mut w = world();
    step(&mut w, Action::send(0, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::send(1, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::send(2, EP2, 0, 0, [0; 4]));
    step_preempted(&mut w, Action::delete(3, false, slot::TCB + 1), &[1]);
    assert_eq!(w.m.endpoints[2].queue, [0, 2]);
}

#[test]
fn a_deleted_fault_endpoint_restarts_its_faults_which_then_stop() {
    let mut w = world();
    step(
        &mut w,
        Action::Exception {
            t: 0,
            vector: 6,
            error: 0,
            cr2: 0,
        },
    );
    step(
        &mut w,
        Action::Exception {
            t: 1,
            vector: 6,
            error: 0,
            cr2: 0,
        },
    );
    assert_eq!(w.m.endpoints[3].queue, [0, 1]);
    for s in [slot::EP3_F0, slot::EP3_F1, EP3] {
        step(&mut w, Action::delete(2, true, s));
    }
    // The last capability went: both restart, with their faults cleared.
    assert_eq!(state(&w, 0), State::Restart);
    assert_eq!(w.m.threads[1].fault, None);
    // Re-executing the faulting instruction faults again and finds no
    // endpoint.
    let out = step(
        &mut w,
        Action::Exception {
            t: 0,
            vector: 6,
            error: 0,
            cr2: 0,
        },
    );
    assert!(matches!(out, Outcome::Stopped(_)), "{out:?}");
    assert_eq!(state(&w, 0), State::Inactive);
}

#[test]
fn a_handler_deleted_after_receiving_leaves_the_fault_waiting() {
    let mut w = world();
    step(&mut w, Action::recv(2, EP3));
    step(
        &mut w,
        Action::Exception {
            t: 0,
            vector: 14,
            error: 6,
            cr2: 0x1000,
        },
    );
    assert_eq!(w.m.threads[2].caller, MCap::Reply { to: 0, grant: true });
    step_preempted(&mut w, Action::delete(1, true, slot::TCB + 2), &[3]);
    assert_eq!(state(&w, 0), State::BlockedOnReply);
    assert!(
        w.m.threads[0].fault.is_some(),
        "it still waits for the reply"
    );
    // Resuming it cancels the fault; it re-executes the instruction.
    step(&mut w, Action::resume(1, true, 0));
    assert_eq!(state(&w, 0), State::Restart);
    assert_eq!(w.m.threads[0].fault, None);
}

#[test]
fn deleting_a_saved_reply_capability_leaves_its_caller_waiting() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::save_caller(1, true, slot::FREE));
    step(&mut w, Action::delete(1, true, slot::FREE));
    assert_eq!(w.m.cap((0, slot::FREE as usize)), MCap::Null);
    assert_eq!(state(&w, 0), State::BlockedOnReply);
    step(&mut w, Action::reply(1, 0, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::BlockedOnReply);
}

// ---------------------------------------------------------------------------
// Scheduling
// ---------------------------------------------------------------------------

#[test]
fn a_woken_thread_of_higher_priority_runs_at_once() {
    let cfg = Config {
        prios: [100, 100, 150, 100, 100, 100],
        ..Config::default()
    };
    let mut w = World::new(&cfg);
    assert_eq!(w.m.current, Some(2));
    step(&mut w, Action::recv(2, EP0));
    assert_eq!(w.m.current, Some(0), "the first at the next priority");
    step(&mut w, Action::send(0, EP0, 0, 0, [0; 4]));
    assert_eq!(w.m.current, Some(2));
    // A lower-priority wake-up waits its turn.
    step(&mut w, Action::recv(2, EP1));
    step(&mut w, Action::recv(0, EP0));
    step(&mut w, Action::send(1, EP1, 0, 0, [0; 4]));
    assert_eq!(w.m.current, Some(2));
    step(&mut w, Action::send(2, EP0, 0, 0, [0; 4]));
    assert_eq!(w.m.current, Some(2));
}

#[test]
fn yield_and_tick_rotate_the_queue() {
    let mut w = world();
    step(&mut w, Action::yield_now(0));
    assert_eq!(w.m.current, Some(1));
    step(&mut w, Action::Tick);
    assert_eq!(w.m.current, Some(2));
    step(&mut w, Action::recv(2, EP0));
    assert_eq!(w.m.current, Some(3));
}

#[test]
fn when_every_thread_stops_the_idle_thread_runs() {
    let mut w = world();
    for t in 0..6 {
        step(&mut w, Action::recv(t, EP2));
    }
    assert_eq!(w.m.current, None);
    step(&mut w, Action::Tick);
    step(&mut w, Action::ExternalResume { t: 4 });
    assert_eq!(w.m.current, Some(4));
    assert_eq!(w.m.endpoints[2].queue, [0, 1, 2, 3, 5]);
}

trait WithGrant {
    fn with_grant(self, g: bool) -> State;
}

impl WithGrant for State {
    fn with_grant(self, g: bool) -> State {
        match self {
            State::BlockedOnSend {
                ep,
                badge,
                grant_reply,
                call,
                ..
            } => State::BlockedOnSend {
                ep,
                badge,
                grant: g,
                grant_reply,
                call,
            },
            s => s,
        }
    }
}

// ---------------------------------------------------------------------------
// Notifications: signal, wait and poll
// ---------------------------------------------------------------------------

const N0: u64 = slot::NTFN;
const N1: u64 = slot::NTFN + 1;
const N2: u64 = slot::NTFN + 2;

fn ntfn(w: &World, i: usize) -> (NState, u64, Option<usize>, Vec<usize>) {
    let n = &w.m.ntfns[i];
    (n.state, n.word, n.bound, n.queue.iter().copied().collect())
}

#[test]
fn signals_or_their_badges_and_a_wait_takes_the_word() {
    let mut w = world();
    step(&mut w, Action::send(0, slot::N0_BADGED, 9, 2, [1, 2, 3, 4]));
    assert_eq!(ntfn(&w, 0), (NState::Active, 0x100, None, vec![]));
    step(
        &mut w,
        Action::nbsend(0, slot::N0_W_BADGED, 9, 2, [1, 2, 3, 4]),
    );
    step(&mut w, Action::send(0, slot::N0_BADGED, 9, 2, [1, 2, 3, 4]));
    assert_eq!(ntfn(&w, 0).1, 0x300, "repeated signals coalesce");
    // The waiter's badge plays no part; its message registers stay.
    step(
        &mut w,
        Action::sys(1, 5, slot::N0_R, 0x77, Some([5, 6, 7, 8])),
    );
    let r = w.m.threads[1].regs;
    assert_eq!((r.rdi, r.rsi), (0x300, 0));
    assert_eq!(mrs(&w, 1), [5, 6, 7, 8]);
    assert_eq!(ntfn(&w, 0), (NState::Idle, 0, None, vec![]));
}

#[test]
fn an_unbadged_signal_is_remembered_with_word_0() {
    let mut w = world();
    step(&mut w, Action::send(0, slot::N0_W, 0, 0, [0; 4]));
    assert_eq!(ntfn(&w, 0), (NState::Active, 0, None, vec![]));
    // A poll returns 0, as for nothing pending, but takes the signal: the
    // next wait blocks.
    step(&mut w, Action::nbrecv(1, N0));
    assert_eq!((w.m.threads[1].regs.rdi, w.m.threads[1].regs.rsi), (0, 0));
    assert_eq!(ntfn(&w, 0).0, NState::Idle);
    step(&mut w, Action::recv(1, N0));
    assert_eq!(state(&w, 1), State::BlockedOnNotification { ntfn: 0 });
}

#[test]
fn an_empty_poll_returns_0_in_rdi_and_rsi_whatever_they_held() {
    let mut w = world();
    // Idle, then Waiting: nothing pending either way. The poller's rsi and
    // MR0 to MR3 hold junk on entry; the message registers must stay.
    for waiting in [false, true] {
        if waiting {
            step(&mut w, Action::recv(2, N0));
            assert_eq!(ntfn(&w, 0), (NState::Waiting, 0, None, vec![2]));
        }
        step(
            &mut w,
            Action::sys(1, sysno::NB_RECV, N0, info(0x55, 3), Some([5, 6, 7, 8])),
        );
        let r = w.m.threads[1].regs;
        assert_eq!((r.rdi, r.rsi), (0, 0), "waiters: {waiting}");
        assert_eq!(mrs(&w, 1), [5, 6, 7, 8]);
        assert_eq!(state(&w, 1), State::Running);
    }
    assert_eq!(state(&w, 2), State::BlockedOnNotification { ntfn: 0 });
}

#[test]
fn a_signal_wakes_the_first_waiter_and_waiters_queue_in_order() {
    let mut w = world();
    step(&mut w, Action::recv(1, N1));
    step(&mut w, Action::reply_recv(2, N1, 0, 0, [0; 4]));
    assert_eq!(ntfn(&w, 1), (NState::Waiting, 0, None, vec![1, 2]));
    step(&mut w, Action::send(0, slot::N1_BADGED, 0, 0, [0; 4]));
    assert_eq!(state(&w, 1), State::Running);
    assert_eq!(
        (w.m.threads[1].regs.rdi, w.m.threads[1].regs.rsi),
        (0x800, 0)
    );
    assert_eq!(ntfn(&w, 1), (NState::Waiting, 0, None, vec![2]));
    step(&mut w, Action::send(0, slot::N1_W_BADGED, 0, 0, [0; 4]));
    assert_eq!(w.m.threads[2].regs.rdi, 0x400);
    assert_eq!(ntfn(&w, 1), (NState::Idle, 0, None, vec![]));
}

#[test]
fn signal_and_wait_need_their_rights() {
    let mut w = world();
    // Without Write: Send does nothing, Call is InvalidCapability.
    step(&mut w, Action::send(0, slot::N0_R, 0, 0, [0; 4]));
    assert_eq!(ntfn(&w, 0).0, NState::Idle);
    step(&mut w, Action::call(0, slot::N1_NONE, 0, 0, [7; 4]));
    assert_eq!(w.m.threads[0].regs.rsi, info(2, 1));
    // With Write a Call signals and gets an empty kernel reply, its
    // message registers kept.
    step(&mut w, Action::call(0, slot::N0_BADGED, 3, 4, [7; 4]));
    let r = w.m.threads[0].regs;
    assert_eq!((r.rdi, r.rsi, mrs(&w, 0)), (0, 0, [7; 4]));
    assert_eq!(ntfn(&w, 0), (NState::Active, 0x100, None, vec![]));
    // Waiting without Read is a capability fault: thread 2 faults to
    // endpoint 0, where thread 1 waits.
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::recv(2, slot::N0_W));
    assert_eq!(state(&w, 2), State::BlockedOnReply);
    assert_eq!(w.m.threads[1].regs.rsi, info(1, 5));
    assert_eq!(mrs(&w, 1)[1..], [slot::N0_W, 1, 2]);
}

#[test]
fn waiting_on_a_notification_keeps_the_caller_slot() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::recv(1, N0));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
    step(&mut w, Action::send(2, slot::N0_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::reply(1, 5, 0, [0; 4]));
    assert_eq!(state(&w, 0), State::Running);
    assert_eq!(w.m.threads[0].regs.rsi, info(5, 0));
}

#[test]
fn an_interrupt_signals_like_a_send() {
    let mut w = world();
    step(&mut w, Action::recv(1, N2));
    step(&mut w, Action::Interrupt { n: 2, badge: 0x8 });
    assert_eq!(state(&w, 1), State::Running);
    assert_eq!(w.m.threads[1].regs.rdi, 0x8);
    step(&mut w, Action::Interrupt { n: 2, badge: 0x1 });
    step(&mut w, Action::Interrupt { n: 2, badge: 0x4 });
    step(&mut w, Action::nbrecv(1, N2));
    assert_eq!(w.m.threads[1].regs.rdi, 0x5);
}

// ---------------------------------------------------------------------------
// Binding
// ---------------------------------------------------------------------------

#[test]
fn bind_checks_its_errors_in_order() {
    let mut w = world();
    let bind_with = |t: usize, target: usize, cptr: u64, extra: u64| {
        let rsi = Info {
            label: 0x2B,
            extra_caps: extra,
            ..Info::default()
        }
        .word();
        Action::sys(t, 1, slot::TCB + target as u64, rsi, None)
            .with_words([(word::CAPS_OR_BADGES, cptr)])
    };
    // No extra capability, or a caller without a readable buffer.
    step(&mut w, bind_with(0, 1, N0, 0));
    assert_eq!(w.m.threads[0].regs.rsi, info(7, 0));
    step(&mut w, bind_with(NO_BUFFER_THREAD, 1, N0, 1));
    assert_eq!(w.m.threads[NO_BUFFER_THREAD].regs.rsi, info(7, 0));
    // A thread with only a readable buffer can bind.
    step(&mut w, Action::bind(RO_THREAD, 1, N0));
    assert_eq!(w.m.threads[RO_THREAD].regs.rsi, 0);
    assert_eq!(w.m.threads[1].bound, Some(0));
    // Already bound, even to another notification.
    step(&mut w, Action::bind(0, 1, N1));
    assert_eq!(w.m.threads[0].regs.rsi, info(3, 0));
    // Not a notification, or one without Read.
    for cptr in [EP0, slot::EMPTY, slot::N0_W] {
        step(&mut w, Action::bind(0, 2, cptr));
        assert_eq!(w.m.threads[0].regs.rsi, info(3, 0), "{cptr}");
    }
    // A notification already bound, or with a waiter.
    step(&mut w, Action::bind(0, 2, slot::N0_R));
    assert_eq!(w.m.threads[0].regs.rsi, info(3, 0));
    step(&mut w, Action::recv(3, N1));
    step(&mut w, Action::bind(0, 2, slot::N1_BADGED));
    assert_eq!(w.m.threads[0].regs.rsi, info(3, 0));
    // A thread waiting on another notification can be bound.
    step(&mut w, Action::bind(0, 3, N2));
    assert_eq!(w.m.threads[3].bound, Some(2));
    assert_eq!(w.m.ntfns[2].bound, Some(3));
}

#[test]
fn a_bound_thread_in_an_endpoint_receive_takes_a_signal() {
    let mut w = world();
    step(&mut w, Action::bind(0, 1, N0));
    step(&mut w, Action::recv(1, EP2));
    step(&mut w, Action::send(0, slot::N0_BADGED, 0, 0, [0; 4]));
    assert_eq!(state(&w, 1), State::Running);
    assert_eq!(
        (w.m.threads[1].regs.rdi, w.m.threads[1].regs.rsi),
        (0x100, 0)
    );
    assert!(
        w.m.endpoints[2].queue.is_empty(),
        "it left the endpoint's queue"
    );
    assert_eq!(ntfn(&w, 0), (NState::Idle, 0, Some(1), vec![]));
}

#[test]
fn a_pending_bound_signal_comes_before_a_queued_message() {
    let mut w = world();
    step(&mut w, Action::bind(0, 1, N0));
    // Thread 1 holds a reply, which receiving gives up even now.
    step(&mut w, Action::recv(1, EP1));
    step(&mut w, Action::call(3, EP1, 0, 0, [0; 4]));
    step(&mut w, Action::send(0, slot::N0_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::send(2, EP0, 4, 1, [9; 4]));
    step(&mut w, Action::recv(1, EP0));
    assert_eq!(
        (w.m.threads[1].regs.rdi, w.m.threads[1].regs.rsi),
        (0x100, 0)
    );
    assert_eq!(w.m.endpoints[0].queue, [2], "the sender still waits");
    assert_eq!(w.m.threads[1].caller, MCap::Null);
    assert_eq!(state(&w, 3), State::BlockedOnReply);
    // The next receive gets the message.
    step(&mut w, Action::recv(1, EP0));
    assert_eq!(w.m.threads[1].regs.rsi, info(4, 1));
}

#[test]
fn a_bound_thread_blocked_otherwise_leaves_the_signal_pending() {
    let mut w = world();
    step(&mut w, Action::bind(0, 1, N0));
    step(&mut w, Action::call(1, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::send(0, slot::N0_BADGED, 0, 0, [0; 4]));
    assert_eq!(ntfn(&w, 0), (NState::Active, 0x100, Some(1), vec![]));
    assert!(matches!(state(&w, 1), State::BlockedOnSend { .. }));
    // Waiting on another notification gets nothing from its own.
    step(&mut w, Action::resume(0, true, 1));
    step(&mut w, Action::nbrecv(1, N0));
    step(&mut w, Action::recv(1, N1));
    step(&mut w, Action::send(0, slot::N0_BADGED, 0, 0, [0; 4]));
    assert_eq!(state(&w, 1), State::BlockedOnNotification { ntfn: 1 });
    assert_eq!(ntfn(&w, 0).0, NState::Active);
}

#[test]
fn binding_an_active_notification_delivers_at_once() {
    let mut w = world();
    step(&mut w, Action::send(0, slot::N0_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::recv(1, EP2));
    step(&mut w, Action::bind(0, 1, N0));
    assert_eq!(state(&w, 1), State::Running);
    assert_eq!(w.m.threads[1].regs.rdi, 0x100);
    assert_eq!(ntfn(&w, 0), (NState::Idle, 0, Some(1), vec![]));
    assert!(w.m.endpoints[2].queue.is_empty());
    // In any other state the signal stays pending.
    step(&mut w, Action::send(0, slot::N1_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::bind(0, 2, N1));
    assert_eq!(ntfn(&w, 1), (NState::Active, 0x800, Some(2), vec![]));
}

#[test]
fn only_the_bound_thread_may_wait_on_its_notification() {
    let mut w = world();
    step(&mut w, Action::recv(3, EP0));
    step(&mut w, Action::bind(0, 1, N1));
    // Thread 2 faults to endpoint 0, where thread 3 handles it.
    step(&mut w, Action::recv(2, N1));
    assert_eq!(state(&w, 2), State::BlockedOnReply);
    assert_eq!(mrs(&w, 3)[1..], [N1, 1, 2]);
    step(&mut w, Action::recv(1, N1));
    assert_eq!(ntfn(&w, 1), (NState::Waiting, 0, Some(1), vec![1]));
}

#[test]
fn unbind_clears_the_links_and_nothing_else() {
    let mut w = world();
    step(&mut w, Action::bind(0, 1, N0));
    step(&mut w, Action::recv(1, N0));
    step(&mut w, Action::unbind(0, 1));
    assert_eq!(w.m.threads[1].bound, None);
    assert_eq!(ntfn(&w, 0), (NState::Waiting, 0, None, vec![1]));
    step(&mut w, Action::unbind(0, 1));
    assert_eq!(w.m.threads[0].regs.rsi, info(3, 0));
    // A thread in an endpoint receive stays there.
    step(&mut w, Action::bind(0, 2, N2));
    step(&mut w, Action::recv(2, EP2));
    step(&mut w, Action::unbind(0, 2));
    assert_eq!(state(&w, 2), State::BlockedOnReceive { ep: 2, grant: true });
}

#[test]
fn suspend_and_resume_leave_a_binding_alone() {
    let mut w = world();
    step(&mut w, Action::bind(0, 1, N0));
    step(&mut w, Action::suspend(0, true, 1));
    step(&mut w, Action::resume(0, true, 1));
    assert_eq!(w.m.threads[1].bound, Some(0));
}

#[test]
fn deleting_a_notification_unbinds_it_and_restarts_its_waiters() {
    let mut w = world();
    step(&mut w, Action::bind(0, 3, N2));
    step(&mut w, Action::recv(3, N2));
    step(&mut w, Action::delete(0, true, N2));
    assert_eq!(w.m.threads[3].bound, None);
    assert_eq!(state(&w, 3), State::Restart);
    assert_eq!(ntfn(&w, 2), (NState::Idle, 0, None, vec![]));
    // Restarted, the wait finds an empty slot: thread 3 faults to nothing
    // and stops.
    let out = step(&mut w, Action::again(3));
    assert!(matches!(out, Outcome::Stopped(_)), "{out:?}");
    // Waiters on a notification with other capabilities keep waiting when
    // one goes; the pending word of a deleted one is dropped.
    step(&mut w, Action::recv(1, N1));
    step(&mut w, Action::delete(0, true, slot::N1_NONE));
    assert_eq!(state(&w, 1), State::BlockedOnNotification { ntfn: 1 });
}

#[test]
fn deleting_a_notification_restarts_several_waiters_in_queue_order() {
    let mut w = world();
    for t in [3, 1, 2] {
        step(&mut w, Action::recv(t, N2));
    }
    assert_eq!(ntfn(&w, 2), (NState::Waiting, 0, None, vec![3, 1, 2]));
    step(&mut w, Action::delete(4, true, N2));
    assert_eq!(ntfn(&w, 2), (NState::Idle, 0, None, vec![]));
    for t in [3, 1, 2] {
        assert_eq!(state(&w, t), State::Restart);
    }
    // Made runnable in queue order, behind the threads already ready.
    let woken: Vec<usize> = w.m.queues[&100]
        .iter()
        .copied()
        .filter(|t| [1, 2, 3].contains(t))
        .collect();
    assert_eq!(woken, [3, 1, 2]);
}

#[test]
fn deleting_a_notification_leaves_a_bound_endpoint_receiver_queued() {
    let mut w = world();
    step(&mut w, Action::bind(0, 3, N2));
    step(&mut w, Action::recv(3, EP2));
    step(&mut w, Action::Interrupt { n: 2, badge: 0 });
    // The interrupt woke it; queue it again and delete.
    step(&mut w, Action::recv(3, EP2));
    step(&mut w, Action::delete(0, true, N2));
    assert_eq!(state(&w, 3), State::BlockedOnReceive { ep: 2, grant: true });
    assert_eq!(w.m.threads[3].bound, None);
}

#[test]
fn deleting_a_bound_tcb_unbinds_its_notification() {
    let mut w = world();
    step(&mut w, Action::bind(0, 1, N0));
    step(&mut w, Action::recv(1, N0));
    step_preempted(&mut w, Action::delete(0, true, slot::TCB + 1), &[1, 1]);
    assert!(!w.m.threads[1].alive);
    assert_eq!(ntfn(&w, 0), (NState::Idle, 0, None, vec![]));
    step(&mut w, Action::bind(0, 2, N0));
    assert_eq!(w.m.threads[2].bound, Some(0));
}

// ---------------------------------------------------------------------------
// Capability transfer
// ---------------------------------------------------------------------------

/// A `MessageInfo` naming `extra` capabilities.
fn with_caps(label: u64, len: u64, extra: u64) -> u64 {
    Info {
        label,
        length: len,
        extra_caps: extra,
        caps_unwrapped: 0,
    }
    .word()
}

/// `number` by `t` on `cptr`, naming `caps`.
fn send_caps(t: usize, number: u64, cptr: u64, caps: &[u64]) -> Action {
    let words = caps
        .iter()
        .enumerate()
        .map(|(i, &c)| (word::CAPS_OR_BADGES + i, c));
    Action::sys(
        t,
        number,
        cptr,
        with_caps(1, 0, caps.len() as u64),
        Some([0; 4]),
    )
    .with_words(words)
}

/// The receive-slot words: `cnode`, `index`, `depth`.
fn receive_slot(cnode: u64, index: u64, depth: u64) -> [(usize, u64); 3] {
    [
        (word::RECEIVE_CNODE, cnode),
        (word::RECEIVE_INDEX, index),
        (word::RECEIVE_DEPTH, depth),
    ]
}

/// `Recv` by `t` on `cptr` into root slot `index`.
fn recv_into(t: usize, cptr: u64, index: u64) -> Action {
    Action::recv(t, cptr).with_words(receive_slot(slot::ROOT, index, 64))
}

const FREE: u64 = slot::FREE;

fn root(w: &World, s: u64) -> MCap {
    w.m.cap((0, s as usize))
}

#[test]
fn a_capability_moves_with_grant_into_the_receive_slot() {
    let mut w = world();
    step(&mut w, recv_into(1, EP0, FREE));
    step(&mut w, send_caps(0, 3, EP0, &[slot::N0_BADGED]));
    assert_eq!(w.m.threads[1].regs.rsi, with_caps(1, 0, 1));
    assert_eq!(
        root(&w, FREE),
        MCap::Notification {
            ntfn: 0,
            badge: 0x100,
            rights: l4core::cap::Rights(3)
        },
        "rights and badge kept"
    );
    // A copy counts: deleting the original no longer finalises.
    step(&mut w, recv_into(1, EP0, FREE + 1));
    step(&mut w, send_caps(0, 3, EP0, &[slot::TCB + 2]));
    step(&mut w, Action::delete(0, true, slot::TCB + 2));
    assert!(w.m.threads[2].alive);
}

#[test]
fn without_grant_or_buffers_nothing_moves() {
    for (sender, cap, receiver) in [
        (0, slot::EP0_W, 1),
        (0, slot::EP0_WGR_BADGED, 1),
        (NO_BUFFER_THREAD, EP0, 1),
        (0, EP0, RO_THREAD),
    ] {
        let mut w = world();
        step(&mut w, recv_into(receiver, EP0, FREE));
        step(&mut w, send_caps(sender, 3, cap, &[N0]));
        let info = Info::decode(w.m.threads[receiver].regs.rsi);
        assert_eq!(
            (info.extra_caps, info.caps_unwrapped),
            (0, 0),
            "{cap} to {receiver}"
        );
        assert_eq!(root(&w, FREE), MCap::Null);
    }
}

#[test]
fn capabilities_to_the_receiving_endpoint_unwrap_to_badges() {
    let mut w = world();
    step(&mut w, recv_into(1, EP0, FREE));
    // Its own badge, 0, and through a capability without rights to send.
    step(
        &mut w,
        send_caps(
            0,
            3,
            slot::EP0_BADGED,
            &[slot::EP0_WGR_BADGED, slot::EP0_R, N0],
        ),
    );
    let info = Info::decode(w.m.threads[1].regs.rsi);
    assert_eq!((info.extra_caps, info.caps_unwrapped), (3, 0b011));
    let words = w.m.threads[1].words;
    assert_eq!(
        words[word::CAPS_OR_BADGES..word::CAPS_OR_BADGES + 2],
        [0x22, 0]
    );
    assert!(matches!(root(&w, FREE), MCap::Notification { ntfn: 0, .. }));
    // An endpoint capability to another endpoint is copied, not unwrapped.
    step(&mut w, recv_into(1, EP0, FREE + 1));
    step(&mut w, send_caps(0, 3, EP0, &[EP1]));
    assert_eq!(Info::decode(w.m.threads[1].regs.rsi).caps_unwrapped, 0);
    assert!(matches!(root(&w, FREE + 1), MCap::Endpoint { ep: 1, .. }));
}

#[test]
fn the_first_capability_that_cannot_move_ends_the_transfer() {
    let processed = |w: &World| Info::decode(w.m.threads[1].regs.rsi).extra_caps;
    // A second copy needs the used slot; a later unwrap is not reached.
    let mut w = world();
    step(&mut w, recv_into(1, EP0, FREE));
    step(&mut w, send_caps(0, 3, EP0, &[N0, N1, slot::EP0_BADGED]));
    assert_eq!(processed(&w), 1);
    // An empty slot, a saved reply capability, or no receive slot.
    step(&mut w, recv_into(1, EP0, FREE + 1));
    step(
        &mut w,
        send_caps(0, 3, EP0, &[slot::EP0_BADGED, slot::EMPTY, N0]),
    );
    assert_eq!(
        processed(&w),
        1,
        "the unwrap counts, the empty slot ends it"
    );
    for words in [
        receive_slot(slot::ROOT, FREE, 64),
        receive_slot(slot::EMPTY, FREE + 2, 64),
        receive_slot(slot::TCB, FREE + 2, 64),
        receive_slot(slot::ROOT, FREE + 2, 0),
        receive_slot(slot::ROOT, FREE + 2, 6),
        receive_slot(slot::ROOT, FREE + 2, 65),
        receive_slot(slot::ROOT, 1 << 40, 64),
    ] {
        step(&mut w, Action::recv(1, EP0).with_words(words));
        step(&mut w, send_caps(0, 3, EP0, &[N2, slot::EP0_BADGED]));
        assert_eq!(processed(&w), 0, "{words:?}");
    }
    assert_eq!(root(&w, FREE + 2), MCap::Null);
    // A saved reply capability cannot be copied.
    step(&mut w, recv_into(2, EP1, FREE + 3));
    step(&mut w, Action::call(3, EP1, 0, 0, [0; 4]));
    step(&mut w, Action::save_caller(2, true, FREE + 4));
    step(&mut w, recv_into(1, EP0, FREE + 5));
    step(&mut w, send_caps(2, 3, EP0, &[FREE + 4]));
    assert_eq!(processed(&w), 0);
    assert!(matches!(root(&w, FREE + 4), MCap::Reply { to: 3, .. }));
}

#[test]
fn a_failed_relookup_moves_nothing_and_a_changed_pointer_moves_the_new_one() {
    let mut w = world();
    // Thread 0 queues with two good pointers; another thread breaks the
    // second before thread 1 receives.
    step(&mut w, send_caps(0, 3, EP2, &[N0, EP1]));
    step(
        &mut w,
        Action::WriteBuffer {
            t: 0,
            words: vec![(word::CAPS_OR_BADGES + 1, BAD_CPTR)],
        },
    );
    step(&mut w, recv_into(1, EP2, FREE));
    assert_eq!(Info::decode(w.m.threads[1].regs.rsi).extra_caps, 0);
    assert_eq!(root(&w, FREE), MCap::Null, "not even the first moves");
    // The pointers are looked up again at transfer: a changed one moves.
    step(&mut w, send_caps(0, 3, EP2, &[N0]));
    step(
        &mut w,
        Action::WriteBuffer {
            t: 0,
            words: vec![(word::CAPS_OR_BADGES, N1)],
        },
    );
    step(&mut w, recv_into(1, EP2, FREE));
    assert!(matches!(root(&w, FREE), MCap::Notification { ntfn: 1, .. }));
    // A capability deleted while its sender waits ends the transfer.
    step(&mut w, send_caps(0, 3, EP2, &[slot::N0_W, N0]));
    step(&mut w, Action::delete(2, true, slot::N0_W));
    step(&mut w, recv_into(1, EP2, FREE + 1));
    assert_eq!(Info::decode(w.m.threads[1].regs.rsi).extra_caps, 0);
}

#[test]
fn a_queued_senders_grant_is_the_one_it_sent_with() {
    let mut w = world();
    step(&mut w, send_caps(0, 3, slot::EP1_WG_BADGED, &[N0]));
    step(&mut w, recv_into(1, slot::EP1_RW, FREE));
    assert_eq!(Info::decode(w.m.threads[1].regs.rsi).extra_caps, 1);
    step(&mut w, send_caps(0, 3, slot::EP1_RW, &[N0]));
    step(&mut w, recv_into(1, slot::EP1_BADGED, FREE + 1));
    assert_eq!(Info::decode(w.m.threads[1].regs.rsi).extra_caps, 0);
}

#[test]
fn replies_carry_capabilities_through_the_reply_capabilitys_grant() {
    let mut w = world();
    // The server received with Grant: its reply moves a capability, and an
    // endpoint capability is copied, never unwrapped.
    step(&mut w, Action::recv(1, EP0));
    step(
        &mut w,
        Action::call(0, EP0, 0, 0, [0; 4]).with_words(receive_slot(slot::ROOT, FREE, 64)),
    );
    step(&mut w, send_caps(1, 6, 0, &[EP0]));
    assert_eq!(w.m.threads[0].regs.rsi, with_caps(1, 0, 1));
    assert!(matches!(root(&w, FREE), MCap::Endpoint { ep: 0, .. }));
    // Without Grant on the receive capability, nothing.
    step(&mut w, Action::recv(1, slot::EP0_R));
    step(
        &mut w,
        Action::call(0, EP0, 0, 0, [0; 4]).with_words(receive_slot(slot::ROOT, FREE + 1, 64)),
    );
    step(&mut w, send_caps(1, 2, EP1, &[N0]));
    assert_eq!(Info::decode(w.m.threads[0].regs.rsi).extra_caps, 0);
    assert_eq!(root(&w, FREE + 1), MCap::Null);
    // A reply's pointer that does not resolve is no fault. Thread 1 now
    // waits on endpoint 1, from its ReplyRecv.
    step(
        &mut w,
        Action::call(0, EP1, 0, 0, [0; 4]).with_words(receive_slot(slot::ROOT, FREE + 1, 64)),
    );
    step(&mut w, send_caps(1, 6, 0, &[BAD_CPTR]));
    assert_eq!(state(&w, 1), State::Running);
    assert_eq!(Info::decode(w.m.threads[0].regs.rsi).extra_caps, 0);
}

#[test]
fn signals_and_fault_messages_move_no_capabilities() {
    let mut w = world();
    step(&mut w, recv_into(1, N0, FREE));
    step(&mut w, send_caps(0, 3, slot::N0_BADGED, &[EP0]));
    assert_eq!((w.m.threads[1].regs.rsi, root(&w, FREE)), (0, MCap::Null));
    // A failed send-time lookup still faults for a signal.
    step(&mut w, recv_into(3, EP3, FREE));
    step(&mut w, send_caps(0, 3, slot::N0_BADGED, &[BAD_CPTR]));
    assert_eq!(state(&w, 0), State::BlockedOnReply);
    assert_eq!(Info::decode(w.m.threads[3].regs.rsi).extra_caps, 0);
    assert_eq!(root(&w, FREE), MCap::Null);
}

// ---------------------------------------------------------------------------
// Two CSpaces
// ---------------------------------------------------------------------------

/// A world where thread 3's CSpace root is the second CNode, whose slot `n`
/// holds another capability than the root's, or none.
fn two_cspaces() -> World {
    let mut second_cspace = [false; THREADS];
    second_cspace[3] = true;
    World::new(&Config {
        second_cspace,
        ..Config::default()
    })
}

fn in_second(w: &World, s: u64) -> MCap {
    w.m.cap((1, s as usize))
}

#[test]
fn each_side_of_a_transfer_names_capabilities_in_its_own_cspace() {
    let mut w = two_cspaces();
    // Thread 3's receive slot is its slot 16; the root's slot 16 holds
    // thread 0's TCB capability, and its slot 28, which thread 0 sends,
    // is empty in the second CNode.
    step(&mut w, recv_into(3, second::EP0, second::FREE));
    step(&mut w, send_caps(0, 3, EP0, &[slot::N0_BADGED]));
    assert_eq!(Info::decode(w.m.threads[3].regs.rsi).extra_caps, 1);
    let n0 = MCap::Notification {
        ntfn: 0,
        badge: 0x100,
        rights: RW,
    };
    assert_eq!(in_second(&w, second::FREE), n0);
    assert_eq!(root(&w, second::FREE), MCap::Tcb(0));
    // Back the other way: thread 3's slot 7 is endpoint 0 with badge 0x11,
    // which unwraps, and its slot 12 notification 1 with badge 0x800; the
    // root's are endpoint 0 with Write only and endpoint 1.
    step(&mut w, recv_into(0, EP0, FREE));
    step(
        &mut w,
        send_caps(3, 3, second::EP0, &[second::EP0_BADGED, second::N1_BADGED]),
    );
    let info = Info::decode(w.m.threads[0].regs.rsi);
    assert_eq!((info.extra_caps, info.caps_unwrapped), (2, 0b01));
    assert_eq!(w.m.threads[0].words[word::CAPS_OR_BADGES], 0x11);
    let n1 = MCap::Notification {
        ntfn: 1,
        badge: 0x800,
        rights: RW,
    };
    assert_eq!(root(&w, FREE), n1);
    // A receive slot in another CNode, through the copy of the root
    // CNode's capability in thread 3's slot 15; the root's slot 15 is an
    // endpoint.
    step(
        &mut w,
        Action::recv(3, second::EP0).with_words(receive_slot(second::ROOT_CNODE, FREE + 1, 64)),
    );
    step(&mut w, send_caps(0, 3, EP0, &[N1]));
    assert!(matches!(
        root(&w, FREE + 1),
        MCap::Notification { ntfn: 1, .. }
    ));
    assert_eq!(in_second(&w, FREE + 1), MCap::Null);
}

#[test]
fn a_fault_endpoint_and_cnode_invocations_resolve_in_the_threads_own_cspace() {
    let mut w = two_cspaces();
    // Thread 3's fault endpoint `CPtr` is 0, empty in both CNodes: the
    // fault finds no handler. Then its slot 2, endpoint 1, which is
    // endpoint 0 in the root.
    let fault = Action::Exception {
        t: 3,
        vector: 6,
        error: 0,
        cr2: 0,
    };
    assert!(matches!(step(&mut w, fault.clone()), Outcome::Stopped(_)));
    let mut second_cspace = [false; THREADS];
    second_cspace[3] = true;
    let mut fault_eps = Config::default().fault_eps;
    fault_eps[3] = second::EP1;
    let mut w = World::new(&Config {
        fault_eps,
        second_cspace,
        ..Config::default()
    });
    step(&mut w, fault);
    assert_eq!(w.m.endpoints[1].queue, [3]);
    assert_eq!(w.m.endpoints[0].queue, []);
    // `CNode_Delete` through `CPtr` 1 deletes in thread 3's own CNode.
    let mut w = two_cspaces();
    step(&mut w, Action::delete(3, true, second::N0_W_BADGED));
    assert_eq!(w.m.threads[3].regs.rsi, 0);
    assert_eq!(in_second(&w, second::N0_W_BADGED), MCap::Null);
    assert!(matches!(
        root(&w, second::N0_W_BADGED),
        MCap::Endpoint { ep: 3, .. }
    ));
    // So does `CNode_SaveCaller`, into thread 3's slot 20.
    step(&mut w, Action::recv(3, second::EP2));
    step(&mut w, Action::call(0, EP2, 0, 0, [0; 4]));
    step(&mut w, Action::save_caller(3, true, 20));
    assert_eq!(in_second(&w, 20), MCap::Reply { to: 0, grant: true });
    assert_eq!(root(&w, 20), MCap::Tcb(4));
}

// ---------------------------------------------------------------------------
// CNode_SaveCaller
// ---------------------------------------------------------------------------

#[test]
fn save_caller_checks_its_errors_in_order() {
    let mut w = world();
    let save = |t: usize, len: u64, index: u64, depth: u64| {
        Action::sys(
            t,
            1,
            slot::ROOT,
            info(0x18, len),
            Some([index, depth, 0, 0]),
        )
    };
    step(&mut w, save(1, 1, FREE, 64));
    assert_eq!(w.m.threads[1].regs.rsi, info(7, 0));
    step(&mut w, save(1, 2, FREE, 65));
    assert_eq!(w.m.threads[1].regs.rsi, info(4, 2));
    step(&mut w, save(1, 2, 1 << 40, 64));
    assert_eq!(Info::decode(w.m.threads[1].regs.rsi).label, 6);
    // A full destination comes before an empty caller slot.
    step(&mut w, save(1, 2, EP0, 64));
    assert_eq!(w.m.threads[1].regs.rsi, info(8, 0));
    step(&mut w, save(1, 2, FREE, 64));
    assert_eq!(w.m.threads[1].regs.rsi, info(3, 0));
    // With a reply to save it moves, and the caller slot empties.
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, save(1, 2, FREE, 64));
    assert_eq!(w.m.threads[1].regs.rsi, 0);
    assert_eq!(root(&w, FREE), MCap::Reply { to: 0, grant: true });
    assert_eq!(w.m.threads[1].caller, MCap::Null);
}

#[test]
fn a_saved_reply_survives_receiving_and_answers_by_send_or_call() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::save_caller(1, true, FREE));
    // Serve another client meanwhile.
    step(&mut w, Action::call(2, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::recv(1, EP0));
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 2, grant: true });
    assert_eq!(root(&w, FREE), MCap::Reply { to: 0, grant: true });
    step(&mut w, Action::send(1, FREE, 0x44, 1, [0xAB; 4]));
    assert_eq!(state(&w, 0), State::Running);
    assert_eq!(
        (w.m.threads[0].regs.rsi, mrs(&w, 0)[0]),
        (info(0x44, 1), 0xAB)
    );
    assert_eq!(root(&w, FREE), MCap::Null, "consumed when used");
    // By Call: the reply, then an empty kernel reply to the server.
    step(&mut w, Action::save_caller(1, true, FREE));
    step(&mut w, Action::call(1, FREE, 0x45, 0, [0; 4]));
    assert_eq!(state(&w, 2), State::Running);
    assert_eq!(w.m.threads[2].regs.rsi, info(0x45, 0));
    assert_eq!((w.m.threads[1].regs.rdi, w.m.threads[1].regs.rsi), (0, 0));
    // Receiving on a reply capability is a capability fault.
    step(&mut w, Action::recv(3, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::save_caller(3, true, FREE));
    step(&mut w, Action::recv(2, FREE));
    assert!(matches!(state(&w, 2), State::BlockedOnSend { .. }));
}

#[test]
fn a_saved_reply_goes_when_its_caller_is_suspended_and_survives_its_holder() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::save_caller(1, true, FREE));
    step(&mut w, Action::delete(2, true, slot::TCB + 1));
    assert_eq!(root(&w, FREE), MCap::Reply { to: 0, grant: true });
    step(&mut w, Action::suspend(2, true, 0));
    assert_eq!(root(&w, FREE), MCap::Null);
    assert_eq!(state(&w, 0), State::Inactive);
}

// ---------------------------------------------------------------------------
// CNode_CancelBadgedSends
// ---------------------------------------------------------------------------

#[test]
fn cancel_badged_sends_releases_that_badge_in_order() {
    let mut w = world();
    step(&mut w, Action::send(0, slot::EP0_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::call(1, slot::EP0_WGR_11, 0, 0, [0; 4]));
    step(&mut w, Action::send(2, slot::EP0_WGR_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::send(3, EP0, 0, 0, [0; 4]));
    step(&mut w, Action::send(5, slot::EP0_BADGED, 0, 0, [0; 4]));
    assert_eq!(w.m.endpoints[0].queue, [0, 1, 2, 3, 5]);
    step(
        &mut w,
        Action::cancel_badged_sends(4, true, slot::EP0_BADGED),
    );
    assert_eq!(w.m.threads[4].regs.rsi, 0);
    assert_eq!(w.m.endpoints[0].queue, [2, 3], "the rest keep their order");
    for t in [0, 1, 5] {
        assert_eq!(state(&w, t), State::Restart);
    }
    assert_eq!(w.m.queues[&100], [0, 1, 5], "released in queue order");
}

#[test]
fn cancel_badged_sends_needs_all_rights_and_does_nothing_for_badge_0() {
    let mut w = world();
    step(&mut w, Action::send(0, slot::EP0_WGR_BADGED, 0, 0, [0; 4]));
    step(&mut w, Action::send(1, EP0, 0, 0, [0; 4]));
    for (s, rsi) in [
        (slot::EP0_WGR_BADGED, info(3, 0)),
        (slot::EP0_WGR_11, info(3, 0)),
        (slot::N0_BADGED, info(3, 0)),
        (slot::EMPTY, info(3, 0)),
        (EP0, 0),
    ] {
        step(&mut w, Action::cancel_badged_sends(2, true, s));
        assert_eq!(w.m.threads[2].regs.rsi, rsi, "slot {s}");
    }
    assert_eq!(w.m.endpoints[0].queue, [0, 1]);
    // A receive queue is left alone.
    step(&mut w, Action::recv(3, EP1));
    step(
        &mut w,
        Action::cancel_badged_sends(2, true, slot::EP1_BADGED),
    );
    assert_eq!(w.m.endpoints[1].queue, [3]);
}

#[test]
fn a_received_call_keeps_waiting_for_its_reply() {
    let mut w = world();
    step(&mut w, Action::recv(1, EP0));
    step(&mut w, Action::call(0, slot::EP0_WGR_11, 0, 0, [0; 4]));
    step(
        &mut w,
        Action::cancel_badged_sends(1, true, slot::EP0_BADGED),
    );
    assert_eq!(state(&w, 0), State::BlockedOnReply);
    assert_eq!(w.m.threads[1].caller, MCap::Reply { to: 0, grant: true });
}
