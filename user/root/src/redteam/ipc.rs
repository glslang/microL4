//! `test=redteam-ipc`, the M6 red team's ring-3 attack on reply
//! capabilities and bound notifications (`docs/redteam/`): every thread
//! shares the root task's CSpace and VSpace, and the root task, at 255,
//! orchestrates threads below it and checks what each saw through statics.
//!
//! - **A stale saved reply.** Server S receives client C's `Call`, moves the
//!   reply capability into slot X with `CNode_SaveCaller`, saves again into
//!   X (`DeleteFirst`) and into empty slot Y (`IllegalOperation`: the
//!   caller slot is empty), and replies with the empty caller slot
//!   (nothing). The root task suspends and resumes C, so
//!   C's IPC is cancelled and its `Call` restarts: X must be empty, and a
//!   `Send` on X must reach nobody, though C is queued on the endpoint
//!   again. S then serves C's new `Call`, saves its reply into X and sends
//!   on X twice: C gets the first reply and only it.
//! - **A bound thread deleted mid-receive.** B, bound to notification N,
//!   waits on endpoint E3 and is woken by a signal with its badge. A second
//!   bind of N, or of B, fails. The root task deletes B's TCB while B waits
//!   on E3 bound to N, then signals N: N must be unbound and `Active`, so
//!   the root task may poll it, and a new thread B2 may be bound to it and
//!   woken by the next signal. Deleting N's capabilities while B2 waits on
//!   E3 leaves B2 queued, unbound: a message on E3 reaches it (after a
//!   `CNode_CancelBadgedSends` of badge 0, and of a badge on a queue of
//!   receivers, which must change nothing), and B2 can be bound again.

use core::sync::atomic::{AtomicU64, Ordering};

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::invoke::{
    Slot, cnode_cancel_badged_sends, cnode_delete, cnode_mint, cnode_move, cnode_save_caller,
    tcb_bind_notification, tcb_resume, tcb_set_priority, tcb_suspend,
};
use libsys::notification::{poll, signal};
use libsys::{
    BootInfo, CPtr, Error, Ipc, LookupFailure, Message, MessageInfo, ObjectAlloc, ObjectType,
    Rights, SyscallError, call, println, recv, reply, send,
};

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// The threads' priorities, below the root task's 255.
const SERVER_PRIORITY: u64 = 200;
const CLIENT_PRIORITY: u64 = 150;

/// What S does when the root task sends it MR0 on its control endpoint.
const SERVE: u64 = 1;
const SEND_ON_X: u64 = 2;

/// The bound notification's signalling badge.
const NTFN_BADGE: u64 = 0x10;
/// The badge of a capability to E3 with all rights, for the cancel.
const E3_BADGE: u64 = 0x33;

/// What the threads saw, for the root task to check.
static C_REPLIES: AtomicU64 = AtomicU64::new(0);
static C_LAST: AtomicU64 = AtomicU64::new(0);
static S_SERVED: AtomicU64 = AtomicU64::new(0);
/// 0 for success, else the error code plus 1; `u64::MAX` before.
static S_SAVE1: AtomicU64 = AtomicU64::new(u64::MAX);
static S_SAVE2: AtomicU64 = AtomicU64::new(u64::MAX);
static S_SAVE3: AtomicU64 = AtomicU64::new(u64::MAX);
static B_COUNT: AtomicU64 = AtomicU64::new(0);
static B_BADGE: AtomicU64 = AtomicU64::new(u64::MAX);
static B_RSI: AtomicU64 = AtomicU64::new(u64::MAX);

fn msg(label: u64, mr0: u64, mr1: u64) -> Message {
    Message::new(MessageInfo::new(label, 0, 0, 2), [mr0, mr1, 0, 0])
}

fn code(r: Result<(), Error>) -> u64 {
    match r {
        Ok(()) => 0,
        Err(e) => e.kernel().map_or(u64::MAX - 1, |k| k.code() + 1),
    }
}

/// Whether root slot `n` holds a capability, without changing it (as
/// `test=captransfer` probes): `CNode_Move` of a slot onto itself.
fn occupied(ipc: Ipc, n: CPtr) -> bool {
    let slot = Slot::root_cnode(n);
    let empty = SyscallError::FailedLookup {
        source: true,
        failure: LookupFailure::MissingCapability { bits_left: 0 },
    };
    match cnode_move(ipc, slot, slot) {
        Err(e) if e.kernel() == Some(SyscallError::DeleteFirst) => true,
        Err(e) if e.kernel() == Some(empty) => false,
        other => fail!("redteam: ipc: probing slot {n}: {other:?}"),
    }
}

fn start(ipc: Ipc, t: &Thread, priority: u64, what: &str) {
    spawn::prepare(ipc, t)
        .and_then(|()| tcb_set_priority(ipc, t.tcb, CAP_INIT_TCB, priority))
        .and_then(|()| tcb_resume(t.tcb))
        .unwrap_or_else(|e| fail!("redteam: ipc: starting {what}: {e}"));
}

fn expect(what: &str, got: u64, want: u64) {
    if got != want {
        fail!("redteam: ipc: {what}: {got:#x}, not {want:#x}");
    }
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let mut retype = |ty, count, what| {
        objects
            .retype(ipc, ty, 0, count)
            .unwrap_or_else(|e| fail!("redteam: ipc: retyping {what}: {e}"))
    };
    let eps = retype(ObjectType::Endpoint, 3, "E, the control endpoint and E3");
    let (ep, ctl, e3) = (eps, eps + 1, eps + 2);
    let ntfns = retype(ObjectType::Notification, 2, "N and N2");
    let (n, n2) = (ntfns, ntfns + 1);
    let tcbs = retype(ObjectType::Tcb, 5, "S, C, B, B2 and B3");
    let (s, c, b, b2, b3) = (tcbs, tcbs + 1, tcbs + 2, tcbs + 3, tcbs + 4);
    let mine = objects
        .slots
        .alloc(4)
        .unwrap_or_else(|| fail!("redteam: ipc: no free slots"));
    let (x, n_badged, e3_badged, y) = (mine, mine + 1, mine + 2, mine + 3);
    cnode_mint(
        ipc,
        Slot::root_cnode(n_badged),
        Slot::root_cnode(n),
        Rights::ALL,
        NTFN_BADGE,
    )
    .and_then(|()| {
        cnode_mint(
            ipc,
            Slot::root_cnode(e3_badged),
            Slot::root_cnode(e3),
            Rights::ALL,
            E3_BADGE,
        )
    })
    .unwrap_or_else(|e| fail!("redteam: ipc: minting: {e}"));

    // ---- A stale saved reply ------------------------------------------
    let server = Thread {
        tcb: s,
        fault_ep: 0,
        stack: STACKS[0],
        entry: server,
        args: [ep, ctl, x, y],
    };
    let client = Thread {
        tcb: c,
        fault_ep: 0,
        stack: STACKS[1],
        entry: client,
        args: [ep, 0, 0, 0],
    };
    start(ipc, &server, SERVER_PRIORITY, "S");
    start(ipc, &client, CLIENT_PRIORITY, "C");
    spawn::let_others_run(ipc);
    // C is queued on E; S waits for a command.
    send(ctl, &msg(0, SERVE, 0));
    spawn::let_others_run(ipc);
    expect("S served", S_SERVED.load(Ordering::SeqCst), 1);
    expect("S's first SaveCaller", S_SAVE1.load(Ordering::SeqCst), 0);
    expect(
        "S's second SaveCaller, into X (DeleteFirst + 1)",
        S_SAVE2.load(Ordering::SeqCst),
        SyscallError::DeleteFirst.code() + 1,
    );
    expect(
        "S's third SaveCaller, into Y (IllegalOperation + 1)",
        S_SAVE3.load(Ordering::SeqCst),
        SyscallError::IllegalOperation.code() + 1,
    );
    if occupied(ipc, y) {
        fail!("redteam: ipc: Y holds a capability after a failed CNode_SaveCaller");
    }
    expect(
        "C's replies after S's empty Reply",
        C_REPLIES.load(Ordering::SeqCst),
        0,
    );
    if !occupied(ipc, x) {
        fail!("redteam: ipc: X is empty after CNode_SaveCaller");
    }
    println!(
        "redteam: ipc: S saved C's reply capability into slot {x}; saving again failed, an empty Reply did nothing"
    );

    // Cancel C's IPC: the saved reply capability must go with it.
    tcb_suspend(c)
        .and_then(|()| tcb_resume(c))
        .unwrap_or_else(|e| fail!("redteam: ipc: suspending and resuming C: {e}"));
    if occupied(ipc, x) {
        fail!("redteam: ipc: the saved reply capability outlived C's Call");
    }
    spawn::let_others_run(ipc);
    send(ctl, &msg(0, SEND_ON_X, 0xBAD1));
    spawn::let_others_run(ipc);
    expect(
        "C's replies after a Send on the emptied X",
        C_REPLIES.load(Ordering::SeqCst),
        0,
    );
    println!(
        "redteam: ipc: suspend and resume of C deleted the saved reply capability; a Send on X reached nobody"
    );

    // Serve C's restarted Call and reply through X twice.
    send(ctl, &msg(0, SERVE, 0));
    spawn::let_others_run(ipc);
    expect("S served", S_SERVED.load(Ordering::SeqCst), 2);
    send(ctl, &msg(0, SEND_ON_X, 0x600D));
    spawn::let_others_run(ipc);
    send(ctl, &msg(0, SEND_ON_X, 0xBAD2));
    spawn::let_others_run(ipc);
    expect("C's replies", C_REPLIES.load(Ordering::SeqCst), 1);
    expect("C's reply", C_LAST.load(Ordering::SeqCst), 0x600D);
    if occupied(ipc, x) {
        fail!("redteam: ipc: X still holds a reply capability after it was used");
    }
    println!(
        "redteam: ipc: two Sends on a saved reply capability: C got the first (0x600d) and only it"
    );

    // ---- A bound thread deleted mid-receive ---------------------------
    let bound = |tcb, stack| Thread {
        tcb,
        fault_ep: 0,
        stack,
        entry: bound_receiver,
        args: [e3, 0, 0, 0],
    };
    tcb_bind_notification(ipc, b, n).unwrap_or_else(|e| fail!("redteam: ipc: binding B: {e}"));
    start(ipc, &bound(b, STACKS[2]), CLIENT_PRIORITY, "B");
    spawn::let_others_run(ipc);
    signal(n_badged);
    spawn::let_others_run(ipc);
    expect("B's wake-ups", B_COUNT.load(Ordering::SeqCst), 1);
    expect("B's rdi", B_BADGE.load(Ordering::SeqCst), NTFN_BADGE);
    expect("B's rsi", B_RSI.load(Ordering::SeqCst), 0);
    let illegal = SyscallError::IllegalOperation.code() + 1;
    expect(
        "binding N, bound to B, to B3",
        code(tcb_bind_notification(ipc, b3, n)),
        illegal,
    );
    expect(
        "binding N2 to B, bound to N",
        code(tcb_bind_notification(ipc, b, n2)),
        illegal,
    );
    println!(
        "redteam: ipc: B, bound to N and waiting on E3, woke with N's badge; N and B cannot be bound twice"
    );

    // B waits on E3 again, bound. Delete its only TCB capability.
    cnode_delete(Slot::root_cnode(b))
        .unwrap_or_else(|e| fail!("redteam: ipc: deleting B's TCB: {e}"));
    signal(n_badged);
    // N must be unbound now, or this poll is a capability fault that
    // stops the root task.
    expect("polling N after B's deletion", poll(n), NTFN_BADGE);
    tcb_bind_notification(ipc, b2, n)
        .unwrap_or_else(|e| fail!("redteam: ipc: binding B2 to N after B's deletion: {e}"));
    start(ipc, &bound(b2, STACKS[3]), CLIENT_PRIORITY, "B2");
    spawn::let_others_run(ipc);
    signal(n_badged);
    spawn::let_others_run(ipc);
    expect("B and B2's wake-ups", B_COUNT.load(Ordering::SeqCst), 2);
    expect("B2's rdi", B_BADGE.load(Ordering::SeqCst), NTFN_BADGE);
    println!(
        "redteam: ipc: B's deletion unbound N; N was Active for a poll, then bound to B2, which its signal woke"
    );

    // Delete N's capabilities while B2 waits on E3: B2 stays queued.
    cnode_delete(Slot::root_cnode(n_badged))
        .and_then(|()| cnode_delete(Slot::root_cnode(n)))
        .unwrap_or_else(|e| fail!("redteam: ipc: deleting N: {e}"));
    // Neither cancel touches a queue of receivers.
    cnode_cancel_badged_sends(Slot::root_cnode(e3))
        .and_then(|()| cnode_cancel_badged_sends(Slot::root_cnode(e3_badged)))
        .unwrap_or_else(|e| fail!("redteam: ipc: CNode_CancelBadgedSends on E3: {e}"));
    send(e3_badged, &msg(0x5, 0x77, 0));
    spawn::let_others_run(ipc);
    expect("B2's messages", B_COUNT.load(Ordering::SeqCst), 3);
    expect(
        "B2's badge from E3",
        B_BADGE.load(Ordering::SeqCst),
        E3_BADGE,
    );
    tcb_bind_notification(ipc, b2, n2)
        .unwrap_or_else(|e| fail!("redteam: ipc: binding B2 again after N's deletion: {e}"));
    println!(
        "redteam: ipc: deleting N left B2 queued on E3, unbound: E3's message reached it, and it bound to N2"
    );

    println!("redteam: ipc: every reply and binding attack held");
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// S: on `SERVE`, receives one `Call` on E, saves its reply capability
/// into X, then into X and Y again, and replies with the empty caller
/// slot; on `SEND_ON_X`, sends MR1 through X.
extern "C" fn server(ep: CPtr, ctl: CPtr, x: CPtr, y: CPtr) -> ! {
    loop {
        let cmd = recv(ctl);
        match cmd.msg.mr[0] {
            SERVE => {
                let _ = recv(ep);
                S_SERVED.fetch_add(1, Ordering::SeqCst);
                S_SAVE1.store(
                    code(cnode_save_caller(Slot::root_cnode(x))),
                    Ordering::SeqCst,
                );
                S_SAVE2.store(
                    code(cnode_save_caller(Slot::root_cnode(x))),
                    Ordering::SeqCst,
                );
                S_SAVE3.store(
                    code(cnode_save_caller(Slot::root_cnode(y))),
                    Ordering::SeqCst,
                );
                reply(&msg(0, 0xBAD0, 0));
            }
            SEND_ON_X => send(x, &msg(0, cmd.msg.mr[1], 0)),
            other => fail!("redteam: ipc: S got command {other}"),
        }
    }
}

/// C: calls E for ever, recording each reply.
extern "C" fn client(ep: CPtr, _: u64, _: u64, _: u64) -> ! {
    let mut i = 0;
    loop {
        i += 1;
        let r = call(ep, &msg(0, i, 0));
        C_REPLIES.fetch_add(1, Ordering::SeqCst);
        C_LAST.store(r.mr[0], Ordering::SeqCst);
    }
}

/// B and B2: receive on E3 for ever, recording each badge and `rsi`.
extern "C" fn bound_receiver(e3: CPtr, _: u64, _: u64, _: u64) -> ! {
    loop {
        let r = recv(e3);
        B_BADGE.store(r.badge, Ordering::SeqCst);
        B_RSI.store(r.msg.info.word(), Ordering::SeqCst);
        B_COUNT.fetch_add(1, Ordering::SeqCst);
    }
}
