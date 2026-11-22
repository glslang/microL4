//! `test=badge`: each client's badge reaches the server, and
//! `CNode_CancelBadgedSends` takes exactly one badge's queued senders off
//! the endpoint (PLAN.md, M6's done-when; `docs/design.md`, "Badges",
//! "Deletion and cancellation" and "Badges, revoke and
//! `CNode_CancelBadgedSends`").
//!
//! The root task is the server, on endpoint E. It mints B1 and B2 from E
//! with badges `0xb1` and `0xb2` and every right, and gives four client
//! threads copies with Write and GrantReply: A1 and A2 copies of B1, B a
//! copy of B2, U a copy of E itself, unbadged. Each client makes
//! [`bc::PHASES`] calls, and records what each returned; the server checks
//! every message's badge against its sender ([`bc::sender`]) and answers
//! with that badge. A badge is set once: `CNode_Mint` of B1 with a new
//! badge, or of A1's copy with its own, is `IllegalOperation`.
//!
//! 1. Phases 0 to 2 run freely. The server answers phases 0 and 1 at once
//!    and keeps each client's phase-2 call waiting with `CNode_SaveCaller`;
//!    a second `CNode_SaveCaller` then fails, `DeleteFirst` into a full
//!    slot before `IllegalOperation` for the empty caller slot.
//! 2. It answers U, A1 and B through their saved reply capabilities, one at
//!    a time, dropping below them each time ([`spawn::let_others_run`]) so
//!    each queues its phase-3 call: E's queue is U, A1, B, while A2 still
//!    waits for its reply. `CNode_CancelBadgedSends` on a client's copy,
//!    without all four rights, is `IllegalOperation`, and on E itself,
//!    unbadged, moves nobody; on B1 it releases A1, whose restarted call
//!    queues again behind U and B, and leaves A2, whose message was already
//!    received, waiting: answered now, A2 queues last. The server must
//!    receive U, B, A1, A2.
//! 3. It answers them in the order A1, U, A2, B, so the queue is that, then
//!    revokes B1, which deletes A1's and A2's copies, and cancels B1's
//!    sends: A1 and A2 restart, find their slots empty, and their calls
//!    return `InvalidCapability`, while U and B stay queued, in order.
//!
//! The queued phases are received with `NBRecv`, so a sender missing from
//! the queue fails the test instead of hanging it.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::invoke::{
    Slot, cnode_cancel_badged_sends, cnode_copy, cnode_mint, cnode_revoke, cnode_save_caller,
    tcb_resume, tcb_set_priority,
};
use libsys::{
    BootInfo, CPtr, Error, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Received, Rights,
    SyscallError, call, nb_recv, println, recv, reply, send,
};
use root::check::badge::{
    self as bc, A1, A2, B, BADGE_1, BADGE_2, BADGES, CANCEL, CLIENTS, FREE, NAMES, Names, PHASES,
    REVOKE, U,
};

use crate::fail;
use crate::spawn::{self, STACKS, Thread, let_others_run};

/// The clients' priority, below the root task's 255.
const CLIENT_PRIORITY: u64 = 100;

/// What a client's call has not returned yet.
const NONE: u64 = u64::MAX;
/// What each client's calls returned: the reply's `MessageInfo` and MR0.
static INFO: [[AtomicU64; PHASES]; CLIENTS] =
    [const { [const { AtomicU64::new(NONE) }; PHASES] }; CLIENTS];
static MR0: [[AtomicU64; PHASES]; CLIENTS] =
    [const { [const { AtomicU64::new(0) }; PHASES] }; CLIENTS];

fn outcome(id: usize, phase: usize) -> bc::Outcome {
    let info = INFO[id][phase].load(Relaxed);
    (info != NONE).then(|| (MessageInfo::from_word(info), MR0[id][phase].load(Relaxed)))
}

fn root_slot(n: CPtr) -> Slot {
    Slot::root_cnode(n)
}

/// The server's answer to a call that carried `badge`.
fn answer(badge: u64) -> Message {
    Message::new(MessageInfo::new(0, 0, 0, 1), [badge, 0, 0, 0])
}

fn is(r: Result<(), Error>, e: SyscallError) -> bool {
    matches!(r, Err(err) if err.kernel() == Some(e))
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let eps = objects
        .retype(ipc, ObjectType::Endpoint, 0, 2)
        .unwrap_or_else(|e| fail!("badge: retyping the endpoints: {e}"));
    let (ep, park) = (eps, eps + 1);
    let tcbs = objects
        .retype(ipc, ObjectType::Tcb, 0, CLIENTS as u64)
        .unwrap_or_else(|e| fail!("badge: retyping the TCBs: {e}"));
    let first = objects
        .slots
        .alloc(4 + 2 * CLIENTS as u64)
        .unwrap_or_else(|| fail!("badge: no free slots"));
    let (b1, b2, fault, spare) = (first, first + 1, first + 2, first + 3);
    let copies: [CPtr; CLIENTS] = core::array::from_fn(|i| first + 4 + i as u64);
    let saved: [CPtr; CLIENTS] = core::array::from_fn(|i| first + 4 + (CLIENTS + i) as u64);

    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    let mints = [
        (b1, Rights::ALL, BADGE_1),
        (b2, Rights::ALL, BADGE_2),
        (fault, w_gr, bc::FAULT_BADGE),
    ];
    for (dest, rights, badge) in mints {
        cnode_mint(ipc, root_slot(dest), root_slot(ep), rights, badge)
            .unwrap_or_else(|e| fail!("badge: minting badge {badge:#x}: {e}"));
    }
    let sources = [b1, b1, b2, ep];
    for (id, (&copy, &src)) in copies.iter().zip(&sources).enumerate() {
        cnode_copy(ipc, root_slot(copy), root_slot(src), w_gr)
            .unwrap_or_else(|e| fail!("badge: copying {}'s capability: {e}", NAMES[id]));
    }
    for (id, &copy) in copies.iter().enumerate() {
        let t = Thread {
            tcb: tcbs + id as u64,
            fault_ep: fault,
            stack: STACKS[id],
            entry: client,
            args: [id as u64, copy, park, 0],
        };
        spawn::prepare(ipc, &t)
            .and_then(|()| tcb_set_priority(ipc, t.tcb, CAP_INIT_TCB, CLIENT_PRIORITY))
            .unwrap_or_else(|e| fail!("badge: setting up client {}: {e}", NAMES[id]));
    }
    println!(
        "badge: server: the root task on endpoint slot {ep}; B1 (slot {b1}) and B2 (slot {b2}) minted from it with badges {BADGE_1:#x} and {BADGE_2:#x} and every right"
    );
    println!(
        "badge: clients at priority {CLIENT_PRIORITY}: A1 and A2 call through copies of B1 (slots {} and {}), B through a copy of B2 (slot {}), U through an unbadged copy (slot {}), each with Write and GrantReply",
        copies[A1], copies[A2], copies[B], copies[U]
    );
    // A badge is set once (`docs/abi.md`, `CNode_Mint`): `spare` stays
    // empty, as the `CNode_SaveCaller` check below needs.
    let new_badge = cnode_mint(ipc, root_slot(spare), root_slot(b1), Rights::ALL, 0xbad);
    let own_badge = cnode_mint(ipc, root_slot(spare), root_slot(copies[A1]), w_gr, BADGE_1);
    if !is(new_badge, SyscallError::IllegalOperation)
        || !is(own_badge, SyscallError::IllegalOperation)
    {
        fail!(
            "badge: CNode_Mint of B1 with badge 0xbad: {new_badge:?}; of A1's copy with badge {BADGE_1:#x}: {own_badge:?}; want IllegalOperation for both"
        );
    }
    println!(
        "badge: ok   CNode_Mint of B1 with a new badge, or of A1's copy with its own: IllegalOperation, a badge is set once"
    );
    for (id, name) in NAMES.iter().enumerate() {
        tcb_resume(tcbs + id as u64)
            .unwrap_or_else(|e| fail!("badge: resuming client {name}: {e}"));
    }

    // 1. The free rounds.
    let mut phases = [[None; FREE]; CLIENTS];
    let mut count = [0; CLIENTS];
    for _ in 0..FREE * CLIENTS {
        let r = recv(ep);
        let (id, phase) = sender(&r);
        let Some(slot) = phases[id].get_mut(count[id]) else {
            fail!(
                "badge: a call from {} in phase {phase}, after {FREE} already",
                NAMES[id]
            );
        };
        *slot = Some(phase);
        count[id] += 1;
        if phase + 1 < FREE {
            reply(&answer(r.badge));
        } else {
            cnode_save_caller(root_slot(saved[id]))
                .unwrap_or_else(|e| fail!("badge: CNode_SaveCaller of {}'s call: {e}", NAMES[id]));
        }
    }
    if let Err((id, m)) = bc::free_rounds(&phases) {
        fail!("badge: client {}: {m}", NAMES[id]);
    }
    println!(
        "badge: ok   phases 0 to 2: {} calls, each with its sender's badge (A1 {BADGE_1:#x}, A2 {BADGE_1:#x}, B {BADGE_2:#x}, U 0x0); each phase-2 caller waits, its reply capability saved with CNode_SaveCaller",
        FREE * CLIENTS
    );
    let full = cnode_save_caller(root_slot(saved[A1]));
    let empty = cnode_save_caller(root_slot(spare));
    if !is(full, SyscallError::DeleteFirst) || !is(empty, SyscallError::IllegalOperation) {
        fail!(
            "badge: CNode_SaveCaller with the caller slot empty: into a full slot {full:?}, want DeleteFirst; into an empty one {empty:?}, want IllegalOperation"
        );
    }
    println!(
        "badge: ok   CNode_SaveCaller with the caller slot empty: DeleteFirst into a full slot, IllegalOperation into an empty one"
    );

    // 2. Cancel without revoke.
    for id in [U, A1, B] {
        release(ipc, saved[id], id, FREE - 1);
    }
    println!(
        "badge: phase 3: U, A1 and B queued on the endpoint in that order; A2 waits for its reply"
    );
    let weak = cnode_cancel_badged_sends(root_slot(copies[A1]));
    if !is(weak, SyscallError::IllegalOperation) {
        fail!(
            "badge: CNode_CancelBadgedSends on A1's copy, Write and GrantReply only: {weak:?}, want IllegalOperation"
        );
    }
    println!(
        "badge: ok   CNode_CancelBadgedSends on A1's copy, without all four rights: IllegalOperation"
    );
    cnode_cancel_badged_sends(root_slot(ep))
        .unwrap_or_else(|e| fail!("badge: CNode_CancelBadgedSends on the unbadged endpoint: {e}"));
    let_others_run(ipc);
    cnode_cancel_badged_sends(root_slot(b1))
        .unwrap_or_else(|e| fail!("badge: CNode_CancelBadgedSends on B1: {e}"));
    let_others_run(ipc);
    if outcome(A2, FREE - 1).is_some() {
        fail!("badge: A2's call returned before its saved reply capability was used");
    }
    release(ipc, saved[A2], A2, FREE - 1);
    let order = receive_queued(ep, CANCEL, &saved, false);
    if let Err(e) = bc::order(order.as_slice(), &[U, B, A1, A2]) {
        fail!(
            "badge: phase 3, after CNode_CancelBadgedSends on the unbadged endpoint and on B1: {e}"
        );
    }
    println!(
        "badge: ok   CNode_CancelBadgedSends on the unbadged endpoint moved nobody; on B1 it released A1, which restarted its call and queued again behind U and B, and left A2, waiting for its reply, alone; received {}",
        Names(order.as_slice())
    );

    // 3. Revoke, then cancel.
    for id in [A1, U, A2, B] {
        release(ipc, saved[id], id, CANCEL);
    }
    println!("badge: phase 4: A1, U, A2 and B queued in that order");
    cnode_revoke(root_slot(b1))
        .and_then(|()| cnode_cancel_badged_sends(root_slot(b1)))
        .unwrap_or_else(|e| fail!("badge: revoking B1 and cancelling its sends: {e}"));
    let_others_run(ipc);
    for id in [A1, A2] {
        if outcome(id, REVOKE) != Some(bc::expected(id, REVOKE)) {
            fail!(
                "badge: after the revoke and cancel, {}'s restarted call returned {:?}, want InvalidCapability",
                NAMES[id],
                outcome(id, REVOKE)
            );
        }
    }
    let order = receive_queued(ep, REVOKE, &saved, true);
    if let Err(e) = bc::order(order.as_slice(), &[U, B]) {
        fail!("badge: phase 4, after revoking B1 and cancelling its sends: {e}");
    }
    let_others_run(ipc);
    println!(
        "badge: ok   CNode_Revoke of B1 deleted A1's and A2's copies; CNode_CancelBadgedSends on B1 then released them, and their restarted calls returned InvalidCapability, MR0 0; U and B stayed queued and were received in order: {}",
        Names(order.as_slice())
    );

    let got: [[bc::Outcome; PHASES]; CLIENTS] =
        core::array::from_fn(|id| core::array::from_fn(|phase| outcome(id, phase)));
    if let Err(e) = bc::outcomes(&got) {
        fail!("badge: {e}");
    }
    println!(
        "badge: ok   every client's every call returned what the design gives it, each answer the badge the server saw"
    );
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// The client and phase of a message the server received, or the test
/// fails.
fn sender(r: &Received) -> (usize, usize) {
    if r.badge == 0 && r.msg.info.word() == 0 {
        fail!("badge: nothing was queued on the endpoint");
    }
    bc::sender(r).unwrap_or_else(|e| fail!("badge: {e}"))
}

/// Answers client `id`'s saved call, whose phase was `phase`, then lets
/// it run until it blocks again, in its next call.
fn release(ipc: Ipc, saved: CPtr, id: usize, phase: usize) {
    send(saved, &answer(BADGES[id]));
    let_others_run(ipc);
    if outcome(id, phase).is_none() {
        fail!(
            "badge: {}'s phase-{phase} call did not return when its saved reply capability was used",
            NAMES[id]
        );
    }
}

/// The clients in the order the server received their calls.
struct Order {
    ids: [usize; CLIENTS],
    len: usize,
}

impl Order {
    fn as_slice(&self) -> &[usize] {
        &self.ids[..self.len]
    }
}

/// Receives every call queued on `ep` with `NBRecv`, until none is left;
/// each must be in `phase`. With `answer_now`, each is answered at once;
/// otherwise its reply capability is saved in `saved`.
fn receive_queued(ep: CPtr, phase: usize, saved: &[CPtr; CLIENTS], answer_now: bool) -> Order {
    let mut order = Order {
        ids: [0; CLIENTS],
        len: 0,
    };
    loop {
        let r = nb_recv(ep);
        if r.badge == 0 && r.msg.info.word() == 0 {
            break order;
        }
        let (id, p) = sender(&r);
        if p != phase {
            fail!(
                "badge: {}'s call in phase {p}, want phase {phase}",
                NAMES[id]
            );
        }
        let Some(slot) = order.ids.get_mut(order.len) else {
            fail!("badge: more than {CLIENTS} calls queued in phase {phase}");
        };
        *slot = id;
        order.len += 1;
        if answer_now {
            reply(&answer(r.badge));
        } else {
            cnode_save_caller(root_slot(saved[id]))
                .unwrap_or_else(|e| fail!("badge: CNode_SaveCaller of {}'s call: {e}", NAMES[id]));
        }
    }
}

/// Client `id`: calls `cap` once per phase and records what each call
/// returned; after a call that failed, or the last one, it waits on
/// `park`, where nothing comes.
extern "C" fn client(id: u64, cap: CPtr, park: CPtr, _: u64) -> ! {
    let id = id as usize;
    for phase in 0..PHASES {
        let msg = Message::new(
            MessageInfo::new(bc::label(id, phase), 0, 0, 1),
            [phase as u64, 0, 0, 0],
        );
        let r = call(cap, &msg);
        MR0[id][phase].store(r.mr[0], Relaxed);
        INFO[id][phase].store(r.info.word(), Relaxed);
        if r.info.label() != 0 {
            break;
        }
    }
    loop {
        recv(park);
    }
}
