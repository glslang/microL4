//! Host tests of capability transfer, driven through system calls as
//! threads make them ([`crate::syscall::handle_syscall`]) in the world of
//! `crate::ipc`'s tests: each rule of `docs/design.md`, "Capability
//! transfer", then a proptest of random sends against a model of where
//! every capability must end up. After every step the scheduler's and
//! IPC's invariants hold ([`World::check`]), and so do the capability
//! core's over every slot of the world ([`check_caps`]): the derivation
//! list, depths and finality.

use std::vec::Vec;

use proptest::prelude::*;

use crate::cap::{
    Cap, CapType, MAX_DERIVATION_DEPTH, NOTIFICATION_BITS, Rights, TCB_SLOT_CALLER,
    TCB_SLOT_IPC_BUFFER, TCB_SLOTS,
};
use crate::cdt;
use crate::invoke::label;
use crate::ipc::tests::*;
use crate::ipc::{MessageInfo, word};
use crate::slot::{Node, Slot, SlotAddr, SlotMemory};
use crate::syscall::Outcome;
use crate::tcb::{Tcbs, ThreadState};

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

const CALL: u64 = 1;
const REPLY_RECV: u64 = 2;
const SEND: u64 = 3;
const NBSEND: u64 = 4;
const REPLY: u64 = 6;

/// A receive slot as the three IPC buffer words name it: `receive_cnode`,
/// `receive_index`, `receive_depth`.
type RecvSlot = (u64, u64, u64);

/// Root CNode slot [`S_FREE`], named from the root CNode.
const INTO_ROOT: RecvSlot = (S_ROOT, S_FREE, 64);
/// Slot 5 of the second CNode, named from it with its 4 bits.
const INTO_CNODE2: RecvSlot = (S_CNODE2, 5, 4);
/// A root slot that stays empty, for pointers to an empty slot.
const S_EMPTY: u64 = 31;
/// What a receiver's `caps_or_badges[i]` holds before a transfer.
const UNTOUCHED: u64 = 0xC0DE_0000;

fn cnode2(i: u64) -> SlotAddr {
    sa(CNODE2).offset(i)
}

/// The slot a receive-slot triple names, for the valid ones the tests use.
fn recv_slot_addr((cnode, index, _): RecvSlot) -> SlotAddr {
    match cnode {
        S_ROOT => rs(index),
        S_CNODE2 => cnode2(index),
        _ => panic!("not a receive slot the tests name"),
    }
}

/// A `MessageInfo` naming `extra` capabilities.
fn info_caps(label: u64, extra: u64, length: u64) -> u64 {
    MessageInfo::new(label, 0, extra, length).word()
}

/// Thread `t` names `slot` as its receive slot and marks its
/// `caps_or_badges`, so a test sees which entries a transfer wrote.
fn offer(w: &mut World, t: usize, (cnode, index, depth): RecvSlot) {
    w.set_buf(t, word::RECEIVE_CNODE, cnode);
    w.set_buf(t, word::RECEIVE_INDEX, index);
    w.set_buf(t, word::RECEIVE_DEPTH, depth);
    for i in 0..3 {
        w.set_buf(t, word::CAPS_OR_BADGES + i, UNTOUCHED + i as u64);
    }
}

/// Thread `t` names `caps` in its `caps_or_badges`.
fn name_caps(w: &mut World, t: usize, caps: &[u64]) {
    for (i, &c) in caps.iter().enumerate() {
        w.set_buf(t, word::CAPS_OR_BADGES + i, c);
    }
}

/// Thread `t` sends (`number`: `Send`, `NBSend`, `Call`, `Reply` or
/// `ReplyRecv`) on `cptr` a one-word message with label `label`, MR0
/// `0x5EED`, naming `caps`, which it writes to its buffer first if it has
/// one.
fn send_caps(w: &mut World, t: usize, number: u64, cptr: u64, label: u64, caps: &[u64]) -> Outcome {
    if t != F {
        name_caps(w, t, caps);
    }
    let rsi = info_caps(label, caps.len() as u64, 1);
    let out = w.syscall(t, number, cptr, rsi, Some([0x5EED, 0, 0, 0]));
    verify(w);
    out
}

/// What thread `t` received in `rsi`: label, `caps_unwrapped`,
/// `extra_caps`, length.
fn got(w: &World, t: usize) -> (u64, u64, u64, u64) {
    let m = MessageInfo::from_word(w.regs(t).rsi);
    (m.label(), m.caps_unwrapped(), m.extra_caps(), m.length())
}

/// Thread `t`'s `caps_or_badges`.
fn badges(w: &World, t: usize) -> [u64; 3] {
    [0, 1, 2].map(|i| w.buf(t, word::CAPS_OR_BADGES + i))
}

/// Every slot of the world: the root CNode's, the second CNode's and each
/// thread's TCB slots. Every capability lives in one of them.
fn all_slots() -> Vec<SlotAddr> {
    let mut v: Vec<SlotAddr> = (0..32).map(rs).collect();
    v.extend((0..16).map(cnode2));
    for i in 0..THREADS {
        v.extend((0..TCB_SLOTS).map(|s| tcb(i).slot(s)));
    }
    v
}

/// The capability core's invariants over every slot: each slot's list
/// links and depth bounds (`cdt::check_slot`), every link inside the
/// world, and `is_final` exactly when no other capability names the same
/// object.
fn check_caps(w: &World) {
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
}

/// [`World::check`] and [`check_caps`], natively; under Miri, which finds
/// nothing in this safe code that the native run does not, the tests'
/// own assertions stand alone.
fn verify(w: &World) {
    if !cfg!(miri) {
        w.check();
        check_caps(w);
    }
}

/// A world in which `r` waits on endpoint 0 (through `S_EP0`, all rights)
/// with `slot` as its receive slot.
fn waiting(r: usize, slot: RecvSlot) -> World {
    let mut w = World::new();
    if r != F {
        offer(&mut w, r, slot);
    }
    w.recv(r, S_EP0);
    verify(&w);
    w
}

fn parent(w: &World, s: SlotAddr) -> Option<SlotAddr> {
    cdt::parent(&w.k, s)
}

// ---------------------------------------------------------------------------
// Copying
// ---------------------------------------------------------------------------

#[test]
fn a_capability_with_grant_is_copied_into_the_receive_slot() {
    let mut w = waiting(B, INTO_ROOT);
    assert_eq!(
        send_caps(&mut w, A, SEND, S_EP0, 5, &[S_FRAME_RW]),
        Outcome::Done
    );
    assert_eq!(w.state(B), ThreadState::Running);
    assert_eq!(got(&w, B), (5, 0, 1, 1));
    assert_eq!((w.regs(B).rdi, w.mrs(B)[0]), (0, 0x5EED));
    // Same rights, a child of the original, which keeps its own.
    let copy = rs(S_FREE);
    assert_eq!(w.cap(copy), frame(FRAME_RW, RW));
    assert_eq!(parent(&w, copy), Some(rs(S_FRAME_RW)));
    assert_eq!(w.k.load(copy).node.depth(), 1);
    assert!(!w.k.load(copy).node.original());
    assert_eq!(w.cap(rs(S_FRAME_RW)), frame(FRAME_RW, RW));
    // The sender's buffer is not written; the receiver's entries stay.
    assert_eq!(w.buf(A, word::CAPS_OR_BADGES), S_FRAME_RW);
    assert_eq!(badges(&w, B), [UNTOUCHED, UNTOUCHED + 1, UNTOUCHED + 2]);
}

#[test]
fn a_copy_of_a_copy_is_its_sibling_and_a_badged_original_keeps_its_badge() {
    // Sent through endpoint 1, so capabilities to endpoint 0 are copied.
    for (src, want, from) in cases(&[
        (S_EP0_W, ep_cap(0, Rights::WRITE, 0), S_EP0),
        (S_EP0_R, ep_cap(0, Rights::READ, 0), S_EP0),
        (S_EP0_BADGED, ep_cap(0, Rights::ALL, BADGE), S_EP0_BADGED),
    ]) {
        let mut w = World::new();
        offer(&mut w, C, INTO_CNODE2);
        w.recv(C, S_EP1);
        send_caps(&mut w, A, CALL, S_EP1, 6, &[src]);
        assert_eq!(got(&w, C), (6, 0, 1, 1));
        assert_eq!(w.state(A), ThreadState::BlockedOnReply);
        let copy = cnode2(5);
        assert_eq!(w.cap(copy), want);
        assert_eq!(parent(&w, copy), Some(rs(from)));
        assert_eq!(
            w.k.load(copy).node.depth(),
            w.k.load(rs(from)).node.depth() + 1
        );
    }
}

#[test]
fn a_received_copy_is_a_descendant_that_revoke_reaches() {
    let mut w = World::new();
    offer(&mut w, C, INTO_ROOT);
    w.recv(C, S_EP1);
    send_caps(&mut w, A, SEND, S_EP1, 1, &[S_EP0_BADGED]);
    assert_eq!(w.cap(rs(S_FREE)), ep_cap(0, Rights::ALL, BADGE));
    // Deleting the copy is not the endpoint's last capability.
    w.k.events.clear();
    w.call(D, S_ROOT, label::CNODE_DELETE, 2, [S_FREE, 64, 0, 0]);
    assert_eq!(w.regs(D).rsi, info(0, 0));
    assert!(matches!(
        w.k.events[..],
        [crate::testing::Event::Finalise { last: false, .. }]
    ));
    // Received again, then revoked with the badged original.
    w.run(C);
    w.recv(C, S_EP1);
    send_caps(&mut w, A, SEND, S_EP1, 1, &[S_EP0_BADGED]);
    assert!(!w.cap(rs(S_FREE)).is_null());
    w.call(D, S_ROOT, label::CNODE_REVOKE, 2, [S_EP0_BADGED, 64, 0, 0]);
    assert!(w.cap(rs(S_FREE)).is_null());
    assert_eq!(w.cap(rs(S_EP0_BADGED)), ep_cap(0, Rights::ALL, BADGE));
    verify(&w);
}

#[test]
fn an_untyped_copy_takes_the_free_space_as_cnode_copy_gives_it() {
    let mut w = waiting(B, INTO_ROOT);
    send_caps(&mut w, A, SEND, S_EP0, 1, &[S_UNTYPED]);
    assert_eq!(got(&w, B), (1, 0, 1, 1));
    assert_eq!(w.cap(rs(S_FREE)), Cap::untyped(UNTYPED, 12, false, 0));
    assert_eq!(
        w.cap(rs(S_UNTYPED)),
        Cap::untyped(UNTYPED, 12, false, 1 << 12)
    );
    assert!(w.k.load(rs(S_FREE)).node.original());
    // Now the source has a child, so it cannot be sent again.
    w.run(B);
    offer(&mut w, B, INTO_CNODE2);
    w.recv(B, S_EP0);
    send_caps(&mut w, A, SEND, S_EP0, 1, &[S_UNTYPED]);
    assert_eq!(got(&w, B), (1, 0, 0, 1));
    assert!(w.cap(cnode2(5)).is_null());
}

#[test]
fn a_capability_can_go_into_a_slot_of_another_cnode() {
    let mut w = waiting(D, INTO_CNODE2);
    send_caps(&mut w, A, CALL, S_EP0, 1, &[S_TCB + F as u64]);
    assert_eq!(got(&w, D), (1, 0, 1, 1));
    let tcb_f = Cap::new(
        CapType::Tcb,
        tcb(F).get(),
        crate::cap::TCB_BITS,
        Rights::NONE,
        false,
        0,
    );
    assert_eq!(w.cap(cnode2(5)), tcb_f);
    assert_eq!(parent(&w, cnode2(5)), Some(rs(S_TCB + F as u64)));
    // A Call that moves a capability also leaves the reply capability.
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert_eq!(w.caller_slot(D), Cap::reply(tcb(A).get(), false, true));
}

/// A world in which C's CSpace is the second CNode, with a 60-bit guard so
/// that `CPtr` `j` names its slot `j`. Its slot 2 holds that CNode's
/// capability, 3 a copy of the read-write frame's, 4 endpoint 1's and 6
/// endpoint 0's. In everyone else's CSpace, `CPtr` 2 is endpoint 0 and 3
/// is endpoint 1.
fn own_cspace() -> World {
    let mut w = World::new();
    let guarded = Cap::cnode(CNODE2, 4, 60, 0);
    let root = tcb(C).slot(crate::cap::TCB_SLOT_CSPACE);
    crate::cnode::delete(&mut w.k, root).unwrap();
    cdt::insert_derived(&mut w.k, rs(S_CNODE2), root, guarded, false).unwrap();
    for (from, to) in [(S_CNODE2, 2), (S_FRAME_RW, 3), (S_EP1, 4), (S_EP0, 6)] {
        let c = if from == S_CNODE2 {
            guarded
        } else {
            w.cap(rs(from))
        };
        cdt::insert_derived(&mut w.k, rs(from), cnode2(to), c, false).unwrap();
    }
    verify(&w);
    w
}

#[test]
fn each_side_resolves_its_own_pointers_in_its_own_cspace() {
    // C receives into its CNode's slot 7, named through its own CPtr 2
    // and the 64 bits that CNode capability resolves.
    let mut w = own_cspace();
    w.run(C);
    offer(&mut w, C, (2, 7, 64));
    w.recv(C, 4);
    assert!(matches!(w.state(C), ThreadState::BlockedOnReceive { .. }));
    send_caps(&mut w, A, SEND, S_EP1, 1, &[S_UNTYPED]);
    assert_eq!(got(&w, C), (1, 0, 1, 1));
    assert_eq!(w.cap(cnode2(7)), Cap::untyped(UNTYPED, 12, false, 0));
    // C sends its CPtr 3, its frame copy, not endpoint 1.
    offer(&mut w, B, INTO_ROOT);
    w.recv(B, S_EP0);
    send_caps(&mut w, C, SEND, 6, 2, &[3]);
    assert_eq!(got(&w, B), (2, 0, 1, 1));
    assert_eq!(w.cap(rs(S_FREE)), frame(FRAME_RW, RW));
    assert_eq!(parent(&w, rs(S_FREE)), Some(rs(S_FRAME_RW)));
    verify(&w);
}

// ---------------------------------------------------------------------------
// When nothing moves
// ---------------------------------------------------------------------------

#[test]
fn without_grant_nothing_is_copied_or_unwrapped() {
    for cptr in [S_EP0_W, S_EP0_WGR] {
        let mut w = waiting(B, INTO_ROOT);
        let number = if cptr == S_EP0_W { SEND } else { CALL };
        send_caps(&mut w, A, number, cptr, 3, &[S_EP0_BADGED, S_FRAME_RW]);
        assert_eq!(w.state(B), ThreadState::Running);
        assert_eq!(got(&w, B), (3, 0, 0, 1));
        assert!(w.cap(rs(S_FREE)).is_null());
        assert_eq!(badges(&w, B), [UNTOUCHED, UNTOUCHED + 1, UNTOUCHED + 2]);
    }
}

#[test]
fn a_sender_needs_a_readable_buffer_and_a_receiver_a_writable_one() {
    // F has no buffer: nothing is looked up or moved.
    let mut w = waiting(B, INTO_ROOT);
    send_caps(&mut w, F, SEND, S_EP0, 2, &[S_FRAME_RW, S_EP0]);
    assert_eq!(got(&w, B), (2, 0, 0, 1));
    assert!(w.cap(rs(S_FREE)).is_null());
    // E's buffer is readable: its capabilities move.
    let mut w = waiting(B, INTO_ROOT);
    send_caps(&mut w, E, SEND, S_EP0, 2, &[S_EP0_BADGED, S_FRAME_RW]);
    assert_eq!(got(&w, B), (2, 1, 2, 1));
    assert_eq!(w.cap(rs(S_FREE)), frame(FRAME_RW, RW));
    // A receiver whose buffer is not writable (E) or missing (F) gets the
    // message and no capability, not even a badge.
    for r in [E, F] {
        let mut w = waiting(r, INTO_ROOT);
        send_caps(&mut w, A, SEND, S_EP0, 4, &[S_EP0_BADGED, S_FRAME_RW]);
        assert_eq!(got(&w, r), (4, 0, 0, 1));
        assert_eq!(w.mrs(r)[0], 0x5EED);
        assert!(w.cap(rs(S_FREE)).is_null());
    }
    // No extra capability named: none moves.
    let mut w = waiting(B, INTO_ROOT);
    name_caps(&mut w, A, &[S_FRAME_RW]);
    w.send(A, S_EP0, 7, 1, [1, 0, 0, 0]);
    assert_eq!(got(&w, B), (7, 0, 0, 1));
    assert!(w.cap(rs(S_FREE)).is_null());
}

// ---------------------------------------------------------------------------
// Unwrapping
// ---------------------------------------------------------------------------

#[test]
fn a_capability_to_the_endpoint_carrying_the_message_arrives_as_its_badge() {
    let mut w = waiting(B, INTO_ROOT);
    send_caps(
        &mut w,
        A,
        SEND,
        S_EP0,
        8,
        &[S_EP0_BADGED, S_FRAME_RW, S_EP0_R],
    );
    // Badges at 0 and 2, whatever the rights (S_EP0_R has Read only); the
    // frame takes the slot; entry 1 keeps the receiver's value.
    assert_eq!(got(&w, B), (8, 0b101, 3, 1));
    assert_eq!(badges(&w, B), [BADGE, UNTOUCHED + 1, 0]);
    assert_eq!(w.cap(rs(S_FREE)), frame(FRAME_RW, RW));
    // Unwrapped capabilities stay where they were, with nothing derived.
    assert!(!cdt::has_children(&w.k, rs(S_EP0_BADGED)));
    // Several unwrap; none uses the slot.
    let mut w = waiting(B, INTO_ROOT);
    send_caps(&mut w, A, SEND, S_EP0, 8, &[S_EP0, S_EP0_W, S_EP0_BADGED]);
    assert_eq!(got(&w, B), (8, 0b111, 3, 1));
    assert_eq!(badges(&w, B), [0, 0, BADGE]);
    assert!(w.cap(rs(S_FREE)).is_null());
    // A capability to another endpoint is copied, not unwrapped.
    let mut w = waiting(B, INTO_ROOT);
    send_caps(&mut w, A, SEND, S_EP0, 8, &[S_EP1, S_EP0_BADGED]);
    assert_eq!(got(&w, B), (8, 0b10, 2, 1));
    assert_eq!(badges(&w, B), [UNTOUCHED, BADGE, UNTOUCHED + 2]);
    assert_eq!(w.cap(rs(S_FREE)), ep_cap(1, Rights::ALL, 0));
}

#[test]
fn a_reply_never_unwraps() {
    let mut w = waiting(B, INTO_ROOT);
    offer(&mut w, A, INTO_CNODE2);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    // A capability to endpoint 0 in the reply is copied; the second needs
    // the slot that is now used.
    send_caps(&mut w, B, REPLY, 0, 9, &[S_EP0_BADGED, S_EP0]);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!((w.regs(A).rdi, got(&w, A)), (0, (9, 0, 1, 1)));
    assert_eq!(w.cap(cnode2(5)), ep_cap(0, Rights::ALL, BADGE));
    assert_eq!(badges(&w, A), [UNTOUCHED, UNTOUCHED + 1, UNTOUCHED + 2]);
}

#[test]
fn senders_sharing_a_buffer_with_their_receiver_have_every_pointer_looked_up_first() {
    // B's buffer is A's: B's badges land on A's pointers.
    let mut w = World::new();
    let shared = w.cap(tcb(A).slot(TCB_SLOT_IPC_BUFFER));
    let b_buf = tcb(B).slot(TCB_SLOT_IPC_BUFFER);
    crate::cnode::delete(&mut w.k, b_buf).unwrap();
    cdt::insert_derived(&mut w.k, rs(S_FRAME_RW), b_buf, shared, false).unwrap();
    let a_vaddr = w.k.ipc_buffer(tcb(A));
    w.k.set_ipc_buffer(tcb(B), a_vaddr);
    offer(&mut w, A, INTO_ROOT);
    w.recv(B, S_EP0);
    send_caps(
        &mut w,
        A,
        SEND,
        S_EP0,
        2,
        &[S_EP0_BADGED, S_FRAME_RO, S_EP0],
    );
    assert_eq!(got(&w, B), (2, 0b101, 3, 1));
    assert_eq!(badges(&w, A), [BADGE, S_FRAME_RO, 0]);
    assert_eq!(w.cap(rs(S_FREE)), frame(FRAME_RO, Rights::READ));
}

// ---------------------------------------------------------------------------
// Where the loop stops
// ---------------------------------------------------------------------------

#[test]
fn the_first_capability_that_can_be_neither_unwrapped_nor_copied_ends_the_transfer() {
    // A saved reply capability in root slot 29, and an untyped with a child
    // in 30.
    let setup = || {
        let mut w = World::new();
        w.recv(D, S_EP2);
        w.call(C, S_EP2, 1, 0, [0; 4]);
        let reply = w.caller_slot(D);
        cdt::move_slot(&mut w.k, reply, tcb(D).slot(TCB_SLOT_CALLER), rs(29));
        let ut = w.cap(rs(S_UNTYPED));
        cdt::insert_derived(&mut w.k, rs(S_UNTYPED), rs(30), ut, true).unwrap();
        verify(&w);
        (w, reply)
    };
    let table = [
        // A second copy needs the slot the first used.
        (&[S_FRAME_RW, S_TCB][..], (0, 1)),
        (&[S_FRAME_RW, S_FRAME_RO, S_EP0_BADGED][..], (0, 1)),
        // An empty slot resolves, then cannot be copied.
        (&[S_EMPTY, S_FRAME_RW][..], (0, 0)),
        (&[S_EP0_BADGED, S_EMPTY, S_FRAME_RW][..], (0b1, 1)),
        // A reply capability and an untyped with children never derive;
        // nothing after them is unwrapped either.
        (&[29, S_FRAME_RW][..], (0, 0)),
        (&[S_UNTYPED, S_EP0_BADGED][..], (0, 0)),
        (&[S_EP0, S_UNTYPED, S_EP0_BADGED][..], (0b1, 1)),
        // Its child has none.
        (&[30, S_EP0_BADGED][..], (0b10, 2)),
        // The slot itself, named as a source, is empty.
        (&[S_FREE][..], (0, 0)),
    ];
    for (caps, (unwrapped, extra)) in cases(&table) {
        let (mut w, reply) = setup();
        let r = B;
        w.run(r);
        offer(&mut w, r, INTO_ROOT);
        w.recv(r, S_EP0);
        // The one capability processed that is not unwrapped is copied, as
        // it is before the transfer (a copied untyped's source fills).
        let copied = caps
            .iter()
            .take(extra as usize)
            .find(|&&c| !matches!(c, S_EP0 | S_EP0_BADGED))
            .map(|&c| w.cap(rs(c)));
        send_caps(&mut w, A, SEND, S_EP0, 1, caps);
        assert_eq!(got(&w, r), (1, unwrapped, extra, 1), "{caps:?}");
        assert_eq!(w.cap(rs(S_FREE)), copied.unwrap_or(Cap::NULL), "{caps:?}");
        assert_eq!(w.cap(rs(29)), reply);
    }
}

#[test]
fn an_unusable_receive_slot_takes_no_copy_but_badges_still_arrive() {
    let bad: [RecvSlot; 9] = [
        // Occupied.
        (S_ROOT, S_EP1, 64),
        (S_ROOT, S_ROOT, 64),
        // `receive_cnode` is not a CNode, does not resolve, or is empty.
        (S_EP1, S_FREE, 64),
        (BAD_CPTR, S_FREE, 64),
        (S_EMPTY, S_FREE, 64),
        // `receive_depth` out of range, or not ending at a slot.
        (S_ROOT, S_FREE, 0),
        (S_ROOT, S_FREE, 65),
        (S_ROOT, S_FREE, 63),
        (S_CNODE2, 5, 5),
    ];
    for slot in cases(&bad) {
        let mut w = waiting(B, slot);
        let before: Vec<Cap> = all_slots().into_iter().map(|s| w.cap(s)).collect();
        send_caps(&mut w, A, SEND, S_EP0, 1, &[S_EP0_BADGED, S_FRAME_RW]);
        assert_eq!(got(&w, B), (1, 0b1, 1, 1), "{slot:?}");
        assert_eq!(badges(&w, B)[0], BADGE);
        let after: Vec<Cap> = all_slots().into_iter().map(|s| w.cap(s)).collect();
        assert_eq!(before, after, "{slot:?}");
    }
}

#[test]
fn a_copy_refused_at_the_depth_limit_ends_the_transfer() {
    // A notification capability nothing else names, an original at the
    // limit: its child would be too deep, so the transfer ends there. As a
    // plain copy at the limit, its copy is a sibling at the same depth and
    // goes, and the transfer goes on to unwrap the last.
    let ntfn = Cap::new(
        CapType::Notification,
        0x7800,
        NOTIFICATION_BITS,
        RW,
        false,
        0,
    );
    for (original, unwrapped, extra) in [(true, 0b1, 1), (false, 0b101, 3)] {
        let mut w = waiting(B, INTO_ROOT);
        let node = Node::new(original, MAX_DERIVATION_DEPTH, MAX_DERIVATION_DEPTH);
        w.k.store(rs(28), Slot { cap: ntfn, node });
        verify(&w);
        send_caps(&mut w, A, SEND, S_EP0, 1, &[S_EP0_BADGED, 28, S_EP0]);
        assert_eq!(got(&w, B), (1, unwrapped, extra, 1), "original {original}");
        if original {
            assert!(w.cap(rs(S_FREE)).is_null());
        } else {
            assert_eq!(w.cap(rs(S_FREE)), ntfn);
            assert_eq!(w.k.load(rs(S_FREE)).node.depth(), MAX_DERIVATION_DEPTH);
        }
    }
}

// ---------------------------------------------------------------------------
// Send-time and transfer-time lookups
// ---------------------------------------------------------------------------

#[test]
fn a_pointer_that_does_not_resolve_at_send_time_faults_before_anything_is_sent() {
    for number in [SEND, CALL] {
        let mut w = World::new();
        w.set_fault_ep(A, S_EP1);
        w.recv(D, S_EP1);
        offer(&mut w, B, INTO_ROOT);
        w.recv(B, S_EP0);
        let ip = w.regs(A).next_ip;
        send_caps(&mut w, A, number, S_EP0, 1, &[S_FRAME_RW, BAD_CPTR]);
        // D, A's handler, gets the CapFault; B still waits.
        assert_eq!(w.state(A), ThreadState::BlockedOnReply);
        assert_eq!(MessageInfo::from_word(w.regs(D).rsi).label(), 1);
        assert_eq!(
            (0..7).map(|i| w.mr(D, i)).collect::<Vec<_>>(),
            [ip, BAD_CPTR, 0, 4, 64, 0, 59]
        );
        assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
        assert!(w.cap(rs(S_FREE)).is_null());
    }
    // NBSend drops the message instead.
    let mut w = waiting(B, INTO_ROOT);
    send_caps(&mut w, A, NBSEND, S_EP0, 1, &[S_FRAME_RW, BAD_CPTR]);
    assert_eq!(w.state(A), ThreadState::Running);
    assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
}

#[test]
fn a_queued_sender_is_looked_up_again_when_its_message_is_taken() {
    // A queues; then its pointer changes (a thread sharing its buffer could
    // write it): the capability named at transfer moves.
    let mut w = World::new();
    send_caps(&mut w, A, SEND, S_EP0, 1, &[S_FRAME_RW]);
    assert!(matches!(
        w.state(A),
        ThreadState::BlockedOnSend {
            can_grant: true,
            ..
        }
    ));
    name_caps(&mut w, A, &[S_UNTYPED]);
    offer(&mut w, B, INTO_ROOT);
    w.recv(B, S_EP0);
    assert_eq!(got(&w, B), (1, 0, 1, 1));
    assert_eq!(w.cap(rs(S_FREE)), Cap::untyped(UNTYPED, 12, false, 0));
    verify(&w);

    // A pointer that no longer resolves moves nothing, not even the badge
    // named before it; the message still arrives, and nobody faults.
    let mut w = World::new();
    send_caps(&mut w, A, CALL, S_EP0, 1, &[S_EP0_BADGED, S_FRAME_RW]);
    name_caps(&mut w, A, &[S_EP0_BADGED, BAD_CPTR]);
    offer(&mut w, B, INTO_ROOT);
    w.recv(B, S_EP0);
    assert_eq!(got(&w, B), (1, 0, 0, 1));
    assert_eq!(w.mrs(B)[0], 0x5EED);
    assert_eq!(badges(&w, B), [UNTOUCHED, UNTOUCHED + 1, UNTOUCHED + 2]);
    assert!(w.cap(rs(S_FREE)).is_null());
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    verify(&w);

    // A capability deleted meanwhile leaves an empty slot, where the
    // transfer stops after what came before.
    let mut w = World::new();
    let frame_copy = rs(27);
    let f = w.cap(rs(S_FRAME_RW));
    cdt::insert_derived(&mut w.k, rs(S_FRAME_RW), frame_copy, f, false).unwrap();
    send_caps(&mut w, A, SEND, S_EP0, 1, &[S_EP0_BADGED, 27]);
    w.call(C, S_ROOT, label::CNODE_DELETE, 2, [27, 64, 0, 0]);
    assert!(w.cap(frame_copy).is_null());
    offer(&mut w, B, INTO_ROOT);
    w.recv(B, S_EP0);
    assert_eq!(got(&w, B), (1, 0b1, 1, 1));
    assert!(w.cap(rs(S_FREE)).is_null());
    verify(&w);
}

#[test]
fn a_queued_sender_keeps_the_grant_it_had_when_it_sent() {
    // A sends through a copy of EP0's capability with Write and Grant,
    // which is then deleted: its message still carries capabilities.
    let mut w = World::new();
    let wg = ep_cap(0, Rights(Rights::WRITE.0 | Rights::GRANT.0), 0);
    cdt::insert_derived(&mut w.k, rs(S_EP0), rs(27), wg, false).unwrap();
    send_caps(&mut w, A, SEND, 27, 1, &[S_FRAME_RW]);
    w.call(C, S_ROOT, label::CNODE_DELETE, 2, [27, 64, 0, 0]);
    assert!(w.cap(rs(27)).is_null());
    offer(&mut w, B, INTO_ROOT);
    w.recv(B, S_EP0);
    assert_eq!(got(&w, B), (1, 0, 1, 1));
    assert_eq!(w.cap(rs(S_FREE)), frame(FRAME_RW, RW));
    // Without Grant when it sent, none.
    let mut w = World::new();
    send_caps(&mut w, A, SEND, S_EP0_W, 1, &[S_FRAME_RW]);
    offer(&mut w, B, INTO_ROOT);
    w.recv(B, S_EP0);
    assert_eq!(got(&w, B), (1, 0, 0, 1));
    assert!(w.cap(rs(S_FREE)).is_null());
}

// ---------------------------------------------------------------------------
// Replies and faults
// ---------------------------------------------------------------------------

/// B received A's `Call` on `on`, A offering `INTO_CNODE2`.
fn called(on: u64) -> World {
    let mut w = World::new();
    w.recv(B, on);
    offer(&mut w, A, INTO_CNODE2);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    verify(&w);
    w
}

#[test]
fn a_reply_carries_capabilities_only_if_its_reply_capability_has_grant() {
    // Received on a capability with Grant: the reply capability has it.
    for number in [REPLY, REPLY_RECV] {
        let mut w = called(S_EP0);
        assert_eq!(w.caller_slot(B), Cap::reply(tcb(A).get(), false, true));
        send_caps(&mut w, B, number, S_EP1, 2, &[S_FRAME_RW]);
        assert_eq!(got(&w, A), (2, 0, 1, 1));
        assert_eq!(w.cap(cnode2(5)), frame(FRAME_RW, RW));
        assert_eq!(parent(&w, cnode2(5)), Some(rs(S_FRAME_RW)));
    }
    // Received with Read only: no Grant, nothing moves.
    let mut w = called(S_EP0_R);
    assert_eq!(w.caller_slot(B), Cap::reply(tcb(A).get(), false, false));
    send_caps(&mut w, B, REPLY, 0, 2, &[S_FRAME_RW]);
    assert_eq!(got(&w, A), (2, 0, 0, 1));
    assert!(w.cap(cnode2(5)).is_null());
}

#[test]
fn a_reply_pointer_that_does_not_resolve_moves_nothing_and_is_no_fault() {
    for number in [REPLY, REPLY_RECV] {
        let mut w = called(S_EP0);
        w.set_fault_ep(B, S_EP1);
        send_caps(&mut w, B, number, S_EP2, 3, &[S_FRAME_RW, BAD_CPTR]);
        assert_eq!(w.state(A), ThreadState::Running);
        assert_eq!(got(&w, A), (3, 0, 0, 1));
        assert!(w.cap(cnode2(5)).is_null());
        // B goes on: it replied, then (ReplyRecv) waits on EP2.
        assert_eq!(w.k.fault(tcb(B)), None);
        let expect = if number == REPLY {
            ThreadState::Running
        } else {
            ThreadState::BlockedOnReceive {
                ep: ep(2),
                can_grant: true,
            }
        };
        assert_eq!(w.state(B), expect);
    }
}

#[test]
fn a_saved_reply_capability_carries_capabilities_by_its_grant() {
    for (on, extra) in [(S_EP0, 1), (S_EP0_R, 0)] {
        let mut w = called(on);
        let cap = w.caller_slot(B);
        cdt::move_slot(&mut w.k, cap, tcb(B).slot(TCB_SLOT_CALLER), rs(29));
        send_caps(&mut w, B, SEND, 29, 4, &[S_FRAME_RO]);
        assert_eq!(got(&w, A), (4, 0, extra, 1));
        assert_eq!(w.cap(cnode2(5)).is_null(), extra == 0);
        assert!(w.cap(rs(29)).is_null());
    }
}

#[test]
fn a_reply_through_a_saved_capability_may_fill_the_slot_it_was_saved_in() {
    // `docs/design.md`, IPC, "Compared with seL4": a reply deletes its
    // reply capability before it transfers, so when the server saved that
    // capability in the very slot the caller named as its receive slot,
    // the copy lands there (seL4's `doReplyTransfer` transfers first, finds
    // the slot full and moves nothing).
    let mut w = World::new();
    w.recv(B, S_EP0);
    offer(&mut w, A, INTO_ROOT);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    let reply = w.caller_slot(B);
    assert_eq!(reply, Cap::reply(tcb(A).get(), false, true));
    w.call(B, S_ROOT, label::CNODE_SAVE_CALLER, 2, [S_FREE, 64, 0, 0]);
    assert_eq!(w.regs(B).rsi, info(0, 0));
    assert_eq!(w.cap(rs(S_FREE)), reply);
    verify(&w);
    send_caps(&mut w, B, SEND, S_FREE, 4, &[S_FRAME_RW]);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!((w.regs(A).rdi, got(&w, A)), (0, (4, 0, 1, 1)));
    assert_eq!(w.cap(rs(S_FREE)), frame(FRAME_RW, RW));
    assert_eq!(parent(&w, rs(S_FREE)), Some(rs(S_FRAME_RW)));
    assert!(!cdt::has_children(
        &w.k,
        tcb(A).slot(crate::cap::TCB_SLOT_REPLY)
    ));
    assert_eq!(w.state(B), ThreadState::Running);
}

#[test]
fn fault_messages_and_fault_replies_move_no_capability() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP1);
    offer(&mut w, D, INTO_ROOT);
    w.recv(D, S_EP1);
    // A's own buffer names a capability; a fault message ignores it.
    offer(&mut w, A, INTO_CNODE2);
    name_caps(&mut w, A, &[S_FRAME_RW]);
    w.exception(A, 14, 0x4, 0xdead_beef);
    verify(&w);
    let m = MessageInfo::from_word(w.regs(D).rsi);
    assert_eq!((m.label(), m.extra_caps(), m.caps_unwrapped()), (5, 0, 0));
    assert!(w.cap(rs(S_FREE)).is_null());
    // D replies with label 0, naming a capability, through a reply
    // capability with Grant: A restarts and gets nothing.
    assert_eq!(w.caller_slot(D), Cap::reply(tcb(A).get(), false, true));
    send_caps(&mut w, D, REPLY, 0, 0, &[S_FRAME_RO]);
    assert_eq!(w.state(A), ThreadState::Restart);
    assert!(w.cap(cnode2(5)).is_null());
    assert_eq!(w.k.fault(tcb(A)), None);
}

// ---------------------------------------------------------------------------
// Random sends against a model
// ---------------------------------------------------------------------------

/// What a pointer in `caps_or_badges` names.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    FrameRw,
    FrameRo,
    Untyped,
    Cnode2,
    TcbF,
    Ep0,
    Ep0Badged,
    Ep0R,
    Ep1,
    Empty,
    /// Does not resolve.
    Bad,
}

impl Src {
    const ALL: [Src; 11] = [
        Src::FrameRw,
        Src::FrameRo,
        Src::Untyped,
        Src::Cnode2,
        Src::TcbF,
        Src::Ep0,
        Src::Ep0Badged,
        Src::Ep0R,
        Src::Ep1,
        Src::Empty,
        Src::Bad,
    ];

    fn cptr(self) -> u64 {
        match self {
            Src::FrameRw => S_FRAME_RW,
            Src::FrameRo => S_FRAME_RO,
            Src::Untyped => S_UNTYPED,
            Src::Cnode2 => S_CNODE2,
            Src::TcbF => S_TCB + F as u64,
            Src::Ep0 => S_EP0,
            Src::Ep0Badged => S_EP0_BADGED,
            Src::Ep0R => S_EP0_R,
            Src::Ep1 => S_EP1,
            Src::Empty => S_EMPTY,
            Src::Bad => BAD_CPTR,
        }
    }

    /// The endpoint it is a capability to, and its badge.
    fn endpoint(self) -> Option<(usize, u64)> {
        match self {
            Src::Ep0 | Src::Ep0R => Some((0, 0)),
            Src::Ep0Badged => Some((0, BADGE)),
            Src::Ep1 => Some((1, 0)),
            _ => None,
        }
    }

    /// The slot a copy of it derives from: the source if it is an original,
    /// else the source's parent.
    fn parent(self) -> u64 {
        match self {
            Src::Ep0R => S_EP0,
            s => s.cptr(),
        }
    }
}

/// The capability a sender sends with: (slot, endpoint, badge, Grant).
const SEND_CAPS: [(u64, usize, u64, bool); 5] = [
    (S_EP0, 0, 0, true),
    (S_EP0_BADGED, 0, BADGE, true),
    (S_EP0_W, 0, 0, false),
    (S_EP0_WGR, 0, 0, false),
    (S_EP1, 1, 0, true),
];

/// Receive slots: valid and empty, then unusable.
const RECV_SLOTS: [RecvSlot; 6] = [
    INTO_ROOT,
    INTO_CNODE2,
    (S_ROOT, S_EP1, 64),
    (S_EP1, S_FREE, 64),
    (S_ROOT, S_FREE, 63),
    (BAD_CPTR, S_FREE, 64),
];

#[derive(Clone, Debug)]
struct Case {
    sender: usize,
    receiver: usize,
    send_cap: usize,
    call: bool,
    /// The receiver waits first; otherwise the sender queues first.
    receiver_first: bool,
    caps: Vec<Src>,
    /// For a sender that queued: pointer `i` becomes this before the
    /// receiver arrives.
    change: Option<(usize, Src)>,
    recv_slot: usize,
}

/// A pointer, mostly to a capability that resolves.
fn src() -> impl Strategy<Value = Src> {
    prop_oneof![
        9 => prop::sample::select(&Src::ALL[..9]),
        1 => Just(Src::Empty),
        1 => Just(Src::Bad),
    ]
}

/// A send, weighted towards the ones whose capabilities may move: a sender
/// with a buffer, a receiver with a writable one, Grant, some pointers, a
/// usable receive slot.
fn case() -> impl Strategy<Value = Case> {
    let sender = prop_oneof![4 => Just(A), 4 => Just(B), 2 => Just(E), 1 => Just(F)];
    let receiver = prop_oneof![5 => Just(C), 5 => Just(D), 1 => Just(E), 1 => Just(F)];
    let send_cap = prop_oneof![
        3 => Just(0usize),
        3 => Just(1),
        1 => Just(2),
        1 => Just(3),
        3 => Just(4),
    ];
    let caps = prop_oneof![
        1 => Just(Vec::new()),
        6 => prop::collection::vec(src(), 1..=3),
    ];
    let recv_slot = prop_oneof![3 => Just(0usize), 3 => Just(1), 2 => 2..RECV_SLOTS.len()];
    (
        sender,
        receiver,
        send_cap,
        any::<bool>(),
        any::<bool>(),
        caps,
        prop::option::weighted(0.3, (0..3usize, src())),
        recv_slot,
    )
        .prop_map(
            |(sender, receiver, send_cap, call, receiver_first, caps, change, recv_slot)| Case {
                sender,
                receiver: if receiver == sender { C } else { receiver },
                send_cap,
                // A capability with neither Grant nor GrantReply cannot Call.
                call: call && SEND_CAPS[send_cap].0 != S_EP0_W,
                receiver_first,
                caps,
                change,
                recv_slot,
            },
        )
}

/// What the model says the receiver gets: `caps_unwrapped`, `extra_caps`,
/// each unwrapped entry's badge, and the capability copied, if any.
#[derive(Debug, Default, PartialEq, Eq)]
struct Expect {
    unwrapped: u64,
    extra: u64,
    badges: [Option<u64>; 3],
    copied: Option<Src>,
}

/// The model of `docs/design.md`, "Capability transfer", over [`Src`].
fn model(c: &Case, at_transfer: &[Src]) -> Expect {
    let (_, through, _, grant) = SEND_CAPS[c.send_cap];
    let mut x = Expect::default();
    let readable = c.sender != F;
    let writable = matches!(c.receiver, A..=D);
    if !grant || at_transfer.is_empty() || !readable || !writable {
        return x;
    }
    if at_transfer.contains(&Src::Bad) {
        return x;
    }
    let mut slot = c.recv_slot < 2;
    for (i, &s) in at_transfer.iter().enumerate() {
        match s.endpoint() {
            Some((ep, badge)) if ep == through => {
                x.unwrapped |= 1 << i;
                x.badges[i] = Some(badge);
            }
            _ if slot && s != Src::Empty => {
                x.copied = Some(s);
                slot = false;
            }
            _ => break,
        }
        x.extra += 1;
    }
    x
}

fn run_case(c: &Case) {
    let mut w = World::new();
    let (cptr, through, badge, _) = SEND_CAPS[c.send_cap];
    let recv_on = if through == 0 { S_EP0 } else { S_EP1 };
    let slot = RECV_SLOTS[c.recv_slot];
    if c.receiver != F {
        offer(&mut w, c.receiver, slot);
    }
    let before: Vec<(SlotAddr, Cap)> = all_slots().into_iter().map(|s| (s, w.cap(s))).collect();
    let number = if c.call { CALL } else { SEND };
    let ptrs: Vec<u64> = c.caps.iter().map(|s| s.cptr()).collect();
    if c.receiver_first {
        w.recv(c.receiver, recv_on);
        verify(&w);
    }
    let out = send_caps(&mut w, c.sender, number, cptr, 0x4C, &ptrs);
    // The send-time lookup: a pointer that does not resolve faults, and
    // with no fault handler the sender stops. Nothing is sent.
    if c.sender != F && c.caps.contains(&Src::Bad) {
        assert!(matches!(out, Outcome::Stopped(_)), "{out:?}");
        assert_eq!(w.state(c.sender), ThreadState::Inactive);
        let after: Vec<(SlotAddr, Cap)> = all_slots().into_iter().map(|s| (s, w.cap(s))).collect();
        assert_eq!(before, after);
        return;
    }
    assert_eq!(out, Outcome::Done);
    let mut at_transfer = c.caps.clone();
    if !c.receiver_first {
        assert!(matches!(
            w.state(c.sender),
            ThreadState::BlockedOnSend { .. }
        ));
        if let Some((i, s)) = c.change
            && i < at_transfer.len()
            && c.sender != F
        {
            at_transfer[i] = s;
            w.set_buf(c.sender, word::CAPS_OR_BADGES + i, s.cptr());
        }
        w.run(c.receiver);
        w.recv(c.receiver, recv_on);
        verify(&w);
    }
    let x = model(c, &at_transfer);
    // The receiver's registers and buffer.
    let r = c.receiver;
    assert_eq!(w.state(r), ThreadState::Running);
    assert_eq!(w.regs(r).rdi, badge);
    assert_eq!(got(&w, r), (0x4C, x.unwrapped, x.extra, 1));
    if r != F {
        for (i, b) in x.badges.iter().enumerate() {
            let want = b.unwrap_or(UNTOUCHED + i as u64);
            assert_eq!(w.buf(r, word::CAPS_OR_BADGES + i), want, "entry {i}");
        }
    }
    let want_sender = if c.call {
        ThreadState::BlockedOnReply
    } else {
        ThreadState::Running
    };
    assert_eq!(w.state(c.sender), want_sender);
    // Every slot as before, but for the copy and an untyped's watermark.
    let dest = x.copied.map(|_| recv_slot_addr(slot));
    for (s, old) in before {
        let now = w.cap(s);
        let want = if Some(s) == dest {
            let src = x.copied.unwrap();
            let c = w.k.load(rs(src.cptr())).cap;
            if src == Src::Untyped {
                Cap::untyped(UNTYPED, 12, false, 0)
            } else {
                c
            }
        } else if x.copied == Some(Src::Untyped) && s == rs(S_UNTYPED) {
            Cap::untyped(UNTYPED, 12, false, 1 << 12)
        } else if s == tcb(r).slot(TCB_SLOT_CALLER) && c.call {
            // The receiver received with Grant.
            Cap::reply(tcb(c.sender).get(), false, true)
        } else {
            old
        };
        assert_eq!(now, want, "slot {:#x}", s.get());
    }
    if let (Some(d), Some(src)) = (dest, x.copied) {
        assert_eq!(parent(&w, d), Some(rs(src.parent())));
    }
    verify(&w);
}

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 1024 },
        // No files: Miri forbids them.
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn random_sends_move_capabilities_where_the_model_says(c in case()) {
        run_case(&c);
    }
}

#[test]
fn the_model_gives_what_the_rules_say() {
    // A case the proptest covers: the frame is copied, the badge unwrapped.
    let c = Case {
        sender: A,
        receiver: C,
        send_cap: 1,
        call: true,
        receiver_first: false,
        caps: std::vec![Src::FrameRw, Src::Ep0Badged],
        change: None,
        recv_slot: 1,
    };
    let x = model(&c, &c.caps);
    assert_eq!(
        x,
        Expect {
            unwrapped: 0b10,
            extra: 2,
            badges: [None, Some(BADGE), None],
            copied: Some(Src::FrameRw),
        }
    );
    run_case(&c);
    // The receiver must be one with a writable buffer, and Grant is needed.
    assert_eq!(
        model(
            &Case {
                receiver: E,
                ..c.clone()
            },
            &c.caps
        ),
        Expect::default()
    );
    assert_eq!(
        model(
            &Case {
                send_cap: 3,
                ..c.clone()
            },
            &c.caps
        ),
        Expect::default()
    );
    // A pointer that fails at transfer moves nothing.
    let bad = [Src::FrameRw, Src::Bad];
    assert_eq!(model(&c, &bad), Expect::default());
}
