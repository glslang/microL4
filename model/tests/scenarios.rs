//! Hand-written scenarios, each run against the kernel and the model at
//! once: every step goes through `World::apply`, which compares the two and
//! checks the invariants, and the tests then check what the specification
//! says the end state must be.

use l4core::cap::{Cap, CapType, MAX_DERIVATION_DEPTH, Rights, TCB_SLOT_CSPACE, TCB_SLOT_REPLY};
use l4core::error::SyscallError;
use l4core::slot::SlotAddr;
use l4core::testing::Event;
use l4core::untyped::RetypeArgs;
use l4model::harness::{Action, Config, Outcome, World, boot, cnode_slot, root_slot};
use l4model::model::slot_at;

const UNTYPED: u64 = 0;
const TCB: u64 = 1;
const ENDPOINT: u64 = 2;
const NOTIFICATION: u64 = 3;
const CNODE: u64 = 4;
const FRAME_4K: u64 = 5;

fn run(w: &mut World, a: Action, schedule: &[u8]) -> Result<(), SyscallError> {
    match w.apply(&a, schedule) {
        Ok(Outcome::Done(r)) => r,
        Ok(other) => panic!("{a:?} returned {other:?}"),
        Err(e) => panic!("{e}"),
    }
}

fn ok(w: &mut World, a: Action) {
    ok_preempted(w, a, &[]);
}

/// Runs `a` with a preemption schedule (see `World::apply`) and expects it to
/// succeed.
fn ok_preempted(w: &mut World, a: Action, schedule: &[u8]) {
    assert_eq!(run(w, a, schedule), Ok(()), "{a:?}");
}

fn retype(
    untyped: SlotAddr,
    dest: Cap,
    object_type: u64,
    size_bits: u64,
    node_offset: u64,
    num_objects: u64,
) -> Action {
    Action::Retype {
        untyped,
        dest,
        args: RetypeArgs {
            object_type,
            size_bits,
            node_offset,
            num_objects,
        },
    }
}

fn big() -> SlotAddr {
    root_slot(boot::BIG_UNTYPED)
}

/// A preemption schedule that preempts at every preemption point.
const EVERY_POINT: [u8; 4096] = [0; 4096];

fn is_zombie_for(cap: Cap, container: Cap) -> bool {
    cap.cap_type() == CapType::Zombie && cap.object() == container.object()
}

/// CNode A holds the only capability to B in its slot 0, and B holds the
/// only capability to C in its slot 0 and an endpoint in slot 1. Deleting A
/// clears A; B's capability, met by a nested deletion, turns into a Zombie
/// in B's own slot 0, which then deletes C's capability the same way. B and
/// C stay, unreachable, until a revoke of their untyped reaches the Zombies.
#[test]
fn nested_cnode_deletion_with_a_cnode_in_slot_0() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, CNODE, 2, 10, 3));
    ok(&mut w, retype(big(), root, ENDPOINT, 0, 13, 1));
    let (a, b, c) = (
        w.m.cap(root_slot(10)),
        w.m.cap(root_slot(11)),
        w.m.cap(root_slot(12)),
    );
    let ep = w.m.cap(root_slot(13));
    ok(
        &mut w,
        Action::Move {
            src: root_slot(12),
            dst: cnode_slot(b, 0),
        },
    );
    ok(
        &mut w,
        Action::Move {
            src: root_slot(13),
            dst: cnode_slot(b, 1),
        },
    );
    ok(
        &mut w,
        Action::Move {
            src: root_slot(11),
            dst: cnode_slot(a, 0),
        },
    );

    ok_preempted(
        &mut w,
        Action::Delete {
            slot: root_slot(10),
        },
        &EVERY_POINT,
    );
    assert!(w.preemptions > 0);
    assert!(w.m.cap(root_slot(10)).is_null());
    assert!((0..4).all(|i| w.m.cap(cnode_slot(a, i)).is_null()));
    assert!(is_zombie_for(w.m.cap(cnode_slot(b, 0)), b));
    assert_eq!(
        w.m.cap(cnode_slot(b, 1)),
        ep,
        "a detached CNode is not cleared"
    );
    assert!(is_zombie_for(w.m.cap(cnode_slot(c, 0)), c));
    assert!(
        !w.last_events
            .iter()
            .any(|e| matches!(e, Event::Finalise { cap, .. } if *cap == ep))
    );

    ok_preempted(&mut w, Action::Revoke { slot: big() }, &EVERY_POINT);
    for cnode in [a, b, c] {
        assert!((0..4).all(|i| w.m.cap(cnode_slot(cnode, i)).is_null()));
    }
    assert!(w.last_events.contains(&Event::Finalise {
        cap: ep,
        last: true
    }));
    assert!(!w.m.has_children(big()));
}

/// A mapped Frame in slot 0 of a nested CNode B, whose only capability is
/// in CNode A: deleting A swaps B's Zombie into B's slot 0, moving the frame
/// out to A's slot, where it is deleted. `moved` keeps its back-reference
/// exact at every preemption point, and `finalise` finds it still in place.
#[test]
fn nested_deletion_moves_a_mapped_capability_out_of_slot_0() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, CNODE, 2, 10, 2));
    let (a, b) = (w.m.cap(root_slot(10)), w.m.cap(root_slot(11)));
    ok(&mut w, retype(big(), b, FRAME_4K, 0, 0, 1));
    ok(
        &mut w,
        Action::SetMapping {
            slot: cnode_slot(b, 0),
            record: 0x5_0001,
        },
    );
    let frame = w.m.cap(cnode_slot(b, 0));
    ok(
        &mut w,
        Action::Move {
            src: root_slot(11),
            dst: cnode_slot(a, 1),
        },
    );

    ok_preempted(
        &mut w,
        Action::Delete {
            slot: root_slot(10),
        },
        &EVERY_POINT,
    );
    assert!(w.last_events.contains(&Event::Moved {
        cap: frame,
        from: cnode_slot(b, 0),
        to: cnode_slot(a, 1)
    }));
    assert!(w.last_events.contains(&Event::Finalise {
        cap: frame,
        last: true
    }));
    assert!(is_zombie_for(w.m.cap(cnode_slot(b, 0)), b));
}

/// A CNode holding the only capability to itself, in slot 2 and then in slot
/// 0, is unreachable; revoking its untyped destroys it.
#[test]
fn cnode_holding_the_only_capability_to_itself() {
    for own_slot in [2, 0] {
        let mut w = World::new(&Config::default());
        let root = w.root;
        ok(&mut w, retype(big(), root, CNODE, 2, 10, 1));
        let a = w.m.cap(root_slot(10));
        ok(&mut w, retype(big(), a, NOTIFICATION, 0, 1, 1));
        let ntfn = w.m.cap(cnode_slot(a, 1));
        ok(
            &mut w,
            Action::Move {
                src: root_slot(10),
                dst: cnode_slot(a, own_slot),
            },
        );
        assert!(!w.reachable().contains(&cnode_slot(a, 1)));

        ok_preempted(&mut w, Action::Revoke { slot: big() }, &EVERY_POINT);
        assert!((0..4).all(|i| w.m.cap(cnode_slot(a, i)).is_null()));
        assert!(w.last_events.contains(&Event::Finalise {
            cap: ntfn,
            last: true
        }));
        assert!(!w.m.has_children(big()));
    }
}

/// Deleting the last TCB capability finalises the TCB, then its Zombie
/// clears its five slots, the reply master in slot 3 among them.
#[test]
fn tcb_deleted_with_its_reply_master() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, TCB, 0, 10, 1));
    let tcb = w.m.cap(root_slot(10));
    let master = Cap::reply(tcb.object(), true, true);
    assert_eq!(w.m.cap(slot_at(tcb.object(), TCB_SLOT_REPLY)), master);
    assert_eq!(w.m.parent(slot_at(tcb.object(), TCB_SLOT_REPLY)), None);
    // A CSpace root, as TCB_Configure will install it, and a second TCB
    // capability.
    ok(
        &mut w,
        Action::DeriveInto {
            src: root_slot(boot::ROOT_COPY),
            dst: slot_at(tcb.object(), TCB_SLOT_CSPACE),
        },
    );
    ok(
        &mut w,
        Action::Copy {
            src: root_slot(10),
            dst: root_slot(11),
            rights: 0xF,
        },
    );

    ok(
        &mut w,
        Action::Delete {
            slot: root_slot(11),
        },
    );
    assert!(w.last_events.contains(&Event::Finalise {
        cap: tcb,
        last: false
    }));

    ok_preempted(
        &mut w,
        Action::Delete {
            slot: root_slot(10),
        },
        &EVERY_POINT,
    );
    assert!((0..5).all(|i| w.m.cap(slot_at(tcb.object(), i)).is_null()));
    assert!(w.last_events.contains(&Event::Finalise {
        cap: tcb,
        last: true
    }));
    assert!(w.last_events.contains(&Event::Finalise {
        cap: master,
        last: true
    }));
    // The installed CNode capability was not the last one.
    assert!(!w.m.cap(root_slot(boot::ROOT_COPY)).is_null());
}

/// An untyped's children sit inside CNodes made from it, and two of those
/// CNodes hold the only capabilities to each other. Revoking the untyped
/// removes everything, and the next retype resets it.
#[test]
fn revoke_untyped_whose_children_sit_in_cnodes_made_from_it() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, UNTYPED, 16, 10, 1));
    let v = root_slot(10);
    ok(&mut w, retype(v, root, CNODE, 3, 11, 1));
    let c1 = w.m.cap(root_slot(11));
    ok(&mut w, retype(v, c1, CNODE, 2, 0, 1));
    let c2 = w.m.cap(cnode_slot(c1, 0));
    ok(&mut w, retype(v, c1, ENDPOINT, 0, 1, 3));
    ok(&mut w, retype(v, c2, TCB, 0, 1, 1));
    ok(&mut w, retype(v, c2, NOTIFICATION, 0, 2, 1));
    ok(
        &mut w,
        Action::Mint {
            src: cnode_slot(c1, 1),
            dst: root_slot(12),
            rights: 0x3,
            data: 5,
        },
    );
    ok(
        &mut w,
        Action::Copy {
            src: root_slot(12),
            dst: root_slot(13),
            rights: 0xF,
        },
    );
    ok(
        &mut w,
        Action::Move {
            src: root_slot(11),
            dst: cnode_slot(c2, 3),
        },
    );
    let watermark = w.m.cap(v).watermark();

    ok_preempted(&mut w, Action::Revoke { slot: v }, &EVERY_POINT);
    assert!(!w.m.has_children(v));
    assert_eq!(
        w.m.cap(v).watermark(),
        watermark,
        "revoke leaves the watermark"
    );
    for slot in [11, 12, 13] {
        assert!(w.m.cap(root_slot(slot)).is_null());
    }

    ok(&mut w, retype(v, root, FRAME_4K, 0, 11, 1));
    assert!(
        w.last_events
            .iter()
            .any(|e| matches!(e, Event::Zero { .. }))
    );
    assert_eq!(w.m.cap(root_slot(11)).object(), w.m.cap(v).object());
}

/// Copying an untyped and deleting the source, over and over, drives the
/// copy to `MAX_DERIVATION_DEPTH`; then every child it would have is
/// refused with `IllegalOperation`.
#[test]
fn copy_delete_chain_to_max_derivation_depth() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, UNTYPED, 4, 10, 1));
    let (mut here, mut there) = (root_slot(10), root_slot(11));
    for _ in 1..MAX_DERIVATION_DEPTH {
        ok(
            &mut w,
            Action::Copy {
                src: here,
                dst: there,
                rights: 0,
            },
        );
        ok(&mut w, Action::Delete { slot: here });
        (here, there) = (there, here);
    }
    assert_eq!(w.m.entry(here).unwrap().depth, MAX_DERIVATION_DEPTH);
    let refused = Err(SyscallError::IllegalOperation);
    assert_eq!(
        run(
            &mut w,
            Action::Copy {
                src: here,
                dst: there,
                rights: 0xF
            },
            &[]
        ),
        refused
    );
    assert_eq!(
        run(
            &mut w,
            Action::Mint {
                src: here,
                dst: there,
                rights: 0xF,
                data: 9
            },
            &[]
        ),
        refused
    );
    assert_eq!(
        run(&mut w, retype(here, root, UNTYPED, 4, 20, 1), &[]),
        refused
    );
    // The holder of an ancestor can still revoke it.
    ok(&mut w, Action::Revoke { slot: big() });
    assert!(w.m.cap(here).is_null());
}

/// Checks that a revoke run with `schedule` was a partial revoke, cut short
/// if `schedule` preempts it: it returned its restart's failed lookup,
/// stopped where the unpreempted revoke passed its preemption point `stop`,
/// and left the Zombies `zombies` where the model's end state holds
/// something else.
fn cut_short(
    w: &World,
    r: Result<(), SyscallError>,
    schedule: &[u8],
    stop: u64,
    zombies: &[(SlotAddr, Cap)],
) {
    assert_eq!(w.partial_revokes, 1, "{schedule:?}");
    if schedule.is_empty() {
        assert_eq!(r, Ok(()));
        assert_eq!(w.cut_short, 0);
        return;
    }
    assert!(
        matches!(r, Err(SyscallError::FailedLookup { .. })),
        "{schedule:?}: {r:?}"
    );
    let p = w.last_partial.as_ref().expect("cut short");
    assert_eq!(p.error, r.unwrap_err());
    assert!(p.stops.contains(&stop), "{schedule:?}: {p:?}");
    assert_eq!(p.zombies, zombies, "{schedule:?}");
}

/// An untyped moved into a CNode C made from it, then revoked through C's
/// only capability: the revoke deletes the two endpoints, then C's
/// capability, whose clearing deletes the untyped's own slot. That is
/// seL4's partial revoke (`docs/design.md`, "Slot operations").
/// Unpreempted, it destroys C. Preempted at every point, its first two
/// restarts look the slot up again and go on; once C's capability is a
/// Zombie, the restart cannot look the slot up through it, so the call
/// returns that failure and leaves C's Zombie half-cleared where its
/// capability was, a slot the user can name: where the unpreempted revoke
/// passed its third preemption point.
#[test]
fn partial_revoke_of_an_untyped_inside_a_cnode_made_from_it() {
    for schedule in [&[][..], &EVERY_POINT[..]] {
        let mut w = World::new(&Config::default());
        let root = w.root;
        let small = root_slot(boot::SMALL_UNTYPED);
        ok(&mut w, retype(small, root, CNODE, 3, 10, 1));
        let c = w.m.cap(root_slot(10));
        ok(&mut w, retype(small, root, ENDPOINT, 0, 11, 2));
        ok(
            &mut w,
            Action::Move {
                src: small,
                dst: cnode_slot(c, 4),
            },
        );

        let r = run(
            &mut w,
            Action::Revoke {
                slot: cnode_slot(c, 4),
            },
            schedule,
        );
        let zombie = Cap::zombie(c.object(), c.size_bits(), 7, false);
        cut_short(&w, r, schedule, 2, &[(root_slot(10), zombie)]);
        for slot in [10, 11, 12] {
            assert!(w.m.cap(root_slot(slot)).is_null());
        }
        assert!((0..8).all(|i| w.m.cap(cnode_slot(c, i)).is_null()));
    }
}

/// CNodes C and D hold each other's only capabilities, C's in D's slot 0.
/// Revoking their untyped deletes C's capability first: clearing C meets
/// D's last capability, whose Zombie is swapped into D's slot 0, which is
/// the slot being deleted. That slot now holds D's Zombie (seL4's
/// "self-referential" case), so that deletion ends; D's Zombie is the
/// untyped's descendant too, so the revoke reaches it next and clears D.
#[test]
fn cnodes_holding_each_others_only_capabilities() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, CNODE, 2, 10, 2));
    // The second object made is the untyped's first child.
    let (d, c) = (w.m.cap(root_slot(10)), w.m.cap(root_slot(11)));
    let irq = root_slot(boot::IRQ_HANDLER);
    ok(
        &mut w,
        Action::Copy {
            src: irq,
            dst: cnode_slot(d, 1),
            rights: 0,
        },
    );
    ok(
        &mut w,
        Action::Move {
            src: root_slot(11),
            dst: cnode_slot(d, 0),
        },
    );
    ok(
        &mut w,
        Action::Move {
            src: root_slot(10),
            dst: cnode_slot(c, 3),
        },
    );
    assert!(!w.reachable().contains(&cnode_slot(c, 0)));

    ok_preempted(&mut w, Action::Revoke { slot: big() }, &EVERY_POINT);
    for cnode in [c, d] {
        assert!((0..4).all(|i| w.m.cap(cnode_slot(cnode, i)).is_null()));
    }
    let swapped_in = w.last_events.iter().any(|e| {
        matches!(e, Event::Moved { cap, from, to }
            if cap.cap_type() == CapType::Zombie && cap.object() == d.object()
                && *from == cnode_slot(c, 3) && *to == cnode_slot(d, 0))
    });
    assert!(swapped_in, "D's Zombie never went into D's slot 0");
    let copy = w.m.cap(irq);
    assert!(w.last_events.contains(&Event::Finalise {
        cap: copy,
        last: false
    }));
}

/// A revoke whose own slot is slot 0 of a CNode D, named through C's only
/// capability and D's, which lies in C's slot 1: the revoke destroys C, a
/// partial revoke. Clearing C, the nested deletion of D's capability swaps
/// D's Zombie into the revoked slot and the untyped being revoked into C's
/// slot 1, where it is deleted. Unpreempted, the revoke goes on to destroy
/// C and leaves D detached. Preempted after C's first step, its restart
/// cannot look the slot up through C's Zombie and returns, leaving that
/// Zombie in C's last capability's slot, where the unpreempted revoke
/// passed its first preemption point.
#[test]
fn revoke_whose_slot_receives_a_zombie() {
    for schedule in [&[][..], &EVERY_POINT[..]] {
        let mut w = World::new(&Config::default());
        let root = w.root;
        ok(&mut w, retype(big(), root, UNTYPED, 12, 10, 1));
        ok(&mut w, retype(root_slot(10), root, CNODE, 2, 11, 1));
        ok(&mut w, retype(big(), root, CNODE, 2, 12, 1));
        let (c, d) = (w.m.cap(root_slot(11)), w.m.cap(root_slot(12)));
        ok(
            &mut w,
            Action::Move {
                src: root_slot(10),
                dst: cnode_slot(d, 0),
            },
        );
        ok(
            &mut w,
            Action::Move {
                src: root_slot(12),
                dst: cnode_slot(c, 1),
            },
        );

        let r = run(
            &mut w,
            Action::Revoke {
                slot: cnode_slot(d, 0),
            },
            schedule,
        );
        let zombie = Cap::zombie(c.object(), c.size_bits(), 3, false);
        cut_short(&w, r, schedule, 0, &[(root_slot(11), zombie)]);
        assert!(is_zombie_for(w.m.cap(cnode_slot(d, 0)), d));
        assert!(w.m.cap(root_slot(11)).is_null());
        assert!((0..4).all(|i| w.m.cap(cnode_slot(c, i)).is_null()));
    }
}

/// The shape of a random failure: CNodes C, from an untyped U made from the
/// big untyped, and D, from the big untyped itself, hold each other's only
/// capabilities, C's in D's slot 0. Revoking U deletes C's capability there;
/// clearing C meets D's last capability, whose Zombie the nested deletion
/// swaps into D's slot 0, the slot being deleted. D's Zombie is not U's
/// descendant, so a restarted revoke could not go on clearing D: the
/// deletion ends there, preempted or not, and D stays detached, its
/// endpoint alive, until a revoke of the big untyped reaches its Zombie.
#[test]
fn revoke_through_a_cycle_leaves_the_other_cnode_detached() {
    let schedules: [&[u8]; 9] = [
        &[],
        &[0],
        &[1],
        &[2],
        &[3],
        &[4],
        &[5],
        &[2, 4],
        &EVERY_POINT,
    ];
    for schedule in schedules {
        let mut w = World::new(&Config::default());
        let root = w.root;
        ok(&mut w, retype(big(), root, UNTYPED, 12, 10, 1));
        ok(&mut w, retype(root_slot(10), root, CNODE, 1, 11, 1));
        ok(&mut w, retype(big(), root, CNODE, 2, 12, 1));
        let (c, d) = (w.m.cap(root_slot(11)), w.m.cap(root_slot(12)));
        ok(&mut w, retype(big(), d, ENDPOINT, 0, 1, 1));
        let endpoint = w.m.cap(cnode_slot(d, 1));
        ok(
            &mut w,
            Action::Move {
                src: root_slot(11),
                dst: cnode_slot(d, 0),
            },
        );
        ok(
            &mut w,
            Action::Move {
                src: root_slot(12),
                dst: cnode_slot(c, 0),
            },
        );

        ok_preempted(
            &mut w,
            Action::Revoke {
                slot: root_slot(10),
            },
            schedule,
        );
        let zombie = w.m.cap(cnode_slot(d, 0));
        assert!(is_zombie_for(zombie, d), "{schedule:?}: {zombie:?}");
        assert_eq!(zombie.zombie_slots(), 4, "{schedule:?}");
        assert_eq!(w.m.cap(cnode_slot(d, 1)), endpoint, "{schedule:?}");
        assert!((0..2).all(|i| w.m.cap(cnode_slot(c, i)).is_null()));
        assert_eq!(w.partial_revokes, 0);

        ok_preempted(&mut w, Action::Revoke { slot: big() }, schedule);
        assert!((0..4).all(|i| w.m.cap(cnode_slot(d, i)).is_null()));
        assert!(w.last_events.contains(&Event::Finalise {
            cap: endpoint,
            last: true
        }));
    }
}

/// Review of 2c60870: the cycle of the test above, where D's Zombie,
/// swapped into the slot being deleted, has one slot left. A revoke cut
/// short leaves such a Zombie in the kernel (`l4core`'s test
/// `a_revoke_through_a_cycle_leaves_a_removable_zombie_the_same_preempted_or_not`),
/// the atomic model never does, so the scenario plants it: D's last
/// capability, in C's slot 1, becomes D's Zombie counting 1, and C's only
/// capability, from the big untyped, lies in D's slot 0. Revoking the big
/// untyped deletes it: clearing C swaps D's Zombie into D's slot 0 and C's
/// Zombie into C's slot 1, and a preemption point falls before C's Zombie
/// moves on to C's slot 0. seL4 would go on to find D's Zombie removable
/// and empty D's slot 0 unless preempted there, since the restart finds C's
/// Zombie in C's slot 1 and never comes back to D's slot 0.
/// `docs/design.md` ("Deletion and finalisation", step 3) says D's Zombie
/// stays, preempted or not.
#[test]
fn revoke_through_a_cycle_leaves_a_removable_zombie_alone() {
    let mut schedules: Vec<Vec<u8>> = (0..8).map(|p| vec![p]).collect();
    schedules.push(Vec::new());
    schedules.push(EVERY_POINT.to_vec());
    for schedule in &schedules {
        let mut w = World::new(&Config::default());
        let root = w.root;
        let small = root_slot(boot::SMALL_UNTYPED);
        ok(&mut w, retype(big(), root, CNODE, 1, 10, 1));
        ok(&mut w, retype(small, root, CNODE, 1, 11, 1));
        let (c, d) = (w.m.cap(root_slot(10)), w.m.cap(root_slot(11)));
        for (src, dst) in [
            (root_slot(11), cnode_slot(c, 1)),
            (root_slot(10), cnode_slot(d, 0)),
        ] {
            ok(&mut w, Action::Move { src, dst });
        }
        w.leave_zombie(cnode_slot(c, 1), 1);

        ok_preempted(&mut w, Action::Revoke { slot: big() }, schedule);
        assert_eq!(w.partial_revokes, 0);
        assert!((0..2).all(|i| w.m.cap(cnode_slot(c, i)).is_null()));
        let zombie = w.m.cap(cnode_slot(d, 0));
        assert!(
            is_zombie_for(zombie, d) && zombie.zombie_slots() == 1,
            "{schedule:?}: D's slot 0 holds {zombie:?}"
        );
    }
}

/// The shape of the random failure behind 2c60870 (seed `266cf27d`): the
/// big untyped U, revoked from slot `u` of a CNode C made from it, named
/// through the root's capability to C, while C's last capability lies in C
/// itself. The revoke deletes the root's capability, which destroys its
/// slot's lookup path, then C's last one, whose clearing deletes U's slot: a
/// partial revoke (`docs/design.md`, "Slot operations"). Unpreempted, it
/// ends as seL4's does:
///
/// - C's last capability in slot 3, U in slot 1. Deleting that capability
///   swaps C's Zombie into C's slot 0, out of every user's reach, and the
///   revoke goes on to clear C from there, deleting U, so C is destroyed.
/// - The same with U in slot 2 and, in slot 1, an endpoint from the small
///   untyped, which goes with C.
/// - C of two slots, its last capability in slot 1, U in slot 0. The
///   nested deletion swaps C's Zombie into U's slot and deletes U; C stays
///   detached in its slot 0, under no untyped, a dead region.
///
/// Preempted at any of its points, all after its first step, its restart
/// fails to look the slot up and the call returns that failure, leaving
/// what the unpreempted revoke had at that point. Mostly that is C's
/// Zombie, part-cleared, in C's slot 0, and deleting it would finish the
/// work. At two points no Delete of a Zombie would finish it as the
/// uninterrupted call does:
///
/// - right after the first step: no Zombie yet, and U and C's last
///   capability stay in C, which no lookup reaches;
/// - in the third shape, right after the nested swap: C's Zombie in C's
///   slot 0 is the model's already, and U waits in C's slot 1 for the
///   nested deletion to delete it.
#[test]
fn revoke_that_destroys_its_own_slot_is_a_partial_revoke() {
    let mut schedules: Vec<Vec<u8>> = (0..12).map(|p| vec![p]).collect();
    schedules.push(Vec::new());
    schedules.push(EVERY_POINT.to_vec());
    // (radix, C's last capability, U, endpoint, C's Zombie's count after)
    let shapes = [
        (2, 3, 1, None, None),
        (2, 3, 2, Some(1), None),
        (1, 1, 0, None, Some(2)),
    ];
    for (radix, last, u, endpoint, left) in shapes {
        for schedule in &schedules {
            let mut w = World::new(&Config::default());
            let root = w.root;
            ok(&mut w, retype(big(), root, CNODE, radix, 10, 1));
            let c = w.m.cap(root_slot(10));
            if let Some(i) = endpoint {
                let small = root_slot(boot::SMALL_UNTYPED);
                ok(&mut w, retype(small, c, ENDPOINT, 0, i, 1));
            }
            ok(
                &mut w,
                Action::Copy {
                    src: root_slot(10),
                    dst: cnode_slot(c, last),
                    rights: 0xF,
                },
            );
            ok(
                &mut w,
                Action::Move {
                    src: big(),
                    dst: cnode_slot(c, u),
                },
            );

            let ep = endpoint.map(|i| w.m.cap(cnode_slot(c, i)));
            let what = format!("U in slot {u}, schedule {schedule:?}");
            let r = run(
                &mut w,
                Action::Revoke {
                    slot: cnode_slot(c, u),
                },
                schedule,
            );
            assert_eq!(w.partial_revokes, 1, "{what}");
            let points = if u == 0 { 4 } else { 8 };
            if w.cut_short == 0 {
                // Past the revoke's last preemption point.
                assert_eq!(r, Ok(()), "{what}");
                assert!(schedule.first().is_none_or(|&p| p >= points), "{what}");
            } else {
                let p = w.last_partial.as_ref().unwrap();
                assert_eq!(r, Err(p.error), "{what}");
                // The first restart already fails.
                assert!(p.stops.contains(&u64::from(schedule[0])), "{what}: {p:?}");
                assert_eq!(p.points, u64::from(points), "{what}");
                assert!(
                    p.zombies
                        .iter()
                        .all(|&(at, z)| at == cnode_slot(c, 0) && is_zombie_for(z, c)),
                    "{what}: {p:?}"
                );
                // The two points listed above: no Zombie differs from the
                // model's.
                if schedule[0] == 0 || (u == 0 && schedule[0] == 1) {
                    assert!(p.zombies.is_empty(), "{what}: {p:?}");
                }
            }
            assert!(w.m.cap(root_slot(10)).is_null(), "{what}");
            assert!(w.m.cap(big()).is_null(), "{what}");
            let zombie = w.m.cap(cnode_slot(c, 0));
            match left {
                None => assert!(zombie.is_null(), "{what}: {zombie:?}"),
                Some(n) => {
                    assert!(is_zombie_for(zombie, c), "{what}: {zombie:?}");
                    assert_eq!(zombie.zombie_slots(), n, "{what}");
                }
            }
            assert!((1..1 << radix).all(|i| w.m.cap(cnode_slot(c, i)).is_null()));
            if let Some(ep) = ep {
                assert!(w.last_events.contains(&Event::Finalise {
                    cap: ep,
                    last: true
                }));
            }
        }
    }
}

/// A Frame's mapping record, written as `l4core::vspace` will write it:
/// Copy and Mint make unmapped copies, Move and Mutate carry it.
#[test]
fn frame_copies_are_unmapped() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, FRAME_4K, 0, 10, 1));
    ok(
        &mut w,
        Action::SetMapping {
            slot: root_slot(10),
            record: 0xABC1,
        },
    );
    ok(
        &mut w,
        Action::Copy {
            src: root_slot(10),
            dst: root_slot(11),
            rights: 0x1,
        },
    );
    assert_eq!(w.m.cap(root_slot(11)).data, 0);
    assert_eq!(w.m.cap(root_slot(11)).rights(), Rights::WRITE);
    ok(
        &mut w,
        Action::Mint {
            src: root_slot(10),
            dst: root_slot(12),
            rights: 0xF,
            data: 77,
        },
    );
    assert_eq!(w.m.cap(root_slot(12)).data, 0);
    ok(
        &mut w,
        Action::Mutate {
            src: root_slot(10),
            dst: root_slot(13),
            data: 5,
        },
    );
    assert_eq!(w.m.cap(root_slot(13)).data, 0xABC1);
    ok(
        &mut w,
        Action::Move {
            src: root_slot(13),
            dst: root_slot(14),
        },
    );
    assert_eq!(w.m.cap(root_slot(14)).data, 0xABC1);
    ok(
        &mut w,
        Action::Delete {
            slot: root_slot(14),
        },
    );
}

/// Rotate with the destination equal to the source swaps two capabilities,
/// each with its place in the derivation tree, and applies each data word.
#[test]
fn rotate_as_a_swap() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok(&mut w, retype(big(), root, CNODE, 2, 10, 1));
    ok(&mut w, retype(big(), root, UNTYPED, 12, 11, 1));
    ok(&mut w, retype(root_slot(11), root, ENDPOINT, 0, 12, 1));
    let (cnode, ut) = (w.m.cap(root_slot(10)), w.m.cap(root_slot(11)));
    let guard = 3 | (5 << 6);

    ok(
        &mut w,
        Action::Rotate {
            dst: root_slot(10),
            dst_data: 0x1234,
            pivot: root_slot(11),
            pivot_data: guard,
            src: root_slot(10),
        },
    );
    assert_eq!(
        w.m.cap(root_slot(10)),
        ut,
        "the untyped ignores its data word"
    );
    let moved = w.m.cap(root_slot(11));
    assert_eq!(
        (moved.object(), moved.guard_size(), moved.guard()),
        (cnode.object(), 3, 5)
    );
    assert_eq!(
        w.m.parent(root_slot(12)),
        Some(root_slot(10)),
        "children follow their parent"
    );
    let moves = w
        .last_events
        .iter()
        .filter(|e| matches!(e, Event::Moved { .. }))
        .count();
    assert_eq!(moves, 2);

    // A parent and its first child, list neighbours, swap too.
    ok(&mut w, retype(root_slot(10), root, CNODE, 1, 13, 1));
    let (ut, child) = (w.m.cap(root_slot(10)), w.m.cap(root_slot(13)));
    ok(
        &mut w,
        Action::Rotate {
            dst: root_slot(10),
            dst_data: 0,
            pivot: root_slot(13),
            pivot_data: 0,
            src: root_slot(10),
        },
    );
    assert_eq!(
        (w.m.cap(root_slot(10)), w.m.cap(root_slot(13))),
        (child, ut)
    );
    assert_eq!(w.m.parent(root_slot(10)), Some(root_slot(13)));
    assert_eq!(w.m.parent(root_slot(12)), Some(root_slot(13)));

    // Mutate data on an endpoint is refused, whatever the word.
    let rotate_ep = Action::Rotate {
        dst: root_slot(12),
        dst_data: 0,
        pivot: root_slot(11),
        pivot_data: 0,
        src: root_slot(12),
    };
    assert_eq!(
        run(&mut w, rotate_ep, &[]),
        Err(SyscallError::IllegalOperation)
    );
}

/// The first retype of the 2 MiB boot untyped clears it in 512 chunks; with
/// a preemption at every point it restarts 511 times and completes.
#[test]
fn preempted_reset_of_a_large_untyped_restarts_to_completion() {
    let mut w = World::new(&Config::default());
    let root = w.root;
    ok_preempted(
        &mut w,
        retype(big(), root, FRAME_4K, 0, 10, 2),
        &EVERY_POINT,
    );
    assert!(w.preemptions >= 500, "only {} preemptions", w.preemptions);
    let frame = w.m.cap(root_slot(10));
    assert_eq!(frame.rights(), Rights(Rights::WRITE.0 | Rights::READ.0));
    assert_eq!(w.m.cap(big()).watermark(), 2 << 12);

    // With children the watermark only rises: no reset.
    ok_preempted(
        &mut w,
        retype(big(), root, FRAME_4K, 0, 12, 1),
        &EVERY_POINT,
    );
    assert_eq!(w.preemptions, 0);
    assert!(
        !w.last_events
            .iter()
            .any(|e| matches!(e, Event::Zero { .. }))
    );
    assert_eq!(w.m.cap(root_slot(12)).object(), frame.object() + (2 << 12));
}

/// Lookups through the root, with and without a guard, reach every root
/// slot, and a 64-bit capability lookup with a zero-size guard is defined.
#[test]
fn lookups_with_guards() {
    for (gs, guard) in [(0, 0), (3, 0b101), (59, 0)] {
        let mut w = World::new(&Config {
            root_guard_size: gs,
            root_guard: guard,
            ..Config::default()
        });
        let root = w.root;
        for i in 0..32u64 {
            let cptr = (guard << 5) | i;
            let a = Action::Lookup {
                root,
                cptr,
                depth: (gs + 5) as u64,
                source: false,
            };
            match w.apply(&a, &[]).unwrap() {
                Outcome::Lookup { slot, .. } => assert_eq!(slot, Ok(root_slot(i))),
                other => panic!("{other:?}"),
            }
            let top = cptr << (64 - gs - 5);
            w.apply(
                &Action::Lookup {
                    root,
                    cptr: top,
                    depth: 64,
                    source: true,
                },
                &[],
            )
            .unwrap();
        }
    }
}
