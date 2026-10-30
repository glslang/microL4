//! The differential property test: random operation sequences run against
//! `l4core` and the model, compared after every step (`PLAN.md`, M2).
//!
//! Operations are generated as intents ("copy a full slot to an empty one")
//! and resolved against the world as it is when they run, so most of them do
//! something and shrinking still works. Arguments lean towards the useful,
//! with enough invalid ones to reach every error path. Before an operation,
//! a preemption schedule may be armed; `World::apply` then checks the
//! invariants at every preemption point and restarts the operation until it
//! completes.
//!
//! 10,000 cases by default; `PROPTEST_CASES` overrides it. Failures persist
//! in `random.regressions` next to this file, which git ignores: a minimal
//! reproduction worth keeping becomes a named test in `scenarios.rs`.
//! `cargo test -p l4model --test random -- --ignored --nocapture` prints
//! what the generated sequences exercise.

use l4core::cap::{CapType, TCB_SLOT_IPC_BUFFER};
use l4core::slot::SlotAddr;
use l4core::untyped::RetypeArgs;
use l4model::harness::{Action, Config, Outcome, World, cnode_slot};
use l4model::model::slot_at;
use proptest::prelude::*;
use proptest::test_runner::FileFailurePersistence;

/// Which slots a selector prefers; it falls back to any reachable slot.
#[derive(Clone, Copy, Debug)]
enum Pick {
    Any,
    Full,
    Empty,
    Untyped,
    CNode,
    Tcb,
    Ipc,
    /// Frames and paging structures.
    Mapped,
}

/// A reachable slot: the `n`-th (modulo) of those `pick` prefers.
#[derive(Clone, Copy, Debug)]
struct Sel {
    pick: Pick,
    n: u16,
}

/// A destination CNode capability for retype, or a lookup root.
#[derive(Clone, Copy, Debug)]
enum Dest {
    Root,
    Slot(Sel),
}

/// A data word for Mint, Mutate and Rotate.
#[derive(Clone, Copy, Debug)]
enum Data {
    Zero,
    Badge(u64),
    Guard(u8, u64),
    Raw(u64),
}

impl Data {
    fn word(self) -> u64 {
        match self {
            Data::Zero => 0,
            Data::Badge(b) => b,
            Data::Guard(size, guard) => (size as u64 & 0x3F) | (guard << 6),
            Data::Raw(w) => w,
        }
    }
}

/// A retype's `node_offset`: the `n`-th run of enough empty slots in the
/// destination, if there is one, or a raw value.
#[derive(Clone, Copy, Debug)]
enum Offset {
    Free(u16),
    Raw(u64),
}

#[derive(Clone, Debug)]
enum Op {
    Copy {
        src: Sel,
        dst: Sel,
        rights: u64,
    },
    Mint {
        src: Sel,
        dst: Sel,
        rights: u64,
        data: Data,
    },
    Move {
        src: Sel,
        dst: Sel,
    },
    Mutate {
        src: Sel,
        dst: Sel,
        data: Data,
    },
    Rotate {
        dst: Sel,
        pivot: Sel,
        src: Sel,
        dst_data: Data,
        pivot_data: Data,
        swap: bool,
    },
    Delete {
        slot: Sel,
    },
    Revoke {
        slot: Sel,
    },
    Retype {
        untyped: Sel,
        dest: Dest,
        object_type: u64,
        size_bits: u64,
        node_offset: Offset,
        num_objects: u64,
    },
    /// A derived copy into TCB slot 0, 1 or 2, as `TCB_Configure` will.
    InstallInTcb {
        tcb: Sel,
        index: u8,
        src: Sel,
    },
    /// Moves or copies a capability into a slot of the CNode that `into`
    /// names, `src`'s own CNode included: CNodes inside CNodes, often in
    /// slot 0, and CNodes holding the only capability to themselves.
    Nest {
        src: Sel,
        into: Sel,
        index: u16,
        copy: bool,
    },
    Lookup {
        root: Dest,
        target: Sel,
        mode: u8,
        noise: u64,
        delta: i8,
        source: bool,
    },
    /// Copies a capability and deletes the source, `n` times.
    Chain {
        src: Sel,
        dst: Sel,
        n: u8,
    },
    /// Writes a mapping record into a Frame or paging structure capability.
    Map {
        slot: Sel,
        record: u64,
    },
}

fn pick(w: &World, reach: &[SlotAddr], sel: Sel) -> SlotAddr {
    let ty = |s: SlotAddr| w.m.cap(s).cap_type();
    let wanted = |s: &&SlotAddr| match sel.pick {
        Pick::Any => true,
        Pick::Full => ty(**s) != CapType::Null,
        Pick::Empty => ty(**s) == CapType::Null,
        Pick::Untyped => ty(**s) == CapType::Untyped,
        Pick::CNode => ty(**s) == CapType::CNode,
        Pick::Tcb => ty(**s) == CapType::Tcb,
        Pick::Ipc => matches!(ty(**s), CapType::Endpoint | CapType::Notification),
        Pick::Mapped => matches!(
            ty(**s),
            CapType::Frame | CapType::PageTable | CapType::PageDirectory | CapType::Pdpt
        ),
    };
    let preferred: Vec<SlotAddr> = reach.iter().filter(wanted).copied().collect();
    let pool = if preferred.is_empty() {
        reach
    } else {
        &preferred
    };
    pool[sel.n as usize % pool.len()]
}

/// Runs one generated operation: resolves it into actions and applies each.
fn exec(w: &mut World, op: &Op, schedule: &[u8]) -> Result<(), String> {
    let reach = w.reachable();
    let p = |sel| pick(w, &reach, sel);
    let action = match *op {
        Op::Copy { src, dst, rights } => Action::Copy {
            src: p(src),
            dst: p(dst),
            rights,
        },
        Op::Mint {
            src,
            dst,
            rights,
            data,
        } => Action::Mint {
            src: p(src),
            dst: p(dst),
            rights,
            data: data.word(),
        },
        Op::Move { src, dst } => Action::Move {
            src: p(src),
            dst: p(dst),
        },
        Op::Mutate { src, dst, data } => Action::Mutate {
            src: p(src),
            dst: p(dst),
            data: data.word(),
        },
        Op::Rotate {
            dst,
            pivot,
            src,
            dst_data,
            pivot_data,
            swap,
        } => {
            let src = p(src);
            Action::Rotate {
                dst: if swap { src } else { p(dst) },
                dst_data: dst_data.word(),
                pivot: p(pivot),
                pivot_data: pivot_data.word(),
                src,
            }
        }
        Op::Delete { slot } => Action::Delete { slot: p(slot) },
        Op::Revoke { slot } => Action::Revoke { slot: p(slot) },
        Op::Retype {
            untyped,
            dest,
            object_type,
            size_bits,
            node_offset,
            num_objects,
        } => {
            let untyped = p(untyped);
            if w.m.cap(untyped).cap_type() != CapType::Untyped {
                return Ok(());
            }
            let dest = match dest {
                Dest::Root => w.root,
                Dest::Slot(sel) => w.m.cap(p(sel)),
            };
            let node_offset = match node_offset {
                Offset::Raw(n) => n,
                Offset::Free(n) if dest.cap_type() == CapType::CNode && num_objects <= 64 => {
                    let slots = 1u64 << dest.radix();
                    let free = |i: u64| {
                        (i..i + num_objects).all(|j| w.m.cap(cnode_slot(dest, j)).is_null())
                    };
                    let runs: Vec<u64> = (0..slots.saturating_sub(num_objects.saturating_sub(1)))
                        .filter(|&i| free(i))
                        .collect();
                    runs.get(n as usize % runs.len().max(1))
                        .copied()
                        .unwrap_or(n as u64)
                }
                Offset::Free(n) => n as u64,
            };
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
        Op::InstallInTcb { tcb, index, src } => {
            let tcb = w.m.cap(p(tcb));
            let src = p(src);
            if tcb.cap_type() != CapType::Tcb {
                return Ok(());
            }
            let dst = slot_at(tcb.object(), index as u64 % (TCB_SLOT_IPC_BUFFER + 1));
            if !w.m.cap(dst).is_null() || w.m.cap(src).cap_type() == CapType::Untyped {
                return Ok(());
            }
            Action::DeriveInto { src, dst }
        }
        Op::Nest {
            src,
            into,
            index,
            copy,
        } => {
            let src = p(src);
            let cnode = w.m.cap(p(into));
            if cnode.cap_type() != CapType::CNode {
                return Ok(());
            }
            let dst = cnode_slot(cnode, index as u64 % (1 << cnode.radix()));
            if copy {
                Action::Copy {
                    src,
                    dst,
                    rights: 0xF,
                }
            } else {
                Action::Move { src, dst }
            }
        }
        Op::Lookup {
            root,
            target,
            mode,
            noise,
            delta,
            source,
        } => {
            let root = match root {
                Dest::Root => w.root,
                Dest::Slot(sel) => w.m.cap(p(sel)),
            };
            let paths: Vec<(u64, u32)> = w.paths(root).into_values().flatten().collect();
            let (cptr, depth) = if paths.is_empty() || mode % 4 == 3 {
                (noise, (delta as u8 % 70) as u64)
            } else {
                let (bits, n) = paths[target.n as usize % paths.len()];
                match mode % 4 {
                    0 => (bits, (n as i64 + (delta % 3) as i64).max(0) as u64),
                    1 if n < 64 => ((bits << (64 - n)) | (noise >> n), 64),
                    1 => (bits, 64),
                    _ => (bits ^ (1 << (noise % n as u64)), n as u64),
                }
            };
            let a = Action::Lookup {
                root,
                cptr,
                depth,
                source,
            };
            let got = w.apply(&a, schedule)?;
            // An exact path must lead where it was built to go.
            if mode % 4 == 0 && delta % 3 == 0 && !paths.is_empty() {
                let Outcome::Lookup { slot, .. } = got else {
                    unreachable!()
                };
                if slot.is_err() {
                    return Err(format!(
                        "{a:?}: the path built for a reachable slot failed: {slot:?}"
                    ));
                }
            }
            return Ok(());
        }
        Op::Map { slot, record } => {
            let slot = p(slot);
            let ty = w.m.cap(slot).cap_type();
            if !matches!(
                ty,
                CapType::Frame | CapType::PageTable | CapType::PageDirectory | CapType::Pdpt
            ) {
                return Ok(());
            }
            // Each record unique, so each mapped capability is.
            let record = (record << 16) | (w.steps & 0x7FFF) << 1 | 1;
            Action::SetMapping { slot, record }
        }
        Op::Chain { src, dst, n } => {
            let (mut here, mut there) = (p(src), p(dst));
            for _ in 0..n % 16 {
                let copy = Action::Copy {
                    src: here,
                    dst: there,
                    rights: 0xF,
                };
                if w.apply(&copy, &[])? != Outcome::Done(Ok(())) {
                    break;
                }
                w.apply(&Action::Delete { slot: here }, schedule)?;
                (here, there) = (there, here);
            }
            return Ok(());
        }
    };
    w.apply(&action, schedule).map(|_| ())
}

fn sel(picks: impl Strategy<Value = Pick>) -> impl Strategy<Value = Sel> {
    (picks, any::<u16>()).prop_map(|(pick, n)| Sel { pick, n })
}

fn source() -> impl Strategy<Value = Sel> {
    sel(prop_oneof![
        6 => Just(Pick::Full),
        2 => Just(Pick::Untyped),
        2 => Just(Pick::CNode),
        1 => Just(Pick::Tcb),
        2 => Just(Pick::Ipc),
        1 => Just(Pick::Mapped),
        1 => Just(Pick::Any),
    ])
}

fn target() -> impl Strategy<Value = Sel> {
    sel(prop_oneof![8 => Just(Pick::Empty), 1 => Just(Pick::Full), 1 => Just(Pick::Any)])
}

fn data() -> impl Strategy<Value = Data> {
    prop_oneof![
        3 => Just(Data::Zero),
        3 => (1u64..1000).prop_map(Data::Badge),
        3 => (0u8..=8, any::<u64>()).prop_map(|(s, g)| Data::Guard(s, g)),
        1 => (any::<u8>(), any::<u64>()).prop_map(|(s, g)| Data::Guard(s, g)),
        1 => any::<u64>().prop_map(Data::Raw),
    ]
}

fn rights() -> impl Strategy<Value = u64> {
    prop_oneof![3 => Just(0xF), 3 => 0u64..16, 1 => any::<u64>()]
}

fn dest() -> impl Strategy<Value = Dest> {
    prop_oneof![
        6 => Just(Dest::Root),
        6 => sel(Just(Pick::CNode)).prop_map(Dest::Slot),
        1 => sel(Just(Pick::Any)).prop_map(Dest::Slot),
    ]
}

/// What to delete: leaning towards containers, so deletions destroy them.
fn victim() -> impl Strategy<Value = Sel> {
    sel(prop_oneof![
        4 => Just(Pick::Full),
        4 => Just(Pick::CNode),
        2 => Just(Pick::Tcb),
        1 => Just(Pick::Untyped),
        1 => Just(Pick::Any),
    ])
}

/// An object type and a `size_bits` that suits it, mostly.
fn object() -> impl Strategy<Value = (u64, u64)> {
    let untyped = prop_oneof![
        6 => 4u64..=16,
        1 => 17u64..=21,
        1 => prop_oneof![0u64..4, 48u64..=64, Just(u64::MAX)],
    ];
    let radix = prop_oneof![
        12 => 1u64..=4,
        3 => 5u64..=8,
        1 => 9u64..=10,
        1 => prop_oneof![Just(0u64), 43u64..=64, Just(u64::MAX)],
    ];
    prop_oneof![
        3 => untyped.prop_map(|s| (0, s)),
        4 => radix.prop_map(|s| (4, s)),
        2 => any::<u64>().prop_map(|s| (1, s)),
        3 => any::<u64>().prop_map(|s| (2, s)),
        2 => any::<u64>().prop_map(|s| (3, s)),
        2 => any::<u64>().prop_map(|s| (5, s)),
        1 => any::<u64>().prop_map(|s| (6, s)),
        2 => (7u64..=10, any::<u64>()),
        1 => (prop_oneof![11u64..=40, Just(u64::MAX)], any::<u64>()),
    ]
}

fn op() -> impl Strategy<Value = Op> {
    let retype = (
        sel(Just(Pick::Untyped)),
        dest(),
        object(),
        prop_oneof![
            10 => any::<u16>().prop_map(Offset::Free),
            1 => (0u64..40).prop_map(Offset::Raw),
            1 => any::<u64>().prop_map(Offset::Raw),
        ],
        prop_oneof![10 => 1u64..=2, 3 => 3u64..=8, 1 => 9u64..=32, 1 => Just(0u64), 1 => 250u64..=260],
    )
        .prop_map(|(untyped, dest, (object_type, size_bits), node_offset, num_objects)| Op::Retype {
            untyped,
            dest,
            object_type,
            size_bits,
            node_offset,
            num_objects,
        });
    prop_oneof![
        20 => retype,
        10 => (source(), target(), rights()).prop_map(|(src, dst, rights)| Op::Copy { src, dst, rights }),
        10 => (source(), target(), rights(), data())
            .prop_map(|(src, dst, rights, data)| Op::Mint { src, dst, rights, data }),
        6 => (source(), target()).prop_map(|(src, dst)| Op::Move { src, dst }),
        5 => (source(), target(), data()).prop_map(|(src, dst, data)| Op::Mutate { src, dst, data }),
        5 => (target(), source(), source(), data(), data(), any::<bool>()).prop_map(
            |(dst, pivot, src, dst_data, pivot_data, swap)| Op::Rotate {
                dst,
                pivot,
                src,
                dst_data,
                pivot_data,
                swap,
            }
        ),
        12 => victim().prop_map(|slot| Op::Delete { slot }),
        7 => sel(prop_oneof![3 => Just(Pick::Untyped), 2 => Just(Pick::Full), 1 => Just(Pick::Any)])
            .prop_map(|slot| Op::Revoke { slot }),
        4 => (sel(Just(Pick::Tcb)), any::<u8>(), source())
            .prop_map(|(tcb, index, src)| Op::InstallInTcb { tcb, index, src }),
        12 => (
            sel(prop_oneof![4 => Just(Pick::CNode), 1 => Just(Pick::Tcb), 2 => Just(Pick::Full)]),
            sel(Just(Pick::CNode)),
            prop_oneof![2 => Just(0u16), 1 => any::<u16>()],
            prop::bool::weighted(0.2),
        )
            .prop_map(|(src, into, index, copy)| Op::Nest { src, into, index, copy }),
        8 => (
            dest(),
            sel(Just(Pick::Any)),
            any::<u8>(),
            any::<u64>(),
            prop_oneof![3 => Just(0i8), 1 => any::<i8>()],
            any::<bool>(),
        )
            .prop_map(
            |(root, target, mode, noise, delta, source)| Op::Lookup {
                root,
                target,
                mode,
                noise,
                delta,
                source,
            }
        ),
        2 => (source(), target(), any::<u8>()).prop_map(|(src, dst, n)| Op::Chain { src, dst, n }),
        3 => (sel(Just(Pick::Mapped)), any::<u64>()).prop_map(|(slot, record)| Op::Map { slot, record: record | 1 }),
    ]
}

/// A preemption schedule: mostly none, sometimes a few re-armings.
fn schedule() -> impl Strategy<Value = Vec<u8>> {
    prop_oneof![2 => Just(Vec::new()), 1 => prop::collection::vec(0u8..8, 1..6)]
}

fn config() -> impl Strategy<Value = Config> {
    (
        0u32..=4,
        any::<u64>(),
        prop::bool::weighted(0.25),
        any::<u64>(),
    )
        .prop_map(|(root_guard_size, root_guard, small_device, seed)| Config {
            root_guard_size,
            root_guard,
            small_device,
            seed,
        })
}

fn cases() -> u32 {
    std::env::var("PROPTEST_CASES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10_000)
}

/// What the generated sequences exercise: each action's kind and result,
/// and how much deletion work they did. Run with `--ignored --nocapture`.
#[test]
#[ignore]
fn coverage_report() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::TestRunner;
    use std::collections::BTreeMap;

    let mut runner = TestRunner::deterministic();
    let strategy = (config(), prop::collection::vec((op(), schedule()), 1..=40));
    let mut tally: BTreeMap<String, u64> = BTreeMap::new();
    let (mut steps, mut preempted, mut zombie_moves, mut max_slots, mut max_depth) =
        (0u64, 0u64, 0u64, 0usize, 0u32);
    let (mut abandoned, mut detached, mut tcb_deaths) = (0u64, 0u64, 0u64);
    let n = cases().min(2000);
    for _ in 0..n {
        let (cfg, ops) = strategy.new_tree(&mut runner).unwrap().current();
        let mut w = World::new(&cfg);
        w.tally = Some(BTreeMap::new());
        for (op, schedule) in &ops {
            let before = w.steps;
            exec(&mut w, op, schedule).unwrap();
            if w.steps > before {
                use l4core::testing::Event;
                preempted += w.preemptions;
                for e in &w.last_events {
                    match e {
                        Event::Moved { cap, .. } if cap.cap_type() == CapType::Zombie => {
                            zombie_moves += 1
                        }
                        Event::Finalise { cap, last: true } if cap.cap_type() == CapType::Tcb => {
                            tcb_deaths += 1
                        }
                        _ => {}
                    }
                }
            }
            max_slots = max_slots.max(w.reachable().len());
            max_depth = max_depth.max(w.m.entries().values().map(|e| e.depth).max().unwrap_or(0));
        }
        steps += w.steps;
        abandoned += w.abandoned;
        detached +=
            w.m.entries()
                .values()
                .filter(|e| e.cap.cap_type() == CapType::Zombie)
                .count() as u64;
        for (k, v) in w.tally.take().unwrap() {
            *tally.entry(k).or_default() += v;
        }
    }
    println!(
        "{n} cases, {steps} steps, {preempted} preemptions, {zombie_moves} Zombie moves (nested deletions), \
         {detached} detached containers left at the end, {tcb_deaths} TCBs finalised, {abandoned} partial revokes, \
         at most {max_slots} reachable slots, depth up to {max_depth}"
    );
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
    fn random_sequences_match_the_model(
        cfg in config(),
        ops in prop::collection::vec((op(), schedule()), 1..=40),
    ) {
        let mut w = World::new(&cfg);
        for (op, schedule) in &ops {
            exec(&mut w, op, schedule).map_err(TestCaseError::fail)?;
        }
    }
}
