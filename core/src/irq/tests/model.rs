//! The IRQ table proptest: random issues, copies, deletions, revokes of
//! IRQControl, Acks, `SetNotification`s, `Clear`s, polls of the bound
//! notifications, stale Remote IRRs and device line changes, run through
//! system calls against [`crate::testing::FakeIoApic`], and compared after
//! every step with a model of the table written from `docs/design.md`'s
//! rules. Every pending interrupt is taken at the end of each kernel entry,
//! as the CPU does once it returns with IF = 1; a line change can instead
//! fall inside the next entry, so that its interrupt is pending while that
//! entry runs (a deletion, say).
//!
//! After every step: the table, the bindings and the notification words
//! equal the model's; every issued pin's entry has its vector, its trigger
//! and a mask bit equal to `masked`; every other pin is masked; no pin was
//! unmasked with Remote IRR set; an edge pin delivered at most three
//! interrupts and a level pin one between two Acks; and [`check`] holds.

use std::collections::BTreeMap;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use super::*;

/// The GSIs the sequences use: COM1's (edge), 9 (level on q35) and two
/// PCI-range GSIs.
const GSIS: [u32; 4] = [4, 9, 16, 17];
/// Handler slots: root slots 25 to 29.
const HANDLERS: u64 = 5;
/// A Read capability to notification 1, for polls.
const S_N1_READ: u64 = 30;
/// The vector a stranded pin names: IRQ 191's, which no sequence issues.
const STRAND_VECTOR: u8 = 0xEF;

#[derive(Clone, Copy, Debug)]
enum Op {
    /// `GetIOAPIC(gsi, level, high)`, or `GetISA` of the same IRQ for GSIs
    /// 4 and 9 with their routes' trigger.
    Issue {
        gsi: usize,
        level: bool,
        isa: bool,
        slot: u64,
    },
    Copy {
        src: u64,
        dst: u64,
    },
    Delete {
        slot: u64,
    },
    Revoke,
    Ack {
        slot: u64,
    },
    Set {
        slot: u64,
        n: usize,
    },
    Clear {
        slot: u64,
    },
    /// A polls notification `n`.
    Poll {
        n: usize,
    },
    /// A free GSI's pin is left with a stale Remote IRR.
    Strand {
        gsi: usize,
    },
    /// The device drives `gsi`'s line; with `defer` the change falls inside
    /// the next kernel entry, whose end takes its interrupt.
    Line {
        gsi: usize,
        high: bool,
        defer: bool,
    },
}

fn op() -> impl Strategy<Value = Op> {
    let slot = 0..HANDLERS;
    let gsi = 0..GSIS.len();
    prop_oneof![
        3 => (gsi.clone(), any::<bool>(), any::<bool>(), slot.clone())
            .prop_map(|(gsi, level, isa, slot)| Op::Issue { gsi, level, isa, slot }),
        1 => (slot.clone(), slot.clone()).prop_map(|(src, dst)| Op::Copy { src, dst }),
        2 => slot.clone().prop_map(|slot| Op::Delete { slot }),
        1 => Just(Op::Revoke),
        4 => slot.clone().prop_map(|slot| Op::Ack { slot }),
        2 => (slot.clone(), 0..2usize).prop_map(|(slot, n)| Op::Set { slot, n }),
        1 => slot.prop_map(|slot| Op::Clear { slot }),
        2 => (0..2usize).prop_map(|n| Op::Poll { n }),
        1 => gsi.clone().prop_map(|gsi| Op::Strand { gsi }),
        8 => (gsi, any::<bool>(), any::<bool>())
            .prop_map(|(gsi, high, defer)| Op::Line { gsi, high, defer }),
    ]
}

/// The model's view of one issued IRQ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M {
    gsi: u32,
    level: bool,
    pending: bool,
    masked: bool,
    /// The notification bound, 0 or 1.
    bound: Option<usize>,
    /// Interrupts delivered since the last Ack or the issue.
    since_ack: u32,
}

#[derive(Default)]
struct Model {
    irqs: BTreeMap<u8, M>,
    /// Handler slot (0 to 4) to IRQ.
    slots: BTreeMap<u64, u8>,
    /// Each notification's word, if Active.
    words: [Option<u64>; 2],
}

impl Model {
    fn holder(&self, gsi: u32) -> Option<u8> {
        self.irqs
            .iter()
            .find(|(_, m)| m.gsi == gsi)
            .map(|(&i, _)| i)
    }

    fn lowest_free(&self) -> u8 {
        (0..IRQS as u8)
            .find(|i| !self.irqs.contains_key(i))
            .unwrap()
    }

    /// Slot `slot` loses its handler; the IRQ is freed with its last.
    fn drop_slot(&mut self, slot: u64) {
        if let Some(irq) = self.slots.remove(&slot)
            && !self.slots.values().any(|&i| i == irq)
        {
            self.irqs.remove(&irq);
        }
    }
}

/// The paths sequences took, counted.
#[derive(Clone, Copy, Debug, Default)]
struct Paths {
    issued: u32,
    cleared_stale: u32,
    signalled: u32,
    lost: u32,
    stale: u32,
    masked_edge: u32,
    masked_level: u32,
    unmasked_by_ack: u32,
    deleted_pending: u32,
    most_between_acks: u32,
}

const BADGES: [u64; 2] = [B0, B1];
const NTFN_SLOTS: [u64; 2] = [S_N0_BADGED, S_N1];
const POLL_SLOTS: [u64; 2] = [S_N0, S_N1_READ];

fn handler(slot: u64) -> u64 {
    S_H + slot
}

/// Takes every interrupt the local APIC holds, as the CPU does once the
/// kernel returns with IF = 1: delivery, EOI, the scheduler.
fn drain(w: &mut World, m: &mut Model, p: &mut Paths) {
    for _ in 0..32 {
        let Some(v) = w.k.dev.take() else {
            return;
        };
        let irq = irq_of_vector(v).unwrap();
        let want = match m.irqs.get_mut(&irq) {
            None => Delivery::Stale,
            Some(e) => {
                let mask = e.level || e.pending;
                if mask && !e.masked {
                    if e.level {
                        p.masked_level += 1;
                    } else {
                        p.masked_edge += 1;
                    }
                }
                e.masked |= mask;
                e.pending |= !e.level;
                e.since_ack += 1;
                p.most_between_acks = p.most_between_acks.max(e.since_ack);
                let most = if e.level { 1 } else { 3 };
                assert!(
                    e.since_ack <= most,
                    "IRQ {irq}: {} between Acks",
                    e.since_ack
                );
                match e.bound {
                    Some(n) => {
                        m.words[n] = Some(m.words[n].unwrap_or(0) | BADGES[n]);
                        Delivery::Signalled
                    }
                    None => Delivery::Lost,
                }
            }
        };
        match want {
            Delivery::Stale => p.stale += 1,
            Delivery::Lost => p.lost += 1,
            Delivery::Signalled => p.signalled += 1,
        }
        assert_eq!(deliver(&mut w.k, irq), want, "vector {v:#x}");
        w.k.dev.eoi(v);
        w.exit();
    }
    panic!("interrupts never stopped");
}

/// Compares the kernel with the model, and checks the invariants.
fn compare(w: &World, m: &Model) {
    checked(w);
    for irq in 0..IRQS as u8 {
        let e = entry(w, irq);
        let node = node(w, irq);
        match m.irqs.get(&irq) {
            None => assert_eq!((e, node), (Entry::FREE, Cap::NULL), "IRQ {irq}"),
            Some(x) => {
                let Source::IoApic { gsi, level, .. } = e.source else {
                    panic!("IRQ {irq} is free; the model has {x:?}")
                };
                assert_eq!(
                    (gsi, level, e.pending, e.masked),
                    (x.gsi, x.level, x.pending, x.masked),
                    "IRQ {irq}"
                );
                let bound = NotificationCap::from_cap(&node).map(|n| n.badge);
                assert_eq!(bound, x.bound.map(|n| BADGES[n]), "IRQ {irq}'s binding");
                let low = rte(w, gsi).0;
                assert_eq!(low & 0xFF, u32::from(vector(irq)), "GSI {gsi}'s vector");
                assert_eq!(
                    low & apic::REDIRECTION_LEVEL != 0,
                    x.level,
                    "GSI {gsi}'s trigger"
                );
                assert_eq!(
                    low & apic::REDIRECTION_MASKED != 0,
                    x.masked,
                    "GSI {gsi}'s mask"
                );
            }
        }
    }
    for gsi in 0..24 {
        if m.holder(gsi).is_none() {
            assert!(masked(w, gsi), "GSI {gsi} is unmasked but not issued");
        }
    }
    for s in 0..HANDLERS {
        let want = m.slots.get(&s).map_or(Cap::NULL, |&i| handler_cap(i));
        assert_eq!(w.cap(rs(handler(s))), want, "handler slot {s}");
    }
    for (n, want) in m.words.iter().enumerate() {
        let got = nt(w, n);
        match want {
            Some(word) => assert_eq!((got.state, got.word), (NtfnState::Active, *word), "N{n}"),
            None => assert_eq!(got.state, NtfnState::Idle, "N{n}"),
        }
    }
}

fn run(version: u8, ops: &[Op]) -> Paths {
    let mut w = world(version);
    cdt::insert_derived(
        &mut w.k,
        rs(S_N1),
        rs(S_N1_READ),
        ntfn_cap(1, Rights::READ, 0),
        false,
    )
    .unwrap();
    let mut m = Model::default();
    let mut p = Paths::default();
    let mut deferred = false;
    for &op in ops {
        let pending_before = !w.k.dev.lapic_irr.is_empty();
        let mut defer = false;
        match op {
            Op::Issue {
                gsi,
                level,
                isa,
                slot,
            } => {
                let g = GSIS[gsi];
                let s = handler(slot);
                let isa = isa && matches!(g, 4 | 9);
                let level = if isa { g == 9 } else { level };
                let stale = apic::remote_irr(rte(&w, g).0);
                let r = if isa {
                    get_isa(&mut w, u64::from(g), s)
                } else {
                    get_ioapic(&mut w, u64::from(g), u64::from(level), 0, s)
                };
                let want = if m.holder(g).is_some() {
                    error(SyscallError::RevokeFirst)
                } else if m.slots.contains_key(&slot) {
                    error(SyscallError::DeleteFirst)
                } else {
                    let irq = m.lowest_free();
                    m.irqs.insert(
                        irq,
                        M {
                            gsi: g,
                            level,
                            pending: false,
                            masked: false,
                            bound: None,
                            since_ack: 0,
                        },
                    );
                    m.slots.insert(slot, irq);
                    p.issued += 1;
                    if stale {
                        p.cleared_stale += 1;
                    }
                    if isa {
                        ok(&[u64::from(irq), u64::from(g), u64::from(level)])
                    } else {
                        ok(&[u64::from(irq)])
                    }
                };
                assert_eq!(r, want, "{op:?}");
            }
            Op::Copy { src, dst } => {
                let r = invoke(
                    &mut w,
                    A,
                    S_ROOT,
                    cnode_label::CNODE_COPY,
                    &[handler(dst), 64, handler(src), 64, 0xF],
                    &[S_ROOT],
                );
                let want = match (m.slots.get(&src).copied(), m.slots.contains_key(&dst)) {
                    (_, true) => error(SyscallError::DeleteFirst),
                    (None, false) => error(SyscallError::FailedLookup {
                        source: true,
                        failure: LookupFailure::MissingCapability { bits_left: 0 },
                    }),
                    (Some(irq), false) => {
                        m.slots.insert(dst, irq);
                        ok(&[])
                    }
                };
                assert_eq!(r, want, "{op:?}");
            }
            Op::Delete { slot } => {
                if pending_before && m.slots.contains_key(&slot) {
                    p.deleted_pending += 1;
                }
                delete(&mut w, handler(slot));
                m.drop_slot(slot);
            }
            Op::Revoke => {
                let r = invoke(
                    &mut w,
                    A,
                    S_ROOT,
                    cnode_label::CNODE_REVOKE,
                    &[S_CONTROL, 64],
                    &[],
                );
                assert_eq!(r, ok(&[]));
                m.slots.clear();
                m.irqs.clear();
            }
            Op::Ack { slot } => {
                let r = ack(&mut w, handler(slot));
                match m.slots.get(&slot).and_then(|i| m.irqs.get_mut(i)) {
                    None => assert_eq!(r, error(SyscallError::InvalidCapability(0))),
                    Some(e) => {
                        assert_eq!(r, ok(&[]));
                        if e.masked {
                            p.unmasked_by_ack += 1;
                        }
                        e.pending = false;
                        e.masked = false;
                        e.since_ack = 0;
                    }
                }
            }
            Op::Set { slot, n } => {
                let r = set_ntfn(&mut w, handler(slot), NTFN_SLOTS[n]);
                match m.slots.get(&slot).and_then(|i| m.irqs.get_mut(i)) {
                    None => assert_eq!(r, error(SyscallError::InvalidCapability(0))),
                    Some(e) => {
                        assert_eq!(r, ok(&[]));
                        e.bound = Some(n);
                    }
                }
            }
            Op::Clear { slot } => {
                let r = clear(&mut w, handler(slot));
                match m.slots.get(&slot).and_then(|i| m.irqs.get_mut(i)) {
                    None => assert_eq!(r, error(SyscallError::InvalidCapability(0))),
                    Some(e) => {
                        assert_eq!(r, ok(&[]));
                        e.bound = None;
                    }
                }
            }
            Op::Poll { n } => {
                w.nbrecv(A, POLL_SLOTS[n]);
                assert_eq!(
                    (w.regs(A).rdi, w.regs(A).rsi),
                    (m.words[n].take().unwrap_or(0), 0)
                );
            }
            Op::Strand { gsi } => {
                let g = GSIS[gsi];
                if m.holder(g).is_none() {
                    let (io, pin) = w.k.dev.pin_mut(g);
                    io.strand(pin, STRAND_VECTOR);
                }
            }
            Op::Line {
                gsi,
                high,
                defer: d,
            } => {
                w.k.dev.set_line(GSIS[gsi], high);
                defer = d;
            }
        }
        // The entry ends: unless the line change falls inside the next one,
        // the CPU takes what is pending. A deferred one is taken now.
        if !defer || deferred {
            drain(&mut w, &mut m, &mut p);
        }
        deferred = defer;
        if !deferred {
            compare(&w, &m);
        }
    }
    drain(&mut w, &mut m, &mut p);
    compare(&w, &m);
    p
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_irq_operations_and_interrupts_match_the_model(
        qemu in any::<bool>(),
        ops in proptest::collection::vec(op(), 1..if cfg!(miri) { 16 } else { 80 }),
    ) {
        run(if qemu { QEMU } else { HYPERV }, &ops);
    }
}

#[test]
fn random_sequences_reach_every_path() {
    let mut runner = TestRunner::new_with_rng(
        Config {
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let cases = if cfg!(miri) { 2 } else { 128 };
    let mut t = Paths::default();
    for i in 0..cases {
        let ops = proptest::collection::vec(op(), 80)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let p = run(if i % 2 == 0 { QEMU } else { HYPERV }, &ops);
        t.issued += p.issued;
        t.cleared_stale += p.cleared_stale;
        t.signalled += p.signalled;
        t.lost += p.lost;
        t.stale += p.stale;
        t.masked_edge += p.masked_edge;
        t.masked_level += p.masked_level;
        t.unmasked_by_ack += p.unmasked_by_ack;
        t.deleted_pending += p.deleted_pending;
        t.most_between_acks = t.most_between_acks.max(p.most_between_acks);
    }
    if cfg!(miri) {
        return;
    }
    for (what, n) in [
        ("issued", t.issued),
        ("cleared a stale Remote IRR", t.cleared_stale),
        ("signalled", t.signalled),
        ("lost an interrupt", t.lost),
        ("dropped a stale one", t.stale),
        ("masked an edge pin", t.masked_edge),
        ("masked a level pin", t.masked_level),
        ("unmasked at Ack", t.unmasked_by_ack),
        ("deleted with an interrupt pending", t.deleted_pending),
    ] {
        assert!(n > 0, "no sequence {what}: {t:?}");
    }
    assert_eq!(t.most_between_acks, 2, "{t:?}");
}
