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
//! From M9 the sequences also issue MSIs and, on the Hyper-V world, which
//! has a SynIC, SINTs (`GetMSI`, `GetSint`), have two model devices send
//! the MSI messages their drivers were told (also after the handler is
//! gone) and the hypervisor raise SINT edges; on QEMU's world `GetSint` is
//! `IllegalOperation`.
//!
//! After every step: the table, the bindings and the notification words
//! equal the model's; every issued pin's entry has its vector, its trigger
//! and a mask bit equal to `masked`; every other pin is masked; every
//! issued SINT holds its vector, unmasked, AutoEOI and polling off, and
//! every other SINT is masked; no pin was unmasked with Remote IRR set; an
//! edge pin delivered at most three interrupts and a level pin one between
//! two Acks; and [`check`] holds.

use std::collections::BTreeMap;
// `prop_oneof!` with more than ten arms builds a `vec!`.
use std::vec;

use proptest::prelude::*;
use proptest::strategy::ValueTree;
use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};

use super::*;
use crate::hyperv::{SINT_AUTO_EOI, SINT_MASKED, SINT_POLLING};
use crate::testing::FakeSynic;

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
    /// `GetMSI`, its message given to model device `device`.
    IssueMsi {
        device: usize,
        slot: u64,
    },
    /// `GetSint(sint)`.
    IssueSint {
        sint: u8,
        slot: u64,
    },
    /// Model device `device` sends the message it was last told, if any.
    Message {
        device: usize,
        defer: bool,
    },
    /// The hypervisor raises an edge on SINT `sint`.
    RaiseSint {
        sint: u8,
        defer: bool,
    },
}

/// The SINTs the sequences use.
const SEQ_SINTS: u8 = 3;

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
        1 => (0..2usize, 0..HANDLERS).prop_map(|(device, slot)| Op::IssueMsi { device, slot }),
        1 => (0..SEQ_SINTS, 0..HANDLERS).prop_map(|(sint, slot)| Op::IssueSint { sint, slot }),
        2 => (0..2usize, any::<bool>()).prop_map(|(device, defer)| Op::Message { device, defer }),
        2 => (0..SEQ_SINTS, any::<bool>()).prop_map(|(sint, defer)| Op::RaiseSint { sint, defer }),
    ]
}

/// Where a model IRQ comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Src {
    Pin { gsi: u32, level: bool },
    Msi,
    Sint(u8),
}

/// The model's view of one issued IRQ.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct M {
    src: Src,
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
    /// The vector each model MSI device was last told, kept after its
    /// handler goes: nothing tells the device.
    devices: [Option<u8>; 2],
    /// Vectors an MSI or a SINT edge made pending and the CPU has not
    /// taken. If an I/O APIC pin holds the vector by the time it is taken
    /// (a stale message, or a deferred one whose source was deleted and
    /// its vector reissued), the pin's driver gets a spurious signal, as
    /// the design accepts; it does not count against the pin's own
    /// interrupts between Acks.
    foreign: std::collections::BTreeSet<u8>,
}

impl Model {
    fn holder(&self, gsi: u32) -> Option<u8> {
        self.irqs
            .iter()
            .find(|(_, m)| matches!(m.src, Src::Pin { gsi: g, .. } if g == gsi))
            .map(|(&i, _)| i)
    }

    fn sint_holder(&self, sint: u8) -> Option<u8> {
        self.irqs
            .iter()
            .find(|(_, m)| m.src == Src::Sint(sint))
            .map(|(&i, _)| i)
    }

    fn issue(&mut self, slot: u64, src: Src) -> u8 {
        let irq = self.lowest_free();
        self.irqs.insert(
            irq,
            M {
                src,
                pending: false,
                masked: false,
                bound: None,
                since_ack: 0,
            },
        );
        self.slots.insert(slot, irq);
        irq
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
    msis_issued: u32,
    sints_issued: u32,
    /// GetSint refused on QEMU's world, which has no SynIC.
    sint_without_synic: u32,
    msi_signalled: u32,
    sint_signalled: u32,
    /// A message from a device whose handler is gone.
    stale_msi: u32,
    /// An edge on a masked SINT.
    lost_sint_edge: u32,
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
        let foreign = m.foreign.remove(&v);
        let mut src = None;
        let want = match m.irqs.get_mut(&irq) {
            None => Delivery::Stale,
            Some(e) => {
                src = Some(e.src);
                if let Src::Pin { level, .. } = e.src {
                    let mask = level || e.pending;
                    if mask && !e.masked {
                        if level {
                            p.masked_level += 1;
                        } else {
                            p.masked_edge += 1;
                        }
                    }
                    e.masked |= mask;
                    e.pending |= !level;
                    if !foreign {
                        e.since_ack += 1;
                        p.most_between_acks = p.most_between_acks.max(e.since_ack);
                        let most = if level { 1 } else { 3 };
                        assert!(
                            e.since_ack <= most,
                            "IRQ {irq}: {} between Acks",
                            e.since_ack
                        );
                    }
                }
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
        match (want, src) {
            (Delivery::Signalled, Some(Src::Msi)) => p.msi_signalled += 1,
            (Delivery::Signalled, Some(Src::Sint(_))) => p.sint_signalled += 1,
            _ => {}
        }
        assert_eq!(deliver(&mut w.k, irq), want, "vector {v:#x}");
        w.k.dev.eoi(v);
        w.exit();
    }
    panic!("interrupts never stopped");
}

/// Compares the kernel with the model, and checks the invariants. Under
/// Miri only the IRQs a sequence can issue (four GSIs, so IRQs 0 to 3) and
/// a few above are compared.
fn compare(w: &World, m: &Model) {
    checked(w);
    let irqs = if cfg!(miri) { 8 } else { IRQS as u8 };
    for irq in 0..irqs {
        let e = entry(w, irq);
        let node = node(w, irq);
        match m.irqs.get(&irq) {
            None => assert_eq!((e, node), (Entry::FREE, Cap::NULL), "IRQ {irq}"),
            Some(x) => {
                assert_eq!((e.pending, e.masked), (x.pending, x.masked), "IRQ {irq}");
                let bound = NotificationCap::from_cap(&node).map(|n| n.badge);
                assert_eq!(bound, x.bound.map(|n| BADGES[n]), "IRQ {irq}'s binding");
                match (x.src, e.source) {
                    (Src::Pin { gsi: g, level: l }, Source::IoApic { gsi, level, .. }) => {
                        assert_eq!((gsi, level), (g, l), "IRQ {irq}");
                        let low = rte(w, gsi).0;
                        assert_eq!(low & 0xFF, u32::from(vector(irq)), "GSI {gsi}'s vector");
                        assert_eq!(
                            low & apic::REDIRECTION_LEVEL != 0,
                            level,
                            "GSI {gsi}'s trigger"
                        );
                        assert_eq!(
                            low & apic::REDIRECTION_MASKED != 0,
                            x.masked,
                            "GSI {gsi}'s mask"
                        );
                    }
                    (Src::Msi, Source::Msi) => {}
                    (Src::Sint(n), Source::Sint(s)) => {
                        assert_eq!(s, n, "IRQ {irq}");
                        let v = w.k.dev.synic.sints[usize::from(n)];
                        assert_eq!(
                            v & (0xFF | SINT_MASKED | SINT_AUTO_EOI | SINT_POLLING),
                            u64::from(vector(irq)),
                            "SINT {n}"
                        );
                    }
                    (want, got) => panic!("IRQ {irq} is {got:?}; the model has {want:?}"),
                }
            }
        }
    }
    for gsi in 0..24 {
        if m.holder(gsi).is_none() {
            assert!(masked(w, gsi), "GSI {gsi} is unmasked but not issued");
        }
    }
    for n in 0..16u8 {
        let v = w.k.dev.synic.sints[usize::from(n)];
        if m.sint_holder(n).is_none() {
            assert_ne!(v & SINT_MASKED, 0, "SINT {n} is unmasked but not issued");
        }
        assert_eq!(
            v & FakeSynic::RESERVED,
            FakeSynic::RESERVED,
            "SINT {n}'s reserved bits"
        );
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
    // Hyper-V's world has a SynIC; QEMU's has none.
    let synic = version == HYPERV;
    w.k.dev.synic = FakeSynic::new(synic);
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
                    let irq = m.issue(slot, Src::Pin { gsi: g, level });
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
            Op::IssueMsi { device, slot } => {
                let r = invoke(
                    &mut w,
                    A,
                    S_CONTROL,
                    label::GET_MSI,
                    &[handler(slot), 64],
                    &[S_ROOT],
                );
                let want = if m.slots.contains_key(&slot) {
                    error(SyscallError::DeleteFirst)
                } else {
                    let irq = m.issue(slot, Src::Msi);
                    m.devices[device] = Some(vector(irq));
                    p.msis_issued += 1;
                    ok(&[u64::from(irq), msi_address(3), msi_data(irq)])
                };
                assert_eq!(r, want, "{op:?}");
            }
            Op::IssueSint { sint, slot } => {
                let r = invoke(
                    &mut w,
                    A,
                    S_CONTROL,
                    label::GET_SINT,
                    &[u64::from(sint), handler(slot), 64],
                    &[S_ROOT],
                );
                let want = if !synic {
                    p.sint_without_synic += 1;
                    error(SyscallError::IllegalOperation)
                } else if m.sint_holder(sint).is_some() {
                    error(SyscallError::RevokeFirst)
                } else if m.slots.contains_key(&slot) {
                    error(SyscallError::DeleteFirst)
                } else {
                    let irq = m.issue(slot, Src::Sint(sint));
                    p.sints_issued += 1;
                    ok(&[u64::from(irq)])
                };
                assert_eq!(r, want, "{op:?}");
            }
            Op::Message { device, defer: d } => {
                if let Some(v) = m.devices[device] {
                    let live = m.irqs.get(&irq_of_vector(v).unwrap()).map(|x| x.src);
                    if live != Some(Src::Msi) {
                        p.stale_msi += 1;
                    }
                    m.foreign.insert(v);
                    w.k.dev.msi(u64::from(v));
                }
                defer = d;
            }
            Op::RaiseSint { sint, defer: d } => {
                if synic {
                    match m.sint_holder(sint) {
                        Some(irq) => {
                            m.foreign.insert(vector(irq));
                        }
                        None => p.lost_sint_edge += 1,
                    }
                    w.k.dev.raise_sint(sint);
                }
                defer = d;
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
        cases: if cfg!(miri) { 2 } else { 512 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_irq_operations_and_interrupts_match_the_model(
        qemu in any::<bool>(),
        ops in proptest::collection::vec(op(), 1..if cfg!(miri) { 12 } else { 80 }),
    ) {
        run(if qemu { QEMU } else { HYPERV }, &ops);
    }
}

#[test]
#[cfg_attr(miri, ignore = "a statistic over many random sequences")]
fn random_sequences_reach_every_path() {
    let mut runner = TestRunner::new_with_rng(
        Config {
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let cases = 128;
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
        t.msis_issued += p.msis_issued;
        t.sints_issued += p.sints_issued;
        t.sint_without_synic += p.sint_without_synic;
        t.msi_signalled += p.msi_signalled;
        t.sint_signalled += p.sint_signalled;
        t.stale_msi += p.stale_msi;
        t.lost_sint_edge += p.lost_sint_edge;
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
        ("issued an MSI", t.msis_issued),
        ("issued a SINT", t.sints_issued),
        ("refused GetSint without a SynIC", t.sint_without_synic),
        ("signalled an MSI", t.msi_signalled),
        ("signalled a SINT", t.sint_signalled),
        ("sent a stale MSI", t.stale_msi),
        ("raised a masked SINT", t.lost_sint_edge),
    ] {
        assert!(n > 0, "no sequence {what}: {t:?}");
    }
    assert_eq!(t.most_between_acks, 2, "{t:?}");
}
