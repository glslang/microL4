//! Host tests of [`crate::irq`]: the routes, the actions' register writes,
//! IRQControl and IRQHandler through system calls as threads make them
//! ([`crate::syscall::handle_syscall`]) with every error row of
//! `docs/abi.md` in its order and nothing changed by a failed call,
//! ADR 0027's clearing of a stale Remote IRR on both I/O APIC versions,
//! delivery for level and edge pins against a model of an I/O APIC
//! ([`crate::testing::FakeIoApic`]), and deletion. The scheduler's, IPC's,
//! the notifications' and the IRQ table's invariants are checked at every
//! kernel exit. `model.rs` is the proptest against a model of the table.

use std::vec::Vec;

use super::*;
use crate::cap::{Cap, CapType, Rights};
use crate::cdt;
use crate::error::{LookupFailure, SyscallError};
use crate::invoke::label as cnode_label;
use crate::ipc::tests::*;
use crate::ipc::{MessageInfo, Notification, NtfnState, notification, word};
use crate::slot::{Node, Slot, SlotMemory};
use crate::syscall::Outcome;
use crate::tcb::{TcbRef, Tcbs, ThreadState};
use crate::testing::FakeDevices;

mod model;

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

/// Root slots: IRQControl, a root.
const S_CONTROL: u64 = 20;
/// Notification 0's original, unbadged, Read and Write.
const S_N0: u64 = 21;
/// Notification 0 minted with badge [`B0`], Read and Write: an original.
const S_N0_BADGED: u64 = 22;
/// A copy of [`S_N0`] with Read only.
const S_N0_READ: u64 = 23;
/// Notification 1 with badge [`B1`] and Write only, a root of its own.
const S_N1: u64 = 24;
/// Slots 25 to 31 are free for handlers.
const S_H: u64 = 25;
const S_H2: u64 = 26;
const S_H3: u64 = 27;

const B0: u64 = 1 << 32;
const B1: u64 = 1 << 33;

/// QEMU's I/O APIC version, with the EOI register, and Hyper-V's, without.
const QEMU: u8 = 0x20;
const HYPERV: u8 = 0x11;

/// The IPC world with q35's routes and one I/O APIC of `version`, the
/// IRQControl capability and notification capabilities. The boot CPU's
/// local APIC ID is 3, so destination words are seen.
fn world(version: u8) -> World {
    let mut w = World::new();
    w.k.dev = FakeDevices::q35(version);
    w.k.dev.apic_id = 3;
    let control = Cap::new(CapType::IrqControl, 0, 0, Rights::NONE, false, 0);
    cdt::insert_root(&mut w.k, rs(S_CONTROL), control);
    cdt::insert_root(&mut w.k, rs(S_N0), ntfn_cap(0, RW, 0));
    cdt::insert_derived(
        &mut w.k,
        rs(S_N0),
        rs(S_N0_BADGED),
        ntfn_cap(0, RW, B0),
        true,
    )
    .unwrap();
    cdt::insert_derived(
        &mut w.k,
        rs(S_N0),
        rs(S_N0_READ),
        ntfn_cap(0, Rights::READ, 0),
        false,
    )
    .unwrap();
    cdt::insert_root(&mut w.k, rs(S_N1), ntfn_cap(1, Rights::WRITE, B1));
    checked(&w);
    w
}

/// Every invariant: the world's and the IRQ table's, and no pin unmasked
/// with Remote IRR set. Under Miri, which finds nothing in this safe code
/// that the native run does not, only the last: the walks would multiply
/// each test's time, as `World`'s own checkpoint decides.
fn checked(w: &World) {
    if !cfg!(miri) {
        w.check();
        check(&w.k).unwrap();
    }
    for io in &w.k.dev.ioapics {
        assert_eq!(
            io.unmasked_with_remote_irr, 0,
            "a pin unmasked with Remote IRR set"
        );
    }
}

/// What thread `t` got back from the kernel: the error code (0 for
/// success) and the detail or result words.
fn kernel_reply(w: &World, t: usize) -> (u64, Vec<u64>) {
    let m = MessageInfo::from_word(w.regs(t).rsi);
    let words = (0..m.length() as usize).map(|i| w.mr(t, i)).collect();
    (m.label(), words)
}

/// The reply an invocation failing with `err` gives.
fn error(err: SyscallError) -> (u64, Vec<u64>) {
    let (words, n) = err.detail();
    (err.code(), words[..n].to_vec())
}

fn ok(words: &[u64]) -> (u64, Vec<u64>) {
    (0, words.to_vec())
}

/// Thread `t` (A to D, which have buffers) calls invocation `label` on
/// `cptr` with `mrs` and the extra capabilities `caps`; returns the reply.
fn invoke(
    w: &mut World,
    t: usize,
    cptr: u64,
    label: u64,
    mrs: &[u64],
    caps: &[u64],
) -> (u64, Vec<u64>) {
    let mut regs = [0; 4];
    for (i, &m) in mrs.iter().enumerate() {
        match regs.get_mut(i) {
            Some(r) => *r = m,
            None => w.set_buf(t, word::MSG + i, m),
        }
    }
    for (i, &c) in caps.iter().enumerate() {
        w.set_buf(t, word::CAPS_OR_BADGES + i, c);
    }
    let rsi = MessageInfo::new(label, 0, caps.len() as u64, mrs.len() as u64).word();
    assert_eq!(w.syscall(t, 1, cptr, rsi, Some(regs)), Outcome::Done);
    checked(w);
    kernel_reply(w, t)
}

/// A calls `GetISA(isa)` into root slot `slot`.
fn get_isa(w: &mut World, isa: u64, slot: u64) -> (u64, Vec<u64>) {
    invoke(w, A, S_CONTROL, label::GET_ISA, &[isa, slot, 64], &[S_ROOT])
}

/// A calls `GetIOAPIC(gsi, trigger, polarity)` into root slot `slot`.
fn get_ioapic(w: &mut World, gsi: u64, trigger: u64, polarity: u64, slot: u64) -> (u64, Vec<u64>) {
    invoke(
        w,
        A,
        S_CONTROL,
        label::GET_IOAPIC,
        &[gsi, trigger, polarity, slot, 64],
        &[S_ROOT],
    )
}

fn ack(w: &mut World, h: u64) -> (u64, Vec<u64>) {
    invoke(w, A, h, label::ACK, &[], &[])
}

fn set_ntfn(w: &mut World, h: u64, n: u64) -> (u64, Vec<u64>) {
    invoke(w, A, h, label::SET_NOTIFICATION, &[], &[n])
}

fn clear(w: &mut World, h: u64) -> (u64, Vec<u64>) {
    invoke(w, A, h, label::CLEAR, &[], &[])
}

fn delete(w: &mut World, slot: u64) {
    let r = invoke(w, A, S_ROOT, cnode_label::CNODE_DELETE, &[slot, 64], &[]);
    assert_eq!(r, ok(&[]), "deleting slot {slot}");
}

/// The CPU takes the highest vector the local APIC holds, with the
/// current thread interrupted: delivery, EOI, then the scheduler. Returns
/// the vector and what delivery did, or `None` if nothing was pending.
fn interrupt(w: &mut World) -> Option<(u8, Delivery)> {
    let v = w.k.dev.take()?;
    let irq = irq_of_vector(v).expect("only device vectors in these tests");
    let d = deliver(&mut w.k, irq);
    w.k.dev.eoi(v);
    w.exit();
    checked(w);
    Some((v, d))
}

/// Raises and lowers `gsi`'s line, a pulse.
fn pulse(w: &mut World, gsi: u32) {
    w.k.dev.set_line(gsi, true);
    w.k.dev.set_line(gsi, false);
}

fn entry(w: &World, irq: u8) -> Entry {
    w.k.dev.table.entry(irq)
}

/// `gsi`'s pin's redirection entry: low and high word.
fn rte(w: &World, gsi: u32) -> (u32, u32) {
    let (io, pin) = w.k.dev.pin(gsi);
    io.entries[usize::from(pin)]
}

fn masked(w: &World, gsi: u32) -> bool {
    rte(w, gsi).0 & apic::REDIRECTION_MASKED != 0
}

fn node(w: &World, irq: u8) -> Cap {
    w.cap(node_slot(&w.k, irq))
}

fn nt(w: &World, i: usize) -> Notification {
    notification(&w.k, ntfn(i))
}

/// Everything a failed invocation must leave as it was: the root CNode's
/// slots, the IRQ table and node, the redirection entries, the local
/// APIC's IRR and the notifications.
type Snapshot = (
    Vec<Slot>,
    IrqTable,
    Vec<Slot>,
    Vec<(u32, u32)>,
    Vec<u8>,
    Vec<Notification>,
);

fn snapshot(w: &World) -> Snapshot {
    (
        (0..32).map(|i| w.k.load(rs(i))).collect(),
        w.k.dev.table.clone(),
        (0..IRQS as u8)
            .take(if cfg!(miri) { 8 } else { IRQS })
            .map(|i| w.k.load(node_slot(&w.k, i)))
            .collect(),
        w.k.dev
            .ioapics
            .iter()
            .flat_map(|io| io.entries.clone())
            .collect(),
        w.k.dev.lapic_irr.iter().copied().collect(),
        (0..NTFNS).map(|i| nt(w, i)).collect(),
    )
}

fn insert(w: &mut World, slot: u64, cap: Cap) {
    cdt::insert_root(&mut w.k, rs(slot), cap);
}

/// The q35 and Hyper-V dumps' platforms, parsed once per test process
/// with the boot tests'.
use crate::boot::tests::{hyperv_acpi, q35_acpi};

// ---------------------------------------------------------------------------
// Vectors, capabilities and routes
// ---------------------------------------------------------------------------

#[test]
fn irq_n_is_vector_0x30_plus_n() {
    assert_eq!(IRQS, 192);
    assert_eq!((vector(0), vector(191)), (0x30, 0xEF));
    for v in 0..=255u8 {
        let want = (0x30..=0xEF).contains(&v).then(|| v - 0x30);
        assert_eq!(irq_of_vector(v), want, "vector {v:#x}");
    }
    for irq in [0, 4, 191] {
        let c = handler_cap(irq);
        assert_eq!(
            (c.cap_type(), c.object(), c.size_bits()),
            (CapType::IrqHandler, 0, 0)
        );
        assert_eq!(handler_irq(&c), Some(irq));
    }
    assert_eq!(handler_irq(&handler_cap(4).with_data(192)), None);
    assert_eq!(handler_irq(&ntfn_cap(0, RW, 4)), None);
}

#[test]
fn routes_from_the_q35_and_hyperv_dumps() {
    let q = Routing::from_platform(q35_acpi(), &[24], &[QEMU]);
    let io = IoApicDesc {
        gsi_base: 0,
        pins: 24,
        version: QEMU,
    };
    assert_eq!(q.ioapics, [Some(io), None, None, None]);
    assert!(io.has_eoi_register());
    let route = |gsi, level| {
        Some(IsaRoute {
            gsi,
            level,
            active_low: false,
        })
    };
    assert_eq!(q.isa[0], route(2, false), "IRQ 0 goes to GSI 2");
    assert_eq!(q.isa[2], None, "GSI 2 is IRQ 0's");
    assert_eq!(q.isa[4], route(4, false), "COM1");
    for n in [5, 9, 10, 11] {
        assert_eq!(q.isa[n], route(n as u32, true), "IRQ {n}");
    }
    let pin = |p| Pin { ioapic: 0, pin: p };
    assert_eq!(q.pin(0), Some((pin(0), io)));
    assert_eq!(q.pin(23), Some((pin(23), io)));
    assert_eq!(q.pin(24), None);
    assert_eq!(q.pin(1 << 32), None, "no GSI wraps to 0");
    assert_eq!(q.pin(u64::MAX), None);
    // The fake's q35 is the dump's.
    assert_eq!(FakeDevices::q35(QEMU).routing, q);

    let h = Routing::from_platform(hyperv_acpi(), &[24], &[HYPERV]);
    let hio = h.ioapics[0].unwrap();
    assert_eq!((hio.gsi_base, hio.pins, hio.version), (0, 24, HYPERV));
    assert!(!hio.has_eoi_register());
    assert_eq!(h.isa[4], route(4, false), "COM1 on Hyper-V");
    assert_eq!(h.isa[9], route(9, true));
    assert_eq!(h.isa[0], route(0, false), "Hyper-V has no IRQ 0 override");
}

#[test]
fn an_ioapic_without_a_pin_count_or_version_serves_nothing_and_the_first_match_wins() {
    let mut p = q35_acpi().clone();
    let first = p.ioapics.get(0).copied().unwrap();
    p.ioapics.push(crate::acpi::IoApic {
        id: 9,
        address: 0xFEC1_0000,
        gsi_base: 20,
    });
    p.ioapics.push(crate::acpi::IoApic {
        id: 10,
        address: 0xFEC2_0000,
        gsi_base: 40,
    });
    assert_eq!(first.gsi_base, 0);
    let r = Routing::from_platform(&p, &[24, 8, 8], &[QEMU, HYPERV]);
    assert!(r.ioapics[2].is_none(), "no version read");
    // GSIs 20 to 23 are both I/O APICs'; the first in MADT order serves
    // them.
    assert_eq!(r.pin(21).map(|(p, _)| p), Some(Pin { ioapic: 0, pin: 21 }));
    assert_eq!(
        r.pin(27).map(|(p, io)| (p, io.version)),
        Some((Pin { ioapic: 1, pin: 7 }, HYPERV))
    );
    assert_eq!(r.pin(28), None);
    assert_eq!(r.pin(40), None);
    let zero = Routing::from_platform(&p, &[0], &[QEMU]);
    assert_eq!(
        zero.ioapics, [None; MAX_IOAPICS],
        "an I/O APIC with no pins"
    );
}

#[test]
fn each_action_writes_the_documented_registers() {
    let pin = Pin { ioapic: 0, pin: 4 };
    // Vector 0x55, level, active low, masked, Remote IRR and delivery
    // status set.
    let low = 0x55 | 1 << 12 | 1 << 13 | 1 << 14 | 1 << 15 | 1 << 16;
    let w = |a: Action| a.writes(low, 3);
    assert_eq!(
        w(Action::MaskRte(pin)),
        [Some(RteWrite::Low(low)), None, None]
    );
    assert_eq!(
        Action::MaskRte(pin).writes(0x30, 3),
        [Some(RteWrite::Low(0x1_0030)), None, None],
        "vector, trigger and polarity kept"
    );
    assert_eq!(
        w(Action::UnmaskRte(pin)),
        [Some(RteWrite::Low(low & !(1 << 16))), None, None]
    );
    assert_eq!(w(Action::CheckRemoteIrr(pin)), [None; 3]);
    let edge_low = 0x55 | 1 << 14;
    let level = edge_low | 1 << 15 | 1 << 16;
    assert_eq!(
        Action::ClearRemoteIrr {
            pin,
            path: ClearPath::EoiRegister
        }
        .writes(edge_low, 3),
        [Some(RteWrite::Low(level)), Some(RteWrite::Eoi(0x55)), None],
        "level, masked, the old vector; then the vector to the EOI register"
    );
    assert_eq!(
        Action::ClearRemoteIrr {
            pin,
            path: ClearPath::TriggerToggle
        }
        .writes(edge_low, 3),
        [
            Some(RteWrite::Low(level)),
            Some(RteWrite::Low(level & !(1 << 15))),
            Some(RteWrite::Low(level))
        ],
        "level, then edge, then level, all masked"
    );
    let program = |level, active_low| {
        Action::ProgramRte {
            pin,
            vector: 0x31,
            level,
            active_low,
        }
        .writes(low, 3)
    };
    assert_eq!(
        program(false, false),
        [
            Some(RteWrite::High(3 << 24)),
            Some(RteWrite::Low(0x31)),
            None
        ],
        "the destination first, then the entry unmasked"
    );
    assert_eq!(
        program(true, true)[1],
        Some(RteWrite::Low(0x31 | 1 << 13 | 1 << 15))
    );
    assert!(Action::MaskRte(pin).pin() == pin && program(true, false).len() == 3);
}

// ---------------------------------------------------------------------------
// IRQControl
// ---------------------------------------------------------------------------

#[test]
fn get_isa_issues_the_lowest_free_irq_through_the_madts_route() {
    let mut w = world(QEMU);
    assert_eq!(
        get_isa(&mut w, 4, S_H),
        ok(&[0, 4, 0]),
        "irq 0, GSI 4, edge, high"
    );
    let h = w.cap(rs(S_H));
    assert_eq!(h, handler_cap(0));
    assert_eq!(
        cdt::parent(&w.k, rs(S_H)),
        Some(rs(S_CONTROL)),
        "a child of IRQControl"
    );
    assert!(
        w.k.load(rs(S_H)).node.original(),
        "copies of it become its children"
    );
    assert_eq!(
        entry(&w, 0),
        Entry {
            source: Source::IoApic {
                gsi: 4,
                pin: Pin { ioapic: 0, pin: 4 },
                level: false,
                active_low: false
            },
            pending: false,
            masked: false
        }
    );
    assert!(node(&w, 0).is_null());
    assert_eq!(
        rte(&w, 4),
        (0x30, 3 << 24),
        "vector 0x30, edge, high, unmasked, CPU 3"
    );
    let pin = Pin { ioapic: 0, pin: 4 };
    assert_eq!(
        w.k.dev.actions,
        [
            Action::MaskRte(pin),
            Action::CheckRemoteIrr(pin),
            Action::ProgramRte {
                pin,
                vector: 0x30,
                level: false,
                active_low: false
            }
        ]
    );
    // ISA IRQ 9 is level and active high on q35; IRQ 0 goes to GSI 2.
    assert_eq!(get_isa(&mut w, 9, S_H2), ok(&[1, 9, 1]));
    assert_eq!(rte(&w, 9).0, 0x31 | apic::REDIRECTION_LEVEL);
    assert_eq!(get_isa(&mut w, 0, S_H3), ok(&[2, 2, 0]));
    assert_eq!(rte(&w, 2).0, 0x32);
    // A freed IRQ is the lowest again.
    delete(&mut w, S_H);
    assert_eq!(get_isa(&mut w, 3, S_H), ok(&[0, 3, 0]));
}

#[test]
fn get_ioapic_takes_explicit_flags_and_applies_no_override() {
    let mut w = world(QEMU);
    assert_eq!(get_ioapic(&mut w, 16, 1, 1, S_H), ok(&[0]));
    assert_eq!(
        rte(&w, 16).0,
        0x30 | apic::REDIRECTION_LEVEL | apic::REDIRECTION_ACTIVE_LOW
    );
    // GSI 9's override says level; GetIOAPIC asks edge, and gets it.
    assert_eq!(get_ioapic(&mut w, 9, 0, 0, S_H2), ok(&[1]));
    assert_eq!(rte(&w, 9).0, 0x31);
    // GSI 2 is reachable only this way, IRQ 0's route aside.
    assert_eq!(get_ioapic(&mut w, 2, 0, 0, S_H3), ok(&[2]));
    assert_eq!(
        entry(&w, 0).source,
        Source::IoApic {
            gsi: 16,
            pin: Pin { ioapic: 0, pin: 16 },
            level: true,
            active_low: true
        }
    );
}

#[test]
fn results_reach_only_a_caller_with_registers_for_them() {
    // Send performs the issue and drops the reply; a thread without an IPC
    // buffer can issue too when the message fits its registers.
    let mut w = world(QEMU);
    let rsi = MessageInfo::new(label::GET_ISA, 0, 1, 3).word();
    w.set_buf(A, word::CAPS_OR_BADGES, S_ROOT);
    let before = w.mrs(A);
    w.syscall(A, 3, S_CONTROL, rsi, Some([4, S_H, 64, 9]));
    assert_eq!(w.cap(rs(S_H)), handler_cap(0));
    assert_eq!(
        (w.regs(A).rsi, w.mrs(A)),
        (rsi, [4, S_H, 64, 9]),
        "nothing written"
    );
    let _ = before;
    // F has no buffer, so no extra capability: TruncatedMessage.
    w.syscall(F, 1, S_CONTROL, rsi, Some([3, S_H2, 64, 0]));
    assert_eq!(kernel_reply(&w, F), error(SyscallError::TruncatedMessage));
}

/// One error case: the call A makes and the error it must get.
struct Case {
    what: &'static str,
    cptr: u64,
    label: u64,
    mrs: Vec<u64>,
    caps: Vec<u64>,
    err: SyscallError,
}

fn case(what: &'static str, label: u64, mrs: &[u64], caps: &[u64], err: SyscallError) -> Case {
    Case {
        what,
        cptr: S_CONTROL,
        label,
        mrs: mrs.to_vec(),
        caps: caps.to_vec(),
        err,
    }
}

/// Runs each case in `w` as it stands: each must fail with its error and
/// change nothing.
fn fails(w: &mut World, cases: &[Case]) {
    for c in miri_subset(cases) {
        let before = snapshot(w);
        let r = invoke(w, A, c.cptr, c.label, &c.mrs, &c.caps);
        assert_eq!(r, error(c.err), "{}", c.what);
        assert!(snapshot(w) == before, "{} changed something", c.what);
    }
}

/// Every case natively; under Miri every fourth and the last, to keep
/// its time down.
fn miri_subset<T>(all: &[T]) -> impl Iterator<Item = &T> {
    let step = if cfg!(miri) { 4 } else { 1 };
    all.iter()
        .enumerate()
        .filter(move |(i, _)| i % step == 0 || *i == all.len() - 1)
        .map(|(_, c)| c)
}

const ILLEGAL: SyscallError = SyscallError::IllegalOperation;
const TRUNCATED: SyscallError = SyscallError::TruncatedMessage;
const REVOKE_FIRST: SyscallError = SyscallError::RevokeFirst;
const DEPTH: SyscallError = SyscallError::RangeError { min: 1, max: 64 };

/// A slot lookup that failed in a destination.
fn lookup(failure: LookupFailure) -> SyscallError {
    SyscallError::FailedLookup {
        source: false,
        failure,
    }
}

#[test]
fn irq_control_errors_in_order() {
    let mut w = world(QEMU);
    // GSI 4 already has a handler, and slot S_H2 is full.
    assert_eq!(get_isa(&mut w, 4, S_H), ok(&[0, 4, 0]));
    insert(&mut w, S_H2, ep_cap(2, Rights::ALL, 0));
    let root = [S_ROOT];
    let isa = label::GET_ISA;
    let io = label::GET_IOAPIC;
    let cases = [
        // 1: the label.
        case(
            "GetMSI before M9",
            label::GET_MSI,
            &[S_H3, 64],
            &root,
            ILLEGAL,
        ),
        case(
            "GetSint before M9",
            label::GET_SINT,
            &[0, S_H3, 64],
            &root,
            ILLEGAL,
        ),
        case("reserved 0x64", 0x64, &[], &[], ILLEGAL),
        case("reserved 0x67", 0x67, &[], &[], ILLEGAL),
        case("IRQHandler's Ack", label::ACK, &[], &[], ILLEGAL),
        case(
            "IOPortControl's Issue",
            0x70,
            &[0x3F8, 0x3FF, S_H3, 64],
            &root,
            ILLEGAL,
        ),
        case("label 0", 0, &[], &[], ILLEGAL),
        // 2: the length.
        case("GetISA, 2 registers", isa, &[3, S_H3], &root, TRUNCATED),
        case("GetISA, no capability", isa, &[3, S_H3, 64], &[], TRUNCATED),
        case(
            "GetISA, bad IRQ but short",
            isa,
            &[16, S_H3],
            &root,
            TRUNCATED,
        ),
        case(
            "GetIOAPIC, 4 registers",
            io,
            &[16, 0, 0, S_H3],
            &root,
            TRUNCATED,
        ),
        case(
            "GetIOAPIC, no capability",
            io,
            &[16, 0, 0, S_H3, 64],
            &[],
            TRUNCATED,
        ),
        // 3: the arguments, in register order.
        case(
            "ISA IRQ 16",
            isa,
            &[16, S_H3, 64],
            &root,
            SyscallError::RangeError { min: 0, max: 15 },
        ),
        case(
            "ISA IRQ 2^63",
            isa,
            &[1 << 63, S_H3, 64],
            &root,
            SyscallError::RangeError { min: 0, max: 15 },
        ),
        case(
            "ISA IRQ 2, no route",
            isa,
            &[2, S_H3, 64],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        case(
            "ISA IRQ 2 into a full slot",
            isa,
            &[2, S_H2, 0],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        case(
            "GSI 24",
            io,
            &[24, 0, 0, S_H3, 64],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        case(
            "GSI 2^32 + 4",
            io,
            &[1 << 32 | 4, 0, 0, S_H3, 64],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        case(
            "GSI 24, trigger 2",
            io,
            &[24, 2, 0, S_H3, 64],
            &root,
            SyscallError::InvalidArgument(0),
        ),
        case(
            "trigger 2",
            io,
            &[16, 2, 0, S_H3, 64],
            &root,
            SyscallError::RangeError { min: 0, max: 1 },
        ),
        case(
            "polarity 2",
            io,
            &[16, 0, 2, S_H3, 64],
            &root,
            SyscallError::RangeError { min: 0, max: 1 },
        ),
        case(
            "trigger 2^63, GSI 4 issued",
            io,
            &[4, 1 << 63, 0, S_H3, 64],
            &root,
            SyscallError::RangeError { min: 0, max: 1 },
        ),
        // 5: the source.
        case("GetISA(4) again", isa, &[4, S_H3, 64], &root, REVOKE_FIRST),
        case(
            "GetIOAPIC(4)",
            io,
            &[4, 1, 0, S_H3, 64],
            &root,
            REVOKE_FIRST,
        ),
        case(
            "GetISA(4), depth 0",
            isa,
            &[4, S_H3, 0],
            &root,
            REVOKE_FIRST,
        ),
        // 6: the destination.
        case("depth 0", isa, &[3, S_H3, 0], &root, DEPTH),
        case("depth 65", io, &[16, 0, 0, S_H3, 65], &root, DEPTH),
        case(
            "depth 0, a root that is no CNode",
            isa,
            &[3, S_H3, 0],
            &[S_N0],
            DEPTH,
        ),
        case(
            "a root that is no CNode",
            isa,
            &[3, S_H3, 64],
            &[S_N0],
            lookup(LookupFailure::InvalidRoot),
        ),
        case(
            "an empty root",
            isa,
            &[3, S_H3, 64],
            &[S_FREE + 10],
            lookup(LookupFailure::InvalidRoot),
        ),
        case(
            "depth 63",
            isa,
            &[3, S_H3, 63],
            &root,
            lookup(LookupFailure::GuardMismatch {
                bits_left: 63,
                guard: 0,
                guard_size: 59,
            }),
        ),
        case(
            "a full slot",
            isa,
            &[3, S_H2, 64],
            &root,
            SyscallError::DeleteFirst,
        ),
        case(
            "a full slot, GetIOAPIC",
            io,
            &[16, 1, 1, S_H, 64],
            &root,
            SyscallError::DeleteFirst,
        ),
    ];
    fails(&mut w, &cases);
}

#[test]
fn an_isa_irq_whose_gsi_no_ioapic_serves_has_no_route() {
    let mut w = world(QEMU);
    w.k.dev.routing.isa[3] = Some(IsaRoute {
        gsi: 30,
        level: false,
        active_low: false,
    });
    fails(
        &mut w,
        &[case(
            "ISA IRQ 3 to GSI 30",
            label::GET_ISA,
            &[3, S_H, 64],
            &[S_ROOT],
            SyscallError::InvalidArgument(0),
        )],
    );
}

#[test]
fn with_every_vector_taken_an_issue_is_revoke_first() {
    let mut w = world(QEMU);
    // A second I/O APIC of 120 pins, GSIs 24 to 143, and a third, 144 to
    // 263, whose pins take every vector, set straight into the table.
    for (i, base) in [(1, 24), (2, 144)] {
        w.k.dev
            .ioapics
            .push(crate::testing::FakeIoApic::new(QEMU, 120));
        w.k.dev.routing.ioapics[i] = Some(IoApicDesc {
            gsi_base: base,
            pins: 120,
            version: QEMU,
        });
    }
    for irq in 0..IRQS as u8 {
        let gsi = 24 + u32::from(irq);
        let (pin, _) = w.k.dev.routing.pin(u64::from(gsi)).unwrap();
        w.k.dev.table.set(
            irq,
            Entry {
                source: Source::IoApic {
                    gsi,
                    pin,
                    level: false,
                    active_low: false,
                },
                pending: false,
                masked: false,
            },
        );
    }
    let before = snapshot(&w);
    let r = invoke(
        &mut w,
        A,
        S_CONTROL,
        label::GET_ISA,
        &[4, S_H, 64],
        &[S_ROOT],
    );
    assert_eq!(r, error(REVOKE_FIRST));
    assert!(snapshot(&w) == before);
    assert!(w.k.dev.actions.is_empty(), "the pin is not touched");
}

#[test]
fn a_refused_issue_never_touches_an_issued_pin() {
    let mut w = world(QEMU);
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H), ok(&[0]));
    w.k.dev.actions.clear();
    assert_eq!(get_ioapic(&mut w, 16, 0, 0, S_H2), error(REVOKE_FIRST));
    assert_eq!(get_isa(&mut w, 4, S_H), error(SyscallError::DeleteFirst));
    assert!(
        !w.k.dev.actions.iter().any(|a| a.pin().pin == 16),
        "{:?}",
        w.k.dev.actions
    );
    assert!(!masked(&w, 16));
}

// ---------------------------------------------------------------------------
// A stale Remote IRR (ADR 0027)
// ---------------------------------------------------------------------------

#[test]
fn issue_clears_a_stale_remote_irr_through_the_eoi_register_from_version_0x20() {
    let mut w = world(QEMU);
    let (io, pin) = w.k.dev.pin_mut(4);
    io.strand(pin, 0x55);
    assert_eq!(get_isa(&mut w, 4, S_H), ok(&[0, 4, 0]));
    let pin = Pin { ioapic: 0, pin: 4 };
    assert_eq!(
        w.k.dev.actions,
        [
            Action::MaskRte(pin),
            Action::CheckRemoteIrr(pin),
            Action::ClearRemoteIrr {
                pin,
                path: ClearPath::EoiRegister
            },
            Action::CheckRemoteIrr(pin),
            Action::ProgramRte {
                pin,
                vector: 0x30,
                level: false,
                active_low: false
            }
        ]
    );
    assert_eq!(rte(&w, 4).0, 0x30, "Remote IRR clear, edge, unmasked");
}

#[test]
fn below_version_0x20_issue_clears_a_stale_remote_irr_by_toggling_the_trigger() {
    let mut w = world(HYPERV);
    let (io, pin) = w.k.dev.pin_mut(9);
    io.strand(pin, 0x55);
    // The EOI register does nothing on this version.
    assert!(w.k.dev.ioapics[0].eoi_register(0x55).is_empty());
    assert!(apic::remote_irr(rte(&w, 9).0));
    assert_eq!(get_isa(&mut w, 9, S_H), ok(&[0, 9, 1]));
    let pin = Pin { ioapic: 0, pin: 9 };
    assert_eq!(
        w.k.dev.actions[2],
        Action::ClearRemoteIrr {
            pin,
            path: ClearPath::TriggerToggle
        }
    );
    assert_eq!(
        rte(&w, 9).0,
        0x30 | apic::REDIRECTION_LEVEL,
        "level, Remote IRR clear, unmasked"
    );
}

#[test]
fn a_remote_irr_that_stays_set_is_revoke_first_and_the_pin_stays_masked() {
    for version in [QEMU, HYPERV] {
        let mut w = world(version);
        let (io, pin) = w.k.dev.pin_mut(16);
        io.strand(pin, 0x55);
        io.stuck_remote_irr = true;
        let table = w.k.dev.table.clone();
        assert_eq!(get_ioapic(&mut w, 16, 0, 0, S_H), error(REVOKE_FIRST));
        let low = rte(&w, 16).0;
        assert!(apic::remote_irr(low) && low & apic::REDIRECTION_MASKED != 0);
        assert_eq!(low & 0xFF, 0x55, "the vector is kept");
        assert!(w.k.dev.table == table && w.cap(rs(S_H)).is_null());
        // Retried later, once the hardware lets go, it succeeds.
        w.k.dev.ioapics[0].stuck_remote_irr = false;
        assert_eq!(get_ioapic(&mut w, 16, 0, 0, S_H), ok(&[0]));
    }
}

#[test]
fn an_issue_failing_at_the_destination_may_have_cleared_a_stale_remote_irr_and_nothing_else() {
    let mut w = world(QEMU);
    let (io, pin) = w.k.dev.pin_mut(4);
    io.strand(pin, 0x55);
    let slots: Vec<Slot> = (0..32).map(|i| w.k.load(rs(i))).collect();
    let table = w.k.dev.table.clone();
    let r = invoke(
        &mut w,
        A,
        S_CONTROL,
        label::GET_ISA,
        &[4, S_H, 0],
        &[S_ROOT],
    );
    assert_eq!(r, error(DEPTH));
    let low = rte(&w, 4).0;
    assert!(!apic::remote_irr(low), "cleared");
    assert!(
        low & apic::REDIRECTION_MASKED != 0 && low & 0xFF == 0x55,
        "still masked, its vector kept"
    );
    assert!(w.k.dev.table == table);
    assert!((0..32).map(|i| w.k.load(rs(i))).eq(slots));
}

// ---------------------------------------------------------------------------
// IRQHandler
// ---------------------------------------------------------------------------

/// A world with ISA IRQ 4 issued into [`S_H`] as IRQ 0, bound to
/// notification 0 through its badged capability and Acked once, as a
/// driver starts.
fn bound(version: u8) -> World {
    let mut w = world(version);
    assert_eq!(get_isa(&mut w, 4, S_H), ok(&[0, 4, 0]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    w.k.dev.actions.clear();
    w
}

#[test]
fn set_notification_copies_the_capability_into_the_irq_node_as_cnode_copy_would() {
    let mut w = bound(QEMU);
    assert_eq!(
        node(&w, 0),
        ntfn_cap(0, RW, B0),
        "badge and rights included"
    );
    let n = node_slot(&w.k, 0);
    assert_eq!(
        cdt::parent(&w.k, n),
        Some(rs(S_N0_BADGED)),
        "a child of the badged original"
    );
    assert!(!w.k.load(n).node.original());
    // From a copy, the bound capability is its sibling: N0_READ has no
    // Write, so bind through a Write-capable copy of N0 instead.
    insert(&mut w, S_H3, Cap::NULL);
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_COPY,
        &[S_H3, 64, S_N0, 64, 0xF],
        &[S_ROOT],
    );
    assert_eq!(r, ok(&[]));
    assert_eq!(set_ntfn(&mut w, S_H, S_H3), ok(&[]));
    assert_eq!(
        cdt::parent(&w.k, n),
        Some(rs(S_N0)),
        "a sibling of the copy"
    );
    // Binding another notification replaces it; nothing touches the pin.
    assert_eq!(set_ntfn(&mut w, S_H, S_N1), ok(&[]));
    assert_eq!(node(&w, 0), ntfn_cap(1, Rights::WRITE, B1));
    assert_eq!(cdt::parent(&w.k, n), Some(rs(S_N1)));
    assert!(w.k.dev.actions.is_empty());
}

#[test]
fn irq_handler_errors_in_order() {
    let mut w = bound(QEMU);
    // A notification capability at the depth limit, an original.
    let deep = rs(S_H3);
    w.k.store(
        deep,
        Slot {
            cap: ntfn_cap(2, RW, 7),
            node: Node::new(true, crate::cap::MAX_DERIVATION_DEPTH, 0),
        },
    );
    let h = |what, label, mrs: &[u64], caps: &[u64], err| Case {
        cptr: S_H,
        ..case(what, label, mrs, caps, err)
    };
    let set = label::SET_NOTIFICATION;
    let cases = [
        h(
            "GetISA on a handler",
            label::GET_ISA,
            &[4, S_H2, 64],
            &[S_ROOT],
            ILLEGAL,
        ),
        h("reserved 0x6B", 0x6B, &[], &[], ILLEGAL),
        h("reserved 0x6F", 0x6F, &[], &[], ILLEGAL),
        h("IOPort_In8", 0x71, &[0x3F8], &[], ILLEGAL),
        h("SetNotification, no capability", set, &[], &[], TRUNCATED),
        h(
            "an endpoint",
            set,
            &[],
            &[S_EP0],
            SyscallError::InvalidCapability(1),
        ),
        h(
            "Read only",
            set,
            &[],
            &[S_N0_READ],
            SyscallError::InvalidCapability(1),
        ),
        h(
            "an empty slot",
            set,
            &[],
            &[S_FREE + 10],
            SyscallError::InvalidCapability(1),
        ),
        h(
            "the handler itself",
            set,
            &[],
            &[S_H],
            SyscallError::InvalidCapability(1),
        ),
        h("deeper than the limit", set, &[], &[S_H3], ILLEGAL),
    ];
    fails(&mut w, &cases);
    assert_eq!(
        node(&w, 0),
        ntfn_cap(0, RW, B0),
        "still bound after every failure"
    );
}

#[test]
fn clear_unbinds_and_neither_it_nor_set_notification_touches_the_pin() {
    let mut w = bound(QEMU);
    pulse(&mut w, 4);
    interrupt(&mut w);
    pulse(&mut w, 4);
    interrupt(&mut w);
    let e = entry(&w, 0);
    assert!(e.pending && e.masked && masked(&w, 4));
    w.k.dev.actions.clear();
    assert_eq!(clear(&mut w, S_H), ok(&[]));
    assert!(node(&w, 0).is_null());
    assert_eq!(clear(&mut w, S_H), ok(&[]), "Clear with nothing bound");
    assert_eq!(set_ntfn(&mut w, S_H, S_N1), ok(&[]));
    assert_eq!(entry(&w, 0), e, "pending and masked as they were");
    assert!(masked(&w, 4) && w.k.dev.actions.is_empty());
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    assert!(!masked(&w, 4));
}

#[test]
fn rebinding_the_last_capability_to_a_notification_finalises_it() {
    let mut w = bound(QEMU);
    // Bind N1, then delete its only other capability: the IRQ node holds
    // the last one. B waits on N1 through a Read capability made first.
    assert_eq!(set_ntfn(&mut w, S_H, S_N1), ok(&[]));
    // A Read capability to N1 next to S_N1, so that deleting it is not
    // the last.
    cdt::insert_derived(
        &mut w.k,
        rs(S_N1),
        rs(S_H3),
        ntfn_cap(1, Rights::READ, 0),
        false,
    )
    .unwrap();
    w.recv(B, S_H3);
    assert_eq!(
        w.state(B),
        ThreadState::BlockedOnNotification { ntfn: ntfn(1) }
    );
    delete(&mut w, S_H3);
    delete(&mut w, S_N1);
    assert_eq!(
        w.state(B),
        ThreadState::BlockedOnNotification { ntfn: ntfn(1) }
    );
    // Binding N0 deletes the node's capability, N1's last: its waiter
    // restarts.
    assert_eq!(set_ntfn(&mut w, S_H, S_N0), ok(&[]));
    assert_eq!(w.state(B), ThreadState::Restart);
    assert_eq!(nt(&w, 1), Notification::IDLE);
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

#[test]
fn an_edge_pin_stays_open_for_the_first_edge_and_masks_on_the_second_before_ack() {
    let mut w = bound(QEMU);
    // First edge: pending, still unmasked, signalled.
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert_eq!((entry(&w, 0).pending, entry(&w, 0).masked), (true, false));
    assert!(!masked(&w, 4));
    assert_eq!(nt(&w, 0).state, NtfnState::Active);
    assert_eq!(nt(&w, 0).word, B0);
    // Second edge before Ack: masked, signalled again (coalesced).
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert_eq!((entry(&w, 0).pending, entry(&w, 0).masked), (true, true));
    assert!(masked(&w, 4));
    // A third edge: the masked pin drops it.
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), None);
    assert_eq!(w.k.dev.ioapics[0].dropped_edges, 1);
    // Ack clears pending and unmasks; the next edge is delivered.
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    assert_eq!((entry(&w, 0).pending, entry(&w, 0).masked), (false, false));
    assert!(!masked(&w, 4));
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert_eq!((entry(&w, 0).pending, entry(&w, 0).masked), (true, false));
    // Ack with nothing masked only clears pending.
    w.k.dev.actions.clear();
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    assert!(w.k.dev.actions.is_empty() && !entry(&w, 0).pending);
}

#[test]
fn the_local_apic_may_hold_a_third_interrupt_when_the_mask_lands() {
    let mut w = bound(QEMU);
    pulse(&mut w, 4);
    interrupt(&mut w);
    // The second edge is sent; before the CPU takes it, the device raises
    // the line again and the local APIC holds it as one.
    pulse(&mut w, 4);
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert!(entry(&w, 0).masked);
    // Delivered while already masked and pending: it stays masked.
    w.k.dev.lapic_irr.insert(0x30);
    w.k.dev.actions.clear();
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert!(w.k.dev.actions.is_empty(), "no second mask");
    assert!(entry(&w, 0).masked && entry(&w, 0).pending);
}

#[test]
fn a_level_pin_is_masked_on_delivery_and_refires_at_ack_while_asserted() {
    let mut w = world(QEMU);
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H), ok(&[0]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    w.k.dev.set_line(16, true);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    let e = entry(&w, 0);
    assert_eq!(
        (e.pending, e.masked),
        (false, true),
        "a level entry is never pending"
    );
    assert!(masked(&w, 16));
    assert!(
        !apic::remote_irr(rte(&w, 16).0),
        "the EOI cleared Remote IRR"
    );
    assert_eq!(
        interrupt(&mut w),
        None,
        "masked: nothing more while asserted"
    );
    // Ack unmasks; the line is still high, so the pin fires again at once.
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    // The driver quiets the device before its Ack: nothing more.
    w.k.dev.set_line(16, false);
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    assert_eq!(interrupt(&mut w), None);
    assert!(!masked(&w, 16));
}

#[test]
fn an_interrupt_with_no_notification_bound_is_lost_but_the_pin_advances() {
    let mut w = world(QEMU);
    assert_eq!(get_isa(&mut w, 4, S_H), ok(&[0, 4, 0]));
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Lost)));
    assert!(entry(&w, 0).pending);
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Lost)));
    assert!(entry(&w, 0).masked);
    assert_eq!(w.k.dev.table.lost, 2);
    // Binding changes nothing; the driver's Ack is still needed.
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), None);
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert_eq!(nt(&w, 0).word, B0);
}

#[test]
fn clear_while_pending_keeps_the_pending_edge_for_the_next_binding() {
    let mut w = bound(QEMU);
    pulse(&mut w, 4);
    interrupt(&mut w);
    assert_eq!(clear(&mut w, S_H), ok(&[]));
    // The next edge finds `pending` set and masks, though it is lost.
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Lost)));
    assert!(entry(&w, 0).masked && masked(&w, 4));
    assert_eq!(set_ntfn(&mut w, S_H, S_N1), ok(&[]));
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert_eq!(nt(&w, 1).word, B1);
}

#[test]
fn a_signal_from_an_interrupt_wakes_the_waiter_and_preempts_only_for_a_higher_priority() {
    for (prio, runs) in cases(&[(200u8, true), (100, false), (50, false)]) {
        let mut w = bound(QEMU);
        w.recv(B, S_N0);
        assert_eq!(
            w.state(B),
            ThreadState::BlockedOnNotification { ntfn: ntfn(0) }
        );
        w.set_prio(B, prio);
        w.run(A);
        pulse(&mut w, 4);
        assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
        assert_eq!(w.state(B), ThreadState::Running);
        assert_eq!((w.regs(B).rdi, w.regs(B).rsi), (B0, 0));
        assert_eq!(w.current() == Some(tcb(B)), runs, "priority {prio}");
        if !runs {
            assert_eq!(w.current(), Some(tcb(A)), "the interrupted thread goes on");
        }
    }
}

#[test]
fn an_interrupt_in_the_idle_thread_runs_the_woken_thread() {
    let mut w = bound(QEMU);
    w.recv(B, S_N0);
    // Every other thread stops; the kernel idles.
    for t in [A, C, D, E, F] {
        w.k.set_state(tcb(t), ThreadState::Inactive);
        crate::sched::dequeue(&mut w.k, tcb(t));
    }
    w.k.sched.set_current(None);
    assert_eq!(w.exit(), None);
    pulse(&mut w, 4);
    interrupt(&mut w);
    assert_eq!(w.current(), Some(tcb(B)));
}

// ---------------------------------------------------------------------------
// Deletion
// ---------------------------------------------------------------------------

#[test]
fn deleting_the_last_handler_unbinds_masks_keeping_vector_and_trigger_and_frees_the_irq() {
    let mut w = world(QEMU);
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H), ok(&[0]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    // A copy and a mint (its data ignored) keep the IRQ issued.
    let copy = |w: &mut World, dst, label, extra: &[u64]| {
        let mut mrs = std::vec![dst, 64, S_H, 64, 0xF];
        mrs.extend_from_slice(extra);
        invoke(w, A, S_ROOT, label, &mrs, &[S_ROOT])
    };
    assert_eq!(copy(&mut w, S_H2, cnode_label::CNODE_COPY, &[]), ok(&[]));
    assert_eq!(copy(&mut w, S_H3, cnode_label::CNODE_MINT, &[9]), ok(&[]));
    assert_eq!(w.cap(rs(S_H3)), handler_cap(0));
    assert_eq!(cdt::parent(&w.k, rs(S_H2)), Some(rs(S_H)));
    delete(&mut w, S_H);
    delete(&mut w, S_H3);
    assert!(entry(&w, 0).source != Source::Free && node(&w, 0) == ntfn_cap(0, RW, B0));
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H), error(REVOKE_FIRST));
    // The handler still works through the copy.
    assert_eq!(ack(&mut w, S_H2), ok(&[]));
    // The last capability goes.
    w.k.dev.actions.clear();
    delete(&mut w, S_H2);
    assert!(node(&w, 0).is_null());
    assert_eq!(entry(&w, 0), Entry::FREE);
    assert_eq!(
        w.k.dev.actions,
        [Action::MaskRte(Pin { ioapic: 0, pin: 16 })]
    );
    let low = rte(&w, 16).0;
    assert_eq!(
        low,
        0x30 | apic::REDIRECTION_LEVEL | apic::REDIRECTION_MASKED
    );
    assert_eq!(
        get_ioapic(&mut w, 16, 0, 0, S_H),
        ok(&[0]),
        "issuable again"
    );
}

#[test]
fn a_level_interrupt_pending_at_deletion_is_dropped_and_its_eoi_clears_remote_irr() {
    let mut w = world(QEMU);
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H), ok(&[0]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    // The device asserts its line in the kernel, which then deletes the
    // handler before it takes the interrupt.
    w.k.dev.set_line(16, true);
    assert!(apic::remote_irr(rte(&w, 16).0));
    delete(&mut w, S_H);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Stale)));
    assert_eq!(w.k.dev.table.stale, 1);
    let low = rte(&w, 16).0;
    assert!(
        !apic::remote_irr(low) && low & apic::REDIRECTION_MASKED != 0,
        "its EOI matched the kept vector"
    );
    // Reissued, the pin is clean, and fires at once while asserted.
    w.k.dev.actions.clear();
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H), ok(&[0]));
    assert!(
        !w.k.dev
            .actions
            .iter()
            .any(|a| matches!(a, Action::ClearRemoteIrr { .. }))
    );
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Lost)));
}

#[test]
fn a_freed_vector_reissued_elsewhere_never_hears_the_old_pin() {
    let mut w = world(QEMU);
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H), ok(&[0]));
    delete(&mut w, S_H);
    // IRQ 0's vector goes to GSI 17; GSI 16's masked pin still names it.
    assert_eq!(get_ioapic(&mut w, 17, 1, 0, S_H), ok(&[0]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    w.k.dev.set_line(16, true);
    assert_eq!(interrupt(&mut w), None, "the old pin is masked");
    w.k.dev.set_line(17, true);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
}

#[test]
fn deleting_the_handler_deletes_the_irq_nodes_capability_and_may_finalise_its_notification() {
    let mut w = bound(QEMU);
    assert_eq!(set_ntfn(&mut w, S_H, S_N1), ok(&[]));
    // A Read capability to N1 next to S_N1, so that deleting it is not
    // the last.
    cdt::insert_derived(
        &mut w.k,
        rs(S_N1),
        rs(S_H3),
        ntfn_cap(1, Rights::READ, 0),
        false,
    )
    .unwrap();
    w.recv(B, S_H3);
    delete(&mut w, S_H3);
    delete(&mut w, S_N1);
    delete(&mut w, S_H);
    assert_eq!(
        w.state(B),
        ThreadState::Restart,
        "N1's last capability went with the handler"
    );
    assert!(node(&w, 0).is_null() && entry(&w, 0) == Entry::FREE);
}

#[test]
fn revoking_irq_control_deletes_every_handler() {
    let mut w = world(QEMU);
    assert_eq!(get_isa(&mut w, 4, S_H), ok(&[0, 4, 0]));
    assert_eq!(get_ioapic(&mut w, 16, 1, 1, S_H2), ok(&[1]));
    assert_eq!(set_ntfn(&mut w, S_H2, S_N0_BADGED), ok(&[]));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_COPY,
        &[S_H3, 64, S_H, 64, 0],
        &[S_ROOT],
    );
    assert_eq!(r, ok(&[]));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_REVOKE,
        &[S_CONTROL, 64],
        &[],
    );
    assert_eq!(r, ok(&[]));
    for s in [S_H, S_H2, S_H3] {
        assert!(w.cap(rs(s)).is_null(), "slot {s}");
    }
    assert!(w.k.dev.table.entries().iter().all(|e| *e == Entry::FREE));
    assert!(masked(&w, 4) && masked(&w, 16) && node(&w, 1).is_null());
    assert_eq!(w.cap(rs(S_CONTROL)).cap_type(), CapType::IrqControl);
}

#[test]
fn irq_control_moves_but_never_copies_and_a_moved_handler_still_works() {
    let mut w = bound(QEMU);
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_COPY,
        &[S_H2, 64, S_CONTROL, 64, 0xF],
        &[S_ROOT],
    );
    assert_eq!(r, error(ILLEGAL));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_MOVE,
        &[S_H2, 64, S_CONTROL, 64],
        &[S_ROOT],
    );
    assert_eq!(r, ok(&[]));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_MOVE,
        &[S_H3, 64, S_H, 64],
        &[S_ROOT],
    );
    assert_eq!(r, ok(&[]));
    pulse(&mut w, 4);
    interrupt(&mut w);
    pulse(&mut w, 4);
    interrupt(&mut w);
    assert!(masked(&w, 4));
    assert_eq!(ack(&mut w, S_H3), ok(&[]));
    assert!(!masked(&w, 4));
    // The moved IRQControl issues, and its revoke still reaches S_H3.
    let r = invoke(&mut w, A, S_H2, label::GET_ISA, &[3, S_H, 64], &[S_ROOT]);
    assert_eq!(r, ok(&[1, 3, 0]));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_REVOKE,
        &[S_H2, 64],
        &[],
    );
    assert_eq!(r, ok(&[]));
    assert!(w.cap(rs(S_H)).is_null() && w.cap(rs(S_H3)).is_null());
}

#[test]
fn check_finds_broken_tables() {
    let w = bound(QEMU);
    assert_eq!(check(&w.k), Ok(()));
    let bad = |f: &dyn Fn(&mut World), why: &str| {
        let mut w = World {
            k: w.k.clone(),
            threads: w.threads.clone(),
            prios: w.prios.clone(),
            debug: w.debug,
        };
        f(&mut w);
        assert_eq!(check(&w.k), Err(why));
    };
    bad(
        &|w| {
            let mut e = entry(w, 0);
            e.source = Source::Free;
            w.k.dev.table.set(0, e);
        },
        "a free entry's IRQ node slot holds a capability",
    );
    bad(
        &|w| {
            w.k.dev.table.set(
                1,
                Entry {
                    pending: true,
                    ..Entry::FREE
                },
            )
        },
        "a free entry is pending or masked",
    );
    bad(
        &|w| {
            let e = entry(w, 0);
            w.k.dev.table.set(5, e);
        },
        "a GSI has two entries",
    );
    bad(
        &|w| {
            let mut e = entry(w, 0);
            if let Source::IoApic { ref mut pin, .. } = e.source {
                pin.pin = 5;
            }
            w.k.dev.table.set(0, e);
        },
        "an entry's pin is not its GSI's",
    );
    bad(
        &|w| {
            let mut e = entry(w, 0);
            if let Source::IoApic { ref mut level, .. } = e.source {
                *level = true;
            }
            e.pending = true;
            w.k.dev.table.set(0, e);
        },
        "a level entry is pending",
    );
    bad(
        &|w| {
            let n = node_slot(&w.k, 0);
            let mut s = w.k.load(n);
            s.cap = ntfn_cap(0, Rights::READ, 0);
            w.k.store(n, s);
        },
        "an IRQ node slot holds something other than a notification with Write",
    );
    let _ = TcbRef::new(0);
}

/// `docs/design.md`, "Interrupts", Invariants: an IRQ node slot never names
/// a deleted notification, because its capability is in the derivation
/// list. A revoke of the bound capability's original deletes it with the
/// other descendants; the next interrupt is lost, and the original is then
/// the notification's last capability.
#[test]
fn revoking_a_bound_notifications_original_empties_the_irq_node_slot() {
    let mut w = bound(QEMU);
    assert_eq!(node(&w, 0), ntfn_cap(0, RW, B0));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_REVOKE,
        &[S_N0, 64],
        &[],
    );
    assert_eq!(r, ok(&[]));
    assert!(w.cap(rs(S_N0_BADGED)).is_null());
    assert!(
        node(&w, 0).is_null(),
        "the IRQ node's copy went with the revoke"
    );
    pulse(&mut w, 4);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Lost)));
    // Deleting the last capability to N0 now finalises it.
    delete(&mut w, S_N0);
    assert_eq!(nt(&w, 0), Notification::IDLE);
}
