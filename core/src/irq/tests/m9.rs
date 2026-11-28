//! Host tests of M9's interrupt sources (`docs/design.md`, "MSI (M9) and
//! the trust model", "SynIC (M9)"): `GetMSI` and `GetSint` through system
//! calls with every error row of `docs/abi.md` in its order and nothing
//! changed by a failed call, the message address and data, the shared pool
//! of 192 vectors, delivery that never masks, `Ack` that does nothing, and
//! deletion, against the model I/O APIC, the local APIC's IRR and a model
//! SynIC that records every SINT write (`crate::testing::FakeSynic`).

use super::*;
use crate::hyperv::{SINT_AUTO_EOI, SINT_MASKED, SINT_POLLING};
use crate::testing::FakeSynic;

/// The world with a SynIC, as on Hyper-V; its I/O APIC at `0x11`.
fn hyperv() -> World {
    let mut w = world(HYPERV);
    w.k.dev.synic = FakeSynic::new(true);
    w
}

fn get_msi(w: &mut World, slot: u64) -> (u64, Vec<u64>) {
    invoke(w, A, S_CONTROL, label::GET_MSI, &[slot, 64], &[S_ROOT])
}

fn get_sint(w: &mut World, sint: u64, slot: u64) -> (u64, Vec<u64>) {
    invoke(
        w,
        A,
        S_CONTROL,
        label::GET_SINT,
        &[sint, slot, 64],
        &[S_ROOT],
    )
}

/// What [`super::fails`] checks, and that no SINT was written.
fn fails_m9(w: &mut World, cases: &[Case]) {
    let synic = w.k.dev.synic.clone();
    let actions = w.k.dev.actions.len();
    fails(w, cases);
    assert_eq!(w.k.dev.synic, synic, "a refused issue wrote a SINT");
    assert_eq!(
        w.k.dev.actions.len(),
        actions,
        "a refused issue touched a pin"
    );
}

/// Fills IRQs `from` to 191 straight into the table as MSIs.
fn take_vectors(w: &mut World, from: u8) {
    for irq in from..IRQS as u8 {
        w.k.dev.table.set(
            irq,
            Entry {
                source: Source::Msi,
                pending: false,
                masked: false,
            },
        );
    }
}

#[test]
fn the_msi_address_and_data_are_the_sdms_physical_fixed_edge_message() {
    // 0xFEE in bits 31:20, the destination's xAPIC ID in 19:12,
    // redirection hint and destination mode 0.
    assert_eq!(msi_address(0), 0xFEE0_0000);
    assert_eq!(msi_address(3), 0xFEE0_3000);
    assert_eq!(msi_address(0xFF), 0xFEEF_F000);
    for id in [0u8, 1, 0x5A, 0xFF] {
        let a = msi_address(id);
        assert_eq!(
            (a >> 20, a >> 12 & 0xFF, a & 0xFFF, a >> 32),
            (0xFEE, id.into(), 0, 0)
        );
    }
    // The vector in 7:0; delivery mode (10:8), level (14) and trigger
    // (15) 0: fixed, edge. It fits MSI's 16 bits.
    for irq in [0u8, 1, 100, 191] {
        let d = msi_data(irq);
        assert_eq!(d, u64::from(vector(irq)));
        assert_eq!(d & !0xFF, 0);
        assert!(d <= 0xFFFF);
    }
    assert_eq!((msi_data(0), msi_data(191)), (0x30, 0xEF));
}

#[test]
fn get_msi_reserves_the_lowest_free_vector_and_programs_nothing() {
    let mut w = world(QEMU);
    // GSI 4 has IRQ 0; the MSI gets IRQ 1, vector 0x31, for APIC ID 3.
    assert_eq!(get_isa(&mut w, 4, S_H), ok(&[0, 4, 0]));
    w.k.dev.actions.clear();
    let before_rtes: Vec<_> = w.k.dev.ioapics[0].entries.clone();
    assert_eq!(get_msi(&mut w, S_H2), ok(&[1, 0xFEE0_3000, 0x31]));
    assert_eq!(
        entry(&w, 1),
        Entry {
            source: Source::Msi,
            pending: false,
            masked: false
        }
    );
    assert_eq!(w.cap(rs(S_H2)), handler_cap(1));
    assert!(w.k.load(rs(S_H2)).node.original());
    assert_eq!(cdt::parent(&w.k, rs(S_H2)), Some(rs(S_CONTROL)));
    assert!(w.k.dev.actions.is_empty(), "GetMSI touches no I/O APIC");
    assert_eq!(w.k.dev.ioapics[0].entries, before_rtes);
    assert!(w.k.dev.synic.writes.is_empty());
    // A second MSI takes the next vector; the I/O APIC's next issue the
    // one after.
    assert_eq!(get_msi(&mut w, S_H3), ok(&[2, 0xFEE0_3000, 0x32]));
    assert_eq!(get_ioapic(&mut w, 16, 1, 0, S_H + 3), ok(&[3]));
    // Another APIC ID shows in the address.
    w.k.dev.apic_id = 0xA5;
    assert_eq!(get_msi(&mut w, S_H + 4), ok(&[4, 0xFEEA_5000, 0x34]));
}

#[test]
fn get_msi_errors_in_order() {
    let mut w = world(QEMU);
    assert_eq!(get_msi(&mut w, S_H), ok(&[0, 0xFEE0_3000, 0x30]));
    let root = [S_ROOT];
    let msi = label::GET_MSI;
    let cases = [
        // 2: the length.
        case("no registers", msi, &[], &root, TRUNCATED),
        case("one register", msi, &[S_H2], &root, TRUNCATED),
        case("no capability", msi, &[S_H2, 64], &[], TRUNCATED),
        // 6: the destination.
        case("depth 0", msi, &[S_H2, 0], &root, DEPTH),
        case("depth 65", msi, &[S_H2, 65], &root, DEPTH),
        case(
            "a root that is no CNode",
            msi,
            &[S_H2, 64],
            &[S_N0],
            lookup(LookupFailure::InvalidRoot),
        ),
        case(
            "a slot past the root",
            msi,
            &[1 << 40, 64],
            &root,
            lookup(LookupFailure::GuardMismatch {
                bits_left: 64,
                guard: 0,
                guard_size: 59,
            }),
        ),
        case(
            "a full slot",
            msi,
            &[S_H, 64],
            &root,
            SyscallError::DeleteFirst,
        ),
    ];
    fails_m9(&mut w, &cases);
    // 5: no vector free, before the destination.
    take_vectors(&mut w, 1);
    fails_m9(
        &mut w,
        &[
            case("no vector free", msi, &[S_H2, 64], &root, REVOKE_FIRST),
            case(
                "no vector free, a full slot",
                msi,
                &[S_H, 64],
                &root,
                REVOKE_FIRST,
            ),
            case(
                "no vector free, depth 0",
                msi,
                &[S_H2, 0],
                &root,
                REVOKE_FIRST,
            ),
        ],
    );
}

#[test]
fn an_msi_is_never_masked_its_ack_does_nothing_and_each_message_signals() {
    let mut w = world(QEMU);
    assert_eq!(get_msi(&mut w, S_H), ok(&[0, 0xFEE0_3000, 0x30]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    // Before any Ack: an MSI signals; a second one before the CPU takes
    // the first merges into the IRR bit.
    w.k.dev.msi(0x30);
    w.k.dev.msi(0x30);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    assert_eq!(interrupt(&mut w), None);
    assert_eq!(entry(&w, 0).source, Source::Msi);
    assert!(!entry(&w, 0).pending && !entry(&w, 0).masked);
    // Many more, with no Ack: each signals.
    for _ in 0..5 {
        w.k.dev.msi(0x30);
        assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    }
    assert_eq!(nt(&w, 0).word, B0);
    // Ack changes nothing and touches nothing.
    let before = snapshot(&w);
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    assert!(snapshot(&w) == before && w.k.dev.actions.is_empty());
    // Clear: the next message is lost, and nothing else changes.
    assert_eq!(clear(&mut w, S_H), ok(&[]));
    w.k.dev.msi(0x30);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Lost)));
    assert_eq!(w.k.dev.table.lost, 1);
}

#[test]
fn deleting_an_msis_last_handler_frees_its_vector_and_a_late_message_is_stale() {
    let mut w = world(QEMU);
    assert_eq!(get_msi(&mut w, S_H), ok(&[0, 0xFEE0_3000, 0x30]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    // A copy keeps the vector.
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_COPY,
        &[S_H2, 64, S_H, 64, 0xF],
        &[S_ROOT],
    );
    assert_eq!(r, ok(&[]));
    delete(&mut w, S_H);
    assert_eq!(entry(&w, 0).source, Source::Msi);
    assert_eq!(get_msi(&mut w, S_H), ok(&[1, 0xFEE0_3000, 0x31]));
    // The last one frees it, unbinds and touches no device.
    delete(&mut w, S_H2);
    assert_eq!(entry(&w, 0), Entry::FREE);
    assert!(node(&w, 0).is_null());
    assert!(w.k.dev.actions.is_empty() && w.k.dev.synic.writes.is_empty());
    // The device, never told, sends again: the message lands on a free
    // entry and is dropped.
    w.k.dev.msi(0x30);
    assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Stale)));
    assert_eq!(w.k.dev.table.stale, 1);
    assert_eq!(nt(&w, 0).state, NtfnState::Idle);
    // The vector is the lowest free again, for any source.
    assert_eq!(get_isa(&mut w, 4, S_H2), ok(&[0, 4, 0]));
}

#[test]
fn get_sint_writes_its_sint_once_unmasked_without_auto_eoi_or_polling() {
    let mut w = hyperv();
    assert_eq!(get_isa(&mut w, 4, S_H), ok(&[0, 4, 0]));
    w.k.dev.actions.clear();
    assert_eq!(get_sint(&mut w, 2, S_H2), ok(&[1]));
    assert_eq!(
        entry(&w, 1),
        Entry {
            source: Source::Sint(2),
            pending: false,
            masked: false
        }
    );
    assert_eq!(w.cap(rs(S_H2)), handler_cap(1));
    assert_eq!(cdt::parent(&w.k, rs(S_H2)), Some(rs(S_CONTROL)));
    let want = FakeSynic::RESERVED | 0x31;
    assert_eq!(w.k.dev.synic.writes, [(2, want)]);
    assert_eq!(w.k.dev.synic.sints[2], want);
    let v = w.k.dev.synic.sints[2];
    assert_eq!(v & (SINT_MASKED | SINT_AUTO_EOI | SINT_POLLING), 0);
    // Every other SINT is untouched, masked.
    for n in (0..16).filter(|&n| n != 2) {
        assert_eq!(w.k.dev.synic.sints[n], FakeSynic::RESERVED | SINT_MASKED);
    }
    assert!(w.k.dev.actions.is_empty(), "GetSint touches no I/O APIC");
    // Another SINT takes the next vector.
    assert_eq!(get_sint(&mut w, 15, S_H3), ok(&[2]));
    assert_eq!(w.k.dev.synic.writes[1], (15, FakeSynic::RESERVED | 0x32));
}

#[test]
fn get_sint_errors_in_order() {
    let root = [S_ROOT];
    let sint = label::GET_SINT;
    // 1: no SynIC, whatever the rest says.
    let mut w = world(QEMU);
    fails_m9(
        &mut w,
        &[
            case("no SynIC", sint, &[2, S_H, 64], &root, ILLEGAL),
            case("no SynIC, short", sint, &[], &[], ILLEGAL),
            case("no SynIC, SINT 16", sint, &[16, S_H, 64], &root, ILLEGAL),
        ],
    );
    let mut w = hyperv();
    assert_eq!(get_sint(&mut w, 2, S_H), ok(&[0]));
    let range = SyscallError::RangeError { min: 0, max: 15 };
    let cases = [
        // 2: the length.
        case("two registers", sint, &[3, S_H2], &root, TRUNCATED),
        case("no capability", sint, &[3, S_H2, 64], &[], TRUNCATED),
        case("SINT 16, short", sint, &[16, S_H2], &root, TRUNCATED),
        // 3: the argument.
        case("SINT 16", sint, &[16, S_H2, 64], &root, range),
        case("SINT 2^63", sint, &[1 << 63, S_H2, 64], &root, range),
        case("SINT 16, depth 0", sint, &[16, S_H2, 0], &root, range),
        // 5: the SINT has a handler.
        case("SINT 2 again", sint, &[2, S_H2, 64], &root, REVOKE_FIRST),
        case(
            "SINT 2 again, a full slot",
            sint,
            &[2, S_H, 64],
            &root,
            REVOKE_FIRST,
        ),
        // 6: the destination.
        case("depth 0", sint, &[3, S_H2, 0], &root, DEPTH),
        case(
            "a root that is no CNode",
            sint,
            &[3, S_H2, 64],
            &[S_N0],
            lookup(LookupFailure::InvalidRoot),
        ),
        case(
            "a full slot",
            sint,
            &[3, S_H, 64],
            &root,
            SyscallError::DeleteFirst,
        ),
    ];
    fails_m9(&mut w, &cases);
    // 5: no vector free: after the SINT's own check, before the slot.
    take_vectors(&mut w, 1);
    fails_m9(
        &mut w,
        &[
            case("no vector free", sint, &[3, S_H2, 64], &root, REVOKE_FIRST),
            case(
                "no vector free, a full slot",
                sint,
                &[3, S_H, 64],
                &root,
                REVOKE_FIRST,
            ),
        ],
    );
}

#[test]
fn a_sint_is_never_masked_on_delivery_and_its_ack_does_nothing() {
    let mut w = hyperv();
    assert_eq!(get_sint(&mut w, 2, S_H), ok(&[0]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    for _ in 0..4 {
        w.k.dev.raise_sint(2);
        assert_eq!(interrupt(&mut w), Some((0x30, Delivery::Signalled)));
    }
    assert_eq!(nt(&w, 0).word, B0);
    assert_eq!(w.k.dev.synic.writes.len(), 1, "delivery writes no SINT");
    assert!(!entry(&w, 0).pending && !entry(&w, 0).masked);
    let before = (snapshot(&w), w.k.dev.synic.clone());
    assert_eq!(ack(&mut w, S_H), ok(&[]));
    assert!((snapshot(&w), w.k.dev.synic.clone()) == before);
    // An edge on a SINT nobody issued is lost in the hypervisor.
    w.k.dev.raise_sint(3);
    assert_eq!(interrupt(&mut w), None);
    assert_eq!(w.k.dev.synic.lost_edges, 1);
}

#[test]
fn deleting_a_sints_last_handler_masks_it_once_and_frees_its_vector() {
    let mut w = hyperv();
    assert_eq!(get_sint(&mut w, 2, S_H), ok(&[0]));
    assert_eq!(set_ntfn(&mut w, S_H, S_N0_BADGED), ok(&[]));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_COPY,
        &[S_H2, 64, S_H, 64, 0xF],
        &[S_ROOT],
    );
    assert_eq!(r, ok(&[]));
    delete(&mut w, S_H);
    assert_eq!(w.k.dev.synic.writes.len(), 1, "a copy keeps the SINT");
    delete(&mut w, S_H2);
    assert_eq!(entry(&w, 0), Entry::FREE);
    assert!(node(&w, 0).is_null());
    // Only the mask bit: the vector and the reserved bits stay.
    let masked = FakeSynic::RESERVED | 0x30 | SINT_MASKED;
    assert_eq!(
        w.k.dev.synic.writes,
        [(2, FakeSynic::RESERVED | 0x30), (2, masked)]
    );
    w.k.dev.raise_sint(2);
    assert_eq!(interrupt(&mut w), None, "a masked SINT raises nothing");
    // The SINT and its vector can be issued again.
    assert_eq!(get_sint(&mut w, 2, S_H), ok(&[0]));
    assert_eq!(w.k.dev.synic.sints[2], FakeSynic::RESERVED | 0x30);
}

#[test]
fn revoking_irq_control_frees_msis_and_masks_sints() {
    let mut w = hyperv();
    assert_eq!(get_msi(&mut w, S_H), ok(&[0, 0xFEE0_3000, 0x30]));
    assert_eq!(get_sint(&mut w, 2, S_H2), ok(&[1]));
    assert_eq!(get_isa(&mut w, 4, S_H3), ok(&[2, 4, 0]));
    let r = invoke(
        &mut w,
        A,
        S_ROOT,
        cnode_label::CNODE_REVOKE,
        &[S_CONTROL, 64],
        &[],
    );
    assert_eq!(r, ok(&[]));
    for irq in 0..3 {
        assert_eq!(entry(&w, irq), Entry::FREE);
    }
    assert_eq!(w.k.dev.synic.sints[2] & SINT_MASKED, SINT_MASKED);
    assert!(masked(&w, 4));
}

#[test]
fn every_source_draws_from_the_same_192_vectors() {
    let mut w = hyperv();
    // MSIs take 191 of them, a SINT the last.
    take_vectors(&mut w, 1);
    assert_eq!(get_sint(&mut w, 2, S_H), ok(&[0]));
    let root = [S_ROOT];
    fails_m9(
        &mut w,
        &[
            case("GetMSI", label::GET_MSI, &[S_H2, 64], &root, REVOKE_FIRST),
            case(
                "GetSint",
                label::GET_SINT,
                &[3, S_H2, 64],
                &root,
                REVOKE_FIRST,
            ),
            case(
                "GetISA",
                label::GET_ISA,
                &[4, S_H2, 64],
                &root,
                REVOKE_FIRST,
            ),
            case(
                "GetIOAPIC",
                label::GET_IOAPIC,
                &[16, 0, 0, S_H2, 64],
                &root,
                REVOKE_FIRST,
            ),
        ],
    );
    // The SINT's deletion gives its vector back.
    delete(&mut w, S_H);
    assert_eq!(get_msi(&mut w, S_H2), ok(&[0, 0xFEE0_3000, 0x30]));
}

#[test]
fn check_finds_broken_m9_entries() {
    let mut w = hyperv();
    assert_eq!(get_sint(&mut w, 2, S_H), ok(&[0]));
    assert_eq!(get_msi(&mut w, S_H2), ok(&[1, 0xFEE0_3000, 0x31]));
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
    for (irq, pending, masked) in [(0, true, false), (1, false, true), (1, true, true)] {
        bad(
            &|w| {
                let mut e = entry(w, irq);
                e.pending = pending;
                e.masked = masked;
                w.k.dev.table.set(irq, e);
            },
            "an MSI or SINT entry is pending or masked",
        );
    }
    bad(
        &|w| {
            let e = entry(w, 0);
            w.k.dev.table.set(5, e);
        },
        "a SINT has two entries",
    );
    bad(
        &|w| w.k.dev.synic.enabled = false,
        "a SINT entry without a SynIC, or past SINT 15",
    );
    bad(
        &|w| {
            let mut e = entry(w, 0);
            e.source = Source::Sint(16);
            w.k.dev.table.set(0, e);
        },
        "a SINT entry without a SynIC, or past SINT 15",
    );
}

#[test]
fn sint_actions_write_what_the_design_says() {
    let issue = SintAction::Issue {
        sint: 7,
        vector: 0x45,
    };
    assert_eq!(issue.sint(), 7);
    let old = 0xFFFF_0000_0000_FF00 | SINT_MASKED | SINT_AUTO_EOI | SINT_POLLING | 0x99;
    assert_eq!(issue.value(old), 0xFFFF_0000_0000_FF45);
    let mask = SintAction::Mask(9);
    assert_eq!(mask.sint(), 9);
    assert_eq!(mask.value(0x45), SINT_MASKED | 0x45);
}
