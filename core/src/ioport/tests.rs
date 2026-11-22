//! Host tests of [`crate::ioport`]: the bitmap and the kernel's ports,
//! `IOPortControl_Issue` and the IOPort accesses through system calls as
//! threads make them ([`crate::syscall::handle_syscall`]), every error row
//! of `docs/abi.md` in its order with nothing changed by a failed call,
//! copies and deletion, and a proptest of random issues, copies,
//! deletions, revokes and accesses against a model of issued ranges.

use std::collections::BTreeMap;
use std::vec::Vec;

use proptest::prelude::*;

use super::*;
use crate::cap::{CapType, Rights};
use crate::cdt;
use crate::error::{LookupFailure, SyscallError};
use crate::invoke::label as cnode_label;
use crate::ipc::tests::*;
use crate::ipc::{MessageInfo, word};
use crate::slot::{Slot, SlotMemory};
use crate::syscall::Outcome;
use crate::testing::{FakeDevices, PortAccess};

/// Root slots: IOPortControl, a root; slots 21 to 31 are free.
const S_CONTROL: u64 = 20;
const S_P: u64 = 21;
const S_P2: u64 = 22;
const S_P3: u64 = 23;

fn world() -> World {
    let mut w = World::new();
    let control = Cap::new(CapType::IoPortControl, 0, 0, Rights::NONE, false, 0);
    cdt::insert_root(&mut w.k, rs(S_CONTROL), control);
    w.check();
    w
}

fn kernel_reply(w: &World, t: usize) -> (u64, Vec<u64>) {
    let m = MessageInfo::from_word(w.regs(t).rsi);
    let words = (0..m.length() as usize).map(|i| w.mr(t, i)).collect();
    (m.label(), words)
}

fn error(err: SyscallError) -> (u64, Vec<u64>) {
    let (words, n) = err.detail();
    (err.code(), words[..n].to_vec())
}

fn ok(words: &[u64]) -> (u64, Vec<u64>) {
    (0, words.to_vec())
}

/// A calls invocation `label` on `cptr` with `mrs` and the extra
/// capabilities `caps`; returns the reply.
fn invoke(w: &mut World, cptr: u64, label: u64, mrs: &[u64], caps: &[u64]) -> (u64, Vec<u64>) {
    let mut regs = [0; 4];
    for (i, &m) in mrs.iter().enumerate() {
        match regs.get_mut(i) {
            Some(r) => *r = m,
            None => w.set_buf(A, word::MSG + i, m),
        }
    }
    for (i, &c) in caps.iter().enumerate() {
        w.set_buf(A, word::CAPS_OR_BADGES + i, c);
    }
    let rsi = MessageInfo::new(label, 0, caps.len() as u64, mrs.len() as u64).word();
    assert_eq!(w.syscall(A, 1, cptr, rsi, Some(regs)), Outcome::Done);
    w.check();
    kernel_reply(w, A)
}

fn issue(w: &mut World, first: u64, last: u64, slot: u64) -> (u64, Vec<u64>) {
    invoke(
        w,
        S_CONTROL,
        label::ISSUE,
        &[first, last, slot, 64],
        &[S_ROOT],
    )
}

fn delete(w: &mut World, slot: u64) {
    assert_eq!(
        invoke(w, S_ROOT, cnode_label::CNODE_DELETE, &[slot, 64], &[]),
        ok(&[])
    );
}

/// Whether the bitmap marks exactly the ports of the disjoint `ranges`.
fn marks_exactly(w: &World, ranges: &[(u16, u16)]) -> bool {
    let n: u32 = ranges.iter().map(|&(a, b)| u32::from(b - a) + 1).sum();
    w.k.dev.ports.count() == n
        && ranges
            .iter()
            .all(|&(a, b)| (a..=b).all(|p| w.k.dev.ports.is_set(p)))
}

/// The root slots, the bitmap and the port accesses so far.
fn snapshot(w: &World) -> (Vec<Slot>, PortBitmap, Vec<PortAccess>) {
    (
        (0..32).map(|i| w.k.load(rs(i))).collect(),
        w.k.dev.ports.clone(),
        w.k.dev.port_log.clone(),
    )
}

/// An error case: what it is, the invoked `CPtr`, the label, the message
/// registers, the extra capabilities, and the error it must return.
type Case<'a> = (&'a str, u64, u64, &'a [u64], &'a [u64], SyscallError);

fn fails(w: &mut World, cases: &[Case<'_>]) {
    for &(what, cptr, label, mrs, caps, err) in cases {
        let before = snapshot(w);
        assert_eq!(invoke(w, cptr, label, mrs, caps), error(err), "{what}");
        assert!(snapshot(w) == before, "{what} changed something");
    }
}

// ---------------------------------------------------------------------------
// The bitmap and the kernel's ports
// ---------------------------------------------------------------------------

#[test]
fn the_kernel_keeps_the_pic_and_imcr_ports() {
    for (first, last, want) in [
        (0x20, 0x23, true),
        (0x00, 0x20, true),
        (0x23, 0x23, true),
        (0x24, 0x9F, false),
        (0x9F, 0xA0, true),
        (0xA1, 0xFFFF, true),
        (0xA2, 0xFFFF, false),
        (0x00, 0x1F, false),
        (0x00, 0xFFFF, true),
        (0x3F8, 0x3FF, false),
    ] {
        assert_eq!(reserved(first, last), want, "{first:#x}-{last:#x}");
    }
}

#[test]
fn the_bitmap_sets_and_clears_exactly_a_range_across_words() {
    let mut b = PortBitmap::new();
    for (first, last) in [
        (0, 0),
        (63, 64),
        (0x3F8, 0x3FF),
        (100, 300),
        (0xFFC0, 0xFFFF),
    ] {
        b.set_range(first, last, true);
        assert!(b.is_set(first) && b.is_set(last));
        if first > 0 {
            assert!(!b.is_set(first - 1) && !b.any_set(0, first - 1));
        }
        if last < u16::MAX {
            assert!(!b.is_set(last + 1) && !b.any_set(last + 1, u16::MAX));
        }
        assert_eq!(b.count(), u32::from(last - first) + 1);
        assert!(b.any_set(first, last) && b.any_set(0, u16::MAX));
        b.set_range(first, last, false);
        assert_eq!(b, PortBitmap::new());
    }
    b.set_range(0, u16::MAX, true);
    assert_eq!(b.count(), 65_536);
    assert_eq!(std::format!("{b:?}"), "PortBitmap(65536 ports issued)");
}

#[test]
fn an_ioport_capability_holds_its_range_in_its_data_word() {
    let c = port_cap(0x3F8, 0x3FF);
    assert_eq!(
        (c.cap_type(), c.object(), c.size_bits()),
        (CapType::IoPort, 0, 0)
    );
    assert_eq!(c.data, 0x03FF_03F8);
    assert_eq!(port_range(&c), Some((0x3F8, 0x3FF)));
    assert_eq!(port_range(&ntfn_cap(0, RW, 0x03FF_03F8)), None);
    assert!(c.same_object(&port_cap(0x3F8, 0x3FF)) && !c.same_object(&port_cap(0x3F8, 0x3FE)));
    assert_eq!(
        (Width::Byte.bytes(), Width::Word.mask(), Width::Dword.mask()),
        (1, 0xFFFF, u32::MAX)
    );
}

// ---------------------------------------------------------------------------
// IOPortControl_Issue
// ---------------------------------------------------------------------------

#[test]
fn issue_makes_a_revocable_child_of_iocontrol_and_marks_its_range() {
    let mut w = world();
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
    assert_eq!(w.cap(rs(S_P)), port_cap(0x3F8, 0x3FF));
    assert_eq!(cdt::parent(&w.k, rs(S_P)), Some(rs(S_CONTROL)));
    assert!(w.k.load(rs(S_P)).node.original());
    assert!(marks_exactly(&w, &[(0x3F8, 0x3FF)]));
    // Ranges that touch but do not overlap; one port; the last port.
    assert_eq!(issue(&mut w, 0x3F0, 0x3F7, S_P2), ok(&[]));
    assert_eq!(issue(&mut w, 0x400, 0x400, S_P3), ok(&[]));
    assert_eq!(issue(&mut w, 0xFFFF, 0xFFFF, 24), ok(&[]));
    assert_eq!(w.k.dev.ports.count(), 8 + 8 + 1 + 1);
    assert!(w.k.dev.port_log.is_empty(), "issuing touches no port");
}

#[test]
fn issue_errors_in_order() {
    let mut w = world();
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
    let root: &[u64] = &[S_ROOT];
    let c = S_CONTROL;
    let i = label::ISSUE;
    let arg = SyscallError::InvalidArgument;
    let depth = SyscallError::RangeError { min: 1, max: 64 };
    let cases: &[Case<'_>] = &[
        (
            "In8 on IOPortControl",
            c,
            label::IN8,
            &[0x3F8],
            &[],
            SyscallError::IllegalOperation,
        ),
        (
            "Out32 on IOPortControl",
            c,
            label::OUT32,
            &[0xF4, 0x10],
            &[],
            SyscallError::IllegalOperation,
        ),
        (
            "reserved 0x77",
            c,
            0x77,
            &[],
            &[],
            SyscallError::IllegalOperation,
        ),
        (
            "reserved 0x7F",
            c,
            0x7F,
            &[],
            &[],
            SyscallError::IllegalOperation,
        ),
        (
            "GetISA",
            c,
            0x60,
            &[4, S_P2, 64],
            root,
            SyscallError::IllegalOperation,
        ),
        (
            "3 registers",
            c,
            i,
            &[0x60, 0x61, S_P2],
            root,
            SyscallError::TruncatedMessage,
        ),
        (
            "no capability",
            c,
            i,
            &[0x60, 0x61, S_P2, 64],
            &[],
            SyscallError::TruncatedMessage,
        ),
        (
            "first 0x10000",
            c,
            i,
            &[0x1_0000, 0x1_0001, S_P2, 64],
            root,
            arg(0),
        ),
        (
            "first 2^32 + 0x60",
            c,
            i,
            &[1 << 32 | 0x60, 0x61, S_P2, 64],
            root,
            arg(0),
        ),
        (
            "first bad, last < first",
            c,
            i,
            &[0x1_0000, 0, S_P2, 64],
            root,
            arg(0),
        ),
        (
            "last 0x10000",
            c,
            i,
            &[0x60, 0x1_0000, S_P2, 64],
            root,
            arg(1),
        ),
        ("last < first", c, i, &[0x61, 0x60, S_P2, 64], root, arg(1)),
        (
            "a reserved port, last bad",
            c,
            i,
            &[0x20, 0x1_0000, S_P2, 64],
            root,
            arg(1),
        ),
        (
            "a reserved port",
            c,
            i,
            &[0x1F, 0x20, S_P2, 64],
            root,
            arg(0),
        ),
        ("0xA0 to 0xA1", c, i, &[0xA0, 0xA1, S_P2, 64], root, arg(0)),
        ("every port", c, i, &[0, 0xFFFF, S_P2, 64], root, arg(0)),
        (
            "reserved and overlapping",
            c,
            i,
            &[0x20, 0x400, S_P2, 64],
            root,
            arg(0),
        ),
        (
            "overlapping the end",
            c,
            i,
            &[0x3FF, 0x400, S_P2, 64],
            root,
            SyscallError::RevokeFirst,
        ),
        (
            "overlapping the start",
            c,
            i,
            &[0x3F0, 0x3F8, S_P2, 64],
            root,
            SyscallError::RevokeFirst,
        ),
        (
            "inside",
            c,
            i,
            &[0x3FA, 0x3FA, S_P2, 64],
            root,
            SyscallError::RevokeFirst,
        ),
        (
            "the same range",
            c,
            i,
            &[0x3F8, 0x3FF, S_P2, 64],
            root,
            SyscallError::RevokeFirst,
        ),
        (
            "overlapping, depth 0",
            c,
            i,
            &[0x3F8, 0x3FF, S_P2, 0],
            root,
            SyscallError::RevokeFirst,
        ),
        ("depth 0", c, i, &[0x60, 0x61, S_P2, 0], root, depth),
        ("depth 65", c, i, &[0x60, 0x61, S_P2, 65], root, depth),
        (
            "a root that is no CNode",
            c,
            i,
            &[0x60, 0x61, S_P2, 64],
            &[S_EP0],
            SyscallError::FailedLookup {
                source: false,
                failure: LookupFailure::InvalidRoot,
            },
        ),
        (
            "a full slot",
            c,
            i,
            &[0x60, 0x61, S_P, 64],
            root,
            SyscallError::DeleteFirst,
        ),
    ];
    fails(&mut w, cases);
}

// ---------------------------------------------------------------------------
// In and Out
// ---------------------------------------------------------------------------

#[test]
fn in_reads_zero_extended_within_the_range_width_included() {
    let mut w = world();
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
    // An unwritten port reads 0xDEADBEEF in the model: each width keeps
    // its own bytes only.
    let floating = u64::from(FakeDevices::FLOATING);
    for port in 0x3F8..=0x3FF {
        assert_eq!(
            invoke(&mut w, S_P, label::IN8, &[port], &[]),
            ok(&[floating & 0xFF])
        );
    }
    assert_eq!(
        invoke(&mut w, S_P, label::IN16, &[0x3FE], &[]),
        ok(&[floating & 0xFFFF])
    );
    assert_eq!(
        invoke(&mut w, S_P, label::IN32, &[0x3FC], &[]),
        ok(&[floating])
    );
    assert_eq!(
        invoke(&mut w, S_P, label::IN32, &[0x3F8], &[]),
        ok(&[floating])
    );
    let last = w.k.dev.port_log.last().copied().unwrap();
    assert_eq!(
        last,
        PortAccess {
            port: 0x3F8,
            width: Width::Dword,
            written: None
        }
    );
}

#[test]
fn out_writes_the_low_bytes_and_in_reads_them_back() {
    let mut w = world();
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
    assert_eq!(
        invoke(&mut w, S_P, label::OUT8, &[0x3FF, 0xFFFF_FF5A], &[]),
        ok(&[])
    );
    assert_eq!(invoke(&mut w, S_P, label::IN8, &[0x3FF], &[]), ok(&[0x5A]));
    assert_eq!(
        invoke(&mut w, S_P, label::OUT16, &[0x3FE, 0xFFFF_1234], &[]),
        ok(&[])
    );
    assert_eq!(
        invoke(&mut w, S_P, label::OUT32, &[0x3FC, 0x1_8765_4321], &[]),
        ok(&[])
    );
    let writes: Vec<(u16, Width, Option<u32>)> =
        w.k.dev
            .port_log
            .iter()
            .filter(|a| a.written.is_some())
            .map(|a| (a.port, a.width, a.written))
            .collect();
    assert_eq!(
        writes,
        [
            (0x3FF, Width::Byte, Some(0x5A)),
            (0x3FE, Width::Word, Some(0x1234)),
            (0x3FC, Width::Dword, Some(0x8765_4321)),
        ]
    );
    // Send performs the access and drops the reply.
    let rsi = MessageInfo::new(label::OUT8, 0, 0, 2).word();
    w.syscall(A, 3, S_P, rsi, Some([0x3F8, 0x41, 7, 8]));
    assert_eq!((w.regs(A).rsi, w.mrs(A)), (rsi, [0x3F8, 0x41, 7, 8]));
    assert_eq!(w.k.dev.port_values[&0x3F8], 0x41);
    // So does a thread without an IPC buffer.
    w.syscall(
        F,
        1,
        S_P,
        MessageInfo::new(label::IN8, 0, 0, 1).word(),
        Some([0x3F8, 0, 0, 0]),
    );
    assert_eq!(kernel_reply(&w, F), ok(&[0x41]));
}

#[test]
fn ioport_errors_in_order() {
    let mut w = world();
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
    assert_eq!(issue(&mut w, 0xFFF0, 0xFFFF, S_P2), ok(&[]));
    let p = S_P;
    let ill = SyscallError::IllegalOperation;
    let arg0 = SyscallError::InvalidArgument(0);
    let cases: &[Case<'_>] = &[
        (
            "Issue on an IOPort",
            p,
            label::ISSUE,
            &[0x60, 0x61, S_P3, 64],
            &[S_ROOT],
            ill,
        ),
        ("reserved 0x77", p, 0x77, &[0x3F8], &[], ill),
        ("label 0x70 + 0x10", p, 0x80, &[0x3F8], &[], ill),
        (
            "In8, no register",
            p,
            label::IN8,
            &[],
            &[],
            SyscallError::TruncatedMessage,
        ),
        (
            "In32, no register",
            p,
            label::IN32,
            &[],
            &[],
            SyscallError::TruncatedMessage,
        ),
        (
            "Out8, one register",
            p,
            label::OUT8,
            &[0x3F8],
            &[],
            SyscallError::TruncatedMessage,
        ),
        (
            "Out8, bad port, one register",
            p,
            label::OUT8,
            &[0x1_0000],
            &[],
            SyscallError::TruncatedMessage,
        ),
        ("In8 at 0x10000", p, label::IN8, &[0x1_0000], &[], arg0),
        (
            "In8 at 2^32 + 0x3F8",
            p,
            label::IN8,
            &[1 << 32 | 0x3F8],
            &[],
            arg0,
        ),
        ("Out16 at 2^63", p, label::OUT16, &[1 << 63, 0], &[], arg0),
        ("In8 below the range", p, label::IN8, &[0x3F7], &[], ill),
        ("In8 above it", p, label::IN8, &[0x400], &[], ill),
        ("In16 at the last port", p, label::IN16, &[0x3FF], &[], ill),
        ("In32 two ports short", p, label::IN32, &[0x3FD], &[], ill),
        (
            "Out32 straddling the start",
            p,
            label::OUT32,
            &[0x3F6, 0],
            &[],
            ill,
        ),
        ("In16 at 0x3F7", p, label::IN16, &[0x3F7], &[], ill),
        (
            "In32 at 0xFFFE: no wrap",
            S_P2,
            label::IN32,
            &[0xFFFE],
            &[],
            ill,
        ),
        (
            "Out16 at 0xFFFF: no wrap",
            S_P2,
            label::OUT16,
            &[0xFFFF, 0],
            &[],
            ill,
        ),
        (
            "In8 at 0xFFFF of another range",
            p,
            label::IN8,
            &[0xFFFF],
            &[],
            ill,
        ),
    ];
    fails(&mut w, cases);
    // The last ports of a range ending at 0xFFFF are reachable.
    assert_eq!(invoke(&mut w, S_P2, label::IN32, &[0xFFFC], &[]).0, 0);
    assert_eq!(invoke(&mut w, S_P2, label::IN8, &[0xFFFF], &[]).0, 0);
}

// ---------------------------------------------------------------------------
// Copies and deletion
// ---------------------------------------------------------------------------

#[test]
fn a_range_is_free_again_only_once_its_last_capability_is_deleted() {
    let mut w = world();
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
    let copy = |w: &mut World, label, dst, extra: &[u64]| {
        let mut mrs = std::vec![dst, 64, S_P, 64, 0xF];
        mrs.extend_from_slice(extra);
        invoke(w, S_ROOT, label, &mrs, &[S_ROOT])
    };
    assert_eq!(copy(&mut w, cnode_label::CNODE_COPY, S_P2, &[]), ok(&[]));
    // Mint cannot narrow it: its data word is ignored.
    assert_eq!(
        copy(&mut w, cnode_label::CNODE_MINT, S_P3, &[0x03F9_03F9]),
        ok(&[])
    );
    assert_eq!(w.cap(rs(S_P3)), port_cap(0x3F8, 0x3FF));
    assert_eq!(cdt::parent(&w.k, rs(S_P2)), Some(rs(S_P)));
    assert_eq!(invoke(&mut w, S_P3, label::IN8, &[0x3FF], &[]).0, 0);
    delete(&mut w, S_P);
    delete(&mut w, S_P3);
    assert_eq!(
        issue(&mut w, 0x3F8, 0x3FF, S_P),
        error(SyscallError::RevokeFirst)
    );
    assert_eq!(w.k.dev.ports.count(), 8);
    delete(&mut w, S_P2);
    assert_eq!(w.k.dev.ports.count(), 0);
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
}

#[test]
fn revoking_iocontrol_frees_every_range_and_it_cannot_be_copied() {
    let mut w = world();
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
    assert_eq!(issue(&mut w, 0xF4, 0xF7, S_P2), ok(&[]));
    let r = invoke(
        &mut w,
        S_ROOT,
        cnode_label::CNODE_COPY,
        &[S_P3, 64, S_CONTROL, 64, 0xF],
        &[S_ROOT],
    );
    assert_eq!(r, error(SyscallError::IllegalOperation));
    let r = invoke(
        &mut w,
        S_ROOT,
        cnode_label::CNODE_REVOKE,
        &[S_CONTROL, 64],
        &[],
    );
    assert_eq!(r, ok(&[]));
    assert!(w.cap(rs(S_P)).is_null() && w.cap(rs(S_P2)).is_null());
    assert_eq!(w.k.dev.ports.count(), 0);
    assert_eq!(issue(&mut w, 0x3F8, 0x3FF, S_P), ok(&[]));
}

#[test]
fn the_hooks_free_only_the_last_capabilitys_range() {
    let c = port_cap(0x60, 0x64);
    assert_eq!(finalise(c, false), None);
    assert_eq!(finalise(c, true), Some(c));
    assert_eq!(finalise(ntfn_cap(0, RW, 0), true), None);
    let mut k = crate::testing::TestKernel::new(0, 0x1000);
    k.dev.ports.set_range(0x60, 0x64, true);
    k.dev.ports.set_range(0x70, 0x71, true);
    after_delete(&mut k, c);
    assert!(!k.dev.ports.any_set(0x60, 0x64) && k.dev.ports.count() == 2);
    after_delete(&mut k, ntfn_cap(0, RW, 0x70));
    assert_eq!(k.dev.ports.count(), 2);
}

// ---------------------------------------------------------------------------
// Random sequences against a model
// ---------------------------------------------------------------------------

/// A step of the proptest.
#[derive(Clone, Debug)]
enum Op {
    /// Issue `[first, first + len]` into slot `slot`.
    Issue {
        first: u16,
        len: u16,
        slot: u8,
    },
    /// `CNode_Copy` slot `src` to `dst`.
    Copy {
        src: u8,
        dst: u8,
    },
    Delete {
        slot: u8,
    },
    /// Revoke IOPortControl.
    Revoke,
    /// An access by the capability in `slot`: `width` 1, 2 or 4, `out`.
    Access {
        slot: u8,
        port: u16,
        width: u8,
        out: bool,
    },
}

/// Slots 21 to 28 are the proptest's.
const FIRST: u64 = 21;
const SLOTS: u8 = 8;

fn op() -> impl Strategy<Value = Op> {
    // Ports near COM1, the PIC and the top, so ranges meet.
    let port = prop_oneof![0x18u16..0x30, 0x3F0u16..0x410, 0xFFF0u16..=0xFFFF];
    prop_oneof![
        3 => (port.clone(), 0u16..12, 0..SLOTS).prop_map(|(first, len, slot)| Op::Issue { first, len, slot }),
        2 => (0..SLOTS, 0..SLOTS).prop_map(|(src, dst)| Op::Copy { src, dst }),
        2 => (0..SLOTS).prop_map(|slot| Op::Delete { slot }),
        1 => Just(Op::Revoke),
        4 => (0..SLOTS, port, prop_oneof![Just(1u8), Just(2), Just(4)], any::<bool>())
            .prop_map(|(slot, port, width, out)| Op::Access { slot, port, width, out }),
    ]
}

/// The model: each slot's range, if it holds an IOPort capability.
type Model = BTreeMap<u8, (u16, u16)>;

/// The paths a sequence took, counted.
#[derive(Clone, Copy, Debug, Default)]
struct Paths {
    issued: u32,
    refused_reserved: u32,
    refused_overlap: u32,
    copied: u32,
    freed: u32,
    accessed: u32,
    refused_access: u32,
}

fn run(ops: &[Op]) -> Paths {
    let mut w = world();
    let mut m = Model::new();
    let mut paths = Paths::default();
    for op in ops {
        let before = w.k.dev.port_log.len();
        match *op {
            Op::Issue { first, len, slot } => {
                let last = first.saturating_add(len);
                let s = FIRST + u64::from(slot);
                let r = issue(&mut w, u64::from(first), u64::from(last), s);
                let overlaps = m.values().any(|&(a, b)| first <= b && a <= last);
                let want = if reserved(first, last) {
                    paths.refused_reserved += 1;
                    error(SyscallError::InvalidArgument(0))
                } else if overlaps {
                    paths.refused_overlap += 1;
                    error(SyscallError::RevokeFirst)
                } else if let std::collections::btree_map::Entry::Vacant(e) = m.entry(slot) {
                    paths.issued += 1;
                    e.insert((first, last));
                    ok(&[])
                } else {
                    error(SyscallError::DeleteFirst)
                };
                assert_eq!(r, want, "{op:?}");
            }
            Op::Copy { src, dst } => {
                let r = invoke(
                    &mut w,
                    S_ROOT,
                    cnode_label::CNODE_COPY,
                    &[FIRST + u64::from(dst), 64, FIRST + u64::from(src), 64, 0xF],
                    &[S_ROOT],
                );
                let want = match (m.get(&src).copied(), m.contains_key(&dst)) {
                    (_, true) => error(SyscallError::DeleteFirst),
                    (None, false) => error(SyscallError::FailedLookup {
                        source: true,
                        failure: LookupFailure::MissingCapability { bits_left: 0 },
                    }),
                    (Some(r), false) => {
                        paths.copied += 1;
                        m.insert(dst, r);
                        ok(&[])
                    }
                };
                assert_eq!(r, want, "{op:?}");
            }
            Op::Delete { slot } => {
                delete(&mut w, FIRST + u64::from(slot));
                if let Some(r) = m.remove(&slot)
                    && !m.values().any(|&o| o == r)
                {
                    paths.freed += 1;
                }
            }
            Op::Revoke => {
                let r = invoke(
                    &mut w,
                    S_ROOT,
                    cnode_label::CNODE_REVOKE,
                    &[S_CONTROL, 64],
                    &[],
                );
                assert_eq!(r, ok(&[]));
                m.clear();
            }
            Op::Access {
                slot,
                port,
                width,
                out,
            } => {
                let (lbl, w_) = match (width, out) {
                    (1, false) => (label::IN8, Width::Byte),
                    (2, false) => (label::IN16, Width::Word),
                    (4, false) => (label::IN32, Width::Dword),
                    (1, true) => (label::OUT8, Width::Byte),
                    (2, true) => (label::OUT16, Width::Word),
                    _ => (label::OUT32, Width::Dword),
                };
                let mrs = [u64::from(port), 0xAB_CDEF_0123];
                let n = if out { 2 } else { 1 };
                let r = invoke(&mut w, FIRST + u64::from(slot), lbl, &mrs[..n], &[]);
                let inside = m.get(&slot).is_some_and(|&(a, b)| {
                    port >= a && u32::from(port) + u32::from(width) - 1 <= u32::from(b)
                });
                match m.get(&slot) {
                    None => assert_eq!(r, error(SyscallError::InvalidCapability(0)), "{op:?}"),
                    Some(_) if !inside => {
                        paths.refused_access += 1;
                        assert_eq!(r, error(SyscallError::IllegalOperation), "{op:?}")
                    }
                    Some(_) => {
                        paths.accessed += 1;
                        assert_eq!(r.0, 0, "{op:?}");
                        let a = *w.k.dev.port_log.last().unwrap();
                        assert_eq!((a.port, a.width), (port, w_));
                        if out {
                            assert_eq!(a.written, Some(0xCDEF_0123 & w_.mask()));
                        } else {
                            assert!(r.1[0] <= u64::from(w_.mask()));
                        }
                    }
                }
                if !inside {
                    assert_eq!(
                        w.k.dev.port_log.len(),
                        before,
                        "a refused access touched a port"
                    );
                }
            }
        }
        // The bitmap is the union of the model's ranges, which are
        // disjoint and hold no reserved port.
        let mut ranges: Vec<(u16, u16)> = m.values().copied().collect();
        ranges.sort();
        ranges.dedup();
        assert!(
            ranges.windows(2).all(|p| p[0].1 < p[1].0),
            "overlapping ranges {ranges:?}"
        );
        assert!(marks_exactly(&w, &ranges), "{ranges:?}");
        for (&s, &r) in &m {
            assert_eq!(w.cap(rs(FIRST + u64::from(s))), port_cap(r.0, r.1));
            assert!(!reserved(r.0, r.1));
        }
    }
    paths
}

#[test]
fn random_sequences_reach_every_path() {
    use proptest::strategy::ValueTree;
    use proptest::test_runner::{Config, RngAlgorithm, TestRng, TestRunner};
    let mut runner = TestRunner::new_with_rng(
        Config {
            failure_persistence: None,
            ..Config::default()
        },
        TestRng::deterministic_rng(RngAlgorithm::ChaCha),
    );
    let cases = if cfg!(miri) { 4 } else { 64 };
    let mut t = Paths::default();
    for _ in 0..cases {
        let ops = proptest::collection::vec(op(), 40)
            .new_tree(&mut runner)
            .unwrap()
            .current();
        let p = run(&ops);
        t.issued += p.issued;
        t.refused_reserved += p.refused_reserved;
        t.refused_overlap += p.refused_overlap;
        t.copied += p.copied;
        t.freed += p.freed;
        t.accessed += p.accessed;
        t.refused_access += p.refused_access;
    }
    for (what, n) in [
        ("issued", t.issued),
        ("refused a reserved port", t.refused_reserved),
        ("refused an overlap", t.refused_overlap),
        ("copied", t.copied),
        ("freed a range", t.freed),
        ("accessed a port", t.accessed),
        ("refused an access", t.refused_access),
    ] {
        assert!(n > 0, "no sequence {what}: {t:?}");
    }
}

proptest! {
    #![proptest_config(ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    })]

    #[test]
    fn random_issues_copies_deletions_and_accesses_match_a_model_of_ranges(
        ops in proptest::collection::vec(op(), 1..if cfg!(miri) { 12 } else { 60 })
    ) {
        run(&ops);
    }
}
