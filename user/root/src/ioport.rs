//! `test=ioport`: IOPortControl and IOPort from ring 3 (`docs/abi.md`,
//! "IOPortControl and IOPort"; `docs/design.md`, "I/O ports").
//!
//! The root task issues COM1's range `0x3F8`-`0x3FF` from IOPortControl
//! (slot 7) and checks, in order:
//!
//! - `Issue`'s errors in `docs/abi.md`'s order: the label, the length, the
//!   bounds, the kernel's ports (`0x20`-`0x23`, `0xA0`-`0xA1`), an overlap
//!   with an issued range, then the destination slot;
//! - accesses at the ends of the range, the width included: In8 at both
//!   ends, In16 and In32 ending at `0x3FF`, and `IllegalOperation` one port
//!   past either end; a port above `0xFFFF` is `InvalidArgument(0)`, not an
//!   alias;
//! - In's reply through COM1's scratch register (`0x3FF`, which nothing
//!   else uses): Out8 writes the low byte only, `Send` performs an Out and
//!   drops the reply, and In8 returns the byte, zero-extended;
//! - copies and a mint (whose data cannot narrow the range) reach the same
//!   ports; the range stays issued while any capability to it does, and
//!   deleting the last one, or revoking IOPortControl, frees it;
//! - IOPortControl cannot be copied, and neither type takes the other's
//!   labels.
//!
//! The test touches only the scratch register of COM1, which the kernel's
//! writer never reads, so its output is unaffected.

use libsys::bootinfo::{CAP_INIT_CNODE as CNODE, CAP_IO_PORT_CONTROL};
use libsys::device::{ioport_control_issue, ioport_in8, ioport_in16, ioport_in32, ioport_out8};
use libsys::invoke::{Slot, cnode_copy, cnode_delete, cnode_mint, cnode_revoke, invoke};
use libsys::{
    BootInfo, CPtr, Error, Ipc, Message, MessageInfo, Rights, SyscallError, println, send,
};

use crate::fail;

const COM1: u16 = 0x3F8;
const SCRATCH: u16 = 0x3FF;

/// An error case: what it is, the label, the message registers, the
/// extra capabilities and the error.
type Case<'a> = (&'a str, u64, &'a [u64], &'a [CPtr], SyscallError);

fn root_slot(n: CPtr) -> Slot {
    Slot::root_cnode(n)
}

/// Fails unless `r` is the kernel error `want`.
fn expect_err<T: core::fmt::Debug>(r: Result<T, Error>, want: SyscallError, what: &str) {
    match r {
        Err(e) if e.kernel() == Some(want) => {}
        other => fail!("ioport: {what}: got {other:?}, want {want:?}"),
    }
}

/// Fails unless `r` succeeded.
fn expect_ok<T>(r: Result<T, Error>, what: &str) -> T {
    r.unwrap_or_else(|e| fail!("ioport: {what}: {e}"))
}

/// A raw invocation of `label` on `cap` with `args` and `caps`.
fn raw(ipc: Ipc, cap: CPtr, label: u64, args: &[u64], caps: &[CPtr]) -> Result<(), Error> {
    invoke(Some(ipc), cap, label, args, caps).map(|_| ())
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let first = bi.empty.start;
    let (p, p2, p3, q) = (first, first + 1, first + 2, first + 3);
    let full = first + 4;
    let control = CAP_IO_PORT_CONTROL;
    println!("ioport: IOPortControl in slot {control}; the test's slots start at {first}");

    // A full slot for the DeleteFirst row: a copy of the root CNode.
    expect_ok(
        cnode_copy(ipc, root_slot(full), root_slot(CNODE), Rights::ALL),
        "filling a slot",
    );

    // Issue's errors, in order.
    let arg = SyscallError::InvalidArgument;
    let cases: [Case<'_>; 14] = [
        (
            "In8 on IOPortControl",
            0x71,
            &[0x3F8],
            &[],
            SyscallError::IllegalOperation,
        ),
        (
            "reserved label 0x77",
            0x77,
            &[],
            &[],
            SyscallError::IllegalOperation,
        ),
        (
            "3 registers",
            0x70,
            &[0x60, 0x61, p],
            &[CNODE],
            SyscallError::TruncatedMessage,
        ),
        (
            "no capability",
            0x70,
            &[0x60, 0x61, p, 64],
            &[],
            SyscallError::TruncatedMessage,
        ),
        (
            "first 0x10000",
            0x70,
            &[0x1_0000, 0x1_0001, p, 64],
            &[CNODE],
            arg(0),
        ),
        (
            "last 0x10000",
            0x70,
            &[0x60, 0x1_0000, p, 64],
            &[CNODE],
            arg(1),
        ),
        (
            "last below first",
            0x70,
            &[0x61, 0x60, p, 64],
            &[CNODE],
            arg(1),
        ),
        (
            "a reserved port, last bad",
            0x70,
            &[0x20, 0x1_0000, p, 64],
            &[CNODE],
            arg(1),
        ),
        (
            "the PIC's 0x20",
            0x70,
            &[0x1F, 0x20, p, 64],
            &[CNODE],
            arg(0),
        ),
        (
            "the slave PIC's 0xA1",
            0x70,
            &[0xA1, 0xA8, p, 64],
            &[CNODE],
            arg(0),
        ),
        (
            "depth 0",
            0x70,
            &[0x60, 0x61, p, 0],
            &[CNODE],
            SyscallError::RangeError { min: 1, max: 64 },
        ),
        (
            "depth 65",
            0x70,
            &[0x60, 0x61, p, 65],
            &[CNODE],
            SyscallError::RangeError { min: 1, max: 64 },
        ),
        (
            "a full slot",
            0x70,
            &[0x60, 0x61, full, 64],
            &[CNODE],
            SyscallError::DeleteFirst,
        ),
        (
            "a reserved port into a full slot",
            0x70,
            &[0x20, 0x20, full, 0],
            &[CNODE],
            arg(0),
        ),
    ];
    for (what, label, args, caps, err) in cases {
        expect_err(raw(ipc, control, label, args, caps), err, what);
    }
    println!(
        "ioport: ok   Issue's errors in order: IllegalOperation for another label, TruncatedMessage, InvalidArgument(0) and (1) for the bounds, InvalidArgument(0) for the kernel's ports, then the destination"
    );

    // COM1's range, and overlaps with it.
    expect_ok(
        ioport_control_issue(ipc, control, COM1, SCRATCH, root_slot(p)),
        "issuing COM1's range",
    );
    for (a, b) in [
        (0x3F8, 0x3FF),
        (0x3FF, 0x400),
        (0x3F0, 0x3F8),
        (0x3FA, 0x3FB),
    ] {
        expect_err(
            ioport_control_issue(ipc, control, a, b, root_slot(q)),
            SyscallError::RevokeFirst,
            "an overlapping range",
        );
    }
    // RevokeFirst comes before the destination's checks.
    expect_err(
        raw(ipc, control, 0x70, &[0x3FF, 0x3FF, full, 0], &[CNODE]),
        SyscallError::RevokeFirst,
        "an overlap into a full slot",
    );
    // Ranges that only touch it are free.
    expect_ok(
        ioport_control_issue(ipc, control, 0x3F0, 0x3F7, root_slot(q)),
        "issuing 0x3F0-0x3F7",
    );
    expect_ok(cnode_delete(root_slot(q)), "deleting it");
    println!(
        "ioport: ok   issued 0x3f8-0x3ff into slot {p}; ranges overlapping it are RevokeFirst, before the destination is checked; 0x3f0-0x3f7, which only touches it, is free"
    );

    // Accesses at the ends of the range.
    let ill = SyscallError::IllegalOperation;
    for port in [COM1, SCRATCH] {
        expect_ok(ioport_in8(p, port), "In8 at an end of the range");
    }
    expect_ok(ioport_in16(p, SCRATCH - 1), "In16 at 0x3fe");
    expect_ok(ioport_in32(p, SCRATCH - 3), "In32 at 0x3fc");
    expect_err(ioport_in8(p, COM1 - 1), ill, "In8 at 0x3f7");
    expect_err(ioport_in8(p, SCRATCH + 1), ill, "In8 at 0x400");
    expect_err(ioport_in16(p, SCRATCH), ill, "In16 at 0x3ff");
    expect_err(ioport_in32(p, SCRATCH - 2), ill, "In32 at 0x3fd");
    expect_err(ioport_in16(p, COM1 - 1), ill, "In16 at 0x3f7");
    expect_err(
        invoke(Some(ipc), p, 0x71, &[0x1_0000 | u64::from(COM1)], &[]).map(|_| ()),
        SyscallError::InvalidArgument(0),
        "In8 at 0x103f8",
    );
    expect_err(
        invoke(Some(ipc), p, 0x71, &[], &[]).map(|_| ()),
        SyscallError::TruncatedMessage,
        "In8 without a port",
    );
    expect_err(
        invoke(Some(ipc), p, 0x74, &[u64::from(SCRATCH)], &[]).map(|_| ()),
        SyscallError::TruncatedMessage,
        "Out8 without a value",
    );
    expect_err(
        invoke(Some(ipc), p, 0x70, &[0x60, 0x61, q, 64], &[CNODE]).map(|_| ()),
        ill,
        "Issue on an IOPort",
    );
    println!(
        "ioport: ok   In8 at 0x3f8 and 0x3ff, In16 at 0x3fe and In32 at 0x3fc succeed; one port past either end, In16 at 0x3ff and In32 at 0x3fd are IllegalOperation; port 0x103f8 is InvalidArgument(0)"
    );

    // In's reply, through the scratch register.
    expect_ok(
        ioport_out8(p, SCRATCH, 0xA5),
        "Out8 to the scratch register",
    );
    let a5 = expect_ok(ioport_in8(p, SCRATCH), "In8 of it");
    // Out8 with high bits: only the low byte is written.
    expect_ok(
        invoke(Some(ipc), p, 0x74, &[u64::from(SCRATCH), 0xFFFF_FF3C], &[]).map(|_| ()),
        "Out8 with high bits",
    );
    let reply = expect_ok(
        invoke(Some(ipc), p, 0x71, &[u64::from(SCRATCH)], &[]),
        "In8 by Call",
    );
    let (len, v) = (reply.length(), reply.word(0));
    // Send performs the access and drops the reply.
    send(
        p,
        &Message::new(
            MessageInfo::new(0x74, 0, 0, 2),
            [u64::from(SCRATCH), 0x5A, 0, 0],
        ),
    );
    let sent = expect_ok(ioport_in8(p, SCRATCH), "In8 after a Send");
    let word = expect_ok(
        ioport_in16(p, SCRATCH - 1),
        "In16 across the scratch register",
    );
    if a5 != 0xA5 || len != 1 || v != 0x3C || sent != 0x5A || word >> 8 != 0x5A {
        fail!(
            "ioport: the scratch register read {a5:#x}, then length {len} MR0 {v:#x}, then {sent:#x}; In16 at 0x3fe {word:#x}"
        );
    }
    println!(
        "ioport: ok   the scratch register: Out8 0xa5 then In8 0xa5; Out8 of 0xffffff3c wrote 0x3c, and In8's reply was length 1, MR0 0x3c; a Send of Out8 0x5a wrote it and dropped the reply; In16 at 0x3fe read {word:#06x}, 0x5a in its high byte"
    );

    // Copies, a mint, and deletion.
    expect_ok(
        cnode_copy(ipc, root_slot(p2), root_slot(p), Rights::ALL),
        "copying the IOPort",
    );
    expect_ok(
        cnode_mint(ipc, root_slot(p3), root_slot(p), Rights::ALL, 0x03FA_03F9),
        "minting it with a narrower range",
    );
    expect_ok(ioport_in8(p3, SCRATCH), "In8 at 0x3ff through the mint");
    expect_ok(ioport_in8(p2, COM1), "In8 at 0x3f8 through the copy");
    expect_ok(cnode_delete(root_slot(p)), "deleting the issued IOPort");
    expect_ok(cnode_delete(root_slot(p3)), "deleting the mint");
    expect_err(
        ioport_control_issue(ipc, control, SCRATCH, SCRATCH, root_slot(q)),
        SyscallError::RevokeFirst,
        "reissuing while a copy is left",
    );
    expect_ok(ioport_in8(p2, SCRATCH), "In8 through the copy left");
    expect_ok(cnode_delete(root_slot(p2)), "deleting the last copy");
    expect_ok(
        ioport_control_issue(ipc, control, COM1, SCRATCH, root_slot(p)),
        "reissuing COM1's range",
    );
    println!(
        "ioport: ok   a copy and a mint with data 0x3fa03f9 reach 0x3f8 to 0x3ff; with the issued capability and the mint deleted the range stays issued, and deleting the last copy frees it"
    );

    // Revoking IOPortControl frees every range; it cannot be copied.
    expect_ok(
        ioport_control_issue(ipc, control, 0xF4, 0xF7, root_slot(q)),
        "issuing 0xf4-0xf7",
    );
    expect_ok(cnode_revoke(root_slot(control)), "revoking IOPortControl");
    expect_err(
        ioport_in8(p, SCRATCH),
        SyscallError::InvalidCapability(0),
        "In8 through a revoked IOPort",
    );
    expect_err(
        ioport_in8(q, 0xF4),
        SyscallError::InvalidCapability(0),
        "In8 through the other",
    );
    expect_ok(
        ioport_control_issue(ipc, control, COM1, SCRATCH, root_slot(p)),
        "issuing after the revoke",
    );
    expect_ok(
        ioport_control_issue(ipc, control, 0xF4, 0xF7, root_slot(q)),
        "and 0xf4-0xf7",
    );
    expect_err(
        cnode_copy(ipc, root_slot(p2), root_slot(control), Rights::ALL),
        ill,
        "copying IOPortControl",
    );
    println!(
        "ioport: ok   CNode_Revoke of IOPortControl deleted both IOPorts and freed their ranges; IOPortControl cannot be copied"
    );
    println!("TEST PASS");
    libsys::debug_halt(0)
}
