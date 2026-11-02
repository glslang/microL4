//! `test=tlb` (M5 review, reviewer K): the TLB after an unmap or a remap,
//! seen from ring 3.
//!
//! `docs/design.md`, "Address spaces", Invariants: "Every change to a
//! present user entry is followed by its flush before the next user
//! instruction". `test=vspace` checks mappings by walking the tables, and
//! `l4core::vspace`'s proptest has a TLB model; nothing ran user code
//! against a translation the kernel had just removed. Here thread T shares
//! the root task's VSpace, so no CR3 write ever separates the two: only
//! the flush each invocation applies (`arch::paging::apply`) can drop a
//! translation T or the root already used.
//!
//! The root maps page tables P1 and P2 and frames F1 and F2 at [`VA1`] and
//! [`VA2`], writes both, and resumes T, which runs these steps, each ended
//! by a `Call` to the root on endpoint E (its fault endpoint too):
//!
//! 1. T reads `VA1`; the root then `Frame_Unmap`s F1 (`invlpg`).
//! 2. T reads `VA1` again: a VMFault. The root maps F1 back and replies;
//!    the read restarts and sees the root's value.
//! 3. T writes `VA1`; the root `Frame_Remap`s F1 read-only (`invlpg`).
//! 4. T writes `VA1` again: a VMFault for a write. The root remaps F1
//!    writable and replies; the write restarts.
//! 5. T reads `VA2`; the root `PageTable_Unmap`s P2 (a CR3 reload).
//! 6. T reads `VA2` again: a VMFault. The root maps P2 and F2 back and
//!    replies; the read restarts.
//!
//! A step that should fault and does not means a stale translation
//! survived the invocation.

use core::ptr;

use libsys::bootinfo::{CAP_INIT_TCB, CAP_INIT_VSPACE};
use libsys::invoke::{invoke, tcb_resume, tcb_set_priority, tcb_suspend};
use libsys::{
    BootInfo, CPtr, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Rights, call, fault_label,
    println, recv, reply,
};

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// The two pages, each in a 2 MiB region of its own that nothing else maps,
/// under the root task's one page directory.
const VA1: u64 = 0x0100_0000;
const VA2: u64 = 0x0120_0000;
/// T's priority, below the root task's 255.
const PRIORITY: u64 = 100;
/// The label of T's step reports.
const STEP: u64 = 0x71B;
/// The values the root writes.
const V1: u64 = 0x1111_2222_3333_4444;
const V2: u64 = 0x5555_6666_7777_8888;
/// What T writes at steps 3 and 4.
const W3: u64 = 0x3333_0000_0000_0003;
const W4: u64 = 0x4444_0000_0000_0004;

/// The paging labels (`docs/abi.md`, "Invocation labels").
const PAGE_TABLE_MAP: u64 = 0x44;
const PAGE_TABLE_UNMAP: u64 = 0x45;
const FRAME_MAP: u64 = 0x50;
const FRAME_UNMAP: u64 = 0x51;
const FRAME_REMAP: u64 = 0x52;
/// Write-back, no-execute.
const ATTRS: u64 = 0;
const RW: u64 = (Rights::READ.0 | Rights::WRITE.0) as u64;
const R: u64 = Rights::READ.0 as u64;

/// The objects the root made.
struct Objects {
    p1: CPtr,
    p2: CPtr,
    f1: CPtr,
    f2: CPtr,
}

/// Performs a paging invocation, failing the test if it fails.
fn paging(ipc: Ipc, what: &str, cap: CPtr, label: u64, args: &[u64], caps: &[CPtr]) {
    if let Err(e) = invoke(Some(ipc), cap, label, args, caps) {
        fail!("tlb: {what}: {e}");
    }
}

fn map_table(ipc: Ipc, pt: CPtr, va: u64) {
    paging(
        ipc,
        "PageTable_Map",
        pt,
        PAGE_TABLE_MAP,
        &[va],
        &[CAP_INIT_VSPACE],
    );
}

fn map_frame(ipc: Ipc, frame: CPtr, va: u64) {
    paging(
        ipc,
        "Frame_Map",
        frame,
        FRAME_MAP,
        &[va, RW, ATTRS],
        &[CAP_INIT_VSPACE],
    );
}

fn read(va: u64) -> u64 {
    // SAFETY: the caller's step maps `va`, or expects the read to fault and
    // its handler to map it before the read restarts; volatile, so the
    // read happens exactly where the step puts it.
    unsafe { ptr::read_volatile(va as *const u64) }
}

fn write(va: u64, v: u64) {
    // SAFETY: as for `read`.
    unsafe { ptr::write_volatile(va as *mut u64, v) }
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let image_end = bi.user_image_end + 0x10_0000;
    if image_end > VA1 {
        fail!("tlb: the root task's image and buffers reach {image_end:#x}, past {VA1:#x}");
    }
    let mut objects = ObjectAlloc::new(bi);
    let mut one = |ty, what| {
        objects
            .retype(ipc, ty, 0, 1)
            .unwrap_or_else(|e| fail!("tlb: retyping {what}: {e}"))
    };
    let e = one(ObjectType::Endpoint, "the endpoint");
    let t = one(ObjectType::Tcb, "the TCB");
    let o = Objects {
        p1: one(ObjectType::PageTable, "P1"),
        p2: one(ObjectType::PageTable, "P2"),
        f1: one(ObjectType::Frame4K, "F1"),
        f2: one(ObjectType::Frame4K, "F2"),
    };
    map_table(ipc, o.p1, VA1);
    map_table(ipc, o.p2, VA2);
    map_frame(ipc, o.f1, VA1);
    map_frame(ipc, o.f2, VA2);
    write(VA1, V1);
    write(VA2, V2);
    if (read(VA1), read(VA2)) != (V1, V2) {
        fail!("tlb: the root task read back other values than it wrote");
    }

    let thread = Thread {
        tcb: t,
        fault_ep: e,
        stack: &STACKS[0],
        entry: worker,
        args: [e, 0, 0, 0],
    };
    spawn::prepare(ipc, &thread)
        .and_then(|()| tcb_set_priority(ipc, t, CAP_INIT_TCB, PRIORITY))
        .and_then(|()| tcb_resume(t))
        .unwrap_or_else(|e| fail!("tlb: starting T: {e}"));
    println!(
        "tlb: T shares the root task's VSpace; F1 at {VA1:#x} and F2 at {VA2:#x}, each under a page table of its own"
    );

    // Each expected message, and what the root does before it replies.
    expect_step(e, 1, Some(V1));
    paging(ipc, "Frame_Unmap", o.f1, FRAME_UNMAP, &[], &[]);
    reply(&Message::EMPTY);
    println!("tlb: 1 T read F1 through {VA1:#x}; Frame_Unmap");

    expect_fault(e, VA1, false, "a read of VA1 after Frame_Unmap");
    map_frame(ipc, o.f1, VA1);
    reply(&Message::EMPTY);
    expect_step(e, 2, Some(V1));
    reply(&Message::EMPTY);
    println!("tlb: 2 T's next read of {VA1:#x} faulted; F1 mapped again, the read restarted");

    expect_step(e, 3, None);
    if read(VA1) != W3 {
        fail!("tlb: T's write at step 3 did not reach F1");
    }
    paging(ipc, "Frame_Remap", o.f1, FRAME_REMAP, &[R, ATTRS], &[]);
    reply(&Message::EMPTY);
    println!("tlb: 3 T wrote F1 through {VA1:#x}; Frame_Remap read-only");

    expect_fault(e, VA1, true, "a write to VA1 after Frame_Remap read-only");
    paging(ipc, "Frame_Remap", o.f1, FRAME_REMAP, &[RW, ATTRS], &[]);
    reply(&Message::EMPTY);
    expect_step(e, 4, None);
    if read(VA1) != W4 {
        fail!("tlb: T's restarted write at step 4 did not reach F1");
    }
    reply(&Message::EMPTY);
    println!(
        "tlb: 4 T's next write to {VA1:#x} faulted; F1 remapped writable, the write restarted"
    );

    expect_step(e, 5, Some(V2));
    paging(ipc, "PageTable_Unmap", o.p2, PAGE_TABLE_UNMAP, &[], &[]);
    reply(&Message::EMPTY);
    println!("tlb: 5 T read F2 through {VA2:#x}; PageTable_Unmap of its page table");

    expect_fault(e, VA2, false, "a read of VA2 after PageTable_Unmap");
    map_table(ipc, o.p2, VA2);
    map_frame(ipc, o.f2, VA2);
    reply(&Message::EMPTY);
    expect_step(e, 6, Some(V2));
    println!(
        "tlb: 6 T's next read of {VA2:#x} faulted; P2 and F2 mapped again, the read restarted"
    );

    tcb_suspend(t).unwrap_or_else(|e| fail!("tlb: suspending T: {e}"));
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// Waits on `e` for T's report of step `n`, with the value it read, if any.
fn expect_step(e: CPtr, n: u64, value: Option<u64>) {
    let r = recv(e).msg;
    let info = r.info;
    if info.label() == fault_label::VM_FAULT {
        fail!(
            "tlb: step {n}: T faulted at {:#x} on {:#x} (error {:#x}) instead of reporting",
            r.mr[0],
            r.mr[1],
            r.mr[3]
        );
    }
    if info.label() != STEP || r.mr[0] != n {
        fail!(
            "tlb: step {n}: label {:#x}, MR0 to MR3 {:#x?} instead of T's report",
            info.label(),
            r.mr
        );
    }
    if let Some(v) = value
        && r.mr[1] != v
    {
        fail!("tlb: step {n}: T read {:#x}, not {v:#x}", r.mr[1]);
    }
}

/// Waits on `e` for T's VMFault on `addr`, a write if `write`. `what` names
/// the access, for the failure: getting T's next report instead means the
/// access used a translation the last invocation removed.
fn expect_fault(e: CPtr, addr: u64, write: bool, what: &str) {
    let r = recv(e).msg;
    if r.info.label() == STEP {
        fail!(
            "tlb: {what} did not fault: T reported step {} with {:#x}, so a stale translation survived",
            r.mr[0],
            r.mr[1]
        );
    }
    // Page-fault error code bit 1: a write.
    let fsr_write = r.mr[3] & 2 != 0;
    if r.info.label() != fault_label::VM_FAULT || r.mr[1] != addr || fsr_write != write {
        fail!(
            "tlb: {what}: label {:#x}, MR0 to MR3 {:#x?} instead of a VMFault on {addr:#x}",
            r.info.label(),
            r.mr
        );
    }
}

/// Reports step `n` to the root and waits for its reply.
fn report(e: CPtr, n: u64, value: u64) {
    call(
        e,
        &Message::new(MessageInfo::new(STEP, 0, 0, 2), [n, value, 0, 0]),
    );
}

/// Thread T: the six steps; the root suspends it after the last.
extern "C" fn worker(e: CPtr, _: u64, _: u64, _: u64) -> ! {
    report(e, 1, read(VA1));
    report(e, 2, read(VA1));
    write(VA1, W3);
    report(e, 3, 0);
    write(VA1, W4);
    report(e, 4, 0);
    report(e, 5, read(VA2));
    report(e, 6, read(VA2));
    loop {
        libsys::yield_now();
    }
}
