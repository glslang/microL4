//! `test=tlb`: the kernel's TLB maintenance seen from ring 3
//! (`docs/design.md`, "TLB maintenance"; the Address spaces invariant
//! "Every change to a present user entry is followed by its flush before
//! the next user instruction").
//!
//! `l4core::vspace` returns a `Flush` for every change to a present entry
//! and its host tests check that against a TLB model, and `test=vspace`
//! checks the entries by walking the tables, but no other test sees
//! whether the kernel's `apply` really drops the translation: a kernel that
//! applies no flush at all passes every other scenario. Here a thread T in
//! the root task's own VSpace loads a translation into the TLB with an
//! access, has the kernel change the entry, and accesses the page again
//! without any other thread running in between, so no CR3 write can hide a
//! missing flush. The second access must fault; if it succeeds through a
//! stale translation, T reports that on the endpoint E and the test fails.
//!
//! 1. `Frame_Remap` of a read-write page to read-only (an `invlpg`): T
//!    writes the page, remaps it, and writes again.
//! 2. `Frame_Unmap` of that page (an `invlpg`): T reads it, unmaps it, and
//!    reads again.
//! 3. `PageTable_Unmap` of a page table holding a mapped page (a CR3
//!    reload): T reads the page, unmaps the table, and reads again.
//!
//! T's faults go to E, where the root task waits and checks each
//! `VMFault`. It then undoes the phase's change (`Frame_Remap` back to
//! read-write, `Frame_Map`, or `PageTable_Map` and `Frame_Map`) and
//! replies, which restarts the faulting access: T must then reach the
//! frame, see what was written there before the change, and report the
//! word on E. (Folded in from reviewer K's `test=tlb`: no other scenario
//! restarts an access after a `VMFault` reply.) The root task then points
//! T at the next phase with `TCB_WriteRegisters`.

use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering::Relaxed;

use libsys::bootinfo::{CAP_INIT_TCB, CAP_INIT_VSPACE};
use libsys::fault_label::VM_FAULT;
use libsys::invoke::{invoke, tcb_set_priority, tcb_write_registers};
use libsys::{
    BootInfo, CPtr, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Registers, Rights, UserReg,
    println, recv, reply, send, yield_now,
};

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// A page under the root task's own page table, which covers the 2 MiB
/// from 0x400000, above its image, IPC buffer and BootInfo.
const PAGE: u64 = 0x50_0000;
/// A page in the next 2 MiB, which no page table covers until the test
/// maps one.
const TABLE_PAGE: u64 = 0x60_0000;

/// Labels (`docs/abi.md`, "Invocation labels").
const PAGE_TABLE_MAP: u64 = 0x44;
const PAGE_TABLE_UNMAP: u64 = 0x45;
const FRAME_MAP: u64 = 0x50;
const FRAME_UNMAP: u64 = 0x51;
const FRAME_REMAP: u64 = 0x52;

/// Rights words (`docs/abi.md`, "Rights word").
const READ: u64 = Rights::READ.0 as u64;
const READ_WRITE: u64 = (Rights::READ.0 | Rights::WRITE.0) as u64;
/// Write-back, no-execute (`docs/abi.md`, "Attributes word").
const RAM: u64 = 0;

/// T's priority, below the root task's.
const PRIORITY: u64 = 100;
/// The label of T's report that its second access succeeded.
const WENT_ON: u64 = 0x57A1E;
/// What T writes in phase 1.
const MAGIC: u64 = 0x7EB_5EED;
/// What the root task writes in the page under the new page table.
const TABLE_MAGIC: u64 = 0x7AB1E_5EED;

/// Page-fault error code bits.
const PF_PRESENT: u64 = 1 << 0;
const PF_WRITE: u64 = 1 << 1;
const PF_USER: u64 = 1 << 2;
const PF_LOW_BITS: u64 = 0x1F;

/// The value T read or wrote last, so the accesses are not optimised away.
static SEEN: AtomicU64 = AtomicU64::new(0);

/// One phase: what T does, which page it touches, the fault the second
/// access must raise, what undoes the change, and the word T must find in
/// the page once its access restarts.
struct Phase {
    name: &'static str,
    page: u64,
    fsr: u64,
    undo: &'static str,
    word: u64,
}

const PHASES: [Phase; 3] = [
    Phase {
        name: "Frame_Remap to read-only (invlpg)",
        page: PAGE,
        fsr: PF_PRESENT | PF_WRITE | PF_USER,
        undo: "Frame_Remap read-write",
        // T's restarted write.
        word: !MAGIC,
    },
    Phase {
        name: "Frame_Unmap (invlpg)",
        page: PAGE,
        fsr: PF_USER,
        undo: "Frame_Map",
        // Phase 1's write, which the frame kept while unmapped.
        word: !MAGIC,
    },
    Phase {
        name: "PageTable_Unmap (CR3 reload)",
        page: TABLE_PAGE,
        fsr: PF_USER,
        undo: "PageTable_Map and Frame_Map",
        word: TABLE_MAGIC,
    },
];

/// `Call` of invocation `label` on `cap` with `args` and `caps`, failing
/// the test on an error.
fn must(ipc: Option<Ipc>, cap: CPtr, label: u64, args: &[u64], caps: &[CPtr], what: &str) {
    if let Err(e) = invoke(ipc, cap, label, args, caps) {
        fail!("tlb: {what}: {e}")
    }
}

/// `Frame_Map` of `frame` at `page`, read-write, in the root task's VSpace.
fn map(ipc: Ipc, frame: CPtr, page: u64, what: &str) {
    must(
        Some(ipc),
        frame,
        FRAME_MAP,
        &[page, READ_WRITE, RAM],
        &[CAP_INIT_VSPACE],
        what,
    );
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mapped = bi.user_image_start..bi.user_image_end + 0x3000;
    if mapped.contains(&PAGE) || PAGE >> 21 != bi.user_image_start >> 21 {
        fail!("tlb: {PAGE:#x} is not a free page under the root task's page table");
    }
    if TABLE_PAGE >> 21 == (bi.user_image_end + 0x2fff) >> 21 {
        fail!("tlb: {TABLE_PAGE:#x} lies under the root task's page table");
    }
    let mut objects = ObjectAlloc::new(bi);
    let mut retype = |ty, count, what| {
        objects
            .retype(ipc, ty, 0, count)
            .unwrap_or_else(|e| fail!("tlb: retyping {what}: {e}"))
    };
    let ep = retype(ObjectType::Endpoint, 1, "the endpoint");
    let tcb = retype(ObjectType::Tcb, 1, "the TCB");
    let frames = retype(ObjectType::Frame4K, 2, "the frames");
    let table = retype(ObjectType::PageTable, 1, "the page table");
    let (frame, table_frame) = (frames, frames + 1);

    must(
        Some(ipc),
        frame,
        FRAME_MAP,
        &[PAGE, READ_WRITE, RAM],
        &[CAP_INIT_VSPACE],
        "Frame_Map of the page",
    );
    must(
        Some(ipc),
        table,
        PAGE_TABLE_MAP,
        &[TABLE_PAGE],
        &[CAP_INIT_VSPACE],
        "PageTable_Map",
    );
    must(
        Some(ipc),
        table_frame,
        FRAME_MAP,
        &[TABLE_PAGE, READ_WRITE, RAM],
        &[CAP_INIT_VSPACE],
        "Frame_Map of the page under the new page table",
    );
    write(TABLE_PAGE, TABLE_MAGIC);
    println!(
        "tlb: page {PAGE:#x} mapped read-write; a new page table maps page {TABLE_PAGE:#x}; thread T in the root task's VSpace touches them"
    );

    let caps = [frame, frame, table];
    let t = Thread {
        tcb,
        fault_ep: ep,
        stack: &STACKS[0],
        entry: worker,
        args: [0, caps[0], ep, 0],
    };
    spawn::prepare(ipc, &t)
        .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, PRIORITY))
        .unwrap_or_else(|e| fail!("tlb: setting up thread T: {e}"));
    let entry: spawn::Entry = worker;
    for (i, phase) in PHASES.iter().enumerate() {
        // Phase 0 starts T where `prepare` left it; the later ones restart
        // it, spinning in `yield_now` after its report, at the worker's
        // entry again.
        let regs = Registers::ZERO
            .with(UserReg::Rip, entry as usize as u64)
            .with(UserReg::Rsp, STACKS[0].top() - 8)
            .with(UserReg::Rflags, 0x202)
            .with(UserReg::Rdi, i as u64)
            .with(UserReg::Rsi, caps[i])
            .with(UserReg::Rdx, ep);
        tcb_write_registers(ipc, tcb, true, &regs, UserReg::Rdi.index() + 1)
            .unwrap_or_else(|e| fail!("tlb: starting phase {}: {e}", i + 1));
        let r = recv(ep);
        let info = r.msg.info;
        let [ip, addr, _, fsr] = r.msg.mr;
        if info.label() == WENT_ON {
            fail!(
                "tlb: phase {}, {}: T accessed {:#x} again without a fault: the kernel left a stale translation",
                i + 1,
                phase.name,
                phase.page
            );
        }
        if info.label() != VM_FAULT
            || info.length() != 4
            || addr != phase.page
            || fsr & PF_LOW_BITS != phase.fsr
        {
            fail!(
                "tlb: phase {}, {}: label {}, length {}, MR0 to MR3 {:#x?}; want a VMFault at {:#x} with fsr low bits {:#x}",
                i + 1,
                phase.name,
                info.label(),
                info.length(),
                r.msg.mr,
                phase.page,
                phase.fsr
            );
        }
        println!(
            "tlb: ok   phase {}, {}: the access after it faulted at {addr:#x}, ip {ip:#x}, fsr {fsr:#x}",
            i + 1,
            phase.name
        );

        match i {
            0 => must(
                Some(ipc),
                frame,
                FRAME_REMAP,
                &[READ_WRITE, RAM],
                &[],
                phase.undo,
            ),
            1 => map(ipc, frame, PAGE, phase.undo),
            _ => {
                must(
                    Some(ipc),
                    table,
                    PAGE_TABLE_MAP,
                    &[TABLE_PAGE],
                    &[CAP_INIT_VSPACE],
                    phase.undo,
                );
                map(ipc, table_frame, TABLE_PAGE, phase.undo);
            }
        }
        // Label 0 restarts the faulting access.
        reply(&Message::EMPTY);
        let r = recv(ep).msg;
        let [n, word, ..] = r.mr;
        if r.info.label() != WENT_ON || n != i as u64 || word != phase.word {
            fail!(
                "tlb: phase {}: after {} and the fault reply, label {:#x}, MR0 to MR3 {:#x?}; want T's report of phase {i} with {:#x}",
                i + 1,
                phase.undo,
                r.info.label(),
                r.mr,
                phase.word
            );
        }
        println!(
            "tlb: ok   phase {}: {}, then the fault reply: the access restarted and found {word:#x}",
            i + 1,
            phase.undo
        );
    }
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// Reads the word at `addr`, which the caller says is mapped readable or
/// faults.
fn read(addr: u64) -> u64 {
    // SAFETY: `addr` is page-aligned in the root task's own VSpace; the
    // read either finds the frame the test mapped there or faults, and the
    // fault goes to the root task, which maps the frame back before the
    // read restarts.
    unsafe { core::ptr::read_volatile(addr as *const u64) }
}

/// Writes `value` to the word at `addr`, likewise.
fn write(addr: u64, value: u64) {
    // SAFETY: as in `read`; the frames hold nothing but what this test
    // writes.
    unsafe { core::ptr::write_volatile(addr as *mut u64, value) }
}

/// Thread T, phase `phase` (0 to 2): an access that loads the TLB, the
/// invocation of `cap` that changes the entry, and the access that must
/// fault. Then, once the root task's fault reply has restarted that access,
/// or at once if it did not fault, reports on `ep` with the page's word.
extern "C" fn worker(phase: u64, cap: CPtr, ep: CPtr, _: u64) -> ! {
    let page = match phase {
        0 => {
            write(PAGE, MAGIC);
            SEEN.store(read(PAGE), Relaxed);
            must(None, cap, FRAME_REMAP, &[READ, RAM], &[], "Frame_Remap");
            write(PAGE, !MAGIC);
            PAGE
        }
        1 => {
            SEEN.store(read(PAGE), Relaxed);
            must(None, cap, FRAME_UNMAP, &[], &[], "Frame_Unmap");
            SEEN.store(read(PAGE), Relaxed);
            PAGE
        }
        _ => {
            SEEN.store(read(TABLE_PAGE), Relaxed);
            must(None, cap, PAGE_TABLE_UNMAP, &[], &[], "PageTable_Unmap");
            SEEN.store(read(TABLE_PAGE), Relaxed);
            TABLE_PAGE
        }
    };
    send(
        ep,
        &Message::new(
            MessageInfo::new(WENT_ON, 0, 0, 2),
            [phase, read(page), 0, 0],
        ),
    );
    loop {
        yield_now();
    }
}
