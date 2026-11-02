//! `test=fault`: a user page fault reaches its fault-handler thread, which
//! prints it and kills the faulting thread (PLAN.md, M5's done-when).
//!
//! The root task retypes two endpoints, E for faults and D for reports to
//! itself, and two TCBs: the handler H, at priority 200 with an IPC buffer,
//! and the faulting thread F, at 210, whose fault endpoint is a copy of E
//! with only Write and GrantReply, as much as `docs/abi.md` asks of a fault
//! endpoint. H's own faults, if any, go to D. F, above H, runs first and
//! reads [`FAULT_ADDR`], which nothing maps, with the one instruction of
//! [`root_fault_read`]; its fault waits on E. H runs only once F is
//! blocked: were F left runnable, it would run again, above H, and H would
//! never receive the fault.
//!
//! H receives the fault on E, checks the message is the `VMFault` that
//! read raises ([`root::check::vm_fault`]), reads F's registers to see `rip`
//! on the same instruction, prints both, has the kernel print every
//! thread's state (`DebugDumpScheduler`: F is `BlockedOnReply`, which the
//! scenario checks), and kills F with `TCB_Suspend`. Suspend,
//! not deleting F's TCB capability, because it is the kill `docs/abi.md`
//! defines for a thread blocked on a fault: F becomes `Inactive`, the
//! fault IPC is cancelled and the reply capability in H's caller slot is
//! deleted, while the TCB stays for the root task to inspect; deleting
//! would leave nothing to check but a failed lookup. H then replies with
//! label 0, which would restart F had its reply capability survived, and
//! reports to the root on D.
//!
//! The root checks F is stopped where it faulted (`TCB_ReadRegisters`:
//! `rip` on the faulting instruction, `rdi` the address) and never ran past
//! it, then drops to priority 50, below F's, and spins for
//! [`SETTLE_MS`]: if F could run, it would fault again and H, which waits
//! on E, would fail the test.

use core::arch::global_asm;
use core::ptr::NonNull;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::Ordering::Relaxed;

use libsys::bootinfo::{CAP_INIT_IPC_BUFFER, CAP_INIT_TCB};
use libsys::invoke::{Slot, cnode_copy};
use libsys::invoke::{
    tcb_read_registers, tcb_resume, tcb_set_ipc_buffer, tcb_set_priority, tcb_set_sched_params,
    tcb_suspend,
};
use libsys::ipc::IPC_BUFFER_SIZE;
use libsys::{
    BootInfo, CPtr, Ipc, IpcBuffer, IpcBufferFrame, Message, MessageInfo, ObjectAlloc, ObjectType,
    Registers, Rights, UserReg, println, rdtsc, recv, reply, send,
};
use root::check;

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// The address F reads: no page is mapped there.
const FAULT_ADDR: u64 = 0xDEAD_BEE8;
/// H's priority, and its MCP.
const HANDLER_PRIORITY: u64 = 200;
/// F's priority, above H's, so F runs and faults first.
const FAULTER_PRIORITY: u64 = 210;
/// The root task's priority while it waits to see F stays stopped.
const ROOT_SETTLE_PRIORITY: u64 = 50;
/// How long it waits: five time slices.
const SETTLE_MS: u64 = 50;
/// The label of H's report to the root.
const REPORT: u64 = 0xF417;
/// Registers read back from F: words 0 to 8, `rip` to `rdi`.
const READ: usize = UserReg::Rdi.index() + 1;

/// Set by F if it ever gets past its faulting read.
static F_WENT_ON: AtomicBool = AtomicBool::new(false);

// The read F faults on, in an instruction of its own so its address is
// known: `rip` in the fault message and in F's registers must be
// `root_fault_read` itself.
global_asm!(
    ".pushsection .text.root_fault_read, \"ax\", @progbits",
    ".global root_fault_read",
    ".type root_fault_read, @function",
    "root_fault_read:",
    "    mov rax, qword ptr [rdi]",
    "    ret",
    ".size root_fault_read, . - root_fault_read",
    ".popsection",
);

unsafe extern "C" {
    /// Reads the word at `addr` with one `mov`, the first instruction.
    fn root_fault_read(addr: u64) -> u64;
}

/// The address of the faulting instruction.
fn fault_ip() -> u64 {
    root_fault_read as *const () as u64
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mapped = bi.user_image_start..bi.user_image_end + 0x3000;
    if mapped.contains(&FAULT_ADDR) {
        fail!("{FAULT_ADDR:#x} lies in the root task's mappings {mapped:#x?}");
    }
    if bi.tsc_hz == 0 {
        fail!("BootInfo's tsc_hz is 0: nothing to time the wait by");
    }
    // H's IPC buffer is the second KiB of the root task's buffer frame.
    if !bi.ipc_buffer.is_multiple_of(0x1000) {
        fail!(
            "the root task's IPC buffer {:#x} is not at the start of its frame",
            bi.ipc_buffer
        );
    }
    let handler_buffer = IpcBufferFrame {
        addr: bi.ipc_buffer + IPC_BUFFER_SIZE,
        frame: CAP_INIT_IPC_BUFFER,
    };

    let mut objects = ObjectAlloc::new(bi);
    let eps = objects
        .retype(ipc, ObjectType::Endpoint, 0, 2)
        .unwrap_or_else(|e| fail!("retyping the endpoints: {e}"));
    let (fault_ep, report_ep) = (eps, eps + 1);
    let tcbs = objects
        .retype(ipc, ObjectType::Tcb, 0, 2)
        .unwrap_or_else(|e| fail!("retyping the TCBs: {e}"));
    let (handler, faulter) = (tcbs, tcbs + 1);
    let f_fault_ep = objects
        .slots
        .alloc(1)
        .unwrap_or_else(|| fail!("no free slot for F's fault endpoint"));
    let rights = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    cnode_copy(
        ipc,
        Slot::root_cnode(f_fault_ep),
        Slot::root_cnode(fault_ep),
        rights,
    )
    .unwrap_or_else(|e| fail!("copying the fault endpoint: {e}"));

    let h = Thread {
        tcb: handler,
        fault_ep: report_ep,
        stack: &STACKS[0],
        entry: handler_main,
        args: [fault_ep, faulter, report_ep, handler_buffer.addr],
    };
    spawn::prepare(ipc, &h)
        .and_then(|()| tcb_set_ipc_buffer(ipc, handler, Some(handler_buffer)))
        .and_then(|()| {
            tcb_set_sched_params(
                ipc,
                handler,
                CAP_INIT_TCB,
                HANDLER_PRIORITY,
                HANDLER_PRIORITY,
            )
        })
        .unwrap_or_else(|e| fail!("setting up the handler thread: {e}"));
    let f = Thread {
        tcb: faulter,
        fault_ep: f_fault_ep,
        stack: &STACKS[1],
        entry: faulter_main,
        args: [FAULT_ADDR, 0, 0, 0],
    };
    spawn::prepare(ipc, &f)
        .and_then(|()| tcb_set_priority(ipc, faulter, CAP_INIT_TCB, FAULTER_PRIORITY))
        .unwrap_or_else(|e| fail!("setting up the faulting thread: {e}"));
    println!(
        "fault: handler thread H (TCB slot {handler}, priority {HANDLER_PRIORITY}, IPC buffer at {:#x}) waits on endpoint slot {fault_ep}",
        handler_buffer.addr
    );
    println!(
        "fault: thread F (TCB slot {faulter}, priority {FAULTER_PRIORITY}) has fault endpoint slot {f_fault_ep}, a copy with Write and GrantReply"
    );
    tcb_resume(handler)
        .and_then(|()| tcb_resume(faulter))
        .unwrap_or_else(|e| fail!("resuming the threads: {e}"));

    // F runs first and faults; H, below it, runs once F is blocked,
    // receives the fault on E and reports.
    let r = recv(report_ep);
    if r.msg.info.label() != REPORT {
        fail!(
            "the root received label {}, length {}, MR0 to MR3 {:#x?} instead of H's report: H faulted?",
            r.msg.info.label(),
            r.msg.info.length(),
            r.msg.mr
        );
    }

    let regs = tcb_read_registers(Some(ipc), faulter, false, READ)
        .unwrap_or_else(|e| fail!("TCB_ReadRegisters on F: {e}"));
    check_stopped(&regs);
    if F_WENT_ON.load(Relaxed) {
        fail!("thread F got past its faulting read");
    }
    println!(
        "fault: root read thread F's registers after the kill: rip {:#x}, still the faulting read, rdi {:#x}",
        regs.get(UserReg::Rip),
        regs.get(UserReg::Rdi)
    );

    // Below F's priority, F would run at once if it could, and fault
    // again; H, waiting on E, would see that and fail the test.
    tcb_set_priority(ipc, CAP_INIT_TCB, CAP_INIT_TCB, ROOT_SETTLE_PRIORITY)
        .unwrap_or_else(|e| fail!("lowering the root task's priority: {e}"));
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < bi.tsc_hz / 1000 * SETTLE_MS {
        core::hint::spin_loop();
    }
    if F_WENT_ON.load(Relaxed) {
        fail!("thread F got past its faulting read");
    }
    println!(
        "fault: thread F stayed stopped for {SETTLE_MS} ms with the root task at priority {ROOT_SETTLE_PRIORITY}, below its {FAULTER_PRIORITY}"
    );
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// Fails unless `regs`, read from F, show it stopped on its faulting read
/// of [`FAULT_ADDR`], on its own stack.
fn check_stopped(regs: &Registers) {
    let rip = regs.get(UserReg::Rip);
    let rdi = regs.get(UserReg::Rdi);
    let rsp = regs.get(UserReg::Rsp);
    if rip != fault_ip() || rdi != FAULT_ADDR || !STACKS[1].contains(rsp) {
        fail!(
            "thread F's rip {rip:#x}, rdi {rdi:#x}, rsp {rsp:#x}; want rip {:#x}, rdi {FAULT_ADDR:#x}, rsp on its stack",
            fault_ip()
        );
    }
}

/// Thread F: reads `addr`, which faults.
extern "C" fn faulter_main(addr: u64, _: u64, _: u64, _: u64) -> ! {
    println!("fault: thread F reads {addr:#x}, which nothing maps");
    // SAFETY: the function reads the word at `addr` and touches nothing
    // else; the read faults, and F is killed before it would return.
    let value = unsafe { root_fault_read(addr) };
    F_WENT_ON.store(true, Relaxed);
    fail!("thread F read {value:#x} at {addr:#x} and went on")
}

/// Thread H: waits on `fault_ep` for F's fault, checks and prints it,
/// kills F, and reports to the root on `report`. `buffer` is its IPC
/// buffer.
extern "C" fn handler_main(fault_ep: CPtr, faulter: CPtr, report: CPtr, buffer: u64) -> ! {
    let buffer = NonNull::new(buffer as *mut IpcBuffer)
        .unwrap_or_else(|| fail!("the handler has no IPC buffer address"));
    // SAFETY: the root task set this thread's IPC buffer to the second KiB
    // of its own buffer frame, mapped RW at `buffer`, 1024-byte aligned;
    // no other thread uses those bytes.
    let ipc = unsafe { Ipc::new(buffer) };

    let r = recv(fault_ep);
    let fault = check::vm_fault(&r, fault_ip(), FAULT_ADDR).unwrap_or_else(|m| {
        fail!(
            "the handler's message, label {}, length {}, badge {:#x}, MR0 to MR3 {:#x?}: {m}",
            r.msg.info.label(),
            r.msg.info.length(),
            r.badge,
            r.msg.mr
        )
    });
    println!(
        "fault: handler received VMFault from thread F: ip {:#x}, addr {:#x}, prefetch {}, fsr {:#x} (a user-mode read of a page not present)",
        fault.ip, fault.addr, fault.prefetch, fault.fsr
    );
    // Words 4 to 8 of the result come through this thread's own buffer.
    let regs = tcb_read_registers(Some(ipc), faulter, false, READ)
        .unwrap_or_else(|e| fail!("the handler's TCB_ReadRegisters on F: {e}"));
    check_stopped(&regs);
    println!(
        "fault: handler read thread F's registers: rip {:#x} is the faulting instruction, rdi {:#x}, rsp {:#x}",
        regs.get(UserReg::Rip),
        regs.get(UserReg::Rdi),
        regs.get(UserReg::Rsp)
    );

    // F is above H, so H runs only while F is blocked; the dump shows how.
    println!(
        "fault: handler runs below thread F's priority {FAULTER_PRIORITY}, so F is blocked; every thread before the kill:"
    );
    libsys::debug_dump_scheduler();
    tcb_suspend(faulter).unwrap_or_else(|e| fail!("the handler's TCB_Suspend on F: {e}"));
    println!("fault: handler killed thread F with TCB_Suspend");
    // F's reply capability went with the kill: this reply, which would
    // restart F, finds an empty caller slot and does nothing.
    reply(&Message::EMPTY);
    send(
        report,
        &Message::new(
            MessageInfo::new(REPORT, 0, 0, 2),
            [fault.ip, fault.addr, 0, 0],
        ),
    );

    // Nothing more may come: a second fault means F ran again.
    let r = recv(fault_ep);
    fail!(
        "the handler received label {}, MR0 to MR3 {:#x?} after it killed thread F",
        r.msg.info.label(),
        r.msg.mr
    )
}
