//! `test=release`: the root task on a kernel built without `debug`
//! (`docs/design.md`, "Scenarios" and "A release kernel without UART
//! code"). The kernel prints nothing, so everything on COM1 after the
//! loader comes from `uart`, or from `watch` once a server has faulted.
//!
//! The root task makes no debug system call: one would raise an
//! `UnknownSyscall` fault in the root task, which has no fault handler, and
//! stop it silently. It issues the COM1 range, IRQ 4 and, under QEMU,
//! `0xF4` to `0xF7`, sets its exit port, starts `watch`, `uart` and
//! `console`, attaches as client 1, sets its output and prints through
//! console: its usual summary; from M9, with `release.flood=<n>` on the
//! command line, `n` numbered lines right after it, back to back
//! (`root::flood`); a probe thread's five debug and reserved system calls,
//! each an `UnknownSyscall` fault the root task answers with the probe's
//! registers and `ip` + 2; the line the harness types, which reaches
//! client 1 since focus starts there; uart's totals; `TEST PASS`.
//! `exit(0)` then syncs the console and writes `0x10` to `isa-debug-exit`.

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::console::Client;
use libsys::invoke::{cnode_mint, tcb_resume, tcb_set_priority, tcb_suspend};
use libsys::syscall::syscall;
use libsys::{
    BootInfo, CPtr, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Rights, Slot, call,
    println, recv, reply,
};
use root::check::console::{
    self as check, PROBE_NUMBERS, RELEASE_INPUT_BYTES, RELEASE_LINE, REPORT, ROOT,
    UNKNOWN_SYSCALL_WORDS,
};
use root::flood::Flood;

use crate::fail;
use crate::servers::{self, CLIENT_PRIORITY, CONSOLE_PRIORITY, UART_PRIORITY, WATCH_PRIORITY};
use crate::spawn::{self, STACKS, Thread};

/// The probe's badge on D, its fault endpoint.
const PROBE_BADGE: u64 = 9;

pub fn run(bi: &'static BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let exit = servers::exit_port(ipc, &mut objects, bi);
    libsys::output::set_exit_port(exit);
    let s = servers::start(bi, ipc, &mut objects, exit);
    let me = Client::new(s.client, Some(ipc));
    let attached = me.attach("root");
    libsys::output::use_console(s.client);
    // print! works from here.
    if attached != Ok(ROOT) {
        fail!("release: root's Attach gave {attached:?}, not client 1");
    }
    crate::summary(bi);
    // From M9: the flood, for the Hyper-V check of COM1's lost bytes,
    // before anything else is printed.
    let flood = Flood::parse(bi.cmdline());
    if let Flood::Ignored(_) = flood {
        println!("release: {flood}");
    }
    for line in flood.lines() {
        println!("{line}");
    }
    println!(
        "release: watch (priority {WATCH_PRIORITY}), uart (priority {UART_PRIORITY}) with the COM1 IOPort and IRQ 4, console (priority {CONSOLE_PRIORITY}); exit port {}",
        if exit.is_some() {
            "0xf4-0xf7"
        } else {
            "none: not QEMU"
        }
    );

    probe(ipc, &mut objects);
    println!(
        "release: a probe thread's DebugPutChar, DebugHalt, DebugDumpScheduler and reserved numbers 19 and 31 each raised UnknownSyscall with the number in MR18"
    );

    println!("release: type a line");
    let mut line = [0u8; 255];
    let n = me
        .read_line(&mut line)
        .unwrap_or_else(|e| fail!("release: Read: {e}"));
    let text = core::str::from_utf8(&line[..n]).unwrap_or("(not UTF-8)");
    println!("release: read {text:?}");
    if text != RELEASE_LINE {
        fail!("release: read {text:?}, not {RELEASE_LINE:?}");
    }
    let stats = libsys::uart::Client::new(s.uart_stats, Some(ipc))
        .stats()
        .unwrap_or_else(|e| fail!("release: uart's Stats: {e}"));
    println!("release: uart: {stats}");
    check::stats(&stats, RELEASE_INPUT_BYTES).unwrap_or_else(|e| fail!("release: {e}"));
    println!("TEST PASS");
    libsys::exit(0)
}

/// Starts the probe with fault endpoint D and answers its five faults,
/// then stops it.
fn probe(ipc: Ipc, objects: &mut ObjectAlloc) {
    let mut retype = |ty, what| {
        objects
            .retype(ipc, ty, 0, 1)
            .unwrap_or_else(|e| fail!("release: retyping {what}: {e}"))
    };
    let d = retype(ObjectType::Endpoint, "D");
    let tcb = retype(ObjectType::Tcb, "the probe's TCB");
    let fault_ep = objects
        .slots
        .alloc(1)
        .unwrap_or_else(|| fail!("release: no free slots"));
    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    cnode_mint(
        ipc,
        Slot::root_cnode(fault_ep),
        Slot::root_cnode(d),
        w_gr,
        PROBE_BADGE,
    )
    .unwrap_or_else(|e| fail!("release: minting the probe's D: {e}"));
    let t = Thread {
        tcb,
        fault_ep,
        stack: STACKS[1],
        entry: prober,
        args: [fault_ep, 0, 0, 0],
    };
    spawn::prepare(ipc, &t)
        .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, CLIENT_PRIORITY))
        .and_then(|()| tcb_resume(tcb))
        .unwrap_or_else(|e| fail!("release: starting the probe: {e}"));
    for i in 0..PROBE_NUMBERS.len() {
        let r = recv(d);
        let info = r.msg.info;
        if r.badge != PROBE_BADGE {
            fail!("release: a message on D with badge {}", r.badge);
        }
        let n = (info.length() as usize).min(UNKNOWN_SYSCALL_WORDS);
        let mut words = [0; UNKNOWN_SYSCALL_WORDS];
        for (j, w) in words.iter_mut().enumerate().take(n) {
            *w = ipc.received_word(&r.msg, j);
        }
        let regs = check::probe_fault(i, info.label(), &words, info.length()).unwrap_or_else(|e| {
            fail!(
                "release: {e}: label {}, length {}, MR18 {:#x}",
                info.label(),
                info.length(),
                words[18]
            )
        });
        reply(&ipc.compose(0, &regs, &[]));
    }
    let r = recv(d);
    if r.msg.info.label() != REPORT || r.badge != PROBE_BADGE {
        fail!(
            "release: the probe's last message: label {:#x}, badge {}",
            r.msg.info.label(),
            r.badge
        );
    }
    tcb_suspend(tcb).unwrap_or_else(|e| fail!("release: stopping the probe: {e}"));
}

/// The probe: each of the five numbers, then a report on D.
extern "C" fn prober(d: CPtr, _: u64, _: u64, _: u64) -> ! {
    for n in PROBE_NUMBERS {
        // SAFETY: on a kernel without `debug` each number raises an
        // UnknownSyscall fault, whose handler, the root task, replies with
        // this thread's registers as the fault reported them and `ip` past
        // the `syscall`, so every register is as before but `rcx` and
        // `r11`, which the `asm!` declares clobbered.
        unsafe { syscall(n, 0, &Message::EMPTY) };
    }
    call(d, &Message::new(MessageInfo::new(REPORT, 0, 0, 0), [0; 4]));
    loop {
        libsys::yield_now();
    }
}
