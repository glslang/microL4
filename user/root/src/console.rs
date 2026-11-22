//! `test=console`: M7's done-when on a kernel with `debug`
//! (`docs/design.md`, "Scenarios" under "User-level drivers and
//! console"). Two clients write interleaved lines through `console`, and
//! input the harness types reaches the right client.
//!
//! The root task prints its summary through `DebugPutChar`, starts
//! `watch`, `uart` and `console` (`servers.rs`), attaches as client 1,
//! points its own output at console and starts clients `a` (badge 2) and
//! `b` (badge 3), and `r`, which reads as client 1 for it, each in the
//! root task's VSpace with a CSpace of its own and an IPC buffer in KiB 1,
//! 2 or 3 of the root task's buffer frame. A client asks for its next step
//! with a `Call` on endpoint D that reports on its last one (label
//! `0x130`); its fault endpoint is the same capability, so the root task
//! tells a fault from a report by the label. The root task answers one
//! client at a time and keeps the others' reply capabilities saved, so
//! every write boundary is fixed, and it blocks only on D or in calls to
//! console and uart, never in a call to a client.
//!
//! At the end each client, root included through `r`, Reads once more,
//! and console must save all three Reads: nothing else the harness typed
//! reached a client.

use core::fmt::Write;

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::console::{Buffered, Client};
use libsys::invoke::{cnode_mint, cnode_save_caller, tcb_resume, tcb_set_sched_params};
use libsys::proto::MAX_BYTES;
use libsys::{
    BootInfo, CPtr, CallError, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Rights, Slot,
    call, nb_recv, println, recv, send,
};
use root::check::console::{
    self as check, A, Action, B, B2_LEN, BURST_LINES, CONSOLE_INPUT_BYTES, DRAIN_STEP, INPUT_STEPS,
    INTERLEAVED_STEPS, REPORT, ROOT, Report, SCRIPT, STARTED, TYPEAHEAD_INPUT_BYTES,
    TYPEAHEAD_LINE, TYPEAHEAD_STEP,
};

use crate::fail;
use crate::servers::{self, CLIENT_PRIORITY, CONSOLE_PRIORITY, UART_PRIORITY, WATCH_PRIORITY};
use crate::spawn::{self, STACKS, Space, Thread};

/// A client's slots in its own 16-slot CNode, named with 64 bits.
const CLIENT_CONSOLE: CPtr = 2;
const CLIENT_D: CPtr = 3;

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let s = servers::start(bi, ipc, &mut objects, None);
    println!(
        "console: watch (TCB slot {}, priority {WATCH_PRIORITY}) receives the servers' faults; uart (TCB slot {}, priority {UART_PRIORITY}) holds copies of the COM1 IOPort (slot {}) and the IRQ 4 handler (slot {}, GSI {}, edge, active high); console (TCB slot {}, priority {CONSOLE_PRIORITY}); each server in a CSpace and VSpace of its own, {} root slots each",
        s.watch_tcb, s.uart_tcb, s.com1, s.irq, s.irq_info.gsi, s.console_tcb, s.slots_each
    );
    let me = Client::new(s.client, Some(ipc));
    match me.attach("root") {
        Ok(ROOT) => {}
        other => fail!("console: root's Attach gave {other:?}, not client 1"),
    }
    // From here print! goes through console.
    libsys::output::use_console(s.client);
    println!("console: root is client 1; its output goes through console from here");

    let d = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("console: retyping D: {e}"));
    let saved = objects
        .slots
        .alloc(4)
        .unwrap_or_else(|| fail!("console: no free slots"));
    // The saved reply capability of client `badge`.
    let saved_slot = |badge: u64| saved + badge;
    // r is client 1, as root is: its console capability has root's badge.
    for (badge, stack, kib) in [(A, STACKS[1], 1), (B, STACKS[2], 2), (ROOT, STACKS[3], 3)] {
        start_client(bi, ipc, &mut objects, s.console_ep, d, badge, stack, kib);
    }
    println!(
        "console: clients a (badge {A}) and b (badge {B}), priority {CLIENT_PRIORITY}, and r, which reads as client {ROOT} for root, each in a CSpace of its own, report on endpoint D (slot {d})"
    );

    // Each client's first report: it has attached.
    for _ in 0..3 {
        let (client, r) = report(ipc, d);
        if r.step != STARTED || r.status != 0 {
            fail!(
                "console: client {}'s first report: step {:#x}, status {:#x}",
                check::name(client),
                r.step,
                r.status
            );
        }
        save(saved_slot(client));
    }

    for (i, step) in SCRIPT[..INPUT_STEPS].iter().enumerate() {
        send(saved_slot(step.client), &step_message(i));
        let (client, r) = report(ipc, d);
        if client != step.client || r.step != i as u64 || r.status != 0 {
            fail!(
                "console: step {i}: client {} reported step {:#x}, status {:#x}; want client {}'s step {i}, status 0",
                check::name(client),
                r.step,
                r.status,
                check::name(step.client)
            );
        }
        save(saved_slot(client));
        if i == INTERLEAVED_STEPS {
            println!("console: interleaved lines written, in 11 steps");
        }
    }
    println!("console: burst of {BURST_LINES} lines written");

    // Input: both clients write a prompt and read; their lines arrive in
    // any order.
    for (i, step) in SCRIPT
        .iter()
        .enumerate()
        .take(TYPEAHEAD_STEP)
        .skip(INPUT_STEPS)
    {
        send(saved_slot(step.client), &step_message(i));
    }
    println!("console: input next");
    let mut lines = [(0, [0u8; 255], 0usize); 2];
    for slot in lines.iter_mut() {
        let (client, r) = report(ipc, d);
        if r.status != 0 || !(INPUT_STEPS..TYPEAHEAD_STEP).contains(&(r.step as usize)) {
            fail!(
                "console: client {} reported step {:#x}, status {:#x}, during the input",
                check::name(client),
                r.step,
                r.status
            );
        }
        *slot = (client, r.line, r.len);
        save(saved_slot(client));
    }
    let got = [
        (lines[0].0, &lines[0].1[..lines[0].2]),
        (lines[1].0, &lines[1].1[..lines[1].2]),
    ];
    check::reads(&got).unwrap_or_else(|e| fail!("console: {e}"));
    println!("console: ok   a read exactly \"hi a\" and b exactly \"to b\"");

    // Type-ahead: once uart has received the line (and so signalled NC),
    // a Sync makes console take that signal first, so the line waits for
    // a when a's Read arrives, with a prompt of more than 24 bytes held.
    let uart = libsys::uart::Client::new(s.uart_stats, Some(ipc));
    let total = CONSOLE_INPUT_BYTES + TYPEAHEAD_INPUT_BYTES;
    println!("console: type ahead next");
    let mut polls = 0u64;
    loop {
        let st = uart
            .stats()
            .unwrap_or_else(|e| fail!("console: uart's Stats: {e}"));
        if st.received >= total {
            break;
        }
        polls += 1;
        if polls > 10_000_000 {
            fail!("console: uart received {} of {total} bytes", st.received);
        }
    }
    me.sync()
        .unwrap_or_else(|e| fail!("console: root's Sync: {e}"));
    send(saved_slot(A), &step_message(TYPEAHEAD_STEP));
    let (client, r) = report(ipc, d);
    if client != A || r.step != TYPEAHEAD_STEP as u64 || r.status != 0 {
        fail!(
            "console: type-ahead: client {} reported step {:#x}, status {:#x}",
            check::name(client),
            r.step,
            r.status
        );
    }
    if r.line() != TYPEAHEAD_LINE.as_bytes() {
        fail!(
            "console: type-ahead: a read {:?}, not {TYPEAHEAD_LINE:?}",
            core::str::from_utf8(r.line()).unwrap_or("(not UTF-8)")
        );
    }
    save(saved_slot(A));
    println!(
        "console: ok   a's Read was answered at once with the {}-byte line typed ahead, after its prompt was flushed",
        TYPEAHEAD_LINE.len()
    );

    // Nothing else reached a client. Console has taken every byte the
    // harness sent: the type-ahead line ended the input. Now r (for
    // client 1), a and b each Read once more, and console must save each
    // Read, as no line waits for any of them. Each client first reports
    // that it has its drain step, so a step that never reached it hangs
    // the test rather than passing it, and Reads only once root has every
    // client's report and answers them. Once every thread above the root
    // task's lowest priority has blocked, each client has made its Read;
    // once root's Sync, queued behind any Read console has not taken yet,
    // is answered, console has taken all three; and once every thread has
    // blocked again, a client whose Read was answered waits on D with its
    // report.
    let drain = &SCRIPT[DRAIN_STEP..];
    for (i, step) in drain.iter().enumerate() {
        send(saved_slot(step.client), &step_message(DRAIN_STEP + i));
    }
    let mut ready = [false; SCRIPT.len() - DRAIN_STEP];
    for _ in drain {
        let (client, r) = report(ipc, d);
        let i = drain.iter().position(|s| s.client == client);
        match i {
            Some(i)
                if !ready[i]
                    && r.step == (DRAIN_STEP + i) as u64
                    && r.status == 0
                    && r.len == 0 =>
            {
                ready[i] = true;
            }
            _ => fail!(
                "console: client {} reported step {:#x}, status {:#x}, waiting for the drain steps",
                check::name(client),
                r.step,
                r.status
            ),
        }
        save(saved_slot(client));
    }
    for (i, step) in drain.iter().enumerate() {
        send(saved_slot(step.client), &step_message(DRAIN_STEP + i));
    }
    spawn::let_others_run(ipc);
    me.sync()
        .unwrap_or_else(|e| fail!("console: root's Sync: {e}"));
    spawn::let_others_run(ipc);
    let r = nb_recv(d);
    if r.badge != 0 && r.msg.info.label() != REPORT {
        fail!(
            "console: client {} (badge {}) fault {}, MR0 to MR3 {:#x?}",
            check::name(r.badge),
            r.badge,
            r.msg.info.label(),
            r.msg.mr
        );
    }
    check::drained(r.badge).unwrap_or_else(|e| fail!("console: {e}"));
    println!(
        "console: ok   nothing else reached a client: r (for root, client 1), a and b each Read once more, and console saved all three Reads, with no line waiting"
    );

    let stats = uart
        .stats()
        .unwrap_or_else(|e| fail!("console: uart's Stats: {e}"));
    println!("console: uart: {stats}");
    check::stats(&stats, total).unwrap_or_else(|e| fail!("console: {e}"));
    println!(
        "console: ok   receive and THRE interrupts both served, all {total} bytes the harness sent received, no overruns"
    );
    println!("TEST PASS");
    libsys::exit(0)
}

/// Moves the reply capability of the report just received into `slot`.
fn save(slot: CPtr) {
    cnode_save_caller(Slot::root_cnode(slot))
        .unwrap_or_else(|e| fail!("console: saving a client's reply: {e}"));
}

/// The reply that sends a client to step `i`.
fn step_message(i: usize) -> Message {
    Message::new(MessageInfo::new(0, 0, 0, 1), [i as u64, 0, 0, 0])
}

/// The next report on D, and the client it came from; a client's fault
/// fails the test.
fn report(ipc: Ipc, d: CPtr) -> (u64, Report) {
    let r = recv(d);
    let info = r.msg.info;
    if info.label() != REPORT {
        fail!(
            "console: client {} (badge {}) fault {}, MR0 to MR3 {:#x?}",
            check::name(r.badge),
            r.badge,
            info.label(),
            r.msg.mr
        );
    }
    let length = info.length() as usize;
    let report = Report::decode(length, |i| ipc.received_word(&r.msg, i)).unwrap_or_else(|| {
        fail!(
            "console: a report from client {} that does not decode",
            check::name(r.badge)
        )
    });
    (r.badge, report)
}

/// Client `badge`: a 16-slot CNode with C and D badged with its number,
/// D also its fault endpoint, and the IPC buffer in KiB `kib` of the root
/// task's buffer frame.
#[allow(clippy::too_many_arguments)]
fn start_client(
    bi: &BootInfo,
    ipc: Ipc,
    objects: &mut ObjectAlloc,
    console_ep: CPtr,
    d: CPtr,
    badge: u64,
    stack: &'static spawn::Stack,
    kib: u64,
) {
    let buffer = spawn::root_frame_buffer(bi, kib).unwrap_or_else(|| {
        fail!(
            "console: the root task's IPC buffer {:#x} is not at the start of its frame",
            bi.ipc_buffer
        )
    });
    let cnode = objects
        .retype(ipc, ObjectType::CNode, 4, 1)
        .unwrap_or_else(|e| fail!("console: retyping a client's CNode: {e}"));
    let tcb = objects
        .retype(ipc, ObjectType::Tcb, 0, 1)
        .unwrap_or_else(|e| fail!("console: retyping a client's TCB: {e}"));
    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    for (dest, src) in [(CLIENT_CONSOLE, console_ep), (CLIENT_D, d)] {
        cnode_mint(
            ipc,
            Slot::new(cnode, dest, 4),
            Slot::root_cnode(src),
            w_gr,
            badge,
        )
        .unwrap_or_else(|e| fail!("console: client {}'s slot {dest}: {e}", check::name(badge)));
    }
    let t = Thread {
        tcb,
        fault_ep: CLIENT_D,
        stack,
        entry: client,
        args: [badge, buffer.addr, 0, 0],
    };
    let space = Space {
        cspace: cnode,
        cspace_data: 60,
        buffer: Some(buffer),
    };
    spawn::prepare_with(ipc, &t, space)
        .and_then(|()| {
            tcb_set_sched_params(ipc, tcb, CAP_INIT_TCB, CLIENT_PRIORITY, CLIENT_PRIORITY)
        })
        .and_then(|()| tcb_resume(tcb))
        .unwrap_or_else(|e| fail!("console: starting client {}: {e}", check::name(badge)));
}

/// A status word for a report: 0, or what went wrong.
fn status(r: Result<(), CallError>) -> u64 {
    match r {
        Ok(()) => 0,
        Err(CallError::Refused(r)) => r.label(),
        Err(CallError::Kernel(e)) => e.kernel().map_or(0xFFFF, |k| k.code()),
        Err(CallError::BadReply { .. }) => 0xFFFE,
    }
}

/// A client: attaches, then reports on D and does the step the reply
/// names, for ever. It writes only through a console client of its own:
/// `print!` would name the root task's slot.
extern "C" fn client(badge: u64, buffer: u64, _: u64, _: u64) -> ! {
    let ipc = spawn::thread_ipc(buffer);
    let con = Client::new(CLIENT_CONSOLE, Some(ipc));
    let mut done = STARTED;
    let mut result = match con.attach(check::name(badge)) {
        Ok(n) if n == badge => Ok(()),
        Ok(_) => Err(CallError::BadReply {
            label: 0,
            length: 1,
        }),
        Err(e) => Err(e),
    };
    let mut line = [0u8; 255];
    let mut len = 0;
    loop {
        let mut words = [0; 120];
        let n = Report::encode(done, status(result), &line[..len], &mut words);
        let r = call(CLIENT_D, &ipc.compose(REPORT, &words[..n], &[]));
        let i = r.mr[0] as usize;
        let Some(step) = SCRIPT.get(i) else {
            // Root never names a step past the script; stop.
            loop {
                libsys::yield_now();
            }
        };
        done = i as u64;
        len = 0;
        result = match step.action {
            Action::Write(bytes) => con.write(bytes),
            Action::B2(piece) => {
                let l = check::b2_line();
                let third = B2_LEN / 3;
                con.write(&l[piece * third..(piece + 1) * third])
            }
            Action::Burst => (1..=BURST_LINES).try_for_each(|n| con.write(&check::burst_line(n))),
            Action::Drain => {
                // Root's answer to this report lets it Read.
                let n = Report::encode(i as u64, 0, &[], &mut words);
                call(CLIENT_D, &ipc.compose(REPORT, &words[..n], &[]));
                let mut got = [0u8; 255];
                con.read_line(&mut got).map(|n| {
                    line[..n].copy_from_slice(&got[..n]);
                    len = n;
                })
            }
            Action::Input(prompt) => con.write(prompt.as_bytes()).and_then(|()| {
                let mut got = [0u8; 255];
                let n = con.read_line(&mut got)?;
                line[..n].copy_from_slice(&got[..n]);
                len = n;
                let text = core::str::from_utf8(&got[..n]).unwrap_or("(not UTF-8)");
                let mut out = Buffered::new(MAX_BYTES, |p| con.write(p));
                let _ = writeln!(out, "{}: read {text:?}", check::name(badge));
                out.finish()
            }),
        };
    }
}
