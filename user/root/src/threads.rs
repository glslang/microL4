//! `test=threads`: two ring-3 threads at the same priority interleave their
//! output under preemption (PLAN.md, M5's done-when).
//!
//! The root task retypes an endpoint and two TCBs, A and B, gives each a
//! stack in its `.bss` and its own CSpace and VSpace, sets both to priority
//! [`PRIORITY`], below its own 255, resumes them and waits on the endpoint.
//! Each thread prints [`LINES`] lines through `DebugPutChar`, and between
//! two lines spins for [`BUSY_MS`] of TSC time without a system call, many
//! 10 ms time slices. While it spins it swaps its id into [`LAST`], the
//! shared "last thread to run" word: finding the other's id there means the
//! other thread ran since it last looked, which, with no system call in
//! between, only a preemption can have allowed. It counts those and logs
//! them, then sends the root its count, and the root suspends it.
//!
//! The root then checks that each thread was preempted with the other
//! running in between at least [`MIN_PREEMPTIONS`] times, and that the
//! lines, in print order, changed thread at least [`MIN_ALTERNATIONS`]
//! times ([`root::check::threads`]).
//!
//! Each line is printed under a lock that a waiting thread yields on, so
//! lines never mix. The root prints nothing while the threads run: it
//! cannot wait for a lock a lower-priority thread holds.

use core::sync::atomic::Ordering::{Acquire, Relaxed, Release};
use core::sync::atomic::{AtomicBool, AtomicU8, AtomicU64, AtomicUsize};

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::invoke::{tcb_resume, tcb_set_priority, tcb_suspend};
use libsys::{
    BootInfo, CPtr, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, println, rdtsc, recv, send,
    yield_now,
};
use root::check::{self, NAMES, ThreadsLog};

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// The threads' priority.
const PRIORITY: u64 = 100;
/// Lines each thread prints.
const LINES: usize = 8;
/// How long each thread spins between two lines, in milliseconds.
const BUSY_MS: u64 = 40;
/// Preemptions each thread must see, with the other running in between.
const MIN_PREEMPTIONS: u64 = 3;
/// Changes of thread the print order must show.
const MIN_ALTERNATIONS: usize = 3;
/// The label of a thread's report to the root.
const DONE: u64 = 0xD0E;

/// The id of the last thread seen running: 1 for A, 2 for B, 0 for none.
static LAST: AtomicU8 = AtomicU8::new(0);
/// Per thread, how many times it saw the other ran in between.
static PREEMPTED: [AtomicU64; 2] = [AtomicU64::new(0), AtomicU64::new(0)];
/// TSC ticks in a busy phase.
static BUSY_TSC: AtomicU64 = AtomicU64::new(0);
/// Held while a line is printed.
static PRINT_LOCK: AtomicBool = AtomicBool::new(false);
/// The index of the thread that printed each line, in print order.
static LINE_LOG: Log<{ 2 * LINES + 8 }> = Log::new();
/// The index of the thread that saw each preemption, in order.
static SWITCH_LOG: Log<64> = Log::new();

/// An append-only log of thread indices, which keeps the first `N`.
struct Log<const N: usize> {
    len: AtomicUsize,
    ids: [AtomicU8; N],
}

impl<const N: usize> Log<N> {
    const fn new() -> Log<N> {
        Log {
            len: AtomicUsize::new(0),
            ids: [const { AtomicU8::new(0) }; N],
        }
    }

    fn push(&self, id: u8) {
        if let Some(slot) = self.ids.get(self.len.fetch_add(1, Relaxed)) {
            slot.store(id, Relaxed);
        }
    }

    /// Copies the entries kept to `out`: how many, and how many were
    /// pushed.
    fn read(&self, out: &mut [u8; N]) -> (usize, usize) {
        let total = self.len.load(Relaxed);
        let kept = total.min(N);
        for (o, id) in out.iter_mut().zip(&self.ids[..kept]) {
            *o = id.load(Relaxed);
        }
        (kept, total)
    }
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    if bi.tsc_hz == 0 {
        fail!("BootInfo's tsc_hz is 0: nothing to time the busy phases by");
    }
    BUSY_TSC.store(bi.tsc_hz / 1000 * BUSY_MS, Relaxed);
    let mut objects = ObjectAlloc::new(bi);
    let done = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("retyping the endpoint: {e}"));
    let tcbs = objects
        .retype(ipc, ObjectType::Tcb, 0, 2)
        .unwrap_or_else(|e| fail!("retyping the TCBs: {e}"));
    for (i, stack) in STACKS.iter().enumerate() {
        // A thread that faults sends its fault to the root, which fails.
        let t = Thread {
            tcb: tcbs + i as u64,
            fault_ep: done,
            stack,
            entry: worker,
            args: [i as u64, done, 0, 0],
        };
        spawn::prepare(ipc, &t)
            .and_then(|()| tcb_set_priority(ipc, t.tcb, CAP_INIT_TCB, PRIORITY))
            .unwrap_or_else(|e| fail!("setting up thread {}: {e}", NAMES[i]));
    }
    println!(
        "threads: threads A and B at priority {PRIORITY}, below the root task's 255, in TCB slots {tcbs} and {}; each prints {LINES} lines and spins {BUSY_MS} ms between two without a system call",
        tcbs + 1
    );
    for i in 0..2 {
        tcb_resume(tcbs + i)
            .unwrap_or_else(|e| fail!("resuming thread {}: {e}", NAMES[i as usize]));
    }

    // Wait for both reports, suspending each thread as it finishes.
    let mut reported = [None; 2];
    for _ in 0..2 {
        let r = recv(done);
        let info = r.msg.info;
        if info.label() != DONE || info.length() != 2 {
            fail!(
                "the root received label {}, length {}, MR0 to MR3 {:#x?} instead of a thread's report: a fault message?",
                info.label(),
                info.length(),
                r.msg.mr
            );
        }
        let [index, count, ..] = r.msg.mr;
        let Some(slot) = reported.get_mut(index as usize).filter(|s| s.is_none()) else {
            fail!("a second report, or one from thread index {index}");
        };
        *slot = Some(count);
        tcb_suspend(tcbs + index)
            .unwrap_or_else(|e| fail!("suspending thread {}: {e}", NAMES[index as usize]));
    }

    let preempted = [PREEMPTED[0].load(Relaxed), PREEMPTED[1].load(Relaxed)];
    if reported != [Some(preempted[0]), Some(preempted[1])] {
        fail!("the threads reported {reported:?} preemptions, but counted {preempted:?}");
    }
    let mut lines = [0; 2 * LINES + 8];
    let (kept, printed) = LINE_LOG.read(&mut lines);
    if kept != printed {
        fail!("{printed} lines printed, more than the log keeps");
    }
    let mut switches = [0; 64];
    let (seen, total) = SWITCH_LOG.read(&mut switches);
    let mut buf = [0; 64];
    println!(
        "threads: thread A was preempted {} times and thread B {} times with the other thread running in between",
        preempted[0], preempted[1]
    );
    println!(
        "threads: the preemptions in the order the threads saw them: {}{}",
        check::names(&switches[..seen], &mut buf),
        if total > seen { "..." } else { "" }
    );
    let log = ThreadsLog {
        preempted,
        lines: &lines[..kept],
        lines_each: LINES,
    };
    match check::threads(&log, MIN_PREEMPTIONS, MIN_ALTERNATIONS) {
        Ok(alternations) => {
            println!(
                "threads: lines in print order: {}, {alternations} changes of thread",
                check::names(&lines[..kept], &mut buf)
            );
            println!("TEST PASS");
            libsys::debug_halt(0)
        }
        Err(e) => fail!("{e}"),
    }
}

/// Thread `index` (0 for A, 1 for B): prints its lines and spins between
/// them, counting preemptions, then reports to the root on `done`.
extern "C" fn worker(index: u64, done: CPtr, _: u64, _: u64) -> ! {
    let i = index as usize;
    let me = index as u8 + 1;
    let busy = BUSY_TSC.load(Relaxed);
    for line in 1..=LINES {
        locked(|| {
            println!(
                "threads: {} line {line} of {LINES}, preempted {} times so far",
                NAMES[i],
                PREEMPTED[i].load(Relaxed)
            );
            LINE_LOG.push(i as u8);
        });
        // No system call from here to the end of the phase: if the other
        // thread's id turns up in LAST, the timer preempted this one and
        // the other ran.
        LAST.store(me, Relaxed);
        let start = rdtsc();
        while rdtsc().wrapping_sub(start) < busy {
            if LAST.swap(me, Relaxed) != me {
                PREEMPTED[i].fetch_add(1, Relaxed);
                SWITCH_LOG.push(i as u8);
            }
        }
    }
    let count = PREEMPTED[i].load(Relaxed);
    send(
        done,
        &Message::new(MessageInfo::new(DONE, 0, 0, 2), [index, count, 0, 0]),
    );
    // The root suspends this thread once it has the report.
    loop {
        yield_now();
    }
}

/// Runs `f` holding the print lock, yielding while the other thread holds
/// it: it runs at the same priority, so it gets to finish its line.
fn locked(f: impl FnOnce()) {
    while PRINT_LOCK.swap(true, Acquire) {
        yield_now();
    }
    f();
    PRINT_LOCK.store(false, Release);
}
