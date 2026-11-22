//! `test=pingpong`: 1,000 `Call`/`ReplyRecv` round trips between the root
//! task and a server thread, each reply checked, timed with the TSC
//! (PLAN.md, M6's done-when).
//!
//! The root task retypes an endpoint and a TCB for the server S, at
//! priority [`SERVER_PRIORITY`] with an IPC buffer in the second KiB of the
//! root task's buffer frame, and calls S through a capability with badge
//! [`BADGE`]. S waits with `Recv`, then answers every request with
//! `ReplyRecv`, checking the badge each time. Each run is [`WARM_UP`]
//! round trips, then [`ROUND_TRIPS`] with an `rdtsc` between each two,
//! every reply checked against its request ([`root::check::pingpong`]):
//! one-word messages first, the done-when's, then zero-length and
//! full-length (120-word) ones, whose MR4 to MR119 the kernel copies
//! between the two buffers both ways. Neither thread does anything else,
//! so each `Call` switches straight to S and each `ReplyRecv` straight
//! back. Each run prints its total and mean cycles, and the fastest and
//! median round trip, with nanoseconds from BootInfo's `tsc_hz`. Under TCG
//! the numbers show trends, not real performance, and the TSC follows host
//! time, so a busy host inflates the mean more than the median.

use core::fmt;

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::invoke::{Slot, cnode_mint, tcb_resume, tcb_set_priority};
use libsys::{
    BootInfo, CPtr, Ipc, Message, ObjectAlloc, ObjectType, Rights, call, println, rdtsc, recv,
    reply_recv,
};
use root::check::pingpong::{self as pp, LAST, Shape};

use crate::fail;
use crate::spawn::{self, STACKS, Space, Thread};

/// Round trips timed in each run.
const ROUND_TRIPS: u64 = 1000;
/// Round trips before the timing starts.
const WARM_UP: u64 = 16;
/// S's priority, below the root task's 255.
const SERVER_PRIORITY: u64 = 200;
/// The badge of the root task's capability to the endpoint.
const BADGE: u64 = 0x9090;

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let buffer = spawn::root_frame_buffer(bi, 1).unwrap_or_else(|| {
        fail!(
            "pingpong: the root task's IPC buffer {:#x} is not at the start of its frame",
            bi.ipc_buffer
        )
    });
    let mut objects = ObjectAlloc::new(bi);
    let ep = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("pingpong: retyping the endpoint: {e}"));
    let tcb = objects
        .retype(ipc, ObjectType::Tcb, 0, 1)
        .unwrap_or_else(|e| fail!("pingpong: retyping the TCB: {e}"));
    let badged = objects
        .slots
        .alloc(1)
        .unwrap_or_else(|| fail!("pingpong: no free slot"));
    let rights = Rights(Rights::WRITE.0 | Rights::GRANT.0);
    cnode_mint(
        ipc,
        Slot::root_cnode(badged),
        Slot::root_cnode(ep),
        rights,
        BADGE,
    )
    .unwrap_or_else(|e| fail!("pingpong: minting the badged capability: {e}"));
    let s = Thread {
        tcb,
        fault_ep: 0,
        stack: STACKS[0],
        entry: server,
        args: [ep, buffer.addr, 0, 0],
    };
    let space = Space {
        buffer: Some(buffer),
        ..Space::ROOT
    };
    spawn::prepare_with(ipc, &s, space)
        .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, SERVER_PRIORITY))
        .and_then(|()| tcb_resume(tcb))
        .unwrap_or_else(|e| fail!("pingpong: starting the server: {e}"));
    println!(
        "pingpong: server S (TCB slot {tcb}, priority {SERVER_PRIORITY}, IPC buffer at {:#x}) answers on endpoint slot {ep}; the root task calls through slot {badged}, badge {BADGE:#x}",
        buffer.addr
    );

    // MR4 to MR118 of the full-length runs: S echoes them.
    for i in 4..LAST {
        ipc.set_mr(i, pp::pattern(i));
    }
    let mut samples = [0; ROUND_TRIPS as usize];
    for shape in Shape::ALL {
        for i in 0..WARM_UP {
            round_trip(ipc, badged, shape, i);
        }
        // One rdtsc between two round trips: each sample is one round
        // trip, and their sum the whole run.
        let mut last = rdtsc();
        for (i, sample) in (WARM_UP..).zip(samples.iter_mut()) {
            round_trip(ipc, badged, shape, i);
            let now = rdtsc();
            *sample = now.wrapping_sub(last);
            last = now;
        }
        let t = pp::Timing::of(&mut samples);
        let hz = bi.tsc_hz;
        println!(
            "pingpong: {} round trips of {}-word messages, every reply checked: {} TSC cycles in all; per round trip {} on average, fastest {}, median {}",
            t.trips,
            shape.words(),
            t.total,
            Cycles(t.mean, hz),
            Cycles(t.fastest, hz),
            Cycles(t.median, hz)
        );
    }
    match bi.tsc_hz {
        0 => println!("pingpong: BootInfo has no TSC rate, so no times in nanoseconds"),
        hz => println!("pingpong: nanoseconds at BootInfo's TSC rate, {hz} Hz"),
    }
    if let Some(i) = (4..LAST).find(|&i| ipc.mr(i) != pp::pattern(i)) {
        fail!(
            "pingpong: after the full-length runs MR{i} is {:#x}, not {:#x}",
            ipc.mr(i),
            pp::pattern(i)
        );
    }
    println!("pingpong: MR4 to MR118 came back unchanged from every full-length round trip");
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// TSC cycles, and their time in nanoseconds if the rate is known.
struct Cycles(u64, u64);

impl fmt::Display for Cycles {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let Cycles(cycles, hz) = *self;
        write!(f, "{cycles}")?;
        match pp::ns(cycles, hz) {
            Some(ns) => write!(f, " ({ns} ns)"),
            None => Ok(()),
        }
    }
}

/// Round trip `i` of `shape` through `ep`, its reply checked.
fn round_trip(ipc: Ipc, ep: CPtr, shape: Shape, i: u64) {
    let full = shape == Shape::Full;
    if full {
        ipc.set_mr(LAST, pp::last_word(i));
    }
    let reply = call(ep, &pp::request(shape, i));
    let last = if full { ipc.mr(LAST) } else { 0 };
    if let Err(m) = pp::check_reply(shape, i, &reply, last) {
        fail!(
            "pingpong: round trip {i} of {}-word messages: {m}",
            shape.words()
        );
    }
}

/// S: answers every request on `ep`. `buffer` is its IPC buffer.
extern "C" fn server(ep: CPtr, buffer: u64, _: u64, _: u64) -> ! {
    let ipc = spawn::thread_ipc(buffer);
    let mut r = recv(ep);
    loop {
        if r.badge != BADGE {
            fail!(
                "pingpong: server: a message with badge {:#x}, not {BADGE:#x}",
                r.badge
            );
        }
        let full = r.msg.info.length() as usize > LAST;
        let last = if full { ipc.mr(LAST) } else { 0 };
        let answer: Message = match pp::answer(&r.msg, last) {
            Ok((answer, last)) => {
                if full {
                    ipc.set_mr(LAST, last);
                }
                answer
            }
            Err(m) => fail!("pingpong: server: {m}"),
        };
        r = reply_recv(ep, &answer);
    }
}
