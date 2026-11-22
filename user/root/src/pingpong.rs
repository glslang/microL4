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
//! between the two buffers both ways: S checks every word of each request
//! and answers each plus one, and the root task checks every word of each
//! reply and adds one for its next request. Neither thread does anything
//! else, so each `Call` switches straight to S and each `ReplyRecv`
//! straight back. Each run prints how many round trips it checked, its
//! total and mean cycles, and the fastest and median round trip, with
//! nanoseconds from BootInfo's `tsc_hz`. Under TCG the numbers show
//! trends, not real performance, and the TSC follows host time, so a busy
//! host inflates the mean more than the median.

use core::fmt;

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::invoke::{Slot, cnode_mint, tcb_resume, tcb_set_priority};
use libsys::{
    BootInfo, CPtr, Ipc, Message, ObjectAlloc, ObjectType, Rights, call, println, rdtsc, recv,
    reply_recv,
};
use root::check::pingpong::{self as pp, FIRST_BUFFER_MR, LAST, Shape};

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

    let mut samples = [0; ROUND_TRIPS as usize];
    for shape in Shape::ALL {
        if shape == Shape::Full {
            // MR4 to MR119 of request 0; each checked reply makes the next.
            for k in FIRST_BUFFER_MR..=LAST {
                ipc.set_mr(k, pp::word(k, pp::request_number(0)));
            }
        }
        // Round trips whose reply passed its check: a failed check ends
        // the test.
        let mut checked = 0u64;
        for i in 0..WARM_UP {
            round_trip(ipc, badged, shape, i);
            checked += 1;
        }
        // One rdtsc between two round trips: each sample is one round
        // trip, and their sum the whole run.
        let mut last = rdtsc();
        for (i, sample) in (WARM_UP..).zip(samples.iter_mut()) {
            round_trip(ipc, badged, shape, i);
            let now = rdtsc();
            *sample = now.wrapping_sub(last);
            last = now;
            checked += 1;
        }
        let t = pp::Timing::of(&mut samples);
        let hz = bi.tsc_hz;
        println!(
            "pingpong: {checked} round trips of {}-word messages, every reply checked, the last {} timed: {} TSC cycles in all; per round trip {} on average, fastest {}, median {}",
            shape.words(),
            t.trips,
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
    println!(
        "pingpong: every full-length round trip carried MR4 to MR119 both ways: S checked each word it received and answered it plus one, and the root task checked each word of the reply"
    );
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

/// Round trip `i` of `shape` through `ep`, its reply checked: for a
/// full-length one every buffer word, which then makes request `i + 1`.
fn round_trip(ipc: Ipc, ep: CPtr, shape: Shape, i: u64) {
    let reply = call(ep, &pp::request(shape, i));
    if let Err(m) = pp::check_reply(shape, i, &reply) {
        fail!(
            "pingpong: round trip {i} of {}-word messages: {m}",
            shape.words()
        );
    }
    if shape == Shape::Full
        && let Err(m) = pp::advance(pp::reply_number(i), |k| ipc.mr(k), |k, v| ipc.set_mr(k, v))
    {
        fail!("pingpong: round trip {i} of 120-word messages: the reply's {m}");
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
        let answer: Message = match pp::answer(&r.msg) {
            Ok(answer) => answer,
            Err(m) => fail!("pingpong: server: {m}"),
        };
        // Every word of a full-length request, each answered plus one.
        if let Ok((Shape::Full, i)) = pp::parse_request(&r.msg)
            && let Err(m) = pp::advance(
                pp::request_number(i),
                |k| ipc.mr(k),
                |k, v| ipc.set_mr(k, v),
            )
        {
            fail!("pingpong: server: request {i}'s {m}");
        }
        r = reply_recv(ep, &answer);
    }
}
