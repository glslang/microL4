//! The microL4 root task: the first user program, which the kernel loads
//! from `.rootimage` and starts in ring 3 (`docs/design.md`, "Boot").
//!
//! It names itself and prints the BootInfo summary it reads, then runs the
//! test the command line's `test=` names, which the kernel passes on when
//! it has no test of that name:
//!
//! - `test=root`: a few system calls the kernel must get right
//!   ([`system_calls`]), then `TEST PASS`;
//! - `test=threads`: two threads at one priority interleave their output
//!   under preemption ([`threads`]);
//! - `test=fault`: a page fault reaches the faulting thread's fault
//!   handler, which kills it ([`fault`]);
//! - `test=isolation`: two threads switched by the scheduler keep their
//!   x87, SSE, FS and GS base and general registers ([`isolation`]);
//! - `test=tlb`: no translation survives the unmap or remap that removed
//!   it, in a VSpace two threads share ([`tlb`]).
//!
//! Every test ends the run with `DebugHalt`: 0 after `TEST PASS`, 1 after a
//! `TEST FAIL` line. With no `test=` the root task halts with 0 after the
//! summary.

#![no_std]
#![no_main]

mod fault;
mod isolation;
mod spawn;
mod threads;
mod tlb;

use libsys::bootinfo::{CAP_INIT_CNODE, SlotRegion};
use libsys::ipc::word;
use libsys::{BootInfo, Ipc, Message, MessageInfo, call, cmdline, println};

libsys::entry!(main);

/// Prints `TEST FAIL: ` and the message, and ends the run with
/// `DebugHalt(1)`.
macro_rules! fail {
    ($($arg:tt)*) => {{
        libsys::println!("TEST FAIL: {}", format_args!($($arg)*));
        libsys::debug_halt(1)
    }};
}
pub(crate) use fail;

fn main(bi: &'static BootInfo) -> ! {
    summary(bi);
    match cmdline::value(bi.cmdline(), "test") {
        None => {
            println!("root: no test= on the command line; nothing more to do");
            libsys::debug_halt(0)
        }
        Some("root") => {
            system_calls(bi);
            println!("TEST PASS");
            libsys::debug_halt(0)
        }
        Some("threads") => threads::run(bi),
        Some("fault") => fault::run(bi),
        Some("isolation") => isolation::run(bi),
        Some("tlb") => tlb::run(bi),
        Some(other) => fail!("unknown test {other:?}"),
    }
}

/// Names the root task and prints what BootInfo says.
fn summary(bi: &BootInfo) {
    println!(
        "root: microL4 root task, BootInfo at {:#x}, version {}",
        bi as *const BootInfo as u64, bi.version
    );
    println!(
        "root: image {:#x}-{:#x}, IPC buffer at {:#x}",
        bi.user_image_start,
        bi.user_image_end,
        Ipc::root().as_ptr() as u64
    );
    println!("root: cmdline {:?}", bi.cmdline());
    let region = |name: &str, r: SlotRegion| {
        if r.is_empty() {
            println!("root: {name}: none");
        } else {
            println!("root: {name}: slots {}-{}, {}", r.start, r.end - 1, r.len());
        }
    };
    region("paging structures", bi.user_image_paging);
    region("image frames", bi.user_image_frames);
    region("extra BootInfo frames", bi.extra_bootinfo_frames);
    region("untyped", bi.untyped);
    region("framebuffer untyped", bi.framebuffer_untyped);
    region("empty", bi.empty);
    let untyped = bi.untyped();
    let ram: u64 = untyped
        .iter()
        .filter(|u| !u.device())
        .map(|u| u.size())
        .sum();
    println!(
        "root: {} untyped, {} KiB of RAM; TSC {} Hz; {}-bit physical addresses",
        untyped.len(),
        ram >> 10,
        bi.tsc_hz,
        bi.phys_addr_bits
    );
}

/// `Untyped_Retype`'s label, and the object type of a 4 KiB frame
/// (`docs/abi.md`, "Untyped invocations", "Object types and sizes").
const UNTYPED_RETYPE: u64 = 0x01;
const FRAME_4K: u64 = 5;
/// The error code of `InvalidCapability` (`docs/abi.md`, "Errors").
const INVALID_CAPABILITY: u64 = 2;

/// A few system calls the kernel must get right: the scheduler's dump, a
/// yield, an invocation with message registers and an extra capability in
/// the IPC buffer, and one that fails.
fn system_calls(bi: &BootInfo) {
    libsys::debug_dump_scheduler();
    libsys::yield_now();
    println!("root: back from Yield, the only thread at its priority");

    // The largest RAM untyped, whose first retype clears all of it: long
    // enough for the timer to preempt the call, which then restarts.
    let Some((i, u)) = bi
        .untyped()
        .iter()
        .enumerate()
        .filter(|(_, u)| !u.device())
        .max_by_key(|(_, u)| u.size())
    else {
        fail!("root: no RAM untyped")
    };
    let ut = bi.untyped.start + i as u64;
    let slot = bi.empty.start;
    // MR4 and MR5, and the destination CNode's CPtr, travel in the buffer.
    let ipc = Ipc::root();
    ipc.set_mr(4, slot);
    ipc.set_mr(5, 1);
    ipc.set_word(word::CAPS_OR_BADGES, CAP_INIT_CNODE);
    // Type, size bits, node index and depth (0: the root CNode itself).
    let info = MessageInfo::new(UNTYPED_RETYPE, 0, 1, 6);
    let r = call(ut, &Message::new(info, [FRAME_4K, 0, 0, 0]));
    if r.info.label() != 0 {
        fail!(
            "root: Untyped_Retype failed: error {}, MR0 {}",
            r.info.label(),
            r.mr[0]
        )
    }
    println!(
        "root: Untyped_Retype of the {} MiB untyped in slot {ut} into a 4 KiB frame in slot {slot}: done",
        u.size() >> 20
    );

    // An empty slot: InvalidCapability, MR0 0 (the invoked capability).
    let r = call(
        slot + 1,
        &Message::new(MessageInfo::new(UNTYPED_RETYPE, 0, 0, 0), [0; 4]),
    );
    if (r.info.label(), r.info.length(), r.mr[0]) != (INVALID_CAPABILITY, 1, 0) {
        fail!(
            "root: a Call on an empty slot gave label {}, length {}, MR0 {}",
            r.info.label(),
            r.info.length(),
            r.mr[0]
        )
    }
    println!(
        "root: a Call on empty slot {}: InvalidCapability, MR0 0",
        slot + 1
    );
}
