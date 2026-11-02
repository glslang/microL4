//! The microL4 root task: the first user program, which the kernel loads
//! from `.rootimage` and starts in ring 3 (`docs/design.md`, "Boot").
//!
//! It names itself and prints the BootInfo summary it reads, then runs the
//! test the command line's `test=` names, which the kernel passes on when
//! it has no test of that name:
//!
//! - `test=root`: `TEST PASS` after the summary;
//! - `test=threads`: two threads at one priority interleave their output
//!   under preemption ([`threads`]);
//! - `test=fault`: a page fault reaches the faulting thread's fault
//!   handler, which kills it ([`fault`]).
//!
//! Every test ends the run with `DebugHalt`: 0 after `TEST PASS`, 1 after a
//! `TEST FAIL` line. With no `test=` the root task halts with 0 after the
//! summary.

#![no_std]
#![no_main]

mod fault;
mod spawn;
mod threads;

use libsys::bootinfo::SlotRegion;
use libsys::{BootInfo, Ipc, cmdline, println};

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
            println!("TEST PASS");
            libsys::debug_halt(0)
        }
        Some("threads") => threads::run(bi),
        Some("fault") => fault::run(bi),
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
