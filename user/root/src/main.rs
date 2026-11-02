//! The microL4 root task: the first user program, which the kernel loads
//! from `.rootimage` and starts in ring 3 (`docs/design.md`, "Boot").
//!
//! For now a stub: it names itself, prints the BootInfo summary it reads,
//! then `TEST PASS`, and ends the run with `DebugHalt(0)`.

#![no_std]
#![no_main]

use libsys::bootinfo::SlotRegion;
use libsys::{BootInfo, Ipc, println};

libsys::entry!(main);

fn main(bi: &'static BootInfo) -> ! {
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
    println!("TEST PASS");
    libsys::debug_halt(0)
}
