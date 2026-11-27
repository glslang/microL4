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
//! - `test=tlb`: a page's translation is gone from the TLB as soon as
//!   `Frame_Remap`, `Frame_Unmap` or `PageTable_Unmap` changes its entry
//!   ([`tlb`]);
//! - `test=redteam-*`: the M5 red-team tests ([`redteam`]);
//! - `test=pingpong`: 1,000 timed `Call`/`ReplyRecv` round trips with a
//!   server thread ([`pingpong`]);
//! - `test=captransfer`: capabilities sent to a server in a CSpace of its
//!   own, unwrapped, refused, sent back in replies, and revoked
//!   ([`captransfer`]);
//! - `test=badge`: each client's badge reaches the server, and
//!   `CNode_CancelBadgedSends` releases exactly one badge's queued senders
//!   ([`badge`]);
//! - `test=ipcntfn`: a server bound to a notification takes calls and
//!   signals on one receive ([`ipcntfn`]);
//! - `test=ioport`: IOPortControl and IOPort: issue, overlaps, accesses
//!   at the ends of a range, In's reply, copies and deletion ([`ioport`]);
//! - `test=irq`: IRQControl and IRQHandler with COM1's THRE interrupt:
//!   the edge and level rules, `Clear`, deletion and revoke ([`irq`]);
//! - `test=console`: two clients write interleaved lines through the
//!   `console` and `uart` servers, which run in address spaces of their
//!   own, and input the harness types reaches the right client
//!   ([`console`], [`servers`]);
//! - `test=release`: the same servers on a kernel without `debug`, where
//!   the root task makes no debug system call and ends the run through
//!   `isa-debug-exit` ([`release`]);
//! - `test=tui`: the TUI app runs inside the terminal emulator, which
//!   draws to the framebuffer mapped write-combining, with keys the
//!   harness types ([`tui`], [`servers`]);
//! - `test=term_fault` and `test=tui_fault` (review): once tui has drawn
//!   its first frame, term or tui faults, and the run ends with failure
//!   through `watch` or through root's report of tui's fault on D
//!   ([`tui`]);
//! - `test=nofb`: with no display, root starts no terminal and still
//!   reads its line ([`nofb`]);
//! - `test=pci`: root reaches ECAM through device frames it carves,
//!   enumerates PCI, finds the virtio-net function, sizes its BARs, checks
//!   its regions and MSI-X, reads its MAC through the region pages it
//!   carved, and unmaps configuration space ([`pci`]).
//!
//! Every test ends the run with `libsys::exit`: status 0 after `TEST
//! PASS`, 1 after a `TEST FAIL` line, through `DebugHalt` unless the test
//! set an exit port. With no `test=` the root task halts with 0 after the
//! summary. `test=release` prints its summary only once console runs.

#![no_std]
#![no_main]

mod badge;
mod captransfer;
mod console;
mod fault;
mod ioport;
mod ipcntfn;
mod irq;
mod isolation;
mod nofb;
mod pci;
mod pingpong;
mod redteam;
mod release;
mod release_fault;
mod servers;
mod spawn;
mod threads;
mod tlb;
mod tui;

use libsys::bootinfo::{CAP_INIT_CNODE, SlotRegion};
use libsys::ipc::word;
use libsys::{BootInfo, Ipc, Message, MessageInfo, call, cmdline, println};
use root::process::UartBurst;

libsys::entry!(main);

/// Prints `TEST FAIL: ` and the message, and ends the run with
/// `libsys::exit(1)`: `DebugHalt(1)`, or the exit port if the test set
/// one.
macro_rules! fail {
    ($($arg:tt)*) => {{
        libsys::println!("TEST FAIL: {}", format_args!($($arg)*));
        libsys::exit(1)
    }};
}
pub(crate) use fail;

fn main(bi: &'static BootInfo) -> ! {
    let test = cmdline::value(bi.cmdline(), "test");
    // A kernel without `debug` has no DebugPutChar: test=release and
    // test=release_fault print only once console runs.
    if !matches!(test, Some("release" | "release_fault")) {
        summary(bi);
    }
    match test {
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
        Some("pingpong") => pingpong::run(bi),
        Some("captransfer") => captransfer::run(bi),
        Some("badge") => badge::run(bi),
        Some("ipcntfn") => ipcntfn::run(bi),
        Some("ioport") => ioport::run(bi),
        Some("irq") => irq::run(bi),
        Some("console") => console::run(bi),
        Some("release") => release::run(bi),
        Some("release_fault") => release_fault::run(bi),
        Some("tui") => tui::run(bi),
        Some("term_fault") => tui::fault(bi, tui::Victim::Term),
        Some("tui_fault") => tui::fault(bi, tui::Victim::Tui),
        Some("nofb") => nofb::run(bi),
        Some("pci") => pci::run(bi),
        Some(name) if name.starts_with("redteam-") => redteam::run(bi, name),
        Some(other) => fail!("unknown test {other:?}"),
    }
}

/// Names the root task and prints what BootInfo says.
pub(crate) fn summary(bi: &BootInfo) {
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
    // From M9: a cap on uart's burst, which `servers::start` passes on.
    let burst = UartBurst::parse(bi.cmdline());
    if burst != UartBurst::Absent {
        println!("root: {burst}");
    }
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
