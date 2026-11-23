//! `test=tui`: M8's done-when on QEMU with the selftest kernel
//! (`docs/design.md`, "Scenarios" under "Framebuffer, terminal and TUI").
//! A TUI app runs inside a terminal emulator that draws to the
//! framebuffer, its keys typed by the harness.
//!
//! The root task starts `watch`, `uart` and `console`, attaches as client
//! 1 and points its output at console; checks the framebuffer and prints
//! its `fb:` line; runs the write-combining check [H10], timing a full
//! clear of the visible area mapped uncached and then write-combining in
//! its own VSpace; starts `term` (125) and `tui` (100) in spaces of their
//! own, term with the framebuffer mapped write-combining in its VSpace
//! alone; shows every framebuffer frame it holds mapped, and prints the
//! priorities it set with the MCPs it reads back; and waits on endpoint D
//! for tui's report, which comes once tui has quit. It checks that tui read
//! exactly the bytes typed for client 4, prints them, prints term's
//! `Stats` and requires no sequence ignored and no byte dropped, then
//! reads one line as client 1, so the run waits for the last screendump.
//!
//! `test=term_fault` and `test=tui_fault` (review tests of
//! `docs/design.md`'s "Failures" under "Framebuffer, terminal and TUI")
//! start the same way, then read a line as client 1, which the harness
//! types once tui has drawn its first frame, and make one of the two fault
//! at its next instruction: suspended, its `rip` written 0 and resumed, it
//! fetches from page 0, which nothing maps. A term fault goes to `watch`,
//! which ends the run with failure; a tui fault comes on D, where root
//! reports it through console and fails the test.

use libsys::bootinfo::{CAP_INIT_VSPACE, MAX_UNTYPED};
use libsys::console::Client;
use libsys::invoke::{invoke, tcb_set_priority, tcb_suspend, tcb_write_registers};
use libsys::proto::{self, MAX_BYTES, label};
use libsys::vspace::{READ_WRITE, UNCACHED, WRITE_COMBINING};
use libsys::{
    BootInfo, CPtr, Error, Ipc, ObjectAlloc, ObjectType, Registers, SyscallError, UserReg, println,
    recv,
};
use root::check::console::ROOT;
use root::check::tui::{
    self as check, Clear, FbLine, Mapped, NoFb, OnD, Priorities, ReadLine, Sched, Started,
    StatsLine,
};

use crate::fail;
use crate::servers::{self, CONSOLE_PRIORITY, FbObjects, TERM_PRIORITY, TUI_PRIORITY};

/// `Frame_Remap`'s label (`docs/abi.md`, "Invocation labels" under
/// "Address spaces"), which libsys does not wrap.
const FRAME_REMAP: u64 = 0x52;

/// What runs once term and tui have started.
struct Running {
    ipc: Ipc,
    /// The root task as console's client 1.
    me: Client,
    t: servers::Terminal,
    /// Endpoint D: tui's report and its faults.
    d: CPtr,
}

pub fn run(bi: &BootInfo) -> ! {
    let r = start(bi);
    let mut bytes = [0u8; MAX_BYTES];
    let n = report(&r, &mut bytes);
    let read = &bytes[..n];
    println!("{}", ReadLine(read));
    check::report(read).unwrap_or_else(|e| fail!("tui: {e}"));

    let stats = libsys::term::Client::new(r.t.stats, Some(r.ipc))
        .stats()
        .unwrap_or_else(|e| fail!("tui: term's Stats: {e}"));
    println!("{}", StatsLine(stats));
    check::stats(&stats).unwrap_or_else(|e| fail!("tui: {e}"));

    // The screen holds still while the harness takes the last screendump:
    // tui waits in its report, term in its receive, root here.
    println!("root: the TUI has quit; Ctrl-T 1 and Enter end the test");
    let mut line = [0u8; libsys::console::MAX_LINE];
    r.me.read_line(&mut line)
        .unwrap_or_else(|e| fail!("tui: root's Read: {e}"));
    println!("TEST PASS");
    libsys::exit(0)
}

/// The thread `test=term_fault` or `test=tui_fault` makes fault.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Victim {
    Term,
    Tui,
}

/// `test=term_fault` and `test=tui_fault`: once tui has drawn its first
/// frame, the victim's next instruction fetch is from address 0.
pub fn fault(bi: &BootInfo, victim: Victim) -> ! {
    let (test, name) = match victim {
        Victim::Term => ("term_fault", "term"),
        Victim::Tui => ("tui_fault", "tui"),
    };
    let r = start(bi);
    // The harness types Enter for root, which has focus, once tui has
    // drawn its first frame: tui then waits in term's Read, saved, and
    // term in its receive on T.
    let mut line = [0u8; libsys::console::MAX_LINE];
    r.me.read_line(&mut line)
        .unwrap_or_else(|e| fail!("{test}: root's Read: {e}"));
    println!("{test}: suspending {name}, setting its rip to 0 and resuming it");
    // Every byte so far on the wire before the fault's line.
    r.me.sync()
        .unwrap_or_else(|e| fail!("{test}: root's Sync: {e}"));
    let tcb = match victim {
        Victim::Term => r.t.term_tcb,
        Victim::Tui => r.t.tui_tcb,
    };
    // Suspended, it leaves its receive or its call; resumed, it fetches
    // from address 0, which no VSpace maps, and faults with a VMFault.
    tcb_suspend(tcb)
        .and_then(|()| {
            tcb_write_registers(r.ipc, tcb, true, &Registers::ZERO, UserReg::Rip.index() + 1)
        })
        .unwrap_or_else(|e| fail!("{test}: making {name} fault: {e}"));
    match victim {
        Victim::Term => {
            // term faults before it receives this; watch ends the run.
            let s = libsys::term::Client::new(r.t.stats, Some(r.ipc)).stats();
            println!("term_fault: term answered Stats after its rip was set to 0: {s:?}");
            fail!("term_fault: watch did not end the run")
        }
        Victim::Tui => {
            // tui's fault comes on D, where root fails the test.
            let mut bytes = [0u8; MAX_BYTES];
            report(&r, &mut bytes);
            fail!("tui_fault: tui reported after its rip was set to 0")
        }
    }
}

/// Starts the servers, checks the framebuffer, runs the write-combining
/// check, starts term and tui, and shows the frames mapped and the
/// priorities, printing a line for each.
fn start(bi: &BootInfo) -> Running {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let s = servers::start(bi, ipc, &mut objects, None);
    let me = Client::new(s.client, Some(ipc));
    match me.attach("root") {
        Ok(ROOT) => {}
        other => fail!("tui: root's Attach gave {other:?}, not client 1"),
    }
    // From here print! goes through console.
    libsys::output::use_console(s.client);

    let mut untyped = [fb::Untyped::default(); MAX_UNTYPED];
    let (fields, n) = check::framebuffer(bi, &mut untyped);
    let plan = match fb::Plan::new(&fields, &untyped[..n]) {
        Ok(p) => p,
        Err(why) => {
            println!("{}", NoFb(why));
            fail!("tui: no usable framebuffer, so no term and no tui")
        }
    };
    println!("{}", FbLine(&plan));
    let fbo = servers::framebuffer_objects(bi, ipc, &mut objects, &plan);
    let clear = write_combining_check(ipc, &plan, &fbo, bi.tsc_hz);
    println!("{clear}");

    let d = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("tui: retyping D: {e}"));
    let t = servers::start_terminal(bi, ipc, &mut objects, &s, &plan, &fbo, d);
    let slots = 1u64 << bi.root_cnode_bits;
    println!(
        "{}",
        Started {
            used: slots - objects.slots.remaining(),
            slots
        }
    );

    // Every frame is mapped, somewhere: in term's VSpace, by review.
    for i in 0..fbo.frames {
        let frame = fbo.first_frame + i;
        let map = libsys::vspace::frame_map(
            ipc,
            frame,
            fb::WINDOW + 1,
            READ_WRITE,
            WRITE_COMBINING,
            CAP_INIT_VSPACE,
        );
        let remap = invoke(None, frame, FRAME_REMAP, &[0, WRITE_COMBINING], &[]).map(|_| ());
        check::mapped(&map, &remap)
            .unwrap_or_else(|e| fail!("tui: framebuffer frame {i} (slot {frame}): {e}"));
    }
    println!("{}", Mapped(fbo.frames));

    let sched = |priority, tcb| Sched {
        priority,
        mcp: mcp(ipc, tcb),
    };
    let p = Priorities {
        console: sched(CONSOLE_PRIORITY, s.console_tcb),
        term: sched(TERM_PRIORITY, t.term_tcb),
        tui: sched(TUI_PRIORITY, t.tui_tcb),
    };
    println!("{p}");
    check::priorities(&p).unwrap_or_else(|e| fail!("tui: {e}"));

    Running { ipc, me, t, d }
}

/// A thread's MCP, read back: `TCB_SetPriority` of the thread to 256,
/// with itself as the authority, is refused with a `RangeError` from 0 to
/// the authority's MCP (`docs/abi.md`, "`TCB_SetPriority`") and changes
/// nothing. No invocation reads a priority back.
fn mcp(ipc: Ipc, tcb: CPtr) -> u64 {
    match tcb_set_priority(ipc, tcb, tcb, 256) {
        Err(Error::Kernel(SyscallError::RangeError { min: 0, max })) => max,
        other => fail!("tui: TCB_SetPriority to 256 of TCB slot {tcb} gave {other:?}"),
    }
}

/// tui's report on D, decoded into `bytes`: how many. Anything else on D,
/// a fault of tui's among them, fails the test.
fn report(r: &Running, bytes: &mut [u8; MAX_BYTES]) -> usize {
    let m = recv(r.d);
    let info = m.msg.info;
    if info.label() != label::TUI_REPORT || m.badge != servers::TUI_BADGE {
        fail!(
            "{}",
            OnD {
                badge: m.badge,
                label: info.label(),
                mr: m.msg.mr
            }
        );
    }
    proto::decode(
        info.length() as usize,
        |i| r.ipc.received_word(&m.msg, i),
        tui::REPORT,
        bytes,
    )
    .unwrap_or_else(|e| fail!("tui: its report does not decode: {e}"))
}

/// The write-combining check [H10] (`docs/design.md`, "`fb`"): maps every
/// framebuffer frame in the root task's own VSpace at `fb::WINDOW`, first
/// uncached, clears the visible area once and times it with the TSC,
/// unmaps, then the same write-combining. The page tables end unmapped and
/// empty, ready for term's VSpace; no frame is mapped twice at once.
fn write_combining_check(ipc: Ipc, plan: &fb::Plan<'_>, fbo: &FbObjects, tsc_hz: u64) -> Clear {
    fbo.map_tables(ipc, plan, CAP_INIT_VSPACE);
    let mut ticks = [0; 2];
    for (t, cache) in ticks.iter_mut().zip([UNCACHED, WRITE_COMBINING]) {
        fbo.map_frames(ipc, plan, CAP_INIT_VSPACE, cache);
        *t = clear(plan.geometry());
        fbo.unmap_frames();
    }
    fbo.unmap_tables();
    Clear {
        uncached: ticks[0],
        write_combining: ticks[1],
        tsc_hz,
    }
}

/// Fills the visible area with 0 through the window as it is mapped now,
/// ending with `sfence`, and returns the TSC ticks it took.
fn clear(g: fb::Geometry) -> u64 {
    // SAFETY: `write_combining_check` has just mapped `fb::Plan`'s frames,
    // which cover the visible bytes, read-write at `fb::WINDOW` + (their
    // address - `base` rounded down to 2 MiB) in this VSpace, the only
    // mapping of each frame; `g.offset()` is `base` mod 2 MiB, so the
    // `stride x height` pixels from `fb::WINDOW + offset` are the visible
    // bytes, 4-byte aligned. No other thread in this VSpace names them,
    // and the slice is gone before they are unmapped. Every bit pattern
    // is a valid `u32`.
    let pixels = unsafe {
        core::slice::from_raw_parts_mut((fb::WINDOW + g.offset()) as *mut u32, g.pixels())
    };
    let mut surface =
        fb::Surface::new(g, pixels).unwrap_or_else(|| fail!("tui: the window's pixels"));
    let start = tsc();
    surface.fill(fb::Rgb(0));
    libsys::cpu::store_fence();
    tsc().wrapping_sub(start)
}

/// The TSC, read as a compiler barrier: `libsys::rdtsc` is `nomem`, so the
/// compiler may move the clear's stores across it, out of the timed
/// stretch; this `asm!` may touch memory as far as the compiler knows, so
/// no store moves across it, as none moves across `store_fence`.
fn tsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` writes only EAX and EDX, reads and writes no memory,
    // needs no stack and leaves the flags alone; with CR4.TSD clear it
    // cannot fault in ring 3. Leaving out `nomem` keeps the compiler from
    // moving memory accesses across it.
    unsafe {
        core::arch::asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}
