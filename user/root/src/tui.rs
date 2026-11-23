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
//! alone; and waits on endpoint D for tui's report, which comes once tui
//! has quit. It checks that tui read exactly the bytes typed for client 4,
//! prints them, prints term's `Stats` and requires no sequence ignored and
//! no byte dropped, then reads one line as client 1, so the run waits for
//! the last screendump.

use libsys::bootinfo::{CAP_INIT_VSPACE, MAX_UNTYPED};
use libsys::console::Client;
use libsys::proto::{self, MAX_BYTES, label};
use libsys::vspace::{UNCACHED, WRITE_COMBINING};
use libsys::{BootInfo, Ipc, ObjectAlloc, ObjectType, println, recv};
use root::check::console::ROOT;
use root::check::tui::{self as check, Clear, FbLine, NoFb, ReadLine, Started, StatsLine};

use crate::fail;
use crate::servers::{self, FbObjects};

pub fn run(bi: &BootInfo) -> ! {
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

    // tui's report, once it has quit; or its fault.
    let r = recv(d);
    let info = r.msg.info;
    if info.label() != label::TUI_REPORT || r.badge != servers::TUI_BADGE {
        fail!(
            "tui: a message on D with badge {}, label {} (a fault of tui's, 1 to 5), MR0 to MR3 {:#x?}",
            r.badge,
            info.label(),
            r.msg.mr
        );
    }
    let mut bytes = [0u8; MAX_BYTES];
    let n = proto::decode(
        info.length() as usize,
        |i| ipc.received_word(&r.msg, i),
        tui::REPORT,
        &mut bytes,
    )
    .unwrap_or_else(|e| fail!("tui: its report does not decode: {e}"));
    let read = &bytes[..n];
    println!("{}", ReadLine(read));
    check::report(read).unwrap_or_else(|e| fail!("tui: {e}"));

    let stats = libsys::term::Client::new(t.stats, Some(ipc))
        .stats()
        .unwrap_or_else(|e| fail!("tui: term's Stats: {e}"));
    println!("{}", StatsLine(stats));
    check::stats(&stats).unwrap_or_else(|e| fail!("tui: {e}"));

    // The screen holds still while the harness takes the last screendump:
    // tui waits in its report, term in its receive, root here.
    println!("root: the TUI has quit; Ctrl-T 1 and Enter end the test");
    let mut line = [0u8; libsys::console::MAX_LINE];
    me.read_line(&mut line)
        .unwrap_or_else(|e| fail!("tui: root's Read: {e}"));
    println!("TEST PASS");
    libsys::exit(0)
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
    let start = libsys::rdtsc();
    surface.fill(fb::Rgb(0));
    libsys::cpu::store_fence();
    libsys::rdtsc().wrapping_sub(start)
}
