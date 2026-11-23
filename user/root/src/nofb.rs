//! `test=nofb`: a machine with no display (`docs/design.md`, "Scenarios"
//! under "Framebuffer, terminal and TUI"; `qemu_args: -vga none`). OVMF
//! finds no display, the loader passes no framebuffer, and the root task
//! prints why, starts no term and no tui, and reads one line as client 1.
//! The harness types bytes for client 4 first: console keeps them in its
//! raw queue, signalling NT, which no thread is bound to, and the line
//! still reaches client 1.

use libsys::bootinfo::MAX_UNTYPED;
use libsys::console::Client;
use libsys::{BootInfo, Ipc, ObjectAlloc, println};
use root::check::console::ROOT;
use root::check::tui::{self as check, FbLine, NoFb};

use crate::fail;
use crate::servers;

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let s = servers::start(bi, ipc, &mut objects, None);
    let me = Client::new(s.client, Some(ipc));
    match me.attach("root") {
        Ok(ROOT) => {}
        other => fail!("nofb: root's Attach gave {other:?}, not client 1"),
    }
    libsys::output::use_console(s.client);

    let mut untyped = [fb::Untyped::default(); MAX_UNTYPED];
    let (fields, n) = check::framebuffer(bi, &mut untyped);
    match fb::Plan::new(&fields, &untyped[..n]) {
        Err(why) => println!("{}", NoFb(why)),
        Ok(plan) => {
            println!("{}", FbLine(&plan));
            fail!("nofb: a framebuffer, though the scenario has no display")
        }
    }
    println!("nofb: type a line");
    let mut line = [0u8; libsys::console::MAX_LINE];
    let n = me
        .read_line(&mut line)
        .unwrap_or_else(|e| fail!("nofb: Read: {e}"));
    let text = core::str::from_utf8(&line[..n]).unwrap_or("(not UTF-8)");
    println!("nofb: read {text:?}");
    check::nofb(&line[..n]).unwrap_or_else(|e| fail!("nofb: {e}"));
    println!("TEST PASS");
    libsys::exit(0)
}
