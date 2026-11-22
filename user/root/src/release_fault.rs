//! `test=release_fault` (review): the failure path of `docs/design.md`,
//! "Failures", on a kernel without `debug`. The root task starts the
//! servers as `test=release` does, prints a line and syncs, then revokes
//! its COM1 IOPort, which deletes uart's copy, and prints again: root waits
//! in console's `Write`, console in uart's, and uart's next port access
//! fails. uart panics; its panic message's first `DebugPutChar` raises
//! `UnknownSyscall`, which the kernel sends to endpoint F, and `watch`
//! writes `TEST FAIL: uart fault 2 (UnknownSyscall), ...` through `Polled`
//! on the root task's COM1 IOPort, which the revoke kept, and ends the run
//! through `isa-debug-exit` with failure. Nothing else could report it: the
//! kernel prints nothing, and the root task waits for good.

use libsys::console::Client;
use libsys::invoke::cnode_revoke;
use libsys::{BootInfo, Ipc, ObjectAlloc, Slot, println};
use root::check::console::ROOT;

use crate::fail;
use crate::servers;

pub fn run(bi: &'static BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let exit = servers::exit_port(ipc, &mut objects, bi);
    libsys::output::set_exit_port(exit);
    let s = servers::start(bi, ipc, &mut objects, exit);
    let me = Client::new(s.client, Some(ipc));
    let attached = me.attach("root");
    libsys::output::use_console(s.client);
    if attached != Ok(ROOT) {
        fail!("release_fault: root's Attach gave {attached:?}, not client 1");
    }
    println!("release_fault: revoking the COM1 IOPort, which deletes uart's copy");
    me.sync()
        .unwrap_or_else(|e| fail!("release_fault: Sync: {e}"));
    cnode_revoke(Slot::root_cnode(s.com1))
        .unwrap_or_else(|e| fail!("release_fault: CNode_Revoke of the COM1 IOPort: {e}"));
    // uart's Write faults here; watch ends the run.
    println!("release_fault: console answered after uart lost its IOPort");
    fail!("release_fault: watch did not end the run")
}
