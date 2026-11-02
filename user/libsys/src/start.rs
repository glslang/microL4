//! `_start` and the program's entry.
//!
//! The kernel starts the root task at its ELF entry with `rsp` 0 and `rdi`
//! BootInfo's address (`docs/abi.md`, "Root-task entry state"). `_start`
//! loads the top of `.libsys_stack`, which `user/link.ld` puts in a segment
//! of its own above an unmapped guard page, and calls [`start`], which
//! checks BootInfo, records the IPC buffer for [`crate::Ipc::root`] and
//! calls the function [`entry!`] named.

use core::arch::global_asm;

use l4core::bootinfo::{BOOTINFO_MAGIC, BOOTINFO_SIZE, BOOTINFO_VERSION, BootInfo};
use l4core::ipc::{IPC_BUFFER_SIZE, IpcBuffer};

/// Bytes of the stack `_start` switches to.
pub const STACK_SIZE: usize = 64 << 10;

// The stack is `.libsys_stack`, no file bytes, 16-byte aligned at both ends,
// so `rsp` is 16-byte aligned before the `call` as the System V ABI wants.
// `rdi` still holds BootInfo's address, `start`'s argument; `rbp` 0 ends a
// backtrace. `start` never returns; `ud2` faults if it somehow did.
global_asm!(
    ".section .libsys_stack, \"aw\", @nobits",
    ".balign 16",
    "2:",
    ".skip {stack_size}",
    "3:",
    "",
    ".section .text._start, \"ax\", @progbits",
    ".global _start",
    "_start:",
    "    lea rsp, [rip + 3b]",
    "    xor ebp, ebp",
    "    call {start}",
    "    ud2",
    stack_size = const STACK_SIZE,
    start = sym start,
);

unsafe extern "Rust" {
    /// The program's `main`, which [`entry!`] defines.
    safe fn __libsys_main(bootinfo: &'static BootInfo) -> !;
}

/// Checks the BootInfo at `bootinfo` and calls the program's `main`.
extern "C" fn start(bootinfo: *const BootInfo) -> ! {
    if bootinfo.is_null() || !bootinfo.is_aligned() {
        crate::println!("libsys: bad BootInfo address {bootinfo:p}");
        crate::debug_halt(1);
    }
    // SAFETY: the kernel maps BootInfo's two frames, RW, at the address it
    // passes in `rdi` (`docs/abi.md`, "Root-task entry state"), and nothing
    // unmaps them. Every field is a plain integer, so any contents are a
    // valid BootInfo. The kernel never writes it again, and this program
    // only reads it through this reference.
    let bi: &'static BootInfo = unsafe { &*bootinfo };
    if bi.magic != BOOTINFO_MAGIC
        || bi.version != BOOTINFO_VERSION
        || bi.size as usize != BOOTINFO_SIZE
    {
        crate::println!(
            "libsys: BootInfo at {bootinfo:p} has magic {:#x}, version {}, size {}; this libsys reads version {BOOTINFO_VERSION}",
            bi.magic,
            bi.version,
            bi.size
        );
        crate::debug_halt(1);
    }
    if !bi.ipc_buffer.is_multiple_of(IPC_BUFFER_SIZE) || bi.ipc_buffer == 0 {
        crate::println!("libsys: bad IPC buffer address {:#x}", bi.ipc_buffer);
        crate::debug_halt(1);
    }
    crate::syscall::set_root_ipc_buffer(bi.ipc_buffer as *mut IpcBuffer);
    __libsys_main(bi)
}

/// Names the program's entry point, a `fn(&'static BootInfo) -> !`, which
/// `_start` calls on the program's own stack:
///
/// ```ignore
/// libsys::entry!(main);
///
/// fn main(bootinfo: &'static libsys::BootInfo) -> ! {
///     libsys::println!("hello");
///     libsys::debug_halt(0)
/// }
/// ```
#[macro_export]
macro_rules! entry {
    ($main:path) => {
        #[unsafe(export_name = "__libsys_main")]
        fn __libsys_main(bootinfo: &'static $crate::BootInfo) -> ! {
            let main: fn(&'static $crate::BootInfo) -> ! = $main;
            main(bootinfo)
        }
    };
}
