//! `libsys`: what every microL4 user program links against.
//!
//! - [`entry!`] names the program's `main(&'static BootInfo) -> !`. The
//!   `_start` here switches to a 64 KiB stack of the program's own (the
//!   kernel gives the root task none), checks the BootInfo the kernel passed
//!   in `rdi`, and calls it (`docs/design.md`, "Root-task image and address
//!   space").
//! - [`syscall`] wraps every system call of `docs/abi.md`, "System calls",
//!   the debug ones included, with messages as [`MessageInfo`] and message
//!   registers laid out by `l4core::ipc`.
//! - [`print!`] and [`println!`] write through `DebugPutChar`; the panic
//!   handler prints the panic and ends the run with `DebugHalt(1)`.
//!
//! User programs build for `x86_64-unknown-none`, like the kernel, so
//! nothing uses SSE (`docs/design.md`, "FP and SIMD"), but with the small
//! code model, statically linked at `0x40_0000` by `user/link.ld`;
//! `cargo xtask build` passes the flags.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

mod debug;
mod start;
pub mod syscall;

pub use l4core::bootinfo::{self, BootInfo};
pub use l4core::ipc::{self, IpcBuffer, MessageInfo};

#[doc(hidden)]
pub use debug::_print;
pub use debug::{Console, debug_dump_scheduler, debug_halt, debug_put_char};
pub use syscall::{
    CPtr, Ipc, Message, Received, call, nb_recv, nb_send, recv, reply, reply_recv, send, yield_now,
};
