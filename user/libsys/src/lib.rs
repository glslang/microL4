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
//! - [`transfer`] lays out messages with words past MR3 and extra
//!   capabilities, and reads what a receive says about the capabilities it
//!   got ([`ReceivedCaps`]); [`Ipc`] names the receive slot.
//! - [`notification`] signals, waits and polls, and tells a bound
//!   notification's signal from a message ([`Event`]).
//! - [`invoke`] performs the Untyped, CNode and TCB invocations,
//!   `CNode_SaveCaller`, `CNode_CancelBadgedSends` and the notification
//!   binding included, and [`Error`] is the error a failed one returns,
//!   decoded.
//! - [`device`] performs the IRQControl, IRQHandler, IOPortControl and
//!   IOPort invocations (M7), `GetMSI` and `GetSint` included (M9), and
//!   [`hyperv`] the Hypervisor invocations (M9).
//! - [`objects`] hands out the root task's free slots and picks the untyped
//!   its objects are retyped from.
//! - [`proto`] defines the `uart`, `console` and `term` protocols;
//!   [`console`], [`uart`] and [`term`] are their clients.
//! - [`print!`] and [`println!`] write where [`output`] says, through
//!   `DebugPutChar` until a program names a console client; [`exit`] ends
//!   the run through an `isa-debug-exit` IOPort if one is set, else with
//!   `DebugHalt`, and [`output::Polled`] writes to COM1 past `uart`. The
//!   panic handler prints the panic and ends the run with `exit(1)`.
//! - [`vspace`] maps paging structures and frames, and [`image`] gives the
//!   program's segment bounds, for building a server's address space from
//!   the root task's image frames.
//! - [`mem`] reaches device registers ([`mem::Mmio`]) and memory shared
//!   with a device, the host or another VSpace ([`mem::Shared`]) through
//!   the [`mem::Regs`] and [`mem::Memory`] traits, which [`mem::Ram`]
//!   implements on the host for the drivers' tests (M9).
//! - [`frames`] is the frame queues a network driver and `net` share (M9).
//!
//! User programs build for `x86_64-unknown-none`, like the kernel, so
//! nothing uses SSE (`docs/design.md`, "FP and SIMD"), but with the small
//! code model, statically linked at `0x40_0000` by `user/link.ld`;
//! `cargo xtask build` passes the flags. `_start` and the panic handler
//! exist only for that target, so the rest also builds for the host, where
//! `cargo test -p libsys` runs the unit tests.

#![no_std]
#![deny(unsafe_op_in_unsafe_fn)]
#![warn(clippy::undocumented_unsafe_blocks)]

#[cfg(test)]
extern crate std;

mod client;
pub mod console;
pub mod cpu;
mod debug;
pub mod device;
pub mod error;
pub mod frames;
pub mod hyperv;
#[cfg(target_os = "none")]
pub mod image;
pub mod invoke;
pub mod mem;
pub mod notification;
pub mod objects;
pub mod output;
pub mod proto;
#[cfg(target_os = "none")]
mod start;
pub mod syscall;
pub mod term;
pub mod transfer;
pub mod uart;
pub mod vspace;

pub use l4core::bootinfo::{self, BootInfo};
pub use l4core::cap::{ObjectType, Rights};
pub use l4core::cmdline;
pub use l4core::error::{LookupFailure, SyscallError};
pub use l4core::ipc::{self, IpcBuffer, MessageInfo};
pub use l4core::regs::{UserReg, fault_label};

pub use client::CallError;
pub use cpu::rdtsc;
pub use debug::{Console, debug_dump_scheduler, debug_halt, debug_put_char};
pub use error::Error;
pub use invoke::{IpcBufferFrame, Registers, Reply, Slot};
pub use notification::{Event, poll, signal, wait};
pub use objects::{AllocError, ObjectAlloc, SlotAlloc, UntypedAlloc};
#[doc(hidden)]
pub use output::_print;
pub use output::exit;
pub use syscall::{
    CPtr, Ipc, Message, Received, call, nb_recv, nb_send, recv, reply, reply_recv, send, yield_now,
};
pub use transfer::{Arrival, ReceivedCaps, compose};
