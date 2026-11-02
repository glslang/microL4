//! System-call dispatch (`docs/design.md`, "System-call dispatch",
//! "Decoding a system call" and "Faults"; `docs/abi.md`, "System calls",
//! "Registers for each system call" and "Errors, faults and silent drops").
//!
//! The kernel's part of a ring-3 entry is: save the frame into the current
//! thread's TCB, call [`handle_syscall`] (or [`handle_exception`] for a
//! fault), act on the [`Outcome`], run [`crate::sched::schedule`], activate
//! and exit. Everything between is here, as functions of the current
//! thread and its saved registers:
//!
//! - `rdx` is decoded by [`Syscall::from_number`]; an unknown number is an
//!   `UnknownSyscall` fault, with `fault_ip` on the `syscall` instruction.
//! - `Call`, `Send` and `NBSend` look up `rdi` with all 64 bits from the
//!   CSpace root, then, if the caller has a readable IPC buffer, the
//!   `extra_caps` pointers in `caps_or_badges`. A failed lookup is a
//!   capability fault, except for `NBSend`, which does nothing. Then the
//!   capability's type decides: an endpoint sends ([`ipc::send`]), a reply
//!   capability replies ([`ipc::reply`]), and anything else is a kernel
//!   invocation through [`invoke::invoke`], with the message read from
//!   MR0 to MR3 and the buffer. Only a `Call` gets the kernel's reply or
//!   error, and only while the caller is still `Running`.
//! - `Recv` and `NBRecv` look up `rdi` and receive on an endpoint with
//!   Read; anything else is a capability fault in the receive phase.
//! - `Reply` uses the caller slot; `ReplyRecv` replies first, then looks up
//!   `rdi` and receives, so a receive-phase fault never holds the reply back.
//! - `Yield` goes to the scheduler; the debug system calls go back to the
//!   kernel, which performs them.
//!
//! An invocation that reaches a preemption point leaves the caller
//! `Restart`, so it re-executes its `syscall` with its arguments unchanged
//! once the kernel has taken the interrupt.
//!
//! # Until M6
//!
//! Endpoints move no capabilities, and a Notification capability is
//! treated as a kernel object without invocations: `Call` returns
//! `IllegalOperation`, `Send` and `NBSend` drop it, and receiving on it is a
//! capability fault.

use crate::abi::Syscall;
use crate::cap::{Cap, TCB_SLOT_CALLER, TCB_SLOT_CSPACE};
use crate::cspace;
use crate::error::{LookupFailure, SyscallError};
use crate::invoke::{self, ExtraCap, InvokeError, Message};
use crate::ipc::{
    self, DoubleFault, EndpointCap, IpcEnv, MSG_MAX_EXTRA_CAPS, MSG_MAX_LENGTH, MSG_REG_COUNT,
    MessageInfo, word,
};
use crate::regs::{Fault, Regs};
use crate::sched::{self, Scheduling};
use crate::slot::SlotAddr;
use crate::tcb::{self, REGS_OFFSET, TcbRef, ThreadState};

/// What the kernel does after [`handle_syscall`] or [`handle_exception`],
/// before it runs the scheduler.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Outcome {
    /// Nothing more.
    Done,
    /// A preemption point found an interrupt pending; the caller is
    /// `Restart`, or stopped if the work so far stopped it (it deleted its
    /// own TCB). Take the interrupt, then schedule.
    Preempted,
    /// A debug system call, which only a `debug` kernel decodes: perform it
    /// for the current thread, whose registers stay as they are.
    Debug(DebugCall),
    /// A fault found no handler: the thread is `Inactive`. A debug kernel
    /// prints both faults and the thread's `rip` (its `fault_ip`).
    Stopped(DoubleFault),
}

/// A debug system call (`docs/abi.md`, "Debug system calls").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DebugCall {
    /// 16: write the byte to COM1, `\n` as `\r\n`.
    PutChar(u8),
    /// 17: print `DEBUG HALT <status> from TCB <address>` and end the run.
    Halt(u64),
    /// 18: print one line per TCB.
    DumpScheduler,
}

/// The current thread's system call: `rdx`, `rdi`, `rsi` and the message
/// registers are in its saved registers, which the kernel stored on entry
/// (`fault_ip` on the `syscall`, `next_ip` after it). `debug` says whether
/// the kernel was built with the `debug` feature. The current thread must
/// be `Running`.
pub fn handle_syscall<E: IpcEnv + ?Sized>(e: &mut E, debug: bool) -> Outcome {
    let t = caller(e);
    let regs = e.regs(t);
    let Some(syscall) = Syscall::from_number(regs.rdx, debug) else {
        return handle_fault(e, Fault::UnknownSyscall { number: regs.rdx });
    };
    match syscall {
        Syscall::Call => invocation(e, t, true, true),
        Syscall::Send => invocation(e, t, false, true),
        Syscall::NBSend => invocation(e, t, false, false),
        Syscall::Recv => receive(e, t, true),
        Syscall::NBRecv => receive(e, t, false),
        Syscall::Reply => {
            ipc::reply(e, t, t.slot(TCB_SLOT_CALLER));
            Outcome::Done
        }
        Syscall::ReplyRecv => {
            ipc::reply(e, t, t.slot(TCB_SLOT_CALLER));
            receive(e, t, true)
        }
        Syscall::Yield => {
            sched::yield_now(e);
            Outcome::Done
        }
        Syscall::DebugPutChar => Outcome::Debug(DebugCall::PutChar(regs.rdi as u8)),
        Syscall::DebugHalt => Outcome::Debug(DebugCall::Halt(regs.rdi)),
        Syscall::DebugDumpScheduler => Outcome::Debug(DebugCall::DumpScheduler),
    }
}

/// A ring-3 exception of the current thread, as `l4core::entry::classify`
/// found it: `#PF` is a VMFault, every other vector a thread can raise a
/// UserException (`docs/design.md`, "Fault types and sources"). The kernel
/// saved the frame with `fault_ip` = `next_ip` = the RIP the CPU pushed.
/// Panics for a vector that is no fault, which `classify` never returns as
/// an exception.
pub fn handle_exception<E: IpcEnv + ?Sized>(
    e: &mut E,
    vector: u8,
    error: u64,
    cr2: u64,
) -> Outcome {
    let fault = Fault::from_exception(vector, error, cr2).expect("a fault vector");
    handle_fault(e, fault)
}

/// Delivers `fault`, raised by the current thread, to its fault endpoint
/// ([`ipc::deliver_fault`]).
pub fn handle_fault<E: IpcEnv + ?Sized>(e: &mut E, fault: Fault) -> Outcome {
    let t = caller(e);
    match ipc::deliver_fault(e, t, fault) {
        Ok(()) => Outcome::Done,
        Err(stopped) => Outcome::Stopped(stopped),
    }
}

/// Whether the invocation being performed came by `Call`: the current
/// thread's `rdx` is `Call`'s number. Every system call preserves `rdx`, and
/// no invocation writes its caller's, so this holds for the whole
/// invocation. False with no current thread (a self-test's invocation).
/// The kernel's [`crate::tcb::Threads::invoked_by_call`] returns it.
pub fn invoked_by_call<E: Scheduling + ?Sized>(e: &E) -> bool {
    const RDX: u64 = REGS_OFFSET + core::mem::offset_of!(Regs, rdx) as u64;
    e.scheduler()
        .current()
        .is_some_and(|t| e.tcb_word(t, RDX) == Syscall::Call.number())
}

/// The thread making the system call.
fn caller<E: IpcEnv + ?Sized>(e: &E) -> TcbRef {
    let t = e
        .scheduler()
        .current()
        .expect("only a thread enters by syscall or a user exception");
    debug_assert_eq!(e.state(t), ThreadState::Running);
    t
}

/// A capability lookup from `t`'s CSpace root, all 64 bits of `cptr`.
fn lookup<E: IpcEnv + ?Sized>(e: &E, t: TcbRef, cptr: u64) -> Result<SlotAddr, LookupFailure> {
    let root = e.load(t.slot(TCB_SLOT_CSPACE)).cap;
    cspace::lookup_cap(e, root, cptr)
}

/// A capability fault of the current thread `t` at `cptr`, for a system
/// call that may fault; `NBSend` (`may_fault` false) does nothing instead.
fn cap_fault<E: IpcEnv + ?Sized>(
    e: &mut E,
    may_fault: bool,
    cptr: u64,
    in_recv_phase: bool,
    failure: LookupFailure,
) -> Outcome {
    if !may_fault {
        return Outcome::Done;
    }
    handle_fault(
        e,
        Fault::CapFault {
            addr: cptr,
            in_recv_phase,
            failure,
        },
    )
}

/// `Call` (`call`), `Send` (`blocking`) or `NBSend` by `t` (seL4
/// `handleInvocation`).
fn invocation<E: IpcEnv + ?Sized>(e: &mut E, t: TcbRef, call: bool, blocking: bool) -> Outcome {
    let regs = e.regs(t);
    let info = MessageInfo::from_word(regs.rsi);
    let slot = match lookup(e, t, regs.rdi) {
        Ok(slot) => slot,
        Err(failure) => return cap_fault(e, blocking, regs.rdi, false, failure),
    };
    // The send-time lookup of the extra capabilities, whatever the target;
    // none without a readable IPC buffer.
    let mut extra = [ExtraCap {
        cap: Cap::NULL,
        slot,
    }; MSG_MAX_EXTRA_CAPS];
    let mut extra_caps = 0;
    if tcb::buffer_word(e, t, 0, false).is_some() {
        extra_caps = info.extra_caps() as usize;
        for (i, x) in extra[..extra_caps].iter_mut().enumerate() {
            let at =
                tcb::buffer_word(e, t, word::CAPS_OR_BADGES + i, false).expect("a readable buffer");
            let cptr = e.read_buffer_word(at);
            match lookup(e, t, cptr) {
                Ok(s) => *x = ExtraCap::load(e, s),
                Err(failure) => return cap_fault(e, blocking, cptr, false, failure),
            }
        }
    }
    let cap = e.load(slot).cap;
    if let Some(ep) = EndpointCap::from_cap(&cap) {
        if !ep.can_send() || (call && !ep.can_call()) {
            if call {
                ipc::reply_error(e, t, SyscallError::InvalidCapability(0));
            }
        } else {
            ipc::send(e, t, &ep, call, blocking);
        }
        return Outcome::Done;
    }
    if cap.cap_type() == crate::cap::CapType::Reply {
        ipc::reply(e, t, slot);
        if call {
            ipc::reply_success(e, t, 0);
        }
        return Outcome::Done;
    }
    // A kernel invocation: the message is MR0 up to its length, at most 4
    // without a readable buffer (seL4 truncates rather than fails).
    let mut mrs = [0; MSG_MAX_LENGTH];
    let n = ipc::read_message(e, t, &regs, &mut mrs[..info.sent_length() as usize]);
    debug_assert!(n == info.sent_length() as usize || n == MSG_REG_COUNT);
    let msg = Message {
        label: info.label(),
        mrs: &mrs[..n],
        extra_caps: &extra[..extra_caps],
    };
    let result = invoke::invoke(e, slot, &msg);
    let running = e.state(t) == ThreadState::Running;
    match result {
        Ok(reply) => {
            if call && running {
                ipc::reply_success(e, t, reply.length);
            }
        }
        Err(InvokeError::Error(err)) => {
            if call && running {
                ipc::reply_error(e, t, err);
            }
        }
        Err(InvokeError::Preempted) => {
            if running {
                sched::set_thread_state(e, t, ThreadState::Restart);
            }
            return Outcome::Preempted;
        }
    }
    Outcome::Done
}

/// `Recv` (`blocking`), `NBRecv`, or the receive phase of `ReplyRecv` by
/// `t` (seL4 `handleRecv`).
fn receive<E: IpcEnv + ?Sized>(e: &mut E, t: TcbRef, blocking: bool) -> Outcome {
    let cptr = e.regs(t).rdi;
    let slot = match lookup(e, t, cptr) {
        Ok(slot) => slot,
        Err(failure) => return cap_fault(e, true, cptr, true, failure),
    };
    match EndpointCap::from_cap(&e.load(slot).cap) {
        Some(ep) if ep.can_receive() => {
            ipc::receive(e, t, &ep, blocking);
            Outcome::Done
        }
        // No Read, an empty slot, or not an endpoint: notifications until
        // M6 included.
        _ => cap_fault(
            e,
            true,
            cptr,
            true,
            LookupFailure::MissingCapability { bits_left: 0 },
        ),
    }
}

#[cfg(test)]
mod tests;
