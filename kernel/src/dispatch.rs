//! What the kernel does with a thread's system call or exception
//! (`docs/design.md`, "System-call dispatch", "Faults"): `l4core::syscall`
//! decides everything, and this module does what only the kernel can with
//! its [`Outcome`]:
//!
//! - a debug system call (16 to 18, `debug` kernels only) is performed for
//!   the current thread;
//! - a fault that found no handler left its thread `Inactive`; a debug
//!   kernel prints both faults and where the thread stopped
//!   (`docs/design.md`, "Missing handlers and double faults");
//! - an invocation a preemption point cut short left its caller `Restart`
//!   (unless the call stopped the caller itself), and is counted. The
//!   interrupt that is pending is taken as soon as a thread runs with
//!   interrupts on, or the kernel idles, and the caller runs its `syscall`
//!   again.
//!
//! The entry seams in `arch` have saved the thread's registers into its
//! TCB before calling here, and schedule afterwards.

use core::sync::atomic::{AtomicU64, Ordering};

use l4core::ipc::DoubleFault;
use l4core::syscall::{self, DebugCall, Outcome};
use l4core::tcb::TcbRef;

use crate::arch::Objects;
#[cfg(feature = "debug")]
use crate::arch::{self, serial};

/// Invocations a preemption point cut short, each restarted by its thread.
static PREEMPTED: AtomicU64 = AtomicU64::new(0);

/// The system call the current thread `t` made; its registers are in its
/// TCB.
pub fn syscall(k: &mut Objects, t: TcbRef) {
    let outcome = syscall::handle_syscall(k, cfg!(feature = "debug"));
    finish(k, t, outcome);
}

/// An exception the current thread `t` caused, which becomes a fault for
/// its handler.
pub fn exception(k: &mut Objects, t: TcbRef, vector: u8, error: u64, cr2: u64) {
    let outcome = syscall::handle_exception(k, vector, error, cr2);
    finish(k, t, outcome);
}

/// Does the kernel's part of `outcome`, for the current thread `t`.
fn finish(k: &mut Objects, t: TcbRef, outcome: Outcome) {
    match outcome {
        Outcome::Done => {}
        Outcome::Preempted => {
            PREEMPTED.fetch_add(1, Ordering::Relaxed);
        }
        Outcome::Debug(call) => debug_call(k, t, call),
        Outcome::Stopped(stopped) => report_stopped(k, &stopped),
    }
}

/// A debug kernel's report of a fault that found no handler: the thread,
/// where it stopped, its fault, and the capability fault of its fault
/// endpoint.
#[cfg(feature = "debug")]
fn report_stopped(k: &Objects, stopped: &DoubleFault) {
    use l4core::tcb::Tcbs;

    kprintln!(
        "thread {:#x} stopped at {:#x}: {:x?}; its fault endpoint: {:x?}",
        stopped.thread.get(),
        k.regs(stopped.thread).fault_ip,
        stopped.fault,
        stopped.handler
    );
}

/// A kernel without `debug` stops the thread silently.
#[cfg(not(feature = "debug"))]
fn report_stopped(_: &Objects, _: &DoubleFault) {}

/// Performs a debug system call for `t`, whose registers stay as they are.
#[cfg(feature = "debug")]
fn debug_call(k: &mut Objects, t: TcbRef, call: DebugCall) {
    match call {
        DebugCall::PutChar(b) => serial::put_byte(b),
        DebugCall::Halt(status) => {
            kprintln!(
                "dispatch: invocations preempted and restarted: {}",
                PREEMPTED.load(Ordering::Relaxed)
            );
            kprintln!("DEBUG HALT {status} from TCB {:#x}", t.get());
            arch::exit(if status == 0 {
                arch::ExitCode::Success
            } else {
                arch::ExitCode::Failure
            })
        }
        DebugCall::DumpScheduler => dump_scheduler(k, t),
    }
}

/// A kernel without `debug` decodes no debug system call: the number is an
/// `UnknownSyscall` fault.
#[cfg(not(feature = "debug"))]
fn debug_call(_: &mut Objects, _: TcbRef, call: DebugCall) {
    unreachable!("{call:?} in a kernel without debug")
}

/// `DebugDumpScheduler`: one line per TCB, newest first: its address,
/// state, priority, where it resumes, and `*` for the caller.
#[cfg(feature = "debug")]
fn dump_scheduler(k: &Objects, caller: TcbRef) {
    use l4core::tcb::{Tcbs, ThreadState};

    arch::for_each_tcb(k, |t| {
        let regs = k.regs(t);
        let state = k.state(t);
        let at = if state == ThreadState::Running {
            regs.next_ip
        } else {
            regs.fault_ip
        };
        kprintln!(
            "tcb {:#x}: {state:?}, priority {}, at {at:#x}{}",
            t.get(),
            k.priority(t),
            if t == caller { " *" } else { "" }
        );
    });
}
