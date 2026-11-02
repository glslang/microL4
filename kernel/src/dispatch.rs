//! What the kernel does with a thread's system call or exception, until
//! IPC, fault delivery and `l4core::syscall` arrive (M5 part 3), which
//! replace this module. Small on purpose:
//!
//! - the debug system calls 16 to 18, in a `debug` kernel;
//! - `Yield`;
//! - `Call`, `Send` and `NBSend` on a kernel object, through
//!   `l4core::invoke`, with MR0 to MR3 from the registers, the rest of the
//!   message and the extra capabilities' CPtrs from the IPC buffer, and the
//!   reply (results or error) only for a `Call` whose caller still runs;
//! - anything else (an endpoint, a notification, a reply capability, a
//!   receive, an unknown number, a failed lookup) and every exception:
//!   printed, and the thread stops (`Inactive`), as a fault with no handler
//!   leaves it.
//!
//! The entry seams in `arch` have saved the thread's registers into its
//! TCB before calling here, and schedule afterwards.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

use l4core::abi::Syscall;
use l4core::cap::{Cap, CapType, TCB_SLOT_CSPACE};
use l4core::cspace;
use l4core::invoke::{self, ExtraCap, InvokeError, Message, Reply};
use l4core::ipc::{MSG_MAX_EXTRA_CAPS, MSG_MAX_LENGTH, MessageInfo, word};
use l4core::regs::{Fault, REGISTER_MRS};
use l4core::sched;
use l4core::slot::SlotMemory;
use l4core::tcb::{self, TcbRef, Tcbs, ThreadState};

use crate::arch::{self, Objects};

/// Invocations a preemption point cut short, each restarted by its thread.
static PREEMPTED: AtomicU64 = AtomicU64::new(0);

/// The system call the current thread `t` made; its registers are in its
/// TCB.
pub fn syscall(k: &mut Objects, t: TcbRef) {
    let regs = k.regs(t);
    match Syscall::from_number(regs.rdx, cfg!(feature = "debug")) {
        #[cfg(feature = "debug")]
        Some(Syscall::DebugPutChar) => arch::serial::put_byte(regs.rdi as u8),
        #[cfg(feature = "debug")]
        Some(Syscall::DebugHalt) => {
            kprintln!(
                "dispatch: invocations preempted and restarted: {}",
                PREEMPTED.load(Ordering::Relaxed)
            );
            kprintln!("DEBUG HALT {} from TCB {:#x}", regs.rdi, t.get());
            arch::exit(if regs.rdi == 0 {
                arch::ExitCode::Success
            } else {
                arch::ExitCode::Failure
            })
        }
        #[cfg(feature = "debug")]
        Some(Syscall::DebugDumpScheduler) => dump_scheduler(k, t),
        Some(Syscall::Yield) => sched::yield_now(k),
        Some(s @ (Syscall::Call | Syscall::Send | Syscall::NBSend)) => {
            invoke_object(k, t, s == Syscall::Call)
        }
        Some(s) => stop(k, t, format_args!("{s} needs IPC, which comes next")),
        None => stop(
            k,
            t,
            format_args!("UnknownSyscall: no system call {:#x}", regs.rdx),
        ),
    }
}

/// An exception the current thread `t` caused.
pub fn exception(k: &mut Objects, t: TcbRef, vector: u8, error: u64, cr2: u64) {
    match Fault::from_exception(vector, error, cr2) {
        Some(fault) => stop(k, t, format_args!("{fault:x?}, and no fault delivery yet")),
        None => panic!("vector {vector} from ring 3 is no fault"),
    }
}

/// Stops `t` (`Inactive`), saying why; the debug report of a fault with no
/// handler (`docs/design.md`, "Missing handlers and double faults").
fn stop(k: &mut Objects, t: TcbRef, why: fmt::Arguments<'_>) {
    kprintln!(
        "thread {:#x} stopped at {:#x}: {why}",
        t.get(),
        k.regs(t).fault_ip
    );
    sched::set_thread_state(k, t, ThreadState::Inactive);
}

/// `Call`, `Send` or `NBSend` by `t` on the capability its `rdi` names.
fn invoke_object(k: &mut Objects, t: TcbRef, call: bool) {
    let regs = k.regs(t);
    let info = MessageInfo::from_word(regs.rsi);
    let cspace = k.load(t.slot(TCB_SLOT_CSPACE)).cap;
    let slot = match cspace::lookup_cap(k, cspace, regs.rdi) {
        Ok(slot) => slot,
        Err(f) => {
            return stop(
                k,
                t,
                format_args!("CapFault: CPtr {:#x} does not resolve: {f:?}", regs.rdi),
            );
        }
    };
    let ty = k.load(slot).cap.cap_type();
    if matches!(
        ty,
        CapType::Endpoint | CapType::Notification | CapType::Reply
    ) {
        return stop(k, t, format_args!("{ty:?} IPC comes next"));
    }
    // The message: MR0 to MR3 in registers, the rest in the IPC buffer, if
    // the thread has one it can read; without it the message is cut there.
    let mut mrs = [0; MSG_MAX_LENGTH];
    let mut length = 0;
    for (i, mr) in mrs.iter_mut().enumerate().take(info.sent_length() as usize) {
        *mr = if i < REGISTER_MRS {
            regs.message_register(i)
        } else {
            match tcb::buffer_word(k, t, word::MSG + i, false) {
                Some(at) => k.buffer_word(at),
                None => break,
            }
        };
        length = i + 1;
    }
    // The extra capabilities, by CPtrs in the buffer; none without one.
    let mut extra = [ExtraCap {
        cap: Cap::NULL,
        slot,
    }; MSG_MAX_EXTRA_CAPS];
    let mut n_extra = 0;
    for (i, x) in extra
        .iter_mut()
        .enumerate()
        .take(info.extra_caps() as usize)
    {
        let Some(at) = tcb::buffer_word(k, t, word::CAPS_OR_BADGES + i, false) else {
            break;
        };
        let cptr = k.buffer_word(at);
        match cspace::lookup_cap(k, cspace, cptr) {
            Ok(s) => *x = ExtraCap::load(k, s),
            Err(f) => {
                return stop(
                    k,
                    t,
                    format_args!("CapFault: extra capability {i}, CPtr {cptr:#x}: {f:?}"),
                );
            }
        }
        n_extra = i + 1;
    }
    let msg = Message {
        label: info.label(),
        mrs: &mrs[..length],
        extra_caps: &extra[..n_extra],
    };
    arch::set_invoked_by_call(call);
    let result = invoke::invoke(k, slot, &msg);
    arch::set_invoked_by_call(false);
    match result {
        // The work so far is kept in the objects: the thread runs its
        // `syscall` again, after the pending interrupt.
        Err(InvokeError::Preempted) => {
            PREEMPTED.fetch_add(1, Ordering::Relaxed);
            sched::set_thread_state(k, t, ThreadState::Restart)
        }
        r if call && k.state(t) == ThreadState::Running => reply(k, t, r),
        _ => {}
    }
}

/// The kernel's reply to a `Call` (`docs/abi.md`, "Errors"): label 0 and
/// the results the invocation wrote, or the error code and its detail
/// words; `rdi`, the badge, is 0.
fn reply(k: &mut Objects, t: TcbRef, r: Result<Reply, InvokeError>) {
    let (label, length) = match r {
        Ok(reply) => (0, reply.length),
        Err(InvokeError::Error(e)) => {
            let (words, n) = e.detail();
            let sent = words[..n]
                .iter()
                .enumerate()
                .take_while(|&(i, &w)| tcb::set_mr(k, t, i, w))
                .count();
            (e.code(), sent)
        }
        Err(InvokeError::Preempted) => unreachable!("a preempted call is restarted"),
    };
    let mut regs = k.regs(t);
    regs.rsi = MessageInfo::new(label, 0, 0, length as u64).word();
    regs.rdi = 0;
    k.set_regs(t, &regs);
}

/// `DebugDumpScheduler`: one line per TCB, newest first: its address,
/// state, priority, where it resumes, and `*` for the caller.
#[cfg(feature = "debug")]
fn dump_scheduler(k: &Objects, caller: TcbRef) {
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
