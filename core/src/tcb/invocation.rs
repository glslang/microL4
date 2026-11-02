//! The TCB invocations (`docs/abi.md`, "TCB invocations"; `docs/design.md`,
//! "Invocations", "Creation and configuration" and "Suspend, Resume and
//! deletion").
//!
//! [`decode`] turns a message into a [`TcbInvocation`] or the first error
//! in `docs/abi.md`'s order, changing nothing; [`perform`] carries it out.
//! [`invoke`] does both, for [`crate::invoke::invoke`]'s TCB arm.
//!
//! # Orders and choices the ABI leaves open
//!
//! - The label is checked first: a label outside `0x20` to `0x2D`, and
//!   BindNotification and UnbindNotification until M6, are
//!   `IllegalOperation` before any length check.
//! - Every check of Configure, SetSpace and SetIPCBuffer, the depth limit
//!   included, runs in `decode`, before any slot is emptied. `perform`
//!   deletes each old capability, then installs the new one only if its
//!   source slot and the invoked TCB capability still name the same objects
//!   (seL4 `invokeTCB_ThreadControl`); a deletion's finalisation cannot
//!   change them, so this is a guard.
//! - A slot-0 deletion that would be long-running is the last capability to
//!   a CNode or TCB, or a Zombie (seL4 `slotCapLongRunningDelete`). Slot 1
//!   can only hold a PML4, whose deletion never is, so only slot 0 is
//!   checked, as `docs/abi.md` says.
//! - The IPC buffer frame is refused when either SynIC page lies anywhere
//!   in it, not only at its base.
//! - ReadRegisters writes its results only for a `Call`
//!   ([`super::Threads::invoked_by_call`]); a `Send` leaves the caller's
//!   registers alone, as for any dropped reply.
//! - SetTLSBase writes FS base without forcing `iretq`: `sysretq` does not
//!   touch it.

use crate::cap::{Cap, CapType, TCB_SLOT_CSPACE, TCB_SLOT_IPC_BUFFER, TCB_SLOT_VSPACE, cnode_data};
use crate::cdt;
use crate::cnode;
use crate::error::SyscallError;
use crate::invoke::{ExtraCap, InvokeError, Message, Reply};
use crate::kernel::Preempted;
use crate::regs::{FRAME_REGS, USER_REGS, UserReg, sanitise};
use crate::sched;
use crate::slot::{SlotAddr, SlotMemory};

use super::{IPC_BUFFER_SIZE, TcbRef, ThreadState, Threads, restart, set_mr, suspend};

/// TCB invocation labels (`docs/abi.md`, "TCB invocations"), `0x20` to
/// `0x2D`; `0x2E` to `0x3F` are reserved.
pub mod label {
    pub const READ_REGISTERS: u64 = 0x20;
    pub const WRITE_REGISTERS: u64 = 0x21;
    pub const COPY_REGISTERS: u64 = 0x22;
    pub const CONFIGURE: u64 = 0x23;
    pub const SET_PRIORITY: u64 = 0x24;
    pub const SET_MC_PRIORITY: u64 = 0x25;
    pub const SET_SCHED_PARAMS: u64 = 0x26;
    pub const SET_IPC_BUFFER: u64 = 0x27;
    pub const SET_SPACE: u64 = 0x28;
    pub const SUSPEND: u64 = 0x29;
    pub const RESUME: u64 = 0x2A;
    /// M6; `IllegalOperation` until then.
    pub const BIND_NOTIFICATION: u64 = 0x2B;
    /// M6; `IllegalOperation` until then.
    pub const UNBIND_NOTIFICATION: u64 = 0x2C;
    pub const SET_TLS_BASE: u64 = 0x2D;
}

/// ReadRegisters: suspend the target first.
const READ_SUSPEND_SOURCE: u64 = 1 << 0;
/// WriteRegisters: resume the target afterwards.
const WRITE_RESUME_TARGET: u64 = 1 << 0;
/// CopyRegisters flags.
const COPY_SUSPEND_SOURCE: u64 = 1 << 0;
const COPY_RESUME_TARGET: u64 = 1 << 1;
const COPY_TRANSFER_FRAME: u64 = 1 << 2;
const COPY_TRANSFER_INTEGER: u64 = 1 << 3;

/// A capability to install in a TCB slot: the copy `derive` made, and the
/// slot it is derived from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Install {
    pub src: SlotAddr,
    pub cap: Cap,
}

/// A decoded TCB invocation: every argument checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TcbInvocation {
    ReadRegisters {
        target: TcbRef,
        suspend_source: bool,
        count: usize,
    },
    WriteRegisters {
        target: TcbRef,
        resume_target: bool,
        count: usize,
        values: [u64; USER_REGS],
    },
    CopyRegisters {
        dest: TcbRef,
        source: TcbRef,
        suspend_source: bool,
        resume_target: bool,
        transfer_frame: bool,
        transfer_integer: bool,
    },
    Configure {
        target: TcbRef,
        fault_ep: u64,
        cspace: Install,
        vspace: Install,
        buffer: u64,
        buffer_frame: Option<Install>,
    },
    SetPriority {
        target: TcbRef,
        priority: u8,
    },
    SetMcPriority {
        target: TcbRef,
        mcp: u8,
    },
    SetSchedParams {
        target: TcbRef,
        mcp: u8,
        priority: u8,
    },
    SetIpcBuffer {
        target: TcbRef,
        buffer: u64,
        buffer_frame: Option<Install>,
    },
    SetSpace {
        target: TcbRef,
        fault_ep: u64,
        cspace: Install,
        vspace: Install,
    },
    Suspend {
        target: TcbRef,
    },
    Resume {
        target: TcbRef,
    },
    SetTlsBase {
        target: TcbRef,
        base: u64,
    },
}

/// Decodes and performs the TCB invocation `msg` of the TCB capability in
/// `slot`: the TCB arm of [`crate::invoke::invoke`].
pub fn invoke<E: Threads + ?Sized>(
    e: &mut E,
    slot: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    let tcb = e.load(slot).cap;
    let inv = decode(e, tcb, msg)?;
    perform(e, slot, inv)
}

/// MR0 to MR`N - 1`, if the message has them and at least `caps` extra
/// capabilities.
fn args<const N: usize>(msg: &Message<'_>, caps: usize) -> Result<[u64; N], SyscallError> {
    match msg.mrs.first_chunk::<N>() {
        Some(words) if msg.extra_caps.len() >= caps => Ok(*words),
        _ => Err(SyscallError::TruncatedMessage),
    }
}

/// `InvalidArgument` 0 if `flags` has a bit outside `defined`.
fn check_flags(flags: u64, defined: u64) -> Result<(), SyscallError> {
    if flags & !defined != 0 {
        return Err(SyscallError::InvalidArgument(0));
    }
    Ok(())
}

/// Decodes the invocation `msg` of `tcb`, a TCB capability, checking every
/// argument in `docs/abi.md`'s order. Changes nothing.
pub fn decode<E: Threads + ?Sized>(
    e: &E,
    tcb: Cap,
    msg: &Message<'_>,
) -> Result<TcbInvocation, SyscallError> {
    let target = TcbRef::from_cap(&tcb).expect("a TCB capability names a TCB");
    let caller = e.scheduler().current();
    let not_caller = |t: TcbRef| {
        if caller == Some(t) {
            Err(SyscallError::IllegalOperation)
        } else {
            Ok(())
        }
    };
    let inv = match msg.label {
        label::READ_REGISTERS => {
            let [flags, count] = args(msg, 0)?;
            check_flags(flags, READ_SUSPEND_SOURCE)?;
            if !(1..=USER_REGS as u64).contains(&count) {
                return Err(SyscallError::RangeError {
                    min: 1,
                    max: USER_REGS as u64,
                });
            }
            not_caller(target)?;
            TcbInvocation::ReadRegisters {
                target,
                suspend_source: flags & READ_SUSPEND_SOURCE != 0,
                count: count as usize,
            }
        }
        label::WRITE_REGISTERS => {
            let [flags, count] = args(msg, 0)?;
            check_flags(flags, WRITE_RESUME_TARGET)?;
            if count > USER_REGS as u64 {
                return Err(SyscallError::RangeError {
                    min: 0,
                    max: USER_REGS as u64,
                });
            }
            let count = count as usize;
            let Some(words) = msg.mrs.get(2..2 + count) else {
                return Err(SyscallError::TruncatedMessage);
            };
            not_caller(target)?;
            let mut values = [0; USER_REGS];
            values[..count].copy_from_slice(words);
            TcbInvocation::WriteRegisters {
                target,
                resume_target: flags & WRITE_RESUME_TARGET != 0,
                count,
                values,
            }
        }
        label::COPY_REGISTERS => {
            let [flags] = args(msg, 1)?;
            check_flags(
                flags,
                COPY_SUSPEND_SOURCE
                    | COPY_RESUME_TARGET
                    | COPY_TRANSFER_FRAME
                    | COPY_TRANSFER_INTEGER,
            )?;
            let source = TcbRef::from_cap(&msg.extra_caps[0].cap)
                .ok_or(SyscallError::InvalidCapability(1))?;
            not_caller(source)?;
            not_caller(target)?;
            TcbInvocation::CopyRegisters {
                dest: target,
                source,
                suspend_source: flags & COPY_SUSPEND_SOURCE != 0,
                resume_target: flags & COPY_RESUME_TARGET != 0,
                transfer_frame: flags & COPY_TRANSFER_FRAME != 0,
                transfer_integer: flags & COPY_TRANSFER_INTEGER != 0,
            }
        }
        label::CONFIGURE => {
            let [fault_ep, cspace_data, buffer] = args(msg, 2)?;
            if buffer != 0 && msg.extra_caps.len() < 3 {
                return Err(SyscallError::TruncatedMessage);
            }
            let buffer_frame = if buffer != 0 {
                Some(check_buffer_frame(e, &msg.extra_caps[2], buffer, 3)?)
            } else {
                None
            };
            check_cspace_deletion(e, target)?;
            let cspace = check_cspace(e, &msg.extra_caps[0], cspace_data)?;
            let vspace = check_vspace(e, &msg.extra_caps[1])?;
            TcbInvocation::Configure {
                target,
                fault_ep,
                cspace,
                vspace,
                buffer,
                buffer_frame,
            }
        }
        label::SET_PRIORITY => {
            let [priority] = args(msg, 1)?;
            let authority = authority(msg)?;
            TcbInvocation::SetPriority {
                target,
                priority: sched::check_prio(e, priority, authority)?,
            }
        }
        label::SET_MC_PRIORITY => {
            let [mcp] = args(msg, 1)?;
            let authority = authority(msg)?;
            TcbInvocation::SetMcPriority {
                target,
                mcp: sched::check_prio(e, mcp, authority)?,
            }
        }
        label::SET_SCHED_PARAMS => {
            let [mcp, priority] = args(msg, 1)?;
            let authority = authority(msg)?;
            let mcp = sched::check_prio(e, mcp, authority)?;
            let priority = sched::check_prio(e, priority, authority)?;
            TcbInvocation::SetSchedParams {
                target,
                mcp,
                priority,
            }
        }
        label::SET_IPC_BUFFER => {
            let [buffer] = args(msg, 0)?;
            let buffer_frame = if buffer != 0 {
                let frame = msg
                    .extra_caps
                    .first()
                    .ok_or(SyscallError::TruncatedMessage)?;
                Some(check_buffer_frame(e, frame, buffer, 1)?)
            } else {
                None
            };
            TcbInvocation::SetIpcBuffer {
                target,
                buffer,
                buffer_frame,
            }
        }
        label::SET_SPACE => {
            let [fault_ep, cspace_data] = args(msg, 2)?;
            check_cspace_deletion(e, target)?;
            let cspace = check_cspace(e, &msg.extra_caps[0], cspace_data)?;
            let vspace = check_vspace(e, &msg.extra_caps[1])?;
            TcbInvocation::SetSpace {
                target,
                fault_ep,
                cspace,
                vspace,
            }
        }
        label::SUSPEND => TcbInvocation::Suspend { target },
        label::RESUME => TcbInvocation::Resume { target },
        label::SET_TLS_BASE => {
            let [base] = args(msg, 0)?;
            TcbInvocation::SetTlsBase { target, base }
        }
        // Reserved labels, labels of other types, and BindNotification and
        // UnbindNotification until M6.
        _ => return Err(SyscallError::IllegalOperation),
    };
    Ok(inv)
}

/// The authority TCB of a priority setter, extra capability 0.
fn authority(msg: &Message<'_>) -> Result<TcbRef, SyscallError> {
    TcbRef::from_cap(&msg.extra_caps[0].cap).ok_or(SyscallError::InvalidCapability(1))
}

/// Step 2 of `TCB_Configure`, and `TCB_SetIPCBuffer`'s checks after its
/// length: a non-device Frame whose copy stays within the depth limit
/// (`IllegalOperation`), no SynIC page in it (`InvalidCapability` `index`),
/// and a 1024-aligned `buffer` (`AlignmentError`).
fn check_buffer_frame<E: Threads + ?Sized>(
    e: &E,
    frame: &ExtraCap,
    buffer: u64,
    index: u64,
) -> Result<Install, SyscallError> {
    let cap = frame.cap;
    if cap.cap_type() != CapType::Frame || cap.is_device() || cdt::child_too_deep(e, frame.slot) {
        return Err(SyscallError::IllegalOperation);
    }
    let base = cap.object();
    let end = base + (1 << cap.size_bits());
    if e.synic_pages()
        .iter()
        .any(|&p| p != 0 && (base..end).contains(&p))
    {
        return Err(SyscallError::InvalidCapability(index));
    }
    if !buffer.is_multiple_of(IPC_BUFFER_SIZE) {
        return Err(SyscallError::AlignmentError);
    }
    install(e, frame)
}

/// Step 3 of `TCB_Configure`: `IllegalOperation` if deleting `target`'s
/// CSpace root would be long-running, because slot 0 holds the last
/// capability to a CNode or TCB, or a Zombie.
fn check_cspace_deletion<M: SlotMemory + ?Sized>(
    mem: &M,
    target: TcbRef,
) -> Result<(), SyscallError> {
    let slot = target.slot(TCB_SLOT_CSPACE);
    let long = match mem.load(slot).cap.cap_type() {
        CapType::Zombie => true,
        CapType::CNode | CapType::Tcb => cdt::is_final(mem, slot),
        _ => false,
    };
    if long {
        return Err(SyscallError::IllegalOperation);
    }
    Ok(())
}

/// Step 4 of `TCB_Configure`: a CNode, with `data` applied as its guard if
/// non-zero, whose copy stays within the depth limit. Every failure is
/// `IllegalOperation`: applying data to a non-CNode either fails so or
/// leaves a non-CNode.
fn check_cspace<M: SlotMemory + ?Sized>(
    mem: &M,
    root: &ExtraCap,
    data: u64,
) -> Result<Install, SyscallError> {
    if root.cap.cap_type() != CapType::CNode || cdt::child_too_deep(mem, root.slot) {
        return Err(SyscallError::IllegalOperation);
    }
    let mut new = install(mem, root)?;
    if data != 0 {
        let guard_size = (data & 0x3F) as u32;
        if guard_size + new.cap.radix() > 64 {
            return Err(SyscallError::IllegalOperation);
        }
        new.cap = new.cap.with_data(cnode_data(guard_size, data >> 6));
    }
    Ok(new)
}

/// Step 5 of `TCB_Configure`: a PML4 whose copy stays within the depth
/// limit.
fn check_vspace<M: SlotMemory + ?Sized>(mem: &M, root: &ExtraCap) -> Result<Install, SyscallError> {
    if root.cap.cap_type() != CapType::Pml4 || cdt::child_too_deep(mem, root.slot) {
        return Err(SyscallError::IllegalOperation);
    }
    install(mem, root)
}

/// The copy of `src` a TCB slot gets, through the capability core's
/// `derive`. The caller checked the type, so `derive` accepts it.
fn install<M: SlotMemory + ?Sized>(mem: &M, src: &ExtraCap) -> Result<Install, SyscallError> {
    let cap = cnode::derive(mem, src.slot)?;
    debug_assert!(cap.cap_type() == src.cap.cap_type());
    Ok(Install { src: src.slot, cap })
}

/// Performs a decoded invocation of the TCB capability in `tcb_slot`.
pub fn perform<E: Threads + ?Sized>(
    e: &mut E,
    tcb_slot: SlotAddr,
    inv: TcbInvocation,
) -> Result<Reply, InvokeError> {
    let tcb = e.load(tcb_slot).cap;
    match inv {
        TcbInvocation::ReadRegisters {
            target,
            suspend_source,
            count,
        } => return Ok(read_registers(e, target, suspend_source, count)),
        TcbInvocation::WriteRegisters {
            target,
            resume_target,
            count,
            values,
        } => {
            let mut regs = e.regs(target);
            for (r, v) in UserReg::ALL.into_iter().zip(&values[..count]) {
                regs.set_user(r, *v);
            }
            regs.set_exit(crate::regs::Exit::Iret);
            e.set_regs(target, &regs);
            if resume_target {
                restart(e, target);
            }
        }
        TcbInvocation::CopyRegisters {
            dest,
            source,
            suspend_source,
            resume_target,
            transfer_frame,
            transfer_integer,
        } => {
            if suspend_source {
                suspend(e, source);
            }
            let from = e.regs(source);
            let running = e.state(source) == ThreadState::Running;
            let mut to = e.regs(dest);
            let words = match (transfer_frame, transfer_integer) {
                (true, true) => 0..USER_REGS,
                (true, false) => 0..FRAME_REGS,
                (false, true) => FRAME_REGS..USER_REGS,
                (false, false) => 0..0,
            };
            for r in &UserReg::ALL[words] {
                to.set_user(*r, from.user(*r, running));
            }
            to.set_exit(crate::regs::Exit::Iret);
            e.set_regs(dest, &to);
            if resume_target {
                restart(e, dest);
            }
        }
        TcbInvocation::Configure {
            target,
            fault_ep,
            cspace,
            vspace,
            buffer,
            buffer_frame,
        } => {
            e.set_fault_ep(target, fault_ep);
            replace_slot(e, tcb, tcb_slot, target, TCB_SLOT_CSPACE, Some(cspace))?;
            replace_slot(e, tcb, tcb_slot, target, TCB_SLOT_VSPACE, Some(vspace))?;
            set_buffer(e, tcb, tcb_slot, target, buffer, buffer_frame)?;
        }
        TcbInvocation::SetPriority { target, priority } => {
            sched::set_priority(e, target, priority);
        }
        TcbInvocation::SetMcPriority { target, mcp } => e.set_mcp(target, mcp),
        TcbInvocation::SetSchedParams {
            target,
            mcp,
            priority,
        } => {
            e.set_mcp(target, mcp);
            sched::set_priority(e, target, priority);
        }
        TcbInvocation::SetIpcBuffer {
            target,
            buffer,
            buffer_frame,
        } => set_buffer(e, tcb, tcb_slot, target, buffer, buffer_frame)?,
        TcbInvocation::SetSpace {
            target,
            fault_ep,
            cspace,
            vspace,
        } => {
            e.set_fault_ep(target, fault_ep);
            replace_slot(e, tcb, tcb_slot, target, TCB_SLOT_CSPACE, Some(cspace))?;
            replace_slot(e, tcb, tcb_slot, target, TCB_SLOT_VSPACE, Some(vspace))?;
        }
        TcbInvocation::Suspend { target } => {
            if e.scheduler().current() == Some(target) && e.invoked_by_call() {
                // The empty success reply, so a Resume continues after the
                // `syscall` as if Suspend returned NoError.
                let mut regs = e.regs(target);
                regs.rsi = 0;
                regs.rdi = 0;
                e.set_regs(target, &regs);
            }
            suspend(e, target);
        }
        TcbInvocation::Resume { target } => restart(e, target),
        TcbInvocation::SetTlsBase { target, base } => {
            let base = sanitise(UserReg::FsBase, base);
            let mut regs = e.regs(target);
            regs.fs_base = base;
            e.set_regs(target, &regs);
            if e.scheduler().current() == Some(target) {
                e.set_current_fs_base(base);
            }
        }
    }
    Ok(Reply::EMPTY)
}

/// `TCB_ReadRegisters`: suspends the target if asked, then writes register
/// word `i` as the caller's MR `i` for a `Call`. Without a writable IPC
/// buffer the caller gets MR0 to MR3 and length `min(count, 4)`.
fn read_registers<E: Threads + ?Sized>(
    e: &mut E,
    target: TcbRef,
    suspend_source: bool,
    count: usize,
) -> Reply {
    if suspend_source {
        suspend(e, target);
    }
    let regs = e.regs(target);
    let running = e.state(target) == ThreadState::Running;
    let caller = e.scheduler().current().filter(|_| e.invoked_by_call());
    let mut length = count;
    if let Some(caller) = caller {
        for (i, r) in UserReg::ALL[..count].iter().enumerate() {
            if !set_mr(e, caller, i, regs.user(*r, running)) {
                length = i;
                break;
            }
        }
    }
    Reply { length }
}

/// Sets the IPC buffer: deletes slot 2's frame, records `buffer`, and
/// installs the new frame, if any.
fn set_buffer<E: Threads + ?Sized>(
    e: &mut E,
    tcb: Cap,
    tcb_slot: SlotAddr,
    target: TcbRef,
    buffer: u64,
    frame: Option<Install>,
) -> Result<(), Preempted> {
    e.set_ipc_buffer(target, buffer);
    replace_slot(e, tcb, tcb_slot, target, TCB_SLOT_IPC_BUFFER, frame)
}

/// Deletes the capability in `target`'s slot `n`, then installs `new` there,
/// derived from its source, if the source still holds a capability to the
/// same object and `tcb_slot` still holds `tcb`'s TCB (seL4
/// `invokeTCB_ThreadControl`). `decode` refused a long-running deletion and
/// checked the depth, so neither the deletion nor the insert fails.
fn replace_slot<E: Threads + ?Sized>(
    e: &mut E,
    tcb: Cap,
    tcb_slot: SlotAddr,
    target: TcbRef,
    n: u64,
    new: Option<Install>,
) -> Result<(), Preempted> {
    let slot = target.slot(n);
    cnode::delete(e, slot)?;
    let Some(new) = new else {
        return Ok(());
    };
    if e.load(new.src).cap.same_object(&new.cap) && e.load(tcb_slot).cap.same_object(&tcb) {
        let inserted = cdt::insert_derived(e, new.src, slot, new.cap, false);
        debug_assert!(inserted.is_ok(), "decode checked the depth limit");
    }
    Ok(())
}
