//! Thread control blocks (`docs/design.md`, "Threads and TCBs").
//!
//! A TCB is a 2 KiB object (`TCB_BITS`). Only its size is ABI; the layout
//! below is internal, except that the capability core relies on the five
//! slots lying at offset 0. `core/` names a TCB by a [`TcbRef`], its physical
//! address, and reaches its fields by value through [`Tcbs`], which the
//! kernel implements in `arch` over the direct map and host tests over fake
//! memory ([`crate::testing`]).
//!
//! - The scalar layout ([`field`]) and the thread states with their blocking
//!   data ([`ThreadState`]).
//! - [`Threads`]: what TCB invocations need besides slots and fields, the
//!   scheduler and the hooks the kernel and IPC fill.
//! - Thread operations: [`init`], [`init_root`], [`suspend`], [`restart`],
//!   [`activate`], and message registers ([`set_mr`], [`buffer_word`]).
//! - The TCB invocations, decoded into a [`TcbInvocation`] and performed
//!   ([`invoke`], [`decode`], [`perform`]).

use core::num::NonZeroU64;

use crate::cap::{
    Cap, CapType, ENDPOINT_BITS, FRAME_4K_BITS, NOTIFICATION_BITS, Rights, SLOT_SIZE, TCB_BITS,
    TCB_SLOTS,
};
use crate::kernel::Kernel;
use crate::regs::{FAULT_WORDS, Fault, REGISTER_MRS, REGS_WORDS, RFLAGS_INITIAL, Regs};
use crate::sched::{self, Scheduling, TIME_SLICE_TICKS};
use crate::slot::{SlotAddr, SlotMemory};

mod invocation;

pub use invocation::{Install, TcbInvocation, decode, invoke, label, perform};

/// The five capability slots ([`crate::cap::TCB_SLOT_CSPACE`] and on).
pub const SLOTS_OFFSET: u64 = 0;
/// The user register frame, [`crate::regs::Regs`].
pub const REGS_OFFSET: u64 = SLOTS_OFFSET + TCB_SLOTS * SLOT_SIZE;
/// The scalars: state and blocking data, priority, MCP, time slice, queue
/// and IPC links, pending fault, fault endpoint, IPC buffer, bound
/// notification ([`field`]). At most 256 bytes.
pub const SCALARS_OFFSET: u64 = REGS_OFFSET + REGS_WORDS as u64 * 8;
/// Debug builds only: the two links of the list `DebugDumpScheduler` walks.
pub const DEBUG_OFFSET: u64 = 608;
/// The XSAVE area, standard format, 64-byte aligned, 1024 bytes reserved.
pub const XSAVE_OFFSET: u64 = 1024;
/// Bytes reserved for the XSAVE area.
pub const XSAVE_SIZE: u64 = 1024;

const _: () = assert!(REGS_OFFSET == 160);
const _: () = assert!(SCALARS_OFFSET == 352);
const _: () = assert!(SCALARS_OFFSET + 256 == DEBUG_OFFSET);
const _: () = assert!(XSAVE_OFFSET + XSAVE_SIZE == 1 << TCB_BITS);

/// Byte offsets of the scalars in a TCB, one word each, from
/// [`SCALARS_OFFSET`]. The layout is internal: only `core/` reads and writes
/// them, through [`Tcbs`].
pub mod field {
    use super::SCALARS_OFFSET;

    /// The [`super::ThreadState`] tag in bits 0 to 7; `can_grant` in bit 8,
    /// `can_grant_reply` in bit 9 and `is_call` in bit 10. 0 is `Inactive`.
    pub const STATE: u64 = SCALARS_OFFSET;
    /// The endpoint or notification a blocked thread waits on, or 0.
    pub const STATE_OBJECT: u64 = STATE + 8;
    /// The badge a `BlockedOnSend` thread sends with.
    pub const STATE_BADGE: u64 = STATE_OBJECT + 8;
    /// The priority, 0 to 255.
    pub const PRIORITY: u64 = STATE_BADGE + 8;
    /// The maximum controlled priority, 0 to 255.
    pub const MCP: u64 = PRIORITY + 8;
    /// Ticks left in the time slice.
    pub const TIME_SLICE: u64 = MCP + 8;
    /// 1 while the thread is in a ready queue.
    pub const QUEUED: u64 = TIME_SLICE + 8;
    /// Ready-queue links: physical addresses of TCBs, 0 for none.
    pub const SCHED_PREV: u64 = QUEUED + 8;
    pub const SCHED_NEXT: u64 = SCHED_PREV + 8;
    /// Endpoint or notification queue links: TCB addresses, 0 for none.
    pub const EP_PREV: u64 = SCHED_NEXT + 8;
    pub const EP_NEXT: u64 = EP_PREV + 8;
    /// The pending fault: [`crate::regs::FAULT_WORDS`] words, the first 0
    /// for none ([`crate::regs::Fault::to_words`]).
    pub const FAULT: u64 = EP_NEXT + 8;
    /// The fault endpoint, a `CPtr` in the thread's own CSpace; 0 for none.
    pub const FAULT_EP: u64 = FAULT + crate::regs::FAULT_WORDS as u64 * 8;
    /// The IPC buffer's user address; 0 for none.
    pub const IPC_BUFFER: u64 = FAULT_EP + 8;
    /// The bound notification's physical address; 0 for none (M6).
    pub const BOUND_NOTIFICATION: u64 = IPC_BUFFER + 8;
    /// The first byte past the scalars.
    pub const END: u64 = BOUND_NOTIFICATION + 8;
}

const _: () = assert!(field::END <= DEBUG_OFFSET);
const _: () = assert!(field::END - SCALARS_OFFSET == 21 * 8);
const _: () = assert!(field::FAULT_EP == field::FAULT + 7 * 8);

/// A TCB, named by its physical address: non-zero and 2 KiB aligned. Made
/// only from a TCB capability or a link the kernel maintains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TcbRef(NonZeroU64);

impl TcbRef {
    /// The TCB at `paddr`, if it is a valid TCB address.
    pub const fn new(paddr: u64) -> Option<TcbRef> {
        if paddr & ((1 << TCB_BITS) - 1) != 0 || paddr >= 1 << 52 {
            return None;
        }
        match NonZeroU64::new(paddr) {
            Some(a) => Some(TcbRef(a)),
            None => None,
        }
    }

    /// The TCB a TCB capability names; `None` for any other capability.
    pub const fn from_cap(cap: &Cap) -> Option<TcbRef> {
        match cap.cap_type() {
            CapType::Tcb => TcbRef::new(cap.object()),
            _ => None,
        }
    }

    /// The physical address.
    pub const fn get(self) -> u64 {
        self.0.get()
    }

    /// The TCB's slot `n`: [`crate::cap::TCB_SLOT_CSPACE`] to
    /// [`crate::cap::TCB_SLOT_CALLER`].
    pub fn slot(self, n: u64) -> SlotAddr {
        assert!(n < TCB_SLOTS, "a TCB has five slots");
        SlotAddr::new(self.get() + n * SLOT_SIZE).expect("a TCB is slot-aligned")
    }

    /// A word for a link field: the address.
    const fn link(t: Option<TcbRef>) -> u64 {
        match t {
            Some(t) => t.get(),
            None => 0,
        }
    }
}

/// An endpoint, named by its physical address: non-zero, 32-byte aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct EpRef(NonZeroU64);

impl EpRef {
    /// The endpoint at `paddr`, if it is a valid endpoint address.
    pub const fn new(paddr: u64) -> Option<EpRef> {
        if paddr & ((1 << ENDPOINT_BITS) - 1) != 0 || paddr >= 1 << 52 {
            return None;
        }
        match NonZeroU64::new(paddr) {
            Some(a) => Some(EpRef(a)),
            None => None,
        }
    }

    /// The physical address.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A notification, named by its physical address: non-zero, 64-byte
/// aligned.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NtfnRef(NonZeroU64);

impl NtfnRef {
    /// The notification at `paddr`, if it is a valid notification address.
    pub const fn new(paddr: u64) -> Option<NtfnRef> {
        if paddr & ((1 << NOTIFICATION_BITS) - 1) != 0 || paddr >= 1 << 52 {
            return None;
        }
        match NonZeroU64::new(paddr) {
            Some(a) => Some(NtfnRef(a)),
            None => None,
        }
    }

    /// The physical address.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}

/// A thread's state (`docs/design.md`, "Thread states" and "Thread states
/// used by IPC"), with what a blocked thread recorded from the capability
/// it blocked on. The idle thread is not a TCB, so no TCB is ever `Idle`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ThreadState {
    /// New, suspended, or stopped by a fault it could not deliver.
    Inactive,
    /// Runnable; continues at `next_ip`.
    Running,
    /// Runnable; runs the instruction at `fault_ip` again: an unfinished
    /// system call, or a faulting instruction after a fault reply.
    Restart,
    /// Sending on `ep`, or a fault message waiting for a receiver.
    BlockedOnSend {
        ep: EpRef,
        badge: u64,
        can_grant: bool,
        can_grant_reply: bool,
        is_call: bool,
    },
    /// Receiving on `ep`; `can_grant` is the Grant right of the capability
    /// received on.
    BlockedOnReceive { ep: EpRef, can_grant: bool },
    /// After a Call, or after its fault message was received.
    BlockedOnReply,
    /// Waiting on `ntfn` (M6).
    BlockedOnNotification { ntfn: NtfnRef },
}

/// [`field::STATE`] tags.
mod tag {
    pub const INACTIVE: u64 = 0;
    pub const RUNNING: u64 = 1;
    pub const RESTART: u64 = 2;
    pub const BLOCKED_ON_SEND: u64 = 3;
    pub const BLOCKED_ON_RECEIVE: u64 = 4;
    pub const BLOCKED_ON_REPLY: u64 = 5;
    pub const BLOCKED_ON_NOTIFICATION: u64 = 6;
}

const CAN_GRANT: u64 = 1 << 8;
const CAN_GRANT_REPLY: u64 = 1 << 9;
const IS_CALL: u64 = 1 << 10;

impl ThreadState {
    /// Whether the scheduler may run the thread: `Running` or `Restart`.
    pub const fn is_runnable(&self) -> bool {
        matches!(self, ThreadState::Running | ThreadState::Restart)
    }

    /// Whether the thread is blocked in IPC: any `BlockedOn` state.
    pub const fn is_blocked(&self) -> bool {
        matches!(
            self,
            ThreadState::BlockedOnSend { .. }
                | ThreadState::BlockedOnReceive { .. }
                | ThreadState::BlockedOnReply
                | ThreadState::BlockedOnNotification { .. }
        )
    }

    /// Whether `TCB_Resume` restarts the thread: `Inactive` or blocked
    /// (seL4 `isStopped`).
    pub const fn is_stopped(&self) -> bool {
        matches!(self, ThreadState::Inactive) || self.is_blocked()
    }

    /// The three state words: [`field::STATE`], [`field::STATE_OBJECT`] and
    /// [`field::STATE_BADGE`].
    pub const fn to_words(&self) -> [u64; 3] {
        match *self {
            ThreadState::Inactive => [tag::INACTIVE, 0, 0],
            ThreadState::Running => [tag::RUNNING, 0, 0],
            ThreadState::Restart => [tag::RESTART, 0, 0],
            ThreadState::BlockedOnSend {
                ep,
                badge,
                can_grant,
                can_grant_reply,
                is_call,
            } => [
                tag::BLOCKED_ON_SEND
                    | if can_grant { CAN_GRANT } else { 0 }
                    | if can_grant_reply { CAN_GRANT_REPLY } else { 0 }
                    | if is_call { IS_CALL } else { 0 },
                ep.get(),
                badge,
            ],
            ThreadState::BlockedOnReceive { ep, can_grant } => [
                tag::BLOCKED_ON_RECEIVE | if can_grant { CAN_GRANT } else { 0 },
                ep.get(),
                0,
            ],
            ThreadState::BlockedOnReply => [tag::BLOCKED_ON_REPLY, 0, 0],
            ThreadState::BlockedOnNotification { ntfn } => {
                [tag::BLOCKED_ON_NOTIFICATION, ntfn.get(), 0]
            }
        }
    }

    /// The state three words hold. Decoding is total: an unknown tag, or a
    /// blocked state without a valid object, reads as `Inactive`; no writer
    /// stores either.
    pub const fn from_words(w: [u64; 3]) -> ThreadState {
        let flags = w[0];
        match w[0] & 0xFF {
            tag::RUNNING => ThreadState::Running,
            tag::RESTART => ThreadState::Restart,
            tag::BLOCKED_ON_SEND => match EpRef::new(w[1]) {
                Some(ep) => ThreadState::BlockedOnSend {
                    ep,
                    badge: w[2],
                    can_grant: flags & CAN_GRANT != 0,
                    can_grant_reply: flags & CAN_GRANT_REPLY != 0,
                    is_call: flags & IS_CALL != 0,
                },
                None => ThreadState::Inactive,
            },
            tag::BLOCKED_ON_RECEIVE => match EpRef::new(w[1]) {
                Some(ep) => ThreadState::BlockedOnReceive {
                    ep,
                    can_grant: flags & CAN_GRANT != 0,
                },
                None => ThreadState::Inactive,
            },
            tag::BLOCKED_ON_REPLY => ThreadState::BlockedOnReply,
            tag::BLOCKED_ON_NOTIFICATION => match NtfnRef::new(w[1]) {
                Some(ntfn) => ThreadState::BlockedOnNotification { ntfn },
                None => ThreadState::Inactive,
            },
            _ => ThreadState::Inactive,
        }
    }
}

/// Reads and writes one TCB's registers and scalars by value. The kernel
/// implements the two word accessors in `arch` over the direct map; host
/// tests over fake memory. The typed accessors are built on them.
///
/// The raw setters change one field and nothing else. A change of state or
/// priority must also keep the ready queues right: use
/// [`sched::set_thread_state`] and [`sched::set_priority`], unless the
/// thread is not and will not be queued (a new TCB, or one IPC blocks or
/// unblocks while it is current).
pub trait Tcbs {
    /// The word at byte `offset` of the TCB `t`. `offset` is a multiple of 8
    /// in `[REGS_OFFSET, XSAVE_OFFSET)`: never the slots, which `core/`
    /// reaches through [`SlotMemory`], nor the XSAVE area.
    fn tcb_word(&self, t: TcbRef, offset: u64) -> u64;

    /// Overwrites the word at byte `offset` of the TCB `t`, as
    /// [`Tcbs::tcb_word`] reads it.
    fn set_tcb_word(&mut self, t: TcbRef, offset: u64, value: u64);

    /// The saved user registers.
    fn regs(&self, t: TcbRef) -> Regs {
        let w = |i: u64| self.tcb_word(t, REGS_OFFSET + 8 * i);
        Regs {
            r15: w(0),
            r14: w(1),
            r13: w(2),
            r12: w(3),
            r11: w(4),
            r10: w(5),
            r9: w(6),
            r8: w(7),
            rbp: w(8),
            rdi: w(9),
            rsi: w(10),
            rdx: w(11),
            rcx: w(12),
            rbx: w(13),
            rax: w(14),
            rsp: w(15),
            rflags: w(16),
            fault_ip: w(17),
            next_ip: w(18),
            fs_base: w(19),
            gs_base: w(20),
            error: w(21),
            exit: w(22),
            pad: w(23),
        }
    }

    /// Overwrites the saved user registers. Callers that write
    /// user-visible registers go through [`Regs::set_user`] first.
    fn set_regs(&mut self, t: TcbRef, regs: &Regs) {
        let words = [
            regs.r15,
            regs.r14,
            regs.r13,
            regs.r12,
            regs.r11,
            regs.r10,
            regs.r9,
            regs.r8,
            regs.rbp,
            regs.rdi,
            regs.rsi,
            regs.rdx,
            regs.rcx,
            regs.rbx,
            regs.rax,
            regs.rsp,
            regs.rflags,
            regs.fault_ip,
            regs.next_ip,
            regs.fs_base,
            regs.gs_base,
            regs.error,
            regs.exit,
            regs.pad,
        ];
        for (i, w) in words.into_iter().enumerate() {
            self.set_tcb_word(t, REGS_OFFSET + 8 * i as u64, w);
        }
    }

    /// The thread state.
    fn state(&self, t: TcbRef) -> ThreadState {
        ThreadState::from_words([
            self.tcb_word(t, field::STATE),
            self.tcb_word(t, field::STATE_OBJECT),
            self.tcb_word(t, field::STATE_BADGE),
        ])
    }

    /// Sets the thread state. Raw: see [`sched::set_thread_state`].
    fn set_state(&mut self, t: TcbRef, s: ThreadState) {
        let [a, b, c] = s.to_words();
        self.set_tcb_word(t, field::STATE, a);
        self.set_tcb_word(t, field::STATE_OBJECT, b);
        self.set_tcb_word(t, field::STATE_BADGE, c);
    }

    /// The priority.
    fn priority(&self, t: TcbRef) -> u8 {
        self.tcb_word(t, field::PRIORITY) as u8
    }

    /// Sets the priority. Raw: see [`sched::set_priority`].
    fn set_priority(&mut self, t: TcbRef, priority: u8) {
        self.set_tcb_word(t, field::PRIORITY, priority as u64);
    }

    /// The maximum controlled priority.
    fn mcp(&self, t: TcbRef) -> u8 {
        self.tcb_word(t, field::MCP) as u8
    }

    /// Sets the maximum controlled priority; the priority is unchanged.
    fn set_mcp(&mut self, t: TcbRef, mcp: u8) {
        self.set_tcb_word(t, field::MCP, mcp as u64);
    }

    /// Ticks left in the time slice.
    fn time_slice(&self, t: TcbRef) -> u64 {
        self.tcb_word(t, field::TIME_SLICE)
    }

    /// Sets the ticks left in the time slice.
    fn set_time_slice(&mut self, t: TcbRef, ticks: u64) {
        self.set_tcb_word(t, field::TIME_SLICE, ticks);
    }

    /// Whether the thread is in a ready queue.
    fn queued(&self, t: TcbRef) -> bool {
        self.tcb_word(t, field::QUEUED) != 0
    }

    /// Marks the thread queued or not. Only [`crate::sched`] calls it.
    fn set_queued(&mut self, t: TcbRef, queued: bool) {
        self.set_tcb_word(t, field::QUEUED, queued as u64);
    }

    /// The ready-queue links: previous and next.
    fn sched_links(&self, t: TcbRef) -> (Option<TcbRef>, Option<TcbRef>) {
        (
            TcbRef::new(self.tcb_word(t, field::SCHED_PREV)),
            TcbRef::new(self.tcb_word(t, field::SCHED_NEXT)),
        )
    }

    /// Sets the ready-queue link to the previous thread.
    fn set_sched_prev(&mut self, t: TcbRef, prev: Option<TcbRef>) {
        self.set_tcb_word(t, field::SCHED_PREV, TcbRef::link(prev));
    }

    /// Sets the ready-queue link to the next thread.
    fn set_sched_next(&mut self, t: TcbRef, next: Option<TcbRef>) {
        self.set_tcb_word(t, field::SCHED_NEXT, TcbRef::link(next));
    }

    /// The endpoint or notification queue links: previous and next.
    fn ep_links(&self, t: TcbRef) -> (Option<TcbRef>, Option<TcbRef>) {
        (
            TcbRef::new(self.tcb_word(t, field::EP_PREV)),
            TcbRef::new(self.tcb_word(t, field::EP_NEXT)),
        )
    }

    /// Sets the endpoint queue link to the previous thread.
    fn set_ep_prev(&mut self, t: TcbRef, prev: Option<TcbRef>) {
        self.set_tcb_word(t, field::EP_PREV, TcbRef::link(prev));
    }

    /// Sets the endpoint queue link to the next thread.
    fn set_ep_next(&mut self, t: TcbRef, next: Option<TcbRef>) {
        self.set_tcb_word(t, field::EP_NEXT, TcbRef::link(next));
    }

    /// The pending fault: the one being delivered or awaiting its reply.
    fn fault(&self, t: TcbRef) -> Option<Fault> {
        let mut w = [0; FAULT_WORDS];
        for (i, w) in w.iter_mut().enumerate() {
            *w = self.tcb_word(t, field::FAULT + 8 * i as u64);
        }
        Fault::from_words(w)
    }

    /// Sets or clears the pending fault.
    fn set_fault(&mut self, t: TcbRef, fault: Option<Fault>) {
        let w = fault.map_or([0; FAULT_WORDS], |f| f.to_words());
        for (i, w) in w.into_iter().enumerate() {
            self.set_tcb_word(t, field::FAULT + 8 * i as u64, w);
        }
    }

    /// The fault endpoint's `CPtr`, looked up when the thread faults.
    fn fault_ep(&self, t: TcbRef) -> u64 {
        self.tcb_word(t, field::FAULT_EP)
    }

    /// Sets the fault endpoint's `CPtr`.
    fn set_fault_ep(&mut self, t: TcbRef, cptr: u64) {
        self.set_tcb_word(t, field::FAULT_EP, cptr);
    }

    /// The IPC buffer's user address; 0 for none.
    fn ipc_buffer(&self, t: TcbRef) -> u64 {
        self.tcb_word(t, field::IPC_BUFFER)
    }

    /// Sets the IPC buffer's user address.
    fn set_ipc_buffer(&mut self, t: TcbRef, addr: u64) {
        self.set_tcb_word(t, field::IPC_BUFFER, addr);
    }

    /// The bound notification (M6).
    fn bound_notification(&self, t: TcbRef) -> Option<NtfnRef> {
        NtfnRef::new(self.tcb_word(t, field::BOUND_NOTIFICATION))
    }

    /// Binds or unbinds a notification (M6).
    fn set_bound_notification(&mut self, t: TcbRef, ntfn: Option<NtfnRef>) {
        self.set_tcb_word(t, field::BOUND_NOTIFICATION, ntfn.map_or(0, NtfnRef::get));
    }
}

/// What the TCB invocations and thread operations need besides slots,
/// hooks and TCB fields: the scheduler ([`Scheduling`]) and five hooks the
/// kernel and IPC supply. The kernel implements it on `arch::Objects`.
pub trait Threads: Kernel + Scheduling {
    /// IPC's `cancel_ipc` (`docs/design.md`, "Deletion and cancellation"):
    /// if `t` is blocked in IPC, takes it off its endpoint or notification
    /// queue, or deletes the reply capability to it if it waits for a reply,
    /// and leaves it `Inactive`; in every state clears its pending fault.
    /// Leaves a thread that is not blocked in its state, and touches no
    /// ready queue.
    fn cancel_ipc(&mut self, t: TcbRef);

    /// Whether the invocation being performed came by `Call`. Only a `Call`
    /// gets the kernel's reply; `Send` and `NBSend` drop it and leave the
    /// caller's registers alone. False when no thread made the invocation.
    fn invoked_by_call(&self) -> bool;

    /// The physical addresses of the two SynIC pages the kernel recorded at
    /// boot, 0 for none (M9). No IPC buffer may lie in either.
    fn synic_pages(&self) -> [u64; 2];

    /// `TCB_SetTLSBase` changed the current thread's FS base to `value`,
    /// already sanitised: write IA32_FS_BASE now, before the switch-away
    /// path saves the MSR over the new value.
    fn set_current_fs_base(&mut self, value: u64);

    /// Writes `value` to the word at `paddr`, which [`buffer_word`] found in
    /// an IPC buffer: inside a non-device frame that a TCB's buffer slot
    /// holds with Read and Write.
    fn write_buffer_word(&mut self, paddr: u64, value: u64);
}

/// Words in an IPC buffer: `tag`, `msg[0..120]`, `user_data`,
/// `caps_or_badges[3]`, `receive_cnode`, `receive_index`, `receive_depth`.
pub const IPC_BUFFER_WORDS: usize = 128;
/// An IPC buffer's size and alignment in bytes.
pub const IPC_BUFFER_SIZE: u64 = IPC_BUFFER_WORDS as u64 * 8;

/// Writes the non-zero fields of a TCB that `Untyped_Retype` just zeroed
/// (`docs/design.md`, "Creation and configuration"): a full time slice and
/// `rflags` = `0x202`. The rest reads as zero: `Inactive`, priority and MCP
/// 0, `exit` `Iret`, no links, no fault, `fault_ep` 0, no IPC buffer, no
/// bound notification. The kernel calls it from its `init_object` hook,
/// beside copying the FP template; retype puts the reply master in slot 3.
pub fn init<T: Tcbs + ?Sized>(e: &mut T, t: TcbRef) {
    e.set_time_slice(t, TIME_SLICE_TICKS);
    e.set_tcb_word(
        t,
        REGS_OFFSET + core::mem::offset_of!(Regs, rflags) as u64,
        RFLAGS_INITIAL,
    );
}

/// The root task's thread state (`docs/abi.md`, "Root-task entry state"), on
/// a TCB [`init`] set up: `Running` at `entry` with `rdi` = `bootinfo`,
/// every other register 0 and `rflags` = `0x202`, priority and MCP 255, a
/// full slice; it leaves by `iretq`. Boot fills its slots, sets its IPC
/// buffer address, and makes it runnable with [`sched::make_runnable`].
pub fn init_root<T: Tcbs + ?Sized>(e: &mut T, t: TcbRef, entry: u64, bootinfo: u64) {
    let mut regs = Regs::new_thread();
    regs.set_user(crate::regs::UserReg::Rip, entry);
    regs.rdi = bootinfo;
    e.set_regs(t, &regs);
    e.set_priority(t, u8::MAX);
    e.set_mcp(t, u8::MAX);
    e.set_time_slice(t, TIME_SLICE_TICKS);
    e.set_state(t, ThreadState::Running);
}

/// Suspends `t` (`docs/design.md`, "Suspend, Resume and deletion"): cancels
/// its IPC, which clears its pending fault; if it was `Running`, moves
/// `fault_ip` to `next_ip` so a Resume does not repeat a finished system
/// call; takes it off the ready queue and makes it `Inactive`. A
/// `SwitchTo` naming it becomes `ChooseNew`, and if it is the current
/// thread another is chosen. The kernel's TCB finalisation calls it too.
pub fn suspend<E: Threads + ?Sized>(e: &mut E, t: TcbRef) {
    e.cancel_ipc(t);
    if e.state(t) == ThreadState::Running {
        let mut regs = e.regs(t);
        regs.stop_running();
        e.set_regs(t, &regs);
    }
    sched::set_thread_state(e, t, ThreadState::Inactive);
}

/// Resumes `t` (`TCB_Resume`, seL4 `restart`): if it is `Inactive` or
/// blocked, cancels its IPC and makes it runnable in `Restart`, so it runs
/// the instruction at `fault_ip` again. A runnable thread is left alone.
pub fn restart<E: Threads + ?Sized>(e: &mut E, t: TcbRef) {
    if e.state(t).is_stopped() {
        e.cancel_ipc(t);
        sched::set_thread_state(e, t, ThreadState::Restart);
        sched::make_runnable(e, t);
    }
}

/// Prepares the thread the scheduler chose to run (seL4 `activateThread`):
/// a `Restart` thread continues at `fault_ip` and becomes `Running`. The
/// kernel calls it on the current thread before it exits to user mode.
pub fn activate<T: Tcbs + ?Sized>(e: &mut T, t: TcbRef) {
    match e.state(t) {
        ThreadState::Running => {}
        ThreadState::Restart => {
            let mut regs = e.regs(t);
            regs.restart();
            e.set_regs(t, &regs);
            e.set_state(t, ThreadState::Running);
        }
        s => panic!("activating a thread that is not runnable: {s:?}"),
    }
}

/// The physical address of word `word` of `t`'s IPC buffer, if `t` has one
/// the kernel may read (`write` false) or write (`write` true)
/// (`docs/abi.md`, "Message registers"): its buffer slot holds a non-device
/// Frame capability with Read, and Write too to write. The buffer lies at
/// the frame's physical address plus the buffer address modulo the frame
/// size; `TCB_SetIPCBuffer` made it 1024-aligned, so all 128 words lie in
/// the frame.
pub fn buffer_word<E: SlotMemory + Tcbs + ?Sized>(
    e: &E,
    t: TcbRef,
    word: usize,
    write: bool,
) -> Option<u64> {
    assert!(word < IPC_BUFFER_WORDS, "an IPC buffer has 128 words");
    let frame = e.load(t.slot(crate::cap::TCB_SLOT_IPC_BUFFER)).cap;
    let needs = if write {
        Rights(Rights::READ.0 | Rights::WRITE.0)
    } else {
        Rights::READ
    };
    if frame.cap_type() != CapType::Frame || frame.is_device() || !frame.rights().contains(needs) {
        return None;
    }
    let size = 1u64 << frame.size_bits().max(FRAME_4K_BITS);
    let offset = e.ipc_buffer(t) & (size - 1) & !(IPC_BUFFER_SIZE - 1);
    Some(frame.object() + offset + 8 * word as u64)
}

/// Sets message register `i` of `t`: MR0 to MR3 in its saved registers, MR4
/// and up in IPC buffer word `1 + i` if it has a writable buffer. Returns
/// false, writing nothing, for an MR past MR3 without one.
pub fn set_mr<E: Threads + ?Sized>(e: &mut E, t: TcbRef, i: usize, v: u64) -> bool {
    if i < REGISTER_MRS {
        let mut regs = e.regs(t);
        regs.set_message_register(i, v);
        e.set_regs(t, &regs);
        return true;
    }
    match buffer_word(e, t, 1 + i, true) {
        Some(paddr) => {
            e.write_buffer_word(paddr, v);
            true
        }
        None => false,
    }
}

#[cfg(test)]
mod tests;
