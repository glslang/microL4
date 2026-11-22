//! The reference model of IPC (`PLAN.md`, M6): threads and their states,
//! endpoints with ordered queues, reply capabilities, message registers
//! and badges, fault messages and replies, and the scheduler as far as IPC
//! moves it.
//!
//! Written from the specification, not from `l4core`: `docs/design.md`,
//! "IPC", "Faults", "Scheduling" and "Threads and TCBs", and `docs/abi.md`,
//! "System calls", "Messages", "IPC and notifications" and "Threads", with
//! seL4 where they leave a choice open (each such place names it). Plain
//! data and atomic operations:
//!
//! - **Threads** are a vector indexed by [`Tid`], never removed: a deleted
//!   thread is only marked dead. Each holds its full saved register set
//!   ([`Regs`], used as plain data), its 128-word IPC buffer when it has
//!   one, its state with the blocking data the design lists, its pending
//!   fault, and its TCB slots that IPC reads: the CSpace root, the IPC
//!   buffer frame and the caller slot.
//! - **Endpoints** are a direction and a `VecDeque` of threads, oldest
//!   first; **notifications** a state, a word, a binding and a queue.
//! - **CNodes** are vectors of [`MCap`]; capabilities name objects by
//!   index. A capability is final when no other slot, a TCB's included,
//!   names its object.
//! - **The scheduler** is a map from priority to a `VecDeque`, the action
//!   and the current thread, with the rules of "Scheduler action and
//!   decision" and seL4's `scheduleTCB`.
//!
//! A system call runs to completion in one step, preemption included: the
//! harness restarts the kernel's preempted calls until they finish, and
//! compares the end state with the model's.
//!
//! A capability moves by IPC as "Capability transfer" says: the copy in
//! the receive slot is the capability as it is, which is what `derive`
//! gives for every capability the world sends (the untyped, whose
//! `derive` depends on its children, is never sent). So the model keeps no
//! derivation tree: IPC reads only finality, and no derivation in the
//! world nears `MAX_DERIVATION_DEPTH`.

use std::collections::{BTreeMap, VecDeque};

use l4core::cap::Rights;
use l4core::error::{LookupFailure, SyscallError};
use l4core::regs::{Fault, Regs};

/// A thread's index.
pub type Tid = usize;
/// An endpoint's index.
pub type EpId = usize;
/// A notification's index.
pub type NtfnId = usize;
/// A CNode's index.
pub type CNodeId = usize;
/// A slot in a CNode: the CNode and the slot's index in it.
pub type CSlot = (CNodeId, usize);

/// Message registers per message (`docs/abi.md`, "Constants").
pub const MSG_MAX_LENGTH: u64 = 120;
/// Message registers held in CPU registers: `r10`, `r8`, `r9`, `r15`.
pub const REGISTER_MRS: usize = 4;
/// Words in an IPC buffer.
pub const BUFFER_WORDS: usize = 128;
/// Capability pointers a message may name.
pub const MAX_EXTRA_CAPS: usize = 3;
/// `exit` word values (`docs/design.md`, "Register frame and restart").
pub const EXIT_IRET: u64 = 0;
pub const EXIT_SYSRET: u64 = 1;

/// IPC buffer word indices (`docs/abi.md`, "IPC buffer").
pub mod word {
    /// `msg[0]`; message register `i` is word `MSG + i`.
    pub const MSG: usize = 1;
    pub const CAPS_OR_BADGES: usize = 122;
    pub const RECEIVE_CNODE: usize = 125;
    pub const RECEIVE_INDEX: usize = 126;
    pub const RECEIVE_DEPTH: usize = 127;
}

/// System-call numbers (`docs/abi.md`, "System calls").
pub mod sysno {
    pub const CALL: u64 = 1;
    pub const REPLY_RECV: u64 = 2;
    pub const SEND: u64 = 3;
    pub const NB_SEND: u64 = 4;
    pub const RECV: u64 = 5;
    pub const REPLY: u64 = 6;
    pub const YIELD: u64 = 7;
    pub const NB_RECV: u64 = 8;
}

/// The invocation labels the model performs (`docs/abi.md`, "Invocation
/// label index").
pub mod label {
    pub const CNODE_DELETE: u64 = 0x11;
    pub const CNODE_CANCEL_BADGED_SENDS: u64 = 0x12;
    pub const CNODE_SAVE_CALLER: u64 = 0x18;
    pub const TCB_SUSPEND: u64 = 0x29;
    pub const TCB_RESUME: u64 = 0x2A;
    pub const TCB_BIND_NOTIFICATION: u64 = 0x2B;
    pub const TCB_UNBIND_NOTIFICATION: u64 = 0x2C;
}

/// A `MessageInfo` word, field by field (`docs/abi.md`, "MessageInfo").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct Info {
    pub label: u64,
    pub length: u64,
    pub extra_caps: u64,
    pub caps_unwrapped: u64,
}

impl Info {
    /// Bits 0 to 6 `length`, 7 to 8 `extra_caps`, 9 to 11
    /// `caps_unwrapped`, 12 to 63 `label`.
    pub fn decode(w: u64) -> Info {
        Info {
            length: w & 0x7F,
            extra_caps: (w >> 7) & 0x3,
            caps_unwrapped: (w >> 9) & 0x7,
            label: w >> 12,
        }
    }

    pub fn word(self) -> u64 {
        debug_assert!(self.length < 0x80 && self.extra_caps < 4 && self.caps_unwrapped < 8);
        self.label << 12 | self.caps_unwrapped << 9 | self.extra_caps << 7 | self.length
    }

    /// The length a sender asks for: 121 to 127 count as 120.
    pub fn sent_length(self) -> usize {
        self.length.min(MSG_MAX_LENGTH) as usize
    }
}

/// A thread's state (`docs/design.md`, "Thread states" and "Thread states
/// used by IPC"), with what a blocked thread recorded from the capability
/// it blocked on.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum State {
    Inactive,
    Running,
    Restart,
    BlockedOnSend {
        ep: EpId,
        badge: u64,
        grant: bool,
        grant_reply: bool,
        call: bool,
    },
    BlockedOnReceive {
        ep: EpId,
        grant: bool,
    },
    BlockedOnReply,
    BlockedOnNotification {
        ntfn: NtfnId,
    },
}

impl State {
    pub fn runnable(self) -> bool {
        matches!(self, State::Running | State::Restart)
    }

    /// `Inactive` or blocked in IPC: what `TCB_Resume` restarts.
    pub fn stopped(self) -> bool {
        !self.runnable()
    }
}

/// A capability, naming its object by index.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MCap {
    Null,
    Endpoint {
        ep: EpId,
        badge: u64,
        rights: Rights,
    },
    CNode {
        cnode: CNodeId,
        guard_size: u32,
        guard: u64,
    },
    Tcb(Tid),
    /// A frame, by index into the world's frames, with its rights.
    Frame(usize, Rights),
    /// An object IPC never uses, standing for every other kernel object.
    Untyped,
    /// A one-shot reply capability to `to`, with Grant `grant`.
    Reply {
        to: Tid,
        grant: bool,
    },
    Notification {
        ntfn: NtfnId,
        badge: u64,
        rights: Rights,
    },
}

impl MCap {
    /// The object a capability names, to decide finality: a reply
    /// capability names nothing that its deletion finalises.
    fn object(&self) -> Option<Obj> {
        match *self {
            MCap::Endpoint { ep, .. } => Some(Obj::Endpoint(ep)),
            MCap::Notification { ntfn, .. } => Some(Obj::Notification(ntfn)),
            MCap::CNode { cnode, .. } => Some(Obj::CNode(cnode)),
            MCap::Tcb(t) => Some(Obj::Tcb(t)),
            MCap::Frame(f, _) => Some(Obj::Frame(f)),
            MCap::Untyped => Some(Obj::Untyped),
            MCap::Null | MCap::Reply { .. } => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Obj {
    Endpoint(EpId),
    Notification(NtfnId),
    CNode(CNodeId),
    Tcb(Tid),
    Frame(usize),
    Untyped,
}

/// What the kernel may do with a thread's IPC buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Buffer {
    None,
    Read,
    ReadWrite,
}

#[derive(Clone, Debug)]
pub struct Thread {
    /// False once its TCB is deleted; nothing may refer to it then.
    pub alive: bool,
    pub state: State,
    pub regs: Regs,
    pub prio: u8,
    pub slice: u64,
    pub fault: Option<Fault>,
    /// The fault endpoint's `CPtr`.
    pub fault_ep: u64,
    /// TCB slot 0: the CSpace root.
    pub cspace: MCap,
    /// TCB slot 2: the IPC buffer frame, and what it allows.
    pub buffer_frame: MCap,
    pub buffer: Buffer,
    /// The IPC buffer's words, if it has one.
    pub words: [u64; BUFFER_WORDS],
    /// TCB slot 4: `Null` or a reply capability.
    pub caller: MCap,
    /// The bound notification.
    pub bound: Option<NtfnId>,
}

/// What the threads queued on an endpoint wait to do.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Dir {
    Idle,
    Send,
    Recv,
}

#[derive(Clone, Debug)]
pub struct Endpoint {
    pub dir: Dir,
    pub queue: VecDeque<Tid>,
}

/// A notification's state (`docs/design.md`, "Notifications", "States").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NState {
    Idle,
    Waiting,
    Active,
}

#[derive(Clone, Debug)]
pub struct Ntfn {
    pub state: NState,
    /// The OR of the badges signalled since the last wait; 0 unless
    /// `Active`.
    pub word: u64,
    pub bound: Option<Tid>,
    /// The waiting threads, oldest first.
    pub queue: VecDeque<Tid>,
}

#[derive(Clone, Debug)]
pub struct CNode {
    pub radix: u32,
    pub slots: Vec<MCap>,
}

/// The scheduler's action (`docs/design.md`, "Scheduler action and
/// decision").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SchedAction {
    ResumeCurrent,
    ChooseNew,
    SwitchTo(Tid),
}

/// What a kernel entry returns: done, or a fault that found no handler.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Done,
    Stopped {
        thread: Tid,
        fault: Fault,
        handler: Fault,
    },
}

/// Where a reply capability lives.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    Caller(Tid),
    Slot(CSlot),
}

/// How often each rule of M6 ran, for coverage reports.
#[derive(Clone, Copy, Debug, Default)]
pub struct Stats {
    pub copied: u64,
    pub unwrapped: u64,
    /// Transfers that looked capabilities up, from a sender to a receiver
    /// with another CSpace root.
    pub between_cspaces: u64,
    /// Transfers that moved nothing because a re-lookup failed.
    pub relookup_failed: u64,
    /// Transfers that stopped at a capability they could not move.
    pub stopped_early: u64,
    pub signals_to_waiters: u64,
    pub signals_to_bound_receivers: u64,
    pub signals_ored: u64,
    pub bound_signals_taken_on_receive: u64,
    pub binds: u64,
    pub signals_delivered_at_bind: u64,
    pub unbinds: u64,
    pub saved: u64,
    pub badged_sends_cancelled: u64,
    pub signals_cancelled: u64,
}

/// The whole IPC world.
#[derive(Clone, Debug)]
pub struct Model {
    pub threads: Vec<Thread>,
    pub endpoints: Vec<Endpoint>,
    pub ntfns: Vec<Ntfn>,
    pub cnodes: Vec<CNode>,
    /// The non-empty ready queues, by priority.
    pub queues: BTreeMap<u8, VecDeque<Tid>>,
    pub action: SchedAction,
    /// `None` while the idle thread runs.
    pub current: Option<Tid>,
    pub stats: Stats,
}

/// The `width` bits of `v` just below bit `top`.
fn field(v: u64, top: u32, width: u32) -> u64 {
    debug_assert!(width <= top && top <= 64);
    let mask = (1u128 << width) - 1;
    (((v as u128) >> (top - width)) & mask) as u64
}

/// A lookup failure's description words (`docs/abi.md`, "Lookup failure
/// description").
pub fn failure_words(f: &LookupFailure) -> Vec<u64> {
    match *f {
        LookupFailure::InvalidRoot => vec![1],
        LookupFailure::MissingCapability { bits_left } => vec![2, bits_left as u64],
        LookupFailure::DepthMismatch {
            bits_left,
            bits_found,
        } => vec![3, bits_left as u64, bits_found as u64],
        LookupFailure::GuardMismatch {
            bits_left,
            guard,
            guard_size,
        } => vec![4, bits_left as u64, guard, guard_size as u64],
    }
}

/// An error's code and detail words (`docs/abi.md`, "Error detail words"),
/// for the errors the model's invocations return.
fn error_reply(e: &SyscallError) -> (u64, Vec<u64>) {
    match *e {
        SyscallError::InvalidCapability(i) => (2, vec![i]),
        SyscallError::IllegalOperation => (3, vec![]),
        SyscallError::RangeError { min, max } => (4, vec![min, max]),
        SyscallError::FailedLookup { source, failure } => {
            let mut w = vec![source as u64];
            w.extend(failure_words(&failure));
            (6, w)
        }
        SyscallError::TruncatedMessage => (7, vec![]),
        SyscallError::DeleteFirst => (8, vec![]),
        other => panic!("the model's invocations never return {other:?}"),
    }
}

/// A user register, in the order the fault messages and replies use
/// (`docs/abi.md`, "UnknownSyscall (2)", "User register set").
#[derive(Clone, Copy, Debug)]
enum UReg {
    Rax,
    Rbx,
    Rcx,
    Rdx,
    Rsi,
    Rdi,
    Rbp,
    R8,
    R9,
    R10,
    R11,
    R12,
    R13,
    R14,
    R15,
    Rip,
    Rsp,
    Rflags,
}

/// MR0 to MR17 of an `UnknownSyscall` message, which its reply may set.
const UNKNOWN_SYSCALL_REGS: [UReg; 18] = [
    UReg::Rax,
    UReg::Rbx,
    UReg::Rcx,
    UReg::Rdx,
    UReg::Rsi,
    UReg::Rdi,
    UReg::Rbp,
    UReg::R8,
    UReg::R9,
    UReg::R10,
    UReg::R11,
    UReg::R12,
    UReg::R13,
    UReg::R14,
    UReg::R15,
    UReg::Rip,
    UReg::Rsp,
    UReg::Rflags,
];

/// MR0 to MR2 of a `UserException` message, which its reply may set.
const USER_EXCEPTION_REGS: [UReg; 3] = [UReg::Rip, UReg::Rsp, UReg::Rflags];

/// The user-visible value of `r` for a thread that is not `Running`:
/// `rip` is `fault_ip`.
fn read_reg(regs: &Regs, r: UReg) -> u64 {
    match r {
        UReg::Rax => regs.rax,
        UReg::Rbx => regs.rbx,
        UReg::Rcx => regs.rcx,
        UReg::Rdx => regs.rdx,
        UReg::Rsi => regs.rsi,
        UReg::Rdi => regs.rdi,
        UReg::Rbp => regs.rbp,
        UReg::R8 => regs.r8,
        UReg::R9 => regs.r9,
        UReg::R10 => regs.r10,
        UReg::R11 => regs.r11,
        UReg::R12 => regs.r12,
        UReg::R13 => regs.r13,
        UReg::R14 => regs.r14,
        UReg::R15 => regs.r15,
        UReg::Rip => regs.fault_ip,
        UReg::Rsp => regs.rsp,
        UReg::Rflags => regs.rflags,
    }
}

/// Writes `r` with the rule of `docs/abi.md`, "User register set": `rip`
/// and `rsp` at or above 2^47 become 0, `rflags` keeps CF, PF, AF, ZF, SF,
/// DF and OF and gets bit 1 and IF. Writing `rip` sets both `fault_ip` and
/// `next_ip`.
fn write_reg(regs: &mut Regs, r: UReg, v: u64) {
    const LIMIT: u64 = 0x0000_8000_0000_0000;
    let canonical = if v >= LIMIT { 0 } else { v };
    match r {
        UReg::Rax => regs.rax = v,
        UReg::Rbx => regs.rbx = v,
        UReg::Rcx => regs.rcx = v,
        UReg::Rdx => regs.rdx = v,
        UReg::Rsi => regs.rsi = v,
        UReg::Rdi => regs.rdi = v,
        UReg::Rbp => regs.rbp = v,
        UReg::R8 => regs.r8 = v,
        UReg::R9 => regs.r9 = v,
        UReg::R10 => regs.r10 = v,
        UReg::R11 => regs.r11 = v,
        UReg::R12 => regs.r12 = v,
        UReg::R13 => regs.r13 = v,
        UReg::R14 => regs.r14 = v,
        UReg::R15 => regs.r15 = v,
        UReg::Rip => {
            regs.fault_ip = canonical;
            regs.next_ip = canonical;
        }
        UReg::Rsp => regs.rsp = canonical,
        UReg::Rflags => regs.rflags = (v & 0x0CD5) | 0x0202,
    }
}

/// A fault message (`docs/abi.md`, "Fault messages"): its label and words,
/// from the fault and the faulting thread's registers.
pub fn fault_message(f: &Fault, regs: &Regs) -> (u64, Vec<u64>) {
    let ip = regs.fault_ip;
    match *f {
        Fault::CapFault {
            addr,
            in_recv_phase,
            failure,
        } => {
            let mut w = vec![ip, addr, in_recv_phase as u64];
            w.extend(failure_words(&failure));
            (1, w)
        }
        Fault::UnknownSyscall { number } => {
            let mut w: Vec<u64> = UNKNOWN_SYSCALL_REGS
                .iter()
                .map(|&r| read_reg(regs, r))
                .collect();
            w.push(number);
            (2, w)
        }
        Fault::UserException { number, code } => (3, vec![ip, regs.rsp, regs.rflags, number, code]),
        Fault::VmFault { addr, fsr } => (5, vec![ip, addr, (fsr >> 4) & 1, fsr]),
    }
}

/// Whether `derive` gives a copy of `cap` (`docs/design.md`, "Slot
/// operations"): not of an empty slot or a reply capability. The world's
/// other capabilities all derive, and the copy is the capability itself:
/// rights and badge kept, frames unmapped. The untyped, which derives only
/// without children, is never sent.
fn derivable(cap: &MCap) -> bool {
    match cap {
        MCap::Null | MCap::Reply { .. } => false,
        MCap::Untyped => panic!("the model does not transfer the untyped"),
        _ => true,
    }
}

/// The fault a ring-3 exception raises (`docs/design.md`, "Fault types and
/// sources"): `#PF` is a VMFault; the vectors with an error code (10 to
/// 13) carry it in a UserException; the other user vectors carry 0.
/// `None` for a vector the kernel panics on.
pub fn exception_fault(vector: u8, error: u64, cr2: u64) -> Option<Fault> {
    let number = vector as u64;
    match vector {
        14 => Some(Fault::VmFault {
            addr: cr2,
            fsr: error,
        }),
        10..=13 => Some(Fault::UserException {
            number,
            code: error,
        }),
        0 | 1 | 3..=7 | 16 | 19 => Some(Fault::UserException { number, code: 0 }),
        _ => None,
    }
}

impl Model {
    // -----------------------------------------------------------------------
    // Registers and buffers
    // -----------------------------------------------------------------------

    pub fn readable(&self, t: Tid) -> bool {
        matches!(self.threads[t].buffer, Buffer::Read | Buffer::ReadWrite)
    }

    pub fn writable(&self, t: Tid) -> bool {
        self.threads[t].buffer == Buffer::ReadWrite
    }

    /// Message register `i` of `t`: MR0 to MR3 in `r10`, `r8`, `r9`, `r15`,
    /// the rest in buffer word `1 + i`.
    pub fn mr(&self, t: Tid, i: usize) -> u64 {
        let th = &self.threads[t];
        match i {
            0 => th.regs.r10,
            1 => th.regs.r8,
            2 => th.regs.r9,
            3 => th.regs.r15,
            _ => th.words[word::MSG + i],
        }
    }

    fn set_mr(&mut self, t: Tid, i: usize, v: u64) {
        let th = &mut self.threads[t];
        match i {
            0 => th.regs.r10 = v,
            1 => th.regs.r8 = v,
            2 => th.regs.r9 = v,
            3 => th.regs.r15 = v,
            _ => {
                assert_eq!(
                    th.buffer,
                    Buffer::ReadWrite,
                    "writing MR{i} without a buffer"
                );
                th.words[word::MSG + i] = v
            }
        }
    }

    /// Gives `t` a message: MR0 and up, then `badge` in `rdi` and `info` in
    /// `rsi`. The caller cut `words` to what `t` can take.
    fn deliver(&mut self, t: Tid, badge: u64, info: Info, words: &[u64]) {
        debug_assert_eq!(info.length as usize, words.len());
        for (i, &v) in words.iter().enumerate() {
            self.set_mr(t, i, v);
        }
        self.threads[t].regs.rdi = badge;
        self.threads[t].regs.rsi = info.word();
    }

    // -----------------------------------------------------------------------
    // Capability lookup (`docs/abi.md`, "Capability lookup")
    // -----------------------------------------------------------------------

    pub fn cap(&self, s: CSlot) -> MCap {
        self.cnodes[s.0].slots[s.1]
    }

    fn set_cap(&mut self, s: CSlot, cap: MCap) {
        self.cnodes[s.0].slots[s.1] = cap;
    }

    /// Resolves `bits` bits of `cptr` from `root`, from the most significant
    /// end: at each CNode the guard must match, then the radix bits index a
    /// slot; the walk goes on through CNode capabilities while bits are
    /// left. Returns the slot and the bits left. seL4's
    /// `resolveAddressBits`: the guard is checked before the depth.
    pub fn resolve(&self, root: MCap, cptr: u64, bits: u32) -> Result<(CSlot, u32), LookupFailure> {
        let MCap::CNode {
            mut cnode,
            mut guard_size,
            mut guard,
        } = root
        else {
            return Err(LookupFailure::InvalidRoot);
        };
        let mut left = bits;
        loop {
            let radix = self.cnodes[cnode].radix;
            if guard_size > left || field(cptr, left, guard_size) != guard {
                return Err(LookupFailure::GuardMismatch {
                    bits_left: left,
                    guard,
                    guard_size,
                });
            }
            if guard_size + radix > left {
                return Err(LookupFailure::DepthMismatch {
                    bits_left: left,
                    bits_found: guard_size + radix,
                });
            }
            let index = field(cptr, left - guard_size, radix) as usize;
            left -= guard_size + radix;
            let slot = (cnode, index);
            if left == 0 {
                return Ok((slot, 0));
            }
            match self.cap(slot) {
                MCap::CNode {
                    cnode: c,
                    guard_size: gs,
                    guard: g,
                } => (cnode, guard_size, guard) = (c, gs, g),
                _ => return Ok((slot, left)),
            }
        }
    }

    /// A capability lookup: 64 bits from `t`'s CSpace root, leftover bits
    /// ignored.
    pub fn lookup_cap(&self, t: Tid, cptr: u64) -> Result<CSlot, LookupFailure> {
        self.resolve(self.threads[t].cspace, cptr, 64)
            .map(|(s, _)| s)
    }

    /// A slot argument: exactly `depth` bits of `index` from `root`.
    pub fn lookup_slot(&self, root: MCap, index: u64, depth: u32) -> Result<CSlot, LookupFailure> {
        match self.resolve(root, index, depth)? {
            (s, 0) => Ok(s),
            (_, left) => Err(LookupFailure::DepthMismatch {
                bits_left: left,
                bits_found: 0,
            }),
        }
    }

    /// Every capability that exists: in CNode slots and in live TCBs'
    /// slots.
    fn all_caps(&self) -> impl Iterator<Item = MCap> + '_ {
        let in_cnodes = self.cnodes.iter().flat_map(|c| c.slots.iter().copied());
        let in_tcbs = self
            .threads
            .iter()
            .filter(|t| t.alive)
            .flat_map(|t| [t.cspace, t.buffer_frame, t.caller]);
        in_cnodes.chain(in_tcbs)
    }

    // -----------------------------------------------------------------------
    // The scheduler (`docs/design.md`, "Scheduling")
    // -----------------------------------------------------------------------

    fn queued(&self, t: Tid) -> bool {
        self.queues
            .get(&self.threads[t].prio)
            .is_some_and(|q| q.contains(&t))
    }

    fn append(&mut self, t: Tid) {
        assert!(!self.queued(t), "queueing a queued thread");
        let p = self.threads[t].prio;
        self.queues.entry(p).or_default().push_back(t);
    }

    fn push_head(&mut self, t: Tid) {
        assert!(!self.queued(t), "queueing a queued thread");
        let p = self.threads[t].prio;
        self.queues.entry(p).or_default().push_front(t);
    }

    fn dequeue(&mut self, t: Tid) {
        let p = self.threads[t].prio;
        if let Some(q) = self.queues.get_mut(&p) {
            q.retain(|&x| x != t);
            if q.is_empty() {
                self.queues.remove(&p);
            }
        }
    }

    /// The highest priority with a queued thread.
    pub fn highest(&self) -> Option<u8> {
        self.queues.keys().next_back().copied()
    }

    /// `reschedule()`: a pending `SwitchTo` target joins its queue's tail;
    /// the action becomes `ChooseNew`.
    fn reschedule(&mut self) {
        if let SchedAction::SwitchTo(t) = self.action {
            self.append(t);
        }
        self.action = SchedAction::ChooseNew;
    }

    /// `make_runnable(t)`: `ResumeCurrent` becomes `SwitchTo(t)`; otherwise
    /// `reschedule()` runs and `t` joins its queue's tail. IPC wakes only
    /// blocked threads, which are neither current, pending nor queued.
    fn make_runnable(&mut self, t: Tid) {
        assert!(self.threads[t].state.runnable());
        assert!(
            self.current != Some(t) && self.action != SchedAction::SwitchTo(t) && !self.queued(t),
            "waking thread {t}, which is current, pending or queued"
        );
        if self.action == SchedAction::ResumeCurrent {
            self.action = SchedAction::SwitchTo(t);
        } else {
            self.reschedule();
            self.append(t);
        }
    }

    /// Sets `t`'s state. A thread that stops being runnable leaves its
    /// ready queue, and a `SwitchTo` naming it becomes `ChooseNew`, as does
    /// `ResumeCurrent` when it is the current thread (seL4 `setThreadState`
    /// and `scheduleTCB`).
    fn set_state(&mut self, t: Tid, s: State) {
        self.threads[t].state = s;
        if s.runnable() {
            return;
        }
        self.dequeue(t);
        if self.action == SchedAction::SwitchTo(t)
            || (self.current == Some(t) && self.action == SchedAction::ResumeCurrent)
        {
            self.action = SchedAction::ChooseNew;
        }
    }

    /// Activating a thread: a `Restart` thread continues at `fault_ip`.
    fn activate(&mut self, t: Tid) {
        let th = &mut self.threads[t];
        match th.state {
            State::Running => {}
            State::Restart => {
                th.regs.next_ip = th.regs.fault_ip;
                th.state = State::Running;
            }
            s => panic!("activating thread {t} in {s:?}"),
        }
    }

    /// `schedule()` at the end of a kernel entry, then the chosen thread's
    /// activation. Unless `ResumeCurrent` with a runnable current thread
    /// (or idle):
    ///
    /// 1. a runnable, unqueued current thread goes to the head of its
    ///    queue;
    /// 2. a `SwitchTo(c)` runs if its priority is above the highest queued
    ///    one, or equal to it and the current thread is no longer runnable;
    ///    otherwise it joins its queue's tail;
    /// 3. failing that, the head of the highest queue runs, or idle.
    pub fn schedule(&mut self) -> Option<Tid> {
        let current_runnable = self
            .current
            .is_some_and(|c| self.threads[c].state.runnable());
        if self.action == SchedAction::ResumeCurrent && (self.current.is_none() || current_runnable)
        {
            if let Some(c) = self.current {
                self.activate(c);
            }
            return self.current;
        }
        if let Some(c) = self.current
            && current_runnable
            && !self.queued(c)
        {
            self.push_head(c);
        }
        let mut next = None;
        if let SchedAction::SwitchTo(c) = self.action {
            let p = self.threads[c].prio;
            let wins = match self.highest() {
                None => true,
                Some(h) => p > h || (p == h && !current_runnable),
            };
            if wins {
                next = Some(c);
            } else {
                self.append(c);
            }
        }
        if next.is_none() {
            next = self.highest().map(|p| self.queues[&p][0]);
        }
        if let Some(n) = next {
            self.dequeue(n);
            self.activate(n);
        }
        self.current = next;
        self.action = SchedAction::ResumeCurrent;
        next
    }

    /// A timer tick: the current thread's slice shrinks; at its end it is
    /// refilled to one tick and the thread joins its queue's tail with a
    /// `reschedule()`. Only a runnable current thread is charged.
    pub fn tick(&mut self) {
        let Some(c) = self.current else { return };
        if !self.threads[c].state.runnable() {
            return;
        }
        if self.threads[c].slice > 1 {
            self.threads[c].slice -= 1;
        } else {
            self.threads[c].slice = 1;
            self.append(c);
            self.reschedule();
        }
    }

    /// `Yield`: the current thread joins its queue's tail with the slice it
    /// has left, and `reschedule()` runs.
    fn yield_now(&mut self) {
        let Some(c) = self.current else { return };
        self.dequeue(c);
        self.append(c);
        self.reschedule();
    }

    /// The threads the scheduler may run now: the runnable ones at the
    /// highest runnable priority, the current thread included.
    pub fn eligible(&self) -> Vec<Tid> {
        let Some(c) = self.current else {
            return Vec::new();
        };
        let p = self.threads[c].prio;
        let mut v = vec![c];
        if let Some(q) = self.queues.get(&p) {
            v.extend(q.iter().copied());
        }
        v
    }

    /// Makes `t`, which [`Model::eligible`] lists, the current thread, as
    /// if the scheduler had chosen it: a runnable current thread joins its
    /// queue's tail. A harness step, not a kernel operation.
    pub fn run(&mut self, t: Tid) {
        if self.current == Some(t) {
            return;
        }
        assert!(
            self.eligible().contains(&t),
            "running thread {t}, which may not run"
        );
        if let Some(c) = self.current
            && self.threads[c].state.runnable()
        {
            self.append(c);
        }
        self.dequeue(t);
        self.current = Some(t);
        self.activate(t);
    }

    // -----------------------------------------------------------------------
    // System calls (`docs/design.md`, "System-call dispatch", "Decoding a
    // system call")
    // -----------------------------------------------------------------------

    /// The current thread's system call, from its saved registers.
    pub fn syscall(&mut self) -> Outcome {
        let t = self.current.expect("a thread makes the system call");
        assert_eq!(self.threads[t].state, State::Running);
        match self.threads[t].regs.rdx {
            sysno::CALL => self.invocation(t, true, true),
            sysno::SEND => self.invocation(t, false, true),
            sysno::NB_SEND => self.invocation(t, false, false),
            sysno::RECV => self.receive_call(t, true),
            sysno::NB_RECV => self.receive_call(t, false),
            sysno::REPLY => {
                self.reply(t, Place::Caller(t));
                Outcome::Done
            }
            sysno::REPLY_RECV => {
                self.reply(t, Place::Caller(t));
                self.receive_call(t, true)
            }
            sysno::YIELD => {
                self.yield_now();
                Outcome::Done
            }
            number => self.fault(t, Fault::UnknownSyscall { number }),
        }
    }

    /// A ring-3 exception of the current thread.
    pub fn exception(&mut self, vector: u8, error: u64, cr2: u64) -> Outcome {
        let t = self.current.expect("a thread takes the exception");
        let f = exception_fault(vector, error, cr2).expect("a user fault vector");
        self.fault(t, f)
    }

    /// A capability fault at `cptr`, or nothing when the call may not
    /// fault (`NBSend`).
    fn cap_fault(
        &mut self,
        t: Tid,
        may_fault: bool,
        cptr: u64,
        in_recv_phase: bool,
        failure: LookupFailure,
    ) -> Outcome {
        if !may_fault {
            return Outcome::Done;
        }
        self.fault(
            t,
            Fault::CapFault {
                addr: cptr,
                in_recv_phase,
                failure,
            },
        )
    }

    /// `Call`, `Send` and `NBSend`: look up `rdi`, then, with a readable
    /// buffer, the `extra_caps` pointers; a failure is a capability fault
    /// except for `NBSend`. Then the capability's type decides.
    fn invocation(&mut self, t: Tid, call: bool, blocking: bool) -> Outcome {
        let regs = self.threads[t].regs;
        let info = Info::decode(regs.rsi);
        let slot = match self.lookup_cap(t, regs.rdi) {
            Ok(s) => s,
            Err(f) => return self.cap_fault(t, blocking, regs.rdi, false, f),
        };
        let mut extra = Vec::new();
        if self.readable(t) {
            for i in 0..info.extra_caps as usize {
                let cptr = self.threads[t].words[word::CAPS_OR_BADGES + i];
                match self.lookup_cap(t, cptr) {
                    Ok(s) => extra.push(s),
                    Err(f) => return self.cap_fault(t, blocking, cptr, false, f),
                }
            }
        }
        match self.cap(slot) {
            MCap::Endpoint { ep, badge, rights } => {
                let write = rights.contains(Rights::WRITE);
                let grant = rights.contains(Rights::GRANT);
                let grant_reply = rights.contains(Rights::GRANT_REPLY);
                if !write || (call && !grant && !grant_reply) {
                    if call {
                        self.reply_error(t, &SyscallError::InvalidCapability(0));
                    }
                } else {
                    self.send(t, ep, badge, grant, grant_reply, call, blocking);
                }
                Outcome::Done
            }
            // Signal: Write; the message and the extra capabilities, looked
            // up above, go nowhere; a Call then gets an empty kernel reply.
            MCap::Notification {
                ntfn,
                badge,
                rights,
            } => {
                if !rights.contains(Rights::WRITE) {
                    if call {
                        self.reply_error(t, &SyscallError::InvalidCapability(0));
                    }
                } else {
                    self.signal(ntfn, badge);
                    if call {
                        self.reply_success(t, 0);
                    }
                }
                Outcome::Done
            }
            MCap::Reply { .. } => {
                self.reply(t, Place::Slot(slot));
                if call {
                    self.reply_success(t, 0);
                }
                Outcome::Done
            }
            cap => {
                let mut n = info.sent_length();
                if !self.readable(t) {
                    n = n.min(REGISTER_MRS);
                }
                let mrs: Vec<u64> = (0..n).map(|i| self.mr(t, i)).collect();
                let result = self.invoke(t, cap, info.label, &mrs, &extra, call);
                let running = self.threads[t].alive && self.threads[t].state == State::Running;
                if call && running {
                    match result {
                        Ok(len) => self.reply_success(t, len),
                        Err(e) => self.reply_error(t, &e),
                    }
                }
                Outcome::Done
            }
        }
    }

    /// `Recv`, `NBRecv`, or `ReplyRecv`'s receive phase: an endpoint with
    /// Read receives, a notification with Read waits unless it is bound to
    /// another thread; any other slot the lookup reaches is a capability
    /// fault with `MissingCapability` and 0 bits left (ADR 0026).
    fn receive_call(&mut self, t: Tid, blocking: bool) -> Outcome {
        let cptr = self.threads[t].regs.rdi;
        let slot = match self.lookup_cap(t, cptr) {
            Ok(s) => s,
            Err(f) => return self.cap_fault(t, true, cptr, true, f),
        };
        match self.cap(slot) {
            MCap::Endpoint { ep, rights, .. } if rights.contains(Rights::READ) => {
                self.receive(t, ep, rights.contains(Rights::GRANT), blocking);
                Outcome::Done
            }
            MCap::Notification { ntfn, rights, .. }
                if rights.contains(Rights::READ)
                    && self.ntfns[ntfn].bound.is_none_or(|b| b == t) =>
            {
                self.wait(t, ntfn, blocking);
                Outcome::Done
            }
            _ => self.cap_fault(
                t,
                true,
                cptr,
                true,
                LookupFailure::MissingCapability { bits_left: 0 },
            ),
        }
    }

    // -----------------------------------------------------------------------
    // The IPC phases (`docs/design.md`, "Send phase" to "Message transfer")
    // -----------------------------------------------------------------------

    /// `send(T, E, badge, g, gr, call, blocking)`.
    #[allow(clippy::too_many_arguments)]
    fn send(
        &mut self,
        t: Tid,
        ep: EpId,
        badge: u64,
        grant: bool,
        grant_reply: bool,
        call: bool,
        blocking: bool,
    ) {
        if self.endpoints[ep].dir == Dir::Recv {
            let r = self.take_head(ep);
            let State::BlockedOnReceive { grant: r_grant, .. } = self.threads[r].state else {
                panic!(
                    "thread {r} queued to receive is {:?}",
                    self.threads[r].state
                )
            };
            self.transfer(t, r, badge, grant, Some(ep));
            self.set_state(r, State::Running);
            self.make_runnable(r);
            if call {
                self.set_state(t, State::BlockedOnReply);
                self.give_reply_cap(r, t, r_grant);
            }
        } else if blocking {
            self.set_state(
                t,
                State::BlockedOnSend {
                    ep,
                    badge,
                    grant,
                    grant_reply,
                    call,
                },
            );
            self.enqueue_ipc(ep, t, Dir::Send);
        }
    }

    /// `receive(R, E, g, blocking)`.
    pub fn receive(&mut self, r: Tid, ep: EpId, grant: bool, blocking: bool) {
        // 1. A server that receives again before replying gives up the
        // reply.
        self.threads[r].caller = MCap::Null;
        // 2. A bound notification's pending signal comes instead.
        if let Some(n) = self.threads[r].bound
            && self.ntfns[n].state == NState::Active
        {
            self.take_signal(r, n);
            self.stats.bound_signals_taken_on_receive += 1;
            return;
        }
        // 3.
        if self.endpoints[ep].dir == Dir::Send {
            let s = self.take_head(ep);
            let State::BlockedOnSend {
                badge,
                grant: s_grant,
                call,
                ..
            } = self.threads[s].state
            else {
                panic!("thread {s} queued to send is {:?}", self.threads[s].state)
            };
            self.transfer(s, r, badge, s_grant, Some(ep));
            if call {
                self.set_state(s, State::BlockedOnReply);
                self.give_reply_cap(r, s, grant);
            } else {
                self.set_state(s, State::Running);
                self.make_runnable(s);
            }
        } else if blocking {
            self.set_state(r, State::BlockedOnReceive { ep, grant });
            self.enqueue_ipc(ep, r, Dir::Recv);
        } else {
            self.threads[r].regs.rdi = 0;
            self.threads[r].regs.rsi = 0;
        }
    }

    /// `reply(R, slot)`: an empty place does nothing; a reply capability to
    /// `C` is deleted, then `C` gets the message, or, waiting on a fault,
    /// the fault-reply rule.
    fn reply(&mut self, r: Tid, place: Place) {
        let MCap::Reply { to: c, grant } = self.take_at(place) else {
            return;
        };
        assert_eq!(
            self.threads[c].state,
            State::BlockedOnReply,
            "a reply capability to thread {c}"
        );
        match self.threads[c].fault.take() {
            None => {
                self.transfer(r, c, 0, grant, None);
                self.set_state(c, State::Running);
                self.make_runnable(c);
            }
            Some(f) => {
                let info = Info::decode(self.threads[r].regs.rsi);
                let mut n = info.sent_length();
                if !self.readable(r) {
                    n = n.min(REGISTER_MRS);
                }
                let mrs: Vec<u64> = (0..n).map(|i| self.mr(r, i)).collect();
                self.fault_reply(c, &f, info.label, &mrs);
            }
        }
    }

    /// `docs/abi.md`, "Fault replies": the registers the fault type names
    /// are set from the reply whatever its label, the thread leaves by
    /// `iretq`, and label 0 restarts it while any other stops it.
    fn fault_reply(&mut self, c: Tid, f: &Fault, label: u64, mrs: &[u64]) {
        let settable: &[UReg] = match f {
            Fault::UnknownSyscall { .. } => &UNKNOWN_SYSCALL_REGS,
            Fault::UserException { .. } => &USER_EXCEPTION_REGS,
            Fault::CapFault { .. } | Fault::VmFault { .. } => &[],
        };
        let regs = &mut self.threads[c].regs;
        for (&r, &v) in settable.iter().zip(mrs) {
            write_reg(regs, r, v);
        }
        regs.exit = EXIT_IRET;
        if label == 0 {
            self.set_state(c, State::Restart);
            self.make_runnable(c);
        } else {
            self.set_state(c, State::Inactive);
        }
    }

    /// `transfer(S, R, badge, g, E)`: a fault message if `s` has a fault,
    /// else `s`'s message; MR4 and up move only with a readable sender
    /// buffer (the kernel's, for a fault, always is) and a writable
    /// receiver buffer.
    fn transfer(&mut self, s: Tid, r: Tid, badge: u64, grant: bool, ep: Option<EpId>) {
        if let Some(f) = self.threads[s].fault {
            let (label, mut words) = fault_message(&f, &self.threads[s].regs);
            if !self.writable(r) {
                words.truncate(REGISTER_MRS);
            }
            let info = Info {
                label,
                length: words.len() as u64,
                ..Info::default()
            };
            self.deliver(r, badge, info, &words);
            return;
        }
        let sent = Info::decode(self.threads[s].regs.rsi);
        let mut n = sent.sent_length();
        if !(self.readable(s) && self.writable(r)) {
            n = n.min(REGISTER_MRS);
        }
        let words: Vec<u64> = (0..n).map(|i| self.mr(s, i)).collect();
        let (extra_caps, caps_unwrapped) = self.transfer_caps(s, r, grant, ep, sent);
        let info = Info {
            label: sent.label,
            length: n as u64,
            extra_caps,
            caps_unwrapped,
        };
        self.deliver(r, badge, info, &words);
    }

    /// Capability transfer (`docs/design.md`, "Capability transfer";
    /// `docs/abi.md`, "Capability transfer"), for a message from `s` to `r`
    /// through endpoint `ep` (`None` for a reply) with Grant `grant`.
    /// Returns the delivered `extra_caps` and `caps_unwrapped`.
    ///
    /// Nothing moves unless `grant`, `s` has a readable buffer and sets
    /// `extra_caps`, and `r` has a writable buffer. Then:
    ///
    /// 1. every pointer is looked up again in `s`'s CSpace; if any fails,
    ///    nothing moves, not even the capabilities named before it;
    /// 2. the receive slot is found once ([`Model::receive_slot`]);
    /// 3. in order, an endpoint capability to `ep` is unwrapped (its badge
    ///    to `r`'s `caps_or_badges[i]`, bit `i` set); any other is copied
    ///    into the receive slot if it is still free and the capability
    ///    passes `derive`; the first that is neither ends the loop;
    /// 4. `extra_caps` counts those processed.
    fn transfer_caps(
        &mut self,
        s: Tid,
        r: Tid,
        grant: bool,
        ep: Option<EpId>,
        sent: Info,
    ) -> (u64, u64) {
        if !grant || !self.readable(s) || sent.extra_caps == 0 || !self.writable(r) {
            return (0, 0);
        }
        if self.threads[s].cspace != self.threads[r].cspace {
            self.stats.between_cspaces += 1;
        }
        let mut caps = Vec::new();
        for i in 0..sent.extra_caps as usize {
            let cptr = self.threads[s].words[word::CAPS_OR_BADGES + i];
            match self.lookup_cap(s, cptr) {
                Ok(slot) => caps.push(self.cap(slot)),
                Err(_) => {
                    self.stats.relookup_failed += 1;
                    return (0, 0);
                }
            }
        }
        let mut free = self.receive_slot(r);
        let (mut processed, mut unwrapped) = (0, 0);
        for (i, cap) in caps.into_iter().enumerate() {
            if let (Some(e), MCap::Endpoint { ep: to, badge, .. }) = (ep, cap)
                && to == e
            {
                self.threads[r].words[word::CAPS_OR_BADGES + i] = badge;
                unwrapped |= 1 << i;
                self.stats.unwrapped += 1;
            } else if let Some(dst) = free
                && derivable(&cap)
            {
                self.set_cap(dst, cap);
                free = None;
                self.stats.copied += 1;
            } else {
                self.stats.stopped_early += 1;
                break;
            }
            processed += 1;
        }
        (processed, unwrapped)
    }

    /// `r`'s receive slot, if its buffer names one: `receive_cnode`,
    /// looked up with all 64 bits in its CSpace, is a CNode capability;
    /// `receive_index` with `receive_depth` bits (1 to 64) names a slot
    /// from it; the slot is empty.
    pub fn receive_slot(&self, r: Tid) -> Option<CSlot> {
        let w = &self.threads[r].words;
        let (cnode, index, depth) = (
            w[word::RECEIVE_CNODE],
            w[word::RECEIVE_INDEX],
            w[word::RECEIVE_DEPTH],
        );
        let root = self.cap(self.lookup_cap(r, cnode).ok()?);
        if !matches!(root, MCap::CNode { .. }) || depth == 0 || depth > 64 {
            return None;
        }
        let slot = self.lookup_slot(root, index, depth as u32).ok()?;
        (self.cap(slot) == MCap::Null).then_some(slot)
    }

    // -----------------------------------------------------------------------
    // Notifications (`docs/design.md`, "Notifications")
    // -----------------------------------------------------------------------

    /// `signal(N, b)`: the first waiter gets `b`; else a bound thread in an
    /// endpoint receive is taken out of it and gets `b`; else the
    /// notification becomes `Active` with `b`, or ORs `b` in if it is.
    pub fn signal(&mut self, n: NtfnId, b: u64) {
        match self.ntfns[n].state {
            NState::Waiting => {
                let w = self.ntfns[n].queue.pop_front().expect("a waiter");
                if self.ntfns[n].queue.is_empty() {
                    self.ntfns[n].state = NState::Idle;
                }
                self.stats.signals_to_waiters += 1;
                self.wake_with_signal(w, b);
            }
            NState::Idle => match self.ntfns[n].bound {
                Some(t) if matches!(self.threads[t].state, State::BlockedOnReceive { .. }) => {
                    self.cancel_ipc(t);
                    self.stats.signals_to_bound_receivers += 1;
                    self.wake_with_signal(t, b);
                }
                _ => {
                    self.ntfns[n].state = NState::Active;
                    self.ntfns[n].word = b;
                }
            },
            NState::Active => {
                self.stats.signals_ored += 1;
                self.ntfns[n].word |= b
            }
        }
    }

    /// A blocked thread gets a signal: `rdi` = `word`, `rsi` = 0, its
    /// message registers unchanged, and runs.
    fn wake_with_signal(&mut self, t: Tid, word: u64) {
        self.threads[t].regs.rdi = word;
        self.threads[t].regs.rsi = 0;
        self.set_state(t, State::Running);
        self.make_runnable(t);
    }

    /// `t` takes `n`'s pending word: `rdi` = word, `rsi` = 0; `n` becomes
    /// `Idle` with word 0.
    fn take_signal(&mut self, t: Tid, n: NtfnId) {
        debug_assert_eq!(self.ntfns[n].state, NState::Active);
        self.threads[t].regs.rdi = std::mem::take(&mut self.ntfns[n].word);
        self.threads[t].regs.rsi = 0;
        self.ntfns[n].state = NState::Idle;
    }

    /// `wait(T, N, blocking)`: a pending word is taken; otherwise a
    /// blocking `t` queues at the tail and a non-blocking one gets 0 and 0.
    /// The caller slot is left alone.
    fn wait(&mut self, t: Tid, n: NtfnId, blocking: bool) {
        if self.ntfns[n].state == NState::Active {
            self.take_signal(t, n);
        } else if blocking {
            self.set_state(t, State::BlockedOnNotification { ntfn: n });
            self.ntfns[n].queue.push_back(t);
            self.ntfns[n].state = NState::Waiting;
        } else {
            self.threads[t].regs.rdi = 0;
            self.threads[t].regs.rsi = 0;
        }
    }

    /// `TCB_BindNotification` of `y` to the notification extra capability
    /// 0 names. Errors in order: `TruncatedMessage` without an extra
    /// capability; `IllegalOperation` if `y` is bound, if the capability is
    /// not a notification with Read, if the notification is bound or has
    /// waiters. An `Active` notification's signal reaches a `y` in an
    /// endpoint receive at once.
    fn bind(&mut self, y: Tid, extra: &[CSlot]) -> Result<u64, SyscallError> {
        let Some(&slot) = extra.first() else {
            return Err(SyscallError::TruncatedMessage);
        };
        if self.threads[y].bound.is_some() {
            return Err(SyscallError::IllegalOperation);
        }
        let n = match self.cap(slot) {
            MCap::Notification { ntfn, rights, .. } if rights.contains(Rights::READ) => ntfn,
            _ => return Err(SyscallError::IllegalOperation),
        };
        if self.ntfns[n].bound.is_some() || !self.ntfns[n].queue.is_empty() {
            return Err(SyscallError::IllegalOperation);
        }
        self.threads[y].bound = Some(n);
        self.ntfns[n].bound = Some(y);
        self.stats.binds += 1;
        if self.ntfns[n].state == NState::Active
            && matches!(self.threads[y].state, State::BlockedOnReceive { .. })
        {
            self.cancel_ipc(y);
            let word = std::mem::take(&mut self.ntfns[n].word);
            self.ntfns[n].state = NState::Idle;
            self.stats.signals_delivered_at_bind += 1;
            self.wake_with_signal(y, word);
        }
        Ok(0)
    }

    /// Clears both links of `t`'s binding, if any, and nothing else.
    fn unbind(&mut self, t: Tid) {
        if let Some(n) = self.threads[t].bound.take() {
            self.ntfns[n].bound = None;
        }
    }

    /// `cancel_all_signals(N)`: every waiter, in queue order, restarts; the
    /// word is discarded; `N` becomes `Idle`.
    fn cancel_all_signals(&mut self, n: NtfnId) {
        let q = std::mem::take(&mut self.ntfns[n].queue);
        self.ntfns[n].state = NState::Idle;
        self.ntfns[n].word = 0;
        for t in q {
            self.stats.signals_cancelled += 1;
            self.threads[t].fault = None;
            self.set_state(t, State::Restart);
            self.make_runnable(t);
        }
    }

    /// Puts a reply capability to `caller`, with Grant `grant`, into
    /// `holder`'s caller slot, which is empty.
    fn give_reply_cap(&mut self, holder: Tid, caller: Tid, grant: bool) {
        assert_eq!(
            self.threads[holder].caller,
            MCap::Null,
            "a full caller slot"
        );
        assert!(
            self.find_reply_cap(caller).is_none(),
            "a second reply capability"
        );
        self.threads[holder].caller = MCap::Reply { to: caller, grant };
    }

    /// Where the reply capability to `t` lives, if anywhere.
    pub fn find_reply_cap(&self, t: Tid) -> Option<Place> {
        let is_to_t = |c: &MCap| matches!(*c, MCap::Reply { to, .. } if to == t);
        for (i, th) in self.threads.iter().enumerate() {
            if th.alive && is_to_t(&th.caller) {
                return Some(Place::Caller(i));
            }
        }
        for (n, c) in self.cnodes.iter().enumerate() {
            if let Some(i) = c.slots.iter().position(is_to_t) {
                return Some(Place::Slot((n, i)));
            }
        }
        None
    }

    /// Empties `place` and returns what it held.
    fn take_at(&mut self, place: Place) -> MCap {
        match place {
            Place::Caller(t) => std::mem::replace(&mut self.threads[t].caller, MCap::Null),
            Place::Slot(s) => std::mem::replace(&mut self.cnodes[s.0].slots[s.1], MCap::Null),
        }
    }

    // -----------------------------------------------------------------------
    // Endpoint queues
    // -----------------------------------------------------------------------

    fn enqueue_ipc(&mut self, ep: EpId, t: Tid, dir: Dir) {
        let e = &mut self.endpoints[ep];
        assert!(e.dir == Dir::Idle || e.dir == dir);
        assert!(!e.queue.contains(&t));
        e.queue.push_back(t);
        e.dir = dir;
    }

    fn take_head(&mut self, ep: EpId) -> Tid {
        let e = &mut self.endpoints[ep];
        let t = e.queue.pop_front().expect("a queued thread");
        if e.queue.is_empty() {
            e.dir = Dir::Idle;
        }
        t
    }

    fn remove_from_queue(&mut self, ep: EpId, t: Tid) {
        let e = &mut self.endpoints[ep];
        let before = e.queue.len();
        e.queue.retain(|&x| x != t);
        assert_eq!(
            e.queue.len() + 1,
            before,
            "thread {t} is not queued on {ep}"
        );
        if e.queue.is_empty() {
            e.dir = Dir::Idle;
        }
    }

    // -----------------------------------------------------------------------
    // Kernel replies
    // -----------------------------------------------------------------------

    /// The reply to a successful invocation: `rdi` 0, label 0 and `len`
    /// result words, which the invocation wrote.
    fn reply_success(&mut self, t: Tid, len: u64) {
        self.threads[t].regs.rdi = 0;
        self.threads[t].regs.rsi = Info {
            length: len,
            ..Info::default()
        }
        .word();
    }

    /// The error reply: the code as the label and the detail words as MR0
    /// and up, cut to 4 without a writable buffer.
    fn reply_error(&mut self, t: Tid, e: &SyscallError) {
        let (code, mut words) = error_reply(e);
        if !self.writable(t) {
            words.truncate(REGISTER_MRS);
        }
        let info = Info {
            label: code,
            length: words.len() as u64,
            ..Info::default()
        };
        self.deliver(t, 0, info, &words);
    }

    // -----------------------------------------------------------------------
    // Faults (`docs/design.md`, "Faults")
    // -----------------------------------------------------------------------

    /// Delivers `f`, raised by `t`: `fault_ep` must resolve now to an
    /// endpoint capability with Write and Grant or GrantReply; then the
    /// fault is stored and sent as a `Call`. Otherwise `t` becomes
    /// `Inactive` holding no fault. The handler's fault for a capability of
    /// the wrong kind is `MissingCapability` with 0 bits left, as seL4's
    /// `sendFaultIPC`.
    fn fault(&mut self, t: Tid, f: Fault) -> Outcome {
        let cptr = self.threads[t].fault_ep;
        let handler = self.lookup_cap(t, cptr).and_then(|s| match self.cap(s) {
            MCap::Endpoint { ep, badge, rights }
                if rights.contains(Rights::WRITE)
                    && (rights.contains(Rights::GRANT) || rights.contains(Rights::GRANT_REPLY)) =>
            {
                Ok((ep, badge, rights))
            }
            _ => Err(LookupFailure::MissingCapability { bits_left: 0 }),
        });
        match handler {
            Ok((ep, badge, rights)) => {
                self.threads[t].fault = Some(f);
                self.send(
                    t,
                    ep,
                    badge,
                    rights.contains(Rights::GRANT),
                    rights.contains(Rights::GRANT_REPLY),
                    true,
                    true,
                );
                Outcome::Done
            }
            Err(failure) => {
                self.set_state(t, State::Inactive);
                Outcome::Stopped {
                    thread: t,
                    fault: f,
                    handler: Fault::CapFault {
                        addr: cptr,
                        in_recv_phase: false,
                        failure,
                    },
                }
            }
        }
    }

    // -----------------------------------------------------------------------
    // Kernel invocations the model performs
    // -----------------------------------------------------------------------

    /// A kernel object invocation by `t`, with the extra capabilities the
    /// send-time lookup found. A label outside the type's rows is
    /// `IllegalOperation`; the model performs `TCB_Suspend`, `TCB_Resume`,
    /// `TCB_BindNotification`, `TCB_UnbindNotification`, `CNode_Delete`,
    /// `CNode_CancelBadgedSends` and `CNode_SaveCaller`, and panics on any
    /// other label inside a type's rows, which the harness never sends.
    /// Returns the result length.
    fn invoke(
        &mut self,
        t: Tid,
        cap: MCap,
        label: u64,
        mrs: &[u64],
        extra: &[CSlot],
        call: bool,
    ) -> Result<u64, SyscallError> {
        let unmodeled =
            |what: &str| -> ! { panic!("the model does not perform {what} label {label:#x}") };
        match cap {
            MCap::Null => Err(SyscallError::InvalidCapability(0)),
            MCap::Tcb(y) => match label {
                label::TCB_SUSPEND => {
                    if y == t && call {
                        // A self-suspend by Call writes its empty reply
                        // first (`docs/design.md`, "Suspend, Resume and
                        // deletion").
                        self.reply_success(t, 0);
                    }
                    self.suspend(y);
                    Ok(0)
                }
                label::TCB_RESUME => {
                    self.resume(y);
                    Ok(0)
                }
                label::TCB_BIND_NOTIFICATION => self.bind(y, extra),
                label::TCB_UNBIND_NOTIFICATION => {
                    if self.threads[y].bound.is_none() {
                        return Err(SyscallError::IllegalOperation);
                    }
                    self.unbind(y);
                    self.stats.unbinds += 1;
                    Ok(0)
                }
                0x20..=0x2D => unmodeled("TCB"),
                _ => Err(SyscallError::IllegalOperation),
            },
            MCap::CNode { .. } => match label {
                label::CNODE_DELETE => {
                    let slot = self.slot_argument(cap, mrs)?;
                    self.delete_slot(slot);
                    Ok(0)
                }
                label::CNODE_CANCEL_BADGED_SENDS => {
                    let slot = self.slot_argument(cap, mrs)?;
                    self.cancel_badged_sends(slot)
                }
                label::CNODE_SAVE_CALLER => {
                    let slot = self.slot_argument(cap, mrs)?;
                    self.save_caller(t, slot)
                }
                0x10..=0x18 => unmodeled("CNode"),
                _ => Err(SyscallError::IllegalOperation),
            },
            MCap::Frame(..) => match label {
                0x50..=0x53 => unmodeled("Frame"),
                _ => Err(SyscallError::IllegalOperation),
            },
            MCap::Untyped => match label {
                0x01 => unmodeled("Untyped"),
                _ => Err(SyscallError::IllegalOperation),
            },
            MCap::Endpoint { .. } | MCap::Notification { .. } | MCap::Reply { .. } => {
                unreachable!("IPC, not an invocation")
            }
        }
    }

    /// The slot a CNode invocation names in MR0 (`index`) and MR1
    /// (`depth`) from the invoked CNode, with the errors every CNode
    /// invocation checks first (`docs/abi.md`, "CNode invocations"):
    /// `TruncatedMessage` below two words, `RangeError` for a depth of 0 or
    /// above 64, `FailedLookup` if the slot does not resolve.
    fn slot_argument(&self, root: MCap, mrs: &[u64]) -> Result<CSlot, SyscallError> {
        let [index, depth, ..] = *mrs else {
            return Err(SyscallError::TruncatedMessage);
        };
        if depth == 0 || depth > 64 {
            return Err(SyscallError::RangeError { min: 1, max: 64 });
        }
        self.lookup_slot(root, index, depth as u32)
            .map_err(|failure| SyscallError::FailedLookup {
                source: false,
                failure,
            })
    }

    /// `CNode_SaveCaller`: `DeleteFirst` if `dst` is full, then
    /// `IllegalOperation` if `t`'s caller slot is empty; otherwise its
    /// reply capability moves to `dst`.
    fn save_caller(&mut self, t: Tid, dst: CSlot) -> Result<u64, SyscallError> {
        if self.cap(dst) != MCap::Null {
            return Err(SyscallError::DeleteFirst);
        }
        if self.threads[t].caller == MCap::Null {
            return Err(SyscallError::IllegalOperation);
        }
        let reply = std::mem::replace(&mut self.threads[t].caller, MCap::Null);
        self.set_cap(dst, reply);
        self.stats.saved += 1;
        Ok(0)
    }

    /// `CNode_CancelBadgedSends` on the capability in `s`: it must be an
    /// endpoint capability with all four rights, else `IllegalOperation`.
    /// For a badge `b` other than 0, every thread queued to send with `b`
    /// leaves, in queue order, with its fault cleared, and restarts; the
    /// rest keep their order. A receive queue is left alone.
    fn cancel_badged_sends(&mut self, s: CSlot) -> Result<u64, SyscallError> {
        let MCap::Endpoint { ep, badge, rights } = self.cap(s) else {
            return Err(SyscallError::IllegalOperation);
        };
        if rights != Rights::ALL {
            return Err(SyscallError::IllegalOperation);
        }
        if badge == 0 || self.endpoints[ep].dir != Dir::Send {
            return Ok(0);
        }
        let queue = std::mem::take(&mut self.endpoints[ep].queue);
        let (gone, kept): (Vec<Tid>, Vec<Tid>) = queue.into_iter().partition(|&t| {
            matches!(self.threads[t].state, State::BlockedOnSend { badge: b, .. } if b == badge)
        });
        self.endpoints[ep].queue = kept.into();
        if self.endpoints[ep].queue.is_empty() {
            self.endpoints[ep].dir = Dir::Idle;
        }
        for t in gone {
            self.stats.badged_sends_cancelled += 1;
            self.threads[t].fault = None;
            self.set_state(t, State::Restart);
            self.make_runnable(t);
        }
        Ok(0)
    }

    /// Deletes the capability in `s`, finalising its object if no other
    /// capability names it: the last endpoint capability releases the
    /// queue; the last notification capability unbinds it, then releases
    /// its waiters; the last TCB capability destroys the thread. A reply
    /// capability deleted unused leaves its caller `BlockedOnReply`.
    pub fn delete_slot(&mut self, s: CSlot) {
        let cap = self.cap(s);
        self.set_cap(s, MCap::Null);
        let Some(obj) = cap.object() else { return };
        if self.all_caps().any(|c| c.object() == Some(obj)) {
            return;
        }
        match obj {
            Obj::Endpoint(ep) => self.cancel_all_ipc(ep),
            Obj::Notification(n) => {
                if let Some(t) = self.ntfns[n].bound {
                    self.unbind(t);
                }
                self.cancel_all_signals(n);
            }
            Obj::Tcb(t) => self.destroy(t),
            Obj::Untyped => {}
            Obj::CNode(_) | Obj::Frame(_) => {
                panic!("the model does not finalise {cap:?}")
            }
        }
    }

    /// Deleting a TCB's last capability (`docs/design.md`, "Suspend, Resume
    /// and deletion"): unbind, suspend, then delete its slots; a reply
    /// capability in its caller slot is lost, and its caller stays
    /// `BlockedOnReply`.
    fn destroy(&mut self, t: Tid) {
        self.unbind(t);
        self.suspend(t);
        let th = &mut self.threads[t];
        th.cspace = MCap::Null;
        th.buffer_frame = MCap::Null;
        th.caller = MCap::Null;
        th.alive = false;
    }

    /// `TCB_Suspend`: cancel the thread's IPC; a `Running` thread's
    /// `fault_ip` moves to `next_ip`; `Inactive`.
    pub fn suspend(&mut self, t: Tid) {
        self.cancel_ipc(t);
        if self.threads[t].state == State::Running {
            let regs = &mut self.threads[t].regs;
            regs.fault_ip = regs.next_ip;
        }
        self.set_state(t, State::Inactive);
    }

    /// `TCB_Resume`: an `Inactive` or blocked thread has its IPC cancelled
    /// and becomes runnable in `Restart`; any other is left alone.
    pub fn resume(&mut self, t: Tid) {
        if self.threads[t].state.stopped() {
            self.cancel_ipc(t);
            self.set_state(t, State::Restart);
            self.make_runnable(t);
        }
    }

    /// `cancel_ipc(T)`: `t` leaves its queue; waiting for a reply, it loses
    /// the reply capability to it, wherever that is. A blocked thread
    /// becomes `Inactive`. The fault is cleared in every state.
    fn cancel_ipc(&mut self, t: Tid) {
        match self.threads[t].state {
            State::BlockedOnSend { ep, .. } | State::BlockedOnReceive { ep, .. } => {
                self.remove_from_queue(ep, t);
                self.set_state(t, State::Inactive);
            }
            State::BlockedOnReply => {
                if let Some(place) = self.find_reply_cap(t) {
                    self.take_at(place);
                }
                self.set_state(t, State::Inactive);
            }
            State::BlockedOnNotification { ntfn } => {
                let n = &mut self.ntfns[ntfn];
                n.queue.retain(|&x| x != t);
                if n.queue.is_empty() {
                    n.state = NState::Idle;
                }
                self.set_state(t, State::Inactive);
            }
            State::Inactive | State::Running | State::Restart => {}
        }
        self.threads[t].fault = None;
    }

    /// `cancel_all_ipc(E)`: every queued thread leaves, in queue order, with
    /// its fault cleared, and is restarted; `E` becomes `Idle`.
    fn cancel_all_ipc(&mut self, ep: EpId) {
        let q = std::mem::take(&mut self.endpoints[ep].queue);
        self.endpoints[ep].dir = Dir::Idle;
        for t in q {
            self.threads[t].fault = None;
            self.set_state(t, State::Restart);
            self.make_runnable(t);
        }
    }

    // -----------------------------------------------------------------------
    // The model's own consistency
    // -----------------------------------------------------------------------

    /// The invariants of `docs/design.md`, "IPC" and "Notifications", as
    /// the model states them: queues and states agree, reply capabilities
    /// name threads waiting for a reply and are unique, receivers hold no
    /// reply capability, faults exist only during fault delivery, a
    /// notification is `Waiting` exactly when it has waiters and holds a
    /// word only when `Active`, bindings are one to one, only a bound
    /// thread waits on its notification and none receives on an endpoint
    /// while it is `Active`, the ready queues hold exactly the runnable
    /// threads but the current one, and dead threads are named by nothing.
    pub fn check(&self) -> Result<(), String> {
        for (i, n) in self.ntfns.iter().enumerate() {
            if (n.state == NState::Waiting) != !n.queue.is_empty() {
                return Err(format!(
                    "notification {i} is {:?} with {:?}",
                    n.state, n.queue
                ));
            }
            if n.state != NState::Active && n.word != 0 {
                return Err(format!(
                    "notification {i} is {:?} with word {:#x}",
                    n.state, n.word
                ));
            }
            for &t in &n.queue {
                if !self.threads[t].alive
                    || self.threads[t].state != (State::BlockedOnNotification { ntfn: i })
                    || n.bound.is_some_and(|b| b != t)
                {
                    return Err(format!("thread {t} waits on notification {i}"));
                }
            }
            if let Some(b) = n.bound {
                let th = &self.threads[b];
                if !th.alive || th.bound != Some(i) {
                    return Err(format!(
                        "notification {i} is bound to thread {b}, not to it"
                    ));
                }
                if n.state == NState::Active && matches!(th.state, State::BlockedOnReceive { .. }) {
                    return Err(format!(
                        "thread {b} receives while notification {i} is Active"
                    ));
                }
            }
        }
        for (i, e) in self.endpoints.iter().enumerate() {
            if (e.dir == Dir::Idle) != e.queue.is_empty() {
                return Err(format!(
                    "endpoint {i} is {:?} with queue {:?}",
                    e.dir, e.queue
                ));
            }
            for &t in &e.queue {
                let ok = match (e.dir, self.threads[t].state) {
                    (Dir::Send, State::BlockedOnSend { ep, .. })
                    | (Dir::Recv, State::BlockedOnReceive { ep, .. }) => ep == i,
                    _ => false,
                };
                if !ok || !self.threads[t].alive {
                    return Err(format!(
                        "thread {t} queued on endpoint {i} is {:?}",
                        self.threads[t].state
                    ));
                }
            }
        }
        let mut replies = Vec::new();
        for (i, th) in self.threads.iter().enumerate() {
            if !th.alive {
                if self.queued(i) {
                    return Err(format!("dead thread {i} is in a ready queue"));
                }
                continue;
            }
            if let State::BlockedOnSend { ep, .. } | State::BlockedOnReceive { ep, .. } = th.state
                && self.endpoints[ep].queue.iter().filter(|&&x| x == i).count() != 1
            {
                return Err(format!("thread {i} is not queued once on endpoint {ep}"));
            }
            if let State::BlockedOnNotification { ntfn } = th.state
                && self.ntfns[ntfn].queue.iter().filter(|&&x| x == i).count() != 1
            {
                return Err(format!(
                    "thread {i} is not queued once on notification {ntfn}"
                ));
            }
            if let Some(n) = th.bound
                && self.ntfns[n].bound != Some(i)
            {
                return Err(format!(
                    "thread {i} is bound to notification {n}, not it to it"
                ));
            }
            if matches!(th.state, State::BlockedOnReceive { .. }) && th.caller != MCap::Null {
                return Err(format!("receiving thread {i} holds {:?}", th.caller));
            }
            if th.fault.is_some()
                && !matches!(
                    th.state,
                    State::BlockedOnSend { call: true, .. } | State::BlockedOnReply
                )
            {
                return Err(format!("thread {i} holds a fault while {:?}", th.state));
            }
            if let MCap::Reply { to, .. } = th.caller {
                replies.push(to);
            }
            let queued = self.queued(i);
            let should = th.state.runnable() && self.current != Some(i);
            if queued != should {
                return Err(format!("thread {i} {:?} queued {queued}", th.state));
            }
        }
        for c in &self.cnodes {
            for cap in &c.slots {
                if let MCap::Reply { to, .. } = *cap {
                    replies.push(to);
                }
                if let MCap::Tcb(t) = *cap
                    && !self.threads[t].alive
                {
                    return Err(format!("a capability to dead thread {t}"));
                }
            }
        }
        for (k, &to) in replies.iter().enumerate() {
            if !self.threads[to].alive || self.threads[to].state != State::BlockedOnReply {
                return Err(format!(
                    "a reply capability to thread {to}, which is {:?}",
                    self.threads[to].state
                ));
            }
            if replies[..k].contains(&to) {
                return Err(format!("two reply capabilities to thread {to}"));
            }
        }
        if let Some(c) = self.current
            && !self.threads[c].alive
        {
            return Err(format!("dead thread {c} is current"));
        }
        if self.action != SchedAction::ResumeCurrent {
            return Err(format!(
                "the action is {:?} at the end of an entry",
                self.action
            ));
        }
        Ok(())
    }
}
