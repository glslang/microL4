//! The IPC world: an `l4core` kernel ([`IpcTestKernel`] over fake memory)
//! and the IPC [`Model`] of the same start state, run side by side.
//!
//! [`World::apply`] runs one [`Action`] on both: the model atomically, the
//! kernel through `l4core::syscall` as the kernel's dispatch calls it, with
//! preemption injected where the kernel has preemption points (deleting a
//! TCB) and the preempted call restarted until it completes. Both then
//! run the scheduler, and the harness compares after every step:
//!
//! - every live thread's state with its blocking data, its whole saved
//!   register set, its pending fault, its caller slot, its bound
//!   notification, its priority and time slice, and every word of every
//!   IPC buffer;
//! - every endpoint's state and queue, in order, and every notification's
//!   state, word, binding and queue;
//! - the current thread and every ready queue, in order;
//! - every slot of both CNodes;
//! - what the system call returned;
//! - `ipc::check`, `ipc::check_notifications`, `sched::check_exit` and the
//!   model's own `check`, and that the kernel wrote IPC buffers only where
//!   it may.
//!
//! A preempted call is restarted at once, before the scheduler runs, as if
//! the interrupt it stopped for woke nobody; the invariants are checked at
//! every preemption point. A thread that deleted its own TCB is not
//! restarted: the harness finishes the deletion by deleting the slot again,
//! as another thread would.
//!
//! The start state:
//!
//! | Address | What |
//! | --- | --- |
//! | `0x1000` | the root CNode, 64 slots, a 58-bit guard of 0, so `CPtr` `n` below 64 names slot `n`; the CSpace of every thread but those of the second CNode |
//! | `0x1800` | endpoints 0 to 3, 32 bytes each |
//! | `0x1900` | notifications 0 to 2, 64 bytes each |
//! | `0x2000` | threads 0 to 5, 2 KiB each |
//! | `0x5000` | a frame with Read and Write: the IPC buffers of threads 0 to 3, 1 KiB each |
//! | `0x6000` | a frame with Read only: thread 4's buffer, readable but not writable; thread 5 has none |
//! | `0x7000` | a 4 KiB untyped, an object IPC never uses |
//! | `0x8000` | the second CNode, shaped as the root, if a thread has it as its CSpace |
//!
//! [`slot`] lists the root CNode's capabilities: the four endpoints' and
//! three notifications' originals and copies of them with various rights
//! and badges, a capability to each TCB, the two frames and the untyped;
//! slots 36 to 63 are free, for received capabilities and saved reply
//! capabilities. Each thread's priority and fault endpoint come from the
//! [`Config`], and so does which threads have the second CNode as their
//! CSpace root ([`second`]): a CNode that holds copies of only some of the
//! root's capabilities, most in other slots than the root's, so that a
//! `CPtr` names another capability, or none, in each CSpace. The second
//! CNode exists only in a world where a thread uses it, so that the copies
//! it holds change no other world.

use std::collections::BTreeMap;

use l4core::cap::{
    Cap, CapType, ENDPOINT_BITS, NOTIFICATION_BITS, Rights, TCB_BITS, TCB_SLOT_CALLER,
    TCB_SLOT_CSPACE, TCB_SLOT_IPC_BUFFER, TCB_SLOT_REPLY,
};
use l4core::cdt;
use l4core::cnode;
use l4core::ipc::{self, DoubleFault, EpState, IpcEnv, NtfnState};
use l4core::kernel::Preempted;
use l4core::regs::Regs;
use l4core::sched;
use l4core::slot::{SlotAddr, SlotMemory};
use l4core::syscall::{self, Outcome};
use l4core::tcb::{self, EpRef, NtfnRef, TcbRef, Tcbs, ThreadState};
use l4core::testing::{IpcTestKernel, ThreadEvent};

use crate::ipc::{
    BUFFER_WORDS, Buffer, CNode, CNodeId, CSlot, Dir, EXIT_IRET, EXIT_SYSRET, Endpoint, Info, MCap,
    Model, NState, Ntfn, SchedAction, State, Thread, Tid, label, sysno, word,
};

pub const THREADS: usize = 6;
pub const EPS: usize = 4;
pub const NTFNS: usize = 3;
pub const MEM_END: u64 = 0x8800;
pub const ROOT: u64 = 0x1000;
pub const ROOT_RADIX: u32 = 6;
pub const ROOT_GUARD_SIZE: u32 = 58;
pub const ROOT_SLOTS: usize = 1 << ROOT_RADIX;
pub const EP_BASE: u64 = 0x1800;
pub const NTFN_BASE: u64 = 0x1900;
pub const TCB_BASE: u64 = 0x2000;
pub const FRAME_RW: u64 = 0x5000;
pub const FRAME_RO: u64 = 0x6000;
pub const UNTYPED: u64 = 0x7000;
/// The second CNode: radix and guard as the root's.
pub const SECOND: u64 = 0x8000;
/// The user address of thread `i`'s buffer is this plus its offset in the
/// frame.
pub const BUFFER_VADDR: u64 = 0x10_0000;
/// Thread `i` starts at `PC_BASE + 4 KiB i`.
pub const PC_BASE: u64 = 0x40_0000;
/// The thread whose buffer is readable but not writable.
pub const RO_THREAD: Tid = 4;
/// The thread without a buffer.
pub const NO_BUFFER_THREAD: Tid = 5;

/// A `CPtr` whose top bits break the root's guard.
pub const BAD_CPTR: u64 = 1 << 63 | 2;

pub const RW: Rights = Rights(Rights::READ.0 | Rights::WRITE.0);
const W_GR: Rights = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
const W_G: Rights = Rights(Rights::WRITE.0 | Rights::GRANT.0);
const R_G: Rights = Rights(Rights::READ.0 | Rights::GRANT.0);

/// Root CNode slots.
pub mod slot {
    /// Stays empty.
    pub const EMPTY: u64 = 0;
    /// The root CNode's own capability, a derivation root; the CSpace slot
    /// of each TCB whose CSpace is the root holds a copy.
    pub const ROOT: u64 = 1;
    /// Endpoint `i`'s original, all rights, unbadged: slots 2 to 5.
    pub const EP: u64 = 2;
    pub const EP0_BADGED: u64 = 6;
    pub const EP0_W: u64 = 7;
    pub const EP0_WGR_BADGED: u64 = 8;
    pub const EP0_R: u64 = 9;
    pub const EP0_RG: u64 = 10;
    pub const EP1_BADGED: u64 = 11;
    pub const EP1_WG_BADGED: u64 = 12;
    pub const EP3_F0: u64 = 13;
    pub const EP3_F1: u64 = 14;
    pub const EP1_RW: u64 = 15;
    /// Thread `i`'s TCB capability, its only one: slots 16 to 21.
    pub const TCB: u64 = 16;
    pub const FRAME_RW: u64 = 22;
    pub const FRAME_RO: u64 = 23;
    pub const UNTYPED: u64 = 24;
    /// Notification `i`'s original, Read and Write, unbadged: slots 25 to
    /// 27. Notification 2's is its only capability.
    pub const NTFN: u64 = 25;
    pub const N0_BADGED: u64 = 28;
    pub const N0_W_BADGED: u64 = 29;
    pub const N0_R: u64 = 30;
    pub const N1_W_BADGED: u64 = 31;
    pub const N1_BADGED: u64 = 32;
    pub const N0_W: u64 = 33;
    pub const N1_NONE: u64 = 34;
    /// Endpoint 0 with Write and GrantReply and badge `0x11`: a copy of
    /// [`EP0_BADGED`], as a server hands one to a client.
    pub const EP0_WGR_11: u64 = 35;
    /// Slots 36 to 63 are free.
    pub const FREE: u64 = 36;
}

/// The second CNode's slots, for the threads [`Config::second_cspace`]
/// names. Slot 0 stays empty; slot 1 holds the second CNode's own
/// capability, its derivation root, as the root's slot 1 does, so a CNode
/// invocation through `CPtr` 1 acts on the invoker's own CSpace; [`COPIES`]
/// lists the rest. It holds no TCB, frame or untyped capability.
///
/// [`COPIES`]: second::COPIES
pub mod second {
    use super::slot as root;

    /// Its own capability, the second CNode's derivation root.
    pub const OWN: u64 = 1;
    pub const EP1: u64 = 2;
    pub const EP0: u64 = 3;
    pub const EP2: u64 = 4;
    pub const EP3: u64 = 5;
    pub const EP1_BADGED: u64 = 6;
    pub const EP0_BADGED: u64 = 7;
    pub const EP0_W: u64 = 8;
    pub const EP0_RG: u64 = 9;
    pub const EP3_F1: u64 = 10;
    pub const EP1_WG_BADGED: u64 = 11;
    pub const N1_BADGED: u64 = 12;
    pub const NTFN0: u64 = 13;
    pub const N0_W_BADGED: u64 = 14;
    /// A copy of the root CNode's capability: the way to the root's slots.
    pub const ROOT_CNODE: u64 = 15;
    /// Slots 16 to 63 are free.
    pub const FREE: u64 = 16;

    /// Each slot and the root slot whose capability it holds a copy of.
    pub const COPIES: [(u64, u64); 14] = [
        (EP1, root::EP + 1),
        (EP0, root::EP),
        (EP2, root::EP + 2),
        (EP3, root::EP + 3),
        (EP1_BADGED, root::EP1_BADGED),
        (EP0_BADGED, root::EP0_BADGED),
        (EP0_W, root::EP0_W),
        (EP0_RG, root::EP0_RG),
        (EP3_F1, root::EP3_F1),
        (EP1_WG_BADGED, root::EP1_WG_BADGED),
        (N1_BADGED, root::N1_BADGED),
        (NTFN0, root::NTFN),
        (N0_W_BADGED, root::N0_W_BADGED),
        (ROOT_CNODE, root::ROOT),
    ];
}

/// The copies of endpoint capabilities in the root CNode: slot, endpoint,
/// rights, badge. A badged copy is an original, as Mint makes it.
pub const EP_COPIES: [(u64, usize, Rights, u64); 10] = [
    (slot::EP0_BADGED, 0, Rights::ALL, 0x11),
    (slot::EP0_W, 0, Rights::WRITE, 0),
    (slot::EP0_WGR_BADGED, 0, W_GR, 0x22),
    (slot::EP0_R, 0, Rights::READ, 0),
    (slot::EP0_RG, 0, R_G, 0),
    (slot::EP1_BADGED, 1, Rights::ALL, 0x33),
    (slot::EP1_WG_BADGED, 1, W_G, 0x55),
    (slot::EP3_F0, 3, W_GR, 0xF0),
    (slot::EP3_F1, 3, W_GR, 0xF1),
    (slot::EP1_RW, 1, RW, 0),
];

/// The copies of notification capabilities: slot, notification, rights,
/// badge. A badged copy is an original, as Mint makes it.
pub const NTFN_COPIES: [(u64, usize, Rights, u64); 7] = [
    (slot::N0_BADGED, 0, RW, 0x100),
    (slot::N0_W_BADGED, 0, Rights::WRITE, 0x200),
    (slot::N0_R, 0, Rights::READ, 0),
    (slot::N1_W_BADGED, 1, Rights::WRITE, 0x400),
    (slot::N1_BADGED, 1, RW, 0x800),
    (slot::N0_W, 0, Rights::WRITE, 0),
    (slot::N1_NONE, 1, Rights::NONE, 0),
];

/// What a world can vary.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    pub prios: [u8; THREADS],
    /// Each thread's fault endpoint `CPtr`.
    pub fault_eps: [u64; THREADS],
    /// The threads whose CSpace root is the second CNode, not the root.
    pub second_cspace: [bool; THREADS],
}

impl Config {
    /// Whether the world has the second CNode.
    pub fn has_second(&self) -> bool {
        self.second_cspace.contains(&true)
    }
}

impl Default for Config {
    /// Every thread at priority 100. Threads 0 and 1 fault to endpoint 3
    /// (Write and GrantReply, badges `0xF0` and `0xF1`), thread 2 to
    /// endpoint 0's original, thread 5 to endpoint 1 (Write and Grant,
    /// badge `0x55`); thread 3's fault endpoint is an empty slot and
    /// thread 4's does not resolve. Every thread's CSpace is the root.
    fn default() -> Config {
        Config {
            prios: [100; THREADS],
            fault_eps: [
                slot::EP3_F0,
                slot::EP3_F1,
                slot::EP,
                slot::EMPTY,
                BAD_CPTR,
                slot::EP1_WG_BADGED,
            ],
            second_cspace: [false; THREADS],
        }
    }
}

/// What a system call sets before it enters, as the thread's code would.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub number: u64,
    pub rdi: u64,
    pub rsi: u64,
    /// MR0 to MR3, or `None` to leave them.
    pub mrs: Option<[u64; 4]>,
}

/// One step, with its thread already chosen.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Action {
    /// Thread `t`, which the scheduler may run, writes `words` (index,
    /// value) into its IPC buffer if it has one and enters by `syscall`:
    /// with `entry`, after setting its registers; without, with them as
    /// they are, as a restarted call re-executes.
    Syscall {
        t: Tid,
        entry: Option<Entry>,
        words: Vec<(usize, u64)>,
    },
    /// Thread `t` takes exception `vector` at its `next_ip`.
    Exception {
        t: Tid,
        vector: u8,
        error: u64,
        cr2: u64,
    },
    /// A timer tick.
    Tick,
    /// While every thread is stopped and the idle thread runs: `t` is
    /// resumed by a thread outside the world, as `TCB_Resume` would.
    ExternalResume { t: Tid },
    /// Between system calls the kernel signals notification `n` with
    /// `badge`, as an interrupt's handler capability does
    /// (`docs/design.md`, "Signal").
    Interrupt { n: usize, badge: u64 },
    /// Another thread, which shares the frame, writes `t`'s IPC buffer
    /// words, whatever `t` is doing: a queued sender's pointers can change
    /// before the transfer.
    WriteBuffer { t: Tid, words: Vec<(usize, u64)> },
}

/// A `MessageInfo` word with no capabilities.
pub fn info(label: u64, length: u64) -> u64 {
    crate::ipc::Info {
        label,
        length,
        ..Default::default()
    }
    .word()
}

impl Action {
    /// System call `number` by `t` with these arguments.
    pub fn sys(t: Tid, number: u64, rdi: u64, rsi: u64, mrs: Option<[u64; 4]>) -> Action {
        Action::Syscall {
            t,
            entry: Some(Entry {
                number,
                rdi,
                rsi,
                mrs,
            }),
            words: Vec::new(),
        }
    }

    pub fn call(t: Tid, cptr: u64, label: u64, len: u64, mrs: [u64; 4]) -> Action {
        Action::sys(t, sysno::CALL, cptr, info(label, len), Some(mrs))
    }

    pub fn send(t: Tid, cptr: u64, label: u64, len: u64, mrs: [u64; 4]) -> Action {
        Action::sys(t, sysno::SEND, cptr, info(label, len), Some(mrs))
    }

    pub fn nbsend(t: Tid, cptr: u64, label: u64, len: u64, mrs: [u64; 4]) -> Action {
        Action::sys(t, sysno::NB_SEND, cptr, info(label, len), Some(mrs))
    }

    pub fn recv(t: Tid, cptr: u64) -> Action {
        Action::sys(t, sysno::RECV, cptr, 0, None)
    }

    pub fn nbrecv(t: Tid, cptr: u64) -> Action {
        Action::sys(t, sysno::NB_RECV, cptr, 0, None)
    }

    pub fn reply(t: Tid, label: u64, len: u64, mrs: [u64; 4]) -> Action {
        Action::sys(t, sysno::REPLY, 0, info(label, len), Some(mrs))
    }

    pub fn reply_recv(t: Tid, cptr: u64, label: u64, len: u64, mrs: [u64; 4]) -> Action {
        Action::sys(t, sysno::REPLY_RECV, cptr, info(label, len), Some(mrs))
    }

    pub fn yield_now(t: Tid) -> Action {
        Action::sys(t, sysno::YIELD, 0, 0, None)
    }

    /// `t` re-executes its `syscall` with its registers as they are.
    pub fn again(t: Tid) -> Action {
        Action::Syscall {
            t,
            entry: None,
            words: Vec::new(),
        }
    }

    /// `Call` (or `Send` without `call`) of invocation `label` on the
    /// capability at `cptr`, with MR0 and MR1.
    pub fn invoke(t: Tid, call: bool, cptr: u64, label: u64, mrs: [u64; 2]) -> Action {
        let number = if call { sysno::CALL } else { sysno::SEND };
        Action::sys(
            t,
            number,
            cptr,
            info(label, 2),
            Some([mrs[0], mrs[1], 0, 0]),
        )
    }

    /// `CNode_Delete` of root slot `index` through the root CNode.
    pub fn delete(t: Tid, call: bool, index: u64) -> Action {
        Action::invoke(t, call, slot::ROOT, label::CNODE_DELETE, [index, 64])
    }

    pub fn suspend(t: Tid, call: bool, target: Tid) -> Action {
        Action::invoke(
            t,
            call,
            slot::TCB + target as u64,
            label::TCB_SUSPEND,
            [0, 0],
        )
    }

    pub fn resume(t: Tid, call: bool, target: Tid) -> Action {
        Action::invoke(
            t,
            call,
            slot::TCB + target as u64,
            label::TCB_RESUME,
            [0, 0],
        )
    }

    /// `CNode_SaveCaller` into root slot `index`.
    pub fn save_caller(t: Tid, call: bool, index: u64) -> Action {
        Action::invoke(t, call, slot::ROOT, label::CNODE_SAVE_CALLER, [index, 64])
    }

    /// `CNode_CancelBadgedSends` on the capability in root slot `index`.
    pub fn cancel_badged_sends(t: Tid, call: bool, index: u64) -> Action {
        Action::invoke(
            t,
            call,
            slot::ROOT,
            label::CNODE_CANCEL_BADGED_SENDS,
            [index, 64],
        )
    }

    /// `TCB_BindNotification` of `target` to the capability at `ntfn`, sent
    /// as extra capability 0.
    pub fn bind(t: Tid, target: Tid, ntfn: u64) -> Action {
        let rsi = Info {
            label: label::TCB_BIND_NOTIFICATION,
            extra_caps: 1,
            ..Info::default()
        }
        .word();
        Action::sys(t, sysno::CALL, slot::TCB + target as u64, rsi, None)
            .with_words([(word::CAPS_OR_BADGES, ntfn)])
    }

    pub fn unbind(t: Tid, target: Tid) -> Action {
        Action::invoke(
            t,
            true,
            slot::TCB + target as u64,
            label::TCB_UNBIND_NOTIFICATION,
            [0, 0],
        )
    }

    /// Adds buffer words to a system call.
    pub fn with_words(mut self, w: impl IntoIterator<Item = (usize, u64)>) -> Action {
        if let Action::Syscall { words, .. } = &mut self {
            words.extend(w);
        }
        self
    }
}

pub fn tcb(i: Tid) -> TcbRef {
    TcbRef::new(TCB_BASE + ((i as u64) << TCB_BITS)).unwrap()
}

pub fn ep(i: usize) -> EpRef {
    EpRef::new(EP_BASE + 32 * i as u64).unwrap()
}

pub fn ntfn(i: usize) -> NtfnRef {
    NtfnRef::new(NTFN_BASE + 64 * i as u64).unwrap()
}

/// Root CNode slot `i`.
pub fn rs(i: u64) -> SlotAddr {
    SlotAddr::new(ROOT).unwrap().offset(i)
}

/// Second CNode slot `i`.
pub fn ss(i: u64) -> SlotAddr {
    SlotAddr::new(SECOND).unwrap().offset(i)
}

/// The kernel's address of model CNode `c`: 0 is the root, 1 the second.
pub fn cnode_addr(c: CNodeId) -> u64 {
    [ROOT, SECOND][c]
}

/// The kernel's slot for a model slot.
pub fn slot_addr((c, i): CSlot) -> SlotAddr {
    SlotAddr::new(cnode_addr(c)).unwrap().offset(i as u64)
}

fn ep_cap(i: usize, rights: Rights, badge: u64) -> Cap {
    Cap::new(
        CapType::Endpoint,
        ep(i).get(),
        ENDPOINT_BITS,
        rights,
        false,
        badge,
    )
}

fn ntfn_cap(i: usize, rights: Rights, badge: u64) -> Cap {
    Cap::new(
        CapType::Notification,
        ntfn(i).get(),
        NOTIFICATION_BITS,
        rights,
        false,
        badge,
    )
}

fn tcb_cap(i: Tid) -> Cap {
    Cap::new(CapType::Tcb, tcb(i).get(), TCB_BITS, Rights::NONE, false, 0)
}

const FRAMES: [(u64, Rights); 2] = [(FRAME_RW, RW), (FRAME_RO, Rights::READ)];

fn frame_cap(f: usize) -> Cap {
    Cap::new(CapType::Frame, FRAMES[f].0, 12, FRAMES[f].1, false, 0)
}

fn root_cap() -> Cap {
    Cap::cnode(ROOT, ROOT_RADIX, ROOT_GUARD_SIZE, 0)
}

fn second_cap() -> Cap {
    Cap::cnode(SECOND, ROOT_RADIX, ROOT_GUARD_SIZE, 0)
}

/// The capability the kernel holds for a model capability.
pub fn kcap(c: MCap) -> Cap {
    match c {
        MCap::Null => Cap::NULL,
        MCap::Endpoint { ep, badge, rights } => ep_cap(ep, rights, badge),
        MCap::Notification {
            ntfn,
            badge,
            rights,
        } => ntfn_cap(ntfn, rights, badge),
        MCap::CNode {
            cnode,
            guard_size,
            guard,
        } => Cap::cnode(cnode_addr(cnode), ROOT_RADIX, guard_size, guard),
        MCap::Tcb(t) => tcb_cap(t),
        MCap::Frame(f, _) => frame_cap(f),
        MCap::Untyped => Cap::untyped(UNTYPED, 12, false, 0),
        MCap::Reply { to, grant } => Cap::reply(tcb(to).get(), false, grant),
    }
}

/// The kernel's thread state for a model state.
pub fn kstate(s: State) -> ThreadState {
    match s {
        State::Inactive => ThreadState::Inactive,
        State::Running => ThreadState::Running,
        State::Restart => ThreadState::Restart,
        State::BlockedOnSend {
            ep: e,
            badge,
            grant,
            grant_reply,
            call,
        } => ThreadState::BlockedOnSend {
            ep: ep(e),
            badge,
            can_grant: grant,
            can_grant_reply: grant_reply,
            is_call: call,
        },
        State::BlockedOnReceive { ep: e, grant } => ThreadState::BlockedOnReceive {
            ep: ep(e),
            can_grant: grant,
        },
        State::BlockedOnReply => ThreadState::BlockedOnReply,
        State::BlockedOnNotification { ntfn: n } => {
            ThreadState::BlockedOnNotification { ntfn: ntfn(n) }
        }
    }
}

/// The kernel's outcome for a model outcome.
pub fn koutcome(o: crate::ipc::Outcome) -> Outcome {
    match o {
        crate::ipc::Outcome::Done => Outcome::Done,
        crate::ipc::Outcome::Stopped {
            thread,
            fault,
            handler,
        } => Outcome::Stopped(DoubleFault {
            thread: tcb(thread),
            fault,
            handler,
        }),
    }
}

/// Thread `t`'s buffer: its physical address and what the kernel may do
/// with it.
pub fn buffer_of(t: Tid) -> Option<(u64, Buffer)> {
    match t {
        0..=3 => Some((FRAME_RW + 0x400 * t as u64, Buffer::ReadWrite)),
        RO_THREAD => Some((FRAME_RO, Buffer::Read)),
        _ => None,
    }
}

/// What a `syscall` saves: the arguments `entry` sets, `fault_ip` on the
/// instruction, `next_ip` after it, `rcx` and `r11` as the instruction
/// leaves them, and a `sysretq` exit.
pub fn enter_syscall(regs: &mut Regs, entry: Option<&Entry>) {
    if let Some(e) = entry {
        regs.rdx = e.number;
        regs.rdi = e.rdi;
        regs.rsi = e.rsi;
        if let Some([a, b, c, d]) = e.mrs {
            (regs.r10, regs.r8, regs.r9, regs.r15) = (a, b, c, d);
        }
    }
    regs.fault_ip = regs.next_ip;
    regs.next_ip = regs.next_ip.wrapping_add(2);
    regs.rcx = regs.next_ip;
    regs.r11 = regs.rflags;
    regs.error = 0;
    regs.exit = EXIT_SYSRET;
}

/// What an exception saves: `fault_ip` = `next_ip` = the pushed RIP, the
/// error code and an `iretq` exit.
pub fn enter_exception(regs: &mut Regs, error: u64) {
    regs.fault_ip = regs.next_ip;
    regs.error = error;
    regs.exit = EXIT_IRET;
}

fn ensure(ok: bool, what: impl FnOnce() -> String) -> Result<(), String> {
    if ok { Ok(()) } else { Err(what()) }
}

/// An `l4core` kernel and the IPC model, side by side.
pub struct World {
    pub k: IpcTestKernel,
    pub m: Model,
    pub cfg: Config,
    /// Actions applied.
    pub steps: u64,
    /// Preemptions met, in all.
    pub preemptions: u64,
    /// If set, counts each action kind with its result, for coverage
    /// reports.
    pub tally: Option<BTreeMap<String, u64>>,
}

impl World {
    pub fn new(cfg: &Config) -> World {
        let k = World::kernel(cfg);
        let m = World::model(cfg);
        let w = World {
            k,
            m,
            cfg: *cfg,
            steps: 0,
            preemptions: 0,
            tally: None,
        };
        w.compare().expect("the start states agree");
        w
    }

    /// Thread `i`'s registers at the start.
    fn start_regs(i: Tid) -> Regs {
        let mut regs = Regs::new_thread();
        regs.fault_ip = PC_BASE + 0x1000 * i as u64;
        regs.next_ip = regs.fault_ip;
        regs
    }

    /// The thread that runs first: the first at the highest priority.
    fn first(cfg: &Config) -> Tid {
        let max = *cfg.prios.iter().max().unwrap();
        cfg.prios.iter().position(|&p| p == max).unwrap()
    }

    fn kernel(cfg: &Config) -> IpcTestKernel {
        let mut k = IpcTestKernel::new(0, MEM_END);
        let root = root_cap();
        cdt::insert_root(&mut k, rs(slot::ROOT), root);
        for i in 0..EPS {
            cdt::insert_root(&mut k, rs(slot::EP + i as u64), ep_cap(i, Rights::ALL, 0));
        }
        for (s, e, rights, badge) in EP_COPIES {
            let cap = ep_cap(e, rights, badge);
            cdt::insert_derived(&mut k, rs(slot::EP + e as u64), rs(s), cap, badge != 0).unwrap();
        }
        let cap = ep_cap(0, W_GR, 0x11);
        cdt::insert_derived(
            &mut k,
            rs(slot::EP0_BADGED),
            rs(slot::EP0_WGR_11),
            cap,
            false,
        )
        .unwrap();
        for i in 0..NTFNS {
            cdt::insert_root(&mut k, rs(slot::NTFN + i as u64), ntfn_cap(i, RW, 0));
        }
        for (s, n, rights, badge) in NTFN_COPIES {
            let cap = ntfn_cap(n, rights, badge);
            cdt::insert_derived(&mut k, rs(slot::NTFN + n as u64), rs(s), cap, badge != 0).unwrap();
        }
        for i in 0..THREADS {
            cdt::insert_root(&mut k, rs(slot::TCB + i as u64), tcb_cap(i));
        }
        cdt::insert_root(&mut k, rs(slot::FRAME_RW), frame_cap(0));
        cdt::insert_root(&mut k, rs(slot::FRAME_RO), frame_cap(1));
        cdt::insert_root(
            &mut k,
            rs(slot::UNTYPED),
            Cap::untyped(UNTYPED, 12, false, 0),
        );
        if cfg.has_second() {
            cdt::insert_root(&mut k, ss(second::OWN), second_cap());
            for (s, from) in second::COPIES {
                let cap = k.load(rs(from)).cap;
                cdt::insert_derived(&mut k, rs(from), ss(s), cap, false).unwrap();
            }
        }
        let first = World::first(cfg);
        for i in 0..THREADS {
            let t = tcb(i);
            tcb::init(&mut k, t);
            let (from, cspace) = match cfg.second_cspace[i] {
                false => (rs(slot::ROOT), root),
                true => (ss(second::OWN), second_cap()),
            };
            cdt::insert_derived(&mut k, from, t.slot(TCB_SLOT_CSPACE), cspace, false).unwrap();
            if let Some((paddr, b)) = buffer_of(i) {
                let f = (b == Buffer::Read) as usize;
                cdt::insert_derived(
                    &mut k,
                    rs(slot::FRAME_RW + f as u64),
                    t.slot(TCB_SLOT_IPC_BUFFER),
                    frame_cap(f),
                    false,
                )
                .unwrap();
                k.set_ipc_buffer(t, BUFFER_VADDR + (paddr & 0xFFF));
            }
            cdt::insert_root(
                &mut k,
                t.slot(TCB_SLOT_REPLY),
                Cap::reply(t.get(), true, true),
            );
            k.set_priority(t, cfg.prios[i]);
            k.set_mcp(t, 255);
            k.set_regs(t, &World::start_regs(i));
            k.set_fault_ep(t, cfg.fault_eps[i]);
            k.set_state(t, ThreadState::Running);
        }
        k.sched.set_current(Some(tcb(first)));
        for i in (0..THREADS).filter(|&i| i != first) {
            sched::append(&mut k, tcb(i));
        }
        k.events.clear();
        k.thread_events.clear();
        k
    }

    fn model(cfg: &Config) -> Model {
        let mut slots = vec![MCap::Null; ROOT_SLOTS];
        let root = MCap::CNode {
            cnode: 0,
            guard_size: ROOT_GUARD_SIZE,
            guard: 0,
        };
        slots[slot::ROOT as usize] = root;
        for i in 0..EPS {
            slots[slot::EP as usize + i] = MCap::Endpoint {
                ep: i,
                badge: 0,
                rights: Rights::ALL,
            };
        }
        for (s, e, rights, badge) in EP_COPIES {
            slots[s as usize] = MCap::Endpoint {
                ep: e,
                badge,
                rights,
            };
        }
        slots[slot::EP0_WGR_11 as usize] = MCap::Endpoint {
            ep: 0,
            badge: 0x11,
            rights: W_GR,
        };
        for i in 0..NTFNS {
            slots[slot::NTFN as usize + i] = MCap::Notification {
                ntfn: i,
                badge: 0,
                rights: RW,
            };
        }
        for (s, n, rights, badge) in NTFN_COPIES {
            slots[s as usize] = MCap::Notification {
                ntfn: n,
                badge,
                rights,
            };
        }
        for i in 0..THREADS {
            slots[slot::TCB as usize + i] = MCap::Tcb(i);
        }
        slots[slot::FRAME_RW as usize] = MCap::Frame(0, RW);
        slots[slot::FRAME_RO as usize] = MCap::Frame(1, Rights::READ);
        slots[slot::UNTYPED as usize] = MCap::Untyped;
        let own = MCap::CNode {
            cnode: 1,
            guard_size: ROOT_GUARD_SIZE,
            guard: 0,
        };
        let mut cnodes = vec![CNode {
            radix: ROOT_RADIX,
            slots,
        }];
        if cfg.has_second() {
            let mut slots = vec![MCap::Null; ROOT_SLOTS];
            slots[second::OWN as usize] = own;
            for (s, from) in second::COPIES {
                slots[s as usize] = cnodes[0].slots[from as usize];
            }
            cnodes.push(CNode {
                radix: ROOT_RADIX,
                slots,
            });
        }
        let threads = (0..THREADS)
            .map(|i| {
                let (frame, buffer) = match buffer_of(i) {
                    Some((_, Buffer::ReadWrite)) => (MCap::Frame(0, RW), Buffer::ReadWrite),
                    Some((_, b)) => (MCap::Frame(1, Rights::READ), b),
                    None => (MCap::Null, Buffer::None),
                };
                Thread {
                    alive: true,
                    state: State::Running,
                    regs: World::start_regs(i),
                    prio: cfg.prios[i],
                    slice: 1,
                    fault: None,
                    fault_ep: cfg.fault_eps[i],
                    cspace: if cfg.second_cspace[i] { own } else { root },
                    buffer_frame: frame,
                    buffer,
                    words: [0; BUFFER_WORDS],
                    caller: MCap::Null,
                    bound: None,
                }
            })
            .collect();
        let first = World::first(cfg);
        let mut queues: BTreeMap<u8, std::collections::VecDeque<Tid>> = BTreeMap::new();
        for i in (0..THREADS).filter(|&i| i != first) {
            queues.entry(cfg.prios[i]).or_default().push_back(i);
        }
        Model {
            threads,
            endpoints: vec![
                Endpoint {
                    dir: Dir::Idle,
                    queue: Default::default(),
                };
                EPS
            ],
            ntfns: vec![
                Ntfn {
                    state: NState::Idle,
                    word: 0,
                    bound: None,
                    queue: Default::default(),
                };
                NTFNS
            ],
            cnodes,
            queues,
            action: SchedAction::ResumeCurrent,
            current: Some(first),
            stats: Default::default(),
        }
    }

    // -----------------------------------------------------------------------
    // Steps
    // -----------------------------------------------------------------------

    /// Whether `action` is one the world can take now: a system call or an
    /// exception by a thread the scheduler may run, an external resume of
    /// a stopped thread while idle.
    pub fn allowed(&self, action: &Action) -> Result<(), String> {
        let eligible = self.m.eligible();
        match *action {
            Action::Syscall { t, ref words, .. } => {
                ensure(eligible.contains(&t), || {
                    format!("thread {t} may not run now")
                })?;
                ensure(words.iter().all(|&(i, _)| i < BUFFER_WORDS), || {
                    "a buffer word past 127".into()
                })
            }
            Action::Exception { t, vector, .. } => {
                ensure(eligible.contains(&t), || {
                    format!("thread {t} may not run now")
                })?;
                ensure(crate::ipc::exception_fault(vector, 0, 0).is_some(), || {
                    format!("vector {vector} is no user fault")
                })
            }
            Action::Tick => Ok(()),
            Action::ExternalResume { t } => {
                ensure(self.m.current.is_none(), || "a thread is running".into())?;
                ensure(self.m.threads[t].alive, || format!("thread {t} is dead"))
            }
            Action::Interrupt { n, .. } => ensure(n < NTFNS, || format!("no notification {n}")),
            Action::WriteBuffer { t, ref words } => {
                ensure(self.m.threads[t].alive, || format!("thread {t} is dead"))?;
                ensure(words.iter().all(|&(i, _)| i < BUFFER_WORDS), || {
                    "a buffer word past 127".into()
                })
            }
        }
    }

    /// Runs `action` on both and compares them. `schedule` drives
    /// preemption: before the first attempt the kernel preempts after
    /// `schedule[0]` preemption points, before the `k`-th restart after
    /// `schedule[k]`; past its end, never.
    pub fn apply(&mut self, action: &Action, schedule: &[u8]) -> Result<Outcome, String> {
        self.steps += 1;
        let step = self.steps;
        let ctx = |e: String| format!("step {step} {action:?}: {e}");
        self.allowed(action).map_err(ctx)?;
        let key = self.tally.is_some().then(|| self.tally_key(action));
        let named = self.named_slot(action);
        let expected = koutcome(self.model_apply(action));
        let got = self.kernel_apply(action, schedule, named).map_err(ctx)?;
        ensure(got == expected, || {
            format!("the kernel returned {got:?}, the model {expected:?}")
        })
        .map_err(ctx)?;
        self.compare().map_err(ctx)?;
        if let (Some(t), Some(key)) = (&mut self.tally, key) {
            let after = match *action {
                Action::Syscall { t, .. } | Action::Exception { t, .. } => {
                    format!(" -> {:?}", self.m.threads[t].state)
                        .split([' ', '{'])
                        .take(3)
                        .collect::<Vec<_>>()
                        .join(" ")
                }
                _ => String::new(),
            };
            let out = match got {
                Outcome::Stopped(_) => " (stopped)",
                _ => "",
            };
            *t.entry(format!("{key}{after}{out}")).or_default() += 1;
        }
        Ok(got)
    }

    /// The slot a CNode invocation by `action` would name, MR0 and MR1 from
    /// the CNode at `rdi`, as the model resolves it before the step: where
    /// a thread that deletes its own TCB leaves the Zombie.
    fn named_slot(&self, action: &Action) -> Option<CSlot> {
        let Action::Syscall { t, entry, .. } = *action else {
            return None;
        };
        let mut regs = self.m.threads[t].regs;
        enter_syscall(&mut regs, entry.as_ref());
        let cnode = self.m.cap(self.m.lookup_cap(t, regs.rdi).ok()?);
        let depth = u32::try_from(regs.r8)
            .ok()
            .filter(|d| (1..=64).contains(d))?;
        self.m.lookup_slot(cnode, regs.r10, depth).ok()
    }

    /// The model's side: atomic, then the scheduler.
    fn model_apply(&mut self, action: &Action) -> crate::ipc::Outcome {
        let m = &mut self.m;
        let out = match *action {
            Action::Syscall {
                t,
                entry,
                ref words,
            } => {
                m.run(t);
                enter_syscall(&mut m.threads[t].regs, entry.as_ref());
                if m.threads[t].buffer != Buffer::None {
                    for &(i, v) in words {
                        m.threads[t].words[i] = v;
                    }
                }
                m.syscall()
            }
            Action::Exception {
                t,
                vector,
                error,
                cr2,
            } => {
                m.run(t);
                enter_exception(&mut m.threads[t].regs, error);
                m.exception(vector, error, cr2)
            }
            Action::Tick => {
                m.tick();
                crate::ipc::Outcome::Done
            }
            Action::ExternalResume { t } => {
                m.resume(t);
                crate::ipc::Outcome::Done
            }
            Action::Interrupt { n, badge } => {
                m.signal(n, badge);
                crate::ipc::Outcome::Done
            }
            Action::WriteBuffer { t, ref words } => {
                if m.threads[t].buffer != Buffer::None {
                    for &(i, v) in words {
                        m.threads[t].words[i] = v;
                    }
                }
                crate::ipc::Outcome::Done
            }
        };
        m.schedule();
        out
    }

    /// Makes `t` the current thread, as the model's [`Model::run`] does.
    fn kernel_run(&mut self, t: Tid) {
        let t = tcb(t);
        let cur = self.k.sched.current();
        if cur == Some(t) {
            return;
        }
        if let Some(c) = cur
            && self.k.state(c).is_runnable()
        {
            sched::append(&mut self.k, c);
        }
        sched::dequeue(&mut self.k, t);
        self.k.sched.set_current(Some(t));
        tcb::activate(&mut self.k, t);
    }

    /// The kernel's side: the entry, restarted until it completes, then the
    /// scheduler and the chosen thread's activation. `named` is the slot
    /// a CNode invocation names, if the action is one.
    fn kernel_apply(
        &mut self,
        action: &Action,
        schedule: &[u8],
        named: Option<CSlot>,
    ) -> Result<Outcome, String> {
        let out = match *action {
            Action::Syscall {
                t,
                entry,
                ref words,
            } => {
                self.kernel_run(t);
                let tr = tcb(t);
                let mut regs = self.k.regs(tr);
                enter_syscall(&mut regs, entry.as_ref());
                self.k.set_regs(tr, &regs);
                if let Some((base, _)) = buffer_of(t) {
                    for &(i, v) in words {
                        self.k.mem.write(base + 8 * i as u64, v);
                    }
                }
                self.kernel_syscall(t, schedule, named)?
            }
            Action::Exception {
                t,
                vector,
                error,
                cr2,
            } => {
                self.kernel_run(t);
                let tr = tcb(t);
                let mut regs = self.k.regs(tr);
                enter_exception(&mut regs, error);
                self.k.set_regs(tr, &regs);
                syscall::handle_exception(&mut self.k, vector, error, cr2)
            }
            Action::Tick => {
                sched::tick(&mut self.k);
                Outcome::Done
            }
            Action::ExternalResume { t } => {
                tcb::restart(&mut self.k, tcb(t));
                Outcome::Done
            }
            Action::Interrupt { n, badge } => {
                ipc::signal(&mut self.k, ntfn(n), badge);
                Outcome::Done
            }
            Action::WriteBuffer { t, ref words } => {
                if let Some((base, _)) = buffer_of(t) {
                    for &(i, v) in words {
                        self.k.mem.write(base + 8 * i as u64, v);
                    }
                }
                Outcome::Done
            }
        };
        if let Some(n) = sched::schedule(&mut self.k) {
            tcb::activate(&mut self.k, n);
        }
        Ok(out)
    }

    /// `handle_syscall` for thread `t`, restarted after each preemption
    /// until it completes.
    fn kernel_syscall(
        &mut self,
        t: Tid,
        schedule: &[u8],
        named: Option<CSlot>,
    ) -> Result<Outcome, String> {
        let tr = tcb(t);
        let mut attempts = 0;
        self.k.preempt_in = schedule.first().map(|&n| n as u64);
        let out = loop {
            let out = syscall::handle_syscall(&mut self.k, false);
            if out != Outcome::Preempted {
                break out;
            }
            attempts += 1;
            self.preemptions += 1;
            self.check_midway()
                .map_err(|e| format!("at preemption {attempts}: {e}"))?;
            self.k.preempt_in = schedule.get(attempts).map(|&n| n as u64);
            if self.k.state(tr) == ThreadState::Restart && self.k.sched.current() == Some(tr) {
                // The caller re-executes its `syscall` with its arguments.
                tcb::activate(&mut self.k, tr);
                let mut regs = self.k.regs(tr);
                enter_syscall(&mut regs, None);
                self.k.set_regs(tr, &regs);
                continue;
            }
            // The caller deleted its own TCB, and the Zombie is left in the
            // slot its `CNode_Delete` named: delete it again until done.
            ensure(!self.m.threads[t].alive, || {
                format!(
                    "preempted thread {t} is {:?}, not Restart",
                    self.k.state(tr)
                )
            })?;
            let at = slot_addr(named.ok_or("a self-deletion that names no slot")?);
            loop {
                match cnode::delete(&mut self.k, at) {
                    Ok(()) => break,
                    Err(Preempted) => {
                        attempts += 1;
                        self.preemptions += 1;
                        self.check_midway()
                            .map_err(|e| format!("at preemption {attempts}: {e}"))?;
                        self.k.preempt_in = schedule.get(attempts).map(|&n| n as u64);
                    }
                }
            }
            break Outcome::Done;
        };
        self.k.preempt_in = None;
        Ok(out)
    }

    /// The threads alive in the model, as the kernel names them.
    fn live(&self) -> Vec<TcbRef> {
        (0..THREADS)
            .filter(|&i| self.m.threads[i].alive)
            .map(tcb)
            .collect()
    }

    fn eps() -> Vec<EpRef> {
        (0..EPS).map(ep).collect()
    }

    fn ntfns() -> Vec<NtfnRef> {
        (0..NTFNS).map(ntfn).collect()
    }

    /// At a preemption point: IPC's invariants over the threads that live
    /// on (a TCB being deleted is half gone), and the scheduler's.
    fn check_midway(&self) -> Result<(), String> {
        ipc::check(&self.k, &self.live(), &World::eps())?;
        ipc::check_notifications(&self.k, &self.live(), &World::ntfns())?;
        sched::check(&self.k, THREADS)?;
        Ok(())
    }

    // -----------------------------------------------------------------------
    // The comparison
    // -----------------------------------------------------------------------

    /// The threads queued on endpoint `i` in the kernel, head first.
    pub fn kernel_queue(&self, i: usize) -> Vec<TcbRef> {
        let mut v = Vec::new();
        let mut cur = self.k.endpoint(ep(i)).head;
        while let Some(t) = cur {
            v.push(t);
            if v.len() > THREADS {
                break;
            }
            cur = self.k.ep_links(t).1;
        }
        v
    }

    /// The threads waiting on notification `i` in the kernel, head first.
    pub fn kernel_ntfn_queue(&self, i: usize) -> Vec<TcbRef> {
        let mut v = Vec::new();
        let mut cur = ipc::notification(&self.k, ntfn(i)).head;
        while let Some(t) = cur {
            v.push(t);
            if v.len() > THREADS {
                break;
            }
            cur = self.k.ep_links(t).1;
        }
        v
    }

    /// The kernel's ready queues, by priority.
    pub fn kernel_ready(&self) -> BTreeMap<u8, Vec<TcbRef>> {
        let mut m = BTreeMap::new();
        for p in 0..=255u8 {
            let mut v = Vec::new();
            let mut cur = self.k.sched.head(p);
            while let Some(t) = cur {
                v.push(t);
                if v.len() > THREADS {
                    break;
                }
                cur = self.k.sched_links(t).1;
            }
            if !v.is_empty() {
                m.insert(p, v);
            }
        }
        m
    }

    /// Compares everything visible, then checks both sides' invariants.
    pub fn compare(&self) -> Result<(), String> {
        let m = &self.m;
        for (i, th) in m.threads.iter().enumerate() {
            if let Some((base, _)) = buffer_of(i) {
                for (w, &want) in th.words.iter().enumerate() {
                    let got = self.k.mem.read(base + 8 * w as u64);
                    ensure(got == want, || {
                        format!("thread {i}'s buffer word {w}: kernel {got:#x}, model {want:#x}")
                    })?;
                }
            }
            if !th.alive {
                continue;
            }
            let t = tcb(i);
            let (ks, ms) = (self.k.state(t), kstate(th.state));
            ensure(ks == ms, || {
                format!("thread {i}: kernel {ks:?}, model {ms:?}")
            })?;
            let (kr, mr) = (self.k.regs(t), th.regs);
            ensure(kr == mr, || {
                format!("thread {i}'s registers:\n  kernel {kr:x?}\n  model  {mr:x?}")
            })?;
            let (kf, mf) = (self.k.fault(t), th.fault);
            ensure(kf == mf, || {
                format!("thread {i}'s fault: kernel {kf:?}, model {mf:?}")
            })?;
            let (kc, mc) = (self.k.load(t.slot(TCB_SLOT_CALLER)).cap, kcap(th.caller));
            ensure(kc == mc, || {
                format!(
                    "thread {i}'s caller slot: kernel {kc:?}, model {:?}",
                    th.caller
                )
            })?;
            ensure(
                self.k.priority(t) == self.cfg.prios[i] && th.prio == self.cfg.prios[i],
                || format!("thread {i}'s priority changed to {}", self.k.priority(t)),
            )?;
            let (kb, mb) = (self.k.bound_notification(t), th.bound.map(ntfn));
            ensure(kb == mb, || {
                format!("thread {i}'s binding: kernel {kb:?}, model {mb:?}")
            })?;
            let (kt, mt) = (self.k.time_slice(t), th.slice);
            ensure(kt == mt, || {
                format!("thread {i}'s slice: kernel {kt}, model {mt}")
            })?;
        }
        for (i, e) in m.endpoints.iter().enumerate() {
            let state = match e.dir {
                Dir::Idle => EpState::Idle,
                Dir::Send => EpState::Send,
                Dir::Recv => EpState::Recv,
            };
            let ks = self.k.endpoint(ep(i)).state;
            ensure(ks == state, || {
                format!("endpoint {i}: kernel {ks:?}, model {state:?}")
            })?;
            let kq = self.kernel_queue(i);
            let mq: Vec<TcbRef> = e.queue.iter().map(|&t| tcb(t)).collect();
            ensure(kq == mq, || {
                format!("endpoint {i}'s queue: kernel {kq:?}, model {mq:?}")
            })?;
            let reserved = self.k.endpoint_word(ep(i), ipc::ep_field::RESERVED);
            ensure(reserved == 0, || {
                format!("endpoint {i}'s reserved word is {reserved:#x}")
            })?;
        }
        for (i, n) in m.ntfns.iter().enumerate() {
            let k = ipc::notification(&self.k, ntfn(i));
            let state = match n.state {
                NState::Idle => NtfnState::Idle,
                NState::Waiting => NtfnState::Waiting,
                NState::Active => NtfnState::Active,
            };
            ensure(
                (k.state, k.word, k.bound) == (state, n.word, n.bound.map(tcb)),
                || {
                    format!(
                        "notification {i}: kernel {:?} word {:#x} bound {:?}, model {:?} word {:#x} bound {:?}",
                        k.state, k.word, k.bound, n.state, n.word, n.bound
                    )
                },
            )?;
            let kq = self.kernel_ntfn_queue(i);
            let mq: Vec<TcbRef> = n.queue.iter().map(|&t| tcb(t)).collect();
            ensure(kq == mq, || {
                format!("notification {i}'s queue: kernel {kq:?}, model {mq:?}")
            })?;
        }
        let (kc, mc) = (self.k.sched.current(), m.current.map(tcb));
        ensure(kc == mc, || {
            format!("current thread: kernel {kc:?}, model {mc:?}")
        })?;
        let kq = self.kernel_ready();
        let mq: BTreeMap<u8, Vec<TcbRef>> = m
            .queues
            .iter()
            .map(|(&p, q)| (p, q.iter().map(|&t| tcb(t)).collect()))
            .collect();
        ensure(kq == mq, || {
            format!("ready queues: kernel {kq:?}, model {mq:?}")
        })?;
        for (n, cnode) in m.cnodes.iter().enumerate() {
            for (s, &c) in cnode.slots.iter().enumerate() {
                let (kc, mc) = (self.k.load(slot_addr((n, s))).cap, kcap(c));
                let which = ["root", "second CNode"][n];
                ensure(kc == mc, || {
                    format!("{which} slot {s}: kernel {kc:?}, model {c:?}")
                })?;
            }
        }
        for e in &self.k.thread_events {
            if let ThreadEvent::WriteBufferWord { paddr, .. } = *e {
                ensure((FRAME_RW..FRAME_RW + 0x1000).contains(&paddr), || {
                    format!("the kernel wrote {paddr:#x}, in no writable IPC buffer")
                })?;
            }
        }
        ipc::check(&self.k, &self.live(), &World::eps())?;
        ipc::check_notifications(&self.k, &self.live(), &World::ntfns())?;
        sched::check_exit(&self.k, THREADS)?;
        m.check()?;
        Ok(())
    }

    /// Clears the kernel's records of hook calls, which only grow.
    pub fn clear_events(&mut self) {
        self.k.events.clear();
        self.k.thread_events.clear();
    }

    /// An action's kind, for [`World::tally`]: the system call and the type
    /// of what it names, or the exception, before it runs.
    fn tally_key(&self, action: &Action) -> String {
        match *action {
            Action::Syscall { t, entry, .. } => {
                let regs = entry.map_or(self.m.threads[t].regs, |e| {
                    let mut r = self.m.threads[t].regs;
                    enter_syscall(&mut r, Some(&e));
                    r
                });
                let name = match regs.rdx {
                    1 => "Call",
                    2 => "ReplyRecv",
                    3 => "Send",
                    4 => "NBSend",
                    5 => "Recv",
                    6 => "Reply",
                    7 => "Yield",
                    8 => "NBRecv",
                    _ => "unknown syscall",
                };
                let target = match regs.rdx {
                    1..=5 | 8 => match self.m.lookup_cap(t, regs.rdi) {
                        Ok(s) => format!("{:?}", self.m.cap(s)),
                        Err(_) => "bad CPtr".into(),
                    },
                    _ => String::new(),
                };
                let mut target = target
                    .split([' ', '{', '('])
                    .next()
                    .unwrap_or("")
                    .to_string();
                if matches!(regs.rdx, 2 | 6) {
                    // What the reply phase answers.
                    let answers = match self.m.threads[t].caller {
                        MCap::Reply { to, .. } if self.m.threads[to].fault.is_some() => "a fault",
                        MCap::Reply { .. } => "a call",
                        _ => "nothing",
                    };
                    target = format!("{answers} {target}");
                }
                let again = if entry.is_none() { " again" } else { "" };
                format!("{name}{again} {target}")
            }
            Action::Exception { vector, .. } => format!("exception {vector}"),
            Action::Tick => "tick".into(),
            Action::ExternalResume { .. } => "external resume".into(),
            Action::Interrupt { .. } => "interrupt".into(),
            Action::WriteBuffer { .. } => "buffer written".into(),
        }
    }
}
