//! Host tests of the TCB layout, the thread operations and every TCB
//! invocation: each error row in `docs/abi.md`'s order, with nothing
//! changed by a failed call, each success path, and the depth limit for the
//! installs.

use std::vec;
use std::vec::Vec;

use super::*;
use crate::cap::{
    MAX_DERIVATION_DEPTH, TCB_SLOT_CALLER, TCB_SLOT_CSPACE, TCB_SLOT_IPC_BUFFER, TCB_SLOT_REPLY,
    TCB_SLOT_VSPACE,
};
use crate::cdt;
use crate::error::SyscallError;
use crate::invoke::{ExtraCap, InvokeError, Message, Reply};
use crate::regs::{Exit, USER_LIMIT, USER_REGS, UserReg, sanitise};
use crate::sched::Action;
use crate::slot::{Node, Slot};
use crate::testing::{Event, TestKernel, ThreadEvent};

const MEM_END: u64 = 0x7000;
const ROOT: u64 = 0x1000;
const TA: u64 = 0x2000;
const TB: u64 = 0x2800;
const TC: u64 = 0x3000;
const TD: u64 = 0x3800;
const X: u64 = 0x4000;
const X2: u64 = 0x4100;
const F: u64 = 0x5000;
const G: u64 = 0x6000;
const P: u64 = 0x8000;
const Q: u64 = 0xA000;
const EP: u64 = 0xC000;
const DEV: u64 = 0xD000;
/// A 2 MiB frame outside fake memory: only its capability is used.
const BIG: u64 = 0x20_0000;

// Root CNode slots.
const S_A: u64 = 1;
const S_B: u64 = 2;
const S_C: u64 = 3;
const S_D: u64 = 4;
const S_X: u64 = 5;
const S_F: u64 = 6;
/// Frame G with Read only.
const S_G: u64 = 7;
const S_P: u64 = 8;
const S_Q: u64 = 9;
const S_EP: u64 = 10;
const S_DEV: u64 = 11;
const S_UT: u64 = 12;
const S_X2: u64 = 13;
const S_BIG: u64 = 14;
/// Slots for capabilities a test adds.
const S_FREE: u64 = 20;

const TRUNCATED: SyscallError = SyscallError::TruncatedMessage;
const ILLEGAL: SyscallError = SyscallError::IllegalOperation;

fn sa(a: u64) -> SlotAddr {
    SlotAddr::new(a).unwrap()
}

fn rs(i: u64) -> SlotAddr {
    sa(ROOT).offset(i)
}

fn t(a: u64) -> TcbRef {
    TcbRef::new(a).unwrap()
}

fn frame(base: u64, bits: u32, rights: Rights, device: bool) -> Cap {
    Cap::new(CapType::Frame, base, bits, rights, device, 0)
}

const RW: Rights = Rights(Rights::READ.0 | Rights::WRITE.0);

/// Four TCBs (A the current, running thread; B, C and D new and
/// `Inactive`), two CNodes, frames, PML4s, an endpoint, a device frame and
/// an untyped, each capability a root in the root CNode.
struct World {
    k: TestKernel,
}

impl World {
    fn new() -> World {
        let mut k = TestKernel::new(0, MEM_END);
        for (slot, cap) in [
            (
                S_A,
                Cap::new(CapType::Tcb, TA, TCB_BITS, Rights::NONE, false, 0),
            ),
            (
                S_B,
                Cap::new(CapType::Tcb, TB, TCB_BITS, Rights::NONE, false, 0),
            ),
            (
                S_C,
                Cap::new(CapType::Tcb, TC, TCB_BITS, Rights::NONE, false, 0),
            ),
            (
                S_D,
                Cap::new(CapType::Tcb, TD, TCB_BITS, Rights::NONE, false, 0),
            ),
            (S_X, Cap::cnode(X, 2, 0, 0)),
            (S_F, frame(F, 12, RW, false)),
            (S_G, frame(G, 12, Rights::READ, false)),
            (S_P, Cap::new(CapType::Pml4, P, 13, Rights::NONE, false, 0)),
            (S_Q, Cap::new(CapType::Pml4, Q, 13, Rights::NONE, false, 0)),
            (
                S_EP,
                Cap::new(CapType::Endpoint, EP, 5, Rights::ALL, false, 0),
            ),
            (S_DEV, frame(DEV, 12, RW, true)),
            (S_UT, Cap::untyped(0xE000, 12, false, 0)),
            (S_X2, Cap::cnode(X2, 2, 0, 0)),
            (S_BIG, frame(BIG, 21, RW, false)),
        ] {
            cdt::insert_root(&mut k, rs(slot), cap);
        }
        for a in [TA, TB, TC, TD] {
            init(&mut k, t(a));
            cdt::insert_root(&mut k, t(a).slot(TCB_SLOT_REPLY), Cap::reply(a, true, true));
        }
        k.set_priority(t(TA), 100);
        k.set_mcp(t(TA), 200);
        k.set_state(t(TA), ThreadState::Running);
        k.sched.set_current(Some(t(TA)));
        k.events.clear();
        World { k }
    }

    fn cap(&self, s: SlotAddr) -> Cap {
        self.k.load(s).cap
    }

    fn node(&self, s: SlotAddr) -> Node {
        self.k.load(s).node
    }

    fn call(
        &mut self,
        tcb: u64,
        label: u64,
        mrs: &[u64],
        extra: &[u64],
    ) -> Result<Reply, InvokeError> {
        let caps: Vec<ExtraCap> = extra
            .iter()
            .map(|&i| ExtraCap::load(&self.k, rs(i)))
            .collect();
        let msg = Message {
            label,
            mrs,
            extra_caps: &caps,
        };
        invoke(&mut self.k, rs(tcb), &msg)
    }

    /// The call succeeds with an empty reply.
    fn ok(&mut self, tcb: u64, label: u64, mrs: &[u64], extra: &[u64]) {
        assert_eq!(
            self.call(tcb, label, mrs, extra),
            Ok(Reply::EMPTY),
            "label {label:#x} {mrs:x?}"
        );
    }

    /// The call fails with `err` and changes nothing.
    fn fails(&mut self, tcb: u64, label: u64, mrs: &[u64], extra: &[u64], err: SyscallError) {
        let mem = self.k.mem.clone();
        let sched = self.k.sched.clone();
        let (events, thread_events) = (self.k.events.len(), self.k.thread_events.len());
        assert_eq!(
            self.call(tcb, label, mrs, extra),
            Err(InvokeError::Error(err)),
            "label {label:#x} {mrs:x?} {extra:?}"
        );
        assert!(self.k.mem == mem, "a failed call changed memory");
        assert_eq!(self.k.sched, sched);
        assert_eq!(self.k.events.len(), events);
        assert_eq!(self.k.thread_events.len(), thread_events);
    }

    /// Puts `cap` in root slot `i` as a root with the given node.
    fn put(&mut self, i: u64, cap: Cap, node: Node) {
        assert!(self.cap(rs(i)).is_null());
        self.k.store(rs(i), Slot { cap, node });
    }

    /// Installs a CNode and a PML4 copy, and frame F at `0x7000_0400`, in
    /// `tcb`'s slots with Configure.
    fn configure(&mut self, tcb: u64) {
        self.ok(
            tcb,
            label::CONFIGURE,
            &[0x55, 0, 0x7000_0400],
            &[S_X, S_P, S_F],
        );
    }
}

fn range(min: u64, max: u64) -> SyscallError {
    SyscallError::RangeError { min, max }
}

// ---------------------------------------------------------------------------
// Layout, states and the thread operations
// ---------------------------------------------------------------------------

#[test]
fn scalars_fit_and_do_not_overlap() {
    let fields = [
        field::STATE,
        field::STATE_OBJECT,
        field::STATE_BADGE,
        field::PRIORITY,
        field::MCP,
        field::TIME_SLICE,
        field::QUEUED,
        field::SCHED_PREV,
        field::SCHED_NEXT,
        field::EP_PREV,
        field::EP_NEXT,
        field::FAULT,
        field::FAULT_EP,
        field::IPC_BUFFER,
        field::BOUND_NOTIFICATION,
        field::END,
    ];
    assert_eq!(fields[0], SCALARS_OFFSET);
    for w in fields.windows(2) {
        let size = if w[0] == field::FAULT {
            FAULT_WORDS as u64 * 8
        } else {
            8
        };
        assert_eq!(w[1], w[0] + size);
    }
    const { assert!(field::END <= DEBUG_OFFSET) };
}

#[test]
fn every_field_reads_back_alone() {
    let mut w = World::new();
    let b = t(TB);
    let before = w.k.mem.clone();
    let ep = EpRef::new(EP).unwrap();
    let ntfn = NtfnRef::new(0xC040).unwrap();
    let state = ThreadState::BlockedOnSend {
        ep,
        badge: u64::MAX,
        can_grant: true,
        can_grant_reply: false,
        is_call: true,
    };
    let fault = Fault::VmFault {
        addr: 0x1234,
        fsr: 6,
    };
    w.k.set_state(b, state);
    w.k.set_priority(b, 255);
    w.k.set_mcp(b, 254);
    w.k.set_time_slice(b, 9);
    w.k.set_queued(b, true);
    w.k.set_sched_prev(b, Some(t(TC)));
    w.k.set_sched_next(b, Some(t(TD)));
    w.k.set_ep_prev(b, Some(t(TD)));
    w.k.set_ep_next(b, Some(t(TA)));
    w.k.set_fault(b, Some(fault));
    w.k.set_fault_ep(b, 0xF00D);
    w.k.set_ipc_buffer(b, 0x7000_0400);
    w.k.set_bound_notification(b, Some(ntfn));
    assert_eq!(w.k.state(b), state);
    assert_eq!(
        (w.k.priority(b), w.k.mcp(b), w.k.time_slice(b)),
        (255, 254, 9)
    );
    assert!(w.k.queued(b));
    assert_eq!(w.k.sched_links(b), (Some(t(TC)), Some(t(TD))));
    assert_eq!(w.k.ep_links(b), (Some(t(TD)), Some(t(TA))));
    assert_eq!(w.k.fault(b), Some(fault));
    assert_eq!((w.k.fault_ep(b), w.k.ipc_buffer(b)), (0xF00D, 0x7000_0400));
    assert_eq!(w.k.bound_notification(b), Some(ntfn));
    // Nothing outside B's scalars changed: B's registers, slots and XSAVE
    // area, and every other TCB.
    for a in (0..MEM_END).step_by(8) {
        if !(TB + SCALARS_OFFSET..TB + field::END).contains(&a) {
            assert_eq!(w.k.mem.read(a), before.read(a), "{a:#x}");
        }
    }
    // The other TCBs read their own values.
    assert_eq!(w.k.state(t(TC)), ThreadState::Inactive);
    assert_eq!(w.k.sched_links(t(TC)), (None, None));
}

#[test]
fn thread_states_round_trip_through_their_words() {
    let ep = EpRef::new(0xFFF_FFFF_FFE0).unwrap();
    let ntfn = NtfnRef::new(0x40).unwrap();
    let mut states = vec![
        ThreadState::Inactive,
        ThreadState::Running,
        ThreadState::Restart,
        ThreadState::BlockedOnReply,
        ThreadState::BlockedOnNotification { ntfn },
    ];
    for bits in 0..8 {
        states.push(ThreadState::BlockedOnSend {
            ep,
            badge: bits * 0x1111,
            can_grant: bits & 1 != 0,
            can_grant_reply: bits & 2 != 0,
            is_call: bits & 4 != 0,
        });
        states.push(ThreadState::BlockedOnReceive {
            ep,
            can_grant: bits & 1 != 0,
        });
    }
    for s in states {
        assert_eq!(ThreadState::from_words(s.to_words()), s);
    }
    // Zero is `Inactive`, so a zeroed TCB is; unknown tags and blocked
    // states without an object read as `Inactive` too.
    assert_eq!(ThreadState::from_words([0; 3]), ThreadState::Inactive);
    for w in [
        [7, 0, 0],
        [0xFF, 1, 1],
        [3, 0, 5],
        [4, 0x10, 0],
        [6, 0x20, 0],
    ] {
        assert_eq!(ThreadState::from_words(w), ThreadState::Inactive, "{w:?}");
    }
    assert!(ThreadState::Running.is_runnable() && ThreadState::Restart.is_runnable());
    assert!(ThreadState::Inactive.is_stopped() && !ThreadState::Inactive.is_blocked());
    assert!(ThreadState::BlockedOnReply.is_stopped() && !ThreadState::Restart.is_stopped());
}

#[test]
fn handles_need_their_alignment() {
    assert_eq!(TcbRef::new(0), None);
    assert_eq!(TcbRef::new(0x400), None);
    assert_eq!(TcbRef::new(1 << 52), None);
    assert_eq!(TcbRef::new(0x800).map(TcbRef::get), Some(0x800));
    assert_eq!(EpRef::new(0x10), None);
    assert_eq!(EpRef::new(0x20).map(EpRef::get), Some(0x20));
    assert_eq!(NtfnRef::new(0x20), None);
    assert_eq!(NtfnRef::new(0x40).map(NtfnRef::get), Some(0x40));
    let ep = Cap::new(CapType::Endpoint, 0x800, 5, Rights::ALL, false, 0);
    assert_eq!(TcbRef::from_cap(&ep), None);
    assert_eq!(t(0x800).slot(TCB_SLOT_CALLER).get(), 0x800 + 4 * 32);
}

#[test]
fn a_new_tcb_and_the_root_task() {
    let mut w = World::new();
    let d = t(TD);
    // `init` on zeroed memory: what docs/abi.md, "TCB object", lists.
    assert_eq!(w.k.state(d), ThreadState::Inactive);
    assert_eq!((w.k.priority(d), w.k.mcp(d)), (0, 0));
    assert_eq!(w.k.time_slice(d), TIME_SLICE_TICKS);
    assert_eq!(w.k.regs(d), Regs::new_thread());
    assert_eq!(w.k.regs(d).exit(), Exit::Iret);
    assert_eq!(
        (w.k.fault(d), w.k.fault_ep(d), w.k.ipc_buffer(d)),
        (None, 0, 0)
    );
    assert_eq!(w.k.bound_notification(d), None);
    assert!(!w.k.queued(d));
    init_root(&mut w.k, d, 0x40_1000, 0x80_3000);
    let r = w.k.regs(d);
    assert_eq!(
        (r.next_ip, r.fault_ip, r.rdi, r.rflags, r.rsp),
        (0x40_1000, 0x40_1000, 0x80_3000, 0x202, 0)
    );
    assert_eq!(r.exit(), Exit::Iret);
    assert_eq!(w.k.state(d), ThreadState::Running);
    assert_eq!((w.k.priority(d), w.k.mcp(d)), (255, 255));
    // Boot makes it runnable and the scheduler picks it over A.
    sched::make_runnable(&mut w.k, d);
    assert_eq!(sched::schedule(&mut w.k), Some(d));
}

#[test]
fn activating_a_restart_thread_rewinds_to_fault_ip() {
    let mut w = World::new();
    let b = t(TB);
    let mut r = w.k.regs(b);
    r.fault_ip = 0x1000;
    r.next_ip = 0x1002;
    w.k.set_regs(b, &r);
    w.k.set_state(b, ThreadState::Running);
    activate(&mut w.k, b);
    assert_eq!(w.k.regs(b).next_ip, 0x1002);
    w.k.set_state(b, ThreadState::Restart);
    activate(&mut w.k, b);
    assert_eq!(w.k.state(b), ThreadState::Running);
    assert_eq!(w.k.regs(b).next_ip, 0x1000);
}

#[test]
fn buffer_words_need_a_frame_with_the_rights() {
    let mut w = World::new();
    let b = t(TB);
    assert_eq!(buffer_word(&w.k, b, 5, false), None);
    w.ok(S_B, label::SET_IPC_BUFFER, &[0x7000_0C00], &[S_F]);
    assert_eq!(buffer_word(&w.k, b, 0, true), Some(F + 0xC00));
    assert_eq!(buffer_word(&w.k, b, 127, false), Some(F + 0xC00 + 127 * 8));
    // A read-only frame can be read, not written.
    w.ok(S_B, label::SET_IPC_BUFFER, &[0x400], &[S_G]);
    assert_eq!(buffer_word(&w.k, b, 1, false), Some(G + 0x400 + 8));
    assert_eq!(buffer_word(&w.k, b, 1, true), None);
    // A 2 MiB frame: the address modulo 2 MiB.
    w.ok(S_B, label::SET_IPC_BUFFER, &[0x7012_3400], &[S_BIG]);
    assert_eq!(buffer_word(&w.k, b, 2, true), Some(BIG + 0x12_3400 + 16));
    w.ok(S_B, label::SET_IPC_BUFFER, &[0], &[]);
    assert_eq!(buffer_word(&w.k, b, 2, false), None);
    // MR0 to MR3 go to registers, MR4 up to the buffer.
    w.ok(S_B, label::SET_IPC_BUFFER, &[0x400], &[S_F]);
    assert!(set_mr(&mut w.k, b, 3, 33));
    assert!(set_mr(&mut w.k, b, 4, 44));
    assert!(set_mr(&mut w.k, b, 119, 1190));
    assert_eq!(w.k.regs(b).r15, 33);
    assert_eq!(w.k.mem.read(F + 0x400 + 5 * 8), 44);
    assert_eq!(w.k.mem.read(F + 0x400 + 120 * 8), 1190);
    w.ok(S_B, label::SET_IPC_BUFFER, &[0x400], &[S_G]);
    assert!(!set_mr(&mut w.k, b, 4, 1));
}

// ---------------------------------------------------------------------------
// Labels
// ---------------------------------------------------------------------------

#[test]
fn labels_outside_the_tcb_methods_are_illegal_before_any_length_check() {
    let mut w = World::new();
    for l in [
        0,
        0x01,
        0x10,
        0x1F,
        label::BIND_NOTIFICATION,
        label::UNBIND_NOTIFICATION,
        0x2E,
        0x3F,
        0x40,
        u64::MAX,
    ] {
        w.fails(S_B, l, &[], &[], ILLEGAL);
        w.fails(S_B, l, &[0; 8], &[S_EP, S_EP, S_EP], ILLEGAL);
    }
}

// ---------------------------------------------------------------------------
// Registers
// ---------------------------------------------------------------------------

/// Gives B distinct user registers and the state `s`.
fn prepare_b(w: &mut World, s: ThreadState) -> Regs {
    let mut r = Regs::new_thread();
    for (i, reg) in UserReg::ALL.into_iter().enumerate() {
        r.set_user(reg, 0x1000 + i as u64);
    }
    r.set_user(UserReg::Rflags, 0x246);
    r.fault_ip = 0x40_0000;
    r.next_ip = 0x40_0002;
    w.k.set_regs(t(TB), &r);
    w.k.set_state(t(TB), s);
    r
}

#[test]
fn read_registers_errors_in_order() {
    let mut w = World::new();
    const L: u64 = label::READ_REGISTERS;
    w.fails(S_B, L, &[], &[], TRUNCATED);
    w.fails(S_B, L, &[0], &[], TRUNCATED);
    // Flags before the count, the count before the caller.
    w.fails(S_A, L, &[2, 0], &[], SyscallError::InvalidArgument(0));
    w.fails(S_B, L, &[1 << 63, 5], &[], SyscallError::InvalidArgument(0));
    w.fails(S_A, L, &[0, 0], &[], range(1, 20));
    w.fails(S_B, L, &[1, 21], &[], range(1, 20));
    w.fails(S_B, L, &[0, u64::MAX], &[], range(1, 20));
    w.fails(S_A, L, &[0, 20], &[], ILLEGAL);
    w.fails(S_A, L, &[1, 1], &[], ILLEGAL);
}

#[test]
fn read_registers_fills_the_callers_message() {
    let mut w = World::new();
    let r = prepare_b(&mut w, ThreadState::Running);
    w.ok(S_A, label::SET_IPC_BUFFER, &[0x7000_0400], &[S_F]);
    let res = w.call(S_B, label::READ_REGISTERS, &[0, 20], &[]);
    assert_eq!(res, Ok(Reply { length: 20 }));
    let a = w.k.regs(t(TA));
    // MR0 is `rip`: `next_ip` for a `Running` thread.
    assert_eq!([a.r10, a.r8, a.r9, a.r15], [0x40_0002, r.rsp, 0x246, r.rax]);
    for i in 4..USER_REGS {
        let v = w.k.mem.read(F + 0x400 + 8 * (1 + i as u64));
        assert_eq!(v, r.user(UserReg::ALL[i], true), "MR{i}");
    }
    // A thread that is not running reads `fault_ip`.
    w.k.set_state(t(TB), ThreadState::BlockedOnReply);
    assert_eq!(
        w.call(S_B, label::READ_REGISTERS, &[0, 1], &[]),
        Ok(Reply { length: 1 })
    );
    assert_eq!(w.k.regs(t(TA)).r10, 0x40_0000);
    // Without a writable buffer: MR0 to MR3 and length min(count, 4).
    w.ok(S_A, label::SET_IPC_BUFFER, &[0x400], &[S_G]);
    let before = w.k.mem.read(G + 0x400 + 5 * 8);
    assert_eq!(
        w.call(S_B, label::READ_REGISTERS, &[0, 20], &[]),
        Ok(Reply { length: 4 })
    );
    assert_eq!(
        w.call(S_B, label::READ_REGISTERS, &[0, 3], &[]),
        Ok(Reply { length: 3 })
    );
    assert_eq!(w.k.mem.read(G + 0x400 + 5 * 8), before);
    // ReadRegisters changes nothing in the target, and leaves the caller's
    // exit alone.
    assert_eq!(w.k.regs(t(TB)), r);
    assert_eq!(w.k.state(t(TB)), ThreadState::BlockedOnReply);
}

#[test]
fn read_registers_by_send_writes_nothing() {
    let mut w = World::new();
    prepare_b(&mut w, ThreadState::Running);
    w.k.by_call = false;
    let a = w.k.regs(t(TA));
    assert_eq!(
        w.call(S_B, label::READ_REGISTERS, &[0, 20], &[]),
        Ok(Reply { length: 20 })
    );
    assert_eq!(w.k.regs(t(TA)), a);
}

#[test]
fn read_registers_can_suspend_first() {
    let mut w = World::new();
    let r = prepare_b(&mut w, ThreadState::Running);
    sched::make_runnable(&mut w.k, t(TB));
    assert_eq!(
        w.call(S_B, label::READ_REGISTERS, &[1, 1], &[]),
        Ok(Reply { length: 1 })
    );
    assert_eq!(w.k.state(t(TB)), ThreadState::Inactive);
    assert_ne!(w.k.sched.action(), Action::SwitchTo(t(TB)));
    // Suspending a running thread moved `fault_ip` to `next_ip`, which the
    // caller read.
    assert_eq!(w.k.regs(t(TA)).r10, r.next_ip);
    assert_eq!(w.k.regs(t(TB)).fault_ip, r.next_ip);
    assert!(w.k.thread_events.contains(&ThreadEvent::CancelIpc(t(TB))));
}

#[test]
fn write_registers_errors_in_order() {
    let mut w = World::new();
    const L: u64 = label::WRITE_REGISTERS;
    w.fails(S_B, L, &[], &[], TRUNCATED);
    w.fails(S_B, L, &[0], &[], TRUNCATED);
    w.fails(S_A, L, &[2, 99], &[], SyscallError::InvalidArgument(0));
    w.fails(S_A, L, &[0, 21], &[], range(0, 20));
    // A huge count is a RangeError, never an overflow.
    w.fails(S_B, L, &[0, u64::MAX], &[], range(0, 20));
    w.fails(S_B, L, &[0, u64::MAX - 1], &[], range(0, 20));
    // Too few values, after the range check and before the caller check.
    w.fails(S_A, L, &[0, 5, 1, 2, 3, 4], &[], TRUNCATED);
    w.fails(S_B, L, &[1, 20], &[], TRUNCATED);
    w.fails(S_A, L, &[0, 0], &[], ILLEGAL);
    w.fails(S_A, L, &[1, 2, 7, 8], &[], ILLEGAL);
}

#[test]
fn write_registers_sanitises_and_forces_iret() {
    let mut w = World::new();
    let mut r = prepare_b(&mut w, ThreadState::BlockedOnReply);
    r.set_exit(Exit::Sysret);
    w.k.set_regs(t(TB), &r);
    let mut mrs = vec![0, 20];
    let values: Vec<u64> = (0..20u64).map(|i| 0x9000 + i).collect();
    mrs.extend(&values);
    mrs[2] = 1 << 47; // rip: non-canonical
    mrs[3] = 0xFFFF_8000_0000_0000; // rsp: kernel half
    mrs[4] = u64::MAX; // rflags
    mrs[2 + 18] = (1 << 47) - 1; // FS base: the last user address
    mrs[2 + 19] = 1 << 63; // GS base
    w.ok(S_B, label::WRITE_REGISTERS, &mrs, &[]);
    let b = w.k.regs(t(TB));
    assert_eq!((b.fault_ip, b.next_ip, b.rsp, b.rflags), (0, 0, 0, 0x0ED7));
    assert_eq!((b.fs_base, b.gs_base), ((1 << 47) - 1, 0));
    for i in 3..18 {
        assert_eq!(b.user(UserReg::ALL[i], false), 0x9000 + i as u64);
    }
    assert_eq!(b.exit(), Exit::Iret);
    assert_eq!((b.error, b.pad), (r.error, r.pad));
    // Blocked and not resumed: the state is unchanged.
    assert_eq!(w.k.state(t(TB)), ThreadState::BlockedOnReply);
    // A short write changes only its words; without `rip`, `next_ip` stays.
    let mut r = w.k.regs(t(TB));
    r.next_ip = 0x5002;
    r.fault_ip = 0x5000;
    w.k.set_regs(t(TB), &r);
    w.ok(S_B, label::WRITE_REGISTERS, &[0, 0], &[]);
    w.ok(
        S_B,
        label::WRITE_REGISTERS,
        &[0, 2, 0x5000, 0x8000, 0xDEAD],
        &[],
    );
    let b = w.k.regs(t(TB));
    assert_eq!(
        (b.fault_ip, b.next_ip, b.rsp, b.rflags),
        (0x5000, 0x5000, 0x8000, 0x0ED7)
    );
}

#[test]
fn write_registers_can_resume_the_target() {
    let mut w = World::new();
    w.k.set_priority(t(TB), 150);
    w.ok(S_B, label::WRITE_REGISTERS, &[1, 2, 0x40_1000, 0x7FF0], &[]);
    assert_eq!(w.k.state(t(TB)), ThreadState::Restart);
    assert_eq!(w.k.sched.action(), Action::SwitchTo(t(TB)));
    assert_eq!(sched::schedule(&mut w.k), Some(t(TB)));
    activate(&mut w.k, t(TB));
    let b = w.k.regs(t(TB));
    assert_eq!(
        (b.next_ip, b.rsp, b.exit()),
        (0x40_1000, 0x7FF0, Exit::Iret)
    );
}

#[test]
fn copy_registers_errors_in_order() {
    let mut w = World::new();
    const L: u64 = label::COPY_REGISTERS;
    w.fails(S_B, L, &[], &[S_C], TRUNCATED);
    w.fails(S_B, L, &[0xF], &[], TRUNCATED);
    w.fails(S_A, L, &[0x10], &[S_EP], SyscallError::InvalidArgument(0));
    w.fails(S_A, L, &[0xF], &[S_EP], SyscallError::InvalidCapability(1));
    w.fails(S_B, L, &[0], &[S_X], SyscallError::InvalidCapability(1));
    w.fails(S_B, L, &[0xF], &[S_A], ILLEGAL);
    w.fails(S_A, L, &[0xF], &[S_B], ILLEGAL);
    w.fails(S_A, L, &[0], &[S_A], ILLEGAL);
}

#[test]
fn copy_registers_copies_the_chosen_words() {
    for flags in 0..4u64 {
        let mut w = World::new();
        // The source C, running, with registers no writer would leave.
        let mut src = Regs::new_thread();
        for (i, reg) in UserReg::ALL.into_iter().enumerate() {
            src.set_user(reg, 0x2000 + i as u64);
        }
        src.next_ip = 0x2_0002;
        src.fault_ip = 0x2_0000;
        src.rsp = u64::MAX;
        src.gs_base = 1 << 47;
        w.k.set_regs(t(TC), &src);
        w.k.set_state(t(TC), ThreadState::Running);
        let old = prepare_b(&mut w, ThreadState::Inactive);
        w.ok(S_B, label::COPY_REGISTERS, &[flags << 2], &[S_C]);
        let b = w.k.regs(t(TB));
        for (i, reg) in UserReg::ALL.into_iter().enumerate() {
            let copied = if i < 18 {
                flags & 1 != 0
            } else {
                flags & 2 != 0
            };
            let expect = if copied {
                sanitise(reg, src.user(reg, true))
            } else {
                old.user(reg, false)
            };
            assert_eq!(b.user(reg, false), expect, "flags {flags} {reg:?}");
        }
        if flags & 1 != 0 {
            // `rip` is the running source's `next_ip`, and sets both.
            assert_eq!((b.fault_ip, b.next_ip, b.rsp), (0x2_0002, 0x2_0002, 0));
        }
        assert_eq!(b.exit(), Exit::Iret);
        // The source is untouched.
        assert_eq!(w.k.regs(t(TC)), src);
        assert_eq!(w.k.state(t(TB)), ThreadState::Inactive);
    }
}

#[test]
fn copy_registers_suspends_the_source_and_resumes_the_target() {
    let mut w = World::new();
    let r = prepare_b(&mut w, ThreadState::Running);
    w.k.set_priority(t(TB), 50);
    sched::make_runnable(&mut w.k, t(TB));
    sched::schedule(&mut w.k);
    assert!(w.k.queued(t(TB)));
    w.k.set_priority(t(TC), 120);
    // C becomes B's copy; B stops first, so C runs from B's `next_ip`.
    w.ok(S_C, label::COPY_REGISTERS, &[0xF], &[S_B]);
    assert_eq!(w.k.state(t(TB)), ThreadState::Inactive);
    assert!(!w.k.queued(t(TB)));
    assert_eq!(w.k.state(t(TC)), ThreadState::Restart);
    assert_eq!(w.k.sched.action(), Action::SwitchTo(t(TC)));
    let c = w.k.regs(t(TC));
    assert_eq!((c.fault_ip, c.rax), (r.next_ip, r.rax));
    // A source and destination that are the same thread.
    w.ok(S_D, label::COPY_REGISTERS, &[0xC], &[S_D]);
}

// ---------------------------------------------------------------------------
// Configure, SetSpace and SetIPCBuffer
// ---------------------------------------------------------------------------

#[test]
fn configure_installs_derived_copies() {
    let mut w = World::new();
    w.ok(
        S_B,
        label::CONFIGURE,
        &[0x77, 3 | (0b101 << 6), 0x7000_0400],
        &[S_X, S_P, S_F],
    );
    let b = t(TB);
    assert_eq!((w.k.fault_ep(b), w.k.ipc_buffer(b)), (0x77, 0x7000_0400));
    // The CSpace root has the guard the data word gave.
    let cs = w.cap(b.slot(TCB_SLOT_CSPACE));
    assert_eq!(
        (cs.cap_type(), cs.object(), cs.radix()),
        (CapType::CNode, X, 2)
    );
    assert_eq!((cs.guard_size(), cs.guard()), (3, 0b101));
    assert_eq!(w.cap(b.slot(TCB_SLOT_VSPACE)), w.cap(rs(S_P)));
    assert_eq!(
        w.cap(b.slot(TCB_SLOT_IPC_BUFFER)),
        w.cap(rs(S_F)).with_data(0)
    );
    // Each is a child of its source, right after it in the list, and not
    // original.
    for (n, src) in [
        (TCB_SLOT_CSPACE, S_X),
        (TCB_SLOT_VSPACE, S_P),
        (TCB_SLOT_IPC_BUFFER, S_F),
    ] {
        let node = w.node(b.slot(n));
        assert_eq!((node.depth(), node.original()), (1, false));
        assert_eq!(node.prev(), Some(rs(src)));
        assert_eq!(cdt::parent(&w.k, b.slot(n)), Some(rs(src)));
        cdt::check_slot(&w.k, b.slot(n)).unwrap();
    }
    // The priority and state are unchanged.
    assert_eq!(w.k.state(b), ThreadState::Inactive);
    assert_eq!(w.k.priority(b), 0);
    // A second Configure deletes the old copies, then installs the new.
    w.k.events.clear();
    w.ok(S_B, label::CONFIGURE, &[0, 0, 0], &[S_X2, S_Q]);
    assert_eq!(w.cap(b.slot(TCB_SLOT_CSPACE)), w.cap(rs(S_X2)));
    assert_eq!(w.cap(b.slot(TCB_SLOT_VSPACE)), w.cap(rs(S_Q)));
    assert!(w.cap(b.slot(TCB_SLOT_IPC_BUFFER)).is_null());
    assert_eq!(w.node(b.slot(TCB_SLOT_IPC_BUFFER)), Node::EMPTY);
    assert_eq!(w.k.ipc_buffer(b), 0);
    assert!(w.k.events.contains(&Event::Finalise {
        cap: w.cap(rs(S_P)),
        last: false
    }));
    assert!(w.k.events.contains(&Event::Finalise {
        cap: w.cap(rs(S_F)).with_data(0),
        last: false
    }));
    // The sources' lists are whole again.
    for s in [S_X, S_P, S_F, S_X2, S_Q] {
        cdt::check_slot(&w.k, rs(s)).unwrap();
    }
    assert!(!cdt::has_children(&w.k, rs(S_P)));
}

#[test]
fn configure_errors_in_order() {
    let mut w = World::new();
    const L: u64 = label::CONFIGURE;
    let buf = 0x7000_0400;
    // 1: too few words or capabilities, or no frame for a buffer.
    w.fails(S_B, L, &[0, 0], &[S_X, S_P, S_F], TRUNCATED);
    w.fails(S_B, L, &[0, 0, 0], &[S_X], TRUNCATED);
    w.fails(S_B, L, &[0, 0, buf], &[S_X, S_P], TRUNCATED);
    // 2: the buffer frame, before the roots are looked at.
    for bad in [S_EP, S_DEV, S_UT, S_X, S_A, S_FREE] {
        w.fails(S_B, L, &[0, 0, buf], &[S_EP, S_EP, bad], ILLEGAL);
    }
    w.k.synic = [0, F];
    w.fails(
        S_B,
        L,
        &[0, 0, 0x1004],
        &[S_EP, S_EP, S_F],
        SyscallError::InvalidCapability(3),
    );
    // A SynIC page anywhere inside a 2 MiB frame.
    w.k.synic = [BIG + 0x1F_F000, 0];
    w.fails(
        S_B,
        L,
        &[0, 0, buf],
        &[S_EP, S_EP, S_BIG],
        SyscallError::InvalidCapability(3),
    );
    w.k.synic = [0; 2];
    w.fails(
        S_B,
        L,
        &[0, 0, 0x1004],
        &[S_EP, S_EP, S_F],
        SyscallError::AlignmentError,
    );
    w.fails(
        S_B,
        L,
        &[0, 0, 0x200],
        &[S_X, S_P, S_F],
        SyscallError::AlignmentError,
    );
    // 4: the CSpace root.
    for bad in [S_EP, S_P, S_F, S_UT, S_A, S_FREE] {
        w.fails(S_B, L, &[0, 0, buf], &[bad, S_P, S_F], ILLEGAL);
    }
    // A guard that does not fit beside the radix (2): 63 bits.
    w.fails(S_B, L, &[0, 63, 0], &[S_X, S_P], ILLEGAL);
    w.ok(S_B, L, &[0, 62, 0], &[S_X, S_P]);
    // Data on an endpoint is refused whatever it is.
    w.fails(S_B, L, &[0, 1, 0], &[S_EP, S_P], ILLEGAL);
    // 5: the VSpace root.
    for bad in [S_EP, S_X, S_F, S_UT, S_FREE] {
        w.fails(S_B, L, &[0, 0, buf], &[S_X, bad, S_F], ILLEGAL);
    }
}

#[test]
fn configure_refuses_a_long_running_cspace_deletion() {
    let mut w = World::new();
    let b = t(TB);
    // Slot 0 holds the last capability to a CNode: deleting it would clear
    // the CNode.
    let last = Cap::cnode(0x4200, 2, 0, 0);
    cdt::insert_root(&mut w.k, b.slot(TCB_SLOT_CSPACE), last);
    w.fails(S_B, label::CONFIGURE, &[0, 0, 0], &[S_X, S_P], ILLEGAL);
    w.fails(S_B, label::SET_SPACE, &[0, 0], &[S_X, S_P], ILLEGAL);
    // Buffer errors come first.
    w.fails(
        S_B,
        label::CONFIGURE,
        &[0, 0, 0x404],
        &[S_X, S_P, S_F],
        SyscallError::AlignmentError,
    );
    // A Zombie left by an interrupted deletion.
    let mut s = w.k.load(b.slot(TCB_SLOT_CSPACE));
    s.cap = Cap::zombie(0x4200, 7, 4, false);
    w.k.store(b.slot(TCB_SLOT_CSPACE), s);
    w.fails(S_B, label::SET_SPACE, &[0, 0], &[S_X, S_P], ILLEGAL);
    // A copy of a CNode that has other capabilities is not the last.
    w.k.store(b.slot(TCB_SLOT_CSPACE), Slot::EMPTY);
    w.ok(S_B, label::SET_SPACE, &[0, 0], &[S_X, S_P]);
    w.ok(S_B, label::SET_SPACE, &[9, 0], &[S_X2, S_Q]);
    assert_eq!(w.cap(b.slot(TCB_SLOT_CSPACE)), w.cap(rs(S_X2)));
    assert_eq!(w.k.fault_ep(b), 9);
    assert!(!cdt::has_children(&w.k, rs(S_X)));
}

#[test]
fn set_space_errors_in_order() {
    let mut w = World::new();
    const L: u64 = label::SET_SPACE;
    w.fails(S_B, L, &[0], &[S_X, S_P], TRUNCATED);
    w.fails(S_B, L, &[0, 0], &[S_X], TRUNCATED);
    w.fails(S_B, L, &[0, 0], &[S_P, S_P], ILLEGAL);
    w.fails(S_B, L, &[0, 0], &[S_X, S_X], ILLEGAL);
    w.fails(S_B, L, &[0, 63], &[S_X, S_P], ILLEGAL);
    w.ok(S_B, L, &[0x10, 0], &[S_X, S_P]);
    // SetSpace leaves the IPC buffer alone.
    assert!(w.cap(t(TB).slot(TCB_SLOT_IPC_BUFFER)).is_null());
    assert_eq!(w.k.fault_ep(t(TB)), 0x10);
}

#[test]
fn set_ipc_buffer_errors_in_order() {
    let mut w = World::new();
    const L: u64 = label::SET_IPC_BUFFER;
    w.fails(S_B, L, &[], &[S_F], TRUNCATED);
    w.fails(S_B, L, &[0x400], &[], TRUNCATED);
    for bad in [S_EP, S_DEV, S_X, S_P, S_FREE] {
        w.fails(S_B, L, &[0x401], &[bad], ILLEGAL);
    }
    w.k.synic = [F, 0];
    w.fails(S_B, L, &[0x401], &[S_F], SyscallError::InvalidCapability(1));
    w.ok(S_B, L, &[0x400], &[S_G]);
    w.k.synic = [0; 2];
    w.fails(S_B, L, &[0x401], &[S_F], SyscallError::AlignmentError);
    w.fails(S_B, L, &[0x7000_0200], &[S_F], SyscallError::AlignmentError);
    // Address 0 needs no frame, and empties the slot.
    w.ok(S_B, L, &[0], &[]);
    assert!(w.cap(t(TB).slot(TCB_SLOT_IPC_BUFFER)).is_null());
    assert!(!cdt::has_children(&w.k, rs(S_G)));
}

#[test]
fn installs_stop_at_the_depth_limit() {
    for (label, mrs, slot) in [
        (label::CONFIGURE, vec![0, 0, 0x400], 0),
        (label::CONFIGURE, vec![0, 0, 0x400], 1),
        (label::CONFIGURE, vec![0, 0, 0x400], 2),
        (label::SET_SPACE, vec![0, 0], 0),
        (label::SET_SPACE, vec![0, 0], 1),
        (label::SET_IPC_BUFFER, vec![0x400], 2),
    ] {
        let extra: Vec<u64> = match label {
            label::SET_IPC_BUFFER => vec![S_FREE + 2],
            _ => vec![S_FREE, S_FREE + 1, S_FREE + 2],
        };
        let caps = [
            Cap::cnode(X, 2, 0, 0),
            Cap::new(CapType::Pml4, P, 13, Rights::NONE, false, 0),
            frame(F, 12, RW, false),
        ];
        // Original sources at depth 4095: a child would be at 4096.
        let mut w = World::new();
        for (i, cap) in caps.into_iter().enumerate() {
            let depth = if i == slot { MAX_DERIVATION_DEPTH } else { 0 };
            w.put(S_FREE + i as u64, cap, Node::new(true, depth, depth));
        }
        w.fails(S_B, label, &mrs, &extra, ILLEGAL);
        // At 4094 the copy lands at 4095.
        let mut w = World::new();
        for (i, cap) in caps.into_iter().enumerate() {
            let depth = if i == slot {
                MAX_DERIVATION_DEPTH - 1
            } else {
                0
            };
            w.put(S_FREE + i as u64, cap, Node::new(true, depth, depth));
        }
        w.ok(S_B, label, &mrs, &extra);
        let n = w.node(t(TB).slot(slot as u64));
        assert_eq!(n.depth(), MAX_DERIVATION_DEPTH);
        // A source that is not original at 4095 gets a sibling at 4095.
        let mut w = World::new();
        for (i, cap) in caps.into_iter().enumerate() {
            let (original, depth) = if i == slot {
                (false, MAX_DERIVATION_DEPTH)
            } else {
                (true, 0)
            };
            w.put(S_FREE + i as u64, cap, Node::new(original, depth, depth));
        }
        w.ok(S_B, label, &mrs, &extra);
        assert_eq!(
            w.node(t(TB).slot(slot as u64)).depth(),
            MAX_DERIVATION_DEPTH
        );
    }
}

#[test]
fn an_install_whose_source_went_is_skipped() {
    let mut w = World::new();
    let caps = [ExtraCap::load(&w.k, rs(S_X)), ExtraCap::load(&w.k, rs(S_P))];
    let msg = Message {
        label: label::SET_SPACE,
        mrs: &[0, 0],
        extra_caps: &caps,
    };
    let inv = decode(&w.k, w.cap(rs(S_B)), &msg).unwrap();
    // The VSpace source is deleted between the decode and the install, as a
    // finalisation could in principle do.
    crate::cnode::delete(&mut w.k, rs(S_P)).unwrap();
    perform(&mut w.k, rs(S_B), inv).unwrap();
    assert_eq!(w.cap(t(TB).slot(TCB_SLOT_CSPACE)), w.cap(rs(S_X)));
    assert!(w.cap(t(TB).slot(TCB_SLOT_VSPACE)).is_null());
    // And with the invoked TCB capability gone, nothing is installed.
    let mut w = World::new();
    let caps = [ExtraCap::load(&w.k, rs(S_X)), ExtraCap::load(&w.k, rs(S_P))];
    let msg = Message {
        label: label::SET_SPACE,
        mrs: &[0, 0],
        extra_caps: &caps,
    };
    let inv = decode(&w.k, w.cap(rs(S_B)), &msg).unwrap();
    w.k.store(rs(S_B), Slot::EMPTY);
    perform(&mut w.k, rs(S_B), inv).unwrap();
    assert!(w.cap(t(TB).slot(TCB_SLOT_CSPACE)).is_null());
    assert!(w.cap(t(TB).slot(TCB_SLOT_VSPACE)).is_null());
}

// ---------------------------------------------------------------------------
// Priorities
// ---------------------------------------------------------------------------

#[test]
fn priority_setters_errors_in_order() {
    let mut w = World::new();
    for l in [label::SET_PRIORITY, label::SET_MC_PRIORITY] {
        w.fails(S_B, l, &[], &[S_A], TRUNCATED);
        w.fails(S_B, l, &[0], &[], TRUNCATED);
        w.fails(S_B, l, &[999], &[S_EP], SyscallError::InvalidCapability(1));
        // A's MCP is 200; C's is 0.
        w.fails(S_B, l, &[201], &[S_A], range(0, 200));
        w.fails(S_B, l, &[256], &[S_A], range(0, 200));
        w.fails(S_B, l, &[u64::MAX], &[S_A], range(0, 200));
        w.fails(S_B, l, &[1], &[S_C], range(0, 0));
    }
    const L: u64 = label::SET_SCHED_PARAMS;
    w.fails(S_B, L, &[0], &[S_A], TRUNCATED);
    w.fails(S_B, L, &[0, 0], &[], TRUNCATED);
    w.fails(
        S_B,
        L,
        &[999, 999],
        &[S_X],
        SyscallError::InvalidCapability(1),
    );
    w.fails(S_B, L, &[201, 0], &[S_A], range(0, 200));
    w.fails(S_B, L, &[0, 201], &[S_A], range(0, 200));
    w.fails(S_B, L, &[1 << 8, 1 << 8], &[S_A], range(0, 200));
}

#[test]
fn priority_setters_change_what_they_name() {
    let mut w = World::new();
    let b = t(TB);
    w.ok(S_B, label::SET_SCHED_PARAMS, &[150, 120], &[S_A]);
    assert_eq!((w.k.mcp(b), w.k.priority(b)), (150, 120));
    // Lowering the MCP leaves the priority alone.
    w.ok(S_B, label::SET_MC_PRIORITY, &[10], &[S_A]);
    assert_eq!((w.k.mcp(b), w.k.priority(b)), (10, 120));
    // B is now an authority up to its MCP, 10.
    w.ok(S_C, label::SET_PRIORITY, &[10], &[S_B]);
    w.fails(S_C, label::SET_PRIORITY, &[11], &[S_B], range(0, 10));
    assert_eq!(w.k.priority(t(TC)), 10);
    // B resumed below the caller A (100) joins its queue.
    w.ok(S_B, label::SET_PRIORITY, &[50], &[S_A]);
    w.ok(S_B, label::RESUME, &[], &[]);
    assert_eq!(w.k.sched.action(), Action::SwitchTo(b));
    assert_eq!(sched::schedule(&mut w.k), Some(t(TA)));
    assert_eq!(w.k.sched.tail(50), Some(b));
    // Raised above the caller, it leaves its queue and becomes the pending
    // switch, as a wake-up does.
    w.ok(S_B, label::SET_PRIORITY, &[200], &[S_A]);
    assert_eq!(w.k.sched.action(), Action::SwitchTo(b));
    assert!(!w.k.queued(b));
    assert_eq!(w.k.sched.tail(50), None);
    // Lowering the caller itself reschedules: B runs, A heads queue 0.
    w.ok(S_A, label::SET_PRIORITY, &[0], &[S_A]);
    assert_eq!(w.k.priority(t(TA)), 0);
    assert_eq!(w.k.sched.action(), Action::ChooseNew);
    assert_eq!(sched::schedule(&mut w.k), Some(b));
    assert_eq!(w.k.sched.head(0), Some(t(TA)));
    sched::check_exit(&w.k, 4).unwrap();
}

// ---------------------------------------------------------------------------
// Suspend, Resume and SetTLSBase
// ---------------------------------------------------------------------------

#[test]
fn suspend_and_resume_take_no_arguments_and_never_fail() {
    let mut w = World::new();
    w.ok(S_B, label::SUSPEND, &[1, 2, 3], &[S_EP]);
    w.ok(S_B, label::RESUME, &[1, 2, 3], &[S_EP]);
    w.ok(S_B, label::RESUME, &[], &[]);
    w.ok(S_B, label::SUSPEND, &[], &[]);
    w.ok(S_B, label::SUSPEND, &[], &[]);
}

#[test]
fn suspend_stops_a_thread_in_any_state() {
    let ep = EpRef::new(EP).unwrap();
    for s in [
        ThreadState::Running,
        ThreadState::Restart,
        ThreadState::Inactive,
        ThreadState::BlockedOnReply,
        ThreadState::BlockedOnReceive {
            ep,
            can_grant: true,
        },
        ThreadState::BlockedOnSend {
            ep,
            badge: 7,
            can_grant: false,
            can_grant_reply: true,
            is_call: true,
        },
    ] {
        let mut w = World::new();
        let r = prepare_b(&mut w, s);
        w.k.set_fault(t(TB), Some(Fault::VmFault { addr: 1, fsr: 4 }));
        if s.is_runnable() {
            w.k.set_priority(t(TB), 10);
            sched::make_runnable(&mut w.k, t(TB));
            sched::schedule(&mut w.k);
            assert!(w.k.queued(t(TB)));
        }
        w.k.thread_events.clear();
        w.ok(S_B, label::SUSPEND, &[], &[]);
        assert_eq!(w.k.state(t(TB)), ThreadState::Inactive, "{s:?}");
        assert!(!w.k.queued(t(TB)));
        assert_eq!(w.k.fault(t(TB)), None);
        assert_eq!(w.k.thread_events, [ThreadEvent::CancelIpc(t(TB))]);
        sched::check(&w.k, 4).unwrap();
        // Only a `Running` thread's `fault_ip` moves to `next_ip`.
        let b = w.k.regs(t(TB));
        let fault_ip = if s == ThreadState::Running {
            r.next_ip
        } else {
            r.fault_ip
        };
        assert_eq!((b.fault_ip, b.next_ip), (fault_ip, r.next_ip), "{s:?}");
        // Resume restarts it at `fault_ip`.
        w.ok(S_B, label::RESUME, &[], &[]);
        assert_eq!(w.k.state(t(TB)), ThreadState::Restart);
        assert!(w.k.queued(t(TB)) || w.k.sched.action() == Action::SwitchTo(t(TB)));
        activate(&mut w.k, t(TB));
        assert_eq!(w.k.regs(t(TB)).next_ip, fault_ip);
    }
}

#[test]
fn suspending_the_pending_thread_chooses_again() {
    let mut w = World::new();
    w.k.set_priority(t(TB), 150);
    w.ok(S_B, label::RESUME, &[], &[]);
    assert_eq!(w.k.sched.action(), Action::SwitchTo(t(TB)));
    w.ok(S_B, label::SUSPEND, &[], &[]);
    assert_eq!(w.k.sched.action(), Action::ChooseNew);
    assert_eq!(sched::schedule(&mut w.k), Some(t(TA)));
}

#[test]
fn a_thread_that_suspends_itself_resumes_after_its_syscall_with_no_error() {
    let mut w = World::new();
    let a = t(TA);
    // A entered with `syscall` at 0x40_1000: `rcx` = `next_ip` = 0x40_1002.
    let mut r = w.k.regs(a);
    r.fault_ip = 0x40_1000;
    r.next_ip = 0x40_1002;
    r.rsi = label::SUSPEND << 12;
    r.rdi = 0x1234;
    r.r10 = 0xAAAA;
    r.set_exit(Exit::Sysret);
    w.k.set_regs(a, &r);
    w.ok(S_A, label::SUSPEND, &[], &[]);
    assert_eq!(w.k.state(a), ThreadState::Inactive);
    assert_eq!(w.k.sched.action(), Action::ChooseNew);
    let s = w.k.regs(a);
    // The empty success reply is written; MRs keep their values.
    assert_eq!((s.rsi, s.rdi, s.r10), (0, 0, 0xAAAA));
    assert_eq!(s.fault_ip, 0x40_1002);
    assert_eq!(sched::schedule(&mut w.k), None);
    // Another thread resumes it: it restarts at `fault_ip`, after the
    // `syscall`, as if Suspend returned NoError.
    w.k.sched.set_current(Some(t(TB)));
    w.k.set_state(t(TB), ThreadState::Running);
    w.ok(S_A, label::RESUME, &[], &[]);
    w.k.set_state(t(TB), ThreadState::Inactive);
    assert_eq!(sched::schedule(&mut w.k), Some(a));
    activate(&mut w.k, a);
    let s = w.k.regs(a);
    assert_eq!((s.next_ip, s.rsi, s.rdi), (0x40_1002, 0, 0));
    assert_eq!(s.exit(), Exit::Sysret);
}

#[test]
fn a_self_suspend_by_send_leaves_the_registers_alone() {
    let mut w = World::new();
    let a = t(TA);
    let mut r = w.k.regs(a);
    r.rsi = 0x29000;
    r.rdi = 0x1234;
    w.k.set_regs(a, &r);
    w.k.by_call = false;
    w.ok(S_A, label::SUSPEND, &[], &[]);
    let s = w.k.regs(a);
    assert_eq!((s.rsi, s.rdi), (0x29000, 0x1234));
    assert_eq!(w.k.state(a), ThreadState::Inactive);
}

#[test]
fn resume_restarts_only_stopped_threads() {
    let mut w = World::new();
    // The caller is running: nothing happens.
    w.ok(S_A, label::RESUME, &[], &[]);
    assert_eq!(w.k.state(t(TA)), ThreadState::Running);
    assert_eq!(w.k.sched.action(), Action::ResumeCurrent);
    assert!(w.k.thread_events.is_empty());
    // A queued thread: nothing happens.
    let b = t(TB);
    w.k.set_state(b, ThreadState::Restart);
    sched::append(&mut w.k, b);
    w.ok(S_B, label::RESUME, &[], &[]);
    assert_eq!(w.k.sched.action(), Action::ResumeCurrent);
    assert!(w.k.thread_events.is_empty());
    // A blocked thread: its IPC is cancelled and it restarts.
    let c = t(TC);
    w.k.set_state(
        c,
        ThreadState::BlockedOnReceive {
            ep: EpRef::new(EP).unwrap(),
            can_grant: false,
        },
    );
    w.ok(S_C, label::RESUME, &[], &[]);
    assert_eq!(w.k.state(c), ThreadState::Restart);
    assert_eq!(w.k.thread_events, [ThreadEvent::CancelIpc(c)]);
    assert_eq!(w.k.sched.action(), Action::SwitchTo(c));
}

#[test]
fn set_tls_base() {
    let mut w = World::new();
    w.fails(S_B, label::SET_TLS_BASE, &[], &[], TRUNCATED);
    let mut r = w.k.regs(t(TB));
    r.set_exit(Exit::Sysret);
    w.k.set_regs(t(TB), &r);
    w.ok(S_B, label::SET_TLS_BASE, &[0x7000_0000], &[]);
    let b = w.k.regs(t(TB));
    assert_eq!((b.fs_base, b.exit()), (0x7000_0000, Exit::Sysret));
    assert!(w.k.thread_events.is_empty());
    w.ok(S_B, label::SET_TLS_BASE, &[USER_LIMIT], &[]);
    assert_eq!(w.k.regs(t(TB)).fs_base, 0);
    // On the caller it takes effect at once.
    w.ok(S_A, label::SET_TLS_BASE, &[0x1000], &[]);
    assert_eq!(w.k.regs(t(TA)).fs_base, 0x1000);
    w.ok(S_A, label::SET_TLS_BASE, &[u64::MAX], &[]);
    assert_eq!(
        w.k.thread_events,
        [
            ThreadEvent::SetCurrentFsBase(0x1000),
            ThreadEvent::SetCurrentFsBase(0)
        ]
    );
}

#[test]
fn configure_then_read_back_a_whole_thread() {
    // The creator's sequence of docs/design.md: Configure, SetSchedParams,
    // WriteRegisters with `rip`, `rsp` and `resume_target`.
    let mut w = World::new();
    w.configure(S_D);
    w.ok(S_D, label::SET_SCHED_PARAMS, &[0, 100], &[S_A]);
    w.ok(
        S_D,
        label::WRITE_REGISTERS,
        &[1, 2, 0x40_2000, 0x7_F000],
        &[],
    );
    let d = t(TD);
    assert_eq!(w.k.state(d), ThreadState::Restart);
    // Equal to the running A: it waits its turn at the tail.
    assert_eq!(sched::schedule(&mut w.k), Some(t(TA)));
    assert_eq!(w.k.sched.head(100), Some(d));
    // A yields; D runs from its entry point.
    sched::yield_now(&mut w.k);
    assert_eq!(sched::schedule(&mut w.k), Some(d));
    activate(&mut w.k, d);
    let r = w.k.regs(d);
    assert_eq!(
        (r.next_ip, r.rsp, r.rflags, r.exit()),
        (0x40_2000, 0x7_F000, 0x202, Exit::Iret)
    );
    assert_eq!(buffer_word(&w.k, d, 1, true), Some(F + 0x400 + 8));
}

#[test]
fn the_invocation_dispatch_reaches_the_tcb_decoder() {
    let mut w = World::new();
    let call = |w: &mut World, slot: SlotAddr, label: u64, mrs: &[u64], extra: &[u64]| {
        let caps: Vec<ExtraCap> = extra.iter().map(|&i| ExtraCap::load(&w.k, rs(i))).collect();
        let msg = Message {
            label,
            mrs,
            extra_caps: &caps,
        };
        crate::invoke::invoke(&mut w.k, slot, &msg)
    };
    assert_eq!(
        call(&mut w, rs(S_B), label::SET_PRIORITY, &[7], &[S_A]),
        Ok(Reply::EMPTY)
    );
    assert_eq!(w.k.priority(t(TB)), 7);
    assert_eq!(
        call(&mut w, rs(S_B), label::READ_REGISTERS, &[0, 21], &[]),
        Err(InvokeError::Error(range(1, 20)))
    );
    // TCB labels on other capabilities, and other labels on a TCB.
    assert_eq!(
        call(&mut w, rs(S_X), label::SUSPEND, &[], &[]),
        Err(InvokeError::Error(ILLEGAL))
    );
    assert_eq!(
        call(
            &mut w,
            rs(S_B),
            crate::invoke::label::CNODE_COPY,
            &[0; 5],
            &[S_X]
        ),
        Err(InvokeError::Error(ILLEGAL))
    );
    // An empty slot or a Zombie is InvalidCapability 0, whatever the label.
    assert_eq!(
        call(&mut w, rs(S_FREE), label::SUSPEND, &[], &[]),
        Err(InvokeError::Error(SyscallError::InvalidCapability(0)))
    );
    w.put(
        S_FREE,
        Cap::zombie(TD, TCB_BITS, 5, true),
        Node::new(true, 0, 0),
    );
    assert_eq!(
        call(&mut w, rs(S_FREE), label::RESUME, &[], &[]),
        Err(InvokeError::Error(SyscallError::InvalidCapability(0)))
    );
    assert_eq!(w.k.state(t(TD)), ThreadState::Inactive);
}
