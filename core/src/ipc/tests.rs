//! Host tests of the endpoint state machine, driven through system calls
//! as threads make them ([`crate::syscall::handle_syscall`]), with the
//! scheduler run at every kernel exit and every invariant of
//! [`super::check`] and [`crate::sched::check_exit`] checked there.
//!
//! [`World`] is shared with `crate::syscall`'s tests.

use std::vec::Vec;

use super::*;
use crate::cap::{
    Cap, CapType, Rights, TCB_BITS, TCB_SLOT_CALLER, TCB_SLOT_CSPACE, TCB_SLOT_IPC_BUFFER,
    TCB_SLOT_REPLY, TCB_SLOTS,
};
use crate::cdt;
use crate::regs::{Exit, Fault, Regs};
use crate::sched;
use crate::slot::{SlotAddr, SlotMemory};
use crate::syscall::{self, Outcome};
use crate::tcb::{self, EpRef, TcbRef, Tcbs, ThreadState};
use crate::testing::IpcTestKernel;

// ---------------------------------------------------------------------------
// The world
// ---------------------------------------------------------------------------

pub(crate) const MEM_END: u64 = 0x8000;
/// The root CNode: 32 slots, a 59-bit guard of 0, so `CPtr` `n` below 32
/// names slot `n` with all 64 bits.
pub(crate) const ROOT: u64 = 0x1000;
/// A second CNode, 16 slots, no guard.
pub(crate) const CNODE2: u64 = 0x1400;
/// Endpoint `i` is at `EP_BASE + 32 i`.
pub(crate) const EP_BASE: u64 = 0x1800;
pub(crate) const EPS: usize = 4;
/// Thread `i` is at `TCB_BASE + 2 KiB i`.
pub(crate) const TCB_BASE: u64 = 0x2000;
pub(crate) const THREADS: usize = 6;
/// A frame with Read and Write: threads A to D have their IPC buffers in
/// it, at 1 KiB each.
pub(crate) const FRAME_RW: u64 = 0x5000;
/// A frame with Read only: thread E's buffer, readable but not writable.
pub(crate) const FRAME_RO: u64 = 0x6000;
/// A 4 KiB untyped.
pub(crate) const UNTYPED: u64 = 0x7000;
/// The user address of a thread's IPC buffer, plus its offset in the
/// frame.
pub(crate) const BUFFER_VADDR: u64 = 0x10_0000;
/// Thread `i` starts at `PC_BASE + 4 KiB i`.
pub(crate) const PC_BASE: u64 = 0x40_0000;

// The threads.
pub(crate) const A: usize = 0;
pub(crate) const B: usize = 1;
pub(crate) const C: usize = 2;
pub(crate) const D: usize = 3;
/// Its IPC buffer is readable, not writable.
pub(crate) const E: usize = 4;
/// It has no IPC buffer.
pub(crate) const F: usize = 5;

// Root CNode slots. Slot 0 stays empty.
pub(crate) const S_ROOT: u64 = 1;
/// Endpoint `i`, all rights, unbadged, the original: slots 2 to 5. EP2's
/// and EP3's are their only capabilities.
pub(crate) const S_EP0: u64 = 2;
pub(crate) const S_EP1: u64 = 3;
pub(crate) const S_EP2: u64 = 4;
/// EP0 with all rights and badge [`BADGE`].
pub(crate) const S_EP0_BADGED: u64 = 6;
/// EP0 with Write only.
pub(crate) const S_EP0_W: u64 = 7;
/// EP0 with Write and GrantReply.
pub(crate) const S_EP0_WGR: u64 = 8;
/// EP0 with Read only.
pub(crate) const S_EP0_R: u64 = 9;
/// Thread `i`'s TCB capability, its only one: slots 10 to 15.
pub(crate) const S_TCB: u64 = 10;
pub(crate) const S_FRAME_RW: u64 = 16;
pub(crate) const S_FRAME_RO: u64 = 17;
pub(crate) const S_UNTYPED: u64 = 18;
pub(crate) const S_CNODE2: u64 = 19;
/// Slots 20 to 31 are free.
pub(crate) const S_FREE: u64 = 20;

pub(crate) const BADGE: u64 = 0x77;
/// A `CPtr` whose top bits break the root's guard.
pub(crate) const BAD_CPTR: u64 = 1 << 63 | 2;
/// The lookup failure [`BAD_CPTR`] meets.
pub(crate) const BAD_CPTR_FAILURE: crate::error::LookupFailure =
    crate::error::LookupFailure::GuardMismatch {
        bits_left: 64,
        guard: 0,
        guard_size: 59,
    };

pub(crate) const RW: Rights = Rights(Rights::READ.0 | Rights::WRITE.0);

pub(crate) fn sa(a: u64) -> SlotAddr {
    SlotAddr::new(a).unwrap()
}

/// Root CNode slot `i`.
pub(crate) fn rs(i: u64) -> SlotAddr {
    sa(ROOT).offset(i)
}

pub(crate) fn tcb(i: usize) -> TcbRef {
    TcbRef::new(TCB_BASE + ((i as u64) << TCB_BITS)).unwrap()
}

pub(crate) fn ep(i: usize) -> EpRef {
    EpRef::new(EP_BASE + 32 * i as u64).unwrap()
}

pub(crate) fn ep_cap(i: usize, rights: Rights, badge: u64) -> Cap {
    Cap::new(
        CapType::Endpoint,
        ep(i).get(),
        crate::cap::ENDPOINT_BITS,
        rights,
        false,
        badge,
    )
}

pub(crate) fn frame(base: u64, rights: Rights) -> Cap {
    Cap::new(CapType::Frame, base, 12, rights, false, 0)
}

pub(crate) fn info(label: u64, length: u64) -> u64 {
    MessageInfo::new(label, 0, 0, length).word()
}

/// The fake kernel, six threads at priority 100 and four endpoints.
/// Thread A is current; B to F are `Running` and queued in order.
pub(crate) struct World {
    pub k: IpcTestKernel,
    /// The threads that exist, for the checks.
    pub threads: Vec<TcbRef>,
    /// Each thread's priority, which IPC must never change.
    pub prios: Vec<(TcbRef, u8)>,
    /// Whether the kernel was built with `debug`, for the dispatch.
    pub debug: bool,
}

impl World {
    pub fn new() -> World {
        let mut k = IpcTestKernel::new(0, MEM_END);
        let root = Cap::cnode(ROOT, 5, 59, 0);
        cdt::insert_root(&mut k, rs(S_ROOT), root);
        for i in 0..EPS {
            cdt::insert_root(&mut k, rs(S_EP0 + i as u64), ep_cap(i, Rights::ALL, 0));
        }
        for (slot, cap, original) in [
            (S_EP0_BADGED, ep_cap(0, Rights::ALL, BADGE), true),
            (S_EP0_W, ep_cap(0, Rights::WRITE, 0), false),
            (
                S_EP0_WGR,
                ep_cap(0, Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0), 0),
                false,
            ),
            (S_EP0_R, ep_cap(0, Rights::READ, 0), false),
        ] {
            cdt::insert_derived(&mut k, rs(S_EP0), rs(slot), cap, original).unwrap();
        }
        for i in 0..THREADS {
            let t = tcb(i);
            let cap = Cap::new(CapType::Tcb, t.get(), TCB_BITS, Rights::NONE, false, 0);
            cdt::insert_root(&mut k, rs(S_TCB + i as u64), cap);
        }
        cdt::insert_root(&mut k, rs(S_FRAME_RW), frame(FRAME_RW, RW));
        cdt::insert_root(&mut k, rs(S_FRAME_RO), frame(FRAME_RO, Rights::READ));
        cdt::insert_root(&mut k, rs(S_UNTYPED), Cap::untyped(UNTYPED, 12, false, 0));
        cdt::insert_root(&mut k, rs(S_CNODE2), Cap::cnode(CNODE2, 4, 0, 0));
        let mut prios = Vec::new();
        for i in 0..THREADS {
            let t = tcb(i);
            tcb::init(&mut k, t);
            cdt::insert_derived(&mut k, rs(S_ROOT), t.slot(TCB_SLOT_CSPACE), root, false).unwrap();
            let buffer = match i {
                A..=D => Some((S_FRAME_RW, frame(FRAME_RW, RW), 0x400 * i as u64)),
                E => Some((S_FRAME_RO, frame(FRAME_RO, Rights::READ), 0)),
                _ => None,
            };
            if let Some((src, cap, offset)) = buffer {
                cdt::insert_derived(&mut k, rs(src), t.slot(TCB_SLOT_IPC_BUFFER), cap, false)
                    .unwrap();
                k.set_ipc_buffer(t, BUFFER_VADDR + offset);
            }
            cdt::insert_root(
                &mut k,
                t.slot(TCB_SLOT_REPLY),
                Cap::reply(t.get(), true, true),
            );
            k.set_priority(t, 100);
            k.set_mcp(t, 255);
            let mut regs = Regs::new_thread();
            regs.fault_ip = PC_BASE + 0x1000 * i as u64;
            regs.next_ip = regs.fault_ip;
            k.set_regs(t, &regs);
            k.set_state(t, ThreadState::Running);
            if i == A {
                k.sched.set_current(Some(t));
            } else {
                sched::append(&mut k, t);
            }
            prios.push((t, 100));
        }
        k.events.clear();
        k.thread_events.clear();
        let w = World {
            k,
            threads: (0..THREADS).map(tcb).collect(),
            prios,
            debug: true,
        };
        w.checkpoint();
        w
    }

    /// Every endpoint.
    pub fn eps() -> Vec<EpRef> {
        (0..EPS).map(ep).collect()
    }

    /// The scheduler's and IPC's invariants, and no priority changed.
    pub fn check(&self) {
        sched::check_exit(&self.k, THREADS).unwrap();
        check(&self.k, &self.threads, &World::eps()).unwrap();
        for &(t, p) in &self.prios {
            if self.threads.contains(&t) {
                assert_eq!(self.k.priority(t), p, "IPC changed a priority");
            }
        }
    }

    /// [`World::check`] at every kernel exit and switch, natively. Under
    /// Miri, which finds nothing in this safe code that the native run
    /// does not, the walk would triple each test's time, so the tests'
    /// own assertions stand alone there.
    fn checkpoint(&self) {
        if !cfg!(miri) {
            self.check();
        }
    }

    /// Makes `t`, which is runnable, the current thread, as if the
    /// scheduler had chosen it: the current thread, if runnable, joins the
    /// tail of its queue.
    pub fn run(&mut self, t: usize) {
        let t = tcb(t);
        let cur = self.k.sched.current();
        if cur == Some(t) {
            return;
        }
        assert!(self.k.state(t).is_runnable(), "running a stopped thread");
        if let Some(c) = cur
            && self.k.state(c).is_runnable()
        {
            sched::append(&mut self.k, c);
        }
        sched::dequeue(&mut self.k, t);
        self.k.sched.set_current(Some(t));
        tcb::activate(&mut self.k, t);
        self.checkpoint();
    }

    /// Changes `t`'s priority as `TCB_SetPriority` does, then exits.
    pub fn set_prio(&mut self, t: usize, p: u8) {
        sched::set_priority(&mut self.k, tcb(t), p);
        for x in &mut self.prios {
            if x.0 == tcb(t) {
                x.1 = p;
            }
        }
        self.exit();
    }

    /// Thread `t` runs `syscall` at its `next_ip` with `rdx` = `number`
    /// and the given `rdi`, `rsi` and, if given, MR0 to MR3, as the kernel
    /// saves the frame; nothing else runs. Returns the dispatch's outcome.
    pub fn enter(
        &mut self,
        t: usize,
        number: u64,
        rdi: u64,
        rsi: u64,
        mrs: Option<[u64; 4]>,
    ) -> Outcome {
        self.run(t);
        let t = tcb(t);
        let mut regs = self.k.regs(t);
        regs.rdx = number;
        regs.rdi = rdi;
        regs.rsi = rsi;
        if let Some(mrs) = mrs {
            for (i, v) in mrs.into_iter().enumerate() {
                regs.set_message_register(i, v);
            }
        }
        regs.fault_ip = regs.next_ip;
        regs.next_ip += 2;
        regs.rcx = regs.next_ip;
        regs.r11 = regs.rflags;
        regs.error = 0;
        regs.set_exit(Exit::Sysret);
        self.k.set_regs(t, &regs);
        syscall::handle_syscall(&mut self.k, self.debug)
    }

    /// The kernel exit: schedule, activate, check. Returns the thread that
    /// runs, `None` for idle.
    pub fn exit(&mut self) -> Option<TcbRef> {
        let next = sched::schedule(&mut self.k);
        if let Some(n) = next {
            tcb::activate(&mut self.k, n);
        }
        self.checkpoint();
        next
    }

    /// [`World::enter`], then [`World::exit`].
    pub fn syscall(
        &mut self,
        t: usize,
        number: u64,
        rdi: u64,
        rsi: u64,
        mrs: Option<[u64; 4]>,
    ) -> Outcome {
        let out = self.enter(t, number, rdi, rsi, mrs);
        self.exit();
        out
    }

    pub fn send(&mut self, t: usize, cptr: u64, label: u64, len: u64, mrs: [u64; 4]) -> Outcome {
        self.syscall(t, 3, cptr, info(label, len), Some(mrs))
    }

    pub fn nbsend(&mut self, t: usize, cptr: u64, label: u64, len: u64, mrs: [u64; 4]) -> Outcome {
        self.syscall(t, 4, cptr, info(label, len), Some(mrs))
    }

    pub fn call(&mut self, t: usize, cptr: u64, label: u64, len: u64, mrs: [u64; 4]) -> Outcome {
        self.syscall(t, 1, cptr, info(label, len), Some(mrs))
    }

    pub fn recv(&mut self, t: usize, cptr: u64) -> Outcome {
        self.syscall(t, 5, cptr, 0, None)
    }

    pub fn nbrecv(&mut self, t: usize, cptr: u64) -> Outcome {
        self.syscall(t, 8, cptr, 0, None)
    }

    pub fn reply(&mut self, t: usize, label: u64, len: u64, mrs: [u64; 4]) -> Outcome {
        self.syscall(t, 6, 0, info(label, len), Some(mrs))
    }

    pub fn reply_recv(
        &mut self,
        t: usize,
        cptr: u64,
        label: u64,
        len: u64,
        mrs: [u64; 4],
    ) -> Outcome {
        self.syscall(t, 2, cptr, info(label, len), Some(mrs))
    }

    /// Thread `t` takes exception `vector` at its `next_ip`, as the kernel
    /// saves the frame; then the kernel exits.
    pub fn exception(&mut self, t: usize, vector: u8, error: u64, cr2: u64) -> Outcome {
        self.run(t);
        let tr = tcb(t);
        let mut regs = self.k.regs(tr);
        regs.fault_ip = regs.next_ip;
        regs.error = error;
        regs.set_exit(Exit::Iret);
        self.k.set_regs(tr, &regs);
        let out = syscall::handle_exception(&mut self.k, vector, error, cr2);
        self.exit();
        out
    }

    pub fn state(&self, t: usize) -> ThreadState {
        self.k.state(tcb(t))
    }

    pub fn regs(&self, t: usize) -> Regs {
        self.k.regs(tcb(t))
    }

    pub fn mrs(&self, t: usize) -> [u64; 4] {
        let r = self.regs(t);
        [r.r10, r.r8, r.r9, r.r15]
    }

    pub fn set_mrs(&mut self, t: usize, mrs: [u64; 4]) {
        let mut r = self.regs(t);
        for (i, v) in mrs.into_iter().enumerate() {
            r.set_message_register(i, v);
        }
        self.k.set_regs(tcb(t), &r);
    }

    /// The physical address of word `w` of thread `t`'s IPC buffer.
    pub fn buf_addr(&self, t: usize, w: usize) -> u64 {
        let base = match t {
            A..=D => FRAME_RW + 0x400 * t as u64,
            E => FRAME_RO,
            _ => panic!("thread F has no IPC buffer"),
        };
        base + 8 * w as u64
    }

    pub fn buf(&self, t: usize, w: usize) -> u64 {
        self.k.mem.read(self.buf_addr(t, w))
    }

    pub fn set_buf(&mut self, t: usize, w: usize, v: u64) {
        let a = self.buf_addr(t, w);
        self.k.mem.write(a, v);
    }

    /// Message register `i` of thread `t`: MR0 to MR3 in registers, then
    /// its buffer.
    pub fn mr(&self, t: usize, i: usize) -> u64 {
        if i < 4 {
            self.mrs(t)[i]
        } else {
            self.buf(t, word::MSG + i)
        }
    }

    pub fn current(&self) -> Option<TcbRef> {
        self.k.sched.current()
    }

    pub fn cap(&self, s: SlotAddr) -> Cap {
        self.k.load(s).cap
    }

    /// What thread `t`'s caller slot holds.
    pub fn caller_slot(&self, t: usize) -> Cap {
        self.cap(tcb(t).slot(TCB_SLOT_CALLER))
    }

    pub fn endpoint(&self, i: usize) -> Endpoint {
        self.k.endpoint(ep(i))
    }

    /// The threads queued on endpoint `i`, head first.
    pub fn queue(&self, i: usize) -> Vec<TcbRef> {
        let mut v = Vec::new();
        let mut cur = self.endpoint(i).head;
        while let Some(t) = cur {
            v.push(t);
            cur = self.k.ep_links(t).1;
        }
        v
    }

    /// The threads in ready queue 100, head first.
    pub fn ready(&self) -> Vec<TcbRef> {
        let mut v = Vec::new();
        let mut cur = self.k.sched.head(100);
        while let Some(t) = cur {
            v.push(t);
            cur = self.k.sched_links(t).1;
        }
        v
    }

    /// `t`'s fault endpoint `CPtr`.
    pub fn set_fault_ep(&mut self, t: usize, cptr: u64) {
        self.k.set_fault_ep(tcb(t), cptr);
    }
}

/// The cases a test loops over, each in a world of its own: all of them
/// natively, the first and the last under Miri, to keep its time down.
pub(crate) fn cases<T: Copy>(all: &[T]) -> Vec<T> {
    if cfg!(miri) && all.len() > 2 {
        std::vec![all[0], all[all.len() - 1]]
    } else {
        all.to_vec()
    }
}

/// Whether `cap` is a reply capability to thread `to` with Grant `grant`.
fn is_reply_to(cap: Cap, to: usize, grant: bool) -> bool {
    cap == Cap::reply(tcb(to).get(), false, grant)
}

// ---------------------------------------------------------------------------
// Send and receive
// ---------------------------------------------------------------------------

#[test]
fn a_send_to_a_waiting_receiver_moves_the_message() {
    let mut w = World::new();
    w.set_mrs(B, [0xB0, 0xB1, 0xB2, 0xB3]);
    assert_eq!(w.recv(B, S_EP0), Outcome::Done);
    assert_eq!(
        w.state(B),
        ThreadState::BlockedOnReceive {
            ep: ep(0),
            can_grant: true
        }
    );
    assert_eq!(w.endpoint(0).state, EpState::Recv);
    assert_eq!(w.queue(0), [tcb(B)]);
    // B ran after A, which went to the tail, so C runs now.
    assert_eq!(w.current(), Some(tcb(C)));

    assert_eq!(w.send(A, S_EP0, 0x55, 3, [1, 2, 3, 4]), Outcome::Done);
    assert_eq!(w.state(B), ThreadState::Running);
    assert_eq!(w.regs(B).rdi, 0);
    assert_eq!(w.regs(B).rsi, info(0x55, 3));
    assert_eq!(w.mrs(B), [1, 2, 3, 0xB3], "MR3 is past the length");
    assert_eq!(w.endpoint(0), Endpoint::IDLE);
    // The sender goes on with its registers as they were.
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!(w.current(), Some(tcb(A)));
    let a = w.regs(A);
    assert_eq!((a.rdi, a.rsi), (S_EP0, info(0x55, 3)));
    assert_eq!(w.mrs(A), [1, 2, 3, 4]);
    // The woken receiver joined the tail of its queue: same priority, and
    // the sender still runs.
    assert_eq!(*w.ready().last().unwrap(), tcb(B));
    assert!(w.caller_slot(B).is_null());
}

#[test]
fn a_sender_waits_for_a_receiver_and_continues_after_the_syscall() {
    let mut w = World::new();
    assert_eq!(w.send(A, S_EP0, 9, 2, [5, 6, 7, 8]), Outcome::Done);
    assert_eq!(
        w.state(A),
        ThreadState::BlockedOnSend {
            ep: ep(0),
            badge: 0,
            can_grant: true,
            can_grant_reply: true,
            is_call: false
        }
    );
    assert_eq!(w.endpoint(0).state, EpState::Send);
    assert_eq!(w.current(), Some(tcb(B)));
    let a_next = w.regs(A).next_ip;

    assert_eq!(w.recv(B, S_EP0), Outcome::Done);
    assert_eq!(w.regs(B).rsi, info(9, 2));
    assert_eq!(w.mrs(B)[..2], [5, 6]);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!(w.state(B), ThreadState::Running);
    assert!(
        w.caller_slot(B).is_null(),
        "a Send leaves no reply capability"
    );
    w.run(A);
    assert_eq!(
        w.regs(A).next_ip,
        a_next,
        "the sender continues after its syscall"
    );
}

#[test]
fn the_badge_is_the_one_the_sender_invoked_when_it_sent() {
    let mut w = World::new();
    w.send(A, S_EP0_BADGED, 1, 0, [0; 4]);
    // Deleting the badged capability after the send changes nothing.
    crate::cnode::delete(&mut w.k, rs(S_EP0_BADGED)).unwrap();
    w.recv(B, S_EP0);
    assert_eq!(w.regs(B).rdi, BADGE);
    // An unbadged send delivers 0, over whatever `rdi` held.
    w.send(C, S_EP0, 1, 0, [0; 4]);
    w.recv(B, S_EP0);
    assert_eq!(w.regs(B).rdi, 0);
}

#[test]
fn words_past_mr3_need_a_readable_sender_buffer_and_a_writable_receiver_buffer() {
    let mut w = World::new();
    // A and B have buffers that are readable and writable.
    for i in 4..12 {
        w.set_buf(A, word::MSG + i, 100 + i as u64);
        w.set_buf(B, word::MSG + i, 0xBBBB);
    }
    w.recv(B, S_EP0);
    w.send(A, S_EP0, 3, 10, [0, 1, 2, 3]);
    assert_eq!(w.regs(B).rsi, info(3, 10));
    for i in 4..10 {
        assert_eq!(w.mr(B, i), 100 + i as u64);
    }
    assert_eq!(w.mr(B, 10), 0xBBBB, "past the length");
    // No buffer on the sender: 4 words.
    w.run(B);
    w.recv(B, S_EP0);
    w.send(F, S_EP0, 3, 10, [0, 1, 2, 3]);
    assert_eq!(w.regs(B).rsi, info(3, 4));
    // A read-only buffer on the receiver: 4 words, and its buffer is not
    // written.
    let e_words: Vec<u64> = (0..128).map(|i| w.buf(E, i)).collect();
    w.recv(E, S_EP0);
    w.send(A, S_EP0, 3, 10, [0, 1, 2, 3]);
    assert_eq!(w.regs(E).rsi, info(3, 4));
    assert_eq!((0..128).map(|i| w.buf(E, i)).collect::<Vec<_>>(), e_words);
    // A read-only buffer on the sender is readable.
    w.set_buf(E, word::MSG + 4, 0xE4);
    w.set_buf(E, word::MSG + 5, 0xE5);
    w.run(B);
    w.recv(B, S_EP0);
    w.send(E, S_EP0, 3, 6, [0, 1, 2, 3]);
    assert_eq!(w.regs(B).rsi, info(3, 6));
    assert_eq!((w.mr(B, 4), w.mr(B, 5)), (0xE4, 0xE5));
}

#[test]
fn a_length_above_120_counts_as_120_and_user_data_is_never_touched() {
    let mut w = World::new();
    for i in 4..120 {
        w.set_buf(A, word::MSG + i, i as u64);
    }
    w.set_buf(A, word::USER_DATA, 0xAAAA);
    w.set_buf(B, word::USER_DATA, 0xBBBB);
    w.set_buf(B, word::CAPS_OR_BADGES, 0xBBBC);
    w.recv(B, S_EP0);
    w.send(A, S_EP0, 0, 127, [0, 1, 2, 3]);
    assert_eq!(w.regs(B).rsi, info(0, 120));
    assert_eq!(w.mr(B, 119), 119);
    assert_eq!(w.buf(B, word::USER_DATA), 0xBBBB);
    assert_eq!(w.buf(B, word::CAPS_OR_BADGES), 0xBBBC);
}

#[test]
fn nbsend_without_a_receiver_drops_the_message() {
    let mut w = World::new();
    let before = w.regs(A);
    assert_eq!(w.nbsend(A, S_EP0, 1, 1, [7, 0, 0, 0]), Outcome::Done);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!(w.endpoint(0), Endpoint::IDLE);
    let after = w.regs(A);
    assert_eq!((after.r10, after.rsi), (7, info(1, 1)));
    assert_eq!(after.next_ip, before.next_ip + 2);
    // With a receiver it is delivered.
    w.recv(B, S_EP0);
    w.nbsend(A, S_EP0, 1, 1, [7, 0, 0, 0]);
    assert_eq!((w.state(B), w.mrs(B)[0]), (ThreadState::Running, 7));
}

#[test]
fn nbrecv_with_nothing_pending_returns_zeros_and_keeps_the_message_registers() {
    let mut w = World::new();
    w.set_mrs(A, [1, 2, 3, 4]);
    assert_eq!(w.syscall(A, 8, S_EP0, 0x5A5A, None), Outcome::Done);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (0, 0));
    assert_eq!(w.mrs(A), [1, 2, 3, 4]);
    // With a sender waiting it receives, and the sender goes on.
    w.send(B, S_EP0_BADGED, 4, 1, [44, 0, 0, 0]);
    w.nbrecv(A, S_EP0);
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (BADGE, info(4, 1)));
    assert_eq!(w.mrs(A)[0], 44);
    assert_eq!(w.state(B), ThreadState::Running);
}

// ---------------------------------------------------------------------------
// Call, Reply and ReplyRecv
// ---------------------------------------------------------------------------

#[test]
fn call_leaves_a_reply_capability_and_reply_consumes_it() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.set_mrs(A, [0xA0, 0xA1, 0xA2, 0xA3]);
    assert_eq!(w.call(A, S_EP0, 1, 2, [10, 20, 0xA2, 0xA3]), Outcome::Done);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert!(is_reply_to(w.caller_slot(B), A, true));
    assert_eq!(
        cdt::first_child(&w.k, tcb(A).slot(TCB_SLOT_REPLY)),
        Some(tcb(B).slot(TCB_SLOT_CALLER))
    );
    // The scheduler's tie rule runs the partner at once.
    assert_eq!(w.current(), Some(tcb(B)));
    assert_eq!((w.regs(B).rdi, w.regs(B).rsi), (0, info(1, 2)));
    assert_eq!(w.mrs(B)[..2], [10, 20]);

    let a_next = w.regs(A).next_ip;
    assert_eq!(w.reply(B, 9, 1, [99, 98, 97, 96]), Outcome::Done);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (0, info(9, 1)));
    assert_eq!(w.mrs(A), [99, 20, 0xA2, 0xA3]);
    assert!(w.caller_slot(B).is_null());
    assert_eq!(cdt::first_child(&w.k, tcb(A).slot(TCB_SLOT_REPLY)), None);
    // The replier goes on; the caller continues after its syscall.
    assert_eq!(w.current(), Some(tcb(B)));
    assert_eq!(w.state(B), ThreadState::Running);
    w.run(A);
    assert_eq!(w.regs(A).next_ip, a_next);
}

#[test]
fn a_queued_call_gets_a_reply_capability_with_the_receivers_grant() {
    let mut w = World::new();
    w.call(A, S_EP0, 1, 0, [0; 4]);
    assert!(matches!(
        w.state(A),
        ThreadState::BlockedOnSend { is_call: true, .. }
    ));
    // B receives through a capability without Grant.
    w.recv(B, S_EP0_R);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert!(is_reply_to(w.caller_slot(B), A, false));
    // And with Grant.
    w.reply(B, 0, 0, [0; 4]);
    w.call(C, S_EP0_WGR, 1, 0, [0; 4]);
    w.recv(B, S_EP0);
    assert!(is_reply_to(w.caller_slot(B), C, true));
}

#[test]
fn reply_recv_replies_then_receives() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    w.call(C, S_EP0, 2, 1, [22, 0, 0, 0]);
    assert!(matches!(w.state(C), ThreadState::BlockedOnSend { .. }));
    // B replies to A and takes C's call at once.
    assert_eq!(w.reply_recv(B, S_EP0, 5, 1, [55, 0, 0, 0]), Outcome::Done);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!((w.regs(A).rsi, w.mrs(A)[0]), (info(5, 1), 55));
    assert_eq!(w.state(B), ThreadState::Running);
    assert_eq!((w.regs(B).rsi, w.mrs(B)[0]), (info(2, 1), 22));
    assert_eq!(w.state(C), ThreadState::BlockedOnReply);
    assert!(is_reply_to(w.caller_slot(B), C, true));
    // With nothing waiting, ReplyRecv replies and blocks with an empty
    // caller slot.
    w.reply_recv(B, S_EP0, 6, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::Running);
    assert_eq!(w.regs(C).rsi, info(6, 0));
    assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
    assert!(w.caller_slot(B).is_null());
}

#[test]
fn a_restarted_reply_recv_is_harmless() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    w.reply_recv(B, S_EP0, 5, 1, [55, 0, 0, 0]);
    assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
    // C resumes B: it restarts and runs its ReplyRecv again.
    w.call(C, S_TCB + B as u64, tcb::label::RESUME, 0, [0; 4]);
    assert_eq!(w.state(B), ThreadState::Restart);
    w.run(B);
    assert_eq!(w.regs(B).next_ip, w.regs(B).fault_ip);
    let a = w.regs(A);
    w.syscall(B, 2, S_EP0, w.regs(B).rsi, None);
    assert_eq!(w.regs(A), a, "the restarted reply phase found no caller");
    assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
}

#[test]
fn receiving_again_before_replying_gives_up_the_reply() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    assert!(is_reply_to(w.caller_slot(B), A, true));
    w.recv(B, S_EP1);
    assert!(w.caller_slot(B).is_null());
    assert_eq!(
        w.state(A),
        ThreadState::BlockedOnReply,
        "the caller is left waiting"
    );
    assert_eq!(cdt::first_child(&w.k, tcb(A).slot(TCB_SLOT_REPLY)), None);
    // Only a suspend, a restart or a deletion frees it.
    w.call(C, S_TCB + A as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Inactive);
}

#[test]
fn reply_with_an_empty_caller_slot_does_nothing() {
    let mut w = World::new();
    let others: Vec<Regs> = (B..=F).map(|t| w.regs(t)).collect();
    assert_eq!(w.reply(A, 1, 1, [1, 2, 3, 4]), Outcome::Done);
    assert_eq!((B..=F).map(|t| w.regs(t)).collect::<Vec<_>>(), others);
    assert_eq!(w.state(A), ThreadState::Running);
    assert_eq!((w.regs(A).rdi, w.regs(A).rsi), (0, info(1, 1)), "preserved");
}

#[test]
fn a_server_can_call_another_while_it_holds_a_reply() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.recv(C, S_EP1);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    // B, holding the reply to A, calls C.
    w.call(B, S_EP1, 2, 0, [0; 4]);
    assert!(
        is_reply_to(w.caller_slot(B), A, true),
        "Call leaves its own caller slot"
    );
    assert!(is_reply_to(w.caller_slot(C), B, true));
    assert_eq!(w.current(), Some(tcb(C)));
    w.reply(C, 3, 1, [33, 0, 0, 0]);
    assert_eq!((w.state(B), w.mrs(B)[0]), (ThreadState::Running, 33));
    w.run(B);
    w.reply(B, 4, 1, [44, 0, 0, 0]);
    assert_eq!((w.state(A), w.mrs(A)[0]), (ThreadState::Running, 44));
}

#[test]
fn send_and_call_on_a_saved_reply_capability_reply() {
    // A reply capability moved into a CSpace slot, as M6's
    // `CNode_SaveCaller` does.
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    let saved = rs(S_FREE);
    let cap = w.caller_slot(B);
    cdt::move_slot(&mut w.k, cap, tcb(B).slot(TCB_SLOT_CALLER), saved);
    w.check();
    // B receives again: a saved reply capability survives.
    w.recv(B, S_EP1);
    assert_eq!(w.cap(saved), cap);
    assert_eq!(w.send(C, S_FREE, 7, 1, [77, 0, 0, 0]), Outcome::Done);
    assert_eq!((w.state(A), w.mrs(A)[0]), (ThreadState::Running, 77));
    assert!(w.cap(saved).is_null());
    // `Call` on one also gets an empty kernel reply.
    w.run(D);
    w.recv(D, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    let cap = w.caller_slot(D);
    cdt::move_slot(&mut w.k, cap, tcb(D).slot(TCB_SLOT_CALLER), saved);
    w.call(C, S_FREE, 8, 1, [88, 0, 0, 0]);
    assert_eq!((w.state(A), w.mrs(A)[0]), (ThreadState::Running, 88));
    assert_eq!((w.regs(C).rdi, w.regs(C).rsi), (0, 0));
    assert_eq!(w.state(C), ThreadState::Running);
}

// ---------------------------------------------------------------------------
// Rights
// ---------------------------------------------------------------------------

#[test]
fn call_needs_write_and_grant_or_grant_reply() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    // Write only: InvalidCapability 0, nothing sent.
    assert_eq!(w.call(A, S_EP0_W, 1, 1, [5, 0, 0, 0]), Outcome::Done);
    assert_eq!(
        (w.regs(A).rdi, w.regs(A).rsi, w.mrs(A)[0]),
        (0, info(2, 1), 0)
    );
    assert_eq!(w.state(A), ThreadState::Running);
    assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
    // Read only: the same.
    w.call(A, S_EP0_R, 1, 1, [5, 0, 0, 0]);
    assert_eq!((w.regs(A).rsi, w.mrs(A)[0]), (info(2, 1), 0));
    assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
    // Write and GrantReply: sent.
    w.call(A, S_EP0_WGR, 1, 1, [5, 0, 0, 0]);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert_eq!(w.mrs(B)[0], 5);
}

#[test]
fn send_needs_write_but_no_grant() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    // Without Write nothing happens, and the registers are kept.
    w.send(A, S_EP0_R, 1, 1, [5, 0, 0, 0]);
    assert_eq!((w.regs(A).rsi, w.mrs(A)[0]), (info(1, 1), 5));
    w.nbsend(A, S_EP0_R, 1, 1, [5, 0, 0, 0]);
    assert!(matches!(w.state(B), ThreadState::BlockedOnReceive { .. }));
    // Write alone sends.
    w.send(A, S_EP0_W, 1, 1, [6, 0, 0, 0]);
    assert_eq!((w.state(B), w.mrs(B)[0]), (ThreadState::Running, 6));
}

#[test]
fn receiving_needs_read() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP1);
    w.recv(D, S_EP1);
    assert_eq!(w.recv(A, S_EP0_W), Outcome::Done);
    assert!(matches!(w.state(A), ThreadState::BlockedOnReply));
    assert_eq!(w.regs(D).rsi, info(1, 5));
    assert_eq!(
        (0..5).map(|i| w.mr(D, i)).collect::<Vec<_>>(),
        [w.regs(A).fault_ip, S_EP0_W, 1, 2, 0]
    );
}

// ---------------------------------------------------------------------------
// Cancellation
// ---------------------------------------------------------------------------

#[test]
fn suspend_takes_a_thread_out_of_its_queue_and_resume_restarts_it() {
    let mut w = World::new();
    for t in [B, C, D] {
        w.send(t, S_EP0, t as u64, 0, [0; 4]);
    }
    assert_eq!(w.queue(0), [tcb(B), tcb(C), tcb(D)]);
    w.call(E, S_TCB + C as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::Inactive);
    assert_eq!(w.queue(0), [tcb(B), tcb(D)]);
    w.call(E, S_TCB + C as u64, tcb::label::RESUME, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::Restart);
    // C runs its Send again, after D.
    w.run(C);
    assert_eq!(w.regs(C).next_ip, w.regs(C).fault_ip);
    w.syscall(C, 3, S_EP0, w.regs(C).rsi, None);
    assert_eq!(w.queue(0), [tcb(B), tcb(D), tcb(C)]);
    // Receivers too; the endpoint becomes Idle when its last one leaves.
    for t in [B, D, C] {
        w.call(E, S_TCB + t as u64, tcb::label::SUSPEND, 0, [0; 4]);
    }
    assert_eq!(w.endpoint(0), Endpoint::IDLE);
    for t in [B, C] {
        w.call(E, S_TCB + t as u64, tcb::label::RESUME, 0, [0; 4]);
        w.run(t);
        w.recv(t, S_EP0);
    }
    assert_eq!(w.queue(0), [tcb(B), tcb(C)]);
    w.call(E, S_TCB + B as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.queue(0), [tcb(C)]);
    w.call(E, S_TCB + C as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.endpoint(0), Endpoint::IDLE);
}

#[test]
fn suspending_a_caller_deletes_the_reply_capability_to_it() {
    let mut w = World::new();
    w.recv(B, S_EP0);
    w.call(A, S_EP0, 1, 0, [0; 4]);
    w.call(C, S_TCB + A as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert!(w.caller_slot(B).is_null());
    // B's reply now does nothing.
    let a = w.regs(A);
    w.run(B);
    w.reply(B, 1, 1, [1, 0, 0, 0]);
    assert_eq!(w.regs(A), a);
    // Resuming a caller restarts its Call.
    w.recv(B, S_EP0);
    w.run(C);
    w.call(C, S_TCB + A as u64, tcb::label::RESUME, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Restart);
    w.run(A);
    w.syscall(A, 1, S_EP0, info(1, 0), None);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert!(is_reply_to(w.caller_slot(B), A, true));
    // Resume of a thread waiting for its reply cancels it too.
    w.run(C);
    w.call(C, S_TCB + A as u64, tcb::label::RESUME, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Restart);
    assert!(w.caller_slot(B).is_null());
}

#[test]
fn deleting_an_endpoint_restarts_every_queued_thread_in_order() {
    let mut w = World::new();
    for t in [B, C, D] {
        w.send(t, S_EP2, t as u64, 0, [0; 4]);
    }
    w.call(E, S_EP2, 9, 0, [0; 4]);
    assert_eq!(w.queue(2), [tcb(B), tcb(C), tcb(D), tcb(E)]);
    assert_eq!(w.ready(), [tcb(A)]);
    // F deletes the endpoint's only capability.
    assert_eq!(w.current(), Some(tcb(F)));
    assert_eq!(
        w.call(
            F,
            S_ROOT,
            crate::invoke::label::CNODE_DELETE,
            2,
            [S_EP2, 64, 0, 0]
        ),
        Outcome::Done
    );
    assert_eq!(w.regs(F).rsi, info(0, 0));
    assert_eq!(w.endpoint(2), Endpoint::IDLE);
    for t in [B, C, D, E] {
        assert_eq!(w.state(t), ThreadState::Restart);
        assert_eq!(w.k.ep_links(tcb(t)), (None, None));
    }
    // They joined the ready queue in queue order, and F goes on.
    assert_eq!(w.current(), Some(tcb(F)));
    assert_eq!(w.ready(), [A, B, C, D, E].map(tcb));
    // Each re-executes its system call: a Send to the now empty slot does
    // nothing, a Call gets InvalidCapability.
    w.run(B);
    assert_eq!(w.regs(B).next_ip, w.regs(B).fault_ip);
    w.syscall(B, 3, S_EP2, w.regs(B).rsi, None);
    assert_eq!(w.state(B), ThreadState::Running);
    w.run(E);
    w.syscall(E, 1, S_EP2, w.regs(E).rsi, None);
    assert_eq!((w.regs(E).rsi, w.mrs(E)[0]), (info(2, 1), 0));
}

#[test]
fn deleting_an_endpoint_restarts_its_receivers() {
    let mut w = World::new();
    w.recv(B, S_EP2);
    w.recv(C, S_EP2);
    w.call(
        A,
        S_ROOT,
        crate::invoke::label::CNODE_DELETE,
        2,
        [S_EP2, 64, 0, 0],
    );
    assert_eq!(w.endpoint(2), Endpoint::IDLE);
    assert_eq!(
        (w.state(B), w.state(C)),
        (ThreadState::Restart, ThreadState::Restart)
    );
    // A receive on the empty slot is a capability fault; B has no handler.
    w.run(B);
    let out = w.syscall(B, 5, S_EP2, 0, None);
    assert!(matches!(out, Outcome::Stopped(_)));
    assert_eq!(w.state(B), ThreadState::Inactive);
}

// ---------------------------------------------------------------------------
// Fault delivery and fault replies
// ---------------------------------------------------------------------------

/// A takes a page fault with handler D waiting on EP1; D runs next.
fn page_fault_received(w: &mut World) -> u64 {
    w.set_fault_ep(A, S_EP1);
    w.recv(D, S_EP1);
    let ip = w.regs(A).next_ip;
    assert_eq!(w.exception(A, 14, 0x14, 0xDEAD_0000), Outcome::Done);
    assert_eq!(w.current(), Some(tcb(D)));
    ip
}

#[test]
fn a_page_fault_reaches_a_waiting_handler_and_a_label_0_reply_restarts() {
    let mut w = World::new();
    let ip = page_fault_received(&mut w);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert_eq!(
        w.k.fault(tcb(A)),
        Some(Fault::VmFault {
            addr: 0xDEAD_0000,
            fsr: 0x14
        })
    );
    assert_eq!((w.regs(D).rdi, w.regs(D).rsi), (0, info(5, 4)));
    assert_eq!(w.mrs(D), [ip, 0xDEAD_0000, 1, 0x14]);
    assert!(is_reply_to(w.caller_slot(D), A, true));

    assert_eq!(w.reply(D, 0, 0, [0; 4]), Outcome::Done);
    assert_eq!(w.state(A), ThreadState::Restart);
    assert_eq!(w.k.fault(tcb(A)), None);
    assert!(w.caller_slot(D).is_null());
    w.run(A);
    assert_eq!(w.regs(A).next_ip, ip, "the faulting instruction runs again");
    assert_eq!(w.regs(A).exit(), Exit::Iret);
}

#[test]
fn a_fault_reply_with_another_label_stops_the_thread() {
    let mut w = World::new();
    page_fault_received(&mut w);
    w.reply(D, 1, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert_eq!(w.k.fault(tcb(A)), None);
}

#[test]
fn a_fault_waits_for_its_handler() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP0_BADGED);
    let ip = w.regs(A).next_ip;
    w.exception(A, 3, 0, 0);
    assert_eq!(
        w.state(A),
        ThreadState::BlockedOnSend {
            ep: ep(0),
            badge: BADGE,
            can_grant: true,
            can_grant_reply: true,
            is_call: true
        }
    );
    w.recv(D, S_EP0);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert_eq!((w.regs(D).rdi, w.regs(D).rsi), (BADGE, info(3, 5)));
    let a = w.regs(A);
    assert_eq!(w.mrs(D), [ip, a.rsp, a.rflags, 3]);
    assert_eq!(w.mr(D, 4), 0, "#BP has no error code");
}

#[test]
fn an_unknown_syscall_sends_every_register_and_its_reply_writes_them() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP1);
    w.recv(D, S_EP1);
    let mut regs = w.regs(A);
    for (i, r) in crate::regs::UserReg::ALL[3..18].iter().enumerate() {
        regs.set_user(*r, 0x1000 + i as u64);
    }
    regs.rsp = 0x7000_0000;
    w.k.set_regs(tcb(A), &regs);
    let ip = w.regs(A).next_ip;
    w.enter(A, 9, 0x1005, 0x1004, Some([0x1009, 0x1007, 0x1008, 0x100E]));
    w.exit();
    let a = w.regs(A);
    assert_eq!(w.state(A), ThreadState::BlockedOnReply);
    assert_eq!(w.regs(D).rsi, info(2, 19));
    let expect = [
        a.rax,
        a.rbx,
        ip + 2,
        9,
        0x1004,
        0x1005,
        a.rbp,
        0x1007,
        0x1008,
        0x1009,
        a.rflags,
        a.r12,
        a.r13,
        a.r14,
        0x100E,
        ip,
        0x7000_0000,
        a.rflags,
        9,
    ];
    assert_eq!((0..19).map(|i| w.mr(D, i)).collect::<Vec<_>>(), expect);

    // The reply sets the first 18 registers, sanitised, whatever its
    // label, and skips the syscall.
    let mut reply = [0u64; 18];
    for (i, v) in reply.iter_mut().enumerate() {
        *v = 0x2000 + i as u64;
    }
    reply[15] = ip + 2;
    reply[16] = 1 << 47;
    reply[17] = u64::MAX;
    for (i, v) in reply.iter().enumerate().skip(4) {
        w.set_buf(D, word::MSG + i, *v);
    }
    w.reply(D, 0, 18, [reply[0], reply[1], reply[2], reply[3]]);
    assert_eq!(w.state(A), ThreadState::Restart);
    w.run(A);
    let a = w.regs(A);
    assert_eq!(
        (a.rax, a.rbx, a.rcx, a.rdx),
        (0x2000, 0x2001, 0x2002, 0x2003)
    );
    assert_eq!((a.r14, a.r15), (0x200D, 0x200E));
    assert_eq!(a.next_ip, ip + 2);
    assert_eq!(a.rsp, 0, "a non-canonical rsp is written as 0");
    assert_eq!(a.rflags, 0x0CD5 | 0x0202, "rflags is sanitised");
    assert_eq!(a.exit(), Exit::Iret);
}

#[test]
fn a_handler_without_a_writable_buffer_gets_four_words() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP1);
    w.recv(F, S_EP1);
    w.syscall(A, 0, 0, 0, None);
    assert_eq!(w.regs(F).rsi, info(2, 4));
    // Its reply sets only what its registers carry.
    let before = w.regs(A);
    w.reply(F, 1, 18, [0x51, 0x52, 0x53, 0x54]);
    assert_eq!(w.state(A), ThreadState::Inactive);
    let a = w.regs(A);
    assert_eq!((a.rax, a.rbx, a.rcx, a.rdx), (0x51, 0x52, 0x53, 0x54));
    assert_eq!((a.rsi, a.rdi), (before.rsi, before.rdi));
}

#[test]
fn a_user_exception_reply_sets_rip_rsp_and_rflags() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP1);
    w.recv(D, S_EP1);
    let ip = w.regs(A).next_ip;
    w.exception(A, 13, 0x18, 0);
    assert_eq!(w.regs(D).rsi, info(3, 5));
    assert_eq!((w.mr(D, 3), w.mr(D, 4)), (13, 0x18));
    w.reply(D, 0, 3, [0x40_8000, 0x7FFF_0000, 0x1 | 0x100, 0x5555]);
    w.run(A);
    let a = w.regs(A);
    assert_eq!((a.next_ip, a.fault_ip), (0x40_8000, 0x40_8000));
    assert_eq!(a.rsp, 0x7FFF_0000);
    assert_eq!(a.rflags, 0x0203, "TF cleared, IF set");
    assert_ne!(a.r15, 0x5555, "only three registers");
    assert_ne!(ip, a.next_ip);
}

#[test]
fn a_cap_fault_carries_the_lookup_failure() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP1);
    w.recv(D, S_EP1);
    let ip = w.regs(A).next_ip;
    assert_eq!(w.send(A, BAD_CPTR, 0, 0, [0; 4]), Outcome::Done);
    assert_eq!(w.regs(D).rsi, info(1, 7));
    assert_eq!(
        (0..7).map(|i| w.mr(D, i)).collect::<Vec<_>>(),
        [ip, BAD_CPTR, 0, 4, 64, 0, 59]
    );
    assert_eq!(
        w.k.fault(tcb(A)),
        Some(Fault::CapFault {
            addr: BAD_CPTR,
            in_recv_phase: false,
            failure: BAD_CPTR_FAILURE
        })
    );
    // A reply restarts it through `iretq`, though it entered by `syscall`
    // and the reply set no register.
    w.reply(D, 0, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Restart);
    assert_eq!(w.regs(A).exit(), Exit::Iret);
    // A receive on an empty slot: MissingCapability in the receive phase.
    w.recv(D, S_EP1);
    w.recv(A, S_FREE);
    assert_eq!(w.regs(D).rsi, info(1, 5));
    assert_eq!(
        (0..5).map(|i| w.mr(D, i)).collect::<Vec<_>>(),
        [w.regs(A).fault_ip, S_FREE, 1, 2, 0]
    );
}

#[test]
fn a_fault_without_a_suitable_handler_stops_the_thread() {
    // Slot 0 is empty; then capabilities that are no endpoint or lack a
    // right; then a pointer that does not resolve.
    let handlers = [
        (
            0,
            crate::error::LookupFailure::MissingCapability { bits_left: 0 },
        ),
        (
            S_EP0_R,
            crate::error::LookupFailure::MissingCapability { bits_left: 0 },
        ),
        (
            S_EP0_W,
            crate::error::LookupFailure::MissingCapability { bits_left: 0 },
        ),
        (
            S_TCB,
            crate::error::LookupFailure::MissingCapability { bits_left: 0 },
        ),
        (BAD_CPTR, BAD_CPTR_FAILURE),
    ];
    for (cptr, failure) in cases(&handlers) {
        let mut w = World::new();
        w.set_fault_ep(B, cptr);
        let fault = Fault::VmFault { addr: 0x10, fsr: 4 };
        let out = w.exception(B, 14, 4, 0x10);
        assert_eq!(
            out,
            Outcome::Stopped(DoubleFault {
                thread: tcb(B),
                fault,
                handler: Fault::CapFault {
                    addr: cptr,
                    in_recv_phase: false,
                    failure
                }
            }),
            "fault_ep {cptr:#x}"
        );
        assert_eq!(w.state(B), ThreadState::Inactive);
        assert_eq!(w.k.fault(tcb(B)), None, "no fault is stored");
        assert!(w.endpoint(0).state == EpState::Idle);
    }
    // Write and GrantReply suffice.
    let mut w = World::new();
    w.set_fault_ep(B, S_EP0_WGR);
    assert_eq!(w.exception(B, 14, 4, 0x10), Outcome::Done);
    assert!(matches!(w.state(B), ThreadState::BlockedOnSend { .. }));
}

#[test]
fn a_handler_that_deletes_the_faulting_thread_leaves_nothing_naming_it() {
    let mut w = World::new();
    page_fault_received(&mut w);
    // D deletes A's only TCB capability.
    w.threads.retain(|t| *t != tcb(A));
    assert_eq!(
        w.call(
            D,
            S_ROOT,
            crate::invoke::label::CNODE_DELETE,
            2,
            [S_TCB, 64, 0, 0]
        ),
        Outcome::Done
    );
    assert_eq!(w.regs(D).rsi, info(0, 0));
    assert!(
        w.caller_slot(D).is_null(),
        "the reply capability went with A"
    );
    for s in 0..TCB_SLOTS {
        assert!(w.cap(tcb(A).slot(s)).is_null(), "slot {s}");
    }
    assert!(w.cap(rs(S_TCB)).is_null());
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert!(!w.ready().contains(&tcb(A)));
    assert_ne!(w.current(), Some(tcb(A)));
    assert!(!w.queue(1).contains(&tcb(A)));
    // D's reply finds nothing.
    w.reply(D, 0, 0, [0; 4]);
    w.check();
}

#[test]
fn a_handler_that_suspends_the_faulting_thread_cancels_its_reply() {
    let mut w = World::new();
    let ip = page_fault_received(&mut w);
    w.call(D, S_TCB + A as u64, tcb::label::SUSPEND, 0, [0; 4]);
    assert_eq!(w.state(A), ThreadState::Inactive);
    assert_eq!(w.k.fault(tcb(A)), None);
    assert!(w.caller_slot(D).is_null());
    // Resumed, it runs the faulting instruction again.
    w.call(D, S_TCB + A as u64, tcb::label::RESUME, 0, [0; 4]);
    w.run(A);
    assert_eq!(w.regs(A).next_ip, ip);
}

#[test]
fn deleting_the_fault_endpoint_restarts_the_thread_which_faults_again_without_it() {
    let mut w = World::new();
    w.set_fault_ep(A, S_EP2);
    w.exception(A, 6, 0, 0);
    assert!(matches!(w.state(A), ThreadState::BlockedOnSend { .. }));
    assert!(w.k.fault(tcb(A)).is_some());
    w.call(
        D,
        S_ROOT,
        crate::invoke::label::CNODE_DELETE,
        2,
        [S_EP2, 64, 0, 0],
    );
    assert_eq!(w.state(A), ThreadState::Restart);
    assert_eq!(w.k.fault(tcb(A)), None);
    // The #UD happens again and finds no handler.
    w.run(A);
    let out = w.exception(A, 6, 0, 0);
    assert!(matches!(out, Outcome::Stopped(DoubleFault { .. })));
    assert_eq!(w.state(A), ThreadState::Inactive);
}

// ---------------------------------------------------------------------------
// Priorities
// ---------------------------------------------------------------------------

#[test]
fn queues_are_fifo_whatever_the_priority() {
    let mut w = World::new();
    w.send(C, S_EP0, 3, 0, [0; 4]);
    w.set_prio(B, 150);
    assert_eq!(w.current(), Some(tcb(B)));
    w.send(B, S_EP0, 2, 0, [0; 4]);
    assert_eq!(w.queue(0), [tcb(C), tcb(B)]);
    // The first sender is served first.
    w.run(D);
    w.recv(D, S_EP0);
    assert_eq!(w.regs(D).rsi, info(3, 0));
    // An equal-priority thread woken by a receive does not preempt it.
    assert_eq!(w.current(), Some(tcb(D)));
    assert_eq!(w.state(C), ThreadState::Running);
    // A higher-priority one does.
    w.recv(D, S_EP0);
    assert_eq!(w.regs(D).rsi, info(2, 0));
    assert_eq!(w.current(), Some(tcb(B)));
}

#[test]
fn a_partner_below_the_highest_ready_priority_waits_its_turn() {
    let mut w = World::new();
    // B waits on EP1, and drops to 50 while blocked.
    w.recv(B, S_EP1);
    w.set_prio(B, 50);
    // C's Call wakes B, but the threads at 100 run first.
    w.run(C);
    w.call(C, S_EP1, 1, 0, [0; 4]);
    assert_eq!(w.state(C), ThreadState::BlockedOnReply);
    assert_eq!(w.state(B), ThreadState::Running);
    let cur = w.current().unwrap();
    assert_ne!(cur, tcb(B));
    assert_eq!(w.k.priority(cur), 100);
    assert_eq!(w.k.sched.head(50), Some(tcb(B)));
    // An equal-priority receiver woken by a Send does not preempt the
    // sender.
    w.recv(D, S_EP0);
    w.run(E);
    w.send(E, S_EP0, 1, 0, [0; 4]);
    assert_eq!(w.state(D), ThreadState::Running);
    assert_eq!(w.current(), Some(tcb(E)));
}

// ---------------------------------------------------------------------------
// The invariant checker
// ---------------------------------------------------------------------------

/// A test that breaks one invariant: its name and what it does.
type Breakage = (&'static str, fn(&mut World));

#[test]
fn check_finds_broken_states() {
    let eps = World::eps();
    let breakages: [Breakage; 6] = [
        ("Recv with an empty queue", |w| {
            w.k.set_endpoint_word(ep(0), ep_field::STATE, EpState::Recv as u64)
        }),
        ("blocked but not queued", |w| {
            w.k.set_state(
                tcb(B),
                ThreadState::BlockedOnReceive {
                    ep: ep(0),
                    can_grant: false,
                },
            )
        }),
        ("a fault on a running thread", |w| {
            w.k.set_fault(tcb(B), Some(Fault::VmFault { addr: 0, fsr: 0 }))
        }),
        ("a reply capability to a running thread", |w| {
            let master = tcb(A).slot(TCB_SLOT_REPLY);
            let to = tcb(B).slot(TCB_SLOT_CALLER);
            cdt::insert_derived(
                &mut w.k,
                master,
                to,
                Cap::reply(tcb(A).get(), false, true),
                false,
            )
            .unwrap();
        }),
        ("a receiver with a reply capability", |w| {
            w.recv(B, S_EP0);
            w.k.set_state(tcb(A), ThreadState::BlockedOnReply);
            let master = tcb(A).slot(TCB_SLOT_REPLY);
            let to = tcb(B).slot(TCB_SLOT_CALLER);
            cdt::insert_derived(
                &mut w.k,
                master,
                to,
                Cap::reply(tcb(A).get(), false, true),
                false,
            )
            .unwrap();
        }),
        ("a missing master", |w| {
            crate::cdt::unlink_and_clear(&mut w.k, tcb(C).slot(TCB_SLOT_REPLY))
        }),
    ];
    for (what, breaks) in breakages {
        let mut w = World::new();
        breaks(&mut w);
        assert!(check(&w.k, &w.threads, &eps).is_err(), "{what}");
    }
    // A queue that runs back on itself is a cycle.
    let mut w = World::new();
    w.send(B, S_EP0, 0, 0, [0; 4]);
    w.send(C, S_EP0, 0, 0, [0; 4]);
    w.k.set_ep_next(tcb(C), Some(tcb(B)));
    w.k.set_ep_prev(tcb(B), Some(tcb(C)));
    assert!(check(&w.k, &w.threads, &eps).is_err());
}
