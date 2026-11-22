//! `test=captransfer`: capabilities sent through an endpoint and used by
//! the server that receives them (PLAN.md, M6's done-when; `docs/abi.md`,
//! "Capability transfer").
//!
//! The root task is the client C. It retypes endpoints E and E2, frames F
//! and F2, and the server S: a TCB at [`SERVER_PRIORITY`] with an IPC buffer
//! in the second KiB of the root task's buffer frame and a CSpace of its
//! own, a 64-slot CNode that holds E with Read and Grant, E with Read only,
//! the CNode itself and the root task's VSpace, which S shares. So S can
//! use only what C gave it at the start and what it receives. C maps F at
//! [`CLIENT_PAGE`] and writes [`ct::MAGIC`] there.
//!
//! C then makes one `Call` on E per step of [`ct::STEPS`], and S, which
//! names the step's receive slot first, answers each with a report of what
//! it saw: the `MessageInfo` and badge it received, its `caps_or_badges`,
//! which of its receive slots hold a capability ([`occupied`]) and the word
//! it read from the frame it received, mapped at [`SERVER_PAGE`]. In
//! order, the steps show that:
//!
//! - an endpoint capability arrives in S's slot, keeps its badge, and S
//!   calls C back through it;
//! - a frame capability arrives, and S maps it and reads what C wrote;
//! - without Grant nothing moves, not even a capability to E;
//! - capabilities to E arrive unwrapped as their badges, 0 included,
//!   whatever their rights, and do not use the slot;
//! - an occupied receive slot ends the transfer, and one message copies at
//!   most one capability;
//! - a reply carries a capability (S's capability to E, copied, not
//!   unwrapped) only through a reply capability with Grant, which a call
//!   received through E with Grant gives and one received through E
//!   without Grant does not;
//! - the copies are derived as `CNode_Copy` would place them: C revokes
//!   and deletes the frame copy it sent and S's copy, its sibling, still
//!   maps the frame; C revokes F and its E2 capability, and S's copies,
//!   their children, are gone, S's mapping with them.

use core::fmt;

use libsys::bootinfo::{CAP_INIT_TCB, CAP_INIT_VSPACE};
use libsys::invoke::{
    Slot, cnode_copy, cnode_delete, cnode_mint, cnode_move, cnode_revoke, invoke, tcb_resume,
    tcb_set_priority,
};
use libsys::{
    BootInfo, CPtr, Error, Ipc, LookupFailure, Message, MessageInfo, ObjectAlloc, ObjectType,
    ReceivedCaps, Rights, SyscallError, call, nb_recv, println, recv, reply,
};
use root::check::captransfer::{
    self as ct, Action, Before, PROBED, REPORT_WORDS, Report, S_GUARD_BITS, S_RADIX, SENTINELS,
    STEPS, Sent, Step, Via, s_slot,
};

use crate::fail;
use crate::spawn::{self, STACKS, Space, Thread};

/// Where C maps F, and where S maps its copy, under the root task's page
/// table, which covers the 2 MiB from 0x400000, above its image.
const CLIENT_PAGE: u64 = 0x50_1000;
const SERVER_PAGE: u64 = 0x50_2000;
/// S's priority, below the root task's 255.
const SERVER_PRIORITY: u64 = 200;

/// Labels (`docs/abi.md`, "Invocation labels").
const FRAME_MAP: u64 = 0x50;
const FRAME_UNMAP: u64 = 0x51;
/// Rights words (`docs/abi.md`, "Rights word").
const READ: u64 = Rights::READ.0 as u64;
const READ_WRITE: u64 = (Rights::READ.0 | Rights::WRITE.0) as u64;
/// Write-back, no-execute (`docs/abi.md`, "Attributes word").
const RAM: u64 = 0;

/// C's capabilities, slots of the root task's CNode.
struct Caps {
    ep: CPtr,
    ep_no_grant: CPtr,
    ep_badged: CPtr,
    e2: CPtr,
    e2_badged: CPtr,
    f: CPtr,
    f_copy: CPtr,
    f2: CPtr,
}

impl Caps {
    fn via(&self, v: Via) -> CPtr {
        match v {
            Via::Grant => self.ep,
            Via::NoGrant => self.ep_no_grant,
        }
    }

    fn sent(&self, s: Sent) -> CPtr {
        match s {
            Sent::E2 => self.e2_badged,
            Sent::FrameCopy => self.f_copy,
            Sent::Frame2 => self.f2,
            Sent::EpBadged => self.ep_badged,
            Sent::EpUnbadged => self.ep_no_grant,
        }
    }
}

fn root_slot(n: CPtr) -> Slot {
    Slot::root_cnode(n)
}

/// A slot of S's CNode, named from S's own capability to it.
fn server_slot(n: u64) -> Slot {
    Slot::new(s_slot::CNODE, n, S_RADIX)
}

/// Whether `slot` holds a capability, without changing it: `CNode_Move`
/// of a slot onto itself is `DeleteFirst` if the destination holds one,
/// and otherwise reaches the empty source, `FailedLookup` of the source
/// with `MissingCapability` and 0 bits left (`docs/abi.md`, `CNode_Copy`'s
/// errors, which `CNode_Move` checks in the same order).
fn occupied(ipc: Ipc, slot: Slot) -> Result<bool, Error> {
    let empty = SyscallError::FailedLookup {
        source: true,
        failure: LookupFailure::MissingCapability { bits_left: 0 },
    };
    match cnode_move(ipc, slot, slot) {
        Err(e) if e.kernel() == Some(SyscallError::DeleteFirst) => Ok(true),
        Err(e) if e.kernel() == Some(empty) => Ok(false),
        Err(e) => Err(e),
        Ok(()) => Err(Error::Kernel(SyscallError::IllegalOperation)),
    }
}

/// Fails unless `slot`, in the root task's CNode, is full exactly when
/// `want` says.
fn expect_occupied(ipc: Ipc, slot: CPtr, want: bool, what: &str) {
    match occupied(ipc, root_slot(slot)) {
        Ok(full) if full == want => {}
        Ok(full) => fail!(
            "captransfer: {what}: slot {slot} is {}",
            if full { "full" } else { "empty" }
        ),
        Err(e) => fail!("captransfer: {what}: probing slot {slot}: {e}"),
    }
}

/// `Frame_Map` of `frame` at `page` in the root task's VSpace.
fn map(ipc: Ipc, frame: CPtr, page: u64, rights: u64) -> Result<(), Error> {
    invoke(
        Some(ipc),
        frame,
        FRAME_MAP,
        &[page, rights, RAM],
        &[CAP_INIT_VSPACE],
    )
    .map(|_| ())
}

/// The word at `page`.
fn read(page: u64) -> u64 {
    // SAFETY: the caller has mapped a frame at `page`, readable, in the
    // VSpace every thread here shares; the frame holds only what this test
    // wrote.
    unsafe { core::ptr::read_volatile(page as *const u64) }
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mapped = bi.user_image_start..bi.user_image_end + 0x3000;
    for page in [CLIENT_PAGE, SERVER_PAGE] {
        if mapped.contains(&page) || page >> 21 != bi.user_image_start >> 21 {
            fail!("captransfer: {page:#x} is not a free page under the root task's page table");
        }
    }
    let buffer = spawn::root_frame_buffer(bi, 1).unwrap_or_else(|| {
        fail!(
            "captransfer: the root task's IPC buffer {:#x} is not at the start of its frame",
            bi.ipc_buffer
        )
    });
    let mut objects = ObjectAlloc::new(bi);
    let mut retype = |ty, size_bits, count, what| {
        objects
            .retype(ipc, ty, size_bits, count)
            .unwrap_or_else(|e| fail!("captransfer: retyping {what}: {e}"))
    };
    let eps = retype(ObjectType::Endpoint, 0, 2, "E and E2");
    let frames = retype(ObjectType::Frame4K, 0, 2, "F and F2");
    let cnode = retype(ObjectType::CNode, S_RADIX, 1, "S's CNode");
    let tcb = retype(ObjectType::Tcb, 0, 1, "S's TCB");
    let mine = objects
        .slots
        .alloc(6)
        .unwrap_or_else(|| fail!("captransfer: no free slots"));
    let caps = Caps {
        ep: eps,
        ep_no_grant: mine,
        ep_badged: mine + 1,
        e2: eps + 1,
        e2_badged: mine + 2,
        f: frames,
        f_copy: mine + 3,
        f2: frames + 1,
    };
    // C's receive slots for steps 6 and 7.
    let reply_slots = [mine + 4, mine + 5];

    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    let s = |n| Slot::new(cnode, n, S_RADIX);
    let setup = [
        (
            "E without Grant",
            root_slot(caps.ep_no_grant),
            caps.ep,
            w_gr,
            None,
        ),
        (
            "E with a badge and no rights",
            root_slot(caps.ep_badged),
            caps.ep,
            Rights::NONE,
            Some(ct::UNWRAP_BADGE),
        ),
        (
            "E2 with a badge",
            root_slot(caps.e2_badged),
            caps.e2,
            w_gr,
            Some(ct::E2_BADGE),
        ),
        (
            "a copy of F",
            root_slot(caps.f_copy),
            caps.f,
            Rights::ALL,
            None,
        ),
        (
            "S's E with Read and Grant",
            s(s_slot::EP),
            caps.ep,
            Rights(Rights::READ.0 | Rights::GRANT.0),
            None,
        ),
        (
            "S's E with Read",
            s(s_slot::EP_NO_GRANT),
            caps.ep,
            Rights::READ,
            None,
        ),
        ("S's CNode", s(s_slot::CNODE), cnode, Rights::ALL, None),
        (
            "S's VSpace",
            s(s_slot::VSPACE),
            CAP_INIT_VSPACE,
            Rights::ALL,
            None,
        ),
    ];
    for (what, dest, src, rights, badge) in setup {
        let r = match badge {
            Some(b) => cnode_mint(ipc, dest, root_slot(src), rights, b),
            None => cnode_copy(ipc, dest, root_slot(src), rights),
        };
        r.unwrap_or_else(|e| fail!("captransfer: making {what}: {e}"));
    }
    map(ipc, caps.f, CLIENT_PAGE, READ_WRITE)
        .unwrap_or_else(|e| fail!("captransfer: mapping F: {e}"));
    // SAFETY: F is mapped read-write at CLIENT_PAGE, and nothing else
    // uses it.
    unsafe { core::ptr::write_volatile(CLIENT_PAGE as *mut u64, ct::MAGIC) };

    let t = Thread {
        tcb,
        fault_ep: 0,
        stack: STACKS[0],
        entry: server,
        args: [buffer.addr, 0, 0, 0],
    };
    let space = Space {
        cspace: cnode,
        // Guard 0 of S_GUARD_BITS bits (`docs/abi.md`, "Capability data").
        cspace_data: S_GUARD_BITS,
        buffer: Some(buffer),
    };
    spawn::prepare_with(ipc, &t, space)
        .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, SERVER_PRIORITY))
        .and_then(|()| tcb_resume(tcb))
        .unwrap_or_else(|e| fail!("captransfer: starting the server: {e}"));
    println!(
        "captransfer: server S (TCB slot {tcb}, priority {SERVER_PRIORITY}) has a CSpace of its own, a {}-slot CNode in slot {cnode} with E with Read and Grant, E with Read, the CNode itself and the root task's VSpace",
        1u64 << S_RADIX
    );
    println!(
        "captransfer: client C, the root task, calls E (slot {}); it holds E2 (slot {}), F (slot {}, mapped at {CLIENT_PAGE:#x}, holding {:#x}) and F2 (slot {})",
        caps.ep,
        caps.e2,
        caps.f,
        ct::MAGIC,
        caps.f2
    );

    let mut next_reply_slot = reply_slots.iter();
    for (i, step) in STEPS.iter().enumerate() {
        match step.before {
            Before::Nothing => {}
            Before::DropSentCopy => cnode_revoke(root_slot(caps.f_copy))
                .and_then(|()| cnode_delete(root_slot(caps.f_copy)))
                .unwrap_or_else(|e| fail!("captransfer: dropping the frame copy: {e}")),
            Before::RevokeOriginals => cnode_revoke(root_slot(caps.f))
                .and_then(|()| cnode_revoke(root_slot(caps.e2_badged)))
                .unwrap_or_else(|e| fail!("captransfer: revoking F and E2: {e}")),
        }
        let reply_slot = step.reply_slot.then(|| {
            *next_reply_slot
                .next()
                .unwrap_or_else(|| fail!("captransfer: out of reply slots"))
        });
        let sent: [CPtr; 3] =
            core::array::from_fn(|j| step.caps.get(j).map_or(0, |&c| caps.sent(c)));
        ipc.set_receive_slot(reply_slot.map(root_slot));
        let msg = ipc.compose(i as u64, &[i as u64], &sent[..step.caps.len()]);
        let answer = call(caps.via(step.via), &msg);
        let words: [u64; REPORT_WORDS] = core::array::from_fn(|j| {
            if j < answer.info.length() as usize {
                ipc.received_word(&answer, j)
            } else {
                0
            }
        });
        let report = Report::decode(words);
        if let Err(m) = ct::check(i, step, &report, answer.info) {
            fail!("captransfer: step {i}, {}: {m}", step.name);
        }
        let got = ReceivedCaps::new(report.info, report.caps_or_badges);
        println!(
            "captransfer: ok   step {i}: {}: S received extra_caps {}, caps_unwrapped {:#05b}, copied {}; S's slots 8 to 11 full: {:04b}",
            step.name,
            got.processed(),
            got.unwrapped(),
            Copied(got.copied()),
            // Slot 8 leftmost.
            report.full.reverse_bits() >> 60
        );
        if let Some(slot) = reply_slot {
            let want = step.expect.reply_caps == 1;
            expect_occupied(ipc, slot, want, "C's receive slot for the reply");
            if want {
                // A copy of E with Read and Grant: a poll finds nothing.
                let r = nb_recv(slot);
                if (r.badge, r.msg.info.word()) != (0, 0) {
                    fail!(
                        "captransfer: NBRecv on the received capability: badge {:#x}, {:?}",
                        r.badge,
                        r.msg.info
                    );
                }
                println!(
                    "captransfer: ok   step {i}: the reply's capability is in C's slot {slot}, and an NBRecv on it returns nothing pending"
                );
            } else {
                println!("captransfer: ok   step {i}: C's slot {slot} stayed empty");
            }
        }
        if step.action == Action::CallBack {
            serve_ping(ipc, caps.e2);
        }
        if step.before == Before::RevokeOriginals {
            check_unmapped(ipc, &caps);
        }
    }
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// Receives S's call back on E2 and answers it.
fn serve_ping(ipc: Ipc, e2: CPtr) {
    ipc.set_receive_slot(None);
    let r = recv(e2);
    let info = r.msg.info;
    if r.badge != ct::E2_BADGE
        || info.label() != ct::PING
        || info.length() != 1
        || r.msg.mr[0] != ct::PING_WORD
    {
        fail!(
            "captransfer: on E2 C received badge {:#x}, {info:?}, MR0 {:#x}; want S's call back with badge {:#x}",
            r.badge,
            r.msg.mr[0],
            ct::E2_BADGE
        );
    }
    reply(&Message::new(
        MessageInfo::new(0, 0, 0, 1),
        [ct::PING_WORD + 1, 0, 0, 0],
    ));
    println!(
        "captransfer: ok   step 0: S called back through its copy of C's E2 capability, and C received the call with its badge {:#x}",
        r.badge
    );
}

/// After the revoke: S's mapping went with its copy, so the server page
/// takes F2; C's own mapping of F, the revoked capability itself, stays.
fn check_unmapped(ipc: Ipc, caps: &Caps) {
    if let Err(e) = map(ipc, caps.f2, SERVER_PAGE, READ_WRITE) {
        fail!("captransfer: mapping F2 at the server page {SERVER_PAGE:#x} after the revoke: {e}");
    }
    invoke(None, caps.f2, FRAME_UNMAP, &[], &[])
        .unwrap_or_else(|e| fail!("captransfer: unmapping F2: {e}"));
    let word = read(CLIENT_PAGE);
    if word != ct::MAGIC {
        fail!("captransfer: C's page {CLIENT_PAGE:#x} holds {word:#x} after the revoke");
    }
    println!(
        "captransfer: ok   step 9: S's mapping at {SERVER_PAGE:#x} went with its copy (F2 maps there now), and C's own mapping of F still reads {word:#x}"
    );
}

/// S: follows [`STEPS`] in its own CSpace, where its `CPtr` `n` is slot
/// `n`. `buffer` is its IPC buffer.
extern "C" fn server(buffer: u64, _: u64, _: u64, _: u64) -> ! {
    let ipc = spawn::thread_ipc(buffer);
    let prepare = |step: &Step| {
        ipc.set_caps(&SENTINELS);
        ipc.set_receive_slot(step.slot.map(server_slot));
    };
    let mut mapped = false;
    prepare(&STEPS[0]);
    let mut r = recv(STEPS[0].recv_on);
    for (i, step) in STEPS.iter().enumerate() {
        let caps_or_badges = ipc.caps_or_badges();
        let value = match step.action {
            Action::MapAndRead => {
                let at = [SERVER_PAGE, READ, RAM];
                // A failure leaves the page unmapped and the word 0; C's
                // check says what went wrong.
                mapped = invoke(
                    Some(ipc),
                    s_slot::FOR_FRAME,
                    FRAME_MAP,
                    &at,
                    &[s_slot::VSPACE],
                )
                .is_ok();
                if mapped { read(SERVER_PAGE) } else { 0 }
            }
            Action::ReadAgain if mapped => read(SERVER_PAGE),
            _ => 0,
        };
        let mut full = 0;
        for (b, &slot) in PROBED.iter().enumerate() {
            match occupied(ipc, server_slot(slot)) {
                Ok(true) => full |= 1 << b,
                Ok(false) => {}
                Err(e) => fail!("captransfer: server: step {i}: probing slot {slot}: {e}"),
            }
        }
        let report = Report {
            info: r.msg.info,
            badge: r.badge,
            full,
            value,
            caps_or_badges,
        };
        reply(&ipc.compose(i as u64, &report.encode(), step.reply_caps));
        if step.action == Action::CallBack {
            let ping = Message::new(
                MessageInfo::new(ct::PING, 0, 0, 1),
                [ct::PING_WORD, 0, 0, 0],
            );
            let pong = call(s_slot::FOR_EP, &ping);
            if (pong.info.label(), pong.info.length(), pong.mr[0]) != (0, 1, ct::PING_WORD + 1) {
                fail!(
                    "captransfer: server: calling back through the received capability: {:?}, MR0 {:#x}",
                    pong.info,
                    pong.mr[0]
                );
            }
        }
        let Some(next) = STEPS.get(i + 1) else { break };
        prepare(next);
        r = recv(next.recv_on);
    }
    // Nothing more may come.
    ipc.set_receive_slot(None);
    let r = recv(s_slot::EP);
    fail!(
        "captransfer: server: a message after the last step: badge {:#x}, {:?}",
        r.badge,
        r.msg.info
    )
}

/// Which capability went into the receive slot, for the log.
struct Copied(Option<usize>);

impl fmt::Display for Copied {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(i) => write!(f, "capability {i}"),
            None => f.write_str("none"),
        }
    }
}
