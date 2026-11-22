//! `test=ipcntfn`: "IPC plus notification on one server" (PLAN.md, M6's
//! done-when; `docs/design.md`, "Notifications", "Binding").
//!
//! The server S is bound to notification N and receives on endpoint E with
//! `Recv`, and with `ReplyRecv` after a call; it records what each receive
//! returned, a signal or a message, which it tells apart by badge
//! ([`libsys::Event::classify`]): endpoint capabilities carry badges below
//! bit 32, notification capabilities single bits from 32 up
//! ([`root::check::ipcntfn`]). The root task, at 255 above every other
//! thread, first checks `TCB_BindNotification`'s refusals, binds S, and
//! runs a script whose every step it lets run to the end
//! ([`spawn::let_others_run`]), so S must record exactly
//! [`ic::SCRIPT`]:
//!
//! 1. A signal while S waits on E wakes it, `rsi` 0.
//! 2. Two signals while S is runnable but not receiving merge in N, and
//!    S's next endpoint receive returns them, ahead of the message the
//!    root task queued on E meanwhile.
//! 3. A signal, then a call: S gets the signal, then the call, and answers.
//! 4. S signals N itself while it handles a call; its `ReplyRecv` answers,
//!    and the receive phase returns the signal at once.
//! 5. S answers a call, then waits on N directly, and a signal ends it.
//!
//! Then the free part: two clients make [`PER_THREAD`] calls each on E and
//! two signallers send [`PER_THREAD`] signals each on N, all at S's
//! priority, yielding between, while the root task waits for their
//! reports. S answers every call, and each client checks every answer; S
//! counts what it received, and a shared sequence number shows that each
//! signaller's bit reached S after that signaller's last signal. The root
//! task's last call flushes any signal still pending, which S receives
//! first.
//!
//! Then the root task unbinds S: a signal then wakes nobody and waits in
//! N, where the root task's polls find it once, and later signals merge
//! there for a wait.
//!
//! Last, with S unbound in an endpoint receive, a signal waits in N, and
//! binding S again delivers it at once (the design's change from seL4):
//! S wakes with the word and `rsi` 0, and N is left Idle, so the next
//! signal wakes S alone.

use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicU64, AtomicUsize};

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::invoke::{
    Slot, cnode_mint, invoke, tcb_bind_notification, tcb_resume, tcb_set_priority,
    tcb_unbind_notification,
};
use libsys::{
    BootInfo, CPtr, Error, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Received, Rights,
    SyscallError, call, poll, println, recv, reply, reply_recv, send, signal, wait, yield_now,
};
use root::check::ipcntfn::{
    self as ic, CLIENT_BADGES, ROOT_BADGE, ROOT_SIGNALS, SCRIPT, SERVER_SIGNAL, SIGNALLER_BADGES,
    Seen, Tally, label,
};

use crate::fail;
use crate::spawn::{self, STACKS, Thread, let_others_run};

/// Every thread's priority but the root task's.
const PRIORITY: u64 = 100;
/// Calls each client makes, and signals each signaller sends.
const PER_THREAD: u64 = 100;
/// The label of a thread's report to the root task when it is done.
const DONE: u64 = 0xD0E;
/// `TCB_BindNotification`'s label (`docs/abi.md`, "TCB invocations"), for
/// a call without the capability `tcb_bind_notification` always sends.
const BIND_NOTIFICATION: u64 = 0x2B;

/// The first receives S recorded, encoded ([`Seen::encode`]), and how
/// many it recorded in all.
const LOG_LEN: usize = 16;
static LOG: [[AtomicU64; 2]; LOG_LEN] = [const { [const { AtomicU64::new(0) }; 2] }; LOG_LEN];
static LOGGED: AtomicUsize = AtomicUsize::new(0);
/// The last receive S recorded, encoded.
static LAST: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

/// What S counted (`Tally`'s fields).
static DELIVERIES: AtomicU64 = AtomicU64::new(0);
static MERGED: AtomicU64 = AtomicU64::new(0);
static SIGNAL_OR: AtomicU64 = AtomicU64::new(0);
static FOREIGN: AtomicU64 = AtomicU64::new(0);
static CALLS: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// Right answers each client received.
static ANSWERED: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
/// Taken by a signaller just before each signal, into `LAST_SENT`, and by
/// S just after each signal it receives, into `LAST_SEEN` for each
/// signaller's bit in it.
static SEQUENCE: AtomicU64 = AtomicU64::new(0);
static LAST_SENT: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];
static LAST_SEEN: [AtomicU64; 2] = [const { AtomicU64::new(0) }; 2];

fn root_slot(n: CPtr) -> Slot {
    Slot::root_cnode(n)
}

fn is(r: Result<(), Error>, e: SyscallError) -> bool {
    matches!(r, Err(err) if err.kernel() == Some(e))
}

/// The root task's capabilities to E and N.
struct Caps {
    /// To E, badge [`ROOT_BADGE`].
    ep: CPtr,
    /// N itself, every right, to bind and later to poll.
    ntfn: CPtr,
    /// To N, Write only, badges [`ROOT_SIGNALS`] and [`SIGNALLER_BADGES`].
    signals: [CPtr; 3],
    signallers: [CPtr; 2],
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let mut retype = |ty, count, what| {
        objects
            .retype(ipc, ty, 0, count)
            .unwrap_or_else(|e| fail!("ipcntfn: retyping {what}: {e}"))
    };
    let eps = retype(ObjectType::Endpoint, 3, "the endpoints");
    let (ep, done, park) = (eps, eps + 1, eps + 2);
    let ntfn = retype(ObjectType::Notification, 1, "the notification");
    let tcbs = retype(ObjectType::Tcb, 5, "the TCBs");
    let (server_tcb, client_tcbs, signaller_tcbs) =
        (tcbs, [tcbs + 1, tcbs + 2], [tcbs + 3, tcbs + 4]);
    let first = objects
        .slots
        .alloc(9)
        .unwrap_or_else(|| fail!("ipcntfn: no free slots"));
    let client_caps = [first, first + 1];
    let caps = Caps {
        ep: first + 2,
        ntfn,
        signals: [first + 3, first + 4, first + 5],
        signallers: [first + 6, first + 7],
    };
    let server_signal = first + 8;

    let w_gr = Rights(Rights::WRITE.0 | Rights::GRANT_REPLY.0);
    let mints = [
        (client_caps[0], ep, w_gr, CLIENT_BADGES[0]),
        (client_caps[1], ep, w_gr, CLIENT_BADGES[1]),
        (caps.ep, ep, w_gr, ROOT_BADGE),
        (caps.signals[0], ntfn, Rights::WRITE, ROOT_SIGNALS[0]),
        (caps.signals[1], ntfn, Rights::WRITE, ROOT_SIGNALS[1]),
        (caps.signals[2], ntfn, Rights::WRITE, ROOT_SIGNALS[2]),
        (caps.signallers[0], ntfn, Rights::WRITE, SIGNALLER_BADGES[0]),
        (caps.signallers[1], ntfn, Rights::WRITE, SIGNALLER_BADGES[1]),
        (server_signal, ntfn, Rights::WRITE, SERVER_SIGNAL),
    ];
    for (dest, src, rights, badge) in mints {
        cnode_mint(ipc, root_slot(dest), root_slot(src), rights, badge)
            .unwrap_or_else(|e| fail!("ipcntfn: minting badge {badge:#x}: {e}"));
    }

    // Every thread reports a fault on D, where the root task waits in the
    // free part.
    let (s, c, g): (spawn::Entry, spawn::Entry, spawn::Entry) = (server, client, signaller);
    let threads = [
        (server_tcb, STACKS[0], s, [ep, ntfn, server_signal, 0]),
        (
            client_tcbs[0],
            STACKS[1],
            c,
            [0, client_caps[0], done, park],
        ),
        (
            client_tcbs[1],
            STACKS[2],
            c,
            [1, client_caps[1], done, park],
        ),
        (
            signaller_tcbs[0],
            STACKS[3],
            g,
            [0, caps.signallers[0], done, park],
        ),
        (
            signaller_tcbs[1],
            STACKS[4],
            g,
            [1, caps.signallers[1], done, park],
        ),
    ];
    for (tcb, stack, entry, args) in threads {
        let t = Thread {
            tcb,
            fault_ep: done,
            stack,
            entry,
            args,
        };
        spawn::prepare(ipc, &t)
            .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, PRIORITY))
            .unwrap_or_else(|e| fail!("ipcntfn: setting up the thread in TCB slot {tcb}: {e}"));
    }
    println!(
        "ipcntfn: server S (TCB slot {server_tcb}, priority {PRIORITY}) receives on endpoint slot {ep} and is bound to notification slot {ntfn}; endpoint capabilities carry badges {:#x} to {ROOT_BADGE:#x}, notification capabilities single bits from bit 32 up",
        CLIENT_BADGES[0]
    );

    bind(ipc, server_tcb, client_tcbs[0], &caps);
    tcb_resume(server_tcb).unwrap_or_else(|e| fail!("ipcntfn: resuming S: {e}"));
    // S waits on E.
    let_others_run(ipc);
    script(ipc, &caps);
    free(&caps, client_tcbs, signaller_tcbs, done);
    unbind(ipc, server_tcb, &caps);
    bind_delivers(ipc, server_tcb, &caps);
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// `TCB_BindNotification`'s refusals, then S bound to N.
fn bind(ipc: Ipc, server: CPtr, other: CPtr, caps: &Caps) {
    let none = invoke(Some(ipc), server, BIND_NOTIFICATION, &[], &[]).map(|_| ());
    let write_only = tcb_bind_notification(ipc, server, caps.signals[0]);
    let unbound = tcb_unbind_notification(server);
    if !is(none, SyscallError::TruncatedMessage)
        || !is(write_only, SyscallError::IllegalOperation)
        || !is(unbound, SyscallError::IllegalOperation)
    {
        fail!(
            "ipcntfn: before binding: TCB_BindNotification without a capability {none:?}, with one without Read {write_only:?}; TCB_UnbindNotification {unbound:?}"
        );
    }
    tcb_bind_notification(ipc, server, caps.ntfn)
        .unwrap_or_else(|e| fail!("ipcntfn: binding S to N: {e}"));
    let again = tcb_bind_notification(ipc, server, caps.ntfn);
    let taken = tcb_bind_notification(ipc, other, caps.ntfn);
    if !is(again, SyscallError::IllegalOperation) || !is(taken, SyscallError::IllegalOperation) {
        fail!(
            "ipcntfn: binding S again: {again:?}; binding another thread to N, which S holds: {taken:?}"
        );
    }
    println!(
        "ipcntfn: ok   TCB_BindNotification: TruncatedMessage without a capability, IllegalOperation for one without Read; TCB_UnbindNotification of an unbound TCB: IllegalOperation; S bound to N; binding S again, or another thread to N: IllegalOperation"
    );
}

/// A call to S through the root task's capability, which S answers with
/// MR0 plus one.
fn echo(caps: &Caps, label: u64, word: u64) {
    let r = call(
        caps.ep,
        &Message::new(MessageInfo::new(label, 0, 0, 1), [word, 0, 0, 0]),
    );
    if (r.info.label(), r.info.length(), r.mr[0]) != (0, 1, word + 1) {
        fail!(
            "ipcntfn: S answered call {label:#x} with {:?}, MR0 {:#x}; want MR0 {:#x}",
            r.info,
            r.mr[0],
            word + 1
        );
    }
}

/// What S recorded so far.
fn logged() -> ([Seen; LOG_LEN], usize) {
    let n = LOGGED.load(Relaxed);
    let mut seen = [Seen::Waited(0); LOG_LEN];
    for (s, w) in seen.iter_mut().zip(&LOG).take(n) {
        let words = [w[0].load(Relaxed), w[1].load(Relaxed)];
        *s = Seen::decode(words).unwrap_or_else(|| fail!("ipcntfn: S's log holds {words:#x?}"));
    }
    (seen, n)
}

/// The scripted part.
fn script(ipc: Ipc, caps: &Caps) {
    let [r0, r1, r2] = caps.signals;
    // 1 and 2: S wakes with r0 and is runnable, not receiving, when r1 and
    // r2 arrive; the Send queues on E, since S is not receiving either.
    signal(r0);
    signal(r1);
    signal(r2);
    send(
        caps.ep,
        &Message::new(MessageInfo::new(label::PING, 0, 0, 0), [0; 4]),
    );
    let_others_run(ipc);
    // 3.
    signal(r2);
    echo(caps, label::ECHO, 41);
    // 4.
    echo(caps, label::ECHO_SIGNAL, 43);
    let_others_run(ipc);
    // 5: S waits on N once its answer is out.
    echo(caps, label::WAIT, 45);
    let_others_run(ipc);
    signal(r1);
    let_others_run(ipc);

    let (seen, n) = logged();
    if n > LOG_LEN {
        fail!(
            "ipcntfn: S recorded {n} receives in the scripted part, want {}",
            SCRIPT.len()
        );
    }
    if let Err(e) = ic::script(&seen[..n], &SCRIPT) {
        fail!("ipcntfn: the scripted part: {e}");
    }
    println!(
        "ipcntfn: ok   1: a signal woke S out of its endpoint receive: rdi {r0:#x}, rsi 0",
        r0 = ROOT_SIGNALS[0]
    );
    println!(
        "ipcntfn: ok   2: two signals while S was not receiving merged into {:#x}, which its next endpoint receive returned ahead of the message queued on E meanwhile",
        ROOT_SIGNALS[1] | ROOT_SIGNALS[2]
    );
    println!(
        "ipcntfn: ok   3: a signal, then a call queued behind it: S received the signal first, then the call, and answered it"
    );
    println!(
        "ipcntfn: ok   4: S signalled N while it handled a call; its ReplyRecv answered, then the receive phase returned the signal {SERVER_SIGNAL:#x} at once"
    );
    println!(
        "ipcntfn: ok   5: S answered a call, then waited on N directly; a signal ended the wait with {:#x}",
        ROOT_SIGNALS[1]
    );
}

/// The free part: clients and signallers at S's priority, then a flush.
fn free(caps: &Caps, clients: [CPtr; 2], signallers: [CPtr; 2], done: CPtr) {
    for counter in [
        &DELIVERIES,
        &MERGED,
        &SIGNAL_OR,
        &FOREIGN,
        &CALLS[0],
        &CALLS[1],
    ] {
        counter.store(0, Relaxed);
    }
    println!(
        "ipcntfn: free part: clients C1 and C2 make {PER_THREAD} calls each and signallers G1 and G2 send {PER_THREAD} signals each, all at priority {PRIORITY}, yielding between"
    );
    for tcb in clients.into_iter().chain(signallers) {
        tcb_resume(tcb).unwrap_or_else(|e| fail!("ipcntfn: resuming TCB slot {tcb}: {e}"));
    }
    let mut reported = [false; 4];
    for _ in 0..reported.len() {
        let r = recv(done);
        let who = r.msg.mr[0] as usize;
        if r.msg.info.label() != DONE || reported.get(who) != Some(&false) {
            fail!(
                "ipcntfn: on D the root task received label {:#x}, length {}, MR0 to MR3 {:#x?}: a fault, or a second report",
                r.msg.info.label(),
                r.msg.info.length(),
                r.msg.mr
            );
        }
        reported[who] = true;
    }
    // Any signal still pending reaches S before this call.
    echo(caps, label::FLUSH, 47);
    let load = |a: &[AtomicU64; 2]| [a[0].load(Relaxed), a[1].load(Relaxed)];
    let t = Tally {
        per_thread: PER_THREAD,
        deliveries: DELIVERIES.load(Relaxed),
        merged: MERGED.load(Relaxed),
        signal_or: SIGNAL_OR.load(Relaxed),
        foreign: FOREIGN.load(Relaxed),
        calls: load(&CALLS),
        answered: load(&ANSWERED),
        last_sent: load(&LAST_SENT),
        last_seen: load(&LAST_SEEN),
    };
    if let Err(m) = ic::free(&t) {
        fail!("ipcntfn: the free part: {m}");
    }
    println!(
        "ipcntfn: ok   every call answered right: S received {} calls from C1 and {} from C2, and {} signal deliveries for {} signals, carrying {:#x} between them, {} with both signallers' bits; each signaller's bit reached S after its last signal",
        t.calls[0],
        t.calls[1],
        t.deliveries,
        2 * PER_THREAD,
        t.signal_or,
        t.merged
    );
}

/// Unbinds S, and checks a signal then waits in N.
fn unbind(ipc: Ipc, server: CPtr, caps: &Caps) {
    tcb_unbind_notification(server).unwrap_or_else(|e| fail!("ipcntfn: unbinding S: {e}"));
    let again = tcb_unbind_notification(server);
    if !is(again, SyscallError::IllegalOperation) {
        fail!("ipcntfn: TCB_UnbindNotification of S again: {again:?}, want IllegalOperation");
    }
    // S waits on E, unbound: a signal must not wake it.
    let before = LOGGED.load(Relaxed);
    signal(caps.signals[2]);
    let_others_run(ipc);
    let after = LOGGED.load(Relaxed);
    if after != before {
        fail!(
            "ipcntfn: S, unbound, received something after a signal to N: {after} receives, not {before}"
        );
    }
    let first = poll(caps.ntfn);
    let second = poll(caps.ntfn);
    signal(caps.signallers[0]);
    signal(caps.signallers[1]);
    let merged = wait(caps.ntfn);
    let both = SIGNALLER_BADGES[0] | SIGNALLER_BADGES[1];
    if (first, second, merged) != (ROOT_SIGNALS[2], 0, both) {
        fail!(
            "ipcntfn: after unbinding: polls returned {first:#x} and {second:#x}, want {:#x} and 0; a wait after two signals {merged:#x}, want {both:#x}",
            ROOT_SIGNALS[2]
        );
    }
    println!(
        "ipcntfn: ok   unbound, S did not wake for a signal, which waited in N: a poll returned {first:#x}, the next 0; two more signals merged into {merged:#x} for a wait"
    );
}

/// S, unbound, waits on E: a signal waits in N, and binding S delivers it
/// at once and leaves N Idle, so the next signal wakes S alone.
fn bind_delivers(ipc: Ipc, server: CPtr, caps: &Caps) {
    let last = || {
        let words = [LAST[0].load(Relaxed), LAST[1].load(Relaxed)];
        Seen::decode(words).unwrap_or_else(|| fail!("ipcntfn: S's last record is {words:#x?}"))
    };
    let start = LOGGED.load(Relaxed);
    let [pending, next, _] = ROOT_SIGNALS;
    signal(caps.signals[0]);
    let_others_run(ipc);
    let waited = LOGGED.load(Relaxed) - start;
    tcb_bind_notification(ipc, server, caps.ntfn)
        .unwrap_or_else(|e| fail!("ipcntfn: binding S again: {e}"));
    let_others_run(ipc);
    let (at_bind, first) = (LOGGED.load(Relaxed) - start, last());
    signal(caps.signals[1]);
    let_others_run(ipc);
    let (after, second) = (LOGGED.load(Relaxed) - start, last());
    let want = (Seen::Signal(pending), Seen::Signal(next));
    if (waited, at_bind, after) != (0, 1, 2) || (first, second) != want {
        fail!(
            "ipcntfn: binding S, in an endpoint receive, with {pending:#x} pending in N: S recorded {waited} receives before the bind, {at_bind} by its end, last {first}, and {after} after one more signal, last {second}; want 0, 1 ({}) and 2 ({})",
            want.0,
            want.1
        );
    }
    println!(
        "ipcntfn: ok   binding S again while it waited on E with {pending:#x} pending in N delivered the signal at once, rsi 0, and left N idle: the next signal woke S with {next:#x} alone"
    );
}

/// Records what one of S's receives returned.
fn record(seen: Seen) {
    let n = LOGGED.load(Relaxed);
    let [a, b] = seen.encode();
    if let Some(slot) = LOG.get(n) {
        slot[0].store(a, Relaxed);
        slot[1].store(b, Relaxed);
    }
    LAST[0].store(a, Relaxed);
    LAST[1].store(b, Relaxed);
    LOGGED.store(n + 1, Relaxed);
    match seen {
        Seen::Signal(word) => {
            let seq = SEQUENCE.fetch_add(1, Relaxed) + 1;
            DELIVERIES.fetch_add(1, Relaxed);
            SIGNAL_OR.fetch_or(word, Relaxed);
            let both = SIGNALLER_BADGES[0] | SIGNALLER_BADGES[1];
            if word == 0 || word & !both != 0 {
                FOREIGN.fetch_add(1, Relaxed);
            }
            if word & both == both {
                MERGED.fetch_add(1, Relaxed);
            }
            for (g, &bit) in SIGNALLER_BADGES.iter().enumerate() {
                if word & bit != 0 {
                    LAST_SEEN[g].store(seq, Relaxed);
                }
            }
        }
        Seen::Message { badge, label } => {
            if label == label::CALL
                && let Some(c) = CLIENT_BADGES.iter().position(|&b| b == badge)
            {
                CALLS[c].fetch_add(1, Relaxed);
            }
        }
        Seen::Waited(_) => {}
    }
}

/// S's answer to a call: MR0 plus one, and `extra` as MR1 if given.
fn answer(r: &Received, extra: Option<u64>) -> Message {
    let length = 1 + u64::from(extra.is_some());
    Message::new(
        MessageInfo::new(0, 0, 0, length),
        [r.msg.mr[0] + 1, extra.unwrap_or(0), 0, 0],
    )
}

/// S: receives on `ep`, bound to `ntfn`; `own` is its own capability to
/// signal it.
extern "C" fn server(ep: CPtr, ntfn: CPtr, own: CPtr, _: u64) -> ! {
    let mut r = recv(ep);
    loop {
        let seen = Seen::of(r);
        record(seen);
        r = match seen {
            Seen::Signal(_) => recv(ep),
            Seen::Message { badge, label } => match label {
                label::CALL => reply_recv(ep, &answer(&r, Some(badge))),
                label::PING => recv(ep),
                label::ECHO | label::FLUSH => reply_recv(ep, &answer(&r, None)),
                label::ECHO_SIGNAL => {
                    signal(own);
                    reply_recv(ep, &answer(&r, None))
                }
                label::WAIT => {
                    reply(&answer(&r, None));
                    record(Seen::Waited(wait(ntfn)));
                    recv(ep)
                }
                _ => fail!(
                    "ipcntfn: server: {seen}, {:?}, MR0 to MR3 {:#x?}",
                    r.msg.info,
                    r.msg.mr
                ),
            },
            Seen::Waited(_) => unreachable!("an endpoint receive is no wait"),
        };
    }
}

/// Client `c`: calls `cap` [`PER_THREAD`] times, checking each answer,
/// then reports on `done` and waits on `park`, where nothing comes.
extern "C" fn client(c: u64, cap: CPtr, done: CPtr, park: CPtr) -> ! {
    let c = c as usize;
    for i in 0..PER_THREAD {
        let r = call(
            cap,
            &Message::new(MessageInfo::new(label::CALL, 0, 0, 1), [i, 0, 0, 0]),
        );
        let want = (0, 2, i + 1, CLIENT_BADGES[c]);
        if (r.info.label(), r.info.length(), r.mr[0], r.mr[1]) != want {
            fail!(
                "ipcntfn: client C{}'s call {i}: answer {:?}, MR0 to MR3 {:#x?}; want MR0 {:#x} and the badge {:#x}",
                c + 1,
                r.info,
                r.mr,
                i + 1,
                CLIENT_BADGES[c]
            );
        }
        ANSWERED[c].fetch_add(1, Relaxed);
        yield_now();
    }
    report_and_park(c as u64, done, park)
}

/// Signaller `g`: signals `cap` [`PER_THREAD`] times, then reports on
/// `done` and waits on `park`.
extern "C" fn signaller(g: u64, cap: CPtr, done: CPtr, park: CPtr) -> ! {
    let g = g as usize;
    for _ in 0..PER_THREAD {
        LAST_SENT[g].store(SEQUENCE.fetch_add(1, Relaxed) + 1, Relaxed);
        signal(cap);
        yield_now();
    }
    report_and_park(2 + g as u64, done, park)
}

fn report_and_park(who: u64, done: CPtr, park: CPtr) -> ! {
    send(
        done,
        &Message::new(MessageInfo::new(DONE, 0, 0, 1), [who, 0, 0, 0]),
    );
    loop {
        recv(park);
    }
}
