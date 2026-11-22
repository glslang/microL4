//! `test=redteam-irq`, the M7 red team's ring-3 attack on IRQControl and
//! IRQHandler (`docs/redteam/`), with the PIT as an interrupt source the
//! attacker controls: channel 0 at 0x40-0x43, ISA IRQ 0, GSI 2 on q35.
//! Every thread shares the root task's CSpace and VSpace.
//!
//! - **A storm.** The PIT runs at about 18.6 kHz, a rate generator, its
//!   edges on GSI 2. With the handler bound and no Ack, the root task polls
//!   the notification for 200 ms: at most three polls may find a signal
//!   (`docs/abi.md`, "IRQHandler": three interrupts per Ack for an edge
//!   pin). Then ten rounds of one Ack and 20 ms of polling: at most three
//!   each, and at least one in all (the storm is real).
//! - **Stealing a pin.** With GSI 2 issued through `GetISA(0)`,
//!   `GetIOAPIC(2)` either trigger is `RevokeFirst`, and `GetISA(2)` has no
//!   route.
//! - **Churn and every pin.** 300 issues and deletions of one GSI must
//!   reuse one vector; then every GSI the I/O APIC serves is issued at
//!   once (24 on q35), the next is `InvalidArgument(0)`, and each comes
//!   back after the deletions.
//! - **A revoked notification.** The handler is bound to notification N
//!   retyped from an untyped U of its own; revoking U deletes N and the IRQ
//!   node's copy, and U is retyped into N2 at N's address. With the PIT
//!   running and the pin Acked, N2 must never be signalled; once the
//!   handler is bound to N2, it is.
//! - **Nested finalisation.** A handler moved into a CNode K holds, in its
//!   IRQ node slot, the last capability to a notification on which thread
//!   W waits. Deleting K finalises the handler inside the Zombie's
//!   reduction, which deletes the notification's last capability and
//!   releases W: the kernel survives, W restarts its Wait on an empty slot
//!   and stops on the capability fault (it has no fault handler), and the
//!   GSI can be issued again.

use core::sync::atomic::{AtomicU64, Ordering};

use libsys::bootinfo::{CAP_INIT_CNODE, CAP_INIT_TCB, CAP_IO_PORT_CONTROL, CAP_IRQ_CONTROL};
use libsys::device::{
    ioport_control_issue, ioport_out8, irq_control_get_ioapic, irq_control_get_isa,
    irq_handler_ack, irq_handler_set_notification,
};
use libsys::invoke::{
    Slot, cnode_delete, cnode_mint, cnode_move, cnode_revoke, tcb_resume, tcb_set_priority,
    untyped_retype,
};
use libsys::notification::{poll, wait};
use libsys::{
    BootInfo, CPtr, Error, Ipc, ObjectAlloc, ObjectType, Rights, SyscallError, println, rdtsc,
};

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// The PIT's ports.
const PIT_CH0: u16 = 0x40;
const PIT_CMD: u16 = 0x43;
/// The badge the bound capabilities carry.
const BADGE: u64 = 1 << 40;
/// The GSI the churn uses, an ISA line nothing on q35 drives.
const CHURN_GSI: u64 = 5;
/// GSIs q35's I/O APIC serves.
const GSIS: u64 = 24;

/// W's wake-ups, for the root task to check.
static W_WOKE: AtomicU64 = AtomicU64::new(0);

fn root_slot(n: CPtr) -> Slot {
    Slot::root_cnode(n)
}

fn ok<T>(r: Result<T, Error>, what: &str) -> T {
    r.unwrap_or_else(|e| fail!("redteam: irq: {what}: {e}"))
}

fn refused<T: core::fmt::Debug>(r: Result<T, Error>, want: SyscallError, what: &str) {
    match r {
        Err(e) if e.kernel() == Some(want) => {}
        other => fail!("redteam: irq: {what}: got {other:?}, want {want:?}"),
    }
}

struct Pit {
    port: CPtr,
}

impl Pit {
    /// Channel 0, rate generator (mode 2), lobyte then hibyte.
    fn periodic(&self, divisor: u16) {
        let [lo, hi] = divisor.to_le_bytes();
        ok(ioport_out8(self.port, PIT_CMD, 0x34), "PIT mode");
        ok(ioport_out8(self.port, PIT_CH0, lo), "PIT divisor");
        ok(ioport_out8(self.port, PIT_CH0, hi), "PIT divisor");
    }

    /// Channel 0, mode 0 with no count written: the output stays low.
    fn stop(&self) {
        ok(ioport_out8(self.port, PIT_CMD, 0x30), "PIT stop");
    }
}

/// Polls `n` for `ms` milliseconds; returns how many polls found a signal.
fn count(n: CPtr, ms: u64, tsc_ms: u64) -> u64 {
    let start = rdtsc();
    let mut hits = 0;
    while rdtsc() - start < ms * tsc_ms {
        let w = poll(n);
        if w != 0 {
            if w != BADGE {
                fail!("redteam: irq: a poll found {w:#x}, not the badge {BADGE:#x}");
            }
            hits += 1;
        }
    }
    hits
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let tsc_ms = bi.tsc_hz / 1000;
    let mut objects = ObjectAlloc::new(bi);
    let n = objects
        .retype(ipc, ObjectType::Notification, 0, 1)
        .unwrap_or_else(|e| fail!("redteam: irq: retyping N0: {e}"));
    let first = objects
        .slots
        .alloc(8)
        .unwrap_or_else(|| fail!("redteam: irq: no free slots"));
    let (pit_port, nb, h, h2) = (first, first + 1, first + 2, first + 3);
    let (n_slot, n_badged, h3, k_slot) = (first + 4, first + 5, first + 6, first + 7);
    ok(
        cnode_mint(ipc, root_slot(nb), root_slot(n), Rights::WRITE, BADGE),
        "minting N0's badged capability",
    );
    ok(
        ioport_control_issue(ipc, CAP_IO_PORT_CONTROL, 0x40, 0x43, root_slot(pit_port)),
        "issuing the PIT's ports",
    );
    let pit = Pit { port: pit_port };
    let control = CAP_IRQ_CONTROL;

    // A storm on GSI 2, and two ways to steal it.
    let isa0 = ok(
        irq_control_get_isa(ipc, control, 0, root_slot(h)),
        "GetISA(0)",
    );
    if isa0.gsi != 2 || isa0.level {
        fail!("redteam: irq: GetISA(0) returned {isa0:?}, not GSI 2, edge");
    }
    for level in [false, true] {
        refused(
            irq_control_get_ioapic(ipc, control, 2, level, false, root_slot(h2)),
            SyscallError::RevokeFirst,
            "GetIOAPIC(2) with GSI 2 issued",
        );
    }
    refused(
        irq_control_get_isa(ipc, control, 2, root_slot(h2)),
        SyscallError::InvalidArgument(0),
        "GetISA(2)",
    );
    ok(
        irq_handler_set_notification(ipc, h, nb),
        "SetNotification(N0)",
    );
    ok(irq_handler_ack(h), "the first Ack");
    pit.periodic(64);
    let unacked = count(n, 200, tsc_ms);
    let mut rounds = [0u64; 10];
    for r in rounds.iter_mut() {
        ok(irq_handler_ack(h), "Ack");
        *r = count(n, 20, tsc_ms);
    }
    pit.stop();
    count(n, 5, tsc_ms);
    let total: u64 = rounds.iter().sum();
    if unacked > 3 || rounds.iter().any(|&r| r > 3) || total == 0 {
        fail!("redteam: irq: storm: {unacked} signals in 200 ms unacked, then {rounds:?} per Ack");
    }
    println!(
        "redteam: irq: a PIT storm at 18.6 kHz on GSI 2 signalled {unacked} times in 200 ms without an Ack, then {rounds:?} for ten Acks; GetIOAPIC(2) is RevokeFirst while GetISA(0) holds it"
    );
    ok(cnode_delete(root_slot(h)), "deleting GetISA(0)'s handler");

    // Churn: one vector, over and over.
    let irq0 = ok(
        irq_control_get_ioapic(ipc, control, CHURN_GSI, false, false, root_slot(h)),
        "GetIOAPIC(5)",
    );
    for i in 0..300 {
        ok(cnode_delete(root_slot(h)), "deleting the churn handler");
        let level = i % 2 == 1;
        let irq = ok(
            irq_control_get_ioapic(ipc, control, CHURN_GSI, level, level, root_slot(h)),
            "GetIOAPIC(5) again",
        );
        if irq != irq0 {
            fail!("redteam: irq: issue {i} of GSI 5 took IRQ {irq}, not {irq0}");
        }
    }
    ok(cnode_delete(root_slot(h)), "deleting the churn handler");
    // Every pin at once.
    let pins = objects
        .slots
        .alloc(GSIS)
        .unwrap_or_else(|| fail!("redteam: irq: no free slots for every pin"));
    for round in 0..2 {
        for g in 0..GSIS {
            ok(
                irq_control_get_ioapic(ipc, control, g, false, false, root_slot(pins + g)),
                "GetIOAPIC of every GSI",
            );
        }
        refused(
            irq_control_get_ioapic(ipc, control, GSIS, false, false, root_slot(h)),
            SyscallError::InvalidArgument(0),
            "GetIOAPIC(24)",
        );
        refused(
            irq_control_get_isa(ipc, control, 4, root_slot(h)),
            SyscallError::RevokeFirst,
            "GetISA(4) with every GSI issued",
        );
        for g in 0..GSIS {
            ok(
                cnode_delete(root_slot(pins + g)),
                "deleting every pin's handler",
            );
        }
        if round == 0 {
            println!(
                "redteam: irq: 300 issues and deletions of GSI 5 reused IRQ {irq0}; all {GSIS} GSIs issued at once, GSI {GSIS} InvalidArgument(0)"
            );
        }
    }

    // A revoked notification and its memory reused.
    let u = objects
        .retype(ipc, ObjectType::Untyped, 12, 1)
        .unwrap_or_else(|e| fail!("redteam: irq: retyping U: {e}"));
    let retype_n = |what: &str| {
        ok(
            untyped_retype(
                ipc,
                u,
                ObjectType::Notification,
                0,
                Slot::cnode_itself(CAP_INIT_CNODE),
                n_slot,
                1,
            ),
            what,
        )
    };
    retype_n("retyping N from U");
    ok(
        cnode_mint(
            ipc,
            root_slot(n_badged),
            root_slot(n_slot),
            Rights::WRITE,
            BADGE,
        ),
        "minting N's badged capability",
    );
    ok(
        irq_control_get_isa(ipc, control, 0, root_slot(h)),
        "GetISA(0) again",
    );
    ok(
        irq_handler_set_notification(ipc, h, n_badged),
        "SetNotification(N)",
    );
    ok(cnode_revoke(root_slot(u)), "revoking U");
    retype_n("retyping N2 from U");
    pit.periodic(1193);
    let mut stolen = 0;
    for _ in 0..20 {
        ok(irq_handler_ack(h), "Ack, unbound");
        stolen += count(n_slot, 10, tsc_ms);
    }
    ok(
        cnode_mint(
            ipc,
            root_slot(n_badged),
            root_slot(n_slot),
            Rights::WRITE,
            BADGE,
        ),
        "minting N2's badged capability",
    );
    ok(
        irq_handler_set_notification(ipc, h, n_badged),
        "SetNotification(N2)",
    );
    let mut bound = 0;
    for _ in 0..20 {
        ok(irq_handler_ack(h), "Ack, bound to N2");
        bound += count(n_slot, 10, tsc_ms);
    }
    pit.stop();
    if stolen != 0 || bound == 0 {
        fail!("redteam: irq: N2 at N's address: {stolen} signals before binding, {bound} after");
    }
    println!(
        "redteam: irq: revoking N's untyped emptied the IRQ node; N2 at its address got no signal in 200 ms of Acks, then {bound} once bound"
    );
    ok(cnode_delete(root_slot(h)), "deleting the handler");
    ok(cnode_revoke(root_slot(u)), "revoking U again");

    // Nested finalisation: the handler's last capability inside a CNode,
    // its IRQ node holding the last capability to the notification W waits
    // on.
    retype_n("retyping N3 from U");
    ok(
        cnode_mint(
            ipc,
            root_slot(n_badged),
            root_slot(n_slot),
            Rights::WRITE,
            BADGE,
        ),
        "minting N3's badged capability",
    );
    let k = objects
        .retype(ipc, ObjectType::CNode, 4, 1)
        .unwrap_or_else(|e| fail!("redteam: irq: retyping K: {e}"));
    ok(cnode_move(ipc, root_slot(k_slot), root_slot(k)), "moving K");
    ok(
        irq_control_get_isa(ipc, control, 0, root_slot(h3)),
        "GetISA(0) for K",
    );
    ok(
        irq_handler_set_notification(ipc, h3, n_badged),
        "SetNotification(N3)",
    );
    ok(
        cnode_move(ipc, Slot::new(k_slot, 3, 4), root_slot(h3)),
        "moving the handler into K",
    );
    let tcb = objects
        .retype(ipc, ObjectType::Tcb, 0, 1)
        .unwrap_or_else(|e| fail!("redteam: irq: retyping W: {e}"));
    let w = Thread {
        tcb,
        fault_ep: 0,
        stack: STACKS[0],
        entry: waiter,
        args: [n_slot, 0, 0, 0],
    };
    ok(
        spawn::prepare(ipc, &w)
            .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, 200))
            .and_then(|()| tcb_resume(tcb)),
        "starting W",
    );
    spawn::let_others_run(ipc);
    ok(
        cnode_delete(root_slot(n_badged)),
        "deleting N3's badged capability",
    );
    ok(cnode_delete(root_slot(n_slot)), "deleting N3's capability");
    ok(
        cnode_delete(root_slot(k_slot)),
        "deleting K, with the handler in it",
    );
    spawn::let_others_run(ipc);
    let woke = W_WOKE.load(Ordering::Relaxed);
    ok(
        irq_control_get_isa(ipc, control, 0, root_slot(h)),
        "GetISA(0) after K's deletion",
    );
    ok(cnode_delete(root_slot(h)), "deleting it");
    if woke != 0 {
        fail!("redteam: irq: W woke {woke} times from a notification nothing signalled");
    }
    println!(
        "redteam: irq: deleting CNode K finalised the handler in it and, through its IRQ node, the notification W waited on; W was released and GSI 2 is free"
    );
    println!("redteam: irq: every interrupt attack held");
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// W: waits on `n` for ever, counting wake-ups.
extern "C" fn waiter(n: CPtr, _: u64, _: u64, _: u64) -> ! {
    loop {
        wait(n);
        W_WOKE.fetch_add(1, Ordering::Relaxed);
    }
}
