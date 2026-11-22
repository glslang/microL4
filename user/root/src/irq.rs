//! `test=irq`: IRQControl and IRQHandler from ring 3, with COM1 raising
//! real interrupts (`docs/abi.md`, "IRQControl", "IRQHandler";
//! `docs/design.md`, "IRQControl and IRQHandler", "Delivery", "Deletion").
//!
//! The root task issues COM1's range and ISA IRQ 4, binds a notification
//! `N` through a capability badged [`BADGE`], and makes COM1 raise its THRE
//! interrupt by setting IER's THRI bit while the transmitter is empty: on
//! QEMU each 0-to-1 change of THRI raises the line, and reading IIR lowers
//! it. It then checks:
//!
//! - `GetISA(4)` returns COM1's route, GSI 4, edge, active high; a second
//!   one, or `GetIOAPIC(4)`, is `RevokeFirst`; ISA IRQ 2 has no route on
//!   q35, and 16 is out of range; a notification without Write is refused;
//! - edge rules (the driver's order is wait, Ack, service, ADR 0028): the
//!   first edge after an Ack signals and leaves the pin open; a second one
//!   before Ack signals and masks it; while masked an edge signals nothing
//!   (whether the I/O APIC drops or latches it is left open); after an Ack
//!   the next edge signals again;
//! - `Clear`: an interrupt with nothing bound signals nothing, and binding
//!   again brings signals back;
//! - deletion frees ISA IRQ 4, and `GetIOAPIC(4, level)` issues it again
//!   level-triggered: the line held high signals once and masks the pin
//!   until an Ack, which signals again while it is still high; deleting the
//!   handler with the line high and reissuing works, and the first Ack after
//!   binding delivers what was pending;
//! - a copy keeps the IRQ issued after the original's deletion; revoking
//!   IRQControl deletes every handler.
//!
//! Nothing is printed while THRI is set, since the kernel's own output would
//! raise more THRE interrupts; IER is 0 and MCR as the kernel left it when
//! the test ends.

use libsys::bootinfo::{CAP_IO_PORT_CONTROL, CAP_IRQ_CONTROL};
use libsys::device::{
    IsaIrq, ioport_control_issue, ioport_in8, ioport_out8, irq_control_get_ioapic,
    irq_control_get_isa, irq_handler_ack, irq_handler_clear, irq_handler_set_notification,
};
use libsys::invoke::{Slot, cnode_copy, cnode_delete, cnode_mint, cnode_revoke};
use libsys::{
    BootInfo, CPtr, Error, Ipc, ObjectAlloc, ObjectType, Rights, SyscallError, poll, println, rdtsc,
};

use crate::fail;

/// COM1's registers.
const COM1: u16 = 0x3F8;
const IER: u16 = COM1 + 1;
const IIR: u16 = COM1 + 2;
const MCR: u16 = COM1 + 4;
const LSR: u16 = COM1 + 5;
const IER_THRI: u8 = 0x02;
const LSR_THRE: u8 = 0x20;
/// DTR, RTS and OUT2, which gates the interrupt line on a PC.
const MCR_OUT2: u8 = 0x0B;

/// The badge `N`'s bound capability carries.
const BADGE: u64 = 1 << 32;

fn root_slot(n: CPtr) -> Slot {
    Slot::root_cnode(n)
}

fn expect_ok<T>(r: Result<T, Error>, what: &str) -> T {
    r.unwrap_or_else(|e| fail!("irq: {what}: {e}"))
}

fn expect_err<T: core::fmt::Debug>(r: Result<T, Error>, want: SyscallError, what: &str) {
    match r {
        Err(e) if e.kernel() == Some(want) => {}
        other => fail!("irq: {what}: got {other:?}, want {want:?}"),
    }
}

/// The test's capabilities and clock.
struct T {
    ipc: Ipc,
    /// COM1's IOPort.
    port: CPtr,
    /// `N` with Read and Write, unbadged: polled.
    n: CPtr,
    /// `N` with Write and [`BADGE`]: bound.
    n_badged: CPtr,
    /// TSC ticks per millisecond.
    tsc_ms: u64,
}

impl T {
    fn out(&self, reg: u16, v: u8) {
        expect_ok(ioport_out8(self.port, reg, v), "writing COM1");
    }

    fn read(&self, reg: u16) -> u8 {
        expect_ok(ioport_in8(self.port, reg), "reading COM1")
    }

    /// Raises COM1's line: THRI 0 then 1, with the transmitter empty.
    fn edge(&self) {
        self.out(IER, 0);
        let start = rdtsc();
        while self.read(LSR) & LSR_THRE == 0 {
            if rdtsc() - start > 100 * self.tsc_ms {
                self.out(IER, 0);
                fail!("irq: COM1's transmitter never emptied");
            }
        }
        self.out(IER, IER_THRI);
    }

    /// Lowers it: reading IIR clears the THRE cause. Returns IIR.
    fn service(&self) -> u8 {
        self.read(IIR)
    }

    /// What `N` holds after up to `ms` milliseconds of polling: the first
    /// non-zero word, or 0.
    fn signal(&self, ms: u64) -> u64 {
        let start = rdtsc();
        loop {
            let w = poll(self.n);
            if w != 0 || rdtsc() - start > ms * self.tsc_ms {
                return w;
            }
        }
    }

    /// A signal must come.
    fn signalled(&self) -> bool {
        self.signal(500) == BADGE
    }

    /// None may.
    fn quiet(&self) -> bool {
        self.signal(20) == 0
    }

    fn ack(&self, h: CPtr) {
        expect_ok(irq_handler_ack(h), "IRQHandler_Ack");
    }

    fn bind(&self, h: CPtr) {
        expect_ok(
            irq_handler_set_notification(self.ipc, h, self.n_badged),
            "SetNotification",
        );
    }

    /// Ends a phase: THRI off, the line low, `N` drained.
    fn settle(&self) {
        self.out(IER, 0);
        self.service();
        self.signal(5);
    }
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let n = objects
        .retype(ipc, ObjectType::Notification, 0, 1)
        .unwrap_or_else(|e| fail!("irq: retyping the notification: {e}"));
    let first = objects
        .slots
        .alloc(6)
        .unwrap_or_else(|| fail!("irq: no free slots"));
    let (port, n_badged, n_read, h, h2, h3) =
        (first, first + 1, first + 2, first + 3, first + 4, first + 5);
    expect_ok(
        cnode_mint(ipc, root_slot(n_badged), root_slot(n), Rights::WRITE, BADGE),
        "minting N's badged capability",
    );
    expect_ok(
        cnode_copy(ipc, root_slot(n_read), root_slot(n), Rights::READ),
        "copying N with Read",
    );
    expect_ok(
        ioport_control_issue(ipc, CAP_IO_PORT_CONTROL, COM1, COM1 + 7, root_slot(port)),
        "issuing COM1's range",
    );
    let t = T {
        ipc,
        port,
        n,
        n_badged,
        tsc_ms: bi.tsc_hz / 1000,
    };
    let mcr = t.read(MCR);
    t.out(IER, 0);
    t.out(MCR, MCR_OUT2);
    println!(
        "irq: COM1's IOPort in slot {port}, N in slot {n} (badged {BADGE:#x} in {n_badged}); MCR was {mcr:#x}"
    );

    // GetISA(4) and the refusals.
    let control = CAP_IRQ_CONTROL;
    let isa = expect_ok(
        irq_control_get_isa(ipc, control, 4, root_slot(h)),
        "GetISA(4)",
    );
    let want = IsaIrq {
        irq: isa.irq,
        gsi: 4,
        level: false,
        active_low: false,
    };
    if isa != want {
        fail!("irq: GetISA(4) returned {isa:?}");
    }
    expect_err(
        irq_control_get_isa(ipc, control, 4, root_slot(h2)),
        SyscallError::RevokeFirst,
        "GetISA(4) again",
    );
    expect_err(
        irq_control_get_ioapic(ipc, control, 4, true, false, root_slot(h2)),
        SyscallError::RevokeFirst,
        "GetIOAPIC(4)",
    );
    expect_err(
        irq_control_get_isa(ipc, control, 2, root_slot(h2)),
        SyscallError::InvalidArgument(0),
        "GetISA(2)",
    );
    expect_err(
        irq_control_get_isa(ipc, control, 16, root_slot(h2)),
        SyscallError::RangeError { min: 0, max: 15 },
        "GetISA(16)",
    );
    expect_err(
        irq_control_get_isa(ipc, control, 3, root_slot(h)),
        SyscallError::DeleteFirst,
        "GetISA(3) into a full slot",
    );
    expect_err(
        irq_handler_set_notification(ipc, h, n_read),
        SyscallError::InvalidCapability(1),
        "SetNotification without Write",
    );
    println!(
        "irq: ok   GetISA(4) issued IRQ {} for GSI 4, edge, active high; GetISA(4) again and GetIOAPIC(4) are RevokeFirst; GetISA(2) InvalidArgument(0); GetISA(16) RangeError(0, 15); a notification without Write InvalidCapability(1)",
        isa.irq
    );

    // Edge rules. Bind, Ack once, service once.
    t.bind(h);
    t.ack(h);
    t.service();
    // 1: the first edge after an Ack signals; the driver Acks, then
    // services.
    t.edge();
    let first_edge = t.signalled();
    t.ack(h);
    t.service();
    // 2 to 4: after that Ack an edge signals; a second before the next
    // Ack signals too and masks the pin; a third, on the masked pin,
    // signals nothing.
    t.edge();
    let second = t.signalled();
    t.service();
    t.edge();
    let third = t.signalled();
    t.service();
    t.edge();
    let masked = t.quiet();
    t.service();
    // An Ack unmasks: an edge the masked pin latched would arrive now; it
    // is recorded, not required (ADR 0028). The next edge signals.
    t.ack(h);
    let latched = t.signal(20) == BADGE;
    t.edge();
    let rearmed = t.signalled();
    t.ack(h);
    t.service();
    t.settle();
    if !(first_edge && second && third && masked && rearmed) {
        fail!(
            "irq: edge rules: first {first_edge}, second {second}, third {third}, quiet while masked {masked}, after Ack {rearmed}"
        );
    }
    println!(
        "irq: ok   edge: the first edge after an Ack signalled {BADGE:#x}; with no Ack between, a second signalled and a third too, masking the pin; a fourth signalled nothing; after an Ack the next edge signalled again ({})",
        if latched {
            "the I/O APIC latched the masked edge and sent it at the Ack"
        } else {
            "the I/O APIC dropped the masked edge"
        }
    );

    // Clear: nothing bound, nothing signalled; binding again restores it.
    expect_ok(irq_handler_clear(h), "IRQHandler_Clear");
    t.ack(h);
    t.edge();
    let unbound = t.quiet();
    t.service();
    t.bind(h);
    t.ack(h);
    t.edge();
    let bound = t.signalled();
    t.ack(h);
    t.settle();
    if !(unbound && bound) {
        fail!("irq: Clear: quiet unbound {unbound}, signalled bound again {bound}");
    }
    println!(
        "irq: ok   after IRQHandler_Clear an edge signalled nothing; bound again, the next edge signalled"
    );

    // Deletion frees the IRQ; GetIOAPIC(4, level) issues it level.
    expect_ok(cnode_delete(root_slot(h)), "deleting the handler");
    expect_ok(
        irq_control_get_isa(ipc, control, 4, root_slot(h)),
        "GetISA(4) after the deletion",
    );
    expect_ok(cnode_delete(root_slot(h)), "deleting it again");
    let irq = expect_ok(
        irq_control_get_ioapic(ipc, control, 4, true, false, root_slot(h)),
        "GetIOAPIC(4, level)",
    );
    t.bind(h);
    t.ack(h);
    // The line held high signals once, then the pin stays masked.
    t.edge();
    let level_first = t.signalled();
    let level_masked = t.quiet();
    // An Ack while the line is still high: it signals again at once.
    t.ack(h);
    let level_refire = t.signalled();
    // Serviced, then Acked: nothing more (a level driver services first).
    t.service();
    t.ack(h);
    let level_quiet = t.quiet();
    // Deleted with the line high, then reissued: the delivery that follows
    // finds nothing bound; binding and the first Ack bring it.
    t.edge();
    let before_delete = t.signalled();
    expect_ok(
        cnode_delete(root_slot(h)),
        "deleting the level handler with its line high",
    );
    let irq2 = expect_ok(
        irq_control_get_ioapic(ipc, control, 4, true, false, root_slot(h)),
        "reissuing GetIOAPIC(4, level)",
    );
    let unbound_quiet = t.quiet();
    t.bind(h);
    t.ack(h);
    let after_bind = t.signalled();
    t.service();
    t.ack(h);
    t.settle();
    if !(level_first
        && level_masked
        && level_refire
        && level_quiet
        && before_delete
        && unbound_quiet
        && after_bind)
    {
        fail!(
            "irq: level: first {level_first}, masked {level_masked}, refire at Ack {level_refire}, quiet once serviced {level_quiet}, before deletion {before_delete}, quiet unbound {unbound_quiet}, after binding {after_bind}"
        );
    }
    println!(
        "irq: ok   level: GetIOAPIC(4, level) issued IRQ {irq}; the line held high signalled once and masked the pin; an Ack while high signalled again; serviced and Acked, nothing; deleted with the line high and reissued as IRQ {irq2}, nothing until bound, then the first Ack signalled"
    );

    // Copies and revoke.
    expect_ok(
        cnode_copy(ipc, root_slot(h2), root_slot(h), Rights::ALL),
        "copying the handler",
    );
    expect_ok(cnode_delete(root_slot(h)), "deleting the original");
    expect_err(
        irq_control_get_ioapic(ipc, control, 4, false, false, root_slot(h)),
        SyscallError::RevokeFirst,
        "GetIOAPIC(4) with a copy left",
    );
    t.ack(h2);
    expect_ok(cnode_delete(root_slot(h2)), "deleting the copy");
    expect_ok(
        irq_control_get_isa(ipc, control, 4, root_slot(h)),
        "GetISA(4) once the copy is gone",
    );
    expect_ok(
        irq_control_get_isa(ipc, control, 3, root_slot(h3)),
        "GetISA(3)",
    );
    expect_ok(cnode_revoke(root_slot(control)), "revoking IRQControl");
    expect_err(
        irq_handler_ack(h),
        SyscallError::InvalidCapability(0),
        "Ack through a revoked handler",
    );
    expect_err(
        irq_handler_ack(h3),
        SyscallError::InvalidCapability(0),
        "Ack through the other",
    );
    expect_ok(
        irq_control_get_isa(ipc, control, 4, root_slot(h)),
        "GetISA(4) after the revoke",
    );
    expect_ok(cnode_delete(root_slot(h)), "deleting it");
    expect_err(
        cnode_copy(ipc, root_slot(h2), root_slot(control), Rights::ALL),
        SyscallError::IllegalOperation,
        "copying IRQControl",
    );
    t.out(IER, 0);
    t.out(MCR, mcr);
    println!(
        "irq: ok   a copy kept IRQ 4 issued after the original's deletion, and deleting it freed the IRQ; revoking IRQControl deleted both handlers; IRQControl cannot be copied; IER 0, MCR {mcr:#x} again"
    );
    println!("TEST PASS");
    libsys::debug_halt(0)
}
