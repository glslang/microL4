//! The M5 red-team tests (`docs/redteam/`): ring-3 attempts to get into
//! ring 0, to raise IOPL, to load a segment the kernel did not, to reach
//! kernel memory or a page through a stale TLB entry, and to crash the
//! kernel through faults or by deleting a thread's own objects under it.
//!
//! - `test=redteam-exceptions` ([`exceptions`]): one thread runs
//!   [`probes::EXCEPTIONS`], each a privileged or faulting instruction
//!   sequence, with the root task as its fault handler. Every probe must
//!   end in exactly the fault `docs/abi.md` names for it.
//! - `test=redteam-movss` ([`mov_ss`]): the same for [`probes::MOV_SS`],
//!   `mov ss` with TF set followed by a control transfer.
//! - `test=redteam-tlb` and `test=redteam-selfdelete`: [`vm`].
//!
//! Every test ends with `TEST PASS` and `DebugHalt(0)`, or `TEST FAIL`.

mod probes;
mod vm;

use libsys::bootinfo::{CAP_INIT_CNODE, CAP_INIT_TCB, CAP_INIT_VSPACE};
use libsys::invoke::{
    Slot, cnode_mint, tcb_configure, tcb_read_registers, tcb_set_priority, tcb_write_registers,
};
use libsys::{BootInfo, CPtr, Ipc, ObjectAlloc, ObjectType, Registers, Rights, UserReg, println};

use crate::fail;
use crate::spawn::STACKS;

/// Words in the user register set (`docs/abi.md`, "User register set").
pub(crate) const USER_REGS: usize = 20;

/// The probing thread's priority, below the root task's 255.
const PROBER_PRIORITY: u64 = 100;
/// The badge of the probing thread's fault endpoint.
const FAULT_BADGE: u64 = 0xFA;

/// `MessageInfo` labels of the faults (`docs/abi.md`, "Fault messages").
const UNKNOWN_SYSCALL: u64 = 2;
const USER_EXCEPTION: u64 = 3;
const VM_FAULT: u64 = 5;
/// The page-fault error code's instruction-fetch bit.
const PF_FETCH: u64 = 1 << 4;
/// RFLAGS bits.
const RFLAGS_TF: u64 = 1 << 8;
const RFLAGS_IOPL: u64 = 3 << 12;

/// What one probe must end in.
#[derive(Clone, Copy, Debug)]
pub enum Expect {
    /// A UserException for this vector, with this error code if `Some`.
    Ue(u64, Option<u64>),
    /// A UserException for either vector: the CPU or emulator decides.
    UeEither(u64, u64),
    /// A VMFault, an instruction fetch or not.
    Vm { fetch: bool },
    /// An UnknownSyscall fault.
    Unknown,
    /// Hardware: this UserException vector. QEMU 8.2 TCG raises a #PF
    /// instead for a non-canonical address, so a VMFault passes too.
    UeOrVm(u64),
    /// Hardware: this UserException vector. QEMU 8.2 TCG checks no MXCSR
    /// reserved bits and raises no #XM, so no fault at all passes too.
    UeOrNothing(u64),
    /// Hardware: #GP with this code. QEMU 8.2 TCG pops a `retfq` or
    /// `iretq` frame off the user stack with a supervisor access, which
    /// SMAP faults first: a VMFault for a present page, read, not user
    /// (fsr 1), passes too.
    GpOrSmapVm(u64),
    /// As the inner expectation, or QEMU 8.2's SMAP VMFault.
    SmapVmOr(&'static Expect),
}

/// One probe: a name for the log and what it must end in.
#[derive(Clone, Copy, Debug)]
pub struct Probe {
    pub name: &'static str,
    pub expect: Expect,
}

/// A fault as the handler received it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Seen {
    label: u64,
    /// UserException: vector and code. VMFault: prefetch and fsr.
    /// UnknownSyscall: the number and 0.
    a: u64,
    b: u64,
    ip: u64,
}

impl Seen {
    fn matches(&self, e: Expect) -> bool {
        match e {
            Expect::Ue(v, code) => {
                self.label == USER_EXCEPTION && self.a == v && code.is_none_or(|c| c == self.b)
            }
            Expect::UeEither(v, w) => self.label == USER_EXCEPTION && (self.a == v || self.a == w),
            Expect::Vm { fetch } => {
                self.label == VM_FAULT
                    && (self.a == 1) == fetch
                    && (self.b & PF_FETCH != 0) == fetch
            }
            Expect::Unknown => self.label == UNKNOWN_SYSCALL,
            Expect::UeOrVm(v) | Expect::UeOrNothing(v) => {
                (self.label == USER_EXCEPTION && self.a == v) || self.label == VM_FAULT
            }
            Expect::GpOrSmapVm(code) => {
                self.matches(Expect::Ue(13, Some(code))) || self.is_qemu_smap_fault()
            }
            Expect::SmapVmOr(e) => self.matches(*e) || self.is_qemu_smap_fault(),
        }
    }

    /// QEMU 8.2 TCG's fault for a user `retfq` or `iretq` under SMAP: a
    /// supervisor read of a present page, at the instruction.
    fn is_qemu_smap_fault(&self) -> bool {
        self.label == VM_FAULT && self.a == 0 && self.b == 1
    }
}

impl Expect {
    /// Whether the probe may run through without a fault.
    fn may_not_fault(self) -> bool {
        matches!(self, Expect::UeOrNothing(_))
    }
}

/// Runs the named red-team test.
pub fn run(bi: &BootInfo, name: &str) -> ! {
    match name {
        "redteam-exceptions" => exceptions(bi),
        "redteam-movss" => mov_ss(bi),
        "redteam-tlb" => vm::tlb(bi),
        "redteam-selfdelete" => vm::self_delete(bi),
        other => fail!("unknown red-team test {other:?}"),
    }
}

unsafe extern "C" {
    /// The probe sequences and their resume offsets (`probes`).
    fn rtx_entry();
    static rtx_resume: [u64; probes::EXCEPTIONS.len()];
    fn rtm_entry();
    static rtm_resume: [u64; probes::MOV_SS.len()];
}

/// `test=redteam-exceptions`.
fn exceptions(bi: &BootInfo) -> ! {
    // SAFETY: `probes` defines `rtx_resume` as one quadword per probe in
    // read-only data; nothing writes it.
    let resume = unsafe { &rtx_resume };
    run_probes(
        bi,
        "exceptions",
        rtx_entry as *const () as u64,
        resume,
        &probes::EXCEPTIONS,
    )
}

/// `test=redteam-movss`.
fn mov_ss(bi: &BootInfo) -> ! {
    // SAFETY: as in `exceptions`, for `rtm_resume`.
    let resume = unsafe { &rtm_resume };
    run_probes(
        bi,
        "movss",
        rtm_entry as *const () as u64,
        resume,
        &probes::MOV_SS,
    )
}

/// A thread in the root task's CSpace and VSpace, at
/// [`PROBER_PRIORITY`], whose faults come to `ep` with [`FAULT_BADGE`].
/// Returns its TCB; it stays `Inactive`.
pub(crate) fn prober(ipc: Ipc, objects: &mut ObjectAlloc<'_>, ep: CPtr) -> CPtr {
    let tcb = objects
        .retype(ipc, ObjectType::Tcb, 0, 1)
        .unwrap_or_else(|e| fail!("retyping the prober's TCB: {e}"));
    let fault_ep = objects
        .slots
        .alloc(1)
        .unwrap_or_else(|| fail!("no slot for the prober's fault endpoint"));
    mint_fault_ep(ipc, ep, fault_ep);
    tcb_configure(ipc, tcb, fault_ep, CAP_INIT_CNODE, 0, CAP_INIT_VSPACE, None)
        .and_then(|()| tcb_set_priority(ipc, tcb, CAP_INIT_TCB, PROBER_PRIORITY))
        .unwrap_or_else(|e| fail!("configuring the prober: {e}"));
    tcb
}

/// Puts a copy of endpoint `ep` badged [`FAULT_BADGE`] in root slot `slot`.
pub(crate) fn mint_fault_ep(ipc: Ipc, ep: CPtr, slot: CPtr) {
    cnode_mint(
        ipc,
        Slot::root_cnode(slot),
        Slot::root_cnode(ep),
        Rights::ALL,
        FAULT_BADGE,
    )
    .unwrap_or_else(|e| fail!("minting a fault endpoint: {e}"));
}

/// Starts `tcb` at `rip` with `rsp` and the argument registers, as a
/// register write with resume.
pub(crate) fn start(ipc: Ipc, tcb: CPtr, rip: u64, rsp: u64, args: [u64; 3]) {
    let regs = Registers::ZERO
        .with(UserReg::Rip, rip)
        .with(UserReg::Rsp, rsp)
        .with(UserReg::Rflags, 0x202)
        .with(UserReg::Rdi, args[0])
        .with(UserReg::Rsi, args[1])
        .with(UserReg::Rdx, args[2]);
    tcb_write_registers(ipc, tcb, true, &regs, USER_REGS)
        .unwrap_or_else(|e| fail!("starting thread {tcb}: {e}"));
}

/// Runs the probes from `entry` in a new thread with the root task as its
/// fault handler, then passes or fails the test.
fn run_probes(bi: &BootInfo, name: &str, entry: u64, resume: &[u64], probes: &[Probe]) -> ! {
    let ipc = Ipc::root();
    let mut objects = ObjectAlloc::new(bi);
    let ep = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("retyping the endpoint: {e}"));
    let tcb = prober(ipc, &mut objects, ep);
    println!(
        "redteam: {name}: {} probes in thread {tcb} at priority {PROBER_PRIORITY}, the root task its fault handler",
        probes.len()
    );
    start(ipc, tcb, entry, STACKS[0].top() - 8, [0; 3]);

    let mut failures = 0;
    let mut next = 0;
    loop {
        let r = libsys::recv(ep);
        if r.badge != FAULT_BADGE {
            fail!("a message with badge {:#x} on the fault endpoint", r.badge);
        }
        let label = r.msg.info.label();
        let (a, b) = match label {
            USER_EXCEPTION => (r.msg.mr[3], ipc.mr(4)),
            VM_FAULT => (r.msg.mr[2], r.msg.mr[3]),
            UNKNOWN_SYSCALL => (ipc.mr(18), 0),
            _ => (r.msg.mr[1], r.msg.mr[2]),
        };
        let seen = Seen {
            label,
            a,
            b,
            ip: if label == UNKNOWN_SYSCALL {
                ipc.mr(15)
            } else {
                r.msg.mr[0]
            },
        };
        // Suspending cancels the fault IPC; the registers then show where
        // the thread stopped.
        let regs = tcb_read_registers(Some(ipc), tcb, true, USER_REGS)
            .unwrap_or_else(|e| fail!("reading the prober's registers: {e}"));
        let k = regs.get(UserReg::R13) as usize;
        if k == probes.len() {
            break;
        }
        if k >= probes.len() || k < next {
            fail!("a fault {seen:x?} with r13 {k}, after probe {next}");
        }
        for (skipped, p) in probes.iter().enumerate().take(k).skip(next) {
            let ok = p.expect.may_not_fault();
            println!(
                "redteam: {name}: probe {skipped} ({}): no fault{}",
                p.name,
                if ok { " (QEMU 8.2 TCG)" } else { ": WRONG" }
            );
            if !ok {
                failures += 1;
            }
        }
        let p = probes[k];
        let ok = seen.matches(p.expect);
        if !ok {
            failures += 1;
        }
        let rflags = regs.get(UserReg::Rflags);
        println!(
            "redteam: {name}: probe {k} ({}): label {label}, {:#x}/{:#x} at ip {:#x}, rsp {:#x}, rflags {rflags:#x}{}",
            p.name,
            seen.a,
            seen.b,
            seen.ip,
            regs.get(UserReg::Rsp),
            if ok { "" } else { ": WRONG" }
        );
        if rflags & RFLAGS_IOPL != 0 {
            println!("redteam: {name}: probe {k}: the thread ran with IOPL > 0");
            failures += 1;
        }
        check_probe(name, k, p, &seen, &regs, &mut failures);
        let rbx = regs.get(UserReg::Rbx);
        let regs = regs
            .with(UserReg::Rip, entry + resume[k])
            .with(UserReg::Rsp, rbx);
        tcb_write_registers(ipc, tcb, true, &regs, USER_REGS)
            .unwrap_or_else(|e| fail!("resuming the prober after probe {k}: {e}"));
        next = k + 1;
    }
    if failures != 0 {
        fail!("redteam: {name}: {failures} probes ended wrong");
    }
    println!(
        "redteam: {name}: all {} probes ended in their own fault",
        probes.len()
    );
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// Checks a probe's register state beyond its fault.
fn check_probe(name: &str, k: usize, p: Probe, seen: &Seen, regs: &Registers, failures: &mut u32) {
    let rsp = regs.get(UserReg::Rsp);
    // A system call with RSP outside the lower half returns with RSP 0.
    if p.name.starts_with("syscall (Yield) with a") && rsp != 0 {
        println!("redteam: {name}: probe {k}: rsp {rsp:#x} after the syscall, want 0");
        *failures += 1;
    }
    // AC survives a system call as the ABI says: the kernel runs with it
    // clear (FMASK, clac) and gives it back.
    if p.name.starts_with("AC and DF set") && regs.get(UserReg::Rflags) & (1 << 18) == 0 {
        println!("redteam: {name}: probe {k}: AC was lost across the syscall");
        *failures += 1;
    }
    // TF across a syscall traps after it, in ring 3, at the return
    // address.
    if p.name == "TF set across syscall (Yield)" && regs.get(UserReg::Rflags) & RFLAGS_TF == 0 {
        println!("redteam: {name}: probe {k}: TF was lost across the syscall");
        *failures += 1;
    }
    let _ = seen;
}
