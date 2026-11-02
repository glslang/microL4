//! A thread's saved user registers and the rules for reading and writing
//! them (`docs/design.md`, "Register frame and restart", "User register set
//! and sanitising" and "Faults"; `docs/abi.md`, "User register set" and
//! "Fault messages").
//!
//! [`Regs`] is the `regs` field of a TCB: 24 words at offset
//! [`crate::tcb::REGS_OFFSET`]. Its order is internal; the general registers
//! come in the order of the M3 trap frame ([`crate::trap::TrapFrame`]) so
//! that entry copies them as a block. The user-visible order, that of
//! `TCB_ReadRegisters`, is [`UserReg`].
//!
//! - [`sanitise`] is what a written register may hold; [`Regs::set_user`],
//!   the one writer of user-visible registers, applies it.
//! - The `rip` rule: [`Regs::user`] reads `next_ip` for a `Running` thread
//!   and `fault_ip` otherwise; writing `rip` sets both.
//! - [`Regs::restart`] and [`Regs::stop_running`] are the Restart and
//!   Suspend rules.
//! - [`Fault`] is a pending fault, with its record in the TCB;
//!   [`fault_message`] encodes it and [`fault_reply`] applies a handler's
//!   reply.

use crate::error::LookupFailure;
use crate::trap::{self, Kind};

/// How the exit path may return to the thread (`docs/design.md`, "Exit").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum Exit {
    /// Entered by an exception or interrupt, or registers were written:
    /// only `iretq` restores every register. The zero value, so a new TCB
    /// leaves by `iretq`.
    Iret = 0,
    /// Entered by `syscall` and unchanged since: `sysretq` may return.
    Sysret = 1,
}

/// A thread's saved user registers: 23 words, padded to 24.
#[repr(C)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Regs {
    pub r15: u64,
    pub r14: u64,
    pub r13: u64,
    pub r12: u64,
    pub r11: u64,
    pub r10: u64,
    pub r9: u64,
    pub r8: u64,
    pub rbp: u64,
    pub rdi: u64,
    pub rsi: u64,
    pub rdx: u64,
    pub rcx: u64,
    pub rbx: u64,
    pub rax: u64,
    pub rsp: u64,
    pub rflags: u64,
    /// The instruction that entered the kernel: the `syscall` (`rcx - 2`)
    /// or the RIP the CPU pushed.
    pub fault_ip: u64,
    /// Where the thread continues: `rcx`, or the pushed RIP.
    pub next_ip: u64,
    pub fs_base: u64,
    pub gs_base: u64,
    /// The exception's error code, 0 for a system call or interrupt.
    pub error: u64,
    /// An [`Exit`] as a word, so that any bit pattern is a valid `Regs`.
    pub exit: u64,
    pub pad: u64,
}

/// Words in [`Regs`].
pub const REGS_WORDS: usize = 24;

const _: () = assert!(core::mem::size_of::<Regs>() == REGS_WORDS * 8);
const _: () = assert!(core::mem::offset_of!(Regs, rax) == 14 * 8);
const _: () = assert!(core::mem::offset_of!(Regs, exit) == 22 * 8);

/// The first non-canonical lower-half address: a `rip`, `rsp`, FS or GS base
/// at or above it is written as 0.
pub const USER_LIMIT: u64 = 0x0000_8000_0000_0000;
/// The RFLAGS bits a register write keeps: CF, PF, AF, ZF, SF, DF, OF.
pub const RFLAGS_USER: u64 = 0x0CD5;
/// The RFLAGS bits a register write sets: bit 1 and IF.
pub const RFLAGS_FIXED: u64 = 0x0202;
/// RFLAGS of a new thread: bit 1 and IF.
pub const RFLAGS_INITIAL: u64 = 0x0202;

/// Words in the user register set.
pub const USER_REGS: usize = 20;
/// The frame registers, words 0 to 17: what `CopyRegisters`'
/// `transfer_frame` copies. Words 18 and 19 are the "integer" registers.
pub const FRAME_REGS: usize = 18;

/// The user register set (`docs/abi.md`, "User register set"): seL4's
/// `seL4_UserContext` order for x86_64. The discriminant is the word index.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
#[repr(u8)]
pub enum UserReg {
    Rip = 0,
    Rsp = 1,
    Rflags = 2,
    Rax = 3,
    Rbx = 4,
    Rcx = 5,
    Rdx = 6,
    Rsi = 7,
    Rdi = 8,
    Rbp = 9,
    R8 = 10,
    R9 = 11,
    R10 = 12,
    R11 = 13,
    R12 = 14,
    R13 = 15,
    R14 = 16,
    R15 = 17,
    FsBase = 18,
    GsBase = 19,
}

impl UserReg {
    /// Every user register, in word order.
    pub const ALL: [UserReg; USER_REGS] = [
        UserReg::Rip,
        UserReg::Rsp,
        UserReg::Rflags,
        UserReg::Rax,
        UserReg::Rbx,
        UserReg::Rcx,
        UserReg::Rdx,
        UserReg::Rsi,
        UserReg::Rdi,
        UserReg::Rbp,
        UserReg::R8,
        UserReg::R9,
        UserReg::R10,
        UserReg::R11,
        UserReg::R12,
        UserReg::R13,
        UserReg::R14,
        UserReg::R15,
        UserReg::FsBase,
        UserReg::GsBase,
    ];

    /// The register at word `i`, if `i` is below [`USER_REGS`].
    pub const fn from_index(i: usize) -> Option<UserReg> {
        if i < USER_REGS {
            Some(UserReg::ALL[i])
        } else {
            None
        }
    }

    /// The word index.
    pub const fn index(self) -> usize {
        self as usize
    }
}

/// What a written register may hold (`docs/abi.md`, "User register set"):
/// a `rip`, `rsp`, FS or GS base at or above [`USER_LIMIT`] becomes 0;
/// `rflags` keeps CF, PF, AF, ZF, SF, DF and OF and gets bit 1 and IF, so
/// TF, IOPL, NT, RF, VM, AC, VIF, VIP and ID are clear; the rest are
/// unchanged.
pub const fn sanitise(r: UserReg, v: u64) -> u64 {
    match r {
        UserReg::Rip | UserReg::Rsp | UserReg::FsBase | UserReg::GsBase => {
            if v >= USER_LIMIT {
                0
            } else {
                v
            }
        }
        UserReg::Rflags => (v & RFLAGS_USER) | RFLAGS_FIXED,
        _ => v,
    }
}

/// The message registers MR0 to MR3 live in `r10`, `r8`, `r9` and `r15`
/// (`docs/abi.md`, "System calls").
pub const REGISTER_MRS: usize = 4;

impl Regs {
    /// A new thread's registers (`docs/abi.md`, "TCB object"): every
    /// register 0 but `rflags`, [`RFLAGS_INITIAL`]; it leaves by `iretq`.
    pub const fn new_thread() -> Regs {
        Regs {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rbp: 0,
            rdi: 0,
            rsi: 0,
            rdx: 0,
            rcx: 0,
            rbx: 0,
            rax: 0,
            rsp: 0,
            rflags: RFLAGS_INITIAL,
            fault_ip: 0,
            next_ip: 0,
            fs_base: 0,
            gs_base: 0,
            error: 0,
            exit: Exit::Iret as u64,
            pad: 0,
        }
    }

    /// The exit kind; any value but `Sysret`'s reads as `Iret`, the safe
    /// one.
    pub const fn exit(&self) -> Exit {
        if self.exit == Exit::Sysret as u64 {
            Exit::Sysret
        } else {
            Exit::Iret
        }
    }

    /// Sets the exit kind.
    pub fn set_exit(&mut self, exit: Exit) {
        self.exit = exit as u64;
    }

    /// The user-visible value of `r`, as `TCB_ReadRegisters` returns it:
    /// `rip` is `next_ip` for a `Running` thread, else `fault_ip`, the
    /// instruction a restarted thread runs again. Reads return the stored
    /// values; they were sanitised when written.
    pub const fn user(&self, r: UserReg, running: bool) -> u64 {
        match r {
            UserReg::Rip => {
                if running {
                    self.next_ip
                } else {
                    self.fault_ip
                }
            }
            UserReg::Rsp => self.rsp,
            UserReg::Rflags => self.rflags,
            UserReg::Rax => self.rax,
            UserReg::Rbx => self.rbx,
            UserReg::Rcx => self.rcx,
            UserReg::Rdx => self.rdx,
            UserReg::Rsi => self.rsi,
            UserReg::Rdi => self.rdi,
            UserReg::Rbp => self.rbp,
            UserReg::R8 => self.r8,
            UserReg::R9 => self.r9,
            UserReg::R10 => self.r10,
            UserReg::R11 => self.r11,
            UserReg::R12 => self.r12,
            UserReg::R13 => self.r13,
            UserReg::R14 => self.r14,
            UserReg::R15 => self.r15,
            UserReg::FsBase => self.fs_base,
            UserReg::GsBase => self.gs_base,
        }
    }

    /// Writes `r`, sanitised. Writing `rip` sets both `fault_ip` and
    /// `next_ip`. Any write makes the thread leave by `iretq`, because
    /// `sysretq` would overwrite `rcx` and `r11`.
    pub fn set_user(&mut self, r: UserReg, v: u64) {
        let v = sanitise(r, v);
        match r {
            UserReg::Rip => {
                self.fault_ip = v;
                self.next_ip = v;
            }
            UserReg::Rsp => self.rsp = v,
            UserReg::Rflags => self.rflags = v,
            UserReg::Rax => self.rax = v,
            UserReg::Rbx => self.rbx = v,
            UserReg::Rcx => self.rcx = v,
            UserReg::Rdx => self.rdx = v,
            UserReg::Rsi => self.rsi = v,
            UserReg::Rdi => self.rdi = v,
            UserReg::Rbp => self.rbp = v,
            UserReg::R8 => self.r8 = v,
            UserReg::R9 => self.r9 = v,
            UserReg::R10 => self.r10 = v,
            UserReg::R11 => self.r11 = v,
            UserReg::R12 => self.r12 = v,
            UserReg::R13 => self.r13 = v,
            UserReg::R14 => self.r14 = v,
            UserReg::R15 => self.r15 = v,
            UserReg::FsBase => self.fs_base = v,
            UserReg::GsBase => self.gs_base = v,
        }
        self.set_exit(Exit::Iret);
    }

    /// Activating a `Restart` thread: it continues at `fault_ip`, re-running
    /// its system call or faulting instruction.
    pub fn restart(&mut self) {
        self.next_ip = self.fault_ip;
    }

    /// Suspending a `Running` thread: `fault_ip` moves to `next_ip`, so a
    /// later Resume, which restarts at `fault_ip`, does not repeat a
    /// finished system call (seL4 `suspend`, `updateRestartPC`).
    pub fn stop_running(&mut self) {
        self.fault_ip = self.next_ip;
    }

    /// Message register `i`, for `i` below [`REGISTER_MRS`]: MR0 to MR3 are
    /// `r10`, `r8`, `r9` and `r15`.
    pub const fn message_register(&self, i: usize) -> u64 {
        match i {
            0 => self.r10,
            1 => self.r8,
            2 => self.r9,
            3 => self.r15,
            _ => panic!("MR4 and up are in the IPC buffer"),
        }
    }

    /// Sets message register `i`, for `i` below [`REGISTER_MRS`]. `sysretq`
    /// preserves these registers, so the exit kind is unchanged.
    pub fn set_message_register(&mut self, i: usize, v: u64) {
        match i {
            0 => self.r10 = v,
            1 => self.r8 = v,
            2 => self.r9 = v,
            3 => self.r15 = v,
            _ => panic!("MR4 and up are in the IPC buffer"),
        }
    }
}

// ---------------------------------------------------------------------------
// Faults
// ---------------------------------------------------------------------------

/// Fault message labels (`docs/abi.md`, "Fault messages"): seL4's x86
/// non-MCS numbers. 4 is reserved; 0 and 6 up are never sent.
pub mod fault_label {
    pub const CAP_FAULT: u64 = 1;
    pub const UNKNOWN_SYSCALL: u64 = 2;
    pub const USER_EXCEPTION: u64 = 3;
    pub const VM_FAULT: u64 = 5;
}

/// A fault a thread is delivering or awaiting the reply to (`docs/design.md`,
/// "Fault types and sources"). Only the fault's own data is kept; the
/// message reads the thread's registers when it is encoded.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Fault {
    /// A lookup of `addr` failed, in the send or the receive phase.
    CapFault {
        addr: u64,
        in_recv_phase: bool,
        failure: LookupFailure,
    },
    /// `rdx` named no system call; `number` is that `rdx`.
    UnknownSyscall { number: u64 },
    /// A ring-3 exception other than `#PF`: its vector and error code.
    UserException { number: u64, code: u64 },
    /// A ring-3 `#PF`: CR2 and the error code.
    VmFault { addr: u64, fsr: u64 },
}

/// Words of a fault record in a TCB: the kind (0 for none) and six words
/// of data.
pub const FAULT_WORDS: usize = 7;

/// The longest fault message, `UnknownSyscall`'s.
pub const FAULT_MESSAGE_MAX: usize = 19;

/// The `#PF` error code bit for an instruction fetch.
const FSR_FETCH: u64 = 1 << 4;

impl Fault {
    /// The fault a ring-3 exception raises (`docs/design.md`, "Fault types
    /// and sources"): a `#PF` is a VMFault with CR2 and the error code;
    /// every other exception a thread can cause is a UserException, with the
    /// error code for the vectors whose CPU pushes one (10 to 13) and 0
    /// otherwise. `None` for a vector that is not a fault: NMI, `#DF`,
    /// `#MC`, the vectors that cannot occur, and every interrupt vector.
    pub const fn from_exception(vector: u8, error: u64, cr2: u64) -> Option<Fault> {
        match trap::kind(vector) {
            Kind::Exception if vector == trap::PAGE_FAULT => Some(Fault::VmFault {
                addr: cr2,
                fsr: error,
            }),
            Kind::Exception => Some(Fault::UserException {
                number: vector as u64,
                code: if trap::cpu_pushes_error_code(vector) {
                    error
                } else {
                    0
                },
            }),
            _ => None,
        }
    }

    /// The message label: the fault type.
    pub const fn label(&self) -> u64 {
        match self {
            Fault::CapFault { .. } => fault_label::CAP_FAULT,
            Fault::UnknownSyscall { .. } => fault_label::UNKNOWN_SYSCALL,
            Fault::UserException { .. } => fault_label::USER_EXCEPTION,
            Fault::VmFault { .. } => fault_label::VM_FAULT,
        }
    }

    /// The record a TCB stores: the label, then the data.
    pub fn to_words(&self) -> [u64; FAULT_WORDS] {
        match *self {
            Fault::CapFault {
                addr,
                in_recv_phase,
                failure,
            } => {
                let (f, _) = failure.words();
                [
                    self.label(),
                    addr,
                    in_recv_phase as u64,
                    f[0],
                    f[1],
                    f[2],
                    f[3],
                ]
            }
            Fault::UnknownSyscall { number } => [self.label(), number, 0, 0, 0, 0, 0],
            Fault::UserException { number, code } => [self.label(), number, code, 0, 0, 0, 0],
            Fault::VmFault { addr, fsr } => [self.label(), addr, fsr, 0, 0, 0, 0],
        }
    }

    /// The fault a record holds, or `None` for no fault. A record no fault
    /// writes also reads as `None`.
    pub fn from_words(w: [u64; FAULT_WORDS]) -> Option<Fault> {
        match w[0] {
            fault_label::CAP_FAULT => Some(Fault::CapFault {
                addr: w[1],
                in_recv_phase: w[2] != 0,
                failure: lookup_failure([w[3], w[4], w[5], w[6]])?,
            }),
            fault_label::UNKNOWN_SYSCALL => Some(Fault::UnknownSyscall { number: w[1] }),
            fault_label::USER_EXCEPTION => Some(Fault::UserException {
                number: w[1],
                code: w[2],
            }),
            fault_label::VM_FAULT => Some(Fault::VmFault {
                addr: w[1],
                fsr: w[2],
            }),
            _ => None,
        }
    }
}

/// A lookup failure from its description words, the inverse of
/// [`LookupFailure::words`].
fn lookup_failure(w: [u64; 4]) -> Option<LookupFailure> {
    let bits = |v: u64| u32::try_from(v).ok();
    match w[0] {
        1 => Some(LookupFailure::InvalidRoot),
        2 => Some(LookupFailure::MissingCapability {
            bits_left: bits(w[1])?,
        }),
        3 => Some(LookupFailure::DepthMismatch {
            bits_left: bits(w[1])?,
            bits_found: bits(w[2])?,
        }),
        4 => Some(LookupFailure::GuardMismatch {
            bits_left: bits(w[1])?,
            guard: w[2],
            guard_size: bits(w[3])?,
        }),
        _ => None,
    }
}

/// A fault message (`docs/abi.md`, "Fault messages"): the label, and the
/// first `length` words of `words` as MR0 and up. Words past MR3 reach the
/// handler only through a writable IPC buffer; the sender cuts `length` to
/// 4 otherwise.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FaultMessage {
    pub label: u64,
    pub words: [u64; FAULT_MESSAGE_MAX],
    pub length: usize,
}

impl FaultMessage {
    /// The message words, MR0 first.
    pub fn mrs(&self) -> &[u64] {
        &self.words[..self.length]
    }
}

/// The `UnknownSyscall` message's registers, MR0 to MR17, which its reply
/// may set in the same order.
const UNKNOWN_SYSCALL_REGS: [UserReg; 18] = [
    UserReg::Rax,
    UserReg::Rbx,
    UserReg::Rcx,
    UserReg::Rdx,
    UserReg::Rsi,
    UserReg::Rdi,
    UserReg::Rbp,
    UserReg::R8,
    UserReg::R9,
    UserReg::R10,
    UserReg::R11,
    UserReg::R12,
    UserReg::R13,
    UserReg::R14,
    UserReg::R15,
    UserReg::Rip,
    UserReg::Rsp,
    UserReg::Rflags,
];

/// The `UserException` message's registers, MR0 to MR2, which its reply may
/// set.
const USER_EXCEPTION_REGS: [UserReg; 3] = [UserReg::Rip, UserReg::Rsp, UserReg::Rflags];

/// Encodes `fault`, raised by the thread whose registers are `regs`. `ip` is
/// `fault_ip`: the `syscall` instruction, or the RIP the exception pushed.
/// Reads nothing but `fault` and `regs`.
pub fn fault_message(fault: &Fault, regs: &Regs) -> FaultMessage {
    let mut words = [0; FAULT_MESSAGE_MAX];
    let length = match *fault {
        Fault::CapFault {
            addr,
            in_recv_phase,
            failure,
        } => {
            let (f, n) = failure.words();
            words[..3].copy_from_slice(&[regs.fault_ip, addr, in_recv_phase as u64]);
            words[3..3 + n].copy_from_slice(&f[..n]);
            3 + n
        }
        Fault::UnknownSyscall { number } => {
            for (w, r) in words.iter_mut().zip(UNKNOWN_SYSCALL_REGS) {
                *w = regs.user(r, false);
            }
            words[18] = number;
            19
        }
        Fault::UserException { number, code } => {
            words[..5].copy_from_slice(&[regs.fault_ip, regs.rsp, regs.rflags, number, code]);
            5
        }
        Fault::VmFault { addr, fsr } => {
            let prefetch = (fsr & FSR_FETCH != 0) as u64;
            words[..4].copy_from_slice(&[regs.fault_ip, addr, prefetch, fsr]);
            4
        }
    };
    FaultMessage {
        label: fault.label(),
        words,
        length,
    }
}

/// What a fault reply does to the faulting thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum FaultOutcome {
    /// Label 0: the thread becomes `Restart` and runs its `rip` again.
    Restart,
    /// Any other label: the thread becomes `Inactive`.
    Inactive,
}

/// Applies a handler's reply to the thread that raised `fault`
/// (`docs/abi.md`, "Fault replies"). `mrs` is the reply as delivered: MR0
/// up to its length, already cut to 4 words if the handler's IPC buffer is
/// not readable. An `UnknownSyscall` reply sets the first `min(length, 18)`
/// registers in the order of its message, a `UserException` reply the first
/// `min(length, 3)`, whatever the label, through [`Regs::set_user`]; the
/// others set none. Returns what label `label` makes of the thread.
pub fn fault_reply(fault: &Fault, label: u64, mrs: &[u64], regs: &mut Regs) -> FaultOutcome {
    let settable: &[UserReg] = match fault {
        Fault::UnknownSyscall { .. } => &UNKNOWN_SYSCALL_REGS,
        Fault::UserException { .. } => &USER_EXCEPTION_REGS,
        Fault::CapFault { .. } | Fault::VmFault { .. } => &[],
    };
    for (r, v) in settable.iter().zip(mrs) {
        regs.set_user(*r, *v);
    }
    if label == 0 {
        FaultOutcome::Restart
    } else {
        FaultOutcome::Inactive
    }
}

#[cfg(test)]
mod tests;
