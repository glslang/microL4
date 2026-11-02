//! A thread's saved user registers (`docs/design.md`, "Register frame and
//! restart").
//!
//! [`Regs`] is the `regs` field of a TCB: 24 words at offset
//! [`crate::tcb::REGS_OFFSET`]. Its order is internal; the general registers
//! come in the order of the M3 trap frame ([`crate::trap::TrapFrame`]) so
//! that entry copies them as a block. The user-visible register order of
//! `TCB_ReadRegisters` is `docs/abi.md`'s "User register set", not this one.
//! M5 adds the user register set, `sanitise`, and the fault encoder and
//! reply decoder here.

/// How the exit path may return to the thread (`docs/design.md`, "Exit").
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum Exit {
    /// Entered by `syscall` and unchanged since: `sysretq` may return.
    Sysret = 0,
    /// Entered by an exception or interrupt, or registers were written:
    /// only `iretq` restores every register.
    Iret = 1,
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

impl Regs {
    /// The exit kind; any value but `Sysret`'s reads as `Iret`, the safe
    /// one.
    pub const fn exit(&self) -> Exit {
        if self.exit == Exit::Sysret as u64 {
            Exit::Sysret
        } else {
            Exit::Iret
        }
    }
}
