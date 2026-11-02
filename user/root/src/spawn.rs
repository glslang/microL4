//! Threads in the root task's own CSpace and VSpace, on two stacks of its
//! image, each above an unmapped guard page.

use core::cell::UnsafeCell;

use libsys::bootinfo::{CAP_INIT_CNODE, CAP_INIT_VSPACE};
use libsys::invoke::{tcb_configure, tcb_write_registers};
use libsys::{CPtr, Error, Ipc, Registers, UserReg};

/// Bytes of each thread's stack.
pub const STACK_BYTES: usize = 16 << 10;

/// RFLAGS of a new thread: bit 1 and IF.
const RFLAGS: u64 = 0x202;

/// A thread's stack, 16-byte aligned at both ends.
#[repr(C, align(16))]
pub struct Stack(UnsafeCell<[u8; STACK_BYTES]>);

// SAFETY: the root task never reads or writes a stack's bytes, only takes
// the address of its top; the one thread a stack is given to uses it
// through its own `rsp`.
unsafe impl Sync for Stack {}

impl Stack {
    const fn new() -> Stack {
        Stack(UnsafeCell::new([0; STACK_BYTES]))
    }

    /// One past its last byte.
    pub fn top(&self) -> u64 {
        self.0.get() as u64 + STACK_BYTES as u64
    }

    /// Whether `addr` lies in it.
    pub fn contains(&self, addr: u64) -> bool {
        (self.top() - STACK_BYTES as u64..self.top()).contains(&addr)
    }
}

/// The stacks. A test gives each to at most one thread.
pub static STACKS: [&Stack; 2] = [&STACK0, &STACK1];

// Each in a segment of its own above an unmapped guard page
// (`user/link.ld`), so an overflow faults instead of running into `.bss`
// or the other stack.
#[unsafe(link_section = ".thread_stack.0")]
static STACK0: Stack = Stack::new();
#[unsafe(link_section = ".thread_stack.1")]
static STACK1: Stack = Stack::new();

/// A thread's entry point. It takes four words, in `rdi`, `rsi`, `rdx` and
/// `rcx`, and never returns.
pub type Entry = extern "C" fn(u64, u64, u64, u64) -> !;

/// A thread to start.
pub struct Thread {
    pub tcb: CPtr,
    /// Its fault endpoint, a `CPtr` in the root task's CSpace.
    pub fault_ep: CPtr,
    pub stack: &'static Stack,
    pub entry: Entry,
    pub args: [u64; 4],
}

/// Configures `t`'s TCB with the root task's CSpace and VSpace, no IPC
/// buffer and its fault endpoint, and writes its registers: `rip` at its
/// entry, `rsp` 8 below its stack's top as if a `call` had pushed a return
/// address (the System V ABI wants `rsp + 8` 16-byte aligned at a
/// function's first instruction), and its arguments. The thread stays
/// `Inactive`; its priority and `TCB_Resume` are the caller's.
pub fn prepare(ipc: Ipc, t: &Thread) -> Result<(), Error> {
    tcb_configure(
        ipc,
        t.tcb,
        t.fault_ep,
        CAP_INIT_CNODE,
        0,
        CAP_INIT_VSPACE,
        None,
    )?;
    let [a0, a1, a2, a3] = t.args;
    let regs = Registers::ZERO
        .with(UserReg::Rip, t.entry as usize as u64)
        .with(UserReg::Rsp, t.stack.top() - 8)
        .with(UserReg::Rflags, RFLAGS)
        .with(UserReg::Rdi, a0)
        .with(UserReg::Rsi, a1)
        .with(UserReg::Rdx, a2)
        .with(UserReg::Rcx, a3);
    // Words 0 to 8: rip to rdi.
    tcb_write_registers(ipc, t.tcb, false, &regs, UserReg::Rdi.index() + 1)
}
