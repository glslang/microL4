//! Threads in the root task's VSpace, on the stacks of its image, each
//! above an unmapped guard page, in the root task's CSpace or one of their
//! own.

use core::cell::UnsafeCell;
use core::ptr::NonNull;

use libsys::bootinfo::{CAP_INIT_CNODE, CAP_INIT_IPC_BUFFER, CAP_INIT_TCB, CAP_INIT_VSPACE};
use libsys::invoke::{tcb_configure, tcb_set_priority, tcb_write_registers};
use libsys::ipc::IPC_BUFFER_SIZE;
use libsys::{BootInfo, CPtr, Error, Ipc, IpcBuffer, IpcBufferFrame, Registers, UserReg};

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

    /// The unmapped guard page below it (`user/link.ld`).
    pub fn guard(&self) -> u64 {
        self.top() - STACK_BYTES as u64 - 0x1000
    }
}

/// The stacks. A test gives each to at most one thread.
pub static STACKS: [&Stack; 6] = [&STACK0, &STACK1, &STACK2, &STACK3, &STACK4, &STACK5];

// Each in a segment of its own above an unmapped guard page
// (`user/link.ld`), so an overflow faults instead of running into `.bss`
// or another stack.
#[unsafe(link_section = ".thread_stack.0")]
static STACK0: Stack = Stack::new();
#[unsafe(link_section = ".thread_stack.1")]
static STACK1: Stack = Stack::new();
#[unsafe(link_section = ".thread_stack.2")]
static STACK2: Stack = Stack::new();
#[unsafe(link_section = ".thread_stack.3")]
static STACK3: Stack = Stack::new();
#[unsafe(link_section = ".thread_stack.4")]
static STACK4: Stack = Stack::new();
#[unsafe(link_section = ".thread_stack.5")]
static STACK5: Stack = Stack::new();

/// A thread's entry point. It takes four words, in `rdi`, `rsi`, `rdx` and
/// `rcx`, and never returns.
pub type Entry = extern "C" fn(u64, u64, u64, u64) -> !;

/// A thread to start.
pub struct Thread {
    pub tcb: CPtr,
    /// Its fault endpoint, a `CPtr` in its CSpace; 0 for none, so that a
    /// fault stops it and a debug kernel prints it.
    pub fault_ep: CPtr,
    pub stack: &'static Stack,
    pub entry: Entry,
    pub args: [u64; 4],
}

/// A thread's CSpace and IPC buffer.
#[derive(Clone, Copy, Debug)]
pub struct Space {
    /// The CNode capability, in the root task's CSpace, that becomes the
    /// thread's CSpace root, and the guard word applied to it (0 keeps
    /// its guard).
    pub cspace: CPtr,
    pub cspace_data: u64,
    pub buffer: Option<IpcBufferFrame>,
}

impl Space {
    /// The root task's own CSpace, and no IPC buffer.
    pub const ROOT: Space = Space {
        cspace: CAP_INIT_CNODE,
        cspace_data: 0,
        buffer: None,
    };
}

/// Configures `t`'s TCB with the root task's CSpace and VSpace, no IPC
/// buffer and its fault endpoint, and writes its registers: `rip` at its
/// entry, `rsp` 8 below its stack's top as if a `call` had pushed a return
/// address (the System V ABI wants `rsp + 8` 16-byte aligned at a
/// function's first instruction), and its arguments. The thread stays
/// `Inactive`; its priority and `TCB_Resume` are the caller's.
pub fn prepare(ipc: Ipc, t: &Thread) -> Result<(), Error> {
    prepare_with(ipc, t, Space::ROOT)
}

/// As [`prepare`], with the CSpace and IPC buffer of `space`; the VSpace
/// is the root task's.
pub fn prepare_with(ipc: Ipc, t: &Thread, space: Space) -> Result<(), Error> {
    tcb_configure(
        ipc,
        t.tcb,
        t.fault_ep,
        space.cspace,
        space.cspace_data,
        CAP_INIT_VSPACE,
        space.buffer,
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

/// The IPC buffer in KiB `k` (1 to 3) of the root task's buffer frame,
/// whose first KiB is the root task's own; `None` if the root task's
/// buffer is not at the start of its frame, or `k` is out of range.
pub fn root_frame_buffer(bi: &BootInfo, k: u64) -> Option<IpcBufferFrame> {
    let per_frame = 0x1000 / IPC_BUFFER_SIZE;
    (bi.ipc_buffer.is_multiple_of(0x1000) && (1..per_frame).contains(&k)).then(|| IpcBufferFrame {
        addr: bi.ipc_buffer + k * IPC_BUFFER_SIZE,
        frame: CAP_INIT_IPC_BUFFER,
    })
}

/// The [`Ipc`] of a thread whose IPC buffer is at `addr`, which the
/// thread got as an argument from [`root_frame_buffer`].
pub fn thread_ipc(addr: u64) -> Ipc {
    let buffer = NonNull::new(addr as *mut IpcBuffer)
        .unwrap_or_else(|| crate::fail!("a thread was given no IPC buffer address"));
    // SAFETY: `root_frame_buffer` names a KiB of the root task's buffer
    // frame, which the kernel maps RW in the VSpace every thread here
    // shares, 1024-byte aligned; each test gives each KiB to one thread.
    unsafe { Ipc::new(buffer) }
}

/// The root task's priority while [`let_others_run`] waits.
pub const LOW_PRIORITY: u64 = 1;

/// Lets every thread above [`LOW_PRIORITY`] run until it blocks: the root
/// task drops to that priority, where it runs again only once no higher
/// thread is runnable, then goes back to 255. Every thread a test starts
/// must therefore block in the end rather than spin.
pub fn let_others_run(ipc: Ipc) {
    tcb_set_priority(ipc, CAP_INIT_TCB, CAP_INIT_TCB, LOW_PRIORITY)
        .and_then(|()| tcb_set_priority(ipc, CAP_INIT_TCB, CAP_INIT_TCB, 255))
        .unwrap_or_else(|e| crate::fail!("dropping the root task's priority and back: {e}"));
}
