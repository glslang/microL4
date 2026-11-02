//! The system calls (`docs/abi.md`, "System calls" and "Registers for each
//! system call").
//!
//! `syscall` takes the number in `rdx`, a capability pointer in `rdi`, the
//! [`MessageInfo`] in `rsi` and MR0 to MR3 in `r10`, `r8`, `r9` and `r15`
//! (`l4core::ipc`'s mapping); a receive phase returns the badge in `rdi` and
//! the message in the same registers. MR4 and up are in the thread's IPC
//! buffer, which [`Ipc`] reads and writes.

use core::arch::asm;
use core::ptr::NonNull;
use core::sync::atomic::{AtomicPtr, Ordering};

use l4core::ipc::{IPC_BUFFER_SIZE, IPC_BUFFER_WORDS, IpcBuffer, MSG_REG_COUNT, MessageInfo};
use l4core::ipc::{MrLocation, MsgReg, mr_location};

/// A capability pointer, resolved in the caller's CSpace.
pub type CPtr = u64;

/// System-call numbers, `rdx` (`docs/abi.md`, "System calls").
/// The kernel decodes them with `l4core::abi::Syscall::from_number`.
pub mod number {
    use l4core::abi::Syscall;

    pub const CALL: u64 = Syscall::Call.number();
    pub const REPLY_RECV: u64 = Syscall::ReplyRecv.number();
    pub const SEND: u64 = Syscall::Send.number();
    pub const NB_SEND: u64 = Syscall::NBSend.number();
    pub const RECV: u64 = Syscall::Recv.number();
    pub const REPLY: u64 = Syscall::Reply.number();
    pub const YIELD: u64 = Syscall::Yield.number();
    pub const NB_RECV: u64 = Syscall::NBRecv.number();
    /// Debug kernels only (`docs/abi.md`, "Debug system calls").
    pub const DEBUG_PUT_CHAR: u64 = Syscall::DebugPutChar.number();
    pub const DEBUG_HALT: u64 = Syscall::DebugHalt.number();
    pub const DEBUG_DUMP_SCHEDULER: u64 = Syscall::DebugDumpScheduler.number();
}

// The `asm!` below names the registers of `l4core::ipc`'s mapping.
const _: () = assert!(matches!(
    MsgReg::ALL,
    [MsgReg::R10, MsgReg::R8, MsgReg::R9, MsgReg::R15]
));

/// A message as it travels in registers: its `MessageInfo` and MR0 to MR3.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Message {
    pub info: MessageInfo,
    pub mr: [u64; MSG_REG_COUNT],
}

impl Message {
    /// No label, no capabilities, no registers.
    pub const EMPTY: Message = Message {
        info: MessageInfo::from_word(0),
        mr: [0; MSG_REG_COUNT],
    };

    pub const fn new(info: MessageInfo, mr: [u64; MSG_REG_COUNT]) -> Message {
        Message { info, mr }
    }
}

/// What a receive phase delivers: the badge in `rdi` and the message.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Received {
    pub badge: u64,
    pub msg: Message,
}

/// Makes system call `number` with `rdi` and `msg`, and returns `rdi`,
/// `rsi` and MR0 to MR3 as the kernel left them.
///
/// # Safety
///
/// The `asm!` declares that the call may change `rdi`, `rsi`, `r10`, `r8`,
/// `r9`, `r15`, `rcx`, `r11` and memory, and preserves every other
/// register, `rdx` and `rsp` included. Every system call of `docs/abi.md`
/// keeps to that, and so does a fault it raises, except the reply to an
/// `UnknownSyscall` fault, which may set any register: for a number
/// `docs/abi.md` does not define, or a debug number on a kernel without
/// `debug`, the caller must know that no fault handler does.
pub unsafe fn syscall(number: u64, rdi: u64, msg: &Message) -> Received {
    let [mut mr0, mut mr1, mut mr2, mut mr3] = msg.mr;
    let (mut rdi, mut rsi) = (rdi, msg.info.word());
    // SAFETY: the caller vouches that the kernel changes no register but
    // the ones named here; `syscall` itself overwrites rcx and r11 and
    // touches no stack. The kernel may read and write this thread's IPC
    // buffer, so memory is not declared untouched.
    unsafe {
        asm!(
            "syscall",
            in("rdx") number,
            inout("rdi") rdi,
            inout("rsi") rsi,
            inout("r10") mr0,
            inout("r8") mr1,
            inout("r9") mr2,
            inout("r15") mr3,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    Received {
        badge: rdi,
        msg: Message {
            info: MessageInfo::from_word(rsi),
            mr: [mr0, mr1, mr2, mr3],
        },
    }
}

/// `Send`: sends `msg` to `dest`, blocking until it is taken. On a kernel
/// object it performs the invocation and drops the reply.
pub fn send(dest: CPtr, msg: &Message) {
    // SAFETY: Send changes no register but rcx and r11, and no fault it
    // raises sets one.
    unsafe { syscall(number::SEND, dest, msg) };
}

/// `NBSend`: as [`send`], but drops the message if no receiver waits.
pub fn nb_send(dest: CPtr, msg: &Message) {
    // SAFETY: as for `send`.
    unsafe { syscall(number::NB_SEND, dest, msg) };
}

/// `Call`: sends `msg` to `dest` and waits for the reply; on a kernel
/// object, performs the invocation and returns its reply, the error code in
/// the label.
pub fn call(dest: CPtr, msg: &Message) -> Message {
    // SAFETY: Call changes rdi, rsi and the message registers, and no
    // fault it raises sets a register.
    unsafe { syscall(number::CALL, dest, msg) }.msg
}

/// `Recv`: waits for a message or a signal on `src`.
pub fn recv(src: CPtr) -> Received {
    // SAFETY: as for `call`.
    unsafe { syscall(number::RECV, src, &Message::EMPTY) }
}

/// `NBRecv`: as [`recv`], but returns badge 0 and an empty message if
/// nothing is pending.
pub fn nb_recv(src: CPtr) -> Received {
    // SAFETY: as for `call`.
    unsafe { syscall(number::NB_RECV, src, &Message::EMPTY) }
}

/// `Reply`: replies to the thread whose call this thread received last.
pub fn reply(msg: &Message) {
    // SAFETY: as for `send`.
    unsafe { syscall(number::REPLY, 0, msg) };
}

/// `ReplyRecv`: [`reply`], then [`recv`] on `src`.
pub fn reply_recv(src: CPtr, msg: &Message) -> Received {
    // SAFETY: as for `call`.
    unsafe { syscall(number::REPLY_RECV, src, msg) }
}

/// `Yield`: gives up the rest of the time slice.
pub fn yield_now() {
    // SAFETY: Yield changes no register but rcx and r11.
    unsafe { syscall(number::YIELD, 0, &Message::EMPTY) };
}

/// The root task's IPC buffer, set by `_start` from BootInfo.
static ROOT_IPC_BUFFER: AtomicPtr<IpcBuffer> = AtomicPtr::new(core::ptr::null_mut());

pub(crate) fn set_root_ipc_buffer(buffer: *mut IpcBuffer) {
    ROOT_IPC_BUFFER.store(buffer, Ordering::Relaxed);
}

/// A thread's IPC buffer, read and written a word at a time with volatile
/// accesses, never through a reference: the kernel writes it during a
/// system call, behind the compiler's back, and threads may share one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Ipc(NonNull<IpcBuffer>);

impl Ipc {
    /// The buffer at `buffer`.
    ///
    /// # Safety
    ///
    /// `buffer` must be mapped readable and writable, 1024-byte aligned,
    /// for as long as the `Ipc` and its copies are used.
    pub const unsafe fn new(buffer: NonNull<IpcBuffer>) -> Ipc {
        Ipc(buffer)
    }

    /// The root task's buffer, which the kernel maps at BootInfo's
    /// `ipc_buffer`.
    pub fn root() -> Ipc {
        let p = NonNull::new(ROOT_IPC_BUFFER.load(Ordering::Relaxed))
            .expect("the root task's IPC buffer is set before main");
        Ipc(p)
    }

    /// The buffer's address.
    pub fn as_ptr(self) -> *mut IpcBuffer {
        self.0.as_ptr()
    }

    /// Word `w`, one of `l4core::ipc::word`'s; panics past 127.
    pub fn word(self, w: usize) -> u64 {
        assert!(w < IPC_BUFFER_WORDS, "IPC buffer word {w} out of range");
        // SAFETY: `new`'s caller vouched that the buffer is mapped and
        // aligned, and `w` is inside it.
        unsafe { self.0.cast::<u64>().add(w).read_volatile() }
    }

    /// Sets word `w`; panics past 127.
    pub fn set_word(self, w: usize, value: u64) {
        assert!(w < IPC_BUFFER_WORDS, "IPC buffer word {w} out of range");
        // SAFETY: as for `word`; the buffer is writable.
        unsafe { self.0.cast::<u64>().add(w).write_volatile(value) }
    }

    /// Message register `i`, for `i` from 4 to 119; MR0 to MR3 are in
    /// [`Message::mr`].
    pub fn mr(self, i: usize) -> u64 {
        self.word(Self::mr_word(i))
    }

    /// Sets message register `i`, for `i` from 4 to 119.
    pub fn set_mr(self, i: usize, value: u64) {
        self.set_word(Self::mr_word(i), value)
    }

    fn mr_word(i: usize) -> usize {
        match mr_location(i) {
            Some(MrLocation::Buffer(w)) => w,
            Some(MrLocation::Register(r)) => panic!("MR{i} travels in {}", r.name()),
            None => panic!("MR{i} past the last message register"),
        }
    }
}

const _: () = assert!(core::mem::align_of::<IpcBuffer>() as u64 == IPC_BUFFER_SIZE);
