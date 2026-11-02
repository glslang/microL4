//! `test=isolation` (M5 review, reviewer K): what a thread sees of another
//! across preemptive switches by the real scheduler.
//!
//! `docs/design.md`, "FP and SIMD", Invariants: "A thread never observes
//! another thread's x87 or SSE state", and "Kernel entry and exit": a
//! thread preempted by the timer leaves by `iretq` with every register as
//! it was. `test=ring3` checks both on a hand-built thread the kernel
//! switches by hand; this test checks them between two threads the
//! scheduler switches on its own, through `fpu::switch_to` and
//! `thread::switch_to`.
//!
//! The root task gives threads X and Y, at priority [`PRIORITY`], distinct
//! FS and GS bases (`TCB_WriteRegisters`, words 18 and 19), each over a
//! marker word of their own. Each thread then:
//!
//! 1. loads XMM0 to XMM15, two x87 registers, FCW and MXCSR with values of
//!    its own, and for [`PHASE_MS`] of TSC time stores them back and
//!    compares, with `fs:[0]` and `gs:[0]` against its markers;
//! 2. for another [`PHASE_MS`], holds twelve general registers (`rcx` and
//!    `r11` among them, which `sysretq` would clobber) and DF and AC at
//!    values of its own in a loop of one function, comparing each pass;
//! 3. checks its x87, SSE and segment state once more.
//!
//! Both phases count, through a shared "last thread to run" word, the
//! times the other thread ran in between, which only a preemption allows.
//! Each thread reports to the root, which also loaded x87 and SSE values
//! of its own before resuming the threads and checks them afterwards. The
//! root passes when no check failed and each thread saw the other run at
//! least [`MIN_PREEMPTIONS`] times in each phase.

use core::arch::global_asm;
use core::sync::atomic::Ordering::Relaxed;
use core::sync::atomic::{AtomicU8, AtomicU64};

use libsys::bootinfo::CAP_INIT_TCB;
use libsys::invoke::{tcb_resume, tcb_set_priority, tcb_suspend, tcb_write_registers};
use libsys::{
    BootInfo, CPtr, Ipc, Message, MessageInfo, ObjectAlloc, ObjectType, Registers, UserReg,
    println, rdtsc, recv, send, yield_now,
};

use crate::fail;
use crate::spawn::{self, STACKS, Thread};

/// The threads' priority, below the root task's 255.
const PRIORITY: u64 = 100;
/// The length of each phase, in milliseconds: several 10 ms slices.
const PHASE_MS: u64 = 80;
/// Times each thread must see the other run during each phase.
const MIN_PREEMPTIONS: u64 = 2;
/// The label of a thread's report.
const DONE: u64 = 0x150;
/// The threads' names.
const NAMES: [char; 2] = ['X', 'Y'];

/// x87 and SSE state as the asm below loads and stores it.
#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
struct FpState {
    /// XMM0 to XMM15, low quadword first.
    xmm: [[u64; 2]; 16],
    /// ST0 and ST1, as doubles.
    st: [u64; 2],
    mxcsr: u32,
    /// FCW in the low 16 bits.
    fcw: u32,
}

const _: () = assert!(core::mem::size_of::<FpState>() == 280);

impl FpState {
    const ZERO: FpState = FpState {
        xmm: [[0; 2]; 16],
        st: [0; 2],
        mxcsr: 0,
        fcw: 0,
    };

    /// A state no other user of `tag` loads: every XMM word distinct, and
    /// the given x87 values, MXCSR and FCW.
    const fn new(tag: u64, st: [u64; 2], mxcsr: u32, fcw: u32) -> FpState {
        let mut xmm = [[0; 2]; 16];
        let mut i = 0;
        while i < 16 {
            xmm[i] = [
                tag << 48 | 0x0000_A11A_0000_0000 | i as u64,
                tag << 48 | 0x0000_B22B_0000_0100 | i as u64,
            ];
            i += 1;
        }
        FpState {
            xmm,
            st,
            mxcsr,
            fcw,
        }
    }

    /// The first difference from `want`, as an error code: 1 + the XMM
    /// register, 17 and 18 for ST0 and ST1, 19 for MXCSR, 20 for FCW.
    fn diff(&self, want: &FpState) -> u64 {
        if let Some(i) = (0..16).find(|&i| self.xmm[i] != want.xmm[i]) {
            return 1 + i as u64;
        }
        if self.st[0] != want.st[0] {
            return 17;
        }
        if self.st[1] != want.st[1] {
            return 18;
        }
        if self.mxcsr != want.mxcsr {
            return 19;
        }
        if self.fcw != want.fcw {
            return 20;
        }
        0
    }
}

/// 1.0, pi, 2.0, e, 3.0 and 0.5 as doubles.
const ONE: u64 = 0x3FF0_0000_0000_0000;
const PI: u64 = 0x4009_21FB_5444_2D18;
const TWO: u64 = 0x4000_0000_0000_0000;
const E: u64 = 0x4005_BF0A_8B14_5769;
const THREE: u64 = 0x4008_0000_0000_0000;
const HALF: u64 = 0x3FE0_0000_0000_0000;

/// What X and Y load: different rounding controls in MXCSR and FCW, Y's
/// MXCSR with FZ, and none the initial state's 0x1F80 and 0x37F.
static STATES: [FpState; 2] = [
    FpState::new(0x1111, [ONE, PI], 0x5F80, 0x077F),
    FpState::new(0x2222, [TWO, E], 0xFF80, 0x0F7F),
];
/// What the root task loads.
static ROOT_STATE: FpState = FpState::new(0x7777, [THREE, HALF], 0x3F80, 0x0B7F);

/// Each thread's FS and GS base points at its own marker.
static FS_MARKS: [u64; 2] = [0xF5F5_0000_0000_0001, 0xF5F5_0000_0000_0002];
static GS_MARKS: [u64; 2] = [0x6565_0000_0000_0001, 0x6565_0000_0000_0002];

/// The id of the last thread seen running: 1 for X, 2 for Y.
static LAST: AtomicU8 = AtomicU8::new(0);
/// TSC ticks in a phase.
static PHASE_TSC: AtomicU64 = AtomicU64::new(0);

/// The general-register phase's table, which `isolation_gprs` reads and
/// updates.
#[repr(C)]
struct GprTable {
    /// rbx, rbp, rcx, rsi, r8 to r15.
    values: [u64; 12],
    /// The TSC at which the loop ends.
    deadline: u64,
    /// [`LAST`].
    last: *const AtomicU8,
    /// This thread's id in its low byte.
    me: u64,
    /// Times the loop found the other thread's id in `last`.
    seen: u64,
}

const _: () = assert!(core::mem::offset_of!(GprTable, deadline) == 96);
const _: () = assert!(core::mem::offset_of!(GprTable, last) == 104);
const _: () = assert!(core::mem::offset_of!(GprTable, me) == 112);
const _: () = assert!(core::mem::offset_of!(GprTable, seen) == 120);

// The x87, SSE and segment-base accesses, and the general-register loop.
// Nothing else in this program touches x87 or SSE state: it builds for a
// target without SSE, which emulates floating point with integers.
global_asm!(
    ".pushsection .text.isolation, \"ax\", @progbits",
    // isolation_load_fp(state: *const FpState)
    ".global isolation_load_fp",
    "isolation_load_fp:",
    ".irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
    "    movdqu xmm\\i, xmmword ptr [rdi + 16 * \\i]",
    ".endr",
    "    ldmxcsr dword ptr [rdi + 272]",
    "    fninit",
    "    fldcw word ptr [rdi + 276]",
    "    fld qword ptr [rdi + 264]",
    "    fld qword ptr [rdi + 256]",
    "    ret",
    // isolation_store_fp(state: *mut FpState): stores without popping.
    ".global isolation_store_fp",
    "isolation_store_fp:",
    ".irp i, 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15",
    "    movdqu xmmword ptr [rdi + 16 * \\i], xmm\\i",
    ".endr",
    "    fst qword ptr [rdi + 256]",
    "    fxch st(1)",
    "    fst qword ptr [rdi + 264]",
    "    fxch st(1)",
    "    stmxcsr dword ptr [rdi + 272]",
    "    fnstcw word ptr [rdi + 276]",
    "    ret",
    // isolation_segment_marks(out: *mut [u64; 2]): fs:[0] and gs:[0].
    ".global isolation_segment_marks",
    "isolation_segment_marks:",
    "    mov rax, qword ptr fs:[0]",
    "    mov qword ptr [rdi], rax",
    "    mov rax, qword ptr gs:[0]",
    "    mov qword ptr [rdi + 8], rax",
    "    ret",
    // isolation_gprs(table: *mut GprTable) -> u64: 0, or 1 + the index of
    // the first register found changed, or 13 if DF or AC was cleared.
    ".global isolation_gprs",
    "isolation_gprs:",
    "    push rbx",
    "    push rbp",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov rbx, qword ptr [rdi + 0]",
    "    mov rbp, qword ptr [rdi + 8]",
    "    mov rcx, qword ptr [rdi + 16]",
    "    mov rsi, qword ptr [rdi + 24]",
    "    mov r8, qword ptr [rdi + 32]",
    "    mov r9, qword ptr [rdi + 40]",
    "    mov r10, qword ptr [rdi + 48]",
    "    mov r11, qword ptr [rdi + 56]",
    "    mov r12, qword ptr [rdi + 64]",
    "    mov r13, qword ptr [rdi + 72]",
    "    mov r14, qword ptr [rdi + 80]",
    "    mov r15, qword ptr [rdi + 88]",
    "    std",
    "    pushfq",
    "    or qword ptr [rsp], 0x40000",
    "    popfq",
    "2:",
    "    mov eax, 1",
    "    cmp rbx, qword ptr [rdi + 0]",
    "    jne 8f",
    "    mov eax, 2",
    "    cmp rbp, qword ptr [rdi + 8]",
    "    jne 8f",
    "    mov eax, 3",
    "    cmp rcx, qword ptr [rdi + 16]",
    "    jne 8f",
    "    mov eax, 4",
    "    cmp rsi, qword ptr [rdi + 24]",
    "    jne 8f",
    "    mov eax, 5",
    "    cmp r8, qword ptr [rdi + 32]",
    "    jne 8f",
    "    mov eax, 6",
    "    cmp r9, qword ptr [rdi + 40]",
    "    jne 8f",
    "    mov eax, 7",
    "    cmp r10, qword ptr [rdi + 48]",
    "    jne 8f",
    "    mov eax, 8",
    "    cmp r11, qword ptr [rdi + 56]",
    "    jne 8f",
    "    mov eax, 9",
    "    cmp r12, qword ptr [rdi + 64]",
    "    jne 8f",
    "    mov eax, 10",
    "    cmp r13, qword ptr [rdi + 72]",
    "    jne 8f",
    "    mov eax, 11",
    "    cmp r14, qword ptr [rdi + 80]",
    "    jne 8f",
    "    mov eax, 12",
    "    cmp r15, qword ptr [rdi + 88]",
    "    jne 8f",
    "    pushfq",
    "    pop rax",
    "    and eax, 0x40400",
    "    cmp eax, 0x40400",
    "    mov eax, 13",
    "    jne 8f",
    // Swap this thread's id into LAST; the other's there means it ran.
    "    mov rdx, qword ptr [rdi + 104]",
    "    mov rax, qword ptr [rdi + 112]",
    "    xchg byte ptr [rdx], al",
    "    cmp al, byte ptr [rdi + 112]",
    "    je 3f",
    "    inc qword ptr [rdi + 120]",
    "3:",
    "    rdtsc",
    "    shl rdx, 32",
    "    or rax, rdx",
    "    cmp rax, qword ptr [rdi + 96]",
    "    jb 2b",
    "    xor eax, eax",
    "8:",
    "    cld",
    "    pushfq",
    "    and qword ptr [rsp], ~0x40000",
    "    popfq",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop rbp",
    "    pop rbx",
    "    ret",
    ".popsection",
);

unsafe extern "C" {
    fn isolation_load_fp(state: *const FpState);
    fn isolation_store_fp(state: *mut FpState);
    fn isolation_segment_marks(out: *mut [u64; 2]);
    fn isolation_gprs(table: *mut GprTable) -> u64;
}

/// The x87 and SSE state now.
fn store_fp() -> FpState {
    let mut s = FpState::ZERO;
    // SAFETY: the function writes the 280 bytes of `s` and changes no
    // register the C ABI preserves; it only reads x87 and SSE state.
    unsafe { isolation_store_fp(&mut s) };
    s
}

/// `fs:[0]` and `gs:[0]`. Only for a thread whose FS and GS bases name
/// mapped words.
fn segment_marks() -> [u64; 2] {
    let mut m = [0; 2];
    // SAFETY: writes `m` only; the caller's bases point at its markers.
    unsafe { isolation_segment_marks(&mut m) };
    m
}

pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    if bi.tsc_hz == 0 {
        fail!("BootInfo's tsc_hz is 0: nothing to time the phases by");
    }
    PHASE_TSC.store(bi.tsc_hz / 1000 * PHASE_MS, Relaxed);
    let mut objects = ObjectAlloc::new(bi);
    let done = objects
        .retype(ipc, ObjectType::Endpoint, 0, 1)
        .unwrap_or_else(|e| fail!("retyping the endpoint: {e}"));
    let tcbs = objects
        .retype(ipc, ObjectType::Tcb, 0, 2)
        .unwrap_or_else(|e| fail!("retyping the TCBs: {e}"));
    for (i, stack) in STACKS.iter().enumerate() {
        let t = Thread {
            tcb: tcbs + i as u64,
            fault_ep: done,
            stack,
            entry: worker,
            args: [i as u64, done, 0, 0],
        };
        // Every register, so that the FS and GS bases are set too.
        let regs = Registers::ZERO
            .with(UserReg::Rip, worker as *const () as u64)
            .with(UserReg::Rsp, stack.top() - 8)
            .with(UserReg::Rflags, 0x202)
            .with(UserReg::Rdi, i as u64)
            .with(UserReg::Rsi, done)
            .with(UserReg::FsBase, &FS_MARKS[i] as *const u64 as u64)
            .with(UserReg::GsBase, &GS_MARKS[i] as *const u64 as u64);
        spawn::prepare(ipc, &t)
            .and_then(|()| tcb_write_registers(ipc, t.tcb, false, &regs, regs.0.len()))
            .and_then(|()| tcb_set_priority(ipc, t.tcb, CAP_INIT_TCB, PRIORITY))
            .unwrap_or_else(|e| fail!("setting up thread {}: {e}", NAMES[i]));
    }
    println!(
        "isolation: threads X and Y at priority {PRIORITY}, each with x87, SSE, FS and GS bases of its own; two phases of {PHASE_MS} ms each"
    );

    // SAFETY: loads x87 and SSE registers from a static; nothing in this
    // program uses them otherwise.
    unsafe { isolation_load_fp(&ROOT_STATE) };
    for i in 0..2 {
        tcb_resume(tcbs + i)
            .unwrap_or_else(|e| fail!("resuming thread {}: {e}", NAMES[i as usize]));
    }
    let mut reports = [None; 2];
    for _ in 0..2 {
        let r = recv(done);
        let info = r.msg.info;
        if info.label() != DONE || info.length() != 4 {
            fail!(
                "the root received label {:#x}, length {}, MR0 to MR3 {:#x?} instead of a thread's report: a fault message?",
                info.label(),
                info.length(),
                r.msg.mr
            );
        }
        let [index, fp_error, gpr_error, seen] = r.msg.mr;
        let Some(slot) = reports.get_mut(index as usize).filter(|s| s.is_none()) else {
            fail!("a second report, or one from thread index {index}");
        };
        *slot = Some((fp_error, gpr_error, seen >> 32, seen & 0xFFFF_FFFF));
        tcb_suspend(tcbs + index)
            .unwrap_or_else(|e| fail!("suspending thread {}: {e}", NAMES[index as usize]));
    }
    let root_error = store_fp().diff(&ROOT_STATE);

    let mut ok = root_error == 0;
    for (i, r) in reports.iter().enumerate() {
        let (fp_error, gpr_error, fp_seen, gpr_seen) = r.expect("both reported");
        println!(
            "isolation: thread {}: x87, SSE and segment check {fp_error}, general-register check {gpr_error}; saw the other thread run {fp_seen} times in the first phase and {gpr_seen} in the second",
            NAMES[i]
        );
        ok &= fp_error == 0
            && gpr_error == 0
            && fp_seen >= MIN_PREEMPTIONS
            && gpr_seen >= MIN_PREEMPTIONS;
    }
    println!("isolation: the root task's x87 and SSE state: check {root_error}");
    if !ok {
        fail!(
            "isolation: a check failed (codes: 1 to 16 XMM0 to XMM15, 17 and 18 ST0 and ST1, 19 MXCSR, 20 FCW, 21 and 22 the FS and GS markers, 100 + any of them after the second phase; 1 to 12 rbx, rbp, rcx, rsi, r8 to r15, 13 DF or AC), or a thread saw the other run fewer than {MIN_PREEMPTIONS} times in a phase"
        );
    }
    println!("TEST PASS");
    libsys::debug_halt(0)
}

/// The x87, SSE and segment check of thread `i`: 0, or an error code.
fn check_fp(i: usize) -> u64 {
    match store_fp().diff(&STATES[i]) {
        0 => {}
        e => return e,
    }
    let [fs, gs] = segment_marks();
    if fs != FS_MARKS[i] {
        return 21;
    }
    if gs != GS_MARKS[i] {
        return 22;
    }
    0
}

/// Thread `index` (0 for X, 1 for Y): the two phases and the final check,
/// then its report to the root on `done`.
extern "C" fn worker(index: u64, done: CPtr, _: u64, _: u64) -> ! {
    let i = index as usize;
    let me = index as u8 + 1;
    let phase = PHASE_TSC.load(Relaxed);

    // Phase 1: x87, SSE and the segment bases.
    // SAFETY: as in `run`.
    unsafe { isolation_load_fp(&STATES[i]) };
    LAST.store(me, Relaxed);
    let mut fp_seen = 0;
    let mut fp_error = 0;
    let start = rdtsc();
    while rdtsc().wrapping_sub(start) < phase {
        fp_error = check_fp(i);
        if fp_error != 0 {
            break;
        }
        if LAST.swap(me, Relaxed) != me {
            fp_seen += 1;
        }
    }

    // Phase 2: the general registers, DF and AC.
    let mut table = GprTable {
        values: core::array::from_fn(|r| {
            0x6000_0000_0000_0000 | (index + 1) << 40 | (r as u64) << 8 | 0x5A
        }),
        deadline: rdtsc().wrapping_add(phase),
        last: &LAST,
        me: u64::from(me),
        seen: 0,
    };
    LAST.store(me, Relaxed);
    // SAFETY: the function reads and updates `table`, restores every
    // register the C ABI preserves, and returns with DF and AC clear.
    let gpr_error = unsafe { isolation_gprs(&mut table) };

    // And the x87 and SSE state once more, after the other thread's
    // second phase.
    if fp_error == 0 {
        fp_error = match check_fp(i) {
            0 => 0,
            e => 100 + e,
        };
    }
    send(
        done,
        &Message::new(
            MessageInfo::new(DONE, 0, 0, 4),
            [index, fp_error, gpr_error, (fp_seen << 32) | table.seen],
        ),
    );
    loop {
        yield_now();
    }
}
