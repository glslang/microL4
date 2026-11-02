//! `test=ring3` (M5): the paths between ring 3 and the kernel, proved
//! before any real thread exists (`tests/qemu/ring3.scenario`).
//!
//! The test retypes ten 4 KiB frames and two TCBs from a small RAM untyped
//! through `l4core::invoke`, as the root task will, and writes a throwaway
//! address space into the frames by hand: a PML4 with the kernel's upper
//! half, a code page, a data and stack page, and the last page of the lower
//! half. Builder V's paging objects replace all of this. It copies
//! `ring3_code` and `ring3_tail` (below) in, writes the first TCB's
//! registers and the initial FP state, and drops to ring 3 by `iretq`.
//!
//! From then on every entry from ring 3 comes to [`on_entry`] through the
//! hook `entry::from_user` calls instead of the seams. The ring-3 code runs
//! a fixed sequence of steps, each a system call the test decodes in place
//! (a checkpoint, `0x100 + step`, which `Syscall::from_number` rejects as
//! the kernel would with `UnknownSyscall`) or an exception it expects; it
//! checks the thread's registers there and goes back by `sysretq` or
//! `iretq` as `l4core::entry::exit_frame` decides, with the x87 and SSE
//! state switched through `fpu::switch_to`. `DebugPutChar` prints a line;
//! `DebugHalt` means the ring-3 code found a register wrong. Interrupts
//! taken in ring 3 go through `irq::handle` and back by `iretq` at any
//! step. Every entry also checks GS, the kernel's RFLAGS and where the
//! frame and the stack are.

use core::arch::{asm, global_asm};
use core::fmt;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

use l4core::abi::Syscall;
use l4core::bootinfo::{BootInfo, CAP_INIT_CNODE};
use l4core::cap::ObjectType;
use l4core::cspace;
use l4core::entry::{self as le, LOWER_HALF_END, UserEntry, rflags};
use l4core::fpu::{self as lf, offset};
use l4core::invoke::{self, ExtraCap, InvokeError, Message, label};
use l4core::regs::{Exit, Regs};
use l4core::slot::SlotMemory;
use l4core::tcb::{REGS_OFFSET, TcbRef};
use l4core::trap::{self as t, PageFaultError, TrapFrame, Vector};
use l4core::vspace::{self as vs, CacheType, UserAccess};

use super::cpu::Hypervisor;
use super::{ExitCode, Objects, StaticCell, cpu, entry, exit, fpu, gdt, irq, phys_to_virt};
use crate::boot::RootSpace;

// ---------------------------------------------------------------------------
// The address space and the constants the ring-3 code shares
// ---------------------------------------------------------------------------

/// The code page.
const CODE: u64 = 0x40_0000;
/// The data and stack page.
const DATA: u64 = 0x40_1000;
const STACK_TOP: u64 = DATA + 0x1000;
/// The line `DebugPutChar` prints, NUL-terminated in the data page.
const MESSAGE_AT: u64 = DATA + 0x100;
const MESSAGE: &str = "ring3: hello from ring 3, one DebugPutChar and one sysretq per byte\n";
/// The thread's FS and GS bases, each over a marker word in the data page.
const FS_BASE: u64 = DATA + 0x800;
const GS_BASE: u64 = DATA + 0x900;
const FS_MARK: u64 = 0xF5F5_0000_0000_F5F5;
const GS_MARK: u64 = 0x6565_0000_0000_6565;
/// The last page below 2^47, which `USER_TOP` keeps out of real address
/// spaces; the test maps it to make a `syscall` return to 2^47.
const TAIL_PAGE: u64 = LOWER_HALF_END - 0x1000;
/// A lower-half address nothing maps.
const UNMAPPED: u64 = 0x60_0008;
/// Register pattern `i` is `PATTERN + i + 1`: rax, rbx, rcx, rdx, rsi,
/// rdi, rbp, r8 to r15.
const PATTERN: u64 = 0x5A5A_0000_0000_0000;
/// What the test writes into RCX and R11 at step 4, as a register write
/// would.
const RCX_WRITTEN: u64 = PATTERN + 0xC0C0;
const R11_WRITTEN: u64 = PATTERN + 0x1111;
/// XMM0's two halves at step 6.
const XMM_LO: u64 = 0x0123_4567_89AB_CDEF;
const XMM_HI: u64 = 0xFEDC_BA98_7654_3210;
/// 1.0 and pi as doubles.
const ONE: u64 = 0x3FF0_0000_0000_0000;
const PI: u64 = 0x4009_21FB_5444_2D18;
/// The checkpoint system calls: `rdx` = this + the step.
const CHECKPOINT: u64 = 0x100;

const fn pattern(i: u64) -> u64 {
    PATTERN + i + 1
}

// The frames, by index.
const PML4: usize = 0;
const PDPT_LO: usize = 1;
const PD_LO: usize = 2;
const PT_LO: usize = 3;
const PDPT_HI: usize = 4;
const PD_HI: usize = 5;
const PT_HI: usize = 6;
const CODE_FRAME: usize = 7;
const DATA_FRAME: usize = 8;
const TAIL_FRAME: usize = 9;
const FRAMES: usize = 10;

// ---------------------------------------------------------------------------
// The ring-3 code
// ---------------------------------------------------------------------------

global_asm!(
    ".set RING3_PATTERN, {pattern}",
    // Fails the run from ring 3 with check `code` unless the last compare
    // found its operands equal.
    ".macro ring3_ensure code",
    "    je 9f",
    "    mov edi, \\code",
    "    jmp .Lr3_fail",
    "9:",
    ".endm",
    // Compares `reg` with register pattern `i`.
    ".macro ring3_check reg, i, code",
    "    cmp \\reg, qword ptr [rip + .Lr3_patterns + 8 * \\i]",
    "    ring3_ensure \\code",
    ".endm",
    ".macro ring3_load reg, i",
    "    mov \\reg, qword ptr [rip + .Lr3_patterns + 8 * \\i]",
    ".endm",
    //
    ".pushsection .rodata.ring3_code, \"a\", @progbits",
    ".balign 16",
    ".global ring3_code, ring3_code_end",
    "ring3_code:",
    ".Lr3_start:",
    // Step 1: the state the thread starts in.
    "    pushfq",
    "    pop r9",
    "    mov ax, cs",
    "    movzx r10d, ax",
    "    mov ax, ss",
    "    movzx r8d, ax",
    "    sub rsp, 16",
    "    fnstcw word ptr [rsp]",
    "    stmxcsr dword ptr [rsp + 4]",
    "    movzx edi, word ptr [rsp]",
    "    mov esi, dword ptr [rsp + 4]",
    "    add rsp, 16",
    "    mov r15, qword ptr fs:[0]",
    "    mov r12, qword ptr gs:[0]",
    "    mov edx, {s_initial}",
    "    syscall",
    ".Lr3_s1_ret:",
    // The line, one DebugPutChar per byte; R12 must survive each.
    "    mov r12, {message}",
    ".Lr3_puts:",
    "    movzx edi, byte ptr [r12]",
    "    test edi, edi",
    "    jz .Lr3_puts_done",
    "    mov edx, 16",
    "    syscall",
    "    inc r12",
    "    jmp .Lr3_puts",
    ".Lr3_puts_done:",
    // Step 2: every register but RCX and R11 survives `syscall` and
    // `sysretq`; RCX is the return address and R11 the RFLAGS restored.
    "    ring3_load rax, 0",
    "    ring3_load rbx, 1",
    "    ring3_load rsi, 4",
    "    ring3_load rdi, 5",
    "    ring3_load rbp, 6",
    "    ring3_load r8, 7",
    "    ring3_load r9, 8",
    "    ring3_load r10, 9",
    "    ring3_load r12, 11",
    "    ring3_load r13, 12",
    "    ring3_load r14, 13",
    "    ring3_load r15, 14",
    "    mov edx, {s_registers}",
    "    syscall",
    ".Lr3_s2_ret:",
    "    pushfq",
    "    cmp r11, qword ptr [rsp]",
    "    ring3_ensure 0x201",
    "    add rsp, 8",
    "    lea r11, [rip + .Lr3_s2_ret]",
    "    cmp rcx, r11",
    "    ring3_ensure 0x202",
    "    cmp rdx, {s_registers}",
    "    ring3_ensure 0x203",
    "    ring3_check rax, 0, 0x210",
    "    ring3_check rbx, 1, 0x211",
    "    ring3_check rsi, 4, 0x214",
    "    ring3_check rdi, 5, 0x215",
    "    ring3_check rbp, 6, 0x216",
    "    ring3_check r8, 7, 0x217",
    "    ring3_check r9, 8, 0x218",
    "    ring3_check r10, 9, 0x219",
    "    ring3_check r12, 11, 0x21b",
    "    ring3_check r13, 12, 0x21c",
    "    ring3_check r14, 13, 0x21d",
    "    ring3_check r15, 14, 0x21e",
    // Step 3: `syscall` with DF, NT and AC set. The thread keeps DF and
    // AC, and NT is cleared.
    "    mov edx, {s_flags}",
    "    pushfq",
    "    or qword ptr [rsp], {df_nt_ac}",
    "    popfq",
    "    syscall",
    "    pushfq",
    "    pop rax",
    "    cld",
    "    and eax, {df_nt_ac}",
    "    cmp eax, {df_ac}",
    "    ring3_ensure 0x301",
    "    pushfq",
    "    and qword ptr [rsp], {not_ac}",
    "    popfq",
    // Step 4: the kernel writes RCX and R11, so the thread comes back by
    // `iretq` with those values, which `sysretq` would have replaced.
    "    mov edx, {s_written}",
    "    syscall",
    "    mov rax, {rcx_written}",
    "    cmp rcx, rax",
    "    ring3_ensure 0x401",
    "    mov rax, {r11_written}",
    "    cmp r11, rax",
    "    ring3_ensure 0x402",
    // Step 5: `int3`, with every register a pattern and DF and AC set;
    // back by `iretq` with all of them.
    "    pushfq",
    "    or qword ptr [rsp], {df_ac}",
    "    popfq",
    "    ring3_load rax, 0",
    "    ring3_load rbx, 1",
    "    ring3_load rcx, 2",
    "    ring3_load rdx, 3",
    "    ring3_load rsi, 4",
    "    ring3_load rdi, 5",
    "    ring3_load rbp, 6",
    "    ring3_load r8, 7",
    "    ring3_load r9, 8",
    "    ring3_load r10, 9",
    "    ring3_load r11, 10",
    "    ring3_load r12, 11",
    "    ring3_load r13, 12",
    "    ring3_load r14, 13",
    "    ring3_load r15, 14",
    "    int3",
    ".Lr3_after_int3:",
    "    pushfq",
    "    ring3_check rax, 0, 0x500",
    "    ring3_check rbx, 1, 0x501",
    "    ring3_check rcx, 2, 0x502",
    "    ring3_check rdx, 3, 0x503",
    "    ring3_check rsi, 4, 0x504",
    "    ring3_check rdi, 5, 0x505",
    "    ring3_check rbp, 6, 0x506",
    "    ring3_check r8, 7, 0x507",
    "    ring3_check r9, 8, 0x508",
    "    ring3_check r10, 9, 0x509",
    "    ring3_check r11, 10, 0x50a",
    "    ring3_check r12, 11, 0x50b",
    "    ring3_check r13, 12, 0x50c",
    "    ring3_check r14, 13, 0x50d",
    "    ring3_check r15, 14, 0x50e",
    "    pop rax",
    "    cld",
    "    and eax, {df_ac}",
    "    cmp eax, {df_ac}",
    "    ring3_ensure 0x510",
    "    pushfq",
    "    and qword ptr [rsp], {not_ac}",
    "    popfq",
    // Step 6: XMM0, XMM15, two x87 registers and MXCSR across an entry
    // whose handler switches to another thread's state and back.
    "    mov rax, {xmm_lo}",
    "    movq xmm0, rax",
    "    mov rax, {xmm_hi}",
    "    movq xmm1, rax",
    "    punpcklqdq xmm0, xmm1",
    "    pshufd xmm15, xmm0, 0x1b",
    "    fldpi",
    "    fld1",
    "    sub rsp, 16",
    "    mov dword ptr [rsp], 0x3f80",
    "    ldmxcsr dword ptr [rsp]",
    "    add rsp, 16",
    "    mov edx, {s_fpu}",
    "    syscall",
    "    mov rbx, {xmm_lo}",
    "    movq rax, xmm0",
    "    cmp rax, rbx",
    "    ring3_ensure 0x601",
    "    pshufd xmm14, xmm15, 0x1b",
    "    movq rax, xmm14",
    "    cmp rax, rbx",
    "    ring3_ensure 0x602",
    "    psrldq xmm0, 8",
    "    movq rax, xmm0",
    "    mov rbx, {xmm_hi}",
    "    cmp rax, rbx",
    "    ring3_ensure 0x603",
    "    sub rsp, 16",
    "    fstp qword ptr [rsp]",
    "    mov rax, qword ptr [rsp]",
    "    mov rbx, {one}",
    "    cmp rax, rbx",
    "    ring3_ensure 0x604",
    "    fstp qword ptr [rsp]",
    "    mov rax, qword ptr [rsp]",
    "    mov rbx, {pi}",
    "    cmp rax, rbx",
    "    ring3_ensure 0x605",
    "    stmxcsr dword ptr [rsp]",
    "    cmp dword ptr [rsp], 0x3f80",
    "    ring3_ensure 0x606",
    "    mov dword ptr [rsp], 0x1f80",
    "    ldmxcsr dword ptr [rsp]",
    "    add rsp, 16",
    // Step 7: an unmasked x87 divide by zero, pending across an entry whose
    // handler runs XSAVE64 and XRSTOR64; step 8: the `fwait` after it
    // raises #MF in ring 3. `fninit` then clears it.
    "    sub rsp, 16",
    "    fnstcw word ptr [rsp]",
    "    and word ptr [rsp], 0xfffb",
    "    fldcw word ptr [rsp]",
    "    add rsp, 16",
    "    fld1",
    "    fdiv qword ptr [rip + .Lr3_zero]",
    "    mov edx, {s_pending}",
    "    syscall",
    ".Lr3_fwait:",
    "    fwait",
    ".Lr3_after_fwait:",
    "    fninit",
    // Step 9: an unmasked SIMD divide by zero raises #XM (CR4.OSXMMEXCPT).
    "    sub rsp, 16",
    "    mov dword ptr [rsp], 0x1d80",
    "    ldmxcsr dword ptr [rsp]",
    "    xorps xmm1, xmm1",
    "    movsd xmm0, qword ptr [rip + .Lr3_one]",
    ".Lr3_divsd:",
    "    divsd xmm0, xmm1",
    ".Lr3_after_divsd:",
    // Step 10: the divide ran with ZM clear: MXCSR has ZE set.
    "    mov edx, {s_mxcsr}",
    "    syscall",
    "    mov dword ptr [rsp], 0x1f80",
    "    ldmxcsr dword ptr [rsp]",
    "    add rsp, 16",
    // Step 11: spin in ring 3 until the kernel says an interrupt was
    // taken here.
    ".Lr3_wait:",
    "    mov ecx, 20000",
    ".Lr3_spin:",
    "    pause",
    "    dec ecx",
    "    jnz .Lr3_spin",
    "    mov edx, {s_interrupt}",
    "    syscall",
    "    test rax, rax",
    "    jz .Lr3_wait",
    // Step 12: `syscall` with TF set by the `popfq` just before it; step
    // 13: `sysretq` keeps TF, and the thread traps at the return address
    // (as QEMU does, and as Linux says hardware does) or after the `nop`.
    "    mov edx, {s_single_step}",
    "    pushfq",
    "    or qword ptr [rsp], {tf}",
    "    popfq",
    "    syscall",
    ".Lr3_s12_ret:",
    "    nop",
    ".Lr3_after_step:",
    // Step 14: loading FS and GS in ring 3 zeroes their bases.
    "    mov eax, {user_ds}",
    "    mov fs, ax",
    "    mov gs, ax",
    "    mov edx, {s_segments}",
    "    syscall",
    // Step 15: the kernel wrote the bases back; the kernel answers with
    // the address of the tail.
    "    mov r15, qword ptr fs:[0]",
    "    mov r12, qword ptr gs:[0]",
    "    mov edx, {s_bases}",
    "    syscall",
    // Step 16, in the tail: a `syscall` whose return address is 2^47;
    // step 17: the thread comes back at RIP 0 and faults; the kernel
    // resumes it here.
    "    jmp rax",
    ".Lr3_after_tail:",
    // Steps 18 to 23: faults, each resumed after its instruction.
    "    mov rax, {unmapped}",
    ".Lr3_pf_write:",
    "    mov qword ptr [rax], 1",
    ".Lr3_after_pf_write:",
    "    lea rax, [rip + .Lr3_start]",
    ".Lr3_pf_code:",
    "    mov byte ptr [rax], 0x90",
    ".Lr3_after_pf_code:",
    ".Lr3_ud2:",
    "    ud2",
    ".Lr3_after_ud2:",
    ".Lr3_int80:",
    "    int 0x80",
    ".Lr3_after_int80:",
    "    sub rsp, 16",
    ".Lr3_sgdt:",
    "    sgdt [rsp]",
    ".Lr3_after_sgdt:",
    "    add rsp, 16",
    ".Lr3_hlt:",
    "    hlt",
    ".Lr3_after_hlt:",
    // Step 24: done.
    "    mov edx, {s_done}",
    "    syscall",
    "    ud2",
    // A check failed: DebugHalt with its number.
    ".Lr3_fail:",
    "    mov edx, 17",
    "    syscall",
    "    ud2",
    ".balign 8",
    ".Lr3_patterns:",
    ".rept 15",
    "    .quad RING3_PATTERN + 1 + (. - .Lr3_patterns) / 8",
    ".endr",
    ".Lr3_one:",
    "    .quad {one}",
    ".Lr3_zero:",
    "    .quad 0",
    "ring3_code_end:",
    ".popsection",
    //
    // Copied to the end of the last page below 2^47, so RCX = 2^47 after
    // its `syscall`.
    ".pushsection .rodata.ring3_tail, \"a\", @progbits",
    ".global ring3_tail, ring3_tail_end",
    "ring3_tail:",
    "    mov edx, {s_tail}",
    "    syscall",
    "ring3_tail_end:",
    ".popsection",
    //
    // Offsets in `ring3_code` the kernel checks against, in [`L`]'s order.
    ".pushsection .rodata.ring3_labels, \"a\", @progbits",
    ".balign 8",
    ".global RING3_LABELS",
    "RING3_LABELS:",
    "    .quad .Lr3_s1_ret - .Lr3_start",
    "    .quad .Lr3_s2_ret - .Lr3_start",
    "    .quad .Lr3_after_int3 - .Lr3_start",
    "    .quad .Lr3_fwait - .Lr3_start",
    "    .quad .Lr3_after_fwait - .Lr3_start",
    "    .quad .Lr3_divsd - .Lr3_start",
    "    .quad .Lr3_after_divsd - .Lr3_start",
    "    .quad .Lr3_s12_ret - .Lr3_start",
    "    .quad .Lr3_after_step - .Lr3_start",
    "    .quad .Lr3_after_tail - .Lr3_start",
    "    .quad .Lr3_pf_write - .Lr3_start",
    "    .quad .Lr3_after_pf_write - .Lr3_start",
    "    .quad .Lr3_pf_code - .Lr3_start",
    "    .quad .Lr3_after_pf_code - .Lr3_start",
    "    .quad .Lr3_ud2 - .Lr3_start",
    "    .quad .Lr3_after_ud2 - .Lr3_start",
    "    .quad .Lr3_int80 - .Lr3_start",
    "    .quad .Lr3_after_int80 - .Lr3_start",
    "    .quad .Lr3_sgdt - .Lr3_start",
    "    .quad .Lr3_after_sgdt - .Lr3_start",
    "    .quad .Lr3_hlt - .Lr3_start",
    "    .quad .Lr3_after_hlt - .Lr3_start",
    ".popsection",
    ".purgem ring3_ensure",
    ".purgem ring3_check",
    ".purgem ring3_load",
    pattern = const PATTERN,
    s_initial = const CHECKPOINT + S_INITIAL as u64,
    s_registers = const CHECKPOINT + S_REGISTERS as u64,
    s_flags = const CHECKPOINT + S_FLAGS as u64,
    s_written = const CHECKPOINT + S_WRITTEN as u64,
    s_fpu = const CHECKPOINT + S_FPU as u64,
    s_pending = const CHECKPOINT + S_PENDING as u64,
    s_mxcsr = const CHECKPOINT + S_MXCSR as u64,
    s_interrupt = const CHECKPOINT + S_INTERRUPT as u64,
    s_single_step = const CHECKPOINT + S_SINGLE_STEP as u64,
    s_segments = const CHECKPOINT + S_SEGMENTS as u64,
    s_bases = const CHECKPOINT + S_BASES as u64,
    s_tail = const CHECKPOINT + S_TAIL as u64,
    s_done = const CHECKPOINT + S_DONE as u64,
    message = const MESSAGE_AT,
    df_nt_ac = const rflags::DF | rflags::NT | rflags::AC,
    df_ac = const rflags::DF | rflags::AC,
    not_ac = const !rflags::AC as i64,
    tf = const rflags::TF,
    rcx_written = const RCX_WRITTEN,
    r11_written = const R11_WRITTEN,
    xmm_lo = const XMM_LO,
    xmm_hi = const XMM_HI,
    one = const ONE,
    pi = const PI,
    user_ds = const t::USER_DS,
    unmapped = const UNMAPPED,
);

/// Labels in `ring3_code`, as indices into `RING3_LABELS`.
#[derive(Clone, Copy, Debug)]
enum L {
    S1Ret,
    S2Ret,
    AfterInt3,
    Fwait,
    AfterFwait,
    Divsd,
    AfterDivsd,
    S12Ret,
    AfterStep,
    AfterTail,
    PfWrite,
    AfterPfWrite,
    PfCode,
    AfterPfCode,
    Ud2,
    AfterUd2,
    Int80,
    AfterInt80,
    Sgdt,
    AfterSgdt,
    Hlt,
    AfterHlt,
}
const LABELS: usize = L::AfterHlt as usize + 1;

// SAFETY: the `global_asm!` above defines each symbol: `RING3_LABELS` as
// `LABELS` quadwords and the others as labels in read-only data, of which
// only the addresses are used, to copy the bytes between them.
unsafe extern "C" {
    safe static RING3_LABELS: [u64; LABELS];
    safe static ring3_code: u8;
    safe static ring3_code_end: u8;
    safe static ring3_tail: u8;
    safe static ring3_tail_end: u8;
}

/// The user address of `l`.
fn at(l: L) -> u64 {
    CODE + RING3_LABELS[l as usize]
}

/// The bytes from `start` to `end`, two labels in the kernel's read-only
/// data.
fn blob(start: &'static u8, end: &'static u8) -> &'static [u8] {
    let (s, e) = (start as *const u8, end as *const u8);
    // SAFETY: both labels are in one read-only section of the kernel
    // image, `start` first, so the range is initialised, immutable memory.
    unsafe { core::slice::from_raw_parts(s, e as usize - s as usize) }
}

// ---------------------------------------------------------------------------
// The steps
// ---------------------------------------------------------------------------

const S_INITIAL: u32 = 1;
const S_REGISTERS: u32 = 2;
const S_FLAGS: u32 = 3;
const S_WRITTEN: u32 = 4;
const X_BREAKPOINT: u32 = 5;
const S_FPU: u32 = 6;
const S_PENDING: u32 = 7;
const X_X87: u32 = 8;
const X_SIMD: u32 = 9;
const S_MXCSR: u32 = 10;
const S_INTERRUPT: u32 = 11;
const S_SINGLE_STEP: u32 = 12;
const X_DEBUG: u32 = 13;
const S_SEGMENTS: u32 = 14;
const S_BASES: u32 = 15;
const S_TAIL: u32 = 16;
const X_FETCH_0: u32 = 17;
const X_PF_WRITE: u32 = 18;
const X_PF_CODE: u32 = 19;
const X_UD: u32 = 20;
const X_INT80: u32 = 21;
const X_SGDT: u32 = 22;
const X_HLT: u32 = 23;
const S_DONE: u32 = 24;

/// Where an expected exception's RIP is, and where the thread resumes.
#[derive(Clone, Copy)]
enum Ip {
    Label(L),
    Abs(u64),
}

impl Ip {
    fn addr(self) -> u64 {
        match self {
            Ip::Label(l) => at(l),
            Ip::Abs(a) => a,
        }
    }
}

/// An exception step: the vector, error code and CR2 it must arrive with
/// (`trap_from_user`, `l4core::entry::classify`), the RIP the CPU pushed,
/// and where the test resumes the thread, as a fault handler would.
struct Expected {
    step: u32,
    what: &'static str,
    vector: u8,
    error: u64,
    cr2: u64,
    rip: Ip,
    resume: Ip,
}

const EXCEPTIONS: [Expected; 11] = [
    Expected {
        step: X_BREAKPOINT,
        what: "int3, the one DPL-3 gate, with RIP after it",
        vector: t::BREAKPOINT,
        error: 0,
        cr2: 0,
        rip: Ip::Label(L::AfterInt3),
        resume: Ip::Label(L::AfterInt3),
    },
    Expected {
        step: X_X87,
        what: "the pending x87 exception at the fwait",
        vector: 16,
        error: 0,
        cr2: 0,
        rip: Ip::Label(L::Fwait),
        resume: Ip::Label(L::AfterFwait),
    },
    Expected {
        step: X_SIMD,
        what: "divsd by zero with ZM clear",
        vector: 19,
        error: 0,
        cr2: 0,
        rip: Ip::Label(L::Divsd),
        resume: Ip::Label(L::AfterDivsd),
    },
    Expected {
        step: X_DEBUG,
        what: "single step: sysretq kept TF; on IST4, handled on the kernel stack",
        vector: t::DEBUG,
        error: 0,
        cr2: 0,
        rip: Ip::Label(L::AfterStep),
        resume: Ip::Label(L::AfterStep),
    },
    Expected {
        step: X_FETCH_0,
        what: "the fetch at RIP 0",
        vector: t::PAGE_FAULT,
        error: PageFaultError::USER | PageFaultError::FETCH,
        cr2: 0,
        rip: Ip::Abs(0),
        resume: Ip::Label(L::AfterTail),
    },
    Expected {
        step: X_PF_WRITE,
        what: "a write to an unmapped page",
        vector: t::PAGE_FAULT,
        error: PageFaultError::USER | PageFaultError::WRITE,
        cr2: UNMAPPED,
        rip: Ip::Label(L::PfWrite),
        resume: Ip::Label(L::AfterPfWrite),
    },
    Expected {
        step: X_PF_CODE,
        what: "a write to its read-only code page",
        vector: t::PAGE_FAULT,
        error: PageFaultError::PRESENT | PageFaultError::USER | PageFaultError::WRITE,
        cr2: CODE,
        rip: Ip::Label(L::PfCode),
        resume: Ip::Label(L::AfterPfCode),
    },
    Expected {
        step: X_UD,
        what: "ud2",
        vector: 6,
        error: 0,
        cr2: 0,
        rip: Ip::Label(L::Ud2),
        resume: Ip::Label(L::AfterUd2),
    },
    Expected {
        step: X_INT80,
        what: "int 0x80 through a DPL-0 gate",
        vector: 13,
        error: 0x80 * 8 + 2,
        cr2: 0,
        rip: Ip::Label(L::Int80),
        resume: Ip::Label(L::AfterInt80),
    },
    Expected {
        step: X_SGDT,
        what: "sgdt under UMIP",
        vector: 13,
        error: 0,
        cr2: 0,
        rip: Ip::Label(L::Sgdt),
        resume: Ip::Label(L::AfterSgdt),
    },
    Expected {
        step: X_HLT,
        what: "hlt in ring 3",
        vector: 13,
        error: 0,
        cr2: 0,
        rip: Ip::Label(L::Hlt),
        resume: Ip::Label(L::AfterHlt),
    },
];

/// What the test made.
struct Ctx {
    /// The thread's TCB, and a second one whose FP state step 6 switches
    /// to.
    ours: TcbRef,
    other: TcbRef,
    /// The tail's entry: `ring3_tail` placed to end at 2^47.
    tail: u64,
    /// Whether CR4.UMIP is set, so `sgdt` faults in ring 3 (H11).
    umip: bool,
}

static CTX: StaticCell<Ctx> = StaticCell::new();
/// The next step expected.
static STEP: AtomicU32 = AtomicU32::new(S_INITIAL);
/// Bytes `DebugPutChar` has printed.
static PUT: AtomicUsize = AtomicUsize::new(0);
/// Interrupts taken from ring 3, how many there were when step 11 began,
/// the RIP of the first one after that, and step 11's polls.
static USER_IRQS: AtomicU64 = AtomicU64::new(0);
static IRQS_BEFORE: AtomicU64 = AtomicU64::new(0);
static IRQ_RIP: AtomicU64 = AtomicU64::new(0);
static POLLS: AtomicU64 = AtomicU64::new(0);
/// Exits by `sysretq` and by `iretq`, and the path of the last one, 1 +
/// `Exit as u32`, to compare with what `entry::exit_to_user` recorded.
static SYSRETS: AtomicU64 = AtomicU64::new(0);
static IRETS: AtomicU64 = AtomicU64::new(0);
static EXPECT_EXIT: AtomicU32 = AtomicU32::new(0);
/// Set when step 9's `divsd` raised no `#XM`, which only QEMU's TCG may do:
/// it never raises SIMD floating-point exceptions.
static NO_SIMD_EXCEPTION: AtomicBool = AtomicBool::new(false);

fn fail(why: fmt::Arguments<'_>) -> ! {
    kprintln!(
        "TEST FAIL: ring3: step {}: {why}",
        STEP.load(Ordering::Relaxed)
    );
    exit(ExitCode::Failure)
}

macro_rules! ensure {
    ($cond:expr, $($arg:tt)*) => {
        if !$cond {
            fail(format_args!($($arg)*))
        }
    };
}

// ---------------------------------------------------------------------------
// Setup
// ---------------------------------------------------------------------------

/// `test=ring3`: builds the throwaway address space and the thread, and
/// drops to ring 3 by `iretq`. Every later entry comes to [`on_entry`].
pub fn test_ring3(root: &'static RootSpace, bi: &BootInfo) -> ! {
    let Some((i, d)) = bi
        .untyped()
        .iter()
        .enumerate()
        .filter(|(_, d)| d.is_device == 0 && d.size_bits >= 16)
        .min_by_key(|(_, d)| d.size_bits)
    else {
        fail(format_args!("no RAM untyped of 64 KiB"))
    };
    let ut = bi.untyped.start + i as u64;
    let e = bi.empty.start;
    // One kernel operation, as a thread's two `Call`s would be.
    let (f, ours, other) = {
        let mut k = Objects::begin();
        retype(&mut k, root, ut, ObjectType::Frame4K, e, FRAMES as u64);
        retype(&mut k, root, ut, ObjectType::Tcb, e + FRAMES as u64, 2);
        let layout = &root.plan.layout;
        let object = |slot: u64| k.load(layout.slot(slot)).cap.object();
        let f: [u64; FRAMES] = core::array::from_fn(|j| object(e + j as u64));
        let tcb = |j: u64| {
            TcbRef::new(object(e + FRAMES as u64 + j))
                .unwrap_or_else(|| fail(format_args!("TCB {j} is not a TCB address")))
        };
        (f, tcb(0), tcb(1))
    };
    kprintln!(
        "ring3: from the {} KiB untyped in root slot {ut} at {:#x}: {FRAMES} frames from {:#x}, TCBs at {:#x} and {:#x}",
        (1u64 << d.size_bits) >> 10,
        d.paddr,
        f[0],
        ours.get(),
        other.get()
    );

    // The address space: the kernel's upper half, then the code, data and
    // tail pages.
    let kernel_pml4 = cpu::read_cr3() & vs::ADDR_4K;
    for slot in 256..vs::ENTRIES {
        write_entry(f[PML4], slot, read_entry(kernel_pml4, slot));
    }
    let rx = UserAccess {
        write: false,
        execute: true,
    };
    let rw = UserAccess {
        write: true,
        execute: false,
    };
    for (va, pdpt, pd, pt, frame, access) in [
        (CODE, PDPT_LO, PD_LO, PT_LO, CODE_FRAME, rx),
        (DATA, PDPT_LO, PD_LO, PT_LO, DATA_FRAME, rw),
        (TAIL_PAGE, PDPT_HI, PD_HI, PT_HI, TAIL_FRAME, rx),
    ] {
        write_entry(f[PML4], vs::index(va, 3), vs::user_table(f[pdpt]));
        write_entry(f[pdpt], vs::index(va, 2), vs::user_table(f[pd]));
        write_entry(f[pd], vs::index(va, 1), vs::user_table(f[pt]));
        let pte = vs::user_pte(f[frame], access, CacheType::WriteBack);
        write_entry(f[pt], vs::index(va, 0), pte);
    }
    let code = blob(&ring3_code, &ring3_code_end);
    let tail = blob(&ring3_tail, &ring3_tail_end);
    ensure!(
        code.len() <= 4096,
        "the ring-3 code is {} bytes",
        code.len()
    );
    // In code order; a label right after another shares its address.
    let mut last = 0;
    for (n, &off) in RING3_LABELS.iter().enumerate() {
        ensure!(
            off > 0 && off >= last && off < code.len() as u64,
            "label {n} at {off:#x} is out of order"
        );
        last = off;
    }
    write_bytes(f[CODE_FRAME], code);
    write_bytes(f[TAIL_FRAME] + 4096 - tail.len() as u64, tail);
    let mut message = [0u8; MESSAGE.len() + 1];
    message[..MESSAGE.len()].copy_from_slice(MESSAGE.as_bytes());
    write_bytes(f[DATA_FRAME] + (MESSAGE_AT - DATA), &message);
    write_bytes(f[DATA_FRAME] + (FS_BASE - DATA), &FS_MARK.to_le_bytes());
    write_bytes(f[DATA_FRAME] + (GS_BASE - DATA), &GS_MARK.to_le_bytes());

    // The thread: every register 0 but RIP, RSP, RFLAGS and the bases; the
    // initial FP state; and a first exit by `iretq`.
    fpu::init_area(ours);
    fpu::init_area(other);
    let regs = regs_of(ours);
    *regs = Regs {
        next_ip: CODE,
        fault_ip: CODE,
        rsp: STACK_TOP,
        rflags: 0x202,
        fs_base: FS_BASE,
        gs_base: GS_BASE,
        exit: Exit::Iret as u64,
        ..Regs::default()
    };
    let umip = cpu::read_cr4() & (1 << 11) != 0;
    CTX.init(Ctx {
        ours,
        other,
        tail: LOWER_HALF_END - tail.len() as u64,
        umip,
    });
    entry::set_user_entry_hook(on_entry);
    kprintln!(
        "ring3: {} bytes of code at {CODE:#x}, the tail at {:#x}, data and stack at {DATA:#x}; UMIP {}",
        code.len(),
        LOWER_HALF_END - tail.len() as u64,
        if umip { "on" } else { "off" }
    );
    // SAFETY: the new PML4's upper half is the kernel's, so the kernel's
    // code, stacks, statics and direct map stay mapped as they were; its
    // lower half maps only the three user pages, which SMEP and SMAP keep
    // the kernel from. The kernel PML4 is not freed or changed.
    unsafe { asm!("mov cr3, {}", in(reg) f[PML4], options(nostack, preserves_flags)) };
    entry::load_user_bases(regs);
    kprintln!("ring3: dropping to ring 3 at {CODE:#x} by iretq");
    resume(regs)
}

/// Retypes `n` objects of type `ty` from the untyped in root slot `ut` into
/// root slots from `offset`, through `l4core::invoke` as a thread's `Call`
/// would, restarting it while the untyped's reset is preempted: interrupts
/// are off, so the pending one stays pending, and each restart clears one
/// more chunk.
fn retype(k: &mut Objects, root: &RootSpace, ut: u64, ty: ObjectType, offset: u64, n: u64) {
    let cnode = k.load(root.plan.layout.slot(CAP_INIT_CNODE)).cap;
    let mrs = [ty as u64, 0, 0, 0, offset, n];
    for _ in 0..100_000 {
        let lookup = |k: &Objects, cptr| {
            cspace::lookup_cap(k, cnode, cptr)
                .unwrap_or_else(|f| fail(format_args!("CPtr {cptr} does not resolve: {f:?}")))
        };
        let slot = lookup(k, ut);
        let extra = [ExtraCap::load(k, lookup(k, CAP_INIT_CNODE))];
        let msg = Message {
            label: label::UNTYPED_RETYPE,
            mrs: &mrs,
            extra_caps: &extra,
        };
        match invoke::invoke(k, slot, &msg) {
            Ok(_) => return,
            Err(InvokeError::Preempted) => {}
            Err(InvokeError::Error(e)) => fail(format_args!("retype into {ty:?}: {e:?}")),
        }
    }
    fail(format_args!("retype into {ty:?} never finished"))
}

/// The page-table entry `index` of the table at physical `table`.
fn read_entry(table: u64, index: usize) -> u64 {
    // SAFETY: `table` is a page table (the kernel PML4, from CR3) in RAM
    // below the direct map's end; a read by value of one word.
    unsafe { ptr::read((phys_to_virt(table) + index as u64 * 8) as *const u64) }
}

/// Writes entry `index` of the test's table at physical `table`.
fn write_entry(table: u64, index: usize, value: u64) {
    debug_assert!(index < vs::ENTRIES);
    // SAFETY: `table` is one of the frames this test retyped from a RAM
    // untyped, mapped in the direct map and referred to by nothing else;
    // no CR3 holds it yet.
    unsafe { ptr::write((phys_to_virt(table) + index as u64 * 8) as *mut u64, value) }
}

/// Copies `bytes` to physical `at`, inside one of the test's frames.
fn write_bytes(at: u64, bytes: &[u8]) {
    debug_assert!(at % 4096 + bytes.len() as u64 <= 4096);
    // SAFETY: as in `write_entry`: `at` and the bytes after it lie in one
    // of the test's frames, which no Rust reference covers.
    unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), phys_to_virt(at) as *mut u8, bytes.len()) }
}

/// The registers of the test's TCB `t`. Call once per entry, so that two
/// of these never coexist.
fn regs_of(t: TcbRef) -> &'static mut Regs {
    // SAFETY: `t` is a TCB this test retyped; its `regs` field is 24
    // words at REGS_OFFSET, 8-byte aligned, in RAM in the direct map. Only
    // this test touches the object, one entry at a time, and each entry
    // takes this reference once; any bit pattern is a valid `Regs`.
    unsafe { &mut *((phys_to_virt(t.get() + REGS_OFFSET)) as *mut Regs) }
}

/// Exits to the thread with `regs`, its FP state in the registers.
fn resume(regs: &Regs) -> ! {
    let ctx = CTX
        .get()
        .unwrap_or_else(|| fail(format_args!("no context")));
    fpu::switch_to(ctx.ours);
    let (_, path) = le::exit_frame(regs);
    match path {
        Exit::Sysret => SYSRETS.fetch_add(1, Ordering::Relaxed),
        Exit::Iret => IRETS.fetch_add(1, Ordering::Relaxed),
    };
    EXPECT_EXIT.store(1 + path as u32, Ordering::Relaxed);
    entry::exit_to_user(regs)
}

// ---------------------------------------------------------------------------
// Entries
// ---------------------------------------------------------------------------

const IA32_GS_BASE: u32 = 0xC000_0101;

fn rflags_now() -> u64 {
    let v;
    // SAFETY: `pushfq; pop` reads RFLAGS through one stack slot it owns.
    unsafe { asm!("pushfq", "pop {}", out(reg) v, options(nomem, preserves_flags)) };
    v
}

fn rsp_now() -> u64 {
    let v;
    // SAFETY: reading RSP has no side effects.
    unsafe { asm!("mov {}, rsp", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// The hook `entry::from_user` calls with every entry from ring 3.
fn on_entry(frame: &TrapFrame, e: UserEntry) -> ! {
    let Some(ctx) = CTX.get() else {
        fail(format_args!("an entry from ring 3 before the test began"))
    };
    check_entry(frame);
    let regs = regs_of(ctx.ours);
    le::save(frame, regs);
    match e {
        UserEntry::Interrupt(v) => {
            irq::handle(v);
            let n = USER_IRQS.fetch_add(1, Ordering::Relaxed);
            if STEP.load(Ordering::Relaxed) == S_INTERRUPT
                && n == IRQS_BEFORE.load(Ordering::Relaxed)
            {
                IRQ_RIP.store(frame.rip, Ordering::Relaxed);
            }
            ensure!(
                regs.exit() == Exit::Iret,
                "an interrupt saved as {:?}",
                regs.exit()
            );
            resume(regs)
        }
        UserEntry::Syscall => syscall(ctx, regs, frame),
        UserEntry::Exception { vector, error, cr2 } => exception(ctx, regs, vector, error, cr2),
        UserEntry::Fatal => fail(format_args!("a fatal entry, vector {:#x}", frame.vector)),
    }
}

/// What every entry from ring 3 must find: GS on the per-CPU area and the
/// thread's bases in their MSRs, the kernel's RFLAGS with IF, TF, DF, AC
/// and NT clear, the frame at the top of the stack its entry uses, this
/// code on the kernel stack, and the user selectors in the frame. Also
/// that the last exit took the path `exit_frame` chose.
fn check_entry(frame: &TrapFrame) {
    let step = STEP.load(Ordering::Relaxed);
    let gs = cpu::read_msr(IA32_GS_BASE);
    ensure!(
        gs == gdt::per_cpu(),
        "GS base {gs:#x} in ring 0, not the per-CPU area"
    );
    let mut bases = Regs::default();
    entry::save_user_bases(&mut bases);
    // Step 14's thread zeroes both bases itself before its checkpoint.
    if step != S_SEGMENTS {
        ensure!(
            (bases.fs_base, bases.gs_base) == (FS_BASE, GS_BASE),
            "FS base {:#x} and user GS base {:#x} in the MSRs",
            bases.fs_base,
            bases.gs_base
        );
    }
    let fl = rflags_now();
    let off = rflags::IF | rflags::TF | rflags::DF | rflags::AC | rflags::NT;
    ensure!(fl & off == 0, "the kernel runs with RFLAGS {fl:#x}");
    let stacks = gdt::stack_layout();
    let top = if frame.vector == u64::from(t::DEBUG) {
        stacks.ist[3].end
    } else {
        stacks.kernel.end
    };
    let at = frame as *const TrapFrame as u64;
    ensure!(
        at == top - size_of::<TrapFrame>() as u64,
        "the frame is at {at:#x}, not at the top of its stack {top:#x}"
    );
    ensure!(
        stacks.kernel.contains(&rsp_now()),
        "the entry runs on RSP {:#x}, off the kernel stack",
        rsp_now()
    );
    ensure!(
        (frame.cs, frame.ss) == (u64::from(t::USER_CS), u64::from(t::USER_DS)),
        "CS {:#x}, SS {:#x}",
        frame.cs,
        frame.ss
    );
    let expect = EXPECT_EXIT.load(Ordering::Relaxed);
    let recorded = entry::last_exit().map_or(0, |p| 1 + p as u32);
    ensure!(
        recorded == expect,
        "exit_to_user took path {recorded}, the test expected {expect}"
    );
}

/// A system call from the thread.
fn syscall(ctx: &Ctx, regs: &mut Regs, frame: &TrapFrame) -> ! {
    let step = STEP.load(Ordering::Relaxed);
    ensure!(
        regs.exit() == Exit::Sysret
            && regs.fault_ip == regs.next_ip.wrapping_sub(2)
            && regs.rcx == regs.next_ip
            && regs.r11 == regs.rflags
            && regs.next_ip == frame.rip,
        "a syscall saved with exit {:?}, fault_ip {:#x}, next_ip {:#x}, RCX {:#x}, R11 {:#x}, RFLAGS {:#x}",
        regs.exit(),
        regs.fault_ip,
        regs.next_ip,
        regs.rcx,
        regs.r11,
        regs.rflags
    );
    match Syscall::from_number(regs.rdx, cfg!(feature = "debug")) {
        Some(Syscall::DebugPutChar) => {
            let i = PUT.fetch_add(1, Ordering::Relaxed);
            let b = regs.rdi as u8;
            ensure!(
                step == S_REGISTERS && MESSAGE.as_bytes().get(i) == Some(&b),
                "DebugPutChar of byte {b:#x} at {i}"
            );
            crate::debug::print(format_args!("{}", b as char));
            resume(regs)
        }
        Some(Syscall::DebugHalt) => fail(format_args!(
            "ring 3 found check {:#x} wrong, at {:#x}",
            regs.rdi, regs.fault_ip
        )),
        Some(s) => fail(format_args!("an unexpected {s}")),
        None => {}
    }
    let n = regs.rdx.wrapping_sub(CHECKPOINT);
    let step = if step == X_SIMD && n == u64::from(S_MXCSR) {
        ensure!(
            cpu::hypervisor() == Hypervisor::QemuTcg,
            "divsd by zero with ZM clear raised no #XM"
        );
        NO_SIMD_EXCEPTION.store(true, Ordering::Relaxed);
        S_MXCSR
    } else {
        step
    };
    ensure!(
        n == u64::from(step),
        "checkpoint system call {:#x} (unknown to the kernel, as it must be) at step {step}",
        regs.rdx
    );
    let next = checkpoint(ctx, regs, frame, step);
    STEP.store(next, Ordering::Relaxed);
    resume(regs)
}

/// Checks checkpoint `step`'s registers; returns the next step.
fn checkpoint(ctx: &Ctx, regs: &mut Regs, frame: &TrapFrame, step: u32) -> u32 {
    match step {
        S_INITIAL => {
            ensure!(
                (regs.r9, regs.r10, regs.r8) == (0x202, 0x23, 0x1B),
                "RFLAGS {:#x}, CS {:#x}, SS {:#x} at the start",
                regs.r9,
                regs.r10,
                regs.r8
            );
            ensure!(
                (regs.rdi, regs.rsi) == (u64::from(lf::FCW_INIT), u64::from(lf::MXCSR_INIT)),
                "FCW {:#x}, MXCSR {:#x} at the start",
                regs.rdi,
                regs.rsi
            );
            ensure!(
                (regs.r15, regs.r12) == (FS_MARK, GS_MARK),
                "fs:[0] {:#x}, gs:[0] {:#x}",
                regs.r15,
                regs.r12
            );
            ensure!(
                [regs.rbx, regs.rbp, regs.r13, regs.r14] == [0; 4] && regs.rsp == STACK_TOP,
                "registers not zero at the start, or RSP {:#x}",
                regs.rsp
            );
            ensure!(
                regs.next_ip == at(L::S1Ret),
                "returns to {:#x}",
                regs.next_ip
            );
            kprintln!(
                "ring3:  1 first entry, by iretq to {CODE:#x}: CS 0x23, SS 0x1b, RFLAGS 0x202, FCW 0x37f, MXCSR 0x1f80, FS and GS bases in place; syscall at {:#x}",
                regs.fault_ip
            );
            S_REGISTERS
        }
        S_REGISTERS => {
            ensure!(
                PUT.load(Ordering::Relaxed) == MESSAGE.len(),
                "DebugPutChar printed {} bytes",
                PUT.load(Ordering::Relaxed)
            );
            let got = [
                regs.rax, regs.rbx, regs.rsi, regs.rdi, regs.rbp, regs.r8, regs.r9, regs.r10,
                regs.r12, regs.r13, regs.r14, regs.r15,
            ];
            let want = [0, 1, 4, 5, 6, 7, 8, 9, 11, 12, 13, 14].map(pattern);
            ensure!(got == want, "registers {got:#x?}");
            ensure!(
                regs.next_ip == at(L::S2Ret),
                "returns to {:#x}",
                regs.next_ip
            );
            kprintln!(
                "ring3:  2 {} DebugPutChar calls, each back by sysretq; every register but RCX and R11 reached the kernel",
                MESSAGE.len()
            );
            S_FLAGS
        }
        S_FLAGS => {
            let set = rflags::DF | rflags::NT | rflags::AC;
            ensure!(
                regs.rflags & set == set,
                "the thread's RFLAGS {:#x}",
                regs.rflags
            );
            kprintln!(
                "ring3:  3 syscall with DF, NT and AC set: RFLAGS {:#x} saved, IA32_FMASK cleared them in ring 0; back with DF and AC, without NT",
                regs.rflags
            );
            S_WRITTEN
        }
        S_WRITTEN => {
            regs.rcx = RCX_WRITTEN;
            regs.r11 = R11_WRITTEN;
            regs.exit = Exit::Iret as u64;
            ensure!(
                le::exit_frame(regs).1 == Exit::Iret,
                "exit_frame chose sysretq"
            );
            kprintln!("ring3:  4 RCX and R11 written after a syscall: back by iretq with them");
            X_BREAKPOINT
        }
        S_FPU => {
            fpu_switch(ctx);
            S_PENDING
        }
        S_PENDING => {
            let a = saved_area(ctx);
            let (fcw, fsw) = (lf::u16_at(&a, offset::FCW), lf::u16_at(&a, offset::FSW));
            // ZM clear in FCW; ZE and ES set in FSW.
            ensure!(
                fcw & 0x4 == 0 && fsw & 0x84 == 0x84,
                "FCW {fcw:#x}, FSW {fsw:#x}"
            );
            kprintln!(
                "ring3:  7 an unmasked x87 divide by zero pending (FCW {fcw:#x}, FSW {fsw:#x}) across XSAVE64 and XRSTOR64: nothing raised in ring 0"
            );
            X_X87
        }
        S_MXCSR => {
            let mxcsr = lf::u32_at(&saved_area(ctx), offset::MXCSR);
            // ZE (bit 2) set, ZM (bit 9) clear.
            ensure!(mxcsr & 0x204 == 0x4, "MXCSR {mxcsr:#x} after divsd by zero");
            if NO_SIMD_EXCEPTION.load(Ordering::Relaxed) {
                kprintln!(
                    "ring3: 10 MXCSR {mxcsr:#x}: divsd by zero set ZE with ZM clear, but QEMU's TCG raised no #XM; it raises no SIMD exception"
                );
            } else {
                kprintln!("ring3: 10 MXCSR {mxcsr:#x} after the #XM: ZE set");
            }
            IRQS_BEFORE.store(USER_IRQS.load(Ordering::Relaxed), Ordering::Relaxed);
            S_INTERRUPT
        }
        S_INTERRUPT => {
            let polls = POLLS.fetch_add(1, Ordering::Relaxed) + 1;
            let n = USER_IRQS.load(Ordering::Relaxed);
            if n == IRQS_BEFORE.load(Ordering::Relaxed) {
                ensure!(polls < 100_000, "no interrupt from ring 3 in {polls} polls");
                regs.rax = 0;
                return S_INTERRUPT;
            }
            regs.rax = n;
            kprintln!(
                "ring3: 11 an interrupt taken in ring 3 at {:#x} while the thread spun, through irq::handle and back by iretq, after {polls} polls; {n} so far",
                IRQ_RIP.load(Ordering::Relaxed)
            );
            S_SINGLE_STEP
        }
        S_SINGLE_STEP => {
            ensure!(
                regs.rflags & rflags::TF != 0,
                "RFLAGS {:#x} without TF",
                regs.rflags
            );
            let steps = entry::ring0_single_steps();
            kprintln!(
                "ring3: 12 syscall with TF set: {steps} #DB at syscall_entry{}; back by sysretq with TF set",
                if steps == 0 {
                    " (the CPU checks TF after IA32_FMASK cleared it)"
                } else {
                    ", returned from"
                }
            );
            X_DEBUG
        }
        S_SEGMENTS => {
            let mut bases = *regs;
            entry::save_user_bases(&mut bases);
            ensure!(
                (bases.fs_base, bases.gs_base) == (0, 0),
                "after mov fs and mov gs in ring 3: FS base {:#x}, user GS base {:#x}",
                bases.fs_base,
                bases.gs_base
            );
            entry::load_user_bases(regs);
            kprintln!(
                "ring3: 14 mov fs and mov gs in ring 3 zeroed IA32_FS_BASE and IA32_KERNEL_GS_BASE; written back from the thread's registers"
            );
            S_BASES
        }
        S_BASES => {
            ensure!(
                (regs.r15, regs.r12) == (FS_MARK, GS_MARK),
                "fs:[0] {:#x}, gs:[0] {:#x}",
                regs.r15,
                regs.r12
            );
            regs.rax = ctx.tail;
            kprintln!(
                "ring3: 15 fs:[0] and gs:[0] read the markers again; to the tail at {:#x}",
                ctx.tail
            );
            S_TAIL
        }
        S_TAIL => {
            ensure!(
                frame.rcx == LOWER_HALF_END && regs.next_ip == LOWER_HALF_END,
                "RCX {:#x} after the tail's syscall",
                frame.rcx
            );
            let (f, path) = le::exit_frame(regs);
            ensure!(
                f.rip == 0 && path == Exit::Iret,
                "exit_frame gives RIP {:#x} by {path:?}",
                f.rip
            );
            kprintln!(
                "ring3: 16 syscall at {:#x} returns to 2^47: RCX {:#x}, so exit_frame gives RIP 0 and iretq",
                regs.fault_ip,
                frame.rcx
            );
            X_FETCH_0
        }
        S_DONE => finish(ctx),
        _ => fail(format_args!("no checkpoint at this step")),
    }
}

/// The thread's x87 and SSE area as XSAVE64 writes it when the other TCB
/// takes the FPU; the thread then takes it back.
fn saved_area(ctx: &Ctx) -> [u8; lf::AREA_SIZE] {
    ensure!(
        fpu::owner() == Some(ctx.ours),
        "the thread does not own the FPU"
    );
    fpu::switch_to(ctx.other);
    let a = fpu::read_area(ctx.ours);
    fpu::switch_to(ctx.ours);
    a
}

/// Step 6: the thread's x87 and SSE state is saved into its area when the
/// other TCB takes the FPU, and comes back when it returns; the other TCB
/// ran on the initial state.
fn fpu_switch(ctx: &Ctx) {
    ensure!(
        fpu::owner() == Some(ctx.ours),
        "the thread does not own the FPU"
    );
    fpu::switch_to(ctx.other);
    ensure!(fpu::owner() == Some(ctx.other), "the switch did not take");
    let a = fpu::read_area(ctx.ours);
    let q = |at: usize| lf::u64_at(&a, at);
    ensure!(
        (q(lf::xmm(0)), q(lf::xmm(0) + 8)) == (XMM_LO, XMM_HI),
        "XMM0 saved as {:#x}:{:#x}",
        q(lf::xmm(0) + 8),
        q(lf::xmm(0))
    );
    ensure!(
        (q(lf::xmm(15)), q(lf::xmm(15) + 8)) == (XMM_HI.rotate_left(32), XMM_LO.rotate_left(32)),
        "XMM15 saved as {:#x}:{:#x}",
        q(lf::xmm(15) + 8),
        q(lf::xmm(15))
    );
    let (fcw, fsw, ftw) = (
        lf::u16_at(&a, offset::FCW),
        lf::u16_at(&a, offset::FSW),
        a[offset::FTW],
    );
    let mxcsr = lf::u32_at(&a, offset::MXCSR);
    // Two pushes: TOP 6, physical registers 6 and 7 valid.
    ensure!(
        fcw == lf::FCW_INIT && (fsw >> 11) & 7 == 6 && ftw == 0xC0 && mxcsr == 0x3F80,
        "FCW {fcw:#x}, FSW {fsw:#x}, FTW {ftw:#x}, MXCSR {mxcsr:#x}"
    );
    // ST0 = 1.0 and ST1 = pi, 80-bit: the significand, then sign and
    // exponent.
    let st0 = (q(lf::st(0)), lf::u16_at(&a, lf::st(0) + 8));
    let st1 = (q(lf::st(1)), lf::u16_at(&a, lf::st(1) + 8));
    ensure!(
        st0 == (1 << 63, 0x3FFF) && st1.1 == 0x4000 && st1.0 >> 32 == 0xC90F_DAA2,
        "ST0 {:#x}/{:#x}, ST1 {:#x}/{:#x}",
        st0.1,
        st0.0,
        st1.1,
        st1.0
    );
    let bv = q(offset::XSTATE_BV);
    ensure!(bv == lf::XCR0, "XSTATE_BV {bv:#x}");
    fpu::switch_to(ctx.ours);
    let b = fpu::read_area(ctx.other);
    let (fcw, mxcsr, xmm0) = (
        lf::u16_at(&b, offset::FCW),
        lf::u32_at(&b, offset::MXCSR),
        lf::u64_at(&b, lf::xmm(0)) | lf::u64_at(&b, lf::xmm(0) + 8),
    );
    ensure!(
        fcw == lf::FCW_INIT && mxcsr == lf::MXCSR_INIT && xmm0 == 0 && b[offset::FTW] == 0,
        "the other TCB ran with FCW {fcw:#x}, MXCSR {mxcsr:#x}, XMM0 {xmm0:#x}"
    );
    kprintln!(
        "ring3:  6 XSAVE64 into the thread's area: XMM0 {XMM_HI:#x}:{XMM_LO:#x}, XMM15 swapped, ST0 1.0, ST1 pi, MXCSR {mxcsr:#x}, XSTATE_BV {bv:#x}; XRSTOR64 of the other TCB's initial state, and back",
        mxcsr = 0x3F80
    );
}

/// An exception from the thread.
fn exception(ctx: &Ctx, regs: &mut Regs, vector: u8, error: u64, cr2: u64) -> ! {
    let step = STEP.load(Ordering::Relaxed);
    let Some(x) = EXCEPTIONS.iter().find(|x| x.step == step) else {
        fail(format_args!(
            "{} at {:#x}, error {error:#x}, CR2 {cr2:#x}, where the test expected a system call",
            Vector(vector),
            regs.next_ip
        ))
    };
    // The single step after `sysretq` restored TF may trap before the next
    // instruction, at the return address, or after it.
    let rip = match step {
        X_DEBUG if regs.next_ip == at(L::S12Ret) => at(L::S12Ret),
        _ => x.rip.addr(),
    };
    ensure!(
        (vector, error, cr2, regs.next_ip) == (x.vector, x.error, x.cr2, rip),
        "{} at {:#x}, error {error:#x}, CR2 {cr2:#x}; expected {} at {:#x}, error {:#x}, CR2 {:#x}",
        Vector(vector),
        regs.next_ip,
        Vector(x.vector),
        x.rip.addr(),
        x.error,
        x.cr2
    );
    ensure!(
        regs.exit() == Exit::Iret && regs.fault_ip == regs.next_ip && regs.error == error,
        "saved with exit {:?}, fault_ip {:#x}, error {:#x}",
        regs.exit(),
        regs.fault_ip,
        regs.error
    );
    let mut note = "";
    match step {
        X_BREAKPOINT => {
            let got = [
                regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi, regs.rdi, regs.rbp, regs.r8,
                regs.r9, regs.r10, regs.r11, regs.r12, regs.r13, regs.r14, regs.r15,
            ];
            ensure!(
                got == core::array::from_fn::<u64, 15, _>(|i| pattern(i as u64)),
                "registers {got:#x?}"
            );
            let set = rflags::DF | rflags::AC;
            ensure!(regs.rflags & set == set, "RFLAGS {:#x}", regs.rflags);
            note = "; all 15 registers and DF and AC reached the kernel, which ran with them clear";
        }
        X_DEBUG => {
            regs.rflags &= !rflags::TF;
            note = if rip == at(L::S12Ret) {
                "; at the return address, before the next instruction ran; TF cleared"
            } else {
                "; after the next instruction; TF cleared"
            };
        }
        X_FETCH_0 => {
            ensure!(
                entry::last_exit() == Some(Exit::Iret),
                "the tail's exit was not iretq"
            );
            note = ", after the iretq exit";
        }
        _ => {}
    }
    kprintln!(
        "ring3: {step:2} {} from ring 3: error {error:#x}{}, RIP {:#x}: {}{note}",
        Vector(vector),
        Cr2((vector == t::PAGE_FAULT).then_some(cr2)),
        regs.next_ip,
        x.what
    );
    // A trap resumes where it was taken; a fault after its instruction.
    regs.next_ip = match step {
        X_DEBUG => rip,
        _ => x.resume.addr(),
    };
    regs.exit = Exit::Iret as u64;
    let next = match step {
        X_INT80 if !ctx.umip => X_HLT,
        _ => step + 1,
    };
    STEP.store(next, Ordering::Relaxed);
    resume(regs)
}

struct Cr2(Option<u64>);

impl fmt::Display for Cr2 {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            Some(v) => write!(f, ", CR2 {v:#x}"),
            None => Ok(()),
        }
    }
}

/// Step 24: everything passed.
fn finish(ctx: &Ctx) -> ! {
    fpu::forget(ctx.other);
    ensure!(
        fpu::owner() == Some(ctx.ours),
        "forgetting a non-owner dropped the owner"
    );
    fpu::forget(ctx.ours);
    ensure!(fpu::owner().is_none(), "forgetting the owner kept it");
    kprintln!(
        "ring3: 24 done: {} exits by sysretq and {} by iretq, {} interrupts taken in ring 3; FPU ownership dropped",
        SYSRETS.load(Ordering::Relaxed),
        IRETS.load(Ordering::Relaxed),
        USER_IRQS.load(Ordering::Relaxed)
    );
    if !ctx.umip {
        kprintln!("ring3: UMIP is off, so sgdt did not fault and was not checked");
    }
    kprintln!("TEST PASS");
    exit(ExitCode::Success)
}
