//! Trap entry and the ring-0 handlers (`docs/design.md`, "Kernel entry and
//! exit": "Entry", "NMI, double fault, machine check and debug",
//! "Interrupts and exceptions taken in ring 0"; ADR 0008), and the idle loop
//! with its interrupt path ("Idle thread").
//!
//! Every vector has a stub, `trap_vector_00` to `trap_vector_ff`, that
//! pushes a zero error code where the CPU pushes none, pushes its vector,
//! runs `clac` and `cld`, and jumps to one of two entries, which push the
//! general registers to complete the [`TrapFrame`] and call Rust with a
//! pointer to it:
//!
//! - `trap_common_entry`, for every vector but NMI, `#DF` and `#MC`, runs
//!   `swapgs` if the saved CS is ring 3, then calls [`trap_from_kernel`] or
//!   [`trap_from_user`].
//! - `trap_fatal_entry`, for NMI, `#DF` and `#MC`, which arrive on their IST
//!   stacks, calls [`trap_fatal`] without `swapgs`; nothing after it reads
//!   GS.
//!
//! No handler returns. A ring-0 trap is a kernel bug and panics with one
//! report, except an interrupt taken in the idle loop, which runs the
//! interrupt path and idles again on a fresh stack. Before M5 nothing runs in
//! ring 3, so a trap from ring 3 panics too.

use core::arch::{asm, global_asm};
use core::ops::Range;
use core::sync::atomic::{AtomicU8, AtomicU32, AtomicU64, Ordering};

use l4core::trap::{self as t, KernelTrap, Report, TrapFrame};

use super::{ExitCode, cpu, exit, gdt, irq};

global_asm!(
    // `trap_stub v`: vector v's entry. The masks come from `l4core::trap`.
    ".macro trap_stub v",
    "    .if \\v < 32",
    "        .if (({error_code} >> \\v) & 1) == 0",
    "            push 0",
    "        .endif",
    "    .else",
    "        push 0",
    "    .endif",
    "    push \\v",
    "    clac",
    "    cld",
    "    .if \\v < 32",
    "        .if ({fatal_vectors} >> \\v) & 1",
    "            jmp trap_fatal_entry",
    "        .else",
    "            jmp trap_common_entry",
    "        .endif",
    "    .else",
    "        jmp trap_common_entry",
    "    .endif",
    ".endm",
    //
    ".pushsection .text.trap, \"ax\", @progbits",
    ".irp hi, 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f",
    ".irp lo, 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f",
    "trap_vector_\\hi\\lo:",
    "    trap_stub 0x\\hi\\lo",
    ".endr",
    ".endr",
    //
    // RSP points at the vector; the saved CS is three words above it.
    "trap_common_entry:",
    "    test byte ptr [rsp + {cs_above_vector}], 3",
    "    jz 2f",
    "    swapgs",
    "2:",
    "    push rax",
    "    push rbx",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push rbp",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    // The frame is 22 words and the CPU aligned RSP to 16 before pushing
    // SS, so RSP is 16-byte aligned at each call.
    "    mov rdi, rsp",
    "    test byte ptr [rsp + {frame_cs}], 3",
    "    jnz 3f",
    "    call {from_kernel}",
    "    ud2",
    "3:",
    "    call {from_user}",
    "    ud2",
    //
    // NMI, #DF and #MC, on IST2, IST1 and IST3: no `swapgs`, whatever the
    // ring, so the window between `swapgs` and `sysretq` or `iretq` in M5
    // cannot mislead them.
    "trap_fatal_entry:",
    "    push rax",
    "    push rbx",
    "    push rcx",
    "    push rdx",
    "    push rsi",
    "    push rdi",
    "    push rbp",
    "    push r8",
    "    push r9",
    "    push r10",
    "    push r11",
    "    push r12",
    "    push r13",
    "    push r14",
    "    push r15",
    "    mov rdi, rsp",
    "    call {fatal}",
    "    ud2",
    ".popsection",
    ".purgem trap_stub",
    //
    // Each stub's address, in vector order, for the IDT.
    ".pushsection .rodata.trap_stubs, \"a\", @progbits",
    ".balign 8",
    // Labels Rust names through `extern` must be global: the asm and its
    // user can land in different codegen units.
    ".global TRAP_STUBS",
    "TRAP_STUBS:",
    ".irp hi, 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f",
    ".irp lo, 0,1,2,3,4,5,6,7,8,9,a,b,c,d,e,f",
    "    .quad trap_vector_\\hi\\lo",
    ".endr",
    ".endr",
    ".popsection",
    //
    // The idle loop, then its `test=idle_irq` variant, which raises the
    // spurious vector itself. A ring-0 interrupt is taken only with RIP in
    // [idle_loop, idle_loop_end). Neither loop continues after an interrupt:
    // the handler discards the frame and enters a loop afresh.
    ".pushsection .text.idle, \"ax\", @progbits",
    ".global idle_loop, idle_loop_int, idle_loop_end",
    "idle_loop:",
    "    sti",
    "    hlt",
    "    jmp idle_loop",
    "idle_loop_int:",
    "    sti",
    "    int {spurious}",
    "    jmp idle_loop_int",
    "idle_loop_end:",
    ".popsection",
    error_code = const t::ERROR_CODE_VECTORS,
    fatal_vectors = const t::FATAL_VECTORS,
    cs_above_vector = const t::FRAME_CS - t::FRAME_VECTOR,
    frame_cs = const t::FRAME_CS,
    from_kernel = sym trap_from_kernel,
    from_user = sym trap_from_user,
    fatal = sym trap_fatal,
    spurious = const t::SPURIOUS,
);

// SAFETY: the `global_asm!` above defines each symbol: `TRAP_STUBS` as 256
// quadwords in read-only data, the others as code labels whose addresses are
// all that is used; none of the three is ever called.
unsafe extern "C" {
    safe static TRAP_STUBS: [u64; 256];
    fn idle_loop();
    fn idle_loop_int();
    fn idle_loop_end();
}

/// Each vector's stub address, for the IDT.
pub fn stubs() -> &'static [u64; 256] {
    &TRAP_STUBS
}

/// The code in which a ring-0 interrupt is taken: the idle loop and its test
/// variant.
fn idle_range() -> Range<u64> {
    idle_loop as *const () as u64..idle_loop_end as *const () as u64
}

/// The report of a fatal trap at `frame`.
fn report(frame: &TrapFrame, cr2: u64) -> Report<'_> {
    Report {
        frame,
        cr2,
        stack: gdt::stack_layout().stack_of(frame as *const TrapFrame as u64),
    }
}

/// A trap taken in ring 0, other than NMI, `#DF` and `#MC`. `frame` is at
/// the top of the interrupted stack, or of IST4 for `#DB`.
extern "C" fn trap_from_kernel(frame: *const TrapFrame) -> ! {
    // CR2 first: nothing here may fault before it is read.
    let cr2 = cpu::read_cr2();
    // SAFETY: `trap_common_entry` passes the frame it just pushed: aligned,
    // initialised, and not referred to by anything else. Nothing writes it
    // while this reference lives.
    let frame = unsafe { &*frame };
    // M5: a #DB whose RIP is exactly `syscall_entry` returns here.
    match t::kernel_trap(frame, &idle_range()) {
        KernelTrap::IdleInterrupt(vector) => {
            // SAFETY: the interrupt came from the idle loop, which holds
            // nothing on the kernel stack, and this handler holds only
            // `vector`, passed in a register; the frame is dead.
            unsafe { on_fresh_stack(interrupt_from_idle, vector.into()) }
        }
        KernelTrap::Fatal => panic!("fatal trap: {}", report(frame, cr2)),
    }
}

/// A trap with a ring-3 saved CS, after `swapgs`. Ring 3 does not exist
/// before M5, which copies the frame into the current thread and turns the
/// trap into a fault, so this is a kernel bug.
extern "C" fn trap_from_user(frame: *const TrapFrame) -> ! {
    let cr2 = cpu::read_cr2();
    // SAFETY: as in `trap_from_kernel`.
    let frame = unsafe { &*frame };
    panic!("trap from ring 3 before M5: {}", report(frame, cr2))
}

/// NMI, `#DF` and `#MC`, from either ring, on their own IST stacks. Fatal;
/// never reads GS or the interrupted RSP.
extern "C" fn trap_fatal(frame: *const TrapFrame) -> ! {
    let cr2 = cpu::read_cr2();
    // SAFETY: as in `trap_from_kernel`; `trap_fatal_entry` pushed the frame
    // on the vector's IST stack.
    let frame = unsafe { &*frame };
    panic!("fatal trap: {}", report(frame, cr2))
}

/// Calls `f(arg)` at the top of the kernel stack.
///
/// # Safety
///
/// Nothing on the kernel stack may be used again: the caller and every frame
/// below it on that stack are abandoned, without running destructors, and
/// nothing on it is pinned.
unsafe fn on_fresh_stack(f: extern "C" fn(u64) -> !, arg: u64) -> ! {
    // SAFETY: the caller abandons the kernel stack; `f` diverges, so control
    // never comes back to it. The top is 16-byte aligned, so `f` starts with
    // RSP 8 below a 16-byte boundary, as the ABI requires.
    unsafe {
        asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "call {f}",
            "ud2",
            top = in(reg) gdt::kernel_stack_top(),
            f = in(reg) f,
            in("rdi") arg,
            options(noreturn),
        )
    }
}

/// Idles: enables interrupts and halts, at the top of the kernel stack, until
/// an interrupt arrives. The interrupt discards the idle frame and runs
/// [`irq::handle`] with interrupts off, then idles again on a fresh stack.
/// Whatever is on the kernel stack when this is called is abandoned.
pub fn idle() -> ! {
    let entry = if IDLE_TEST_ROUNDS.load(Ordering::Relaxed) > 0 {
        idle_loop_int as *const () as u64
    } else {
        idle_loop as *const () as u64
    };
    // SAFETY: the loop enables interrupts and halts; it touches no memory and
    // never returns, and every interrupt leaves it through
    // `trap_from_kernel`. Kernel code runs on one stack with no pinned or
    // borrowed state across this call, which diverges, so abandoning the
    // stack is sound; the top is 16-byte aligned.
    unsafe {
        asm!(
            "mov rsp, {top}",
            "xor ebp, ebp",
            "jmp {entry}",
            top = in(reg) gdt::kernel_stack_top(),
            entry = in(reg) entry,
            options(noreturn),
        )
    }
}

/// The interrupt path for an interrupt taken in the idle loop, at the top of
/// the kernel stack with interrupts off.
extern "C" fn interrupt_from_idle(vector: u64) -> ! {
    let (rsp, rflags) = (rsp(), rflags());
    let vector = vector as u8;
    irq::handle(vector);
    idle_test_round(vector, rsp, rflags);
    // M5: `schedule()` picks a thread here and exits to it, or idles.
    idle()
}

fn rsp() -> u64 {
    let v;
    // SAFETY: reading RSP has no side effects.
    unsafe { asm!("mov {}, rsp", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

fn rflags() -> u64 {
    let v;
    // SAFETY: `pushfq; pop` reads RFLAGS through two stack slots it owns.
    unsafe { asm!("pushfq", "pop {}", out(reg) v, options(nomem, preserves_flags)) };
    v
}

// ---------------------------------------------------------------------------
// Test hooks (`tests/qemu/`)
// ---------------------------------------------------------------------------

/// How many times `test=idle_irq` runs the interrupt path.
const IDLE_TEST: u32 = 3;
/// Rounds of `test=idle_irq` left; while non-zero, [`idle`] enters the loop
/// that raises the spurious vector itself.
static IDLE_TEST_ROUNDS: AtomicU32 = AtomicU32::new(0);
/// RSP in the interrupt path in the first round.
static IDLE_TEST_RSP: AtomicU64 = AtomicU64::new(0);

/// `test=idle_irq`: idles in the loop that runs `int 0xff`, so that the
/// interrupt path runs without a timer, [`IDLE_TEST`] times, then passes if
/// each round got the spurious vector with interrupts off, at the same RSP.
pub fn idle_self_test() -> ! {
    IDLE_TEST_ROUNDS.store(IDLE_TEST, Ordering::Relaxed);
    idle()
}

fn idle_test_round(vector: u8, rsp: u64, rflags: u64) {
    const IF: u64 = 1 << 9;
    let left = IDLE_TEST_ROUNDS.load(Ordering::Relaxed);
    if left == 0 {
        return;
    }
    let round = IDLE_TEST - left + 1;
    assert_eq!(vector, t::SPURIOUS, "round {round}: wrong vector");
    assert_eq!(
        rflags & IF,
        0,
        "round {round}: interrupts on in the interrupt path"
    );
    let first = IDLE_TEST_RSP.load(Ordering::Relaxed);
    if first == 0 {
        IDLE_TEST_RSP.store(rsp, Ordering::Relaxed);
    } else {
        assert_eq!(rsp, first, "round {round}: the stack was not fresh");
    }
    kprintln!("idle: round {round}: interrupt {vector:#04x} with IF 0 at RSP {rsp:#x}");
    IDLE_TEST_ROUNDS.store(left - 1, Ordering::Relaxed);
    if left == 1 {
        kprintln!("idle: {IDLE_TEST} interrupts from the idle loop, each on a fresh stack");
        kprintln!("TEST PASS");
        exit(ExitCode::Success);
    }
}

/// An upper-half address no page table maps: PML4 slot 300, between the
/// direct map (256) and the kernel image (511).
const UNMAPPED: u64 = 0xFFFF_9600_0000_0000;

/// A trap a `test=` hook raises in ring 0. Each one panics with its report.
#[derive(Clone, Copy, Debug)]
pub enum Provoke {
    /// `#PF`: a read of [`UNMAPPED`].
    PageFault,
    /// `#DF`: `ud2` with RSP in [`UNMAPPED`]'s page, so neither the `#UD`
    /// nor the `#PF` that follows it can push a frame. IST1 is painted first
    /// and the panic prints how much of it the report used.
    DoubleFault,
    /// `#BP`: `int3`, with a distinct value in each general register.
    Breakpoint,
    /// `#GP`: a load of DS with selector `0x38`, past the GDT's limit, so
    /// the CPU pushes the selector as the error code.
    GeneralProtection,
    /// `int 2`: the NMI handler on IST2.
    Nmi,
    /// `int 18`: the `#MC` handler on IST3.
    MachineCheck,
    /// `#DB`: a single step in ring 0, TF set by `popfq`, on IST4. (QEMU
    /// 8.2's TCG raises `#UD` for `int1` in ring 0.)
    Debug,
    /// `int 21`: `#CP`, which cannot occur; its stub must not expect the
    /// error code the CPU would push for a real one.
    CannotOccur,
    /// `int 0x30` outside the idle loop.
    InterruptOutsideIdle,
}

/// Raises `p` in ring 0. In every arm the instruction traps and the handler
/// never returns (a trailing `ud2` would panic if it did); the asm touches
/// no memory Rust can see but the stack it abandons.
pub fn provoke(p: Provoke) -> ! {
    match p {
        // SAFETY: the load faults; nothing is read.
        Provoke::PageFault => unsafe {
            asm!("mov rax, qword ptr [{}]", "ud2", in(reg) UNMAPPED, options(noreturn, nostack));
        },
        Provoke::DoubleFault => {
            paint_ist(1);
            // SAFETY: the kernel stack is abandoned for RSP in an unmapped
            // page, which no push can reach; the #DF handler runs on IST1.
            unsafe {
                asm!("mov rsp, {}", "ud2", in(reg) UNMAPPED + 0x1000, options(noreturn));
            }
        }
        // SAFETY: the registers are clobbered only on the way to the trap.
        Provoke::Breakpoint => unsafe {
            asm!(
                "mov rax, 0xaaaa",
                "mov rbx, 0xbbbb",
                "mov rcx, 0xcccc",
                "mov rdx, 0xdddd",
                "mov rsi, 0x5151",
                "mov rdi, 0xd1d1",
                "mov rbp, 0xb9b9",
                "mov r8, 0x8888",
                "mov r9, 0x9999",
                "mov r10, 0x1010",
                "mov r11, 0x1111",
                "mov r12, 0x1212",
                "mov r13, 0x1313",
                "mov r14, 0x1414",
                "mov r15, 0x1515",
                "int3",
                "ud2",
                options(noreturn, nostack),
            );
        },
        // SAFETY: the selector load faults before DS changes.
        Provoke::GeneralProtection => unsafe {
            asm!(
                "mov eax, 0x38",
                "mov ds, ax",
                "ud2",
                options(noreturn, nostack)
            );
        },
        // SAFETY: a software interrupt through the NMI gate.
        Provoke::Nmi => unsafe { asm!("int 2", "ud2", options(noreturn, nostack)) },
        // SAFETY: a software interrupt through the #MC gate.
        Provoke::MachineCheck => unsafe { asm!("int 18", "ud2", options(noreturn, nostack)) },
        // SAFETY: TF set by `popfq` traps after the next instruction; the one
        // stack slot is pushed and popped here.
        Provoke::Debug => unsafe {
            asm!(
                "pushfq",
                "or qword ptr [rsp], {tf}",
                "popfq",
                "nop",
                "ud2",
                tf = const 1 << 8,
                options(noreturn),
            );
        },
        // SAFETY: a software interrupt through the #CP gate.
        Provoke::CannotOccur => unsafe { asm!("int 21", "ud2", options(noreturn, nostack)) },
        // SAFETY: a software interrupt through a device vector's gate.
        Provoke::InterruptOutsideIdle => unsafe {
            asm!("int 0x30", "ud2", options(noreturn, nostack));
        },
    }
}

/// What a painted stack holds where nothing has written.
const PAINT: u64 = 0x5A5A_5A5A_5A5A_5A5A;
/// The IST stack painted by [`Provoke::DoubleFault`], 1 to 4, or 0.
static PAINTED_IST: AtomicU8 = AtomicU8::new(0);

fn ist_words(n: u8) -> (*mut u64, usize) {
    let r = &gdt::stack_layout().ist[usize::from(n) - 1];
    (r.start as *mut u64, ((r.end - r.start) / 8) as usize)
}

fn paint_ist(n: u8) {
    let (start, len) = ist_words(n);
    // SAFETY: IST n is mapped, writable kernel memory that only its vector's
    // handler uses, and that handler is not running: this runs on the kernel
    // stack. No reference to it exists.
    unsafe { core::slice::from_raw_parts_mut(start, len) }.fill(PAINT);
    PAINTED_IST.store(n, Ordering::Relaxed);
}

/// Called by the panic handler after the message: if a test painted an IST
/// stack, moves to the kernel stack, prints how many bytes of the IST stack
/// the panic used, and ends the run. Otherwise does nothing.
pub fn print_stack_use() {
    if PAINTED_IST.load(Ordering::Relaxed) != 0 {
        // SAFETY: only the double_fault test paints a stack, and it
        // abandoned the kernel stack before faulting.
        unsafe { on_fresh_stack(measure_painted_stack, 0) }
    }
}

extern "C" fn measure_painted_stack(_: u64) -> ! {
    let n = PAINTED_IST.load(Ordering::Relaxed);
    let (start, len) = ist_words(n);
    // SAFETY: the panic that ran on IST n was abandoned when this function
    // moved to the kernel stack, so nothing runs on that stack or refers to
    // it; it is mapped kernel memory.
    let words = unsafe { core::slice::from_raw_parts(start, len) };
    kprintln!(
        "IST{n}: the fatal report used {} of {} bytes",
        t::high_water(words, PAINT),
        gdt::IST_STACK_SIZE
    );
    exit(ExitCode::Failure)
}
