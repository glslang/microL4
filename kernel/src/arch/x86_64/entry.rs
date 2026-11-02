//! Kernel entry and exit (`docs/design.md`, "Kernel entry and exit"; ADR
//! 0008): the boot entry point, and from M5 every way between ring 3 and
//! the kernel.
//!
//! - `_start`: the loader jumps here in 64-bit mode on its own page
//!   tables, with interrupts off and the physical address of the handoff
//!   in `rdi`. Those tables map this image at KERNEL_VIRT_BASE, physical
//!   memory at PHYS_MAP_BASE and low memory 1:1, until the kernel replaces
//!   them (M3). See docs/abi.md, "Boot handoff".
//! - [`init`], from step 3: the syscall MSRs. `IA32_STAR`, `IA32_LSTAR` =
//!   `syscall_entry`, `IA32_CSTAR` = `compat_entry`, `IA32_FMASK`, EFER.SCE,
//!   and the SYSENTER MSRs zeroed so `sysenter` cannot enter ring 0; and
//!   `IA32_TSC_AUX` zeroed, which `rdtscp` and `rdpid` read in ring 3.
//! - `syscall_entry` builds the 22-word trap frame at the top of the
//!   kernel stack with vector 256 and calls `syscall_from_user`; the IDT
//!   stubs in [`super::trap`] build the same frame for exceptions and
//!   interrupts and call `trap_from_user`. Both end in [`from_user`],
//!   which hands the frame to one function per kind of entry:
//!   [`user_syscall`], [`user_exception`] and [`user_interrupt`]. Each
//!   saves the frame into the current thread's registers, hands the work
//!   to `crate::dispatch` or `irq::handle`, and ends through the
//!   scheduler (`thread::exit_to_scheduled`).
//! - [`exit_to_user`] leaves for a thread from its saved [`Regs`]: the
//!   frame comes from `l4core::entry::exit_frame`, and `exit_sysret` or
//!   `exit_iret` pops it, runs `swapgs`, and returns.
//! - [`load_user_bases`] and [`save_user_bases`] move a thread's FS and GS
//!   bases between its [`Regs`] and `IA32_FS_BASE` and
//!   `IA32_KERNEL_GS_BASE` at a thread switch (ADR 0015).
//! - [`return_to_kernel`] ends the ring-0 traps that return: the
//!   single-step `#DB` a `syscall` with TF set may raise at
//!   `syscall_entry`, and the one `mov ss` with TF set defers onto the
//!   first instruction of the `#BP` stub.
//!
//! GS points at the per-CPU area whenever ring-0 code outside the IST
//! handlers runs: `swapgs` runs exactly once on each entry from ring 3
//! (here, or in `trap_common_entry` keyed on the saved CS) and once on each
//! exit to it.

use core::arch::{asm, global_asm};
use core::mem::offset_of;
use core::sync::atomic::{AtomicBool, Ordering};

use l4core::entry::{FMASK, STAR, SYSCALL_VECTOR, UserEntry, exit_frame, lower_half};
use l4core::regs::{Exit, Regs};
use l4core::sched::Scheduling;
use l4core::tcb::{TcbRef, Tcbs};
use l4core::trap::{TrapFrame, USER_CS, USER_DS};

use super::{Objects, cpu, gdt, irq, serial, thread, trap};

#[cfg(feature = "selftest")]
pub use self::selftest::{last_exit, ring0_single_steps, set_user_entry_hook};

global_asm!(
    // The kernel stack is the linker script's `.stacks` section, above an
    // unmapped guard page once the kernel's own page tables are in place.
    ".section .text._start, \"ax\", @progbits",
    ".global _start",
    "_start:",
    "    cli",
    "    cld",
    // Keep the handoff pointer out of the way of `rep stosb`.
    "    mov r12, rdi",
    // Zero BSS. The loader has already done so, but the kernel does not rely
    // on it. Nothing here uses a stack: RSP is still the loader's.
    "    lea rdi, [rip + __bss_start]",
    "    lea rcx, [rip + __bss_end]",
    "    sub rcx, rdi",
    "    xor eax, eax",
    "    rep stosb",
    "    lea rsp, [rip + __kernel_stack_top]",
    "    xor ebp, ebp",
    "    mov rdi, r12",
    "    call {entry}",
    "2:  cli",
    "    hlt",
    "    jmp 2b",
    entry = sym rust_entry,
);

/// First Rust code to run, on the kernel stack with BSS zeroed.
extern "C" fn rust_entry(handoff_phys: u64) -> ! {
    serial::init();
    crate::kmain(handoff_phys)
}

// ---------------------------------------------------------------------------
// The syscall MSRs
// ---------------------------------------------------------------------------

const IA32_SYSENTER_CS: u32 = 0x174;
const IA32_SYSENTER_ESP: u32 = 0x175;
const IA32_SYSENTER_EIP: u32 = 0x176;
const IA32_STAR: u32 = 0xC000_0081;
const IA32_LSTAR: u32 = 0xC000_0082;
const IA32_CSTAR: u32 = 0xC000_0083;
const IA32_FMASK: u32 = 0xC000_0084;
const IA32_FS_BASE: u32 = 0xC000_0100;
/// The user's GS base while the kernel runs: `swapgs` exchanges it with
/// `IA32_GS_BASE` on every entry and exit.
const IA32_KERNEL_GS_BASE: u32 = 0xC000_0102;
/// What `rdtscp` returns in ECX and `rdpid` in its register.
const IA32_TSC_AUX: u32 = 0xC000_0103;
/// EFER.SCE: `syscall` and `sysret` enabled.
const EFER_SCE: u64 = 1 << 0;

/// Writes the syscall MSRs (`docs/design.md`, "Descriptor tables and
/// MSRs"), and `IA32_TSC_AUX` = 0 if the CPU has it. Called once from step
/// 3, after the GDT is loaded; nothing can execute `syscall` before ring 3
/// exists, so the entry is ready long before it can be used.
pub fn init() {
    let entry = syscall_entry as *const () as u64;
    // SAFETY: every MSR here exists on every x86_64 CPU (the SYSENTER ones
    // on AMD too). STAR names the GDT's kernel code and data and, for
    // `sysretq`, its user data and code (host-tested); LSTAR and CSTAR are
    // the stubs below, canonical kernel addresses; FMASK clears IF, TF, DF,
    // AC and NT on entry. SYSENTER_CS 0 makes `sysenter` fault in ring 3.
    // Setting EFER.SCE only enables `syscall` and `sysretq`, which nothing
    // in ring 0 executes but the exit path; NXE and LME are kept.
    unsafe {
        cpu::write_msr(IA32_STAR, STAR);
        cpu::write_msr(IA32_LSTAR, entry);
        cpu::write_msr(IA32_CSTAR, compat_entry as *const () as u64);
        cpu::write_msr(IA32_FMASK, FMASK);
        cpu::write_msr(IA32_SYSENTER_CS, 0);
        cpu::write_msr(IA32_SYSENTER_ESP, 0);
        cpu::write_msr(IA32_SYSENTER_EIP, 0);
        cpu::write_msr(cpu::IA32_EFER, cpu::read_msr(cpu::IA32_EFER) | EFER_SCE);
    }
    kprintln!(
        "entry: syscall_entry at {entry:#x}, IA32_STAR {STAR:#x}, IA32_FMASK {FMASK:#x}, EFER.SCE on, IA32_SYSENTER_CS 0"
    );
    // `rdtscp` and `rdpid` return IA32_TSC_AUX in ring 3 (ADR 0025), so
    // the firmware's value must not stay in it.
    if cpu::cpuid_features().has_tsc_aux() {
        // SAFETY: CPUID reports `rdtscp` or `rdpid`, so the MSR exists, and
        // any 32-bit value is valid; only those two instructions read it.
        unsafe { cpu::write_msr(IA32_TSC_AUX, 0) };
        kprintln!(
            "entry: IA32_TSC_AUX {:#x}, which rdtscp and rdpid read in ring 3",
            cpu::read_msr(IA32_TSC_AUX)
        );
    } else {
        kprintln!("entry: no rdtscp or rdpid, so no IA32_TSC_AUX");
    }
}

/// `syscall_entry`'s address, as `IA32_LSTAR` holds it.
pub fn syscall_entry_addr() -> u64 {
    syscall_entry as *const () as u64
}

// ---------------------------------------------------------------------------
// The stubs
// ---------------------------------------------------------------------------

/// Byte offsets above the frame's `vector` word, where RSP points once the
/// exit stubs have popped the general registers.
const RIP_ABOVE_VECTOR: usize = offset_of!(TrapFrame, rip) - offset_of!(TrapFrame, vector);
const RFLAGS_ABOVE_VECTOR: usize = offset_of!(TrapFrame, rflags) - offset_of!(TrapFrame, vector);
const RSP_ABOVE_VECTOR: usize = offset_of!(TrapFrame, rsp) - offset_of!(TrapFrame, vector);

global_asm!(
    // Pops the 15 general registers of a trap frame at RSP, `r15` first.
    ".macro pop_general_registers",
    "    pop r15",
    "    pop r14",
    "    pop r13",
    "    pop r12",
    "    pop r11",
    "    pop r10",
    "    pop r9",
    "    pop r8",
    "    pop rbp",
    "    pop rdi",
    "    pop rsi",
    "    pop rdx",
    "    pop rcx",
    "    pop rbx",
    "    pop rax",
    ".endm",
    //
    ".pushsection .text.entry, \"ax\", @progbits",
    // Labels Rust names through `extern` must be global: the asm and its
    // user can land in different codegen units.
    ".global syscall_entry, compat_entry, exit_sysret, exit_iret, kernel_trap_return",
    //
    // `syscall`: RIP in RCX, RFLAGS in R11, IF DF AC TF NT cleared by
    // IA32_FMASK, CS 0x08 and SS 0x10; RSP and GS are still the user's.
    // Nothing here can fault, and interrupts are off, so only an NMI, #MC
    // or #DB can arrive before `swapgs`, and their handlers read no GS.
    ".balign 16",
    "syscall_entry:",
    "    swapgs",
    "    mov qword ptr gs:[{user_rsp}], rsp",
    "    mov rsp, qword ptr gs:[{stack_top}]",
    "    push {user_ds}",
    "    push qword ptr gs:[{user_rsp}]",
    "    push r11",
    "    push {user_cs}",
    "    push rcx",
    "    push 0",
    "    push {syscall_vector}",
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
    // 22 words from the 16-byte-aligned stack top: RSP is aligned for the
    // call.
    "    mov rdi, rsp",
    "    call {syscall_from_user}",
    "    ud2",
    //
    // `syscall` from compatibility mode, which has no code segment here:
    // off the user's stack at once, then panic.
    ".balign 16",
    "compat_entry:",
    "    swapgs",
    "    mov rsp, qword ptr gs:[{stack_top}]",
    "    call {compat_from_user}",
    "    ud2",
    //
    // RDI: a frame from `exit_frame` whose path is `Sysret`, in memory the
    // kernel no longer needs. RCX and R11 come from its RIP and RFLAGS, as
    // `sysretq` loads them; RIP is below 2^47, so `sysretq` cannot raise
    // #GP in ring 0 with the user's RSP loaded. From the RSP load on, only
    // an NMI, #MC or #DB can arrive, on their own stacks.
    ".balign 16",
    "exit_sysret:",
    "    mov rsp, rdi",
    "    pop_general_registers",
    "    mov rcx, qword ptr [rsp + {rip_slot}]",
    "    mov r11, qword ptr [rsp + {rflags_slot}]",
    "    mov rsp, qword ptr [rsp + {rsp_slot}]",
    "    swapgs",
    "    sysretq",
    //
    // RDI: a frame from `exit_frame`. User CS and SS, canonical RIP and
    // RSP and masked RFLAGS, so `iretq` cannot fault.
    ".balign 16",
    "exit_iret:",
    "    mov rsp, rdi",
    "    pop_general_registers",
    "    add rsp, 16",
    "    swapgs",
    "    iretq",
    //
    // RDI: the frame of a ring-0 trap to resume as it was, on its own
    // stack; no `swapgs`, as the entry ran none.
    ".balign 16",
    "kernel_trap_return:",
    "    mov rsp, rdi",
    "    pop_general_registers",
    "    add rsp, 16",
    "    iretq",
    ".popsection",
    ".purgem pop_general_registers",
    user_rsp = const gdt::PER_CPU_USER_RSP,
    stack_top = const gdt::PER_CPU_KERNEL_STACK_TOP,
    user_ds = const USER_DS,
    user_cs = const USER_CS,
    syscall_vector = const SYSCALL_VECTOR,
    syscall_from_user = sym syscall_from_user,
    compat_from_user = sym compat_from_user,
    rip_slot = const RIP_ABOVE_VECTOR,
    rflags_slot = const RFLAGS_ABOVE_VECTOR,
    rsp_slot = const RSP_ABOVE_VECTOR,
);

// SAFETY: the `global_asm!` above defines each as a code label. Rust uses
// `syscall_entry` and `compat_entry` only for their addresses; the other
// three are entered only by `jmp` from this module, with RDI as each
// expects.
unsafe extern "C" {
    fn syscall_entry();
    fn compat_entry();
    fn exit_sysret();
    fn exit_iret();
    fn kernel_trap_return();
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// `syscall_entry`'s Rust half, on the kernel stack with interrupts off and
/// GS on the per-CPU area.
extern "C" fn syscall_from_user(frame: *const TrapFrame) -> ! {
    // SAFETY: `syscall_entry` passes the frame it just pushed at the top of
    // the kernel stack: aligned, initialised, and referred to by nothing
    // else. Nothing writes it while this reference lives.
    let frame = unsafe { &*frame };
    from_user(frame, l4core::entry::classify(frame, 0))
}

extern "C" fn compat_from_user() -> ! {
    panic!("syscall from compatibility mode, which no code segment allows")
}

/// Every entry from ring 3 ends here, on the kernel stack with interrupts
/// off and GS on the per-CPU area, with CR2 already read: `frame` is the
/// trap frame the stub built, at the top of the kernel stack (or, for
/// `#DB`, on IST4, which nothing else uses meanwhile), and `entry` what
/// `l4core::entry::classify` made of it.
pub(super) fn from_user(frame: &TrapFrame, entry: UserEntry) -> ! {
    #[cfg(feature = "selftest")]
    if let Some(hook) = selftest::USER_ENTRY_HOOK.get() {
        hook(frame, entry)
    }
    match entry {
        UserEntry::Syscall => user_syscall(frame),
        UserEntry::Exception { vector, error, cr2 } => user_exception(frame, vector, error, cr2),
        UserEntry::Interrupt(vector) => user_interrupt(frame, vector),
        UserEntry::Fatal => panic!("fatal trap from ring 3: {}", trap::report(frame, 0)),
    }
}

// The seams: one function per kind of entry. Each saves the frame into
// the current thread's registers, does its work, and ends the entry
// through the scheduler (`thread::exit_to_scheduled`), which exits to a
// thread or idles; nothing stays on the kernel stack between entries. The
// system-call and fault work is `crate::dispatch`'s.

/// Copies `frame` into the current thread's registers
/// (`l4core::entry::save`) and returns the thread. A ring-3 entry always
/// has one: only a thread runs in ring 3.
fn save_current(k: &mut Objects, frame: &TrapFrame) -> TcbRef {
    let Some(t) = k.scheduler().current() else {
        panic!(
            "an entry from ring 3 at {:#x}, but no thread is current",
            frame.rip
        )
    };
    let mut regs = k.regs(t);
    l4core::entry::save(frame, &mut regs);
    k.set_regs(t, &regs);
    t
}

/// A `syscall` from the current thread: saved with `fault_ip` on the
/// `syscall`, `next_ip` after it and `exit` = `Sysret`, then dispatched
/// (`crate::dispatch::syscall`).
fn user_syscall(frame: &TrapFrame) -> ! {
    {
        let mut k = Objects::begin();
        let t = save_current(&mut k, frame);
        crate::dispatch::syscall(&mut k, t);
    }
    thread::exit_to_scheduled()
}

/// An exception the current thread caused: `vector` below 32, its error
/// code (0 if the CPU pushes none) and, for `#PF`, CR2. Saved with
/// `next_ip` = `fault_ip` = the RIP the CPU pushed and `exit` = `Iret`,
/// then made a fault (`crate::dispatch::exception`).
fn user_exception(frame: &TrapFrame, vector: u8, error: u64, cr2: u64) -> ! {
    {
        let mut k = Objects::begin();
        let t = save_current(&mut k, frame);
        crate::dispatch::exception(&mut k, t, vector, error, cr2);
    }
    thread::exit_to_scheduled()
}

/// An interrupt taken while the current thread ran: saved with `exit` =
/// `Iret`, then handled by `irq::handle`, whose timer tick charges the
/// thread's slice.
fn user_interrupt(frame: &TrapFrame, vector: u8) -> ! {
    {
        let mut k = Objects::begin();
        save_current(&mut k, frame);
    }
    irq::handle(vector);
    thread::exit_to_scheduled()
}

// ---------------------------------------------------------------------------
// Exit
// ---------------------------------------------------------------------------

/// Whether [`exit_to_user`] has warned of a RIP, or of an RSP, at or above
/// 2^47.
static WARNED_RIP: AtomicBool = AtomicBool::new(false);
static WARNED_RSP: AtomicBool = AtomicBool::new(false);

/// Leaves the kernel for the thread whose registers are `regs`: by
/// `sysretq` if it entered by `syscall` and nothing wrote its registers
/// since, else by `iretq` (`l4core::entry::exit_frame`). The caller has
/// put the thread's address space in CR3, its x87 and SSE state in the
/// registers (`fpu::switch_to`) and its FS and GS bases in their MSRs
/// ([`load_user_bases`]), and holds nothing on the kernel stack: the stack
/// is abandoned, and the next entry starts at its top.
///
/// The first exit to any thread, the root task's included, uses this too:
/// a new TCB's `exit` reads as `Iret`.
pub fn exit_to_user(regs: &Regs) -> ! {
    let (frame, path) = exit_frame(regs);
    // Without a kernel bug these fire only for an RSP the thread set
    // itself, or a return address past the lower half (`docs/design.md`,
    // Exit). A thread can do either on every system call, so each warning
    // is printed once per boot, not once per exit.
    if frame.rip != regs.next_ip && !WARNED_RIP.swap(true, Ordering::Relaxed) {
        kprintln!(
            "entry: warning: RIP {:#x} at or above 2^47 exits as 0 (printed once per boot)",
            regs.next_ip
        );
    }
    if frame.rsp != regs.rsp && !WARNED_RSP.swap(true, Ordering::Relaxed) {
        kprintln!(
            "entry: warning: RSP {:#x} at or above 2^47 exits as 0 (printed once per boot)",
            regs.rsp
        );
    }
    #[cfg(feature = "selftest")]
    selftest::record_exit(path);
    let stub = match path {
        Exit::Sysret => exit_sysret as *const () as u64,
        Exit::Iret => exit_iret as *const () as u64,
    };
    // SAFETY: `frame` is a complete frame from `exit_frame`, in this
    // function's own stack frame, which the stub makes the stack: it pops
    // the frame and leaves ring 0, so nothing on the kernel stack is used
    // again, and the caller holds nothing there. Each ring-0 path between
    // an entry's `swapgs` and here keeps GS on the per-CPU area (at boot,
    // `gdt::init` put it there), so the stub's `swapgs` gives the thread
    // its own GS base and leaves the per-CPU area in IA32_KERNEL_GS_BASE
    // for the next entry. The frame's RIP and RSP are below 2^47, its CS
    // and SS the user selectors, its RFLAGS masked, and `Sysret` only
    // with a RIP below 2^47, so neither `sysretq` nor `iretq` can fault in
    // ring 0.
    unsafe {
        asm!(
            "jmp {stub}",
            stub = in(reg) stub,
            in("rdi") &raw const frame,
            options(noreturn),
        )
    }
}

/// Writes the thread's FS and GS bases into `IA32_FS_BASE` and
/// `IA32_KERNEL_GS_BASE`, at a switch to it (ADR 0015). The exit's
/// `swapgs` then makes the second the GS base. A base at or above 2^47
/// becomes 0, the sanitiser's rule, so the WRMSRs cannot fault.
pub fn load_user_bases(regs: &Regs) {
    // SAFETY: both MSRs exist on every x86_64 CPU and take any canonical
    // address; a lower-half one is. The kernel never uses FS, and
    // IA32_KERNEL_GS_BASE becomes the GS base only after the exit's
    // `swapgs`, in ring 3.
    unsafe {
        cpu::write_msr(IA32_FS_BASE, lower_half(regs.fs_base));
        cpu::write_msr(IA32_KERNEL_GS_BASE, lower_half(regs.gs_base));
    }
}

/// Writes `IA32_FS_BASE` now, for `TCB_SetTLSBase` on the current thread,
/// before the switch-away path saves the MSR over the new value. `value`
/// is sanitised already; a value at or above 2^47 becomes 0 regardless.
pub fn set_fs_base(value: u64) {
    // SAFETY: as in `load_user_bases`: a lower-half address is canonical,
    // and the kernel never uses FS.
    unsafe { cpu::write_msr(IA32_FS_BASE, lower_half(value)) };
}

/// Reads the current thread's FS and GS bases back from `IA32_FS_BASE` and
/// `IA32_KERNEL_GS_BASE` into `regs`, at a switch away from it: a segment
/// load in ring 3 may have changed them since they were written (ADR
/// 0015).
pub fn save_user_bases(regs: &mut Regs) {
    regs.fs_base = cpu::read_msr(IA32_FS_BASE);
    regs.gs_base = cpu::read_msr(IA32_KERNEL_GS_BASE);
}

/// Resumes a ring-0 trap whose frame is `frame`, by `iretq` on the stack
/// the frame is on, with no `swapgs`: for the single-step `#DB` at the
/// first instruction of `syscall_entry` (`l4core::entry::
/// single_step_into_syscall_entry`), whose frame is on IST4 and which
/// returns to `syscall_entry` before its `swapgs`, with the user's RSP;
/// and for the one at the first instruction of the `#BP` stub
/// (`single_step_into_breakpoint_stub`), which returns to the stub with
/// RSP on the `#BP` frame at the top of the kernel stack.
///
/// # Safety
///
/// `frame` must be the frame `trap_common_entry` pushed for that trap, and
/// nothing the handler did since may need undoing: the handler's own
/// frames below it are abandoned.
pub unsafe fn return_to_kernel(frame: &TrapFrame) -> ! {
    #[cfg(feature = "selftest")]
    selftest::count_single_step();
    // SAFETY: the caller vouches for the frame; the stub pops it and
    // returns to the trapped instruction in ring 0 with its RFLAGS, in
    // which IA32_FMASK, or the `#BP` gate, cleared TF and IF.
    unsafe {
        asm!(
            "jmp {stub}",
            stub = in(reg) kernel_trap_return as *const () as u64,
            in("rdi") frame as *const TrapFrame,
            options(noreturn),
        )
    }
}

/// The test hooks (`tests/qemu/ring3.scenario`), with `selftest` only.
#[cfg(feature = "selftest")]
mod selftest {
    use core::sync::atomic::{AtomicU8, AtomicU64, Ordering};

    use l4core::entry::UserEntry;
    use l4core::regs::Exit;
    use l4core::trap::TrapFrame;

    use super::super::StaticCell;

    /// Called with every entry from ring 3 instead of the seams, if a
    /// self-test installed it.
    pub static USER_ENTRY_HOOK: StaticCell<fn(&TrapFrame, UserEntry) -> !> = StaticCell::new();

    /// Installs `hook`, which takes every entry from ring 3 from now on.
    /// Once per boot.
    pub fn set_user_entry_hook(hook: fn(&TrapFrame, UserEntry) -> !) {
        USER_ENTRY_HOOK.init(hook);
    }

    /// The last exit's path: 0 for none yet, else 1 + `Exit as u8`.
    static LAST_EXIT: AtomicU8 = AtomicU8::new(0);
    /// Ring-0 single-step `#DB`s returned from.
    static SINGLE_STEPS: AtomicU64 = AtomicU64::new(0);

    pub fn record_exit(path: Exit) {
        LAST_EXIT.store(1 + path as u8, Ordering::Relaxed);
    }

    /// The path the last [`super::exit_to_user`] took.
    pub fn last_exit() -> Option<Exit> {
        match LAST_EXIT.load(Ordering::Relaxed) {
            0 => None,
            n if n - 1 == Exit::Sysret as u8 => Some(Exit::Sysret),
            _ => Some(Exit::Iret),
        }
    }

    pub fn count_single_step() {
        SINGLE_STEPS.fetch_add(1, Ordering::Relaxed);
    }

    /// How many ring-0 single-step `#DB`s, at `syscall_entry` or the `#BP`
    /// stub, have been returned from.
    pub fn ring0_single_steps() -> u64 {
        SINGLE_STEPS.load(Ordering::Relaxed)
    }
}
