//! The kernel's GDT and TSS, the per-CPU area, and step 3 of the M3 boot
//! sequence (`docs/design.md`, "Rings and segments", "Descriptor tables and
//! MSRs", "The per-CPU area and `swapgs`"), which also loads the IDT built
//! by [`super::idt`].
//!
//! The descriptor values come from `l4core::trap`, which tests them on the
//! host; this module places the tables, loads them and sets the registers
//! that go with them.

use core::arch::asm;
use core::mem::{offset_of, size_of};
use core::sync::atomic::{AtomicU64, Ordering};

use l4core::trap::{self, StackLayout, Tss};

use super::{StaticCell, cpu, idt};

/// `IA32_GS_BASE`: the GS base in ring 0, which points at [`PerCpu`].
const IA32_GS_BASE: u32 = 0xC000_0101;
/// CR4.MCE: a machine check raises `#MC` instead of shutting the core down.
const CR4_MCE: u64 = 1 << 6;
/// DR7's reset value: no breakpoint enabled, so the only ring-0 `#DB` is a
/// single step (`docs/design.md`, "NMI, double fault, machine check and
/// debug").
const DR7_RESET: u64 = 0x400;
/// The size of the kernel stack and of each IST stack, as `kernel/linker.ld`
/// reserves them.
const KERNEL_STACK_SIZE: u64 = 64 * 1024;
pub const IST_STACK_SIZE: u64 = 8 * 1024;
/// The guard page the linker script leaves below each stack.
const GUARD_SIZE: u64 = 4096;

// SAFETY: `kernel/linker.ld` defines each of these symbols. Only their
// addresses are used; nothing reads or writes them as `u8`s.
#[allow(non_upper_case_globals)]
unsafe extern "C" {
    safe static __kernel_stack_bottom: u8;
    safe static __kernel_stack_top: u8;
    safe static __ist1_top: u8;
    safe static __ist2_top: u8;
    safe static __ist3_top: u8;
    safe static __ist4_top: u8;
}

/// The top of the kernel stack: RSP0, and where the idle loop runs.
pub fn kernel_stack_top() -> u64 {
    &raw const __kernel_stack_top as u64
}

/// Where the kernel stack and the four IST stacks lie.
pub fn stack_layout() -> StackLayout {
    let ist = |top: *const u8| {
        let top = top as u64;
        top - IST_STACK_SIZE..top
    };
    StackLayout {
        kernel: &raw const __kernel_stack_bottom as u64..kernel_stack_top(),
        ist: [
            ist(&raw const __ist1_top),
            ist(&raw const __ist2_top),
            ist(&raw const __ist3_top),
            ist(&raw const __ist4_top),
        ],
    }
}

#[repr(C, align(16))]
struct Gdt([u64; trap::GDT_ENTRIES]);

/// The TSS, aligned beyond `Tss`'s own 4 bytes.
#[repr(C, align(16))]
struct TssCell(Tss);

// The CPU reads these tables; it writes only the TSS descriptor's busy bit in
// the GDT (`ltr`), into the cell's `UnsafeCell`, and no Rust code reads the
// GDT after loading it.
static GDT: StaticCell<Gdt> = StaticCell::new();
static TSS: StaticCell<TssCell> = StaticCell::new();

/// The per-CPU area (`docs/design.md`, "The per-CPU area and `swapgs`"):
/// `IA32_GS_BASE` points here in ring 0. Only the entry stubs reach it
/// through GS (M5); Rust uses the static. Each field is an atomic because
/// those stubs write it.
#[repr(C)]
pub struct PerCpu {
    /// Its own address, so a stub can turn GS into a pointer (offset 0).
    this: AtomicU64,
    /// The top of the kernel stack (offset 8).
    kernel_stack_top: AtomicU64,
    /// The user's RSP, saved by `syscall_entry` (M5) (offset 16).
    user_rsp: AtomicU64,
}

const _: () = {
    assert!(offset_of!(PerCpu, this) == 0);
    assert!(offset_of!(PerCpu, kernel_stack_top) == 8);
    assert!(offset_of!(PerCpu, user_rsp) == 16);
};

static PER_CPU: PerCpu = PerCpu {
    this: AtomicU64::new(0),
    kernel_stack_top: AtomicU64::new(0),
    user_rsp: AtomicU64::new(0),
};

/// The operand of `lgdt` and `lidt`.
#[repr(C, packed(2))]
pub(super) struct DescriptorPointer {
    pub limit: u16,
    pub base: u64,
}

/// Step 3 of the M3 boot sequence (`docs/design.md`, "Boot sequence"):
/// builds the GDT, the TSS and the IDT, then loads them in that order, so no
/// table is loaded before it is complete and no gate names an IST before the
/// TSS is in place; then sets CR4.MCE, points `IA32_GS_BASE` at the per-CPU
/// area and resets DR7. Runs once, with interrupts off. The firmware's GDT
/// and IDT are dead afterwards.
pub fn init() {
    let stacks = stack_layout();
    check_stacks(&stacks);
    let [ist1, ist2, ist3, ist4] = &stacks.ist;
    let tss = TSS.init(TssCell(Tss::new(
        stacks.kernel.end,
        [ist1.end, ist2.end, ist3.end, ist4.end],
    )));
    let gdt = GDT.init(Gdt(trap::gdt(tss as *const TssCell as u64)));
    let idt = idt::build();

    load_gdt(gdt);
    // SAFETY: the GDT just loaded has the TSS descriptor at this selector,
    // describing the complete, static TSS. `ltr` marks it busy in the GDT,
    // which nothing reads.
    unsafe {
        asm!("ltr {:x}", in(reg) trap::TSS_SELECTOR, options(nostack, preserves_flags));
    }
    idt::load(idt);

    // The kernel reads GS only in the entry stubs from M5; it holds nothing
    // the firmware set.
    let per_cpu = &raw const PER_CPU as u64;
    PER_CPU.this.store(per_cpu, Ordering::Relaxed);
    PER_CPU
        .kernel_stack_top
        .store(stacks.kernel.end, Ordering::Relaxed);
    PER_CPU.user_rsp.store(0, Ordering::Relaxed);
    // SAFETY: setting CR4.MCE changes no translation. A CPU without the
    // machine-check architecture would raise #GP here, which the IDT just
    // loaded reports. Writing IA32_GS_BASE changes only what GS-relative
    // accesses reach; no kernel code makes one before M5.
    unsafe {
        cpu::write_cr4(cpu::read_cr4() | CR4_MCE);
        cpu::write_msr(IA32_GS_BASE, per_cpu);
    }
    // SAFETY: writing DR7's reset value disables every hardware breakpoint;
    // it touches no memory.
    unsafe {
        asm!("mov dr7, {}", in(reg) DR7_RESET, options(nomem, nostack, preserves_flags));
    }
}

/// Panics unless the linker script laid the stacks out as this module and
/// the TSS assume: the kernel stack, then each IST stack above a guard page.
fn check_stacks(s: &StackLayout) {
    assert_eq!(s.kernel.end - s.kernel.start, KERNEL_STACK_SIZE);
    let mut below = s.kernel.end;
    for ist in &s.ist {
        assert_eq!(ist.start, below + GUARD_SIZE, "IST stack layout");
        below = ist.end;
    }
}

/// Loads the GDT, reloads CS with a far return and the data segment
/// registers: SS, DS and ES with kernel data, FS and GS with the null
/// selector. Any selector the firmware left would otherwise name a slot of
/// this GDT the next time the CPU reloads it, as `iretq` reloads SS.
fn load_gdt(gdt: &'static Gdt) {
    // The limit covers the entries only, not `Gdt`'s alignment padding,
    // whose bytes are undefined: a selector past the last entry must fault.
    let pointer = DescriptorPointer {
        limit: (size_of::<[u64; trap::GDT_ENTRIES]>() - 1) as u16,
        base: gdt as *const Gdt as u64,
    };
    // SAFETY: the GDT is complete and static, and its kernel code and data
    // descriptors are what the loader's flat 64-bit segments were, so the
    // reloads change no address. FS and GS bases are not used by the kernel;
    // `init` writes IA32_GS_BASE afterwards. The pushes stay within the
    // kernel stack, which has no red zone on this target.
    unsafe {
        asm!(
            "lgdt [{pointer}]",
            "push {cs}",
            "lea {tmp}, [rip + 2f]",
            "push {tmp}",
            "retfq",
            "2:",
            "mov {tmp:e}, {ds}",
            "mov ss, {tmp:x}",
            "mov ds, {tmp:x}",
            "mov es, {tmp:x}",
            "xor {tmp:e}, {tmp:e}",
            "mov fs, {tmp:x}",
            "mov gs, {tmp:x}",
            pointer = in(reg) &pointer,
            cs = const trap::KERNEL_CS,
            ds = const trap::KERNEL_DS,
            tmp = out(reg) _,
        );
    }
}
