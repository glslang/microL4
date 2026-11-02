//! x87 and SSE state (`docs/design.md`, "FP and SIMD"; ADR 0014): the
//! control registers and XCR0 at boot, and the eager switch of a user
//! thread's state through its TCB's XSAVE area.
//!
//! - [`init`], from step 3: CR0.EM, TS and AM clear, MP and NE set;
//!   CR4.OSFXSR, OSXMMEXCPT and OSXSAVE set, FSGSBASE and PKE clear; XCR0 =
//!   `0x3` once CPUID leaf `0xD` says the CPU has x87 and SSE, and its area
//!   size checked against the TCB's 1024-byte reserve. Prints XCR0 and the
//!   size for the boot summary.
//! - [`switch_to`], before every exit to a user thread: if another thread's
//!   state is in the registers, XSAVE64 it into that thread's area and
//!   XRSTOR64 this one's. The idle thread and the kernel never own the
//!   registers, so A, idle, A costs nothing.
//! - [`init_area`] writes `l4core::fpu::initial_state` into a new TCB, and
//!   [`forget`] drops ownership when a TCB is finalised, without saving.
//!
//! The kernel itself never executes an x87 or SSE instruction: only
//! XSAVE64, XRSTOR64, XSETBV and XGETBV, here.

// Until the scheduler switches threads, only `test=ring3` switches state.
#![cfg_attr(
    not(feature = "selftest"),
    expect(dead_code, reason = "the scheduler switches FP state through it")
)]

use core::arch::asm;
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};

use l4core::fpu::{self, AREA_SIZE, XCR0};
use l4core::tcb::{self, TcbRef};

use super::{cpu, phys_to_virt};

const CR0_MP: u64 = 1 << 1;
const CR0_EM: u64 = 1 << 2;
const CR0_TS: u64 = 1 << 3;
const CR0_NE: u64 = 1 << 5;
const CR0_AM: u64 = 1 << 18;
const CR4_OSFXSR: u64 = 1 << 9;
const CR4_OSXMMEXCPT: u64 = 1 << 10;
const CR4_FSGSBASE: u64 = 1 << 16;
const CR4_OSXSAVE: u64 = 1 << 18;
const CR4_PKE: u64 = 1 << 22;

/// The TCB whose x87 and SSE state the registers hold, by physical
/// address, or 0 for none: at boot, and after [`forget`].
static OWNER: AtomicU64 = AtomicU64::new(0);

/// Sets up the x87 and SSE control state, with interrupts off, before
/// anything runs in ring 3. Panics, with the reason, on a CPU whose XSAVE
/// cannot hold x87 and SSE in the TCB's reserve. `check_cpu` has already
/// refused a CPU without XSAVE.
pub fn init() {
    let (eax, _, _, edx) = cpu::cpuid_count(0xD, 0);
    let supported = u64::from(edx) << 32 | u64::from(eax);
    if let Err(e) = fpu::check_supported(supported) {
        panic!("{e}");
    }
    let cr0 = (cpu::read_cr0() & !(CR0_EM | CR0_TS | CR0_AM)) | CR0_MP | CR0_NE;
    // SAFETY: EM, TS, MP and NE only change how x87 and SSE instructions
    // and their errors behave, and the kernel executes none; AM only
    // matters with AC set in ring 3. No translation changes.
    unsafe { write_cr0(cr0) };
    let cr4 =
        (cpu::read_cr4() | CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE) & !(CR4_FSGSBASE | CR4_PKE);
    // SAFETY: every long-mode CPU has FXSR and SSE, and `check_cpu` found
    // XSAVE, so the three bits are allowed; FSGSBASE and PKE may always be
    // cleared, and nothing in the kernel uses them. No translation changes.
    unsafe { cpu::write_cr4(cr4) };
    // SAFETY: CR4.OSXSAVE is set; XCR0 = 3 has x87, which XSETBV requires,
    // and only components CPUID reports, checked above. The kernel's own
    // code uses no extended state.
    unsafe { xsetbv(XCR0) };
    // EBX is the area size for the components XCR0 now enables.
    let (_, size, _, _) = cpu::cpuid_count(0xD, 0);
    if let Err(e) = fpu::check_size(size) {
        panic!("{e}");
    }
    check_control_state();
    kprintln!(
        "fpu: XCR0 {:#x} of {supported:#x} supported, XSAVE area {size} bytes of the TCB's {}",
        xgetbv(),
        tcb::XSAVE_SIZE
    );
}

/// Panics unless CR0, CR4 and XCR0 read back as [`init`] set them
/// (`docs/design.md`, "FP and SIMD", Invariants).
pub fn check_control_state() {
    let (cr0, cr4, xcr0) = (cpu::read_cr0(), cpu::read_cr4(), xgetbv());
    assert!(
        cr0 & (CR0_EM | CR0_TS | CR0_AM) == 0 && cr0 & (CR0_MP | CR0_NE) == CR0_MP | CR0_NE,
        "CR0 {cr0:#x}: EM, TS and AM must be clear, MP and NE set"
    );
    let on = CR4_OSFXSR | CR4_OSXMMEXCPT | CR4_OSXSAVE;
    assert!(
        cr4 & on == on && cr4 & (CR4_FSGSBASE | CR4_PKE) == 0,
        "CR4 {cr4:#x}: OSFXSR, OSXMMEXCPT and OSXSAVE must be set, FSGSBASE and PKE clear"
    );
    assert_eq!(xcr0, XCR0, "XCR0");
}

/// The TCB whose state the registers hold, if any.
pub fn owner() -> Option<TcbRef> {
    TcbRef::new(OWNER.load(Ordering::Relaxed))
}

/// Makes the registers hold `t`'s x87 and SSE state, before an exit to
/// `t`: if another TCB owns them, XSAVE64s its state into its area first.
/// Nothing when `t` already owns them.
///
/// `t` must be a live TCB (a `TcbRef` comes only from a TCB capability or
/// a link the kernel keeps), whose area [`init_area`] wrote when it was
/// made; finalising a TCB must call [`forget`].
pub fn switch_to(t: TcbRef) {
    let owner = OWNER.load(Ordering::Relaxed);
    if owner == t.get() {
        return;
    }
    if let Some(o) = TcbRef::new(owner) {
        // SAFETY: the owner is a live TCB: it was `t` of an earlier call,
        // and finalisation calls `forget`, so it was not destroyed since.
        // Its area is the 1024 bytes at XSAVE_OFFSET of the 2 KiB object,
        // 64-byte aligned because the object is 2 KiB aligned, in RAM below
        // the direct map's end and mapped write-back there; XSAVE64 with
        // XCR0 writes 576 of them. TCB memory is reached only by value
        // through raw pointers, so no Rust reference to it exists.
        unsafe { xsave64(area(o)) };
    }
    // SAFETY: as above for `t`, which the caller vouches is live. Its area
    // was written only by `init_area`, from a template whose header and
    // MXCSR XRSTOR64 accepts (host-tested), or by XSAVE64, so XRSTOR64
    // cannot fault; it reads 576 bytes.
    unsafe { xrstor64(area(t)) };
    OWNER.store(t.get(), Ordering::Relaxed);
}

/// Drops ownership if `t` owns the registers, without saving: `t` is being
/// finalised, and the next XRSTOR64 loads every enabled component, so
/// nothing of its state survives into another thread.
pub fn forget(t: TcbRef) {
    let _ = OWNER.compare_exchange(t.get(), 0, Ordering::Relaxed, Ordering::Relaxed);
}

/// Writes the initial x87 and SSE state into the new TCB `t`'s area (a
/// TCB's `init_object`). `t` must be a TCB just made from untyped memory,
/// which therefore owns nothing.
pub fn init_area(t: TcbRef) {
    debug_assert_ne!(
        OWNER.load(Ordering::Relaxed),
        t.get(),
        "a new TCB owns the FPU"
    );
    // SAFETY: as in `switch_to`: the area lies in the TCB object, in RAM
    // mapped write-back in the direct map, and nothing refers to it; the
    // write covers 576 of its 1024 bytes and any bytes are valid there.
    unsafe { ptr::write(area(t).cast::<[u8; AREA_SIZE]>(), fpu::initial_state()) };
}

/// A copy of the first [`AREA_SIZE`] bytes of `t`'s area, for the
/// self-tests. `t` must be a live TCB.
#[cfg(feature = "selftest")]
pub fn read_area(t: TcbRef) -> [u8; AREA_SIZE] {
    // SAFETY: as in `init_area`; a read by value of plain bytes.
    unsafe { ptr::read(area(t).cast::<[u8; AREA_SIZE]>()) }
}

/// The virtual address of `t`'s XSAVE area in the direct map.
fn area(t: TcbRef) -> *mut u8 {
    phys_to_virt(t.get() + tcb::XSAVE_OFFSET) as *mut u8
}

/// Writes CR0.
///
/// # Safety
///
/// The new value must keep paging and protection as the kernel relies on
/// them (PG, PE, WP), and may change only bits whose effect the caller has
/// accounted for.
unsafe fn write_cr0(v: u64) {
    // SAFETY: the caller vouches for the value. CR0 can change how memory
    // is accessed, so this is not `nomem`.
    unsafe { asm!("mov cr0, {}", in(reg) v, options(nostack, preserves_flags)) };
}

/// Writes XCR0.
///
/// # Safety
///
/// CR4.OSXSAVE must be set, and `v` must be a value the CPU accepts:
/// x87 set, and only components CPUID.(EAX=0xD, ECX=0) reports.
unsafe fn xsetbv(v: u64) {
    // SAFETY: the caller vouches for CR4 and the value; XSETBV touches no
    // memory.
    unsafe {
        asm!("xsetbv", in("ecx") 0, in("eax") v as u32, in("edx") (v >> 32) as u32,
            options(nomem, nostack, preserves_flags));
    }
}

/// Reads XCR0. CR4.OSXSAVE must be set, as [`init`] leaves it.
fn xgetbv() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: XGETBV reads XCR0 and touches no memory; `init` set
    // CR4.OSXSAVE before anything calls this.
    unsafe {
        asm!("xgetbv", in("ecx") 0, out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
    }
    u64::from(hi) << 32 | u64::from(lo)
}

/// XSAVE64 of the components in XCR0 into the area at `at`.
///
/// # Safety
///
/// `at` must be 64-byte aligned and the start of [`AREA_SIZE`] writable
/// bytes that nothing else refers to.
unsafe fn xsave64(at: *mut u8) {
    // SAFETY: the caller vouches for the area; XSAVE64 writes only there.
    unsafe {
        asm!("xsave64 [{}]", in(reg) at, in("eax") XCR0 as u32, in("edx") (XCR0 >> 32) as u32,
            options(nostack, preserves_flags));
    }
}

/// XRSTOR64 of the components in XCR0 from the area at `at`.
///
/// # Safety
///
/// `at` must be 64-byte aligned and the start of [`AREA_SIZE`] readable
/// bytes that XSAVE64 or [`init_area`] wrote, so XRSTOR64 cannot fault.
unsafe fn xrstor64(at: *const u8) {
    // SAFETY: the caller vouches for the area; XRSTOR64 reads only there
    // and changes only x87 and SSE registers, which the kernel never uses.
    unsafe {
        asm!("xrstor64 [{}]", in(reg) at, in("eax") XCR0 as u32, in("edx") (XCR0 >> 32) as u32,
            options(readonly, nostack, preserves_flags));
    }
}
