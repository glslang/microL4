//! The few x86_64 operations the loader needs.

use core::arch::asm;

const EFER: u32 = 0xC000_0080;
const EFER_NXE: u64 = 1 << 11;
const CR4_LA57: u64 = 1 << 12;
const CR0_WP: u64 = 1 << 16;
const DEBUG_EXIT_PORT: u16 = 0xF4;
/// Makes QEMU exit with status 35, the same failure status as the kernel's.
const DEBUG_EXIT_FAILURE: u32 = 0x11;

fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx);
    // SAFETY: CPUID only reads identification registers. LLVM reserves rbx,
    // so it is saved and restored by hand.
    unsafe {
        asm!(
            "mov {saved:r}, rbx",
            "cpuid",
            "xchg {saved:r}, rbx",
            saved = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") 0u32 => ecx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

fn is_qemu() -> bool {
    if cpuid(1).2 & (1 << 31) == 0 {
        return false;
    }
    let (_, ebx, ecx, edx) = cpuid(0x4000_0000);
    let sig = [ebx.to_le_bytes(), ecx.to_le_bytes(), edx.to_le_bytes()];
    sig == [*b"TCGT", *b"CGTC", *b"GTCG"] || sig == [*b"KVMK", *b"VMKV", *b"M\0\0\0"]
}

pub fn nx_supported() -> bool {
    cpuid(0x8000_0000).0 >= 0x8000_0001 && cpuid(0x8000_0001).3 & (1 << 20) != 0
}

/// Sets EFER.NXE, so page-table entries may use the no-execute bit.
///
/// # Safety
///
/// The CPU must support NX ([`nx_supported`]).
pub unsafe fn enable_nx() {
    let (lo, hi): (u32, u32);
    // SAFETY: EFER exists on every x86_64 CPU; setting NXE only enables a
    // page-table bit, and the caller checked the CPU supports it.
    unsafe {
        asm!("rdmsr", in("ecx") EFER, out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags));
        let efer = ((u64::from(hi) << 32) | u64::from(lo)) | EFER_NXE;
        asm!("wrmsr", in("ecx") EFER, in("eax") efer as u32, in("edx") (efer >> 32) as u32, options(nomem, nostack, preserves_flags));
    }
}

pub fn la57_enabled() -> bool {
    let cr4: u64;
    // SAFETY: reading CR4 has no side effects.
    unsafe { asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags)) };
    cr4 & CR4_LA57 != 0
}

pub fn disable_interrupts() {
    // SAFETY: `cli` only clears IF.
    unsafe { asm!("cli", options(nomem, nostack)) };
}

/// Stops after a loader failure: exits QEMU with the failure status, or
/// halts anywhere else.
pub fn fail() -> ! {
    if is_qemu() {
        // SAFETY: under QEMU, xtask attaches isa-debug-exit at this port, and
        // writing to it only ends the emulator.
        unsafe {
            asm!("out dx, eax", in("dx") DEBUG_EXIT_PORT, in("eax") DEBUG_EXIT_FAILURE, options(nomem, nostack))
        };
    }
    loop {
        // SAFETY: halting touches no memory.
        unsafe { asm!("cli", "hlt", options(nomem, nostack)) };
    }
}

/// Sets CR0.WP, so that ring 0 honours read-only pages, loads `pml4` into
/// CR3 and jumps to the kernel with `handoff` in `rdi`.
///
/// # Safety
///
/// Boot services must be gone and interrupts off, and nothing may write
/// memory the firmware's tables map read-only after this point. `pml4` must
/// map the code running this function 1:1 and `entry` at its link address,
/// and `handoff` must be the physical address of a complete Handoff.
pub unsafe fn enter_kernel(pml4: u64, entry: u64, handoff: u64) -> ! {
    let cr0: u64;
    // SAFETY: reading CR0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) cr0, options(nomem, nostack, preserves_flags)) };
    // SAFETY: the caller upholds the contract above. Setting WP only makes
    // writes to read-only pages fault, and nothing here writes memory. After
    // the CR3 write the next instruction is still mapped, by the 1:1 map.
    unsafe {
        asm!(
            "mov cr0, {cr0}",
            "mov cr3, {pml4}",
            "jmp {entry}",
            cr0 = in(reg) cr0 | CR0_WP,
            pml4 = in(reg) pml4,
            entry = in(reg) entry,
            in("rdi") handoff,
            options(noreturn, nostack),
        )
    }
}
