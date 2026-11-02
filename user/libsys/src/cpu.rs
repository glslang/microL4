//! What user code reads from the CPU itself.

use core::arch::asm;

/// The time-stamp counter. The kernel leaves CR4.TSD clear, so `rdtsc`
/// works in ring 3; BootInfo's `tsc_hz` gives its rate.
pub fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` writes only EDX and EAX, touches no memory or stack
    // and leaves the flags alone; with CR4.TSD clear it cannot fault.
    unsafe {
        asm!(
            "rdtsc",
            out("eax") lo,
            out("edx") hi,
            options(nomem, nostack, preserves_flags),
        );
    }
    (u64::from(hi) << 32) | u64::from(lo)
}
