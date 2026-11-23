//! What user code reads from the CPU itself, and the one fence it needs.

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

/// `sfence`: every store before it, the write-combining buffers' included,
/// becomes visible before any store after it, so term calls it at the end
/// of each frame's pixel writes, before it replies (`docs/design.md`, "The
/// renderer"), and root's write-combining check before its second TSC
/// read. It is also a compiler barrier: the `asm!` may touch memory, so no
/// store moves across it. Under Miri, which runs no inline assembly, a
/// sequentially consistent fence stands in for it.
pub fn store_fence() {
    #[cfg(not(miri))]
    // SAFETY: `sfence` orders stores and does nothing else: it reads and
    // writes no register, no memory and no flag, needs no stack, and
    // cannot fault in ring 3. Leaving out `nomem` keeps the compiler from
    // moving memory accesses across it.
    unsafe {
        asm!("sfence", options(nostack, preserves_flags));
    }
    #[cfg(miri)]
    core::sync::atomic::fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    /// The fence runs on the host too, where host tests draw frames.
    #[test]
    fn the_store_fence_runs() {
        super::store_fence();
    }
}
