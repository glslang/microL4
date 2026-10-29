//! The microL4 kernel.
//!
//! M0: the loader enters [`arch`] at `_start`, which sets up a stack, zeroes
//! BSS and calls [`kmain`]. The kernel prints what the loader handed over, runs
//! the test named on the command line, if any, and stops.

#![no_std]
#![no_main]
// All `unsafe` lives in `arch/`, which opts back in. Each block there carries
// a `SAFETY:` comment, which clippy enforces.
#![deny(unsafe_code)]
#![warn(clippy::undocumented_unsafe_blocks)]

#[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
compile_error!("the kernel builds only for x86_64-unknown-none");

// x86_64-unknown-none keeps the compiler off SSE registers. A build with SSE
// would let `memcpy` and friends clobber user FP state.
#[cfg(target_feature = "sse")]
compile_error!("the kernel must be built without SSE");

#[macro_use]
mod debug;
#[allow(unsafe_code)]
mod arch;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use l4core::cmdline;
use l4core::handoff::{self, Handoff, RegionKind};

/// The kernel proper, called once by `arch` on the boot stack with interrupts
/// off.
fn kmain(handoff: &'static Handoff) -> ! {
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    kprintln!("microL4 kernel {} ({build})", env!("CARGO_PKG_VERSION"));
    if let Err(e) = handoff.validate() {
        panic!("bad handoff: {e}");
    }
    print_boot_info(handoff);

    match cmdline::value(handoff.cmdline(), "test") {
        None => {
            kprintln!("hello from microL4");
            kprintln!("nothing more to do; halting");
            arch::halt()
        }
        Some("hello") => {
            kprintln!("hello from microL4");
            kprintln!("TEST PASS");
            arch::exit(arch::ExitCode::Success)
        }
        Some("panic") => panic!("deliberate panic requested by the command line"),
        Some(other) => {
            kprintln!("TEST FAIL: unknown test {other:?}");
            arch::exit(arch::ExitCode::Failure)
        }
    }
}

fn print_boot_info(h: &Handoff) {
    kprintln!(
        "kernel: {} KiB at phys {:#x}, virt {:#x}",
        h.kernel_size >> 10,
        h.kernel_phys_base,
        handoff::KERNEL_VIRT_BASE
    );
    let regions = arch::memory_map(h);
    kprintln!(
        "memory: {} regions, {} MiB usable, direct map covers {} GiB",
        regions.len(),
        handoff::total_bytes(regions, RegionKind::USABLE) >> 20,
        h.phys_map_size >> 30
    );
    for r in regions {
        kprintln!("  {:#014x}-{:#014x} {}", r.base, r.end(), r.kind.name());
    }
    let fb = &h.framebuffer;
    if fb.base == 0 {
        kprintln!("framebuffer: none");
    } else {
        kprintln!(
            "framebuffer: {}x{}, stride {}, {} at {:#x}",
            fb.width,
            fb.height,
            fb.stride,
            fb.format.name(),
            fb.base
        );
    }
    match h.rsdp {
        0 => kprintln!("acpi: no RSDP"),
        rsdp => kprintln!("acpi: RSDP at {rsdp:#x}"),
    }
    kprintln!("cpu: hypervisor {}", arch::hypervisor());
    kprintln!("cmdline: {:?}", h.cmdline());
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // A panic while printing a panic would recurse forever; stop instead.
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if !PANICKING.swap(true, Ordering::Relaxed) {
        match info.location() {
            Some(loc) => kprintln!(
                "KERNEL PANIC at {}:{}: {}",
                loc.file(),
                loc.line(),
                info.message()
            ),
            None => kprintln!("KERNEL PANIC: {}", info.message()),
        }
    }
    arch::exit(arch::ExitCode::Failure)
}
