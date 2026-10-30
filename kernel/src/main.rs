//! The microL4 kernel.
//!
//! The loader enters [`arch`] at `_start`, which sets up a stack, zeroes BSS
//! and calls [`kmain`]. The kernel checks the CPU, copies what the loader
//! handed over, moves onto its own descriptor tables and page tables (M3),
//! prints a boot summary, runs the test named on the command line, if any,
//! and stops.

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
mod boot;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use l4core::cmdline;
use l4core::handoff::{self, RegionKind};

use boot::BootState;

/// The kernel proper, called once by `arch` on the kernel stack with
/// interrupts off, with the physical address of the loader's handoff.
fn kmain(handoff_phys: u64) -> ! {
    let build = if cfg!(debug_assertions) {
        "debug"
    } else {
        "release"
    };
    kprintln!("microL4 kernel {} ({build})", env!("CARGO_PKG_VERSION"));
    // The M3 boot sequence (docs/design.md, "Boot sequence"), steps 2 to 5.
    arch::check_cpu();
    let boot = boot::take_handoff(handoff_phys);
    print_boot_info(boot);
    arch::init(boot);
    arch::print_cpu_state();

    match cmdline::value(boot.cmdline(), "test") {
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
        // Ring-0 traps and the idle loop's interrupt path (M3).
        Some("page_fault") => arch::provoke(arch::Provoke::PageFault),
        Some("double_fault") => arch::provoke(arch::Provoke::DoubleFault),
        Some("trap_breakpoint") => arch::provoke(arch::Provoke::Breakpoint),
        Some("trap_general_protection") => arch::provoke(arch::Provoke::GeneralProtection),
        Some("trap_nmi") => arch::provoke(arch::Provoke::Nmi),
        Some("trap_machine_check") => arch::provoke(arch::Provoke::MachineCheck),
        Some("trap_debug") => arch::provoke(arch::Provoke::Debug),
        Some("trap_cannot_occur") => arch::provoke(arch::Provoke::CannotOccur),
        Some("trap_irq_outside_idle") => arch::provoke(arch::Provoke::InterruptOutsideIdle),
        Some("idle_irq") => arch::idle_self_test(),
        Some("paging") => arch::test_paging(boot),
        Some("lowmem") => arch::test_lowmem(),
        Some("stack_overflow") => {
            kprintln!("recursing until the kernel stack overflows");
            let depth = overflow_stack(0);
            panic!("the stack never overflowed (depth {depth})")
        }
        Some(other) => {
            kprintln!("TEST FAIL: unknown test {other:?}");
            arch::exit(arch::ExitCode::Failure)
        }
    }
}

/// Recurses until the kernel stack runs into its guard page, for the
/// `stack_overflow` scenario. Each frame holds 512 bytes the optimiser
/// cannot drop, so the 64 KiB stack is gone after about 128 calls.
fn overflow_stack(depth: u64) -> u64 {
    let frame = core::hint::black_box([depth; 64]);
    if depth == u64::MAX {
        return 0;
    }
    overflow_stack(depth + 1) + frame[(depth % 64) as usize]
}

fn print_boot_info(boot: &BootState) {
    let h = &boot.handoff;
    kprintln!(
        "kernel: {} KiB at phys {:#x}, virt {:#x}",
        h.kernel_size >> 10,
        h.kernel_phys_base,
        handoff::KERNEL_VIRT_BASE
    );
    let regions = boot.memory_map();
    kprintln!(
        "memory: {} regions, {} MiB usable, direct map covers {} GiB",
        regions.len(),
        handoff::total_bytes(regions, RegionKind::USABLE) >> 20,
        h.direct_map_end() >> 30
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
    kprintln!("cmdline: {:?}", boot.cmdline());
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
        arch::print_stack_use();
    }
    arch::exit(arch::ExitCode::Failure)
}
