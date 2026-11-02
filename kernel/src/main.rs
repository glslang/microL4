//! The microL4 kernel.
//!
//! The loader enters [`arch`] at `_start`, which sets up a stack, zeroes BSS
//! and calls [`kmain`]. The kernel checks the CPU, copies what the loader
//! handed over, moves onto its own descriptor tables and page tables (M3),
//! prints a boot summary, runs the test named on the command line, if any,
//! and stops. The tests exist only in a kernel built with the `selftest`
//! feature, as xtask builds every image.

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
#[cfg(feature = "selftest")]
mod rootimage;
#[cfg(feature = "selftest")]
mod selftest;

use core::panic::PanicInfo;
use core::sync::atomic::{AtomicBool, Ordering};

use l4core::cmdline;
use l4core::handoff::{self, RegionKind};

use arch::BootFacts;
use boot::{BootState, RootSpace};

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
    let facts = arch::init(boot);
    arch::print_cpu_state();
    // Steps 6, 7 and 9 (M4); 8 and 10 enter the root task from M5.
    let root = boot::make_root_space(boot, facts);
    boot::print_root_space(root);

    match cmdline::value(boot.cmdline(), "test") {
        None => {
            kprintln!("hello from microL4");
            kprintln!("nothing more to do; halting");
            arch::halt()
        }
        Some(name) => run_test(name, boot, facts, root),
    }
}

/// Runs the self-test `test=` names (ADR 0003), which ends the run.
#[cfg(feature = "selftest")]
fn run_test(
    name: &str,
    boot: &'static BootState,
    facts: &'static BootFacts,
    root: &'static RootSpace,
) -> ! {
    match name {
        "hello" => {
            kprintln!("hello from microL4");
            kprintln!("TEST PASS");
            arch::exit(arch::ExitCode::Success)
        }
        "panic" => panic!("deliberate panic requested by the command line"),
        // Ring-0 traps and the idle loop's interrupt path (M3).
        "page_fault" => arch::provoke(arch::Provoke::PageFault),
        "double_fault" => arch::provoke(arch::Provoke::DoubleFault),
        "df_stack" => arch::provoke(arch::Provoke::DoubleFaultStack),
        "trap_breakpoint" => arch::provoke(arch::Provoke::Breakpoint),
        "trap_general_protection" => arch::provoke(arch::Provoke::GeneralProtection),
        "trap_nmi" => arch::provoke(arch::Provoke::Nmi),
        "trap_machine_check" => arch::provoke(arch::Provoke::MachineCheck),
        "trap_debug" => arch::provoke(arch::Provoke::Debug),
        "trap_cannot_occur" => arch::provoke(arch::Provoke::CannotOccur),
        "trap_irq_outside_idle" => arch::provoke(arch::Provoke::InterruptOutsideIdle),
        "idle_irq" => arch::idle_self_test(),
        "paging" => arch::test_paging(boot),
        "lowmem" => arch::test_lowmem(),
        // The interrupt controllers and the timer (M3).
        "ticks" => {
            arch::start_ticks_test();
            arch::idle()
        }
        "nmi_stack" => arch::test_nmi_stack(),
        "stack_overflow" => {
            kprintln!("recursing until the kernel stack overflows");
            let depth = overflow_stack(0);
            panic!("the stack never overflowed (depth {depth})")
        }
        // Kernel objects and BootInfo (M4).
        "bootinfo" => selftest::bootinfo(boot, facts, root),
        "retype" => selftest::retype(root),
        // Threads, address spaces and the root task (M5).
        "rootimage" => rootimage::test(boot, root),
        "ring3" => arch::test_ring3(root),
        "vspace" => arch::test_vspace(root),
        other => {
            kprintln!("TEST FAIL: unknown test {other:?}");
            arch::exit(arch::ExitCode::Failure)
        }
    }
}

/// Without `selftest` there are no tests: says so and fails the run.
#[cfg(not(feature = "selftest"))]
fn run_test(
    name: &str,
    _boot: &'static BootState,
    _facts: &'static BootFacts,
    _root: &'static RootSpace,
) -> ! {
    kprintln!("test={name}: this kernel has no self-tests (built without the `selftest` feature)");
    arch::exit(arch::ExitCode::Failure)
}

/// Recurses until the kernel stack runs into its guard page, for the
/// `stack_overflow` scenario. Each frame holds 512 bytes the optimiser
/// cannot drop, so the 64 KiB stack is gone after about 128 calls.
#[cfg(feature = "selftest")]
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
        #[cfg(feature = "selftest")]
        arch::print_stack_use();
    }
    arch::exit(arch::ExitCode::Failure)
}
