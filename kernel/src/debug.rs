//! Kernel debug output on COM1, in a kernel built with `debug` only.
//!
//! There is one core, and kernel code runs with interrupts off except in the
//! idle loop, which prints nothing, so the writer needs no lock. An NMI or
//! machine-check panic can split a line; both end the run.
//!
//! Without `debug`, COM1 belongs to the `uart` server and the kernel has
//! no writer: `kprintln!` expands to `if false { let _ = format_args!(..); }`,
//! which type-checks its arguments, so every `cfg` compiles both ways, and
//! emits no code (ADR 0021).

#[cfg(feature = "debug")]
macro_rules! kprintln {
    () => { $crate::debug::print(format_args!("\n")) };
    ($($arg:tt)*) => { $crate::debug::print(format_args!("{}\n", format_args!($($arg)*))) };
}

#[cfg(not(feature = "debug"))]
macro_rules! kprintln {
    () => { () };
    ($($arg:tt)*) => {
        if false {
            let _ = format_args!($($arg)*);
        }
    };
}

#[cfg(feature = "debug")]
pub fn print(args: core::fmt::Arguments<'_>) {
    use core::fmt::Write;
    // The serial writer never fails, so there is nothing to report.
    let _ = crate::arch::serial::Writer.write_fmt(args);
}
