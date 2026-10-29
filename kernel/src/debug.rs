//! Kernel debug output on COM1.
//!
//! There is one core and interrupts stay off in M0, so the writer needs no
//! lock. M3 turns interrupts on and must add one. M7 compiles this out of
//! release kernels, once the `uart` server owns COM1.

use core::fmt::{self, Write};

use crate::arch::serial;

macro_rules! kprintln {
    () => { $crate::debug::print(format_args!("\n")) };
    ($($arg:tt)*) => { $crate::debug::print(format_args!("{}\n", format_args!($($arg)*))) };
}

pub fn print(args: fmt::Arguments<'_>) {
    // The serial writer never fails, so there is nothing to report.
    let _ = serial::Writer.write_fmt(args);
}
