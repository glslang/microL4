//! The debug system calls (`docs/abi.md`, "Debug system calls"), the
//! console they give, the `print!` macros and the panic handler. The calls
//! exist only in a kernel built with `debug`, where they change no register
//! but `rcx` and `r11`. In any other kernel each raises an `UnknownSyscall`
//! fault, and a fault handler that replies to one must leave the registers
//! as they were. `print!` goes where [`crate::output`] says: `DebugPutChar`
//! until a program names a console.

use core::fmt::{self, Write};
#[cfg(target_os = "none")]
use core::panic::PanicInfo;
#[cfg(target_os = "none")]
use core::sync::atomic::{AtomicBool, Ordering};

use crate::syscall::{Message, number, syscall};

/// `DebugPutChar`: writes `byte` to COM1, `\n` as `\r\n`.
pub fn debug_put_char(byte: u8) {
    // SAFETY: DebugPutChar changes no register but rcx and r11, nor does
    // a handler of the fault it raises without `debug` (module docs).
    unsafe { syscall(number::DEBUG_PUT_CHAR, byte.into(), &Message::EMPTY) };
}

/// `DebugHalt`: the kernel prints `DEBUG HALT <status> from TCB
/// <address>` and ends the run, under QEMU with success for status 0 and
/// failure otherwise.
pub fn debug_halt(status: u64) -> ! {
    // SAFETY: DebugHalt does not return; without `debug` a handler of its
    // fault changes no register (module docs), and a reply restarts it.
    unsafe { syscall(number::DEBUG_HALT, status, &Message::EMPTY) };
    loop {
        // SAFETY: as above, for every later attempt.
        unsafe { syscall(number::DEBUG_HALT, status, &Message::EMPTY) };
    }
}

/// `DebugDumpScheduler`: the kernel prints one line per TCB.
pub fn debug_dump_scheduler() {
    // SAFETY: as for `debug_put_char`.
    unsafe { syscall(number::DEBUG_DUMP_SCHEDULER, 0, &Message::EMPTY) };
}

/// Text written with `DebugPutChar`, for [`core::fmt::Write`].
pub struct Console;

impl Write for Console {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        s.bytes().for_each(debug_put_char);
        Ok(())
    }
}

/// Prints through `DebugPutChar`, or through the console client
/// [`crate::output::use_console`] named.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::_print(::core::format_args!($($arg)*))
    };
}

/// Prints a line, as [`print!`] does.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}

// Only on the user target: a host build, for the unit tests, has std's.
// It prints where `print!` goes and ends the run with `output::exit(1)`,
// through the exit port if the program set one.
#[cfg(target_os = "none")]
#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // A panic while printing a panic would recurse forever; stop instead,
    // without the console's Sync, which may be what panicked.
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if PANICKING.swap(true, Ordering::Relaxed) {
        crate::output::exit_now(1)
    }
    match info.location() {
        Some(loc) => crate::println!(
            "USER PANIC at {}:{}: {}",
            loc.file(),
            loc.line(),
            info.message()
        ),
        None => crate::println!("USER PANIC: {}", info.message()),
    }
    crate::output::exit(1)
}
