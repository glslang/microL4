//! The debug system calls (`docs/abi.md`, "Debug system calls"), the
//! console they give, and the panic handler. They exist only in a kernel
//! built with `debug`, where they change no register but `rcx` and `r11`.
//! In any other kernel each raises an `UnknownSyscall` fault, and a fault
//! handler that replies to one must leave the registers as they were.

use core::fmt::{self, Write};
use core::panic::PanicInfo;
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

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    // Console's `write_str` never fails.
    let _ = Console.write_fmt(args);
}

/// Prints to COM1 through `DebugPutChar`.
#[macro_export]
macro_rules! print {
    ($($arg:tt)*) => {
        $crate::_print(::core::format_args!($($arg)*))
    };
}

/// Prints a line to COM1 through `DebugPutChar`.
#[macro_export]
macro_rules! println {
    () => {
        $crate::print!("\n")
    };
    ($($arg:tt)*) => {
        $crate::_print(::core::format_args!("{}\n", ::core::format_args!($($arg)*)))
    };
}

#[panic_handler]
fn panic(info: &PanicInfo) -> ! {
    // A panic while printing a panic would recurse forever; stop instead.
    static PANICKING: AtomicBool = AtomicBool::new(false);
    if !PANICKING.swap(true, Ordering::Relaxed) {
        match info.location() {
            Some(loc) => crate::println!(
                "USER PANIC at {}:{}: {}",
                loc.file(),
                loc.line(),
                info.message()
            ),
            None => crate::println!("USER PANIC: {}", info.message()),
        }
    }
    debug_halt(1)
}
