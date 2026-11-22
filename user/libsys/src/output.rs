//! Where [`crate::print!`] and [`crate::println!`] go, and how a program
//! ends (`docs/design.md`, "libsys" under "User-level drivers and
//! console").
//!
//! The output is `DebugPutChar`, the default, or a console client
//! capability ([`use_console`]); [`set_exit_port`] names an IOPort
//! capability for QEMU's `isa-debug-exit` at `0xF4`. Both are statics of
//! the VSpace and name a slot of one CSpace, so they suit the thread that
//! set them and threads sharing its CSpace: a thread with a CSpace of its
//! own writes through a [`crate::console::Client`] of its own, and a server
//! in a VSpace copied from the root task's calls [`reset`] first, since its
//! copy names the root task's slots.
//!
//! [`exit`] syncs the console if the output goes there, then ends the run
//! through the exit port if one is set, else with `DebugHalt`, so a test
//! that set an exit port can fail on a kernel without `debug`, where
//! `DebugHalt` raises a fault. [`Polled`] writes to COM1 through an IOPort
//! capability, bypassing `uart`, for the one thread that reports a
//! server's fault.

use core::fmt::{self, Write};
use core::sync::atomic::{AtomicU64, Ordering};

use crate::console::{Buffered, Client};
use crate::proto::MAX_BYTES;
use crate::syscall::{CPtr, Ipc};

/// The console client capability `print!` writes through; 0 (the null
/// slot) for `DebugPutChar`.
static CONSOLE: AtomicU64 = AtomicU64::new(0);
/// The IOPort capability for `isa-debug-exit`; 0 for none.
static EXIT_PORT: AtomicU64 = AtomicU64::new(0);

/// `isa-debug-exit`'s port, and what [`exit`] writes there: QEMU exits
/// with status `(value << 1) | 1`, 33 for success and 35 for failure.
pub const EXIT_PORT_NUMBER: u16 = 0xF4;
pub const EXIT_SUCCESS: u32 = 0x10;
pub const EXIT_FAILURE: u32 = 0x11;

/// `print!` writes through the console client capability `cap`, with the
/// IPC buffer [`Ipc::root`] names. `cap` must not be 0.
pub fn use_console(cap: CPtr) {
    assert_ne!(cap, 0, "the null slot is no console client");
    CONSOLE.store(cap, Ordering::Relaxed);
}

/// `print!` writes through `DebugPutChar`, as at start.
pub fn use_debug() {
    CONSOLE.store(0, Ordering::Relaxed);
}

/// The console client `print!` writes through, if any.
pub fn console() -> Option<CPtr> {
    match CONSOLE.load(Ordering::Relaxed) {
        0 => None,
        c => Some(c),
    }
}

/// [`exit`] ends the run through `port`, an IOPort capability that covers
/// `0xF4` to `0xF7`, or with `DebugHalt` for `None`.
pub fn set_exit_port(port: Option<CPtr>) {
    EXIT_PORT.store(port.unwrap_or(0), Ordering::Relaxed);
}

/// The exit port, if any.
pub fn exit_port() -> Option<CPtr> {
    match EXIT_PORT.load(Ordering::Relaxed) {
        0 => None,
        p => Some(p),
    }
}

/// `DebugPutChar` output and no exit port: what a server in a VSpace
/// copied from the root task's starts with.
pub fn reset() {
    use_debug();
    set_exit_port(None);
}

/// The value [`exit`] writes to the exit port for `status`.
pub const fn exit_value(status: u64) -> u32 {
    if status == 0 {
        EXIT_SUCCESS
    } else {
        EXIT_FAILURE
    }
}

/// Ends the run: syncs the console if `print!` goes there, then, with an
/// exit port, writes [`exit_value`] to it with `IOPort_Out32` (under QEMU
/// the run ends there; elsewhere this thread then yields for ever), else
/// calls `DebugHalt(status)`.
pub fn exit(status: u64) -> ! {
    if let Some(c) = console() {
        // A console that cannot answer leaves nothing better to do.
        let _ = Client::new(c, Some(Ipc::root())).sync();
    }
    exit_now(status)
}

/// [`exit`] without the console's `Sync`: for a panic while printing.
pub fn exit_now(status: u64) -> ! {
    if let Some(port) = exit_port() {
        let _ = crate::standin::ioport_out32(port, EXIT_PORT_NUMBER, exit_value(status));
        loop {
            crate::yield_now();
        }
    }
    crate::debug::debug_halt(status)
}

#[doc(hidden)]
pub fn _print(args: fmt::Arguments<'_>) {
    match console() {
        Some(c) => {
            let client = Client::new(c, Some(Ipc::root()));
            let mut out = Buffered::new(MAX_BYTES, |piece| client.write(piece));
            // Output that cannot be delivered is dropped: print! has no
            // way to report it.
            let _ = out.write_fmt(args);
            let _ = out.finish();
        }
        None => {
            let _ = crate::debug::Console.write_fmt(args);
        }
    }
}

/// Byte-wide port accesses, for [`Polled`]: an IOPort capability on the
/// target, a model in host tests. `None` or `false` for an access that
/// failed.
pub trait PortIo {
    fn in8(&mut self, port: u16) -> Option<u8>;
    fn out8(&mut self, port: u16, value: u8) -> bool;
}

/// An IOPort capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoPort(pub CPtr);

impl PortIo for IoPort {
    fn in8(&mut self, port: u16) -> Option<u8> {
        crate::standin::ioport_in8(self.0, port).ok()
    }

    fn out8(&mut self, port: u16, value: u8) -> bool {
        crate::standin::ioport_out8(self.0, port, value).is_ok()
    }
}

/// COM1's base port.
pub const COM1: u16 = 0x3F8;
/// Polls of LSR before a byte is written anyway, as the kernel's writer
/// bounds its wait.
pub const POLLS: u32 = 100_000;
const THR: u16 = 0;
const LSR: u16 = 5;
const LSR_THRE: u8 = 0x20;
const LSR_TEMT: u8 = 0x40;

/// A `core::fmt::Write` on COM1 that bypasses `uart`: before each byte it
/// polls LSR until THRE, at most [`POLLS`] times, then writes THR, `\n` as
/// `\r\n`; after the text it polls for TEMT within the same bound. It
/// touches no other register, so it can write between `uart`'s bytes
/// without overflowing the FIFO, as a debug kernel's writer does.
pub struct Polled<P: PortIo = IoPort> {
    port: P,
    base: u16,
}

impl<P: PortIo> Polled<P> {
    /// COM1 through `port`.
    pub const fn com1(port: P) -> Polled<P> {
        Polled { port, base: COM1 }
    }

    /// The port accesses, back.
    pub fn into_inner(self) -> P {
        self.port
    }

    fn wait_for(&mut self, bit: u8) -> fmt::Result {
        for _ in 0..POLLS {
            if self.port.in8(self.base + LSR).ok_or(fmt::Error)? & bit != 0 {
                return Ok(());
            }
        }
        Ok(())
    }

    fn byte(&mut self, b: u8) -> fmt::Result {
        self.wait_for(LSR_THRE)?;
        if self.port.out8(self.base + THR, b) {
            Ok(())
        } else {
            Err(fmt::Error)
        }
    }
}

impl<P: PortIo> Write for Polled<P> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for b in s.bytes() {
            if b == b'\n' {
                self.byte(b'\r')?;
            }
            self.byte(b)?;
        }
        self.wait_for(LSR_TEMT)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    /// A UART whose LSR shows THRE and TEMT after `busy` reads that do
    /// not, each time a byte is written.
    struct Fake {
        log: Vec<(char, u16, u8)>,
        busy: u32,
        left: u32,
        broken: bool,
    }

    impl PortIo for Fake {
        fn in8(&mut self, port: u16) -> Option<u8> {
            if self.broken {
                return None;
            }
            let v = if self.left > 0 {
                self.left -= 1;
                0
            } else {
                LSR_THRE | LSR_TEMT
            };
            self.log.push(('i', port, v));
            Some(v)
        }

        fn out8(&mut self, port: u16, value: u8) -> bool {
            self.log.push(('o', port, value));
            self.left = self.busy;
            true
        }
    }

    fn fake(busy: u32) -> Fake {
        Fake {
            log: Vec::new(),
            busy,
            left: 0,
            broken: false,
        }
    }

    #[test]
    fn polled_waits_for_thre_and_writes_crlf() {
        let mut p = Polled::com1(fake(2));
        write!(p, "a\nb").unwrap();
        let log = p.into_inner().log;
        let lsr = |v| ('i', 0x3FD, v);
        let thr = |b| ('o', 0x3F8, b);
        let ready = LSR_THRE | LSR_TEMT;
        assert_eq!(
            log,
            [
                lsr(ready),
                thr(b'a'),
                lsr(0),
                lsr(0),
                lsr(ready),
                thr(b'\r'),
                lsr(0),
                lsr(0),
                lsr(ready),
                thr(b'\n'),
                lsr(0),
                lsr(0),
                lsr(ready),
                thr(b'b'),
                // TEMT after the text.
                lsr(0),
                lsr(0),
                lsr(ready),
            ]
        );
        // Only LSR and THR.
        assert!(
            log.iter()
                .all(|&(_, port, _)| port == 0x3FD || port == 0x3F8)
        );
    }

    #[test]
    #[cfg_attr(miri, ignore = "200,000 polls")]
    fn polled_gives_up_waiting_but_still_writes() {
        let mut p = Polled::com1(fake(u32::MAX));
        write!(p, "xy").unwrap();
        let log = p.into_inner().log;
        let writes: Vec<u8> = log.iter().filter(|e| e.0 == 'o').map(|e| e.2).collect();
        assert_eq!(writes, b"xy");
        // One full bound of polls before y, and one for TEMT.
        assert_eq!(log.len(), 1 + 1 + POLLS as usize + 1 + POLLS as usize);
    }

    #[test]
    fn polled_stops_when_the_capability_fails() {
        let mut f = fake(0);
        f.broken = true;
        let mut p = Polled::com1(f);
        assert!(write!(p, "z").is_err());
        assert!(p.into_inner().log.is_empty());
    }

    #[test]
    fn exit_values_are_isa_debug_exits() {
        assert_eq!(exit_value(0), 0x10);
        assert_eq!(exit_value(1), 0x11);
        assert_eq!(exit_value(7), 0x11);
        assert_eq!((EXIT_SUCCESS << 1) | 1, 33);
        assert_eq!((EXIT_FAILURE << 1) | 1, 35);
    }
}
