//! System-call numbers (`docs/abi.md`, "System calls", "Debug system
//! calls"; `docs/design.md`, "System-call dispatch").
//!
//! A thread names the system call in `rdx`. Numbers 1 to 8 are the
//! system calls proper; 16 to 18 are the debug system calls, which exist
//! only in a kernel built with the `debug` feature (ADR 0021); 19 to 31 are
//! reserved for more of them. Every other number, 0 included, and a debug
//! number in a kernel without `debug`, names nothing: the caller gets an
//! `UnknownSyscall` fault with `fault_ip` on its `syscall` instruction.
//! Numbers are positive, unlike seL4's ([ADR 0022]).
//!
//! [ADR 0022]: ../../docs/adr/0022-abi-v0-numbering.md

use core::fmt;

/// A system call, by its number in `rdx`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
#[repr(u64)]
pub enum Syscall {
    /// Send, then wait for the reply; invokes a kernel object.
    Call = 1,
    /// Reply to the caller, then receive.
    ReplyRecv = 2,
    /// Send, blocking until a receiver takes the message.
    Send = 3,
    /// Send if a receiver is waiting; never blocks.
    NBSend = 4,
    /// Receive, blocking.
    Recv = 5,
    /// Reply to the caller.
    Reply = 6,
    /// Go to the tail of the priority's queue.
    Yield = 7,
    /// Receive if a message or signal is waiting; never blocks.
    NBRecv = 8,
    /// `debug` only: write the low byte of `rdi` to COM1.
    DebugPutChar = 16,
    /// `debug` only: print who halted with status `rdi`, and end the run.
    DebugHalt = 17,
    /// `debug` only: print every TCB.
    DebugDumpScheduler = 18,
}

/// The first debug system-call number.
pub const DEBUG_FIRST: u64 = 16;
/// The last number reserved for debug system calls; 19 to 31 name none.
pub const DEBUG_LAST: u64 = 31;

impl Syscall {
    /// Every system call, in number order.
    pub const ALL: [Syscall; 11] = [
        Syscall::Call,
        Syscall::ReplyRecv,
        Syscall::Send,
        Syscall::NBSend,
        Syscall::Recv,
        Syscall::Reply,
        Syscall::Yield,
        Syscall::NBRecv,
        Syscall::DebugPutChar,
        Syscall::DebugHalt,
        Syscall::DebugDumpScheduler,
    ];

    /// The system call `rdx` names in a kernel built with `debug` (from
    /// `cfg!(feature = "debug")`) or without it, or `None`, which raises
    /// `UnknownSyscall`. All 64 bits count: `0x1_0000_0001` is not `Call`.
    pub const fn from_number(rdx: u64, debug: bool) -> Option<Syscall> {
        Some(match rdx {
            1 => Syscall::Call,
            2 => Syscall::ReplyRecv,
            3 => Syscall::Send,
            4 => Syscall::NBSend,
            5 => Syscall::Recv,
            6 => Syscall::Reply,
            7 => Syscall::Yield,
            8 => Syscall::NBRecv,
            16 if debug => Syscall::DebugPutChar,
            17 if debug => Syscall::DebugHalt,
            18 if debug => Syscall::DebugDumpScheduler,
            _ => return None,
        })
    }

    /// Its number.
    pub const fn number(self) -> u64 {
        self as u64
    }

    /// Whether it is a debug system call, which only a `debug` kernel has.
    pub const fn is_debug(self) -> bool {
        self.number() >= DEBUG_FIRST
    }

    /// Its name in `docs/abi.md`.
    pub const fn name(self) -> &'static str {
        match self {
            Syscall::Call => "Call",
            Syscall::ReplyRecv => "ReplyRecv",
            Syscall::Send => "Send",
            Syscall::NBSend => "NBSend",
            Syscall::Recv => "Recv",
            Syscall::Reply => "Reply",
            Syscall::Yield => "Yield",
            Syscall::NBRecv => "NBRecv",
            Syscall::DebugPutChar => "DebugPutChar",
            Syscall::DebugHalt => "DebugHalt",
            Syscall::DebugDumpScheduler => "DebugDumpScheduler",
        }
    }
}

impl fmt::Display for Syscall {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({})", self.name(), self.number())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;
    use std::string::ToString;
    use std::vec::Vec;

    /// The numbers `from_number` accepts, read straight from `docs/abi.md`'s
    /// tables rather than from the enum.
    fn abi_table(debug: bool) -> Vec<(u64, &'static str)> {
        let mut t = std::vec![
            (1, "Call"),
            (2, "ReplyRecv"),
            (3, "Send"),
            (4, "NBSend"),
            (5, "Recv"),
            (6, "Reply"),
            (7, "Yield"),
            (8, "NBRecv"),
        ];
        if debug {
            t.extend([
                (16, "DebugPutChar"),
                (17, "DebugHalt"),
                (18, "DebugDumpScheduler"),
            ]);
        }
        t
    }

    #[test]
    fn numbers_follow_the_abi_tables() {
        for debug in [false, true] {
            let found: Vec<(u64, &str)> = (0..=64)
                .filter_map(|n| Syscall::from_number(n, debug).map(|s| (n, s.name())))
                .collect();
            assert_eq!(found, abi_table(debug), "debug {debug}");
        }
    }

    #[test]
    fn zero_reserved_and_large_numbers_name_nothing() {
        for debug in [false, true] {
            for n in [0, 9, 15, 19, 20, 31, 32, 255, 256, 1 << 32, u64::MAX] {
                assert_eq!(Syscall::from_number(n, debug), None, "{n:#x}");
            }
            // The high bits are not ignored.
            for s in Syscall::ALL {
                for high in [1 << 8, 1 << 32, 1 << 63] {
                    assert_eq!(Syscall::from_number(s.number() | high, debug), None);
                }
            }
        }
    }

    #[test]
    fn debug_numbers_need_a_debug_kernel() {
        for n in DEBUG_FIRST..=DEBUG_LAST {
            assert_eq!(Syscall::from_number(n, false), None, "{n}");
        }
        let with: Vec<u64> = (DEBUG_FIRST..=DEBUG_LAST)
            .filter(|&n| Syscall::from_number(n, true).is_some())
            .collect();
        assert_eq!(with, [16, 17, 18]);
        for s in Syscall::ALL {
            assert_eq!(
                s.is_debug(),
                (DEBUG_FIRST..=DEBUG_LAST).contains(&s.number())
            );
        }
    }

    #[test]
    fn all_is_every_call_in_number_order() {
        let numbers: Vec<u64> = Syscall::ALL.iter().map(|s| s.number()).collect();
        assert_eq!(numbers, [1, 2, 3, 4, 5, 6, 7, 8, 16, 17, 18]);
        for s in Syscall::ALL {
            assert_eq!(Syscall::from_number(s.number(), true), Some(s));
        }
        assert_eq!(Syscall::DebugHalt.to_string(), "DebugHalt (17)");
    }

    fn config() -> ProptestConfig {
        ProptestConfig {
            cases: if cfg!(miri) { 16 } else { 4096 },
            failure_persistence: None,
            ..ProptestConfig::default()
        }
    }

    proptest! {
        #![proptest_config(config())]

        /// Over all of `u64`: a number names a call exactly when the ABI
        /// table lists it for that build, and then names the call with that
        /// number.
        #[test]
        fn any_number_decodes_as_the_table_says(n in any::<u64>(), debug in any::<bool>()) {
            let listed = abi_table(debug).into_iter().find(|&(m, _)| m == n);
            match (Syscall::from_number(n, debug), listed) {
                (Some(s), Some((_, name))) => {
                    prop_assert_eq!(s.number(), n);
                    prop_assert_eq!(s.name(), name);
                }
                (None, None) => {}
                (got, want) => prop_assert!(false, "{n:#x}: {got:?}, table {want:?}"),
            }
        }

        /// The small numbers, where every case is interesting.
        #[test]
        fn small_numbers_decode_as_the_table_says(n in 0u64..64, debug in any::<bool>()) {
            let listed = abi_table(debug).iter().any(|&(m, _)| m == n);
            prop_assert_eq!(Syscall::from_number(n, debug).is_some(), listed);
        }
    }
}
