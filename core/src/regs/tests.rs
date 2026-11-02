//! Host tests of the register set, `sanitise`, the Restart and Suspend
//! rules, and the fault encoder and reply decoder.

use std::vec::Vec;

use proptest::prelude::*;

use super::*;

/// The canonical boundaries: the last lower-half address, the first
/// non-canonical one, the first upper-half one, and the extremes.
const LAST_LOW: u64 = (1 << 47) - 1;
const FIRST_HOLE: u64 = 1 << 47;
const FIRST_HIGH: u64 = 0u64.wrapping_sub(1 << 47);

const ADDRESS_REGS: [UserReg; 4] = [UserReg::Rip, UserReg::Rsp, UserReg::FsBase, UserReg::GsBase];

fn config() -> ProptestConfig {
    ProptestConfig {
        cases: if cfg!(miri) { 4 } else { 256 },
        failure_persistence: None,
        ..ProptestConfig::default()
    }
}

#[test]
fn sanitise_at_the_canonical_boundaries() {
    for r in ADDRESS_REGS {
        assert_eq!(sanitise(r, 0), 0);
        assert_eq!(sanitise(r, LAST_LOW), LAST_LOW, "{r:?}");
        assert_eq!(sanitise(r, FIRST_HOLE), 0, "{r:?}");
        assert_eq!(sanitise(r, FIRST_HOLE + 1), 0, "{r:?}");
        assert_eq!(sanitise(r, FIRST_HIGH - 1), 0, "{r:?}");
        assert_eq!(sanitise(r, FIRST_HIGH), 0, "{r:?}");
        assert_eq!(sanitise(r, u64::MAX), 0, "{r:?}");
    }
    // Every other general register is unchanged, even at the boundaries.
    for r in UserReg::ALL {
        if ADDRESS_REGS.contains(&r) || r == UserReg::Rflags {
            continue;
        }
        for v in [0, LAST_LOW, FIRST_HOLE, FIRST_HIGH, u64::MAX] {
            assert_eq!(sanitise(r, v), v, "{r:?}");
        }
    }
}

#[test]
fn sanitise_rflags() {
    // Bit 1 and IF are always set; nothing else survives from 0.
    assert_eq!(sanitise(UserReg::Rflags, 0), 0x202);
    // CF PF AF ZF SF DF OF survive; TF (8), IOPL (12-13), NT (14), RF (16),
    // VM (17), AC (18), VIF (19), VIP (20) and ID (21) are cleared.
    assert_eq!(sanitise(UserReg::Rflags, 0x0CD5), 0x0ED7);
    assert_eq!(sanitise(UserReg::Rflags, u64::MAX), 0x0ED7);
    for bit in [8, 12, 13, 14, 16, 17, 18, 19, 20, 21, 63] {
        assert_eq!(sanitise(UserReg::Rflags, 1 << bit), 0x202, "bit {bit}");
    }
    for bit in [0, 2, 4, 6, 7, 10, 11] {
        assert_eq!(
            sanitise(UserReg::Rflags, 1 << bit),
            0x202 | 1 << bit,
            "bit {bit}"
        );
    }
}

proptest! {
    #![proptest_config(config())]

    /// Whatever is written, an address register ends below 2^47, RFLAGS has
    /// IF and bit 1 set and IOPL, TF, NT, AC, RF, VM and ID clear, and
    /// sanitising twice changes nothing more.
    #[test]
    fn sanitise_holds_for_any_word(v in any::<u64>(), i in 0..USER_REGS) {
        let r = UserReg::ALL[i];
        let s = sanitise(r, v);
        prop_assert_eq!(sanitise(r, s), s);
        if ADDRESS_REGS.contains(&r) {
            prop_assert!(s < USER_LIMIT);
            prop_assert!(s == v || s == 0);
        } else if r == UserReg::Rflags {
            prop_assert_eq!(s & 0x202, 0x202);
            prop_assert_eq!(s & !0x0ED7, 0);
            prop_assert_eq!(s & 0x0CD5, v & 0x0CD5);
        } else {
            prop_assert_eq!(s, v);
        }
    }

    /// The fault encoder and reply decoder round-trip: replying to an
    /// `UnknownSyscall` or `UserException` with the message's own words
    /// leaves the registers as they were, but for `next_ip`, which a
    /// written `rip` sets to `fault_ip`, and the exit, now `Iret`.
    #[test]
    fn a_fault_reply_with_the_message_restores_the_registers(
        words in prop::array::uniform24(any::<u64>()),
        number in any::<u64>(),
        code in any::<u64>(),
    ) {
        let mut regs = sanitised(words);
        regs.exit = Exit::Sysret as u64;
        for fault in [Fault::UnknownSyscall { number }, Fault::UserException { number, code }] {
            let m = fault_message(&fault, &regs);
            let mut after = regs;
            prop_assert_eq!(fault_reply(&fault, 0, m.mrs(), &mut after), FaultOutcome::Restart);
            let mut expected = regs;
            expected.next_ip = regs.fault_ip;
            expected.exit = Exit::Iret as u64;
            prop_assert_eq!(after, expected);
        }
    }
}

/// Registers as a writer could have left them: every user register passed
/// through `sanitise`.
fn sanitised(words: [u64; 24]) -> Regs {
    let mut regs = Regs {
        error: words[21],
        exit: words[22],
        pad: words[23],
        ..Regs::default()
    };
    for (i, r) in UserReg::ALL.into_iter().enumerate() {
        regs.set_user(r, words[i]);
    }
    regs.next_ip = sanitise(UserReg::Rip, words[20]);
    regs
}

#[test]
fn a_new_thread_leaves_by_iret() {
    // The zero value is `Iret`, so zeroed memory leaves by `iretq`.
    assert_eq!(Regs::default().exit(), Exit::Iret);
    assert_eq!(Exit::Iret as u64, 0);
    let r = Regs::new_thread();
    assert_eq!(r.exit(), Exit::Iret);
    assert_eq!(r.rflags, 0x202);
    assert_eq!(Regs { rflags: 0, ..r }, Regs::default());
    // Any value but `Sysret`'s reads as `Iret`.
    for v in [2, 3, u64::MAX] {
        assert_eq!(Regs { exit: v, ..r }.exit(), Exit::Iret);
    }
    assert_eq!(
        Regs {
            exit: Exit::Sysret as u64,
            ..r
        }
        .exit(),
        Exit::Sysret
    );
}

#[test]
fn rip_reads_next_ip_only_while_running() {
    let regs = Regs {
        fault_ip: 0x1000,
        next_ip: 0x1002,
        ..Regs::default()
    };
    assert_eq!(regs.user(UserReg::Rip, true), 0x1002);
    assert_eq!(regs.user(UserReg::Rip, false), 0x1000);
}

#[test]
fn writing_a_register_forces_iret_and_rip_sets_both() {
    let mut regs = Regs {
        fault_ip: 0x1000,
        next_ip: 0x1002,
        exit: Exit::Sysret as u64,
        ..Regs::default()
    };
    regs.set_user(UserReg::Rax, 7);
    assert_eq!((regs.rax, regs.exit()), (7, Exit::Iret));
    regs.set_exit(Exit::Sysret);
    regs.set_user(UserReg::Rip, 0x4000);
    assert_eq!(
        (regs.fault_ip, regs.next_ip, regs.exit()),
        (0x4000, 0x4000, Exit::Iret)
    );
    regs.set_user(UserReg::Rip, FIRST_HOLE);
    assert_eq!((regs.fault_ip, regs.next_ip), (0, 0));
}

#[test]
fn every_user_register_reads_back_what_was_written() {
    let mut regs = Regs::default();
    for (i, r) in UserReg::ALL.into_iter().enumerate() {
        assert_eq!(UserReg::from_index(i), Some(r));
        assert_eq!(r.index(), i);
        // Distinct values that every sanitiser keeps.
        let v = if r == UserReg::Rflags {
            0x283
        } else {
            0x1000 + i as u64
        };
        regs.set_user(r, v);
    }
    assert_eq!(UserReg::from_index(USER_REGS), None);
    for (i, r) in UserReg::ALL.into_iter().enumerate() {
        let v = if r == UserReg::Rflags {
            0x283
        } else {
            0x1000 + i as u64
        };
        assert_eq!(regs.user(r, true), v, "{r:?}");
        assert_eq!(regs.user(r, false), v, "{r:?}");
    }
    // The internal order is the trap frame's; check a few fields by name.
    assert_eq!(
        (regs.rbx, regs.rdx, regs.r8, regs.r15, regs.gs_base),
        (0x1004, 0x1006, 0x100A, 0x1011, 0x1013)
    );
}

#[test]
fn restart_and_suspend_rules() {
    let mut regs = Regs {
        fault_ip: 0x1000,
        next_ip: 0x1002,
        ..Regs::default()
    };
    let mut r = regs;
    r.restart();
    assert_eq!((r.fault_ip, r.next_ip), (0x1000, 0x1000));
    regs.stop_running();
    assert_eq!((regs.fault_ip, regs.next_ip), (0x1002, 0x1002));
}

#[test]
fn message_registers_are_r10_r8_r9_r15() {
    let mut regs = Regs::default();
    for i in 0..REGISTER_MRS {
        regs.set_message_register(i, 10 + i as u64);
    }
    assert_eq!((regs.r10, regs.r8, regs.r9, regs.r15), (10, 11, 12, 13));
    for i in 0..REGISTER_MRS {
        assert_eq!(regs.message_register(i), 10 + i as u64);
    }
    assert_eq!(regs.exit(), Exit::Iret);
    let mut sys = Regs {
        exit: Exit::Sysret as u64,
        ..regs
    };
    sys.set_message_register(0, 1);
    assert_eq!(sys.exit(), Exit::Sysret, "sysretq keeps the MR registers");
}

#[test]
fn exceptions_classify_as_docs_abi_says() {
    // UserException with code 0.
    for v in [0u8, 1, 3, 4, 5, 6, 7, 16, 19] {
        assert_eq!(
            Fault::from_exception(v, 0x55, 0x66),
            Some(Fault::UserException {
                number: v as u64,
                code: 0
            }),
            "vector {v}"
        );
    }
    // UserException with the error code.
    for v in [10u8, 11, 12, 13] {
        assert_eq!(
            Fault::from_exception(v, 0x55, 0x66),
            Some(Fault::UserException {
                number: v as u64,
                code: 0x55
            }),
            "vector {v}"
        );
    }
    // `int 0x80` from ring 3 arrives as #GP with code 8n + 2.
    assert_eq!(
        Fault::from_exception(13, 8 * 0x80 + 2, 0),
        Some(Fault::UserException {
            number: 13,
            code: 0x402
        })
    );
    assert_eq!(
        Fault::from_exception(14, 0x15, 0xdead_b000),
        Some(Fault::VmFault {
            addr: 0xdead_b000,
            fsr: 0x15
        })
    );
    // Never a user fault: NMI, #DF, #MC, the vectors that cannot occur,
    // and every interrupt vector.
    for v in [
        2u8, 8, 9, 15, 17, 18, 20, 21, 22, 28, 29, 30, 31, 32, 0x30, 0xFD, 0xFF,
    ] {
        assert_eq!(Fault::from_exception(v, 0, 0), None, "vector {v}");
    }
}

/// One fault of every kind, with every lookup failure.
fn faults() -> Vec<Fault> {
    let failures = [
        LookupFailure::InvalidRoot,
        LookupFailure::MissingCapability { bits_left: 64 },
        LookupFailure::DepthMismatch {
            bits_left: 3,
            bits_found: 12,
        },
        LookupFailure::GuardMismatch {
            bits_left: 60,
            guard: u64::MAX >> 6,
            guard_size: 58,
        },
    ];
    let mut v: Vec<Fault> = failures
        .into_iter()
        .enumerate()
        .map(|(i, failure)| Fault::CapFault {
            addr: u64::MAX - i as u64,
            in_recv_phase: i % 2 == 1,
            failure,
        })
        .collect();
    v.extend([
        Fault::UnknownSyscall { number: u64::MAX },
        Fault::UnknownSyscall { number: 0 },
        Fault::UserException {
            number: 13,
            code: 0x402,
        },
        Fault::VmFault {
            addr: 0x7FFF_FFFF_F000,
            fsr: 0x15,
        },
    ]);
    v
}

#[test]
fn fault_records_round_trip() {
    for f in faults() {
        let w = f.to_words();
        assert_eq!(w[0], f.label());
        assert_eq!(Fault::from_words(w), Some(f), "{f:?}");
    }
    // An empty record, and records no writer makes, are no fault.
    assert_eq!(Fault::from_words([0; FAULT_WORDS]), None);
    for label in [4, 6, u64::MAX] {
        assert_eq!(Fault::from_words([label, 1, 2, 3, 4, 5, 6]), None);
    }
    assert_eq!(Fault::from_words([1, 0, 0, 9, 0, 0, 0]), None);
    assert_eq!(Fault::from_words([1, 0, 0, 2, 1 << 32, 0, 0]), None);
}

/// Registers with a distinct value in every word.
fn distinct() -> Regs {
    Regs {
        r15: 15,
        r14: 14,
        r13: 13,
        r12: 12,
        r11: 11,
        r10: 10,
        r9: 9,
        r8: 8,
        rbp: 0xBB,
        rdi: 0xD1,
        rsi: 0x51,
        rdx: 0xD0,
        rcx: 0xC0,
        rbx: 0xB0,
        rax: 0xA0,
        rsp: 0x7000,
        rflags: 0x246,
        fault_ip: 0x4000,
        next_ip: 0x4002,
        fs_base: 0xF5,
        gs_base: 0x65,
        error: 0xEE,
        exit: Exit::Sysret as u64,
        pad: 0,
    }
}

#[test]
fn fault_messages_carry_the_abi_words() {
    let regs = distinct();
    let m = fault_message(
        &Fault::CapFault {
            addr: 0x99,
            in_recv_phase: true,
            failure: LookupFailure::GuardMismatch {
                bits_left: 60,
                guard: 5,
                guard_size: 3,
            },
        },
        &regs,
    );
    assert_eq!((m.label, m.mrs()), (1, &[0x4000, 0x99, 1, 4, 60, 5, 3][..]));
    let m = fault_message(
        &Fault::CapFault {
            addr: 0x99,
            in_recv_phase: false,
            failure: LookupFailure::InvalidRoot,
        },
        &regs,
    );
    assert_eq!((m.label, m.mrs()), (1, &[0x4000, 0x99, 0, 1][..]));
    let m = fault_message(&Fault::UnknownSyscall { number: 0x77 }, &regs);
    assert_eq!(m.label, 2);
    assert_eq!(
        m.mrs(),
        &[
            0xA0, 0xB0, 0xC0, 0xD0, 0x51, 0xD1, 0xBB, 8, 9, 10, 11, 12, 13, 14, 15, 0x4000, 0x7000,
            0x246, 0x77
        ][..]
    );
    let m = fault_message(&Fault::UserException { number: 6, code: 0 }, &regs);
    assert_eq!((m.label, m.mrs()), (3, &[0x4000, 0x7000, 0x246, 6, 0][..]));
    // The prefetch flag is the error code's bit 4.
    for (fsr, prefetch) in [(0x15, 1), (0x05, 0), (0x10, 1), (0, 0)] {
        let m = fault_message(&Fault::VmFault { addr: 0x1234, fsr }, &regs);
        assert_eq!(
            (m.label, m.mrs()),
            (5, &[0x4000, 0x1234, prefetch, fsr][..])
        );
    }
    // CapFault's length is 4 to 7, the others fixed.
    for f in faults() {
        let n = fault_message(&f, &regs).length;
        match f {
            Fault::CapFault { failure, .. } => assert_eq!(n, 3 + failure.words().1),
            Fault::UnknownSyscall { .. } => assert_eq!(n, 19),
            Fault::UserException { .. } => assert_eq!(n, 5),
            Fault::VmFault { .. } => assert_eq!(n, 4),
        }
    }
}

#[test]
fn a_fault_reply_sets_only_the_registers_its_type_names() {
    let regs = distinct();
    let words: Vec<u64> = (0..30).map(|i| 0x100 + i).collect();
    // CapFault and VMFault replies set nothing, whatever they carry.
    for f in [
        Fault::CapFault {
            addr: 0,
            in_recv_phase: false,
            failure: LookupFailure::InvalidRoot,
        },
        Fault::VmFault { addr: 0, fsr: 0 },
    ] {
        for label in [0, 1, u64::MAX] {
            let mut r = regs;
            let outcome = fault_reply(&f, label, &words, &mut r);
            assert_eq!(r, regs, "{f:?}");
            let expect = if label == 0 {
                FaultOutcome::Restart
            } else {
                FaultOutcome::Inactive
            };
            assert_eq!(outcome, expect);
        }
    }
    // UnknownSyscall: the first min(length, 18), in message order, whatever
    // the label; MR18 (the number) is never read.
    let f = Fault::UnknownSyscall { number: 1 };
    for len in [0, 1, 4, 15, 16, 17, 18, 19, 30] {
        for label in [0, 9] {
            let mut r = regs;
            fault_reply(&f, label, &words[..len], &mut r);
            let mut expect = regs;
            for (i, reg) in UNKNOWN_SYSCALL_REGS.iter().enumerate().take(len) {
                expect.set_user(*reg, words[i]);
            }
            assert_eq!(r, expect, "length {len}");
            assert_eq!(r.exit() == Exit::Iret, len > 0);
        }
    }
    let mut r = regs;
    fault_reply(&f, 0, &words[..18], &mut r);
    assert_eq!((r.rax, r.r15), (0x100, 0x10E));
    assert_eq!((r.fault_ip, r.next_ip), (0x10F, 0x10F));
    assert_eq!((r.rsp, r.rflags), (0x110, 0x202 | (0x111 & 0x0CD5)));
    assert_eq!((r.fs_base, r.gs_base, r.error), (0xF5, 0x65, 0xEE));
    // UserException: rip, rsp, rflags.
    let f = Fault::UserException { number: 3, code: 0 };
    for len in 0..6 {
        let mut r = regs;
        assert_eq!(
            fault_reply(&f, 2, &words[..len], &mut r),
            FaultOutcome::Inactive
        );
        let mut expect = regs;
        for (i, reg) in USER_EXCEPTION_REGS.iter().enumerate().take(len) {
            expect.set_user(*reg, words[i]);
        }
        assert_eq!(r, expect, "length {len}");
    }
}

#[test]
fn fault_reply_values_are_sanitised() {
    let mut r = distinct();
    let f = Fault::UserException { number: 6, code: 0 };
    fault_reply(&f, 0, &[FIRST_HIGH, FIRST_HOLE, u64::MAX], &mut r);
    assert_eq!((r.fault_ip, r.next_ip, r.rsp, r.rflags), (0, 0, 0, 0x0ED7));
    let mut r = distinct();
    let mut words = [0u64; 18];
    words[15] = LAST_LOW;
    words[16] = u64::MAX;
    words[17] = 1 << 9;
    fault_reply(&Fault::UnknownSyscall { number: 0 }, 0, &words, &mut r);
    assert_eq!((r.fault_ip, r.rsp, r.rflags), (LAST_LOW, 0, 0x202));
}

#[test]
fn a_handler_emulating_a_syscall_adds_two_to_the_ip() {
    // The thread's `syscall` at 0x4000 named no system call. The handler
    // replies with the message, `ip` + 2 and a result in rax; the thread
    // restarts after the `syscall`.
    let regs = distinct();
    let f = Fault::UnknownSyscall { number: 99 };
    let m = fault_message(&f, &regs);
    let mut reply = m.words;
    reply[0] = 42;
    reply[15] += 2;
    let mut r = regs;
    assert_eq!(
        fault_reply(&f, 0, &reply[..18], &mut r),
        FaultOutcome::Restart
    );
    r.restart();
    assert_eq!((r.next_ip, r.rax), (0x4002, 42));
}
