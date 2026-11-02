//! Kernel entry from ring 3 and exit to it, the host-testable part
//! (`docs/design.md`, "Kernel entry and exit"; ADR 0008).
//!
//! - The syscall MSR values, [`STAR`] and [`FMASK`], and the RFLAGS bits.
//! - [`classify`]: what a ring-3 entry is, from the trap frame the stubs
//!   built: a system call, an exception the thread caused, an interrupt,
//!   or a vector that must never arrive from ring 3.
//! - [`save`]: the frame copied into the thread's [`Regs`], with `fault_ip`,
//!   `next_ip` and `exit` set for the kind of entry.
//! - [`exit_frame`]: the frame the exit path pops, built from [`Regs`], and
//!   whether it may leave by `sysretq` or must use `iretq`. Its rules make
//!   both instructions safe whatever the registers hold: RIP and RSP below
//!   2^47, constant user selectors, RFLAGS masked, and `sysretq` only for a
//!   thread that entered by `syscall`, whose registers nothing has written
//!   since, and whose return address is below 2^47, so RCX is never
//!   non-canonical (the Intel `sysretq` #GP in ring 0 on the user's stack,
//!   [H9]).
//!
//! `arch` runs the instructions; everything they decide is here.

use crate::regs::{Exit, Regs};
use crate::trap::{self, Kind, TrapFrame, USER_CS, USER_DS};

// ---------------------------------------------------------------------------
// RFLAGS
// ---------------------------------------------------------------------------

/// RFLAGS bits (SDM vol. 1, 3.4.3).
pub mod rflags {
    pub const CF: u64 = 1 << 0;
    /// Bit 1, which always reads as 1.
    pub const FIXED: u64 = 1 << 1;
    pub const PF: u64 = 1 << 2;
    pub const AF: u64 = 1 << 4;
    pub const ZF: u64 = 1 << 6;
    pub const SF: u64 = 1 << 7;
    pub const TF: u64 = 1 << 8;
    pub const IF: u64 = 1 << 9;
    pub const DF: u64 = 1 << 10;
    pub const OF: u64 = 1 << 11;
    /// The two-bit I/O privilege level.
    pub const IOPL: u64 = 3 << 12;
    pub const NT: u64 = 1 << 14;
    pub const RF: u64 = 1 << 16;
    pub const VM: u64 = 1 << 17;
    pub const AC: u64 = 1 << 18;
    pub const VIF: u64 = 1 << 19;
    pub const VIP: u64 = 1 << 20;
    pub const ID: u64 = 1 << 21;
}

/// `IA32_FMASK`: the RFLAGS bits `syscall` clears, seL4's
/// `FLAGS_SYSCALL_MASK`. The kernel runs with interrupts off (IF), string
/// operations upward (DF), no single step (TF), SMAP in force (AC), and no
/// task return on `iretq` (NT); the rest gives a defined state.
pub const FMASK: u64 = rflags::CF
    | rflags::PF
    | rflags::AF
    | rflags::ZF
    | rflags::SF
    | rflags::TF
    | rflags::IF
    | rflags::DF
    | rflags::OF
    | rflags::IOPL
    | rflags::NT
    | rflags::RF
    | rflags::AC
    | rflags::ID;

/// The RFLAGS bits a thread keeps across an exit: those ring 3 can set
/// itself with `popfq` (CF, PF, AF, ZF, SF, TF, DF, OF, AC, ID). IOPL, NT,
/// RF, VM, VIF and VIP are cleared; [`EXIT_RFLAGS_SET`] is forced on.
pub const EXIT_RFLAGS_KEEP: u64 = rflags::CF
    | rflags::PF
    | rflags::AF
    | rflags::ZF
    | rflags::SF
    | rflags::TF
    | rflags::DF
    | rflags::OF
    | rflags::AC
    | rflags::ID;

/// The RFLAGS bits every exit sets: bit 1 and IF.
pub const EXIT_RFLAGS_SET: u64 = rflags::FIXED | rflags::IF;

const _: () = assert!(FMASK == 0x0025_7FD5);
const _: () = assert!(EXIT_RFLAGS_KEEP == 0x0024_0DD5);
const _: () = assert!(EXIT_RFLAGS_SET == 0x0202);

/// A thread's RFLAGS as it runs after an exit: `(v & 0x0024_0DD5) | 0x0202`.
pub const fn exit_rflags(v: u64) -> u64 {
    (v & EXIT_RFLAGS_KEEP) | EXIT_RFLAGS_SET
}

// ---------------------------------------------------------------------------
// The syscall MSRs
// ---------------------------------------------------------------------------

/// `IA32_STAR`: `syscall` loads CS = `STAR[47:32]` and SS = that + 8;
/// `sysretq` loads SS = `STAR[63:48]` + 8 and CS = `STAR[63:48]` + 16, each
/// with RPL 3. `0x13` names kernel data with RPL 3, so the two land on user
/// data and user code ("Rings and segments").
pub const STAR: u64 = (0x13 << 48) | ((trap::KERNEL_CS as u64) << 32);

const _: () = assert!(STAR == 0x0013_0008_0000_0000);

/// The selectors `syscall` loads, CS and SS, from [`STAR`].
pub const fn syscall_selectors(star: u64) -> (u16, u16) {
    let cs = (star >> 32) as u16;
    (cs, cs + 8)
}

/// The selectors `sysretq` loads, CS and SS, from [`STAR`], RPL 3 forced.
pub const fn sysret_selectors(star: u64) -> (u16, u16) {
    let base = (star >> 48) as u16;
    ((base + 16) | 3, (base + 8) | 3)
}

// ---------------------------------------------------------------------------
// Entry
// ---------------------------------------------------------------------------

/// The `vector` word `syscall_entry` pushes: past every IDT vector, so a
/// frame says how it was made.
pub const SYSCALL_VECTOR: u64 = 256;

/// The length of the `syscall` instruction, `0F 05`: `fault_ip` is the
/// return address less this.
pub const SYSCALL_LEN: u64 = 2;

/// 2^47, the first address past the lower half. Every user RIP, RSP, FS
/// base and GS base the kernel installs lies below it.
pub const LOWER_HALF_END: u64 = 0x0000_8000_0000_0000;

/// `v` if it is below 2^47, else 0: the sanitiser's rule for `rip`, `rsp`,
/// `fs_base` and `gs_base` ("User register set and sanitising").
pub const fn lower_half(v: u64) -> u64 {
    if v < LOWER_HALF_END { v } else { 0 }
}

/// How a thread entered the kernel from ring 3.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum UserEntry {
    /// `syscall`; the number is in `rdx`.
    Syscall,
    /// A CPU exception the thread caused, which becomes a fault ("Fault
    /// types and sources"). `error` is the CPU's error code, or 0 for a
    /// vector without one; `cr2` is CR2 for `#PF`, 0 for any other vector.
    Exception { vector: u8, error: u64, cr2: u64 },
    /// An interrupt, vector 32 or more, taken while the thread ran.
    Interrupt(u8),
    /// A vector that never comes from a thread: NMI, `#DF` and `#MC` (whose
    /// stubs never reach the ring-3 path), a vector that cannot occur here
    /// (only an injected MSI raises one), or a frame that is not a ring-3
    /// frame at all. The kernel panics.
    Fatal,
}

/// What the ring-3 frame `frame` is. `cr2` is CR2 as the handler read it
/// first; it is kept only for `#PF`.
pub fn classify(frame: &TrapFrame, cr2: u64) -> UserEntry {
    if frame.ring() != 3 {
        return UserEntry::Fatal;
    }
    if frame.vector == SYSCALL_VECTOR {
        return UserEntry::Syscall;
    }
    let Ok(vector) = u8::try_from(frame.vector) else {
        return UserEntry::Fatal;
    };
    match trap::kind(vector) {
        Kind::Exception => UserEntry::Exception {
            vector,
            error: frame.error,
            cr2: if vector == trap::PAGE_FAULT { cr2 } else { 0 },
        },
        Kind::Fatal | Kind::CannotOccur => UserEntry::Fatal,
        Kind::Pic { .. }
        | Kind::Device { .. }
        | Kind::Ipi
        | Kind::Timer
        | Kind::ApicError
        | Kind::Spurious => UserEntry::Interrupt(vector),
    }
}

/// Copies the ring-3 frame `frame` into the thread's registers (`docs/
/// design.md`, Entry): the general registers, `rsp` and `rflags`; then
///
/// - for `syscall`: `next_ip` = the return address (RCX), `fault_ip` = the
///   `syscall` instruction, two bytes before it, `error` = 0, and `exit` =
///   `Sysret`;
/// - for an exception or interrupt: `next_ip` = `fault_ip` = the RIP the CPU
///   pushed, `error` = the error code, and `exit` = `Iret`, since RCX and
///   R11 hold the thread's own values.
///
/// `fs_base` and `gs_base` are left alone: they live in MSRs while the
/// thread runs, and a switch away reads them back.
pub fn save(frame: &TrapFrame, regs: &mut Regs) {
    regs.r15 = frame.r15;
    regs.r14 = frame.r14;
    regs.r13 = frame.r13;
    regs.r12 = frame.r12;
    regs.r11 = frame.r11;
    regs.r10 = frame.r10;
    regs.r9 = frame.r9;
    regs.r8 = frame.r8;
    regs.rbp = frame.rbp;
    regs.rdi = frame.rdi;
    regs.rsi = frame.rsi;
    regs.rdx = frame.rdx;
    regs.rcx = frame.rcx;
    regs.rbx = frame.rbx;
    regs.rax = frame.rax;
    regs.rsp = frame.rsp;
    regs.rflags = frame.rflags;
    regs.next_ip = frame.rip;
    if frame.vector == SYSCALL_VECTOR {
        regs.fault_ip = frame.rip.wrapping_sub(SYSCALL_LEN);
        regs.error = 0;
        regs.exit = Exit::Sysret as u64;
    } else {
        regs.fault_ip = frame.rip;
        regs.error = frame.error;
        regs.exit = Exit::Iret as u64;
    }
}

// ---------------------------------------------------------------------------
// Exit
// ---------------------------------------------------------------------------

/// The frame the exit path pops for a thread with registers `regs`, and
/// which instruction leaves (`docs/design.md`, Exit):
///
/// - the general registers from `regs`; `vector` and `error` 0;
/// - `rip` = `next_ip` and `rsp` = `rsp`, each 0 if at or above 2^47;
/// - `rflags` = `(rflags & 0x0024_0DD5) | 0x0202`;
/// - `cs` = `0x23` and `ss` = `0x1B`, never from the TCB;
/// - `Sysret` only if `regs.exit()` is `Sysret` and `next_ip` is below
///   2^47, else `Iret`. A return address at or above 2^47 (a `syscall` in
///   the last bytes of the lower half, which `USER_TOP` keeps unmapped)
///   leaves by `iretq` to RIP 0, so RCX is never non-canonical at a
///   `sysretq` even if a writer forgot to sanitise.
///
/// On the `Sysret` path the frame's `rcx` and `r11` are the RIP and RFLAGS
/// `sysretq` loads into them, so the frame is exactly the thread's state
/// after the exit either way.
pub fn exit_frame(regs: &Regs) -> (TrapFrame, Exit) {
    let rip = lower_half(regs.next_ip);
    let rflags = exit_rflags(regs.rflags);
    let path = match regs.exit() {
        Exit::Sysret if regs.next_ip < LOWER_HALF_END => Exit::Sysret,
        _ => Exit::Iret,
    };
    let (rcx, r11) = match path {
        Exit::Sysret => (rip, rflags),
        Exit::Iret => (regs.rcx, regs.r11),
    };
    let frame = TrapFrame {
        r15: regs.r15,
        r14: regs.r14,
        r13: regs.r13,
        r12: regs.r12,
        r11,
        r10: regs.r10,
        r9: regs.r9,
        r8: regs.r8,
        rbp: regs.rbp,
        rdi: regs.rdi,
        rsi: regs.rsi,
        rdx: regs.rdx,
        rcx,
        rbx: regs.rbx,
        rax: regs.rax,
        vector: 0,
        error: 0,
        rip,
        cs: USER_CS as u64,
        rflags,
        rsp: lower_half(regs.rsp),
        ss: USER_DS as u64,
    };
    (frame, path)
}

/// Whether a ring-0 trap is the single-step `#DB` a `syscall` executed
/// with TF set may raise on the first instruction of `syscall_entry`, at
/// `syscall_entry`, before its `swapgs` ("NMI, double fault, machine check
/// and debug"). Such a trap returns at once, as does
/// [`single_step_into_breakpoint_stub`]'s; every other ring-0 `#DB`
/// panics.
pub fn single_step_into_syscall_entry(frame: &TrapFrame, syscall_entry: u64) -> bool {
    frame.vector == u64::from(trap::DEBUG) && frame.ring() == 0 && frame.rip == syscall_entry
}

/// Whether a ring-0 trap is the single-step `#DB` that a thread's `mov ss`
/// or `pop ss` with TF set defers past a following `int3`: the CPU
/// delivers the `#BP` first, pushing its frame on the kernel stack and
/// clearing TF, then the `#DB` on the first instruction of the `#BP` stub,
/// `stubs[BREAKPOINT]` (CVE-2018-8897's mechanism;
/// `docs/redteam/m5-movss-db.md`). Such a trap returns at once, as at
/// `syscall_entry`, with its saved state unchanged: the `#BP` stub then
/// runs as if no trap had been taken, on its own frame, whose ring-3 CS
/// gives it its `swapgs`.
///
/// `#BP` is the only gate with DPL 3, so it is the only stub an instruction
/// after `mov ss` can enter directly; a ring-0 `#DB` on any other stub
/// panics. The `#DB` stub's own above all: a nested `#DB` there is
/// delivered on IST4, over the frame of the `#DB` it interrupted.
pub fn single_step_into_breakpoint_stub(frame: &TrapFrame, stubs: &[u64; 256]) -> bool {
    frame.vector == u64::from(trap::DEBUG)
        && frame.ring() == 0
        && frame.rip == stubs[usize::from(trap::BREAKPOINT)]
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::trap::{FRAME_WORDS, KERNEL_DS};
    use proptest::prelude::*;

    /// A frame whose every word is distinct, for `vector`, from ring 3.
    fn user_frame(vector: u64, rip: u64) -> TrapFrame {
        TrapFrame {
            r15: 0xF15,
            r14: 0xF14,
            r13: 0xF13,
            r12: 0xF12,
            r11: 0x246,
            r10: 0xF10,
            r9: 0xF09,
            r8: 0xF08,
            rbp: 0xB0,
            rdi: 0xD1,
            rsi: 0x51,
            rdx: 0xD0,
            rcx: rip,
            rbx: 0xB1,
            rax: 0xA0,
            vector,
            error: if vector == SYSCALL_VECTOR { 0 } else { 0xE0 },
            rip,
            cs: USER_CS.into(),
            rflags: 0x246,
            rsp: 0x7FF0,
            ss: USER_DS.into(),
        }
    }

    /// Registers with every word distinct and the given exit.
    fn regs(next_ip: u64, rsp: u64, exit: Exit) -> Regs {
        Regs {
            r15: 15,
            r14: 14,
            r13: 13,
            r12: 12,
            r11: 11,
            r10: 10,
            r9: 9,
            r8: 8,
            rbp: 0xB9,
            rdi: 0xD1,
            rsi: 0x51,
            rdx: 0xD0,
            rcx: 0xC0,
            rbx: 0xB1,
            rax: 0xA0,
            rsp,
            rflags: 0x202,
            fault_ip: next_ip.wrapping_sub(2),
            next_ip,
            fs_base: 0xF5,
            gs_base: 0x65,
            error: 0,
            exit: exit as u64,
            pad: 0,
        }
    }

    #[test]
    fn star_gives_the_gdt_selectors() {
        assert_eq!(syscall_selectors(STAR), (trap::KERNEL_CS, KERNEL_DS));
        assert_eq!(sysret_selectors(STAR), (USER_CS, USER_DS));
        // The kernel data and user code descriptors follow kernel code and
        // user data in the GDT, as both instructions require.
        assert_eq!(KERNEL_DS, trap::KERNEL_CS + 8);
        assert_eq!(USER_CS & !3, (USER_DS & !3) + 8);
    }

    #[test]
    fn fmask_clears_what_the_kernel_relies_on() {
        use rflags::*;
        for bit in [IF, TF, DF, AC, NT, IOPL, RF] {
            assert_eq!(FMASK & bit, bit, "{bit:#x}");
        }
        // Bit 1 reads as 1 whatever the mask; VM is meaningless in long mode.
        assert_eq!(FMASK & (FIXED | VM | VIF | VIP), 0);
    }

    #[test]
    fn exit_rflags_keep_only_what_ring_3_may_set() {
        use rflags::*;
        assert_eq!(exit_rflags(0), 0x202);
        assert_eq!(exit_rflags(u64::MAX), 0x0024_0FD7);
        for bit in [IOPL, NT, RF, VM, VIF, VIP] {
            assert_eq!(exit_rflags(bit) & bit, 0, "{bit:#x} must be cleared");
        }
        for bit in [CF, PF, AF, ZF, SF, TF, DF, OF, AC, ID] {
            assert_eq!(exit_rflags(bit) & bit, bit, "{bit:#x} must be kept");
        }
        // Applied after the register-write sanitiser, it changes nothing.
        for v in [0, 0x0CD5, u64::MAX, 0x3202, 0x4246] {
            let sanitised = (v & 0x0CD5) | 0x0202;
            assert_eq!(exit_rflags(sanitised), sanitised);
        }
    }

    #[test]
    fn lower_half_at_the_boundaries() {
        assert_eq!(lower_half(0), 0);
        assert_eq!(lower_half((1 << 47) - 1), (1 << 47) - 1);
        assert_eq!(lower_half(1 << 47), 0);
        // 2^64 - 2^47: the first canonical upper-half address.
        assert_eq!(lower_half(0xFFFF_8000_0000_0000), 0);
        assert_eq!(lower_half(u64::MAX), 0);
    }

    #[test]
    fn a_syscall_frame_saves_as_a_sysret_entry() {
        let f = user_frame(SYSCALL_VECTOR, 0x40_1002);
        assert_eq!(classify(&f, 0xDEAD), UserEntry::Syscall);
        let mut r = Regs {
            fs_base: 0xF5,
            gs_base: 0x65,
            exit: Exit::Iret as u64,
            ..Regs::default()
        };
        save(&f, &mut r);
        assert_eq!(r.next_ip, 0x40_1002);
        assert_eq!(r.fault_ip, 0x40_1000);
        assert_eq!(r.exit(), Exit::Sysret);
        assert_eq!((r.rsp, r.rflags, r.error), (0x7FF0, 0x246, 0));
        assert_eq!((r.fs_base, r.gs_base), (0xF5, 0x65), "bases untouched");
        assert_eq!(
            [
                r.r15, r.r10, r.r9, r.r8, r.rdi, r.rsi, r.rdx, r.rcx, r.r11, r.rax
            ],
            [
                0xF15, 0xF10, 0xF09, 0xF08, 0xD1, 0x51, 0xD0, 0x40_1002, 0x246, 0xA0
            ]
        );
    }

    #[test]
    fn exceptions_and_interrupts_save_as_iret_entries() {
        let f = user_frame(u64::from(trap::PAGE_FAULT), 0x40_1234);
        assert_eq!(
            classify(&f, 0x60_0008),
            UserEntry::Exception {
                vector: 14,
                error: 0xE0,
                cr2: 0x60_0008
            }
        );
        let mut r = Regs {
            exit: Exit::Sysret as u64,
            ..Regs::default()
        };
        save(&f, &mut r);
        assert_eq!((r.next_ip, r.fault_ip), (0x40_1234, 0x40_1234));
        assert_eq!(r.exit(), Exit::Iret);
        assert_eq!((r.error, r.rcx, r.r11), (0xE0, 0x40_1234, 0x246));

        // CR2 is kept for #PF only.
        let gp = user_frame(13, 0x40_1000);
        assert_eq!(
            classify(&gp, 0x1234),
            UserEntry::Exception {
                vector: 13,
                error: 0xE0,
                cr2: 0
            }
        );
        let timer = user_frame(u64::from(trap::TIMER), 0x40_1000);
        assert_eq!(classify(&timer, 0), UserEntry::Interrupt(trap::TIMER));
        save(&timer, &mut r);
        assert_eq!(
            (r.next_ip, r.fault_ip, r.exit()),
            (0x40_1000, 0x40_1000, Exit::Iret)
        );
    }

    #[test]
    fn every_vector_classifies_by_the_vector_map() {
        for v in 0..=255u8 {
            let f = user_frame(u64::from(v), 0x1000);
            let e = classify(&f, 7);
            match trap::kind(v) {
                Kind::Exception => assert!(
                    matches!(e, UserEntry::Exception { vector, .. } if vector == v),
                    "{v}"
                ),
                Kind::Fatal | Kind::CannotOccur => assert_eq!(e, UserEntry::Fatal, "{v}"),
                _ => assert_eq!(e, UserEntry::Interrupt(v), "{v}"),
            }
        }
        // NMI, #DF, #MC and the vectors that cannot occur.
        let fatal: std::vec::Vec<u8> = (0..32)
            .filter(|&v| classify(&user_frame(u64::from(v), 0), 0) == UserEntry::Fatal)
            .collect();
        assert_eq!(
            fatal,
            [
                2, 8, 9, 15, 17, 18, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31
            ]
        );
        for vector in [257, 1 << 32, u64::MAX] {
            assert_eq!(classify(&user_frame(vector, 0), 0), UserEntry::Fatal);
        }
    }

    #[test]
    fn a_ring_0_frame_is_not_a_user_entry() {
        let mut f = user_frame(SYSCALL_VECTOR, 0x1000);
        f.cs = trap::KERNEL_CS.into();
        assert_eq!(classify(&f, 0), UserEntry::Fatal);
    }

    #[test]
    fn exit_frame_fixes_the_selectors_and_masks_rflags() {
        let mut r = regs(0x40_1000, 0x40_2000, Exit::Iret);
        r.rflags = u64::MAX;
        let (f, path) = exit_frame(&r);
        assert_eq!(path, Exit::Iret);
        assert_eq!((f.cs, f.ss), (0x23, 0x1B));
        assert_eq!(f.rflags, 0x0024_0FD7);
        assert_eq!((f.rip, f.rsp), (0x40_1000, 0x40_2000));
        assert_eq!((f.vector, f.error), (0, 0));
        // On iretq every general register is the thread's own.
        assert_eq!(
            [f.r15, f.r14, f.r13, f.r12, f.r11, f.r10, f.r9, f.r8],
            [15, 14, 13, 12, 11, 10, 9, 8]
        );
        assert_eq!(
            [f.rbp, f.rdi, f.rsi, f.rdx, f.rcx, f.rbx, f.rax],
            [0xB9, 0xD1, 0x51, 0xD0, 0xC0, 0xB1, 0xA0]
        );
    }

    #[test]
    fn sysret_frames_carry_rip_and_rflags_in_rcx_and_r11() {
        let (f, path) = exit_frame(&regs(0x40_1002, 0x40_2000, Exit::Sysret));
        assert_eq!(path, Exit::Sysret);
        assert_eq!((f.rcx, f.r11), (0x40_1002, 0x202));
        assert_eq!((f.rip, f.rflags), (0x40_1002, 0x202));
    }

    /// The design's table: return addresses at 2^47 - 1, 2^47 and
    /// 2^64 - 2^47, on both paths.
    #[test]
    fn exit_frame_at_the_lower_half_boundary() {
        let cases = [
            // (next_ip, recorded exit, rip, path)
            ((1 << 47) - 1, Exit::Sysret, (1 << 47) - 1, Exit::Sysret),
            ((1 << 47) - 1, Exit::Iret, (1 << 47) - 1, Exit::Iret),
            (1 << 47, Exit::Sysret, 0, Exit::Iret),
            (1 << 47, Exit::Iret, 0, Exit::Iret),
            (0xFFFF_8000_0000_0000, Exit::Sysret, 0, Exit::Iret),
            (0xFFFF_8000_0000_0000, Exit::Iret, 0, Exit::Iret),
            (u64::MAX, Exit::Sysret, 0, Exit::Iret),
            (0, Exit::Sysret, 0, Exit::Sysret),
        ];
        for (next_ip, exit, rip, path) in cases {
            let (f, p) = exit_frame(&regs(next_ip, 0x1000, exit));
            assert_eq!((f.rip, p), (rip, path), "next_ip {next_ip:#x}, {exit:?}");
            if p == Exit::Sysret {
                assert_eq!(f.rcx, f.rip);
            }
        }
        for (rsp, want) in [
            ((1 << 47) - 1, (1 << 47) - 1),
            (1 << 47, 0),
            (0xFFFF_8000_0000_0000, 0),
        ] {
            let (f, p) = exit_frame(&regs(0x1000, rsp, Exit::Sysret));
            assert_eq!(f.rsp, want, "rsp {rsp:#x}");
            // RSP plays no part in the choice: sysretq does not load it.
            assert_eq!(p, Exit::Sysret);
        }
    }

    #[test]
    fn a_non_sysret_exit_word_leaves_by_iretq() {
        for word in [Exit::Iret as u64, 2, 0x8000_0000_0000_0000, u64::MAX] {
            let mut r = regs(0x1000, 0x2000, Exit::Sysret);
            r.exit = word;
            if word != Exit::Sysret as u64 {
                assert_eq!(exit_frame(&r).1, Exit::Iret, "exit word {word:#x}");
            }
        }
    }

    #[test]
    fn single_step_into_syscall_entry_needs_db_ring_0_and_that_rip() {
        const ENTRY: u64 = 0xFFFF_FFFF_8000_1000;
        let mut f = user_frame(u64::from(trap::DEBUG), ENTRY);
        f.cs = trap::KERNEL_CS.into();
        assert!(single_step_into_syscall_entry(&f, ENTRY));
        assert!(!single_step_into_syscall_entry(&f, ENTRY + 1));
        let mut other = f;
        other.vector = u64::from(trap::BREAKPOINT);
        assert!(!single_step_into_syscall_entry(&other, ENTRY));
        let mut user = f;
        user.cs = USER_CS.into();
        assert!(!single_step_into_syscall_entry(&user, ENTRY));
    }

    #[test]
    fn single_step_into_breakpoint_stub_needs_db_ring_0_and_vector_3s_stub() {
        const ENTRY: u64 = 0xFFFF_FFFF_8000_1000;
        // Distinct stub addresses, 16 bytes apart as the kernel's are.
        let stubs: [u64; 256] = core::array::from_fn(|v| 0xFFFF_FFFF_8000_2000 + 16 * v as u64);
        let bp = stubs[usize::from(trap::BREAKPOINT)];
        // As the CPU leaves it: on the #BP frame at the top of the kernel
        // stack, with the null SS of a ring change.
        let mut f = user_frame(u64::from(trap::DEBUG), bp);
        f.cs = trap::KERNEL_CS.into();
        f.rsp = 0xFFFF_FFFF_8010_0000 - 40;
        f.ss = 0;
        assert!(single_step_into_breakpoint_stub(&f, &stubs));
        // Only vector 3's stub: never the #DB stub's own, whose IST4 frame
        // the nested #DB overwrote, nor #GP's, nor any other.
        for (v, &stub) in stubs.iter().enumerate() {
            let at = TrapFrame { rip: stub, ..f };
            assert_eq!(
                single_step_into_breakpoint_stub(&at, &stubs),
                v == usize::from(trap::BREAKPOINT),
                "a ring-0 #DB on vector {v}'s stub"
            );
        }
        for rip in [bp - 1, bp + 1, bp + 2, ENTRY] {
            let at = TrapFrame { rip, ..f };
            assert!(
                !single_step_into_breakpoint_stub(&at, &stubs),
                "rip {rip:#x}"
            );
        }
        // Only a #DB, and only from ring 0.
        for vector in (0..=255).filter(|&v| v != u64::from(trap::DEBUG)) {
            let other = TrapFrame { vector, ..f };
            assert!(
                !single_step_into_breakpoint_stub(&other, &stubs),
                "vector {vector}"
            );
        }
        let user = TrapFrame {
            cs: USER_CS.into(),
            ..f
        };
        assert!(!single_step_into_breakpoint_stub(&user, &stubs));
        // The syscall_entry rule does not take the stub either.
        assert!(!single_step_into_syscall_entry(&f, ENTRY));
    }

    #[test]
    fn the_frame_is_the_trap_frame() {
        assert_eq!(core::mem::size_of::<TrapFrame>(), FRAME_WORDS * 8);
    }

    /// A random word, half the time moved to one of the boundaries: just
    /// below or at 2^47, around 2^64 - 2^47, 0 or `u64::MAX`. A plain map
    /// over random words, which Miri runs far faster than `prop_oneof!`.
    fn word(x: u64) -> u64 {
        let d = (x >> 8) & 3;
        match x & 7 {
            0 => (1 << 47) - 2 + d,
            1 => 0xFFFF_8000_0000_0000 - 2 + d,
            2 => 0,
            3 => u64::MAX,
            _ => x,
        }
    }

    fn any_regs() -> impl Strategy<Value = Regs> {
        (any::<[u64; 16]>(), any::<[u64; 8]>())
            .prop_map(|(a, b)| (a.map(word), b.map(word)))
            .prop_map(|(a, b)| Regs {
                r15: a[0],
                r14: a[1],
                r13: a[2],
                r12: a[3],
                r11: a[4],
                r10: a[5],
                r9: a[6],
                r8: a[7],
                rbp: a[8],
                rdi: a[9],
                rsi: a[10],
                rdx: a[11],
                rcx: a[12],
                rbx: a[13],
                rax: a[14],
                rsp: a[15],
                rflags: b[0],
                fault_ip: b[1],
                next_ip: b[2],
                fs_base: b[3],
                gs_base: b[4],
                error: b[5],
                // Mostly one of the two real values.
                exit: match b[6] % 3 {
                    0 => Exit::Sysret as u64,
                    1 => Exit::Iret as u64,
                    _ => b[6],
                },
                pad: b[7],
            })
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

        /// Whatever a TCB holds, the exit is one both instructions can
        /// take without faulting in ring 0, and the thread runs on the
        /// user selectors with IF = 1, IOPL = 0 and NT = 0.
        #[test]
        fn every_exit_is_safe(r in any_regs()) {
            let (f, path) = exit_frame(&r);
            prop_assert!(f.rip < LOWER_HALF_END);
            prop_assert!(f.rsp < LOWER_HALF_END);
            prop_assert_eq!((f.cs, f.ss), (0x23, 0x1B));
            prop_assert_eq!(f.rflags & (rflags::IF | rflags::FIXED), rflags::IF | rflags::FIXED);
            prop_assert_eq!(f.rflags & !EXIT_RFLAGS_KEEP & !EXIT_RFLAGS_SET, 0);
            prop_assert_eq!(f.rflags & (rflags::IOPL | rflags::NT | rflags::RF | rflags::VM), 0);
            match path {
                Exit::Sysret => {
                    prop_assert_eq!(r.exit, Exit::Sysret as u64);
                    prop_assert!(r.next_ip < LOWER_HALF_END);
                    prop_assert_eq!(f.rcx, f.rip);
                    prop_assert_eq!(f.r11, f.rflags);
                }
                Exit::Iret => {
                    prop_assert!(r.exit != Exit::Sysret as u64 || r.next_ip >= LOWER_HALF_END);
                    prop_assert_eq!((f.rcx, f.r11), (r.rcx, r.r11));
                }
            }
            // The other general registers are always the thread's.
            prop_assert_eq!(
                [f.r15, f.r14, f.r13, f.r12, f.r10, f.r9, f.r8, f.rbp, f.rdi, f.rsi, f.rdx, f.rbx, f.rax],
                [r.r15, r.r14, r.r13, r.r12, r.r10, r.r9, r.r8, r.rbp, r.rdi, r.rsi, r.rdx, r.rbx, r.rax]
            );
            // RIP and RSP change only when they were outside the lower half.
            prop_assert_eq!(f.rip == r.next_ip, r.next_ip < LOWER_HALF_END);
            prop_assert_eq!(f.rsp == r.rsp, r.rsp < LOWER_HALF_END);
        }

        /// An exit followed at once by an interrupt, before the thread
        /// runs an instruction, saves back the registers the thread really
        /// had: the sanitised ones, and `rcx` and `r11` as `sysretq` left
        /// them.
        #[test]
        fn an_exit_then_an_interrupt_saves_what_the_thread_had(r in any_regs(), v in 32u8..=255) {
            let (mut f, _) = exit_frame(&r);
            f.vector = u64::from(v);
            prop_assert_eq!(classify(&f, 0), UserEntry::Interrupt(v));
            let mut back = r;
            save(&f, &mut back);
            prop_assert_eq!(exit_frame(&back), (TrapFrame { vector: 0, ..f }, Exit::Iret));
            prop_assert_eq!((back.fs_base, back.gs_base), (r.fs_base, r.gs_base));
        }

        /// A `syscall` saved and then exited unchanged returns to the next
        /// instruction by `sysretq`, with every register but RCX and R11
        /// as it was, and RCX the return address.
        #[test]
        fn a_syscall_round_trip_preserves_the_registers(
            r in any_regs(),
            rip in 2u64..LOWER_HALF_END,
        ) {
            let (mut f, _) = exit_frame(&r);
            f.vector = SYSCALL_VECTOR;
            f.error = 0;
            f.rip = rip;
            f.rcx = rip;
            f.r11 = f.rflags;
            let mut s = r;
            save(&f, &mut s);
            prop_assert_eq!((s.next_ip, s.fault_ip), (rip, rip - 2));
            let (out, path) = exit_frame(&s);
            prop_assert_eq!(path, Exit::Sysret);
            prop_assert_eq!(out, TrapFrame { vector: 0, ..f });
        }
    }
}
