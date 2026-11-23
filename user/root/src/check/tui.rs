//! The verdicts of `test=tui` and `test=nofb` (`docs/design.md`,
//! "Scenarios" under "Framebuffer, terminal and TUI"): BootInfo's
//! framebuffer as `fb` takes it, the lines root prints of the framebuffer,
//! the write-combining check, the servers, the frames' mappings, the
//! priorities, tui's report and term's `Stats`, and what the report, the
//! probes and the counts must hold; and the line root fails with for a
//! message on D that is not the report, a tui fault among them
//! (`test=tui_fault`).

use core::fmt;

use libsys::bootinfo::MAX_UNTYPED;
use libsys::proto::TermStats;
use libsys::{BootInfo, Error, SyscallError};

use crate::process::{Fault, fault_kind};

/// tui's badge on endpoint C, as console's client 5, and on endpoint D,
/// its report and fault endpoint.
pub const TUI_BADGE: u64 = 5;

/// What the `tui` scenario types for client 4, the focus keys excluded:
/// Down, Down, Enter, then `q`. tui reports the first 255 bytes it read
/// from term, and term passes keys through as typed, so it reports
/// exactly these.
pub const TYPED: &[u8] = b"\x1b[B\x1b[B\rq";

/// The line `test=nofb` reads as client 1: the harness types
/// `\x144abc\e[A\x141hi\r`, and the bytes for client 4 wait in its raw
/// queue.
pub const NOFB_LINE: &str = "hi";

/// BootInfo's framebuffer as `fb`'s plain numbers: its fields, and the
/// descriptors of `framebuffer_untyped`, the leading part of `untyped`,
/// into `out`; returns how many.
pub fn framebuffer(bi: &BootInfo, out: &mut [fb::Untyped; MAX_UNTYPED]) -> (fb::Fields, usize) {
    let f = bi.framebuffer;
    let fields = fb::Fields {
        base: f.base,
        size: f.size,
        width: f.width,
        height: f.height,
        stride: f.stride,
        format: f.format.0,
    };
    let n = (bi.framebuffer_untyped.len() as usize).min(bi.untyped().len());
    for (o, d) in out.iter_mut().zip(&bi.untyped()[..n]) {
        *o = fb::Untyped::new(d.paddr, d.size_bits, d.device());
    }
    (fields, n)
}

/// `fb: <the plan>; <cols>x<rows> cells`: the framebuffer, its frames
/// and term's grid on it.
pub struct FbLine<'a, 'b>(pub &'a fb::Plan<'b>);

impl fmt::Display for FbLine<'_, '_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let (cols, rows) = term::cells(self.0.geometry());
        write!(f, "fb: {}; {cols}x{rows} cells", self.0)
    }
}

/// `fb: none: <why>`.
pub struct NoFb(pub fb::Unusable);

impl fmt::Display for NoFb {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "fb: none: {}", self.0)
    }
}

/// Microseconds in `ticks` of a TSC at `hz`; 0 if `hz` is.
pub fn micros(ticks: u64, hz: u64) -> u64 {
    if hz == 0 {
        return 0;
    }
    (u128::from(ticks) * 1_000_000 / u128::from(hz)) as u64
}

/// The write-combining check's line [H10]: `fb: full clear: uncached <n>
/// us, write-combining <m> us`, from the two clears' TSC ticks.
pub struct Clear {
    pub uncached: u64,
    pub write_combining: u64,
    pub tsc_hz: u64,
}

impl fmt::Display for Clear {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fb: full clear: uncached {} us, write-combining {} us",
            micros(self.uncached, self.tsc_hz),
            micros(self.write_combining, self.tsc_hz)
        )
    }
}

/// `servers: term and tui started; root CNode <used> of <slots> slots
/// used`.
pub struct Started {
    pub used: u64,
    pub slots: u64,
}

impl fmt::Display for Started {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "servers: term and tui started; root CNode {} of {} slots used",
            self.used, self.slots
        )
    }
}

/// `fb: all <n> frames are mapped: ...`, once every framebuffer frame
/// root holds has passed [`mapped`]'s probes.
pub struct Mapped(pub u64);

impl fmt::Display for Mapped {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "fb: all {} frames are mapped: a second Frame_Map of each is refused as mapped, and a Frame_Remap without read for its rights",
            self.0
        )
    }
}

/// Whether a framebuffer frame's two probes show it mapped, as the
/// kernel checks in `docs/abi.md`'s order, changing nothing when it
/// refuses: a second `Frame_Map`, into root's VSpace at an address
/// aligned to no frame size, refused with `InvalidCapability` 0, which
/// the kernel checks before the alignment (an unmapped frame would be an
/// `AlignmentError`); and a `Frame_Remap` asking no read right, refused
/// with `InvalidArgument` 0, which the kernel checks only after finding
/// the frame mapped (an unmapped frame would be `IllegalOperation`). The
/// second rules out an empty slot, which both refuse with
/// `InvalidCapability` 0, before looking at any argument.
pub fn mapped<'a>(
    map: &'a Result<(), Error>,
    remap: &'a Result<(), Error>,
) -> Result<(), Unmapped<'a>> {
    let mapped_map = Err(Error::Kernel(SyscallError::InvalidCapability(0)));
    let mapped_remap = Err(Error::Kernel(SyscallError::InvalidArgument(0)));
    if *map == mapped_map && *remap == mapped_remap {
        Ok(())
    } else {
        Err(Unmapped { map, remap })
    }
}

/// A framebuffer frame whose probes did not show it mapped: what each
/// gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Unmapped<'a> {
    pub map: &'a Result<(), Error>,
    pub remap: &'a Result<(), Error>,
}

impl fmt::Display for Unmapped<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let probe = |r: &Result<(), Error>, f: &mut fmt::Formatter<'_>| match r {
            Ok(()) => f.write_str("success"),
            Err(e) => write!(f, "{e}"),
        };
        f.write_str("a second Frame_Map gave ")?;
        probe(self.map, f)?;
        f.write_str(", Frame_Remap without read ")?;
        probe(self.remap, f)?;
        f.write_str(": not InvalidCapability(0) and InvalidArgument(0), a mapped frame's")
    }
}

/// A thread's priority as root set it, and its MCP as root read it back.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Sched {
    pub priority: u64,
    pub mcp: u64,
}

/// `servers: priority as set, MCP as read back: console <p>, <m>; term
/// <p>, <m>; tui <p>, <m>`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Priorities {
    pub console: Sched,
    pub term: Sched,
    pub tui: Sched,
}

impl fmt::Display for Priorities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("servers: priority as set, MCP as read back:")?;
        let mut sep = " ";
        for (name, s) in [
            ("console", self.console),
            ("term", self.term),
            ("tui", self.tui),
        ] {
            write!(f, "{sep}{name} {}, {}", s.priority, s.mcp)?;
            sep = "; ";
        }
        Ok(())
    }
}

/// Console above term, its client, and term above tui, its client
/// (`docs/design.md`, "Where it runs"), each with an MCP equal to its
/// priority, as `spawn_server` sets them.
pub fn priorities(p: &Priorities) -> Result<(), Failure> {
    let all = [p.console, p.term, p.tui];
    if all.iter().any(|s| s.mcp != s.priority) {
        return Err(Failure::Priorities("an MCP is not its thread's priority"));
    }
    if !(p.console.priority > p.term.priority && p.term.priority > p.tui.priority) {
        return Err(Failure::Priorities("not console above term above tui"));
    }
    Ok(())
}

/// What root fails with for a message on D that is not tui's report: for
/// a fault, since D is tui's fault endpoint, `tui fault <label>
/// (<kind>), MR0 to MR3 <words>`, as `watch` names a server's; for
/// anything else its badge and label.
pub struct OnD {
    pub badge: u64,
    pub label: u64,
    pub mr: [u64; 4],
}

impl fmt::Display for OnD {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.badge == TUI_BADGE && fault_kind(self.label).is_some() {
            let fault = Fault {
                who: "tui",
                label: self.label,
                mr: self.mr,
            };
            return write!(f, "{fault}");
        }
        let [a, b, c, d] = self.mr;
        write!(
            f,
            "tui: a message on D with badge {}, label {}, MR0 to MR3 {a:#x} {b:#x} {c:#x} {d:#x}",
            self.badge, self.label
        )
    }
}

/// `tui: read <n> bytes: <the bytes>`, escaped as a scenario's `send:`
/// writes them, from tui's report.
pub struct ReadLine<'a>(pub &'a [u8]);

impl fmt::Display for ReadLine<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "tui: read {} bytes: ", self.0.len())?;
        tui::escaped(self.0, f)
    }
}

/// `term: stats: <the counts>`; the scenario matches `, 0 ignored,` and
/// `, 0 dropped` on it.
pub struct StatsLine(pub TermStats);

impl fmt::Display for StatsLine {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "term: stats: {}", self.0)
    }
}

/// Why `test=tui` or `test=nofb` fails.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Failure {
    /// tui read something other than what the harness typed for it.
    Read,
    /// term's counts are wrong: what.
    Stats(&'static str),
    /// `test=nofb` read another line.
    Line,
    /// The priorities or MCPs are wrong: what.
    Priorities(&'static str),
}

impl fmt::Display for Failure {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Failure::Read => {
                f.write_str("tui did not read exactly the bytes typed for client 4: ")?;
                tui::escaped(TYPED, f)
            }
            Failure::Stats(what) => write!(f, "term's Stats: {what}"),
            Failure::Line => write!(f, "nofb did not read {NOFB_LINE:?}"),
            Failure::Priorities(what) => write!(f, "priorities: {what}"),
        }
    }
}

/// tui's report must be exactly the bytes typed for client 4, the focus
/// keys excluded: each reached term's client once, in order, unedited.
pub fn report(bytes: &[u8]) -> Result<(), Failure> {
    if bytes == TYPED {
        Ok(())
    } else {
        Err(Failure::Read)
    }
}

/// term's counts once tui has quit: no sequence ignored (tui sends only
/// what term acts on) and no byte dropped; every typed byte came from
/// console, and no DSR or DA reply was queued; a frame for each of tui's
/// `Write`s after the first, and its bytes.
pub fn stats(s: &TermStats) -> Result<(), Failure> {
    if s.ignored != 0 {
        return Err(Failure::Stats("sequences ignored"));
    }
    if s.dropped != 0 {
        return Err(Failure::Stats("bytes dropped"));
    }
    if s.from_console != TYPED.len() as u64 {
        return Err(Failure::Stats("not the bytes typed for client 4"));
    }
    if s.replies != 0 {
        return Err(Failure::Stats("reply bytes queued"));
    }
    // The first frame, then at least one Write for the banner and each of
    // the five frames (four keys and the goodbye).
    if s.frames < 6 || s.written == 0 || s.cells == 0 {
        return Err(Failure::Stats("too few frames, bytes or cells"));
    }
    Ok(())
}

/// `test=nofb`'s line.
pub fn nofb(line: &[u8]) -> Result<(), Failure> {
    if line == NOFB_LINE.as_bytes() {
        Ok(())
    } else {
        Err(Failure::Line)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use libsys::bootinfo::{SlotRegion, UntypedDesc};
    use std::format;
    use std::string::ToString;

    /// QEMU's BootInfo: OVMF's 1280x800 BGR framebuffer at 2 GiB, which
    /// the kernel hands out as six device untyped at the start of
    /// `untyped`, a RAM untyped after them.
    fn qemu() -> BootInfo {
        let mut bi = BootInfo::ZERO;
        bi.framebuffer.base = 0x8000_0000;
        bi.framebuffer.size = 4 * 1280 * 800;
        bi.framebuffer.width = 1280;
        bi.framebuffer.height = 800;
        bi.framebuffer.stride = 1280;
        bi.framebuffer.format.0 = 2;
        let list = [
            (0x8000_0000, 21),
            (0x8020_0000, 20),
            (0x8030_0000, 19),
            (0x8038_0000, 18),
            (0x803C_0000, 17),
            (0x803E_0000, 15),
        ];
        for (i, (paddr, bits)) in list.into_iter().enumerate() {
            bi.untyped_list[i] = UntypedDesc::new(paddr, bits, true);
        }
        bi.untyped_list[6] = UntypedDesc::new(0x10_0000, 20, false);
        bi.untyped = SlotRegion { start: 30, end: 37 };
        bi.framebuffer_untyped = SlotRegion { start: 30, end: 36 };
        bi
    }

    #[test]
    fn the_fb_line_on_qemu() {
        let bi = qemu();
        let mut u = [fb::Untyped::default(); MAX_UNTYPED];
        let (fields, n) = framebuffer(&bi, &mut u);
        assert_eq!(n, 6);
        assert_eq!(u[1], fb::Untyped::new(0x8020_0000, 20, true));
        let plan = fb::Plan::new(&fields, &u[..n]).unwrap();
        assert_eq!(
            FbLine(&plan).to_string(),
            "fb: 1280x800 BGR, stride 1280, 4000 KiB at 0x80000000: 6 untyped, 1 2 MiB and 488 4 KiB frames; 160x50 cells"
        );
    }

    #[test]
    fn the_fb_line_on_hyper_v() {
        let mut bi = BootInfo::ZERO;
        bi.framebuffer.base = 0xF800_0000;
        bi.framebuffer.size = 8 << 20;
        bi.framebuffer.width = 1024;
        bi.framebuffer.height = 768;
        bi.framebuffer.stride = 1024;
        bi.framebuffer.format.0 = 2;
        bi.untyped_list[0] = UntypedDesc::new(0xF800_0000, 23, true);
        bi.untyped = SlotRegion { start: 30, end: 31 };
        bi.framebuffer_untyped = SlotRegion { start: 30, end: 31 };
        let mut u = [fb::Untyped::default(); MAX_UNTYPED];
        let (fields, n) = framebuffer(&bi, &mut u);
        let plan = fb::Plan::new(&fields, &u[..n]).unwrap();
        assert_eq!(
            FbLine(&plan).to_string(),
            "fb: 1024x768 BGR, stride 1024, 8192 KiB at 0xf8000000: 1 untyped, 2 2 MiB and 0 4 KiB frames; 128x48 cells"
        );
    }

    #[test]
    fn no_framebuffer() {
        let mut bi = qemu();
        bi.framebuffer = BootInfo::ZERO.framebuffer;
        bi.framebuffer_untyped = SlotRegion { start: 30, end: 30 };
        let mut u = [fb::Untyped::default(); MAX_UNTYPED];
        let (fields, n) = framebuffer(&bi, &mut u);
        assert_eq!(n, 0);
        let why = fb::Plan::new(&fields, &u[..n]).unwrap_err();
        assert_eq!(
            NoFb(why).to_string(),
            "fb: none: the loader found no GOP framebuffer"
        );
        // A framebuffer the kernel kept.
        let mut bi = qemu();
        bi.framebuffer_untyped = SlotRegion { start: 30, end: 30 };
        let (fields, n) = framebuffer(&bi, &mut u);
        let why = fb::Plan::new(&fields, &u[..n]).unwrap_err();
        assert_eq!(
            NoFb(why).to_string(),
            "fb: none: the kernel kept it (see its boot summary)"
        );
    }

    #[test]
    fn the_clear_and_started_lines() {
        let c = Clear {
            uncached: 3_000_000_000,
            write_combining: 600_000,
            tsc_hz: 2_000_000_000,
        };
        assert_eq!(
            c.to_string(),
            "fb: full clear: uncached 1500000 us, write-combining 300 us"
        );
        assert_eq!(micros(5, 0), 0);
        assert_eq!(micros(999, 1_000_000), 999);
        assert_eq!(
            Started {
                used: 1612,
                slots: 4096
            }
            .to_string(),
            "servers: term and tui started; root CNode 1612 of 4096 slots used"
        );
    }

    /// The bytes tui must report, and the line root prints of them, as
    /// the scenario's `send:` wrote them.
    #[test]
    fn tui_must_report_the_typed_bytes() {
        assert_eq!(TYPED.len(), 8);
        assert_eq!(report(TYPED), Ok(()));
        assert_eq!(
            ReadLine(TYPED).to_string(),
            "tui: read 8 bytes: \\e[B\\e[B\\rq"
        );
        // The focus keys, a byte lost, one more, or another order fail.
        for bad in [
            &b"\x144\x1b[B\x1b[B\rq"[..],
            b"\x1b[B\x1b[\rq",
            b"\x1b[B\x1b[B\rqq",
            b"\x1b[B\r\x1b[Bq",
            b"",
        ] {
            assert_eq!(report(bad), Err(Failure::Read), "{bad:?}");
        }
        assert_eq!(
            ReadLine(b"\x14\\ #\x7f").to_string(),
            "tui: read 5 bytes: \\x14\\\\ #\\x7f"
        );
        assert_eq!(
            Failure::Read.to_string(),
            "tui did not read exactly the bytes typed for client 4: \\e[B\\e[B\\rq"
        );
    }

    #[test]
    fn terms_counts() {
        let good = TermStats {
            written: 40_000,
            frames: 7,
            cells: 9_000,
            ignored: 0,
            from_console: 8,
            dropped: 0,
            replies: 0,
        };
        assert_eq!(stats(&good), Ok(()));
        let line = StatsLine(good).to_string();
        assert_eq!(
            line,
            "term: stats: 40000 bytes written, 7 frames drawn, 9000 cells drawn, 0 ignored, 8 bytes from console, 0 dropped, 0 reply bytes queued"
        );
        assert!(line.contains(", 0 ignored,") && line.contains(", 0 dropped"));
        for (bad, why) in [
            (TermStats { ignored: 1, ..good }, "sequences ignored"),
            (TermStats { dropped: 3, ..good }, "bytes dropped"),
            (
                TermStats {
                    from_console: 9,
                    ..good
                },
                "not the bytes typed for client 4",
            ),
            (TermStats { replies: 4, ..good }, "reply bytes queued"),
            (
                TermStats { frames: 5, ..good },
                "too few frames, bytes or cells",
            ),
            (
                TermStats { cells: 0, ..good },
                "too few frames, bytes or cells",
            ),
        ] {
            assert_eq!(stats(&bad), Err(Failure::Stats(why)));
            assert_eq!(
                format!("{}", Failure::Stats(why)),
                format!("term's Stats: {why}")
            );
        }
    }

    /// Only a mapped frame passes both probes; an unmapped one, an empty
    /// slot or another capability fails one, with what each gave.
    #[test]
    fn the_probes_show_a_frame_mapped() {
        use SyscallError::*;
        let k = |e| Err(Error::Kernel(e));
        assert_eq!(
            mapped(&k(InvalidCapability(0)), &k(InvalidArgument(0))),
            Ok(())
        );
        for (map, remap) in [
            // Unmapped: the alignment, then the mapping, refuse.
            (k(AlignmentError), k(IllegalOperation)),
            // An empty slot.
            (k(InvalidCapability(0)), k(InvalidCapability(0))),
            // Another type of capability.
            (k(IllegalOperation), k(IllegalOperation)),
            // Either probe alone.
            (k(InvalidCapability(0)), k(IllegalOperation)),
            (k(AlignmentError), k(InvalidArgument(0))),
            (Ok(()), k(InvalidArgument(0))),
            (k(InvalidCapability(0)), Ok(())),
            (k(InvalidCapability(1)), k(InvalidArgument(0))),
        ] {
            assert_eq!(
                mapped(&map, &remap),
                Err(Unmapped {
                    map: &map,
                    remap: &remap
                }),
                "{map:?} {remap:?}"
            );
        }
        assert_eq!(
            Unmapped {
                map: &k(AlignmentError),
                remap: &Ok(())
            }
            .to_string(),
            "a second Frame_Map gave AlignmentError, Frame_Remap without read success: not InvalidCapability(0) and InvalidArgument(0), a mapped frame's"
        );
        assert_eq!(
            Mapped(489).to_string(),
            "fb: all 489 frames are mapped: a second Frame_Map of each is refused as mapped, and a Frame_Remap without read for its rights"
        );
    }

    #[test]
    fn the_priorities_line() {
        let s = |p| Sched {
            priority: p,
            mcp: p,
        };
        let good = Priorities {
            console: s(150),
            term: s(125),
            tui: s(100),
        };
        assert_eq!(priorities(&good), Ok(()));
        assert_eq!(
            good.to_string(),
            "servers: priority as set, MCP as read back: console 150, 150; term 125, 125; tui 100, 100"
        );
        let mcp = Failure::Priorities("an MCP is not its thread's priority");
        let order = Failure::Priorities("not console above term above tui");
        let term_mcp = Sched {
            priority: 125,
            mcp: 255,
        };
        let tui_mcp = Sched {
            priority: 100,
            mcp: 0,
        };
        for (bad, why) in [
            (
                Priorities {
                    term: term_mcp,
                    ..good
                },
                mcp,
            ),
            (
                Priorities {
                    tui: tui_mcp,
                    ..good
                },
                mcp,
            ),
            (
                Priorities {
                    term: s(150),
                    ..good
                },
                order,
            ),
            (
                Priorities {
                    tui: s(125),
                    ..good
                },
                order,
            ),
            (
                Priorities {
                    term: s(90),
                    ..good
                },
                order,
            ),
            (
                Priorities {
                    console: s(100),
                    ..good
                },
                order,
            ),
        ] {
            assert_eq!(priorities(&bad), Err(why), "{bad:?}");
        }
        assert_eq!(
            order.to_string(),
            "priorities: not console above term above tui"
        );
    }

    /// tui's fault on D reads as `watch`'s line for a server's; any other
    /// message by its badge and label.
    #[test]
    fn a_message_on_d_that_is_not_the_report() {
        let on_d = |badge, label| {
            OnD {
                badge,
                label,
                mr: [0, 0, 1, 0x14],
            }
            .to_string()
        };
        assert_eq!(
            on_d(TUI_BADGE, 5),
            "tui fault 5 (VMFault), MR0 to MR3 0x0 0x0 0x1 0x14"
        );
        assert_eq!(
            on_d(TUI_BADGE, 1),
            "tui fault 1 (CapFault), MR0 to MR3 0x0 0x0 0x1 0x14"
        );
        assert_eq!(
            on_d(TUI_BADGE, 2),
            "tui fault 2 (UnknownSyscall), MR0 to MR3 0x0 0x0 0x1 0x14"
        );
        assert_eq!(
            on_d(TUI_BADGE, 3),
            "tui fault 3 (UserException), MR0 to MR3 0x0 0x0 0x1 0x14"
        );
        // Label 4 is reserved, 0x131 tui's report; badge 3 is not tui's.
        for (badge, label) in [(TUI_BADGE, 4), (TUI_BADGE, 0x131), (3, 5), (0, 0)] {
            assert_eq!(
                on_d(badge, label),
                format!(
                    "tui: a message on D with badge {badge}, label {label}, MR0 to MR3 0x0 0x0 0x1 0x14"
                )
            );
        }
    }

    #[test]
    fn nofbs_line() {
        assert_eq!(nofb(b"hi"), Ok(()));
        for bad in [&b"abchi"[..], b"hi\r", b"", b"\x1b[Ahi"] {
            assert_eq!(nofb(bad), Err(Failure::Line));
        }
    }
}
