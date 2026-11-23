//! The verdicts of `test=tui` and `test=nofb` (`docs/design.md`,
//! "Scenarios" under "Framebuffer, terminal and TUI"): BootInfo's
//! framebuffer as `fb` takes it, the lines root prints of the framebuffer,
//! the write-combining check, the servers, tui's report and term's
//! `Stats`, and what the report and the counts must hold.

use core::fmt;

use libsys::BootInfo;
use libsys::bootinfo::MAX_UNTYPED;
use libsys::proto::TermStats;

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

    #[test]
    fn nofbs_line() {
        assert_eq!(nofb(b"hi"), Ok(()));
        for bad in [&b"abchi"[..], b"hi\r", b"", b"\x1b[Ahi"] {
            assert_eq!(nofb(bad), Err(Failure::Line));
        }
    }
}
