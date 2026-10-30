//! ACPI table dumps: the loader prints every table it can reach to COM1 when
//! the kernel command line has the word `acpidump`, and `cargo xtask
//! acpidump` turns the log into a file under `core/tests/acpi/`, so host
//! tests run the parser on each platform's real tables.
//!
//! Each line is self-contained and starts at [`MARKER`]. A reader takes every
//! line holding the marker, wherever it starts, and ignores the rest, so a
//! COM1 log copied from Windows (`\r\n` line ends, the loader's `loader: `
//! prefix, other output between lines) reads back:
//!
//! ```text
//! acpidump: rsdp 000000000fb7e014
//! acpidump: table 000000000fb7e014 36 RSDP
//! acpidump: data 000000000fb7e014 52534420505452204e424f4348532002...
//! acpidump: end 9
//! ```
//!
//! `table` gives a table's address, the length dumped and its signature (for
//! people); `data` gives up to [`BYTES_PER_LINE`] bytes from an address;
//! `end` counts the tables and marks a dump that was not cut short.

use core::fmt;

use super::{
    HEADER_LEN, MAX_TABLE_LEN, PhysRead, RSDP_MAX_LEN, RSDP_V1_LEN, RSDP_V2_LEN, Signature,
    read_bytes, read_header, read_u32, read_u64,
};

/// Every dump line holds this, followed by the line's kind.
pub const MARKER: &str = "acpidump: ";
/// The most bytes one `data` line carries.
pub const BYTES_PER_LINE: usize = 32;
/// Distinct tables the walk remembers to skip a repeat; past this a table
/// listed twice is dumped twice, which readers accept.
const SEEN: usize = 64;

/// A table [`walk`] found.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Found {
    /// The signature, or `RSDP` for the RSDP.
    pub name: Signature,
    pub address: u64,
    /// The bytes to dump: the header's `length`, or the header alone if
    /// that is implausible.
    pub length: u32,
}

/// Calls `f` once for every table reachable from the RSDP at `rsdp`: the
/// RSDP, the RSDT and the XSDT, every table either lists, and the FADT's
/// DSDT and FACS. Lenient where [`super::parse`] is strict, so a broken
/// table is still dumped for a test to look at; it skips only tables whose
/// first 8 bytes cannot be read.
pub fn walk<M: PhysRead + ?Sized>(mem: &M, rsdp: u64, mut f: impl FnMut(Found)) {
    let mut seen = [0u64; SEEN];
    let mut n = 0;
    let mut emit = |address: u64, f: &mut dyn FnMut(Found)| -> Option<(Signature, u32)> {
        if address == 0 {
            return None;
        }
        let (name, length) = read_header(mem, address)?;
        if seen[..n].contains(&address) {
            return None;
        }
        if let Some(slot) = seen.get_mut(n) {
            *slot = address;
            n += 1;
        }
        let length = if (8..=MAX_TABLE_LEN).contains(&length) {
            length
        } else {
            HEADER_LEN
        };
        f(Found {
            name,
            address,
            length,
        });
        Some((name, length))
    };

    if rsdp == 0 || read_bytes::<8, _>(mem, rsdp, 0).is_none() {
        return;
    }
    let revision = read_bytes::<1, _>(mem, rsdp, 15).map_or(0, |[r]| r);
    let length = match read_u32(mem, rsdp, 20) {
        _ if revision == 0 => RSDP_V1_LEN,
        Some(n) if (RSDP_V2_LEN..=RSDP_MAX_LEN).contains(&n) => n,
        _ => RSDP_V2_LEN,
    };
    f(Found {
        name: Signature(*b"RSDP"),
        address: rsdp,
        length,
    });

    let rsdt = read_u32(mem, rsdp, 16).map_or(0, u64::from);
    let xsdt = if revision == 0 {
        0
    } else {
        read_u64(mem, rsdp, 24).unwrap_or(0)
    };
    for (root, entry) in [(rsdt, 4u32), (xsdt, 8)] {
        let Some((_, length)) = emit(root, &mut f) else {
            continue;
        };
        for i in 0..length.saturating_sub(HEADER_LEN) / entry {
            let off = u64::from(HEADER_LEN + i * entry);
            let address = match entry {
                8 => read_u64(mem, root, off),
                _ => read_u32(mem, root, off).map(u64::from),
            };
            let Some(address) = address else { break };
            if let Some((Signature::FADT, length)) = emit(address, &mut f) {
                // FIRMWARE_CTRL and DSDT, then X_FIRMWARE_CTRL and X_DSDT
                // where the FADT is long enough to hold them.
                let fadt = |off: u64, wide: bool| -> u64 {
                    if wide {
                        read_u64(mem, address, off).unwrap_or(0)
                    } else {
                        read_u32(mem, address, off).map_or(0, u64::from)
                    }
                };
                emit(fadt(36, false), &mut f);
                emit(fadt(40, false), &mut f);
                if length >= 140 {
                    emit(fadt(132, true), &mut f);
                }
                if length >= 148 {
                    emit(fadt(140, true), &mut f);
                }
            }
        }
    }
}

/// Writes the dump of every table reachable from `rsdp`, one line per call
/// to `line`, each starting with [`MARKER`] and without a line end.
pub fn write<M: PhysRead + ?Sized>(mem: &M, rsdp: u64, mut line: impl FnMut(fmt::Arguments<'_>)) {
    line(format_args!("{MARKER}rsdp {rsdp:016x}"));
    let mut tables = 0u32;
    walk(mem, rsdp, |t| {
        tables += 1;
        line(format_args!(
            "{MARKER}table {:016x} {} {}",
            t.address, t.length, t.name
        ));
        let mut off = 0u32;
        while off < t.length {
            let want = (t.length - off).min(BYTES_PER_LINE as u32);
            let mut buf = [0u8; BYTES_PER_LINE];
            let mut got = 0;
            for (i, b) in (0..want).zip(buf.iter_mut()) {
                match mem.read_u8(t.address.saturating_add(u64::from(off + i))) {
                    Some(v) => *b = v,
                    None => break,
                }
                got += 1;
            }
            if got == 0 {
                break;
            }
            line(format_args!(
                "{MARKER}data {:016x} {}",
                t.address.saturating_add(u64::from(off)),
                Hex(&buf[..got])
            ));
            if got < want as usize {
                break;
            }
            off += want;
        }
    });
    line(format_args!("{MARKER}end {tables}"));
}

struct Hex<'a>(&'a [u8]);

impl fmt::Display for Hex<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        self.0.iter().try_for_each(|b| write!(f, "{b:02x}"))
    }
}

/// One dump line, as [`parse_line`] reads it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Line<'a> {
    Rsdp(u64),
    Table {
        address: u64,
        length: u32,
        name: &'a str,
    },
    /// `bytes[..len]`, from `address` on.
    Data {
        address: u64,
        bytes: [u8; BYTES_PER_LINE],
        len: usize,
    },
    End(u32),
}

impl Line<'_> {
    /// A `data` line's bytes; empty for the other kinds.
    pub fn data(&self) -> &[u8] {
        match self {
            Self::Data { bytes, len, .. } => bytes.get(..*len).unwrap_or(&[]),
            _ => &[],
        }
    }
}

/// Reads one line of a log: `None` if it holds no [`MARKER`], else the dump
/// line or why it is malformed. Byte-oriented, so that the host tests stay
/// quick under Miri.
pub fn parse_line(text: &str) -> Option<Result<Line<'_>, &'static str>> {
    after_marker(text).map(parse_rest)
}

/// The text after [`MARKER`], without trailing white space.
fn after_marker(text: &str) -> Option<&str> {
    // Dump files start each line with the marker; logs put text before it.
    let rest = match text.strip_prefix(MARKER) {
        Some(rest) => rest,
        None => text.split_once(MARKER)?.1,
    };
    Some(rest.trim_end())
}

/// A dump line after its marker. Words are split on spaces with `split`,
/// which finds them with `memchr`: far quicker under Miri than a per-byte
/// white-space test.
fn parse_rest(rest: &str) -> Result<Line<'_>, &'static str> {
    let mut words = rest.split(' ').filter(|w| !w.is_empty());
    let addr = |w: Option<&str>| w.and_then(hex_u64).ok_or("bad address");
    let line = match words.next() {
        Some("rsdp") => addr(words.next()).map(Line::Rsdp),
        Some("table") => addr(words.next()).and_then(|address| {
            let length = words
                .next()
                .and_then(|w| w.parse().ok())
                .ok_or("bad length")?;
            Ok(Line::Table {
                address,
                length,
                name: words.next().unwrap_or(""),
            })
        }),
        Some("data") => addr(words.next()).and_then(|address| {
            let hex = words.next().ok_or("no data")?;
            let mut bytes = [0; BYTES_PER_LINE];
            let len = decode_hex(hex, &mut bytes).ok_or("bad hex")?;
            Ok(Line::Data {
                address,
                bytes,
                len,
            })
        }),
        Some("end") => words
            .next()
            .and_then(|w| w.parse().ok())
            .map(Line::End)
            .ok_or("bad table count"),
        _ => Err("unknown line kind"),
    };
    line.and_then(|l| match words.next() {
        Some(_) if !matches!(l, Line::Table { .. }) => Err("trailing text"),
        _ => Ok(l),
    })
}

fn nibble(c: u8) -> Option<u8> {
    match c {
        b'0'..=b'9' => Some(c - b'0'),
        b'a'..=b'f' => Some(c - b'a' + 10),
        b'A'..=b'F' => Some(c - b'A' + 10),
        _ => None,
    }
}

/// Exactly 16 hex digits.
fn hex_u64(w: &str) -> Option<u64> {
    let digits = w.as_bytes();
    if digits.len() != 16 {
        return None;
    }
    digits
        .iter()
        .try_fold(0u64, |v, &c| Some(v << 4 | u64::from(nibble(c)?)))
}

/// Decodes the hex of a `data` line into `out`; `None` unless it is 1 to
/// [`BYTES_PER_LINE`] whole bytes.
pub fn decode_hex(hex: &str, out: &mut [u8; BYTES_PER_LINE]) -> Option<usize> {
    let digits = hex.as_bytes();
    if digits.is_empty() || !digits.len().is_multiple_of(2) || digits.len() / 2 > BYTES_PER_LINE {
        return None;
    }
    for (pair, b) in digits.chunks_exact(2).zip(out.iter_mut()) {
        let [hi, lo] = [*pair.first()?, *pair.get(1)?];
        *b = nibble(hi)? << 4 | nibble(lo)?;
    }
    Some(digits.len() / 2)
}

#[cfg(any(test, feature = "testing"))]
pub use memory::{DumpMemory, DumpTable};

#[cfg(any(test, feature = "testing"))]
mod memory {
    use alloc::format;
    use alloc::string::{String, ToString};
    use alloc::vec::Vec;

    use super::{Line, MARKER, PhysRead, after_marker, parse_rest};

    /// A table a dump announces.
    #[derive(Clone, Debug, PartialEq, Eq)]
    pub struct DumpTable {
        pub address: u64,
        pub length: u32,
        pub name: String,
    }

    /// A run of contiguous dumped bytes.
    #[derive(Clone, Debug)]
    struct Run {
        base: u64,
        bytes: Vec<u8>,
    }

    impl Run {
        /// `bytes[addr - base..][..len]`, if the run holds all of it.
        fn range(&self, addr: u64, len: usize) -> Option<core::ops::Range<usize>> {
            let start = usize::try_from(addr.checked_sub(self.base)?).ok()?;
            let end = start.checked_add(len)?;
            (end <= self.bytes.len()).then_some(start..end)
        }
    }

    /// The memory a dump describes: readable exactly where it has bytes.
    #[derive(Clone, Debug, Default)]
    pub struct DumpMemory {
        rsdp: Option<u64>,
        tables: Vec<DumpTable>,
        /// Sorted by base. Runs overlap only where a dump repeats a table,
        /// with the same bytes.
        runs: Vec<Run>,
        end: Option<u32>,
        /// The dump lines, after the marker, as they appeared, each ended
        /// by `\n`: one allocation, so a copy is cheap under Miri.
        lines: String,
    }

    impl DumpMemory {
        /// Reads every dump line of `text` and ignores the rest. Fails on a
        /// malformed dump line, naming it by line number.
        pub fn parse(text: &str) -> Result<Self, String> {
            let mut m = Self::default();
            for (n, raw) in text.lines().enumerate() {
                let Some(rest) = after_marker(raw) else {
                    continue;
                };
                let line = parse_rest(rest).map_err(|e| format!("line {}: {e}: {raw:?}", n + 1))?;
                m.lines.push_str(rest);
                m.lines.push('\n');
                match line {
                    Line::Rsdp(a) => m.rsdp = Some(a),
                    Line::Table {
                        address,
                        length,
                        name,
                    } => m.tables.push(DumpTable {
                        address,
                        length,
                        name: name.to_string(),
                    }),
                    Line::Data { address, .. } => m.add(address, line.data()),
                    Line::End(count) => m.end = Some(count),
                }
            }
            m.runs.sort_by_key(|r| r.base);
            Ok(m)
        }

        fn add(&mut self, address: u64, bytes: &[u8]) {
            if let Some(run) = self.runs.last_mut()
                && run.base.checked_add(run.bytes.len() as u64) == Some(address)
            {
                run.bytes.extend_from_slice(bytes);
                return;
            }
            self.runs.push(Run {
                base: address,
                bytes: bytes.to_vec(),
            });
        }

        /// The run holding `[addr, addr + len)`, and where in it.
        fn find(&self, addr: u64, len: usize) -> Option<(usize, core::ops::Range<usize>)> {
            // The last run starting at or below `addr` usually holds it.
            let i = self.runs.partition_point(|r| r.base <= addr);
            let near = i.checked_sub(1).and_then(|j| {
                let r = self.runs.get(j)?.range(addr, len)?;
                Some((j, r))
            });
            near.or_else(|| {
                self.runs
                    .iter()
                    .enumerate()
                    .find_map(|(j, run)| Some((j, run.range(addr, len)?)))
            })
        }

        /// The RSDP address the dump starts from.
        pub fn rsdp(&self) -> Option<u64> {
            self.rsdp
        }

        pub fn tables(&self) -> &[DumpTable] {
            &self.tables
        }

        /// The `end` line's table count, if the dump has one.
        pub fn end(&self) -> Option<u32> {
            self.end
        }

        /// The dump lines, without the marker, as they appeared.
        pub fn lines(&self) -> impl Iterator<Item = String> + '_ {
            self.lines.lines().map(|l| format!("{MARKER}{l}"))
        }

        /// Total bytes of table data.
        pub fn bytes(&self) -> usize {
            self.runs.iter().map(|r| r.bytes.len()).sum()
        }

        /// The `len` bytes at `addr`, if one run holds them all.
        pub fn slice(&self, addr: u64, len: usize) -> Option<&[u8]> {
            let (j, r) = self.find(addr, len)?;
            self.runs.get(j)?.bytes.get(r)
        }

        /// As [`DumpMemory::slice`], to change them.
        pub fn slice_mut(&mut self, addr: u64, len: usize) -> Option<&mut [u8]> {
            let (j, r) = self.find(addr, len)?;
            self.runs.get_mut(j)?.bytes.get_mut(r)
        }

        /// Problems that make the dump unfit to commit: no RSDP or `end`
        /// line, a table count that disagrees, a table whose bytes are
        /// missing.
        pub fn check(&self) -> Result<(), String> {
            if self.rsdp.is_none() {
                return Err("no `rsdp` line".into());
            }
            match self.end {
                None => return Err("no `end` line: the log stops inside the dump".into()),
                Some(n) if n as usize != self.tables.len() => {
                    return Err(format!(
                        "`end` counts {n} tables but the dump has {}",
                        self.tables.len()
                    ));
                }
                Some(_) => {}
            }
            for t in &self.tables {
                if self.slice(t.address, t.length as usize).is_some() {
                    continue;
                }
                let missing = (0..u64::from(t.length))
                    .find(|&i| self.read_u8(t.address.saturating_add(i)).is_none());
                if let Some(i) = missing {
                    return Err(format!(
                        "{} at {:#x}: byte {i} of {} missing",
                        t.name, t.address, t.length
                    ));
                }
            }
            Ok(())
        }

        /// Overwrites the byte at `addr` wherever the dump holds it; `false`
        /// if it holds none.
        pub fn poke(&mut self, addr: u64, value: u8) -> bool {
            let mut hit = false;
            for run in &mut self.runs {
                if let Some(r) = run.range(addr, 1)
                    && let Some(b) = run.bytes.get_mut(r.start)
                {
                    *b = value;
                    hit = true;
                }
            }
            hit
        }
    }

    impl PhysRead for DumpMemory {
        fn read_u8(&self, addr: u64) -> Option<u8> {
            self.slice(addr, 1)?.first().copied()
        }
    }
}
