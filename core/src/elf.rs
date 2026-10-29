//! A small, strict ELF64 parser for loading executables.
//!
//! It accepts only little-endian x86_64 `ET_EXEC` files and checks every
//! loadable segment up front, so that a loader can copy segments without any
//! further bounds checks. The loader uses it for `kernel.elf`, and the
//! kernel's ELF loader for the root task (M5) will too.

use core::fmt;

pub const PAGE_SIZE: u64 = 4096;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;
const ET_EXEC: u16 = 2;
const EM_X86_64: u16 = 62;
const PT_LOAD: u32 = 1;

/// Segment permission bits from `p_flags`.
pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ElfError {
    TooShort,
    BadMagic,
    NotElf64,
    NotLittleEndian,
    BadVersion,
    WrongMachine(u16),
    NotExecutable(u16),
    BadProgramHeaders,
    NoLoadableSegments,
    /// A segment's file bytes run past the end of the file.
    SegmentOutsideFile,
    /// A segment has more file bytes than memory bytes.
    FileSizeExceedsMemSize,
    /// `vaddr + memsz` overflows, or rounds up past the top of memory.
    AddressOverflow,
    OverlappingSegments,
    /// The entry point is not inside an executable segment.
    BadEntry(u64),
}

impl fmt::Display for ElfError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::TooShort => f.write_str("file too short for an ELF header"),
            Self::BadMagic => f.write_str("not an ELF file"),
            Self::NotElf64 => f.write_str("not a 64-bit ELF file"),
            Self::NotLittleEndian => f.write_str("not little-endian"),
            Self::BadVersion => f.write_str("unknown ELF version"),
            Self::WrongMachine(m) => write!(f, "machine {m}, expected x86_64 ({EM_X86_64})"),
            Self::NotExecutable(t) => write!(f, "type {t}, expected ET_EXEC ({ET_EXEC})"),
            Self::BadProgramHeaders => f.write_str("program header table out of range"),
            Self::NoLoadableSegments => f.write_str("no PT_LOAD segments"),
            Self::SegmentOutsideFile => f.write_str("segment extends past the end of the file"),
            Self::FileSizeExceedsMemSize => f.write_str("segment file size exceeds memory size"),
            Self::AddressOverflow => f.write_str("segment address range overflows"),
            Self::OverlappingSegments => f.write_str("loadable segments overlap"),
            Self::BadEntry(e) => write!(f, "entry point {e:#x} is not in an executable segment"),
        }
    }
}

/// A loadable (`PT_LOAD`) segment.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segment {
    pub vaddr: u64,
    pub memsz: u64,
    pub offset: u64,
    pub filesz: u64,
    pub flags: u32,
}

impl Segment {
    pub fn writable(&self) -> bool {
        self.flags & PF_W != 0
    }

    pub fn executable(&self) -> bool {
        self.flags & PF_X != 0
    }

    /// One past the last virtual address. Cannot overflow: [`Elf::parse`]
    /// checked it.
    pub fn vend(&self) -> u64 {
        self.vaddr + self.memsz
    }
}

/// A parsed, validated ELF executable borrowing the file's bytes.
#[derive(Clone, Copy, Debug)]
pub struct Elf<'a> {
    data: &'a [u8],
    entry: u64,
    phoff: usize,
    phentsize: usize,
    phnum: usize,
}

impl<'a> Elf<'a> {
    pub fn parse(data: &'a [u8]) -> Result<Self, ElfError> {
        if data.len() < EHDR_SIZE {
            return Err(ElfError::TooShort);
        }
        if data[0..4] != *b"\x7fELF" {
            return Err(ElfError::BadMagic);
        }
        if data[4] != 2 {
            return Err(ElfError::NotElf64);
        }
        if data[5] != 1 {
            return Err(ElfError::NotLittleEndian);
        }
        if data[6] != 1 || u32_at(data, 20) != 1 {
            return Err(ElfError::BadVersion);
        }
        let machine = u16_at(data, 18);
        if machine != EM_X86_64 {
            return Err(ElfError::WrongMachine(machine));
        }
        let ty = u16_at(data, 16);
        if ty != ET_EXEC {
            return Err(ElfError::NotExecutable(ty));
        }

        let phoff = usize::try_from(u64_at(data, 32)).map_err(|_| ElfError::BadProgramHeaders)?;
        let phentsize = usize::from(u16_at(data, 54));
        let phnum = usize::from(u16_at(data, 56));
        let table_end = phentsize
            .checked_mul(phnum)
            .and_then(|n| n.checked_add(phoff));
        if phentsize < PHDR_SIZE || !matches!(table_end, Some(end) if end <= data.len()) {
            return Err(ElfError::BadProgramHeaders);
        }

        let elf = Elf {
            data,
            entry: u64_at(data, 24),
            phoff,
            phentsize,
            phnum,
        };
        elf.check_segments()?;
        Ok(elf)
    }

    pub fn entry(&self) -> u64 {
        self.entry
    }

    /// The loadable segments, in file order.
    pub fn segments(&self) -> impl Iterator<Item = Segment> + 'a {
        let Elf {
            data,
            phoff,
            phentsize,
            phnum,
            ..
        } = *self;
        (0..phnum).filter_map(move |i| {
            let ph = &data[phoff + i * phentsize..][..PHDR_SIZE];
            (u32_at(ph, 0) == PT_LOAD).then(|| Segment {
                flags: u32_at(ph, 4),
                offset: u64_at(ph, 8),
                vaddr: u64_at(ph, 16),
                filesz: u64_at(ph, 32),
                memsz: u64_at(ph, 40),
            })
        })
    }

    /// The bytes of `seg` stored in the file. The rest, up to `memsz`, is zero.
    pub fn file_bytes(&self, seg: &Segment) -> &'a [u8] {
        // In range: check_segments verified offset + filesz <= data.len().
        &self.data[seg.offset as usize..][..seg.filesz as usize]
    }

    /// The page-aligned virtual range `[start, end)` covering every non-empty
    /// loadable segment.
    pub fn bounds(&self) -> (u64, u64) {
        let nonempty = || self.segments().filter(|s| s.memsz > 0);
        let start = nonempty().map(|s| s.vaddr).min().unwrap_or(0);
        let end = nonempty().map(|s| s.vend()).max().unwrap_or(0);
        // Rounding up cannot overflow: check_segments rejected segments that
        // end within the last page of the address space.
        (start & !(PAGE_SIZE - 1), end.next_multiple_of(PAGE_SIZE))
    }

    fn check_segments(&self) -> Result<(), ElfError> {
        let mut any = false;
        let mut entry_ok = false;
        for (i, s) in self.segments().enumerate() {
            any = true;
            let file_end = s
                .offset
                .checked_add(s.filesz)
                .ok_or(ElfError::SegmentOutsideFile)?;
            if file_end > self.data.len() as u64 {
                return Err(ElfError::SegmentOutsideFile);
            }
            if s.filesz > s.memsz {
                return Err(ElfError::FileSizeExceedsMemSize);
            }
            let vend = s
                .vaddr
                .checked_add(s.memsz)
                .ok_or(ElfError::AddressOverflow)?;
            if vend > u64::MAX - PAGE_SIZE {
                return Err(ElfError::AddressOverflow);
            }
            // Overlap is judged on whole pages, because that is the unit the
            // loader maps with.
            for t in self.segments().take(i) {
                if pages_overlap(&s, &t) {
                    return Err(ElfError::OverlappingSegments);
                }
            }
            if s.executable() && s.vaddr <= self.entry && self.entry < vend {
                entry_ok = true;
            }
        }
        if !any {
            return Err(ElfError::NoLoadableSegments);
        }
        if !entry_ok {
            return Err(ElfError::BadEntry(self.entry));
        }
        Ok(())
    }
}

fn pages_overlap(a: &Segment, b: &Segment) -> bool {
    if a.memsz == 0 || b.memsz == 0 {
        return false;
    }
    let page = |x: u64| x & !(PAGE_SIZE - 1);
    let (a0, a1) = (page(a.vaddr), page(a.vend() - 1));
    let (b0, b1) = (page(b.vaddr), page(b.vend() - 1));
    a0 <= b1 && b0 <= a1
}

// Callers have already checked that `off + N` is within `b`.
fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u32_at(b: &[u8], off: usize) -> u32 {
    u32::from_le_bytes(b[off..off + 4].try_into().unwrap())
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;

    struct Ph {
        ty: u32,
        flags: u32,
        offset: u64,
        vaddr: u64,
        filesz: u64,
        memsz: u64,
    }

    fn load(flags: u32, offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Ph {
        Ph {
            ty: PT_LOAD,
            flags,
            offset,
            vaddr,
            filesz,
            memsz,
        }
    }

    /// Builds an ELF64 executable with `phs` and enough trailing bytes to
    /// cover every segment's file range.
    fn build(entry: u64, phs: &[Ph]) -> Vec<u8> {
        let mut f = std::vec![0u8; EHDR_SIZE];
        f[0..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&ET_EXEC.to_le_bytes());
        f[18..20].copy_from_slice(&EM_X86_64.to_le_bytes());
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[24..32].copy_from_slice(&entry.to_le_bytes());
        f[32..40].copy_from_slice(&(EHDR_SIZE as u64).to_le_bytes());
        f[52..54].copy_from_slice(&(EHDR_SIZE as u16).to_le_bytes());
        f[54..56].copy_from_slice(&(PHDR_SIZE as u16).to_le_bytes());
        f[56..58].copy_from_slice(&(phs.len() as u16).to_le_bytes());
        for p in phs {
            let mut h = [0u8; PHDR_SIZE];
            h[0..4].copy_from_slice(&p.ty.to_le_bytes());
            h[4..8].copy_from_slice(&p.flags.to_le_bytes());
            h[8..16].copy_from_slice(&p.offset.to_le_bytes());
            h[16..24].copy_from_slice(&p.vaddr.to_le_bytes());
            h[24..32].copy_from_slice(&p.vaddr.to_le_bytes());
            h[32..40].copy_from_slice(&p.filesz.to_le_bytes());
            h[40..48].copy_from_slice(&p.memsz.to_le_bytes());
            h[48..56].copy_from_slice(&PAGE_SIZE.to_le_bytes());
            f.extend_from_slice(&h);
        }
        // Ranges that overflow or are absurdly large are left uncovered: those
        // tests want the parser to reject them.
        let need = phs
            .iter()
            .filter(|p| p.ty == PT_LOAD)
            .filter_map(|p| p.offset.checked_add(p.filesz))
            .filter(|&end| end < 1 << 20)
            .max()
            .unwrap_or(0) as usize;
        if f.len() < need {
            f.resize(need, 0xAB);
        }
        f
    }

    const K: u64 = 0xFFFF_FFFF_8000_0000;

    fn kernel_like() -> Vec<u8> {
        build(
            K + 0x10,
            &[
                load(PF_R | PF_X, 0x1000, K, 0x800, 0x800),
                load(PF_R, 0x2000, K + 0x1000, 0x100, 0x100),
                load(PF_R | PF_W, 0x3000, K + 0x2000, 0x10, 0x5000), // .data + .bss
            ],
        )
    }

    #[test]
    fn parses_a_kernel_like_image() {
        let bytes = kernel_like();
        let elf = Elf::parse(&bytes).unwrap();
        assert_eq!(elf.entry(), K + 0x10);
        let segs: Vec<_> = elf.segments().collect();
        assert_eq!(segs.len(), 3);
        assert!(segs[0].executable() && !segs[0].writable());
        assert!(segs[2].writable() && !segs[2].executable());
        assert_eq!(elf.file_bytes(&segs[0]).len(), 0x800);
        assert_eq!(elf.file_bytes(&segs[2]), &bytes[0x3000..0x3010]);
        assert_eq!(elf.bounds(), (K, K + 0x7000));
    }

    #[test]
    fn skips_non_load_headers() {
        let mut phs = std::vec![load(PF_R | PF_X, 0x1000, 0x40_0000, 0x10, 0x10)];
        phs.push(Ph {
            ty: 0x6474_e551,
            flags: PF_R | PF_W,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
        }); // PT_GNU_STACK
        let bytes = build(0x40_0000, &phs);
        assert_eq!(Elf::parse(&bytes).unwrap().segments().count(), 1);
    }

    #[test]
    fn rejects_bad_headers() {
        let good = kernel_like();
        assert_eq!(Elf::parse(&good[..63]).unwrap_err(), ElfError::TooShort);

        let mut b = good.clone();
        b[1] = b'X';
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::BadMagic);

        let mut b = good.clone();
        b[4] = 1;
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::NotElf64);

        let mut b = good.clone();
        b[5] = 2;
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::NotLittleEndian);

        let mut b = good.clone();
        b[20] = 2;
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::BadVersion);

        let mut b = good.clone();
        b[18..20].copy_from_slice(&183u16.to_le_bytes()); // aarch64
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::WrongMachine(183));

        let mut b = good.clone();
        b[16..18].copy_from_slice(&3u16.to_le_bytes()); // ET_DYN, a PIE
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::NotExecutable(3));
    }

    #[test]
    fn rejects_program_headers_out_of_range() {
        let mut b = kernel_like();
        let len = b.len() as u64;
        b[32..40].copy_from_slice(&len.to_le_bytes());
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::BadProgramHeaders);

        let mut b = kernel_like();
        b[32..40].copy_from_slice(&u64::MAX.to_le_bytes());
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::BadProgramHeaders);

        let mut b = kernel_like();
        b[54..56].copy_from_slice(&32u16.to_le_bytes());
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::BadProgramHeaders);
    }

    #[test]
    fn rejects_an_image_with_nothing_to_load() {
        let b = build(0x1000, &[]);
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::NoLoadableSegments);
    }

    #[test]
    fn rejects_segment_past_end_of_file() {
        let mut b = build(K, &[load(PF_R | PF_X, 0x1000, K, 0x100, 0x100)]);
        b.truncate(0x10FF);
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::SegmentOutsideFile);

        let b = build(K, &[load(PF_R | PF_X, u64::MAX - 4, K, 0x10, 0x10)]);
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::SegmentOutsideFile);
    }

    #[test]
    fn rejects_filesz_larger_than_memsz() {
        let b = build(K, &[load(PF_R | PF_X, 0x1000, K, 0x200, 0x100)]);
        assert_eq!(
            Elf::parse(&b).unwrap_err(),
            ElfError::FileSizeExceedsMemSize
        );
    }

    #[test]
    fn rejects_address_overflow() {
        let b = build(
            u64::MAX - 0x100,
            &[load(PF_R | PF_X, 0x1000, u64::MAX - 0x100, 0, 0x200)],
        );
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::AddressOverflow);

        // Ends inside the last page: rounding the end up would overflow.
        let b = build(
            u64::MAX - 0x100,
            &[load(PF_R | PF_X, 0x1000, u64::MAX - 0x100, 0, 0x10)],
        );
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::AddressOverflow);
    }

    #[test]
    fn rejects_overlapping_segments() {
        let b = build(
            K,
            &[
                load(PF_R | PF_X, 0x1000, K, 0x100, 0x2000),
                load(PF_R | PF_W, 0x2000, K + 0x1000, 0x10, 0x10),
            ],
        );
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::OverlappingSegments);

        // Disjoint bytes but a shared page still count as overlapping.
        let b = build(
            K,
            &[
                load(PF_R | PF_X, 0x1000, K, 0x100, 0x100),
                load(PF_R | PF_W, 0x2000, K + 0x800, 0x10, 0x10),
            ],
        );
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::OverlappingSegments);
    }

    #[test]
    fn rejects_entry_outside_executable_code() {
        let b = build(
            K + 0x1000,
            &[
                load(PF_R | PF_X, 0x1000, K, 0x100, 0x100),
                load(PF_R | PF_W, 0x2000, K + 0x1000, 0x10, 0x10),
            ],
        );
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::BadEntry(K + 0x1000));

        let b = build(K + 0x100, &[load(PF_R | PF_X, 0x1000, K, 0x100, 0x100)]);
        assert_eq!(Elf::parse(&b).unwrap_err(), ElfError::BadEntry(K + 0x100));
    }

    #[test]
    fn empty_segments_never_overlap() {
        let b = build(
            K,
            &[
                load(PF_R | PF_X, 0x1000, K, 0x100, 0x100),
                load(PF_R, 0x1000, K, 0, 0),
            ],
        );
        assert!(Elf::parse(&b).is_ok());
    }

    #[test]
    fn empty_segments_do_not_widen_bounds() {
        let b = build(
            K,
            &[
                load(PF_R | PF_X, 0x1000, K, 0x100, 0x100),
                load(PF_R, 0x1000, 0, 0, 0),
            ],
        );
        assert_eq!(Elf::parse(&b).unwrap().bounds(), (K, K + PAGE_SIZE));
    }

    #[test]
    fn garbage_never_panics() {
        // A cheap fuzz pass: corrupt bytes of a valid image one at a time.
        let good = kernel_like();
        for i in 0..EHDR_SIZE + 3 * PHDR_SIZE {
            for v in [0x00, 0x01, 0x7F, 0x80, 0xFF] {
                let mut b = good.clone();
                b[i] = v;
                if let Ok(elf) = Elf::parse(&b) {
                    for s in elf.segments() {
                        let _ = elf.file_bytes(&s);
                    }
                    let _ = elf.bounds();
                }
            }
        }
    }
}
