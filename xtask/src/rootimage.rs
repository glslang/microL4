//! The root image: `user/root`'s ELF, stripped and checked, which the kernel
//! embeds in `.rootimage` (`docs/design.md`, "Root-task image and address
//! space").
//!
//! Stripping keeps the ELF header, the program headers and the bytes of
//! every segment, and drops everything else: section headers, symbols and
//! debug information. Bytes between segments that no header names are
//! zeroed, so nothing but loadable data travels in the kernel. The result is
//! then checked with `l4core::boot::image`, the same check boot step 8
//! makes, so an image the kernel would refuse fails the build instead,
//! among them one whose `PT_LOAD` segments span more than 8 MiB.

use std::fs;
use std::path::Path;

use l4core::boot::image::{ROOT_IMAGE_MAX_SPAN, RootImage};
use l4core::elf::Elf;

use crate::Result;

const EHDR_SIZE: usize = 64;
const PHDR_SIZE: usize = 56;

fn u16_at(b: &[u8], off: usize) -> u16 {
    u16::from_le_bytes([b[off], b[off + 1]])
}

fn u64_at(b: &[u8], off: usize) -> u64 {
    u64::from_le_bytes(b[off..off + 8].try_into().unwrap())
}

/// `elf` with only its ELF header, program headers and segment bytes.
pub fn strip(elf: &[u8]) -> Result<Vec<u8>> {
    Elf::parse(elf).map_err(|e| format!("not an ELF executable the kernel loads: {e}"))?;
    // `Elf::parse` checked the header and that the program-header table
    // lies inside the file.
    let phoff = u64_at(elf, 32) as usize;
    let phentsize = usize::from(u16_at(elf, 54));
    let phnum = usize::from(u16_at(elf, 56));
    let mut keep = vec![(0, EHDR_SIZE), (phoff, phoff + phentsize * phnum)];
    for i in 0..phnum {
        let ph = &elf[phoff + i * phentsize..][..PHDR_SIZE];
        let (offset, filesz) = (u64_at(ph, 8), u64_at(ph, 32));
        let end = offset
            .checked_add(filesz)
            .filter(|&end| end <= elf.len() as u64)
            .ok_or_else(|| format!("program header {i} names bytes past the end of the file"))?;
        keep.push((offset as usize, end as usize));
    }
    let len = keep.iter().map(|&(_, end)| end).max().unwrap_or(0);
    let mut out = vec![0; len];
    for (start, end) in keep {
        out[start..end].copy_from_slice(&elf[start..end]);
    }
    // No section headers: e_shoff, e_shentsize, e_shnum and e_shstrndx.
    out[40..48].fill(0);
    out[58..64].fill(0);
    Ok(out)
}

/// What `pack` made, for `cargo xtask build` to report.
pub struct Packed {
    pub bytes: usize,
    pub entry: u64,
    pub image: (u64, u64),
    pub frames: u64,
}

/// Strips the ELF at `elf`, checks it as boot step 8 will, and writes it to
/// `out`, leaving `out` untouched if it already holds those bytes so that
/// cargo does not rebuild the kernel for nothing.
pub fn pack(elf: &Path, out: &Path) -> Result<Packed> {
    let file = fs::read(elf).map_err(|e| format!("cannot read {}: {e}", elf.display()))?;
    let stripped = strip(&file).map_err(|e| format!("{}: {e}", elf.display()))?;
    let image = RootImage::check(&stripped).map_err(|e| {
        format!(
            "{}: the kernel would refuse this root image: {e} (it must span at most {} MiB)",
            elf.display(),
            ROOT_IMAGE_MAX_SPAN >> 20
        )
    })?;
    let packed = Packed {
        bytes: stripped.len(),
        entry: image.entry(),
        image: (image.image().start, image.image().end),
        frames: image.image_frames(),
    };
    if fs::read(out).ok().as_deref() != Some(&stripped[..]) {
        if let Some(dir) = out.parent() {
            fs::create_dir_all(dir)?;
        }
        fs::write(out, &stripped)?;
    }
    Ok(packed)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An ELF with two `PT_LOAD` segments, a `PT_GNU_STACK`, junk between
    /// and after the segments, and a section-header table at the end.
    fn sample(span_end: u64) -> Vec<u8> {
        let mut f = vec![0u8; 0x3000];
        f[0..4].copy_from_slice(b"\x7fELF");
        f[4] = 2;
        f[5] = 1;
        f[6] = 1;
        f[16..18].copy_from_slice(&2u16.to_le_bytes());
        f[18..20].copy_from_slice(&62u16.to_le_bytes());
        f[20..24].copy_from_slice(&1u32.to_le_bytes());
        f[24..32].copy_from_slice(&0x40_0000u64.to_le_bytes());
        f[32..40].copy_from_slice(&64u64.to_le_bytes());
        f[40..48].copy_from_slice(&0x2F00u64.to_le_bytes()); // e_shoff
        f[52..54].copy_from_slice(&64u16.to_le_bytes());
        f[54..56].copy_from_slice(&56u16.to_le_bytes());
        f[56..58].copy_from_slice(&3u16.to_le_bytes());
        f[58..60].copy_from_slice(&64u16.to_le_bytes());
        f[60..62].copy_from_slice(&4u16.to_le_bytes());
        f[62..64].copy_from_slice(&3u16.to_le_bytes());
        let phs: [(u32, u32, u64, u64, u64, u64); 3] = [
            (1, 5, 0x1000, 0x40_0000, 0x100, 0x100),
            (1, 6, 0x2000, 0x40_1000, 0x80, span_end - 0x40_1000),
            (0x6474_e551, 6, 0, 0, 0, 0),
        ];
        for (i, (ty, flags, off, vaddr, filesz, memsz)) in phs.into_iter().enumerate() {
            let h = &mut f[64 + 56 * i..][..56];
            h[0..4].copy_from_slice(&ty.to_le_bytes());
            h[4..8].copy_from_slice(&flags.to_le_bytes());
            h[8..16].copy_from_slice(&off.to_le_bytes());
            h[16..24].copy_from_slice(&vaddr.to_le_bytes());
            h[32..40].copy_from_slice(&filesz.to_le_bytes());
            h[40..48].copy_from_slice(&memsz.to_le_bytes());
        }
        f[0x1000..0x1100].fill(0x90);
        f[0x1100..0x2000].fill(0xEE); // junk between segments
        f[0x2000..0x2080].fill(0x11);
        f[0x2080..].fill(0xEE); // symbols, debug info, section headers
        f
    }

    #[test]
    fn strip_keeps_headers_and_segments_only() {
        let elf = sample(0x40_2000);
        let out = strip(&elf).unwrap();
        assert_eq!(out.len(), 0x2080);
        assert_eq!(out[..40], elf[..40]);
        assert_eq!(out[40..48], [0; 8]);
        assert_eq!(out[48..58], elf[48..58]);
        assert_eq!(out[58..64], [0; 6]);
        assert_eq!(out[64..64 + 3 * 56], elf[64..64 + 3 * 56]);
        assert!(out[64 + 3 * 56..0x1000].iter().all(|&b| b == 0));
        assert!(out[0x1000..0x1100].iter().all(|&b| b == 0x90));
        assert!(out[0x1100..0x2000].iter().all(|&b| b == 0));
        assert!(out[0x2000..].iter().all(|&b| b == 0x11));
        // The stripped file loads the same segments.
        let (a, b) = (Elf::parse(&elf).unwrap(), Elf::parse(&out).unwrap());
        assert!(a.segments().eq(b.segments()));
        assert_eq!(a.entry(), b.entry());
        assert!(RootImage::check(&out).is_ok());
    }

    #[test]
    fn strip_refuses_what_is_not_an_executable() {
        assert!(strip(b"not an elf").is_err());
        let mut elf = sample(0x40_2000);
        elf[16] = 3; // ET_DYN
        assert!(strip(&elf).is_err());
    }

    #[test]
    fn pack_refuses_a_span_over_8_mib() {
        let dir = std::env::temp_dir().join(format!("xtask-rootimage-{}", std::process::id()));
        fs::create_dir_all(&dir).unwrap();
        let (src, out) = (dir.join("root"), dir.join("root.elf"));

        fs::write(&src, sample(0x40_0000 + (8 << 20))).unwrap();
        let p = pack(&src, &out).unwrap();
        assert_eq!((p.image, p.frames), ((0x40_0000, 0xC0_0000), 2048));
        assert_eq!(fs::read(&out).unwrap().len(), 0x2080);

        fs::write(&src, sample(0x40_0000 + (8 << 20) + 1)).unwrap();
        let e = pack(&src, &out).err().unwrap().to_string();
        assert!(e.contains("more than 8 MiB"), "{e}");
        fs::remove_dir_all(&dir).unwrap();
    }
}
