//! The boot disk: a GPT image with one EFI system partition holding the
//! loader, the kernel, the command line and the licences of the
//! third-party data the image carries.

use std::fs::{self, File};
use std::io::{Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::compile::{Artifacts, Kernel};
use crate::{Result, output};

const DISK_BYTES: u64 = 64 << 20;
const SECTOR: u64 = 512;

/// Tools the image needs, and the package that provides each.
const TOOLS: &[(&str, &str)] = &[
    ("sgdisk", "gdisk"),
    ("mkfs.fat", "dosfstools"),
    ("mmd", "mtools"),
    ("mcopy", "mtools"),
    ("qemu-img", "qemu-utils"),
];

/// The licence notices the image carries, each from its file in the
/// repository to its path on the ESP. The root image embeds term's font,
/// whose ASCII glyphs are Spleen's: a binary redistribution, for which
/// Spleen's BSD 2-Clause licence asks that the notice come with it
/// (`docs/design.md`, "The font").
pub const LICENCES: &[(&str, &str)] =
    &[("user/term/src/font/LICENSE-spleen", "licenses/spleen.txt")];

/// Builds `dir/disk.img` with `kernel` as `\kernel.elf` and the
/// [`LICENCES`] under `\licenses\`. `cmdline`, if any, goes in
/// `\cmdline.txt`.
pub fn build_disk(
    dir: &Path,
    art: &Artifacts,
    kernel: Kernel,
    cmdline: Option<&str>,
) -> Result<PathBuf> {
    let kernel = art.kernel(kernel)?;
    check_tools()?;
    fs::create_dir_all(dir)?;
    let disk = dir.join("disk.img");
    let esp = dir.join("esp.img");
    let _ = fs::remove_file(&disk);
    let _ = fs::remove_file(&esp);

    // `-o` writes a fresh GPT; without it sgdisk leaves a blank file
    // unpartitioned and OVMF finds nothing to boot.
    File::create(&disk)?.set_len(DISK_BYTES)?;
    output(
        Command::new("sgdisk")
            .args(["-o", "-n", "1:2048:0", "-t", "1:ef00", "-c", "1:ESP"])
            .arg(&disk),
    )?;
    let (first, last) = partition_bounds(&output(
        Command::new("sgdisk").args(["-i", "1"]).arg(&disk),
    )?)?;

    File::create(&esp)?.set_len((last - first + 1) * SECTOR)?;
    output(
        Command::new("mkfs.fat")
            .args(["-F", "32", "-n", "ESP"])
            .arg(&esp),
    )?;
    mtools(
        Command::new("mmd")
            .arg("-i")
            .arg(&esp)
            .args(["::/EFI", "::/EFI/BOOT"]),
    )?;
    mtools(
        Command::new("mcopy")
            .arg("-i")
            .arg(&esp)
            .arg(&art.loader)
            .arg("::/EFI/BOOT/BOOTX64.EFI"),
    )?;
    mtools(
        Command::new("mcopy")
            .arg("-i")
            .arg(&esp)
            .arg(kernel)
            .arg("::/kernel.elf"),
    )?;
    copy_licences(&esp)?;
    if let Some(text) = cmdline {
        let file = dir.join("cmdline.txt");
        fs::write(&file, format!("{text}\n"))?;
        mtools(
            Command::new("mcopy")
                .arg("-i")
                .arg(&esp)
                .arg(&file)
                .arg("::/cmdline.txt"),
        )?;
    }

    let mut out = File::options().write(true).open(&disk)?;
    out.seek(SeekFrom::Start(first * SECTOR))?;
    std::io::copy(&mut File::open(&esp)?, &mut out)?;
    out.flush()?;
    fs::remove_file(&esp)?;
    Ok(disk)
}

/// Copies the [`LICENCES`] into the FAT image `esp`, under `\licenses\`.
fn copy_licences(esp: &Path) -> Result<()> {
    mtools(Command::new("mmd").arg("-i").arg(esp).arg("::/licenses"))?;
    for (from, to) in LICENCES {
        mtools(
            Command::new("mcopy")
                .arg("-i")
                .arg(esp)
                .arg(crate::root().join(from))
                .arg(format!("::/{to}")),
        )?;
    }
    Ok(())
}

/// Converts `disk` to a dynamic VHDX next to it, for Hyper-V.
pub fn to_vhdx(disk: &Path) -> Result<PathBuf> {
    let vhdx = disk.with_extension("vhdx");
    let _ = fs::remove_file(&vhdx);
    output(
        Command::new("qemu-img")
            .args([
                "convert",
                "-f",
                "raw",
                "-O",
                "vhdx",
                "-o",
                "subformat=dynamic",
            ])
            .arg(disk)
            .arg(&vhdx),
    )?;
    Ok(vhdx)
}

fn check_tools() -> Result<()> {
    for (tool, package) in TOOLS {
        if !on_path(tool) {
            return Err(
                format!("{tool} not found; install {package}, or run tools/setup.sh").into(),
            );
        }
    }
    Ok(())
}

pub fn on_path(tool: &str) -> bool {
    std::env::var_os("PATH")
        .is_some_and(|p| std::env::split_paths(&p).any(|d| d.join(tool).is_file()))
}

fn mtools(cmd: &mut Command) -> Result<()> {
    // The ESP image is not a floppy; skip mtools' geometry sanity checks.
    output(cmd.env("MTOOLS_SKIP_CHECK", "1")).map(drop)
}

/// First and last sector of a partition, from `sgdisk -i`.
fn partition_bounds(info: &str) -> Result<(u64, u64)> {
    let field = |name: &str| -> Result<u64> {
        let line = info
            .lines()
            .find_map(|l| l.trim().strip_prefix(name))
            .ok_or_else(|| format!("sgdisk -i: no {name:?}"))?;
        let digits: String = line
            .trim()
            .chars()
            .take_while(char::is_ascii_digit)
            .collect();
        Ok(digits
            .parse()
            .map_err(|_| format!("sgdisk -i: bad {name:?} line"))?)
    };
    let (first, last) = (field("First sector:")?, field("Last sector:")?);
    if first >= last {
        return Err(format!("sgdisk -i: partition {first}..{last} is empty").into());
    }
    Ok((first, last))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Spleen's licence, as its tag has it, goes on the ESP as
    /// `\licenses\spleen.txt`: copied into a FAT image as `build_disk`
    /// copies it, and read back.
    #[test]
    fn the_spleen_licence_goes_on_the_esp() {
        let (from, to) = LICENCES
            .iter()
            .find(|(_, to)| *to == "licenses/spleen.txt")
            .expect("Spleen's licence is one of the image's");
        let licence = fs::read(crate::root().join(from)).unwrap();
        let text = String::from_utf8(licence.clone()).unwrap();
        assert!(
            text.starts_with("Copyright (c) 2018-2026, Frederic Cambus\n")
                && text.contains("Redistribution and use in source and binary forms"),
            "{from} is Spleen's BSD 2-Clause licence"
        );

        check_tools().expect("the image tools; run tools/setup.sh");
        let dir = crate::xtask_dir().join("unit/the_spleen_licence_goes_on_the_esp");
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let esp = dir.join("esp.img");
        File::create(&esp).unwrap().set_len(2 << 20).unwrap();
        output(Command::new("mkfs.fat").arg(&esp)).unwrap();
        copy_licences(&esp).unwrap();
        let back = dir.join("spleen.txt");
        mtools(
            Command::new("mcopy")
                .arg("-i")
                .arg(&esp)
                .arg(format!("::/{to}"))
                .arg(&back),
        )
        .unwrap();
        assert_eq!(fs::read(&back).unwrap(), licence);
        let listing = output(
            Command::new("mdir")
                .env("MTOOLS_SKIP_CHECK", "1")
                .args(["-b", "-i"])
                .arg(&esp)
                .arg("::/licenses"),
        )
        .unwrap();
        assert_eq!(listing.trim(), "::/licenses/spleen.txt", "{listing}");
        fs::remove_dir_all(&dir).unwrap();
    }

    #[test]
    fn parses_sgdisk_info() {
        let info = "Partition GUID code: C12A7328-F81F-11D2-BA4B-00A0C93EC93B (EFI system partition)\n\
                    Partition unique GUID: 0B0E7A6B-6D3D-4E4B-9D5E-1F9E6B4C2A11\n\
                    First sector: 2048 (at 1024.0 KiB)\n\
                    Last sector: 131038 (at 64.0 MiB)\n\
                    Partition size: 128991 sectors (63.0 MiB)\n";
        assert_eq!(partition_bounds(info).unwrap(), (2048, 131038));
    }

    #[test]
    fn rejects_missing_fields() {
        assert!(partition_bounds("First sector: 2048 (at 1024.0 KiB)\n").is_err());
        assert!(partition_bounds("First sector: 9\nLast sector: 9\n").is_err());
    }
}
