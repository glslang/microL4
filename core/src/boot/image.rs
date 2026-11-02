//! The root task's image and address space (`docs/design.md`, "Root-task
//! image and address space" and "Root-task entry state"; `docs/abi.md`,
//! "Initial CSpace" and "Root-task entry state").
//!
//! [`RootImage::check`] takes the ELF file the kernel embeds in
//! `.rootimage` and refuses one the kernel must not load: `l4core::elf`
//! checks the header, that no page is shared by two segments and that the
//! entry lies in an executable segment; this module checks that every
//! segment lies inside `[USER_MIN, USER_TOP - 12 KiB)`, that none is both
//! writable and executable, and that the segments span at most 8 MiB. xtask
//! runs the same check when it embeds the image.
//!
//! From a checked image come the root task's [`RootNeeds`] for the boot
//! plan, and the root VSpace of boot step 8 ([`root_mappings`]): every
//! paging structure and the virtual range it translates, then every frame
//! (image pages, the IPC buffer, BootInfo's two frames) with its page, its
//! permissions and, for an image page, the file bytes it holds, each named
//! by its root CNode slot. The kernel builds the VSpace from that list; this
//! module maps nothing.
//!
//! The paging structures are those that translate
//! `[user_image_start, user_image_end + 12 KiB)`: one PDPT per 512 GiB, one
//! page directory per 1 GiB and one page table per 2 MiB that the range
//! touches, as seL4's `arch_get_n_paging` counts them over its image
//! region. An 8 MiB span plus the three pages after it needs at most 2, 2
//! and 6. A page of the span that no segment covers gets no frame and no
//! mapping, but the page table its 2 MiB needs is made all the same.

#[cfg(test)]
mod tests;

use core::fmt;

use super::{RootLayout, RootNeeds, SlotPlan};
use crate::bootinfo::{BOOTINFO_FRAMES, CAP_BOOTINFO_FRAME, CAP_INIT_IPC_BUFFER};
use crate::cap::CapType;
use crate::elf::{Elf, ElfError, Segment};
use crate::regs::{Exit, Regs};
use crate::vspace::{PAGE_4K, Span, UserAccess};

/// The lowest address a frame may map; page 0 never maps (`docs/abi.md`,
/// "Address spaces", Constants).
pub const USER_MIN: u64 = 0x0000_0000_0000_1000;
/// A frame mapping must end at or below this address.
pub const USER_TOP: u64 = 0x0000_7FFF_FFFF_F000;

/// The most the image's segments may span, from the first segment's page
/// to the end of the last segment's last page.
pub const ROOT_IMAGE_MAX_SPAN: u64 = 8 << 20;
/// Pages mapped right after the image: the IPC buffer, then BootInfo's two
/// frames.
pub const ROOT_EXTRA_PAGES: u64 = 1 + BOOTINFO_FRAMES;
/// The image must end at or below this address, so that the pages after it
/// end at or below [`USER_TOP`].
pub const ROOT_IMAGE_TOP: u64 = USER_TOP - ROOT_EXTRA_PAGES * PAGE_4K;
/// The root task's RFLAGS when it first runs: IF set.
pub const ROOT_RFLAGS: u64 = 0x202;

/// How far each level of paging structure reaches: a PDPT 512 GiB, a page
/// directory 1 GiB, a page table 2 MiB. In `user_image_paging` order.
const LEVELS: [(CapType, u32); 3] = [
    (CapType::Pdpt, 39),
    (CapType::PageDirectory, 30),
    (CapType::PageTable, 21),
];

const fn page_down(a: u64) -> u64 {
    a & !(PAGE_4K - 1)
}

/// Does not overflow for an address `l4core::elf` accepted.
const fn page_up(a: u64) -> u64 {
    (a + PAGE_4K - 1) & !(PAGE_4K - 1)
}

/// Why the kernel refuses a root image. The kernel panics with the
/// `Display` text, and xtask fails the build with it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootImageError {
    /// `l4core::elf` refused the file: not an x86_64 `ET_EXEC`, a page
    /// shared by two segments, or the entry outside every executable
    /// segment, among others.
    Elf(ElfError),
    /// A segment is both writable and executable.
    WritableAndExecutable { vaddr: u64 },
    /// A segment's pages reach below [`USER_MIN`] or above
    /// [`ROOT_IMAGE_TOP`].
    OutsideUserRange { start: u64, end: u64 },
    /// The segments span more than [`ROOT_IMAGE_MAX_SPAN`].
    TooLarge { span: u64 },
}

impl From<ElfError> for RootImageError {
    fn from(e: ElfError) -> Self {
        RootImageError::Elf(e)
    }
}

impl fmt::Display for RootImageError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::Elf(e) => write!(f, "{e}"),
            Self::WritableAndExecutable { vaddr } => {
                write!(f, "the segment at {vaddr:#x} is writable and executable")
            }
            Self::OutsideUserRange { start, end } => write!(
                f,
                "the segment's pages {start:#x}-{end:#x} are not inside {USER_MIN:#x}-{ROOT_IMAGE_TOP:#x}"
            ),
            Self::TooLarge { span } => write!(
                f,
                "the segments span {span:#x} bytes, more than {} MiB",
                ROOT_IMAGE_MAX_SPAN >> 20
            ),
        }
    }
}

/// A root image that passed [`RootImage::check`], borrowing the file.
#[derive(Clone, Copy, Debug)]
pub struct RootImage<'a> {
    elf: Elf<'a>,
    image: Span,
}

/// One page of the image that a segment covers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ImagePage<'a> {
    /// The page's virtual address.
    pub vaddr: u64,
    /// From the segment's flags: always readable, writable with `PF_W`,
    /// executable with `PF_X`.
    pub access: UserAccess,
    /// The file bytes the page holds, which go at `offset` in its frame;
    /// the rest of the frame is zero. Empty for a page of `.bss` alone.
    pub offset: usize,
    pub bytes: &'a [u8],
}

/// A paging structure of the root VSpace.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PagingObject {
    /// [`CapType::Pdpt`], [`CapType::PageDirectory`] or
    /// [`CapType::PageTable`].
    pub ty: CapType,
    /// The virtual range it translates, aligned to its size; it maps at
    /// `span.start`.
    pub span: Span,
}

impl<'a> RootImage<'a> {
    /// Checks `file` as boot step 8 does before loading it.
    pub fn check(file: &'a [u8]) -> Result<RootImage<'a>, RootImageError> {
        let elf = Elf::parse(file)?;
        for s in elf.segments() {
            if s.writable() && s.executable() {
                return Err(RootImageError::WritableAndExecutable { vaddr: s.vaddr });
            }
            let (start, end) = (page_down(s.vaddr), page_up(s.vend()));
            if start < USER_MIN || end > ROOT_IMAGE_TOP {
                return Err(RootImageError::OutsideUserRange { start, end });
            }
        }
        let (start, end) = elf.bounds();
        if end - start > ROOT_IMAGE_MAX_SPAN {
            return Err(RootImageError::TooLarge { span: end - start });
        }
        Ok(RootImage {
            elf,
            image: Span { start, end },
        })
    }

    /// The ELF entry point, the root task's first `rip`.
    pub fn entry(&self) -> u64 {
        self.elf.entry()
    }

    /// `[user_image_start, user_image_end)`: from the first segment's page
    /// to the end of the last segment's last page.
    pub fn image(&self) -> Span {
        self.image
    }

    /// The IPC buffer's page, `user_image_end`, BootInfo's `ipc_buffer`.
    pub fn ipc_buffer(&self) -> u64 {
        self.image.end
    }

    /// BootInfo's first page, `user_image_end + 4 KiB`, the root task's
    /// `rdi`; the second follows it.
    pub fn bootinfo(&self) -> u64 {
        self.image.end + PAGE_4K
    }

    /// Every page the root VSpace maps lies in this range: the image, the
    /// IPC buffer and BootInfo.
    pub fn mapped(&self) -> Span {
        Span {
            start: self.image.start,
            end: self.image.end + ROOT_EXTRA_PAGES * PAGE_4K,
        }
    }

    /// The pages a segment covers, by ascending address: image frame `i`
    /// holds the `i`th.
    pub fn pages(&self) -> impl Iterator<Item = ImagePage<'a>> + use<'a> {
        let elf = self.elf;
        self.segments().flat_map(move |s| {
            let access = UserAccess {
                write: s.writable(),
                execute: s.executable(),
            };
            let file = elf.file_bytes(&s);
            (page_down(s.vaddr)..s.vend())
                .step_by(PAGE_4K as usize)
                .map(move |vaddr| {
                    // The file bytes on this page, if any.
                    let lo = vaddr.max(s.vaddr);
                    let hi = (vaddr + PAGE_4K).min(s.vaddr + s.filesz);
                    let (offset, bytes) = if lo < hi {
                        let at = (lo - s.vaddr) as usize;
                        ((lo - vaddr) as usize, &file[at..at + (hi - lo) as usize])
                    } else {
                        (0, &[][..])
                    };
                    ImagePage {
                        vaddr,
                        access,
                        offset,
                        bytes,
                    }
                })
        })
    }

    /// The non-empty segments by ascending address, whatever their order
    /// in the file. No two share a page: `Elf::parse` refused that.
    fn segments(&self) -> impl Iterator<Item = Segment> + use<'a> {
        let elf = self.elf;
        let mut last = None;
        core::iter::from_fn(move || {
            let next = elf
                .segments()
                .filter(|s| last.is_none_or(|l| s.vaddr > l))
                .min_by_key(|s| s.vaddr)?;
            last = Some(next.vaddr);
            Some(next)
        })
    }

    /// Image frames: pages a segment covers.
    pub fn image_frames(&self) -> u64 {
        self.segments()
            .map(|s| (page_up(s.vend()) - page_down(s.vaddr)) / PAGE_4K)
            .sum()
    }

    /// How many paging structures of the level that reaches `2^bits` bytes
    /// translate [`RootImage::mapped`].
    fn count(&self, bits: u32) -> u64 {
        let m = self.mapped();
        ((m.end - 1) >> bits) - (m.start >> bits) + 1
    }

    /// The paging structures, in `user_image_paging` order: PDPTs, then
    /// page directories, then page tables, each by ascending address.
    pub fn paging(&self) -> impl Iterator<Item = PagingObject> + use<> {
        let m = self.mapped();
        let counts = LEVELS.map(|(_, bits)| self.count(bits));
        LEVELS
            .into_iter()
            .zip(counts)
            .flat_map(move |((ty, bits), n)| {
                let first = m.start >> bits << bits;
                (0..n).map(move |i| PagingObject {
                    ty,
                    span: Span {
                        start: first + (i << bits),
                        end: first + ((i + 1) << bits),
                    },
                })
            })
    }

    /// What the root task needs from the boot region: a TCB, a PML4, the
    /// paging structures of [`RootImage::paging`] and the frames of
    /// [`RootImage::pages`]. The Hypervisor capability is M9's to add.
    pub fn needs(&self) -> RootNeeds {
        let [pdpts, pds, pts] = LEVELS.map(|(_, bits)| self.count(bits));
        RootNeeds {
            tcb: true,
            pml4: true,
            pdpts,
            pds,
            pts,
            image_frames: self.image_frames(),
            hypervisor: None,
        }
    }

    /// The root task's registers when it first runs (`docs/abi.md`,
    /// "Root-task entry state"): `rip` the entry, `rdi` BootInfo, RFLAGS
    /// `0x202`, every other register 0 and the first exit an `iretq`.
    pub fn entry_regs(&self) -> Regs {
        Regs {
            rdi: self.bootinfo(),
            rflags: ROOT_RFLAGS,
            next_ip: self.entry(),
            exit: Exit::Iret as u64,
            ..Regs::default()
        }
    }
}

/// One step of building the root VSpace (boot step 8), naming the
/// capability in root CNode slot `slot`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RootMapping<'a> {
    /// A paging structure: `ty`, at `paddr`, mapped at `vaddr`, the start
    /// of the range it translates.
    Table {
        slot: u64,
        ty: CapType,
        paddr: u64,
        vaddr: u64,
    },
    /// A 4 KiB frame at `paddr`, mapped at `vaddr` with `access`. `bytes`
    /// go at `offset` in it; the rest stays zero, as the boot region is.
    Frame {
        slot: u64,
        paddr: u64,
        vaddr: u64,
        access: UserAccess,
        offset: usize,
        bytes: &'a [u8],
    },
}

/// Everything boot step 8 maps in the root VSpace, given the boot region
/// `layout` and the slot plan `slots`, both made for `image.needs()`:
/// first the paging structures, in `user_image_paging` order, so that each
/// one's parent is mapped before it; then the frames by ascending address:
/// the image's (`user_image_frames`, file bytes to copy), the IPC buffer
/// (slot 10, RW and NX) and BootInfo's two (slots 9 and 16, RW and NX).
///
/// Panics if `layout` or `slots` were made for other needs.
pub fn root_mappings<'a>(
    image: &RootImage<'a>,
    layout: &RootLayout,
    slots: &SlotPlan,
) -> impl Iterator<Item = RootMapping<'a>> + use<'a> {
    let needs = image.needs();
    let made = layout.needs();
    assert!(
        (made.pdpts, made.pds, made.pts, made.image_frames)
            == (needs.pdpts, needs.pds, needs.pts, needs.image_frames)
            && slots.user_image_paging.len() == needs.paging()
            && slots.user_image_frames.len() == needs.image_frames
            && slots.extra_bootinfo_frames.len() == BOOTINFO_FRAMES - 1,
        "the boot plan was not made for this root image"
    );
    let rw = UserAccess {
        write: true,
        execute: false,
    };
    let data = |slot, paddr, vaddr| RootMapping::Frame {
        slot,
        paddr,
        vaddr,
        access: rw,
        offset: 0,
        bytes: &[],
    };
    let tables = image.paging().zip(0..).map({
        let layout = *layout;
        let first = slots.user_image_paging.start;
        move |(p, i)| {
            let (ty, paddr) = layout.paging_object(i);
            debug_assert_eq!(ty, p.ty);
            RootMapping::Table {
                slot: first + i,
                ty,
                paddr,
                vaddr: p.span.start,
            }
        }
    });
    let frames = image.pages().zip(0..).map({
        let layout = *layout;
        let first = slots.user_image_frames.start;
        move |(p, i)| RootMapping::Frame {
            slot: first + i,
            paddr: layout.image_frame(i),
            vaddr: p.vaddr,
            access: p.access,
            offset: p.offset,
            bytes: p.bytes,
        }
    });
    let after = [
        data(CAP_INIT_IPC_BUFFER, layout.ipc_buffer, image.ipc_buffer()),
        data(CAP_BOOTINFO_FRAME, layout.bootinfo, image.bootinfo()),
        data(
            slots.extra_bootinfo_frames.start,
            layout.bootinfo + PAGE_4K,
            image.bootinfo() + PAGE_4K,
        ),
    ];
    tables.chain(frames).chain(after)
}
