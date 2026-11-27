//! The paging invocations (`docs/abi.md`, "Address spaces"): mapping
//! paging structures and frames into a VSpace, for a program that builds
//! address spaces of its own, as the root task does for its servers.
//!
//! [`frame_map`] maps a frame of either size: a 4 KiB frame under a page
//! table, a 2 MiB frame (`ObjectType::Frame2M`) straight into the page
//! directory, at an address aligned to [`HUGE_PAGE`] where no page table
//! is mapped. A frame from device untyped maps only [`UNCACHED`] or
//! [`WRITE_COMBINING`], one from RAM only [`WRITE_BACK`].
//!
//! [`frame_get_address`] (M9) gives a frame's physical address, which is
//! also the bus address a device's DMA uses: the address root passes a
//! driver for its DMA frame, or `vmbus` posts in a GPADL.

use l4core::cap::Rights;
use l4core::vspace::label;

use crate::device::{Request, undecoded, word};
use crate::error::Error;
use crate::invoke::invoke;
use crate::syscall::{CPtr, Ipc};

/// Rights words for `Frame_Map` (`docs/abi.md`, "Rights word").
pub const READ: u64 = Rights::READ.0 as u64;
pub const READ_WRITE: u64 = (Rights::READ.0 | Rights::WRITE.0) as u64;

/// Attributes words (`docs/abi.md`, "Attributes word"): bits 0 to 2 the
/// cache type, the PAT index: write-back for RAM; uncached or
/// write-combining for device memory, such as the framebuffer.
pub const WRITE_BACK: u64 = 0;
pub const UNCACHED: u64 = 3;
pub const WRITE_COMBINING: u64 = 4;
/// Bit 3: executable; clear, no-execute.
pub const EXECUTE: u64 = 1 << 3;

/// A small frame's bytes, and a large one's.
pub const PAGE: u64 = 1 << 12;
pub const HUGE_PAGE: u64 = 1 << 21;

/// A paging structure's level, for [`map_table`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Table {
    Pdpt,
    PageDirectory,
    PageTable,
}

impl Table {
    /// Bytes one structure of this level translates.
    pub const fn span(self) -> u64 {
        match self {
            Table::Pdpt => 1 << 39,
            Table::PageDirectory => 1 << 30,
            Table::PageTable => 1 << 21,
        }
    }

    const fn map_label(self) -> u64 {
        match self {
            Table::Pdpt => label::PDPT_MAP,
            Table::PageDirectory => label::PAGE_DIRECTORY_MAP,
            Table::PageTable => label::PAGE_TABLE_MAP,
        }
    }

    const fn unmap_label(self) -> u64 {
        match self {
            Table::Pdpt => label::PDPT_UNMAP,
            Table::PageDirectory => label::PAGE_DIRECTORY_UNMAP,
            Table::PageTable => label::PAGE_TABLE_UNMAP,
        }
    }
}

/// `PDPT_Map`, `PageDirectory_Map` or `PageTable_Map`: the structure
/// `table`, of level `level`, translates the range holding `vaddr` in the
/// VSpace whose PML4 is `vspace`. The structure must be unmapped and
/// empty: one that held frames is moved with [`unmap_table`] first.
pub fn map_table(
    ipc: Ipc,
    table: CPtr,
    level: Table,
    vaddr: u64,
    vspace: CPtr,
) -> Result<(), Error> {
    invoke(Some(ipc), table, level.map_label(), &[vaddr], &[vspace]).map(|_| ())
}

/// `PDPT_Unmap`, `PageDirectory_Unmap` or `PageTable_Unmap`: removes the
/// structure from its VSpace and unmaps everything mapped in it, leaving
/// it unmapped and empty, so it can be mapped again, in any VSpace.
pub fn unmap_table(table: CPtr, level: Table) -> Result<(), Error> {
    invoke(None, table, level.unmap_label(), &[], &[]).map(|_| ())
}

/// `Frame_Map`: `frame`, of either size, at `vaddr` (aligned to its size)
/// in `vspace` with the rights word `rights` and the attributes word
/// `attributes`.
pub fn frame_map(
    ipc: Ipc,
    frame: CPtr,
    vaddr: u64,
    rights: u64,
    attributes: u64,
    vspace: CPtr,
) -> Result<(), Error> {
    invoke(
        Some(ipc),
        frame,
        label::FRAME_MAP,
        &[vaddr, rights, attributes],
        &[vspace],
    )
    .map(|_| ())
}

/// `Frame_Unmap`: removes the mapping of this frame capability, if any.
pub fn frame_unmap(frame: CPtr) -> Result<(), Error> {
    invoke(None, frame, label::FRAME_UNMAP, &[], &[]).map(|_| ())
}

/// The most bits a physical address has on x86-64.
const MAX_PHYS_BITS: u32 = 52;

/// `Frame_GetAddress`'s message: the label, no registers, no extra
/// capabilities.
pub const fn get_address_request() -> Request {
    Request::new(label::FRAME_GET_ADDRESS, &[], &[])
}

/// The physical address a `Frame_GetAddress` result word names, or `None`
/// for one the kernel never returns: not page-aligned, or at or past
/// 2^52.
pub const fn frame_address(word: u64) -> Option<u64> {
    if word.is_multiple_of(PAGE) && word >> MAX_PHYS_BITS == 0 {
        Some(word)
    } else {
        None
    }
}

/// `Frame_GetAddress` (M9): the physical address of the frame's first
/// byte, for any frame capability (RAM or device, either size, mapped or
/// not, any rights). Without an IOMMU it is also the bus address a
/// device's DMA uses; DMA into a `WriteBack` RAM frame is coherent.
/// Deleting the frame or revoking its untyped does not stop a device that
/// was given the address: stop the device first. Needs no IPC buffer.
pub fn frame_get_address(frame: CPtr) -> Result<u64, Error> {
    let r = get_address_request().call(None, frame)?;
    frame_address(word(&r, 0)?).ok_or_else(|| undecoded(&r))
}

#[cfg(test)]
mod tests {
    use super::*;
    use l4core::vspace::paging::Attributes;

    /// The attributes words are the ABI's: the PAT indices, and the
    /// execute bit.
    #[test]
    fn attribute_words_are_the_abis() {
        assert_eq!((WRITE_BACK, UNCACHED, WRITE_COMBINING), (0, 3, 4));
        for x in [0, EXECUTE] {
            assert!(Attributes::decode(WRITE_BACK | x, false).is_some());
            for w in [UNCACHED, WRITE_COMBINING] {
                assert!(Attributes::decode(w | x, true).is_some(), "{:#x}", w | x);
                assert!(Attributes::decode(w | x, false).is_none(), "{:#x}", w | x);
            }
        }
        assert_eq!(Table::PageTable.span(), HUGE_PAGE);
        assert_eq!(
            [Table::Pdpt, Table::PageDirectory, Table::PageTable].map(Table::unmap_label),
            [0x41, 0x43, 0x45]
        );
    }

    /// `Frame_GetAddress` is label `0x53` with no registers and no extra
    /// capabilities, and its one result word is a page-aligned physical
    /// address.
    #[test]
    fn get_address_is_the_abis() {
        let r = get_address_request();
        assert_eq!((r.label, r.args(), r.caps()), (0x53, &[][..], &[][..]));
        for a in [
            0,
            0x1000,
            0x20_0000,
            0xE000_0000,
            0x8_0000_0000,
            (1 << 52) - 0x1000,
        ] {
            assert_eq!(frame_address(a), Some(a));
        }
        for a in [0x800, 0x1001, 1 << 52, !0xFFF] {
            assert_eq!(frame_address(a), None, "{a:#x}");
        }
    }
}
