//! The paging invocations (`docs/abi.md`, "Address spaces"): mapping
//! paging structures and frames into a VSpace, for a program that builds
//! address spaces of its own, as the root task does for its servers.
//!
//! [`frame_map`] maps a frame of either size: a 4 KiB frame under a page
//! table, a 2 MiB frame (`ObjectType::Frame2M`) straight into the page
//! directory, at an address aligned to [`HUGE_PAGE`] where no page table
//! is mapped. A frame from device untyped maps only [`UNCACHED`] or
//! [`WRITE_COMBINING`], one from RAM only [`WRITE_BACK`].

use l4core::cap::Rights;
use l4core::vspace::label;

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
}
