//! The paging invocations (`docs/abi.md`, "Address spaces"): mapping
//! paging structures and frames into a VSpace, for a program that builds
//! address spaces of its own, as the root task does for its servers.

use l4core::cap::Rights;
use l4core::vspace::label;

use crate::error::Error;
use crate::invoke::invoke;
use crate::syscall::{CPtr, Ipc};

/// Rights words for `Frame_Map` (`docs/abi.md`, "Rights word").
pub const READ: u64 = Rights::READ.0 as u64;
pub const READ_WRITE: u64 = (Rights::READ.0 | Rights::WRITE.0) as u64;

/// Attributes words (`docs/abi.md`, "Attributes word"): write-back RAM,
/// no-execute or executable.
pub const WRITE_BACK: u64 = 0;
pub const EXECUTE: u64 = 1 << 3;

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
}

/// `PDPT_Map`, `PageDirectory_Map` or `PageTable_Map`: the structure
/// `table`, of level `level`, translates the range holding `vaddr` in the
/// VSpace whose PML4 is `vspace`.
pub fn map_table(
    ipc: Ipc,
    table: CPtr,
    level: Table,
    vaddr: u64,
    vspace: CPtr,
) -> Result<(), Error> {
    invoke(Some(ipc), table, level.map_label(), &[vaddr], &[vspace]).map(|_| ())
}

/// `Frame_Map`: `frame` at `vaddr` in `vspace` with the rights word
/// `rights` and the attributes word `attributes`.
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
