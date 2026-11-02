//! Decoding the paging invocations (`docs/abi.md`, "Address spaces",
//! "Invocation labels" to "`Frame_GetAddress`").
//!
//! [`crate::invoke::invoke`] sends every Frame, PDPT, page-directory and
//! page-table capability here; a PML4 capability has no invocations. The
//! label is checked before the message length, as for the other types, and
//! a label of another type or level is `IllegalOperation`. The checks after
//! the length are [`super::paging`]'s, in the ABI's order, and an
//! invocation that fails has changed nothing. A successful one hands its
//! flush to [`PagingStore::flush`] before returning.

use crate::cap::CapType;
use crate::error::SyscallError;
use crate::invoke::{InvokeError, Message, Reply};
use crate::slot::{SlotAddr, SlotMemory};

use super::paging::{self, PagingStore};

/// The labels (`docs/abi.md`, "Invocation labels"). `0x46` to `0x4F` and
/// `0x54` to `0x5F` are reserved.
pub mod label {
    pub const PDPT_MAP: u64 = 0x40;
    pub const PDPT_UNMAP: u64 = 0x41;
    pub const PAGE_DIRECTORY_MAP: u64 = 0x42;
    pub const PAGE_DIRECTORY_UNMAP: u64 = 0x43;
    pub const PAGE_TABLE_MAP: u64 = 0x44;
    pub const PAGE_TABLE_UNMAP: u64 = 0x45;
    pub const FRAME_MAP: u64 = 0x50;
    pub const FRAME_UNMAP: u64 = 0x51;
    pub const FRAME_REMAP: u64 = 0x52;
    /// M9; `IllegalOperation` until then.
    pub const FRAME_GET_ADDRESS: u64 = 0x53;
}

/// MR0 to MR`N - 1`, if the message has them and at least `caps` extra
/// capabilities; else `TruncatedMessage`.
fn args<const N: usize>(msg: &Message<'_>, caps: usize) -> Result<[u64; N], SyscallError> {
    match msg.mrs.first_chunk::<N>() {
        Some(words) if msg.extra_caps.len() >= caps => Ok(*words),
        _ => Err(SyscallError::TruncatedMessage),
    }
}

/// The Map and Unmap labels of a PDPT, page directory or page table.
fn table_labels(ty: CapType) -> Option<(u64, u64)> {
    match ty {
        CapType::Pdpt => Some((label::PDPT_MAP, label::PDPT_UNMAP)),
        CapType::PageDirectory => Some((label::PAGE_DIRECTORY_MAP, label::PAGE_DIRECTORY_UNMAP)),
        CapType::PageTable => Some((label::PAGE_TABLE_MAP, label::PAGE_TABLE_UNMAP)),
        _ => None,
    }
}

/// Decodes and performs the invocation `msg` of the Frame or paging
/// structure capability in `slot`, which the caller has looked up.
///
/// | Capability | Label | Registers | Extra capabilities |
/// | --- | --- | --- | --- |
/// | PDPT, PageDirectory, PageTable | its `_Map` | MR0 `vaddr` | the VSpace |
/// | PDPT, PageDirectory, PageTable | its `_Unmap` | | |
/// | Frame | `Frame_Map` | MR0 `vaddr`, MR1 rights, MR2 attributes | the VSpace |
/// | Frame | `Frame_Unmap` | | |
/// | Frame | `Frame_Remap` | MR0 rights, MR1 attributes | |
///
/// Anything else, `Frame_GetAddress` until M9 and any label on a PML4
/// included, is `IllegalOperation`. No invocation has results.
pub fn invoke<K: SlotMemory + PagingStore + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    let ty = k.load(slot).cap.cap_type();
    let flush = match (ty, table_labels(ty)) {
        (_, Some((map, _))) if msg.label == map => {
            let [vaddr] = args(msg, 1)?;
            paging::map_table(k, slot, msg.extra_caps[0].cap, vaddr)?
        }
        (_, Some((_, unmap))) if msg.label == unmap => paging::unmap_table(k, slot),
        (CapType::Frame, _) => match msg.label {
            label::FRAME_MAP => {
                let [vaddr, rights, attrs] = args(msg, 1)?;
                paging::map_frame(k, slot, msg.extra_caps[0].cap, vaddr, rights, attrs)?
            }
            label::FRAME_UNMAP => paging::unmap_frame(k, slot),
            label::FRAME_REMAP => {
                let [rights, attrs] = args(msg, 0)?;
                paging::remap_frame(k, slot, rights, attrs)?
            }
            _ => return Err(SyscallError::IllegalOperation.into()),
        },
        _ => return Err(SyscallError::IllegalOperation.into()),
    };
    k.flush(flush);
    Ok(Reply::EMPTY)
}
