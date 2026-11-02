//! Thread control blocks (`docs/design.md`, "Threads and TCBs").
//!
//! A TCB is a 2 KiB object (`TCB_BITS`). Only its size is ABI; the layout
//! below is internal, except that the capability core relies on the five
//! slots lying at offset 0. `core/` names a TCB by a [`TcbRef`], its physical
//! address, and reaches its fields through a trait the kernel implements in
//! `arch` over the direct map and host tests over fake memory. M5 adds the
//! thread states, that trait and the TCB invocations here.

use core::num::NonZeroU64;

use crate::cap::{SLOT_SIZE, TCB_BITS, TCB_SLOTS};
use crate::regs::REGS_WORDS;

/// The five capability slots ([`crate::cap::TCB_SLOT_CSPACE`] and on).
pub const SLOTS_OFFSET: u64 = 0;
/// The user register frame, [`crate::regs::Regs`].
pub const REGS_OFFSET: u64 = SLOTS_OFFSET + TCB_SLOTS * SLOT_SIZE;
/// The scalars: state and blocking data, priority, MCP, time slice, queue
/// and IPC links, pending fault, fault endpoint, IPC buffer, bound
/// notification. At most 256 bytes.
pub const SCALARS_OFFSET: u64 = REGS_OFFSET + REGS_WORDS as u64 * 8;
/// Debug builds only: the two links of the list `DebugDumpScheduler` walks.
pub const DEBUG_OFFSET: u64 = 608;
/// The XSAVE area, standard format, 64-byte aligned, 1024 bytes reserved.
pub const XSAVE_OFFSET: u64 = 1024;
/// Bytes reserved for the XSAVE area.
pub const XSAVE_SIZE: u64 = 1024;

const _: () = assert!(REGS_OFFSET == 160);
const _: () = assert!(SCALARS_OFFSET == 352);
const _: () = assert!(SCALARS_OFFSET + 256 == DEBUG_OFFSET);
const _: () = assert!(XSAVE_OFFSET + XSAVE_SIZE == 1 << TCB_BITS);

/// A TCB, named by its physical address: non-zero and 2 KiB aligned. Made
/// only from a TCB capability or a link the kernel maintains.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct TcbRef(NonZeroU64);

impl TcbRef {
    /// The TCB at `paddr`, if it is a valid TCB address.
    pub const fn new(paddr: u64) -> Option<TcbRef> {
        if paddr & ((1 << TCB_BITS) - 1) != 0 || paddr >= 1 << 52 {
            return None;
        }
        match NonZeroU64::new(paddr) {
            Some(a) => Some(TcbRef(a)),
            None => None,
        }
    }

    /// The physical address.
    pub const fn get(self) -> u64 {
        self.0.get()
    }
}
