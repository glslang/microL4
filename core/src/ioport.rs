//! I/O ports (`docs/design.md`, "I/O ports"; `docs/abi.md`,
//! "IOPortControl and IOPort"): the bitmap of issued ports, the ports the
//! kernel keeps, the IOPortControl and IOPort invocations and the
//! deletion hooks.
//!
//! Nothing here executes `in` or `out`: an access is a call of
//! [`IoPorts::port_in`] or [`IoPorts::port_out`] with the port, width and
//! value, which the kernel performs in `arch/x86_64/io.rs` and the host
//! tests record.
//!
//! - `IOPortControl_Issue` checks the range, the kernel's ports and the
//!   bitmap, then the destination slot, and makes an IOPort capability for
//!   `[first, last]`, a revocable child of IOPortControl, whose `data` word
//!   is `first | last << 16`.
//! - `IOPort_In8` to `_Out32` check the port against the capability's
//!   range, the width included, in 32-bit arithmetic, so nothing wraps
//!   past `0xFFFF`.
//! - The last capability with a range frees it: [`finalise`] returns it as
//!   the cleanup and [`after_delete`] clears its bits once its slot is
//!   empty, as seL4's `Arch_finaliseCap` and `Arch_postCapDeletion`.
//!
//! # Orders the ABI leaves open
//!
//! - The destination slot's `depth` is checked before its root, as for
//!   [`crate::irq`].
//! - In and Out ignore extra capabilities and message registers past their
//!   own.

use crate::cap::{Cap, CapType, Rights};
use crate::cdt;
use crate::error::SyscallError;
use crate::invoke::{self, InvokeError, Message, Reply};
use crate::kernel::Kernel;
use crate::slot::SlotAddr;
use crate::tcb::Threads;

/// IOPortControl and IOPort invocation labels (`docs/abi.md`, "Invocation
/// label index"): `0x70` to `0x7F`.
pub mod label {
    pub const ISSUE: u64 = 0x70;
    pub const IN8: u64 = 0x71;
    pub const IN16: u64 = 0x72;
    pub const IN32: u64 = 0x73;
    pub const OUT8: u64 = 0x74;
    pub const OUT16: u64 = 0x75;
    pub const OUT32: u64 = 0x76;
}

/// The highest port.
pub const MAX_PORT: u64 = 0xFFFF;

/// The ports the kernel keeps, never issued: the PIC's and the IMCR's,
/// which could route legacy interrupts past the local APIC's masks
/// (`docs/design.md`, "Ports the kernel uses").
pub const RESERVED: [(u16, u16); 2] = [(0x20, 0x23), (0xA0, 0xA1)];

/// Whether `[first, last]` holds a port the kernel keeps.
pub fn reserved(first: u16, last: u16) -> bool {
    RESERVED.iter().any(|&(a, b)| first <= b && a <= last)
}

/// An access's width.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Width {
    Byte = 1,
    Word = 2,
    Dword = 4,
}

impl Width {
    /// The bytes it covers.
    pub const fn bytes(self) -> u64 {
        self as u64
    }

    /// The bits of a value it carries.
    pub const fn mask(self) -> u32 {
        match self {
            Width::Byte => 0xFF,
            Width::Word => 0xFFFF,
            Width::Dword => u32::MAX,
        }
    }
}

/// An IOPort capability for `[first, last]`.
pub const fn port_cap(first: u16, last: u16) -> Cap {
    Cap::new(
        CapType::IoPort,
        0,
        0,
        Rights::NONE,
        false,
        first as u64 | (last as u64) << 16,
    )
}

/// The range `(first, last)` an IOPort capability holds; `None` for any
/// other capability.
pub fn port_range(cap: &Cap) -> Option<(u16, u16)> {
    (cap.cap_type() == CapType::IoPort).then_some((cap.data as u16, (cap.data >> 16) as u16))
}

/// The 65,536-bit bitmap of issued ports (8 KiB of kernel memory).
#[derive(Clone, PartialEq, Eq)]
pub struct PortBitmap {
    words: [u64; 1024],
}

impl core::fmt::Debug for PortBitmap {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let issued = self.words.iter().map(|w| w.count_ones()).sum::<u32>();
        write!(f, "PortBitmap({issued} ports issued)")
    }
}

impl PortBitmap {
    /// No port issued.
    pub const fn new() -> PortBitmap {
        PortBitmap { words: [0; 1024] }
    }

    /// Whether `port` is issued.
    pub fn is_set(&self, port: u16) -> bool {
        self.words[usize::from(port / 64)] >> (port % 64) & 1 == 1
    }

    /// Whether any port of `[first, last]` is issued.
    pub fn any_set(&self, first: u16, last: u16) -> bool {
        Self::masks(first, last).any(|(w, m)| self.words[w] & m != 0)
    }

    /// Marks `[first, last]` issued (`true`) or free.
    pub fn set_range(&mut self, first: u16, last: u16, issued: bool) {
        for (w, m) in Self::masks(first, last) {
            if issued {
                self.words[w] |= m;
            } else {
                self.words[w] &= !m;
            }
        }
    }

    /// The words `[first, last]` covers, each with the bits it covers
    /// there; `first <= last`.
    fn masks(first: u16, last: u16) -> impl Iterator<Item = (usize, u64)> {
        debug_assert!(first <= last);
        let (fw, lw) = (usize::from(first / 64), usize::from(last / 64));
        (fw..=lw).map(move |w| {
            let lo = if w == fw { u32::from(first % 64) } else { 0 };
            let hi = if w == lw { u32::from(last % 64) } else { 63 };
            (w, (u64::MAX >> (63 - (hi - lo))) << lo)
        })
    }

    /// The issued ports, counted.
    pub fn count(&self) -> u32 {
        self.words.iter().map(|w| w.count_ones()).sum()
    }
}

impl Default for PortBitmap {
    fn default() -> PortBitmap {
        PortBitmap::new()
    }
}

/// What `core::ioport` needs from the kernel: the bitmap, and the port
/// instructions.
pub trait IoPorts {
    /// The bitmap of issued ports.
    fn port_bitmap(&self) -> &PortBitmap;

    /// The bitmap, to change.
    fn port_bitmap_mut(&mut self) -> &mut PortBitmap;

    /// Reads `width` bytes from `port`, zero-extended. The caller checked
    /// that an IOPort capability covers them.
    fn port_in(&mut self, port: u16, width: Width) -> u32;

    /// Writes the low `width` bytes of `value` to `port`. The caller
    /// checked that an IOPort capability covers them.
    fn port_out(&mut self, port: u16, width: Width, value: u32);
}

/// Decodes and performs the IOPortControl invocation `msg` of the
/// capability in `control`: `Issue`.
pub fn invoke_control<K: Kernel + IoPorts + ?Sized>(
    k: &mut K,
    control: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    if msg.label != label::ISSUE {
        return Err(SyscallError::IllegalOperation.into());
    }
    let [first, last, index, depth] = msg.args(1)?;
    if first > MAX_PORT {
        return Err(SyscallError::InvalidArgument(0).into());
    }
    if last > MAX_PORT || last < first {
        return Err(SyscallError::InvalidArgument(1).into());
    }
    let (first, last) = (first as u16, last as u16);
    if reserved(first, last) {
        return Err(SyscallError::InvalidArgument(0).into());
    }
    if k.port_bitmap().any_set(first, last) {
        return Err(SyscallError::RevokeFirst.into());
    }
    let dst = invoke::destination(k, msg.cap(0), index, depth)?;
    k.port_bitmap_mut().set_range(first, last, true);
    cdt::insert_derived(k, control, dst, port_cap(first, last), true)
        .expect("IOPortControl is a derivation root, which cannot be copied");
    Ok(Reply::EMPTY)
}

/// Decodes and performs the IOPort invocation `msg` of the capability in
/// `slot`: In and Out of 8, 16 and 32 bits.
pub fn invoke_port<K: Threads + IoPorts + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    let (first, last) = port_range(&k.load(slot).cap).expect("an IOPort capability");
    let (width, out) = match msg.label {
        label::IN8 => (Width::Byte, false),
        label::IN16 => (Width::Word, false),
        label::IN32 => (Width::Dword, false),
        label::OUT8 => (Width::Byte, true),
        label::OUT16 => (Width::Word, true),
        label::OUT32 => (Width::Dword, true),
        _ => return Err(SyscallError::IllegalOperation.into()),
    };
    let (port, value) = if out {
        let [port, value] = msg.args(0)?;
        (port, value)
    } else {
        let [port] = msg.args(0)?;
        (port, 0)
    };
    if port > MAX_PORT {
        return Err(SyscallError::InvalidArgument(0).into());
    }
    if port < u64::from(first) || port + width.bytes() - 1 > u64::from(last) {
        return Err(SyscallError::IllegalOperation.into());
    }
    let port = port as u16;
    if out {
        k.port_out(port, width, value as u32 & width.mask());
        Ok(Reply::EMPTY)
    } else {
        let v = k.port_in(port, width) & width.mask();
        Ok(invoke::results(k, &[u64::from(v)]))
    }
}

/// The IOPort arm of the kernel's `finalise` hook: the last capability
/// with a range returns itself as the cleanup.
pub fn finalise(cap: Cap, last: bool) -> Option<Cap> {
    (last && cap.cap_type() == CapType::IoPort).then_some(cap)
}

/// The IOPort arm of the kernel's `after_delete` hook: the range of the
/// last capability, whose slot is now empty, can be issued again.
pub fn after_delete<E: IoPorts + ?Sized>(e: &mut E, cap: Cap) {
    if let Some((first, last)) = port_range(&cap) {
        e.port_bitmap_mut().set_range(first, last, false);
    }
}

#[cfg(test)]
mod tests;
