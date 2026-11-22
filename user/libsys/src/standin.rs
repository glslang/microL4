//! Stand-ins for the IRQControl, IRQHandler, IOPortControl and IOPort
//! wrappers (`docs/abi.md`, "Interrupts, I/O ports and Hyper-V"), which
//! another M7 builder adds to `libsys` as `libsys::device` beside the
//! kernel side. They carry that module's names and signatures, so the
//! integrator replaces every `standin::` path with `device::` and deletes
//! this file; only `output`, `uart`'s run loop and the root task's server
//! setup call them.

use crate::error::Error;
use crate::invoke::{Slot, invoke};
use crate::syscall::{CPtr, Ipc};

/// Invocation labels (`docs/abi.md`, "Invocation label index").
mod label {
    pub const IRQ_CONTROL_GET_ISA: u64 = 0x60;
    pub const IRQ_HANDLER_ACK: u64 = 0x68;
    pub const IRQ_HANDLER_SET_NOTIFICATION: u64 = 0x69;
    pub const IRQ_HANDLER_CLEAR: u64 = 0x6A;
    pub const IOPORT_CONTROL_ISSUE: u64 = 0x70;
    pub const IOPORT_IN8: u64 = 0x71;
    pub const IOPORT_IN16: u64 = 0x72;
    pub const IOPORT_IN32: u64 = 0x73;
    pub const IOPORT_OUT8: u64 = 0x74;
    pub const IOPORT_OUT16: u64 = 0x75;
    pub const IOPORT_OUT32: u64 = 0x76;
}

/// What `IRQControl_GetISA` returns: the IRQ number, the GSI, and the
/// trigger and polarity (MR2's bits 0 and 1).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsaIrq {
    pub irq: u8,
    pub gsi: u32,
    pub level: bool,
    pub active_low: bool,
}

/// `IRQControl_GetISA`: a handler for ISA IRQ `isa_irq` in `dest`.
pub fn irq_control_get_isa(
    ipc: Ipc,
    control: CPtr,
    isa_irq: u64,
    dest: Slot,
) -> Result<IsaIrq, Error> {
    let r = invoke(
        Some(ipc),
        control,
        label::IRQ_CONTROL_GET_ISA,
        &[isa_irq, dest.index, dest.depth],
        &[dest.root],
    )?;
    Ok(IsaIrq {
        irq: r.mr[0] as u8,
        gsi: r.mr[1] as u32,
        level: r.mr[2] & 1 != 0,
        active_low: r.mr[2] & 2 != 0,
    })
}

/// `IRQHandler_Ack`.
pub fn irq_handler_ack(handler: CPtr) -> Result<(), Error> {
    invoke(None, handler, label::IRQ_HANDLER_ACK, &[], &[]).map(|_| ())
}

/// `IRQHandler_SetNotification`: binds `ntfn`, a notification capability
/// with Write, badge included.
pub fn irq_handler_set_notification(ipc: Ipc, handler: CPtr, ntfn: CPtr) -> Result<(), Error> {
    invoke(
        Some(ipc),
        handler,
        label::IRQ_HANDLER_SET_NOTIFICATION,
        &[],
        &[ntfn],
    )
    .map(|_| ())
}

/// `IRQHandler_Clear`.
pub fn irq_handler_clear(handler: CPtr) -> Result<(), Error> {
    invoke(None, handler, label::IRQ_HANDLER_CLEAR, &[], &[]).map(|_| ())
}

/// `IOPortControl_Issue`: an IOPort capability for `first..=last` in
/// `dest`.
pub fn ioport_control_issue(
    ipc: Ipc,
    control: CPtr,
    first: u16,
    last: u16,
    dest: Slot,
) -> Result<(), Error> {
    invoke(
        Some(ipc),
        control,
        label::IOPORT_CONTROL_ISSUE,
        &[first.into(), last.into(), dest.index, dest.depth],
        &[dest.root],
    )
    .map(|_| ())
}

fn port_in(cap: CPtr, label: u64, port: u16) -> Result<u64, Error> {
    invoke(None, cap, label, &[port.into()], &[]).map(|r| r.mr[0])
}

fn port_out(cap: CPtr, label: u64, port: u16, value: u64) -> Result<(), Error> {
    invoke(None, cap, label, &[port.into(), value], &[]).map(|_| ())
}

/// `IOPort_In8`.
pub fn ioport_in8(cap: CPtr, port: u16) -> Result<u8, Error> {
    port_in(cap, label::IOPORT_IN8, port).map(|v| v as u8)
}

/// `IOPort_In16`.
pub fn ioport_in16(cap: CPtr, port: u16) -> Result<u16, Error> {
    port_in(cap, label::IOPORT_IN16, port).map(|v| v as u16)
}

/// `IOPort_In32`.
pub fn ioport_in32(cap: CPtr, port: u16) -> Result<u32, Error> {
    port_in(cap, label::IOPORT_IN32, port).map(|v| v as u32)
}

/// `IOPort_Out8`.
pub fn ioport_out8(cap: CPtr, port: u16, value: u8) -> Result<(), Error> {
    port_out(cap, label::IOPORT_OUT8, port, value.into())
}

/// `IOPort_Out16`.
pub fn ioport_out16(cap: CPtr, port: u16, value: u16) -> Result<(), Error> {
    port_out(cap, label::IOPORT_OUT16, port, value.into())
}

/// `IOPort_Out32`.
pub fn ioport_out32(cap: CPtr, port: u16, value: u32) -> Result<(), Error> {
    port_out(cap, label::IOPORT_OUT32, port, value.into())
}
