//! Interrupts and I/O ports: the IRQControl, IRQHandler, IOPortControl and
//! IOPort invocations (`docs/abi.md`, "Interrupts, I/O ports and
//! Hyper-V").
//!
//! Each wrapper builds its message with a [`Request`], so the encoding is
//! host-tested, and sends it by `Call` through [`crate::invoke::invoke`].
//! The issues travel a destination CNode as an extra capability, so they
//! take the caller's [`Ipc`]; `Ack`, `Clear`, In and Out need no buffer and
//! work in any thread.
//!
//! A driver binds its handler, Acks once and services its device once, then
//! loops by its pin's trigger (ADR 0028): an edge pin (ISA IRQ 4, COM1's,
//! on both platforms) wait, Ack, service; a level pin wait, service, Ack.

use l4core::ioport::{Width, label as port_label};
use l4core::irq::label as irq_label;

use crate::error::Error;
use crate::invoke::{Reply, Slot, invoke};
use crate::syscall::{CPtr, Ipc};

/// One invocation's message: label, message registers and extra
/// capabilities, as `docs/abi.md` lays them out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub label: u64,
    args: [u64; 5],
    len: usize,
    caps: [CPtr; 1],
    n_caps: usize,
}

impl Request {
    const fn new(label: u64, args: &[u64], caps: &[CPtr]) -> Request {
        let mut a = [0; 5];
        let mut i = 0;
        while i < args.len() {
            a[i] = args[i];
            i += 1;
        }
        let mut c = [0; 1];
        if !caps.is_empty() {
            c[0] = caps[0];
        }
        Request {
            label,
            args: a,
            len: args.len(),
            caps: c,
            n_caps: caps.len(),
        }
    }

    /// The message registers, MR0 first.
    pub fn args(&self) -> &[u64] {
        &self.args[..self.len]
    }

    /// The extra capabilities.
    pub fn caps(&self) -> &[CPtr] {
        &self.caps[..self.n_caps]
    }

    /// Sends it to `cap` by `Call`; `ipc` must be the caller's buffer if
    /// it has more than four registers or a capability.
    fn call(&self, ipc: Option<Ipc>, cap: CPtr) -> Result<Reply, Error> {
        invoke(ipc, cap, self.label, self.args(), self.caps())
    }

    /// `IRQControl_GetISA`: MR0 `isa_irq`, then the destination.
    pub const fn get_isa(isa_irq: u64, dest: Slot) -> Request {
        Request::new(
            irq_label::GET_ISA,
            &[isa_irq, dest.index, dest.depth],
            &[dest.root],
        )
    }

    /// `IRQControl_GetIOAPIC`: MR0 `gsi`, MR1 `trigger` (1 level), MR2
    /// `polarity` (1 active low), then the destination.
    pub const fn get_ioapic(gsi: u64, level: bool, active_low: bool, dest: Slot) -> Request {
        Request::new(
            irq_label::GET_IOAPIC,
            &[gsi, level as u64, active_low as u64, dest.index, dest.depth],
            &[dest.root],
        )
    }

    /// `IRQHandler_Ack`.
    pub const fn ack() -> Request {
        Request::new(irq_label::ACK, &[], &[])
    }

    /// `IRQHandler_SetNotification` with the notification capability
    /// `ntfn`.
    pub const fn set_notification(ntfn: CPtr) -> Request {
        Request::new(irq_label::SET_NOTIFICATION, &[], &[ntfn])
    }

    /// `IRQHandler_Clear`.
    pub const fn clear() -> Request {
        Request::new(irq_label::CLEAR, &[], &[])
    }

    /// `IOPortControl_Issue`: MR0 `first_port`, MR1 `last_port`, then the
    /// destination.
    pub const fn issue(first: u64, last: u64, dest: Slot) -> Request {
        Request::new(
            port_label::ISSUE,
            &[first, last, dest.index, dest.depth],
            &[dest.root],
        )
    }

    /// `IOPort_In8`, `_In16` or `_In32` of `port`.
    pub const fn port_in(width: Width, port: u64) -> Request {
        let label = match width {
            Width::Byte => port_label::IN8,
            Width::Word => port_label::IN16,
            Width::Dword => port_label::IN32,
        };
        Request::new(label, &[port], &[])
    }

    /// `IOPort_Out8`, `_Out16` or `_Out32` of `value`'s low bytes to
    /// `port`.
    pub const fn port_out(width: Width, port: u64, value: u64) -> Request {
        let label = match width {
            Width::Byte => port_label::OUT8,
            Width::Word => port_label::OUT16,
            Width::Dword => port_label::OUT32,
        };
        Request::new(label, &[port, value], &[])
    }
}

/// What `IRQControl_GetISA` returns: the IRQ, and the GSI and flags the
/// MADT's route gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IsaIrq {
    pub irq: u8,
    pub gsi: u32,
    pub level: bool,
    pub active_low: bool,
}

impl IsaIrq {
    /// Decodes the result words MR0 `irq`, MR1 `gsi` and MR2 `flags` (bit
    /// 0 level-triggered, bit 1 active low); `None` for values the kernel
    /// never returns.
    pub fn from_words(irq: u64, gsi: u64, flags: u64) -> Option<IsaIrq> {
        if flags > 3 {
            return None;
        }
        Some(IsaIrq {
            irq: u8::try_from(irq).ok()?,
            gsi: u32::try_from(gsi).ok()?,
            level: flags & 1 != 0,
            active_low: flags & 2 != 0,
        })
    }
}

/// The result word `i` of `reply`, or an undecodable-reply error if the
/// kernel sent fewer.
fn word(reply: &Reply, i: usize) -> Result<u64, Error> {
    if i < reply.length() {
        Ok(reply.word(i))
    } else {
        Err(undecoded(reply))
    }
}

fn undecoded(reply: &Reply) -> Error {
    Error::Undecoded {
        label: 0,
        length: reply.length() as u64,
        words: [0; crate::error::MAX_DETAIL_WORDS],
    }
}

/// `IRQControl_GetISA`: a handler for ISA IRQ `isa_irq`, routed through
/// the MADT's overrides, into `dest`. `RevokeFirst` if its GSI has a
/// handler, no vector is free or the pin's Remote IRR stays set (retry
/// later); `InvalidArgument(0)` if the IRQ has no route.
pub fn irq_control_get_isa(
    ipc: Ipc,
    control: CPtr,
    isa_irq: u64,
    dest: Slot,
) -> Result<IsaIrq, Error> {
    let r = Request::get_isa(isa_irq, dest).call(Some(ipc), control)?;
    IsaIrq::from_words(word(&r, 0)?, word(&r, 1)?, word(&r, 2)?).ok_or_else(|| undecoded(&r))
}

/// `IRQControl_GetIOAPIC`: a handler for `gsi` with the trigger and
/// polarity given and no override, into `dest`; returns the IRQ.
pub fn irq_control_get_ioapic(
    ipc: Ipc,
    control: CPtr,
    gsi: u64,
    level: bool,
    active_low: bool,
    dest: Slot,
) -> Result<u8, Error> {
    let r = Request::get_ioapic(gsi, level, active_low, dest).call(Some(ipc), control)?;
    u8::try_from(word(&r, 0)?).map_err(|_| undecoded(&r))
}

/// `IRQHandler_Ack`: clears the pin's `pending` and unmasks it if the
/// kernel masked it.
pub fn irq_handler_ack(handler: CPtr) -> Result<(), Error> {
    Request::ack().call(None, handler)?;
    Ok(())
}

/// `IRQHandler_SetNotification`: from now on the IRQ signals the
/// notification `ntfn` names (a capability with Write), with its badge;
/// any earlier binding is removed. `InvalidCapability(1)` for anything
/// else.
pub fn irq_handler_set_notification(ipc: Ipc, handler: CPtr, ntfn: CPtr) -> Result<(), Error> {
    Request::set_notification(ntfn).call(Some(ipc), handler)?;
    Ok(())
}

/// `IRQHandler_Clear`: unbinds the notification, if any; interrupts are
/// then lost, though the pin's state advances.
pub fn irq_handler_clear(handler: CPtr) -> Result<(), Error> {
    Request::clear().call(None, handler)?;
    Ok(())
}

/// `IOPortControl_Issue`: an IOPort capability for ports `first` to
/// `last` into `dest`. `RevokeFirst` if any of them is issued;
/// `InvalidArgument(0)` for a range holding a port the kernel keeps
/// (`0x20`-`0x23`, `0xA0`-`0xA1`).
pub fn ioport_control_issue(
    ipc: Ipc,
    control: CPtr,
    first: u16,
    last: u16,
    dest: Slot,
) -> Result<(), Error> {
    Request::issue(u64::from(first), u64::from(last), dest).call(Some(ipc), control)?;
    Ok(())
}

fn port_in(cap: CPtr, width: Width, port: u16) -> Result<u32, Error> {
    let r = Request::port_in(width, u64::from(port)).call(None, cap)?;
    let v = word(&r, 0)?;
    u32::try_from(v)
        .ok()
        .filter(|&v| v <= width.mask())
        .ok_or_else(|| undecoded(&r))
}

fn port_out(cap: CPtr, width: Width, port: u16, value: u32) -> Result<(), Error> {
    Request::port_out(width, u64::from(port), u64::from(value)).call(None, cap)?;
    Ok(())
}

/// `IOPort_In8`. `IllegalOperation` outside the capability's range.
pub fn ioport_in8(cap: CPtr, port: u16) -> Result<u8, Error> {
    port_in(cap, Width::Byte, port).map(|v| v as u8)
}

/// `IOPort_In16`: `port` and `port + 1` must be in the range.
pub fn ioport_in16(cap: CPtr, port: u16) -> Result<u16, Error> {
    port_in(cap, Width::Word, port).map(|v| v as u16)
}

/// `IOPort_In32`: `port` to `port + 3` must be in the range.
pub fn ioport_in32(cap: CPtr, port: u16) -> Result<u32, Error> {
    port_in(cap, Width::Dword, port)
}

/// `IOPort_Out8`.
pub fn ioport_out8(cap: CPtr, port: u16, value: u8) -> Result<(), Error> {
    port_out(cap, Width::Byte, port, value.into())
}

/// `IOPort_Out16`.
pub fn ioport_out16(cap: CPtr, port: u16, value: u16) -> Result<(), Error> {
    port_out(cap, Width::Word, port, value.into())
}

/// `IOPort_Out32`.
pub fn ioport_out32(cap: CPtr, port: u16, value: u32) -> Result<(), Error> {
    port_out(cap, Width::Dword, port, value)
}

#[cfg(test)]
mod tests {
    use super::*;

    const DEST: Slot = Slot::new(2, 40, 64);

    #[test]
    fn issues_name_the_source_then_the_destination() {
        let r = Request::get_isa(4, DEST);
        assert_eq!(
            (r.label, r.args(), r.caps()),
            (0x60, &[4, 40, 64][..], &[2][..])
        );
        let r = Request::get_ioapic(16, true, false, DEST);
        assert_eq!(
            (r.label, r.args(), r.caps()),
            (0x61, &[16, 1, 0, 40, 64][..], &[2][..])
        );
        assert_eq!(
            Request::get_ioapic(9, false, true, DEST).args()[1..3],
            [0, 1]
        );
        let r = Request::issue(0x3F8, 0x3FF, DEST);
        assert_eq!(
            (r.label, r.args(), r.caps()),
            (0x70, &[0x3F8, 0x3FF, 40, 64][..], &[2][..])
        );
    }

    #[test]
    fn handler_invocations_take_no_registers() {
        assert_eq!(
            (Request::ack().label, Request::ack().args()),
            (0x68, &[][..])
        );
        let r = Request::set_notification(9);
        assert_eq!((r.label, r.args(), r.caps()), (0x69, &[][..], &[9][..]));
        assert_eq!(
            (Request::clear().label, Request::clear().caps()),
            (0x6A, &[][..])
        );
    }

    #[test]
    fn port_accesses_pick_the_label_by_width() {
        for (w, i, o) in [
            (Width::Byte, 0x71, 0x74),
            (Width::Word, 0x72, 0x75),
            (Width::Dword, 0x73, 0x76),
        ] {
            let r = Request::port_in(w, 0x3F8);
            assert_eq!((r.label, r.args(), r.caps()), (i, &[0x3F8][..], &[][..]));
            let r = Request::port_out(w, 0xF4, 0x10);
            assert_eq!((r.label, r.args()), (o, &[0xF4, 0x10][..]));
        }
    }

    #[test]
    fn get_isa_results_decode() {
        assert_eq!(
            IsaIrq::from_words(0, 4, 0),
            Some(IsaIrq {
                irq: 0,
                gsi: 4,
                level: false,
                active_low: false
            })
        );
        let level_low = IsaIrq::from_words(191, 9, 3).unwrap();
        assert!(level_low.level && level_low.active_low && level_low.irq == 191);
        assert_eq!(IsaIrq::from_words(256, 4, 0), None);
        assert_eq!(IsaIrq::from_words(0, 1 << 32, 0), None);
        assert_eq!(IsaIrq::from_words(0, 4, 4), None);
    }
}
