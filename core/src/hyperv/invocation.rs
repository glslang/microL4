//! The Hypervisor capability (`docs/design.md`, "The Hypervisor capability
//! (M9)"; `docs/abi.md`, "Hypervisor"; ADRs 0020 and 0029): its fields,
//! Mint's narrowing, the permission check, and the four invocations.
//!
//! No object stands behind the capability. Its data word holds the fields:
//! 0 for the unrestricted capability boot puts in slot 12, and for a
//! restricted one [`RESTRICTED`] with the connection and the `post` and
//! `signal` rights in the bits the Mint data word gives them. The kernel
//! makes no hypercall itself: [`invoke`] checks a call, builds its input
//! as a [`PostMessage`] or [`SignalEvent`], which only this module can
//! make, and hands it to the kernel's [`Hypercalls`], which writes the
//! input page and calls `.hvcall` (`arch/x86_64/hyperv.rs`). The host tests
//! record the calls instead.
//!
//! # Orders the ABI leaves open
//!
//! - `PostMessage` checks its three registers' values before it counts the
//!   payload's, as `docs/abi.md` lists the rows: so `payload_size` 241 with
//!   no payload is `InvalidArgument(2)`, not `TruncatedMessage`.
//! - Each invocation ignores extra capabilities, and message registers
//!   past its own.

use crate::cap::{Cap, CapType, Rights};
use crate::error::SyscallError;
use crate::invoke::{self, InvokeError, Message, Reply};
use crate::slot::SlotAddr;
use crate::tcb::Threads;

use super::{
    BLOCK_WORDS, CONNECTIONS, FLAGS, MAX_MESSAGE_TYPE, MAX_PAYLOAD, POST_MESSAGE_INPUT,
    SIGNAL_EVENT_INPUT, post_message_block, signal_event_input,
};

/// The Hypervisor invocation labels (`docs/abi.md`, "Invocation label
/// index"): `0x80` to `0x83`; `0x84` to `0x8F` are reserved.
pub mod label {
    pub const POST_MESSAGE: u64 = 0x80;
    pub const SIGNAL_EVENT: u64 = 0x81;
    pub const EOM: u64 = 0x82;
    pub const VP_INDEX: u64 = 0x83;
}

/// A Mint data word's connection, bits 0-23.
pub const MINT_CONNECTION: u64 = (1 << 24) - 1;
/// A Mint data word's `post` right, bit 24.
pub const MINT_POST: u64 = 1 << 24;
/// A Mint data word's `signal` right, bit 25.
pub const MINT_SIGNAL: u64 = 1 << 25;
/// The bits a Mint data word may set; 26-63 must be 0.
pub const MINT_BITS: u64 = MINT_CONNECTION | MINT_POST | MINT_SIGNAL;
/// A restricted capability's data word has this bit, so that it is never
/// 0, the unrestricted capability's, even for connection 0 with no right.
pub const RESTRICTED: u64 = 1 << 63;

/// A Hypervisor capability's fields.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum HypervisorCap {
    /// Any connection, `Eom` and `VpIndex`: the boot capability and its
    /// copies.
    Unrestricted,
    /// One connection, with the rights to post and to signal on it.
    Restricted {
        connection: u32,
        post: bool,
        signal: bool,
    },
}

/// The unrestricted capability boot puts in initial slot 12.
pub const fn hypervisor_cap() -> Cap {
    HypervisorCap::Unrestricted.cap()
}

impl HypervisorCap {
    /// The fields of a Hypervisor capability; `None` for any other type.
    pub const fn from_cap(cap: &Cap) -> Option<HypervisorCap> {
        if !matches!(cap.cap_type(), CapType::Hypervisor) {
            return None;
        }
        Some(if cap.data == 0 {
            HypervisorCap::Unrestricted
        } else {
            HypervisorCap::Restricted {
                connection: (cap.data & MINT_CONNECTION) as u32,
                post: cap.data & MINT_POST != 0,
                signal: cap.data & MINT_SIGNAL != 0,
            }
        })
    }

    /// The capability with these fields: no memory, no rights.
    pub const fn cap(self) -> Cap {
        let data = match self {
            HypervisorCap::Unrestricted => 0,
            HypervisorCap::Restricted {
                connection,
                post,
                signal,
            } => {
                RESTRICTED
                    | (connection as u64 & MINT_CONNECTION)
                    | if post { MINT_POST } else { 0 }
                    | if signal { MINT_SIGNAL } else { 0 }
            }
        };
        Cap::new(CapType::Hypervisor, 0, 0, Rights::NONE, false, data)
    }

    /// `CNode_Mint`'s data word applied to a copy of this capability
    /// (`docs/abi.md`, "Mint data word"): the result, and whether it is
    /// an original. Data 0 is a Copy. Non-zero data narrows an
    /// unrestricted capability to the word's connection and rights, or
    /// gives a restricted one a subset of its rights on its own connection,
    /// and makes an original, as a new badge does, so that the minter can
    /// revoke every copy. Anything else, set bits 26-63 included, would
    /// widen or is not a word: `IllegalOperation`.
    pub const fn mint(self, data: u64) -> Result<(HypervisorCap, bool), SyscallError> {
        if data == 0 {
            return Ok((self, false));
        }
        if data & !MINT_BITS != 0 {
            return Err(SyscallError::IllegalOperation);
        }
        let connection = (data & MINT_CONNECTION) as u32;
        let (post, signal) = (data & MINT_POST != 0, data & MINT_SIGNAL != 0);
        let allowed = match self {
            HypervisorCap::Unrestricted => true,
            HypervisorCap::Restricted {
                connection: own,
                post: may_post,
                signal: may_signal,
            } => connection == own && (may_post || !post) && (may_signal || !signal),
        };
        if !allowed {
            return Err(SyscallError::IllegalOperation);
        }
        Ok((
            HypervisorCap::Restricted {
                connection,
                post,
                signal,
            },
            true,
        ))
    }

    /// Whether it may `PostMessage` on `connection`.
    pub const fn may_post(self, connection: u64) -> bool {
        match self {
            HypervisorCap::Unrestricted => true,
            HypervisorCap::Restricted {
                connection: own,
                post,
                ..
            } => post && connection == own as u64,
        }
    }

    /// Whether it may `SignalEvent` on `connection`.
    pub const fn may_signal(self, connection: u64) -> bool {
        match self {
            HypervisorCap::Unrestricted => true,
            HypervisorCap::Restricted {
                connection: own,
                signal,
                ..
            } => signal && connection == own as u64,
        }
    }

    /// Whether it may `Eom` and `VpIndex`: only unrestricted.
    pub const fn may_manage(self) -> bool {
        matches!(self, HypervisorCap::Unrestricted)
    }
}

/// A `PostMessage` [`invoke`] checked: the input value and the whole
/// 256-byte input block, built here and only here, so that kernel code
/// outside `l4core` cannot hand [`Hypercalls::post_message`] a block of its
/// own:
///
/// ```compile_fail,E0451
/// use l4core::hyperv::PostMessage;
/// let p = PostMessage { block: [0; 32] };
/// ```
///
/// It is neither `Clone` nor `Copy`: one check, one hypercall.
#[derive(Debug, PartialEq, Eq)]
pub struct PostMessage {
    block: [u64; BLOCK_WORDS],
}

impl PostMessage {
    /// `rcx`: memory-based `HvCallPostMessage`.
    pub const fn input_value(&self) -> u64 {
        POST_MESSAGE_INPUT
    }

    /// The input block, to write whole into the kernel's input page.
    pub const fn block(&self) -> &[u64; BLOCK_WORDS] {
        &self.block
    }
}

/// A `SignalEvent` [`invoke`] checked: its input value and its 8 bytes of
/// fast input, built only here.
#[derive(Debug, PartialEq, Eq)]
pub struct SignalEvent {
    input: u64,
}

impl SignalEvent {
    /// `rcx`: fast `HvCallSignalEvent`.
    pub const fn input_value(&self) -> u64 {
        SIGNAL_EVENT_INPUT
    }

    /// `rdx`: `connection | flag << 32`.
    pub const fn input(&self) -> u64 {
        self.input
    }
}

/// What `core::hyperv` needs from the kernel: the two hypercalls, the EOM
/// register and the VP index. The kernel implements it in
/// `arch/x86_64/hyperv.rs`, only once the hypercall page has read back
/// enabled at `.hvcall`; the host tests record each call.
pub trait Hypercalls {
    /// Writes `call`'s block into the input page and runs
    /// `HvCallPostMessage` on it; returns the `HV_STATUS`.
    fn post_message(&mut self, call: PostMessage) -> u16;

    /// Runs `HvCallSignalEvent` with `call`'s fast input; returns the
    /// `HV_STATUS`.
    fn signal_event(&mut self, call: SignalEvent) -> u16;

    /// Writes 0 to the SynIC's EOM register.
    fn eom(&mut self);

    /// This processor's VP index.
    fn vp_index(&mut self) -> u64;
}

/// Decodes and performs the Hypervisor invocation `msg` of the capability
/// in `slot`, in `docs/abi.md`'s order: label, message length, argument
/// values, then the capability's own limits. The hypercalls' `HV_STATUS`
/// is the result, label `NoError`.
pub fn invoke<K: Threads + Hypercalls + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    let hv = HypervisorCap::from_cap(&k.load(slot).cap).expect("a Hypervisor capability");
    let result = match msg.label {
        label::POST_MESSAGE => {
            let [connection, message_type, size] = msg.args(0)?;
            if connection >= CONNECTIONS {
                return Err(SyscallError::InvalidArgument(0).into());
            }
            if message_type == 0 || message_type > MAX_MESSAGE_TYPE {
                return Err(SyscallError::InvalidArgument(1).into());
            }
            if size > MAX_PAYLOAD {
                return Err(SyscallError::InvalidArgument(2).into());
            }
            let words = size.div_ceil(8) as usize;
            let Some(payload) = msg.mrs.get(3..3 + words) else {
                return Err(SyscallError::TruncatedMessage.into());
            };
            if !hv.may_post(connection) {
                return Err(SyscallError::IllegalOperation.into());
            }
            let call = PostMessage {
                block: post_message_block(
                    connection as u32,
                    message_type as u32,
                    size as u32,
                    payload,
                ),
            };
            u64::from(k.post_message(call))
        }
        label::SIGNAL_EVENT => {
            let [connection, flag] = msg.args(0)?;
            if connection >= CONNECTIONS {
                return Err(SyscallError::InvalidArgument(0).into());
            }
            if flag >= FLAGS {
                return Err(SyscallError::InvalidArgument(1).into());
            }
            if !hv.may_signal(connection) {
                return Err(SyscallError::IllegalOperation.into());
            }
            let call = SignalEvent {
                input: signal_event_input(connection as u32, flag as u16),
            };
            u64::from(k.signal_event(call))
        }
        label::EOM | label::VP_INDEX if !hv.may_manage() => {
            return Err(SyscallError::IllegalOperation.into());
        }
        label::EOM => {
            k.eom();
            return Ok(Reply::EMPTY);
        }
        label::VP_INDEX => k.vp_index(),
        _ => return Err(SyscallError::IllegalOperation.into()),
    };
    Ok(invoke::results(k, &[result]))
}

#[cfg(test)]
mod tests;
