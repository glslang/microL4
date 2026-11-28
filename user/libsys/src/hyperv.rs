//! The Hypervisor invocations (`docs/abi.md`, "Hypervisor"; M9):
//! `PostMessage`, `SignalEvent`, `Eom` and `VpIndex` on the capability in
//! the root task's slot 12 or one minted from it, the Mint data word that
//! narrows one to a connection ([`Restriction`]), the `HV_STATUS` the two
//! hypercalls return ([`Status`]), and the layout of the SynIC frames in
//! slots 13 and 14 ([`synic`]).
//!
//! Each wrapper builds its message with a [`Request`], so the encoding is
//! host-tested, and sends it by `Call` through [`crate::invoke::invoke`].
//! A hypercall that the hypervisor refuses still succeeds as an
//! invocation: its status is the result, and the caller decides, as
//! `vmbus` retries a failed `PostMessage`.

use core::fmt;

use crate::device::{undecoded, word};
use crate::error::Error;
use crate::invoke::{Reply, invoke};
use crate::syscall::{CPtr, Ipc};

/// The invocation labels (`docs/abi.md`, "Invocation label index"): `0x80`
/// to `0x83`; `0x84` to `0x8F` are reserved.
pub mod label {
    pub const POST_MESSAGE: u64 = 0x80;
    pub const SIGNAL_EVENT: u64 = 0x81;
    pub const EOM: u64 = 0x82;
    pub const VP_INDEX: u64 = 0x83;
}

/// Connection IDs are below 2^24.
pub const CONNECTIONS: u32 = 1 << 24;
/// The most bytes one `PostMessage` carries.
pub const MAX_PAYLOAD: usize = 240;
/// The largest message type; 0 is none.
pub const MAX_MESSAGE_TYPE: u32 = 0x7FFF_FFFF;
/// The most message registers a request takes: `PostMessage`'s three and
/// its payload's 30.
pub const MAX_WORDS: usize = 3 + MAX_PAYLOAD / 8;

/// A hypercall's `HV_STATUS` (TLFS `hv_status.md`), the result of
/// `PostMessage` and `SignalEvent`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Status(pub u16);

impl Status {
    pub const SUCCESS: Status = Status(0x00);
    /// `SignalEvent`: a flag at or above the port's flag count.
    pub const INVALID_PARAMETER: Status = Status(0x05);
    /// Cannot come back: boot checked the privileges.
    pub const ACCESS_DENIED: Status = Status(0x06);
    /// The target processor is gone, or none can take it.
    pub const INVALID_VP_INDEX: Status = Status(0x0E);
    /// The connection's port is deleted, inactive or of the wrong kind.
    pub const INVALID_PORT_ID: Status = Status(0x11);
    /// No such connection.
    pub const INVALID_CONNECTION_ID: Status = Status(0x12);
    /// `PostMessage`: the port's message buffers are all in use; retry.
    pub const INSUFFICIENT_BUFFERS: Status = Status(0x13);
    /// The target's SynIC, SIM or SIEF is off, or for an event its SINT is
    /// masked.
    pub const INVALID_SYNIC_STATE: Status = Status(0x18);

    pub const fn is_success(self) -> bool {
        self.0 == 0
    }

    /// The TLFS's name for it, if it is one `hv_status.md` lists.
    pub const fn name(self) -> Option<&'static str> {
        Some(match self.0 {
            0x00 => "HV_STATUS_SUCCESS",
            0x02 => "HV_STATUS_INVALID_HYPERCALL_CODE",
            0x03 => "HV_STATUS_INVALID_HYPERCALL_INPUT",
            0x04 => "HV_STATUS_INVALID_ALIGNMENT",
            0x05 => "HV_STATUS_INVALID_PARAMETER",
            0x06 => "HV_STATUS_ACCESS_DENIED",
            0x07 => "HV_STATUS_INVALID_PARTITION_STATE",
            0x0D => "HV_STATUS_INVALID_PARTITION_ID",
            0x0E => "HV_STATUS_INVALID_VP_INDEX",
            0x11 => "HV_STATUS_INVALID_PORT_ID",
            0x12 => "HV_STATUS_INVALID_CONNECTION_ID",
            0x13 => "HV_STATUS_INSUFFICIENT_BUFFERS",
            0x15 => "HV_STATUS_INVALID_VP_STATE",
            0x18 => "HV_STATUS_INVALID_SYNIC_STATE",
            0x50 => "HV_STATUS_INVALID_REGISTER_VALUE",
            0x51 => "HV_STATUS_INVALID_VTL_STATE",
            _ => return None,
        })
    }
}

/// `HV_STATUS_INSUFFICIENT_BUFFERS (0x13)`, or `HV_STATUS 0x1234` for one
/// the TLFS does not list.
impl fmt::Display for Status {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.name() {
            Some(n) => write!(f, "{n} ({:#x})", self.0),
            None => write!(f, "HV_STATUS {:#x}", self.0),
        }
    }
}

/// One invocation's message: its label and message registers; none takes
/// an extra capability.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Request {
    pub label: u64,
    args: [u64; MAX_WORDS],
    len: usize,
}

impl Request {
    const fn new(label: u64, args: &[u64]) -> Request {
        let mut a = [0; MAX_WORDS];
        let mut i = 0;
        while i < args.len() {
            a[i] = args[i];
            i += 1;
        }
        Request {
            label,
            args: a,
            len: args.len(),
        }
    }

    /// The message registers, MR0 first.
    pub fn args(&self) -> &[u64] {
        &self.args[..self.len]
    }

    /// Sends it to `cap` by `Call`; `ipc` must be the caller's buffer if
    /// it has more than four registers.
    fn call(&self, ipc: Option<Ipc>, cap: CPtr) -> Result<Reply, Error> {
        invoke(ipc, cap, self.label, self.args(), &[])
    }

    /// `Hypervisor_PostMessage`: MR0 `connection`, MR1 `message_type`, MR2
    /// `payload_size`, then the payload, eight bytes a word, little-endian,
    /// the last word's bytes past the payload 0. Panics past 240 bytes; the
    /// kernel checks the rest.
    #[track_caller]
    pub fn post_message(connection: u32, message_type: u32, payload: &[u8]) -> Request {
        assert!(
            payload.len() <= MAX_PAYLOAD,
            "hyperv: a PostMessage of {} bytes",
            payload.len()
        );
        let mut r = Request::new(
            label::POST_MESSAGE,
            &[connection.into(), message_type.into(), payload.len() as u64],
        );
        for chunk in payload.chunks(8) {
            let mut b = [0; 8];
            b[..chunk.len()].copy_from_slice(chunk);
            r.args[r.len] = u64::from_le_bytes(b);
            r.len += 1;
        }
        r
    }

    /// `Hypervisor_SignalEvent`: MR0 `connection`, MR1 `flag`.
    pub const fn signal_event(connection: u32, flag: u16) -> Request {
        Request::new(label::SIGNAL_EVENT, &[connection as u64, flag as u64])
    }

    /// `Hypervisor_Eom`: no registers.
    pub const fn eom() -> Request {
        Request::new(label::EOM, &[])
    }

    /// `Hypervisor_VpIndex`: no registers.
    pub const fn vp_index() -> Request {
        Request::new(label::VP_INDEX, &[])
    }
}

/// A hypercall's result: MR0, the status, 16 bits.
fn status(r: &Reply) -> Result<Status, Error> {
    u16::try_from(word(r, 0)?)
        .map(Status)
        .map_err(|_| undecoded(r))
}

/// `Hypervisor_PostMessage`: posts `payload` (at most 240 bytes; panics
/// past) as a message of type `message_type` on `connection`, and returns
/// the hypervisor's status. The kernel refuses a connection of 2^24 or
/// more (`InvalidArgument(0)`), a type of 0 or 2^31 or more
/// (`InvalidArgument(1)`), and, on a restricted capability, another
/// connection or no `post` right (`IllegalOperation`). `ipc` is the
/// caller's IPC buffer: a payload past 8 bytes travels in it.
pub fn post_message(
    ipc: Ipc,
    hypervisor: CPtr,
    connection: u32,
    message_type: u32,
    payload: &[u8],
) -> Result<Status, Error> {
    let r = Request::post_message(connection, message_type, payload).call(Some(ipc), hypervisor)?;
    status(&r)
}

/// `Hypervisor_SignalEvent`: signals event flag `flag` of `connection`
/// (relative to its port's base; VMBus channels use 0) as a fast
/// hypercall, and returns the hypervisor's status. On a restricted
/// capability only its own connection, with `signal`.
pub fn signal_event(hypervisor: CPtr, connection: u32, flag: u16) -> Result<Status, Error> {
    let r = Request::signal_event(connection, flag).call(None, hypervisor)?;
    status(&r)
}

/// `Hypervisor_Eom`: asks the hypervisor for the next queued message, once
/// the slot is empty ([`synic`]). `IllegalOperation` on a restricted
/// capability.
pub fn eom(hypervisor: CPtr) -> Result<(), Error> {
    Request::eom().call(None, hypervisor)?;
    Ok(())
}

/// `Hypervisor_VpIndex`: this processor's VP index, which channel
/// messages name. `IllegalOperation` on a restricted capability.
pub fn vp_index(hypervisor: CPtr) -> Result<u32, Error> {
    let r = Request::vp_index().call(None, hypervisor)?;
    u32::try_from(word(&r, 0)?).map_err(|_| undecoded(&r))
}

/// A narrowing of a Hypervisor capability: the Mint data word
/// (`docs/abi.md`, "Mint data word"). Minting an unrestricted capability
/// with it makes a restricted original that may use only `connection`,
/// with the rights given; minting a restricted one with its own
/// connection and fewer rights drops rights. `CNode_Mint`'s data is
/// [`Restriction::data`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Restriction {
    /// The only connection, below 2^24.
    pub connection: u32,
    /// May `PostMessage`.
    pub post: bool,
    /// May `SignalEvent`.
    pub signal: bool,
}

impl Restriction {
    const POST: u64 = 1 << 24;
    const SIGNAL: u64 = 1 << 25;

    /// `signal` alone on `connection`: what `vmbus` mints `netvsc`.
    pub const fn signal_only(connection: u32) -> Restriction {
        Restriction {
            connection,
            post: false,
            signal: true,
        }
    }

    /// The data word: `connection` in bits 0 to 23, `post` bit 24,
    /// `signal` bit 25. `None` for a connection of 2^24 or more, and for
    /// connection 0 with neither right, whose word, 0, would make the
    /// Mint a plain copy of an unrestricted capability.
    pub const fn data(self) -> Option<u64> {
        if self.connection >= CONNECTIONS {
            return None;
        }
        let w = self.connection as u64
            | if self.post { Self::POST } else { 0 }
            | if self.signal { Self::SIGNAL } else { 0 };
        if w == 0 { None } else { Some(w) }
    }

    /// The restriction a data word names; `None` for 0 (a copy) and for a
    /// word with bits 26 to 63 set, which Mint refuses.
    pub const fn from_data(w: u64) -> Option<Restriction> {
        if w == 0 || w >> 26 != 0 {
            return None;
        }
        Some(Restriction {
            connection: (w & (CONNECTIONS as u64 - 1)) as u32,
            post: w & Self::POST != 0,
            signal: w & Self::SIGNAL != 0,
        })
    }
}

/// The SynIC frames (`docs/abi.md`, "SynIC frames"): the message frame
/// (SIM, initial slot 13) and the event-flag frame (SIEF, slot 14), 16
/// slots of 256 bytes each, one per SINT. Offsets are from the frame's
/// start.
pub mod synic {
    /// SINTs, and slots in each frame.
    pub const SINTS: usize = 16;
    /// Bytes in a slot.
    pub const SLOT_SIZE: usize = 256;
    /// Event flags in a SIEF slot.
    pub const FLAGS: usize = 8 * SLOT_SIZE;

    /// Where SINT `sint`'s slot starts, in either frame.
    pub const fn slot(sint: usize) -> usize {
        assert!(sint < SINTS);
        SLOT_SIZE * sint
    }

    /// In a SIM slot: `MessageType` (u32); 0 means the slot is empty.
    pub const MESSAGE_TYPE: usize = 0;
    /// `PayloadSize` (u8), at most 240.
    pub const PAYLOAD_SIZE: usize = 4;
    /// `MessageFlags` (u8).
    pub const MESSAGE_FLAGS: usize = 5;
    /// `MessageFlags`' `MessagePending`: read it after emptying the slot
    /// and a full fence, and if set invoke `Hypervisor_Eom`.
    pub const MESSAGE_PENDING: u8 = 1 << 0;
    /// The origination (u64): the sender's port or partition ID.
    pub const ORIGIN: usize = 8;
    /// The payload.
    pub const PAYLOAD: usize = 16;
    /// Its most bytes.
    pub const MAX_PAYLOAD: usize = 240;

    /// Event flag `n` of SINT `sint` in the SIEF: the byte that holds it
    /// and the bit in that byte (`n mod 8`).
    pub const fn flag_byte(sint: usize, n: usize) -> (usize, u8) {
        assert!(n < FLAGS);
        (slot(sint) + n / 8, 1 << (n % 8))
    }

    /// The same flag as a bit of the aligned 64-bit word that holds it,
    /// for clearing a word at a time with one atomic swap.
    pub const fn flag_word(sint: usize, n: usize) -> (usize, u64) {
        assert!(n < FLAGS);
        (slot(sint) + 8 * (n / 64), 1 << (n % 64))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn labels_are_the_abis() {
        assert_eq!(
            [
                label::POST_MESSAGE,
                label::SIGNAL_EVENT,
                label::EOM,
                label::VP_INDEX
            ],
            [0x80, 0x81, 0x82, 0x83]
        );
        assert_eq!(Request::eom().label, 0x82);
        assert_eq!(Request::vp_index().label, 0x83);
        assert!(Request::eom().args().is_empty() && Request::vp_index().args().is_empty());
    }

    /// MR0 connection, MR1 type, MR2 size, then byte `i` in byte `i mod 8`
    /// of MR`3 + i / 8`, the rest of the last word 0.
    #[test]
    fn post_message_lays_its_payload_out_little_endian() {
        let r = Request::post_message(1, 1, b"abcdefghij");
        assert_eq!(r.label, 0x80);
        assert_eq!(
            r.args(),
            &[
                1,
                1,
                10,
                u64::from_le_bytes(*b"abcdefgh"),
                u64::from(b'i') | u64::from(b'j') << 8
            ][..]
        );
        let r = Request::post_message(0xFF_FFFF, MAX_MESSAGE_TYPE, &[]);
        assert_eq!(r.args(), &[0xFF_FFFF, 0x7FFF_FFFF, 0][..]);
        for n in [1usize, 7, 8, 9, 239, 240] {
            let payload: std::vec::Vec<u8> = (0..n).map(|i| i as u8 ^ 0xA5).collect();
            let r = Request::post_message(14, 1, &payload);
            assert_eq!(r.args().len(), 3 + n.div_ceil(8), "{n}");
            assert_eq!(r.args()[2], n as u64);
            let bytes: std::vec::Vec<u8> =
                r.args()[3..].iter().flat_map(|w| w.to_le_bytes()).collect();
            assert_eq!(&bytes[..n], &payload[..]);
            assert!(bytes[n..].iter().all(|&b| b == 0));
        }
        assert_eq!(
            Request::post_message(1, 1, &[0; 240]).args().len(),
            MAX_WORDS
        );
    }

    #[test]
    #[should_panic(expected = "a PostMessage of 241 bytes")]
    fn a_payload_past_240_bytes_panics() {
        Request::post_message(1, 1, &[0; 241]);
    }

    #[test]
    fn signal_event_takes_the_connection_then_the_flag() {
        let r = Request::signal_event(0x1_000E, 0);
        assert_eq!((r.label, r.args()), (0x81, &[0x1_000E, 0][..]));
        let r = Request::signal_event(5, u16::MAX);
        assert_eq!(r.args(), &[5, 0xFFFF][..]);
    }

    #[test]
    fn statuses_are_the_abis() {
        assert_eq!(
            [
                Status::SUCCESS,
                Status::INVALID_PARAMETER,
                Status::INVALID_VP_INDEX,
                Status::INVALID_PORT_ID,
                Status::INVALID_CONNECTION_ID,
                Status::INSUFFICIENT_BUFFERS,
                Status::INVALID_SYNIC_STATE
            ]
            .map(|s| s.0),
            [0x00, 0x05, 0x0E, 0x11, 0x12, 0x13, 0x18]
        );
        assert!(Status::SUCCESS.is_success() && !Status::INSUFFICIENT_BUFFERS.is_success());
        assert_eq!(
            std::format!("{}", Status::INSUFFICIENT_BUFFERS),
            "HV_STATUS_INSUFFICIENT_BUFFERS (0x13)"
        );
        assert_eq!(std::format!("{}", Status(0x1234)), "HV_STATUS 0x1234");
        assert_eq!(
            Status::ACCESS_DENIED.name(),
            Some("HV_STATUS_ACCESS_DENIED")
        );
    }

    /// The Mint data word of `docs/abi.md`: connection in bits 0 to 23,
    /// `post` 24, `signal` 25, the rest 0; 0 is a copy, never a narrowing.
    #[test]
    fn restrictions_are_the_mint_data_word() {
        let r = Restriction::signal_only(0x1_000E);
        assert_eq!(r.data(), Some(0x1_000E | 1 << 25));
        assert_eq!(Restriction::from_data(0x1_000E | 1 << 25), Some(r));
        let both = Restriction {
            connection: 0xFF_FFFF,
            post: true,
            signal: true,
        };
        assert_eq!(both.data(), Some(0x3FF_FFFF));
        assert_eq!(Restriction::from_data(0x3FF_FFFF), Some(both));
        // Connection 0 is fine with a right; with none its word would be 0.
        assert_eq!(Restriction::signal_only(0).data(), Some(1 << 25));
        let nothing = Restriction {
            connection: 0,
            post: false,
            signal: false,
        };
        assert_eq!(nothing.data(), None);
        assert_eq!(
            Restriction {
                connection: 7,
                ..nothing
            }
            .data(),
            Some(7)
        );
        assert_eq!(Restriction::signal_only(1 << 24).data(), None);
        assert_eq!(Restriction::from_data(0), None);
        assert_eq!(Restriction::from_data(1 << 26), None);
        assert_eq!(Restriction::from_data(1 << 63 | 1), None);
    }

    /// The SynIC frames' layout from `docs/abi.md`: slot `s` at `256 s`,
    /// the message header, and flag `n` of SINT `s` at bit `n mod 8` of
    /// byte `256 s + n / 8`.
    #[test]
    fn synic_frame_layout() {
        use synic::*;
        assert_eq!((slot(0), slot(2), slot(15)), (0, 512, 3840));
        assert_eq!(
            (MESSAGE_TYPE, PAYLOAD_SIZE, MESSAGE_FLAGS, ORIGIN, PAYLOAD),
            (0, 4, 5, 8, 16)
        );
        assert_eq!(PAYLOAD + MAX_PAYLOAD, SLOT_SIZE);
        assert_eq!(MESSAGE_PENDING, 1);
        assert_eq!(FLAGS, 2048);
        assert_eq!(flag_byte(2, 0), (512, 1));
        assert_eq!(flag_byte(2, 14), (513, 1 << 6));
        assert_eq!(flag_byte(2, 2047), (767, 1 << 7));
        assert_eq!(flag_word(2, 14), (512, 1 << 14));
        assert_eq!(flag_word(2, 64), (520, 1));
        assert_eq!(flag_word(2, 2047), (760, 1 << 63));
        // The byte and the word agree, little-endian.
        for n in [0, 1, 63, 64, 100, 2047] {
            let (b, bit) = flag_byte(2, n);
            let (w, mask) = flag_word(2, n);
            assert_eq!(mask.to_le_bytes()[b - w], bit, "{n}");
        }
        assert_eq!(MAX_PAYLOAD, super::MAX_PAYLOAD);
    }
}
