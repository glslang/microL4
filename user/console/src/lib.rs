//! `console`: the terminal server (`docs/design.md`, "console" under
//! "User-level drivers and console").
//!
//! console multiplexes up to eight clients onto uart. It keeps each
//! client's unfinished output line until the client ends it, flushes it,
//! reads, or fills 512 bytes, so a line of at most 512 bytes reaches the
//! wire whole and the clients' output interleaves line by line, with each
//! client's control bytes shown as visible escapes rather than sent, so
//! that no client can rewrite another's line or the status line; it edits
//! input lines and routes each to the client focused when its bytes were
//! read (Ctrl-T and a digit moves the focus). The logic is
//! [`Terminal`], pure and host-tested; [`decode`] checks a request's
//! label, badge and length; [`run`], the server loop, exists only on the
//! user target, where the root task starts it in a VSpace and CSpace of
//! its own with the capabilities [`slot`] lists, bound to notification NC,
//! which uart signals with `RX_READY` when input waits.
//!
//! console never waits for a client: a `Read` it cannot answer yet is saved
//! with `CNode_SaveCaller` into slot 7 + its badge and answered later with
//! `Send` on that slot. It blocks only in calls to uart, which always reply.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

#[cfg(target_os = "none")]
mod run;
mod terminal;
#[cfg(test)]
mod tests;

use libsys::proto::{self, MAX_BYTES, Refusal, label};

#[cfg(target_os = "none")]
pub use run::run;
pub use terminal::{
    CLIENTS, Chunks, EDIT, LINE, NAME, Out, Owner, ReadAnswer, Source, Terminal, WAITING, passes,
    shown,
};

/// console's CSpace: a 16-slot CNode with guard 0 of size 60, so `CPtr`
/// `n` is slot `n` (`docs/design.md`, "Capabilities").
pub mod slot {
    pub const RADIX: u64 = 4;
    pub const GUARD_BITS: u64 = 64 - RADIX;
    /// Its own CNode, with the same guard, for `CNode_SaveCaller`.
    pub const CNODE: u64 = 1;
    /// Endpoint C, console's requests, with Read.
    pub const ENDPOINT: u64 = 2;
    /// Endpoint U, with Write, GrantReply and badge 1: uart's writer.
    pub const UART: u64 = 3;
    /// Endpoint F, console's fault endpoint.
    pub const FAULT: u64 = 4;

    /// Where client `badge`'s saved Read reply goes: slots 8 to 15.
    pub const fn saved_read(badge: u64) -> u64 {
        7 + badge
    }
}

/// A request, decoded, from the client of index `badge - 1`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Request<'a> {
    Attach(&'a [u8]),
    Write(&'a [u8]),
    Flush,
    Read,
    Sync,
}

/// Decodes a request: its label, then its badge (1 to 8), then its length
/// (`docs/design.md`, "Protocols"), any byte string into `buf`. Returns
/// the client's index, `badge - 1`. `word` reads MR0 and up. Requests
/// without words ignore any sent.
pub fn decode<'a>(
    label: u64,
    badge: u64,
    length: usize,
    word: impl FnMut(usize) -> u64,
    buf: &'a mut [u8; MAX_BYTES],
) -> Result<(usize, Request<'a>), Refusal> {
    let limit = match label {
        label::CONSOLE_ATTACH => NAME,
        label::CONSOLE_WRITE => MAX_BYTES,
        label::CONSOLE_FLUSH | label::CONSOLE_READ | label::CONSOLE_SYNC => 0,
        _ => return Err(Refusal::BadLabel),
    };
    if !(1..=CLIENTS as u64).contains(&badge) {
        return Err(Refusal::BadBadge);
    }
    let c = badge as usize - 1;
    let req = match label {
        label::CONSOLE_ATTACH | label::CONSOLE_WRITE => {
            let n = proto::decode(length, word, limit, buf)?;
            if label == label::CONSOLE_ATTACH {
                Request::Attach(&buf[..n])
            } else {
                Request::Write(&buf[..n])
            }
        }
        label::CONSOLE_FLUSH => Request::Flush,
        label::CONSOLE_READ => Request::Read,
        _ => Request::Sync,
    };
    Ok((c, req))
}
