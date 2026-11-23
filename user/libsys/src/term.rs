//! A client of the `term` server (`docs/design.md`, "Input and the term
//! protocol"): a capability to term's endpoint T with Write and
//! GrantReply. `Write`, `Read` and `Size` need badge 1, term's one client;
//! `Stats` takes any badge (root's has 2).
//!
//! Like a pseudo-terminal's slave side in raw mode, term passes input
//! through as typed: [`Client::read`] returns the keys as the host
//! terminal on COM1 sent them, VT sequences included, and the replies DSR
//! and DA queue, in the order they came.

use core::fmt;

use crate::client::{CallError, Endpoint};
use crate::console::split;
use crate::proto::{TermSize, TermStats, label};
use crate::syscall::{CPtr, Ipc, Message};

/// The most bytes one [`Client::read`] returns: term's input queue.
pub const MAX_READ: usize = 512;

const _: () = assert!(MAX_READ <= crate::proto::MAX_BYTES);

/// A term client capability, used from one thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client(Endpoint);

impl Client {
    /// The capability `cap`, called from a thread whose IPC buffer is
    /// `ipc`. Without a buffer each `Write` carries at most 24 bytes,
    /// `read` takes only replies that fit and `stats` returns only MR0 to
    /// MR3.
    pub const fn new(cap: CPtr, ipc: Option<Ipc>) -> Client {
        Client(Endpoint { cap, ipc })
    }

    /// The capability.
    pub fn cap(&self) -> CPtr {
        self.0.cap
    }

    /// `Write`, split into requests of at most 952 bytes (24 without an
    /// IPC buffer); each is answered once term has applied every byte and
    /// drawn the frame.
    pub fn write(&self, bytes: &[u8]) -> Result<(), CallError> {
        for chunk in split(bytes, self.0.max_bytes()) {
            let r = self.0.call(label::TERM_WRITE, Some(chunk))?;
            self.written(&r, chunk.len())?;
        }
        Ok(())
    }

    /// A `Write`'s reply: MR0 must be `n`, the bytes the request carried.
    fn written(&self, r: &Message, n: usize) -> Result<(), CallError> {
        if self.0.word(r, 0) != Some(n as u64) {
            return Err(bad_reply(r));
        }
        Ok(())
    }

    /// `Read`: everything in term's input queue, into `out`, waiting until
    /// it holds something; returns how many bytes. `Busy` if another
    /// thread of the client already waits in one.
    pub fn read(&self, out: &mut [u8; MAX_READ]) -> Result<usize, CallError> {
        let r = self.0.call(label::TERM_READ, None)?;
        self.0.bytes(&r, out)
    }

    /// `Size`: the screen in cells and the framebuffer in pixels.
    pub fn size(&self) -> Result<TermSize, CallError> {
        let r = self.0.call(label::TERM_SIZE, None)?;
        let mut words = [0; TermSize::WORDS];
        for (i, w) in words.iter_mut().enumerate() {
            *w = self.0.word(&r, i).ok_or_else(|| bad_reply(&r))?;
        }
        Ok(TermSize::from_words(words))
    }

    /// `Stats`: the counters. It needs an IPC buffer: the reply carries
    /// [`TermStats::WORDS`] words, the kernel delivers at most four to a
    /// thread without one (`docs/abi.md`), and a reply with fewer words is
    /// `BadReply`.
    pub fn stats(&self) -> Result<TermStats, CallError> {
        let r = self.0.call(label::TERM_STATS, None)?;
        self.stats_from(&r)
    }

    /// The counters a `Stats` reply carries.
    fn stats_from(&self, r: &Message) -> Result<TermStats, CallError> {
        if (r.info.length() as usize) < TermStats::WORDS {
            return Err(bad_reply(r));
        }
        let words = core::array::from_fn(|i| self.0.word(r, i).unwrap_or(0));
        Ok(TermStats::from_words(words))
    }
}

/// A success reply without the words its request answers with.
fn bad_reply(r: &Message) -> CallError {
    CallError::BadReply {
        label: 0,
        length: r.info.length(),
    }
}

impl fmt::Write for Client {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Client::write(self, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// console's raw queue and term's input queue are the same size, so a
    /// `ReadRaw` always fits term's queue when it is empty.
    #[test]
    fn the_queues_match() {
        assert_eq!(crate::console::MAX_RAW, MAX_READ);
        assert_eq!(TermStats::WORDS, 7);
    }

    fn reply(length: u64, mr: [u64; 4]) -> Message {
        Message::new(l4core::ipc::MessageInfo::new(0, 0, 0, length), mr)
    }

    fn bad(length: u64) -> CallError {
        CallError::BadReply { label: 0, length }
    }

    /// A `Write` succeeds only if MR0 counts every byte the request
    /// carried: a reply with another count, or none, is `BadReply`.
    #[test]
    fn a_write_reply_must_count_every_byte() {
        let c = Client::new(9, None);
        assert_eq!(c.written(&reply(1, [24, 0, 0, 0]), 24), Ok(()));
        assert_eq!(c.written(&reply(1, [23, 0, 0, 0]), 24), Err(bad(1)));
        assert_eq!(c.written(&reply(1, [25, 0, 0, 0]), 24), Err(bad(1)));
        // MR0 holds 24, but the reply has no words.
        assert_eq!(c.written(&reply(0, [24, 0, 0, 0]), 24), Err(bad(0)));
    }

    /// A `Stats` reply with fewer than seven words is `BadReply`, not
    /// zeros. (This host client has no IPC buffer, so its words past MR3
    /// read 0; on the target seven words arrive only through one.)
    #[test]
    fn a_stats_reply_needs_its_seven_words() {
        let c = Client::new(9, None);
        for length in 0..7 {
            assert_eq!(c.stats_from(&reply(length, [1, 2, 3, 4])), Err(bad(length)));
        }
        assert_eq!(
            c.stats_from(&reply(7, [1, 2, 3, 4])),
            Ok(TermStats::from_words([1, 2, 3, 4, 0, 0, 0]))
        );
    }

    /// A client without an IPC buffer gets at most four words back
    /// (`docs/abi.md`, "Either side has no usable IPC buffer"), so its
    /// `Stats` is always `BadReply`: `stats` needs a buffer, as its doc
    /// says (found by the M8 re-check).
    #[test]
    fn a_stats_reply_without_an_ipc_buffer_is_bad_reply() {
        let c = Client::new(9, None);
        assert_eq!(c.stats_from(&reply(4, [1, 2, 3, 4])), Err(bad(4)));
    }
}
