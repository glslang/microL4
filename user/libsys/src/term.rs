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
use crate::syscall::{CPtr, Ipc};

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
            if self.0.word(&r, 0) != Some(chunk.len() as u64) {
                return Err(CallError::BadReply {
                    label: 0,
                    length: r.info.length(),
                });
            }
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
            *w = self.0.word(&r, i).ok_or(CallError::BadReply {
                label: 0,
                length: r.info.length(),
            })?;
        }
        Ok(TermSize::from_words(words))
    }

    /// `Stats`: the counters; those past MR3 read 0 without an IPC buffer.
    pub fn stats(&self) -> Result<TermStats, CallError> {
        let r = self.0.call(label::TERM_STATS, None)?;
        let words = core::array::from_fn(|i| self.0.word(&r, i).unwrap_or(0));
        Ok(TermStats::from_words(words))
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
}
