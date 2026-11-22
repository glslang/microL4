//! A client of the `uart` server (`docs/design.md`, "The uart protocol"):
//! console's side, with badge 1, and `Stats` for anyone holding endpoint
//! U with Write and GrantReply.

use crate::client::{CallError, Endpoint};
use crate::proto::{MAX_BYTES, UartStats, label};
use crate::syscall::{CPtr, Ipc};

/// A capability to uart's endpoint, used from one thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client(Endpoint);

impl Client {
    /// The capability `cap`, called from a thread whose IPC buffer is
    /// `ipc`; without one, a request carries at most 24 bytes and `Stats`
    /// returns only MR0 to MR3.
    pub const fn new(cap: CPtr, ipc: Option<Ipc>) -> Client {
        Client(Endpoint { cap, ipc })
    }

    /// `Write` of at most 952 bytes (24 without an IPC buffer), answered
    /// once all are queued; returns how many. uart holds the call while
    /// its queue has no room for them all. Panics past the limit.
    pub fn write(&self, bytes: &[u8]) -> Result<usize, CallError> {
        assert!(
            bytes.len() <= self.0.max_bytes(),
            "{} bytes in one uart Write",
            bytes.len()
        );
        let r = self.0.call(label::UART_WRITE, Some(bytes))?;
        let n = self.0.word(&r, 0).ok_or(CallError::BadReply {
            label: 0,
            length: r.info.length(),
        })?;
        Ok(n as usize)
    }

    /// `Read`: everything the receive ring holds, possibly nothing, into
    /// `out`; returns how many bytes.
    pub fn read(&self, out: &mut [u8; MAX_BYTES]) -> Result<usize, CallError> {
        let r = self.0.call(label::UART_READ, None)?;
        self.0.bytes(&r, out)
    }

    /// `Drain`: answered once the queue and the transmit FIFO are empty.
    pub fn drain(&self) -> Result<(), CallError> {
        self.0.call(label::UART_DRAIN, None).map(|_| ())
    }

    /// `Stats`: the counters; those past MR3 read 0 without an IPC buffer.
    pub fn stats(&self) -> Result<UartStats, CallError> {
        let r = self.0.call(label::UART_STATS, None)?;
        let words = core::array::from_fn(|i| self.0.word(&r, i).unwrap_or(0));
        Ok(UartStats::from_words(words))
    }
}
