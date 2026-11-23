//! A client of the `console` server (`docs/design.md`, "console"): a
//! capability to console's endpoint C with Write and GrantReply and a
//! badge from 1 to 8, the client's number.
//!
//! console keeps each client's unfinished output line until the client
//! ends it with `\n`, flushes it, reads, or fills 512 bytes, so a client's
//! lines reach the terminal whole however it splits its writes. A prompt
//! is what a client wrote since its last newline: write it, then
//! [`Client::read_line`], with no [`Client::flush`] between.

use core::fmt;

use crate::client::{CallError, Endpoint};
use crate::proto::{MAX_BYTES, label};
use crate::syscall::{CPtr, Ipc};

/// The longest name [`Client::attach`] takes.
pub const MAX_NAME: usize = 16;
/// The longest line [`Client::read_line`] returns.
pub const MAX_LINE: usize = 255;
/// The most bytes [`Client::read_raw`] returns: console's raw queue.
pub const MAX_RAW: usize = 512;

/// A console client capability, used from one thread.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Client(Endpoint);

impl Client {
    /// The client capability `cap`, called from a thread whose IPC buffer
    /// is `ipc`. Without a buffer each request carries at most 24 bytes,
    /// and `read_line` takes only lines that fit.
    pub const fn new(cap: CPtr, ipc: Option<Ipc>) -> Client {
        Client(Endpoint { cap, ipc })
    }

    /// The capability.
    pub fn cap(&self) -> CPtr {
        self.0.cap
    }

    /// `Attach`: names the client in console's status lines; returns its
    /// client number. Names past 16 bytes are `BadLength`.
    pub fn attach(&self, name: &str) -> Result<u64, CallError> {
        let r = self.0.call(label::CONSOLE_ATTACH, Some(name.as_bytes()))?;
        self.0.word(&r, 0).ok_or(CallError::BadReply {
            label: 0,
            length: 0,
        })
    }

    /// `Write`, split into requests of at most 952 bytes (24 without an
    /// IPC buffer); each is answered once every line it completed is in
    /// uart's queue.
    pub fn write(&self, bytes: &[u8]) -> Result<(), CallError> {
        for chunk in split(bytes, self.0.max_bytes()) {
            let r = self.0.call(label::CONSOLE_WRITE, Some(chunk))?;
            if self.0.word(&r, 0) != Some(chunk.len() as u64) {
                return Err(CallError::BadReply {
                    label: 0,
                    length: r.info.length(),
                });
            }
        }
        Ok(())
    }

    /// `Flush`: the unfinished line goes to the terminal now.
    pub fn flush(&self) -> Result<(), CallError> {
        self.0.call(label::CONSOLE_FLUSH, None).map(|_| ())
    }

    /// `Read`: waits for the next line typed while this client had focus,
    /// without its terminator, and returns its length in `out`. `Busy` if
    /// another thread of this client already waits in one.
    pub fn read_line(&self, out: &mut [u8; MAX_LINE]) -> Result<usize, CallError> {
        let r = self.0.call(label::CONSOLE_READ, None)?;
        self.0.bytes(&r, out)
    }

    /// `ReadRaw`, for client 4 only (term): everything in console's raw
    /// queue, the bytes typed while client 4 had focus but the focus keys,
    /// into `out`, at once; possibly nothing. Returns how many bytes.
    /// Any other client is refused with `BadBadge`.
    pub fn read_raw(&self, out: &mut [u8; MAX_RAW]) -> Result<usize, CallError> {
        let r = self.0.call(label::CONSOLE_READ_RAW, None)?;
        self.0.bytes(&r, out)
    }

    /// `Sync`: answered once everything console has emitted, this client's
    /// unfinished line included, has left the UART.
    pub fn sync(&self) -> Result<(), CallError> {
        self.0.call(label::CONSOLE_SYNC, None).map(|_| ())
    }
}

impl fmt::Write for Client {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        Client::write(self, s.as_bytes()).map_err(|_| fmt::Error)
    }
}

/// `bytes` in pieces of at most `max` bytes; none for no bytes.
pub fn split(bytes: &[u8], max: usize) -> core::slice::Chunks<'_, u8> {
    bytes.chunks(max.max(1))
}

/// Text gathered into pieces of up to 952 bytes before it goes out, so
/// that one `print!` makes a few requests rather than one per formatted
/// piece. [`Buffered::finish`] sends what is left.
pub struct Buffered<F: FnMut(&[u8]) -> Result<(), CallError>> {
    send: F,
    buf: [u8; MAX_BYTES],
    len: usize,
    cap: usize,
    failed: Option<CallError>,
}

impl<F: FnMut(&[u8]) -> Result<(), CallError>> Buffered<F> {
    /// Sends pieces of at most `cap` bytes (at most 952) with `send`.
    pub fn new(cap: usize, send: F) -> Buffered<F> {
        Buffered {
            send,
            buf: [0; MAX_BYTES],
            len: 0,
            cap: cap.clamp(1, MAX_BYTES),
            failed: None,
        }
    }

    fn push(&mut self, mut bytes: &[u8]) {
        while !bytes.is_empty() && self.failed.is_none() {
            let n = (self.cap - self.len).min(bytes.len());
            self.buf[self.len..self.len + n].copy_from_slice(&bytes[..n]);
            self.len += n;
            bytes = &bytes[n..];
            if self.len == self.cap {
                self.send_buffered();
            }
        }
    }

    fn send_buffered(&mut self) {
        if self.len > 0
            && self.failed.is_none()
            && let Err(e) = (self.send)(&self.buf[..self.len])
        {
            self.failed = Some(e);
        }
        self.len = 0;
    }

    /// Sends what is buffered; the first error any piece met.
    pub fn finish(mut self) -> Result<(), CallError> {
        self.send_buffered();
        self.failed.map_or(Ok(()), Err)
    }
}

impl<F: FnMut(&[u8]) -> Result<(), CallError>> fmt::Write for Buffered<F> {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        self.push(s.as_bytes());
        if self.failed.is_some() {
            Err(fmt::Error)
        } else {
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::fmt::Write;
    use std::vec::Vec;

    #[test]
    fn writes_split_at_952() {
        let bytes: Vec<u8> = (0..3000u32).map(|i| i as u8).collect();
        let pieces: Vec<&[u8]> = split(&bytes, MAX_BYTES).collect();
        assert_eq!(
            pieces.iter().map(|p| p.len()).collect::<Vec<_>>(),
            [952, 952, 952, 144]
        );
        assert_eq!(pieces.concat(), bytes);
        assert_eq!(split(&bytes[..952], MAX_BYTES).count(), 1);
        assert_eq!(split(&bytes[..953], MAX_BYTES).count(), 2);
        assert_eq!(split(&[], MAX_BYTES).count(), 0);
        // Without an IPC buffer: 24 bytes.
        assert_eq!(split(&bytes[..49], 24).count(), 3);
    }

    #[test]
    fn formatted_text_goes_out_in_full_pieces() {
        let mut sent: Vec<Vec<u8>> = Vec::new();
        let mut b = Buffered::new(MAX_BYTES, |p: &[u8]| {
            sent.push(p.to_vec());
            Ok(())
        });
        for i in 0..300 {
            writeln!(b, "line {i:03}").unwrap();
        }
        b.finish().unwrap();
        let lens: Vec<usize> = sent.iter().map(Vec::len).collect();
        assert_eq!(lens, [952, 952, 796], "9 bytes a line");
        let all = sent.concat();
        assert!(all.starts_with(b"line 000\nline 001\n"));
        assert!(all.ends_with(b"line 299\n"));
    }

    #[test]
    fn a_failed_piece_stops_the_rest() {
        let mut calls = 0;
        let mut b = Buffered::new(4, |_: &[u8]| {
            calls += 1;
            Err(CallError::BadReply {
                label: 1,
                length: 0,
            })
        });
        assert!(b.write_str("abcdefghij").is_err());
        assert!(b.finish().is_err());
        assert_eq!(calls, 1);
        // Nothing to send sends nothing.
        let mut calls = 0;
        let b = Buffered::new(4, |_: &[u8]| {
            calls += 1;
            Ok(())
        });
        b.finish().unwrap();
        assert_eq!(calls, 0);
    }
}
