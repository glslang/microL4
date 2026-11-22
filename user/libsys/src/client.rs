//! What [`crate::console::Client`] and [`crate::uart::Client`] share: a
//! request is a `Call` on the server's endpoint capability, its byte string
//! laid out by [`crate::proto`], and a reply with a non-zero label is a
//! [`CallError`].

use core::fmt;

use l4core::ipc::MessageInfo;

use crate::error::{Error, MAX_DETAIL_WORDS};
use crate::proto::{self, MAX_BYTES, MAX_REGISTER_BYTES, MAX_WORDS, Refusal};
use crate::syscall::{CPtr, Ipc, Message, call};
use crate::transfer::compose;

/// Why a request failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CallError {
    /// The server refused it.
    Refused(Refusal),
    /// The kernel refused the `Call`: no capability in the slot, or one
    /// without Write, for example.
    Kernel(Error),
    /// A reply that is neither success nor a refusal or kernel error, or
    /// a success that does not have the words the request answers with.
    BadReply { label: u64, length: u64 },
}

impl fmt::Display for CallError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            CallError::Refused(r) => write!(f, "refused: {r}"),
            CallError::Kernel(e) => write!(f, "the kernel: {e}"),
            CallError::BadReply { label, length } => {
                write!(f, "a reply with label {label:#x} and length {length}")
            }
        }
    }
}

/// A server's endpoint capability and the calling thread's IPC buffer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub cap: CPtr,
    pub ipc: Option<Ipc>,
}

impl Endpoint {
    /// The most bytes one request carries: 952 with an IPC buffer, 24
    /// without.
    pub fn max_bytes(&self) -> usize {
        if self.ipc.is_some() {
            MAX_BYTES
        } else {
            MAX_REGISTER_BYTES
        }
    }

    /// `Call`s request `label` with `bytes` as its byte string, or no words
    /// for `None`; the reply, label 0.
    pub fn call(&self, label: u64, bytes: Option<&[u8]>) -> Result<Message, CallError> {
        let mut words = [0; MAX_WORDS];
        let length = bytes.map_or(0, |b| proto::encode(b, &mut words));
        let reply = call(self.cap, &compose(self.ipc, label, &words[..length], &[]));
        check(reply, self.ipc)
    }

    /// Reply word `i`: MR0 to MR3 from registers, the rest from the IPC
    /// buffer. `None` past the reply's length, or past MR3 without a
    /// buffer.
    pub fn word(&self, reply: &Message, i: usize) -> Option<u64> {
        if i >= reply.info.length() as usize {
            return None;
        }
        match reply.mr.get(i) {
            Some(&w) => Some(w),
            None => self.ipc.map(|b| b.mr(i)),
        }
    }

    /// The byte string a reply carries, into `out`.
    pub fn bytes(&self, reply: &Message, out: &mut [u8]) -> Result<usize, CallError> {
        let length = reply.info.length() as usize;
        let bad = CallError::BadReply {
            label: 0,
            length: length as u64,
        };
        if length > 4 && self.ipc.is_none() {
            return Err(bad);
        }
        proto::decode(length, |i| self.word(reply, i).unwrap_or(0), out.len(), out).map_err(|_| bad)
    }
}

/// Success, or the error a non-zero reply label names.
pub(crate) fn check(reply: Message, ipc: Option<Ipc>) -> Result<Message, CallError> {
    let info: MessageInfo = reply.info;
    match info.label() {
        0 => Ok(reply),
        l if Refusal::from_label(l).is_some() && info.length() == 0 => {
            Err(CallError::Refused(Refusal::from_label(l).unwrap()))
        }
        1..=10 => {
            let mut words = [0; MAX_DETAIL_WORDS];
            let n = (info.length() as usize).min(MAX_DETAIL_WORDS);
            for (i, w) in words.iter_mut().enumerate().take(n) {
                *w = match reply.mr.get(i) {
                    Some(&r) => r,
                    None => ipc.map_or(0, |b| b.mr(i)),
                };
            }
            Err(CallError::Kernel(Error::decode(info, &words)))
        }
        label => Err(CallError::BadReply {
            label,
            length: info.length(),
        }),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use l4core::error::SyscallError;

    fn reply(label: u64, length: u64, mr: [u64; 4]) -> Message {
        Message::new(MessageInfo::new(label, 0, 0, length), mr)
    }

    #[test]
    fn replies_are_told_apart() {
        let ok = reply(0, 1, [5, 0, 0, 0]);
        assert_eq!(check(ok, None), Ok(ok));
        assert_eq!(
            check(reply(0x103, 0, [0; 4]), None),
            Err(CallError::Refused(Refusal::Busy))
        );
        // A refusal label with words is no refusal.
        assert_eq!(
            check(reply(0x103, 1, [0; 4]), None),
            Err(CallError::BadReply {
                label: 0x103,
                length: 1
            })
        );
        // The kernel's InvalidCapability, for a slot without Write.
        assert_eq!(
            check(reply(2, 1, [0; 4]), None),
            Err(CallError::Kernel(Error::Kernel(
                SyscallError::InvalidCapability(0)
            )))
        );
        assert_eq!(
            check(reply(0x200, 0, [0; 4]), None),
            Err(CallError::BadReply {
                label: 0x200,
                length: 0
            })
        );
    }

    #[test]
    fn a_reply_byte_string_needs_a_buffer_past_three_words() {
        let ep = Endpoint { cap: 9, ipc: None };
        let mut out = [0; 64];
        let r = reply(0, 2, [3, u64::from_le_bytes(*b"xyz\0\0\0\0\0"), 0, 0]);
        assert_eq!(ep.bytes(&r, &mut out), Ok(3));
        assert_eq!(&out[..3], b"xyz");
        let r = reply(0, 5, [32, 0, 0, 0]);
        assert_eq!(
            ep.bytes(&r, &mut out),
            Err(CallError::BadReply {
                label: 0,
                length: 5
            })
        );
        // Over what the caller takes.
        let r = reply(0, 2, [65, 0, 0, 0]);
        assert!(ep.bytes(&r, &mut out).is_err());
        assert_eq!(ep.max_bytes(), 24);
    }
}
