//! The error a kernel invocation returns, decoded from its reply
//! (`docs/abi.md`, "Errors" and "Error detail words").
//!
//! A `Call` on a kernel object returns a `MessageInfo` whose label is 0 on
//! success and an error code otherwise, with `length` detail words in MR0
//! and up. [`Error::decode`] turns the code and the words into
//! `l4core`'s [`SyscallError`], the type the kernel encodes them from, so the
//! two sides cannot disagree on the layout.

use core::fmt;

use l4core::error::{LookupFailure, SyscallError};
use l4core::ipc::MessageInfo;

/// The most detail words an error has: `FailedLookup` with a
/// `GuardMismatch`.
pub const MAX_DETAIL_WORDS: usize = 5;

/// A failed kernel invocation.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Error {
    /// An error code of `docs/abi.md` with its detail words.
    Kernel(SyscallError),
    /// A reply that does not decode: a label that is no error code, or
    /// fewer detail words than the code has. A thread without an IPC buffer
    /// receives only MR0 to MR3, so a `FailedLookup` with a
    /// `DepthMismatch` or `GuardMismatch` arrives cut short.
    Undecoded {
        label: u64,
        length: u64,
        words: [u64; MAX_DETAIL_WORDS],
    },
}

impl Error {
    /// Decodes a reply whose label is not 0. `words` holds MR0 and up, at
    /// least as many as `info.length()` says, up to [`MAX_DETAIL_WORDS`];
    /// words past `length` are ignored.
    pub fn decode(info: MessageInfo, words: &[u64]) -> Error {
        let length = info.length();
        let mut w = [0; MAX_DETAIL_WORDS];
        let n = (length as usize).min(MAX_DETAIL_WORDS).min(words.len());
        w[..n].copy_from_slice(&words[..n]);
        let undecoded = Error::Undecoded {
            label: info.label(),
            length,
            words: w,
        };
        // Exactly the detail words `l4core` encodes for the code.
        let need = |count: u64| length == count;
        let e = match info.label() {
            1 if need(1) => SyscallError::InvalidArgument(w[0]),
            2 if need(1) => SyscallError::InvalidCapability(w[0]),
            3 if need(0) => SyscallError::IllegalOperation,
            4 if need(2) => SyscallError::RangeError {
                min: w[0],
                max: w[1],
            },
            5 if need(0) => SyscallError::AlignmentError,
            6 if length >= 2 && w[0] <= 1 => match lookup_failure(&w[1..], length as usize - 1) {
                Some(failure) => SyscallError::FailedLookup {
                    source: w[0] == 1,
                    failure,
                },
                None => return undecoded,
            },
            7 if need(0) => SyscallError::TruncatedMessage,
            8 if need(0) => SyscallError::DeleteFirst,
            9 if need(0) => SyscallError::RevokeFirst,
            10 if need(1) => SyscallError::NotEnoughMemory(w[0]),
            _ => return undecoded,
        };
        Error::Kernel(e)
    }

    /// The kernel's error, if the reply decoded.
    pub fn kernel(&self) -> Option<SyscallError> {
        match *self {
            Error::Kernel(e) => Some(e),
            Error::Undecoded { .. } => None,
        }
    }
}

/// The lookup failure description in `w[..n]` (`docs/abi.md`, "Lookup
/// failure description"), if it is one: the type word, then exactly the
/// words that type has.
fn lookup_failure(w: &[u64], n: usize) -> Option<LookupFailure> {
    let small = |v: u64| u32::try_from(v).ok();
    Some(match (w.first()?, n) {
        (1, 1) => LookupFailure::InvalidRoot,
        (2, 2) => LookupFailure::MissingCapability {
            bits_left: small(w[1])?,
        },
        (3, 3) => LookupFailure::DepthMismatch {
            bits_left: small(w[1])?,
            bits_found: small(w[2])?,
        },
        (4, 4) => LookupFailure::GuardMismatch {
            bits_left: small(w[1])?,
            guard: w[2],
            guard_size: small(w[3])?,
        },
        _ => return None,
    })
}

impl From<SyscallError> for Error {
    fn from(e: SyscallError) -> Error {
        Error::Kernel(e)
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::Kernel(e) => write!(f, "{e:?}"),
            Error::Undecoded {
                label,
                length,
                words,
            } => {
                write!(f, "undecoded reply: label {label}, length {length}")?;
                let n = (*length as usize).min(MAX_DETAIL_WORDS);
                for (i, w) in words[..n].iter().enumerate() {
                    write!(f, ", MR{i} {w:#x}")?;
                }
                Ok(())
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::format;
    use std::vec::Vec;

    /// Every error variant, with detail words worth telling apart.
    fn samples() -> Vec<SyscallError> {
        let failures = [
            LookupFailure::InvalidRoot,
            LookupFailure::MissingCapability { bits_left: 0 },
            LookupFailure::MissingCapability { bits_left: 64 },
            LookupFailure::DepthMismatch {
                bits_left: 12,
                bits_found: 0,
            },
            LookupFailure::DepthMismatch {
                bits_left: 7,
                bits_found: 64,
            },
            LookupFailure::GuardMismatch {
                bits_left: 64,
                guard: u64::MAX >> 6,
                guard_size: 58,
            },
        ];
        let mut v = std::vec![
            SyscallError::InvalidArgument(0),
            SyscallError::InvalidArgument(119),
            SyscallError::InvalidCapability(0),
            SyscallError::InvalidCapability(3),
            SyscallError::IllegalOperation,
            SyscallError::RangeError { min: 0, max: 255 },
            SyscallError::RangeError {
                min: 1,
                max: u64::MAX,
            },
            SyscallError::AlignmentError,
            SyscallError::TruncatedMessage,
            SyscallError::DeleteFirst,
            SyscallError::RevokeFirst,
            SyscallError::NotEnoughMemory(0),
            SyscallError::NotEnoughMemory(1 << 40),
        ];
        for failure in failures {
            for source in [false, true] {
                v.push(SyscallError::FailedLookup { source, failure });
            }
        }
        v
    }

    /// The reply the kernel sends for `e`: its `MessageInfo` and words.
    fn reply(e: &SyscallError) -> (MessageInfo, [u64; MAX_DETAIL_WORDS]) {
        let (words, n) = e.detail();
        (MessageInfo::new(e.code(), 0, 0, n as u64), words)
    }

    #[test]
    fn every_error_the_kernel_encodes_decodes_to_itself() {
        for e in samples() {
            let (info, words) = reply(&e);
            assert_eq!(Error::decode(info, &words), Error::Kernel(e), "{e:?}");
            assert_eq!(Error::decode(info, &words).kernel(), Some(e));
        }
    }

    #[test]
    fn words_past_length_are_ignored() {
        for e in samples() {
            let (info, mut words) = reply(&e);
            let n = info.length() as usize;
            words[n..].fill(0xDEAD);
            assert_eq!(Error::decode(info, &words), Error::Kernel(e), "{e:?}");
        }
    }

    #[test]
    fn a_wrong_length_or_an_unknown_code_does_not_decode() {
        for e in samples() {
            let (info, words) = reply(&e);
            for length in 0..=MAX_DETAIL_WORDS as u64 {
                if length == info.length() {
                    continue;
                }
                let cut = MessageInfo::new(info.label(), 0, 0, length);
                let got = Error::decode(cut, &words);
                assert!(
                    matches!(got, Error::Undecoded { label, length: l, .. }
                        if label == info.label() && l == length),
                    "{e:?} with length {length}: {got:?}"
                );
            }
        }
        for label in [0, 11, 12, 0xFF, (1 << 52) - 1] {
            let info = MessageInfo::new(label, 0, 0, 1);
            assert!(matches!(
                Error::decode(info, &[7]),
                Error::Undecoded {
                    words: [7, 0, 0, 0, 0],
                    ..
                }
            ));
        }
    }

    #[test]
    fn a_bad_lookup_description_does_not_decode() {
        let bad: [&[u64]; 6] = [
            &[2, 1],             // source word above 1
            &[0, 5],             // no such failure type
            &[0, 0],             // nor 0
            &[1, 2, 1 << 32],    // bits left wider than 32 bits
            &[0, 3, 1, 1 << 40], // bits found likewise
            &[0, 4, 1, 0, 1 << 33],
        ];
        for words in bad {
            let info = MessageInfo::new(6, 0, 0, words.len() as u64);
            assert!(
                matches!(Error::decode(info, words), Error::Undecoded { .. }),
                "{words:?}"
            );
        }
    }

    #[test]
    fn a_short_word_slice_counts_as_zeros() {
        // A caller that read fewer words than `length` says: the rest are 0.
        let info = MessageInfo::new(4, 0, 0, 2);
        assert_eq!(
            Error::decode(info, &[3]),
            Error::Kernel(SyscallError::RangeError { min: 3, max: 0 })
        );
    }

    #[test]
    fn display() {
        assert_eq!(
            format!(
                "{}",
                Error::Kernel(SyscallError::RangeError { min: 0, max: 20 })
            ),
            "RangeError { min: 0, max: 20 }"
        );
        let info = MessageInfo::new(99, 0, 0, 2);
        assert_eq!(
            format!("{}", Error::decode(info, &[1, 0x20])),
            "undecoded reply: label 99, length 2, MR0 0x1, MR1 0x20"
        );
    }
}
