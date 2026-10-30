//! Invocation errors and lookup failures, with their detail words
//! (`docs/abi.md`, "Errors" and "Error detail words").

/// Why a capability or slot lookup failed (`docs/abi.md`, "Lookup failure
/// description"). "Bits left" is the number of `CPtr` bits not yet resolved
/// where the lookup stopped.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum LookupFailure {
    /// The root is not a CNode capability.
    InvalidRoot,
    /// The slot reached is empty, or holds the wrong type of capability.
    MissingCapability { bits_left: u32 },
    /// A CNode needs more bits than are left (`bits_found` is its radix plus
    /// guard size), or a slot argument reached a non-CNode with bits left
    /// (`bits_found` is 0).
    DepthMismatch { bits_left: u32, bits_found: u32 },
    /// The CNode's guard is longer than the bits left, or differs from them.
    GuardMismatch {
        bits_left: u32,
        guard: u64,
        guard_size: u32,
    },
}

impl LookupFailure {
    /// The description words: one to four.
    pub fn words(&self) -> ([u64; 4], usize) {
        match *self {
            LookupFailure::InvalidRoot => ([1, 0, 0, 0], 1),
            LookupFailure::MissingCapability { bits_left } => ([2, bits_left as u64, 0, 0], 2),
            LookupFailure::DepthMismatch {
                bits_left,
                bits_found,
            } => ([3, bits_left as u64, bits_found as u64, 0], 3),
            LookupFailure::GuardMismatch {
                bits_left,
                guard,
                guard_size,
            } => ([4, bits_left as u64, guard, guard_size as u64], 4),
        }
    }
}

/// An error a kernel invocation returns. The code is the reply's label and
/// the detail words go in MR0 and up.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SyscallError {
    /// Message register `n` holds an invalid value.
    InvalidArgument(u64),
    /// Capability `n` is invalid: 0 for the invoked one, `i + 1` for extra
    /// capability `i`.
    InvalidCapability(u64),
    IllegalOperation,
    /// A value outside `[min, max]`.
    RangeError {
        min: u64,
        max: u64,
    },
    AlignmentError,
    /// A slot argument failed to resolve; `source` is set for `src_*` and
    /// `pivot_*` arguments.
    FailedLookup {
        source: bool,
        failure: LookupFailure,
    },
    TruncatedMessage,
    DeleteFirst,
    RevokeFirst,
    /// The objects do not fit; the bytes free in the untyped.
    NotEnoughMemory(u64),
}

impl SyscallError {
    /// The error code, the reply's label.
    pub const fn code(&self) -> u64 {
        match self {
            SyscallError::InvalidArgument(_) => 1,
            SyscallError::InvalidCapability(_) => 2,
            SyscallError::IllegalOperation => 3,
            SyscallError::RangeError { .. } => 4,
            SyscallError::AlignmentError => 5,
            SyscallError::FailedLookup { .. } => 6,
            SyscallError::TruncatedMessage => 7,
            SyscallError::DeleteFirst => 8,
            SyscallError::RevokeFirst => 9,
            SyscallError::NotEnoughMemory(_) => 10,
        }
    }

    /// The detail words and how many there are, the reply's `length`.
    pub fn detail(&self) -> ([u64; 5], usize) {
        match *self {
            SyscallError::InvalidArgument(n)
            | SyscallError::InvalidCapability(n)
            | SyscallError::NotEnoughMemory(n) => ([n, 0, 0, 0, 0], 1),
            SyscallError::RangeError { min, max } => ([min, max, 0, 0, 0], 2),
            SyscallError::FailedLookup { source, failure } => {
                let (w, n) = failure.words();
                ([source as u64, w[0], w[1], w[2], w[3]], 1 + n)
            }
            SyscallError::IllegalOperation
            | SyscallError::AlignmentError
            | SyscallError::TruncatedMessage
            | SyscallError::DeleteFirst
            | SyscallError::RevokeFirst => ([0; 5], 0),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detail_words() {
        let e = SyscallError::FailedLookup {
            source: true,
            failure: LookupFailure::GuardMismatch {
                bits_left: 9,
                guard: 5,
                guard_size: 3,
            },
        };
        assert_eq!(e.code(), 6);
        assert_eq!(e.detail(), ([1, 4, 9, 5, 3], 5));
        let e = SyscallError::RangeError { min: 1, max: 256 };
        assert_eq!((e.code(), e.detail()), (4, ([1, 256, 0, 0, 0], 2)));
        assert_eq!(SyscallError::DeleteFirst.detail().1, 0);
        let e = SyscallError::FailedLookup {
            source: false,
            failure: LookupFailure::InvalidRoot,
        };
        assert_eq!(e.detail(), ([0, 1, 0, 0, 0], 2));
    }
}
