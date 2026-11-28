//! RFC 1071's Internet checksum: the ones' complement sum of the data's
//! 16-bit big-endian words, over any length, an odd last byte padded with
//! 0, and its complement. IPv4's header, ICMP's message and UDP's datagram
//! with its pseudo-header all use it.
//!
//! A sum that verifies folds to `0xFFFF`: data that carries its own
//! checksum sums to the ones' complement of 0. With end-around carries a
//! sum is `0x0000` only for data that is all zeros, which no header is.

/// A running sum: byte strings added in order sum as if they were one,
/// however they are split.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Sum {
    /// The words added, not yet folded: 2^48 words before it could
    /// overflow, far past any frame.
    acc: u64,
    /// An odd number of bytes has been added, so the next byte is the low
    /// half of a word whose high half came before.
    odd: bool,
}

impl Sum {
    /// The sum of nothing.
    pub const fn new() -> Sum {
        Sum { acc: 0, odd: false }
    }

    /// Adds `bytes`, as if they followed everything added so far.
    pub fn add(&mut self, mut bytes: &[u8]) -> &mut Sum {
        if self.odd {
            let Some((&low, rest)) = bytes.split_first() else {
                return self;
            };
            self.acc += u64::from(low);
            self.odd = false;
            bytes = rest;
        }
        let (words, rest) = bytes.as_chunks::<2>();
        for w in words {
            self.acc += u64::from(u16::from_be_bytes(*w));
        }
        if let [high] = rest {
            self.acc += u64::from(*high) << 8;
            self.odd = true;
        }
        self
    }

    /// Adds one big-endian word, as its two bytes.
    pub fn add_u16(&mut self, word: u16) -> &mut Sum {
        self.add(&word.to_be_bytes())
    }

    /// The ones' complement sum: the carries folded back in.
    pub const fn fold(&self) -> u16 {
        let mut s = self.acc;
        while s > 0xFFFF {
            s = (s & 0xFFFF) + (s >> 16);
        }
        s as u16
    }

    /// The checksum to send: the complement of the sum.
    pub const fn checksum(&self) -> u16 {
        !self.fold()
    }

    /// Whether data that carries its checksum verifies.
    pub const fn verifies(&self) -> bool {
        self.fold() == 0xFFFF
    }
}

/// The ones' complement sum of `bytes`.
pub fn sum(bytes: &[u8]) -> u16 {
    Sum::new().add(bytes).fold()
}

/// The checksum of `bytes`: the complement of their sum.
pub fn checksum(bytes: &[u8]) -> u16 {
    Sum::new().add(bytes).checksum()
}

/// Whether `bytes`, which carry their own checksum, verify.
pub fn verifies(bytes: &[u8]) -> bool {
    Sum::new().add(bytes).verifies()
}
