//! A fixed-size byte ring.

/// Up to `N` bytes, first in first out.
#[derive(Clone, Debug)]
pub struct Ring<const N: usize> {
    buf: [u8; N],
    head: usize,
    len: usize,
}

impl<const N: usize> Default for Ring<N> {
    fn default() -> Self {
        Self::new()
    }
}

impl<const N: usize> Ring<N> {
    pub const fn new() -> Ring<N> {
        Ring {
            buf: [0; N],
            head: 0,
            len: 0,
        }
    }

    pub const fn len(&self) -> usize {
        self.len
    }

    pub const fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub const fn is_full(&self) -> bool {
        self.len == N
    }

    /// Bytes it can still take.
    pub const fn room(&self) -> usize {
        N - self.len
    }

    /// Appends `b`; false, and nothing changes, if full.
    pub fn push(&mut self, b: u8) -> bool {
        if self.is_full() {
            return false;
        }
        self.buf[(self.head + self.len) % N] = b;
        self.len += 1;
        true
    }

    /// Appends all of `bytes`, or nothing if they do not all fit; whether
    /// they did.
    pub fn push_all(&mut self, bytes: &[u8]) -> bool {
        if bytes.len() > self.room() {
            return false;
        }
        for &b in bytes {
            self.push(b);
        }
        true
    }

    /// The oldest byte.
    pub fn pop(&mut self) -> Option<u8> {
        if self.is_empty() {
            return None;
        }
        let b = self.buf[self.head];
        self.head = (self.head + 1) % N;
        self.len -= 1;
        Some(b)
    }

    /// Moves the oldest bytes into `out`, as many as fit; how many.
    pub fn take_into(&mut self, out: &mut [u8]) -> usize {
        let mut n = 0;
        while n < out.len() {
            match self.pop() {
                Some(b) => out[n] = b,
                None => break,
            }
            n += 1;
        }
        n
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bytes_come_out_in_order_across_the_wrap() {
        let mut r: Ring<4> = Ring::new();
        assert!(r.is_empty() && r.room() == 4);
        assert!(r.push_all(b"abc"));
        assert_eq!(r.pop(), Some(b'a'));
        assert!(r.push_all(b"de"));
        assert!(r.is_full());
        assert!(!r.push(b'x'));
        assert!(!r.push_all(b"y"));
        let mut out = [0; 3];
        assert_eq!(r.take_into(&mut out), 3);
        assert_eq!(&out, b"bcd");
        assert_eq!(r.len(), 1);
        assert!(!r.push_all(b"wxyz"), "all or nothing");
        assert_eq!(r.len(), 1);
        assert_eq!(r.take_into(&mut out), 1);
        assert_eq!(out[0], b'e');
        assert_eq!(r.pop(), None);
    }
}
