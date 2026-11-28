//! GPADLs: how vmbus describes a run of the channel frame's pages to the
//! host (FreeBSD's `vmbus_chan_gpadl_connect`).
//!
//! A GPADL is one range of whole pages from offset 0: a `GPADL_CONN` with
//! `chm_range_len` 8 + 8 × pages, `chm_range_cnt` 1, the range's byte
//! length and its first 26 page numbers, then `GPADL_SUBCONN` messages of
//! up to 28 more each, `chm_msgno` 0. The host answers the last with
//! `GPADL_CONNRESP`. Handles are vmbus's to choose: FreeBSD's count up
//! from `0xE1E10` (`VMBUS_GPADL_START`) and skip 0.

use crate::layout::PAGE;
use crate::msg::{CONN_PAGES, Msg, PageList, SUBCONN_PAGES};

/// The first handle.
pub const START: u32 = 0xE1E10;

/// A run of pages: `count` from `first`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pages {
    pub first: u64,
    pub count: u64,
}

impl Pages {
    pub const fn end(&self) -> u64 {
        self.first + self.count
    }

    pub const fn contains(&self, page: u64) -> bool {
        self.first <= page && page < self.end()
    }
}

/// The messages that make GPADL `gpadl` of `pages` (physical page numbers)
/// on `channel`: a `GPADL_CONN`, then as many `GPADL_SUBCONN`s as the rest
/// needs. A GPADL has at least one page and at most 8,190, which keeps
/// `chm_range_len` in 16 bits (FreeBSD refuses more); `None` otherwise.
pub fn messages(channel: u32, gpadl: u32, pages: Pages) -> Option<Messages> {
    let range_len = u16::try_from(pages.count.checked_mul(8)?.checked_add(8)?).ok()?;
    let byte_len = u32::try_from(pages.count.checked_mul(PAGE)?).ok()?;
    pages.first.checked_add(pages.count)?;
    (pages.count != 0).then_some(Messages {
        channel,
        gpadl,
        range_len,
        byte_len,
        next: pages.first,
        end: pages.end(),
        first: true,
    })
}

/// The number of messages a GPADL of `count` pages takes.
pub const fn message_count(count: u64) -> u64 {
    let conn = CONN_PAGES as u64;
    let sub = SUBCONN_PAGES as u64;
    if count <= conn {
        1
    } else {
        1 + (count - conn).div_ceil(sub)
    }
}

/// A GPADL's messages, in the order vmbus posts them.
#[derive(Clone, Debug)]
pub struct Messages {
    channel: u32,
    gpadl: u32,
    range_len: u16,
    byte_len: u32,
    next: u64,
    end: u64,
    first: bool,
}

impl Iterator for Messages {
    type Item = Msg;

    fn next(&mut self) -> Option<Msg> {
        let left = self.end - self.next;
        if left == 0 {
            return None;
        }
        let max = if self.first {
            CONN_PAGES
        } else {
            SUBCONN_PAGES
        };
        let n = (left as usize).min(max);
        let pages = PageList::run(self.next, n).expect("at most 28 pages");
        self.next += n as u64;
        let m = if self.first {
            Msg::GpadlConn {
                channel: self.channel,
                gpadl: self.gpadl,
                range_len: self.range_len,
                range_count: 1,
                byte_len: self.byte_len,
                byte_offset: 0,
                pages,
            }
        } else {
            Msg::GpadlSubconn {
                number: 0,
                gpadl: self.gpadl,
                pages,
            }
        };
        self.first = false;
        Some(m)
    }
}

/// Handles, from [`START`] up, never 0.
#[derive(Clone, Copy, Debug)]
pub struct Handles(u32);

impl Default for Handles {
    fn default() -> Handles {
        Handles(START)
    }
}

impl Handles {
    /// The next handle.
    pub fn take(&mut self) -> u32 {
        if self.0 == 0 {
            self.0 = 1;
        }
        let h = self.0;
        self.0 = self.0.wrapping_add(1);
        h
    }
}
