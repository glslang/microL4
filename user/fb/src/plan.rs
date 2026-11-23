//! The frame plan: which frames root makes of the framebuffer's device
//! untyped and where each maps in term's VSpace (`docs/design.md`, "The
//! frame plan").
//!
//! The frames cover the visible bytes, `[base, base + 4 x stride x
//! height)` rounded out to pages, taken from the untyped in order: from
//! each, a 2 MiB frame for every 2 MiB stretch that is 2 MiB-aligned and
//! lies inside that untyped, 4 KiB frames for the rest, stopping once the
//! visible bytes are covered. Untyped are aligned to their size, so an
//! untyped of 2 MiB or more gives only 2 MiB frames and a smaller one only
//! 4 KiB frames, each from the untyped's start: a fresh untyped's first
//! `Untyped_Retype` places its objects there. A frame at physical `p` maps
//! at [`WINDOW`] + `p` - (`base` rounded down to 2 MiB).

use core::fmt;

use crate::{
    Fields, Geometry, HUGE, HUGE_BITS, PAGE, PAGE_BITS, RETYPE_FAN_OUT_LIMIT, Untyped, Unusable,
    WINDOW, round_down, round_up,
};

/// One `Untyped_Retype`: `count` frames of `2^size_bits` bytes from
/// `framebuffer_untyped`'s descriptor `untyped`, the first at physical
/// `paddr`, frame `i` at `paddr + (i << size_bits)`, mapped at `vaddr +
/// (i << size_bits)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Retype {
    pub untyped: usize,
    /// 12 for 4 KiB frames, 21 for 2 MiB.
    pub size_bits: u32,
    /// 1 to [`RETYPE_FAN_OUT_LIMIT`].
    pub count: usize,
    pub paddr: u64,
    pub vaddr: u64,
}

impl Retype {
    /// Whether these are 2 MiB frames.
    pub const fn huge(&self) -> bool {
        self.size_bits == HUGE_BITS
    }

    /// Frame `i`.
    pub const fn frame(&self, i: usize) -> Frame {
        let off = (i as u64) << self.size_bits;
        Frame {
            paddr: self.paddr + off,
            vaddr: self.vaddr + off,
            size_bits: self.size_bits,
        }
    }
}

/// One frame of the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Frame {
    pub paddr: u64,
    pub vaddr: u64,
    pub size_bits: u32,
}

/// The frames that cover a checked framebuffer's visible bytes.
#[derive(Clone, Copy, Debug)]
pub struct Plan<'a> {
    fields: Fields,
    geometry: Geometry,
    untyped: &'a [Untyped],
    /// The visible bytes' physical end, rounded up to a page.
    end: u64,
    /// `base` rounded down to 2 MiB: the physical address at [`WINDOW`].
    window_base: u64,
}

impl<'a> Plan<'a> {
    /// The plan for BootInfo's `framebuffer` fields and
    /// `framebuffer_untyped`'s descriptors, once [`Geometry::check`]
    /// accepts them.
    pub fn new(fields: &Fields, untyped: &'a [Untyped]) -> Result<Plan<'a>, Unusable> {
        let geometry = Geometry::check(fields, untyped)?;
        let end = round_up(fields.base + geometry.visible_bytes(), PAGE)
            .expect("check bounds base + size");
        Ok(Plan {
            fields: *fields,
            geometry,
            untyped,
            end,
            window_base: round_down(fields.base, HUGE),
        })
    }

    pub const fn geometry(&self) -> Geometry {
        self.geometry
    }

    pub const fn fields(&self) -> Fields {
        self.fields
    }

    /// The descriptors the plan was made from: all of
    /// `framebuffer_untyped`, though the last may give no frame.
    pub const fn untyped(&self) -> &'a [Untyped] {
        self.untyped
    }

    /// One past the window's last byte that a frame maps.
    pub fn window_end(&self) -> u64 {
        self.frames()
            .last()
            .map_or(WINDOW, |f| f.vaddr + (1 << f.size_bits))
    }

    /// The retypes, in order, each within [`RETYPE_FAN_OUT_LIMIT`].
    pub fn retypes(&self) -> Retypes<'a> {
        Retypes {
            untyped: self.untyped,
            end: self.end,
            window_base: self.window_base,
            index: 0,
            next: None,
        }
    }

    /// Every frame, in address order.
    pub fn frames(&self) -> impl Iterator<Item = Frame> + 'a {
        self.retypes()
            .flat_map(|r| (0..r.count).map(move |i| r.frame(i)))
    }

    /// The 2 MiB-aligned window addresses that hold 4 KiB frames, each
    /// once and in order: root maps a page table at each. A 2 MiB frame
    /// maps in the page directory itself.
    pub fn page_tables(&self) -> PageTables<'a> {
        PageTables {
            retypes: self.retypes(),
            last: None,
        }
    }

    /// 2 MiB frames.
    pub fn huge_frames(&self) -> usize {
        self.count(true)
    }

    /// 4 KiB frames.
    pub fn small_frames(&self) -> usize {
        self.count(false)
    }

    fn count(&self, huge: bool) -> usize {
        self.retypes()
            .filter(|r| r.huge() == huge)
            .map(|r| r.count)
            .sum()
    }
}

/// `1280x800 BGR, stride 1280, 4000 KiB at 0x80000000: 6 untyped, 1 2
/// MiB and 488 4 KiB frames`, the start of root's `fb:` line.
impl fmt::Display for Plan<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let g = &self.geometry;
        write!(
            f,
            "{}x{} {}, stride {}, {} KiB at {:#x}: {} untyped, {} 2 MiB and {} 4 KiB frames",
            g.width(),
            g.height(),
            g.format(),
            g.stride(),
            self.fields.size.div_ceil(1024),
            self.fields.base,
            self.untyped.len(),
            self.huge_frames(),
            self.small_frames()
        )
    }
}

/// [`Plan::retypes`].
#[derive(Clone, Debug)]
pub struct Retypes<'a> {
    untyped: &'a [Untyped],
    end: u64,
    window_base: u64,
    index: usize,
    /// The next frame's physical address within `untyped[index]`, once
    /// it has given a retype.
    next: Option<u64>,
}

impl Iterator for Retypes<'_> {
    type Item = Retype;

    fn next(&mut self) -> Option<Retype> {
        loop {
            let u = self.untyped.get(self.index)?;
            if u.paddr >= self.end {
                return None;
            }
            let bits = if u.size() >= HUGE {
                HUGE_BITS
            } else {
                PAGE_BITS
            };
            let size = 1u64 << bits;
            // The untyped's frames that cover visible bytes. `check` made
            // the untyped tile the page-rounded framebuffer, each aligned
            // to its size, so these sums cannot overflow.
            let stop = (u.paddr + u.size()).min(round_up(self.end, size).unwrap_or(u64::MAX));
            let at = self.next.unwrap_or(u.paddr);
            if at >= stop {
                self.index += 1;
                self.next = None;
                continue;
            }
            let count = (((stop - at) >> bits) as usize).min(RETYPE_FAN_OUT_LIMIT);
            self.next = Some(at + ((count as u64) << bits));
            return Some(Retype {
                untyped: self.index,
                size_bits: bits,
                count,
                paddr: at,
                vaddr: WINDOW + (at - self.window_base),
            });
        }
    }
}

/// [`Plan::page_tables`].
#[derive(Clone, Debug)]
pub struct PageTables<'a> {
    retypes: Retypes<'a>,
    last: Option<u64>,
}

impl Iterator for PageTables<'_> {
    type Item = u64;

    fn next(&mut self) -> Option<u64> {
        loop {
            let r = self.retypes.next()?;
            if r.huge() {
                continue;
            }
            // 4 KiB frames come from untyped under 2 MiB, aligned to their
            // size, so one retype lies in one 2 MiB stretch.
            let table = round_down(r.vaddr, HUGE);
            if self.last != Some(table) {
                self.last = Some(table);
                return Some(table);
            }
        }
    }
}
