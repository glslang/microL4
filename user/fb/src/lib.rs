//! `fb`: the GOP framebuffer as microL4's user space sees it
//! (`docs/design.md`, "`fb`" under "Framebuffer, terminal and TUI").
//!
//! The root task uses it to decide whether there is a usable framebuffer
//! ([`Geometry::check`], whose [`Unusable`] says why not) and which frames
//! to make of the framebuffer's device untyped ([`Plan`]); term uses it to
//! write pixels ([`Surface`]). There is no server: root maps the frames
//! into term's VSpace at [`WINDOW`], write-combining, and passes term the
//! geometry in three words ([`Geometry::to_words`]), which term's entry
//! checks again ([`Geometry::from_words`]).
//!
//! A pixel is a `u32`: [`Format::Rgb`] has red in byte 0, [`Format::Bgr`]
//! blue; byte 3 is written 0. Both QEMU's OVMF and Hyper-V give BGR.
//! Nothing reads the framebuffer, which is uncached or write-combining
//! memory: the surface has no read method.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

mod plan;
mod surface;
#[cfg(test)]
mod tests;

use core::fmt;

pub use plan::{Frame, PageTables, Plan, Retype, Retypes};
pub use surface::Surface;

/// Where the framebuffer's frames map in term's VSpace: the framebuffer's
/// first byte at `WINDOW` + (`base` mod 2 MiB), so virtual and physical
/// addresses agree modulo 2 MiB.
pub const WINDOW: u64 = 0x1000_0000;
/// The window must end at or below this: the first GiB, under the page
/// directory the root image's range already uses.
pub const WINDOW_END: u64 = 0x4000_0000;
/// A small frame, and a page table's reach.
pub const PAGE: u64 = 1 << PAGE_BITS;
pub const PAGE_BITS: u32 = 12;
/// A large frame.
pub const HUGE: u64 = 1 << HUGE_BITS;
pub const HUGE_BITS: u32 = 21;
/// The most objects one `Untyped_Retype` makes (`docs/abi.md`,
/// "Untyped_Retype"); the plan's retypes stay within it.
pub const RETYPE_FAN_OUT_LIMIT: usize = 256;
/// Bytes per pixel: only 32-bit formats exist.
pub const BYTES_PER_PIXEL: u64 = 4;
/// The smallest usable mode: 80 x 24 cells of 8 x 16 pixels.
pub const MIN_WIDTH: u32 = 640;
pub const MIN_HEIGHT: u32 = 384;
/// A cell of the font, in pixels.
pub const CELL_WIDTH: u32 = 8;
pub const CELL_HEIGHT: u32 = 16;

/// A pixel format, as the handoff and BootInfo number them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u32)]
pub enum Format {
    /// Byte 0 red, byte 1 green, byte 2 blue.
    Rgb = 1,
    /// Byte 0 blue, byte 1 green, byte 2 red.
    Bgr = 2,
}

impl Format {
    /// The format numbered `n` (1 RGB, 2 BGR), if it is one.
    pub const fn from_number(n: u32) -> Option<Format> {
        match n {
            1 => Some(Format::Rgb),
            2 => Some(Format::Bgr),
            _ => None,
        }
    }

    pub const fn number(self) -> u32 {
        self as u32
    }

    pub const fn name(self) -> &'static str {
        match self {
            Format::Rgb => "RGB",
            Format::Bgr => "BGR",
        }
    }

    /// The pixel for `c`: `r | g << 8 | b << 16` for RGB, `b | g << 8 |
    /// r << 16` for BGR; byte 3 is 0.
    pub const fn pixel(self, c: Rgb) -> u32 {
        let (r, g, b) = (c.r() as u32, c.g() as u32, c.b() as u32);
        match self {
            Format::Rgb => r | g << 8 | b << 16,
            Format::Bgr => b | g << 8 | r << 16,
        }
    }

    /// The colour of `pixel`, byte 3 ignored: what a host test reads back
    /// from its own buffer, never from the framebuffer.
    pub const fn colour(self, pixel: u32) -> Rgb {
        let (b0, b1, b2) = (pixel as u8, (pixel >> 8) as u8, (pixel >> 16) as u8);
        match self {
            Format::Rgb => Rgb::new(b0, b1, b2),
            Format::Bgr => Rgb::new(b2, b1, b0),
        }
    }
}

impl fmt::Display for Format {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.name())
    }
}

/// A colour, `0xRRGGBB`, as the design writes palettes.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub struct Rgb(pub u32);

impl Rgb {
    pub const fn new(r: u8, g: u8, b: u8) -> Rgb {
        Rgb((r as u32) << 16 | (g as u32) << 8 | b as u32)
    }

    pub const fn r(self) -> u8 {
        (self.0 >> 16) as u8
    }

    pub const fn g(self) -> u8 {
        (self.0 >> 8) as u8
    }

    pub const fn b(self) -> u8 {
        self.0 as u8
    }
}

/// BootInfo's `framebuffer` fields, as plain numbers: `fb` depends on
/// nothing.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Fields {
    /// Physical address of the first pixel; 0 for none.
    pub base: u64,
    /// Bytes from `base` the GOP reports.
    pub size: u64,
    pub width: u32,
    pub height: u32,
    /// Pixels per scan line.
    pub stride: u32,
    /// 0 for none, 1 RGB, 2 BGR, or anything a loader passed.
    pub format: u32,
}

/// One descriptor of BootInfo's `framebuffer_untyped`, as plain numbers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Untyped {
    pub paddr: u64,
    /// The size is `2^size_bits` bytes.
    pub size_bits: u8,
    pub device: bool,
}

impl Untyped {
    pub const fn new(paddr: u64, size_bits: u8, device: bool) -> Untyped {
        Untyped {
            paddr,
            size_bits,
            device,
        }
    }

    /// Bytes covered; 0 for a size no untyped has (64 bits or more).
    pub const fn size(&self) -> u64 {
        if self.size_bits < 64 {
            1 << self.size_bits
        } else {
            0
        }
    }
}

/// Why there is no usable framebuffer, in the order
/// [`Geometry::check`] looks. Its `Display` is the text after root's
/// `fb: none: `.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unusable {
    /// `format` or `base` is 0: no GOP framebuffer, or a bitmask or
    /// BLT-only mode, which the loader does not pass.
    None,
    /// `framebuffer_untyped` is empty: the kernel kept it (ADR 0024).
    NotHandedOut,
    /// A format neither RGB (1) nor BGR (2).
    Format(u32),
    /// Below 640 x 384 pixels, 80 x 24 cells.
    TooSmall { width: u32, height: u32 },
    /// `stride` below `width`, `base` not 4-byte aligned, or 4 x `stride`
    /// x `height` above `size` (or `base + size` past the address space).
    Geometry(Fields),
    /// Descriptor `index` of `count` is not device memory continuing the
    /// tiling of the page-rounded `[base, base + size)` at `expected`; an
    /// `index` of `count` means the descriptors end there, short.
    Untyped {
        index: usize,
        count: usize,
        expected: u64,
    },
    /// The window, from [`WINDOW`] to the visible bytes' end rounded up to
    /// 2 MiB, would take `bytes` and pass [`WINDOW_END`].
    TooLarge { bytes: u64 },
}

impl fmt::Display for Unusable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Unusable::None => f.write_str("the loader found no GOP framebuffer"),
            Unusable::NotHandedOut => f.write_str("the kernel kept it (see its boot summary)"),
            Unusable::Format(n) => write!(f, "pixel format {n}, neither RGB (1) nor BGR (2)"),
            Unusable::TooSmall { width, height } => {
                write!(f, "{width}x{height}, below {MIN_WIDTH}x{MIN_HEIGHT}")
            }
            Unusable::Geometry(g) => write!(
                f,
                "{}x{}, stride {}, {:#x} bytes at {:#x}: needs a stride of at least the width, \
                 a 4-byte aligned base and 4 x stride x height bytes within the size",
                g.width, g.height, g.stride, g.size, g.base
            ),
            Unusable::Untyped {
                index,
                count,
                expected,
            } if index < count => write!(
                f,
                "framebuffer untyped {index} of {count} is not the device untyped at \
                 {expected:#x} that the tiling needs"
            ),
            Unusable::Untyped {
                count, expected, ..
            } => write!(
                f,
                "the {count} framebuffer untyped end at {expected:#x}, before its last page"
            ),
            Unusable::TooLarge { bytes } => write!(
                f,
                "a {} KiB window from {WINDOW:#x} would pass {WINDOW_END:#x}",
                bytes / 1024
            ),
        }
    }
}

pub(crate) const fn round_down(x: u64, to: u64) -> u64 {
    x & !(to - 1)
}

/// `None` on overflow.
pub(crate) const fn round_up(x: u64, to: u64) -> Option<u64> {
    match x.checked_add(to - 1) {
        Some(y) => Some(round_down(y, to)),
        None => None,
    }
}

/// A checked mode: what term needs to draw, with the first pixel's offset
/// in the window. Only [`Geometry::check`], [`Geometry::from_words`] and,
/// for host buffers, [`Geometry::new`] make one, so `stride` is at least
/// `width` and the window fits below [`WINDOW_END`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Geometry {
    width: u32,
    height: u32,
    stride: u32,
    format: Format,
    offset: u64,
}

impl Geometry {
    /// BootInfo's `framebuffer` fields and `framebuffer_untyped`'s
    /// descriptors: the geometry, or the first reason, in the design's
    /// order, that there is none usable.
    pub fn check(f: &Fields, untyped: &[Untyped]) -> Result<Geometry, Unusable> {
        if f.format == 0 || f.base == 0 {
            return Err(Unusable::None);
        }
        if untyped.is_empty() {
            return Err(Unusable::NotHandedOut);
        }
        let format = Format::from_number(f.format).ok_or(Unusable::Format(f.format))?;
        if f.width < MIN_WIDTH || f.height < MIN_HEIGHT {
            return Err(Unusable::TooSmall {
                width: f.width,
                height: f.height,
            });
        }
        let visible = BYTES_PER_PIXEL * u64::from(f.stride) * u64::from(f.height);
        let span = f
            .base
            .checked_add(f.size)
            .and_then(|end| round_up(end, PAGE));
        let Some(end) =
            span.filter(|_| f.stride >= f.width && f.base.is_multiple_of(4) && visible <= f.size)
        else {
            return Err(Unusable::Geometry(*f));
        };
        tile(round_down(f.base, PAGE), end, untyped)?;
        let g = Geometry {
            width: f.width,
            height: f.height,
            stride: f.stride,
            format,
            offset: f.base % HUGE,
        };
        match g.window_bytes() {
            Some(bytes) if bytes <= WINDOW_END - WINDOW => Ok(g),
            bytes => Err(Unusable::TooLarge {
                bytes: bytes.unwrap_or(u64::MAX),
            }),
        }
    }

    /// A geometry for a host buffer of `stride x height` pixels, with the
    /// first pixel at its start: any size from 1 x 1 whose window would
    /// fit, so that tests can draw on small surfaces. The root task and
    /// term use [`check`](Self::check) and
    /// [`from_words`](Self::from_words), which also require 640 x 384.
    pub fn new(width: u32, height: u32, stride: u32, format: Format) -> Option<Geometry> {
        let g = Geometry {
            width,
            height,
            stride,
            format,
            offset: 0,
        };
        g.fits().then_some(g)
    }

    /// The words root passes term in `rdi`, `rsi` and `rdx`: `width |
    /// height << 32`, `stride | format << 32`, and the first pixel's
    /// offset in the window.
    pub const fn to_words(&self) -> [u64; 3] {
        [
            self.width as u64 | (self.height as u64) << 32,
            self.stride as u64 | (self.format as u64) << 32,
            self.offset,
        ]
    }

    /// Checks `to_words`' words again: a known format, at least 640 x
    /// 384, a stride of at least the width, an offset 4-byte aligned and
    /// below 2 MiB, and a window below [`WINDOW_END`]. `None` otherwise.
    pub fn from_words(w: [u64; 3]) -> Option<Geometry> {
        let g = Geometry {
            width: w[0] as u32,
            height: (w[0] >> 32) as u32,
            stride: w[1] as u32,
            format: Format::from_number((w[1] >> 32) as u32)?,
            offset: w[2],
        };
        (g.width >= MIN_WIDTH
            && g.height >= MIN_HEIGHT
            && g.offset.is_multiple_of(4)
            && g.offset < HUGE
            && g.fits())
        .then_some(g)
    }

    fn fits(&self) -> bool {
        self.width > 0
            && self.height > 0
            && self.stride >= self.width
            && self
                .window_bytes()
                .is_some_and(|b| b <= WINDOW_END - WINDOW)
    }

    pub const fn width(&self) -> u32 {
        self.width
    }

    pub const fn height(&self) -> u32 {
        self.height
    }

    /// Pixels per scan line.
    pub const fn stride(&self) -> u32 {
        self.stride
    }

    pub const fn format(&self) -> Format {
        self.format
    }

    /// The first pixel's byte offset from [`WINDOW`]: `base` mod 2 MiB.
    pub const fn offset(&self) -> u64 {
        self.offset
    }

    /// The pixel slice's length, `stride x height`.
    pub const fn pixels(&self) -> usize {
        self.stride as usize * self.height as usize
    }

    /// The visible bytes, 4 x `stride` x `height`.
    pub const fn visible_bytes(&self) -> u64 {
        BYTES_PER_PIXEL * self.stride as u64 * self.height as u64
    }

    /// The window's size: from [`WINDOW`] to the visible bytes' end,
    /// rounded up to 2 MiB.
    pub fn window_bytes(&self) -> Option<u64> {
        let visible = BYTES_PER_PIXEL
            .checked_mul(u64::from(self.stride))?
            .checked_mul(u64::from(self.height))?;
        round_up(self.offset.checked_add(visible)?, HUGE)
    }

    /// Whole cells: `width / 8` columns and `height / 16` rows.
    pub const fn cells(&self) -> (u32, u32) {
        (self.width / CELL_WIDTH, self.height / CELL_HEIGHT)
    }
}

/// Checks that `untyped` are device memory tiling `[start, end)` in order,
/// each aligned to its size.
fn tile(start: u64, end: u64, untyped: &[Untyped]) -> Result<(), Unusable> {
    let mut at = start;
    for (index, u) in untyped.iter().enumerate() {
        let next = at.checked_add(u.size());
        let fits = u.device
            && u.size_bits >= PAGE_BITS as u8
            && u.size_bits < 64
            && u.paddr == at
            && u.paddr.is_multiple_of(u.size())
            && next.is_some_and(|n| n <= end);
        match next {
            Some(n) if fits => at = n,
            _ => {
                return Err(Unusable::Untyped {
                    index,
                    count: untyped.len(),
                    expected: at,
                });
            }
        }
    }
    if at == end {
        Ok(())
    } else {
        Err(Unusable::Untyped {
            index: untyped.len(),
            count: untyped.len(),
            expected: at,
        })
    }
}
