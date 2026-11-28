//! Device windows and shared memory (`docs/design.md`, "Where the network
//! servers run", "Memory access").
//!
//! A window that a device, the host or another VSpace writes is reached
//! only through this module, never through a Rust reference, since its
//! contents may change at any time:
//!
//! - [`Mmio`] is a device's registers, mapped `Uncached`: volatile 8-, 16-
//!   and 32-bit accesses, each a plain access of its width and never a
//!   locked instruction ([`Regs`]).
//! - [`Shared`] is RAM shared with a device, the host or another VSpace,
//!   mapped `WriteBack`: atomic loads, stores, swaps and ORs of 8 to 64
//!   bits with explicit orderings, fences, and volatile byte copies
//!   ([`Memory`]).
//!
//! Each checks every offset against its window and every atomic access's
//! alignment, and panics on one outside. Their constructors are `unsafe
//! fn`s, called only in root, which knows what it mapped where; the only
//! other `unsafe` is the accesses themselves.
//!
//! The drivers and the frame queues are generic over [`Regs`] and
//! [`Memory`]. On the host, [`Ram`], a heap allocation behind the same
//! [`Shared`] and [`Mmio`] code, implements both, so a driver's host tests
//! run its real code, under Miri too; a device model implements [`Regs`]
//! itself. [`Part`] narrows either to a sub-window, and [`copy`] moves
//! bytes between two windows.
//!
//! Both traits take `&self`: a window is a handle, and what it reaches may
//! change behind it. They are also implemented for `&T`, so a driver can
//! hold a borrowed window while a test keeps the model.

use core::fmt;
use core::ptr::NonNull;
use core::sync::atomic::{self, AtomicU8, AtomicU16, AtomicU32, AtomicU64, Ordering};

/// An access's width.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Width {
    Byte = 1,
    Word = 2,
    Dword = 4,
    Qword = 8,
}

impl Width {
    /// The bytes it covers.
    pub const fn bytes(self) -> usize {
        self as usize
    }

    /// The values it holds.
    pub const fn mask(self) -> u64 {
        match self {
            Width::Qword => u64::MAX,
            w => (1 << (8 * w.bytes())) - 1,
        }
    }
}

/// A device's registers: 8-, 16- and 32-bit reads and writes at byte
/// offsets in a window, each aligned to its width. An access outside the
/// window, or misaligned, panics.
pub trait Regs {
    /// The window's length in bytes.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    fn read8(&self, offset: usize) -> u8;
    fn read16(&self, offset: usize) -> u16;
    fn read32(&self, offset: usize) -> u32;
    fn write8(&self, offset: usize, value: u8);
    fn write16(&self, offset: usize, value: u16);
    fn write32(&self, offset: usize, value: u32);
}

/// RAM that others write too: atomic accesses with orderings and
/// volatile byte copies at byte offsets in a window. An access outside the
/// window, or an atomic one not aligned to its width, panics, as does an
/// ordering `core::sync::atomic` refuses (a `Release` load, an `Acquire`
/// store, a `Relaxed` fence).
///
/// Implementors provide the width-generic accesses; the typed ones
/// (`load32`, `swap64`, ...) are written over them. Values are
/// little-endian, as x86 stores them, and a narrower access returns its
/// value zero-extended and ignores the bits above its width.
pub trait Memory {
    /// The window's length in bytes.
    fn len(&self) -> usize;

    fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// An atomic load.
    fn load(&self, offset: usize, width: Width, order: Ordering) -> u64;
    /// An atomic store of `value`'s low `width` bytes.
    fn store(&self, offset: usize, width: Width, value: u64, order: Ordering);
    /// An atomic swap; returns the old value.
    fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64;
    /// An atomic OR of `bits`; returns the old value.
    fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64;
    /// Copies `out.len()` bytes from `offset` into `out`, a volatile read
    /// of each.
    fn read(&self, offset: usize, out: &mut [u8]);
    /// Copies `bytes` to `offset`, a volatile write of each.
    fn write(&self, offset: usize, bytes: &[u8]);

    /// A memory fence: `SeqCst` is a full fence (`mfence` or a locked
    /// instruction), as the SynIC's message slot and a virtio notify
    /// need.
    fn fence(&self, order: Ordering) {
        atomic::fence(order);
    }

    /// Writes `len` bytes of `byte` from `offset`.
    fn fill(&self, offset: usize, len: usize, byte: u8) {
        check(offset, len, self.len());
        let chunk = [byte; 64];
        let mut done = 0;
        while done < len {
            let n = (len - done).min(chunk.len());
            self.write(offset + done, &chunk[..n]);
            done += n;
        }
    }

    fn load8(&self, offset: usize, order: Ordering) -> u8 {
        self.load(offset, Width::Byte, order) as u8
    }
    fn load16(&self, offset: usize, order: Ordering) -> u16 {
        self.load(offset, Width::Word, order) as u16
    }
    fn load32(&self, offset: usize, order: Ordering) -> u32 {
        self.load(offset, Width::Dword, order) as u32
    }
    fn load64(&self, offset: usize, order: Ordering) -> u64 {
        self.load(offset, Width::Qword, order)
    }
    fn store8(&self, offset: usize, value: u8, order: Ordering) {
        self.store(offset, Width::Byte, value.into(), order)
    }
    fn store16(&self, offset: usize, value: u16, order: Ordering) {
        self.store(offset, Width::Word, value.into(), order)
    }
    fn store32(&self, offset: usize, value: u32, order: Ordering) {
        self.store(offset, Width::Dword, value.into(), order)
    }
    fn store64(&self, offset: usize, value: u64, order: Ordering) {
        self.store(offset, Width::Qword, value, order)
    }
    fn swap32(&self, offset: usize, value: u32, order: Ordering) -> u32 {
        self.swap(offset, Width::Dword, value.into(), order) as u32
    }
    fn swap64(&self, offset: usize, value: u64, order: Ordering) -> u64 {
        self.swap(offset, Width::Qword, value, order)
    }
    fn or32(&self, offset: usize, bits: u32, order: Ordering) -> u32 {
        self.or(offset, Width::Dword, bits.into(), order) as u32
    }
    fn or64(&self, offset: usize, bits: u64, order: Ordering) -> u64 {
        self.or(offset, Width::Qword, bits, order)
    }
}

impl<T: Regs + ?Sized> Regs for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn read8(&self, offset: usize) -> u8 {
        (**self).read8(offset)
    }
    fn read16(&self, offset: usize) -> u16 {
        (**self).read16(offset)
    }
    fn read32(&self, offset: usize) -> u32 {
        (**self).read32(offset)
    }
    fn write8(&self, offset: usize, value: u8) {
        (**self).write8(offset, value)
    }
    fn write16(&self, offset: usize, value: u16) {
        (**self).write16(offset, value)
    }
    fn write32(&self, offset: usize, value: u32) {
        (**self).write32(offset, value)
    }
}

impl<T: Memory + ?Sized> Memory for &T {
    fn len(&self) -> usize {
        (**self).len()
    }
    fn load(&self, offset: usize, width: Width, order: Ordering) -> u64 {
        (**self).load(offset, width, order)
    }
    fn store(&self, offset: usize, width: Width, value: u64, order: Ordering) {
        (**self).store(offset, width, value, order)
    }
    fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64 {
        (**self).swap(offset, width, value, order)
    }
    fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64 {
        (**self).or(offset, width, bits, order)
    }
    fn read(&self, offset: usize, out: &mut [u8]) {
        (**self).read(offset, out)
    }
    fn write(&self, offset: usize, bytes: &[u8]) {
        (**self).write(offset, bytes)
    }
    fn fence(&self, order: Ordering) {
        (**self).fence(order)
    }
}

/// Panics unless `offset..offset + len` lies in a window of `size` bytes.
#[track_caller]
fn check(offset: usize, len: usize, size: usize) {
    match offset.checked_add(len) {
        Some(end) if end <= size => {}
        _ => panic!("mem: {len} bytes at {offset:#x} outside a window of {size:#x}"),
    }
}

/// A window's base and length, and the checked address of an access.
#[derive(Clone, Copy, PartialEq, Eq)]
struct Window {
    base: NonNull<u8>,
    len: usize,
}

impl Window {
    #[track_caller]
    fn new(base: *mut u8, len: usize) -> Window {
        let Some(base) = NonNull::new(base) else {
            panic!("mem: a window at address 0");
        };
        assert!(
            (base.as_ptr() as usize).checked_add(len).is_some(),
            "mem: a window of {len:#x} bytes at {base:p} wraps"
        );
        Window { base, len }
    }

    #[track_caller]
    fn sub(self, offset: usize, len: usize) -> Window {
        check(offset, len, self.len);
        // SAFETY: `offset + len` is inside the window, so the result is
        // inside the allocation or mapping the window's constructor
        // vouched for.
        let base = unsafe { self.base.add(offset) };
        Window { base, len }
    }

    /// The address of `bytes` bytes at `offset`, aligned to `align`.
    #[track_caller]
    fn at(self, offset: usize, bytes: usize, align: usize) -> *mut u8 {
        check(offset, bytes, self.len);
        // SAFETY: `offset + bytes <= len`, so the address is inside the
        // window.
        let p = unsafe { self.base.as_ptr().add(offset) };
        assert!(
            (p as usize).is_multiple_of(align),
            "mem: a {bytes}-byte access at {offset:#x} ({p:p}) is misaligned"
        );
        p
    }
}

impl fmt::Debug for Window {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{:p}+{:#x}", self.base, self.len)
    }
}

/// A device's registers: a window of uncached device memory (or, on the
/// host, any memory) read and written with volatile accesses.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Mmio(Window);

// SAFETY: an `Mmio` names addresses, not memory a thread owns; moving it
// to another thread of the same VSpace leaves the mapping its
// constructor's caller vouched for as valid there.
unsafe impl Send for Mmio {}

impl Mmio {
    /// The registers at `base..base + len`.
    ///
    /// # Safety
    ///
    /// The range must be mapped readable and writable in this VSpace, and
    /// stay so as long as the `Mmio`, or any copy or sub-window of it, is
    /// used. Nothing may hold a Rust reference into it meanwhile: the
    /// device changes it behind the compiler's back, so it is reached only
    /// through this window's volatile accesses. Panics if `base` is null
    /// or the range wraps.
    #[track_caller]
    pub unsafe fn new(base: *mut u8, len: usize) -> Mmio {
        Mmio(Window::new(base, len))
    }

    pub fn len(&self) -> usize {
        self.0.len
    }

    pub fn is_empty(&self) -> bool {
        self.0.len == 0
    }

    /// The `len` bytes at `offset`, as a window of their own. Panics
    /// outside this one.
    #[track_caller]
    pub fn sub(&self, offset: usize, len: usize) -> Mmio {
        Mmio(self.0.sub(offset, len))
    }
}

impl Regs for Mmio {
    fn len(&self) -> usize {
        self.0.len
    }
    #[track_caller]
    fn read8(&self, offset: usize) -> u8 {
        let p = self.0.at(offset, 1, 1);
        // SAFETY: `at` checked that the byte is inside the window, which
        // `new`'s caller vouched is mapped and reached only volatilely.
        unsafe { p.read_volatile() }
    }
    #[track_caller]
    fn read16(&self, offset: usize) -> u16 {
        let p = self.0.at(offset, 2, 2).cast::<u16>();
        // SAFETY: as for `read8`; `at` checked the alignment.
        unsafe { p.read_volatile() }
    }
    #[track_caller]
    fn read32(&self, offset: usize) -> u32 {
        let p = self.0.at(offset, 4, 4).cast::<u32>();
        // SAFETY: as for `read16`.
        unsafe { p.read_volatile() }
    }
    #[track_caller]
    fn write8(&self, offset: usize, value: u8) {
        let p = self.0.at(offset, 1, 1);
        // SAFETY: as for `read8`; the window is writable.
        unsafe { p.write_volatile(value) }
    }
    #[track_caller]
    fn write16(&self, offset: usize, value: u16) {
        let p = self.0.at(offset, 2, 2).cast::<u16>();
        // SAFETY: as for `read16`; the window is writable.
        unsafe { p.write_volatile(value) }
    }
    #[track_caller]
    fn write32(&self, offset: usize, value: u32) {
        let p = self.0.at(offset, 4, 4).cast::<u32>();
        // SAFETY: as for `read32`; the window is writable.
        unsafe { p.write_volatile(value) }
    }
}

/// RAM shared with a device, the host or another VSpace: a window read and
/// written only with atomic accesses and volatile byte copies.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shared(Window);

// SAFETY: as for `Mmio`.
unsafe impl Send for Shared {}

impl Shared {
    /// The memory at `base..base + len`.
    ///
    /// # Safety
    ///
    /// The range must be mapped readable and writable in this VSpace, as
    /// ordinary write-back memory (atomic instructions on uncached memory
    /// are not what this window promises), and stay so as long as the
    /// `Shared`, or any copy or sub-window of it, is used. Nothing may
    /// hold a Rust reference into it meanwhile: others write it behind the
    /// compiler's back, so it is reached only through this window's atomic
    /// and volatile accesses. Panics if `base` is null or the range
    /// wraps.
    #[track_caller]
    pub unsafe fn new(base: *mut u8, len: usize) -> Shared {
        Shared(Window::new(base, len))
    }

    pub fn len(&self) -> usize {
        self.0.len
    }

    pub fn is_empty(&self) -> bool {
        self.0.len == 0
    }

    /// The `len` bytes at `offset`, as a window of their own. Panics
    /// outside this one.
    #[track_caller]
    pub fn sub(&self, offset: usize, len: usize) -> Shared {
        Shared(self.0.sub(offset, len))
    }
}

impl Memory for Shared {
    fn len(&self) -> usize {
        self.0.len
    }

    #[track_caller]
    fn load(&self, offset: usize, width: Width, order: Ordering) -> u64 {
        let p = self.0.at(offset, width.bytes(), width.bytes());
        // SAFETY: in each arm, `at` checked that the value lies in the
        // window and is aligned to its width, the alignment of the atomic
        // type; `new`'s caller vouched that the window is mapped and that
        // nothing reaches it but these atomic and volatile accesses.
        unsafe {
            match width {
                Width::Byte => AtomicU8::from_ptr(p).load(order).into(),
                Width::Word => AtomicU16::from_ptr(p.cast()).load(order).into(),
                Width::Dword => AtomicU32::from_ptr(p.cast()).load(order).into(),
                Width::Qword => AtomicU64::from_ptr(p.cast()).load(order),
            }
        }
    }

    #[track_caller]
    fn store(&self, offset: usize, width: Width, value: u64, order: Ordering) {
        let p = self.0.at(offset, width.bytes(), width.bytes());
        // SAFETY: as for `load`.
        unsafe {
            match width {
                Width::Byte => AtomicU8::from_ptr(p).store(value as u8, order),
                Width::Word => AtomicU16::from_ptr(p.cast()).store(value as u16, order),
                Width::Dword => AtomicU32::from_ptr(p.cast()).store(value as u32, order),
                Width::Qword => AtomicU64::from_ptr(p.cast()).store(value, order),
            }
        }
    }

    #[track_caller]
    fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64 {
        let p = self.0.at(offset, width.bytes(), width.bytes());
        // SAFETY: as for `load`.
        unsafe {
            match width {
                Width::Byte => AtomicU8::from_ptr(p).swap(value as u8, order).into(),
                Width::Word => AtomicU16::from_ptr(p.cast())
                    .swap(value as u16, order)
                    .into(),
                Width::Dword => AtomicU32::from_ptr(p.cast())
                    .swap(value as u32, order)
                    .into(),
                Width::Qword => AtomicU64::from_ptr(p.cast()).swap(value, order),
            }
        }
    }

    #[track_caller]
    fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64 {
        let p = self.0.at(offset, width.bytes(), width.bytes());
        // SAFETY: as for `load`.
        unsafe {
            match width {
                Width::Byte => AtomicU8::from_ptr(p).fetch_or(bits as u8, order).into(),
                Width::Word => AtomicU16::from_ptr(p.cast())
                    .fetch_or(bits as u16, order)
                    .into(),
                Width::Dword => AtomicU32::from_ptr(p.cast())
                    .fetch_or(bits as u32, order)
                    .into(),
                Width::Qword => AtomicU64::from_ptr(p.cast()).fetch_or(bits, order),
            }
        }
    }

    #[track_caller]
    fn read(&self, offset: usize, out: &mut [u8]) {
        let p = self.0.at(offset, out.len(), 1);
        for (i, b) in out.iter_mut().enumerate() {
            // SAFETY: `at` checked that all `out.len()` bytes are in the
            // window, which `new`'s caller vouched is mapped.
            *b = unsafe { p.add(i).read_volatile() };
        }
    }

    #[track_caller]
    fn write(&self, offset: usize, bytes: &[u8]) {
        let p = self.0.at(offset, bytes.len(), 1);
        for (i, &b) in bytes.iter().enumerate() {
            // SAFETY: as for `read`; the window is writable.
            unsafe { p.add(i).write_volatile(b) };
        }
    }
}

/// The `len` bytes at `offset` of another window, as a window of their
/// own: offsets are relative to `offset`, and checked against `len` before
/// the inner window checks its own.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Part<M> {
    inner: M,
    offset: usize,
    len: usize,
}

impl<M> Part<M> {
    /// `len` bytes of the memory `inner` from `offset`. Panics outside it.
    #[track_caller]
    pub fn memory(inner: M, offset: usize, len: usize) -> Part<M>
    where
        M: Memory,
    {
        check(offset, len, inner.len());
        Part { inner, offset, len }
    }

    /// `len` bytes of the registers `inner` from `offset`. Panics outside
    /// them.
    #[track_caller]
    pub fn regs(inner: M, offset: usize, len: usize) -> Part<M>
    where
        M: Regs,
    {
        check(offset, len, inner.len());
        Part { inner, offset, len }
    }

    pub fn len(&self) -> usize {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// Where it starts in the inner window.
    pub fn offset(&self) -> usize {
        self.offset
    }

    /// The inner window.
    pub fn inner(&self) -> &M {
        &self.inner
    }

    #[track_caller]
    fn at(&self, offset: usize, bytes: usize) -> usize {
        check(offset, bytes, self.len);
        self.offset + offset
    }
}

impl<M: Regs> Regs for Part<M> {
    fn len(&self) -> usize {
        self.len
    }
    #[track_caller]
    fn read8(&self, offset: usize) -> u8 {
        self.inner.read8(self.at(offset, 1))
    }
    #[track_caller]
    fn read16(&self, offset: usize) -> u16 {
        self.inner.read16(self.at(offset, 2))
    }
    #[track_caller]
    fn read32(&self, offset: usize) -> u32 {
        self.inner.read32(self.at(offset, 4))
    }
    #[track_caller]
    fn write8(&self, offset: usize, value: u8) {
        self.inner.write8(self.at(offset, 1), value)
    }
    #[track_caller]
    fn write16(&self, offset: usize, value: u16) {
        self.inner.write16(self.at(offset, 2), value)
    }
    #[track_caller]
    fn write32(&self, offset: usize, value: u32) {
        self.inner.write32(self.at(offset, 4), value)
    }
}

impl<M: Memory> Memory for Part<M> {
    fn len(&self) -> usize {
        self.len
    }
    #[track_caller]
    fn load(&self, offset: usize, width: Width, order: Ordering) -> u64 {
        self.inner
            .load(self.at(offset, width.bytes()), width, order)
    }
    #[track_caller]
    fn store(&self, offset: usize, width: Width, value: u64, order: Ordering) {
        self.inner
            .store(self.at(offset, width.bytes()), width, value, order)
    }
    #[track_caller]
    fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64 {
        self.inner
            .swap(self.at(offset, width.bytes()), width, value, order)
    }
    #[track_caller]
    fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64 {
        self.inner
            .or(self.at(offset, width.bytes()), width, bits, order)
    }
    #[track_caller]
    fn read(&self, offset: usize, out: &mut [u8]) {
        self.inner.read(self.at(offset, out.len()), out)
    }
    #[track_caller]
    fn write(&self, offset: usize, bytes: &[u8]) {
        self.inner.write(self.at(offset, bytes.len()), bytes)
    }
    fn fence(&self, order: Ordering) {
        self.inner.fence(order)
    }
}

/// Copies `len` bytes from `src` at `src_offset` to `dst` at `dst_offset`,
/// through a buffer on the stack, in order. Panics, before copying
/// anything, if either range leaves its window.
#[track_caller]
pub fn copy(
    src: &impl Memory,
    src_offset: usize,
    dst: &impl Memory,
    dst_offset: usize,
    len: usize,
) {
    check(src_offset, len, src.len());
    check(dst_offset, len, dst.len());
    let mut chunk = [0u8; 256];
    let mut done = 0;
    while done < len {
        let n = (len - done).min(chunk.len());
        src.read(src_offset + done, &mut chunk[..n]);
        dst.write(dst_offset + done, &chunk[..n]);
        done += n;
    }
}

#[cfg(not(target_os = "none"))]
pub use host::Ram;

/// The host's window: a heap allocation behind the target's own code.
#[cfg(not(target_os = "none"))]
mod host {
    extern crate alloc;

    use alloc::boxed::Box;
    use alloc::vec;
    use alloc::vec::Vec;
    use core::fmt;
    use core::ptr::NonNull;
    use core::sync::atomic::Ordering;

    use super::{Memory, Mmio, Regs, Shared, Width};

    /// Zeroed memory on the heap, 8-byte aligned, for host tests: as a
    /// [`Memory`] it is a [`Shared`] window over the allocation, as
    /// [`Regs`] an [`Mmio`] one, so a test runs the target's accesses. It
    /// is `Send` but not `Sync`, since its volatile byte copies are not
    /// atomic: share it within a thread by reference.
    pub struct Ram {
        words: NonNull<u64>,
        n_words: usize,
        len: usize,
    }

    // SAFETY: `Ram` owns its allocation, and nothing else points into it
    // but the windows its methods make for one call.
    unsafe impl Send for Ram {}

    impl Ram {
        /// `len` zeroed bytes.
        pub fn new(len: usize) -> Ram {
            let n_words = len.div_ceil(8).max(1);
            let words: Box<[u64]> = vec![0u64; n_words].into_boxed_slice();
            let words =
                NonNull::new(Box::into_raw(words).cast::<u64>()).expect("a Box is not null");
            Ram {
                words,
                n_words,
                len,
            }
        }

        /// A copy of `bytes`.
        pub fn from_bytes(bytes: &[u8]) -> Ram {
            let ram = Ram::new(bytes.len());
            ram.write(0, bytes);
            ram
        }

        pub fn len(&self) -> usize {
            self.len
        }

        pub fn is_empty(&self) -> bool {
            self.len == 0
        }

        /// Its bytes.
        pub fn to_vec(&self) -> Vec<u8> {
            let mut v = vec![0; self.len];
            self.read(0, &mut v);
            v
        }

        fn base(&self) -> *mut u8 {
            self.words.as_ptr().cast()
        }

        fn shared(&self) -> Shared {
            // SAFETY: the allocation holds at least `len` bytes, is ours
            // until `drop`, which needs `&mut self` and so cannot run
            // while this window is used, and no reference into it is ever
            // made.
            unsafe { Shared::new(self.base(), self.len) }
        }

        fn mmio(&self) -> Mmio {
            // SAFETY: as for `shared`.
            unsafe { Mmio::new(self.base(), self.len) }
        }
    }

    impl Drop for Ram {
        fn drop(&mut self) {
            let words = core::ptr::slice_from_raw_parts_mut(self.words.as_ptr(), self.n_words);
            // SAFETY: `words` came from `Box::into_raw` of a slice of
            // `n_words` words in `new`, and is freed only here.
            drop(unsafe { Box::from_raw(words) });
        }
    }

    impl Clone for Ram {
        fn clone(&self) -> Ram {
            Ram::from_bytes(&self.to_vec())
        }
    }

    impl fmt::Debug for Ram {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            write!(f, "Ram({:#x} bytes)", self.len)
        }
    }

    impl Memory for Ram {
        fn len(&self) -> usize {
            self.len
        }
        #[track_caller]
        fn load(&self, offset: usize, width: Width, order: Ordering) -> u64 {
            self.shared().load(offset, width, order)
        }
        #[track_caller]
        fn store(&self, offset: usize, width: Width, value: u64, order: Ordering) {
            self.shared().store(offset, width, value, order)
        }
        #[track_caller]
        fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64 {
            self.shared().swap(offset, width, value, order)
        }
        #[track_caller]
        fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64 {
            self.shared().or(offset, width, bits, order)
        }
        #[track_caller]
        fn read(&self, offset: usize, out: &mut [u8]) {
            self.shared().read(offset, out)
        }
        #[track_caller]
        fn write(&self, offset: usize, bytes: &[u8]) {
            self.shared().write(offset, bytes)
        }
    }

    impl Regs for Ram {
        fn len(&self) -> usize {
            self.len
        }
        #[track_caller]
        fn read8(&self, offset: usize) -> u8 {
            self.mmio().read8(offset)
        }
        #[track_caller]
        fn read16(&self, offset: usize) -> u16 {
            self.mmio().read16(offset)
        }
        #[track_caller]
        fn read32(&self, offset: usize) -> u32 {
            self.mmio().read32(offset)
        }
        #[track_caller]
        fn write8(&self, offset: usize, value: u8) {
            self.mmio().write8(offset, value)
        }
        #[track_caller]
        fn write16(&self, offset: usize, value: u16) {
            self.mmio().write16(offset, value)
        }
        #[track_caller]
        fn write32(&self, offset: usize, value: u32) {
            self.mmio().write32(offset, value)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use core::sync::atomic::Ordering::{AcqRel, Acquire, Relaxed, Release, SeqCst};
    use std::panic::{AssertUnwindSafe, catch_unwind};
    use std::string::{String, ToString};
    use std::vec::Vec;

    /// The panic message of `f`, which must panic.
    fn panics(f: impl FnOnce()) -> String {
        let e = catch_unwind(AssertUnwindSafe(f)).expect_err("no panic");
        e.downcast_ref::<String>()
            .cloned()
            .or_else(|| e.downcast_ref::<&str>().map(|s| s.to_string()))
            .unwrap_or_default()
    }

    /// Evaluating `$e` panics with a message that contains `$msg`.
    macro_rules! assert_panics {
        ($e:expr, $msg:expr) => {{
            let m = panics(|| {
                let _ = $e;
            });
            assert!(m.contains($msg), "{m:?} does not contain {:?}", $msg);
        }};
    }

    #[test]
    fn widths() {
        assert_eq!(
            [Width::Byte, Width::Word, Width::Dword, Width::Qword].map(Width::bytes),
            [1, 2, 4, 8]
        );
        assert_eq!(Width::Byte.mask(), 0xFF);
        assert_eq!(Width::Dword.mask(), 0xFFFF_FFFF);
        assert_eq!(Width::Qword.mask(), u64::MAX);
    }

    #[test]
    fn ram_starts_zeroed_and_reads_back_little_endian() {
        let ram = Ram::new(100);
        assert_eq!(ram.len(), 100);
        assert!(ram.to_vec().iter().all(|&b| b == 0));
        ram.store64(8, 0x0807_0605_0403_0201, Relaxed);
        assert_eq!(&ram.to_vec()[8..16], &[1, 2, 3, 4, 5, 6, 7, 8]);
        assert_eq!(ram.load8(9, Relaxed), 2);
        assert_eq!(ram.load16(10, Acquire), 0x0403);
        assert_eq!(ram.load32(12, SeqCst), 0x0807_0605);
        assert_eq!(ram.load64(8, Acquire), 0x0807_0605_0403_0201);
        ram.store8(9, 0xAA, Release);
        ram.store16(10, 0xBBCC, Relaxed);
        ram.store32(12, 0xDDEE_FF00, SeqCst);
        assert_eq!(ram.load64(8, Relaxed), 0xDDEE_FF00_BBCC_AA01);
        // A narrow store ignores the bits above its width.
        ram.store(0, Width::Byte, 0x1234, Relaxed);
        assert_eq!(ram.load16(0, Relaxed), 0x34);
        assert!(Ram::new(0).is_empty());
    }

    #[test]
    fn swaps_and_ors_return_the_old_value() {
        let ram = Ram::new(64);
        ram.store64(0, 0xF0, Relaxed);
        assert_eq!(ram.swap64(0, 7, AcqRel), 0xF0);
        assert_eq!(ram.or64(0, 1 << 63, AcqRel), 7);
        assert_eq!(ram.load64(0, Relaxed), 7 | 1 << 63);
        assert_eq!(ram.swap32(8, 5, SeqCst), 0);
        assert_eq!(ram.or32(8, 0x30, Relaxed), 5);
        assert_eq!(ram.load32(8, Relaxed), 0x35);
        assert_eq!(ram.swap(16, Width::Byte, 0x1FF, Relaxed), 0);
        assert_eq!(ram.or(16, Width::Word, 0x100, Relaxed), 0xFF);
        assert_eq!(ram.load16(16, Relaxed), 0x1FF);
        ram.fence(SeqCst);
        ram.fence(Acquire);
    }

    #[test]
    fn byte_copies_and_fills() {
        let ram = Ram::new(300);
        ram.write(3, b"hello");
        let mut out = [0; 7];
        ram.read(2, &mut out);
        assert_eq!(&out, b"\0hello\0");
        ram.fill(10, 290, 0x5A);
        assert!(ram.to_vec()[10..].iter().all(|&b| b == 0x5A));
        ram.fill(300, 0, 1);
        ram.write(300, &[]);
        let other = Ram::from_bytes(&[9; 400]);
        copy(&ram, 3, &other, 395, 5);
        assert_eq!(&other.to_vec()[393..], b"\x09\x09hello");
        // A long copy goes in chunks and in order.
        let bytes: Vec<u8> = (0..1000u32).map(|i| (i * 7) as u8).collect();
        let big = Ram::from_bytes(&bytes);
        let dst = Ram::new(1000);
        copy(&big, 0, &dst, 0, 1000);
        assert_eq!(dst.to_vec(), bytes);
        assert_eq!(big.clone().to_vec(), bytes);
    }

    #[test]
    fn every_access_is_checked_against_its_window() {
        let ram = Ram::new(16);
        assert_panics!(ram.load32(16, Relaxed), "outside a window of 0x10");
        assert_panics!(ram.store64(9, 0, Relaxed), "outside");
        assert_panics!(ram.load8(usize::MAX, Relaxed), "outside");
        assert_panics!(ram.write(15, b"ab"), "outside");
        assert_panics!(ram.read(17, &mut []), "outside");
        assert_panics!(ram.fill(8, 9, 0), "outside");
        assert_panics!(Regs::write32(&ram, 13, 0), "outside");
        assert_panics!(Regs::read16(&ram, 15), "outside");
        let dst = Ram::new(4);
        assert_panics!(copy(&ram, 0, &dst, 1, 4), "outside");
        assert_panics!(copy(&ram, 13, &dst, 0, 4), "outside");
        // Nothing was copied before the check failed.
        assert_eq!(dst.to_vec(), [0; 4]);
        // The last value in the window is fine.
        ram.store64(8, 1, Relaxed);
        Regs::write8(&ram, 15, 2);
    }

    #[test]
    fn atomic_and_register_accesses_must_be_aligned() {
        let ram = Ram::new(64);
        assert_panics!(ram.load32(2, Relaxed), "misaligned");
        assert_panics!(ram.swap64(4, 0, Relaxed), "misaligned");
        assert_panics!(ram.or(1, Width::Word, 0, Relaxed), "misaligned");
        assert_panics!(Regs::read32(&ram, 6), "misaligned");
        assert_panics!(Regs::write16(&ram, 3, 0), "misaligned");
        // Bytes and byte copies go anywhere.
        ram.store8(3, 1, Relaxed);
        ram.write(5, &[1, 2, 3]);
        // A sub-window's accesses are aligned by their address.
        let p = Part::memory(&ram, 4, 16);
        p.store32(0, 0xABCD, Relaxed);
        assert_eq!(ram.load32(4, Relaxed), 0xABCD);
        assert_panics!(p.store64(0, 0, Relaxed), "misaligned");
    }

    #[test]
    fn orderings_core_refuses_still_panic() {
        let ram = Ram::new(8);
        assert_panics!(ram.load32(0, Release), "");
        assert_panics!(ram.store32(0, 0, Acquire), "");
        assert_panics!(ram.fence(Relaxed), "");
    }

    #[test]
    fn registers_are_read_and_written_at_their_width() {
        let ram = Ram::new(32);
        Regs::write32(&ram, 0, 0x4433_2211);
        Regs::write16(&ram, 4, 0x6655);
        Regs::write8(&ram, 6, 0x77);
        assert_eq!(Regs::read8(&ram, 1), 0x22);
        assert_eq!(Regs::read16(&ram, 2), 0x4433);
        assert_eq!(Regs::read32(&ram, 4), 0x0077_6655);
        assert_eq!(Regs::len(&ram), 32);
        // The same memory through both traits.
        assert_eq!(ram.load64(0, Relaxed), 0x0077_6655_4433_2211);
    }

    #[test]
    fn parts_translate_and_check_offsets() {
        let ram = Ram::new(64);
        let p = Part::memory(&ram, 16, 8);
        assert_eq!((p.len(), p.offset(), p.is_empty()), (8, 16, false));
        p.store64(0, u64::MAX, Relaxed);
        assert_eq!(ram.load64(16, Relaxed), u64::MAX);
        assert_eq!(ram.load64(8, Relaxed), 0);
        assert_eq!(ram.load64(24, Relaxed), 0);
        p.write(6, b"xy");
        assert_eq!(&ram.to_vec()[22..24], b"xy");
        assert_panics!(p.write(7, b"xy"), "outside a window of 0x8");
        assert_panics!(p.load8(8, Relaxed), "outside");
        // A part of a part.
        let q = Part::memory(&p, 4, 4);
        q.store32(0, 5, Relaxed);
        assert_eq!(ram.load32(20, Relaxed), 5);
        assert_panics!(Part::memory(&ram, 60, 8), "outside");
        assert_panics!(Part::memory(&p, 1, 8), "outside");
        let r = Part::regs(&ram, 32, 4);
        r.write16(2, 0xBEEF);
        assert_eq!(ram.load16(34, Relaxed), 0xBEEF);
        assert_eq!(r.read32(0), 0xBEEF_0000);
        assert_panics!(r.read32(4), "outside");
        assert_panics!(Part::regs(&ram, 62, 4), "outside");
    }

    #[test]
    fn windows_over_raw_memory_and_their_sub_windows() {
        let mut backing = [0u64; 8];
        let base = backing.as_mut_ptr().cast::<u8>();
        // SAFETY: `backing` outlives both windows and is not touched
        // through a reference while they are used.
        let (shared, mmio) = unsafe { (Shared::new(base, 64), Mmio::new(base, 64)) };
        assert_eq!((shared.len(), mmio.len()), (64, 64));
        let s = shared.sub(8, 16);
        s.store32(4, 0x1234_5678, Release);
        assert_eq!(mmio.read32(12), 0x1234_5678);
        let m = mmio.sub(32, 32);
        m.write8(31, 0xEE);
        assert_eq!(shared.load8(63, Acquire), 0xEE);
        assert_panics!(s.sub(8, 9), "outside");
        assert_panics!(m.read8(32), "outside");
        assert!(!s.is_empty() && mmio.sub(64, 0).is_empty());
        let null = core::ptr::null_mut();
        // SAFETY: the constructor refuses the address before any access.
        assert_panics!(unsafe { Shared::new(null, 1) }, "address 0");
        // A window may not wrap the address space.
        let top = core::ptr::without_provenance_mut::<u8>(usize::MAX - 3);
        // SAFETY: as above: the constructor refuses it.
        assert_panics!(unsafe { Mmio::new(top, 8) }, "wraps");
    }
}
