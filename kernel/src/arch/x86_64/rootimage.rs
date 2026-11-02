//! `.rootimage`: the root task's ELF file, embedded in the kernel image
//! (`docs/design.md`, "Root-task image and address space").
//!
//! `cargo xtask build` builds `user/root`, strips and checks it, and passes
//! its path in `MICROL4_ROOT_IMAGE`; `include_bytes!` puts the file in the
//! `.rootimage` section, which `kernel/linker.ld` makes a read-only PT_LOAD
//! segment of its own between `__rootimage_start` and `__rootimage_end`,
//! page-aligned at both ends, at the end of the range the kernel maps as
//! rodata.
//!
//! [`take_rootimage`] hands the section out once. Boot step 8 is to read
//! the file through it and then unmap the section with a function that
//! consumes the [`RootImageSection`], so that no borrow of its bytes
//! outlives the mapping.

use core::ops::Range;
use core::sync::atomic::{AtomicBool, Ordering};

use l4core::handoff::KERNEL_VIRT_BASE;
use l4core::vspace::Span;

macro_rules! root_image_path {
    () => {
        env!(
            "MICROL4_ROOT_IMAGE",
            "the kernel embeds the root task's ELF from $MICROL4_ROOT_IMAGE: build it with `cargo xtask build`"
        )
    };
}

/// The file's length, without the section's padding.
const ROOT_IMAGE_LEN: usize = include_bytes!(root_image_path!()).len();

/// The file, as xtask packed it.
///
/// Nothing may read this static, by name or through any reference, after
/// boot step 8: [`RootImageSection::unmap`] then takes its pages out of the
/// kernel window and hands them to the root task as RAM untyped, though it
/// stays a Rust static over them. Its only reader is
/// [`RootImageSection::bytes`], whose borrow ends before that unmap. It is
/// named here only so `#[used]` keeps it in `.rootimage`.
#[used]
#[unsafe(link_section = ".rootimage")]
static ROOT_IMAGE: [u8; ROOT_IMAGE_LEN] = *include_bytes!(root_image_path!());

/// The address the linker gave `$sym`, from `lea`. Taken as the address of
/// a Rust `extern` static, two symbols would be two distinct objects to the
/// compiler, which could then fold a comparison of their addresses.
macro_rules! linker_addr {
    ($sym:literal) => {{
        let addr: u64;
        // SAFETY: `lea` only computes the address the linker gave `$sym`;
        // nothing is read.
        unsafe {
            core::arch::asm!(
                concat!("lea {}, [rip + ", $sym, "]"),
                out(reg) addr,
                options(pure, nomem, nostack, preserves_flags)
            )
        };
        addr
    }};
}

/// `.rootimage` while it is mapped: the only way to its bytes.
pub struct RootImageSection {
    _private: (),
}

static TAKEN: AtomicBool = AtomicBool::new(false);

/// The section, once; panics on a second call.
pub fn take_rootimage() -> RootImageSection {
    assert!(
        !TAKEN.swap(true, Ordering::Relaxed),
        ".rootimage was already taken"
    );
    RootImageSection { _private: () }
}

impl RootImageSection {
    /// `[__rootimage_start, __rootimage_end)`: the file, then zeros to the
    /// next page.
    pub fn virt(&self) -> Range<u64> {
        linker_addr!("__rootimage_start")..linker_addr!("__rootimage_end")
    }

    /// The section's physical pages, for the boot plan's `rootimage`: the
    /// kernel image is contiguous from `kernel_phys_base` at
    /// `KERNEL_VIRT_BASE`.
    pub fn phys(&self, kernel_phys_base: u64) -> Span {
        let v = self.virt();
        Span {
            start: v.start - KERNEL_VIRT_BASE + kernel_phys_base,
            end: v.end - KERNEL_VIRT_BASE + kernel_phys_base,
        }
    }

    /// The section's bytes, found through the linker's symbols: the file,
    /// then zeros to the page boundary.
    pub fn bytes(&self) -> &[u8] {
        let v = self.virt();
        // SAFETY: the linker script puts `.rootimage` between the two
        // symbols, in a loaded segment the kernel's tables map read-only
        // and nothing writes. It stays mapped while this
        // `RootImageSection` lives, which the borrow ties the slice to:
        // unmapping it consumes the section.
        unsafe { core::slice::from_raw_parts(v.start as *const u8, (v.end - v.start) as usize) }
    }

    /// Boot step 8's end: unmaps the section from the kernel window and
    /// toggles CR4.PGE, so its pages can become RAM untyped; consuming the
    /// section ends every borrow of its bytes first. Returns its physical
    /// range, which the kernel's object-memory checks now accept.
    pub fn unmap(self, kernel_phys_base: u64) -> Span {
        let phys = self.phys(kernel_phys_base);
        super::paging::unmap_rootimage(self.virt(), phys.start..phys.end);
        super::objects::reclaim(phys.start..phys.end);
        phys
    }
}
