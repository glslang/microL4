//! The program's own segments, as `user/link.ld` placed them: the bounds
//! its symbols export, for a program that maps its image into another
//! VSpace (`docs/design.md`, "Where the servers run"). Only on the user
//! target, where the program is linked with that script.

/// The page-aligned bounds of the image's segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Segments {
    /// Text runs from the image's start to here.
    pub rodata_start: u64,
    /// Read-only data runs from `rodata_start` to here.
    pub data_start: u64,
    /// `.data` and `.bss` run from `data_start` to here, rounded up to a
    /// page.
    pub data_end: u64,
    /// The 64 KiB `_start` stack runs from here to the image's end.
    pub libsys_stack_start: u64,
}

unsafe extern "C" {
    safe static __rodata_start: u8;
    safe static __data_start: u8;
    safe static __data_end: u8;
    safe static __libsys_stack_start: u8;
}

/// The bounds `user/link.ld` exported for this program.
pub fn segments() -> Segments {
    // Only the symbols' addresses: raw pointers, never references, since
    // `__data_end` may lie on an unmapped guard page.
    Segments {
        rodata_start: (&raw const __rodata_start) as u64,
        data_start: (&raw const __data_start) as u64,
        data_end: ((&raw const __data_end) as u64).next_multiple_of(0x1000),
        libsys_stack_start: (&raw const __libsys_stack_start) as u64,
    }
}
