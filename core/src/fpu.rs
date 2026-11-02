//! x87 and SSE state, the host-testable part (`docs/design.md`, "FP and
//! SIMD"; ADR 0014; `docs/abi.md`, "Initial FP state").
//!
//! The kernel enables x87 and SSE only, XCR0 = [`XCR0`], and switches the
//! state with XSAVE64 and XRSTOR64 in the standard (non-compacted) format,
//! into each TCB's 1024-byte reserve at [`crate::tcb::XSAVE_OFFSET`]. A new
//! thread's area is [`initial_state`], built from constants, so the kernel
//! runs no x87 or SSE instruction to make it. [`check_cpuid`] is the boot
//! check of CPUID leaf `0xD`.

use core::fmt;

use crate::tcb;

/// XCR0's x87 bit, state component 0.
pub const XCR0_X87: u64 = 1 << 0;
/// XCR0's SSE bit, state component 1: the XMM registers and MXCSR.
pub const XCR0_SSE: u64 = 1 << 1;
/// What the kernel writes to XCR0: x87 and SSE, every other component off.
pub const XCR0: u64 = XCR0_X87 | XCR0_SSE;

/// Bytes XSAVE uses for x87 and SSE: the 512-byte legacy region and the
/// 64-byte header.
pub const AREA_SIZE: usize = 576;

/// Offsets in the standard-format area (SDM vol. 1, 10.5.1 and 13.4).
pub mod offset {
    /// The x87 control word, 16 bits.
    pub const FCW: usize = 0;
    /// The x87 status word, 16 bits; TOP is bits 11 to 13.
    pub const FSW: usize = 2;
    /// The abridged x87 tag word, 8 bits: bit i is set when physical
    /// register i is valid.
    pub const FTW: usize = 4;
    /// The last x87 opcode, 16 bits.
    pub const FOP: usize = 6;
    /// The last x87 instruction pointer, 64 bits with XSAVE64.
    pub const FIP: usize = 8;
    /// The last x87 data pointer, 64 bits with XSAVE64.
    pub const FDP: usize = 16;
    /// MXCSR, 32 bits.
    pub const MXCSR: usize = 24;
    /// MXCSR_MASK, 32 bits; written by XSAVE, ignored by XRSTOR.
    pub const MXCSR_MASK: usize = 28;
    /// ST0, or MM0, in 16 bytes; ST1 to ST7 follow, each 16 bytes.
    pub const ST0: usize = 32;
    /// XMM0, 16 bytes; XMM1 to XMM15 follow.
    pub const XMM0: usize = 160;
    /// The XSAVE header: XSTATE_BV, 64 bits.
    pub const XSTATE_BV: usize = 512;
    /// XCOMP_BV, 64 bits; 0 for the standard format.
    pub const XCOMP_BV: usize = 520;
}

/// FCW for a new thread: every x87 exception masked, 64-bit precision,
/// round to nearest.
pub const FCW_INIT: u16 = 0x037F;
/// MXCSR for a new thread: every SIMD exception masked, round to nearest,
/// no flush-to-zero, no denormals-are-zero.
pub const MXCSR_INIT: u32 = 0x1F80;

/// The x87 register `i` in the area: ST(i) relative to the stack top is
/// physical register `(TOP + i) % 8`, but the area stores them in stack
/// order, ST0 first.
pub const fn st(i: usize) -> usize {
    offset::ST0 + 16 * i
}

/// XMM register `i` in the area.
pub const fn xmm(i: usize) -> usize {
    offset::XMM0 + 16 * i
}

const _: () = assert!(AREA_SIZE as u64 <= tcb::XSAVE_SIZE);
const _: () = assert!(st(8) == offset::XMM0);
const _: () = assert!(xmm(16) <= offset::XSTATE_BV);
const _: () = assert!(tcb::XSAVE_OFFSET.is_multiple_of(64));

/// The initial state of a new thread (`docs/abi.md`, "Initial FP state"):
/// FCW `0x037F`, FSW 0, every x87 register empty (abridged FTW 0), MXCSR
/// `0x1F80`, every register 0, XSTATE_BV `0x3` and the rest of the header
/// 0, which XRSTOR64 accepts with XCR0 = `0x3`.
pub const fn initial_state() -> [u8; AREA_SIZE] {
    let mut a = [0u8; AREA_SIZE];
    let fcw = FCW_INIT.to_le_bytes();
    a[offset::FCW] = fcw[0];
    a[offset::FCW + 1] = fcw[1];
    let mxcsr = MXCSR_INIT.to_le_bytes();
    let mut i = 0;
    while i < 4 {
        a[offset::MXCSR + i] = mxcsr[i];
        i += 1;
    }
    a[offset::XSTATE_BV] = XCR0 as u8;
    a
}

/// Reads the little-endian `N`-byte field at `at` of an area.
pub fn field<const N: usize>(area: &[u8], at: usize) -> [u8; N] {
    let mut v = [0; N];
    v.copy_from_slice(&area[at..at + N]);
    v
}

/// A 16-bit field of an area.
pub fn u16_at(area: &[u8], at: usize) -> u16 {
    u16::from_le_bytes(field(area, at))
}

/// A 32-bit field of an area.
pub fn u32_at(area: &[u8], at: usize) -> u32 {
    u32::from_le_bytes(field(area, at))
}

/// A 64-bit field of an area.
pub fn u64_at(area: &[u8], at: usize) -> u64 {
    u64::from_le_bytes(field(area, at))
}

/// Why the CPU's XSAVE support cannot hold the kernel's state.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum XsaveError {
    /// CPUID.(EAX=0xD, ECX=0) EDX:EAX lacks x87 or SSE.
    Unsupported { supported: u64 },
    /// CPUID.(EAX=0xD, ECX=0).EBX, with XCR0 = `0x3`, is not between the
    /// 576 bytes x87 and SSE take and the TCB's 1024-byte reserve.
    Size { size: u32 },
}

impl fmt::Display for XsaveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            XsaveError::Unsupported { supported } => write!(
                f,
                "XSAVE supports components {supported:#x}, without both x87 and SSE ({XCR0:#x})"
            ),
            XsaveError::Size { size } => write!(
                f,
                "the XSAVE area for XCR0 {XCR0:#x} is {size} bytes, not {AREA_SIZE} to {} (the TCB's reserve)",
                tcb::XSAVE_SIZE
            ),
        }
    }
}

/// Before XSETBV: whether the components CPUID.(EAX=0xD, ECX=0) reports in
/// EDX:EAX include x87 and SSE (seL4 `Arch_initFpu`).
pub const fn check_supported(supported: u64) -> Result<(), XsaveError> {
    if supported & XCR0 == XCR0 {
        Ok(())
    } else {
        Err(XsaveError::Unsupported { supported })
    }
}

/// After XSETBV with [`XCR0`]: whether the area CPUID.(EAX=0xD, ECX=0).EBX
/// reports for it fits the TCB's reserve. It is 576 for x87 and SSE.
pub const fn check_size(size: u32) -> Result<(), XsaveError> {
    if size as usize >= AREA_SIZE && size as u64 <= tcb::XSAVE_SIZE {
        Ok(())
    } else {
        Err(XsaveError::Size { size })
    }
}

/// Both checks of CPUID leaf `0xD`, for one CPU: the components it
/// supports, read before XSETBV, and the area size read after.
pub const fn check_cpuid(supported: u64, size: u32) -> Result<(), XsaveError> {
    match check_supported(supported) {
        Ok(()) => check_size(size),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    #[test]
    fn the_template_is_the_abi_initial_state() {
        let a = initial_state();
        assert_eq!(u16_at(&a, offset::FCW), 0x037F);
        assert_eq!(u16_at(&a, offset::FSW), 0);
        assert_eq!(a[offset::FTW], 0, "every x87 register empty");
        assert_eq!(u16_at(&a, offset::FOP), 0);
        assert_eq!(u64_at(&a, offset::FIP), 0);
        assert_eq!(u64_at(&a, offset::FDP), 0);
        assert_eq!(u32_at(&a, offset::MXCSR), 0x1F80);
        for i in 0..8 {
            assert_eq!(&a[st(i)..st(i) + 16], &[0; 16], "ST{i}");
        }
        for i in 0..16 {
            assert_eq!(&a[xmm(i)..xmm(i) + 16], &[0; 16], "XMM{i}");
        }
    }

    /// XRSTOR raises #GP on a header with XCOMP_BV set in the standard
    /// format, a reserved header byte set, an XSTATE_BV bit outside XCR0,
    /// or a reserved MXCSR bit (SDM vol. 1, 13.8). The template has none.
    #[test]
    fn xrstor_accepts_the_template() {
        let a = initial_state();
        assert_eq!(u64_at(&a, offset::XSTATE_BV), XCR0);
        assert_eq!(u64_at(&a, offset::XSTATE_BV) & !XCR0, 0);
        assert_eq!(u64_at(&a, offset::XCOMP_BV), 0);
        assert!(a[offset::XCOMP_BV + 8..AREA_SIZE].iter().all(|&b| b == 0));
        // Bits 16 and up of MXCSR are reserved on every CPU; the rest are
        // flags, masks, rounding, DAZ and FZ, which every SSE2 CPU has.
        assert_eq!(u32_at(&a, offset::MXCSR) & 0xFFFF_0000, 0);
        // The reserved bytes of the legacy region, 464 to 511, are zero
        // too, though XRSTOR ignores them.
        assert!(a[464..512].iter().all(|&b| b == 0));
    }

    #[test]
    fn the_masks_are_the_documented_values() {
        // FCW: IM DM ZM OM UM PM (bits 0 to 5), reserved bit 6 set by
        // FNINIT, PC = 11 (64-bit), RC = 00 (nearest).
        assert_eq!(FCW_INIT & 0x3F, 0x3F);
        assert_eq!((FCW_INIT >> 8) & 3, 3);
        assert_eq!((FCW_INIT >> 10) & 3, 0);
        // MXCSR: IM DM ZM OM UM PM (bits 7 to 12), RC = 00, FZ = DAZ = 0,
        // no exception flag.
        assert_eq!(MXCSR_INIT, 0x3F << 7);
    }

    #[test]
    fn offsets_are_the_sdm_layout() {
        assert_eq!(
            [
                offset::FCW,
                offset::FSW,
                offset::FTW,
                offset::FOP,
                offset::FIP,
                offset::FDP,
                offset::MXCSR,
                offset::MXCSR_MASK,
                offset::ST0,
                offset::XMM0,
                offset::XSTATE_BV,
                offset::XCOMP_BV,
            ],
            [0, 2, 4, 6, 8, 16, 24, 28, 32, 160, 512, 520]
        );
        assert_eq!(st(7), 144);
        assert_eq!(xmm(15), 400);
        assert_eq!(AREA_SIZE, 512 + 64);
    }

    #[test]
    fn cpuid_checks() {
        // QEMU's -cpu max and a CPU with AVX and AVX-512: both have x87 and
        // SSE; the size is read with XCR0 = 3, so it is 576.
        assert_eq!(check_cpuid(0x7, 576), Ok(()));
        assert_eq!(check_cpuid(0x2E7, 576), Ok(()));
        assert_eq!(check_cpuid(0x3, 1024), Ok(()));
        assert_eq!(
            check_cpuid(0x1, 576),
            Err(XsaveError::Unsupported { supported: 1 })
        );
        assert_eq!(
            check_cpuid(0x2, 576),
            Err(XsaveError::Unsupported { supported: 2 })
        );
        assert_eq!(check_cpuid(0x7, 1025), Err(XsaveError::Size { size: 1025 }));
        assert_eq!(check_cpuid(0x7, 512), Err(XsaveError::Size { size: 512 }));
        assert_eq!(
            XsaveError::Size { size: 2696 }.to_string(),
            "the XSAVE area for XCR0 0x3 is 2696 bytes, not 576 to 1024 (the TCB's reserve)"
        );
    }
}
