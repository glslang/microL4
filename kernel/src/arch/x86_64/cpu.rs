//! CPUID and hypervisor detection.

use core::arch::asm;
use core::fmt;

/// Runs CPUID for `leaf`, sub-leaf 0, and returns `(eax, ebx, ecx, edx)`.
fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    let (eax, ebx, ecx, edx);
    // SAFETY: CPUID only reads processor identification; it touches no
    // memory. LLVM reserves rbx, so it is saved and restored by hand.
    unsafe {
        asm!(
            "mov {saved:r}, rbx",
            "cpuid",
            "xchg {saved:r}, rbx",
            saved = out(reg) ebx,
            inout("eax") leaf => eax,
            inout("ecx") 0u32 => ecx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

/// The hypervisor we run under, from CPUID leaf 0x4000_0000.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Hypervisor {
    /// No hypervisor-present bit: bare metal, which is not supported.
    None,
    /// QEMU's TCG emulator, `"TCGTCGTCGTCG"`.
    QemuTcg,
    /// QEMU on KVM, `"KVMKVMKVM\0\0\0"`.
    QemuKvm,
    /// Hyper-V, `"Microsoft Hv"`.
    HyperV,
    /// Some other vendor signature.
    Other([u8; 12]),
}

impl Hypervisor {
    /// Whether QEMU's `isa-debug-exit` device can be expected.
    pub fn is_qemu(self) -> bool {
        matches!(self, Self::QemuTcg | Self::QemuKvm)
    }
}

impl fmt::Display for Hypervisor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::None => f.write_str("none"),
            Self::QemuTcg => f.write_str("QEMU TCG (\"TCGTCGTCGTCG\")"),
            Self::QemuKvm => f.write_str("QEMU KVM (\"KVMKVMKVM\")"),
            Self::HyperV => f.write_str("Hyper-V (\"Microsoft Hv\")"),
            Self::Other(sig) => {
                f.write_str("unknown (\"")?;
                for &b in sig {
                    if b.is_ascii_graphic() || b == b' ' {
                        write!(f, "{}", b as char)?;
                    } else {
                        write!(f, "\\x{b:02x}")?;
                    }
                }
                f.write_str("\")")
            }
        }
    }
}

pub fn hypervisor() -> Hypervisor {
    const HYPERVISOR_PRESENT: u32 = 1 << 31;
    let (_, _, ecx, _) = cpuid(1);
    if ecx & HYPERVISOR_PRESENT == 0 {
        return Hypervisor::None;
    }
    let (_, ebx, ecx, edx) = cpuid(0x4000_0000);
    let mut sig = [0u8; 12];
    sig[0..4].copy_from_slice(&ebx.to_le_bytes());
    sig[4..8].copy_from_slice(&ecx.to_le_bytes());
    sig[8..12].copy_from_slice(&edx.to_le_bytes());
    match &sig {
        b"TCGTCGTCGTCG" => Hypervisor::QemuTcg,
        b"KVMKVMKVM\0\0\0" => Hypervisor::QemuKvm,
        b"Microsoft Hv" => Hypervisor::HyperV,
        _ => Hypervisor::Other(sig),
    }
}
