//! CPUID, control registers, MSRs, the CPU feature check and hypervisor
//! detection.

use core::arch::asm;
use core::fmt;

use l4core::cpu::{Cpuid, Meltdown};

/// `IA32_ARCH_CAPABILITIES`; bit 0 is `RDCL_NO` (`docs/design.md`, H14).
const IA32_ARCH_CAPABILITIES: u32 = 0x10A;
/// `IA32_APIC_BASE`.
pub const IA32_APIC_BASE: u32 = 0x1B;
/// `IA32_EFER`.
pub const IA32_EFER: u32 = 0xC000_0080;

/// Runs CPUID for `leaf`, sub-leaf 0, and returns `(eax, ebx, ecx, edx)`.
pub fn cpuid(leaf: u32) -> (u32, u32, u32, u32) {
    cpuid_count(leaf, 0)
}

/// Runs CPUID for `leaf` and `subleaf` and returns `(eax, ebx, ecx, edx)`.
pub fn cpuid_count(leaf: u32, subleaf: u32) -> (u32, u32, u32, u32) {
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
            inout("ecx") subleaf => ecx,
            out("edx") edx,
            options(nomem, nostack, preserves_flags),
        );
    }
    (eax, ebx, ecx, edx)
}

/// The CPUID words the feature check reads; a leaf above the CPU's maximum
/// reads as zero.
pub fn cpuid_features() -> Cpuid {
    let (max_basic, ..) = cpuid(0);
    let (max_ext, ..) = cpuid(0x8000_0000);
    let (_, _, leaf1_ecx, leaf1_edx) = cpuid(1);
    let (_, leaf7_ebx, leaf7_ecx, leaf7_edx) = if max_basic >= 7 {
        cpuid_count(7, 0)
    } else {
        (0, 0, 0, 0)
    };
    let ext1_edx = if max_ext >= 0x8000_0001 {
        cpuid(0x8000_0001).3
    } else {
        0
    };
    Cpuid {
        leaf1_ecx,
        leaf1_edx,
        leaf7_ebx,
        leaf7_ecx,
        leaf7_edx,
        ext1_edx,
    }
}

/// Step 2 of the M3 boot sequence, before any CPU or firmware state
/// changes: refuses to boot, with one `CPU lacks` line, on a CPU without a
/// required feature (`docs/design.md`, CPU features). Prints the features
/// found.
pub fn check_cpu() -> Cpuid {
    let c = cpuid_features();
    if let Some(missing) = c.lacks() {
        panic!("CPU lacks {missing}");
    }
    kprintln!("cpu: features {}", c.present());
    c
}

/// Prints the M3 boot-summary lines for the CPU state the kernel booted
/// with: CR0, CR4, EFER, `IA32_APIC_BASE` and Meltdown exposure.
pub fn print_cpu_state() {
    kprintln!(
        "cpu: CR0 {:#x} CR4 {:#x} EFER {:#x}",
        read_cr0(),
        read_cr4(),
        read_msr(IA32_EFER)
    );
    kprintln!("cpu: IA32_APIC_BASE {:#x}", read_msr(IA32_APIC_BASE));
    let caps = cpuid_features()
        .has_arch_capabilities()
        .then(|| read_msr(IA32_ARCH_CAPABILITIES));
    kprintln!(
        "cpu: meltdown: {}",
        Meltdown::from_arch_capabilities(caps).name()
    );
}

/// Reads CR0.
pub fn read_cr0() -> u64 {
    let v;
    // SAFETY: reading CR0 has no side effects.
    unsafe { asm!("mov {}, cr0", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Reads CR2, the address of the last page fault.
pub fn read_cr2() -> u64 {
    let v;
    // SAFETY: reading CR2 has no side effects.
    unsafe { asm!("mov {}, cr2", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Reads CR3.
pub fn read_cr3() -> u64 {
    let v;
    // SAFETY: reading CR3 has no side effects.
    unsafe { asm!("mov {}, cr3", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Reads CR4.
pub fn read_cr4() -> u64 {
    let v;
    // SAFETY: reading CR4 has no side effects.
    unsafe { asm!("mov {}, cr4", out(reg) v, options(nomem, nostack, preserves_flags)) };
    v
}

/// Writes CR4.
///
/// # Safety
///
/// The new value must keep every mapping the kernel relies on valid, and
/// may set only features the CPU has.
pub unsafe fn write_cr4(v: u64) {
    // SAFETY: the caller vouches for the value. The write can change how
    // memory is translated, so it is not `nomem`.
    unsafe { asm!("mov cr4, {}", in(reg) v, options(nostack, preserves_flags)) };
}

/// Reads model-specific register `msr`. An MSR the CPU lacks raises #GP,
/// which the kernel reports as a fatal fault.
pub fn read_msr(msr: u32) -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdmsr` reads a register and touches no memory.
    unsafe {
        asm!("rdmsr", in("ecx") msr, out("eax") lo, out("edx") hi,
            options(nomem, nostack, preserves_flags));
    }
    (hi as u64) << 32 | lo as u64
}

/// Writes model-specific register `msr`.
///
/// # Safety
///
/// The MSR must exist, and the value must leave the CPU in a state the
/// kernel's memory safety survives.
pub unsafe fn write_msr(msr: u32, v: u64) {
    // SAFETY: the caller vouches for the register and value. Some MSRs
    // change how memory is accessed, so this is not `nomem`.
    unsafe {
        asm!("wrmsr", in("ecx") msr, in("eax") v as u32, in("edx") (v >> 32) as u32,
            options(nostack, preserves_flags));
    }
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
