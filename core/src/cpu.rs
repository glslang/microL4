//! The CPU features the kernel requires, decided from CPUID words
//! (`docs/design.md`, "CPU features"; ADR 0004).
//!
//! The kernel reads CPUID and the architecture-capabilities MSR in `arch/`
//! and asks this module what they mean, so the decision is host-tested.

use core::fmt;

/// The CPUID words the feature check reads (`docs/design.md`, H12, H14).
/// A leaf the CPU does not have reads as zero.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Cpuid {
    /// Leaf 1, ECX.
    pub leaf1_ecx: u32,
    /// Leaf 1, EDX.
    pub leaf1_edx: u32,
    /// Leaf 7 sub-leaf 0, EBX.
    pub leaf7_ebx: u32,
    /// Leaf 7 sub-leaf 0, ECX.
    pub leaf7_ecx: u32,
    /// Leaf 7 sub-leaf 0, EDX.
    pub leaf7_edx: u32,
    /// Leaf `0x8000_0001`, EDX.
    pub ext1_edx: u32,
}

/// A CPU feature the kernel checks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feature {
    /// Execute-disable pages: leaf `0x8000_0001` EDX bit 20.
    Nx,
    /// Global pages: leaf 1 EDX bit 13.
    Pge,
    /// The page attribute table: leaf 1 EDX bit 16.
    Pat,
    /// Supervisor-mode execution prevention: leaf 7 EBX bit 7.
    Smep,
    /// Supervisor-mode access prevention: leaf 7 EBX bit 20.
    Smap,
    /// `xsave` and XCR0: leaf 1 ECX bit 26.
    Xsave,
    /// User-mode instruction prevention: leaf 7 ECX bit 2. Optional.
    Umip,
}

impl Feature {
    /// Every feature, in the order the boot summary prints them.
    pub const ALL: [Feature; 7] = [
        Feature::Nx,
        Feature::Pge,
        Feature::Pat,
        Feature::Smep,
        Feature::Smap,
        Feature::Xsave,
        Feature::Umip,
    ];

    /// The features without which the kernel refuses to boot.
    pub const REQUIRED: [Feature; 6] = [
        Feature::Nx,
        Feature::Pge,
        Feature::Pat,
        Feature::Smep,
        Feature::Smap,
        Feature::Xsave,
    ];

    /// The name the boot log uses.
    pub fn name(self) -> &'static str {
        match self {
            Feature::Nx => "NX",
            Feature::Pge => "PGE",
            Feature::Pat => "PAT",
            Feature::Smep => "SMEP",
            Feature::Smap => "SMAP",
            Feature::Xsave => "XSAVE",
            Feature::Umip => "UMIP",
        }
    }
}

impl Cpuid {
    /// Whether the CPU reports `feature`.
    pub fn has(&self, feature: Feature) -> bool {
        let (word, bit) = match feature {
            Feature::Nx => (self.ext1_edx, 20),
            Feature::Pge => (self.leaf1_edx, 13),
            Feature::Pat => (self.leaf1_edx, 16),
            Feature::Smep => (self.leaf7_ebx, 7),
            Feature::Smap => (self.leaf7_ebx, 20),
            Feature::Xsave => (self.leaf1_ecx, 26),
            Feature::Umip => (self.leaf7_ecx, 2),
        };
        word & (1 << bit) != 0
    }

    /// The required features the CPU lacks, or `None` if it has them all.
    /// Displays as their names separated by spaces.
    pub fn lacks(&self) -> Option<Features> {
        let mut missing = Features::default();
        for f in Feature::REQUIRED {
            if !self.has(f) {
                missing.insert(f);
            }
        }
        (!missing.is_empty()).then_some(missing)
    }

    /// Every checked feature the CPU has, required or not.
    pub fn present(&self) -> Features {
        let mut present = Features::default();
        for f in Feature::ALL {
            if self.has(f) {
                present.insert(f);
            }
        }
        present
    }

    /// Whether `IA32_ARCH_CAPABILITIES` (MSR `0x10A`) exists: leaf 7 EDX
    /// bit 29.
    pub fn has_arch_capabilities(&self) -> bool {
        self.leaf7_edx & (1 << 29) != 0
    }
}

/// A set of [`Feature`]s, displayed in [`Feature::ALL`] order.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Features(u8);

impl Features {
    fn bit(f: Feature) -> u8 {
        1 << Feature::ALL.iter().position(|x| *x == f).unwrap_or(0)
    }

    /// Adds `f`.
    pub fn insert(&mut self, f: Feature) {
        self.0 |= Self::bit(f);
    }

    /// Whether `f` is in the set.
    pub fn contains(&self, f: Feature) -> bool {
        self.0 & Self::bit(f) != 0
    }

    /// Whether the set is empty.
    pub fn is_empty(&self) -> bool {
        self.0 == 0
    }
}

impl fmt::Display for Features {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut sep = "";
        for feature in Feature::ALL {
            if self.contains(feature) {
                write!(f, "{sep}{}", feature.name())?;
                sep = " ";
            }
        }
        Ok(())
    }
}

/// Whether the CPU is open to Meltdown (rogue data cache load), from
/// `RDCL_NO`, bit 0 of `IA32_ARCH_CAPABILITIES` (`docs/design.md`, H14).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Meltdown {
    /// The MSR exists and `RDCL_NO` is clear.
    Vulnerable,
    /// The MSR exists and `RDCL_NO` is set.
    NotVulnerable,
    /// The MSR does not exist.
    Unknown,
}

impl Meltdown {
    /// `arch_capabilities` is the MSR's value, or `None` if CPUID says it
    /// does not exist.
    pub fn from_arch_capabilities(arch_capabilities: Option<u64>) -> Meltdown {
        match arch_capabilities {
            None => Meltdown::Unknown,
            Some(v) if v & 1 != 0 => Meltdown::NotVulnerable,
            Some(_) => Meltdown::Vulnerable,
        }
    }

    /// The boot log's words: `cpu: meltdown: <name>`.
    pub fn name(self) -> &'static str {
        match self {
            Meltdown::Vulnerable => "vulnerable",
            Meltdown::NotVulnerable => "not vulnerable",
            Meltdown::Unknown => "unknown",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    /// Every checked bit set.
    fn full() -> Cpuid {
        Cpuid {
            leaf1_ecx: 1 << 26,
            leaf1_edx: (1 << 13) | (1 << 16),
            leaf7_ebx: (1 << 7) | (1 << 20),
            leaf7_ecx: 1 << 2,
            leaf7_edx: 1 << 29,
            ext1_edx: 1 << 20,
        }
    }

    #[test]
    fn a_full_cpu_lacks_nothing() {
        let c = full();
        assert_eq!(c.lacks(), None);
        assert_eq!(c.present().to_string(), "NX PGE PAT SMEP SMAP XSAVE UMIP");
        assert!(c.has_arch_capabilities());
    }

    #[test]
    fn each_bit_is_the_one_h12_names() {
        for f in Feature::ALL {
            let mut c = full();
            match f {
                Feature::Nx => c.ext1_edx = 0,
                Feature::Pge => c.leaf1_edx &= !(1 << 13),
                Feature::Pat => c.leaf1_edx &= !(1 << 16),
                Feature::Smep => c.leaf7_ebx &= !(1 << 7),
                Feature::Smap => c.leaf7_ebx &= !(1 << 20),
                Feature::Xsave => c.leaf1_ecx = 0,
                Feature::Umip => c.leaf7_ecx = 0,
            }
            for g in Feature::ALL {
                assert_eq!(c.has(g), g != f, "{f:?} cleared, checking {g:?}");
            }
        }
    }

    #[test]
    fn qemu64_lacks_smep_smap_and_xsave() {
        // QEMU's qemu64 model has NX, PGE and PAT but not the rest (H1).
        let c = Cpuid {
            leaf1_edx: (1 << 13) | (1 << 16),
            ext1_edx: 1 << 20,
            ..Cpuid::default()
        };
        assert_eq!(c.lacks().unwrap().to_string(), "SMEP SMAP XSAVE");
    }

    #[test]
    fn umip_is_optional() {
        let mut c = full();
        c.leaf7_ecx = 0;
        assert_eq!(c.lacks(), None);
        assert_eq!(c.present().to_string(), "NX PGE PAT SMEP SMAP XSAVE");
    }

    #[test]
    fn nothing_lacks_everything_required() {
        assert_eq!(
            Cpuid::default().lacks().unwrap().to_string(),
            "NX PGE PAT SMEP SMAP XSAVE"
        );
    }

    #[test]
    fn meltdown_from_rdcl_no() {
        assert_eq!(Meltdown::from_arch_capabilities(None), Meltdown::Unknown);
        assert_eq!(
            Meltdown::from_arch_capabilities(Some(0x1)),
            Meltdown::NotVulnerable
        );
        assert_eq!(
            Meltdown::from_arch_capabilities(Some(0x2)),
            Meltdown::Vulnerable
        );
        assert_eq!(Meltdown::NotVulnerable.name(), "not vulnerable");
    }
}
