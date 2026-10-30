//! The kernel's GDT, TSS and IDT (`docs/design.md`, "Descriptor tables and
//! MSRs"): step 3 of the M3 boot sequence. Built in M3.

/// Loads the kernel's GDT, TSS and IDT, sets CR4.MCE, points `IA32_GS_BASE`
/// at the per-CPU area and resets DR7. Until M3 builds them, the
/// firmware's tables stay in use.
pub fn init() {}
