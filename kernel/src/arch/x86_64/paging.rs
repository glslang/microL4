//! The kernel's own page tables (`docs/design.md`, "The kernel half"): step 4
//! of the M3 boot sequence. Built in M3.

use crate::boot::BootState;

/// Programs `IA32_PAT`, builds the kernel's page tables in `.bss`, sets
/// CR4.SMEP, SMAP, PGE and UMIP, loads CR3 and toggles CR4.PGE. Until M3
/// builds them, the loader's tables stay in use.
pub fn init(_boot: &'static BootState) {}
