//! `no_std` logic shared by the loader and the kernel.
//!
//! Everything here is plain, safe Rust with no hardware access, so it also
//! builds for the host and runs under `cargo test` and Miri. It holds the boot
//! handoff ABI, the ELF parser and the command-line parser (M0), the
//! capability core (M2): capabilities and slots, the derivation list, capability
//! addressing, the slot operations and untyped retype; and from M3 the CPU
//! feature check and the kernel device window.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

#[cfg(any(test, feature = "testing"))]
extern crate alloc;

pub mod cap;
pub mod cdt;
pub mod cmdline;
pub mod cnode;
pub mod cpu;
pub mod cspace;
pub mod elf;
pub mod error;
pub mod handoff;
pub mod kernel;
pub mod slot;
pub mod untyped;
pub mod window;

#[cfg(any(test, feature = "testing"))]
pub mod testing;

#[cfg(test)]
mod tests;

#[cfg(test)]
mod review_tests;
