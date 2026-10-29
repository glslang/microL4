//! `no_std` logic shared by the loader and the kernel.
//!
//! Everything here is plain, safe Rust with no hardware access, so it also
//! builds for the host and runs under `cargo test` and Miri. From M2 this crate
//! holds the capability core; in M0 it holds the boot handoff ABI, the ELF
//! parser and the command-line parser.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod cmdline;
pub mod elf;
pub mod handoff;
