//! The root task's logic that needs no kernel: the verdicts of its tests,
//! built for the host as well, where `cargo test -p root --lib` runs them.
//! The program itself is `main.rs`.

#![no_std]
#![forbid(unsafe_code)]

#[cfg(test)]
extern crate std;

pub mod check;
