//! Architecture-specific code. This is the only part of the kernel allowed to
//! use `unsafe`.

mod x86_64;

pub use self::x86_64::*;
