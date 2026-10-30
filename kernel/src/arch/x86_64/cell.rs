//! [`StaticCell`]: a static the kernel fills once at boot.

use core::cell::UnsafeCell;
use core::mem::MaybeUninit;
use core::sync::atomic::{AtomicU8, Ordering};

const EMPTY: u8 = 0;
const WRITING: u8 = 1;
const READY: u8 = 2;

/// A `static` written once, at boot, then only read. Safe code builds kernel
/// state at run time and keeps a `&'static` to it, with no `static mut`.
pub struct StaticCell<T> {
    state: AtomicU8,
    value: UnsafeCell<MaybeUninit<T>>,
}

// SAFETY: the value is written once, through `init`, before any reference
// to it exists, and only shared references are handed out afterwards; `T:
// Sync` makes sharing those sound.
unsafe impl<T: Sync> Sync for StaticCell<T> {}

impl<T> StaticCell<T> {
    pub const fn new() -> Self {
        StaticCell {
            state: AtomicU8::new(EMPTY),
            value: UnsafeCell::new(MaybeUninit::uninit()),
        }
    }

    /// Stores `value` and returns a reference to it for the rest of the
    /// kernel's life. Panics if called twice.
    pub fn init(&'static self, value: T) -> &'static T {
        let claimed =
            self.state
                .compare_exchange(EMPTY, WRITING, Ordering::Acquire, Ordering::Relaxed);
        assert!(claimed.is_ok(), "StaticCell initialised twice");
        // SAFETY: the exchange above lets exactly one caller past, and `get`
        // hands out no reference until READY, so this write aliases nothing.
        let value = unsafe { (*self.value.get()).write(value) };
        self.state.store(READY, Ordering::Release);
        value
    }

    /// The value, if `init` has finished.
    pub fn get(&'static self) -> Option<&'static T> {
        if self.state.load(Ordering::Acquire) == READY {
            // SAFETY: READY is stored only after `init` wrote the value, and
            // nothing writes it again.
            Some(unsafe { (*self.value.get()).assume_init_ref() })
        } else {
            None
        }
    }
}
