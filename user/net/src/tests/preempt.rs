//! Preemption points for the end-to-end tests: a window ([`Preempt`])
//! whose every access first lets a [`Hook`] run, so that another thread
//! acts between any two of a thread's accesses to its shared memory.
//!
//! On the target that is what happens: a device or the host, on its own
//! processor, reads and writes a driver's rings while the driver runs;
//! and a driver, at a higher priority than `net`, preempts `net` the
//! moment its interrupt or signal arrives, between any two of `net`'s
//! accesses to the frame queues. The tests step the threads in turn
//! otherwise, so without these points nothing would ever act inside
//! another's `on_signal` or `pump`.
//!
//! Shared by the tests of `net`, `virtio-net` and `netvsc`, which include
//! this file by path.

use core::cell::{Cell, RefCell};
use core::sync::atomic::Ordering;
use std::boxed::Box;
use std::rc::Rc;

use libsys::mem::{Memory, Width};

/// One access, as its hook sees it before it happens.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Access {
    Load,
    /// A store of this value.
    Store(u64),
    Swap(u64),
    Or(u64),
    /// A copy of this many bytes out of the window, or into it.
    Read(usize),
    Write(usize),
    Fence,
}

/// An access and where: its offset in the window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct At {
    pub offset: usize,
    pub access: Access,
}

/// A hook's action.
type Action<'a> = Box<dyn FnMut(At) + 'a>;

/// What runs at each preemption point of the windows made with it: none
/// until [`Hook::set`]. A hook never runs inside itself, so an action may
/// use windows of its own hook without recursing.
pub struct Hook<'a> {
    action: RefCell<Option<Action<'a>>>,
    busy: Cell<bool>,
    /// Points passed, the hook's runs among them.
    pub points: Cell<u64>,
}

impl Default for Hook<'_> {
    fn default() -> Self {
        Hook::new()
    }
}

impl<'a> Hook<'a> {
    pub fn new() -> Hook<'a> {
        Hook {
            action: RefCell::new(None),
            busy: Cell::new(false),
            points: Cell::new(0),
        }
    }

    /// From now on `f` runs before every access.
    pub fn set(&self, f: impl FnMut(At) + 'a) {
        *self.action.borrow_mut() = Some(Box::new(f));
    }

    fn point(&self, at: At) {
        self.points.set(self.points.get() + 1);
        if self.busy.get() {
            return;
        }
        let Some(mut f) = self.action.borrow_mut().take() else {
            return;
        };
        self.busy.set(true);
        f(at);
        self.busy.set(false);
        let mut slot = self.action.borrow_mut();
        if slot.is_none() {
            *slot = Some(f);
        }
    }
}

/// `inner`, with `hook` run before each access.
pub struct Preempt<'a, M> {
    pub inner: M,
    pub hook: Rc<Hook<'a>>,
}

impl<'a, M> Preempt<'a, M> {
    pub fn new(inner: M, hook: Rc<Hook<'a>>) -> Self {
        Preempt { inner, hook }
    }
}

impl<M: Memory> Memory for Preempt<'_, M> {
    fn len(&self) -> usize {
        self.inner.len()
    }

    fn load(&self, offset: usize, width: Width, order: Ordering) -> u64 {
        self.hook.point(At {
            offset,
            access: Access::Load,
        });
        self.inner.load(offset, width, order)
    }

    fn store(&self, offset: usize, width: Width, value: u64, order: Ordering) {
        self.hook.point(At {
            offset,
            access: Access::Store(value),
        });
        self.inner.store(offset, width, value, order)
    }

    fn swap(&self, offset: usize, width: Width, value: u64, order: Ordering) -> u64 {
        self.hook.point(At {
            offset,
            access: Access::Swap(value),
        });
        self.inner.swap(offset, width, value, order)
    }

    fn or(&self, offset: usize, width: Width, bits: u64, order: Ordering) -> u64 {
        self.hook.point(At {
            offset,
            access: Access::Or(bits),
        });
        self.inner.or(offset, width, bits, order)
    }

    fn read(&self, offset: usize, out: &mut [u8]) {
        self.hook.point(At {
            offset,
            access: Access::Read(out.len()),
        });
        self.inner.read(offset, out)
    }

    fn write(&self, offset: usize, bytes: &[u8]) {
        self.hook.point(At {
            offset,
            access: Access::Write(bytes.len()),
        });
        self.inner.write(offset, bytes)
    }

    fn fence(&self, order: Ordering) {
        self.hook.point(At {
            offset: 0,
            access: Access::Fence,
        });
        self.inner.fence(order)
    }
}

/// xorshift64*: small, deterministic and fast under Miri, for the
/// interleavings a proptest's seed picks.
#[derive(Clone, Debug)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Rng {
        Rng(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1)
    }

    pub fn next(&mut self) -> u64 {
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    /// Below `n`, which is not 0.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }

    /// True `per_mille` times in a thousand.
    pub fn chance(&mut self, per_mille: u32) -> bool {
        self.below(1000) < u64::from(per_mille)
    }
}
