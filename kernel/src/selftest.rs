//! The kernel's own self-tests from M4, built only with `selftest` and
//! picked by `test=` on the command line (ADR 0003). M3's trap, paging and
//! timer tests live in `arch`, next to what they test. Each test ends the
//! run with `TEST PASS`, or `TEST FAIL` and a failure status.
//!
//! A call these tests make through `l4core` may return `Preempted`. Then the
//! test idles, the pending interrupt is taken, and the resume hook the idle
//! path calls restarts the call from its unchanged arguments, as a thread's
//! restarted `syscall` will from M5. If no interrupt is pending, because the
//! preemption was injected, the next timer tick resumes it.

use core::fmt;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use l4core::handoff::RegionKind;
use l4core::kernel::{Kernel, Preempted};
use l4core::objmem::LOW_MEMORY_END;

use crate::arch::{self, BootFacts, Objects};
use crate::boot::BootState;

/// Ends the run with `TEST FAIL` and `why`.
fn fail(why: fmt::Arguments<'_>) -> ! {
    kprintln!("TEST FAIL: {why}");
    arch::exit(arch::ExitCode::Failure)
}

/// Nanoseconds, shown as microseconds with three decimals.
struct Micros(u64);

impl fmt::Display for Micros {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{:03}", self.0 / 1000, self.0 % 1000)
    }
}

// ---------------------------------------------------------------------------
// test=preempt
// ---------------------------------------------------------------------------

/// What one preemption point follows: the chunk an untyped reset clears.
const CHUNK: u64 = 4096;
/// The most memory one pass clears, and the least the test runs with.
const MAX_LEN: u64 = 16 << 20;
const MIN_LEN: u64 = 1 << 20;
/// Passes allowed before an interrupt must have preempted one.
const MAX_PASSES: u64 = 16;
/// The poll after each start or restart that an injected preemption hits,
/// until one has been injected.
const INJECT_AT: u64 = 64;
/// What the range holds before each pass.
const PATTERN: u8 = 0xA5;

/// The range the test clears, `[BASE, TOP)`.
static BASE: AtomicU64 = AtomicU64::new(0);
static TOP: AtomicU64 = AtomicU64::new(0);
/// The call's progress: everything from here to `TOP` is zero. Only the
/// call itself lowers it, so a restart continues where the call stopped.
static WATERMARK: AtomicU64 = AtomicU64::new(0);
/// The call waits for the idle path to start or restart it.
static WAITING: AtomicBool = AtomicBool::new(false);
/// Passes started, and restarts from the idle path.
static PASSES: AtomicU64 = AtomicU64::new(0);
static RESTARTS: AtomicU64 = AtomicU64::new(0);
/// Preemptions by an interrupt, and injected ones, seen so far, to name the
/// cause of the next.
static SEEN_INTERRUPTED: AtomicU64 = AtomicU64::new(0);
static SEEN_INJECTED: AtomicU64 = AtomicU64::new(0);

/// `test=preempt`: a long, restartable operation through [`Objects`], as an
/// untyped reset runs. It clears up to 16 MiB of a free `USABLE` range from
/// the top down, one 4 KiB chunk at a time, passing a preemption point after
/// each, and keeps its progress in [`WATERMARK`]. It must be preempted at
/// least once by a real interrupt (the 100 Hz timer) and once by an
/// injected preemption, restart from the idle path each time, finish, and
/// leave the range zero. It prints the restarts, the polls and the longest
/// stretch between two polls in microseconds (`docs/design.md`, Open
/// questions: "Is 4 KiB the right chunk?").
///
/// Each pass fills the range with a pattern first. The first pass starts
/// from the idle path, just after an interrupt, so that its preemption by
/// the timer comes from a tick during the clearing. If no interrupt has
/// preempted a pass, on a fast host, another follows at once, at most
/// [`MAX_PASSES`] in all.
pub fn preempt(boot: &BootState, facts: &BootFacts) -> ! {
    let Some((base, top)) = free_range(boot, facts) else {
        fail(format_args!(
            "preempt: no free USABLE range of {} KiB",
            MIN_LEN >> 10
        ))
    };
    BASE.store(base, Ordering::Relaxed);
    TOP.store(top, Ordering::Relaxed);
    kprintln!(
        "preempt: clearing {} KiB at {base:#x}-{top:#x} from the top, {} chunks of {} KiB, a preemption point after each",
        (top - base) >> 10,
        (top - base) / CHUNK,
        CHUNK >> 10
    );
    arch::set_resume_hook(resume);
    start_pass()
}

/// The largest `USABLE` range above the kernel image, or anywhere if none
/// there is big enough, from 1 MiB to the direct map's end, at most
/// [`MAX_LEN`] of it from its start. Nothing uses `USABLE` memory once step
/// 5 is over.
fn free_range(boot: &BootState, facts: &BootFacts) -> Option<(u64, u64)> {
    let end = boot.handoff.direct_map_end();
    let usable = || {
        boot.memory_map()
            .iter()
            .filter(|r| r.kind == RegionKind::USABLE)
            .map(move |r| {
                let s = r.base.max(LOW_MEMORY_END).next_multiple_of(CHUNK);
                let e = r.end().min(end) & !(CHUNK - 1);
                (s, e)
            })
            .filter(|&(s, e)| s < e && e - s >= MIN_LEN)
    };
    let largest = |from: u64| {
        usable()
            .filter(|&(s, _)| s >= from)
            .max_by_key(|&(s, e)| e - s)
    };
    let (s, e) = largest(facts.kernel_image.end).or_else(|| largest(0))?;
    Some((s, s + (e - s).min(MAX_LEN)))
}

/// Fills the range with [`PATTERN`] and resets the progress. The first pass
/// then idles, so the next interrupt starts the call with nothing pending;
/// a later one starts it at once, so passes add up until a tick falls in
/// one.
fn start_pass() -> ! {
    let (base, top) = (BASE.load(Ordering::Relaxed), TOP.load(Ordering::Relaxed));
    let pass = PASSES.fetch_add(1, Ordering::Relaxed) + 1;
    Objects::begin().fill(base, top - base, PATTERN);
    WATERMARK.store(top, Ordering::Relaxed);
    if pass > 1 {
        kprintln!("preempt: pass {pass}: range filled with {PATTERN:#04x}; starting the call");
        run()
    }
    WAITING.store(true, Ordering::Relaxed);
    kprintln!(
        "preempt: pass {pass}: range filled with {PATTERN:#04x}; idling until an interrupt starts the call"
    );
    arch::idle()
}

/// The resume hook, on the idle path after every interrupt: starts or
/// restarts the call if it waits, else idles again.
fn resume() -> ! {
    if !WAITING.swap(false, Ordering::Relaxed) {
        arch::idle()
    }
    let watermark = WATERMARK.load(Ordering::Relaxed);
    if watermark != TOP.load(Ordering::Relaxed) {
        let n = RESTARTS.fetch_add(1, Ordering::Relaxed) + 1;
        kprintln!("preempt: restart {n} from the idle path, at {watermark:#x}");
    }
    run()
}

/// The call: runs [`clear`] until it finishes or is preempted.
fn run() -> ! {
    if arch::poll_stats().injected == 0 {
        arch::inject_preemption(INJECT_AT);
    }
    let mut k = Objects::begin();
    match clear(&mut k) {
        Ok(()) => finish(&k),
        Err(Preempted) => {
            let s = arch::poll_stats();
            let cause = if s.interrupted != SEEN_INTERRUPTED.load(Ordering::Relaxed) {
                "by an interrupt"
            } else if s.injected != SEEN_INJECTED.load(Ordering::Relaxed) {
                "by an injected preemption"
            } else {
                fail(format_args!("preempt: preempted, but no poll says why"))
            };
            SEEN_INTERRUPTED.store(s.interrupted, Ordering::Relaxed);
            SEEN_INJECTED.store(s.injected, Ordering::Relaxed);
            kprintln!(
                "preempt: preempted {cause} at {:#x}",
                WATERMARK.load(Ordering::Relaxed)
            );
            WAITING.store(true, Ordering::Relaxed);
            arch::idle()
        }
    }
}

/// Clears the range from [`WATERMARK`] down, one chunk at a time, lowering
/// the watermark after each and passing a preemption point while any is
/// left, as `l4core::untyped`'s reset does.
fn clear(k: &mut Objects) -> Result<(), Preempted> {
    let base = BASE.load(Ordering::Relaxed);
    loop {
        let watermark = WATERMARK.load(Ordering::Relaxed);
        if watermark == base {
            return Ok(());
        }
        let low = watermark - CHUNK;
        k.zero(low, CHUNK);
        WATERMARK.store(low, Ordering::Relaxed);
        if low > base {
            k.preempt()?;
        }
    }
}

/// The call finished: checks the range is zero, runs another pass if no
/// interrupt has preempted one yet, and otherwise checks and reports the
/// restarts.
fn finish(k: &Objects) -> ! {
    let (base, top) = (BASE.load(Ordering::Relaxed), TOP.load(Ordering::Relaxed));
    let pass = PASSES.load(Ordering::Relaxed);
    if let Some(at) = k.first_non_zero(base, top - base) {
        fail(format_args!(
            "preempt: pass {pass}: byte {at:#x} is not zero"
        ))
    }
    let s = arch::poll_stats();
    if s.interrupted == 0 {
        if pass == MAX_PASSES {
            fail(format_args!(
                "preempt: no interrupt preempted {MAX_PASSES} passes"
            ))
        }
        kprintln!("preempt: pass {pass} finished before an interrupt preempted it; again");
        start_pass()
    }
    let restarts = RESTARTS.load(Ordering::Relaxed);
    kprintln!(
        "preempt: {pass} pass(es) done, the range is zero; {restarts} restarts from the idle path after {} preemptions by an interrupt and {} injected",
        s.interrupted,
        s.injected
    );
    let (b, f) = (&s.between, &s.first);
    kprintln!(
        "preempt: {} polls; the longest stretch between two took {} us ({} TSC ticks, ending at poll {}), the mean {} us",
        s.polls,
        Micros(b.longest_ns),
        b.longest_tsc,
        b.longest_at,
        Micros(b.mean_ns)
    );
    kprintln!(
        "preempt: from the start of a call to its first poll: {} times, the longest {} us (poll {}), the mean {} us",
        f.count,
        Micros(f.longest_ns),
        f.longest_at,
        Micros(f.mean_ns)
    );
    if s.injected == 0 {
        fail(format_args!("preempt: no injected preemption"))
    }
    if restarts != s.interrupted + s.injected {
        fail(format_args!(
            "preempt: {restarts} restarts for {} preemptions",
            s.interrupted + s.injected
        ))
    }
    kprintln!("TEST PASS");
    arch::exit(arch::ExitCode::Success)
}
