//! Timer calibration and the 100 Hz tick (`docs/design.md`, "The timer"):
//! the last part of step 5 of the M3 boot sequence, and the `test=ticks`
//! hook.
//!
//! The local APIC timer and the TSC are measured over three 20 ms windows
//! of the reference: Hyper-V's partition reference counter if the
//! partition may read it, else the HPET's main counter; with neither the
//! kernel panics. `l4core::calibration` reads each window and
//! `l4core::timer` turns the windows into rates and the initial count.

use core::arch::asm;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicU64, Ordering};

use l4core::calibration::{self, Clocks};
use l4core::hpet::counter_delta;
use l4core::timer::{
    self as t, Calibration, FS_PER_MS, Reference, TICK_HZ, WINDOW_MS, WINDOWS, Window,
};
use l4core::trap;

use super::hpet::Hpet;
use super::hyperv::{self, ReferenceCounter};
use super::{ExitCode, StaticCell, apic, exit, irq};

/// How long a calibration window, or the wait for the first reference
/// edge, may take before the kernel gives up: 2^36 TSC ticks, 6.9 s at
/// 10 GHz.
const TSC_LIMIT: u64 = 1 << 36;

/// The calibration reference.
enum Source {
    HyperV(ReferenceCounter),
    Hpet(Hpet),
}

impl Source {
    fn read(&self) -> u64 {
        match self {
            Source::HyperV(c) => c.read(),
            Source::Hpet(h) => h.counter(),
        }
    }

    fn mask(&self) -> u64 {
        match self {
            Source::HyperV(_) => u64::MAX,
            Source::Hpet(h) => h.mask(),
        }
    }

    fn reference(&self) -> Reference {
        match self {
            Source::HyperV(_) => Reference::HyperV,
            Source::Hpet(h) => h.reference(),
        }
    }
}

/// The calibrated timer and its reference, kept for the `ticks` test and
/// BootInfo's `tsc_hz` (M4).
struct Clock {
    source: Source,
    calibration: Calibration,
}

static CLOCK: StaticCell<Clock> = StaticCell::new();

/// The live clocks one window reads.
struct Live<'a>(&'a Source);

impl Clocks for Live<'_> {
    fn reference(&mut self) -> u64 {
        self.0.read()
    }

    fn lapic(&mut self) -> u32 {
        apic::timer_current()
    }

    fn tsc(&mut self) -> u64 {
        rdtsc()
    }
}

fn rdtsc() -> u64 {
    let (lo, hi): (u32, u32);
    // SAFETY: `rdtsc` reads the time-stamp counter; it touches no memory.
    // CR4.TSD is clear, and the kernel runs in ring 0 regardless.
    unsafe {
        asm!("rdtsc", out("eax") lo, out("edx") hi, options(nomem, nostack, preserves_flags))
    };
    u64::from(hi) << 32 | u64::from(lo)
}

/// The last part of step 5: picks the reference, calibrates the local APIC
/// timer and the TSC against it, prints the rates, and starts the periodic
/// timer at [`TICK_HZ`]. Panics with `no timer reference` if there is
/// neither reference, and on an implausible rate. Interrupts must be off;
/// the first tick is taken in the idle loop.
pub fn init(hv: &'static hyperv::Info, hpet: Option<Hpet>) {
    let source = match (&hv.reference_counter, hpet) {
        (Some(counter), _) => Source::HyperV(*counter),
        (None, Some(h)) => Source::Hpet(h),
        (None, None) => {
            panic!("no timer reference: neither Hyper-V's reference counter nor an HPET")
        }
    };
    let reference = source.reference();
    let target = reference.ticks_in_ms(WINDOW_MS);
    kprintln!(
        "timer: calibrating against the {} at {} Hz: {WINDOWS} windows of {WINDOW_MS} ms, {target} ticks each",
        reference.name(),
        reference.hz()
    );

    let mut windows = [Window::default(); WINDOWS];
    for (i, w) in windows.iter_mut().enumerate() {
        apic::timer_start_countdown();
        let measured =
            calibration::measure_window(&mut Live(&source), target, source.mask(), TSC_LIMIT);
        apic::timer_stop();
        *w = match measured {
            Ok(w) => w,
            Err(e) => panic!("timer: window {}: {e}", i + 1),
        };
        kprintln!(
            "timer: window {}: {} reference ticks, LAPIC {}, TSC {}",
            i + 1,
            w.reference_ticks,
            w.lapic_ticks,
            w.tsc_ticks
        );
    }
    let calibration = match t::calibrate(reference, &windows) {
        Ok(c) => c,
        Err(e) => panic!("timer: {e}"),
    };
    kprintln!(
        "timer: LAPIC timer {} Hz, TSC {} Hz (medians)",
        calibration.lapic_hz,
        calibration.tsc_hz
    );
    if let Some(msr) = hv.apic_hz {
        kprintln!(
            "timer: Hyper-V's APIC frequency MSR says {msr} Hz: calibration off by {} ppm",
            ppm(calibration.lapic_hz, msr)
        );
    }
    if let Some(msr) = hv.tsc_hz {
        kprintln!(
            "timer: Hyper-V's TSC frequency MSR says {msr} Hz: calibration off by {} ppm",
            ppm(calibration.tsc_hz, msr)
        );
    }

    apic::timer_start_periodic(calibration.initial_count);
    kprintln!(
        "timer: periodic at {TICK_HZ} Hz: divide by 1, vector {:#04x}, initial count {}",
        trap::TIMER,
        calibration.initial_count
    );
    CLOCK.init(Clock {
        source,
        calibration,
    });
}

/// How far `measured` is from `expected`, in parts per million.
fn ppm(measured: u64, expected: u64) -> i128 {
    if expected == 0 {
        return 0;
    }
    (i128::from(measured) - i128::from(expected)) * 1_000_000 / i128::from(expected)
}

// ---------------------------------------------------------------------------
// test=ticks
// ---------------------------------------------------------------------------

/// Tick intervals the test times.
const TIMED_TICKS: u64 = 10;
/// Ticks the test has seen.
static TEST_SEEN: AtomicU64 = AtomicU64::new(0);
/// The reference when the handler of the tick that starts the timing ran,
/// and when that tick's reload happened.
static TEST_START: AtomicU64 = AtomicU64::new(0);
static TEST_START_RELOAD: AtomicU64 = AtomicU64::new(0);

/// `test=ticks`, before the kernel idles: checks with interrupts still off
/// that the preemption point's IRR poll sees the timer, then installs the
/// tick hook. The kernel then idles; the hook skips the first tick, which
/// may have waited in the IRR since before the idle loop, and times the
/// next [`TIMED_TICKS`] intervals against the reference, dating each tick
/// by its reload ([`calibration::last_reload`]) so that the host's delay in
/// delivering an interrupt does not count. It passes if they took 100 ms
/// within 1%, and prints the handler-to-handler time as well.
pub fn start_ticks_test() {
    let Some(clock) = CLOCK.get() else {
        panic!("ticks: the timer is not running");
    };
    let start = rdtsc();
    while !apic::interrupt_pending() {
        if rdtsc().wrapping_sub(start) > TSC_LIMIT {
            panic!("ticks: no interrupt became pending with interrupts off");
        }
        spin_loop();
    }
    kprintln!(
        "ticks: with interrupts off the IRR poll sees an interrupt pending; the timer's: {}",
        if apic::requested(trap::TIMER) {
            "yes"
        } else {
            "no"
        }
    );
    irq::set_tick_hook(ticks_test_tick);
    kprintln!(
        "ticks: idling; timing {TIMED_TICKS} ticks of {} LAPIC ticks at {} Hz against the {}",
        clock.calibration.initial_count,
        clock.calibration.lapic_hz,
        clock.source.reference().name()
    );
}

fn ticks_test_tick(_tick: u64) {
    let Some(clock) = CLOCK.get() else {
        return;
    };
    let now = clock.source.read();
    let current = apic::timer_current();
    let (reference, mask) = (clock.source.reference(), clock.source.mask());
    let c = &clock.calibration;
    let reload =
        calibration::last_reload(reference, now, mask, c.initial_count, current, c.lapic_hz);
    let seen = TEST_SEEN.fetch_add(1, Ordering::Relaxed) + 1;
    if seen == 2 {
        TEST_START.store(now, Ordering::Relaxed);
        TEST_START_RELOAD.store(reload, Ordering::Relaxed);
    }
    if seen != 2 + TIMED_TICKS {
        return;
    }
    let fs = |from: &AtomicU64, to: u64| {
        reference.elapsed_fs(counter_delta(from.load(Ordering::Relaxed), to, mask))
    };
    let handlers = fs(&TEST_START, now);
    let reloads = fs(&TEST_START_RELOAD, reload);
    let expected = u128::from(TIMED_TICKS) * 1000 / u128::from(TICK_HZ) * FS_PER_MS;
    let ok = t::within_percent(reloads, expected, 1);
    let us = |fs: u128| fs / 1_000_000_000;
    let millihertz = (u128::from(TIMED_TICKS) * t::FS_PER_S * 1000)
        .checked_div(reloads)
        .unwrap_or(0);
    kprintln!(
        "ticks: {TIMED_TICKS} ticks: the timer reloaded over {} us, {} us per tick, {}.{:03} Hz; the handlers ran over {} us",
        us(reloads),
        us(reloads / u128::from(TIMED_TICKS)),
        millihertz / 1000,
        millihertz % 1000,
        us(handlers)
    );
    kprintln!(
        "ticks: {} {} us within 1%",
        if ok { "within" } else { "NOT within" },
        us(expected)
    );
    if ok {
        kprintln!("TEST PASS");
        exit(ExitCode::Success)
    } else {
        kprintln!("TEST FAIL");
        exit(ExitCode::Failure)
    }
}
