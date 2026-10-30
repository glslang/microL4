//! One calibration window (`docs/design.md`, "The timer"): how the kernel
//! reads the reference clock, the local APIC timer's countdown and the TSC
//! so that one window measures all three over the same stretch of time.
//! [`crate::timer`] turns three windows into rates; `arch` supplies the
//! clocks. Also when a periodic tick really happened, for the ten-tick
//! check.

use core::fmt;

use crate::hpet::counter_delta;
use crate::timer::{FS_PER_S, Reference, Window};

/// The three clocks a window reads.
pub trait Clocks {
    /// The reference counter: the Hyper-V reference counter or the HPET
    /// main counter.
    fn reference(&mut self) -> u64;
    /// The local APIC timer's current count, counting down.
    fn lapic(&mut self) -> u32;
    /// The TSC.
    fn tsc(&mut self) -> u64;
}

/// Why a window failed; the kernel panics on each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WindowError {
    /// The reference did not move, or did not cover the window, within
    /// the TSC bound.
    ReferenceStuck,
    /// The local APIC countdown reached 0 inside the window, so its count
    /// says nothing.
    LapicExpired,
}

impl fmt::Display for WindowError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::ReferenceStuck => "the reference did not advance through the window",
            Self::LapicExpired => "the LAPIC countdown ran out inside the window",
        })
    }
}

/// One reading of all three clocks: the reference, bracketed by a LAPIC
/// and a TSC reading on each side, so that each counter's value at the
/// reference reading is the midpoint of its two readings, whatever the
/// reads cost.
struct Sample {
    reference: u64,
    lapic: u64,
    tsc: u64,
}

fn sample(c: &mut impl Clocks) -> Sample {
    let tsc_before = c.tsc();
    let lapic_before = c.lapic();
    let reference = c.reference();
    let lapic_after = c.lapic();
    let tsc_after = c.tsc();
    Sample {
        reference,
        // The countdown runs down: before >= after, unless it expired.
        lapic: u64::from(lapic_after) + u64::from(lapic_before.saturating_sub(lapic_after)) / 2,
        tsc: tsc_before.wrapping_add(tsc_after.wrapping_sub(tsc_before) / 2),
    }
}

/// Measures one window of `target` reference ticks. The reference is
/// `mask`'s width and may wrap once. The local APIC countdown must already
/// be running from a large initial count.
///
/// The window opens at a reference edge: the first reading that differs
/// from the one before, so the reference's own granularity does not cut
/// the window short. It closes at the first reading at least `target`
/// ticks later. Each reading is bracketed by LAPIC and TSC readings, whose
/// midpoints stand for the moment of the reference reading. Either wait
/// gives up after `tsc_limit` TSC ticks.
pub fn measure_window(
    c: &mut impl Clocks,
    target: u64,
    mask: u64,
    tsc_limit: u64,
) -> Result<Window, WindowError> {
    let wait_from = c.tsc();
    let first = c.reference();
    let start = loop {
        let s = sample(c);
        if s.reference != first {
            break s;
        }
        if s.tsc.wrapping_sub(wait_from) > tsc_limit {
            return Err(WindowError::ReferenceStuck);
        }
    };
    loop {
        let s = sample(c);
        let moved = counter_delta(start.reference, s.reference, mask);
        if moved >= target {
            if s.lapic == 0 {
                return Err(WindowError::LapicExpired);
            }
            return Ok(Window {
                reference_ticks: moved,
                lapic_ticks: start.lapic.saturating_sub(s.lapic),
                tsc_ticks: s.tsc.wrapping_sub(start.tsc),
            });
        }
        if s.tsc.wrapping_sub(start.tsc) > tsc_limit {
            return Err(WindowError::ReferenceStuck);
        }
    }
}

/// The reference reading at which the periodic timer last reloaded, that
/// is, last fired: `reading` was taken with the countdown at `current` of
/// `initial_count`, so `initial_count - current` LAPIC ticks after the
/// reload. That stretch is converted with the calibrated `lapic_hz` and
/// subtracted, wrapping at `mask`. Timing ticks by their reloads leaves out
/// how long each interrupt took to reach its handler, which on an emulator
/// is the host's scheduling, while an error in `lapic_hz` still shows in
/// full, since it sets the reload interval itself and touches only the
/// short correction here.
pub fn last_reload(
    reference: Reference,
    reading: u64,
    mask: u64,
    initial_count: u32,
    current: u32,
    lapic_hz: u64,
) -> u64 {
    let since = u128::from(initial_count.saturating_sub(current));
    let fs = since * FS_PER_S / u128::from(lapic_hz.max(1));
    let period = u128::from(reference.period_fs().max(1));
    let ticks = u64::try_from((fs + period / 2) / period).unwrap_or(u64::MAX);
    reading.wrapping_sub(ticks) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::timer;

    /// Simulated clocks on one time line, in nanoseconds: each read costs
    /// `read_ns`. The reference ticks every `ref_ns` (from `ref_base`,
    /// masked), the LAPIC counts down from `lapic_start` at `lapic_per_us`
    /// per microsecond, the TSC counts `tsc_per_ns` per nanosecond.
    struct Sim {
        now_ns: u64,
        read_ns: u64,
        ref_ns: u64,
        ref_base: u64,
        ref_mask: u64,
        ref_stuck: bool,
        lapic_start: u32,
        lapic_per_us: u64,
        tsc_per_ns: u64,
        reads: u64,
    }

    impl Sim {
        fn new() -> Self {
            Sim {
                now_ns: 3,
                read_ns: 1_000,
                ref_ns: 10,
                ref_base: 0,
                ref_mask: u64::MAX,
                ref_stuck: false,
                lapic_start: u32::MAX,
                lapic_per_us: 1_000,
                tsc_per_ns: 3,
                reads: 0,
            }
        }

        fn step(&mut self) -> u64 {
            self.reads += 1;
            assert!(self.reads < 10_000_000, "the window never closed");
            self.now_ns += self.read_ns;
            self.now_ns
        }
    }

    impl Clocks for Sim {
        fn reference(&mut self) -> u64 {
            let t = self.step();
            if self.ref_stuck {
                return 7;
            }
            self.ref_base.wrapping_add(t / self.ref_ns) & self.ref_mask
        }

        fn lapic(&mut self) -> u32 {
            let t = self.step();
            let gone = t * self.lapic_per_us / 1_000;
            u32::try_from(u64::from(self.lapic_start).saturating_sub(gone)).unwrap()
        }

        fn tsc(&mut self) -> u64 {
            self.step() * self.tsc_per_ns
        }
    }

    const HPET: Reference = Reference::Hpet {
        period_fs: 10_000_000,
    };

    #[test]
    fn qemu_like_window_measures_both_rates() {
        let mut sim = Sim::new();
        let target = HPET.ticks_in_ms(timer::WINDOW_MS);
        let w = measure_window(&mut sim, target, u64::MAX, 1 << 36).unwrap();
        assert!(w.reference_ticks >= target);
        // Reads cost 1 us, so the window overshoots by less than 2 us.
        assert!(w.reference_ticks < target + 200);
        let lapic = timer::rate_hz(HPET, w.lapic_ticks, w.reference_ticks).unwrap();
        let tsc = timer::rate_hz(HPET, w.tsc_ticks, w.reference_ticks).unwrap();
        // 1 GHz and 3 GHz within the read jitter: 1 us in 20 ms is 50 ppm.
        assert!(lapic.abs_diff(1_000_000_000) < 100_000, "{lapic}");
        assert!(tsc.abs_diff(3_000_000_000) < 300_000, "{tsc}");
    }

    #[test]
    fn a_coarse_reference_is_measured_from_an_edge() {
        // Hyper-V's 100 ns counter, with reads of 30 ns: without the edge
        // the window could start up to 100 ns late and measure short.
        let mut sim = Sim::new();
        sim.ref_ns = 100;
        sim.read_ns = 30;
        // A 1 ms window keeps the read count low for Miri.
        let target = Reference::HyperV.ticks_in_ms(1);
        let w = measure_window(&mut sim, target, u64::MAX, 1 << 36).unwrap();
        // A sample takes 150 ns, so a reading may land past the next edge.
        assert!((target..=target + 2).contains(&w.reference_ticks));
        let lapic = timer::rate_hz(Reference::HyperV, w.lapic_ticks, w.reference_ticks).unwrap();
        // Within two reads, 60 ns, of 1 ms: 60 ppm.
        assert!(lapic.abs_diff(1_000_000_000) < 60_000, "{lapic}");
    }

    #[test]
    fn a_32_bit_reference_may_wrap_inside_the_window() {
        let mut sim = Sim::new();
        sim.ref_mask = u64::from(u32::MAX);
        sim.ref_base = u64::from(u32::MAX) - 1_000;
        let target = HPET.ticks_in_ms(timer::WINDOW_MS);
        let mask = sim.ref_mask;
        let w = measure_window(&mut sim, target, mask, 1 << 36).unwrap();
        assert!(w.reference_ticks >= target && w.reference_ticks < target + 200);
    }

    #[test]
    fn a_stuck_reference_gives_up() {
        let mut sim = Sim::new();
        sim.ref_stuck = true;
        assert_eq!(
            measure_window(&mut sim, 2_000_000, u64::MAX, 1 << 20),
            Err(WindowError::ReferenceStuck)
        );
        // A reference that moves, but too slowly to cover the window.
        let mut sim = Sim::new();
        sim.ref_ns = 1_000_000;
        assert_eq!(
            measure_window(&mut sim, 2_000_000, u64::MAX, 1 << 24),
            Err(WindowError::ReferenceStuck)
        );
    }

    #[test]
    fn a_late_tick_is_dated_to_its_reload() {
        // 1 GHz LAPIC, 10 ms period: the handler read the HPET 250 us
        // after the reload, when 250,000 of 10,000,000 LAPIC ticks had gone.
        let at = last_reload(
            HPET,
            1_025_000,
            u64::MAX,
            10_000_000,
            9_750_000,
            1_000_000_000,
        );
        assert_eq!(at, 1_000_000);
        // No time since the reload: the reading itself.
        assert_eq!(
            last_reload(HPET, 77, u64::MAX, 10_000_000, 10_000_000, 1_000_000_000),
            77
        );
        // Hyper-V: 200 MHz LAPIC, 100 ns reference; 1 ms late.
        let at = last_reload(
            Reference::HyperV,
            50_000,
            u64::MAX,
            2_000_000,
            1_800_000,
            200_000_000,
        );
        assert_eq!(at, 40_000);
        // A 32-bit reference wraps backwards.
        assert_eq!(
            last_reload(
                HPET,
                5,
                u64::from(u32::MAX),
                10_000_000,
                9_999_000,
                1_000_000_000
            ),
            u64::from(u32::MAX) - 94
        );
        // A miscalibrated rate moves only the short correction: 10% off
        // on 250 us is 25 us.
        let at = last_reload(
            HPET,
            1_025_000,
            u64::MAX,
            10_000_000,
            9_750_000,
            1_100_000_000,
        );
        assert_eq!(at, 1_002_273);
    }

    #[test]
    fn last_reload_never_panics() {
        for hz in [0, 1, u64::MAX] {
            for (initial, current) in [(0, u32::MAX), (u32::MAX, 0), (5, 5)] {
                let _ = last_reload(HPET, 0, u64::MAX, initial, current, hz);
                let _ = last_reload(Reference::Hpet { period_fs: 0 }, 0, 1, initial, current, hz);
            }
        }
    }

    #[test]
    fn an_expired_countdown_is_refused() {
        let mut sim = Sim::new();
        sim.lapic_start = 1_000_000;
        assert_eq!(
            measure_window(&mut sim, 2_000_000, u64::MAX, 1 << 36),
            Err(WindowError::LapicExpired)
        );
    }
}
