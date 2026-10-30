//! Timer calibration arithmetic (`docs/design.md`, "The timer").
//!
//! The kernel counts local APIC timer ticks and TSC ticks over a 20 ms
//! window of a reference clock, three times, and asks this module what they
//! mean: the rates, their medians, the bounds and the LAPIC initial count
//! for the 100 Hz tick. The reference is Hyper-V's partition reference
//! counter (100 ns units) if present, else the HPET main counter, whose
//! period in femtoseconds the HPET reports. Every product is formed in 128
//! bits, so no input overflows, and nothing here panics.

use core::fmt;

/// Femtoseconds per second.
pub const FS_PER_S: u128 = 1_000_000_000_000_000;
/// Femtoseconds per millisecond.
pub const FS_PER_MS: u128 = 1_000_000_000_000;
/// The periodic tick's rate: a 10 ms timeslice.
pub const TICK_HZ: u64 = 100;
/// One calibration window's length.
pub const WINDOW_MS: u64 = 20;
/// Calibration windows; the median of each rate is kept.
pub const WINDOWS: usize = 3;
/// The plausible range for the LAPIC timer and the TSC, inclusive.
pub const MIN_HZ: u64 = 1_000_000;
pub const MAX_HZ: u64 = 10_000_000_000;
/// The longest HPET period accepted: 100 ns, as the HPET specification
/// allows.
pub const HPET_MAX_PERIOD_FS: u32 = 100_000_000;
/// The Hyper-V reference counter's period: 100 ns.
pub const HYPERV_PERIOD_FS: u32 = 100_000_000;

/// The clock the calibration windows are measured against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Reference {
    /// Hyper-V's partition reference counter, MSR `0x4000_0020`.
    HyperV,
    /// The HPET main counter, ticking every `period_fs` femtoseconds
    /// (`GCAP_ID[63:32]`).
    Hpet { period_fs: u32 },
}

impl Reference {
    /// The HPET as a reference, if its period is plausible:
    /// `0 < period <= 10^8` fs.
    pub fn hpet(period_fs: u32) -> Result<Self, TimerError> {
        if period_fs == 0 || period_fs > HPET_MAX_PERIOD_FS {
            return Err(TimerError::HpetPeriod(period_fs));
        }
        Ok(Self::Hpet { period_fs })
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::HyperV => "Hyper-V reference counter",
            Self::Hpet { .. } => "HPET",
        }
    }

    /// One reference tick in femtoseconds.
    pub fn period_fs(self) -> u32 {
        match self {
            Self::HyperV => HYPERV_PERIOD_FS,
            Self::Hpet { period_fs } => period_fs,
        }
    }

    /// The reference's own rate in Hz, rounded; 0 for a zero period.
    pub fn hz(self) -> u64 {
        let p = u128::from(self.period_fs());
        if p == 0 {
            return 0;
        }
        u64::try_from((FS_PER_S + p / 2) / p).unwrap_or(u64::MAX)
    }

    /// Reference ticks in `ms` milliseconds, rounded up, so a window is
    /// never shorter than asked; saturates at `u64::MAX`.
    pub fn ticks_in_ms(self, ms: u64) -> u64 {
        let p = u128::from(self.period_fs());
        if p == 0 {
            return u64::MAX;
        }
        u64::try_from((u128::from(ms) * FS_PER_MS).div_ceil(p)).unwrap_or(u64::MAX)
    }

    /// The time `ticks` reference ticks take, in femtoseconds.
    pub fn elapsed_fs(self, ticks: u64) -> u128 {
        u128::from(ticks) * u128::from(self.period_fs())
    }
}

/// What one calibration window measured: how far each counter moved while
/// the reference moved `reference_ticks`.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Window {
    pub reference_ticks: u64,
    pub lapic_ticks: u64,
    pub tsc_ticks: u64,
}

/// The calibration's result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Calibration {
    /// The LAPIC timer's rate at divide-by-1.
    pub lapic_hz: u64,
    /// The TSC's rate, BootInfo's `tsc_hz`.
    pub tsc_hz: u64,
    /// LAPIC ticks per 10 ms: the periodic timer's initial count.
    pub initial_count: u32,
}

/// Why calibration failed; the kernel panics on each.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TimerError {
    /// The HPET reports a period outside `0 < p <= 10^8` fs.
    HpetPeriod(u32),
    /// A window in which the reference did not move.
    EmptyWindow,
    /// The LAPIC timer's median rate is outside 1 MHz to 10 GHz.
    LapicRate(u64),
    /// The TSC's median rate is outside 1 MHz to 10 GHz.
    TscRate(u64),
}

impl fmt::Display for TimerError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::HpetPeriod(p) => write!(f, "HPET period {p} fs is implausible"),
            Self::EmptyWindow => f.write_str("the reference did not move in a window"),
            Self::LapicRate(hz) => write!(f, "LAPIC timer at {hz} Hz is implausible"),
            Self::TscRate(hz) => write!(f, "TSC at {hz} Hz is implausible"),
        }
    }
}

/// The rate in Hz, rounded to nearest, of a counter that moved `count`
/// while the reference moved `reference_ticks`. `None` if the reference did
/// not move; saturates at `u64::MAX`.
pub fn rate_hz(reference: Reference, count: u64, reference_ticks: u64) -> Option<u64> {
    let fs = reference.elapsed_fs(reference_ticks);
    if fs == 0 {
        return None;
    }
    // count < 2^64 and FS_PER_S < 2^50, so the product fits in 128 bits.
    let hz = (u128::from(count) * FS_PER_S + fs / 2) / fs;
    Some(u64::try_from(hz).unwrap_or(u64::MAX))
}

/// The median of three.
pub fn median3([a, b, c]: [u64; 3]) -> u64 {
    a.max(b).min(a.min(b).max(c))
}

/// Whether `hz` is a plausible LAPIC or TSC rate: 1 MHz to 10 GHz.
pub fn plausible(hz: u64) -> bool {
    (MIN_HZ..=MAX_HZ).contains(&hz)
}

/// The LAPIC initial count for a [`TICK_HZ`] periodic timer: ticks per
/// 10 ms, rounded to nearest. Within the plausible range it lies between
/// 10,000 and 100,000,000, so it always fits the 32-bit register.
pub fn initial_count(lapic_hz: u64) -> Result<u32, TimerError> {
    if !plausible(lapic_hz) {
        return Err(TimerError::LapicRate(lapic_hz));
    }
    let count = (lapic_hz + TICK_HZ / 2) / TICK_HZ;
    u32::try_from(count).map_err(|_| TimerError::LapicRate(lapic_hz))
}

/// The rates from [`WINDOWS`] windows against `reference`: each counter's
/// rate per window, the median of each, the bounds, and the initial count.
pub fn calibrate(
    reference: Reference,
    windows: &[Window; WINDOWS],
) -> Result<Calibration, TimerError> {
    let mut lapic = [0; WINDOWS];
    let mut tsc = [0; WINDOWS];
    for ((w, l), t) in windows.iter().zip(&mut lapic).zip(&mut tsc) {
        *l = rate_hz(reference, w.lapic_ticks, w.reference_ticks).ok_or(TimerError::EmptyWindow)?;
        *t = rate_hz(reference, w.tsc_ticks, w.reference_ticks).ok_or(TimerError::EmptyWindow)?;
    }
    let lapic_hz = median3(lapic);
    let tsc_hz = median3(tsc);
    let initial_count = initial_count(lapic_hz)?;
    if !plausible(tsc_hz) {
        return Err(TimerError::TscRate(tsc_hz));
    }
    Ok(Calibration {
        lapic_hz,
        tsc_hz,
        initial_count,
    })
}

/// Whether `measured` lies within `percent` percent of `expected`, in any
/// unit; for the ten-tick check against the reference.
pub fn within_percent(measured: u128, expected: u128, percent: u32) -> bool {
    measured.abs_diff(expected).saturating_mul(100) <= expected.saturating_mul(u128::from(percent))
}

#[cfg(test)]
mod tests {
    use super::*;

    const QEMU_HPET: Reference = Reference::Hpet {
        period_fs: 10_000_000,
    };

    /// A window of `ms` against `reference`, with counters at the given
    /// rates.
    fn window(reference: Reference, ms: u64, lapic_hz: u64, tsc_hz: u64) -> Window {
        let reference_ticks = reference.ticks_in_ms(ms);
        let fs = reference.elapsed_fs(reference_ticks);
        let count = |hz: u64| u64::try_from(u128::from(hz) * fs / FS_PER_S).unwrap();
        Window {
            reference_ticks,
            lapic_ticks: count(lapic_hz),
            tsc_ticks: count(tsc_hz),
        }
    }

    #[test]
    fn qemu_apic_clock_gives_ten_million() {
        // QEMU's HPET runs at 100 MHz (10 ns) and its APIC timer at 1 GHz.
        assert_eq!(QEMU_HPET.ticks_in_ms(WINDOW_MS), 2_000_000);
        assert_eq!(QEMU_HPET.hz(), 100_000_000);
        let w = window(QEMU_HPET, WINDOW_MS, 1_000_000_000, 3_000_000_000);
        assert_eq!(w.lapic_ticks, 20_000_000);
        let c = calibrate(QEMU_HPET, &[w; 3]).unwrap();
        assert_eq!(
            c,
            Calibration {
                lapic_hz: 1_000_000_000,
                tsc_hz: 3_000_000_000,
                initial_count: 10_000_000,
            }
        );
    }

    #[test]
    fn hyperv_reference_counter() {
        assert_eq!(Reference::HyperV.ticks_in_ms(WINDOW_MS), 200_000);
        assert_eq!(Reference::HyperV.hz(), 10_000_000);
        // Hyper-V's APIC timer runs at 200 MHz (HV_X64_MSR_APIC_FREQUENCY).
        let w = window(Reference::HyperV, WINDOW_MS, 200_000_000, 2_400_000_000);
        let c = calibrate(Reference::HyperV, &[w; 3]).unwrap();
        assert_eq!(c.lapic_hz, 200_000_000);
        assert_eq!(c.tsc_hz, 2_400_000_000);
        assert_eq!(c.initial_count, 2_000_000);
    }

    #[test]
    fn classic_hpet_period_rounds_the_window_up() {
        // 14.31818 MHz: 69,841,279 fs. 20 ms is 286,363.6 ticks.
        let r = Reference::hpet(69_841_279).unwrap();
        assert_eq!(r.ticks_in_ms(20), 286_364);
        assert!(r.elapsed_fs(r.ticks_in_ms(20)) >= 20 * FS_PER_MS);
        assert_eq!(r.hz(), 14_318_180);
    }

    #[test]
    fn calibration_takes_each_median() {
        let r = QEMU_HPET;
        let windows = [
            window(r, 20, 1_000_000_000, 2_000_000_000),
            // An outlier in each counter, in different windows.
            window(r, 20, 5_000_000_000, 2_000_000_100),
            window(r, 20, 1_000_000_100, 9_000_000_000),
        ];
        let c = calibrate(r, &windows).unwrap();
        assert_eq!(c.lapic_hz, 1_000_000_100);
        assert_eq!(c.tsc_hz, 2_000_000_100);
        assert_eq!(c.initial_count, 10_000_001);
    }

    #[test]
    fn windows_of_different_lengths_give_the_same_rate() {
        // A window that overshoots its target still measures the rate.
        let r = QEMU_HPET;
        let mut long = window(r, 20, 1_000_000_000, 2_000_000_000);
        long.reference_ticks += 1_000;
        long.lapic_ticks += 10_000;
        long.tsc_ticks += 20_000;
        assert_eq!(
            rate_hz(r, long.lapic_ticks, long.reference_ticks),
            Some(1_000_000_000)
        );
        assert_eq!(
            rate_hz(r, long.tsc_ticks, long.reference_ticks),
            Some(2_000_000_000)
        );
    }

    #[test]
    fn median_of_every_order() {
        for v in [
            [1, 2, 3],
            [1, 3, 2],
            [2, 1, 3],
            [2, 3, 1],
            [3, 1, 2],
            [3, 2, 1],
        ] {
            assert_eq!(median3(v), 2, "{v:?}");
        }
        assert_eq!(median3([5, 5, 1]), 5);
        assert_eq!(median3([1, 5, 1]), 1);
        assert_eq!(median3([0, u64::MAX, 7]), 7);
        assert_eq!(median3([4, 4, 4]), 4);
    }

    #[test]
    fn rate_bounds_are_inclusive() {
        assert!(!plausible(MIN_HZ - 1));
        assert!(plausible(MIN_HZ));
        assert!(plausible(MAX_HZ));
        assert!(!plausible(MAX_HZ + 1));
        assert_eq!(initial_count(MIN_HZ), Ok(10_000));
        assert_eq!(initial_count(MAX_HZ), Ok(100_000_000));
        assert_eq!(
            initial_count(MIN_HZ - 1),
            Err(TimerError::LapicRate(MIN_HZ - 1))
        );
        assert_eq!(
            initial_count(MAX_HZ + 1),
            Err(TimerError::LapicRate(MAX_HZ + 1))
        );
        assert_eq!(initial_count(0), Err(TimerError::LapicRate(0)));
    }

    #[test]
    fn implausible_rates_fail_calibration() {
        let r = QEMU_HPET;
        let slow = window(r, 20, 500_000, 2_000_000_000);
        assert_eq!(
            calibrate(r, &[slow; 3]),
            Err(TimerError::LapicRate(500_000))
        );
        let fast_tsc = window(r, 20, 1_000_000_000, 11_000_000_000);
        assert_eq!(
            calibrate(r, &[fast_tsc; 3]),
            Err(TimerError::TscRate(11_000_000_000))
        );
        let stuck_tsc = Window {
            tsc_ticks: 0,
            ..window(r, 20, 1_000_000_000, 1)
        };
        assert_eq!(calibrate(r, &[stuck_tsc; 3]), Err(TimerError::TscRate(0)));
    }

    #[test]
    fn a_reference_that_did_not_move_fails() {
        let w = Window {
            reference_ticks: 0,
            lapic_ticks: 1,
            tsc_ticks: 1,
        };
        assert_eq!(rate_hz(QEMU_HPET, 1, 0), None);
        let good = window(QEMU_HPET, 20, 1_000_000_000, 2_000_000_000);
        assert_eq!(
            calibrate(QEMU_HPET, &[good, w, good]),
            Err(TimerError::EmptyWindow)
        );
    }

    #[test]
    fn hpet_period_bounds() {
        assert_eq!(Reference::hpet(0), Err(TimerError::HpetPeriod(0)));
        assert_eq!(Reference::hpet(1), Ok(Reference::Hpet { period_fs: 1 }));
        assert!(Reference::hpet(HPET_MAX_PERIOD_FS).is_ok());
        assert_eq!(
            Reference::hpet(HPET_MAX_PERIOD_FS + 1),
            Err(TimerError::HpetPeriod(HPET_MAX_PERIOD_FS + 1))
        );
        assert_eq!(
            Reference::hpet(u32::MAX),
            Err(TimerError::HpetPeriod(u32::MAX))
        );
    }

    #[test]
    fn extremes_neither_overflow_nor_panic() {
        let fastest = Reference::Hpet { period_fs: 1 };
        let slowest = Reference::Hpet {
            period_fs: u32::MAX,
        };
        assert_eq!(rate_hz(fastest, u64::MAX, 1), Some(u64::MAX));
        assert_eq!(rate_hz(slowest, 1, u64::MAX), Some(0));
        assert_eq!(rate_hz(slowest, u64::MAX, u64::MAX), Some(232_831));
        assert_eq!(fastest.ticks_in_ms(u64::MAX), u64::MAX);
        assert_eq!(Reference::Hpet { period_fs: 0 }.ticks_in_ms(20), u64::MAX);
        assert_eq!(Reference::Hpet { period_fs: 0 }.hz(), 0);
        assert_eq!(rate_hz(Reference::Hpet { period_fs: 0 }, 5, 5), None);
        let all_max = Window {
            reference_ticks: u64::MAX,
            lapic_ticks: u64::MAX,
            tsc_ticks: u64::MAX,
        };
        // u64::MAX ticks of each over u64::MAX * 100 ns: 10 MHz.
        let c = calibrate(Reference::HyperV, &[all_max; 3]).unwrap();
        assert_eq!(
            (c.lapic_hz, c.tsc_hz, c.initial_count),
            (10_000_000, 10_000_000, 100_000)
        );
    }

    #[test]
    fn ten_ticks_within_one_percent() {
        let expected = 100 * FS_PER_MS;
        assert!(within_percent(expected, expected, 1));
        assert!(within_percent(101 * FS_PER_MS, expected, 1));
        assert!(within_percent(99 * FS_PER_MS, expected, 1));
        assert!(!within_percent(101 * FS_PER_MS + 1, expected, 1));
        assert!(!within_percent(99 * FS_PER_MS - 1, expected, 1));
        assert!(!within_percent(u128::MAX, expected, 1));
        assert!(within_percent(0, 0, 0));
    }
}
