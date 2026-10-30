//! The HPET (`docs/design.md`, "The timer"): register layout, the
//! capabilities register, and the clean-up the kernel does before it uses
//! the main counter as a calibration reference. Only the main counter is
//! used; every comparator stays silent. `arch` does the MMIO.
//!
//! Register offsets and bits follow the IA-PC HPET specification 1.0a,
//! section 2.3.

use core::fmt;

use crate::timer::{self, Reference, TimerError};

/// General capabilities and ID; see [`Capabilities`].
pub const GCAP_ID: u32 = 0x000;
/// General configuration: bit 0 `ENABLE_CNF` runs the main counter, bit 1
/// `LEG_RT_CNF` routes comparators 0 and 1 to IRQ 0 and 8.
pub const GEN_CONF: u32 = 0x010;
/// General interrupt status: a level-triggered comparator's bit, cleared by
/// writing 1.
pub const GINTR_STA: u32 = 0x020;
/// The main counter.
pub const MAIN_COUNTER: u32 = 0x0F0;

/// `GEN_CONF` bit 0: the main counter runs.
pub const ENABLE_CNF: u64 = 1 << 0;
/// `GEN_CONF` bit 1: legacy replacement routing.
pub const LEG_RT_CNF: u64 = 1 << 1;
/// A comparator's `Tn_INT_ENB_CNF`: it raises interrupts.
pub const TN_INT_ENB_CNF: u64 = 1 << 2;
/// A comparator's `Tn_FSB_EN_CNF`: it delivers by FSB (MSI) message.
pub const TN_FSB_EN_CNF: u64 = 1 << 14;
/// The most comparators whose registers lie in the HPET's 1 KiB block
/// (`0x100` + `0x20` n up to `0x3FF`): `NUM_TIM_CAP` can say 32, but the
/// specification's register map leaves room for 24, and the kernel never
/// reads past the block.
pub const MAX_COMPARATORS: u8 = 24;

/// Comparator `n`'s configuration and capabilities register.
pub const fn comparator_config(n: u8) -> u32 {
    0x100 + 0x20 * n as u32
}

/// The general configuration to write: legacy replacement off, the main
/// counter running, every reserved bit as read.
pub const fn general_config(old: u64) -> u64 {
    (old & !LEG_RT_CNF) | ENABLE_CNF
}

/// A comparator's configuration with interrupts and FSB delivery off, every
/// other bit as read. `None` if both are already off, so nothing is
/// written.
pub const fn quiet_comparator(old: u64) -> Option<u64> {
    if old & (TN_INT_ENB_CNF | TN_FSB_EN_CNF) == 0 {
        None
    } else {
        Some(old & !(TN_INT_ENB_CNF | TN_FSB_EN_CNF))
    }
}

/// The general capabilities and ID register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities(pub u64);

impl Capabilities {
    /// `COUNTER_CLK_PERIOD`, bits 32-63: the main counter's tick in
    /// femtoseconds.
    pub fn period_fs(self) -> u32 {
        (self.0 >> 32) as u32
    }

    /// The comparators: `NUM_TIM_CAP`, bits 8-12, plus 1.
    pub fn comparators(self) -> u8 {
        (self.0 >> 8 & 0x1F) as u8 + 1
    }

    /// The comparators whose registers the kernel may reach: at most
    /// [`MAX_COMPARATORS`].
    pub fn comparators_in_block(self) -> u8 {
        self.comparators().min(MAX_COMPARATORS)
    }

    /// `COUNT_SIZE_CAP`, bit 13: the main counter has 64 bits, not 32.
    pub fn counter_64bit(self) -> bool {
        self.0 >> 13 & 1 == 1
    }

    /// `LEG_RT_CAP`, bit 15.
    pub fn legacy_replacement(self) -> bool {
        self.0 >> 15 & 1 == 1
    }

    /// `VENDOR_ID`, bits 16-31.
    pub fn vendor(self) -> u16 {
        (self.0 >> 16) as u16
    }

    /// `REV_ID`, bits 0-7.
    pub fn revision(self) -> u8 {
        self.0 as u8
    }

    /// The main counter's bits: all 64, or the low 32.
    pub fn counter_mask(self) -> u64 {
        if self.counter_64bit() {
            u64::MAX
        } else {
            u64::from(u32::MAX)
        }
    }

    /// The HPET as a calibration reference, if its period is plausible
    /// ([`timer::Reference::hpet`]); an all-ones read, as from a missing
    /// device, has an implausible period.
    pub fn reference(self) -> Result<Reference, TimerError> {
        timer::Reference::hpet(self.period_fs())
    }
}

impl fmt::Display for Capabilities {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "period {} fs, {} comparators, {}-bit counter, vendor {:#06x} revision {}",
            self.period_fs(),
            self.comparators(),
            if self.counter_64bit() { 64 } else { 32 },
            self.vendor(),
            self.revision()
        )?;
        if self.legacy_replacement() {
            f.write_str(", legacy replacement capable")?;
        }
        Ok(())
    }
}

/// How far a counter of `mask`'s width moved from `start` to `now`,
/// across at most one wrap.
pub const fn counter_delta(start: u64, now: u64, mask: u64) -> u64 {
    now.wrapping_sub(start) & mask
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;

    /// QEMU's HPET: 10 ns, three comparators, 64-bit, legacy replacement
    /// capable, vendor 0x8086, revision 1 (hw/timer/hpet.c).
    const QEMU: Capabilities = Capabilities(0x0098_9680_8086_A201);

    #[test]
    fn qemu_capabilities() {
        assert_eq!(QEMU.period_fs(), 10_000_000);
        assert_eq!(QEMU.comparators(), 3);
        assert!(QEMU.counter_64bit());
        assert!(QEMU.legacy_replacement());
        assert_eq!(QEMU.vendor(), 0x8086);
        assert_eq!(QEMU.revision(), 1);
        assert_eq!(QEMU.counter_mask(), u64::MAX);
        assert_eq!(
            QEMU.reference(),
            Ok(Reference::Hpet {
                period_fs: 10_000_000
            })
        );
        assert_eq!(
            QEMU.to_string(),
            "period 10000000 fs, 3 comparators, 64-bit counter, vendor 0x8086 revision 1, legacy replacement capable"
        );
    }

    #[test]
    fn a_missing_hpet_is_no_reference() {
        let ones = Capabilities(u64::MAX);
        assert_eq!(ones.period_fs(), u32::MAX);
        assert_eq!(ones.comparators(), 32);
        assert_eq!(ones.comparators_in_block(), MAX_COMPARATORS);
        assert_eq!(QEMU.comparators_in_block(), 3);
        assert_eq!(ones.reference(), Err(TimerError::HpetPeriod(u32::MAX)));
        assert_eq!(Capabilities(0).reference(), Err(TimerError::HpetPeriod(0)));
    }

    #[test]
    fn a_32_bit_counter_wraps() {
        let c = Capabilities(0x0429_B17F_0000_0001);
        assert!(!c.counter_64bit());
        assert_eq!(c.period_fs(), 69_841_279);
        assert_eq!(counter_delta(0xFFFF_FFF0, 0x10, c.counter_mask()), 0x20);
        assert_eq!(counter_delta(5, 7, c.counter_mask()), 2);
        assert_eq!(counter_delta(u64::MAX - 1, 3, u64::MAX), 5);
    }

    #[test]
    fn general_config_turns_legacy_off_and_the_counter_on() {
        assert_eq!(general_config(0), ENABLE_CNF);
        assert_eq!(general_config(LEG_RT_CNF), ENABLE_CNF);
        assert_eq!(general_config(LEG_RT_CNF | ENABLE_CNF), ENABLE_CNF);
        // Reserved bits are written back as read.
        assert_eq!(general_config(0xF0 | LEG_RT_CNF), 0xF0 | ENABLE_CNF);
    }

    #[test]
    fn comparators_are_silenced_and_nothing_else_changes() {
        assert_eq!(quiet_comparator(0), None);
        // Periodic and 64-bit capable (bits 4 and 5), interrupts off.
        assert_eq!(quiet_comparator(0x0000_00F0_0000_0030), None);
        assert_eq!(quiet_comparator(TN_INT_ENB_CNF | 0x8), Some(0x8));
        assert_eq!(quiet_comparator(TN_FSB_EN_CNF | 0x8000), Some(0x8000));
        assert_eq!(
            quiet_comparator(u64::MAX),
            Some(!(TN_INT_ENB_CNF | TN_FSB_EN_CNF))
        );
        assert_eq!(comparator_config(0), 0x100);
        assert_eq!(comparator_config(2), 0x140);
        // Every comparator the kernel reaches lies in the 1 KiB block.
        assert_eq!(comparator_config(MAX_COMPARATORS - 1), 0x3E0);
        assert!(comparator_config(MAX_COMPARATORS - 1) + 0x18 < 0x400);
    }
}
