//! The local APIC, the I/O APICs and the 8259 PIC (`docs/design.md`, "Local
//! APIC, PIC and I/O APIC (M3)", "Vector map"): register layouts, the values
//! the kernel writes at boot, and the decisions the interrupt path and the
//! preemption point make. `arch` does the MMIO, the MSR accesses and the port
//! I/O.

use core::fmt;

use crate::trap::{self, Kind};

// ---------------------------------------------------------------------------
// IA32_APIC_BASE
// ---------------------------------------------------------------------------

/// `IA32_APIC_BASE` bit 8: this is the bootstrap processor.
pub const APIC_BASE_BSP: u64 = 1 << 8;
/// `IA32_APIC_BASE` bit 10 (EXTD): x2APIC mode.
pub const APIC_BASE_X2APIC: u64 = 1 << 10;
/// `IA32_APIC_BASE` bit 11 (EN): the local APIC is globally enabled.
pub const APIC_BASE_ENABLE: u64 = 1 << 11;

/// The local APIC's mode, from `IA32_APIC_BASE`'s EN and EXTD bits (SDM vol.
/// 3, "x2APIC State Transitions").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ApicMode {
    /// EN = 0, EXTD = 0: globally disabled.
    Disabled,
    /// EN = 1, EXTD = 0.
    XApic,
    /// EN = 1, EXTD = 1.
    X2Apic,
    /// EN = 0, EXTD = 1, which the SDM calls invalid.
    Invalid,
}

impl ApicMode {
    pub fn of(apic_base: u64) -> Self {
        match (
            apic_base & APIC_BASE_ENABLE != 0,
            apic_base & APIC_BASE_X2APIC != 0,
        ) {
            (false, false) => Self::Disabled,
            (true, false) => Self::XApic,
            (true, true) => Self::X2Apic,
            (false, true) => Self::Invalid,
        }
    }

    pub fn name(self) -> &'static str {
        match self {
            Self::Disabled => "disabled",
            Self::XApic => "xAPIC",
            Self::X2Apic => "x2APIC",
            Self::Invalid => "invalid (EXTD without EN)",
        }
    }
}

/// The values to write to `IA32_APIC_BASE`, in order, to put the local APIC
/// found as `apic_base` in xAPIC mode, keeping its base address and the BSP
/// bit. x2APIC goes through the disabled state, because the SDM makes a
/// direct x2APIC-to-xAPIC write raise `#GP`; leaving x2APIC resets the
/// local APIC, which the kernel programs afresh anyway.
pub fn xapic_writes(apic_base: u64) -> [Option<u64>; 2] {
    let off = apic_base & !(APIC_BASE_ENABLE | APIC_BASE_X2APIC);
    let xapic = off | APIC_BASE_ENABLE;
    match ApicMode::of(apic_base) {
        ApicMode::XApic => [None, None],
        ApicMode::Disabled => [Some(xapic), None],
        ApicMode::X2Apic | ApicMode::Invalid => [Some(off), Some(xapic)],
    }
}

// ---------------------------------------------------------------------------
// Local APIC registers (xAPIC: byte offsets in its 4 KiB page)
// ---------------------------------------------------------------------------

/// The local APIC ID, in bits 24-31.
pub const ID: u32 = 0x020;
/// The version register; see [`Version`].
pub const VERSION: u32 = 0x030;
/// The task priority register.
pub const TPR: u32 = 0x080;
/// End of interrupt: any write.
pub const EOI: u32 = 0x0B0;
/// The spurious interrupt vector register.
pub const SVR: u32 = 0x0F0;
/// The in-service register: 8 words, see [`vector_bit`].
pub const ISR: u32 = 0x100;
/// The interrupt request register: 8 words, see [`vector_bit`].
pub const IRR: u32 = 0x200;
/// The error status register; see [`Esr`].
pub const ESR: u32 = 0x280;
/// The corrected machine-check interrupt LVT, if [`Version::max_lvt`] >= 6.
pub const LVT_CMCI: u32 = 0x2F0;
/// The interrupt command register: low word (writing it sends) and high
/// word (destination).
pub const ICR_LOW: u32 = 0x300;
pub const ICR_HIGH: u32 = 0x310;
pub const LVT_TIMER: u32 = 0x320;
/// The thermal sensor LVT, if [`Version::max_lvt`] >= 5.
pub const LVT_THERMAL: u32 = 0x330;
/// The performance counter LVT, if [`Version::max_lvt`] >= 4.
pub const LVT_PERF: u32 = 0x340;
pub const LVT_LINT0: u32 = 0x350;
pub const LVT_LINT1: u32 = 0x360;
pub const LVT_ERROR: u32 = 0x370;
/// The timer's initial count: writing it starts the countdown, 0 stops it.
pub const TIMER_INITIAL: u32 = 0x380;
pub const TIMER_CURRENT: u32 = 0x390;
pub const TIMER_DIVIDE: u32 = 0x3E0;

/// An LVT entry's mask bit.
pub const LVT_MASKED: u32 = 1 << 16;
/// The timer LVT's periodic mode (bits 17-18 = 01); 00 is one-shot.
pub const LVT_TIMER_PERIODIC: u32 = 1 << 17;
/// SVR bit 8: the local APIC is software-enabled.
pub const SVR_ENABLE: u32 = 1 << 8;
/// SVR bit 12: EOI-broadcast suppression, which the kernel leaves off so a
/// local EOI reaches the I/O APIC for level-triggered pins.
pub const SVR_EOI_BROADCAST_SUPPRESSION: u32 = 1 << 12;
/// The SVR the kernel writes: enabled, spurious vector `0xFF`, focus
/// checking and EOI-broadcast suppression off.
pub const SVR_VALUE: u32 = SVR_ENABLE | trap::SPURIOUS as u32;
/// The error LVT the kernel writes: unmasked, fixed, vector `0xFE`.
pub const LVT_ERROR_VALUE: u32 = trap::APIC_ERROR as u32;
/// The divide configuration for divide by 1 (bits 0, 1 and 3 = 1011b).
pub const TIMER_DIVIDE_BY_1: u32 = 0b1011;
/// The timer LVT during calibration: one-shot, masked, vector `0xFD`.
pub const LVT_TIMER_CALIBRATE: u32 = LVT_MASKED | trap::TIMER as u32;
/// The timer LVT from then on: periodic, unmasked, vector `0xFD`.
pub const LVT_TIMER_TICK: u32 = LVT_TIMER_PERIODIC | trap::TIMER as u32;
/// The calibration windows' initial count: the largest, so the countdown
/// cannot reach 0 within a window below about 200 GHz.
pub const TIMER_CALIBRATE_COUNT: u32 = u32::MAX;

/// An LVT value with its mask bit set and every other field kept.
pub const fn lvt_masked(old: u32) -> u32 {
    old | LVT_MASKED
}

/// The local APIC's version register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Version(pub u32);

impl Version {
    /// The version: `0x10`-`0x1F` for an integrated APIC.
    pub fn version(self) -> u8 {
        self.0 as u8
    }

    /// Whether this is an integrated (xAPIC-capable) local APIC, not an
    /// 82489DX; the kernel refuses anything else, as seL4's `apic_init`
    /// does.
    pub fn integrated(self) -> bool {
        (0x10..=0x1F).contains(&self.version())
    }

    /// The index of the last LVT entry: the LVT has `max_lvt + 1` entries.
    pub fn max_lvt(self) -> u8 {
        (self.0 >> 16) as u8
    }

    /// The LVT registers this local APIC has, each to be masked at boot:
    /// timer, LINT0, LINT1 and error always; the performance counter from
    /// a max LVT of 4, thermal from 5 and CMCI from 6, as Linux's
    /// `clear_local_APIC` decides (SDM vol. 3, "Local Vector Table").
    pub fn lvts(self) -> impl Iterator<Item = u32> {
        let max = self.max_lvt();
        [
            (LVT_TIMER, 0),
            (LVT_LINT0, 0),
            (LVT_LINT1, 0),
            (LVT_ERROR, 0),
            (LVT_PERF, 4),
            (LVT_THERMAL, 5),
            (LVT_CMCI, 6),
        ]
        .into_iter()
        .filter(move |&(_, min)| max >= min)
        .map(|(reg, _)| reg)
    }
}

/// The error status register's bits (SDM vol. 3, "Error Handling").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Esr(pub u32);

impl fmt::Display for Esr {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        const NAMES: [&str; 8] = [
            "send checksum",
            "receive checksum",
            "send accept",
            "receive accept",
            "redirectable IPI",
            "send illegal vector",
            "received illegal vector",
            "illegal register address",
        ];
        let mut sep = "";
        for (bit, name) in NAMES.iter().enumerate() {
            if self.0 >> bit & 1 == 1 {
                write!(f, "{sep}{name}")?;
                sep = ", ";
            }
        }
        if self.0 & !0xFF != 0 {
            write!(f, "{sep}reserved bits {:#x}", self.0 & !0xFF)?;
        } else if sep.is_empty() {
            f.write_str("no error")?;
        }
        Ok(())
    }
}

/// The ICR's delivery-status bit: the last IPI has not been sent yet.
pub const ICR_SEND_PENDING: u32 = 1 << 12;

/// The ICR words, `(high, low)`, that send an NMI to the local APIC with
/// physical ID `apic_id`: delivery mode NMI (100b), physical destination,
/// level assert, edge, no shorthand. The "self" shorthand is valid only for
/// fixed delivery (SDM vol. 3, "Valid Combinations for the Local xAPIC
/// Interrupt Command Register"), so an NMI to itself names its own ID.
pub const fn icr_nmi(apic_id: u8) -> (u32, u32) {
    const DELIVERY_NMI: u32 = 0b100 << 8;
    const LEVEL_ASSERT: u32 = 1 << 14;
    ((apic_id as u32) << 24, DELIVERY_NMI | LEVEL_ASSERT)
}

/// The register, starting at `base` ([`ISR`], [`IRR`] or the TMR), that
/// holds `vector`'s bit, and that bit's mask: eight 32-bit words, 16 bytes
/// apart.
pub const fn vector_bit(base: u32, vector: u8) -> (u32, u32) {
    (base + (vector as u32 / 32) * 0x10, 1 << (vector % 32))
}

/// The IRR words a preemption point reads: 1 to 7, vectors `0x20`-`0xFF`.
/// Word 0 holds the exceptions, which never reach the IRR.
pub const PREEMPT_IRR_WORDS: core::ops::Range<usize> = 1..8;

/// The bits of IRR word `word` that make a preemption point stop: vectors
/// `0x30`-`0xFE` (`docs/design.md`, "Vector map"). The PIC's `0x20`-`0x2F`
/// share word 1 with `0x30`-`0x3F` and are masked off, as seL4's
/// `apic_is_interrupt_pending` reads only from `int_irq_min`; the spurious
/// vector never enters the IRR, and is masked too.
pub const fn preempt_irr_mask(word: usize) -> u32 {
    match word {
        1 => 0xFFFF_0000,
        2..=6 => u32::MAX,
        7 => 0x7FFF_FFFF,
        _ => 0,
    }
}

/// Whether the interrupt path writes EOI for `vector`, given whether its
/// ISR bit is set (`docs/design.md`, "Vector map" and the invariant "Every
/// fixed interrupt is EOI'd exactly once"): always for `0x30`-`0xFE`, for
/// the PIC's `0x20`-`0x2F` only when the bit is set (an injected MSI; a
/// masked 8259's spurious IRQ 7 or 15 sets none), never for the spurious
/// vector `0xFF`, whose delivery sets no ISR bit. Exceptions never reach
/// the interrupt path.
pub const fn needs_eoi(vector: u8, in_service: bool) -> bool {
    match trap::kind(vector) {
        Kind::Pic { .. } => in_service,
        Kind::Device { .. } | Kind::Ipi | Kind::Timer | Kind::ApicError => true,
        Kind::Spurious | Kind::Exception | Kind::Fatal | Kind::CannotOccur => false,
    }
}

// ---------------------------------------------------------------------------
// I/O APIC
// ---------------------------------------------------------------------------

/// The I/O APIC's register select, at offset 0 of its MMIO block.
pub const IOREGSEL: u32 = 0x00;
/// The I/O APIC's data window, at offset `0x10`.
pub const IOWIN: u32 = 0x10;
/// Indirect register 0: the I/O APIC ID in bits 24-27.
pub const IOAPIC_ID: u32 = 0x00;
/// Indirect register 1: see [`IoApicVersion`].
pub const IOAPIC_VERSION: u32 = 0x01;
/// A redirection entry's mask bit, in its low word.
pub const REDIRECTION_MASKED: u32 = 1 << 16;
/// The most pins an I/O APIC can have: the 8-bit register select reaches
/// redirection entries 0 to 119 only (registers `0x10`-`0xFF`).
pub const MAX_PINS: u16 = 120;

/// The indirect register holding the low word of pin `pin`'s redirection
/// entry; the high word (destination) is the next one.
pub const fn redirection_low(pin: u16) -> u32 {
    0x10 + 2 * pin as u32
}

/// The indirect register holding the high word of pin `pin`'s entry.
pub const fn redirection_high(pin: u16) -> u32 {
    redirection_low(pin) + 1
}

/// A redirection entry's low word with its mask bit set and every other
/// field kept, so the pin keeps its vector until M7 issues it.
pub const fn redirection_masked(old: u32) -> u32 {
    old | REDIRECTION_MASKED
}

/// The I/O APIC version register.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApicVersion(pub u32);

impl IoApicVersion {
    pub fn version(self) -> u8 {
        self.0 as u8
    }

    /// The pin count: the maximum redirection entry (bits 16-23) plus 1,
    /// at most [`MAX_PINS`].
    pub fn pins(self) -> u16 {
        ((self.0 >> 16 & 0xFF) as u16 + 1).min(MAX_PINS)
    }
}

// ---------------------------------------------------------------------------
// 8259 PIC
// ---------------------------------------------------------------------------

/// The master 8259's command and data ports.
pub const PIC1_COMMAND: u16 = 0x20;
pub const PIC1_DATA: u16 = 0x21;
/// The slave 8259's command and data ports.
pub const PIC2_COMMAND: u16 = 0xA0;
pub const PIC2_DATA: u16 = 0xA1;

/// The port writes, in order, that remap both 8259s to `0x20` and `0x28`
/// and mask every line: ICW1 (edge, cascade, ICW4 follows), ICW2 (vector
/// base), ICW3 (slave on master line 2; slave identity 2), ICW4 (8086
/// mode, normal EOI), then OCW1 with every mask bit set. ICW1 clears the
/// masks, so the local APIC's LINT0 is masked before this runs.
pub const PIC_INIT: [(u16, u8); 10] = [
    (PIC1_COMMAND, 0x11),
    (PIC2_COMMAND, 0x11),
    (PIC1_DATA, trap::PIC_BASE),
    (PIC2_DATA, trap::PIC_BASE + 8),
    (PIC1_DATA, 1 << 2),
    (PIC2_DATA, 2),
    (PIC1_DATA, 0x01),
    (PIC2_DATA, 0x01),
    (PIC1_DATA, 0xFF),
    (PIC2_DATA, 0xFF),
];

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;
    use std::vec::Vec;

    #[test]
    fn apic_modes() {
        assert_eq!(ApicMode::of(0xFEE0_0900), ApicMode::XApic);
        assert_eq!(ApicMode::of(0xFEE0_0D00), ApicMode::X2Apic);
        assert_eq!(ApicMode::of(0xFEE0_0100), ApicMode::Disabled);
        assert_eq!(ApicMode::of(0xFEE0_0500), ApicMode::Invalid);
    }

    #[test]
    fn xapic_is_left_alone() {
        // OVMF hands over 0xfee00900: enabled, BSP, xAPIC.
        assert_eq!(xapic_writes(0xFEE0_0900), [None, None]);
    }

    #[test]
    fn x2apic_is_left_through_the_disabled_state() {
        let [first, second] = xapic_writes(0xFEE0_0D00);
        assert_eq!(first, Some(0xFEE0_0100), "disabled, base and BSP kept");
        assert_eq!(second, Some(0xFEE0_0900), "then xAPIC");
        // Never x2APIC to xAPIC in one write.
        assert_eq!(ApicMode::of(first.unwrap()), ApicMode::Disabled);
    }

    #[test]
    fn a_disabled_apic_is_enabled_in_one_write() {
        assert_eq!(xapic_writes(0xFEE0_0100), [Some(0xFEE0_0900), None]);
        assert_eq!(
            xapic_writes(0xFEE0_0500),
            [Some(0xFEE0_0100), Some(0xFEE0_0900)]
        );
    }

    #[test]
    fn every_write_keeps_the_base_and_reserved_bits() {
        let base = 0x0000_000F_FEDC_B000 | APIC_BASE_BSP;
        for mode in [0, APIC_BASE_ENABLE, APIC_BASE_X2APIC | APIC_BASE_ENABLE] {
            for w in xapic_writes(base | mode).into_iter().flatten() {
                assert_eq!(w & !(APIC_BASE_ENABLE | APIC_BASE_X2APIC), base);
            }
        }
    }

    #[test]
    fn svr_error_and_timer_values() {
        assert_eq!(SVR_VALUE, 0x1FF);
        assert_eq!(SVR_VALUE & SVR_EOI_BROADCAST_SUPPRESSION, 0);
        assert_eq!(LVT_ERROR_VALUE, 0xFE);
        assert_eq!(LVT_ERROR_VALUE & LVT_MASKED, 0);
        assert_eq!(LVT_TIMER_CALIBRATE, 0x1_00FD);
        assert_eq!(LVT_TIMER_TICK, 0x2_00FD);
        assert_eq!(TIMER_DIVIDE_BY_1, 0xB);
        assert_eq!(lvt_masked(0x700), 0x1_0700);
    }

    #[test]
    fn lvts_follow_the_max_lvt_entry() {
        let lvts = |max: u32| Version(0x14 | max << 16).lvts().collect::<Vec<_>>();
        let base = [LVT_TIMER, LVT_LINT0, LVT_LINT1, LVT_ERROR];
        assert_eq!(lvts(3), base);
        assert_eq!(lvts(4), [&base[..], &[LVT_PERF]].concat());
        // QEMU's local APIC: version 0x50014, six LVT entries.
        assert_eq!(Version(0x5_0014).max_lvt(), 5);
        assert_eq!(lvts(5), [&base[..], &[LVT_PERF, LVT_THERMAL]].concat());
        assert_eq!(
            lvts(6),
            [&base[..], &[LVT_PERF, LVT_THERMAL, LVT_CMCI]].concat()
        );
    }

    #[test]
    fn integrated_versions() {
        assert!(Version(0x5_0014).integrated());
        assert!(Version(0x10).integrated());
        assert!(Version(0x1F).integrated());
        assert!(!Version(0x0F).integrated());
        assert!(!Version(0x20).integrated());
        assert!(!Version(u32::MAX).integrated());
    }

    #[test]
    fn esr_decodes() {
        assert_eq!(Esr(0).to_string(), "no error");
        assert_eq!(Esr(0x40).to_string(), "received illegal vector");
        assert_eq!(
            Esr(0xA0).to_string(),
            "send illegal vector, illegal register address"
        );
        assert_eq!(Esr(0x101).to_string(), "send checksum, reserved bits 0x100");
    }

    #[test]
    fn nmi_icr() {
        assert_eq!(icr_nmi(0), (0, 0x4400));
        assert_eq!(icr_nmi(0xAB), (0xAB00_0000, 0x4400));
        let (_, low) = icr_nmi(3);
        assert_eq!(low >> 18 & 3, 0, "no shorthand");
        assert_eq!(low >> 11 & 1, 0, "physical destination");
        assert_eq!(low >> 15 & 1, 0, "edge");
        assert_eq!(low & ICR_SEND_PENDING, 0);
    }

    #[test]
    fn vector_bits() {
        assert_eq!(vector_bit(ISR, 0x00), (0x100, 1));
        assert_eq!(vector_bit(ISR, 0x20), (0x110, 1));
        assert_eq!(vector_bit(IRR, 0x3F), (0x210, 1 << 31));
        assert_eq!(vector_bit(IRR, 0xFD), (0x270, 1 << 29));
        assert_eq!(vector_bit(IRR, 0xFF), (0x270, 1 << 31));
    }

    #[test]
    fn preemption_sees_exactly_0x30_to_0xfe() {
        for v in 0..=255u8 {
            let (reg, bit) = vector_bit(IRR, v);
            let word = ((reg - IRR) / 0x10) as usize;
            let seen = PREEMPT_IRR_WORDS.contains(&word) && preempt_irr_mask(word) & bit != 0;
            assert_eq!(seen, (0x30..=0xFE).contains(&v), "vector {v:#x}");
        }
    }

    #[test]
    fn every_fixed_interrupt_is_eoied_once() {
        for v in 0..=255u8 {
            let (with, without) = (needs_eoi(v, true), needs_eoi(v, false));
            match v {
                0x00..=0x1F => assert!(!with && !without, "{v:#x}"),
                0x20..=0x2F => assert!(with && !without, "{v:#x}"),
                0x30..=0xFE => assert!(with && without, "{v:#x}"),
                0xFF => assert!(!with && !without, "{v:#x}"),
            }
        }
    }

    #[test]
    fn ioapic_registers() {
        assert_eq!(redirection_low(0), 0x10);
        assert_eq!(redirection_high(0), 0x11);
        assert_eq!(redirection_low(23), 0x3E);
        assert_eq!(redirection_high(23), 0x3F);
        assert_eq!(redirection_high(MAX_PINS - 1), 0xFF);
        assert_eq!(redirection_masked(0x0000_A030), 0x0001_A030);
        // QEMU's I/O APIC: version 0x20, 24 pins.
        let v = IoApicVersion(0x0017_0020);
        assert_eq!((v.version(), v.pins()), (0x20, 24));
        assert_eq!(IoApicVersion(0x0077_0011).pins(), 120);
        assert_eq!(IoApicVersion(0x00FF_0011).pins(), MAX_PINS);
        assert_eq!(IoApicVersion(0).pins(), 1);
    }

    #[test]
    fn pic_is_remapped_then_masked() {
        let master: Vec<u8> = PIC_INIT
            .iter()
            .filter(|(p, _)| *p == PIC1_COMMAND || *p == PIC1_DATA)
            .map(|&(_, v)| v)
            .collect();
        let slave: Vec<u8> = PIC_INIT
            .iter()
            .filter(|(p, _)| *p == PIC2_COMMAND || *p == PIC2_DATA)
            .map(|&(_, v)| v)
            .collect();
        assert_eq!(master, [0x11, 0x20, 0x04, 0x01, 0xFF]);
        assert_eq!(slave, [0x11, 0x28, 0x02, 0x01, 0xFF]);
        // ICW1 goes to the command port, the rest to the data port.
        for &(p, v) in &PIC_INIT {
            assert_eq!(v == 0x11, p == PIC1_COMMAND || p == PIC2_COMMAND);
        }
        // The last write to each PIC masks every line.
        assert_eq!(PIC_INIT[8..], [(PIC1_DATA, 0xFF), (PIC2_DATA, 0xFF)]);
    }
}
