//! Hyper-V at boot (`docs/design.md`, "Detection (M3)", "Firmware leftovers
//! (M3)"): the first part of step 5 of the M3 boot sequence.
//!
//! `l4core::hyperv` decides what the CPUID leaves mean and which synthetic
//! MSR each privilege allows; this file runs CPUID, reads and writes those
//! MSRs, and prints what the firmware left. Every synthetic MSR access is
//! behind its privilege bit, so none can fault.

use l4core::hyperv::{self as hv, Detection, HypercallMsr, LEFTOVERS, Privileges};

use super::StaticCell;
use super::cpu::{cpuid, read_msr, write_msr};

/// What step 5 learnt about Hyper-V.
pub struct Info {
    /// The partition reference counter, if the partition may read it.
    pub reference_counter: Option<ReferenceCounter>,
    /// `HV_X64_MSR_APIC_FREQUENCY`, if the partition may read it.
    pub apic_hz: Option<u64>,
    /// `HV_X64_MSR_TSC_FREQUENCY`, likewise.
    pub tsc_hz: Option<u64>,
    /// The hypercall page the firmware locked enabled: M4 keeps it out of
    /// every untyped and the boot region.
    pub locked_hypercall_page: Option<u64>,
}

/// Hyper-V's partition reference counter, 100 ns per tick. Only [`init`]
/// makes one, and only with `AccessPartitionReferenceCounter`.
#[derive(Clone, Copy)]
pub struct ReferenceCounter(());

impl ReferenceCounter {
    pub fn read(&self) -> u64 {
        read_msr(hv::MSR_TIME_REF_COUNT)
    }
}

static INFO: StaticCell<Info> = StaticCell::new();

/// Detects the TLFS interface and, with each privilege, turns off what the
/// firmware left enabled: the synthetic timers (one of which can raise an
/// NMI), the SINTs, the SynIC, the overlay pages and the hypercall page.
/// Prints each value found. Runs once, with interrupts off, before the
/// interrupt controllers are set up and before M4 reuses any memory.
pub fn init() -> &'static Info {
    let detection = hv::detect(|leaf| {
        let (a, b, c, d) = cpuid(leaf);
        [a, b, c, d]
    });
    match detection {
        Detection::HyperV { .. } => kprintln!("hyperv: {detection}"),
        _ => kprintln!("hyperv: no TLFS interface: {detection}"),
    }
    let mut info = Info {
        reference_counter: None,
        apic_hz: None,
        tsc_hz: None,
        locked_hypercall_page: None,
    };
    if let Some(p) = detection.privileges() {
        turn_off_leftovers(&p, &mut info);
        if p.reference_counter() {
            info.reference_counter = Some(ReferenceCounter(()));
            kprintln!(
                "hyperv: reference counter allowed, now {}",
                read_msr(hv::MSR_TIME_REF_COUNT)
            );
        } else {
            kprintln!("hyperv: no AccessPartitionReferenceCounter");
        }
        if p.frequency_msrs() {
            let (tsc, apic) = (
                read_msr(hv::MSR_TSC_FREQUENCY),
                read_msr(hv::MSR_APIC_FREQUENCY),
            );
            kprintln!("hyperv: frequency MSRs: TSC {tsc} Hz, APIC {apic} Hz");
            info.tsc_hz = Some(tsc);
            info.apic_hz = Some(apic);
        } else {
            kprintln!("hyperv: no frequency MSRs");
        }
    }
    INFO.init(info)
}

fn turn_off_leftovers(p: &Privileges, info: &mut Info) {
    let mut off = 0;
    // The synthetic timers first: they are interrupt sources.
    for l in &LEFTOVERS[..5] {
        off += turn_off(p, l);
    }
    if p.synic() {
        let mut unmasked = 0u16;
        for n in 0..hv::SINTS {
            let msr = hv::MSR_SINT0 + n;
            if let Some(v) = hv::sint_masked(read_msr(msr)) {
                // SAFETY: AccessSynicRegs allows the SINT MSRs; setting the
                // mask bit only stops the SINT interrupting.
                unsafe { write_msr(msr, v) };
                unmasked |= 1 << n;
            }
        }
        kprintln!("hyperv: SINTs found unmasked: {unmasked:#06x}; all masked");
        off += unmasked.count_ones();
    } else {
        kprintln!("hyperv: SINTs: no AccessSynicRegs");
    }
    for l in &LEFTOVERS[5..] {
        off += turn_off(p, l);
    }
    if p.hypercall_msrs() {
        let v = read_msr(hv::MSR_HYPERCALL);
        let state = HypercallMsr::of(v);
        if let Some(w) = HypercallMsr::off(v) {
            // SAFETY: AccessHypercallMsrs allows the MSR, and it is not
            // locked. Clearing the enable bit removes the hypercall
            // overlay; the kernel makes no hypercall before M9.
            unsafe { write_msr(hv::MSR_HYPERCALL, w) };
            off += 1;
        }
        info.locked_hypercall_page = state.locked_page();
        let what = match state {
            HypercallMsr::Off => "off",
            HypercallMsr::Enabled { .. } => "enabled, now off",
            HypercallMsr::Locked { enabled: true, .. } => {
                "LOCKED enabled: M4 keeps the page out of every untyped"
            }
            HypercallMsr::Locked { enabled: false, .. } => "LOCKED disabled",
        };
        kprintln!("hyperv: hypercall MSR {v:#x}: {what}");
    } else {
        kprintln!("hyperv: hypercall MSR: no AccessHypercallMsrs");
    }
    kprintln!("hyperv: {off} firmware leftovers turned off");
}

/// Prints leftover `l` as found and turns it off if it is on; returns 1 if
/// it was on.
fn turn_off(p: &Privileges, l: &hv::Leftover) -> u32 {
    if !(l.allowed)(p) {
        kprintln!("hyperv: {}: no privilege", l.name);
        return 0;
    }
    let v = read_msr(l.msr);
    match l.off(v) {
        Some(w) => {
            // SAFETY: the privilege `allowed` checks grants this MSR.
            // Clearing its enable bit stops a timer or removes an overlay
            // page; the kernel has not used either.
            unsafe { write_msr(l.msr, w) };
            kprintln!("hyperv: {} {v:#x}: enabled, now off", l.name);
            1
        }
        None => {
            kprintln!("hyperv: {} {v:#x}: off", l.name);
            0
        }
    }
}
