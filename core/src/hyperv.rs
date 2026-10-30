//! Hyper-V at boot (`docs/design.md`, "Hyper-V interface": "Detection
//! (M3)", "Firmware leftovers (M3)"): which CPUID leaves say the TLFS
//! interface is there, what the partition may touch, and which synthetic
//! MSRs the firmware may have left enabled, each with the privilege the
//! kernel needs before it reads or writes it. `arch` runs CPUID and the MSR
//! accesses; the kernel touches a synthetic MSR only if [`Privileges`] says
//! it may, so no synthetic MSR access can fault.
//!
//! Numbers and bits follow the TLFS (`feature-discovery.md`,
//! `hv_partition_privilege_mask.md`, `timers.md`,
//! `inter-partition-communication.md`, `vp-properties.md`,
//! `hypercall-interface.md`).

use core::fmt;

/// CPUID.1:ECX bit 31: a hypervisor is present.
pub const HYPERVISOR_PRESENT: u32 = 1 << 31;
/// The vendor leaf; EAX is the highest hypervisor leaf.
pub const LEAF_VENDOR: u32 = 0x4000_0000;
/// The interface leaf; EAX is the interface signature.
pub const LEAF_INTERFACE: u32 = 0x4000_0001;
/// The feature leaf: EAX and EBX the privilege mask, EDX more features.
pub const LEAF_FEATURES: u32 = 0x4000_0003;
/// The least highest leaf a TLFS hypervisor reports.
pub const MIN_MAX_LEAF: u32 = 0x4000_0005;
/// `"Hv#1"`, the TLFS interface signature.
pub const INTERFACE_HV1: u32 = 0x3123_7648;

/// `HV_X64_MSR_HYPERCALL`; see [`HypercallMsr`].
pub const MSR_HYPERCALL: u32 = 0x4000_0001;
/// `HV_X64_MSR_TIME_REF_COUNT`: the partition reference counter, 100 ns.
pub const MSR_TIME_REF_COUNT: u32 = 0x4000_0020;
/// `HV_X64_MSR_REFERENCE_TSC`: the reference TSC page.
pub const MSR_REFERENCE_TSC: u32 = 0x4000_0021;
/// `HV_X64_MSR_TSC_FREQUENCY`, in Hz.
pub const MSR_TSC_FREQUENCY: u32 = 0x4000_0022;
/// `HV_X64_MSR_APIC_FREQUENCY`: the local APIC timer's rate, in Hz.
pub const MSR_APIC_FREQUENCY: u32 = 0x4000_0023;
/// `HV_X64_MSR_VP_ASSIST_PAGE`.
pub const MSR_VP_ASSIST_PAGE: u32 = 0x4000_0073;
/// The SynIC control register.
pub const MSR_SCONTROL: u32 = 0x4000_0080;
/// The SynIC event flags page.
pub const MSR_SIEFP: u32 = 0x4000_0082;
/// The SynIC message page.
pub const MSR_SIMP: u32 = 0x4000_0083;
/// `SINT0`; `SINTn` is at `MSR_SINT0 + n`.
pub const MSR_SINT0: u32 = 0x4000_0090;
/// The SINT count.
pub const SINTS: u32 = 16;
/// `HV_X64_MSR_STIMER0_CONFIG`; timer `n`'s configuration is at
/// `MSR_STIMER0_CONFIG + 2 * n`.
pub const MSR_STIMER0_CONFIG: u32 = 0x4000_00B0;
/// `HV_X64_MSR_STIME_UNHALTED_TIMER_CONFIG`, which can deliver an NMI.
pub const MSR_TIME_UNHALTED_TIMER_CONFIG: u32 = 0x4000_0114;

/// A SINT's mask bit.
pub const SINT_MASKED: u64 = 1 << 16;
/// The enable bit of SCONTROL, SIMP, SIEFP, the reference TSC page, the VP
/// assist page and each synthetic timer's configuration.
pub const ENABLE: u64 = 1 << 0;
/// The time-unhalted timer's enable bit: bit 8, below which is its vector
/// (TLFS `timers.md`), unlike every other overlay and timer here.
pub const TIME_UNHALTED_ENABLE: u64 = 1 << 8;
/// The hypercall MSR's enable bit.
pub const HYPERCALL_ENABLE: u64 = 1 << 0;
/// The hypercall MSR's Locked bit: only a reset clears it.
pub const HYPERCALL_LOCKED: u64 = 1 << 1;

/// What CPUID leaf `0x4000_0003` grants: `HV_PARTITION_PRIVILEGE_MASK` in
/// EAX (bits 0-31) and EBX (bits 32-63), and the feature bits in EDX.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Privileges {
    pub eax: u32,
    pub ebx: u32,
    pub edx: u32,
}

impl Privileges {
    fn eax(&self, bit: u32) -> bool {
        self.eax >> bit & 1 == 1
    }

    /// `AccessPartitionReferenceCounter` (EAX 1): [`MSR_TIME_REF_COUNT`],
    /// the calibration reference.
    pub fn reference_counter(&self) -> bool {
        self.eax(1)
    }

    /// `AccessSynicRegs` (EAX 2): SCONTROL to EOM and the SINTs.
    pub fn synic(&self) -> bool {
        self.eax(2)
    }

    /// `AccessSyntheticTimerRegs` (EAX 3): the four synthetic timers.
    pub fn synthetic_timers(&self) -> bool {
        self.eax(3)
    }

    /// The time-unhalted timer: `AccessSyntheticTimerRegs` and EDX bit 23,
    /// "synthetic time-unhalted timer available" (TLFS `timers.md`).
    pub fn time_unhalted_timer(&self) -> bool {
        self.synthetic_timers() && self.edx >> 23 & 1 == 1
    }

    /// `AccessIntrCtrlRegs` (EAX 4): the APIC MSRs and, as KVM's Hyper-V
    /// emulation gates it (`hv_check_msr_access`), the VP assist page; the
    /// TLFS names no privilege for that page.
    pub fn interrupt_control(&self) -> bool {
        self.eax(4)
    }

    /// `AccessHypercallMsrs` (EAX 5): the guest OS ID and hypercall MSRs.
    pub fn hypercall_msrs(&self) -> bool {
        self.eax(5)
    }

    /// `AccessVpIndex` (EAX 6).
    pub fn vp_index(&self) -> bool {
        self.eax(6)
    }

    /// `AccessPartitionReferenceTsc` (EAX 9): the reference TSC page.
    pub fn reference_tsc(&self) -> bool {
        self.eax(9)
    }

    /// The TSC and APIC frequency MSRs: `AccessFrequencyRegs` (EAX 11) and
    /// EDX bit 8, "timer frequency query available", both of which Linux
    /// and FreeBSD require.
    pub fn frequency_msrs(&self) -> bool {
        self.eax(11) && self.edx >> 8 & 1 == 1
    }

    /// `PostMessages` (EBX 4).
    pub fn post_messages(&self) -> bool {
        self.ebx >> 4 & 1 == 1
    }

    /// `SignalEvents` (EBX 5).
    pub fn signal_events(&self) -> bool {
        self.ebx >> 5 & 1 == 1
    }
}

/// What detection found (`docs/design.md`, "Detection (M3)").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Detection {
    /// CPUID.1:ECX bit 31 is clear.
    NoHypervisor,
    /// The highest hypervisor leaf is below [`MIN_MAX_LEAF`].
    MaxLeaf(u32),
    /// The interface signature is not `"Hv#1"`.
    Interface(u32),
    /// The TLFS interface, with what it grants.
    HyperV {
        max_leaf: u32,
        privileges: Privileges,
    },
}

impl Detection {
    /// The privileges, if the TLFS interface is there.
    pub fn privileges(&self) -> Option<Privileges> {
        match *self {
            Self::HyperV { privileges, .. } => Some(privileges),
            _ => None,
        }
    }
}

impl fmt::Display for Detection {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoHypervisor => f.write_str("no hypervisor-present bit"),
            Self::MaxLeaf(max) => write!(f, "highest leaf {max:#x}, below {MIN_MAX_LEAF:#x}"),
            Self::Interface(sig) => {
                f.write_str("interface \"")?;
                for b in sig.to_le_bytes() {
                    if b.is_ascii_graphic() || b == b' ' {
                        write!(f, "{}", b as char)?;
                    } else {
                        write!(f, "\\x{b:02x}")?;
                    }
                }
                f.write_str("\", not \"Hv#1\"")
            }
            Self::HyperV {
                max_leaf,
                privileges: p,
            } => write!(
                f,
                "interface \"Hv#1\", highest leaf {max_leaf:#x}, privileges EAX {:#x} EBX {:#x}, features EDX {:#x}",
                p.eax, p.ebx, p.edx
            ),
        }
    }
}

/// Detects the TLFS interface: CPUID.1:ECX bit 31, then leaf
/// `0x4000_0000` EAX at least `0x4000_0005`, then leaf `0x4000_0001` EAX =
/// `"Hv#1"`, which the TLFS says to base compatibility on rather than the
/// vendor string; only then leaf `0x4000_0003`. `cpuid(leaf)` returns
/// `[eax, ebx, ecx, edx]` for sub-leaf 0, and no leaf is read before the
/// check that makes it meaningful.
pub fn detect(mut cpuid: impl FnMut(u32) -> [u32; 4]) -> Detection {
    if cpuid(1)[2] & HYPERVISOR_PRESENT == 0 {
        return Detection::NoHypervisor;
    }
    let max_leaf = cpuid(LEAF_VENDOR)[0];
    if max_leaf < MIN_MAX_LEAF {
        return Detection::MaxLeaf(max_leaf);
    }
    let interface = cpuid(LEAF_INTERFACE)[0];
    if interface != INTERFACE_HV1 {
        return Detection::Interface(interface);
    }
    let [eax, ebx, _, edx] = cpuid(LEAF_FEATURES);
    Detection::HyperV {
        max_leaf,
        privileges: Privileges { eax, ebx, edx },
    }
}

/// A synthetic MSR whose enable bit the firmware may have left set, and the
/// privilege the kernel needs to touch it.
#[derive(Clone, Copy)]
pub struct Leftover {
    pub name: &'static str,
    pub msr: u32,
    /// The bit that, set, means the firmware left it on.
    pub enable: u64,
    pub allowed: fn(&Privileges) -> bool,
}

impl Leftover {
    /// The value to write to turn it off, every other bit as read, or
    /// `None` if it is already off.
    pub const fn off(&self, value: u64) -> Option<u64> {
        if value & self.enable == 0 {
            None
        } else {
            Some(value & !self.enable)
        }
    }
}

impl fmt::Debug for Leftover {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{} ({:#x})", self.name, self.msr)
    }
}

const fn leftover(
    name: &'static str,
    msr: u32,
    enable: u64,
    allowed: fn(&Privileges) -> bool,
) -> Leftover {
    Leftover {
        name,
        msr,
        enable,
        allowed,
    }
}

/// Every overlay page and timer the firmware may have left on, except the
/// SINTs ([`sint_masked`]) and the hypercall page ([`HypercallMsr`]), in the
/// order the kernel turns them off: interrupt sources first (the
/// synthetic timers, one of which can raise an NMI), then the SynIC and
/// the overlay pages (`docs/design.md`, "Firmware leftovers (M3)").
pub const LEFTOVERS: [Leftover; 10] = [
    leftover(
        "synthetic timer 0",
        MSR_STIMER0_CONFIG,
        ENABLE,
        Privileges::synthetic_timers,
    ),
    leftover(
        "synthetic timer 1",
        MSR_STIMER0_CONFIG + 2,
        ENABLE,
        Privileges::synthetic_timers,
    ),
    leftover(
        "synthetic timer 2",
        MSR_STIMER0_CONFIG + 4,
        ENABLE,
        Privileges::synthetic_timers,
    ),
    leftover(
        "synthetic timer 3",
        MSR_STIMER0_CONFIG + 6,
        ENABLE,
        Privileges::synthetic_timers,
    ),
    leftover(
        "time-unhalted timer",
        MSR_TIME_UNHALTED_TIMER_CONFIG,
        TIME_UNHALTED_ENABLE,
        Privileges::time_unhalted_timer,
    ),
    leftover("SCONTROL", MSR_SCONTROL, ENABLE, Privileges::synic),
    leftover("SIMP", MSR_SIMP, ENABLE, Privileges::synic),
    leftover("SIEFP", MSR_SIEFP, ENABLE, Privileges::synic),
    leftover(
        "reference TSC page",
        MSR_REFERENCE_TSC,
        ENABLE,
        Privileges::reference_tsc,
    ),
    leftover(
        "VP assist page",
        MSR_VP_ASSIST_PAGE,
        ENABLE,
        Privileges::interrupt_control,
    ),
];

/// A SINT's value with its mask bit set and every other bit as read, or
/// `None` if it is already masked. Touch the SINTs only with
/// [`Privileges::synic`].
pub const fn sint_masked(value: u64) -> Option<u64> {
    if value & SINT_MASKED != 0 {
        None
    } else {
        Some(value | SINT_MASKED)
    }
}

/// The hypercall MSR as the firmware left it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HypercallMsr {
    /// Disabled and not locked: nothing to do.
    Off,
    /// Enabled over `page` and not locked: the kernel disables it.
    Enabled { page: u64 },
    /// Locked: nothing can move or disable it until a reset. If enabled, the
    /// hypervisor overlays `page` for good, so M4 keeps it out of every
    /// untyped and the boot region.
    Locked { page: u64, enabled: bool },
}

impl HypercallMsr {
    pub const fn of(value: u64) -> Self {
        let page = value & !0xFFF;
        let enabled = value & HYPERCALL_ENABLE != 0;
        if value & HYPERCALL_LOCKED != 0 {
            Self::Locked { page, enabled }
        } else if enabled {
            Self::Enabled { page }
        } else {
            Self::Off
        }
    }

    /// The value that disables an unlocked, enabled hypercall page, every
    /// other bit as read.
    pub const fn off(value: u64) -> Option<u64> {
        match Self::of(value) {
            Self::Enabled { .. } => Some(value & !HYPERCALL_ENABLE),
            Self::Off | Self::Locked { .. } => None,
        }
    }

    /// The page the hypervisor overlays for good, if any.
    pub const fn locked_page(self) -> Option<u64> {
        match self {
            Self::Locked {
                page,
                enabled: true,
            } => Some(page),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::string::ToString;
    use std::vec::Vec;

    /// A Generation 2 guest's leaf `0x4000_0003` as Linux's boot log
    /// commonly shows it: "privilege flags low 0x2e7f, high 0x3b8030 ...
    /// misc 0xbed7b2".
    const GEN2: Privileges = Privileges {
        eax: 0x2E7F,
        ebx: 0x3B_8030,
        edx: 0xBE_D7B2,
    };

    /// Runs detection on `table` and returns the result and the leaves
    /// read, in order.
    fn run(table: &[(u32, [u32; 4])]) -> (Detection, Vec<u32>) {
        let mut asked = Vec::new();
        let d = detect(|leaf| {
            asked.push(leaf);
            table
                .iter()
                .find(|(l, _)| *l == leaf)
                .map_or([0; 4], |(_, r)| *r)
        });
        (d, asked)
    }

    const PRESENT: (u32, [u32; 4]) = (1, [0, 0, HYPERVISOR_PRESENT, 0]);

    #[test]
    fn hyper_v_generation_2() {
        let (d, asked) = run(&[
            PRESENT,
            (LEAF_VENDOR, [0x4000_000B, 0, 0, 0]),
            (LEAF_INTERFACE, [INTERFACE_HV1, 0, 0, 0]),
            (LEAF_FEATURES, [GEN2.eax, GEN2.ebx, 0xDEAD, GEN2.edx]),
        ]);
        assert_eq!(
            d,
            Detection::HyperV {
                max_leaf: 0x4000_000B,
                privileges: GEN2
            }
        );
        assert_eq!(asked, [1, LEAF_VENDOR, LEAF_INTERFACE, LEAF_FEATURES]);
        assert_eq!(
            d.to_string(),
            "interface \"Hv#1\", highest leaf 0x4000000b, privileges EAX 0x2e7f EBX 0x3b8030, features EDX 0xbed7b2"
        );
        let p = d.privileges().unwrap();
        assert!(p.reference_counter() && p.synic() && p.synthetic_timers());
        assert!(p.interrupt_control() && p.hypercall_msrs() && p.vp_index());
        assert!(p.reference_tsc() && p.frequency_msrs() && p.time_unhalted_timer());
        assert!(p.post_messages() && p.signal_events());
    }

    #[test]
    fn no_hypervisor_reads_nothing_more() {
        let (d, asked) = run(&[(LEAF_VENDOR, [0x4000_0010, 0, 0, 0])]);
        assert_eq!(d, Detection::NoHypervisor);
        assert_eq!(asked, [1]);
        assert_eq!(d.privileges(), None);
    }

    #[test]
    fn qemu_tcg_is_not_hyper_v() {
        // TCG reports its vendor with a highest leaf below 0x40000005.
        let (d, asked) = run(&[PRESENT, (LEAF_VENDOR, [0x4000_0001, 0, 0, 0])]);
        assert_eq!(d, Detection::MaxLeaf(0x4000_0001));
        assert_eq!(asked, [1, LEAF_VENDOR]);
        assert_eq!(d.to_string(), "highest leaf 0x40000001, below 0x40000005");
    }

    #[test]
    fn the_interface_signature_decides_not_the_vendor() {
        // KVM with Hyper-V enlightenments says "Hv#1" under its own vendor
        // string; a vendor that says "Microsoft Hv" with another interface
        // is not the TLFS.
        let (d, asked) = run(&[
            PRESENT,
            (LEAF_VENDOR, [0x4000_0005, 0, 0, 0]),
            (LEAF_INTERFACE, [0x3123_7656, 0, 0, 0]),
        ]);
        assert_eq!(d, Detection::Interface(0x3123_7656));
        assert_eq!(asked, [1, LEAF_VENDOR, LEAF_INTERFACE]);
        assert_eq!(d.to_string(), "interface \"Vv#1\", not \"Hv#1\"");
        assert_eq!(
            Detection::Interface(0).to_string(),
            "interface \"\\x00\\x00\\x00\\x00\", not \"Hv#1\""
        );
    }

    #[test]
    fn without_privileges_no_synthetic_msr_is_touched() {
        let none = Privileges::default();
        assert!(LEFTOVERS.iter().all(|l| !(l.allowed)(&none)));
        assert!(!none.reference_counter() && !none.frequency_msrs());
        assert!(!none.synic() && !none.hypercall_msrs());
        // EDX alone grants nothing.
        let edx_only = Privileges {
            edx: u32::MAX,
            ..none
        };
        assert!(LEFTOVERS.iter().all(|l| !(l.allowed)(&edx_only)));
        assert!(!edx_only.frequency_msrs());
    }

    #[test]
    fn each_leftover_needs_exactly_its_privilege() {
        let bit = |n: u32| Privileges {
            eax: 1 << n,
            ..Default::default()
        };
        let allowed_by = |n: u32| -> Vec<&str> {
            LEFTOVERS
                .iter()
                .filter(|l| (l.allowed)(&bit(n)))
                .map(|l| l.name)
                .collect()
        };
        assert_eq!(
            allowed_by(3),
            [
                "synthetic timer 0",
                "synthetic timer 1",
                "synthetic timer 2",
                "synthetic timer 3"
            ]
        );
        assert_eq!(allowed_by(2), ["SCONTROL", "SIMP", "SIEFP"]);
        assert_eq!(allowed_by(9), ["reference TSC page"]);
        assert_eq!(allowed_by(4), ["VP assist page"]);
        for n in [0, 1, 5, 6, 7, 8, 10, 11, 12, 13] {
            assert!(allowed_by(n).is_empty(), "EAX bit {n}");
        }
        // The time-unhalted timer needs EDX bit 23 as well.
        let unhalted = Privileges {
            eax: 1 << 3,
            ebx: 0,
            edx: 1 << 23,
        };
        assert!((LEFTOVERS[4].allowed)(&unhalted) && !(LEFTOVERS[4].allowed)(&bit(3)));
    }

    #[test]
    fn msr_numbers() {
        let msrs: Vec<u32> = LEFTOVERS.iter().map(|l| l.msr).collect();
        assert_eq!(
            msrs,
            [
                0x4000_00B0,
                0x4000_00B2,
                0x4000_00B4,
                0x4000_00B6,
                0x4000_0114,
                0x4000_0080,
                0x4000_0083,
                0x4000_0082,
                0x4000_0021,
                0x4000_0073
            ]
        );
        assert_eq!(MSR_SINT0 + SINTS - 1, 0x4000_009F);
    }

    #[test]
    fn turning_off_keeps_every_other_bit() {
        let simp = &LEFTOVERS[6];
        assert_eq!(simp.off(0x1FE0_1000), None);
        assert_eq!(simp.off(0x1FE0_1001), Some(0x1FE0_1000));
        assert_eq!(simp.off(0x1FE0_1FF1), Some(0x1FE0_1FF0));
        // The time-unhalted timer's enable is bit 8; its vector stays.
        let unhalted = &LEFTOVERS[4];
        assert_eq!(unhalted.off(0x002), None);
        assert_eq!(unhalted.off(0x102), Some(0x002));
        // A synthetic timer: enabled, periodic, SINT 2.
        assert_eq!(LEFTOVERS[0].off(0x2_0003), Some(0x2_0002));
        assert_eq!(sint_masked(0x1_0000), None);
        assert_eq!(sint_masked(0x2_00F0), Some(0x3_00F0));
    }

    #[test]
    fn hypercall_msr_states() {
        assert_eq!(HypercallMsr::of(0), HypercallMsr::Off);
        assert_eq!(HypercallMsr::of(0x1234_5000), HypercallMsr::Off);
        assert_eq!(
            HypercallMsr::of(0x1234_5001),
            HypercallMsr::Enabled { page: 0x1234_5000 }
        );
        assert_eq!(HypercallMsr::off(0x1234_5001), Some(0x1234_5000));
        let locked = HypercallMsr::of(0x1234_5003);
        assert_eq!(
            locked,
            HypercallMsr::Locked {
                page: 0x1234_5000,
                enabled: true
            }
        );
        assert_eq!(locked.locked_page(), Some(0x1234_5000));
        assert_eq!(
            HypercallMsr::off(0x1234_5003),
            None,
            "locked: never written"
        );
        assert_eq!(HypercallMsr::of(0x1234_5002).locked_page(), None);
        assert_eq!(HypercallMsr::off(0), None);
    }
}
