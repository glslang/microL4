//! Hyper-V at boot (`docs/design.md`, "Hyper-V interface": "Detection
//! (M3)", "Firmware leftovers (M3)"): which CPUID leaves say the TLFS
//! interface is there, what the partition may touch, and which synthetic
//! MSRs the firmware may have left enabled, each with the privilege the
//! kernel needs before it reads or writes it. `arch` runs CPUID and the MSR
//! accesses; the kernel touches a synthetic MSR only if [`Privileges`] says
//! it may, so no synthetic MSR access can fault.
//!
//! From M9 (`docs/design.md`, "Hypercalls (M9)", "SynIC (M9)", "The
//! Hypervisor capability (M9)"; ADR 0029): the guest OS ID, the hypercall
//! MSR's value and the read-back decision, the SynIC registers' values,
//! the two hypercalls' input values and `PostMessage`'s input block; and in
//! [`invocation`], the Hypervisor capability's fields, Mint's narrowing,
//! the permission check and the invocations, performed through the
//! [`Hypercalls`] trait the kernel implements in `arch/x86_64/hyperv.rs`.
//!
//! Numbers and bits follow the TLFS (`feature-discovery.md`,
//! `hv_partition_privilege_mask.md`, `timers.md`,
//! `inter-partition-communication.md`, `vp-properties.md`,
//! `hypercall-interface.md`, `HvCallPostMessage.md`,
//! `HvCallSignalEvent.md`, `hv_status.md`).

use core::fmt;

pub mod invocation;

pub use invocation::{Hypercalls, HypervisorCap, PostMessage, SignalEvent, hypervisor_cap};

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

// ---------------------------------------------------------------------------
// M9: hypercalls and the SynIC
// ---------------------------------------------------------------------------

/// `HV_X64_MSR_GUEST_OS_ID`.
pub const MSR_GUEST_OS_ID: u32 = 0x4000_0000;
/// `HV_X64_MSR_VP_INDEX`: this processor's VP index.
pub const MSR_VP_INDEX: u32 = 0x4000_0002;
/// The SynIC end-of-message register: a write of 0 makes the hypervisor
/// try to deliver the next queued message.
pub const MSR_EOM: u32 = 0x4000_0084;

/// The guest OS identity the kernel writes before the hypercall page
/// (ADR 0029): bit 63 set, the TLFS's encoding for an open-source system;
/// OS type 0, as Microsoft has allocated none for microL4; OS ID,
/// version and build 0, since the kernel has no release numbers. The TLFS
/// needs only a non-zero value before the page will enable.
pub const GUEST_OS_ID: u64 = 0x8000_0000_0000_0000;

/// The hypercall MSR's bits 11:2: RsvdP, "preserved on writes".
pub const HYPERCALL_RSVDP: u64 = 0xFFC;
/// SIMP's and SIEFP's bits 11:1: reserved, preserved.
pub const OVERLAY_RSVDP: u64 = 0xFFE;
/// A page's address bits, 63:12.
const PAGE_BITS: u64 = !0xFFF;

/// A SINT's vector, bits 7:0.
pub const SINT_VECTOR: u64 = 0xFF;
/// A SINT's AutoEOI bit.
pub const SINT_AUTO_EOI: u64 = 1 << 17;
/// A SINT's polling bit.
pub const SINT_POLLING: u64 = 1 << 18;
/// The lowest vector a SINT takes: a SINT write with a vector below 16
/// is `#GP` (TLFS).
pub const SINT_MIN_VECTOR: u8 = 16;

/// The privileges the Hypervisor capability needs, each with its TLFS
/// name, in the order the kernel checks them (`docs/design.md`,
/// "Detection (M3)"): the SynIC registers, the hypercall MSRs, the VP
/// index, and the two hypercalls.
pub const M9_PRIVILEGES: [(&str, fn(&Privileges) -> bool); 5] = [
    ("AccessSynicRegs", Privileges::synic),
    ("AccessHypercallMsrs", Privileges::hypercall_msrs),
    ("AccessVpIndex", Privileges::vp_index),
    ("PostMessages", Privileges::post_messages),
    ("SignalEvents", Privileges::signal_events),
];

/// The first M9 privilege `p` lacks, if any.
pub fn missing_m9_privilege(p: &Privileges) -> Option<&'static str> {
    M9_PRIVILEGES
        .iter()
        .find(|(_, has)| !has(p))
        .map(|&(name, _)| name)
}

/// Why the kernel makes no Hypervisor capability, and so sets up no
/// SynIC: initial slots 12, 13 and 14 are null and `GetSint` is
/// `IllegalOperation` (ADR 0029). A debug kernel prints it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unavailable {
    /// No TLFS interface: not Hyper-V, as under QEMU's TCG.
    NoInterface,
    /// The partition lacks this M9 privilege.
    Privilege(&'static str),
    /// The firmware locked the hypercall MSR, disabled or over a page
    /// that is not `.hvcall`: only a reset could move it.
    Locked { page: u64, enabled: bool },
    /// The hypercall MSR, written with `.hvcall` and the enable bit, read
    /// back as this: not enabled at `.hvcall`, as the TLFS says it reads
    /// when no guest OS identity was accepted.
    NotEnabled { read_back: u64 },
}

impl fmt::Display for Unavailable {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Self::NoInterface => f.write_str("no TLFS interface"),
            Self::Privilege(name) => write!(f, "no {name} privilege"),
            Self::Locked {
                page,
                enabled: true,
            } => write!(
                f,
                "the firmware locked the hypercall page at {page:#x}, not .hvcall"
            ),
            Self::Locked { enabled: false, .. } => {
                f.write_str("the firmware locked the hypercall MSR disabled")
            }
            Self::NotEnabled { read_back } => write!(
                f,
                "the hypercall MSR read back {read_back:#x}, not enabled at .hvcall"
            ),
        }
    }
}

/// What the kernel does with the hypercall MSR, read once the overlay
/// reset is done and the guest OS ID written, for the hypercall page at
/// physical `page` (`.hvcall`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HypercallStep {
    /// Write this value, then read the MSR back ([`hypercall_enabled_at`]).
    Write(u64),
    /// The firmware locked it enabled at `page` already: nothing to write.
    Ready,
    /// No hypercall page: locked elsewhere, or locked disabled.
    Unavailable(Unavailable),
}

/// The hypercall MSR's value that enables the page at `page`, from its
/// value `old`: the page number in bits 63:12, bits 11:2 as read (RsvdP),
/// Locked (bit 1) clear, the enable bit set (TLFS "Establishing the
/// Hypercall Interface"; FreeBSD's `hypercall_page_setup`).
pub const fn hypercall_enable(old: u64, page: u64) -> u64 {
    (page & PAGE_BITS) | (old & HYPERCALL_RSVDP) | HYPERCALL_ENABLE
}

/// The step for the hypercall MSR reading `old`, for `.hvcall` at `page`.
pub const fn hypercall_step(old: u64, page: u64) -> HypercallStep {
    match HypercallMsr::of(old) {
        HypercallMsr::Locked {
            page: p,
            enabled: true,
        } if p == page & PAGE_BITS => HypercallStep::Ready,
        HypercallMsr::Locked { page, enabled } => {
            HypercallStep::Unavailable(Unavailable::Locked { page, enabled })
        }
        HypercallMsr::Off | HypercallMsr::Enabled { .. } => {
            HypercallStep::Write(hypercall_enable(old, page))
        }
    }
}

/// Whether the hypercall MSR, read back as `read_back`, has the page
/// enabled at `page`. Only then may anything call `.hvcall`: a page that
/// did not enable still holds its `int3` filler (ADR 0029).
pub const fn hypercall_enabled_at(read_back: u64, page: u64) -> bool {
    read_back & HYPERCALL_ENABLE != 0 && read_back & PAGE_BITS == page & PAGE_BITS
}

/// SIMP's or SIEFP's value that enables the overlay at `page`, from its
/// value `old`: the page number, bits 11:1 as read, the enable bit.
pub const fn overlay_enable(old: u64, page: u64) -> u64 {
    (page & PAGE_BITS) | (old & OVERLAY_RSVDP) | ENABLE
}

/// SCONTROL's value with the SynIC enabled, every other bit as read.
pub const fn scontrol_enable(old: u64) -> u64 {
    old | ENABLE
}

/// SINTn's value once `GetSint` issues it, from its value `old`: `vector`,
/// unmasked, AutoEOI off, polling off, every reserved bit as read
/// (`docs/design.md`, "SynIC (M9)"). AutoEOI stays off because the
/// interrupt path EOIs every device vector itself. `vector` is a device
/// vector, `0x30` to `0xEF`, so at least [`SINT_MIN_VECTOR`].
pub const fn sint_issued(old: u64, vector: u8) -> u64 {
    debug_assert!(vector >= SINT_MIN_VECTOR);
    (old & !(SINT_VECTOR | SINT_MASKED | SINT_AUTO_EOI | SINT_POLLING)) | vector as u64
}

/// SINTn's value once its last handler is deleted: the mask bit set,
/// every other bit as read.
pub const fn sint_deleted(old: u64) -> u64 {
    old | SINT_MASKED
}

/// `HvCallPostMessage`'s call code.
pub const CALL_POST_MESSAGE: u64 = 0x005C;
/// `HvCallSignalEvent`'s call code.
pub const CALL_SIGNAL_EVENT: u64 = 0x005D;
/// The hypercall input value's fast bit: input in registers.
pub const FAST: u64 = 1 << 16;
/// `PostMessage`'s input value: memory-based, no rep count, no variable
/// header.
pub const POST_MESSAGE_INPUT: u64 = CALL_POST_MESSAGE;
/// `SignalEvent`'s input value: fast, its 8 bytes in `rdx`.
pub const SIGNAL_EVENT_INPUT: u64 = FAST | CALL_SIGNAL_EVENT;
/// `rax` bits 0-15, the `HV_STATUS`, after a hypercall.
pub const STATUS_MASK: u64 = 0xFFFF;

/// The `HV_STATUS` values the two hypercalls can return once the kernel's
/// checks pass (`docs/abi.md`, "Hypervisor").
pub mod status {
    pub const SUCCESS: u16 = 0x00;
    pub const INVALID_PARAMETER: u16 = 0x05;
    pub const INVALID_VP_INDEX: u16 = 0x0E;
    pub const INVALID_PORT_ID: u16 = 0x11;
    pub const INVALID_CONNECTION_ID: u16 = 0x12;
    pub const INSUFFICIENT_BUFFERS: u16 = 0x13;
    pub const INVALID_SYNIC_STATE: u16 = 0x18;
}

/// Connection IDs are below `2^24`.
pub const CONNECTIONS: u64 = 1 << 24;
/// The highest message type: types are 1 to `2^31 - 1`.
pub const MAX_MESSAGE_TYPE: u64 = 0x7FFF_FFFF;
/// The most payload bytes one message carries.
pub const MAX_PAYLOAD: u64 = 240;
/// Event flags are below `2^16`.
pub const FLAGS: u64 = 1 << 16;
/// `HV_INPUT_POST_MESSAGE`, 256 bytes, as words.
pub const BLOCK_WORDS: usize = 32;
/// The words before the payload: connection and reserved, then message
/// type and payload size.
pub const BLOCK_HEADER_WORDS: usize = 2;

/// `PostMessage`'s whole input block (`HvCallPostMessage.md`): connection
/// ID (4 bytes), reserved 0 (4), message type (4), payload size (4), then
/// the 240 payload bytes, those past `size` zero. `payload` gives the
/// payload as little-endian words, byte `i` in byte `i mod 8` of word
/// `i / 8`, as the message registers carry it; bytes past `size`, and
/// words past the 30th, are ignored. A `size` above [`MAX_PAYLOAD`] counts
/// as 240.
pub fn post_message_block(
    connection: u32,
    message_type: u32,
    size: u32,
    payload: &[u64],
) -> [u64; BLOCK_WORDS] {
    let size = u64::from(size).min(MAX_PAYLOAD);
    let mut block = [0u64; BLOCK_WORDS];
    block[0] = u64::from(connection);
    block[1] = u64::from(message_type) | size << 32;
    for (i, w) in block[BLOCK_HEADER_WORDS..].iter_mut().enumerate() {
        let bytes = size.saturating_sub(8 * i as u64).min(8);
        let mask = if bytes == 8 {
            u64::MAX
        } else {
            (1u64 << (8 * bytes)) - 1
        };
        *w = payload.get(i).copied().unwrap_or(0) & mask;
    }
    block
}

/// A block's fields, as a host reads them: connection ID, the reserved
/// word, message type, payload size and the 240 payload bytes. For the
/// mock host's tests.
pub fn parse_post_message_block(block: &[u64; BLOCK_WORDS]) -> (u32, u32, u32, u32, [u8; 240]) {
    let mut payload = [0u8; 240];
    for (chunk, w) in payload
        .chunks_exact_mut(8)
        .zip(&block[BLOCK_HEADER_WORDS..])
    {
        chunk.copy_from_slice(&w.to_le_bytes());
    }
    (
        block[0] as u32,
        (block[0] >> 32) as u32,
        block[1] as u32,
        (block[1] >> 32) as u32,
        payload,
    )
}

/// `SignalEvent`'s 8 bytes of input, passed in `rdx`
/// (`HvCallSignalEvent.md`): the connection ID in bits 0-31, the flag
/// number in bits 32-47, bits 48-63 reserved 0. `connection` is below
/// `2^24`.
pub const fn signal_event_input(connection: u32, flag: u16) -> u64 {
    connection as u64 | (flag as u64) << 32
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

    // M9.

    /// `.hvcall`'s physical page in these tests.
    const HVCALL: u64 = 0x0123_4000;

    #[test]
    fn the_guest_os_id_is_open_source_with_every_other_field_zero() {
        assert_eq!(GUEST_OS_ID, 1 << 63);
        assert_ne!(GUEST_OS_ID, 0, "the TLFS needs a non-zero ID");
        // OS type (62:56), OS ID (55:48), version (47:16), build (15:0).
        assert_eq!(GUEST_OS_ID >> 56 & 0x7F, 0);
        assert_eq!(GUEST_OS_ID & ((1 << 56) - 1), 0);
        assert_eq!(
            (MSR_GUEST_OS_ID, MSR_HYPERCALL, MSR_VP_INDEX, MSR_EOM),
            (0x4000_0000, 0x4000_0001, 0x4000_0002, 0x4000_0084)
        );
    }

    #[test]
    fn the_hypercall_msr_keeps_bits_11_to_2_and_never_locks() {
        assert_eq!(hypercall_enable(0, HVCALL), HVCALL | 1);
        // RsvdP bits as read; Locked, the old enable and the old page not.
        assert_eq!(hypercall_enable(0xFFF, HVCALL), HVCALL | 0xFFD);
        assert_eq!(
            hypercall_enable(0xDEAD_B000 | 0x5A4, HVCALL),
            HVCALL | 0x5A5
        );
        // A page number with low bits set is the page.
        assert_eq!(hypercall_enable(0, HVCALL | 0x123), HVCALL | 1);
        assert_eq!(HYPERCALL_RSVDP, 0b1111_1111_1100);
    }

    #[test]
    fn the_hypercall_step_for_each_state_the_firmware_can_leave() {
        // Off, or enabled elsewhere (M3 turned that off already): write.
        assert_eq!(
            hypercall_step(0x8, HVCALL),
            HypercallStep::Write(HVCALL | 0x9)
        );
        assert_eq!(
            hypercall_step(0xDEAD_B001, HVCALL),
            HypercallStep::Write(HVCALL | 1)
        );
        // Locked enabled at `.hvcall`: ready as it is.
        assert_eq!(hypercall_step(HVCALL | 3, HVCALL), HypercallStep::Ready);
        // Locked anywhere else, or disabled: no hypercall page.
        assert_eq!(
            hypercall_step(0xDEAD_B003, HVCALL),
            HypercallStep::Unavailable(Unavailable::Locked {
                page: 0xDEAD_B000,
                enabled: true
            })
        );
        assert_eq!(
            hypercall_step(HVCALL | 2, HVCALL),
            HypercallStep::Unavailable(Unavailable::Locked {
                page: HVCALL,
                enabled: false
            })
        );
    }

    #[test]
    fn only_a_read_back_enabled_at_hvcall_lets_anything_call_the_page() {
        assert!(hypercall_enabled_at(HVCALL | 1, HVCALL));
        assert!(hypercall_enabled_at(HVCALL | 0xFFD, HVCALL));
        assert!(hypercall_enabled_at(HVCALL | 3, HVCALL), "locked enabled");
        // The TLFS: with no guest OS ID the enable bit stays 0.
        assert!(!hypercall_enabled_at(HVCALL, HVCALL));
        assert!(!hypercall_enabled_at(0, HVCALL));
        assert!(!hypercall_enabled_at(0xDEAD_B001, HVCALL));
        assert!(!hypercall_enabled_at(HVCALL + 0x1000 | 1, HVCALL));
    }

    #[test]
    fn the_hypervisor_capability_needs_all_five_m9_privileges() {
        assert_eq!(missing_m9_privilege(&GEN2), None);
        let all = Privileges {
            eax: 1 << 2 | 1 << 5 | 1 << 6,
            ebx: 1 << 4 | 1 << 5,
            edx: 0,
        };
        assert_eq!(missing_m9_privilege(&all), None);
        for (bit, ebx, name) in [
            (2, false, "AccessSynicRegs"),
            (5, false, "AccessHypercallMsrs"),
            (6, false, "AccessVpIndex"),
            (4, true, "PostMessages"),
            (5, true, "SignalEvents"),
        ] {
            let mut p = all;
            if ebx {
                p.ebx &= !(1 << bit);
            } else {
                p.eax &= !(1 << bit);
            }
            assert_eq!(missing_m9_privilege(&p), Some(name), "{name}");
        }
        assert_eq!(
            missing_m9_privilege(&Privileges::default()),
            Some("AccessSynicRegs")
        );
    }

    #[test]
    fn why_there_is_no_hypervisor_capability() {
        let lines = [
            (Unavailable::NoInterface, "no TLFS interface"),
            (
                Unavailable::Privilege("PostMessages"),
                "no PostMessages privilege",
            ),
            (
                Unavailable::Locked {
                    page: 0xDEAD_B000,
                    enabled: true,
                },
                "the firmware locked the hypercall page at 0xdeadb000, not .hvcall",
            ),
            (
                Unavailable::Locked {
                    page: 0,
                    enabled: false,
                },
                "the firmware locked the hypercall MSR disabled",
            ),
            (
                Unavailable::NotEnabled {
                    read_back: HVCALL | 0x8,
                },
                "the hypercall MSR read back 0x1234008, not enabled at .hvcall",
            ),
        ];
        for (u, line) in lines {
            assert_eq!(u.to_string(), line);
        }
    }

    #[test]
    fn synic_registers_keep_their_reserved_bits() {
        let page = 0x1FE0_3000;
        assert_eq!(overlay_enable(0, page), page | 1);
        assert_eq!(overlay_enable(0xFFE, page), page | 0xFFF);
        // The firmware's old page and enable bit are replaced.
        assert_eq!(overlay_enable(0xABC0_0001, page), page | 1);
        assert_eq!(scontrol_enable(0), 1);
        assert_eq!(
            scontrol_enable(0xF0F0_0000_0000_0000),
            0xF0F0_0000_0000_0001
        );
        // GetSint: the vector, unmasked, AutoEOI and polling off,
        // reserved bits 15:8 and 63:19 kept.
        assert_eq!(sint_issued(SINT_MASKED, 0x30), 0x30);
        let reserved = 0xFFFF_FFFF_FFF8_FF00;
        let all = reserved | SINT_POLLING | SINT_AUTO_EOI | SINT_MASKED | 0xFF;
        assert_eq!(sint_issued(all, 0x31), reserved | 0x31);
        assert_eq!(sint_issued(SINT_MASKED | SINT_AUTO_EOI | 0x10, 0xEF), 0xEF);
        // Deletion only sets the mask bit.
        assert_eq!(sint_deleted(0x31), SINT_MASKED | 0x31);
        assert_eq!(sint_deleted(reserved | 0x31), reserved | SINT_MASKED | 0x31);
        assert_eq!(sint_deleted(SINT_MASKED), SINT_MASKED);
        assert_eq!(
            (SINT_MASKED, SINT_AUTO_EOI, SINT_POLLING),
            (1 << 16, 1 << 17, 1 << 18)
        );
    }

    #[test]
    fn hypercall_input_values() {
        // PostMessage: memory-based, code 0x5C, no rep count, no
        // variable header; SignalEvent: code 0x5D with the fast bit.
        assert_eq!(POST_MESSAGE_INPUT, 0x5C);
        assert_eq!(SIGNAL_EVENT_INPUT, 0x1_005D);
        for v in [POST_MESSAGE_INPUT, SIGNAL_EVENT_INPUT] {
            // Variable header size (bits 26:17), rep count (43:32) and rep
            // start (59:48) are 0.
            assert_eq!(v & (0x3FF << 17 | 0xFFF << 32 | 0xFFF << 48), 0);
        }
        assert_eq!(signal_event_input(0x12_3456, 0xBEEF), 0xBEEF_0012_3456);
        assert_eq!(signal_event_input(0xFF_FFFF, 0xFFFF) >> 48, 0);
        assert_eq!(
            (
                status::SUCCESS,
                status::INVALID_PARAMETER,
                status::INVALID_VP_INDEX,
                status::INVALID_PORT_ID,
                status::INVALID_CONNECTION_ID,
                status::INSUFFICIENT_BUFFERS,
                status::INVALID_SYNIC_STATE
            ),
            (0, 5, 0x0E, 0x11, 0x12, 0x13, 0x18)
        );
    }

    #[test]
    fn the_post_message_block_holds_the_payload_and_zeros_to_its_end() {
        let words: Vec<u64> = (0..31u64)
            .map(|i| 0x0101_0101_0101_0101 * (i + 1))
            .collect();
        for size in [0, 1, 7, 8, 9, 100, 239, 240] {
            let block = post_message_block(0x12_3456, 0x7FFF_FFFF, size, &words);
            let (connection, reserved, ty, got_size, payload) = parse_post_message_block(&block);
            assert_eq!(
                (connection, reserved, ty, got_size),
                (0x12_3456, 0, 0x7FFF_FFFF, size)
            );
            for (i, &b) in payload.iter().enumerate() {
                let want = if (i as u32) < size {
                    words[i / 8].to_le_bytes()[i % 8]
                } else {
                    0
                };
                assert_eq!(b, want, "size {size}, byte {i}");
            }
        }
        // Fewer words than the size: the rest is zero; a 31st word is
        // never read.
        let block = post_message_block(1, 1, 240, &[u64::MAX]);
        assert_eq!(block[2], u64::MAX);
        assert!(block[3..].iter().all(|&w| w == 0));
        assert_eq!(block.len() * 8, 256);
        // A size past 240 is 240.
        assert_eq!(post_message_block(1, 1, 1000, &words)[1] >> 32, 240);
    }
}
