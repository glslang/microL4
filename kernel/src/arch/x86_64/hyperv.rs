//! Hyper-V (`docs/design.md`, "Hyper-V interface"): detection and the
//! firmware's leftovers at step 5 of the boot sequence (M3); then, from M9
//! and only with the five M9 privileges, the hypercall interface (the guest
//! OS ID, the hypercall MSR at `.hvcall`, read back; ADR 0029), the SynIC
//! (SIMP and SIEFP on the two boot-region frames, SCONTROL; `GetSint`'s
//! SINT writes), and the executor of the Hypervisor capability's
//! invocations: the two hypercalls, EOM and the VP index.
//!
//! `l4core::hyperv` decides what the CPUID leaves mean, which synthetic MSR
//! each privilege allows, and every value written; this file runs CPUID,
//! reads and writes those MSRs, calls the hypercall page, and prints what
//! it found. Every synthetic MSR access is behind its privilege bit, so
//! none can fault. Only [`hypercall`] calls `.hvcall`, and only once the
//! MSR has read back enabled there; the release kernel's disassembly check
//! requires it to be the one caller (`xtask/src/disasm.rs`).

use core::arch::asm;
use core::cell::UnsafeCell;
use core::ptr;

use l4core::handoff::KERNEL_VIRT_BASE;
use l4core::hyperv::{
    self as hv, Detection, HypercallMsr, HypercallStep, LEFTOVERS, PostMessage, Privileges,
    SignalEvent, Unavailable,
};
use l4core::irq::SintAction;

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
    /// Whether the hypercall page is enabled at `.hvcall`, and if not why:
    /// with it, boot makes the Hypervisor capability and the SynIC frames
    /// (M9); without it, initial slots 12 to 14 are null.
    pub hypercalls: Result<(), Unavailable>,
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
/// Then, with the five M9 privileges, sets up the hypercall page at
/// `.hvcall` (ADR 0029). Prints each value found. `kernel_phys_base` is
/// where the loader put the kernel image, which is physically contiguous.
/// Runs once, with interrupts off, before the interrupt controllers are
/// set up and before M4 reuses any memory.
pub fn init(kernel_phys_base: u64) -> &'static Info {
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
        hypercalls: Err(Unavailable::NoInterface),
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
        info.hypercalls = set_up_hypercalls(&p, kernel_phys_base);
    }
    match info.hypercalls {
        Ok(()) => kprintln!("hyperv: Hypervisor capability: yes"),
        Err(why) => kprintln!("hyperv: no Hypervisor capability, slots 12 to 14 null: {why}"),
    }
    INFO.init(info)
}

// ---------------------------------------------------------------------------
// Hypercalls (M9)
// ---------------------------------------------------------------------------

/// The hypercall input page: page-aligned kernel BSS, ordinary RAM in the
/// kernel image, never an overlay page, as the TLFS requires. `PostMessage`
/// writes its whole 256-byte block here; the hypervisor reads it by its
/// guest physical address.
#[repr(C, align(4096))]
struct InputPage(UnsafeCell<[u64; 512]>);

// SAFETY: one core, and kernel code runs with interrupts off; only
// `post_message` writes the page, by value through a raw pointer, and no
// reference into it is ever made.
unsafe impl Sync for InputPage {}

static INPUT: InputPage = InputPage(UnsafeCell::new([0; 512]));

/// What a working hypercall page needs, recorded once it reads back
/// enabled at `.hvcall`: the input page's guest physical address.
struct Hypercalls {
    input_gpa: u64,
}

static HYPERCALLS: StaticCell<Hypercalls> = StaticCell::new();

/// The SynIC frames' physical addresses, SIM then SIEF, once SIMP and
/// SIEFP point at them.
static SYNIC: StaticCell<[u64; 2]> = StaticCell::new();

/// `.hvcall`'s virtual address. Never inlined: with [`hypercall`] it is one
/// of the two functions the release kernel's disassembly check lets name
/// the page, and the only one that takes its address, for the MSR.
#[inline(never)]
fn hvcall_page() -> u64 {
    let addr: u64;
    // SAFETY: `lea` only computes the address the linker gave
    // `__hvcall_start`, the start of `.hvcall`; nothing is read.
    unsafe {
        asm!(
            "lea {}, [rip + __hvcall_start]",
            out(reg) addr,
            options(pure, nomem, nostack, preserves_flags)
        )
    };
    addr
}

/// The guest OS ID, then the hypercall MSR at `.hvcall` with bits 11:2
/// kept, read back (`docs/design.md`, "Hypercalls (M9)"; ADR 0029). `Ok`
/// only if the read-back is enabled at `.hvcall`.
fn set_up_hypercalls(p: &Privileges, kernel_phys_base: u64) -> Result<(), Unavailable> {
    if let Some(name) = hv::missing_m9_privilege(p) {
        return Err(Unavailable::Privilege(name));
    }
    let to_phys = |virt: u64| virt - KERNEL_VIRT_BASE + kernel_phys_base;
    let page = to_phys(hvcall_page());
    // SAFETY: `AccessHypercallMsrs`, which `missing_m9_privilege` checked,
    // allows the guest OS ID MSR. The value only names the guest; the
    // firmware's identity is stale once it has exited.
    unsafe { write_msr(hv::MSR_GUEST_OS_ID, hv::GUEST_OS_ID) };
    let old = read_msr(hv::MSR_HYPERCALL);
    let read_back = match hv::hypercall_step(old, page) {
        HypercallStep::Unavailable(why) => return Err(why),
        HypercallStep::Ready => old,
        HypercallStep::Write(value) => {
            // SAFETY: `AccessHypercallMsrs` allows the MSR, which is not
            // locked (`hypercall_step` writes no locked one). The value
            // points the overlay at `.hvcall`, a page of the kernel's text
            // that holds only `int3`s, which nothing reads or writes, and
            // which no untyped, boot-region object or other kernel data
            // shares; bits 11:2 are kept as read.
            unsafe { write_msr(hv::MSR_HYPERCALL, value) };
            read_msr(hv::MSR_HYPERCALL)
        }
    };
    kprintln!(
        "hyperv: guest OS ID {:#x}; hypercall MSR {old:#x}, written for .hvcall at {page:#x}, reads back {read_back:#x}",
        hv::GUEST_OS_ID
    );
    if !hv::hypercall_enabled_at(read_back, page) {
        return Err(Unavailable::NotEnabled { read_back });
    }
    let input_gpa = to_phys(INPUT.0.get() as u64);
    HYPERCALLS.init(Hypercalls { input_gpa });
    Ok(())
}

/// Whether the hypercall page is enabled at `.hvcall`: boot then makes
/// the Hypervisor capability and lays out the SynIC frames (M9).
pub fn hypercalls_enabled() -> bool {
    HYPERCALLS.get().is_some()
}

/// Boot, once the boot region is zeroed and before untyped is made:
/// points SIMP at `message` and SIEFP at `event`, the two zeroed 4 KiB
/// boot-region frames for slots 13 and 14, with the enable bit and their
/// reserved bits kept, then enables SCONTROL (`docs/design.md`, "SynIC
/// (M9)"). Records both addresses for `TCB_SetIPCBuffer`'s refusal; the
/// kernel never touches the pages again. Only with the hypercall page
/// enabled; once.
pub fn set_up_synic(message: u64, event: u64) {
    assert!(hypercalls_enabled(), "a SynIC without a hypercall page");
    for (msr, page, name) in [
        (hv::MSR_SIMP, message, "SIMP"),
        (hv::MSR_SIEFP, event, "SIEFP"),
    ] {
        let old = read_msr(msr);
        // SAFETY: `AccessSynicRegs` allows SIMP and SIEFP (the hypercall
        // page is enabled only with every M9 privilege). The page is a
        // zeroed 4 KiB RAM frame of the boot region, which no untyped
        // covers, so revoke and retype never reuse memory the hypervisor
        // writes; the kernel reads and writes it no more.
        unsafe { write_msr(msr, hv::overlay_enable(old, page)) };
        kprintln!("hyperv: {name} {old:#x}, now {:#x}", read_msr(msr));
    }
    let old = read_msr(hv::MSR_SCONTROL);
    // SAFETY: as above, for SCONTROL; every SINT is still masked (step 5
    // masked them), so enabling the SynIC raises nothing until `GetSint`.
    unsafe { write_msr(hv::MSR_SCONTROL, hv::scontrol_enable(old)) };
    SYNIC.init([message, event]);
}

/// The SynIC frames' physical addresses, SIM then SIEF; zeros without a
/// SynIC.
pub fn synic_pages() -> [u64; 2] {
    SYNIC.get().copied().unwrap_or([0; 2])
}

/// Whether the SynIC is set up: `GetSint` works only then.
pub fn synic() -> bool {
    SYNIC.get().is_some()
}

/// Performs a SINT action for `l4core::irq`: reads SINTn, writes the value
/// core decides from it.
pub fn sint_action(action: SintAction) {
    assert!(synic(), "a SINT write without a SynIC");
    let n = action.sint();
    assert!(u32::from(n) < hv::SINTS, "SINT {n}");
    let msr = hv::MSR_SINT0 + u32::from(n);
    let old = read_msr(msr);
    // SAFETY: the SynIC exists only with `AccessSynicRegs`, which allows
    // the SINTs, and `n` is below 16. Core writes a device vector (0x30 to
    // 0xEF, so at least 16, which the TLFS requires) with AutoEOI and
    // polling off, or only sets the mask bit; reserved bits stay as read.
    unsafe { write_msr(msr, action.value(old)) };
}

/// The one caller of the hypercall page: `rcx` the input value, `rdx` the
/// input's guest physical address or its fast 8 bytes, `r8` 0 (neither
/// call has output); returns `rax`'s bits 0-15, the `HV_STATUS`. Never
/// inlined, so that its symbol bounds the only `call` into `.hvcall`,
/// which the release kernel's disassembly check requires.
#[inline(never)]
fn hypercall(input_value: u64, input: u64) -> u16 {
    assert!(
        hypercalls_enabled(),
        "a hypercall before the page read back enabled at .hvcall"
    );
    let rax: u64;
    // SAFETY: the hypercall MSR read back enabled at `.hvcall`
    // (`set_up_hypercalls`, checked above), so the page holds the
    // hypervisor's code, which ends in a near return: hence the kernel
    // stack, and no `nostack`. Only two input values reach here,
    // `HvCallPostMessage` with the input page's address and fast
    // `HvCallSignalEvent` with its 8 bytes, which `l4core::hyperv` built
    // after its checks; the hypervisor reads the input page, so no
    // `nomem`. For a call that is neither rep nor fast output the TLFS
    // changes only `rax`; `rcx`, `rdx` and `r8` are declared clobbered all
    // the same, and no XMM register is used. Interrupts are off, in ring
    // 0, as the TLFS requires.
    unsafe {
        asm!(
            "call __hvcall_start",
            inout("rcx") input_value => _,
            inout("rdx") input => _,
            inout("r8") 0u64 => _,
            out("rax") rax,
        )
    };
    (rax & hv::STATUS_MASK) as u16
}

/// `HvCallPostMessage`: writes the whole block into the input page, then
/// calls the page with its address.
pub fn post_message(call: PostMessage) -> u16 {
    let gpa = HYPERCALLS
        .get()
        .expect("a Hypervisor capability exists only with the hypercall page")
        .input_gpa;
    // SAFETY: the input page is this file's static, page-aligned and 4 KiB
    // long, so the 256-byte block fits at its start; it is written by
    // value through a raw pointer, and nothing else refers to it. The
    // write is volatile so that it happens before the hypercall, which
    // reads the page by its guest physical address.
    unsafe {
        ptr::write_volatile(
            INPUT.0.get().cast::<[u64; hv::BLOCK_WORDS]>(),
            *call.block(),
        )
    };
    hypercall(call.input_value(), gpa)
}

/// Fast `HvCallSignalEvent`: its 8 bytes in `rdx`.
pub fn signal_event(call: SignalEvent) -> u16 {
    hypercall(call.input_value(), call.input())
}

/// Writes 0 to the EOM register.
pub fn eom() {
    assert!(synic(), "EOM without a SynIC");
    // SAFETY: `AccessSynicRegs` allows EOM; a write of 0 only makes the
    // hypervisor try to deliver the next queued message.
    unsafe { write_msr(hv::MSR_EOM, 0) };
}

/// This processor's VP index (`AccessVpIndex`).
pub fn vp_index() -> u64 {
    assert!(hypercalls_enabled(), "VpIndex without the M9 privileges");
    read_msr(hv::MSR_VP_INDEX)
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
