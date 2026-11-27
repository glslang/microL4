//! M9's kernel self-tests on QEMU, for what TCG can run (`selftest`
//! only). Every invocation goes through `l4core::invoke` on the root
//! task's capabilities, as the root task's `Call` would make it: the root
//! TCB is the current thread, with `rdx` the `Call` number, while each
//! call runs, so its results reach the root TCB's message registers, where
//! the test reads them.
//!
//! - `test=msi` (`tests/qemu/msi.scenario`): no Hypervisor capability and
//!   no SynIC under TCG (slots 12 to 14 null, `GetSint`
//!   `IllegalOperation`); `IRQControl_GetMSI`'s address and data; the
//!   allocation of all 192 vectors, lowest first, then `RevokeFirst` for
//!   `GetMSI` and `GetIOAPIC` alike, a deleted handler's vector reissued;
//!   then an MSI delivered by a device: the HPET's last comparator, with
//!   FSB delivery (`-global hpet.msi=on`), writes `GetMSI`'s data to its
//!   address, and the interrupt path signals the bound notification; a
//!   second message signals again with no `Ack` between, since the kernel
//!   never masks an MSI; after the handler's deletion a third lands on a
//!   free entry and signals nothing.
//! - `test=ecam` (`tests/qemu/ecam.scenario`): BootInfo's ECAM range as
//!   the MCFG gives it, all device untyped, and every memory BAR the
//!   firmware assigned on bus 0, a 64-bit one above 4 GiB among them,
//!   inside device untyped.
//! - `test=frame_address` (`tests/qemu/frame_address.scenario`):
//!   `Frame_GetAddress` on the root task's own frames (mapped), a 4 KiB
//!   device frame and a 2 MiB RAM frame retyped from untyped (unmapped),
//!   and a copy with no rights: each the physical address BootInfo or the
//!   boot plan gives.

use core::sync::atomic::{AtomicU8, Ordering};

use l4core::abi::Syscall;
use l4core::bootinfo::{
    BootInfo, CAP_BOOTINFO_FRAME, CAP_HYPERVISOR, CAP_INIT_CNODE, CAP_INIT_IPC_BUFFER,
    CAP_IRQ_CONTROL, CAP_SYNIC_EVENT_FRAME, CAP_SYNIC_MESSAGE_FRAME,
};
use l4core::cap::{Cap, ObjectType};
use l4core::error::SyscallError;
use l4core::invoke::{self, ExtraCap, InvokeError, Message, label as cnode};
use l4core::ipc::{self, NotificationCap, NtfnState};
use l4core::irq::{self, IRQS, Interrupts, Source, label};
use l4core::sched::Scheduling;
use l4core::slot::SlotMemory;
use l4core::tcb::Tcbs;
use l4core::vspace::label as frame;

use super::{ExitCode, FACTS, Objects, StaticCell, apic, cpu, exit, hpet, idle, set_resume_hook};
use crate::boot::{BootState, RootSpace};

fn fail(test: &str, why: core::fmt::Arguments<'_>) -> ! {
    kprintln!("TEST FAIL: {test}: {why}");
    exit(ExitCode::Failure)
}

/// Invokes the capability in root slot `invoked` with `label`, `mrs` and
/// the capabilities in root slots `extra`, as the root task's `Call` would,
/// and returns MR0 to MR3 of its reply. A call a preemption point stops
/// (a retype's reset, with the timer pending, since interrupts are off) is
/// restarted, as a thread's `syscall` is, and goes on where it stopped.
fn call(
    k: &mut Objects,
    root: &RootSpace,
    invoked: u64,
    label: u64,
    mrs: &[u64],
    extra: &[u64],
) -> Result<[u64; 4], SyscallError> {
    let l = &root.plan.layout;
    let t = root.tcb;
    let saved = k.regs(t);
    let mut regs = saved;
    regs.rdx = Syscall::Call.number();
    k.set_regs(t, &regs);
    k.scheduler_mut().set_current(Some(t));
    let r = loop {
        let mut caps = [ExtraCap {
            cap: Cap::NULL,
            slot: l.slot(invoked),
        }; 2];
        for (x, &s) in caps.iter_mut().zip(extra) {
            *x = ExtraCap::load(k, l.slot(s));
        }
        let msg = Message {
            label,
            mrs,
            extra_caps: &caps[..extra.len()],
        };
        match invoke::invoke(k, l.slot(invoked), &msg) {
            Err(InvokeError::Preempted) => continue,
            Err(InvokeError::Error(e)) => break Err(e),
            Ok(_) => {
                let regs = k.regs(t);
                break Ok(core::array::from_fn(|i| regs.message_register(i)));
            }
        }
    };
    k.scheduler_mut().set_current(None);
    k.set_regs(t, &saved);
    r
}

/// `Untyped_Retype` of one `ty` from root slot `untyped` into root slot
/// `dest`.
fn retype(
    k: &mut Objects,
    root: &RootSpace,
    untyped: u64,
    ty: ObjectType,
    dest: u64,
) -> Result<(), SyscallError> {
    let mrs = [ty as u64, 0, 0, 0, dest, 1];
    call(
        k,
        root,
        untyped,
        cnode::UNTYPED_RETYPE,
        &mrs,
        &[CAP_INIT_CNODE],
    )
    .map(|_| ())
}

fn delete(k: &mut Objects, root: &RootSpace, slot: u64) -> Result<(), SyscallError> {
    call(
        k,
        root,
        CAP_INIT_CNODE,
        cnode::CNODE_DELETE,
        &[slot, 64],
        &[],
    )
    .map(|_| ())
}

/// Root slot of the smallest untyped of the kind asked, at least
/// `2^bits` bytes.
fn untyped(bi: &BootInfo, device: bool, bits: u8) -> Option<u64> {
    bi.untyped()
        .iter()
        .enumerate()
        .filter(|(_, d)| d.device() == device && d.size_bits >= bits)
        .min_by_key(|(_, d)| d.size_bits)
        .map(|(i, _)| bi.untyped.start + i as u64)
}

// ---------------------------------------------------------------------------
// test=msi
// ---------------------------------------------------------------------------

/// HPET ticks before the comparator fires: 10 µs at QEMU's 100 MHz.
const TICKS: u64 = 1000;
/// The two badges the bound notification is minted with.
const BADGE1: u64 = 1 << 40;
const BADGE2: u64 = 1 << 41;

/// What the delivery steps, run from the idle path, need.
struct MsiCtx {
    root: &'static RootSpace,
    handler: u64,
    address: u64,
    data: u64,
    /// The notification, and root slots of its two badged copies.
    ntfn: NotificationCap,
    second: u64,
    source: hpet::LevelSource,
    deadline: u64,
}

static MSI: StaticCell<MsiCtx> = StaticCell::new();
/// 1: waiting for the first message's signal; 2: for the second's; 3:
/// for the third message, which must land on a free entry.
static STEP: AtomicU8 = AtomicU8::new(0);

fn msi_fail(why: core::fmt::Arguments<'_>) -> ! {
    fail("msi", why)
}

pub fn test_msi(root: &'static RootSpace, bi: &BootInfo) -> ! {
    let facts = FACTS.get().expect("boot facts before the self-tests");
    let mut k = Objects::begin();
    let l = &root.plan.layout;
    let check = |ok: bool, what: core::fmt::Arguments<'_>| {
        if !ok {
            msi_fail(what)
        }
        kprintln!("msi: ok   {what}");
    };

    // No SynIC under TCG.
    let nulls = [
        CAP_HYPERVISOR,
        CAP_SYNIC_MESSAGE_FRAME,
        CAP_SYNIC_EVENT_FRAME,
    ]
    .map(|s| k.load(l.slot(s)).cap.is_null());
    check(
        nulls == [true; 3] && !k.synic(),
        format_args!("no Hypervisor capability under TCG: slots 12, 13 and 14 null, no SynIC"),
    );
    let e = bi.empty.start;
    let r = call(
        &mut k,
        root,
        CAP_IRQ_CONTROL,
        label::GET_SINT,
        &[2, e, 64],
        &[CAP_INIT_CNODE],
    );
    check(
        r == Err(SyscallError::IllegalOperation) && k.load(l.slot(e)).cap.is_null(),
        format_args!("GetSint(2) is IllegalOperation without a SynIC"),
    );

    // The message.
    let id = apic::id();
    let get_msi = |k: &mut Objects, slot: u64| {
        call(
            k,
            root,
            CAP_IRQ_CONTROL,
            label::GET_MSI,
            &[slot, 64],
            &[CAP_INIT_CNODE],
        )
    };
    let [irq0, address, data, _] = match get_msi(&mut k, e) {
        Ok(w) => w,
        Err(err) => msi_fail(format_args!("GetMSI failed: {err:?}")),
    };
    let entry = k.irq_table().entry(irq0 as u8);
    check(
        irq0 == 0
            && address == 0xFEE0_0000 | u64::from(id) << 12
            && data == 0x30 + irq0
            && entry.source == Source::Msi
            && irq::handler_irq(&k.load(l.slot(e)).cap) == Some(0),
        format_args!(
            "GetMSI: IRQ {irq0}, address {address:#x} (APIC ID {id}), data {data:#x}: the lowest vector, physical, fixed, edge"
        ),
    );

    // Every vector, lowest first, then none.
    for i in 1..IRQS as u64 {
        match get_msi(&mut k, e + i) {
            Ok([irq, a, d, _]) if irq == i && a == address && d == 0x30 + i => {}
            other => msi_fail(format_args!("GetMSI number {i} gave {other:?}")),
        }
    }
    let full = e + IRQS as u64;
    let r = get_msi(&mut k, full);
    let r2 = call(
        &mut k,
        root,
        CAP_IRQ_CONTROL,
        label::GET_IOAPIC,
        &[16, 1, 0, full, 64],
        &[CAP_INIT_CNODE],
    );
    check(
        r == Err(SyscallError::RevokeFirst)
            && r2 == Err(SyscallError::RevokeFirst)
            && k.load(l.slot(full)).cap.is_null(),
        format_args!(
            "GetMSI 192 times gave IRQs 0 to 191 in order; then GetMSI and GetIOAPIC are RevokeFirst"
        ),
    );
    // A deleted handler's vector is the one reissued.
    if let Err(err) = delete(&mut k, root, e + 100) {
        msi_fail(format_args!("deleting IRQ 100's handler: {err:?}"))
    }
    let freed = k.irq_table().entry(100).source == Source::Free;
    let again = get_msi(&mut k, full);
    check(
        freed && matches!(again, Ok([100, ..])),
        format_args!("deleting IRQ 100's handler freed its vector, and GetMSI reissued it"),
    );
    for i in 1..IRQS as u64 {
        let slot = if i == 100 { full } else { e + i };
        if let Err(err) = delete(&mut k, root, slot) {
            msi_fail(format_args!("deleting root slot {slot}: {err:?}"))
        }
    }
    let free = (1..IRQS as u8).all(|i| k.irq_table().entry(i).source == Source::Free);
    check(
        free,
        format_args!("deleting the 191 other handlers freed IRQs 1 to 191"),
    );

    // A notification, minted with two badges, bound to IRQ 0.
    let Some(ut) = untyped(bi, false, 6) else {
        msi_fail(format_args!("no RAM untyped for a notification"))
    };
    let (n, b1, b2) = (e + 1, e + 2, e + 3);
    if let Err(err) = retype(&mut k, root, ut, ObjectType::Notification, n) {
        msi_fail(format_args!("retyping a notification: {err:?}"))
    }
    for (slot, badge) in [(b1, BADGE1), (b2, BADGE2)] {
        let mrs = [slot, 64, n, 64, 0xF, badge];
        if let Err(err) = call(
            &mut k,
            root,
            CAP_INIT_CNODE,
            cnode::CNODE_MINT,
            &mrs,
            &[CAP_INIT_CNODE],
        ) {
            msi_fail(format_args!("minting badge {badge:#x}: {err:?}"))
        }
    }
    let ntfn = NotificationCap::from_cap(&k.load(l.slot(n)).cap).expect("a notification");
    if let Err(err) = call(&mut k, root, e, label::SET_NOTIFICATION, &[], &[b1]) {
        msi_fail(format_args!("SetNotification: {err:?}"))
    }
    let Some(source) = hpet::level_source(facts.platform) else {
        msi_fail(format_args!("no HPET comparator to send a message"))
    };
    if !source.fsb_capable() {
        msi_fail(format_args!(
            "HPET comparator {} cannot deliver by FSB: the scenario needs -global hpet.msi=on",
            source.comparator()
        ))
    }
    kprintln!(
        "msi: IRQ 0 bound to a notification with badge {BADGE1:#x}; HPET comparator {} sends data {data:#x} to {address:#x} by FSB",
        source.comparator()
    );
    let deadline = cpu::rdtsc() + facts.tsc_hz / 2;
    let ctx = MSI.init(MsiCtx {
        root,
        handler: e,
        address,
        data,
        ntfn,
        second: b2,
        source,
        deadline,
    });
    STEP.store(1, Ordering::Relaxed);
    set_resume_hook(msi_step);
    ctx.source.fire_fsb(address, data, TICKS);
    drop(k);
    idle()
}

/// The idle path's hook, after every interrupt: the next step once the
/// last one's interrupt has arrived, else idle again until the deadline.
fn msi_step() -> ! {
    let ctx = MSI.get().expect("test=msi's context");
    let mut k = Objects::begin();
    let n = ipc::notification(&k, ctx.ntfn.ntfn);
    let timed_out = cpu::rdtsc() > ctx.deadline;
    match STEP.load(Ordering::Relaxed) {
        1 if n.state == NtfnState::Active && n.word == BADGE1 => {
            ctx.source.stop();
            let e = k.irq_table().entry(0);
            if e.source != Source::Msi || e.pending || e.masked {
                msi_fail(format_args!("IRQ 0's entry after delivery: {e:?}"))
            }
            kprintln!(
                "msi: ok   the HPET's FSB message signalled the notification with badge {BADGE1:#x}; IRQ 0 not masked"
            );
            // A second message, with no Ack between, to a second binding.
            if let Err(err) = call(
                &mut k,
                ctx.root,
                ctx.handler,
                label::SET_NOTIFICATION,
                &[],
                &[ctx.second],
            ) {
                msi_fail(format_args!("SetNotification again: {err:?}"))
            }
            STEP.store(2, Ordering::Relaxed);
            ctx.source.fire_fsb(ctx.address, ctx.data, TICKS);
        }
        2 if n.word == BADGE1 | BADGE2 => {
            ctx.source.stop();
            kprintln!(
                "msi: ok   a second message, with no Ack, signalled again (badge {BADGE2:#x}): the kernel never masks an MSI"
            );
            let before = k.irq_table().stale;
            if let Err(err) = delete(&mut k, ctx.root, ctx.handler) {
                msi_fail(format_args!("deleting IRQ 0's handler: {err:?}"))
            }
            if k.irq_table().entry(0).source != Source::Free {
                msi_fail(format_args!(
                    "IRQ 0 is not free after its handler's deletion"
                ))
            }
            STALE_BEFORE.store(before as u8, Ordering::Relaxed);
            STEP.store(3, Ordering::Relaxed);
            ctx.source.fire_fsb(ctx.address, ctx.data, TICKS);
        }
        3 if k.irq_table().stale > u64::from(STALE_BEFORE.load(Ordering::Relaxed)) => {
            ctx.source.stop();
            if n.word != BADGE1 | BADGE2 {
                msi_fail(format_args!(
                    "the stale message changed the notification: {n:?}"
                ))
            }
            kprintln!(
                "msi: ok   after the handler's deletion the device's next message landed on a free entry and signalled nothing"
            );
            kprintln!("TEST PASS");
            exit(ExitCode::Success)
        }
        step if timed_out => {
            ctx.source.stop();
            msi_fail(format_args!(
                "step {step}: no message arrived in 500 ms: notification {n:?}, IRQ 0 {:?}, {} stale",
                k.irq_table().entry(0),
                k.irq_table().stale
            ))
        }
        _ => {}
    }
    drop(k);
    idle()
}

static STALE_BEFORE: AtomicU8 = AtomicU8::new(0);

// ---------------------------------------------------------------------------
// test=ecam
// ---------------------------------------------------------------------------

/// One function's configuration space, through the direct map, which maps
/// ECAM uncached (no 2 MiB page of it holds RAM).
struct Config(u64);

impl Config {
    fn read(&self, offset: u64) -> u32 {
        // SAFETY: `self.0` is a function's 4 KiB of ECAM, inside the MCFG's
        // range and below the direct map's end (checked by `test_ecam`),
        // mapped uncached there; `offset` is a 32-bit register below 4 KiB.
        // Reading configuration space has no side effects.
        unsafe { core::ptr::read_volatile((super::phys_to_virt(self.0) + offset) as *const u32) }
    }

    fn write(&self, offset: u64, value: u32) {
        // SAFETY: as in `read`. Only `bar_size` writes, as firmware sizes
        // a BAR: the command register with decode off, the BAR with all
        // ones, then both back as they were.
        unsafe {
            core::ptr::write_volatile((super::phys_to_virt(self.0) + offset) as *mut u32, value)
        }
    }

    /// Memory BAR `i`'s base and size, and whether it is 64-bit; `None`
    /// for an I/O BAR, a BAR the firmware left at 0, or a size that does
    /// not read back. Sizes it with decode off, as firmware does.
    fn bar(&self, i: u64) -> Option<(u64, u64, bool)> {
        let at = 0x10 + 4 * i;
        let low = self.read(at);
        if low & 1 != 0 {
            return None;
        }
        let wide = low >> 1 & 3 == 2;
        let high = if wide { self.read(at + 4) } else { 0 };
        let base = u64::from(high) << 32 | u64::from(low & !0xF);
        if base == 0 {
            return None;
        }
        let command = self.read(4);
        self.write(4, command & !0x3);
        self.write(at, u32::MAX);
        let mask_low = self.read(at);
        self.write(at, low);
        let mask_high = if wide {
            self.write(at + 4, u32::MAX);
            let m = self.read(at + 4);
            self.write(at + 4, high);
            m
        } else {
            u32::MAX
        };
        self.write(4, command);
        let mask = u64::from(mask_high) << 32 | u64::from(mask_low & !0xF);
        let size = (!mask).wrapping_add(1);
        (size != 0 && size.is_power_of_two()).then_some((base, size, wide))
    }
}

/// `test=ecam` (`tests/qemu/ecam.scenario`, with a `virtio-net-pci`): the
/// MCFG's one range in BootInfo's `InterruptInfo.ecam`, as the design
/// gives it for q35; all of it in device untyped; then bus 0's functions,
/// read through the direct map, each memory BAR the firmware assigned,
/// sized, inside device untyped, a 64-bit one above 4 GiB among them
/// (`docs/design.md`, "What user space gets, and kernel devices").
pub fn test_ecam(boot: &BootState, bi: &BootInfo) -> ! {
    let facts = FACTS.get().expect("boot facts before the self-tests");
    let fail = |why: core::fmt::Arguments<'_>| -> ! { fail("ecam", why) };
    let covered = |start: u64, end: u64| {
        let mut at = start & !0xFFF;
        while at < end {
            match bi
                .untyped()
                .iter()
                .find(|d| d.device() && d.paddr <= at && at < d.end())
            {
                Some(d) => at = d.end(),
                None => return false,
            }
        }
        true
    };
    let info = &bi.interrupts;
    let ecam = info.ecam[0];
    let from_acpi = facts.platform.ecam.get(0).copied();
    if info.ecam_count != 1
        || from_acpi.map(|e| (e.base, e.segment, e.start_bus, e.end_bus))
            != Some((ecam.base, ecam.segment, ecam.start_bus, ecam.end_bus))
    {
        fail(format_args!(
            "InterruptInfo.ecam: {} entries, the first {ecam:?}; the MCFG gave {from_acpi:?}",
            info.ecam_count
        ))
    }
    let (start, end) = (
        ecam.base + (u64::from(ecam.start_bus) << 20),
        ecam.base + ((u64::from(ecam.end_bus) + 1) << 20),
    );
    if !covered(start, end) {
        fail(format_args!(
            "ECAM {start:#x}-{end:#x} is not all device untyped"
        ))
    }
    kprintln!(
        "ecam: ok   InterruptInfo.ecam: base {:#x}, segment {}, buses {}-{}; {start:#x}-{end:#x} all device untyped",
        ecam.base,
        ecam.segment,
        ecam.start_bus,
        ecam.end_bus
    );
    // Bus 0's 1 MiB, which the test reads, in the direct map.
    if ecam.start_bus != 0 || ecam.base + (1 << 20) > boot.handoff.direct_map_end() {
        fail(format_args!("bus 0's ECAM is not in the direct map"))
    }
    let (mut functions, mut bars, mut high) = (0, 0, 0);
    for dev in 0..32u64 {
        for func in 0..8u64 {
            let cfg = Config(ecam.base + (dev << 15 | func << 12));
            let id = cfg.read(0);
            if id & 0xFFFF == 0xFFFF {
                if func == 0 {
                    break;
                }
                continue;
            }
            functions += 1;
            let header = cfg.read(0xC) >> 16 & 0xFF;
            kprintln!(
                "ecam: 00:{dev:02x}.{func} {:04x}:{:04x} class {:06x}",
                id & 0xFFFF,
                id >> 16,
                cfg.read(8) >> 8
            );
            if header & 0x7F == 0 {
                let mut i = 0;
                while i < 6 {
                    let Some((base, size, wide)) = cfg.bar(i) else {
                        i += 1;
                        continue;
                    };
                    if !covered(base, base + size) {
                        fail(format_args!(
                            "00:{dev:02x}.{func} BAR{i} {base:#x}+{size:#x} is not all device untyped"
                        ))
                    }
                    kprintln!(
                        "ecam: ok   00:{dev:02x}.{func} BAR{i} {base:#x}, {size:#x} bytes, {}-bit: device untyped",
                        if wide { 64 } else { 32 }
                    );
                    bars += 1;
                    if base >= 1 << 32 {
                        high += 1;
                    }
                    i += if wide { 2 } else { 1 };
                }
            }
            if func == 0 && header & 0x80 == 0 {
                break;
            }
        }
    }
    if high == 0 {
        fail(format_args!(
            "{functions} functions, {bars} memory BARs, none above 4 GiB"
        ))
    }
    kprintln!(
        "ecam: ok   {functions} functions on bus 0; {bars} memory BARs, {high} above 4 GiB, all in device untyped"
    );
    kprintln!("TEST PASS");
    exit(ExitCode::Success)
}

// ---------------------------------------------------------------------------
// test=frame_address
// ---------------------------------------------------------------------------

pub fn test_frame_address(root: &'static RootSpace, bi: &BootInfo) -> ! {
    let mut k = Objects::begin();
    let l = &root.plan.layout;
    let address = |k: &mut Objects, slot: u64| -> u64 {
        match call(k, root, slot, frame::FRAME_GET_ADDRESS, &[], &[]) {
            Ok([a, ..]) => a,
            Err(e) => fail("frame_address", format_args!("root slot {slot}: {e:?}")),
        }
    };
    let check = |what: &str, slot: u64, got: u64, want: u64| {
        if got != want {
            fail(
                "frame_address",
                format_args!("{what} (root slot {slot}) at {got:#x}, not {want:#x}"),
            )
        }
        kprintln!("frame_address: ok   {what} (root slot {slot}) at {got:#x}");
    };
    // The root task's own frames, mapped in its VSpace.
    let first_image = bi.user_image_frames.start;
    let extra = bi.extra_bootinfo_frames.start;
    for (what, slot, want) in [
        ("the IPC buffer, mapped", CAP_INIT_IPC_BUFFER, l.ipc_buffer),
        (
            "BootInfo's first frame, mapped",
            CAP_BOOTINFO_FRAME,
            l.bootinfo,
        ),
        ("BootInfo's second frame, mapped", extra, l.bootinfo + 4096),
        ("the first image frame, mapped", first_image, l.image_frames),
    ] {
        let got = address(&mut k, slot);
        check(what, slot, got, want);
    }
    // Retyped, unmapped: a 4 KiB device frame at its untyped's base, and
    // a 2 MiB RAM frame at its untyped's.
    let e = bi.empty.start;
    for (what, device, ty, bits, dest) in [
        (
            "a 4 KiB device frame, unmapped",
            true,
            ObjectType::Frame4K,
            12,
            e,
        ),
        (
            "a 2 MiB RAM frame, unmapped",
            false,
            ObjectType::Frame2M,
            21,
            e + 1,
        ),
    ] {
        let Some(ut) = untyped(bi, device, bits) else {
            fail("frame_address", format_args!("no untyped for {what}"))
        };
        let base = bi.untyped()[(ut - bi.untyped.start) as usize].paddr;
        if let Err(err) = retype(&mut k, root, ut, ty, dest) {
            fail("frame_address", format_args!("retyping {what}: {err:?}"))
        }
        let got = address(&mut k, dest);
        check(what, dest, got, base);
    }
    // A copy with no rights answers the same.
    let mrs = [e + 2, 64, e + 1, 64, 0];
    if let Err(err) = call(
        &mut k,
        root,
        CAP_INIT_CNODE,
        cnode::CNODE_COPY,
        &mrs,
        &[CAP_INIT_CNODE],
    ) {
        fail(
            "frame_address",
            format_args!("copying with no rights: {err:?}"),
        )
    }
    let want = address(&mut k, e + 1);
    let got = address(&mut k, e + 2);
    check("a copy of the 2 MiB frame with no rights", e + 2, got, want);
    // Not a frame: the root CNode does not decode the label.
    let r = call(
        &mut k,
        root,
        CAP_INIT_CNODE,
        frame::FRAME_GET_ADDRESS,
        &[],
        &[],
    );
    if r != Err(SyscallError::IllegalOperation) {
        fail(
            "frame_address",
            format_args!("the root CNode answered {r:?}"),
        )
    }
    kprintln!("frame_address: ok   the root CNode refuses the label: IllegalOperation");
    kprintln!("TEST PASS");
    exit(ExitCode::Success)
}
