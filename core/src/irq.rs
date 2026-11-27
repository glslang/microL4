//! Interrupts (`docs/design.md`, "Interrupts"; `docs/abi.md`,
//! "IRQControl" and "IRQHandler"; ADRs 0019 and 0027): the IRQ table and
//! its states, the I/O APIC routes, the IRQControl and IRQHandler
//! invocations, interrupt delivery, and the deletion hooks.
//!
//! Nothing here touches hardware. Every I/O APIC access is an [`Action`]
//! the kernel performs through [`Interrupts::irq_action`], and
//! [`Action::writes`] gives the register writes each one makes, so the
//! whole state machine, ADR 0027's clearing of a stale Remote IRR
//! included, runs on the host against a model of an I/O APIC
//! (`crate::testing::FakeIoApic`).
//!
//! - IRQ `irq` (0 to 191) is vector `0x30 + irq`. Its table [`Entry`]
//!   holds the source, `pending` (an edge pin delivered since the last
//!   Ack) and `masked` (the kernel masked the pin and waits for an Ack),
//!   and its IRQ node slot ([`node_slot`]) the bound notification
//!   capability, or nothing.
//! - [`invoke_control`] issues an IRQHandler for an ISA IRQ or a GSI, in
//!   `docs/abi.md`'s check order: label, length, arguments, resources (the
//!   source free, a vector free, Remote IRR clear after the kernel tried to
//!   clear it), then the destination slot. Only the Remote IRR step changes
//!   anything before every check has passed, as ADR 0027 allows. From M9
//!   it also issues one for an MSI (`GetMSI`: the vector reserved, nothing
//!   programmed, the message address and data returned) and for a SynIC
//!   SINT (`GetSint`: SINTn written once, after every check, through
//!   [`Interrupts::sint_action`]).
//! - [`invoke_handler`] decodes `Ack`, `SetNotification` and `Clear`.
//! - [`deliver`] is the interrupt path's part for a device vector: an MSI
//!   or a SINT is never masked, only signalled.
//! - [`finalise`] and [`after_delete`] are the IRQHandler arms of the
//!   kernel's hooks: the last capability deletes the IRQ node slot's
//!   capability, and once its own slot is empty the pin or SINT is masked
//!   and the entry, and so the vector, freed.
//!
//! # Orders the ABI leaves open
//!
//! - The destination slot's `depth` is checked before its root
//!   (`RangeError(1, 64)` before `FailedLookup` with `InvalidRoot`), as
//!   `docs/abi.md`'s conventions list them; seL4's `lookupTargetSlot`
//!   checks the root first.
//! - Within step 5: the source, then the vector, then Remote IRR, so an
//!   issued pin is never masked by a refused issue. `GetSint` checks its
//!   SINT, then the vector; `GetMSI` has only the vector.
//! - `IRQHandler_Ack`, `_SetNotification` and `_Clear` take any number of
//!   message registers; `SetNotification` ignores extra capabilities past
//!   the first.

use crate::acpi::{IsaRoute, Platform};
use crate::apic;
use crate::cap::{Cap, CapType, Rights};
use crate::cdt;
use crate::cnode;
use crate::error::SyscallError;
use crate::invoke::{self, InvokeError, Message, Reply};
use crate::ipc::{self, IpcEnv, NotificationCap};
use crate::kernel::Kernel;
use crate::slot::{SlotAddr, SlotMemory};
use crate::tcb::Threads;
use crate::trap::{DEVICE_BASE, DEVICE_LAST};
use crate::window::MAX_IOAPICS;

/// IRQ numbers, one per device vector `0x30`-`0xEF`.
pub const IRQS: usize = (DEVICE_LAST - DEVICE_BASE) as usize + 1;
/// ISA IRQs `GetISA` accepts: 0 to 15.
pub const ISA_IRQS: usize = 16;
/// SynIC SINTs `GetSint` accepts: 0 to 15.
pub const SINTS: usize = 16;

/// IRQControl and IRQHandler invocation labels (`docs/abi.md`,
/// "Invocation label index"): `0x60` to `0x6F`.
pub mod label {
    pub const GET_ISA: u64 = 0x60;
    pub const GET_IOAPIC: u64 = 0x61;
    /// M9.
    pub const GET_MSI: u64 = 0x62;
    /// M9.
    pub const GET_SINT: u64 = 0x63;
    pub const ACK: u64 = 0x68;
    pub const SET_NOTIFICATION: u64 = 0x69;
    pub const CLEAR: u64 = 0x6A;
}

/// The vector of IRQ `irq`, which must be below [`IRQS`].
pub const fn vector(irq: u8) -> u8 {
    debug_assert!((irq as usize) < IRQS);
    DEVICE_BASE + irq
}

/// The x86 MSI message address `GetMSI` returns (`docs/design.md`, "MSI
/// (M9) and the trust model"): `0xFEE` in bits 31:20, the boot CPU's
/// xAPIC ID in bits 19:12, redirection hint (bit 3) and destination mode
/// (bit 2) 0, so physical destination; the upper 32 bits 0.
pub const fn msi_address(apic_id: u8) -> u64 {
    0xFEE0_0000 | (apic_id as u64) << 12
}

/// The MSI message data `GetMSI` returns for IRQ `irq`: its vector in bits
/// 7:0 and every other bit 0, which is fixed delivery, edge-triggered. It
/// fits MSI's 16-bit Message Data register and MSI-X's 32-bit one.
pub const fn msi_data(irq: u8) -> u64 {
    vector(irq) as u64
}

/// The IRQ of a device vector, `None` for any other vector.
pub const fn irq_of_vector(vector: u8) -> Option<u8> {
    if vector >= DEVICE_BASE && vector <= DEVICE_LAST {
        Some(vector - DEVICE_BASE)
    } else {
        None
    }
}

/// An IRQHandler capability for `irq`: no memory, `data` the IRQ.
pub const fn handler_cap(irq: u8) -> Cap {
    Cap::new(CapType::IrqHandler, 0, 0, Rights::NONE, false, irq as u64)
}

/// The IRQ an IRQHandler capability names; `None` for any other
/// capability, or a data word no IRQ has.
pub fn handler_irq(cap: &Cap) -> Option<u8> {
    (cap.cap_type() == CapType::IrqHandler && cap.data < IRQS as u64).then_some(cap.data as u8)
}

// ---------------------------------------------------------------------------
// Routes
// ---------------------------------------------------------------------------

/// An I/O APIC pin: the I/O APIC's index in MADT order and the pin on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct Pin {
    pub ioapic: u8,
    pub pin: u16,
}

/// What the kernel knows of one I/O APIC: the GSIs it serves and its
/// version, which picks how a stale Remote IRR is cleared.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct IoApicDesc {
    pub gsi_base: u32,
    /// The version register's MRE + 1, at most `apic::MAX_PINS`.
    pub pins: u16,
    pub version: u8,
}

impl IoApicDesc {
    /// Whether it has the EOI register (version `0x20` and later).
    pub const fn has_eoi_register(&self) -> bool {
        self.version >= apic::IOAPIC_EOI_VERSION
    }

    fn serves(&self, gsi: u64) -> bool {
        gsi >= u64::from(self.gsi_base) && gsi < u64::from(self.gsi_base) + u64::from(self.pins)
    }
}

/// The interrupt routes, fixed at boot: the I/O APICs in MADT order and the
/// ISA IRQs' routes through the MADT's overrides.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Routing {
    pub ioapics: [Option<IoApicDesc>; MAX_IOAPICS],
    /// ISA IRQ `n`'s route; `None` if its GSI is another IRQ's override
    /// target ([`Platform::isa_route`]). Whether an I/O APIC serves the
    /// GSI is [`Routing::pin`]'s question.
    pub isa: [Option<IsaRoute>; ISA_IRQS],
}

impl Routing {
    /// No I/O APIC and no ISA route.
    pub const NONE: Routing = Routing {
        ioapics: [None; MAX_IOAPICS],
        isa: [None; ISA_IRQS],
    };

    /// The routes of a parsed `platform`, given each I/O APIC's pin count
    /// and version as the kernel read them, in MADT order. An I/O APIC
    /// without both, with no pins, or whose last GSI would pass
    /// `u32::MAX` (bad firmware: a GSI is 32 bits), serves nothing.
    pub fn from_platform(platform: &Platform, pins: &[u16], versions: &[u8]) -> Routing {
        let mut r = Routing::NONE;
        for (i, io) in platform.ioapics.iter().enumerate().take(MAX_IOAPICS) {
            if let (Some(&pins), Some(&version)) = (pins.get(i), versions.get(i))
                && pins > 0
                && u64::from(io.gsi_base) + u64::from(pins) <= 1 << 32
            {
                r.ioapics[i] = Some(IoApicDesc {
                    gsi_base: io.gsi_base,
                    pins,
                    version,
                });
            }
        }
        for (irq, route) in r.isa.iter_mut().enumerate() {
            *route = platform.isa_route(irq as u8);
        }
        r
    }

    /// The I/O APIC pin that serves `gsi`, with its I/O APIC: the first
    /// match in MADT order, as [`Platform::ioapic_for_gsi`] decides.
    pub fn pin(&self, gsi: u64) -> Option<(Pin, IoApicDesc)> {
        self.ioapics.iter().enumerate().find_map(|(i, io)| {
            let io = io.filter(|io| io.serves(gsi))?;
            let pin = Pin {
                ioapic: i as u8,
                pin: (gsi - u64::from(io.gsi_base)) as u16,
            };
            Some((pin, io))
        })
    }
}

// ---------------------------------------------------------------------------
// The IRQ table
// ---------------------------------------------------------------------------

/// Where an IRQ comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    /// Not issued: the vector is free.
    Free,
    /// An I/O APIC pin, with the GSI it was issued for.
    IoApic {
        gsi: u32,
        pin: Pin,
        level: bool,
        active_low: bool,
    },
    /// An MSI or MSI-X message (M9): the vector is reserved, and nothing in
    /// the kernel can mask it or names the device.
    Msi,
    /// SynIC SINT `n`, 0 to 15 (M9), unmasked with this IRQ's vector.
    Sint(u8),
}

/// One IRQ's state (`docs/design.md`, "The IRQ table").
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry {
    pub source: Source,
    /// An edge pin delivered since the last Ack.
    pub pending: bool,
    /// The kernel masked the pin on delivery and waits for an Ack.
    pub masked: bool,
}

impl Entry {
    /// A free entry.
    pub const FREE: Entry = Entry {
        source: Source::Free,
        pending: false,
        masked: false,
    };
}

/// The IRQ table: fixed kernel memory indexed by IRQ, and two counters
/// for the debug output.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct IrqTable {
    entries: [Entry; IRQS],
    /// Deliveries that found no notification bound: lost, though the
    /// pin's state advanced.
    pub lost: u64,
    /// Deliveries that found the entry free: a source deleted while its
    /// interrupt was pending.
    pub stale: u64,
}

impl IrqTable {
    /// Every entry free.
    pub const fn new() -> IrqTable {
        IrqTable {
            entries: [Entry::FREE; IRQS],
            lost: 0,
            stale: 0,
        }
    }

    /// IRQ `irq`'s entry; panics for `irq` >= [`IRQS`].
    pub fn entry(&self, irq: u8) -> Entry {
        self.entries[irq as usize]
    }

    fn set(&mut self, irq: u8, e: Entry) {
        self.entries[irq as usize] = e;
    }

    /// The IRQ issued for `gsi`, if any.
    pub fn holder(&self, gsi: u32) -> Option<u8> {
        self.entries
            .iter()
            .position(|e| matches!(e.source, Source::IoApic { gsi: g, .. } if g == gsi))
            .map(|i| i as u8)
    }

    /// The IRQ issued for SINT `sint`, if any.
    pub fn sint_holder(&self, sint: u8) -> Option<u8> {
        self.entries
            .iter()
            .position(|e| e.source == Source::Sint(sint))
            .map(|i| i as u8)
    }

    /// The lowest free IRQ, whose vector an issue takes.
    pub fn lowest_free(&self) -> Option<u8> {
        self.entries
            .iter()
            .position(|e| e.source == Source::Free)
            .map(|i| i as u8)
    }

    /// Every entry, by IRQ.
    pub fn entries(&self) -> &[Entry; IRQS] {
        &self.entries
    }
}

impl Default for IrqTable {
    fn default() -> IrqTable {
        IrqTable::new()
    }
}

// ---------------------------------------------------------------------------
// Hardware actions
// ---------------------------------------------------------------------------

/// How [`Action::ClearRemoteIrr`] clears a stale Remote IRR (ADR 0027).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum ClearPath {
    /// Version `0x20` and later: the entry's vector to the EOI register.
    EoiRegister,
    /// Below `0x20`, which has no EOI register: the entry edge-triggered,
    /// then level-triggered again, both masked (Linux's
    /// `__eoi_ioapic_pin`).
    TriggerToggle,
}

/// An I/O APIC access the kernel performs for `core::irq`: one per call of
/// [`Interrupts::irq_action`], in order. Each reads the pin's entry first;
/// [`Action::writes`] gives what it then writes.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Action {
    /// Sets the entry's mask bit, keeping vector, trigger and polarity.
    MaskRte(Pin),
    /// Clears the entry's mask bit.
    UnmaskRte(Pin),
    /// Reads the entry: the kernel answers whether Remote IRR is set.
    CheckRemoteIrr(Pin),
    /// Clears a stale Remote IRR: writes the entry level-triggered, still
    /// masked and with its vector, then takes `path` (ADR 0027).
    ClearRemoteIrr { pin: Pin, path: ClearPath },
    /// Writes the issued entry: the destination word first (physical, the
    /// boot CPU), then vector, fixed delivery, the trigger and polarity,
    /// unmasked.
    ProgramRte {
        pin: Pin,
        vector: u8,
        level: bool,
        active_low: bool,
    },
}

/// One I/O APIC register write.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum RteWrite {
    /// The low word of the action's pin's entry.
    Low(u32),
    /// The high word of the entry.
    High(u32),
    /// The EOI register, with a vector.
    Eoi(u32),
}

impl Action {
    /// The pin the action names.
    pub const fn pin(&self) -> Pin {
        match *self {
            Action::MaskRte(pin)
            | Action::UnmaskRte(pin)
            | Action::CheckRemoteIrr(pin)
            | Action::ClearRemoteIrr { pin, .. }
            | Action::ProgramRte { pin, .. } => pin,
        }
    }

    /// The register writes, in order, that perform the action on a pin
    /// whose entry's low word reads `low`, for the boot CPU's local APIC
    /// `apic_id`. `CheckRemoteIrr` writes nothing: its answer is
    /// [`apic::remote_irr`] of `low`. Read-only bits in `low` (delivery
    /// status, Remote IRR) are written back as read, which the I/O APIC
    /// ignores.
    pub const fn writes(&self, low: u32, apic_id: u8) -> [Option<RteWrite>; 3] {
        match *self {
            Action::MaskRte(_) => [
                Some(RteWrite::Low(low | apic::REDIRECTION_MASKED)),
                None,
                None,
            ],
            Action::UnmaskRte(_) => [
                Some(RteWrite::Low(low & !apic::REDIRECTION_MASKED)),
                None,
                None,
            ],
            Action::CheckRemoteIrr(_) => [None, None, None],
            Action::ClearRemoteIrr { path, .. } => {
                let level = low | apic::REDIRECTION_MASKED | apic::REDIRECTION_LEVEL;
                match path {
                    ClearPath::EoiRegister => [
                        Some(RteWrite::Low(level)),
                        Some(RteWrite::Eoi(low & apic::REDIRECTION_VECTOR)),
                        None,
                    ],
                    ClearPath::TriggerToggle => [
                        Some(RteWrite::Low(level)),
                        Some(RteWrite::Low(level & !apic::REDIRECTION_LEVEL)),
                        Some(RteWrite::Low(level)),
                    ],
                }
            }
            Action::ProgramRte {
                vector,
                level,
                active_low,
                ..
            } => [
                Some(RteWrite::High(apic::redirection_destination(apic_id))),
                Some(RteWrite::Low(apic::redirection_entry(
                    vector, level, active_low,
                ))),
                None,
            ],
        }
    }
}

/// A SynIC SINT register write the kernel performs for `core::irq` (M9):
/// it reads SINTn, then writes [`SintAction::value`] of what it read.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum SintAction {
    /// `GetSint`: the SINT unmasked with `vector`, AutoEOI and polling off.
    Issue { sint: u8, vector: u8 },
    /// The last handler deleted: the mask bit set.
    Mask(u8),
}

impl SintAction {
    /// The SINT it writes, 0 to 15.
    pub const fn sint(&self) -> u8 {
        match *self {
            SintAction::Issue { sint, .. } | SintAction::Mask(sint) => sint,
        }
    }

    /// The value it writes to a SINT that reads `old`, every reserved bit
    /// as read ([`crate::hyperv::sint_issued`],
    /// [`crate::hyperv::sint_deleted`]).
    pub const fn value(&self, old: u64) -> u64 {
        match *self {
            SintAction::Issue { vector, .. } => crate::hyperv::sint_issued(old, vector),
            SintAction::Mask(_) => crate::hyperv::sint_deleted(old),
        }
    }
}

/// What `core::irq` needs from the kernel beyond slots, threads and IPC:
/// the IRQ table, the routes, the IRQ node and the I/O APICs; from M9 the
/// boot CPU's APIC ID, for MSI messages, and the SynIC's SINTs. The kernel
/// implements it over statics, `arch/x86_64/ioapic.rs` and
/// `arch/x86_64/hyperv.rs`, the host tests over models of an I/O APIC and
/// a SynIC.
pub trait Interrupts {
    /// The IRQ table.
    fn irq_table(&self) -> &IrqTable;

    /// The IRQ table, to change.
    fn irq_table_mut(&mut self) -> &mut IrqTable;

    /// The routes the kernel found at boot.
    fn routing(&self) -> &Routing;

    /// The IRQ node's first slot; IRQ `irq`'s is [`node_slot`]. The node
    /// is [`IRQS`] ordinary slots in kernel memory.
    fn irq_node(&self) -> SlotAddr;

    /// Performs `action` on its pin's I/O APIC. Returns whether Remote IRR
    /// is set for `CheckRemoteIrr`, and false for every other action.
    fn irq_action(&mut self, action: Action) -> bool;

    /// The boot CPU's local APIC ID (bits 31:24 of its ID register): the
    /// destination of every MSI `GetMSI` describes.
    fn apic_id(&self) -> u8;

    /// Whether the kernel set the SynIC up at boot, which it does exactly
    /// when it makes the Hypervisor capability (ADR 0029). Without it
    /// `GetSint` is `IllegalOperation` and no SINT is touched.
    fn synic(&self) -> bool;

    /// Performs `action` on its SINT: reads SINTn, writes
    /// [`SintAction::value`]. Called only when [`Interrupts::synic`] holds.
    fn sint_action(&mut self, action: SintAction);
}

/// IRQ `irq`'s slot in the IRQ node.
pub fn node_slot<E: Interrupts + ?Sized>(e: &E, irq: u8) -> SlotAddr {
    debug_assert!((irq as usize) < IRQS);
    e.irq_node().offset(u64::from(irq))
}

// ---------------------------------------------------------------------------
// IRQControl
// ---------------------------------------------------------------------------

/// What a successful issue returns.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Issued {
    pub irq: u8,
    pub gsi: u32,
    pub level: bool,
    pub active_low: bool,
}

/// Decodes and performs the IRQControl invocation `msg` of the capability
/// in `control`: `GetISA` and `GetIOAPIC` (M7), `GetMSI` and `GetSint`
/// (M9). Results go to the caller's message registers when it called.
pub fn invoke_control<K: Kernel + Threads + Interrupts + ?Sized>(
    k: &mut K,
    control: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    match msg.label {
        label::GET_ISA => {
            let [isa_irq, index, depth] = msg.args(1)?;
            if isa_irq >= ISA_IRQS as u64 {
                return Err(SyscallError::RangeError {
                    min: 0,
                    max: ISA_IRQS as u64 - 1,
                }
                .into());
            }
            let route = k.routing().isa[isa_irq as usize];
            let (route, pin, io) = route
                .and_then(|r| k.routing().pin(u64::from(r.gsi)).map(|(p, io)| (r, p, io)))
                .ok_or(SyscallError::InvalidArgument(0))?;
            let dest = (msg.cap(0), index, depth);
            let issued = issue(k, control, route, pin, io, dest)?;
            let flags = IsaRoute {
                gsi: issued.gsi,
                level: issued.level,
                active_low: issued.active_low,
            }
            .flags();
            let words = [
                u64::from(issued.irq),
                u64::from(issued.gsi),
                u64::from(flags),
            ];
            Ok(invoke::results(k, &words))
        }
        label::GET_IOAPIC => {
            let [gsi, trigger, polarity, index, depth] = msg.args(1)?;
            let (pin, io) = k
                .routing()
                .pin(gsi)
                .ok_or(SyscallError::InvalidArgument(0))?;
            // Every GSI an I/O APIC serves fits (`Routing::from_platform`).
            let gsi = u32::try_from(gsi).map_err(|_| SyscallError::InvalidArgument(0))?;
            if trigger > 1 || polarity > 1 {
                return Err(SyscallError::RangeError { min: 0, max: 1 }.into());
            }
            let route = IsaRoute {
                gsi,
                level: trigger == 1,
                active_low: polarity == 1,
            };
            let dest = (msg.cap(0), index, depth);
            let issued = issue(k, control, route, pin, io, dest)?;
            Ok(invoke::results(k, &[u64::from(issued.irq)]))
        }
        label::GET_MSI => {
            let [index, depth] = msg.args(1)?;
            let irq = k
                .irq_table()
                .lowest_free()
                .ok_or(SyscallError::RevokeFirst)?;
            let dst = invoke::destination(k, msg.cap(0), index, depth)?;
            issue_entry(k, control, dst, irq, Source::Msi);
            let words = [u64::from(irq), msi_address(k.apic_id()), msi_data(irq)];
            Ok(invoke::results(k, &words))
        }
        label::GET_SINT if !k.synic() => Err(SyscallError::IllegalOperation.into()),
        label::GET_SINT => {
            let [sint, index, depth] = msg.args(1)?;
            if sint >= SINTS as u64 {
                return Err(SyscallError::RangeError {
                    min: 0,
                    max: SINTS as u64 - 1,
                }
                .into());
            }
            let sint = sint as u8;
            if k.irq_table().sint_holder(sint).is_some() {
                return Err(SyscallError::RevokeFirst.into());
            }
            let irq = k
                .irq_table()
                .lowest_free()
                .ok_or(SyscallError::RevokeFirst)?;
            let dst = invoke::destination(k, msg.cap(0), index, depth)?;
            issue_entry(k, control, dst, irq, Source::Sint(sint));
            k.sint_action(SintAction::Issue {
                sint,
                vector: vector(irq),
            });
            Ok(invoke::results(k, &[u64::from(irq)]))
        }
        _ => Err(SyscallError::IllegalOperation.into()),
    }
}

/// Once every check of an issue has passed: IRQ `irq`'s entry, with
/// `pending` and `masked` clear, and its IRQHandler in `dst`, a revocable
/// child of IRQControl.
fn issue_entry<K: Kernel + Interrupts + ?Sized>(
    k: &mut K,
    control: SlotAddr,
    dst: SlotAddr,
    irq: u8,
    source: Source,
) {
    k.irq_table_mut().set(
        irq,
        Entry {
            source,
            pending: false,
            masked: false,
        },
    );
    cdt::insert_derived(k, control, dst, handler_cap(irq), true)
        .expect("IRQControl is a derivation root, which cannot be copied");
}

/// Steps 5 and 6 of an issue, then the issue itself: the GSI must have no
/// handler and a vector must be free; the pin is masked, keeping its
/// fields, and a set Remote IRR is cleared and must then read clear
/// (ADR 0027); then the destination slot. Only then the entry, the
/// capability (a revocable child of IRQControl) and the final
/// redirection entry are written.
fn issue<K: Kernel + Threads + Interrupts + ?Sized>(
    k: &mut K,
    control: SlotAddr,
    route: IsaRoute,
    pin: Pin,
    io: IoApicDesc,
    (root, index, depth): (Cap, u64, u64),
) -> Result<Issued, SyscallError> {
    if k.irq_table().holder(route.gsi).is_some() {
        return Err(SyscallError::RevokeFirst);
    }
    let irq = k
        .irq_table()
        .lowest_free()
        .ok_or(SyscallError::RevokeFirst)?;
    k.irq_action(Action::MaskRte(pin));
    if k.irq_action(Action::CheckRemoteIrr(pin)) {
        let path = if io.has_eoi_register() {
            ClearPath::EoiRegister
        } else {
            ClearPath::TriggerToggle
        };
        k.irq_action(Action::ClearRemoteIrr { pin, path });
        if k.irq_action(Action::CheckRemoteIrr(pin)) {
            return Err(SyscallError::RevokeFirst);
        }
    }
    let dst = invoke::destination(k, root, index, depth)?;
    let source = Source::IoApic {
        gsi: route.gsi,
        pin,
        level: route.level,
        active_low: route.active_low,
    };
    issue_entry(k, control, dst, irq, source);
    k.irq_action(Action::ProgramRte {
        pin,
        vector: vector(irq),
        level: route.level,
        active_low: route.active_low,
    });
    Ok(Issued {
        irq,
        gsi: route.gsi,
        level: route.level,
        active_low: route.active_low,
    })
}

// ---------------------------------------------------------------------------
// IRQHandler
// ---------------------------------------------------------------------------

/// Decodes and performs the IRQHandler invocation `msg` of the capability
/// in `slot`: `Ack`, `SetNotification` and `Clear`.
pub fn invoke_handler<K: Kernel + Interrupts + ?Sized>(
    k: &mut K,
    slot: SlotAddr,
    msg: &Message<'_>,
) -> Result<Reply, InvokeError> {
    let Some(irq) = handler_irq(&k.load(slot).cap) else {
        return Err(SyscallError::InvalidCapability(0).into());
    };
    match msg.label {
        label::ACK => ack(k, irq),
        label::SET_NOTIFICATION => {
            let Some(x) = msg.extra_caps.first() else {
                return Err(SyscallError::TruncatedMessage.into());
            };
            if !NotificationCap::from_cap(&x.cap).is_some_and(|n| n.can_signal()) {
                return Err(SyscallError::InvalidCapability(1).into());
            }
            if cdt::child_too_deep(k, x.slot) {
                return Err(SyscallError::IllegalOperation.into());
            }
            let node = node_slot(k, irq);
            cnode::delete(k, node)?;
            // The hooks the deletion ran (a notification's finalisation)
            // move no capability, but every slot is read again after one.
            let src = k.load(x.slot).cap;
            if src == x.cap {
                cdt::insert_derived(k, x.slot, node, src, false)
                    .expect("SetNotification checked the depth");
            }
        }
        label::CLEAR => cnode::delete(k, node_slot(k, irq))?,
        _ => return Err(SyscallError::IllegalOperation.into()),
    }
    Ok(Reply::EMPTY)
}

/// `IRQHandler_Ack`: clears `pending` and unmasks the pin if the kernel
/// masked it. Nothing for an MSI or a SINT, which are never masked.
pub fn ack<E: Interrupts + ?Sized>(e: &mut E, irq: u8) {
    let mut entry = e.irq_table().entry(irq);
    if let Source::IoApic { pin, .. } = entry.source {
        if entry.masked {
            e.irq_action(Action::UnmaskRte(pin));
        }
        entry.pending = false;
        entry.masked = false;
        e.irq_table_mut().set(irq, entry);
    }
}

// ---------------------------------------------------------------------------
// Delivery
// ---------------------------------------------------------------------------

/// What [`deliver`] did with an interrupt.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Delivery {
    /// The entry was free: a source deleted while its interrupt was
    /// pending, or a stale MSI. Dropped.
    Stale,
    /// No notification was bound: the interrupt is lost, though the pin's
    /// state advanced.
    Lost,
    /// The bound notification was signalled.
    Signalled,
}

/// The interrupt path's work for IRQ `irq`'s vector, with the interrupted
/// thread's registers saved and before the EOI (`docs/design.md`,
/// "Delivery"): a level pin is masked; an edge pin is masked if `pending`
/// is already set, and then `pending` is set; an MSI or a SINT stays as it
/// is; the notification in the IRQ node slot, if any, is signalled with
/// its capability's badge. Constant work; reads no user memory. The caller
/// EOIs, then runs the scheduler, which switches to a thread the signal
/// woke if it outranks the one interrupted.
pub fn deliver<E: IpcEnv + Interrupts + ?Sized>(e: &mut E, irq: u8) -> Delivery {
    let mut entry = e.irq_table().entry(irq);
    match entry.source {
        Source::Free => {
            e.irq_table_mut().stale += 1;
            return Delivery::Stale;
        }
        Source::IoApic { pin, level, .. } => {
            let mask = level || entry.pending;
            if mask && !entry.masked {
                e.irq_action(Action::MaskRte(pin));
            }
            entry.masked |= mask;
            entry.pending |= !level;
            e.irq_table_mut().set(irq, entry);
        }
        Source::Msi | Source::Sint(_) => {}
    }
    match NotificationCap::from_cap(&e.load(node_slot(e, irq)).cap) {
        Some(n) => {
            ipc::signal(e, n.ntfn, n.badge);
            Delivery::Signalled
        }
        None => {
            e.irq_table_mut().lost += 1;
            Delivery::Lost
        }
    }
}

// ---------------------------------------------------------------------------
// Deletion
// ---------------------------------------------------------------------------

/// The IRQHandler arm of the kernel's `finalise` hook: the last
/// capability to an IRQ deletes its IRQ node slot's capability (which may
/// finalise the notification, as seL4's `deletingIRQHandler`) and returns
/// itself as the cleanup, so that [`after_delete`] frees the IRQ once the
/// handler's slot is empty. Any other deletion does nothing.
pub fn finalise<K: Kernel + Interrupts + ?Sized>(k: &mut K, cap: Cap, last: bool) -> Option<Cap> {
    let irq = handler_irq(&cap)?;
    if !last {
        return None;
    }
    cnode::delete(k, node_slot(k, irq)).expect(
        "an IRQ node slot holds only a notification capability, whose deletion never stops",
    );
    Some(cap)
}

/// The IRQHandler arm of the kernel's `after_delete` hook (seL4's
/// `deletedIRQHandler`): masks the pin, keeping its vector and trigger, or
/// the SINT, and frees the entry and its vector. An MSI's device is not
/// touched: a message it still sends lands on a free entry.
pub fn after_delete<E: Interrupts + ?Sized>(e: &mut E, cap: Cap) {
    let Some(irq) = handler_irq(&cap) else {
        return;
    };
    match e.irq_table().entry(irq).source {
        Source::IoApic { pin, .. } => {
            e.irq_action(Action::MaskRte(pin));
        }
        Source::Sint(sint) => e.sint_action(SintAction::Mask(sint)),
        Source::Free | Source::Msi => {}
    }
    e.irq_table_mut().set(irq, Entry::FREE);
}

// ---------------------------------------------------------------------------
// Invariants
// ---------------------------------------------------------------------------

/// The IRQ table's invariants (`docs/design.md`, "Interrupts",
/// Invariants), as a function for the tests: each GSI has at most one
/// entry, and its pin is the one the routes give; a free entry has
/// neither `pending` nor `masked`, and nothing in its IRQ node slot; a
/// level entry is never `pending`; an MSI or SINT entry is never `pending`
/// or `masked`; a SINT below 16 has at most one entry, and only with a
/// SynIC; every IRQ node slot is empty or holds a notification capability
/// with Write.
pub fn check<E: SlotMemory + Interrupts + ?Sized>(e: &E) -> Result<(), &'static str> {
    let table = e.irq_table();
    for (i, entry) in table.entries().iter().enumerate() {
        let node = e.load(node_slot(e, i as u8)).cap;
        if !node.is_null() && !NotificationCap::from_cap(&node).is_some_and(|n| n.can_signal()) {
            return Err("an IRQ node slot holds something other than a notification with Write");
        }
        match entry.source {
            Source::Free => {
                if entry.pending || entry.masked {
                    return Err("a free entry is pending or masked");
                }
                if !node.is_null() {
                    return Err("a free entry's IRQ node slot holds a capability");
                }
            }
            Source::IoApic {
                gsi, pin, level, ..
            } => {
                if table.holder(gsi) != Some(i as u8) {
                    return Err("a GSI has two entries");
                }
                if e.routing().pin(u64::from(gsi)).map(|(p, _)| p) != Some(pin) {
                    return Err("an entry's pin is not its GSI's");
                }
                if level && entry.pending {
                    return Err("a level entry is pending");
                }
            }
            Source::Msi | Source::Sint(_) if entry.pending || entry.masked => {
                return Err("an MSI or SINT entry is pending or masked");
            }
            Source::Msi => {}
            Source::Sint(sint) => {
                if usize::from(sint) >= SINTS || !e.synic() {
                    return Err("a SINT entry without a SynIC, or past SINT 15");
                }
                if table.sint_holder(sint) != Some(i as u8) {
                    return Err("a SINT has two entries");
                }
            }
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests;
