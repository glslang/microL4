//! The scan (`docs/design.md`, "PCI on QEMU", "The scan"): for each bus
//! reached, device 0 to 31's function 0, and functions 1 to 7 of a
//! multi-function device; a bridge's secondary bus is reached once, if
//! the range holds it; and each function's capability list, walked from
//! offset `0x34` with every pointer masked, bounded and never revisited.

use core::fmt;

use crate::{
    Address, Config, HEADER_BYTES, LAYOUT_BRIDGE, LAYOUT_DEVICE, MULTI_FUNCTION, NO_VENDOR,
    STATUS_CAPABILITIES, reg,
};

/// The buses an ECAM range decodes: `start_bus` to `end_bus` of one
/// segment (BootInfo's `Ecam`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Range {
    pub segment: u16,
    pub start_bus: u8,
    pub end_bus: u8,
}

impl Range {
    pub const fn contains(&self, bus: u8) -> bool {
        self.start_bus <= bus && bus <= self.end_bus
    }
}

/// The configuration space of one segment's functions, reached a bus at a
/// time.
pub trait Segment {
    /// One function's 4 KiB.
    type Function<'a>: Config
    where
        Self: 'a;
    /// Why a bus cannot be reached.
    type Error;

    /// Makes bus `bus` reachable: called once for each bus the scan
    /// visits, before it reads any of the bus's functions. Root carves
    /// and maps the device frame that holds the bus here.
    fn reach(&mut self, bus: u8) -> Result<(), Self::Error>;

    /// Function `at`'s 4 KiB, on a bus [`reach`](Segment::reach) made
    /// reachable; an implementation may panic on any other.
    fn function(&self, at: Address) -> Self::Function<'_>;
}

/// What a scan found.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Scanned {
    pub functions: usize,
    pub buses: usize,
}

/// A bus the scan could not reach, and why.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ScanError<E> {
    pub bus: u8,
    pub error: E,
}

/// The most capabilities a list can hold: one at each multiple of 4 from
/// `0x40` to `0xFC`, none visited twice.
pub const MAX_CAPABILITIES: usize = (HEADER_BYTES - 0x40) / 4;

/// One entry of a capability list.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Capability {
    pub id: u8,
    /// Where it starts, a multiple of 4 from `0x40`.
    pub offset: u8,
}

/// How a capability walk ended.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum WalkEnd {
    /// Status bit 4 is clear, or the header has no list at `0x34`.
    #[default]
    NoList,
    /// At a null pointer: the list as the specification has it.
    Null,
    /// At a pointer, masked to a multiple of 4, below `0x40`, inside the
    /// header.
    BadPointer(u8),
    /// At a pointer to an entry already visited.
    Loop(u8),
}

/// A function's capability list, in list order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Capabilities {
    list: [Capability; MAX_CAPABILITIES],
    len: u8,
    pub end: WalkEnd,
}

impl Default for Capabilities {
    fn default() -> Capabilities {
        Capabilities {
            list: [Capability::default(); MAX_CAPABILITIES],
            len: 0,
            end: WalkEnd::NoList,
        }
    }
}

impl Capabilities {
    /// Walks the list from `0x34`, if status bit 4 says there is one and
    /// the header layout keeps it there (types 0 and 1).
    pub fn walk(cfg: &impl Config, status: u16, layout: u8) -> Capabilities {
        let mut caps = Capabilities::default();
        if status & STATUS_CAPABILITIES == 0 || layout > LAYOUT_BRIDGE {
            return caps;
        }
        // Bit `(offset - 0x40) / 4`: the entries visited.
        let mut seen = 0u64;
        let mut at = cfg.read8(reg::CAPABILITIES) & !3;
        caps.end = loop {
            if at == 0 {
                break WalkEnd::Null;
            }
            if at < 0x40 {
                break WalkEnd::BadPointer(at);
            }
            let bit = 1u64 << ((at - 0x40) / 4);
            if seen & bit != 0 {
                break WalkEnd::Loop(at);
            }
            seen |= bit;
            let id = cfg.read8(u16::from(at));
            caps.list[usize::from(caps.len)] = Capability { id, offset: at };
            caps.len += 1;
            at = cfg.read8(u16::from(at) + 1) & !3;
        };
        caps
    }

    pub fn as_slice(&self) -> &[Capability] {
        &self.list[..usize::from(self.len)]
    }

    pub fn len(&self) -> usize {
        usize::from(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The offsets of the entries with ID `id`, in list order.
    pub fn with_id(&self, id: u8) -> impl Iterator<Item = u8> + '_ {
        self.as_slice()
            .iter()
            .filter(move |c| c.id == id)
            .map(|c| c.offset)
    }
}

/// One function, as the scan read it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Function {
    pub address: Address,
    pub vendor: u16,
    pub device: u16,
    pub command: u16,
    pub status: u16,
    pub revision: u8,
    /// Base class, subclass and programming interface, in bits 23:16,
    /// 15:8 and 7:0.
    pub class: u32,
    /// Bits 6:0 the layout, bit 7 multi-function.
    pub header_type: u8,
    /// Type 0 only; 0 otherwise.
    pub subsystem_vendor: u16,
    pub subsystem: u16,
    /// The BARs as the firmware programmed them: six for type 0, two for
    /// type 1, none for other layouts (0s).
    pub bars: [u32; 6],
    /// Type 1 only; 0 otherwise.
    pub secondary_bus: u8,
    pub subordinate_bus: u8,
    pub capabilities: Capabilities,
}

impl Function {
    /// The function at `at`, or `None` if its vendor ID reads `0xFFFF`.
    pub fn read(cfg: &impl Config, at: Address) -> Option<Function> {
        let vendor = cfg.read16(reg::VENDOR);
        if vendor == NO_VENDOR {
            return None;
        }
        let class = cfg.read32(reg::CLASS);
        let header_type = cfg.read8(reg::HEADER_TYPE);
        let status = cfg.read16(reg::STATUS);
        let mut f = Function {
            address: at,
            vendor,
            device: cfg.read16(reg::DEVICE),
            command: cfg.read16(reg::COMMAND),
            status,
            revision: class as u8,
            class: class >> 8,
            header_type,
            subsystem_vendor: 0,
            subsystem: 0,
            bars: [0; 6],
            secondary_bus: 0,
            subordinate_bus: 0,
            capabilities: Capabilities::walk(cfg, status, header_type & !MULTI_FUNCTION),
        };
        let count = f.bar_count();
        for (i, bar) in f.bars.iter_mut().enumerate().take(count) {
            *bar = cfg.read32(reg::BAR0 + 4 * i as u16);
        }
        match f.layout() {
            LAYOUT_DEVICE => {
                f.subsystem_vendor = cfg.read16(reg::SUBSYSTEM_VENDOR);
                f.subsystem = cfg.read16(reg::SUBSYSTEM);
            }
            LAYOUT_BRIDGE => {
                f.secondary_bus = cfg.read8(reg::SECONDARY_BUS);
                f.subordinate_bus = cfg.read8(reg::SUBORDINATE_BUS);
            }
            _ => {}
        }
        Some(f)
    }

    /// The header layout: 0 a device, 1 a PCI-to-PCI bridge.
    pub const fn layout(&self) -> u8 {
        self.header_type & !MULTI_FUNCTION
    }

    pub const fn multi_function(&self) -> bool {
        self.header_type & MULTI_FUNCTION != 0
    }

    /// BARs in its header: 6 for a device, 2 for a bridge, else 0.
    pub const fn bar_count(&self) -> usize {
        match self.layout() {
            LAYOUT_DEVICE => 6,
            LAYOUT_BRIDGE => 2,
            _ => 0,
        }
    }

    /// A bridge's secondary bus.
    pub const fn secondary(&self) -> Option<u8> {
        if self.layout() == LAYOUT_BRIDGE {
            Some(self.secondary_bus)
        } else {
            None
        }
    }
}

/// `00:02.0 1af4:1000 class 020000`, root's line for each function.
impl fmt::Display for Function {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} {:04x}:{:04x} class {:06x}",
            self.address, self.vendor, self.device, self.class
        )
    }
}

/// Visits every function of the buses `range` reaches from its first
/// bus, calling `visit` with each in scan order, and returns how many
/// functions and buses it saw. Each bus is visited at most once: a
/// bridge's secondary bus is queued only if `range` holds it and it has
/// not been queued before, so the scan ends on any configuration space,
/// after at most 256 buses. Stops at the first bus `segment` cannot
/// reach.
pub fn scan<S: Segment>(
    segment: &mut S,
    range: Range,
    mut visit: impl FnMut(&Function),
) -> Result<Scanned, ScanError<S::Error>> {
    let mut buses = Buses::new(range);
    buses.push(range.start_bus);
    let mut seen = Scanned::default();
    while let Some(bus) = buses.pop() {
        segment
            .reach(bus)
            .map_err(|error| ScanError { bus, error })?;
        seen.buses += 1;
        for device in 0..32 {
            let zero = Address {
                bus,
                device,
                function: 0,
            };
            let Some(first) = Function::read(&segment.function(zero), zero) else {
                continue;
            };
            let functions = if first.multi_function() { 8 } else { 1 };
            for function in 0..functions {
                let at = Address {
                    bus,
                    device,
                    function,
                };
                let f = if function == 0 {
                    first
                } else {
                    match Function::read(&segment.function(at), at) {
                        Some(f) => f,
                        None => continue,
                    }
                };
                seen.functions += 1;
                visit(&f);
                if let Some(secondary) = f.secondary() {
                    buses.push(secondary);
                }
            }
        }
    }
    Ok(seen)
}

/// The buses to visit, in the order they were found, each queued once.
struct Buses {
    range: Range,
    queued: [u64; 4],
    order: [u8; 256],
    head: usize,
    tail: usize,
}

impl Buses {
    fn new(range: Range) -> Buses {
        Buses {
            range,
            queued: [0; 4],
            order: [0; 256],
            head: 0,
            tail: 0,
        }
    }

    /// Queues `bus` if the range holds it and it was never queued, so at
    /// most 256 are.
    fn push(&mut self, bus: u8) {
        let (word, bit) = (usize::from(bus / 64), 1u64 << (bus % 64));
        if self.range.contains(bus) && self.queued[word] & bit == 0 {
            self.queued[word] |= bit;
            self.order[self.tail] = bus;
            self.tail += 1;
        }
    }

    fn pop(&mut self) -> Option<u8> {
        let bus = *self
            .order
            .get(self.head)
            .filter(|_| self.head < self.tail)?;
        self.head += 1;
        Some(bus)
    }
}
