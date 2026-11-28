//! The virtio-net function and the plan of its pages (`docs/design.md`,
//! "PCI on QEMU", "The virtio-net function"): its modern interface's
//! common, notify and device regions, found through virtio's
//! vendor-specific capabilities (`struct virtio_pci_cap` and
//! `virtio_pci_notify_cap`, as Linux's BSD-licensed
//! `include/uapi/linux/virtio_pci.h` lays them out; from memory), and its
//! MSI-X table, each checked against the BAR that holds it. The ISR region
//! is not needed with MSI-X, and the legacy I/O BAR is never used.

use core::fmt;

use crate::{Address, Bar, Bars, Bytes, Config, Function, HEADER_BYTES, LAYOUT_DEVICE, Msix, PAGE};

/// The virtio vendor ID, and virtio-net's device IDs: modern, and
/// transitional with subsystem device 1, the network device (virtio 1.2,
/// 4.1.2, from memory).
pub const VENDOR: u16 = 0x1AF4;
pub const DEVICE_NET: u16 = 0x1041;
pub const DEVICE_TRANSITIONAL_NET: u16 = 0x1000;
pub const SUBSYSTEM_NET: u16 = 1;
/// The vendor-specific capability ID virtio's capabilities use.
pub const CAP_VENDOR: u8 = 0x09;
/// `struct virtio_pci_cap`'s fields, from the capability's start: `cap_len`,
/// `cfg_type`, `bar`, `offset` and `length`; `virtio_pci_notify_cap` adds
/// `notify_off_multiplier`.
const CAP_LEN: u16 = 2;
const CFG_TYPE: u16 = 3;
const CAP_BAR: u16 = 4;
const CAP_OFFSET: u16 = 8;
const CAP_LENGTH: u16 = 12;
const CAP_MULTIPLIER: u16 = 16;

/// The most bytes a region may have: it starts below 4 KiB into its 64
/// KiB window in the driver's VSpace and ends inside it.
pub const MAX_REGION: u32 = 60 << 10;
/// Each region's window in the driver's VSpace: region `r` at `r` times
/// this from the windows' base (`virtio_net::layout::REGIONS`).
pub const REGION_WINDOW: u64 = 64 << 10;

/// Whether `f` is a virtio-net device: vendor `0x1AF4` and device
/// `0x1041`, or the transitional `0x1000` with subsystem device 1.
pub fn is_virtio_net(f: &Function) -> bool {
    f.vendor == VENDOR
        && f.layout() == LAYOUT_DEVICE
        && (f.device == DEVICE_NET
            || (f.device == DEVICE_TRANSITIONAL_NET && f.subsystem == SUBSYSTEM_NET))
}

/// The three regions the driver maps, in window order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    Common,
    Notify,
    Device,
}

impl Kind {
    pub const ALL: [Kind; 3] = [Kind::Common, Kind::Notify, Kind::Device];

    /// Its window, 0 to 2.
    pub const fn index(self) -> usize {
        self as usize
    }

    /// Its `cfg_type`: `VIRTIO_PCI_CAP_COMMON_CFG` (1), `NOTIFY_CFG` (2)
    /// and `DEVICE_CFG` (4).
    pub const fn cfg_type(self) -> u8 {
        match self {
            Kind::Common => 1,
            Kind::Notify => 2,
            Kind::Device => 4,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Kind::Common => "common",
            Kind::Notify => "notify",
            Kind::Device => "device",
        }
    }

    /// The capability's least `cap_len`: 16, and 20 for notify's
    /// multiplier.
    const fn cap_bytes(self) -> u8 {
        match self {
            Kind::Notify => 20,
            _ => 16,
        }
    }

    /// The fewest bytes the driver takes (`virtio_net::Start`): the common
    /// configuration's 56, a 16-bit notify, and the device region's MAC
    /// and status.
    pub const fn min_length(self) -> u32 {
        match self {
            Kind::Common => 56,
            Kind::Notify => 2,
            Kind::Device => 8,
        }
    }
}

/// One region, as its capability names it and its BAR places it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Region {
    pub kind: Kind,
    /// Its capability's offset in configuration space.
    pub cap: u8,
    pub bar: u8,
    /// Its offset in the BAR.
    pub offset: u32,
    pub length: u32,
    /// Its first byte's physical address.
    pub paddr: u64,
}

impl Region {
    /// The physical address of its first page.
    pub const fn page(&self) -> u64 {
        self.paddr & !(PAGE - 1)
    }

    /// Its offset in its first page, and so in its window.
    pub const fn in_page(&self) -> u32 {
        (self.paddr & (PAGE - 1)) as u32
    }

    /// Pages it touches: at most 16.
    pub const fn pages(&self) -> u64 {
        (self.in_page() as u64 + self.length as u64).div_ceil(PAGE)
    }

    /// The driver's argument word: its offset in its window plus its
    /// length shifted up 16 bits (`docs/design.md`, "Arguments").
    pub const fn word(&self) -> u32 {
        self.in_page() | self.length << 16
    }

    const fn page_end(&self) -> u64 {
        self.page() + self.pages() * PAGE
    }
}

/// `common at BAR4+0x0, 4 KiB`.
impl fmt::Display for Region {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "{} at BAR{}+{:#x}, {}",
            self.kind.name(),
            self.bar,
            self.offset,
            Bytes(self.length.into())
        )
    }
}

/// One page a driver maps: page `index` of region `kind`, at `offset` in
/// the driver's regions window (`kind`'s window, then the page).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Page {
    pub kind: Kind,
    pub index: u64,
    pub paddr: u64,
    pub offset: u64,
}

/// What a check names: a region, the MSI-X table or the PBA.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum What {
    Region(Kind),
    Table,
    Pba,
}

impl fmt::Display for What {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            What::Region(k) => f.write_str(k.name()),
            What::Table => f.write_str("the MSI-X table"),
            What::Pba => f.write_str("the MSI-X PBA"),
        }
    }
}

/// Why a virtio-net function cannot be driven. Root prints it after
/// `pci: `.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Refusal {
    /// No capability of this type with `cap_len` long enough, in the
    /// header, naming a memory BAR 0 to 5 that sized.
    NoCapability(Kind),
    /// No MSI-X capability, or its table or PBA not in a memory BAR.
    NoMsix,
    /// Past its BAR's size, or an address that overflows.
    Outside {
        what: What,
        bar: u8,
    },
    /// The pages a region touches reach past its BAR.
    PagesOutside {
        kind: Kind,
        bar: u8,
    },
    TooShort {
        kind: Kind,
        length: u32,
    },
    TooLong {
        kind: Kind,
        length: u32,
    },
    /// `notify_off_multiplier` is odd, which virtio forbids (0 or even;
    /// virtio 1.2, 4.1.4.4, from memory).
    OddMultiplier(u32),
    /// A page of the region is also a page of `with`.
    SharesPage {
        kind: Kind,
        with: What,
    },
    /// MSI-X entry 0 does not lie in one page.
    EntryCrossesPage,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("virtio-net: ")?;
        match *self {
            Refusal::NoCapability(k) => write!(f, "no {} capability", k.name()),
            Refusal::NoMsix => f.write_str("no MSI-X"),
            Refusal::Outside {
                what: What::Region(k),
                bar,
            } => write!(f, "{} outside BAR{bar}", k.name()),
            Refusal::Outside { what, bar } => {
                let what = if what == What::Table {
                    "MSI-X table"
                } else {
                    "MSI-X PBA"
                };
                write!(f, "{what} outside BAR{bar}")
            }
            Refusal::PagesOutside { kind, bar } => {
                write!(f, "{}'s pages reach outside BAR{bar}", kind.name())
            }
            Refusal::TooShort { kind, length } => write!(
                f,
                "{} region of {length} bytes, under {}",
                kind.name(),
                kind.min_length()
            ),
            Refusal::TooLong { kind, length } => write!(
                f,
                "{} region of {length} bytes, over {MAX_REGION}",
                kind.name()
            ),
            Refusal::OddMultiplier(m) => write!(f, "notify_off_multiplier {m} is odd"),
            Refusal::SharesPage { kind, with } => {
                write!(f, "{} shares a page with {with}", kind.name())
            }
            Refusal::EntryCrossesPage => f.write_str("MSI-X entry 0 crosses a page"),
        }
    }
}

/// A virtio-net function's checked regions and MSI-X: the pages root
/// carves for the driver and maps in its VSpace ([`Plan::pages`]), and the
/// page of the MSI-X table that root alone maps ([`Plan::table_page`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Plan {
    pub function: Address,
    /// By [`Kind::index`].
    pub regions: [Region; 3],
    pub notify_off_multiplier: u32,
    pub msix: Msix,
    /// The physical addresses of the MSI-X table and PBA.
    pub table: u64,
    pub pba: u64,
}

impl Plan {
    /// The plan for the virtio-net function `f`, whose BARs `bars` are
    /// sized, checked in this order: the first capability of each type
    /// the driver uses that names a memory BAR; the MSI-X capability, its
    /// table and PBA in memory BARs; each region no shorter than the
    /// driver takes and at most 60 KiB, inside its BAR, whole pages of it
    /// too; an even `notify_off_multiplier`; the table and the PBA inside
    /// their BARs, entry 0 in one page; and no page of a region shared
    /// with the table, the PBA or another region.
    pub fn virtio_net(f: &Function, cfg: &impl Config, bars: &Bars) -> Result<Plan, Refusal> {
        let mut found: [Option<Found>; 3] = [None; 3];
        for at in f.capabilities.with_id(CAP_VENDOR) {
            let c = u16::from(at);
            let ty = cfg.read8(c + CFG_TYPE);
            let Some(kind) = Kind::ALL.into_iter().find(|k| k.cfg_type() == ty) else {
                continue;
            };
            let need = kind.cap_bytes();
            if found[kind.index()].is_some()
                || usize::from(at) + usize::from(need) > HEADER_BYTES
                || cfg.read8(c + CAP_LEN) < need
            {
                continue;
            }
            // A BAR index above 5 is reserved, and `memory` gives none.
            let Some(bar) = bars.memory(cfg.read8(c + CAP_BAR)) else {
                continue;
            };
            let multiplier = if kind == Kind::Notify {
                cfg.read32(c + CAP_MULTIPLIER)
            } else {
                0
            };
            found[kind.index()] = Some(Found {
                cap: at,
                bar,
                offset: cfg.read32(c + CAP_OFFSET),
                length: cfg.read32(c + CAP_LENGTH),
                multiplier,
            });
        }
        let caps = Kind::ALL.map(|k| found[k.index()].ok_or(Refusal::NoCapability(k)));
        let caps = [caps[0]?, caps[1]?, caps[2]?];
        let msix = Msix::find(f, cfg).ok_or(Refusal::NoMsix)?;
        let table_bar = bars.memory(msix.table.bar).ok_or(Refusal::NoMsix)?;
        let pba_bar = bars.memory(msix.pba.bar).ok_or(Refusal::NoMsix)?;

        let mut regions = [Region {
            kind: Kind::Common,
            cap: 0,
            bar: 0,
            offset: 0,
            length: 0,
            paddr: 0,
        }; 3];
        for kind in Kind::ALL {
            let Found {
                cap,
                bar,
                offset,
                length,
                ..
            } = caps[kind.index()];
            if length < kind.min_length() {
                return Err(Refusal::TooShort { kind, length });
            }
            if length > MAX_REGION {
                return Err(Refusal::TooLong { kind, length });
            }
            let paddr = inside(&bar, offset, length.into()).ok_or(Refusal::Outside {
                what: What::Region(kind),
                bar: bar.index,
            })?;
            let r = Region {
                kind,
                cap,
                bar: bar.index,
                offset,
                length,
                paddr,
            };
            // `inside` checked that `base + size`, rounded up to a page,
            // does not overflow.
            if r.page() < bar.base || r.page_end() > bar.base + bar.size {
                return Err(Refusal::PagesOutside {
                    kind,
                    bar: bar.index,
                });
            }
            regions[kind.index()] = r;
        }
        let multiplier = caps[Kind::Notify.index()].multiplier;
        if !multiplier.is_multiple_of(2) {
            return Err(Refusal::OddMultiplier(multiplier));
        }
        let table =
            inside(&table_bar, msix.table.offset, msix.table_bytes()).ok_or(Refusal::Outside {
                what: What::Table,
                bar: table_bar.index,
            })?;
        let pba = inside(&pba_bar, msix.pba.offset, msix.pba_bytes()).ok_or(Refusal::Outside {
            what: What::Pba,
            bar: pba_bar.index,
        })?;
        if (table % PAGE) + crate::msix::ENTRY_BYTES > PAGE {
            return Err(Refusal::EntryCrossesPage);
        }
        let table_pages = pages_of(table, msix.table_bytes());
        let pba_pages = pages_of(pba, msix.pba_bytes());
        for (i, r) in regions.iter().enumerate() {
            let mine = (r.page(), r.page_end());
            let others = [(What::Table, table_pages), (What::Pba, pba_pages)]
                .into_iter()
                .chain(
                    regions[..i]
                        .iter()
                        .map(|o| (What::Region(o.kind), (o.page(), o.page_end()))),
                );
            for (with, theirs) in others {
                if mine.0 < theirs.1 && theirs.0 < mine.1 {
                    return Err(Refusal::SharesPage { kind: r.kind, with });
                }
            }
        }
        Ok(Plan {
            function: f.address,
            regions,
            notify_off_multiplier: multiplier,
            msix,
            table,
            pba,
        })
    }

    pub const fn region(&self, kind: Kind) -> &Region {
        &self.regions[kind.index()]
    }

    /// Every page of the three regions, region by region: what root
    /// carves for the driver and maps uncached in its VSpace.
    pub fn pages(&self) -> impl Iterator<Item = Page> + '_ {
        self.regions.iter().flat_map(|r| {
            (0..r.pages()).map(move |k| Page {
                kind: r.kind,
                index: k,
                paddr: r.page() + k * PAGE,
                offset: r.kind.index() as u64 * REGION_WINDOW + k * PAGE,
            })
        })
    }

    pub fn page_count(&self) -> u64 {
        self.regions.iter().map(Region::pages).sum()
    }

    /// The physical address of the page that holds MSI-X entry 0, which
    /// root alone maps.
    pub const fn table_page(&self) -> u64 {
        self.table & !(PAGE - 1)
    }

    /// Entry 0's offset in [`table_page`](Plan::table_page).
    pub const fn entry0_in_page(&self) -> u16 {
        (self.table % PAGE) as u16
    }
}

/// A capability [`Plan::virtio_net`] takes: where it is, its BAR, its
/// region's offset and length, and notify's multiplier (else 0).
#[derive(Clone, Copy, Debug)]
struct Found {
    cap: u8,
    bar: Bar,
    offset: u32,
    length: u32,
    multiplier: u32,
}

/// The physical address of `bytes` bytes at `offset` in `bar`, if they lie
/// inside it and nothing overflows, the BAR's end rounded up to a page
/// included.
fn inside(bar: &Bar, offset: u32, bytes: u64) -> Option<u64> {
    let end = u64::from(offset).checked_add(bytes)?;
    bar.end()?.checked_add(PAGE)?;
    (end <= bar.size).then(|| bar.base + u64::from(offset))
}

/// The pages `[start, end)` that `bytes` bytes at `paddr` touch, where
/// [`inside`] placed them.
fn pages_of(paddr: u64, bytes: u64) -> (u64, u64) {
    let start = paddr & !(PAGE - 1);
    let end = (paddr + bytes).div_ceil(PAGE) * PAGE;
    (start, end)
}
