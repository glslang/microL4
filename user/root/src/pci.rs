//! Root's PCI setup on QEMU (`docs/design.md`, "PCI on QEMU") and
//! `test=pci` ("Network scenarios"). No PCI manager runs: root reaches
//! ECAM through device frames it carves out of device untyped and maps
//! uncached at [`WINDOW`] in its own VSpace, scans with the crate `pci`,
//! sizes the virtio-net function's BARs, checks its regions and MSI-X
//! ([`pci::Plan`]), carves the pages the driver will map and the MSI-X
//! table's page, programs MSI-X entry 0, and unmaps configuration space
//! and the table; it keeps every capability.
//!
//! `test=pci` does all of that and programs MSI-X entry 0 with
//! `IRQControl_GetMSI`'s message, leaving bus mastering off: no driver
//! runs, so the device has nothing to send. It then maps the region pages
//! in its own VSpace, reads the device's `num_queues` and MAC without
//! touching its status, prints the function's first 256 bytes of
//! configuration space as the firmware left them (the `pci` crate's
//! fixture, `user/pci/tests/q35-virtio-net.cfg`), unmaps everything and
//! passes. `test=net` (builder W) adds binding the handler, bus mastering
//! and the driver.

use core::fmt;
use core::marker::PhantomData;

use ::pci::{Address, Bytes, Config, Function, Kind, Msix, Plan, Segment};
use libsys::bootinfo::{CAP_INIT_VSPACE, CAP_IRQ_CONTROL, Ecam as EcamRange};
use libsys::device::{Msi, irq_control_get_msi};
use libsys::mem::{Mmio, Regs};
use libsys::objects::{CarveError, Carver};
use libsys::vspace::{self, HUGE_PAGE, PAGE, READ_WRITE, Table, UNCACHED};
use libsys::{BootInfo, CPtr, Error, Ipc, ObjectAlloc, ObjectType, Slot, println};

use crate::fail;

/// Where root maps ECAM in its own VSpace: the 2 MiB frame that holds bus
/// `b` at `WINDOW` + (its address - the segment's base rounded down to 2
/// MiB), so bus `b`'s 1 MiB is at `WINDOW` + (`base` mod 2 MiB) + `b <<
/// 20`. All 256 buses fit below [`MSIX_WINDOW`].
pub const WINDOW: u64 = 0x2000_0000;
/// Where root maps the page that holds MSI-X entry 0, under a page table
/// of its own.
pub const MSIX_WINDOW: u64 = 0x3400_0000;
/// Where `test=pci` maps the regions' pages, region `r`'s at `r` times 64
/// KiB from here, under the same page table.
const REGIONS_WINDOW: u64 = MSIX_WINDOW + 0x10_0000;
/// 2 MiB frames ECAM can need: 256 MiB of buses from a base 1 MiB into a
/// 2 MiB page.
const ECAM_FRAMES: usize = 129;
const _: () = assert!(WINDOW + ECAM_FRAMES as u64 * HUGE_PAGE <= MSIX_WINDOW);
const _: () = assert!(REGIONS_WINDOW + 3 * ::pci::virtio::REGION_WINDOW <= MSIX_WINDOW + HUGE_PAGE);

/// Why a bus cannot be reached.
#[derive(Clone, Copy, Debug)]
pub enum ReachError {
    Carve { paddr: u64, error: CarveError },
    Map { paddr: u64, error: Error },
}

impl fmt::Display for ReachError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ReachError::Carve { paddr, error } => {
                write!(f, "carving the 2 MiB device frame at {paddr:#x}: {error}")
            }
            ReachError::Map { paddr, error } => {
                write!(f, "mapping the 2 MiB device frame at {paddr:#x}: {error}")
            }
        }
    }
}

/// One function's 4 KiB of ECAM, or the MSI-X table's page, as a
/// [`Config`], for as long as `'e` keeps it mapped.
pub struct Cfg<'e> {
    regs: Mmio,
    mapped: PhantomData<&'e ()>,
}

impl Cfg<'_> {
    /// # Safety
    ///
    /// As `Mmio::new`'s, for as long as the `Cfg` lives.
    unsafe fn new(base: u64, len: usize) -> Self {
        Cfg {
            // SAFETY: the caller's.
            regs: unsafe { Mmio::new(base as *mut u8, len) },
            mapped: PhantomData,
        }
    }
}

impl Config for Cfg<'_> {
    fn read8(&self, offset: u16) -> u8 {
        self.regs.read8(offset.into())
    }
    fn read16(&self, offset: u16) -> u16 {
        self.regs.read16(offset.into())
    }
    fn read32(&self, offset: u16) -> u32 {
        self.regs.read32(offset.into())
    }
    fn write8(&self, offset: u16, value: u8) {
        self.regs.write8(offset.into(), value)
    }
    fn write16(&self, offset: u16, value: u16) {
        self.regs.write16(offset.into(), value)
    }
    fn write32(&self, offset: u16, value: u32) {
        self.regs.write32(offset.into(), value)
    }
}

/// A segment's ECAM, its 2 MiB device frames carved and mapped uncached
/// at [`WINDOW`] as the scan reaches each bus. The carver and the
/// allocator stay borrowed until [`Ecam::unmap`].
pub struct Ecam<'s, 'a> {
    ipc: Ipc,
    pub objects: &'s mut ObjectAlloc<'a>,
    pub carver: &'s mut Carver<'a>,
    pub range: ::pci::Range,
    /// Bus 0's configuration space, physical.
    base: u64,
    /// `base` rounded down to 2 MiB: the physical address at [`WINDOW`].
    window_base: u64,
    /// The frame for each 2 MiB of the window, by slot; 0 for none yet.
    frames: [CPtr; ECAM_FRAMES],
}

impl<'s, 'a> Ecam<'s, 'a> {
    pub fn new(
        ipc: Ipc,
        objects: &'s mut ObjectAlloc<'a>,
        carver: &'s mut Carver<'a>,
        e: &EcamRange,
    ) -> Ecam<'s, 'a> {
        Ecam {
            ipc,
            objects,
            carver,
            range: ::pci::Range {
                segment: e.segment,
                start_bus: e.start_bus,
                end_bus: e.end_bus,
            },
            base: e.base,
            window_base: e.base & !(HUGE_PAGE - 1),
            frames: [0; ECAM_FRAMES],
        }
    }

    /// The window's 2 MiB frame that holds bus `bus`.
    fn frame_index(&self, bus: u8) -> usize {
        ((self.base - self.window_base + (u64::from(bus) << 20)) / HUGE_PAGE) as usize
    }

    /// Carves a device frame for whoever asks.
    pub fn carve(&mut self, paddr: u64, ty: ObjectType) -> Result<CPtr, CarveError> {
        self.carver.carve_frame(self.ipc, self.objects, paddr, ty)
    }

    /// Unmaps every ECAM frame, ending this view of configuration space;
    /// root keeps the capabilities.
    pub fn unmap(self) {
        for &frame in self.frames.iter().filter(|&&f| f != 0) {
            vspace::frame_unmap(frame)
                .unwrap_or_else(|e| fail!("pci: unmapping the ECAM frame in slot {frame}: {e}"));
        }
    }
}

impl Segment for Ecam<'_, '_> {
    type Function<'f>
        = Cfg<'f>
    where
        Self: 'f;
    type Error = ReachError;

    fn reach(&mut self, bus: u8) -> Result<(), ReachError> {
        let i = self.frame_index(bus);
        if self.frames[i] != 0 {
            return Ok(());
        }
        let paddr = self.window_base + i as u64 * HUGE_PAGE;
        let frame = self
            .carve(paddr, ObjectType::Frame2M)
            .map_err(|error| ReachError::Carve { paddr, error })?;
        let vaddr = WINDOW + i as u64 * HUGE_PAGE;
        vspace::frame_map(
            self.ipc,
            frame,
            vaddr,
            READ_WRITE,
            UNCACHED,
            CAP_INIT_VSPACE,
        )
        .map_err(|error| ReachError::Map { paddr, error })?;
        self.frames[i] = frame;
        Ok(())
    }

    fn function(&self, at: Address) -> Cfg<'_> {
        assert!(
            self.frames[self.frame_index(at.bus)] != 0,
            "pci: bus {} read before it was reached",
            at.bus
        );
        let vaddr = WINDOW + (self.base - self.window_base) + at.ecam_offset();
        // SAFETY: `reach` carved the 2 MiB device frame that holds bus
        // `at.bus`'s 1 MiB and mapped it read-write and uncached at
        // `WINDOW` + its offset from `window_base`, the only mapping of it,
        // as the assertion checks; function `at`'s 4 KiB lie inside it.
        // The frame stays mapped until `unmap`, which takes `self`, and
        // the `Cfg` borrows `self`, so it cannot outlive the mapping.
        // Nothing holds a reference into it: it is reached only through
        // `Mmio`'s volatile accesses.
        unsafe { Cfg::new(vaddr, ::pci::CONFIG_BYTES) }
    }
}

/// BootInfo's first ECAM range, with its line printed; none fails the
/// test.
pub fn ecam_range(bi: &BootInfo) -> EcamRange {
    let info = &bi.interrupts;
    if info.ecam_count == 0 {
        fail!("pci: no ECAM range: BootInfo's InterruptInfo lists none, so no PCI");
    }
    let e = info.ecam[0];
    println!(
        "pci: ecam {:#x}, segment {}, buses {}-{}",
        e.base, e.segment, e.start_bus, e.end_bus
    );
    e
}

/// Scans, printing a line for each function and the count, and returns
/// the first virtio-net function.
pub fn find_virtio_net(ecam: &mut Ecam<'_, '_>) -> Function {
    let mut found = None;
    let range = ecam.range;
    let seen = ::pci::scan(ecam, range, |f| {
        println!("pci: {f}");
        if found.is_none() && ::pci::is_virtio_net(f) {
            found = Some(*f);
        }
    })
    .unwrap_or_else(|e| fail!("pci: bus {}: {}", e.bus, e.error));
    println!(
        "pci: {} functions on {} bus{}",
        seen.functions,
        seen.buses,
        if seen.buses == 1 { "" } else { "es" }
    );
    found.unwrap_or_else(|| fail!("pci: no virtio-net function"))
}

/// Sizes `f`'s BARs and checks its plan, printing what it found.
pub fn plan(ecam: &Ecam<'_, '_>, f: &Function) -> Plan {
    let cfg = ecam.function(f.address);
    let bars = ::pci::size(&cfg, f);
    let mut line = Line::new();
    for (i, bar) in bars.iter().enumerate() {
        line.push(if i == 0 { "" } else { "; " }, format_args!("{bar}"));
    }
    println!(
        "pci: virtio-net at {}: {:04x}:{:04x}, subsystem {:04x}:{:04x}; {}",
        f.address,
        f.vendor,
        f.device,
        f.subsystem_vendor,
        f.subsystem,
        line.as_str()
    );
    let plan = Plan::virtio_net(f, &cfg, &bars).unwrap_or_else(|why| fail!("pci: {why}"));
    let r = |k| plan.region(k);
    println!(
        "pci: virtio-net: {}; {}, notify_off_multiplier {}; {}",
        r(Kind::Common),
        r(Kind::Notify),
        plan.notify_off_multiplier,
        r(Kind::Device)
    );
    println!(
        "pci: virtio-net: MSI-X {} vectors, table at {} ({:#x}), PBA at {} ({:#x})",
        plan.msix.vectors, plan.msix.table, plan.table, plan.msix.pba, plan.pba
    );
    plan
}

/// The device frames the driver maps and the MSI-X table's page, by slot.
pub struct Pages {
    /// [`Plan::pages`]'s, in its order.
    pub regions: [CPtr; 48],
    pub count: usize,
    pub table: CPtr,
}

/// Carves every page `plan` names: the regions' for the driver and the
/// MSI-X table's for root.
pub fn carve_pages(ecam: &mut Ecam<'_, '_>, plan: &Plan) -> Pages {
    let mut pages = Pages {
        regions: [0; 48],
        count: 0,
        table: 0,
    };
    for p in plan.pages() {
        let slot = ecam
            .carve(p.paddr, ObjectType::Frame4K)
            .unwrap_or_else(|e| {
                fail!(
                    "pci: virtio-net: carving {}'s page {} at {:#x}: {e}",
                    p.kind.name(),
                    p.index,
                    p.paddr
                )
            });
        pages.regions[pages.count] = slot;
        pages.count += 1;
    }
    let table = plan.table_page();
    pages.table = ecam.carve(table, ObjectType::Frame4K).unwrap_or_else(|e| {
        fail!("pci: virtio-net: carving the MSI-X table's page at {table:#x}: {e}")
    });
    pages
}

/// `test=pci`.
pub fn run(bi: &BootInfo) -> ! {
    let ipc = Ipc::root();
    if bi.user_image_end > WINDOW {
        fail!(
            "pci: the root image reaches {:#x}, past the ECAM window",
            bi.user_image_end
        );
    }
    let range = ecam_range(bi);
    let mut objects = ObjectAlloc::new(bi);
    let mut carver = Carver::new(bi, &objects.untyped);
    // One page table for the MSI-X window and the regions' look.
    let table = objects
        .retype(ipc, ObjectType::PageTable, 0, 1)
        .unwrap_or_else(|e| fail!("pci: retyping a page table: {e}"));
    vspace::map_table(ipc, table, Table::PageTable, MSIX_WINDOW, CAP_INIT_VSPACE)
        .unwrap_or_else(|e| fail!("pci: mapping a page table at {MSIX_WINDOW:#x}: {e}"));

    let mut ecam = Ecam::new(ipc, &mut objects, &mut carver, &range);
    let f = find_virtio_net(&mut ecam);
    // The first 256 bytes as the firmware left them, before sizing.
    let mut snapshot = [0u8; ::pci::HEADER_BYTES];
    {
        let cfg = ecam.function(f.address);
        for (i, dword) in snapshot.as_chunks_mut::<4>().0.iter_mut().enumerate() {
            dword.copy_from_slice(&cfg.read32(4 * i as u16).to_le_bytes());
        }
    }
    let plan = plan(&ecam, &f);
    let pages = carve_pages(&mut ecam, &plan);

    // Memory decode on, so the table and the region pages answer; bus
    // mastering stays off: no driver runs, so the device has no message
    // to send and no DMA to do.
    let (_, msi) = get_msi(ipc, ecam.objects);
    let cfg = ecam.function(f.address);
    ::pci::enable_memory(&cfg, false);
    let was = program_msix(ipc, &cfg, &plan, &pages, &msi);
    println!(
        "pci: virtio-net: MSI-X entry 0 at {:#x} was {}masked (vector control {was:#x}); \
         now IRQ {}: address {:#x}, data {:#x}, unmasked, MSI-X enabled",
        plan.table,
        if was & ::pci::msix::VECTOR_MASKED != 0 {
            ""
        } else {
            "not "
        },
        msi.irq,
        msi.address,
        msi.data
    );
    look_at_regions(ipc, &plan, &pages);

    for (i, row) in snapshot.as_chunks::<16>().0.iter().enumerate() {
        let mut line = Line::new();
        for b in row {
            line.push(" ", format_args!("{b:02x}"));
        }
        println!("pci: cfg {:02x}:{}", 16 * i, line.as_str());
    }
    ecam.unmap();
    let slots = 1u64 << bi.root_cnode_bits;
    println!(
        "pci: configuration space and the MSI-X table unmapped; root CNode {} of {slots} slots used",
        slots - objects.slots.remaining()
    );
    println!("TEST PASS");
    libsys::exit(0)
}

/// A handler for one MSI from `IRQControl_GetMSI`, in a fresh slot, and
/// its message.
pub fn get_msi(ipc: Ipc, objects: &mut ObjectAlloc<'_>) -> (CPtr, Msi) {
    let slot = objects
        .slots
        .alloc(1)
        .unwrap_or_else(|| fail!("pci: no free slot for the MSI handler"));
    let msi = irq_control_get_msi(ipc, CAP_IRQ_CONTROL, Slot::root_cnode(slot))
        .unwrap_or_else(|e| fail!("pci: IRQControl_GetMSI: {e}"));
    (slot, msi)
}

/// Programs MSI-X entry 0 of the function `cfg` reaches to send `msi`
/// (`docs/design.md`, "PCI on QEMU", "Interrupt"): maps the table's page
/// uncached at [`MSIX_WINDOW`], programs it with [`Msix::program`], reads
/// entry 0 and Message Control back, and unmaps the page, so no driver
/// ever sees the table. Memory decode must be on. Returns entry 0's
/// Vector Control as it was; fails the test if what reads back is not
/// what was written.
pub fn program_msix(ipc: Ipc, cfg: &Cfg<'_>, plan: &Plan, pages: &Pages, msi: &Msi) -> u32 {
    vspace::frame_map(
        ipc,
        pages.table,
        MSIX_WINDOW,
        READ_WRITE,
        UNCACHED,
        CAP_INIT_VSPACE,
    )
    .unwrap_or_else(|e| fail!("pci: mapping the MSI-X table's page: {e}"));
    // SAFETY: the MSI-X table's page, a device frame carved for it, was
    // just mapped read-write and uncached at `MSIX_WINDOW`, its only
    // mapping, and stays mapped until the unmap below, after the last use
    // of `table`; it is reached only through `Mmio`.
    let table = unsafe { Cfg::new(MSIX_WINDOW, PAGE as usize) };
    let at = plan.entry0_in_page();
    let was = Msix::vector_control(&table, at);
    let message = ::pci::Message {
        address: msi.address,
        data: msi.data,
    };
    plan.msix.program(cfg, &table, at, message);
    let entry = [0, 4, 8, 12].map(|o| table.read32(at + o));
    let want = [
        msi.address as u32,
        (msi.address >> 32) as u32,
        msi.data,
        was & !::pci::msix::VECTOR_MASKED,
    ];
    let control = cfg.read16(u16::from(plan.msix.cap) + 2);
    vspace::frame_unmap(pages.table)
        .unwrap_or_else(|e| fail!("pci: unmapping the MSI-X table's page: {e}"));
    if entry != want {
        fail!("pci: virtio-net: MSI-X entry 0 reads back {entry:#x?}, not {want:#x?}");
    }
    if control & ::pci::msix::ENABLE == 0 || control & ::pci::msix::FUNCTION_MASK != 0 {
        fail!("pci: virtio-net: MSI-X Message Control reads back {control:#x}");
    }
    was
}

/// Maps the region pages in root's own VSpace as the driver's windows lay
/// them out, reads `num_queues` and the MAC (under `config_generation`)
/// and unmaps them.
fn look_at_regions(ipc: Ipc, plan: &Plan, pages: &Pages) {
    for (p, &frame) in plan.pages().zip(&pages.regions[..pages.count]) {
        vspace::frame_map(
            ipc,
            frame,
            REGIONS_WINDOW + p.offset,
            READ_WRITE,
            UNCACHED,
            CAP_INIT_VSPACE,
        )
        .unwrap_or_else(|e| fail!("pci: mapping {}'s page {}: {e}", p.kind.name(), p.index));
    }
    let window = |k: Kind| {
        let r = plan.region(k);
        let at = REGIONS_WINDOW + k.index() as u64 * ::pci::virtio::REGION_WINDOW;
        // SAFETY: the loop above mapped every page of region `k`
        // read-write and uncached from `at`, each device frame's only
        // mapping, so its `length` bytes from `at + in_page` are mapped;
        // they stay mapped until the unmaps below, after the last use of
        // the window, and are reached only through `Mmio`.
        unsafe { Mmio::new((at + u64::from(r.in_page())) as *mut u8, r.length as usize) }
    };
    let common = window(Kind::Common);
    let device = window(Kind::Device);
    let queues = common.read16(COMMON_NUM_QUEUES);
    let mut mac = [0u8; 6];
    let mut tries = 0;
    loop {
        let before = common.read8(COMMON_CONFIG_GENERATION);
        for (i, b) in mac.iter_mut().enumerate() {
            *b = device.read8(i);
        }
        if common.read8(COMMON_CONFIG_GENERATION) == before {
            break;
        }
        tries += 1;
        if tries == 16 {
            fail!("pci: virtio-net: config_generation changed 16 times while the MAC was read");
        }
    }
    println!(
        "pci: virtio-net: {queues} queues, MAC {:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}",
        mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]
    );
    for &frame in &pages.regions[..pages.count] {
        vspace::frame_unmap(frame).unwrap_or_else(|e| fail!("pci: unmapping a region page: {e}"));
    }
    println!(
        "pci: virtio-net: {} region pages ({}) carved and mapped uncached, then unmapped",
        plan.page_count(),
        Bytes(plan.page_count() * PAGE)
    );
}

/// The common configuration's `num_queues` and `config_generation`
/// (virtio 1.2, 4.1.4.3, from memory of `struct virtio_pci_common_cfg`).
const COMMON_NUM_QUEUES: usize = 0x12;
const COMMON_CONFIG_GENERATION: usize = 0x15;

/// A line built a piece at a time, for lists printed on one line.
struct Line {
    buf: [u8; 512],
    len: usize,
}

impl Line {
    fn new() -> Line {
        Line {
            buf: [0; 512],
            len: 0,
        }
    }

    fn push(&mut self, sep: &str, piece: fmt::Arguments<'_>) {
        use fmt::Write;
        // A line too long is cut short; nothing here is that long.
        let _ = self.write_str(sep);
        let _ = self.write_fmt(piece);
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.buf[..self.len]).unwrap_or("(not UTF-8)")
    }
}

impl fmt::Write for Line {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let end = self.len + s.len();
        if end > self.buf.len() {
            return Err(fmt::Error);
        }
        self.buf[self.len..end].copy_from_slice(s.as_bytes());
        self.len = end;
        Ok(())
    }
}
