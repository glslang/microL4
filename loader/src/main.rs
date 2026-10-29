//! The microL4 UEFI loader.
//!
//! It runs as `\EFI\BOOT\BOOTX64.EFI` on the EFI system partition and:
//!
//! 1. finds the ACPI RSDP and the GOP framebuffer,
//! 2. reads `\kernel.elf` and the optional `\cmdline.txt` from the same
//!    partition,
//! 3. copies the kernel's segments into freshly allocated pages,
//! 4. builds page tables that map the kernel at `KERNEL_VIRT_BASE`, all of
//!    physical memory at `PHYS_MAP_BASE` and low memory 1:1,
//! 5. exits boot services, converts the memory map, fills in the
//!    [`Handoff`], and
//! 6. switches to the new page tables and jumps to the kernel.
//!
//! docs/boot.md specifies the state the kernel is entered in.

#![no_std]
#![no_main]
#![warn(clippy::undocumented_unsafe_blocks)]

#[macro_use]
mod serial;
mod paging;
mod uefi;
mod x86;

use core::ffi::c_void;
use core::fmt;
use core::ptr;

use l4core::elf::{Elf, ElfError, PAGE_SIZE};
use l4core::handoff::{
    self, CMDLINE_MAX, Framebuffer, HANDOFF_MAGIC, HANDOFF_VERSION, Handoff, KERNEL_VIRT_BASE,
    MemoryRegion, PixelFormat, RegionKind,
};

use paging::PageTables;
use uefi::{BootServices, FileProtocol, Guid, Handle, Status, SystemTable};

/// The direct map covers at least this much, so that low MMIO such as the
/// local APIC and the framebuffer is always reachable.
const MIN_PHYS_MAP: u64 = 4 << 30;
/// ...and at most one PML4 slot, which keeps it clear of the kernel image.
const MAX_PHYS_MAP: u64 = 512 << 30;
/// Spare memory-map descriptors to allow for allocations made between
/// sizing the map and reading it for the last time.
const MAP_SLACK_DESCRIPTORS: usize = 32;

#[derive(Debug)]
enum Error {
    Efi(&'static str, Status),
    Elf(ElfError),
    Missing(&'static str),
    Truncated(&'static str),
    Unsupported(&'static str),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Efi(what, status) => write!(f, "{what}: {status}"),
            Self::Elf(e) => write!(f, "kernel.elf: {e}"),
            Self::Missing(what) => write!(f, "{what} not found"),
            Self::Truncated(what) => write!(f, "{what} is shorter than its reported size"),
            Self::Unsupported(what) => write!(f, "unsupported: {what}"),
        }
    }
}

/// Everything needed to enter the kernel once boot services are gone.
struct Launch {
    pml4: u64,
    entry: u64,
    handoff: u64,
}

#[unsafe(no_mangle)]
extern "efiapi" fn efi_main(image: Handle, system_table: *mut SystemTable) -> Status {
    serial::init();
    log!("microL4 loader {}", env!("CARGO_PKG_VERSION"));
    // SAFETY: the firmware passes a valid system table that outlives boot
    // services.
    let st = unsafe { &*system_table };
    match boot(image, st) {
        Ok(launch) => {
            // SAFETY: `boot` built page tables that map this code 1:1 and the
            // kernel at its link address, and loaded the kernel. Boot services
            // are gone, so nothing else owns the machine.
            unsafe { x86::enter_kernel(launch.pml4, launch.entry, launch.handoff) }
        }
        Err(e) => {
            log!("LOADER ERROR: {e}");
            x86::fail()
        }
    }
}

fn boot(image: Handle, st: &SystemTable) -> Result<Launch, Error> {
    // SAFETY: the system table's boot services pointer is valid until
    // ExitBootServices, and `boot` calls nothing through it afterwards.
    let bs = unsafe { &*st.boot_services };
    if x86::la57_enabled() {
        return Err(Error::Unsupported("5-level paging is on"));
    }

    let rsdp = find_rsdp(st);
    match rsdp {
        0 => log!("no ACPI RSDP"),
        _ => log!("ACPI RSDP at {rsdp:#x}"),
    }
    let framebuffer = find_framebuffer(bs);
    match framebuffer.base {
        0 => log!("no GOP framebuffer"),
        base => log!(
            "GOP framebuffer {}x{} at {base:#x}",
            framebuffer.width,
            framebuffer.height
        ),
    }

    let root = open_boot_volume(bs, image)?;
    let kernel_file = read_file(bs, root, "\\kernel.elf")?.ok_or(Error::Missing("\\kernel.elf"))?;
    let cmdline = read_file(bs, root, "\\cmdline.txt")?.unwrap_or(&[]);
    let cmdline = cmdline.trim_ascii();
    let cmdline = &cmdline[..cmdline.len().min(CMDLINE_MAX)];
    log!(
        "kernel.elf: {} KiB; cmdline: {:?}",
        kernel_file.len() >> 10,
        core::str::from_utf8(cmdline).unwrap_or("?")
    );

    let elf = Elf::parse(kernel_file).map_err(Error::Elf)?;
    let (kernel_phys, kernel_size) = load_kernel(bs, &elf)?;
    log!(
        "kernel loaded at phys {kernel_phys:#x}, {} KiB, entry {:#x}",
        kernel_size >> 10,
        elf.entry()
    );

    let handoff_phys = alloc_pages(bs, size_of::<Handoff>().div_ceil(PAGE_SIZE as usize))?;
    let mut map = MapBuffers::alloc(bs)?;
    let phys_map_size = map
        .phys_top(bs)?
        .clamp(MIN_PHYS_MAP, MAX_PHYS_MAP)
        .next_multiple_of(1 << 30);

    let nx = x86::nx_supported();
    if nx {
        // SAFETY: the CPU reports NX support, so setting EFER.NXE is valid.
        // Firmware page tables do not depend on it being clear.
        unsafe { x86::enable_nx() };
    }
    let mut pt = PageTables::alloc(bs, paging::tables_needed(phys_map_size, kernel_size), nx)?;
    pt.map_identity(phys_map_size)?;
    pt.map_direct(phys_map_size)?;
    for seg in elf.segments().filter(|s| s.memsz > 0) {
        pt.map_kernel_segment(&seg, kernel_phys)?;
    }
    log!(
        "page tables: {} pages, direct map {} GiB, NX {}",
        pt.used(),
        phys_map_size >> 30,
        if nx { "on" } else { "off" }
    );

    log!("exiting boot services");
    let (map_size, desc_size) = map.exit_boot_services(bs, image)?;
    // Boot services are gone from here on: no allocation, no protocols.
    x86::disable_interrupts();
    let len = convert_memory_map(&map.raw[..map_size], desc_size, map.regions);

    // SAFETY: `handoff_phys` is a fresh, page-aligned LoaderData allocation
    // large enough for a Handoff, identity-mapped by the firmware's page
    // tables that are still live.
    let h = unsafe { &mut *(handoff_phys as *mut Handoff) };
    *h = Handoff {
        magic: HANDOFF_MAGIC,
        version: HANDOFF_VERSION,
        size: size_of::<Handoff>() as u32,
        kernel_phys_base: kernel_phys,
        kernel_size,
        phys_map_size,
        memory_map: map.regions.as_ptr() as u64,
        memory_map_len: len as u64,
        rsdp,
        framebuffer,
        cmdline_len: cmdline.len() as u64,
        cmdline: [0; CMDLINE_MAX],
    };
    h.cmdline[..cmdline.len()].copy_from_slice(cmdline);
    log!("{len} memory regions; entering kernel");

    Ok(Launch {
        pml4: pt.root(),
        entry: elf.entry(),
        handoff: handoff_phys,
    })
}

/// Allocates `pages` zeroed 4 KiB pages of LoaderData and returns the
/// physical address of the first.
fn alloc_pages(bs: &BootServices, pages: usize) -> Result<u64, Error> {
    let mut addr = 0u64;
    // SAFETY: a plain AllocatePages call with a valid out pointer.
    unsafe {
        (bs.allocate_pages)(
            uefi::ALLOCATE_ANY_PAGES,
            uefi::LOADER_DATA,
            pages,
            &mut addr,
        )
    }
    .ok()
    .map_err(|s| Error::Efi("AllocatePages", s))?;
    // SAFETY: the firmware just gave us these pages, and its page tables map
    // all memory 1:1.
    unsafe { ptr::write_bytes(addr as *mut u8, 0, pages * PAGE_SIZE as usize) };
    Ok(addr)
}

fn find_rsdp(st: &SystemTable) -> u64 {
    // SAFETY: the firmware's configuration table has
    // `number_of_table_entries` valid entries.
    let tables =
        unsafe { core::slice::from_raw_parts(st.configuration_table, st.number_of_table_entries) };
    let find = |guid: Guid| {
        tables
            .iter()
            .find(|t| t.vendor_guid == guid)
            .map(|t| t.vendor_table as u64)
    };
    find(uefi::ACPI_20_TABLE)
        .or_else(|| find(uefi::ACPI_10_TABLE))
        .unwrap_or(0)
}

fn find_framebuffer(bs: &BootServices) -> Framebuffer {
    let mut gop: *mut c_void = ptr::null_mut();
    // SAFETY: LocateProtocol with a valid GUID and out pointer.
    let status =
        unsafe { (bs.locate_protocol)(&uefi::GRAPHICS_OUTPUT_PROTOCOL, ptr::null_mut(), &mut gop) };
    if status.is_error() || gop.is_null() {
        return Framebuffer::default();
    }
    // SAFETY: the firmware returned a live GOP instance; its mode and mode
    // information stay valid until the mode changes, which nothing does.
    let (mode, info) = unsafe {
        let mode = &*(*(gop as *const uefi::GraphicsOutputProtocol)).mode;
        (mode, &*mode.info)
    };
    let format = match info.pixel_format {
        uefi::PIXEL_RGB_RESERVED_8BIT => PixelFormat::RGB,
        uefi::PIXEL_BGR_RESERVED_8BIT => PixelFormat::BGR,
        // Bitmask formats and BLT-only modes have no usable linear framebuffer.
        _ => return Framebuffer::default(),
    };
    Framebuffer {
        base: mode.frame_buffer_base,
        size: mode.frame_buffer_size as u64,
        width: info.horizontal_resolution,
        height: info.vertical_resolution,
        stride: info.pixels_per_scan_line,
        format,
    }
}

/// Opens the root directory of the partition this loader was started from.
fn open_boot_volume(bs: &BootServices, image: Handle) -> Result<*mut FileProtocol, Error> {
    let mut loaded: *mut c_void = ptr::null_mut();
    // SAFETY: HandleProtocol on our own image handle, with a valid out pointer.
    unsafe { (bs.handle_protocol)(image, &uefi::LOADED_IMAGE_PROTOCOL, &mut loaded) }
        .ok()
        .map_err(|s| Error::Efi("LoadedImage protocol", s))?;
    // SAFETY: the firmware returned a live LoadedImage protocol instance.
    let device = unsafe { (*(loaded as *const uefi::LoadedImageProtocol)).device_handle };

    let mut fs: *mut c_void = ptr::null_mut();
    // SAFETY: as above, on the device our image was loaded from.
    unsafe { (bs.handle_protocol)(device, &uefi::SIMPLE_FILE_SYSTEM_PROTOCOL, &mut fs) }
        .ok()
        .map_err(|s| Error::Efi("SimpleFileSystem protocol", s))?;
    let fs = fs as *mut uefi::SimpleFileSystemProtocol;

    let mut root = ptr::null_mut();
    // SAFETY: `fs` is a live SimpleFileSystem instance.
    unsafe { ((*fs).open_volume)(fs, &mut root) }
        .ok()
        .map_err(|s| Error::Efi("OpenVolume", s))?;
    Ok(root)
}

/// Reads a whole file into fresh LoaderData pages. Returns `None` if the file
/// does not exist.
fn read_file(
    bs: &BootServices,
    root: *mut FileProtocol,
    path: &'static str,
) -> Result<Option<&'static [u8]>, Error> {
    // UCS-2 and NUL-terminated: the zeros after the path end it.
    let mut name = [0u16; 64];
    assert!(path.len() < name.len(), "path too long");
    for (slot, unit) in name.iter_mut().zip(path.encode_utf16()) {
        *slot = unit;
    }

    let mut file = ptr::null_mut();
    // SAFETY: `root` is a live directory handle and `name` is NUL-terminated.
    let status = unsafe { ((*root).open)(root, &mut file, name.as_ptr(), uefi::FILE_MODE_READ, 0) };
    if status.is_error() {
        // Any failure to open counts as absent; reads below report real errors.
        return Ok(None);
    }

    #[repr(C, align(8))]
    struct InfoBuffer([u8; 512]);
    let mut info = InfoBuffer([0; 512]);
    let mut info_size = info.0.len();
    // SAFETY: `file` is a live handle and the buffer is as large as stated.
    unsafe { ((*file).get_info)(file, &uefi::FILE_INFO, &mut info_size, info.0.as_mut_ptr()) }
        .ok()
        .map_err(|s| Error::Efi("GetInfo", s))?;
    let off = uefi::FILE_INFO_FILE_SIZE_OFFSET;
    let size = u64::from_le_bytes(info.0[off..off + 8].try_into().unwrap()) as usize;

    let data: &'static mut [u8] = if size == 0 {
        &mut []
    } else {
        let addr = alloc_pages(bs, size.div_ceil(PAGE_SIZE as usize))?;
        // SAFETY: a fresh allocation of at least `size` bytes, identity-mapped
        // and never freed, so it lives as long as the program.
        unsafe { core::slice::from_raw_parts_mut(addr as *mut u8, size) }
    };
    let mut done = 0;
    while done < size {
        let mut chunk = size - done;
        // SAFETY: the destination has `size - done` writable bytes left.
        unsafe { ((*file).read)(file, &mut chunk, data[done..].as_mut_ptr()) }
            .ok()
            .map_err(|s| Error::Efi("Read", s))?;
        if chunk == 0 {
            return Err(Error::Truncated(path));
        }
        done += chunk;
    }
    // SAFETY: `file` is a live handle we opened. A failed close loses nothing.
    let _ = unsafe { ((*file).close)(file) };
    Ok(Some(data))
}

/// Copies the kernel's loadable segments into one contiguous allocation and
/// returns its physical address and size.
fn load_kernel(bs: &BootServices, elf: &Elf<'_>) -> Result<(u64, u64), Error> {
    let (start, end) = elf.bounds();
    if start != KERNEL_VIRT_BASE {
        return Err(Error::Unsupported("kernel not linked at KERNEL_VIRT_BASE"));
    }
    let size = end - start;
    let phys = alloc_pages(bs, (size / PAGE_SIZE) as usize)?;
    for seg in elf.segments() {
        let bytes = elf.file_bytes(&seg);
        // SAFETY: Elf::parse checked every segment lies inside
        // [start, end), and the allocation covers that range; the rest of
        // each segment (BSS) is already zero.
        unsafe {
            ptr::copy_nonoverlapping(
                bytes.as_ptr(),
                (phys + (seg.vaddr - start)) as *mut u8,
                bytes.len(),
            )
        };
    }
    Ok((phys, size))
}

/// The buffers for the final memory map, allocated before it is read so that
/// reading it does not change it.
struct MapBuffers {
    raw: &'static mut [u8],
    regions: &'static mut [MemoryRegion],
}

impl MapBuffers {
    fn alloc(bs: &BootServices) -> Result<Self, Error> {
        let (mut size, mut key, mut desc_size, mut version) = (0usize, 0usize, 0usize, 0u32);
        // SAFETY: a size query: a zero-sized buffer and valid out pointers.
        let status = unsafe {
            (bs.get_memory_map)(
                &mut size,
                ptr::null_mut(),
                &mut key,
                &mut desc_size,
                &mut version,
            )
        };
        if status != Status::BUFFER_TOO_SMALL || desc_size < size_of::<uefi::MemoryDescriptor>() {
            return Err(Error::Efi("GetMemoryMap size query", status));
        }
        let descriptors = size / desc_size + MAP_SLACK_DESCRIPTORS;
        let raw_bytes = descriptors * desc_size;
        let raw = alloc_pages(bs, raw_bytes.div_ceil(PAGE_SIZE as usize))?;
        let regions = alloc_pages(
            bs,
            (descriptors * size_of::<MemoryRegion>()).div_ceil(PAGE_SIZE as usize),
        )?;
        // SAFETY: fresh page-aligned allocations of the stated sizes, never
        // freed. MemoryRegion is plain integers, so zeroed memory is valid.
        unsafe {
            Ok(Self {
                raw: core::slice::from_raw_parts_mut(raw as *mut u8, raw_bytes),
                regions: core::slice::from_raw_parts_mut(regions as *mut MemoryRegion, descriptors),
            })
        }
    }

    /// Reads the memory map into `raw` and returns its key and descriptor
    /// size.
    fn read(&mut self, bs: &BootServices) -> Result<(usize, usize, usize), Error> {
        let (mut size, mut key, mut desc_size, mut version) =
            (self.raw.len(), 0usize, 0usize, 0u32);
        // SAFETY: `raw` is writable for `size` bytes.
        unsafe {
            (bs.get_memory_map)(
                &mut size,
                self.raw.as_mut_ptr(),
                &mut key,
                &mut desc_size,
                &mut version,
            )
        }
        .ok()
        .map_err(|s| Error::Efi("GetMemoryMap", s))?;
        Ok((size, key, desc_size))
    }

    /// One past the highest address of memory the kernel might use: RAM,
    /// firmware and ACPI memory, but not reserved or MMIO ranges, which can
    /// sit near the top of the address space (QEMU reserves a hole below
    /// 1 TiB). Low MMIO is covered by the 4 GiB minimum instead.
    fn phys_top(&mut self, bs: &BootServices) -> Result<u64, Error> {
        let (size, _, desc_size) = self.read(bs)?;
        let top = descriptors(&self.raw[..size], desc_size)
            .filter(|d| !matches!(region_kind(d.ty), RegionKind::RESERVED | RegionKind::MMIO))
            .map(|d| {
                d.physical_start
                    .saturating_add(d.number_of_pages.saturating_mul(PAGE_SIZE))
            })
            .max()
            .unwrap_or(0);
        Ok(top)
    }

    /// Reads the final memory map into `raw` and exits boot services.
    /// Returns the map's size in bytes and its descriptor size.
    fn exit_boot_services(
        &mut self,
        bs: &BootServices,
        image: Handle,
    ) -> Result<(usize, usize), Error> {
        // ExitBootServices fails if the map changed since it was read, which
        // firmware events can cause. Only GetMemoryMap may be called between
        // attempts.
        let mut last = Status::SUCCESS;
        for _ in 0..3 {
            let (size, key, desc_size) = self.read(bs)?;
            // SAFETY: `key` came from the GetMemoryMap call just above.
            last = unsafe { (bs.exit_boot_services)(image, key) };
            if last == Status::SUCCESS {
                return Ok((size, desc_size));
            }
            if last != Status::INVALID_PARAMETER {
                break;
            }
        }
        Err(Error::Efi("ExitBootServices", last))
    }
}

/// Iterates over raw UEFI memory descriptors `stride` bytes apart.
fn descriptors(raw: &[u8], stride: usize) -> impl Iterator<Item = uefi::MemoryDescriptor> + '_ {
    raw.chunks_exact(stride).map(|d| {
        // SAFETY: each chunk holds at least one descriptor (checked when the
        // buffers were sized); read_unaligned copes with any alignment.
        unsafe { ptr::read_unaligned(d.as_ptr() as *const uefi::MemoryDescriptor) }
    })
}

/// Converts the firmware's memory map into sorted, merged [`MemoryRegion`]s.
/// Runs after ExitBootServices, so it must not allocate.
fn convert_memory_map(raw: &[u8], stride: usize, out: &mut [MemoryRegion]) -> usize {
    let mut n = 0;
    for (d, slot) in descriptors(raw, stride).zip(out.iter_mut()) {
        *slot = MemoryRegion::new(
            d.physical_start,
            d.number_of_pages * PAGE_SIZE,
            region_kind(d.ty),
        );
        n += 1;
    }
    handoff::normalize_regions(&mut out[..n])
}

fn region_kind(efi_type: u32) -> RegionKind {
    match efi_type {
        uefi::CONVENTIONAL_MEMORY | uefi::BOOT_SERVICES_CODE | uefi::BOOT_SERVICES_DATA => {
            RegionKind::USABLE
        }
        uefi::LOADER_CODE | uefi::LOADER_DATA => RegionKind::LOADER,
        uefi::RUNTIME_SERVICES_CODE | uefi::RUNTIME_SERVICES_DATA => RegionKind::FIRMWARE,
        uefi::ACPI_RECLAIM_MEMORY => RegionKind::ACPI_RECLAIMABLE,
        uefi::ACPI_MEMORY_NVS => RegionKind::ACPI_NVS,
        uefi::MEMORY_MAPPED_IO | uefi::MEMORY_MAPPED_IO_PORT_SPACE => RegionKind::MMIO,
        uefi::UNUSABLE_MEMORY => RegionKind::BAD,
        uefi::RESERVED_MEMORY_TYPE | uefi::PERSISTENT_MEMORY => RegionKind::RESERVED,
        // PAL code, unaccepted memory and vendor-specific types.
        _ => RegionKind::RESERVED,
    }
}

#[panic_handler]
fn panic(info: &core::panic::PanicInfo) -> ! {
    log!("LOADER PANIC: {info}");
    x86::fail()
}
