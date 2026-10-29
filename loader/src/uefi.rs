//! Minimal UEFI bindings: only the tables, protocols and calls the loader
//! uses, laid out as in the UEFI 2.10 specification. Unused function slots
//! are `usize` placeholders so the used ones land at the right offsets, which
//! the assertions at the bottom pin.

use core::ffi::c_void;
use core::mem::offset_of;

pub type Handle = *mut c_void;

/// An EFI_STATUS. Errors have the top bit set.
#[repr(transparent)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Status(pub usize);

impl Status {
    const ERROR: usize = 1 << (usize::BITS - 1);
    pub const SUCCESS: Self = Self(0);
    pub const INVALID_PARAMETER: Self = Self(Self::ERROR | 2);
    pub const BUFFER_TOO_SMALL: Self = Self(Self::ERROR | 5);

    pub fn is_error(self) -> bool {
        self.0 & Self::ERROR != 0
    }

    /// `Ok(())` for success and warnings, `Err(self)` for errors.
    pub fn ok(self) -> Result<(), Status> {
        if self.is_error() { Err(self) } else { Ok(()) }
    }
}

impl core::fmt::Debug for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        core::fmt::Display::fmt(self, f)
    }
}

impl core::fmt::Display for Status {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        if self.is_error() {
            write!(f, "EFI error {}", self.0 & !Self::ERROR)
        } else {
            write!(f, "EFI status {}", self.0)
        }
    }
}

#[repr(C)]
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Guid(pub u32, pub u16, pub u16, pub [u8; 8]);

pub const LOADED_IMAGE_PROTOCOL: Guid = Guid(
    0x5B1B_31A1,
    0x9562,
    0x11D2,
    [0x8E, 0x3F, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);
pub const SIMPLE_FILE_SYSTEM_PROTOCOL: Guid = Guid(
    0x964E_5B22,
    0x6459,
    0x11D2,
    [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);
pub const GRAPHICS_OUTPUT_PROTOCOL: Guid = Guid(
    0x9042_A9DE,
    0x23DC,
    0x4A38,
    [0x96, 0xFB, 0x7A, 0xDE, 0xD0, 0x80, 0x51, 0x6A],
);
pub const FILE_INFO: Guid = Guid(
    0x0957_6E92,
    0x6D3F,
    0x11D2,
    [0x8E, 0x39, 0x00, 0xA0, 0xC9, 0x69, 0x72, 0x3B],
);
pub const ACPI_20_TABLE: Guid = Guid(
    0x8868_E871,
    0xE4F1,
    0x11D3,
    [0xBC, 0x22, 0x00, 0x80, 0xC7, 0x3C, 0x88, 0x81],
);
pub const ACPI_10_TABLE: Guid = Guid(
    0xEB9D_2D30,
    0x2D88,
    0x11D3,
    [0x9A, 0x16, 0x00, 0x90, 0x27, 0x3F, 0xC1, 0x4D],
);

#[repr(C)]
pub struct TableHeader {
    pub signature: u64,
    pub revision: u32,
    pub header_size: u32,
    pub crc32: u32,
    pub reserved: u32,
}

#[repr(C)]
pub struct SystemTable {
    pub hdr: TableHeader,
    pub firmware_vendor: *const u16,
    pub firmware_revision: u32,
    pub console_in_handle: Handle,
    pub con_in: *mut c_void,
    pub console_out_handle: Handle,
    pub con_out: *mut c_void,
    pub standard_error_handle: Handle,
    pub std_err: *mut c_void,
    pub runtime_services: *mut c_void,
    pub boot_services: *mut BootServices,
    pub number_of_table_entries: usize,
    pub configuration_table: *const ConfigurationTable,
}

#[repr(C)]
pub struct ConfigurationTable {
    pub vendor_guid: Guid,
    pub vendor_table: *mut c_void,
}

// EFI_ALLOCATE_TYPE
pub const ALLOCATE_ANY_PAGES: u32 = 0;

// EFI_MEMORY_TYPE
pub const RESERVED_MEMORY_TYPE: u32 = 0;
pub const LOADER_CODE: u32 = 1;
pub const LOADER_DATA: u32 = 2;
pub const BOOT_SERVICES_CODE: u32 = 3;
pub const BOOT_SERVICES_DATA: u32 = 4;
pub const RUNTIME_SERVICES_CODE: u32 = 5;
pub const RUNTIME_SERVICES_DATA: u32 = 6;
pub const CONVENTIONAL_MEMORY: u32 = 7;
pub const UNUSABLE_MEMORY: u32 = 8;
pub const ACPI_RECLAIM_MEMORY: u32 = 9;
pub const ACPI_MEMORY_NVS: u32 = 10;
pub const MEMORY_MAPPED_IO: u32 = 11;
pub const MEMORY_MAPPED_IO_PORT_SPACE: u32 = 12;
pub const PERSISTENT_MEMORY: u32 = 14;

/// EFI_MEMORY_DESCRIPTOR. The firmware's descriptor stride may be larger
/// than this struct; always step by the returned descriptor size.
#[repr(C)]
#[derive(Clone, Copy)]
pub struct MemoryDescriptor {
    pub ty: u32,
    pub physical_start: u64,
    pub virtual_start: u64,
    pub number_of_pages: u64,
    pub attribute: u64,
}

type Unused = usize;

#[repr(C)]
pub struct BootServices {
    pub hdr: TableHeader,
    raise_tpl: Unused,
    restore_tpl: Unused,
    pub allocate_pages: unsafe extern "efiapi" fn(
        ty: u32,
        memory_type: u32,
        pages: usize,
        memory: *mut u64,
    ) -> Status,
    free_pages: Unused,
    pub get_memory_map: unsafe extern "efiapi" fn(
        size: *mut usize,
        map: *mut u8,
        map_key: *mut usize,
        descriptor_size: *mut usize,
        descriptor_version: *mut u32,
    ) -> Status,
    allocate_pool: Unused,
    free_pool: Unused,
    create_event: Unused,
    set_timer: Unused,
    wait_for_event: Unused,
    signal_event: Unused,
    close_event: Unused,
    check_event: Unused,
    install_protocol_interface: Unused,
    reinstall_protocol_interface: Unused,
    uninstall_protocol_interface: Unused,
    pub handle_protocol: unsafe extern "efiapi" fn(
        handle: Handle,
        protocol: *const Guid,
        interface: *mut *mut c_void,
    ) -> Status,
    reserved: Unused,
    register_protocol_notify: Unused,
    locate_handle: Unused,
    locate_device_path: Unused,
    install_configuration_table: Unused,
    load_image: Unused,
    start_image: Unused,
    exit: Unused,
    unload_image: Unused,
    pub exit_boot_services: unsafe extern "efiapi" fn(image: Handle, map_key: usize) -> Status,
    get_next_monotonic_count: Unused,
    stall: Unused,
    set_watchdog_timer: Unused,
    connect_controller: Unused,
    disconnect_controller: Unused,
    open_protocol: Unused,
    close_protocol: Unused,
    open_protocol_information: Unused,
    protocols_per_handle: Unused,
    locate_handle_buffer: Unused,
    pub locate_protocol: unsafe extern "efiapi" fn(
        protocol: *const Guid,
        registration: *mut c_void,
        interface: *mut *mut c_void,
    ) -> Status,
}

#[repr(C)]
pub struct LoadedImageProtocol {
    pub revision: u32,
    pub parent_handle: Handle,
    pub system_table: *mut SystemTable,
    pub device_handle: Handle,
    // The remaining fields are not used.
}

#[repr(C)]
pub struct SimpleFileSystemProtocol {
    pub revision: u64,
    pub open_volume: unsafe extern "efiapi" fn(
        this: *mut SimpleFileSystemProtocol,
        root: *mut *mut FileProtocol,
    ) -> Status,
}

pub const FILE_MODE_READ: u64 = 1;

#[repr(C)]
pub struct FileProtocol {
    pub revision: u64,
    pub open: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        new_handle: *mut *mut FileProtocol,
        file_name: *const u16,
        open_mode: u64,
        attributes: u64,
    ) -> Status,
    pub close: unsafe extern "efiapi" fn(this: *mut FileProtocol) -> Status,
    delete: Unused,
    pub read: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> Status,
    write: Unused,
    get_position: Unused,
    set_position: Unused,
    pub get_info: unsafe extern "efiapi" fn(
        this: *mut FileProtocol,
        information_type: *const Guid,
        buffer_size: *mut usize,
        buffer: *mut u8,
    ) -> Status,
}

/// Offset of `FileSize` in EFI_FILE_INFO.
pub const FILE_INFO_FILE_SIZE_OFFSET: usize = 8;

#[repr(C)]
pub struct GraphicsOutputProtocol {
    query_mode: Unused,
    set_mode: Unused,
    blt: Unused,
    pub mode: *const GraphicsOutputMode,
}

#[repr(C)]
pub struct GraphicsOutputMode {
    pub max_mode: u32,
    pub mode: u32,
    pub info: *const GraphicsOutputModeInformation,
    pub size_of_info: usize,
    pub frame_buffer_base: u64,
    pub frame_buffer_size: usize,
}

#[repr(C)]
pub struct GraphicsOutputModeInformation {
    pub version: u32,
    pub horizontal_resolution: u32,
    pub vertical_resolution: u32,
    pub pixel_format: u32,
    pub pixel_information: [u32; 4],
    pub pixels_per_scan_line: u32,
}

// EFI_GRAPHICS_PIXEL_FORMAT
pub const PIXEL_RGB_RESERVED_8BIT: u32 = 0;
pub const PIXEL_BGR_RESERVED_8BIT: u32 = 1;

// Offsets from the UEFI specification, so a miscounted placeholder fails the
// build instead of calling the wrong service.
const _: () = {
    assert!(offset_of!(SystemTable, boot_services) == 96);
    assert!(offset_of!(SystemTable, configuration_table) == 112);
    assert!(size_of::<ConfigurationTable>() == 24);
    assert!(size_of::<MemoryDescriptor>() == 40);
    assert!(offset_of!(BootServices, allocate_pages) == 40);
    assert!(offset_of!(BootServices, get_memory_map) == 56);
    assert!(offset_of!(BootServices, handle_protocol) == 152);
    assert!(offset_of!(BootServices, exit_boot_services) == 232);
    assert!(offset_of!(BootServices, locate_protocol) == 320);
    assert!(offset_of!(LoadedImageProtocol, device_handle) == 24);
    assert!(offset_of!(FileProtocol, read) == 32);
    assert!(offset_of!(FileProtocol, get_info) == 64);
    assert!(offset_of!(GraphicsOutputProtocol, mode) == 24);
    assert!(offset_of!(GraphicsOutputMode, frame_buffer_base) == 24);
    assert!(offset_of!(GraphicsOutputModeInformation, pixels_per_scan_line) == 32);
};
