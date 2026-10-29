# Boot: from UEFI to `kmain`

Status: M0. M1 folds the handoff layout into `docs/abi.md`; until then this
note is the specification. The code is `loader/`, `core/src/handoff.rs` and
`kernel/src/arch/x86_64/entry.rs`.

The UEFI loader builds the kernel's first page tables, exits boot services and
jumps to the kernel in the upper half with one handoff structure. The kernel
never sees UEFI.

## Boot flow

1. The firmware (OVMF on QEMU, Hyper-V's UEFI on Hyper-V) starts
   `\EFI\BOOT\BOOTX64.EFI` from the EFI system partition. Secure Boot must be
   off, because the loader is unsigned.
2. The loader finds the ACPI RSDP in the configuration table (ACPI 2.0 GUID
   first, then 1.0) and the GOP framebuffer, if the current mode has a linear
   RGB or BGR framebuffer.
3. It reads `\kernel.elf` and the optional `\cmdline.txt` from the partition it
   was loaded from, and parses the ELF with `l4core::elf`.
4. It copies the kernel's `PT_LOAD` segments into one contiguous run of
   LoaderData pages and zeroes the rest (BSS).
5. It builds 4-level page tables in a pool of LoaderData pages (see
   [Address space at entry](#address-space-at-entry)).
6. It reads the memory map into a buffer allocated beforehand and calls
   ExitBootServices, retrying up to three times if the map key went stale.
7. With boot services gone, it disables interrupts, converts the memory map
   into sorted, merged [`MemoryRegion`](#memory-map)s and fills in the
   [`Handoff`](#handoff-structure).
8. It loads CR3 and jumps to the kernel's entry point with the handoff's
   physical address in `rdi`.
9. `_start` zeroes BSS, switches to a 64 KiB boot stack in BSS and calls
   `rust_entry`, which initialises COM1 and calls `kmain`.

## Disk layout

`cargo xtask image` builds a 64 MiB raw disk with a GPT and one partition, the
EFI system partition (type `EF00`, FAT32, sectors 2048 to the end), and converts
it to a dynamic VHDX for Hyper-V.

| Path on the ESP | Content |
| --- | --- |
| `\EFI\BOOT\BOOTX64.EFI` | the loader |
| `\kernel.elf` | the kernel, an `ET_EXEC` ELF64 linked at `KERNEL_VIRT_BASE` |
| `\cmdline.txt` | the kernel command line, optional; surrounding whitespace is trimmed and it is cut at 256 bytes |

## State at kernel entry

| Item | State |
| --- | --- |
| Mode | 64-bit long mode, CPL 0, the firmware's GDT and code segment |
| Interrupts | off (`IF = 0`); the firmware's IDT is still loaded |
| `rdi` | physical address of the `Handoff`, 8-byte aligned |
| `rsp` | the firmware's stack; the kernel switches away at once |
| CR3 | the loader's page tables |
| EFER.NXE | set if CPUID reports NX, otherwise clear and no NX bits are used |
| CR4.LA57 | clear; the loader refuses to run under 5-level paging |
| Direction flag, SSE state, other registers | unspecified |

The firmware's GDT, IDT and stack live in memory the memory map reports as
`USABLE` (boot-services memory). The kernel must load its own GDT and IDT
(M3) before it reuses any `USABLE` memory (M4).

## Address space at entry

| Virtual range | Maps | Page size | Permissions |
| --- | --- | --- | --- |
| `0` to `phys_map_size` | physical memory 1:1 | 2 MiB | RW, executable |
| `PHYS_MAP_BASE` (`0xFFFF_8000_0000_0000`) + `[0, phys_map_size)` | physical memory (the direct map) | 2 MiB | RW, NX |
| `KERNEL_VIRT_BASE` (`0xFFFF_FFFF_8000_0000`) to the image end | the kernel image, contiguous | 4 KiB | from each segment: `.text` RX, `.rodata` R+NX, `.data`/`.bss` RW+NX |

`phys_map_size` is the end of the highest RAM, firmware or ACPI range in the
UEFI memory map, at least 4 GiB so that low MMIO (local APIC, I/O APIC, HPET,
framebuffer) is covered, rounded up to 1 GiB, and at most 512 GiB (one PML4
slot). Reserved and MMIO ranges do not raise it: QEMU's q35 reports a reserved
range just below 1 TiB. Everything is mapped write-back through PAT entry 0;
the firmware's MTRRs keep MMIO uncached. M3 programs the PAT.

The 1:1 map exists only so the loader survives its own CR3 write. It covers the
lower half, which belongs to user space, so the kernel must drop it before it
creates the first user address space (M3 builds the kernel's own tables).

## Handoff structure

`l4core::handoff::Handoff`, `#[repr(C)]`, 360 bytes. Every address in it is
physical. Host tests pin every offset.

| Offset | Field | Type | Meaning |
| --- | --- | --- | --- |
| 0 | `magic` | u64 | `"uL4BOOT\0"` as a little-endian u64 |
| 8 | `version` | u32 | 1 |
| 12 | `size` | u32 | 360, `size_of::<Handoff>()` |
| 16 | `kernel_phys_base` | u64 | first byte of the kernel image, page-aligned |
| 24 | `kernel_size` | u64 | bytes the image occupies, a multiple of 4 KiB |
| 32 | `phys_map_size` | u64 | bytes covered by the direct map and the 1:1 map |
| 40 | `memory_map` | u64 | address of the `MemoryRegion` array, 8-byte aligned |
| 48 | `memory_map_len` | u64 | number of entries |
| 56 | `rsdp` | u64 | ACPI RSDP, or 0 |
| 64 | `framebuffer` | `Framebuffer` | 32 bytes, below; all zero if there is none |
| 96 | `cmdline_len` | u64 | bytes used in `cmdline`, at most 256 |
| 104 | `cmdline` | [u8; 256] | the command line, UTF-8, not NUL-terminated |

`Framebuffer` is `base: u64, size: u64, width: u32, height: u32, stride: u32,
format: u32`. `stride` is in pixels. `format` is 1 for RGB (byte 0 red), 2 for
BGR (byte 0 blue), 0 for none. The loader passes no framebuffer for bitmask and
BLT-only GOP modes.

`Handoff::validate` checks the magic, version, size, command-line length, and
that the memory-map array is aligned and inside the direct map. The kernel
calls it before using anything else in the handoff.

## Memory map

An array of `MemoryRegion { base: u64, len: u64, kind: u32, reserved: u32 }`
(24 bytes), sorted by `base`, with empty entries dropped and touching entries of
the same kind merged. UEFI guarantees its descriptors do not overlap; the loader
does not check.

| `kind` | Name | UEFI memory types | Meaning for the kernel |
| --- | --- | --- | --- |
| 1 | `USABLE` | Conventional, BootServicesCode, BootServicesData | free RAM, once the kernel has its own GDT and IDT |
| 2 | `RESERVED` | Reserved, Persistent, PalCode, Unaccepted, vendor types | never touch |
| 3 | `ACPI_RECLAIMABLE` | ACPIReclaimMemory | ACPI tables; free after parsing |
| 4 | `ACPI_NVS` | ACPIMemoryNVS | never touch |
| 5 | `MMIO` | MemoryMappedIO, MemoryMappedIOPortSpace | device memory; device untyped in M4 |
| 6 | `LOADER` | LoaderCode, LoaderData | the kernel image, the page tables, the handoff, the memory map and the loader; the kernel decides what to keep |
| 7 | `FIRMWARE` | RuntimeServicesCode, RuntimeServicesData | UEFI runtime services; never touch |
| 8 | `BAD` | UnusableMemory | never touch |

Kinds are a transparent `u32`, not a Rust enum, so an unknown value read from
memory is not undefined behaviour.

## Command line

Space-separated `key=value` words, read with `l4core::cmdline::value`. M0
knows one key:

| Word | Kernel behaviour |
| --- | --- |
| (no `test=`) | print the boot summary and `hello from microL4`, then halt |
| `test=hello` | the same, then `TEST PASS` and exit with success |
| `test=panic` | panic deliberately |
| `test=<other>` | `TEST FAIL: unknown test`, exit with failure |

QEMU scenarios choose a test by writing `cmdline.txt`; there is one kernel
binary for every scenario. `cargo xtask image`, and so the CI-built VHDX, uses
`test=hello`.

## Ending a run

The kernel and the loader end a run the same way. If CPUID leaf `0x4000_0000`
reports QEMU (`TCGTCGTCGTCG` or `KVMKVMKVM`), they write 0x10 (success) or
0x11 (failure) to `isa-debug-exit` at port `0xF4`, and QEMU exits with status
33 or 35. Anywhere else, including Hyper-V (`Microsoft Hv`), they halt with
interrupts off and the host stops the VM. Marker lines tell the host what
happened: `TEST PASS`, `TEST FAIL`, `KERNEL PANIC at <file>:<line>: <message>`,
`LOADER ERROR` and `LOADER PANIC`.

## Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Every address in the handoff is physical; the memory-map array lies inside the direct map | `Handoff::validate`, host tests | M0 |
| The handoff layout is identical for the loader and the kernel | `#[repr(C)]` with fixed-width fields; offsets pinned in host tests | M0 |
| The kernel image is mapped contiguously at `KERNEL_VIRT_BASE` and no segment shares a page with another | `l4core::elf` rejects overlapping pages; the linker script page-aligns each output section | M0 |
| Kernel text is not writable and kernel data is not executable, when the CPU has NX | loader page tables from ELF segment flags | M0 |
| The memory map is sorted and holds no empty or mergeable neighbours | `normalize_regions`, host tests | M0 |
| The kernel is built only for `x86_64-unknown-none`, without SSE | `compile_error!` in `kernel/src/main.rs`; xtask hard-codes the target | M0 |
| `unsafe` appears only in `kernel/src/arch/`, each block with a `SAFETY:` comment | `#![deny(unsafe_code)]` outside `arch`; `clippy::undocumented_unsafe_blocks` | M0 |
| The kernel reuses no `USABLE` memory before loading its own GDT and IDT | not yet enforced; the kernel allocates nothing in M0 | M3, M4 |
| No user address space contains the loader's 1:1 map | not yet enforced; no user space exists | M3, M5 |
| `LOADER` memory holding the kernel image is never handed out as untyped | not yet enforced | M4 |

## Comparison with seL4

seL4 on x86_64 boots differently, and nothing here needs to match it:

- **Boot protocol.** seL4 is started by a Multiboot 1 or 2 loader such as GRUB
  and enters in 32-bit protected mode. Its own boot code (`head.S`,
  `boot_sys`) enables long mode, builds the initial page tables and copies the
  multiboot memory map. Here a UEFI application does that work and the kernel
  starts in long mode on the loader's tables.
- **Kernel window.** seL4 maps the kernel image at `KERNEL_ELF_BASE`
  (`0xFFFFFFFF80000000` plus the image's physical load address) and a window of
  physical memory at `PPTR_BASE` (`0xFFFFFF8000000000`). Here the image is at
  `0xFFFFFFFF80000000` whatever its physical address, and the direct map starts
  at `0xFFFF800000000000`, the bottom of the upper half.
- **Root task image.** seL4 takes the root task as a Multiboot module. microL4
  embeds it in the kernel image (M5), so the loader handles only one file.
- **Boot information.** Like seL4's `seL4_BootInfo`, the root task will get a
  BootInfo page (M4). The handoff here is internal to the kernel and never
  reaches user space.
