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
4. It copies the kernel's non-empty `PT_LOAD` segments into one contiguous
   run of LoaderData pages and zeroes the rest (BSS). Every loader allocation
   uses AllocateMaxAddress below 512 GiB, so the direct map covers it.
5. It builds 4-level page tables in a pool of LoaderData pages (see
   [Address space at entry](#address-space-at-entry)).
6. It reads the memory map into a buffer allocated beforehand and calls
   ExitBootServices, making up to three attempts if the map key went stale.
7. With boot services gone, it disables interrupts, converts the memory map
   into sorted, merged [`MemoryRegion`](#memory-map)s and fills in the
   [`Handoff`](#handoff-structure).
8. It sets CR0.WP, loads CR3 and jumps to the kernel's entry point with the
   handoff's physical address in `rdi`.
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
| `\cmdline.txt` | the kernel command line, optional; surrounding whitespace is trimmed and it is cut at 256 bytes, even mid-character |

## State at kernel entry

| Item | State |
| --- | --- |
| Mode | 64-bit long mode, CPL 0, the firmware's GDT and code segment |
| Interrupts | off (`IF = 0`); the firmware's IDT is still loaded |
| `rdi` | physical address of the `Handoff`, 8-byte aligned |
| `rsp` | the firmware's stack; the kernel switches away at once |
| CR3 | the loader's page tables |
| EFER.NXE | set if CPUID reports NX, otherwise clear and no NX bits are used |
| CR0.WP | set by the loader, so ring 0 honours read-only pages |
| CR4.LA57 | clear; the loader refuses to run under 5-level paging |
| CR4.PGE, SMEP, SMAP, PAT, MTRRs | as the firmware left them; M3 sets them |
| 8259 PIC, local APIC timer | as the firmware left them; M3 masks them before enabling interrupts |
| Direction flag, SSE state, other registers | unspecified |

The firmware's IDT and stack, and on some firmware its GDT, live in
boot-services memory, which the memory map reports as `USABLE`. EDK2-derived
firmware such as OVMF puts its GDT in runtime-services data, reported as
`FIRMWARE`. Either way the kernel must load its own GDT and IDT (M3) before it
reuses any `USABLE` memory (M4). Until then an NMI lands in the firmware's IDT.

## Address space at entry

| Virtual range | Maps | Page size | Permissions |
| --- | --- | --- | --- |
| `0` to `phys_map_size` | physical memory 1:1 | 2 MiB | RW, executable |
| `PHYS_MAP_BASE` (`0xFFFF_8000_0000_0000`) + `[0, phys_map_size)` | physical memory (the direct map) | 2 MiB | RW, NX if the CPU has NX |
| `KERNEL_VIRT_BASE` (`0xFFFF_FFFF_8000_0000`) to the image end | the kernel image, contiguous | 4 KiB | from each segment: `.text` RX, `.rodata` R, `.data`/`.bss` RW; the last two NX if the CPU has NX |

`phys_map_size` is the end of the highest range in the UEFI memory map that is
not `RESERVED` or `MMIO`, at least 4 GiB so that low MMIO (local APIC, I/O
APIC, HPET, framebuffer) is covered, rounded up to 1 GiB, and at most 512 GiB
(one PML4 slot). Reserved and MMIO ranges do not raise it: QEMU's q35 reports
a reserved range just below 1 TiB. On a machine with more than 512 GiB the
memory map lists RAM the direct map does not cover; M4 must not make untyped
from it. Everything is mapped write-back through PAT entry 0;
the firmware's MTRRs keep MMIO uncached. M3 programs the PAT.

The 1:1 map exists only so the loader survives its own CR3 write. It covers the
lower half, which belongs to user space, so the kernel must drop it before it
creates the first user address space (M3 builds the kernel's own tables). The
1:1 map and the direct map also alias the kernel image with weaker
permissions until then.

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
| 104 | `cmdline` | [u8; 256] | the command-line bytes, not NUL-terminated and not checked; `Handoff::cmdline` reads invalid UTF-8 as empty |

`Framebuffer` is `base: u64, size: u64, width: u32, height: u32, stride: u32,
format: u32`. `stride` is in pixels. `format` is 1 for RGB (byte 0 red), 2 for
BGR (byte 0 blue), 0 for none. The loader passes no framebuffer for bitmask and
BLT-only GOP modes.

`Handoff::validate` checks the magic, version, size, command-line length, and
that the memory-map array is aligned and inside the direct map. The kernel
calls it before using anything else in the handoff, and `arch::memory_map`
calls it again, so safe code cannot build a slice from an unchecked handoff.

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
| 5 | `MMIO` | MemoryMappedIO, MemoryMappedIOPortSpace | device memory the firmware chose to list; see below |
| 6 | `LOADER` | LoaderCode, LoaderData | the kernel image, the page tables, the handoff, the memory map and the loader; the kernel decides what to keep |
| 7 | `FIRMWARE` | RuntimeServicesCode, RuntimeServicesData | UEFI runtime services; never touch |
| 8 | `BAD` | UnusableMemory | never touch |

Kinds are a transparent `u32`, not a Rust enum, so an unknown value read from
memory is not undefined behaviour.

UEFI memory maps usually leave out PCI BARs, the local APIC, the I/O APIC and
the HPET. M4 therefore makes device untyped from every range that is not RAM,
ACPI, `FIRMWARE` or kernel-owned, including ranges absent from the map, as
seL4 does for the gaps between its reserved regions. Building them from `MMIO`
entries alone would miss the virtio-net and framebuffer BARs that M8 and M9
need.

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
| Every loader allocation, and so the handoff, the memory map, the page tables and the kernel image, lies inside the direct map | AllocateMaxAddress below 512 GiB in `alloc_pages`; RAM raises `phys_map_size` | M0 |
| The handoff layout is identical for the loader and the kernel | `#[repr(C)]` with fixed-width fields; compile-time offset asserts in `core/src/handoff.rs`, checked by each target's build | M0 |
| The kernel image is mapped contiguously at `KERNEL_VIRT_BASE` and no segment shares a page with another | `l4core::elf` rejects segments that share a page; the linker script page-aligns the first section of each `PT_LOAD`; `load_kernel` rejects an image that does not start at `KERNEL_VIRT_BASE` | M0 |
| At `KERNEL_VIRT_BASE`, text is not writable and data is not executable | loader page tables from ELF segment flags, NX when the CPU has it, CR0.WP set by the loader; the 1:1 and direct maps alias the image with weaker permissions until M3 | M0 partly, M3 |
| BSS lies inside the last `PT_LOAD`'s `memsz`, and `_start` zeroes it before any Rust code runs | `.bss` placed in the `data` segment by `linker.ld`; `rep stosb` in `entry.rs` | M0 |
| Interrupts stay off until the kernel's IDT is loaded and the PIC and any firmware-armed LAPIC timer are masked | `cli` in the loader after ExitBootServices and in `_start` | M0, M3 |
| The memory map is sorted and holds no empty or mergeable neighbours | `normalize_regions`, host tests | M0 |
| The kernel is built only for `x86_64-unknown-none`, without SSE | `compile_error!` in `kernel/src/main.rs`; xtask hard-codes the target | M0 |
| `unsafe` appears only in `kernel/src/arch/`, each block with a `SAFETY:` comment | `#![deny(unsafe_code)]` outside `arch`; `clippy::undocumented_unsafe_blocks` | M0 |
| The boot stack has a guard page below it | not yet: `boot_stack_bottom` follows `.data`, so an overflow silently corrupts kernel data | M3 |
| The kernel reuses no `USABLE` memory before loading its own GDT and IDT | not yet enforced; the kernel allocates nothing in M0 | M3, M4 |
| `LOADER` memory holding the live page tables, the handoff and the memory map is not reused before M3 switches CR3 and M4 copies what it needs into BootInfo; `ACPI_RECLAIMABLE` memory is not reused before ACPI is parsed | not yet enforced | M3, M4 |
| No user address space contains the loader's 1:1 map | not yet enforced; no user space exists | M3, M5 |
| `LOADER` memory holding the kernel image is never handed out as untyped | not yet enforced | M4 |

## Comparison with seL4

seL4 on x86_64 boots differently, and nothing here needs to match it. Sources
are files in [seL4's repository](https://github.com/seL4/seL4) as of
2026-10-29.

- **Boot protocol.** seL4 is started by a Multiboot 1 or 2 loader such as GRUB
  and enters in 32-bit protected mode. Its own boot code (`head.S`,
  `boot_sys.c`) loads its own GDT and boot stack, enables long mode, builds the
  initial page tables and copies the multiboot memory map. Here a UEFI
  application builds the tables, and the kernel starts in long mode on the
  firmware's GDT until M3.
- **Kernel window.** seL4 links its image at `KERNEL_ELF_BASE` =
  `PPTR_TOP` + `KERNEL_ELF_PADDR_BASE` = `0xFFFFFFFF80100000`, so it is always
  loaded at physical 1 MiB. Its physical-memory window maps
  `[0, PADDR_TOP)`, 510 GiB, from `PPTR_BASE` (`0xFFFFFF8000000000`) up to
  `PPTR_TOP` (`include/plat/pc99/plat/64/plat_mode/machine/hardware.h`). Here
  the image is at `0xFFFFFFFF80000000` whatever physical address the loader
  allocated, and the direct map starts at `0xFFFF800000000000`, the bottom of
  the upper half.
- **Low memory.** seL4 uses only RAM at or above 1 MiB and treats RAM above
  `PADDR_TOP` as device memory (`boot_sys.c`, `add_mem_p_regs`). Here the
  memory map reports RAM from address 0 as `USABLE`. M4 keeps one page below
  1 MiB for the multi-core AP trampoline (a stretch goal) and makes no RAM
  untyped at or above `phys_map_size`.
- **Root task image.** seL4 takes the root task as Multiboot module 0, ELF-loads
  it and places it just after the kernel image. microL4 embeds it in the kernel
  image (M5), so the loader handles only one file. The embedded image goes in
  its own page-aligned section: M5 copies it into frames retyped from untyped,
  and the section is then reclaimed, as seL4 reclaims its boot code. Otherwise
  it would sit in kernel memory with kernel permissions for good.
- **Boot information.** Like seL4's `seL4_BootInfo`, the root task will get a
  BootInfo page (M4). The handoff here is internal to the kernel and never
  reaches user space. seL4 also passes the RSDP, the framebuffer, the raw
  memory map and the TSC frequency as extra BootInfo chunks
  (`libsel4/include/sel4/bootinfo_types.h`). The kernel will copy the
  framebuffer, the RSDP and the command line into BootInfo the same way,
  because `fb` (M8) and ECAM discovery (M9) run in user space.
