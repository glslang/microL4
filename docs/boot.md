# Boot: from UEFI to `kmain`

Status: M0 loader note. The handoff ABI is in `docs/abi.md`, [Boot
handoff](abi.md#boot-handoff-loader-to-kernel); what the kernel does after it
is in `docs/design.md`, [Boot](design.md#boot). The code is `loader/`,
`core/src/handoff.rs` and `kernel/src/arch/x86_64/entry.rs`.

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
   uses AllocateMaxAddress below 64 GiB, the end of the kernel's direct map
   (from M3; [ADR 0006](adr/0006-direct-map-bound.md)), so the direct map
   covers it.
5. It builds 4-level page tables in a pool of LoaderData pages (see
   [Address space at entry](abi.md#address-space-at-entry)).
6. It reads the memory map into a buffer allocated beforehand and calls
   ExitBootServices, making up to three attempts if the map key went stale.
7. With boot services gone, it disables interrupts, converts the memory map
   into sorted, merged [`MemoryRegion`](abi.md#memory-map)s and fills in the
   [`Handoff`](abi.md#handoff-structure).
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

See `docs/abi.md`, Boot handoff, [State at kernel
entry](abi.md#state-at-kernel-entry).

## Address space at entry

See `docs/abi.md`, Boot handoff, [Address space at
entry](abi.md#address-space-at-entry). The kernel replaces these tables in M3
(`docs/design.md`, [Privilege levels](design.md#privilege-levels)).

## Handoff structure

See `docs/abi.md`, Boot handoff, [Handoff
structure](abi.md#handoff-structure). ABI version 1.

## Memory map

See `docs/abi.md`, Boot handoff, [Memory map](abi.md#memory-map). Which kinds
become untyped is `docs/design.md`, [Boot](design.md#boot).

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
`test=hello`. From M5 the root task reads the same bytes from BootInfo's
`cmdline` (`docs/abi.md`, [BootInfo](abi.md#bootinfo)).

## Ending a run

The kernel and the loader end a run the same way. If CPUID leaf `0x4000_0000`
reports QEMU (`TCGTCGTCGTCG` or `KVMKVMKVM`), they write 0x10 (success) or
0x11 (failure) to `isa-debug-exit` at port `0xF4`, and QEMU exits with status
33 or 35. Anywhere else, including Hyper-V (`Microsoft Hv`), they halt with
interrupts off and the host stops the VM. Marker lines tell the host what
happened: `TEST PASS`, `TEST FAIL`, `KERNEL PANIC at <file>:<line>: <message>`,
`LOADER ERROR` and `LOADER PANIC`. A user-space test ends the run with
`DebugHalt` in a debug kernel ([Debug system
calls](abi.md#debug-system-calls)), or through an IOPort capability for
`0xF4` in a release kernel.

## Invariants

| Invariant | Enforced by | Milestone |
| --- | --- | --- |
| Every address in the handoff is physical; the memory-map array lies inside the direct map | `Handoff::validate`, host tests | M0 |
| Every loader allocation, and so the handoff, the memory map, the page tables and the kernel image, lies below 64 GiB, inside the kernel's direct map | `AllocateMaxAddress` below 64 GiB in `alloc_pages` (512 GiB in M0); M3 panics otherwise ([ADR 0006](adr/0006-direct-map-bound.md)) | M0, M3 |
| The handoff layout is identical for the loader and the kernel | `#[repr(C)]` with fixed-width fields; compile-time offset asserts in `core/src/handoff.rs`, checked by each target's build | M0 |
| The kernel image is mapped contiguously at `KERNEL_VIRT_BASE` and no segment shares a page with another | `l4core::elf` rejects segments that share a page; the linker script page-aligns the first section of each `PT_LOAD`; `load_kernel` rejects an image that does not start at `KERNEL_VIRT_BASE` | M0 |
| Kernel text is never writable and kernel data never executable, at `KERNEL_VIRT_BASE` and, from M3, through every alias | loader page tables from ELF segment flags, NX, CR0.WP; until M3 the 1:1 and direct maps alias the image with weaker permissions; M3 drops the 1:1 map and maps the image's 2 MiB regions in the direct map with 4 KiB pages, text and read-only data read-only and everything NX; the one exception is `.rootimage`, writable and never executed in the direct map and RAM untyped from M5 ([ADR 0004](adr/0004-privilege-features.md)) | M0 partly, M3 |
| BSS lies inside the last `PT_LOAD`'s `memsz`, and `_start` zeroes it before any Rust code runs | `.bss` placed in the `data` segment by `linker.ld`; `rep stosb` in `entry.rs` | M0 |
| Interrupts stay off until the kernel's IDT is loaded and the PIC and any firmware-armed LAPIC timer are masked | `cli` in the loader after ExitBootServices and in `_start` | M0, M3 |
| The memory map is sorted and holds no empty or mergeable neighbours | `normalize_regions`, host tests | M0 |
| The kernel is built only for `x86_64-unknown-none`, without SSE | `compile_error!` in `kernel/src/main.rs`; xtask hard-codes the target | M0 |
| `unsafe` appears only in `kernel/src/arch/`, each block with a `SAFETY:` comment | `#![deny(unsafe_code)]` outside `arch`; `clippy::undocumented_unsafe_blocks` | M0 |

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
  the upper half, and covers at most 64 GiB.
- **Low memory.** seL4 uses only RAM at or above 1 MiB and treats RAM above
  `PADDR_TOP` as device memory (`boot_sys.c`, `add_mem_p_regs`). Here the
  memory map reports RAM from address 0 as `USABLE`. M4 hands out nothing
  below 1 MiB, so no kernel object lies at physical address 0 ([ADR
  0007](adr/0007-boot-region-and-bootinfo.md)), and no RAM untyped at or
  above the direct map's end, `min(phys_map_size, 64 GiB)` ([ADR
  0006](adr/0006-direct-map-bound.md)). seL4 also keeps low memory out of RAM
  untyped (`HIGHMEM_PADDR`, `boot_sys.c`) but hands it out as device untyped,
  since it is a gap between reserved regions (`create_untypeds`).
- **Root task image.** seL4 takes the root task as Multiboot module 0, ELF-loads
  it and places it just after the kernel image. microL4 embeds it in the kernel
  image (M5), so the loader handles only one file. The embedded image goes in
  its own page-aligned section: M5 copies it into frames in the boot region,
  which no untyped covers; seL4 keeps both its rootserver objects and its user
  image (reserved with the kernel image, `arch_init_freemem`) outside every
  untyped. `.rootimage` is then unmapped and becomes RAM untyped, as seL4
  reclaims its boot code. Otherwise it would sit in kernel memory with kernel
  permissions for good.
- **Boot information.** Like seL4's `seL4_BootInfo`, the root task gets a
  two-page BootInfo (`docs/abi.md`, [BootInfo](abi.md#bootinfo)). The handoff
  here is internal to the kernel and never reaches user space. seL4 also
  passes the RSDP, the framebuffer, the raw memory map and the TSC frequency
  as extra BootInfo chunks (`libsel4/include/sel4/bootinfo_types.h`). The
  kernel copies the framebuffer, the RSDP and the command line into BootInfo
  the same way. ACPI memory is reused after boot, so the ECAM ranges reach
  `virtio-net` through BootInfo's `InterruptInfo` block, and the RSDP address
  is for information only ([ADR 0007](adr/0007-boot-region-and-bootinfo.md)).
