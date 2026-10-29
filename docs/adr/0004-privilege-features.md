# 0004: The kernel requires NX, PGE, PAT, SMEP and SMAP, and maps itself from static tables shared by every address space

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Privilege levels row puts the kernel in ring 0 in the upper half of
every address space, with SMEP and SMAP on from the start. It does not say
what happens on a CPU without them. QEMU's default TCG model, `qemu64`,
which xtask uses today, has neither (from memory; check in M3). The owner's
Hyper-V host exposes them only if its CPU has them (from memory; check in
M3). seL4 turns SMEP and SMAP on only when CPUID reports them, leaves SMAP
off in printing builds and both off with `CONFIG_DANGEROUS_CODE_INJECTION`
(`init_cpu`, `src/arch/x86/kernel/boot.c`); it uses no NX bits at all
(`map_kernel_window`, `makeUserPTE`) and never sets EFER.NXE
(`src/arch/x86/64/head.S`). It maps kernel devices in their own uncached
window (`map_kernel_window_devices`), and turns its Meltdown skim window on
by default on x86_64 (`KernelSkimWindow`, `src/arch/x86/config.cmake`).

`docs/boot.md` and ADR 0002 leave M3 to build the kernel's own tables, drop
the loader's 1:1 map, and program the PAT. The loader maps the direct map up
to 512 GiB, all write-back through PAT entry 0, relying on the firmware's
MTRRs to keep device memory uncached, and the 1:1 map and the direct map
alias the kernel image writable.

## Decision

- **Required features.** M3 checks CPUID before it changes any state and
  panics with one `CPU lacks <features>` line, naming every missing feature,
  unless the CPU has NX, PGE, PAT, SMEP, SMAP and XSAVE (which M5 first uses;
  [ADR 0014](0014-fp-simd.md)). EFER.NXE and CR0.WP come set from the loader and M3 checks them; M3
  sets CR4.PGE, CR4.SMEP and CR4.SMAP. None is ever cleared. UMIP is turned on when present and otherwise skipped:
  it hides only the GDT, IDT and TSS addresses, which are fixed and public
  in microL4. PCID and LA57 are never turned on.
- **AC and DF.** `IA32_FMASK` clears AC and DF on `syscall`, and every
  exception and interrupt entry runs `clac` and `cld`, because exception
  delivery clears neither (from memory; check in M3). The kernel never runs
  `stac`.
- **QEMU and Hyper-V.** From M3, xtask's `base_command()` passes
  `-cpu max,la57=off`, and a scenario key `qemu_args:` lets a refusal test
  boot `-cpu qemu64`. `tools/hyperv/New-L4Vm.ps1` turns processor
  compatibility mode off. The boot summary prints the CPUID features the
  kernel requires.
- **Static tables.** The kernel PML4; the direct-map PDPT, 64 page directories
  and 9 page tables; the image's PDPT, PD and 8 page tables; the device
  window's PD and page table: 87 pages, 348 KiB of `.bss`. The direct map
  covers at most 64 GiB ([ADR 0006](0006-direct-map-bound.md)). The image is
  at most 16 MiB, `.rootimage` included, asserted by the linker script and
  checked by xtask from M5.
- **Guard pages.** The kernel stack and the four IST stacks each sit above an
  unmapped 4 KiB page that the linker script reserves.
- **No writable alias of text.** The direct map maps the 2 MiB regions that
  cover the kernel image with 4 KiB pages, the image's text and read-only
  data read-only, everything NX.
- **Device window.** `KERNEL_DEVICE_BASE` = `0xFFFF_FFFF_FFE0_0000`, the last
  2 MiB, one page table of UC 4 KiB pages: the local APIC, up to four I/O
  APICs and the HPET. The kernel reaches device registers only there. The
  hypercall page is the `.hvcall` section in kernel text, mapped RX.
- **Cache types.** The PAT is WB, WT, UC-, UC, WC, WT, UC-, UC
  (`0x0007_0401_0007_0406`): entries 0 to 4 as seL4 writes them
  (`init_pat_msr`), 5 to 7 the power-on values, which seL4 leaves as it
  finds them. A direct-map 2 MiB page is WB if it overlaps a RAM-like
  memory-map region (`USABLE`, `LOADER`, `ACPI_RECLAIMABLE`, `ACPI_NVS`,
  `FIRMWARE`) and holds no kernel device page, and UC otherwise; M4 makes no
  RAM untyped from a 2 MiB page holding a kernel device page.
- **Sharing.** Kernel PML4 entries 256 and 511 are supervisor-only; kernel
  leaves are global. Retyping a PML4 copies entries 256 to 511 from the
  kernel PML4, which the kernel writes only during boot. The kernel switches
  to its PML4 and toggles CR4.PGE in M3, which removes the loader's 1:1 map
  before any user address space exists.
- **Meltdown is an accepted risk in v0.** No skim window. M3 reads
  `IA32_ARCH_CAPABILITIES.RDCL_NO` when CPUID says the MSR exists and prints
  `cpu: meltdown: vulnerable`, `not vulnerable` or `unknown`.

## Consequences

- A CPU or hypervisor configuration without SMEP or SMAP cannot boot
  microL4. The owner's Hyper-V VM is checked at M3, with compatibility mode
  off; if the host CPU lacks them, a new ADR makes them optional.
- Every scenario needs the new QEMU model from M3. Golden outputs that print
  CPU features depend on it.
- After M3 no alias of the kernel image is weaker than its own mapping, so
  `docs/boot.md`'s "weaker permissions until M3" becomes true. A kernel
  write bug cannot patch kernel code through the direct map.
- The kernel never reaches a device register write-back, whatever the MTRRs
  say, and never through the direct map.
- M4 needs no list of kernel-reserved pages for page tables; the image covers
  them.
- The stack-guard and 1:1-map open issues in `STATUS.md` close in M3.
- On a Meltdown-vulnerable host, ring 3 can read all RAM through the direct
  map. The Hyper-V check records the boot line in `STATUS.md`, and M10 lists
  the risk.
