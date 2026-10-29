# 0007: The root task's objects come from a boot region outside every untyped, and a two-page BootInfo describes the rest

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Boot row says the kernel builds the root task from the embedded
image and passes it "a BootInfo page". `docs/boot.md` adds that M5 copies the
image into "frames retyped from untyped", that `ACPI_RECLAIMABLE` memory is
"free after parsing", and that M4 keeps one page below 1 MiB. Three things
the row leaves open matter for the ABI and for what an attacker holding the
root task's capabilities can reach:

- If the root task's CNode, TCB and VSpace were retyped from an untyped the
  root task holds, the root CNode would have to exist before the untyped cap
  it is made from has a slot, and revoking that untyped would destroy the
  root task. seL4 instead carves the rootserver objects from free memory
  before it makes untyped (`init_freemem`, `src/kernel/boot.c`).
- seL4's BootInfo is one page plus extra chunks with headers, and untyped that
  do not fit its list are left out with only a printed warning
  (`provide_untyped_cap`, `src/kernel/boot.c`).
- [ADR 0004](0004-privilege-features.md) maps every 2 MiB page that holds
  RAM-like memory write-back in the direct map, so a device untyped there
  would let user space map the same page uncached.

## Decision

- The kernel allocates one zeroed boot region at the top of the highest
  `USABLE` range above 1 MiB that touches no `kernel_reserved` page nor any
  2 MiB page holding one: root CNode
  (radix 12), PML4 and paging structures, TCB, IPC buffer, BootInfo, image
  frames and, on Hyper-V, the two SynIC frames ([ADR
  0020](0020-hypervisor-capability.md)). No untyped covers it and it is never
  freed.
- BootInfo is one 8 KiB `#[repr(C)]` struct in `l4core::bootinfo`: a 1 KiB
  header with seL4's slot regions plus the framebuffer and its untyped, the
  RSDP address (information only), the command line, the TSC frequency
  measured in M3, the hypervisor vendor, the physical address width, the
  image bounds and the 256-byte `InterruptInfo` block, whose fields are
  defined with the interrupt ABI (`docs/abi.md`, [BootInfo fields for
  interrupts and Hyper-V](../abi.md#bootinfo-fields-for-interrupts-and-hyper-v));
  then 448 `UntypedDesc` entries. If more untyped or slots are needed, boot
  panics.
- The root CNode's fixed slots keep seL4's numbers where the object exists
  and hold null where it does not; on Hyper-V, from M9, slot 12 holds the
  Hypervisor capability and slots 13 and 14 the SynIC message and event-flag
  frames, all three null before M9, if an M9 privilege is missing, or if the
  firmware locked the hypercall MSR to a page outside `.hvcall` ([ADR 0020](0020-hypervisor-capability.md)).
- Untyped: RAM from `USABLE`, `LOADER` (except the kernel image),
  `ACPI_RECLAIMABLE` and the reclaimed `.rootimage`; device untyped from
  `RESERVED`, `MMIO` and gaps below `2^phys_addr_bits`, never in a write-back
  direct-map page; the framebuffer gets its own device untyped, listed first.
  No RAM untyped in a 2 MiB page holding a kernel device page ([ADR
  0004](0004-privilege-features.md)). Nothing from `[0, 1 MiB)` (so no kernel
  object at physical address 0), `ACPI_NVS`, `FIRMWARE`, `BAD`, the kernel
  image, the boot region or `kernel_reserved`: the local APIC, at most four
  I/O APICs and the HPET (the pages the kernel device window maps), the MSI
  window `0xFEE0_0000` to `0xFEEF_FFFF`, and a locked hypercall page
  ([ADR 0004](0004-privilege-features.md),
  [ADR 0020](0020-hypervisor-capability.md)). RAM at or above the direct
  map's 64 GiB end becomes nothing; that rule applies last
  ([ADR 0006](0006-direct-map-bound.md)).
- The root image spans at most 8 MiB, checked by xtask and again at boot;
  xtask strips it, and the kernel image with it fits `KERNEL_IMAGE_MAX` =
  16 MiB. A page in the span that no segment covers gets no frame and no
  mapping.

## Consequences

- Every untyped and slot rule is a pure function in `l4core::boot`, testable
  on recorded QEMU and Hyper-V maps and under proptest, including a
  `kernel_reserved` page inside the range the boot region would take.
- The root task cannot revoke its own CNode or image; that memory, a few
  hundred KiB plus the image, is never reclaimed, as in seL4.
- ACPI tables are unreadable from user space after boot. What user space
  needs from ACPI (the ECAM ranges for `virtio-net` in M9, I/O APIC and ISA
  override facts) comes through `InterruptInfo`; `docs/boot.md`'s plan for
  user-space ECAM discovery from the RSDP changes accordingly.
- The page below 1 MiB that `docs/boot.md` kept for the AP trampoline is now
  the whole first MiB, which costs under 640 KiB.
- BootInfo's size and layout are ABI; growing it beyond 448 untyped needs a
  new version.
