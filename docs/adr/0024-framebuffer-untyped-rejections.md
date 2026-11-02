# 0024: `framebuffer_untyped` is empty for any framebuffer the kernel cannot hand out whole

Status: accepted, M4 (2026-11-02)

## Context

`docs/abi.md` says BootInfo's `framebuffer_untyped` is empty if there is no
framebuffer, or if any 2 MiB page it touches is write-back in the direct
map. Building the untyped in M4 (`l4core::boot`) showed other framebuffers
the kernel cannot hand out as device untyped. One that reaches below 1 MiB
or past `2^phys_addr_bits` names memory no untyped may cover. One that
overlaps the kernel image, the boot region, a `kernel_reserved` page, or
`ACPI_NVS`, `FIRMWARE`, `BAD` or unknown memory would give `fb` a
capability to memory that must stay out of every untyped. Neither QEMU nor
Hyper-V shows any of these; a broken handoff or firmware could.

## Decision

- `framebuffer_untyped` is empty, and the framebuffer's pages become
  nothing, whenever the framebuffer cannot be handed out whole: any 2 MiB
  page it touches is write-back in the direct map, it reaches below 1 MiB or
  past `2^phys_addr_bits`, or it overlaps any of the ranges above. A debug
  kernel prints the reason.
- BootInfo's `framebuffer` field still holds the handoff's values, so the
  root task can see that a framebuffer exists but was not handed out.
- The layout and every other field are unchanged; BootInfo stays version 1.

## Consequences

- `fb` (M8) gets all of the framebuffer or none of it, and never memory
  another rule keeps out of every untyped.
- A root task that finds `framebuffer` non-zero and `framebuffer_untyped`
  empty runs without a framebuffer; the debug log says why.
