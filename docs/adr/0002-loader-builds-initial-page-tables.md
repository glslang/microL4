# 0002: The loader builds the initial page tables; the kernel lives in the upper half from M0

Status: accepted, M0 (2026-10-29)

## Context

The plan puts the kernel in the upper half of every address space and has the
kernel build its own page tables in M3. In M0 the kernel could instead run 1:1
on the firmware's tables, but then it would have to be relinked and its
early code rewritten in M3.

## Decision

The kernel is linked at `0xFFFF_FFFF_8000_0000` from the start. The loader
builds 4-level tables that map the kernel image there (4 KiB pages, permissions
from the ELF segments), a direct map of physical memory at
`0xFFFF_8000_0000_0000`, and a temporary 1:1 map of low memory, and enters the
kernel on them. `docs/boot.md` specifies the layout.

## Consequences

- M3 replaces the tables with the kernel's own but keeps the same layout, so
  no kernel code moves.
- The 1:1 map covers the lower half, which belongs to user space. M3 must drop
  it before M5 creates the first user address space. This is listed as an open
  issue in `STATUS.md`.
- The loader needs a small page-table builder (`loader/src/paging.rs`); it
  shares no code with the kernel's M3 builder, which will manage kernel objects
  rather than loader memory.
