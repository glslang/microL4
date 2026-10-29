# 0006: The kernel's direct map covers at most 64 GiB, and the loader allocates below it

Status: accepted, M1 (2026-10-29). Amends ADR 0002 and `docs/boot.md`.

## Context

`docs/boot.md` has the loader allocate every page below 512 GiB with
`AllocateMaxAddress`, and map a direct map of up to 512 GiB, so that the
kernel image, the handoff and its memory map lie inside the direct map. ADR
0002 has M3 replace the loader's tables with the kernel's own.

The kernel's M3 tables are static, in `.bss`. Its direct map uses 2 MiB pages
from 64 page directories, so it covers at most 64 GiB. A paging-structure
capability names its table in 23 bits of an 8 KiB-aligned address, which
also stops at 64 GiB. EDK2 searches for `AllocateMaxAddress` pages downwards
from the bound (from memory; check in M3), so on a machine with more than
64 GiB of RAM the loader would likely put the kernel image, and with it the
embedded root task, above the kernel's direct map. The untyped rules of
`docs/design.md`, [What each physical page
becomes](../design.md#what-each-physical-page-becomes), would then make RAM
untyped of `.rootimage` the kernel cannot reach, and M3 could not read the
handoff.

## Decision

- `DIRECT_MAP_MAX` = 64 GiB. The kernel's direct map covers
  `[0, min(phys_map_size, DIRECT_MAP_MAX))`.
- M3 changes the loader's `AllocateMaxAddress` bound from 512 GiB to 64 GiB,
  so the kernel image, the page tables, the handoff and the memory map all
  lie below 64 GiB.
- `phys_map_size` keeps its meaning: what the loader's own tables map. The
  handoff layout and version do not change.
- In the untyped rules of `docs/design.md`, [What each physical page
  becomes](../design.md#what-each-physical-page-becomes), the direct-map row
  applies last: RAM at or above the direct map's end becomes no untyped,
  whatever an earlier row says.
- M3 panics if the kernel image, the handoff or its memory map ends above the
  direct map.

## Consequences

- On a machine with more than 64 GiB of RAM, only the first 64 GiB is used.
  QEMU runs with 256 MiB and the owner's Hyper-V VM with 512 MiB.
- `docs/boot.md` changes in three places: step 4 ("below 512 GiB" becomes
  64 GiB), the paragraph on `phys_map_size` (M4 makes no untyped above
  64 GiB, not 512 GiB), and the invariant that every loader allocation lies
  inside the direct map, which now means the kernel's.
- Every kernel object, and every table a mapped capability names, lies below
  64 GiB, so the capability fields fit.
- Raising the bound later costs 4 KiB of `.bss` per extra GiB, up to
  512 GiB, and wider capability fields.
