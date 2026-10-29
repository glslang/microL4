# 0005: Paging structures keep back-references to the capabilities mapped in them, instead of ASIDs; PCID is off

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's object set is seL4's "minus ASID pools" but does not say what
replaces them. A mapped frame or paging-structure capability must name the
place it is mapped, so that Unmap and delete can clear the entry, and that
name must stay safe when the VSpace or an intermediate table is deleted
first.

seL4 records (ASID, virtual address) in the capability. Unmap looks the
VSpace up by ASID, walks to the entry, and clears it only if it still points
at the frame or table (`unmapPage`, `unmapPageTable`, `findVSpaceForASID` in
`src/arch/x86/kernel/vspace.c`). An ASID is a logical name, so it cannot
dangle. On x86_64 there are 4096 ASIDs, 8 pools of 512
(`seL4_NumASIDPoolsBits`, `seL4_ASIDPoolIndexBits`); ASID Control and ASID
Pool capabilities hand them out (manual, `vspace.tex`), so that one task
cannot use up another's.

The attacker is a ring-3 task holding some untyped, frames and paging
structures. The options:

1. **seL4's ASID pools after all.** Two more object types, two more
   invocations (`MakePool`, `Assign`; `object-api-arch.xml`), and an Assign
   step before a VSpace can be used. A pool holder can exhaust only its own
   512 ASIDs. ASIDs are reused after a VSpace dies: a stale frame capability
   still tagged with the old ASID and address can unmap a mapping of the same
   frame at the same address in the new VSpace, since `unmapPage` checks only
   the frame's address. Every map re-checks ASID to VSpace.
2. **A kernel-static ASID table, assigned at PML4 retype.** No new objects,
   but any task with 16 MiB of untyped can retype 4096 PML4s and make every
   later VSpace creation fail for every task: a denial of service that
   capabilities cannot confine. A table with one entry per 4 KiB of RAM
   cannot be exhausted, since each ASID needs a 4 KiB PML4, but costs 0.2%
   of RAM in static memory and keeps the reuse problem of option 1.
3. **Back-references kept exact.** Each paging structure records, for each
   entry, the slot of the capability that installed it; each mapped
   capability records its table and index. Delete and Unmap clear both
   sides. There is no shared namespace to exhaust and no stale name to
   reuse. The risk moves into the kernel: a bug that breaks the link (a slot
   move that forgets to update it) is a dangling pointer, which an attacker
   can turn into a kernel write.

## Decision

Option 3.

- Every paging structure (PML4, PDPT, PageDirectory, PageTable) is 8 KiB:
  the 4 KiB hardware table, then 512 back-reference words, each 0 or the
  physical address of the capability slot holding the capability that installed
  the entry.
- A mapped frame capability holds its table, index and virtual address; a
  mapped PDPT, PageDirectory or PageTable capability holds its parent table
  and index.
- PDPT, PageDirectory and PageTable capabilities fail `derive` with
  `IllegalOperation`: they cannot be copied or minted, and IPC transfer stops
  at them; they can only be moved. So each structure's mapping state lives
  in its one capability and the structure is mapped at most once. Frame
  copies start unmapped, as in seL4. PML4 capabilities derive freely.
- Every slot move of a mapped capability rewrites its back-reference. The
  capability core's `Kernel` trait has `moved(cap, old_slot, new_slot)`,
  called after `CNode_Move`, `CNode_Mutate`, both halves of `CNode_Rotate`
  and every Zombie swap.
- Every use of a link checks it in both directions first, and panics on a
  mismatch: before writing through a capability's (table, index), the kernel
  checks that the table's back-reference names the capability's slot, and
  before acting on a back-reference it checks that the named slot holds a
  capability mapped at that entry. A broken link becomes a crash, not a
  write into reused memory.
- Map requires an unmapped, empty structure. A structure's Unmap or delete
  detaches it and clears its entries; a structure whose parent is deleted
  keeps its entries but is unreachable, and must be unmapped before it is
  mapped again. Every step touches at most 512 entries.
- One `core` module (`l4core::vspace`) makes every write to entries,
  back-references and mapping fields, and its proptest model checks both
  directions of the link after every step. The M2 proptest covers nested
  CNode deletion with mapped capabilities in slot 0 and random preemption.
- PCID is off: CR4.PCIDE is never set. Every CR3 write then drops all
  non-global translations (from memory; check in M3), so the TLB holds user
  translations only for the loaded VSpace, and only changes within it need
  `invlpg` or a CR3 reload. With no ASIDs there is nothing to tag a PCID
  with; a later PCID scheme would assign tags dynamically, as Linux does,
  without a user-visible namespace.

## Consequences

- No ASID Control or ASID Pool objects, no Assign step, no `0x90`-range
  labels and no ASID-control slot in BootInfo.
- Unmapping a frame is a constant-time clear with no lookup, and nothing in
  the kernel can refer to a dead VSpace or table, so no invocation can act
  on a reused name.
- Paging structures cost twice seL4's memory: 32 KiB, not 16 KiB, for the
  four tables of a small task.
- A delegated table capability cannot be revoked back; only revoking its
  untyped reclaims it. seL4 allows copies of mapped table capabilities.
- Table capabilities cannot travel by IPC, since IPC transfer derives;
  delegating one needs a CNode the giver can address (`CNode_Move`).
- The capability core (M2) calls `moved` on every slot move, Zombie swaps
  included, and its proptest model includes mapping state from M5.
- The two-way check costs one extra read per use of a link.
- Remapping a frame with new rights is its own invocation, `Frame_Remap`,
  because the back-reference already names the mapping.
- Red-team brief 4 (M10) targets the link: moves, rotates, CNode deletion
  and untyped revoke with mapped capabilities in every order.
