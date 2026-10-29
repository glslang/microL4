# 0009: A capability is a common header word and a data word, and CNodes and TCBs are destroyed through Zombie capabilities

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Kernel objects row lists the object types and M2 asks for "the
capability representation (type, object, size, rights, badge, guard)". The
row does not say how a capability is laid out, how `core/`, which forbids
`unsafe`, reaches capabilities in kernel memory, which capability types
exist besides the listed objects (the Reply capability of the IPC row, the
Hypervisor capability of the Hyper-V row), or how an object that holds
capabilities is destroyed. seL4 packs each capability type into its own
128-bit layout with kernel virtual pointers
(`include/object/structures_64.bf`) and destroys CNodes and TCBs through
Zombie capabilities (`src/object/cnode.c`).

## Decision

- A capability is 16 bytes: a per-type `data` word (badge, guard, watermark,
  mapping record) and a header common to every type: a 5-bit type tag,
  `size_bits`, four rights bits, a device bit, and bits 4 to 51 of the
  object's physical address. A slot is the capability plus a 16-byte
  derivation node.
- The tags cover seL4's classic x86_64 capabilities without ASID pools,
  domains, IOMMU or VT-x, plus Hypervisor, Reply, a kernel-internal Zombie,
  and six reserved tags ([ADR 0005](0005-paging-back-references.md) replaces
  ASID pools with back-references and needs none).
- `core/` reads and writes slots only through a `SlotMemory` trait over slot
  physical addresses held in `NonZeroU64` (no kernel object lies at physical
  address 0, [ADR 0007](0007-boot-region-and-bootinfo.md)), and calls other
  subsystems through hook traits, among them `moved(cap, old_slot, new_slot)`,
  called by the one move and one swap function after every relocation ([ADR
  0005](0005-paging-back-references.md)). The kernel implements them in
  `kernel/src/arch/` over the direct map; host tests implement them over fake
  physical memory.
- Slots live in CNodes, in the first five 32-byte slots of a TCB (CSpace
  root, VSpace root, IPC buffer, `reply`, `caller`), and in the IRQ node's
  192 slots in kernel static memory, which are in the derivation list but
  never a container.
- Deleting the last capability to a CNode or TCB turns it into a Zombie
  that clears the container one slot per preemptible step, with seL4's
  rules for nested containers.
- Every object is at least 16 bytes, a power of two, aligned to its size,
  and kernel objects are in RAM inside the direct map, below 64 GiB
  ([ADR 0006](0006-direct-map-bound.md)).
- `derive` refuses PDPT, PageDirectory and PageTable capabilities and unmaps
  Frame copies ([ADR 0005](0005-paging-back-references.md)); PML4 and
  Hypervisor capabilities derive, and a Hypervisor Mint narrows ([ADR
  0020](0020-hypervisor-capability.md)).

## Consequences

- One decoder serves every type for type, object, size and rights; `core/`
  never sees a virtual address, so M2 tests it on the host and under Miri.
- Per-type packing room is smaller than seL4's: a Frame's or page table's
  mapping record must fit one word (a concern for [ADR
  0005](0005-paging-back-references.md)).
- The Zombie algorithm is the most intricate code in `core/`; porting it
  from seL4 rather than inventing a new one keeps a proven reference, at the
  price of seL4's behaviour that a nested CNode becomes unreachable, not
  cleared, until its untyped is revoked.
- Every other object type must keep its size a power of two of at least
  16 bytes, and hold capability slots only as a TCB does or, in kernel
  static memory, as the IRQ node does.
- Every relocation of a capability to another slot, the Zombie swap included,
  calls `moved` before the next preemption point; [ADR
  0005](0005-paging-back-references.md) uses it to keep back-references exact,
  and checks each back-reference in both directions before use.
- Reply capabilities are the one exception to "every capability to an object
  in an untyped's region is its descendant": the master is a root ([ADR
  0016](0016-reply-capability.md)), and TCB finalisation deletes the master
  and its child.
