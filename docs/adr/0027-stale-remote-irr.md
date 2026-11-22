# 0027: Issuing an I/O APIC pin clears a stale Remote IRR with the entry level-triggered, through the EOI register or a trigger toggle

Status: accepted, M7 (2026-11-22). Amends ADR 0019.

## Context

An I/O APIC sets an entry's Remote IRR when it sends a level interrupt,
and sends nothing more on that pin until an EOI for the entry's vector
clears it. The local APIC broadcasts that EOI when the kernel writes its EOI
register for a level vector, with EOI-broadcast suppression off, which is
how microL4 and seL4 clear it in normal operation. seL4 never reads Remote
IRR: boot writes every pin masked, edge-triggered and with vector 0
(`single_ioapic_init`, `src/plat/pc99/machine/ioapic.c`), and issue writes
the entry without looking (`ioapic_map_pin_to_vector`).

[ADR 0019](0019-irqcontrol.md) had issue write the pin masked and
edge-triggered and check that Remote IRR reads 0, and `docs/design.md`
added that a set one is first cleared by writing the old vector to the I/O
APIC's EOI register. Three things were wrong with that. An I/O APIC clears
Remote IRR on an EOI only for a level entry: QEMU's `ioapic_eoi_broadcast`
skips edge entries, and Linux's `clear_IO_APIC_pin`
(`arch/x86/kernel/apic/io_apic.c`, from memory) makes the entry level first
for that reason. QEMU clears Remote IRR whenever an entry is written
edge-triggered (`ioapic_fix_edge_remote_irr`, from memory), so there the
check could never fire and the EOI path would never run. And the EOI
register exists only from version `0x20`; the M3 Hyper-V check found
Hyper-V's I/O APIC at version `0x11`, so there a pin with a stale Remote
IRR would stay refused with `RevokeFirst`. The M7 spec check compared
seL4's approach, masking and unmasking, an EOI broadcast through the local
APIC and Linux's.

- seL4's approach is what clears Remote IRR in normal operation on every
  version, since every delivery is EOI'd against a vector the pin keeps.
  It does nothing for a stale one, left by a delivery whose EOI never came
  (the firmware's, lost when the local APIC was reset), and microL4 boot
  keeps each pin's vector and trigger.
- Masking and unmasking leaves Remote IRR set: the mask bit only holds back
  new messages.
- The kernel cannot make the local APIC broadcast an EOI for a stale
  vector: an EOI broadcasts only the in-service vector, and only if its TMR
  bit is set, and a self-IPI is edge-triggered.
- Linux (`__eoi_ioapic_pin`, from memory) writes the vector to the EOI
  register from version `0x20` and, below it, writes the masked entry
  edge-triggered and then level-triggered again, which clears Remote IRR
  where a switch to edge does, as on QEMU.

## Decision

- Issue (`GetISA`, `GetIOAPIC`) masks the pin's entry, keeping vector,
  trigger and polarity, and reads it back.
- If Remote IRR is set, the kernel writes the entry level-triggered, still
  masked and with its old vector; then, on an I/O APIC of version `0x20` or
  later, it writes the old vector to the EOI register (offset `0x40`), and on
  an older one it writes the entry edge-triggered and then level-triggered
  again, both masked.
- It reads Remote IRR again. Still set gives `RevokeFirst`, and the pin
  stays masked; otherwise it writes the destination word, then the final
  entry, unmasked.
- This runs in the resource check, before the destination slot is checked,
  so an issue that then fails may have cleared a free pin's stale Remote
  IRR.
- Deletion is unchanged: it sets only the mask bit, keeping vector and
  trigger, so a delivery pending at the deletion clears its own Remote IRR
  through the EOI broadcast.

## Consequences

- A stale Remote IRR no longer leaves a pin refused for good on Hyper-V;
  `RevokeFirst` for it means the clearing failed, or a delivery was still
  in flight.
- `core::irq` gains a `ClearRemoteIrr` action that picks the path by the
  I/O APIC's version, and the I/O APIC's register block is `0x44` bytes
  from version `0x20`.
- Both paths run on QEMU, whose I/O APIC takes `-global ioapic.version=0x11`
  (from memory), in a self-test that strands Remote IRR and then issues the
  pin. Hyper-V's behaviour stays unchecked: no planned driver there uses a
  level pin.
- `docs/abi.md`, [`IRQControl_GetISA`](../abi.md#0x60-irqcontrol_getisa) and
  [`IRQControl_GetIOAPIC`](../abi.md#0x61-irqcontrol_getioapic), say the
  kernel clears a stale Remote IRR before checking it.
