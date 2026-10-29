# 0019: IRQControl names interrupt sources; the kernel allocates vectors, applies MADT overrides, bounds every pin to three interrupts per Ack and runs the local APIC in xAPIC mode

Status: accepted, M1 (2026-10-29)

## Context

PLAN.md's Interrupts row says: local APIC and I/O APIC found through the MADT,
IRQControl issues IRQHandler capabilities, interrupts arrive as notification
signals the driver acknowledges, MSI later. It does not say who picks the CPU
vector, who applies the MADT's interrupt source overrides, which local APIC
mode is used, or when a source is masked.

seL4 on x86 leaves the first two to user space: `GetIOAPIC` takes a vector, a
trigger and a polarity from the caller and `GetMSI` a vector
(`src/arch/x86/object/interrupt.c`), the kernel only prints the overrides
(`src/plat/pc99/machine/acpi.c`), and the root task finds them by parsing ACPI
from the RSDP in BootInfo. seL4 checks that a vector is unused but not that a
pin is (`ioapic_decode_map_pin_to_vector`), masks every source on delivery
until Ack (`handleInterrupt`), and on deletion sets only the pin's mask bit
(`ioapic_mask`). In microL4 user space has no ACPI parser and never reads
ACPI, whose memory becomes untyped after boot ([ADR
0007](0007-boot-region-and-bootinfo.md)), and the platforms differ in their
overrides. Masking an edge-triggered pin from its first delivery loses edges
on an I/O APIC that drops them while masked; never masking it lets a driver
that programs its device (the PIT, say) to interrupt at full rate starve every
thread.

## Decision

- Vectors `0x30`-`0xEF` are device vectors, allocated by the kernel. The IRQ
  number is the vector minus `0x30`. Kernel vectors sit at the top: timer
  `0xFD`, error `0xFE`, spurious `0xFF`; the PIC is remapped to `0x20`-`0x2F`
  and masked. Only `#BP` has DPL 3; vectors 17, 21, 29, 30 and the reserved
  exception vectors cannot occur and panic ([ADR
  0008](0008-kernel-entry-and-exit.md)).
- IRQControl's invocations name a source and return the IRQ number:
  `GetISA(isa_irq)` applies the MADT overrides in the kernel;
  `GetIOAPIC(gsi, trigger, polarity)` takes explicit flags; `GetMSI()` (M9)
  returns the message address and data; `GetSint(sint)` (M9) is Hyper-V's
  SynIC. The kernel refuses a second handler for any source.
- Masking: a level pin is masked on delivery until Ack, as in seL4. An
  edge pin has a `pending` bit, set on delivery and cleared by Ack; a delivery
  that finds it set masks the pin, and Ack unmasks it. MSI and SINTs are never
  masked.
- Deleting a handler sets only the pin's mask bit and keeps vector and
  trigger, as seL4 does. Issuing a pin writes it masked and edge-triggered
  first, checks that Remote IRR reads 0, then writes the final entry.
- The local APIC runs in xAPIC mode only. If the firmware left x2APIC on, the
  kernel leaves it through the disabled state. LINT0 and LINT1 are masked.
  The kernel reaches the LAPIC, I/O APICs and HPET only through the kernel
  device window ([ADR 0004](0004-privilege-features.md)).

## Consequences

- The root task needs no ACPI parser to give `uart` COM1's interrupt:
  `GetISA(4)` works on both platforms, and `InterruptInfo` in BootInfo shows
  the routes and GSI ranges.
- User space cannot choose an APIC priority class. The kernel runs with
  interrupts off, and drivers are ordered by thread priority, so little is
  lost.
- Between two Acks an I/O APIC pin delivers at most three interrupts, so a
  storming device costs only its driver's own scheduling; no edge that
  follows an Ack is lost.
- Every driver binds, Acks once and services its device once, then loops:
  wait, service the device, Ack.
- A level interrupt pending during a deletion cannot leave the pin dead for
  its next owner.
- `core/` gains the override resolution, the vector allocator and the pin
  state machine, all host-tested; seL4's PIC mode is not offered.
- Hyper-V's recommendation to use x2APIC MSRs is ignored; only speed is lost.
- `docs/abi.md` gets the IRQControl and IRQHandler sections ([Interrupts,
  I/O ports and Hyper-V](../abi.md#interrupts-io-ports-and-hyper-v)).
